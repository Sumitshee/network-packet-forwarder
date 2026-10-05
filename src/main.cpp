// npf, the router.
//
//   npf run --config <file> [--pidfile <path>] [--stats-file <path>] [--busy-poll]
//       Forwards until SIGINT or SIGTERM, with a stats line every 5 s. SIGUSR1 prints the whole
//       counter table and writes it to the stats file, which is how `npf show stats` reads it.
//       SIGUSR2 empties the ARP cache of all but its static entries, for tests.
//   npf dump --iface <name>
//       Prints the parsed headers of every frame received on one interface.
//   npf show stats [--pidfile <path>] [--stats-file <path>]
//       Asks the running `npf run` for its counters, and prints them.
//   npf replay <in.pcap> <out.pcap> --config <file> [--stats-json <path>]
//       Runs every frame of in.pcap through the router, as if it had arrived on port 0, and writes
//       every frame the router sends to out.pcap. No clock is read and no ARP request is ever
//       answered, so the same input always gives the same output, byte for byte. --stats-json
//       writes the final counters as JSON.
//
// run and dump need CAP_NET_RAW, and show signals a process that has it: in practice, sudo.
// replay needs nothing.

#include <poll.h>
#include <sys/signalfd.h>
#include <sys/types.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <format>
#include <fstream>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <npf/core/config.hpp>
#include <npf/core/log.hpp>
#include <npf/core/packet.hpp>
#include <npf/core/pool.hpp>
#include <npf/core/time.hpp>
#include <npf/core/unique_fd.hpp>
#include <npf/io/af_packet.hpp>
#include <npf/io/backend.hpp>
#include <npf/io/pcap_file.hpp>
#include <npf/pipe/decision.hpp>
#include <npf/pipe/filter.hpp>
#include <npf/pipe/forward.hpp>
#include <npf/proto/arp.hpp>
#include <npf/proto/checksum.hpp>
#include <npf/proto/ethernet.hpp>
#include <npf/proto/format.hpp>
#include <npf/proto/icmp.hpp>
#include <npf/proto/ipv4.hpp>
#include <npf/proto/l4.hpp>
#include <npf/stat/counters.hpp>
#include <npf/table/arp_cache.hpp>
#include <npf/table/fib.hpp>
#include <npf/table/lpm_linear.hpp>
#include <npf/table/mac_table.hpp>
#include <optional>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace {

using npf::DropReason;
using npf::Verdict;
using npf::core::Packet;
using npf::core::PacketPool;
using npf::proto::format_ipv4;
using npf::proto::format_mac;

constexpr std::string_view kUsage =
    "usage: npf run --config <file> [--pidfile <path>] [--stats-file <path>] [--busy-poll]\n"
    "       npf dump --iface <name>\n"
    "       npf show stats [--pidfile <path>] [--stats-file <path>]\n"
    "       npf replay <in.pcap> <out.pcap> --config <file> [--stats-json <path>]\n";

constexpr auto kStatsPeriod = std::chrono::seconds{5};
constexpr int kPollTimeoutMs = 100;  // long enough that an idle router does not spin a core
constexpr std::size_t kArpCapacity = 1024;
constexpr std::size_t kMacCapacity = 4096;
constexpr std::size_t kDumpPoolSize = 256;
constexpr auto kShowTimeout = std::chrono::seconds{2};

class UsageError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

[[noreturn]] void throw_errno(const std::string& what) {
  throw std::system_error(errno, std::generic_category(), what);
}

void print(const std::string& text) {
  std::fputs(text.c_str(), stdout);
}

// --- the command line ----------------------------------------------------------------------------

struct Options {
  std::string command;
  std::filesystem::path config;
  std::filesystem::path pidfile{"/run/npf.pid"};
  std::filesystem::path stats_file{"/run/npf.stats"};
  std::string iface;
  bool busy_poll{false};
  std::vector<std::filesystem::path> files;  // replay's: the pcap to read, then the one to write
  std::filesystem::path stats_json;
};

struct Flag {
  std::string_view name;
  std::string_view value;
};

// Applies one "--name value" pair. False if the command has no such option.
bool set_option(Options& o, const Flag& flag) {
  const bool run_or_replay = o.command == "run" || o.command == "replay";
  const bool run_or_show = o.command == "run" || o.command == "show";
  if (flag.name == "--config" && run_or_replay) {
    o.config = flag.value;
  } else if (flag.name == "--iface" && o.command == "dump") {
    o.iface = flag.value;
  } else if (flag.name == "--pidfile" && run_or_show) {
    o.pidfile = flag.value;
  } else if (flag.name == "--stats-file" && run_or_show) {
    o.stats_file = flag.value;
  } else if (flag.name == "--stats-json" && o.command == "replay") {
    o.stats_json = flag.value;
  } else {
    return false;
  }
  return true;
}

// What each command cannot do without.
void require_complete(const Options& o) {
  if (o.command == "replay" && o.files.size() != 2) {
    throw UsageError("npf replay takes two files: the pcap to read, and the pcap to write");
  }
  if ((o.command == "run" || o.command == "replay") && o.config.empty()) {
    throw UsageError(std::format("npf {} needs --config <file>", o.command));
  }
  if (o.command == "dump" && o.iface.empty()) {
    throw UsageError("npf dump needs --iface <name>");
  }
}

Options parse_args(std::span<char* const> argv) {
  std::vector<std::string_view> args;
  for (const char* arg : argv.subspan(1)) {
    args.emplace_back(arg);
  }
  if (args.empty()) {
    throw UsageError("no command given");
  }
  Options o;
  o.command = args.front();
  std::size_t i = 1;
  if (o.command == "show") {
    if (args.size() < 2 || args[1] != "stats") {
      throw UsageError("show what? The only thing to show is: npf show stats");
    }
    i = 2;
  } else if (o.command != "run" && o.command != "dump" && o.command != "replay") {
    throw UsageError(std::format("unknown command '{}'", o.command));
  }
  for (; i < args.size(); ++i) {
    const std::string_view arg = args[i];
    if (o.command == "replay" && !arg.starts_with("--")) {
      o.files.emplace_back(arg);
    } else if (arg == "--busy-poll" && o.command == "run") {
      o.busy_poll = true;
    } else if (i + 1 == args.size()) {
      throw UsageError(std::format("{} needs a value", arg));
    } else if (!set_option(o, {.name = arg, .value = args[++i]})) {
      throw UsageError(std::format("'{}' is not an option of npf {}", arg, o.command));
    }
  }
  require_complete(o);
  return o;
}

// --- process plumbing ----------------------------------------------------------------------------

// Signals arrive as reads from a descriptor instead of interrupting the loop, so the poll() loop
// treats them as one more readable fd, and no global flag is needed.
class SignalFd {
 public:
  explicit SignalFd(std::initializer_list<int> signals) {
    sigset_t mask{};
    sigemptyset(&mask);
    for (const int s : signals) {
      sigaddset(&mask, s);
    }
    if (const int rc = ::pthread_sigmask(SIG_BLOCK, &mask, nullptr); rc != 0) {
      throw std::system_error(rc, std::generic_category(), "pthread_sigmask");
    }
    fd_.reset(::signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC));
    if (!fd_.valid()) {
      throw_errno("signalfd");
    }
  }

  [[nodiscard]] int fd() const noexcept { return fd_.get(); }

  // The next signal waiting, if any.
  [[nodiscard]] std::optional<int> next() const noexcept {
    signalfd_siginfo info{};
    if (::read(fd_.get(), &info, sizeof(info)) != static_cast<ssize_t>(sizeof(info))) {
      return std::nullopt;
    }
    return static_cast<int>(info.ssi_signo);
  }

 private:
  npf::core::UniqueFd fd_;
};

std::optional<pid_t> read_pid(const std::filesystem::path& path) {
  std::ifstream in(path);
  long pid = 0;
  if (!(in >> pid) || pid <= 0 || pid > std::numeric_limits<pid_t>::max()) {
    return std::nullopt;
  }
  return static_cast<pid_t>(pid);
}

// Records this process's pid for `npf show stats`, and removes the file again on the way out.
class Pidfile {
 public:
  explicit Pidfile(std::filesystem::path path) : path_{std::move(path)} {
    if (const std::optional<pid_t> pid = read_pid(path_);
        pid && (::kill(*pid, 0) == 0 || errno == EPERM)) {
      throw std::runtime_error(std::format(
          "{} names process {}, which is still running. Is npf already running? If not, delete "
          "the file",
          path_.string(), *pid));
    }
    std::ofstream out(path_, std::ios::trunc);
    out << ::getpid() << '\n';
    if (!out) {
      throw std::runtime_error("cannot write " + path_.string());
    }
  }
  Pidfile(const Pidfile&) = delete;
  Pidfile(Pidfile&&) = delete;
  Pidfile& operator=(const Pidfile&) = delete;
  Pidfile& operator=(Pidfile&&) = delete;
  ~Pidfile() {
    std::error_code ignored;
    std::filesystem::remove(path_, ignored);
  }

 private:
  std::filesystem::path path_;
};

// --- statistics ----------------------------------------------------------------------------------

using CounterList = std::vector<std::pair<std::string, std::uint64_t>>;

// Every counter, by name, in one fixed order: the drop reasons in DropReason's, then only the IP
// protocols seen, by number.
CounterList counter_list(const npf::stat::Counters& c, const PacketPool& pool) {
  CounterList out{
      {"rx_packets", c.rx_packets},
      {"rx_bytes", c.rx_bytes},
      {"tx_packets", c.tx_packets},
      {"tx_bytes", c.tx_bytes},
      {"forwarded", c.forwarded},
      {"flooded", c.flooded},
      {"to_host", c.to_host},
      {"arp_requests_rx", c.arp_requests_rx},
      {"arp_replies_rx", c.arp_replies_rx},
      {"arp_requests_tx", c.arp_requests_tx},
      {"arp_replies_tx", c.arp_replies_tx},
      {"icmp_generated", c.icmp_generated},
  };
  for (std::size_t r = 1; r < npf::kDropReasons; ++r) {
    const auto reason = static_cast<DropReason>(r);
    out.emplace_back(npf::to_string(reason), c.drop(reason));
  }
  std::size_t protocol = 0;
  for (const std::uint64_t n : c.by_protocol) {
    if (n != 0) {
      out.emplace_back(std::format("ip_proto_{}", protocol), n);
    }
    ++protocol;
  }
  out.emplace_back("pool_available", pool.available());
  out.emplace_back("pool_capacity", pool.capacity());
  return out;
}

// One "name value" pair per line, so a script can pick out any counter with awk.
std::string counter_table(const npf::stat::Counters& c, const PacketPool& pool) {
  std::string out;
  for (const auto& [name, value] : counter_list(c, pool)) {
    out += std::format("{:<18}{}\n", name, value);
  }
  return out;
}

// The same, as one JSON object: a "name": value pair per line, in the same order.
std::string counter_json(const npf::stat::Counters& c, const PacketPool& pool) {
  std::string out = "{";
  std::string_view separator = "\n";
  for (const auto& [name, value] : counter_list(c, pool)) {
    out += std::format("{}  \"{}\": {}", separator, name, value);
    separator = ",\n";
  }
  return out + "\n}\n";
}

// Written aside and renamed into place, so `npf show stats` never reads half a table.
void write_stats_file(const std::filesystem::path& path, const std::string& table) {
  std::filesystem::path tmp = path;
  tmp += ".tmp";
  {
    std::ofstream out(tmp, std::ios::trunc);
    out << table;
    if (!out) {
      npf::core::log_warn("cannot write {}", tmp.string());
      return;
    }
  }
  std::error_code ec;
  std::filesystem::rename(tmp, path, ec);
  if (ec) {
    npf::core::log_warn("cannot rename {} to {}: {}", tmp.string(), path.string(), ec.message());
  }
}

// --- the forwarding loop -------------------------------------------------------------------------

// Packets waiting to go out of one port: at most one burst's worth.
class TxQueue {
 public:
  [[nodiscard]] bool push(Packet* p) noexcept {
    if (size_ == slots_.size()) {
      return false;
    }
    // The check above is the bounds check.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
    slots_[size_++] = p;
    return true;
  }
  [[nodiscard]] std::span<Packet* const> packets() const noexcept { return {slots_.data(), size_}; }
  void clear() noexcept { size_ = 0; }

 private:
  std::array<Packet*, npf::core::kMaxBurst> slots_{};
  std::size_t size_{0};
};

// What the ARP cache asks of the worker. A request is built in a fresh buffer and queued on its
// port, to leave with the rest of the burst. A packet the cache gives up on is released and
// counted as ArpUnresolved -- but the head of a queue first earns its sender a Host Unreachable,
// which takes the control plane, built after the cache. So a head waits here, and the worker
// answers it straight after the tick() that gave it up.
class ArpCacheEvents final : public npf::table::ArpEvents {
 public:
  // capacity: the ARP cache's. One tick() gives up on each entry at most once.
  ArpCacheEvents(PacketPool& pool, std::vector<npf::pipe::PortState> ports,
                 std::vector<TxQueue>& queues, npf::stat::Counters& stats, std::size_t capacity)
      : pool_{&pool},
        ports_{std::move(ports)},
        queues_{&queues},
        stats_{&stats},
        unresolved_(capacity) {}

  void send_arp_request(std::uint32_t target_ip, std::uint16_t out_port) noexcept override {
    if (out_port >= ports_.size()) {
      return;
    }
    Packet* p = pool_->acquire();
    if (p == nullptr) {
      return;  // no buffer to spare: the next packet for this neighbour asks again
    }
    const npf::pipe::PortState& port = ports_[out_port];
    if (!npf::proto::build_arp_request(*p, port.mac, port.ip, target_ip) ||
        !(*queues_)[out_port].push(p)) {
      pool_->release(p);
    }
  }

  void unresolved(Packet* p) noexcept override {
    if (n_unresolved_ == unresolved_.size()) {
      discard(p);  // not reached: see the constructor
      return;
    }
    unresolved_[n_unresolved_++] = p;
  }

  void discard(Packet* p) noexcept override {
    pool_->release(p);
    ++stats_->drop(DropReason::ArpUnresolved);
  }

  // The heads given up on since the last clear_unresolved(), still to be answered and dropped.
  [[nodiscard]] std::span<Packet* const> unresolved_heads() const noexcept {
    return {unresolved_.data(), n_unresolved_};
  }
  void clear_unresolved() noexcept { n_unresolved_ = 0; }

 private:
  PacketPool* pool_;  // borrowed, like everything the worker uses
  std::vector<npf::pipe::PortState> ports_;
  std::vector<TxQueue>* queues_;
  npf::stat::Counters* stats_;
  std::vector<Packet*> unresolved_;  // sized once; the first n_unresolved_ are waiting
  std::size_t n_unresolved_{0};
};

// The one worker: run the ARP cache's timers, receive a burst, decide every packet, send the
// answers and the forwarded.
class Worker {
 public:
  using Pipeline = npf::pipe::Forwarder<npf::table::LinearLpm>;

  Worker(npf::io::IoBackend& backend, PacketPool& pool, Pipeline& pipeline,
         npf::table::ArpCache& arp, ArpCacheEvents& arp_events, npf::stat::Counters& stats,
         std::vector<TxQueue>& requests, std::size_t burst)
      : backend_{&backend},
        pool_{&pool},
        pipeline_{&pipeline},
        arp_{&arp},
        arp_events_{&arp_events},
        stats_{&stats},
        requests_{&requests},
        forward_(requests.size()),
        arp_replies_(requests.size()),
        icmp_(requests.size()),
        burst_{burst} {}

  void run_one_burst(npf::core::Clock::time_point now) noexcept {
    arp_->tick(now);
    answer_unresolved(now);
    const std::size_t n = backend_->rx_burst(rx_.data(), burst_);
    const std::span<Packet* const> got(rx_.data(), n);
    for (const Packet* p : got) {
      ++stats_->rx_packets;
      stats_->rx_bytes += p->size();
    }
    pipeline_->process_burst(rx_.data(), n, decisions_.data());
    const std::span<const npf::Decision> decided(decisions_.data(), n);
    for (std::size_t i = 0; i < n; ++i) {
      dispatch(got[i], decided[i], now);
    }
    transmit();
  }

 private:
  // The heads of the queues tick() gave up on: a Host Unreachable each, out of the port each
  // arrived on, then dropped, as the packets queued behind them already were.
  void answer_unresolved(npf::core::Clock::time_point now) noexcept {
    for (Packet* p : arp_events_->unresolved_heads()) {
      if (Packet* error = pipeline_->host_unreachable(*p, *pool_, now); error != nullptr) {
        queue(icmp_[p->in_port()], error);
      }
      pool_->release(p);
      ++stats_->drop(DropReason::ArpUnresolved);
    }
    arp_events_->clear_unresolved();
  }

  // Every packet leaves here queued for transmission, released, or held by the ARP cache: exactly
  // one of those. So does every answer the control plane hands back.
  void dispatch(Packet* p, npf::Decision d, npf::core::Clock::time_point now) noexcept {
    switch (d.verdict) {
      case Verdict::Forward:
        forward(p, d.out_port);
        return;
      case Verdict::ToHost: {
        const std::optional<npf::pipe::Reply> reply = pipeline_->deliver_to_host(*p, *pool_, now);
        for (const npf::pipe::Reply& freed : pipeline_->released()) {  // an ARP answer's doing
          forward(freed.packet, freed.port);
        }
        if (reply && reply->packet == p) {  // an ARP request, turned into its reply in place
          queue(arp_replies_[reply->port], p);
          return;
        }
        if (reply) {
          queue(icmp_[reply->port], reply->packet);
        }
        pool_->release(p);
        return;
      }
      case Verdict::Drop:
        if (Packet* error = pipeline_->error_for(*p, d.reason, *pool_, now); error != nullptr) {
          queue(icmp_[p->in_port()], error);
        }
        pool_->release(p);
        return;
      case Verdict::Queued:  // the ARP cache's now, until deliver_to_host() or tick() lets it go
        return;
      case Verdict::Flood:  // nothing floods before phase 12
        pool_->release(p);
        return;
    }
  }

  void forward(Packet* p, std::uint16_t port) noexcept {
    if (!forward_[port].push(p)) {
      pool_->release(p);
      ++stats_->drop(DropReason::TxFull);
    }
  }

  void queue(TxQueue& q, Packet* p) noexcept {
    if (!q.push(p)) {
      pool_->release(p);
    }
  }

  // One tx_burst per queue per port: what the router says itself goes first, since traffic waits
  // on ARP and senders wait on ICMP.
  void transmit() noexcept {
    for (std::size_t i = 0; i < forward_.size(); ++i) {
      const auto port = static_cast<std::uint16_t>(i);
      stats_->arp_replies_tx += send(port, arp_replies_[i]);
      stats_->arp_requests_tx += send(port, (*requests_)[i]);
      send(port, icmp_[i]);  // counted as generated already, and in tx_packets once sent
      const std::size_t queued = forward_[i].packets().size();
      const std::size_t sent = send(port, forward_[i]);
      stats_->forwarded += sent;
      stats_->drop(DropReason::TxFull) += queued - sent;
    }
    backend_->tx_flush();
  }

  // Hands a queue to the backend, and releases what it refuses. Returns how many it took.
  std::size_t send(std::uint16_t port, TxQueue& q) noexcept {
    const std::span<Packet* const> pkts = q.packets();
    if (pkts.empty()) {
      return 0;
    }
    std::size_t bytes = 0;  // summed first: the backend releases what it sends
    for (const Packet* p : pkts) {
      bytes += p->size();
    }
    const std::size_t sent = backend_->tx_burst(pkts.data(), pkts.size(), port);
    for (Packet* p : pkts.subspan(sent)) {
      bytes -= p->size();
      pool_->release(p);
    }
    stats_->tx_packets += sent;
    stats_->tx_bytes += bytes;
    q.clear();
    return sent;
  }

  npf::io::IoBackend* backend_;  // all borrowed: their owner outlives the worker
  PacketPool* pool_;
  Pipeline* pipeline_;
  npf::table::ArpCache* arp_;
  ArpCacheEvents* arp_events_;
  npf::stat::Counters* stats_;
  std::vector<TxQueue>* requests_;    // per port, filled by the ARP cache through ArpCacheEvents
  std::vector<TxQueue> forward_;      // per port
  std::vector<TxQueue> arp_replies_;  // per port: the ARP requests deliver_to_host() turned around
  std::vector<TxQueue> icmp_;         // per port: echo replies and ICMP errors
  std::array<Packet*, npf::core::kMaxBurst> rx_{};
  std::array<npf::Decision, npf::core::kMaxBurst> decisions_{};
  std::size_t burst_;
};

// What this phase can run. The parser accepts more, for the phases that will implement it. io is
// what the command reads and writes through: af_packet for npf run, pcap for npf replay.
void require_supported(const npf::core::Config& cfg, npf::core::IoKind io) {
  if (cfg.interfaces.empty()) {
    throw std::runtime_error("the configuration has no interfaces");
  }
  if (cfg.io != io) {
    throw std::runtime_error(io == npf::core::IoKind::Pcap
                                 ? "npf replay needs 'io pcap' in the configuration"
                                 : "npf run needs 'io af_packet': io mmap and io xdp are not "
                                   "implemented yet, and io pcap is for npf replay");
  }
  if (cfg.fib != npf::core::FibKind::Linear) {
    throw std::runtime_error("only 'fib linear' is implemented so far");
  }
  if (cfg.mode != npf::core::RunMode::Rtc || cfg.workers != 1) {
    throw std::runtime_error("only 'mode rtc' with 'workers 1' is implemented so far");
  }
  if (cfg.arp.size() > kArpCapacity) {
    throw std::runtime_error(std::format("at most {} arp entries", kArpCapacity));
  }
}

npf::core::Config load_config_for(const std::filesystem::path& path, npf::core::IoKind io) {
  npf::core::ParseResult parsed = npf::core::load_config(path);
  if (!parsed.value) {
    throw std::runtime_error(std::format("{}: {}", path.string(), parsed.error));
  }
  require_supported(*parsed.value, io);
  return std::move(*parsed.value);
}

// The packet filter cfg, read from config_file, names; without one, no rules, and every packet is
// allowed.
npf::core::FilterConfig load_filter_for(const npf::core::Config& cfg,
                                        const std::filesystem::path& config_file) {
  const std::filesystem::path path = npf::core::filter_path(cfg, config_file);
  if (path.empty()) {
    return {};
  }
  npf::core::FilterParseResult parsed = npf::core::load_filter(path, cfg);
  if (!parsed.value) {
    throw std::runtime_error(std::format("{}: {}", path.string(), parsed.error));
  }
  return std::move(*parsed.value);
}

// Every interface's MAC as the backend has it: read from the interface for "mac auto", or else the
// configuration's own.
void take_macs(const npf::io::IoBackend& backend, npf::core::Config& cfg) {
  for (npf::core::InterfaceConfig& iface : cfg.interfaces) {
    iface.mac = backend.ports()[iface.port].mac;
  }
}

// The router itself -- its tables, the pipeline, and the worker that drives them -- around the
// backend and the pool that run() or replay() brings. cfg's interfaces must have their MACs.
// Members are built in the order declared, each from those above it.
struct Router {
  Router(const npf::core::Config& cfg, const npf::core::FilterConfig& rules,
         npf::io::IoBackend& backend, PacketPool& pool)
      : requests(cfg.interfaces.size()),
        arp_events(pool, npf::pipe::make_port_table(cfg), requests, stats, kArpCapacity),
        arp(arp_events, kArpCapacity),
        macs(kMacCapacity),
        filter(rules.rules, rules.policy),
        pipeline(cfg, fib, arp, macs, filter, stats),
        worker(backend, pool, pipeline, arp, arp_events, stats, requests, cfg.burst) {
    for (const npf::table::Route& r : cfg.routes) {
      if (!fib.add(r)) {
        throw std::runtime_error("the FIB refused a route the parser accepted");
      }
    }
    for (const npf::core::StaticArp& a : cfg.arp) {
      arp.insert_static(a.ip, a.mac, a.port);
    }
  }

  npf::table::LinearLpm fib;
  npf::stat::Counters stats;
  std::vector<TxQueue> requests;
  ArpCacheEvents arp_events;
  npf::table::ArpCache arp;
  npf::table::MacTable macs;
  npf::pipe::Filter filter;
  Worker::Pipeline pipeline;
  Worker worker;
};

void report(const npf::stat::Counters& stats, const PacketPool& pool,
            const std::filesystem::path& stats_file) {
  const std::string table = counter_table(stats, pool);
  print(table);
  write_stats_file(stats_file, table);
}

// The loop: forwards until SIGINT or SIGTERM, answers SIGUSR1 with the counters, and SIGUSR2 by
// flushing the ARP cache.
void serve(const Options& o, const npf::io::AfPacketBackend& backend, const PacketPool& pool,
           npf::table::ArpCache& arp, const npf::stat::Counters& stats, Worker& worker) {
  const SignalFd signals{SIGINT, SIGTERM, SIGUSR1, SIGUSR2};
  const Pidfile pidfile(o.pidfile);
  std::vector<pollfd> fds;
  for (const int fd : backend.fds()) {
    fds.push_back({fd, POLLIN, 0});
  }
  fds.push_back({signals.fd(), POLLIN, 0});
  const int timeout_ms = o.busy_poll ? 0 : kPollTimeoutMs;

  npf::core::log_info("forwarding on {} ports{}; Ctrl-C to stop", backend.ports().size(),
                      o.busy_poll ? ", busy-polling" : "");
  const auto start = npf::core::Clock::now();
  auto next_report = start + kStatsPeriod;
  for (bool running = true; running;) {
    if (::poll(fds.data(), fds.size(), timeout_ms) < 0 && errno != EINTR) {
      throw_errno("poll");
    }
    while ((fds.back().revents & POLLIN) != 0) {
      const std::optional<int> sig = signals.next();
      if (!sig) {
        break;
      }
      if (*sig == SIGUSR1) {
        report(stats, pool, o.stats_file);
      } else if (*sig == SIGUSR2) {
        arp.flush();
        npf::core::log_info("ARP cache flushed; {} static entries kept", arp.size());
      } else {
        running = false;
      }
    }
    const auto now = npf::core::Clock::now();
    worker.run_one_burst(now);
    if (now >= next_report) {
      next_report += kStatsPeriod;
      print(std::format(
          "npf: {:>6}s  rx {}  forwarded {}  to_host {}  dropped {}  tx {}  pool {}/{}\n",
          std::chrono::duration_cast<std::chrono::seconds>(now - start).count(), stats.rx_packets,
          stats.forwarded, stats.to_host, stats.total_drops(), stats.tx_packets, pool.available(),
          pool.capacity()));
    }
  }
}

int run(const Options& o) {
  npf::core::Config cfg = load_config_for(o.config, npf::core::IoKind::AfPacket);
  const npf::core::FilterConfig rules = load_filter_for(cfg, o.config);
  if (!cfg.filter.empty()) {
    npf::core::log_info("packet filter: {} rules from {}, policy {}", rules.rules.size(),
                        npf::core::filter_path(cfg, o.config).string(),
                        rules.policy == npf::pipe::Action::Allow ? "allow" : "deny");
  }
  PacketPool pool(cfg.pool_size);
  npf::io::AfPacketBackend backend(cfg.interfaces, pool);
  take_macs(backend, cfg);
  Router router(cfg, rules, backend, pool);

  serve(o, backend, pool, router.arp, router.stats, router.worker);

  router.arp.flush();  // packets still waiting on ARP are dropped now, and so counted
  print("npf: stopped; final counters:\n");
  report(router.stats, pool, o.stats_file);
  if (backend.rx_oversized() != 0) {
    npf::core::log_warn("{} frames were too big for a buffer and never reached the pipeline",
                        backend.rx_oversized());
  }
  return 0;
}

// --- npf replay ----------------------------------------------------------------------------------

// A replay's one moment. No clock is read, so the ICMP rate limiter and the ARP cache's timers see
// no time pass, and the same input always makes the same output.
constexpr npf::core::Clock::time_point kReplayTime{};

void write_text(const std::filesystem::path& path, const std::string& text) {
  std::ofstream out(path, std::ios::trunc);
  out << text;
  out.close();
  if (!out) {
    throw std::runtime_error("cannot write " + path.string());
  }
}

int replay(const Options& o) {
  const std::filesystem::path& in = o.files.at(0);
  const std::filesystem::path& out = o.files.at(1);
  npf::core::Config cfg = load_config_for(o.config, npf::core::IoKind::Pcap);
  const npf::core::FilterConfig rules = load_filter_for(cfg, o.config);
  PacketPool pool(cfg.pool_size);
  npf::io::PcapFileBackend backend({.in = in, .out = out}, cfg.interfaces, pool);
  take_macs(backend, cfg);
  Router router(cfg, rules, backend, pool);

  while (!backend.done()) {
    const std::size_t read = backend.records_read();
    router.worker.run_one_burst(kReplayTime);
    // Between bursts only the ARP cache holds buffers, and a replay never answers its requests.
    if (backend.records_read() == read) {
      throw std::runtime_error(std::format(
          "all {} packet buffers are waiting on ARP, which a replay never answers, and frames "
          "are left to read: give the neighbours arp lines, or raise pool_size",
          cfg.pool_size));
    }
  }
  router.arp.flush();  // packets still waiting on ARP are dropped now, and so counted
  backend.tx_flush();
  if (!backend.ok()) {
    throw std::runtime_error("cannot write " + out.string());
  }
  if (!o.stats_json.empty()) {
    write_text(o.stats_json, counter_json(router.stats, pool));
  }
  npf::core::log_info("replayed {} frames from {}, and wrote {} to {}", backend.records_read(),
                      in.string(), backend.records_written(), out.string());
  if (backend.rx_oversized() != 0) {
    npf::core::log_warn("{} frames were too big for a buffer and never reached the pipeline",
                        backend.rx_oversized());
  }
  return 0;
}

// --- npf dump ------------------------------------------------------------------------------------

std::string tcp_flags(std::uint8_t f) {
  std::string out;
  constexpr std::array<std::pair<std::uint8_t, char>, 6> kFlags{
      {{0x02, 'S'}, {0x01, 'F'}, {0x04, 'R'}, {0x08, 'P'}, {0x20, 'U'}, {0x10, '.'}}};
  for (const auto& [bit, letter] : kFlags) {
    if ((f & bit) != 0) {
      out += letter;
    }
  }
  return out.empty() ? "none" : out;
}

std::string describe_icmp(const npf::proto::Ipv4View& ip, const npf::proto::L4Info& l4) {
  const std::optional<npf::proto::IcmpView> icmp = npf::proto::IcmpView::parse(ip.payload());
  if (!icmp) {
    return std::format(", ICMP type {} code {}, bad checksum", l4.icmp_type, l4.icmp_code);
  }
  switch (icmp->type()) {
    case npf::proto::kIcmpEchoRequest:
    case npf::proto::kIcmpEchoReply:
      return std::format(", ICMP echo {}, id {}, seq {}",
                         icmp->type() == npf::proto::kIcmpEchoRequest ? "request" : "reply",
                         icmp->echo_id(), icmp->echo_seq());
    case npf::proto::kIcmpTimeExceeded:
      return std::format(", ICMP time exceeded, code {}", icmp->code());
    case npf::proto::kIcmpDestUnreachable:
      return std::format(", ICMP destination unreachable, code {}", icmp->code());
    default:
      return std::format(", ICMP type {} code {}", icmp->type(), icmp->code());
  }
}

std::string describe_ipv4(npf::core::CBytes body) {
  const std::optional<npf::proto::Ipv4View> ip = npf::proto::Ipv4View::parse(body);
  if (!ip) {
    return ", IPv4, malformed header";
  }
  std::string out = std::format(", IPv4 {} > {}, ttl {}", format_ipv4(ip->src()),
                                format_ipv4(ip->dst()), ip->ttl());
  if (!npf::proto::ipv4_checksum_valid(ip->header())) {
    out += ", bad checksum";
  }
  if (ip->is_fragment()) {
    out += std::format(", fragment at {}{}", ip->frag_offset() * 8, ip->mf() ? ", more" : "");
  }
  if (!ip->is_first_fragment()) {
    return out + std::format(", protocol {} (no header: not the first fragment)", ip->protocol());
  }
  const std::optional<npf::proto::L4Info> l4 = npf::proto::parse_l4(*ip);
  if (!l4) {
    return out + std::format(", protocol {}, malformed header", ip->protocol());
  }
  switch (l4->protocol) {
    case npf::proto::kIpProtoTcp:
      return out + std::format(", TCP {} > {} [{}] seq {}", l4->sport, l4->dport,
                               tcp_flags(l4->tcp_flags), l4->seq);
    case npf::proto::kIpProtoUdp:
      return out + std::format(", UDP {} > {}", l4->sport, l4->dport);
    case npf::proto::kIpProtoIcmp:
      return out + describe_icmp(*ip, *l4);
    default:
      return out + std::format(", protocol {}", l4->protocol);
  }
}

std::string describe_arp(npf::core::CBytes body) {
  const std::optional<npf::proto::ArpView> arp = npf::proto::ArpView::parse(body);
  if (!arp) {
    return ", ARP, malformed";
  }
  switch (arp->oper()) {
    case npf::proto::ArpView::kOpRequest:
      return std::format(", ARP, who-has {} tell {}", format_ipv4(arp->tpa()),
                         format_ipv4(arp->spa()));
    case npf::proto::ArpView::kOpReply:
      return std::format(", ARP, {} is-at {}", format_ipv4(arp->spa()), format_mac(arp->sha()));
    default:
      return std::format(", ARP, operation {}", arp->oper());
  }
}

// One line per frame, in the spirit of tcpdump -e.
std::string describe(npf::core::CBytes frame) {
  const std::optional<npf::proto::EthView> eth = npf::proto::EthView::parse(frame);
  if (!eth) {
    return std::format("runt frame, length {}", frame.size());
  }
  std::string out = format_mac(eth->src()) + " > " + format_mac(eth->dst());
  if (eth->has_vlan()) {
    out += std::format(", vlan {}", eth->vlan_id());
  }
  switch (eth->ethertype()) {
    case npf::proto::kEtherTypeArp:
      out += describe_arp(eth->payload());
      break;
    case npf::proto::kEtherTypeIpv4:
      out += describe_ipv4(eth->payload());
      break;
    default:
      out += std::format(", ethertype 0x{:04x}", eth->ethertype());
  }
  return out + std::format(", length {}", frame.size());
}

int dump(const Options& o) {
  PacketPool pool(kDumpPoolSize);
  npf::core::InterfaceConfig iface;  // port 0, and its MAC read from the interface
  iface.name = o.iface;
  npf::io::AfPacketBackend backend(std::span(&iface, 1), pool);
  const SignalFd signals{SIGINT, SIGTERM};
  std::array<pollfd, 2> fds{{{backend.fds().front(), POLLIN, 0}, {signals.fd(), POLLIN, 0}}};
  std::array<Packet*, npf::core::kBurst> got{};

  npf::core::log_info("printing the frames received on {}; Ctrl-C to stop", o.iface);
  const auto start = npf::core::Clock::now();
  for (;;) {
    if (::poll(fds.data(), fds.size(), -1) < 0 && errno != EINTR) {
      throw_errno("poll");
    }
    if (signals.next()) {
      return 0;
    }
    const std::size_t n = backend.rx_burst(got.data(), got.size());
    const std::chrono::duration<double> t = npf::core::Clock::now() - start;
    for (Packet* p : std::span(got.data(), n)) {
      print(std::format("{:12.6f} {}\n", t.count(), describe(std::as_const(*p).data())));
      pool.release(p);
    }
  }
}

// --- npf show stats ------------------------------------------------------------------------------

std::optional<std::filesystem::file_time_type> modified(const std::filesystem::path& path) {
  std::error_code ec;
  const std::filesystem::file_time_type t = std::filesystem::last_write_time(path, ec);
  if (ec) {
    return std::nullopt;
  }
  return t;
}

int show(const Options& o) {
  const std::optional<pid_t> pid = read_pid(o.pidfile);
  if (!pid) {
    throw std::runtime_error(
        std::format("no npf is running: there is no pid in {}", o.pidfile.string()));
  }
  const std::optional<std::filesystem::file_time_type> before = modified(o.stats_file);
  if (::kill(*pid, SIGUSR1) != 0) {
    throw_errno(std::format("cannot signal npf (pid {})", *pid));
  }
  // It answers between two bursts, so within milliseconds unless it is wedged.
  const auto deadline = npf::core::Clock::now() + kShowTimeout;
  while (npf::core::Clock::now() < deadline) {
    if (const auto now = modified(o.stats_file); now && now != before) {
      std::ifstream in(o.stats_file);
      std::ostringstream text;
      text << in.rdbuf();
      print(text.str());
      return 0;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{10});
  }
  throw std::runtime_error(std::format("npf (pid {}) did not update {} within {} s", *pid,
                                       o.stats_file.string(), kShowTimeout.count()));
}

// Usable while handling an exception: no allocation, nothing that can throw.
void print_error(const char* message) noexcept {
  std::fputs("npf: error: ", stderr);
  std::fputs(message, stderr);
  std::fputs("\n", stderr);
}

}  // namespace

int main(int argc, char** argv) {
  try {
    std::setvbuf(stdout, nullptr, _IOLBF, 0);  // a line at a time, even into a log file
    const Options o = parse_args(std::span(argv, static_cast<std::size_t>(argc)));
    if (o.command == "run") {
      return run(o);
    }
    if (o.command == "dump") {
      return dump(o);
    }
    if (o.command == "replay") {
      return replay(o);
    }
    return show(o);
  } catch (const UsageError& e) {
    print_error(e.what());
    std::fputs(kUsage.data(), stderr);
    return 2;
  } catch (const std::exception& e) {
    print_error(e.what());
    return 1;
  }
}
