// npf, the router.
//
//   npf run --config <file> [--io af_packet|mmap] [--mode rtc|pipeline] [--workers <n>]
//           [--pidfile <path>] [--stats-file <path>] [--busy-poll]
//       Forwards until SIGINT or SIGTERM, with a stats line every 5 s. --mode and --workers stand
//       in for the configuration's own: n workers, each running to completion on sockets of its
//       own (rtc), or fed by an RX thread per port (pipeline). --io likewise stands in for the
//       configuration's io: AF_PACKET with a system call per frame, or PACKET_MMAP's rings. SIGUSR1
//       prints the whole counter table and writes it to the stats file, which is how `npf show
//       stats` reads it. SIGRTMIN and SIGRTMIN+1 write the MAC table and the ARP cache next to it,
//       with the extensions .mac and .arp, for `npf show mac` and `npf show arp`, a section per
//       worker when there are several. SIGUSR2 empties the ARP caches of all but their static
//       entries, for tests.
//   npf dump --iface <name>
//       Prints the parsed headers of every frame received on one interface.
//   npf show stats|mac|arp [--pidfile <path>] [--stats-file <path>]
//       Asks the running `npf run` for its counters, its MAC table or its ARP cache, and prints
//       them.
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

#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <charconv>
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
#include <memory>
#include <npf/core/config.hpp>
#include <npf/core/log.hpp>
#include <npf/core/packet.hpp>
#include <npf/core/pool.hpp>
#include <npf/core/time.hpp>
#include <npf/core/unique_fd.hpp>
#include <npf/io/af_packet.hpp>
#include <npf/io/backend.hpp>
#include <npf/io/packet_mmap.hpp>
#include <npf/io/pcap_file.hpp>
#include <npf/pipe/decision.hpp>
#include <npf/pipe/filter.hpp>
#include <npf/pipe/forward.hpp>
#include <npf/pipe/worker.hpp>
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
#include <type_traits>
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
    "usage: npf run --config <file> [--io af_packet|mmap] [--mode rtc|pipeline] [--workers <n>]\n"
    "               [--pidfile <path>] [--stats-file <path>] [--busy-poll]\n"
    "       npf dump --iface <name>\n"
    "       npf show stats|mac|arp [--pidfile <path>] [--stats-file <path>]\n"
    "       npf replay <in.pcap> <out.pcap> --config <file> [--stats-json <path>]\n";

constexpr auto kStatsPeriod = std::chrono::seconds{5};
constexpr int kPollTimeoutMs = 100;  // long enough that an idle router does not spin a core
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
  std::string what;  // show's: stats, mac or arp
  std::filesystem::path config;
  std::filesystem::path pidfile{"/run/npf.pid"};
  std::filesystem::path stats_file{"/run/npf.stats"};
  std::string iface;
  bool busy_poll{false};
  std::optional<npf::core::RunMode> mode;  // run's: nullopt keeps the configuration's
  std::optional<npf::core::IoKind> io;
  std::optional<std::size_t> workers;
  std::vector<std::filesystem::path> files;  // replay's: the pcap to read, then the one to write
  std::filesystem::path stats_json;
};

struct Flag {
  std::string_view name;
  std::string_view value;
};

std::size_t parse_count(std::string_view text, std::string_view what) {
  std::size_t n = 0;
  const auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), n);
  if (ec != std::errc{} || end != text.data() + text.size() || n == 0) {
    throw UsageError(std::format("{} needs a positive whole number, not '{}'", what, text));
  }
  return n;
}

npf::core::IoKind parse_io(std::string_view value) {
  if (value != "af_packet" && value != "mmap") {
    throw UsageError(std::format("--io is af_packet or mmap, not '{}'", value));
  }
  return value == "mmap" ? npf::core::IoKind::Mmap : npf::core::IoKind::AfPacket;
}

npf::core::RunMode parse_mode(std::string_view value) {
  if (value != "rtc" && value != "pipeline") {
    throw UsageError(std::format("--mode is rtc or pipeline, not '{}'", value));
  }
  return value == "rtc" ? npf::core::RunMode::Rtc : npf::core::RunMode::Pipeline;
}

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
  } else if (flag.name == "--workers" && o.command == "run") {
    o.workers = parse_count(flag.value, "--workers");
  } else if (flag.name == "--io" && o.command == "run") {
    o.io = parse_io(flag.value);
  } else if (flag.name == "--mode" && o.command == "run") {
    o.mode = parse_mode(flag.value);
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
    if (args.size() < 2 || (args[1] != "stats" && args[1] != "mac" && args[1] != "arp")) {
      throw UsageError("show what? npf show stats, npf show mac, or npf show arp");
    }
    o.what = args[1];
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

// Buffers free and buffers in all, over every pool.
struct PoolUse {
  std::size_t available{0};
  std::size_t capacity{0};
};

// Every counter, by name, in one fixed order: the drop reasons in DropReason's, then only the IP
// protocols seen, by number.
// kernel_drops: npf run's, the frames the kernel dropped before a socket was read
// (PACKET_STATISTICS); none for a replay.
CounterList counter_list(const npf::stat::Counters& c, PoolUse pool,
                         std::optional<std::uint64_t> kernel_drops = std::nullopt) {
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
  out.emplace_back("pool_available", pool.available);
  out.emplace_back("pool_capacity", pool.capacity);
  if (kernel_drops) {
    out.emplace_back("kernel_rx_drops", *kernel_drops);
  }
  return out;
}

// One "name value" pair per line, so a script can pick out any counter with awk.
std::string counter_table(const npf::stat::Counters& c, PoolUse pool,
                          std::optional<std::uint64_t> kernel_drops = std::nullopt) {
  std::string out;
  for (const auto& [name, value] : counter_list(c, pool, kernel_drops)) {
    out += std::format("{:<18}{}\n", name, value);
  }
  return out;
}

// The same, as one JSON object: a "name": value pair per line, in the same order.
std::string counter_json(const npf::stat::Counters& c, PoolUse pool) {
  std::string out = "{";
  std::string_view separator = "\n";
  for (const auto& [name, value] : counter_list(c, pool)) {
    out += std::format("{}  \"{}\": {}", separator, name, value);
    separator = ",\n";
  }
  return out + "\n}\n";
}

// The MAC table, a station a line, by port and then MAC: what `npf show mac` prints. Lines
// starting with '#' are notes, not stations.
std::string mac_table_text(const npf::table::MacTable& macs, npf::core::Clock::time_point now) {
  std::vector<npf::table::MacTable::Station> stations = macs.list();
  std::ranges::sort(stations, {}, [](const npf::table::MacTable::Station& s) {
    return std::pair{s.port, s.mac.b};
  });
  std::string out = std::format("# {:<17} {:>5} {:>8}\n", "mac", "port", "age (s)");
  for (const npf::table::MacTable::Station& s : stations) {
    out += std::format("{:<19} {:>5} {:>8}\n", format_mac(s.mac), s.port,
                       std::chrono::duration_cast<std::chrono::seconds>(now - s.last_seen).count());
  }
  out += std::format("# {} of {} entries; a station is forgotten {} s after it last sent\n",
                     stations.size(), macs.capacity(), macs.max_age().count());
  return out;
}

// The ARP cache, a neighbour a line, by address: what `npf show arp` prints.
std::string arp_cache_text(const npf::table::ArpCache& arp) {
  std::vector<std::pair<std::uint32_t, npf::table::ArpNeighbour>> entries = arp.list();
  std::ranges::sort(entries, {}, [](const auto& e) { return e.first; });
  const auto state = [](const npf::table::ArpNeighbour& n) -> std::string_view {
    if (n.is_static) {
      return "static";
    }
    switch (n.state) {
      case npf::table::ArpState::Incomplete:
        return "incomplete";
      case npf::table::ArpState::Reachable:
        return "reachable";
      case npf::table::ArpState::Stale:
        return "stale";
    }
    return "?";
  };
  std::string out = std::format("# {:<15} {:<17} {:>5} {:<10} {}\n", "address", "mac", "port",
                                "state", "waiting");
  for (const auto& [ip, n] : entries) {
    const bool incomplete = !n.is_static && n.state == npf::table::ArpState::Incomplete;
    out += std::format("{:<17} {:<17} {:>5} {:<10} {}\n", format_ipv4(ip),
                       incomplete ? "-" : format_mac(n.mac), n.port, state(n), n.queued);
  }
  return out;
}

// What `npf show` asks of the running `npf run`: the signal that asks, and the file that the answer
// is written to. The MAC table and the ARP cache go next to the stats file, as <name>.mac and
// <name>.arp.
struct ShowRequest {
  int signal;
  std::filesystem::path file;
};

ShowRequest show_request(std::string_view what, const std::filesystem::path& stats_file) {
  if (what == "mac") {
    return {SIGRTMIN, std::filesystem::path{stats_file}.replace_extension(".mac")};
  }
  if (what == "arp") {
    return {SIGRTMIN + 1, std::filesystem::path{stats_file}.replace_extension(".arp")};
  }
  return {SIGUSR1, stats_file};
}

// Written aside and renamed into place, so `npf show` never reads half a table.
void write_snapshot(const std::filesystem::path& path, const std::string& table) {
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

// --- the router ----------------------------------------------------------------------------------

using npf::pipe::Worker;

// What this phase can run. The parser accepts more, for the phases that will implement it. io is
// what the command reads and writes through: pcap for npf replay, live interfaces for npf run.
void require_supported(const npf::core::Config& cfg, npf::core::IoKind io) {
  if (cfg.interfaces.empty()) {
    throw std::runtime_error("the configuration has no interfaces");
  }
  if (io == npf::core::IoKind::Pcap && cfg.io != npf::core::IoKind::Pcap) {
    throw std::runtime_error("npf replay needs 'io pcap' in the configuration");
  }
  if (io != npf::core::IoKind::Pcap && cfg.io != npf::core::IoKind::AfPacket &&
      cfg.io != npf::core::IoKind::Mmap) {
    throw std::runtime_error(
        "npf run needs 'io af_packet' or 'io mmap': io xdp is not implemented yet, and io pcap is "
        "for npf replay");
  }
  if (cfg.fib != npf::core::FibKind::Linear) {
    throw std::runtime_error("only 'fib linear' is implemented so far");
  }
  if (cfg.arp.size() > npf::pipe::kArpCapacity) {
    throw std::runtime_error(std::format("at most {} arp entries", npf::pipe::kArpCapacity));
  }
  if (io == npf::core::IoKind::Pcap) {
    if (cfg.mode != npf::core::RunMode::Rtc || cfg.workers != 1) {
      throw std::runtime_error(
          "npf replay runs one worker on one thread, to be deterministic: it needs 'mode rtc' "
          "and 'workers 1'");
    }
    return;
  }
  if (cfg.workers > npf::pipe::kMaxWorkers) {
    throw std::runtime_error(std::format("at most {} workers", npf::pipe::kMaxWorkers));
  }
  if (cfg.mode == npf::core::RunMode::Pipeline) {
    if (!std::has_single_bit(cfg.workers)) {
      throw std::runtime_error(
          "pipeline mode picks a worker by hash & (workers - 1), so workers must be a power of "
          "two");
    }
    if (cfg.pool_size > npf::pipe::kReturnRingSize) {
      throw std::runtime_error(
          std::format("pipeline mode allows a pool_size of at most {}, the packets a ring home "
                      "to an RX thread can hold",
                      npf::pipe::kReturnRingSize));
    }
  }
  const bool bridged = std::ranges::any_of(
      cfg.interfaces, [](const auto& i) { return i.mode == npf::PortMode::Bridged; });
  if (bridged && cfg.workers != 1) {
    throw std::runtime_error(
        "bridged ports need 'workers 1': each worker has a MAC table of its own, and would learn "
        "only the stations whose frames the kernel happens to hand it");
  }
}

// The configuration file, with the command line's --io, --mode and --workers in place of its own.
npf::core::Config load_config_for(const Options& o, npf::core::IoKind io) {
  npf::core::ParseResult parsed = npf::core::load_config(o.config);  // io: replay's pcap or run's
  if (!parsed.value) {
    throw std::runtime_error(std::format("{}: {}", o.config.string(), parsed.error));
  }
  npf::core::Config cfg = std::move(*parsed.value);
  if (o.mode) {
    cfg.mode = *o.mode;
  }
  if (o.workers) {
    cfg.workers = *o.workers;
  }
  if (o.io) {
    cfg.io = *o.io;
  }
  require_supported(cfg, io);
  return cfg;
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

// Whether each port's link was up when the backend opened it, by port id.
std::vector<bool> link_states(const npf::io::IoBackend& backend) {
  std::vector<bool> up;
  for (const npf::io::PortInfo& port : backend.ports()) {
    up.push_back(port.up);
  }
  return up;
}

// What every worker shares, and only reads once the workers run: the FIB and the packet filter.
struct SharedTables {
  SharedTables(const npf::core::Config& cfg, const npf::core::FilterConfig& rules)
      : filter(rules.rules, rules.policy) {
    for (const npf::table::Route& r : cfg.routes) {
      if (!fib.add(r)) {
        throw std::runtime_error("the FIB refused a route the parser accepted");
      }
    }
  }
  npf::table::LinearLpm fib;
  npf::pipe::Filter filter;
};

// Every thread's counters summed, and every pool's buffers.
struct Totals {
  npf::stat::Counters counters;
  PoolUse pools;
  std::optional<std::uint64_t> kernel_rx_drops;
};

// The sockets a lane opens: AF_PACKET's or PACKET_MMAP's. sockets_per_port: how many sockets of
// this kind share each port, which PACKET_MMAP splits its RX ring between.
template <class Socket>
std::unique_ptr<Socket> open_sockets(const npf::core::Config& cfg, PacketPool& pool,
                                     const npf::io::AfPacketOptions& options,
                                     std::size_t sockets_per_port) {
  if constexpr (std::is_same_v<Socket, npf::io::PacketMmapBackend>) {
    return std::make_unique<Socket>(cfg.interfaces, pool, options,
                                    npf::io::MmapRingSizes::shared_by(sockets_per_port));
  } else {
    return std::make_unique<Socket>(cfg.interfaces, pool, options);
  }
}

// One worker and what it owns besides its tables: its pool, the recycler over it, and its backend
// -- its own sockets in run-to-completion mode, the rings and its transmit-only sockets in
// pipeline mode.
template <class Socket>
struct LaneOf {
  std::unique_ptr<PacketPool> pool;
  std::unique_ptr<npf::pipe::Recycler> recycler;
  std::unique_ptr<Socket> sockets;
  std::unique_ptr<npf::pipe::Doorbell> bell;              // pipeline mode
  std::unique_ptr<npf::pipe::RingBackend<Socket>> rings;  // pipeline mode
  std::unique_ptr<Worker> worker;
};

// One pipeline RX thread's: its pool, its socket on its port, and the stage that steers.
template <class Socket>
struct RxLaneOf {
  std::unique_ptr<PacketPool> pool;
  std::unique_ptr<Socket> sockets;
  std::unique_ptr<npf::pipe::RxStage> stage;
};

// Lets the threads go again however the caller leaves the scope that parked them.
class ResumeOnExit {
 public:
  explicit ResumeOnExit(npf::pipe::Rendezvous& rv) : rv_{&rv} {}
  ResumeOnExit(const ResumeOnExit&) = delete;
  ResumeOnExit(ResumeOnExit&&) = delete;
  ResumeOnExit& operator=(const ResumeOnExit&) = delete;
  ResumeOnExit& operator=(ResumeOnExit&&) = delete;
  ~ResumeOnExit() { rv_->resume_all(); }

 private:
  npf::pipe::Rendezvous* rv_;
};

// npf run's threads, in either model (ARCHITECTURE.md §12), and the control thread's hold on them,
// over either socket backend. Built whole by the constructor; start() lets the threads go, and
// stop() joins them.
template <class Socket>
class Engine {
  using Lane = LaneOf<Socket>;
  using RxLane = RxLaneOf<Socket>;

 public:
  Engine(npf::core::Config cfg, const npf::core::FilterConfig& rules, bool busy_poll)
      : cfg_{std::move(cfg)}, busy_poll_{busy_poll} {
    if (cfg_.mode == npf::core::RunMode::Rtc) {
      build_rtc(rules);
    } else {
      build_pipeline(rules);
    }
    if (lanes_.size() > 1) {
      std::vector<Worker*> workers;
      workers.reserve(lanes_.size());
      for (const Lane& lane : lanes_) {
        workers.push_back(lane.worker.get());
      }
      news_ = std::make_unique<npf::pipe::NewsRings>(workers.size());
      news_->connect(workers);
    }
    rendezvous_ = std::make_unique<npf::pipe::Rendezvous>(lanes_.size() + rx_lanes_.size());
  }
  Engine(const Engine&) = delete;
  Engine(Engine&&) = delete;
  Engine& operator=(const Engine&) = delete;
  Engine& operator=(Engine&&) = delete;
  ~Engine() { stop(); }

  // Starts every thread. Signals must already be blocked, so that the threads inherit the mask
  // and every signal reaches the control thread's signalfd.
  void start() {
    for (Lane& lane : lanes_) {
      threads_.emplace_back([this, &lane] { run_worker(lane); });
    }
    for (RxLane& lane : rx_lanes_) {
      threads_.emplace_back([this, &lane] { run_rx(lane); });
    }
  }

  // Ends every thread, then lets go of every packet still held: those waiting on ARP, and in
  // pipeline mode those in rings. Only this thread is left to touch anything.
  void stop() noexcept {
    if (threads_.empty()) {
      return;
    }
    rendezvous_->stop_all();
    threads_.clear();  // joins
    for (Lane& lane : lanes_) {
      lane.worker->arp().flush();  // dropped now, and so counted
    }
    for (RxLane& lane : rx_lanes_) {
      lane.stage->reclaim();
    }
  }

  // Runs f with every thread parked between bursts, so it may read or change what they own.
  template <class F>
  auto parked(F f) {
    if (threads_.empty()) {
      return f();
    }
    rendezvous_->park_all();
    const ResumeOnExit resume{*rendezvous_};
    return f();
  }

  // Callers hold the threads parked, or have stopped them. Not const: reading the kernel's drop
  // counts resets them, so the backends keep the totals.
  [[nodiscard]] Totals totals() {
    Totals t;
    t.kernel_rx_drops = 0;
    for (Lane& lane : lanes_) {
      *t.kernel_rx_drops +=
          cfg_.mode == npf::core::RunMode::Rtc ? lane.sockets->kernel_rx_drops() : 0;
    }
    for (RxLane& lane : rx_lanes_) {
      *t.kernel_rx_drops += lane.sockets->kernel_rx_drops();
    }
    for (const Lane& lane : lanes_) {
      t.counters.merge(lane.worker->stats());
      t.pools.available += lane.pool->available();
      t.pools.capacity += lane.pool->capacity();
    }
    for (const RxLane& lane : rx_lanes_) {
      t.counters.merge(lane.stage->stats());
      t.pools.available += lane.pool->available();
      t.pools.capacity += lane.pool->capacity();
    }
    return t;
  }

  [[nodiscard]] std::string mac_tables(npf::core::Clock::time_point now) const {
    return per_worker([now](const Worker& w) { return mac_table_text(w.macs(), now); });
  }
  [[nodiscard]] std::string arp_caches() {
    return per_worker([](Worker& w) { return arp_cache_text(w.arp()); });
  }
  // Returns how many entries each cache kept: its static ones.
  std::size_t flush_arp() {
    for (Lane& lane : lanes_) {
      lane.worker->arp().flush();
    }
    return lanes_.front().worker->arp().size();
  }

  [[nodiscard]] std::uint64_t rx_oversized() const {
    std::uint64_t n = 0;
    for (const Lane& lane : lanes_) {
      n += cfg_.mode == npf::core::RunMode::Rtc ? lane.sockets->rx_oversized() : 0;
    }
    for (const RxLane& lane : rx_lanes_) {
      n += lane.sockets->rx_oversized();
    }
    return n;
  }

  [[nodiscard]] std::size_t ports() const noexcept { return cfg_.interfaces.size(); }
  [[nodiscard]] std::size_t workers() const noexcept { return lanes_.size(); }
  [[nodiscard]] std::size_t rx_threads() const noexcept { return rx_lanes_.size(); }

 private:
  // N workers, each with its own sockets, all in the ports' fanout groups. The first backend
  // makes the groups and reads the MACs, and the others join.
  void build_rtc(const npf::core::FilterConfig& rules) {
    for (std::size_t w = 0; w < cfg_.workers; ++w) {
      Lane& lane = lanes_.emplace_back();
      lane.pool = std::make_unique<PacketPool>(cfg_.pool_size);
      npf::io::AfPacketOptions options;
      options.fanout = true;
      options.quiet = w != 0;
      if (w != 0) {
        options.fanout_groups = lanes_.front().sockets->fanout_groups();
      }
      lane.sockets = open_sockets<Socket>(cfg_, *lane.pool, options, cfg_.workers);
      if (w == 0) {
        take_macs(*lane.sockets, cfg_);
        shared_ = std::make_unique<SharedTables>(cfg_, rules);
      }
    }
    const auto flood_sets = npf::pipe::make_flood_sets(npf::pipe::make_port_table(cfg_),
                                                       link_states(*lanes_.front().sockets));
    for (Lane& lane : lanes_) {
      lane.recycler = std::make_unique<npf::pipe::Recycler>(*lane.pool);
      lane.worker = std::make_unique<Worker>(cfg_, shared_->fib, shared_->filter, *lane.sockets,
                                             *lane.recycler, flood_sets);
    }
  }

  // One RX thread per port, each receiving on its port only, and N workers, each transmitting
  // through sockets that receive nothing.
  void build_pipeline(const npf::core::FilterConfig& rules) {
    const std::size_t n_ports = cfg_.interfaces.size();
    for (std::size_t k = 0; k < n_ports; ++k) {
      RxLane& lane = rx_lanes_.emplace_back();
      lane.pool = std::make_unique<PacketPool>(cfg_.pool_size);
      npf::io::AfPacketOptions options;
      options.receive.assign(n_ports, false);
      options.receive[k] = true;
      options.quiet = k != 0;
      lane.sockets = open_sockets<Socket>(cfg_, *lane.pool, options, 1);
    }
    take_macs(*rx_lanes_.front().sockets, cfg_);
    shared_ = std::make_unique<SharedTables>(cfg_, rules);
    rings_ = std::make_unique<npf::pipe::PipelineRings>(n_ports, cfg_.workers);
    const auto flood_sets = npf::pipe::make_flood_sets(npf::pipe::make_port_table(cfg_),
                                                       link_states(*rx_lanes_.front().sockets));
    std::vector<npf::pipe::Doorbell*> bells;
    for (std::size_t w = 0; w < cfg_.workers; ++w) {
      Lane& lane = lanes_.emplace_back();
      lane.pool = std::make_unique<PacketPool>(cfg_.pool_size);
      npf::io::AfPacketOptions transmit_only;
      transmit_only.receive.assign(n_ports, false);
      transmit_only.quiet = true;
      lane.sockets = open_sockets<Socket>(cfg_, *lane.pool, transmit_only, 1);
      lane.recycler = std::make_unique<npf::pipe::Recycler>(*lane.pool);
      std::vector<npf::pipe::PacketRing*> in;
      for (std::size_t k = 0; k < n_ports; ++k) {
        lane.recycler->add_home(*rx_lanes_[k].pool, rings_->home(w, k));
        in.push_back(&rings_->to_worker(k, w));
      }
      lane.bell = std::make_unique<npf::pipe::Doorbell>();
      bells.push_back(lane.bell.get());
      lane.rings = std::make_unique<npf::pipe::RingBackend<Socket>>(std::move(in), *lane.sockets,
                                                                    *lane.recycler, *lane.bell);
      lane.worker = std::make_unique<Worker>(cfg_, shared_->fib, shared_->filter, *lane.rings,
                                             *lane.recycler, flood_sets);
    }
    for (std::size_t k = 0; k < n_ports; ++k) {
      RxLane& lane = rx_lanes_[k];
      lane.stage = std::make_unique<npf::pipe::RxStage>(*lane.sockets, *lane.pool, *rings_, k,
                                                        bells, cfg_.burst);
    }
  }

  void run_worker(Lane& lane) noexcept {
    Worker& worker = *lane.worker;
    const auto burst = [&worker] { return worker.run_one_burst(npf::core::Clock::now()); };
    if (lane.rings) {
      npf::pipe::RingBackend<Socket>& rings = *lane.rings;
      std::array<pollfd, 2> fds{
          {{rings.bell().fd(), POLLIN, 0}, {rendezvous_->wake_fd(), POLLIN, 0}}};
      npf::pipe::serve_loop(*rendezvous_, burst, [this, &rings, &fds] {
        if (busy_poll_) {
          return;
        }
        if (rings.arm_and_check_empty()) {
          ::poll(fds.data(), fds.size(), kPollTimeoutMs);
        }
        rings.bell().disarm();
      });
      return;
    }
    run_polling(lane.sockets->fds(), burst);
  }

  void run_rx(RxLane& lane) noexcept {
    npf::pipe::RxStage& stage = *lane.stage;
    run_polling(lane.sockets->fds(), [&stage] { return stage.run_once(); });
  }

  // A thread whose work arrives on sockets: when a burst finds nothing, it sleeps in poll() until
  // one is readable, the rendezvous wakes it, or kPollTimeoutMs passes -- the timers run at least
  // that often.
  template <class Burst>
  void run_polling(const std::vector<int>& sockets, Burst burst) noexcept {
    std::vector<pollfd> fds;
    fds.reserve(sockets.size() + 1);
    for (const int fd : sockets) {
      fds.push_back({fd, POLLIN, 0});
    }
    fds.push_back({rendezvous_->wake_fd(), POLLIN, 0});
    const int timeout_ms = busy_poll_ ? 0 : kPollTimeoutMs;
    npf::pipe::serve_loop(*rendezvous_, burst,
                          [&fds, timeout_ms] { ::poll(fds.data(), fds.size(), timeout_ms); });
  }

  // The text f makes of each worker, under a heading per worker when there are several.
  template <class F>
  [[nodiscard]] std::string per_worker(F f) const {
    if (lanes_.size() == 1) {
      return f(*lanes_.front().worker);
    }
    std::string out;
    for (std::size_t w = 0; w < lanes_.size(); ++w) {
      out += std::format("# worker {}\n", w);
      out += f(*lanes_[w].worker);
    }
    return out;
  }

  npf::core::Config cfg_;
  bool busy_poll_;
  std::unique_ptr<SharedTables> shared_;
  std::unique_ptr<npf::pipe::PipelineRings> rings_;
  std::vector<RxLane> rx_lanes_;
  std::vector<Lane> lanes_;
  std::unique_ptr<npf::pipe::NewsRings> news_;
  std::unique_ptr<npf::pipe::Rendezvous> rendezvous_;
  std::vector<std::jthread> threads_;  // last: joined before anything they use is destroyed
};

void report(const Totals& t, const std::filesystem::path& stats_file) {
  const std::string table = counter_table(t.counters, t.pools, t.kernel_rx_drops);
  print(table);
  write_snapshot(stats_file, table);
}

// One signal, answered: SIGUSR1 with the counters, SIGRTMIN with the MAC tables and SIGRTMIN+1
// with the ARP caches, all read with the threads parked, and SIGUSR2 by flushing the ARP caches.
// False for SIGINT and SIGTERM: time to stop.
template <class Engine>
bool answer(int sig, const Options& o, Engine& engine) {
  if (sig == SIGUSR1) {
    report(engine.parked([&engine] { return engine.totals(); }), o.stats_file);
  } else if (sig == SIGRTMIN) {
    write_snapshot(show_request("mac", o.stats_file).file,
                   engine.parked([&engine] { return engine.mac_tables(npf::core::Clock::now()); }));
  } else if (sig == SIGRTMIN + 1) {
    write_snapshot(show_request("arp", o.stats_file).file,
                   engine.parked([&engine] { return engine.arp_caches(); }));
  } else if (sig == SIGUSR2) {
    const std::size_t kept = engine.parked([&engine] { return engine.flush_arp(); });
    npf::core::log_info("ARP cache flushed; {} static entries kept", kept);
  } else {
    return false;
  }
  return true;
}

// The control thread: lets the workers go, then answers signals, with a stats line every
// kStatsPeriod, until SIGINT or SIGTERM. Stops the workers on the way out.
template <class Engine>
void serve(const Options& o, Engine& engine) {
  const SignalFd signals{SIGINT, SIGTERM, SIGUSR1, SIGUSR2, SIGRTMIN, SIGRTMIN + 1};
  const Pidfile pidfile(o.pidfile);
  engine.start();  // after the mask: every thread inherits it, so signals come only to this one
  npf::core::log_info("forwarding on {} ports: {} worker{}{}{}; Ctrl-C to stop", engine.ports(),
                      engine.workers(), engine.workers() == 1 ? "" : "s",
                      engine.rx_threads() == 0
                          ? ", run to completion"
                          : std::format(" fed by {} RX thread{}", engine.rx_threads(),
                                        engine.rx_threads() == 1 ? "" : "s"),
                      o.busy_poll ? ", busy-polling" : "");
  pollfd fd{signals.fd(), POLLIN, 0};
  const auto start = npf::core::Clock::now();
  auto next_report = start + kStatsPeriod;
  for (bool running = true; running;) {
    const auto wait =
        std::chrono::ceil<std::chrono::milliseconds>(next_report - npf::core::Clock::now());
    if (::poll(&fd, 1, static_cast<int>(std::max<std::int64_t>(wait.count(), 0))) < 0 &&
        errno != EINTR) {
      throw_errno("poll");
    }
    for (std::optional<int> sig = signals.next(); sig && running; sig = signals.next()) {
      running = answer(*sig, o, engine);
    }
    const auto now = npf::core::Clock::now();
    if (now >= next_report) {
      next_report += kStatsPeriod;
      const Totals t = engine.parked([&engine] { return engine.totals(); });
      const npf::stat::Counters& c = t.counters;
      print(std::format(
          "npf: {:>6}s  rx {}  forwarded {}  flooded {}  to_host {}  dropped {}  tx {}  pool "
          "{}/{}\n",
          std::chrono::duration_cast<std::chrono::seconds>(now - start).count(), c.rx_packets,
          c.forwarded, c.flooded, c.to_host, c.total_drops(), c.tx_packets, t.pools.available,
          t.pools.capacity));
    }
  }
  engine.stop();
}

template <class Socket>
int run_engine(const Options& o, npf::core::Config cfg, const npf::core::FilterConfig& rules) {
  Engine<Socket> engine(std::move(cfg), rules, o.busy_poll);

  serve(o, engine);

  print("npf: stopped; final counters:\n");
  report(engine.totals(), o.stats_file);
  if (engine.rx_oversized() != 0) {
    npf::core::log_warn("{} frames were too big for a buffer and never reached the pipeline",
                        engine.rx_oversized());
  }
  return 0;
}

int run(const Options& o) {
  npf::core::Config cfg = load_config_for(o, npf::core::IoKind::AfPacket);
  const npf::core::FilterConfig rules = load_filter_for(cfg, o.config);
  if (!cfg.filter.empty()) {
    npf::core::log_info("packet filter: {} rules from {}, policy {}", rules.rules.size(),
                        npf::core::filter_path(cfg, o.config).string(),
                        rules.policy == npf::pipe::Action::Allow ? "allow" : "deny");
  }
  if (cfg.io == npf::core::IoKind::Mmap) {
    return run_engine<npf::io::PacketMmapBackend>(o, std::move(cfg), rules);
  }
  return run_engine<npf::io::AfPacketBackend>(o, std::move(cfg), rules);
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
  npf::core::Config cfg = load_config_for(o, npf::core::IoKind::Pcap);
  const npf::core::FilterConfig rules = load_filter_for(cfg, o.config);
  PacketPool pool(cfg.pool_size);
  npf::io::PcapFileBackend backend({.in = in, .out = out}, cfg.interfaces, pool);
  take_macs(backend, cfg);
  SharedTables shared(cfg, rules);
  npf::pipe::Recycler recycler(pool);
  Worker worker(cfg, shared.fib, shared.filter, backend, recycler,
                npf::pipe::make_flood_sets(npf::pipe::make_port_table(cfg), link_states(backend)));

  while (!backend.done()) {
    const std::size_t read = backend.records_read();
    worker.run_one_burst(kReplayTime);
    // Between bursts only the ARP cache holds buffers, and a replay never answers its requests.
    if (backend.records_read() == read) {
      throw std::runtime_error(std::format(
          "all {} packet buffers are waiting on ARP, which a replay never answers, and frames "
          "are left to read: give the neighbours arp lines, or raise pool_size",
          cfg.pool_size));
    }
  }
  worker.arp().flush();  // packets still waiting on ARP are dropped now, and so counted
  backend.tx_flush();
  if (!backend.ok()) {
    throw std::runtime_error("cannot write " + out.string());
  }
  if (!o.stats_json.empty()) {
    write_text(o.stats_json, counter_json(worker.stats(), {pool.available(), pool.capacity()}));
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
  const ShowRequest request = show_request(o.what, o.stats_file);
  const std::optional<std::filesystem::file_time_type> before = modified(request.file);
  if (::kill(*pid, request.signal) != 0) {
    throw_errno(std::format("cannot signal npf (pid {})", *pid));
  }
  // It answers between two bursts, so within milliseconds unless it is wedged.
  const auto deadline = npf::core::Clock::now() + kShowTimeout;
  while (npf::core::Clock::now() < deadline) {
    if (const auto now = modified(request.file); now && now != before) {
      std::ifstream in(request.file);
      std::ostringstream text;
      text << in.rdbuf();
      print(text.str());
      return 0;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{10});
  }
  throw std::runtime_error(std::format("npf (pid {}) did not update {} within {} s", *pid,
                                       request.file.string(), kShowTimeout.count()));
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
