// Tier A (CLAUDE.md §9): the forwarding logic itself, in process, with no I/O at all
// (docs/BUILD_PLAN.md phase 14). docs/performance.md says how it is run and what it does and does
// not measure.
//
// 1024 UDP frames are built once, in a pool, and walked in bursts of 32, kNumFlows flows between
// them. Every benchmark's iteration is one burst, so its time per iteration is per 32 packets;
// the `packets` counter says so, and `cycles_per_packet` divides the CPU's own cycle count -- read
// through perf_event_open, user space only -- by the packets in the run.
//
//   parse_only                     EthView, Ipv4View and parse_l4 on each packet
//   parse_only/refilled            the same, with the frames refilled after every lap, as
//                                  full_datapath must: the difference is what the pause leaves
//                                  in the timings
//   parse_and_lookup/<fib>/<size>  the same, plus a FIB lookup of the destination
//   full_datapath/<fib>/<size>     the real Forwarder::process_burst: all fourteen steps,
//                                  rewrite and incremental checksum included
//   full_datapath/dir24_8/topology/burst:<n>
//                                  [phase 15] the same with bursts of 1 to 64; `packets` says n
//
// <fib> is linear, binary_trie, patricia or dir24_8. <size> is `topology`, the three routes of
// configs/router.conf, or `100k`, those plus the 100,000-route sample of the RouteViews table,
// every route sent to the server, which has a static ARP entry; with that table each frame's
// destination is drawn from a prefix of the table. LinearLpm, the oracle, runs at `topology`
// only, as in bench_lpm.
//
// process() rewrites each frame it forwards -- the server's MAC as destination, so a frame sent
// round again would be dropped as not the router's -- so full_datapath copies every frame back
// from its pristine template after each lap of the 1024, with the timer and the cycle counter
// stopped: one pause per 32 bursts. It checks, before timing and again after, that every frame of
// a lap is forwarded. The parse benchmarks change nothing, and never pause.

#include <benchmark/benchmark.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <format>
#include <memory>
#include <npf/core/byte_span.hpp>
#include <npf/core/config.hpp>
#include <npf/core/packet.hpp>
#include <npf/core/pool.hpp>
#include <npf/pipe/decision.hpp>
#include <npf/pipe/filter.hpp>
#include <npf/pipe/forward.hpp>
#include <npf/proto/checksum.hpp>
#include <npf/proto/ethernet.hpp>
#include <npf/proto/ipv4.hpp>
#include <npf/proto/l4.hpp>
#include <npf/proto/mac.hpp>
#include <npf/stat/counters.hpp>
#include <npf/table/arp_cache.hpp>
#include <npf/table/fib.hpp>
#include <npf/table/lpm_dir24_8.hpp>
#include <npf/table/lpm_linear.hpp>
#include <npf/table/lpm_patricia.hpp>
#include <npf/table/lpm_trie.hpp>
#include <npf/table/mac_table.hpp>
#include <random>
#include <span>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

#include "bgp_routes.hpp"
#include "spread.hpp"

namespace {

using npf::bench::with_spread;
using npf::core::Packet;
using npf::proto::MacAddr;
using npf::table::Route;

constexpr std::size_t kFrames = 1024;
constexpr std::size_t kBurst = 32;
constexpr std::size_t kNumFlows = 16;
constexpr std::uint32_t kSeed = 20261014;

constexpr MacAddr kPort0Mac{{0x02, 0x00, 0x00, 0x00, 0x01, 0x01}};
constexpr MacAddr kPort1Mac{{0x02, 0x00, 0x00, 0x00, 0x02, 0x01}};
constexpr MacAddr kClientMac{{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01}};
constexpr MacAddr kServerMac{{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02}};
constexpr std::uint32_t kPort0Ip = 0x0A000101;  // 10.0.1.1
constexpr std::uint32_t kPort1Ip = 0x0A000201;  // 10.0.2.1
constexpr std::uint32_t kClient = 0x0A000102;   // 10.0.1.2
constexpr std::uint32_t kServer = 0x0A000202;   // 10.0.2.2

// --- cycles --------------------------------------------------------------------------------------

// The CPU's cycle counter for this thread, user space only, through perf_event_open: what
// `perf stat -e cycles:u` reads. Unavailable on a machine without the counters, or where
// kernel.perf_event_paranoid forbids them; then nothing is reported.
class CycleCounter {
 public:
  CycleCounter() {
    perf_event_attr attr{};
    attr.type = PERF_TYPE_HARDWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_HW_CPU_CYCLES;
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    fd_ = static_cast<int>(::syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0));
  }
  CycleCounter(const CycleCounter&) = delete;
  CycleCounter& operator=(const CycleCounter&) = delete;
  CycleCounter(CycleCounter&&) = delete;
  CycleCounter& operator=(CycleCounter&&) = delete;
  ~CycleCounter() {
    if (fd_ >= 0) {
      ::close(fd_);
    }
  }

  [[nodiscard]] bool available() const { return fd_ >= 0; }
  void start() const {
    if (fd_ >= 0) {
      ::ioctl(fd_, PERF_EVENT_IOC_RESET, 0);
      ::ioctl(fd_, PERF_EVENT_IOC_ENABLE, 0);
    }
  }
  void pause() const {
    if (fd_ >= 0) {
      ::ioctl(fd_, PERF_EVENT_IOC_DISABLE, 0);
    }
  }
  void resume() const {
    if (fd_ >= 0) {
      ::ioctl(fd_, PERF_EVENT_IOC_ENABLE, 0);
    }
  }
  [[nodiscard]] std::uint64_t read() const {
    std::uint64_t n = 0;
    if (fd_ >= 0 && ::read(fd_, &n, sizeof(n)) != static_cast<ssize_t>(sizeof(n))) {
      n = 0;
    }
    return n;
  }

 private:
  int fd_{-1};
};

bool cycles_available() {
  static const bool available = CycleCounter{}.available();
  return available;
}

// --- the frames ----------------------------------------------------------------------------------

// A 70-byte frame, as bench/system/gen sends: client to dst, UDP from port 10000 + flow to 5001,
// 28 bytes of payload, TTL 255.
std::vector<std::byte> udp_frame(std::uint32_t dst, std::size_t flow) {
  using npf::core::wr_be16;
  using npf::core::wr_be32;
  using npf::core::wr_u8;
  std::vector<std::byte> f(14 + 20 + 8 + 28);
  npf::proto::wr_mac(f, 0, kPort0Mac);
  npf::proto::wr_mac(f, 6, kClientMac);
  wr_be16(f, 12, npf::proto::kEtherTypeIpv4);
  const std::span<std::byte> ip = std::span(f).subspan(14, 20);
  wr_u8(ip, 0, 0x45);
  wr_be16(ip, 2, static_cast<std::uint16_t>(f.size() - 14));
  wr_u8(ip, 8, 64);
  wr_u8(ip, 9, npf::proto::kIpProtoUdp);
  wr_be32(ip, 12, kClient);
  wr_be32(ip, 16, dst);
  wr_be16(ip, 10, npf::proto::ipv4_header_checksum(ip));
  const std::span<std::byte> udp = std::span(f).subspan(34);
  wr_be16(udp, 0, static_cast<std::uint16_t>(10000 + flow));
  wr_be16(udp, 2, 5001);
  wr_be16(udp, 4, static_cast<std::uint16_t>(udp.size()));
  return f;
}

// One table size: its routes, and the destination of each of the kFrames frames.
struct Workload {
  std::string name;
  std::vector<Route> routes;
  std::vector<std::uint32_t> destinations;
};

// The three routes of configs/router.conf, every frame to the server.
Workload topology() {
  Workload w;
  w.name = "topology";
  w.routes = {{{0x0A000100, 24}, 0, 0}, {{0x0A000200, 24}, 0, 1}, {{0, 0}, 0x0A0002FE, 1}};
  w.destinations.assign(kFrames, kServer);
  return w;
}

// Those, plus the 100k sample with every route's next hop the server. Each destination is drawn
// uniformly from a prefix of the sample, drawn uniformly, outside 10/8, where the topology's own
// directly connected routes would want ARP for it.
Workload sample_100k() {
  Workload w;
  w.name = "100k";
  w.routes = npf::bench::load_routes(npf::bench::bgp_data_dir() / "bgp_prefixes_100k.txt");
  for (Route& r : w.routes) {
    r.next_hop = kServer;
    r.out_port = 1;
  }
  const Workload top = topology();
  w.routes.insert(w.routes.end(), top.routes.begin(), top.routes.end());
  std::mt19937 rng(kSeed);
  while (w.destinations.size() < kFrames) {
    const Route& r = w.routes[rng() % (w.routes.size() - top.routes.size())];
    const std::uint32_t dst = r.prefix.addr | (static_cast<std::uint32_t>(rng()) &
                                               ~npf::table::prefix_mask(r.prefix.len));
    if ((dst >> 24U) != 10 && (dst >> 24U) != 0 && (dst >> 24U) < 224 && (dst & 0xFFU) != 0xFFU) {
      w.destinations.push_back(dst);
    }
  }
  return w;
}

// The frames in a pool, and their pristine copies to refill them from.
class Frames {
 public:
  explicit Frames(std::span<const std::uint32_t> destinations) : pool_(kFrames) {
    for (std::size_t i = 0; i < kFrames; ++i) {
      templates_.push_back(udp_frame(destinations[i], i % kNumFlows));
      packets_.push_back(pool_.acquire());
    }
    refill();
  }

  void refill() {
    for (std::size_t i = 0; i < kFrames; ++i) {
      Packet& p = *packets_[i];
      p.resize(templates_[i].size());
      std::ranges::copy(templates_[i], p.data().begin());
      p.set_in_port(0);
    }
  }

  // The i-th burst of n frames: n divides kFrames, so bursts never straddle the end.
  [[nodiscard]] Packet** burst(std::size_t i, std::size_t n = kBurst) {
    return &packets_[(i * n) % kFrames];
  }

 private:
  npf::core::PacketPool pool_;
  std::vector<std::vector<std::byte>> templates_;
  std::vector<Packet*> packets_;
};

// The loop all three share: one burst of `n` per iteration and the counters, and with `refill`,
// the frames restored after every lap, with the timer and the cycle counter stopped.
template <class Body>
void run(benchmark::State& state, Frames& frames, bool refill, Body body, std::size_t n = kBurst) {
  const CycleCounter cycles;
  const std::size_t bursts_per_lap = kFrames / n;
  std::size_t i = 0;
  std::size_t packets = 0;
  cycles.start();
  for ([[maybe_unused]] auto _ : state) {
    body(frames.burst(i, n));
    packets += n;
    if (++i == bursts_per_lap) {
      i = 0;
      if (refill) {
        state.PauseTiming();
        cycles.pause();
        frames.refill();
        cycles.resume();
        state.ResumeTiming();
      }
    }
  }
  cycles.pause();
  state.counters["packets"] = static_cast<double>(n);
  state.SetItemsProcessed(static_cast<std::int64_t>(packets));
  if (cycles.available() && packets != 0) {
    state.counters["cycles_per_packet"] =
        static_cast<double>(cycles.read()) / static_cast<double>(packets);
  }
}

// refill: restore the frames after every lap, as full_datapath must, though nothing changed them --
// to measure what the pause itself leaves in the timings.
void parse_only(benchmark::State& state, bool refill) {
  Frames frames(topology().destinations);
  run(state, frames, refill, [](Packet** burst) {
    for (std::size_t k = 0; k < kBurst; ++k) {
      const std::optional<npf::proto::EthView> eth = npf::proto::EthView::parse(burst[k]->data());
      const std::optional<npf::proto::Ipv4View> ip =
          eth ? npf::proto::Ipv4View::parse(eth->payload()) : std::nullopt;
      std::optional<npf::proto::L4Info> l4 = ip ? npf::proto::parse_l4(*ip) : std::nullopt;
      benchmark::DoNotOptimize(l4);
    }
  });
}

template <class Fib>
std::unique_ptr<Fib> built(std::span<const Route> routes) {
  auto fib = std::make_unique<Fib>();
  if constexpr (std::is_same_v<Fib, npf::table::LinearLpm>) {
    for (const Route& r : routes) {
      fib->add(r);
    }
  } else if (!fib->build(routes)) {
    throw std::runtime_error(std::format("{} refused the table", fib->name()));
  }
  return fib;
}

template <class Fib>
void parse_and_lookup(benchmark::State& state, const Workload& w) {
  const std::unique_ptr<Fib> fib = built<Fib>(w.routes);
  Frames frames(w.destinations);
  run(state, frames, false, [&fib](Packet** burst) {
    for (std::size_t k = 0; k < kBurst; ++k) {
      const std::optional<npf::proto::EthView> eth = npf::proto::EthView::parse(burst[k]->data());
      const std::optional<npf::proto::Ipv4View> ip =
          eth ? npf::proto::Ipv4View::parse(eth->payload()) : std::nullopt;
      std::optional<npf::proto::L4Info> l4 = ip ? npf::proto::parse_l4(*ip) : std::nullopt;
      std::optional<npf::table::NextHop> hop =
          ip ? fib->lookup(ip->dst()) : std::optional<npf::table::NextHop>{};
      benchmark::DoNotOptimize(l4);
      benchmark::DoNotOptimize(hop);
    }
  });
  state.counters["routes"] = static_cast<double>(fib->size());
}

// The ARP cache never has to ask anyone: the server is static.
class NoEvents final : public npf::table::ArpEvents {
 public:
  void send_arp_request(std::uint32_t /*ip*/, std::uint16_t /*port*/) override {}
  void unresolved(Packet* /*p*/) override {}
  void discard(Packet* /*p*/) override {}
};

npf::core::Config router_config() {
  npf::core::Config c;
  c.interfaces = {
      {"veth-cr", 0, kPort0Ip, 24, npf::PortMode::Routed, kPort0Mac},
      {"veth-sr", 1, kPort1Ip, 24, npf::PortMode::Routed, kPort1Mac},
  };
  return c;
}

// n: the burst size, from 1 to kMaxBurst, a divisor of kFrames.
template <class Fib>
void full_datapath(benchmark::State& state, const Workload& w, std::size_t n = kBurst) {
  const npf::core::Config cfg = router_config();
  const std::unique_ptr<Fib> fib = built<Fib>(w.routes);
  NoEvents events;
  npf::table::ArpCache arp(events, 16);
  arp.insert_static(kServer, kServerMac, 1);
  npf::table::MacTable macs(16);
  const npf::pipe::Filter filter({}, npf::pipe::Action::Allow);
  npf::stat::Counters stats;
  npf::pipe::Forwarder<Fib> forwarder(cfg, *fib, arp, macs, filter, stats);
  Frames frames(w.destinations);

  // Every frame of a lap must be forwarded, before timing and after, or this would be timing some
  // other path.
  std::array<npf::Decision, npf::core::kMaxBurst> decisions{};
  const std::span<const npf::Decision> decided(decisions.data(), n);
  const auto every_frame_forwarded = [&] {
    frames.refill();
    for (std::size_t b = 0; b < kFrames / n; ++b) {
      forwarder.process_burst(frames.burst(b, n), n, decisions.data());
      if (!std::ranges::all_of(
              decided, [](const npf::Decision& d) { return d.verdict == npf::Verdict::Forward; })) {
        return false;
      }
    }
    frames.refill();
    return true;
  };
  if (!every_frame_forwarded()) {
    state.SkipWithError("a frame was not forwarded");
    return;
  }
  run(
      state, frames, true,
      [&forwarder, &decisions, n](Packet** burst) {
        forwarder.process_burst(burst, n, decisions.data());
        benchmark::DoNotOptimize(decisions);
      },
      n);
  if (stats.total_drops() != 0 || !every_frame_forwarded()) {
    state.SkipWithError("a frame was dropped while timed, or not forwarded after");
  }
  state.counters["routes"] = static_cast<double>(fib->size());
}

template <class Fib>
void register_fib(const char* name, const std::vector<Workload>& workloads) {
  for (const Workload& w : workloads) {
    if (std::is_same_v<Fib, npf::table::LinearLpm> && w.routes.size() > 1000) {
      continue;
    }
    benchmark::RegisterBenchmark(std::format("parse_and_lookup/{}/{}", name, w.name),
                                 [&w](benchmark::State& s) { parse_and_lookup<Fib>(s, w); })
        ->Apply(with_spread);
    benchmark::RegisterBenchmark(std::format("full_datapath/{}/{}", name, w.name),
                                 [&w](benchmark::State& s) { full_datapath<Fib>(s, w); })
        ->Apply(with_spread);
  }
}

}  // namespace

int main(int argc, char** argv) {
  benchmark::AddCustomContext("npf_compiler", NPF_BENCH_COMPILER);
  benchmark::AddCustomContext("npf_build_type", NPF_BENCH_BUILD_TYPE);
  benchmark::AddCustomContext("npf_cxx_flags", NPF_BENCH_FLAGS);
  benchmark::AddCustomContext("npf_burst", std::to_string(kBurst));
  benchmark::AddCustomContext("npf_perf_event_open_cycles",
                              cycles_available() ? "available" : "unavailable");
  benchmark::Initialize(&argc, argv);
  if (benchmark::ReportUnrecognizedArguments(argc, argv)) {
    return 1;
  }
  static std::vector<Workload> workloads;
  try {
    workloads.push_back(topology());
    workloads.push_back(sample_100k());
  } catch (const std::exception& e) {
    std::fprintf(stderr, "bench_datapath: %s\n", e.what());
    return 1;
  }
  benchmark::RegisterBenchmark("parse_only", [](benchmark::State& s) {
    parse_only(s, false);
  })->Apply(with_spread);
  benchmark::RegisterBenchmark("parse_only/refilled", [](benchmark::State& s) {
    parse_only(s, true);
  })->Apply(with_spread);
  register_fib<npf::table::LinearLpm>("linear", workloads);
  register_fib<npf::table::BinaryTrie>("binary_trie", workloads);
  register_fib<npf::table::PatriciaLpm>("patricia", workloads);
  register_fib<npf::table::Dir24_8Lpm>("dir24_8", workloads);
  // [phase 15] The burst size swept, docs/performance.md entry 5: one benchmark per size.
  for (const std::size_t n : {1UL, 2UL, 4UL, 8UL, 16UL, 32UL, 64UL}) {
    benchmark::RegisterBenchmark(std::format("full_datapath/dir24_8/topology/burst:{}", n),
                                 [n](benchmark::State& s) {
                                   full_datapath<npf::table::Dir24_8Lpm>(s, workloads.front(), n);
                                 })
        ->Apply(with_spread);
  }
  benchmark::RunSpecifiedBenchmarks();
  benchmark::Shutdown();
  return 0;
}
