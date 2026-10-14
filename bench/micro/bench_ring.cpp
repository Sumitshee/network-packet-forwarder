// Tier A (CLAUDE.md §9): the SPSC ring, in process, no I/O (docs/BUILD_PLAN.md phase 14). The
// ring is pipeline mode's: SpscRing<Packet*, 1024>.
//
//   ring_push_pop       one thread: one push, then one pop, per iteration -- the cost of the
//                       operations themselves, every cache line already in this core's cache
//   ring_round_trip     two threads, two rings: thread 0 pushes to one ring and waits for the
//                       element to come back on the other; thread 1 sends each back as it arrives.
//                       One iteration is one round trip: two hand-overs between cores, so two
//                       cache-line transfers of an index and two of a slot, at least
//   ring_throughput     two threads, one ring: thread 0 pushes bursts of 32 with push_bulk,
//                       thread 1 takes bursts of 32 with pop_bulk. One iteration is one burst
//                       through the ring; the threads overlap, as RX thread and worker do
//
// Run the two-thread benchmarks with the process confined to two CPUs on different cores, or the
// numbers mix in hyperthread sharing and scheduling.

#include <benchmark/benchmark.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <npf/core/packet.hpp>
#include <npf/core/ring.hpp>

#include "spread.hpp"

namespace {

using npf::bench::with_spread;
using npf::core::Packet;
using Ring = npf::core::SpscRing<Packet*, 1024>;

constexpr std::size_t kBurst = 32;

// Any distinct non-null pointer will do: no packet is ever looked at.
Packet* token(std::uintptr_t n) {
  return reinterpret_cast<Packet*>((n + 1) * 64);  // NOLINT(performance-no-int-to-ptr)
}

void ring_push_pop(benchmark::State& state) {
  const auto ring = std::make_unique<Ring>();
  std::uintptr_t n = 0;
  for ([[maybe_unused]] auto _ : state) {
    Packet* out = nullptr;
    benchmark::DoNotOptimize(ring->push(token(n++)));
    benchmark::DoNotOptimize(ring->pop(out));
    benchmark::DoNotOptimize(out);
  }
  state.SetItemsProcessed(state.iterations());
}

// Shared by the two threads of one run; each run leaves them empty.
Ring& ping() {
  static const auto ring = std::make_unique<Ring>();
  return *ring;
}
Ring& pong() {
  static const auto ring = std::make_unique<Ring>();
  return *ring;
}
Ring& stream() {
  static const auto ring = std::make_unique<Ring>();
  return *ring;
}

void ring_round_trip(benchmark::State& state) {
  Packet* p = nullptr;
  if (state.thread_index() == 0) {
    std::uintptr_t n = 0;
    for ([[maybe_unused]] auto _ : state) {
      while (!ping().push(token(n))) {
      }
      while (!pong().pop(p)) {
      }
      ++n;
    }
  } else {
    for ([[maybe_unused]] auto _ : state) {
      while (!ping().pop(p)) {
      }
      while (!pong().push(p)) {
      }
    }
  }
  benchmark::DoNotOptimize(p);
}

void ring_throughput(benchmark::State& state) {
  std::array<Packet*, kBurst> burst{};
  if (state.thread_index() == 0) {
    std::uintptr_t n = 0;
    for ([[maybe_unused]] auto _ : state) {
      for (Packet*& p : burst) {
        p = token(n++);
      }
      for (std::size_t done = 0; done < kBurst;) {
        done += stream().push_bulk(burst.data() + done, kBurst - done);
      }
    }
  } else {
    for ([[maybe_unused]] auto _ : state) {
      for (std::size_t got = 0; got < kBurst;) {
        got += stream().pop_bulk(burst.data() + got, kBurst - got);
      }
      benchmark::DoNotOptimize(burst);
    }
  }
  if (state.thread_index() == 0) {  // counters are summed over threads: one thread's say
    state.counters["packets"] = static_cast<double>(kBurst);
    state.SetItemsProcessed(state.iterations() * static_cast<benchmark::IterationCount>(kBurst));
  }
}

}  // namespace

BENCHMARK(ring_push_pop)->Apply(with_spread);
BENCHMARK(ring_round_trip)->Threads(2)->UseRealTime()->Apply(with_spread);
BENCHMARK(ring_throughput)->Threads(2)->UseRealTime()->Apply(with_spread);

int main(int argc, char** argv) {
  benchmark::AddCustomContext("npf_compiler", NPF_BENCH_COMPILER);
  benchmark::AddCustomContext("npf_build_type", NPF_BENCH_BUILD_TYPE);
  benchmark::AddCustomContext("npf_cxx_flags", NPF_BENCH_FLAGS);
  benchmark::Initialize(&argc, argv);
  if (benchmark::ReportUnrecognizedArguments(argc, argv)) {
    return 1;
  }
  benchmark::RunSpecifiedBenchmarks();
  benchmark::Shutdown();
  return 0;
}
