// Tier A (CLAUDE.md §9): the packet pool, in process, no I/O (docs/BUILD_PLAN.md phase 14).
//
//   pool_acquire_release        one acquire() and one release() per iteration
//   pool_acquire_release/burst  32 acquires, then 32 releases, per iteration: a burst's worth,
//                               as the RX path takes buffers and the TX path gives them back
//
// The pool holds 4096 packets, router.conf's pool_size. A packet comes back reset -- reset() is
// part of acquire() -- so acquire()'s cost includes clearing the metadata.

#include <benchmark/benchmark.h>

#include <array>
#include <cstddef>
#include <npf/core/packet.hpp>
#include <npf/core/pool.hpp>

#include "spread.hpp"

namespace {

using npf::bench::with_spread;
using npf::core::Packet;
using npf::core::PacketPool;

constexpr std::size_t kPoolSize = 4096;
constexpr std::size_t kBurst = 32;

void pool_acquire_release(benchmark::State& state) {
  PacketPool pool(kPoolSize);
  for ([[maybe_unused]] auto _ : state) {
    Packet* p = pool.acquire();
    benchmark::DoNotOptimize(p);
    pool.release(p);
  }
  state.SetItemsProcessed(state.iterations());
}

void pool_acquire_release_burst(benchmark::State& state) {
  PacketPool pool(kPoolSize);
  std::array<Packet*, kBurst> burst{};
  for ([[maybe_unused]] auto _ : state) {
    for (Packet*& p : burst) {
      p = pool.acquire();
    }
    benchmark::DoNotOptimize(burst);
    for (Packet* p : burst) {
      pool.release(p);
    }
  }
  state.counters["packets"] = static_cast<double>(kBurst);
  state.SetItemsProcessed(state.iterations() * static_cast<benchmark::IterationCount>(kBurst));
}

}  // namespace

BENCHMARK(pool_acquire_release)->Apply(with_spread);
BENCHMARK(pool_acquire_release_burst)->Name("pool_acquire_release/burst")->Apply(with_spread);

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
