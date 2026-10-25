// Tier A (CLAUDE.md §9): the three checksum implementations in isolation, no I/O. How it is run
// and what it does and does not measure is in docs/performance.md.

#include <benchmark/benchmark.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <npf/proto/checksum.hpp>
#include <npf/proto/checksum_simd.hpp>
#include <random>
#include <vector>

namespace {

std::vector<std::byte> random_bytes(std::size_t n) {
  std::mt19937 rng(20260930);
  std::vector<std::byte> v(n);
  for (std::byte& b : v) {
    b = static_cast<std::byte>(rng());
  }
  return v;
}

// CLAUDE.md §9 wants the median and p95, and the spread. Google Benchmark's aggregates give mean,
// median, stddev and cv across repetitions; these add p95 (nearest rank), min and max.
double p95(const std::vector<double>& v) {
  std::vector<double> sorted = v;
  std::sort(sorted.begin(), sorted.end());
  const auto rank = static_cast<std::size_t>(std::ceil(0.95 * static_cast<double>(sorted.size())));
  return sorted[std::max<std::size_t>(rank, 1) - 1];
}
double min_of(const std::vector<double>& v) {
  return *std::min_element(v.begin(), v.end());
}
double max_of(const std::vector<double>& v) {
  return *std::max_element(v.begin(), v.end());
}

void with_spread(benchmark::internal::Benchmark* b) {
  b->ComputeStatistics("p95", p95)
      ->ComputeStatistics("min", min_of)
      ->ComputeStatistics("max", max_of);
}

void BM_ChecksumReference(benchmark::State& state) {
  const std::vector<std::byte> data = random_bytes(static_cast<std::size_t>(state.range(0)));
  for ([[maybe_unused]] auto _ : state) {
    std::uint16_t sum = npf::proto::checksum_reference(data);
    benchmark::DoNotOptimize(sum);
    benchmark::ClobberMemory();  // re-read the data each iteration instead of hoisting the sum
  }
  state.SetBytesProcessed(state.iterations() * state.range(0));
}

void BM_OnesComplementSum(benchmark::State& state) {
  const std::vector<std::byte> data = random_bytes(static_cast<std::size_t>(state.range(0)));
  for ([[maybe_unused]] auto _ : state) {
    std::uint16_t sum = npf::proto::ones_complement_sum(data);
    benchmark::DoNotOptimize(sum);
    benchmark::ClobberMemory();
  }
  state.SetBytesProcessed(state.iterations() * state.range(0));
}

// One incremental update per iteration. The operands cycle through a table so that none of them
// is a constant the compiler could fold; the table load is part of what is measured, as it would
// be in the forwarder.
void BM_ChecksumUpdate16(benchmark::State& state) {
  struct Update {
    std::uint16_t hc, m, m_prime;
  };
  std::array<Update, 1024> updates{};
  std::mt19937 rng(20260930);
  for (Update& u : updates) {
    u = {static_cast<std::uint16_t>(rng()), static_cast<std::uint16_t>(rng()),
         static_cast<std::uint16_t>(rng())};
  }
  std::size_t i = 0;
  for ([[maybe_unused]] auto _ : state) {
    const Update& u = updates[i++ & (updates.size() - 1)];
    std::uint16_t hc = npf::proto::checksum_update16(u.hc, u.m, u.m_prime);
    benchmark::DoNotOptimize(hc);
  }
}

// [phase 18] The sums of checksum_simd.hpp, each out of line, so all pay the same call: scalar,
// the vector one of this architecture, and the dispatched one, which adds its choice's lookup.
using SumFn = std::uint16_t (*)(npf::core::CBytes) noexcept;

void run_sum(benchmark::State& state, SumFn fn) {
  const std::vector<std::byte> data = random_bytes(static_cast<std::size_t>(state.range(0)));
  for ([[maybe_unused]] auto _ : state) {
    std::uint16_t sum = fn(data);
    benchmark::DoNotOptimize(sum);
    benchmark::ClobberMemory();
  }
  state.SetBytesProcessed(state.iterations() * state.range(0));
}

void BM_SumScalar(benchmark::State& state) {
  run_sum(state, &npf::proto::ones_complement_sum_scalar);
}

void BM_SumVector(benchmark::State& state) {
#if defined(__x86_64__)
  if (__builtin_cpu_supports("avx2") == 0) {
    state.SkipWithError("this CPU has no AVX2");
    return;
  }
  state.SetLabel("avx2");
  run_sum(state, &npf::proto::ones_complement_sum_avx2);
#elif defined(__aarch64__)
  state.SetLabel("neon");
  run_sum(state, &npf::proto::ones_complement_sum_neon);
#else
  state.SkipWithError("no vector sum for this architecture");
#endif
}

void BM_SumFast(benchmark::State& state) {
  state.SetLabel(npf::proto::checksum_implementation());
  run_sum(state, &npf::proto::ones_complement_sum_fast);
}

// 20 and 60 bytes: the smallest and largest IPv4 headers. 1500: an MTU-sized payload, the scale an
// L4 checksum works at.
BENCHMARK(BM_ChecksumReference)->Arg(20)->Arg(60)->Arg(1500)->Apply(with_spread);
BENCHMARK(BM_OnesComplementSum)->Arg(20)->Arg(60)->Arg(1500)->Apply(with_spread);
BENCHMARK(BM_ChecksumUpdate16)->Apply(with_spread);
// 576: the most an ICMP error may quote, RFC 1812. 1500: an echo request of a full MTU.
BENCHMARK(BM_SumScalar)->Arg(20)->Arg(60)->Arg(576)->Arg(1500)->Apply(with_spread);
BENCHMARK(BM_SumVector)->Arg(20)->Arg(60)->Arg(576)->Arg(1500)->Apply(with_spread);
BENCHMARK(BM_SumFast)->Arg(20)->Arg(60)->Arg(576)->Arg(1500)->Apply(with_spread);

}  // namespace

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
