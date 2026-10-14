#pragma once

// CLAUDE.md §9 wants the median and p95 and the spread. Google Benchmark's aggregates give mean,
// median, stddev and cv across repetitions; with_spread() adds p95 (nearest rank), min and max.

#include <benchmark/benchmark.h>

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <vector>

namespace npf::bench {

inline double p95(const std::vector<double>& v) {
  std::vector<double> sorted = v;
  std::ranges::sort(sorted);
  const auto rank = static_cast<std::size_t>(std::ceil(0.95 * static_cast<double>(sorted.size())));
  return sorted[std::max<std::size_t>(rank, 1) - 1];
}

inline double min_of(const std::vector<double>& v) {
  return *std::ranges::min_element(v);
}

inline double max_of(const std::vector<double>& v) {
  return *std::ranges::max_element(v);
}

inline void with_spread(benchmark::internal::Benchmark* b) {
  b->ComputeStatistics("p95", p95)
      ->ComputeStatistics("min", min_of)
      ->ComputeStatistics("max", max_of);
}

}  // namespace npf::bench
