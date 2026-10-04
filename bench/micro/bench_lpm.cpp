// Tier A (CLAUDE.md §9): the LPM implementations in isolation, no I/O, at Internet scale
// (docs/BUILD_PLAN.md phase 10). docs/performance.md says how it is run and what it does and does
// not measure.
//
// It reads the tables scripts/fetch_bgp_table.sh writes -- data/bgp_prefixes_10.txt, _1k, _100k
// and the full bgp_prefixes.txt, or the same names in the directory NPF_BGP_DATA names -- and for
// each implementation and table size times:
//   lookup/<impl>/<size>/<keys>  one lookup, over a million keys drawn three ways: uniform over the
//                                address space; Zipf, alpha 0.99, over the table's prefixes, a key
//                                anywhere inside the prefix drawn; and sequential addresses
//   build/<impl>/<size>          constructing the table and building it from the routes
//   memory/<impl>/<size>         no timing: memory_bytes() against how much the resident set grew
//                                as the table was built, once
// LinearLpm, the oracle, is in only at 10 and 1k: at 100k a lookup walks a hundred thousand routes.

#include <benchmark/benchmark.h>
#include <malloc.h>
#include <unistd.h>

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <memory>
#include <npf/table/fib.hpp>
#include <npf/table/lpm_dir24_8.hpp>
#include <npf/table/lpm_linear.hpp>
#include <npf/table/lpm_patricia.hpp>
#include <npf/table/lpm_trie.hpp>
#include <random>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

using npf::table::Route;

constexpr std::size_t kKeys = std::size_t{1} << 20U;  // a power of two: the loop masks its index
constexpr double kZipfAlpha = 0.99;
constexpr std::uint32_t kSeed = 20261005;

// --- statistics, as bench_checksum reports them --------------------------------------------------

// CLAUDE.md §9 wants the median and p95, and the spread. Google Benchmark's aggregates give mean,
// median, stddev and cv across repetitions; these add p95 (nearest rank), min and max.
double p95(const std::vector<double>& v) {
  std::vector<double> sorted = v;
  std::ranges::sort(sorted);
  const auto rank = static_cast<std::size_t>(std::ceil(0.95 * static_cast<double>(sorted.size())));
  return sorted[std::max<std::size_t>(rank, 1) - 1];
}
double min_of(const std::vector<double>& v) {
  return *std::ranges::min_element(v);
}
double max_of(const std::vector<double>& v) {
  return *std::ranges::max_element(v);
}

void with_spread(benchmark::internal::Benchmark* b) {
  b->ComputeStatistics("p95", p95)
      ->ComputeStatistics("min", min_of)
      ->ComputeStatistics("max", max_of);
}

// --- the data ------------------------------------------------------------------------------------

std::uint32_t next32(std::mt19937& rng) {
  return static_cast<std::uint32_t>(rng());
}

// "a.b.c.d/len id" lines. The id stands for a next hop; any distinct value per id will do.
std::vector<Route> load_routes(const std::filesystem::path& path) {
  std::ifstream in(path);
  if (!in) {
    throw std::runtime_error(
        std::format("cannot read {}: run scripts/fetch_bgp_table.sh first", path.string()));
  }
  std::vector<Route> routes;
  std::string line;
  while (std::getline(in, line)) {
    unsigned a = 0;
    unsigned b = 0;
    unsigned c = 0;
    unsigned d = 0;
    unsigned len = 0;
    unsigned id = 0;
    char dot1 = 0;
    char dot2 = 0;
    char dot3 = 0;
    char slash = 0;
    std::istringstream fields(line);
    if (!(fields >> a >> dot1 >> b >> dot2 >> c >> dot3 >> d >> slash >> len >> id) ||
        dot1 != '.' || dot2 != '.' || dot3 != '.' || slash != '/' || a > 255 || b > 255 ||
        c > 255 || d > 255 || len > 32) {
      throw std::runtime_error(std::format("{}: cannot read '{}'", path.string(), line));
    }
    const npf::table::Prefix prefix{a << 24U | b << 16U | c << 8U | d,
                                    static_cast<std::uint8_t>(len)};
    if (!npf::table::is_valid(prefix)) {
      throw std::runtime_error(
          std::format("{}: '{}' has bits set past its length", path.string(), line));
    }
    routes.push_back({prefix, 0x0AFF0000U + id, static_cast<std::uint16_t>(id % 4)});
  }
  return routes;
}

std::vector<std::uint32_t> uniform_keys() {
  std::mt19937 rng(kSeed);
  std::vector<std::uint32_t> keys(kKeys);
  std::ranges::generate(keys, [&rng] { return next32(rng); });
  return keys;
}

// Rank r of the prefixes is drawn with weight 1 / r^alpha; which prefix holds which rank is a
// shuffle, so that popularity has nothing to do with the order of the file. The key is anywhere
// in the prefix drawn -- and may well match a longer one inside it.
std::vector<std::uint32_t> zipf_keys(std::span<const Route> routes) {
  std::mt19937 rng(kSeed + 1);
  std::vector<std::size_t> owner(routes.size());
  for (std::size_t i = 0; i < owner.size(); ++i) {
    owner[i] = i;
  }
  for (std::size_t i = owner.size(); i > 1; --i) {  // Fisher-Yates, on rng's raw output
    std::swap(owner[i - 1], owner[next32(rng) % i]);
  }
  std::vector<double> cdf(routes.size());
  double total = 0;
  for (std::size_t r = 0; r < cdf.size(); ++r) {
    total += 1.0 / std::pow(static_cast<double>(r + 1), kZipfAlpha);
    cdf[r] = total;
  }
  std::vector<std::uint32_t> keys(kKeys);
  for (std::uint32_t& key : keys) {
    const double u = static_cast<double>(next32(rng)) / 4294967296.0 * total;
    const auto rank = static_cast<std::size_t>(std::ranges::upper_bound(cdf, u) - cdf.begin());
    const npf::table::Prefix p = routes[owner[std::min(rank, cdf.size() - 1)]].prefix;
    key = p.addr | (next32(rng) & ~npf::table::prefix_mask(p.len));
  }
  return keys;
}

// A million consecutive addresses, from the lowest the table routes.
std::vector<std::uint32_t> sequential_keys(std::span<const Route> routes) {
  const std::uint32_t start =
      std::ranges::min(routes, {}, [](const Route& r) { return r.prefix.addr; }).prefix.addr;
  std::vector<std::uint32_t> keys(kKeys);
  for (std::size_t i = 0; i < kKeys; ++i) {
    keys[i] = start + static_cast<std::uint32_t>(i);
  }
  return keys;
}

// --- measuring -----------------------------------------------------------------------------------

// What the kernel says this process holds in memory, once malloc_trim() has given back what was
// freed: /proc/self/statm's resident pages.
std::size_t resident_bytes() {
  ::malloc_trim(0);
  std::ifstream statm("/proc/self/statm");
  std::size_t total = 0;
  std::size_t resident = 0;
  statm >> total >> resident;
  return resident * static_cast<std::size_t>(::sysconf(_SC_PAGESIZE));
}

template <class Table>
std::unique_ptr<Table> built(std::span<const Route> routes) {
  auto table = std::make_unique<Table>();
  if constexpr (std::is_same_v<Table, npf::table::LinearLpm>) {
    for (const Route& r : routes) {
      table->add(r);
    }
  } else if (!table->build(routes)) {
    throw std::runtime_error(std::format("{} refused the table", table->name()));
  }
  return table;
}

template <class Table>
void lookup_bench(benchmark::State& state, const Table& table,
                  std::span<const std::uint32_t> keys) {
  std::size_t i = 0;
  for ([[maybe_unused]] auto _ : state) {
    auto hop =
        table.lookup(keys[i++ & (kKeys - 1)]);  // not const: DoNotOptimize takes it by reference
    benchmark::DoNotOptimize(hop);
  }
  state.counters["memory_bytes"] = static_cast<double>(table.memory_bytes());
  state.counters["routes"] = static_cast<double>(table.size());
}

template <class Table>
void build_bench(benchmark::State& state, std::span<const Route> routes) {
  for ([[maybe_unused]] auto _ : state) {
    auto table = built<Table>(routes);
    benchmark::DoNotOptimize(table.get());
    state.PauseTiming();
    table.reset();  // freeing is not building
    state.ResumeTiming();
  }
  state.counters["routes"] = static_cast<double>(routes.size());
}

template <class Table>
void memory_bench(benchmark::State& state, std::span<const Route> routes) {
  for ([[maybe_unused]] auto _ : state) {
    const std::size_t before = resident_bytes();
    const auto table = built<Table>(routes);
    const std::size_t grown = resident_bytes() - before;
    state.counters["memory_bytes"] = static_cast<double>(table->memory_bytes());
    state.counters["rss_growth_bytes"] = static_cast<double>(grown);
    state.counters["memory_over_rss"] =
        grown == 0 ? 0.0 : static_cast<double>(table->memory_bytes()) / static_cast<double>(grown);
  }
}

// --- the sweep -----------------------------------------------------------------------------------

struct Size {
  std::string name;
  std::vector<Route> routes;
  std::vector<std::uint32_t> uniform, zipf, sequential;
};

// Everything the benchmarks read lives here, made once, for the whole run.
struct Data {
  std::vector<Size> sizes;
  std::vector<std::unique_ptr<npf::table::Fib>> tables;
};

template <class Table>
void register_impl(Data& data, const char* impl, bool small_only) {
  for (const Size& size : data.sizes) {
    if (small_only && size.routes.size() > 1000) {
      continue;
    }
    std::unique_ptr<Table> table = built<Table>(size.routes);
    const Table& t = *table;
    data.tables.push_back(std::move(table));
    for (const auto& [keys_name, keys] :
         {std::pair{"uniform", &size.uniform}, std::pair{"zipf", &size.zipf},
          std::pair{"sequential", &size.sequential}}) {
      benchmark::RegisterBenchmark(std::format("lookup/{}/{}/{}", impl, size.name, keys_name),
                                   [&t, keys](benchmark::State& s) { lookup_bench(s, t, *keys); })
          ->Apply(with_spread);
    }
    const std::span<const Route> routes = size.routes;
    benchmark::RegisterBenchmark(std::format("build/{}/{}", impl, size.name),
                                 [routes](benchmark::State& s) { build_bench<Table>(s, routes); })
        ->Unit(benchmark::kMillisecond)
        ->Apply(with_spread);
    benchmark::RegisterBenchmark(std::format("memory/{}/{}", impl, size.name),
                                 [routes](benchmark::State& s) { memory_bench<Table>(s, routes); })
        ->Iterations(1)
        ->Repetitions(1)
        ->Unit(benchmark::kMillisecond);
  }
}

}  // namespace

int main(int argc, char** argv) {
  benchmark::AddCustomContext("npf_compiler", NPF_BENCH_COMPILER);
  benchmark::AddCustomContext("npf_build_type", NPF_BENCH_BUILD_TYPE);
  benchmark::AddCustomContext("npf_cxx_flags", NPF_BENCH_FLAGS);
  benchmark::Initialize(&argc, argv);
  if (benchmark::ReportUnrecognizedArguments(argc, argv)) {
    return 1;
  }
  try {
    const char* dir = std::getenv("NPF_BGP_DATA");
    const std::filesystem::path data_dir = dir != nullptr ? dir : "data";
    static Data data;
    for (const auto& [name, file] :
         {std::pair{"10", "bgp_prefixes_10.txt"}, std::pair{"1k", "bgp_prefixes_1k.txt"},
          std::pair{"100k", "bgp_prefixes_100k.txt"}, std::pair{"full", "bgp_prefixes.txt"}}) {
      Size& size = data.sizes.emplace_back();
      size.name = name;
      size.routes = load_routes(data_dir / file);
      size.uniform = uniform_keys();
      size.zipf = zipf_keys(size.routes);
      size.sequential = sequential_keys(size.routes);
      benchmark::AddCustomContext(std::format("npf_routes_{}", name),
                                  std::to_string(size.routes.size()));
    }
    register_impl<npf::table::BinaryTrie>(data, "binary_trie", false);
    register_impl<npf::table::PatriciaLpm>(data, "patricia", false);
    register_impl<npf::table::Dir24_8Lpm>(data, "dir24_8", false);
    register_impl<npf::table::LinearLpm>(data, "linear", true);
  } catch (const std::exception& e) {
    std::fprintf(stderr, "bench_lpm: %s\n", e.what());
    return 1;
  }
  benchmark::RunSpecifiedBenchmarks();
  benchmark::Shutdown();
  return 0;
}
