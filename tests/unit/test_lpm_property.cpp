// docs/BUILD_PLAN.md phase 10's conformance suite: every LPM implementation against the phase 5
// oracle, LinearLpm, on adversarial random tables. If an implementation disagrees with the oracle
// once, it is the implementation that is wrong.

#include <gtest/gtest.h>
#include <malloc.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <memory>
#include <npf/table/fib.hpp>
#include <npf/table/lpm_dir24_8.hpp>
#include <npf/table/lpm_linear.hpp>
#include <npf/table/lpm_patricia.hpp>
#include <npf/table/lpm_trie.hpp>
#include <optional>
#include <ostream>
#include <random>
#include <string>
#include <type_traits>
#include <vector>

#include "support/prefix_gen.hpp"

namespace npf::table {

// Found by argument-dependent lookup, so GoogleTest prints "11.0.0.3 port 3", not raw bytes.
void PrintTo(const NextHop& h, std::ostream* os) {
  *os << npf::test::ip_to_string(h.ip) << " port " << h.port;
}

}  // namespace npf::table

namespace {

using npf::table::BinaryTrie;
using npf::table::Dir24_8Lpm;
using npf::table::LinearLpm;
using npf::table::NextHop;
using npf::table::PatriciaLpm;
using npf::table::Prefix;
using npf::table::Route;
using npf::test::adversarial_prefix_set;
using npf::test::dump;
using npf::test::ip_to_string;
using npf::test::probe_keys;
using npf::test::RouteOp;

#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
constexpr bool kSanitized = true;
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer)
constexpr bool kSanitized = true;
#else
constexpr bool kSanitized = false;
#endif
#else
constexpr bool kSanitized = false;
#endif

constexpr std::uint32_t ip(std::uint32_t a, std::uint32_t b, std::uint32_t c, std::uint32_t d) {
  return a << 24U | b << 16U | c << 8U | d;
}

Route route(std::uint32_t addr, std::uint8_t len, std::uint32_t hop) {
  return {{addr, len}, hop, static_cast<std::uint16_t>(hop % 4)};
}

NextHop hop(std::uint32_t h) {
  return {h, static_cast<std::uint16_t>(h % 4)};
}

template <class T>
class LpmConformance : public ::testing::Test {};

using Implementations = ::testing::Types<BinaryTrie, PatriciaLpm, Dir24_8Lpm>;

struct ImplementationName {
  template <class T>
  static std::string GetName(int /*index*/) {
    if constexpr (std::is_same_v<T, BinaryTrie>) {
      return "BinaryTrie";
    } else if constexpr (std::is_same_v<T, PatriciaLpm>) {
      return "PatriciaLpm";
    } else {
      return "Dir24_8Lpm";
    }
  }
};

TYPED_TEST_SUITE(LpmConformance, Implementations, ImplementationName);

bool apply(npf::table::Fib& table, const RouteOp& op) {
  return op.kind == RouteOp::Kind::Add ? table.add(op.route) : table.remove(op.route.prefix);
}

// How many random tables a suite tries: all of them, but for Dir24_8Lpm under a sanitizer, a fifth.
// Its trials write millions of table entries each, which the sanitizers' checks slow fifteen-fold;
// the dev and ci builds still run every trial, and a fifth is still thousands of operations through
// every path for ASan and TSan to watch.
template <class T>
constexpr int trials(int all) {
  return kSanitized && std::is_same_v<T, Dir24_8Lpm> ? all / 5 : all;
}

// The exit test. Both tables take every operation, and must agree on what each did and on how many
// routes are left; then on a thousand addresses, chosen to hit the set's edges. Along the way, a
// few addresses every 64 operations, so that a mistake a later operation would hide is caught too.
// The implementation is one table, cleared between trials -- which tests clear() a thousand times,
// and spares Dir24_8Lpm allocating its 48 MiB afresh for each.
TYPED_TEST(LpmConformance, AgreesWithOracle) {
  std::mt19937 rng(1234);
  TypeParam impl;
  for (int trial = 0; trial < trials<TypeParam>(1000); ++trial) {
    const std::vector<RouteOp> ops = adversarial_prefix_set(rng, 1 + (rng() % 500));
    LinearLpm oracle;
    impl.clear();
    for (std::size_t i = 0; i < ops.size(); ++i) {
      ASSERT_EQ(apply(impl, ops[i]), apply(oracle, ops[i]))
          << "trial " << trial << ", operation " << i + 1 << " of:\n"
          << dump(ops);
      ASSERT_EQ(impl.size(), oracle.size()) << "trial " << trial << ", operation " << i + 1;
      if (i % 64 == 63) {
        for (const std::uint32_t key : probe_keys(rng, ops, 16)) {
          ASSERT_EQ(impl.lookup(key), oracle.lookup(key))
              << "trial " << trial << " after operation " << i + 1 << ", key " << ip_to_string(key)
              << "\nroutes:\n"
              << dump(ops);
        }
      }
    }
    for (const std::uint32_t key : probe_keys(rng, ops, 1000)) {
      ASSERT_EQ(impl.lookup(key), oracle.lookup(key))
          << "trial " << trial << " key " << ip_to_string(key) << "\nroutes:\n"
          << dump(ops);
    }
  }
}

// build() is a path of its own -- for Dir24_8Lpm, other code altogether -- so it is held to the
// oracle too; and so is a built table's first change, which for Dir24_8Lpm makes its length
// tables from the route list.
TYPED_TEST(LpmConformance, BuildAgreesWithOracleAndTakesChangesAfter) {
  std::mt19937 rng(5678);
  TypeParam impl;  // build() replaces whatever the last trial left
  for (int trial = 0; trial < trials<TypeParam>(200); ++trial) {
    std::vector<RouteOp> ops = adversarial_prefix_set(rng, 1 + (rng() % 500));
    std::erase_if(ops, [](const RouteOp& op) { return op.kind == RouteOp::Kind::Remove; });
    std::vector<Route> routes;
    LinearLpm oracle;
    for (const RouteOp& op : ops) {
      routes.push_back(op.route);
      oracle.add(op.route);
    }
    ASSERT_TRUE(impl.build(routes));
    ASSERT_EQ(impl.size(), oracle.size()) << "trial " << trial;
    for (const std::uint32_t key : probe_keys(rng, ops, 500)) {
      ASSERT_EQ(impl.lookup(key), oracle.lookup(key))
          << "trial " << trial << " key " << ip_to_string(key) << " after build of:\n"
          << dump(ops);
    }

    std::vector<RouteOp> changes = adversarial_prefix_set(rng, 20);
    for (int k = 0; k < 10; ++k) {
      changes.push_back({RouteOp::Kind::Remove, routes[rng() % routes.size()]});
    }
    for (std::size_t i = 0; i < changes.size(); ++i) {
      ASSERT_EQ(apply(impl, changes[i]), apply(oracle, changes[i]))
          << "trial " << trial << ", change " << i + 1 << " of:\n"
          << dump(changes) << "after build of:\n"
          << dump(ops);
    }
    ASSERT_EQ(impl.size(), oracle.size()) << "trial " << trial;
    ops.insert(ops.end(), changes.begin(), changes.end());
    for (const std::uint32_t key : probe_keys(rng, ops, 500)) {
      ASSERT_EQ(impl.lookup(key), oracle.lookup(key))
          << "trial " << trial << " key " << ip_to_string(key) << " after changes:\n"
          << dump(ops);
    }
  }
}

// --- particular cases, each shown once on its own ------------------------------------------------

// The first and the last entries of every table, where an index off by one falls outside it.
TYPED_TEST(LpmConformance, TheEndsOfTheAddressSpaceAreNoSpecialCase) {
  TypeParam table;
  ASSERT_TRUE(table.add(route(ip(255, 255, 255, 0), 24, 1)));
  ASSERT_TRUE(table.add(route(ip(255, 255, 255, 128), 25, 2)));
  ASSERT_TRUE(table.add(route(0xFFFFFFFFU, 32, 3)));
  ASSERT_TRUE(table.add(route(0, 32, 4)));
  ASSERT_TRUE(table.add(route(ip(0, 0, 0, 128), 25, 5)));
  EXPECT_EQ(table.lookup(0xFFFFFFFFU), hop(3));
  EXPECT_EQ(table.lookup(ip(255, 255, 255, 254)), hop(2));
  EXPECT_EQ(table.lookup(ip(255, 255, 255, 127)), hop(1));
  EXPECT_FALSE(table.lookup(ip(255, 255, 254, 255)).has_value());
  EXPECT_EQ(table.lookup(0), hop(4));
  EXPECT_FALSE(table.lookup(1).has_value());
  EXPECT_EQ(table.lookup(ip(0, 0, 0, 255)), hop(5));
  ASSERT_TRUE(table.remove({0xFFFFFFFFU, 32}));
  EXPECT_EQ(table.lookup(0xFFFFFFFFU), hop(2));
}

TYPED_TEST(LpmConformance, AnEmptyTableFindsNothing) {
  const TypeParam table;
  for (const std::uint32_t key : {0U, 1U, ip(10, 0, 0, 1), 0x7FFFFFFFU, 0xFFFFFFFFU}) {
    EXPECT_FALSE(table.lookup(key).has_value()) << ip_to_string(key);
  }
  EXPECT_EQ(table.size(), 0U);
}

TYPED_TEST(LpmConformance, TheDefaultRouteMatchesEveryAddress) {
  TypeParam table;
  ASSERT_TRUE(table.add(route(0, 0, 7)));
  for (const std::uint32_t key : {0U, ip(10, 1, 2, 3), 0x7FFFFFFFU, 0x80000000U, 0xFFFFFFFFU}) {
    EXPECT_EQ(table.lookup(key), hop(7)) << ip_to_string(key);
  }
}

TYPED_TEST(LpmConformance, AHostRouteMatchesItsAddressAlone) {
  TypeParam table;
  ASSERT_TRUE(table.add(route(ip(10, 1, 2, 3), 32, 1)));
  EXPECT_EQ(table.lookup(ip(10, 1, 2, 3)), hop(1));
  EXPECT_FALSE(table.lookup(ip(10, 1, 2, 2)).has_value());
  EXPECT_FALSE(table.lookup(ip(10, 1, 2, 4)).has_value());
}

// At and either side of the lengths where shift arithmetic breaks: the first and last addresses
// match, and the ones just outside do not.
TYPED_TEST(LpmConformance, APrefixEndsExactlyWhereItsMaskSays) {
  for (const std::uint8_t len : std::array<std::uint8_t, 10>{7, 8, 9, 15, 16, 17, 23, 24, 25, 31}) {
    TypeParam table;
    const Prefix p{ip(10, 255, 255, 128) & npf::table::prefix_mask(len), len};
    const std::uint32_t last = p.addr | ~npf::table::prefix_mask(len);
    ASSERT_TRUE(table.add(route(p.addr, len, 2)));
    EXPECT_EQ(table.lookup(p.addr), hop(2)) << "/" << int{len};
    EXPECT_EQ(table.lookup(last), hop(2)) << "/" << int{len};
    EXPECT_FALSE(table.lookup(p.addr - 1).has_value()) << "/" << int{len};
    EXPECT_FALSE(table.lookup(last + 1).has_value()) << "/" << int{len};
  }
}

TYPED_TEST(LpmConformance, TheLongestMatchWinsAndRemovingItHandsBackToTheNext) {
  TypeParam table;
  ASSERT_TRUE(table.add(route(ip(10, 0, 0, 0), 8, 1)));
  ASSERT_TRUE(table.add(route(ip(10, 1, 0, 0), 16, 2)));
  ASSERT_TRUE(table.add(route(ip(10, 1, 2, 0), 24, 3)));
  ASSERT_TRUE(table.add(route(ip(10, 1, 2, 128), 25, 4)));
  const std::uint32_t key = ip(10, 1, 2, 200);
  EXPECT_EQ(table.lookup(key), hop(4));
  ASSERT_TRUE(table.remove({ip(10, 1, 2, 128), 25}));
  EXPECT_EQ(table.lookup(key), hop(3));
  ASSERT_TRUE(table.remove({ip(10, 1, 2, 0), 24}));
  EXPECT_EQ(table.lookup(key), hop(2));
  ASSERT_TRUE(table.remove({ip(10, 1, 0, 0), 16}));
  EXPECT_EQ(table.lookup(key), hop(1));
  ASSERT_TRUE(table.remove({ip(10, 0, 0, 0), 8}));
  EXPECT_FALSE(table.lookup(key).has_value());
  EXPECT_EQ(table.size(), 0U);
  EXPECT_FALSE(table.remove({ip(10, 0, 0, 0), 8}));  // gone already
}

TYPED_TEST(LpmConformance, AddingAPrefixAgainReplacesItsNextHop) {
  TypeParam table;
  ASSERT_TRUE(table.add(route(ip(192, 168, 0, 0), 16, 1)));
  ASSERT_TRUE(table.add(route(ip(192, 168, 0, 0), 16, 2)));
  EXPECT_EQ(table.size(), 1U);
  EXPECT_EQ(table.lookup(ip(192, 168, 7, 7)), hop(2));
  // build() too: of two routes for one prefix, the later wins.
  const std::array<Route, 2> twice{route(ip(192, 168, 0, 0), 16, 5),
                                   route(ip(192, 168, 0, 0), 16, 6)};
  ASSERT_TRUE(table.build(twice));
  EXPECT_EQ(table.size(), 1U);
  EXPECT_EQ(table.lookup(ip(192, 168, 7, 7)), hop(6));
}

TYPED_TEST(LpmConformance, AnInvalidPrefixIsRefusedChangingNothing) {
  TypeParam table;
  ASSERT_TRUE(table.add(route(ip(10, 0, 0, 0), 8, 1)));
  EXPECT_FALSE(table.add(route(ip(10, 0, 0, 1), 8, 2)));  // a host bit set past the length
  EXPECT_FALSE(table.add({{0, 33}, 0, 0}));               // longer than an address
  EXPECT_FALSE(table.remove({ip(10, 0, 0, 1), 8}));
  const std::array<Route, 2> one_bad{route(ip(172, 16, 0, 0), 12, 3),
                                     route(ip(172, 16, 0, 1), 12, 4)};
  EXPECT_FALSE(table.build(one_bad));
  EXPECT_EQ(table.size(), 1U);
  EXPECT_EQ(table.lookup(ip(10, 0, 0, 1)), hop(1));
  EXPECT_FALSE(table.lookup(ip(172, 16, 0, 1)).has_value());
}

TYPED_TEST(LpmConformance, ClearEmptiesIt) {
  TypeParam table;
  ASSERT_TRUE(table.add(route(0, 0, 1)));
  ASSERT_TRUE(table.add(route(ip(10, 1, 2, 3), 32, 2)));
  table.clear();
  EXPECT_EQ(table.size(), 0U);
  EXPECT_FALSE(table.lookup(ip(10, 1, 2, 3)).has_value());
  ASSERT_TRUE(table.add(route(ip(10, 1, 2, 3), 32, 3)));  // and it still works
  EXPECT_EQ(table.lookup(ip(10, 1, 2, 3)), hop(3));
}

// The resident memory a table's construction adds, as the kernel counts it: /proc/self/statm,
// after malloc_trim() has handed back what was freed, so that only what is live is counted.
std::size_t resident_bytes() {
  ::malloc_trim(0);
  std::ifstream statm("/proc/self/statm");
  std::size_t total = 0;
  std::size_t resident = 0;
  statm >> total >> resident;
  return resident * static_cast<std::size_t>(::sysconf(_SC_PAGESIZE));
}

// Exit test 3 at a size CI can build: memory_bytes() within 5% of what the kernel says the table
// takes. bench_lpm checks it again at the full Internet table.
TYPED_TEST(LpmConformance, MemoryBytesIsTheMemoryItTakes) {
  if (kSanitized) {
    GTEST_SKIP() << "a sanitizer's own memory would be counted too";
  }
  std::mt19937 rng(42);
  const std::vector<Route> routes = npf::test::internet_like_routes(rng, 200'000);
  const std::size_t before = resident_bytes();
  const auto table = std::make_unique<TypeParam>();
  ASSERT_TRUE(table->build(routes));
  const std::size_t grown = resident_bytes() - before;
  const auto claimed = static_cast<double>(table->memory_bytes());
  EXPECT_NEAR(claimed / static_cast<double>(grown), 1.0, 0.05)
      << "memory_bytes() " << table->memory_bytes() << ", resident memory grew by " << grown;
}

// --- Dir24_8Lpm's own limits ---------------------------------------------------------------------

TEST(Dir24_8Lpm, ThePrefixesLongerThanA24ShareOneGroupThatGoesBackWhenTheyDo) {
  Dir24_8Lpm table;
  ASSERT_TRUE(table.add(route(ip(10, 1, 2, 0), 25, 1)));
  ASSERT_TRUE(table.add(route(ip(10, 1, 2, 128), 26, 2)));
  ASSERT_TRUE(table.add(route(ip(10, 1, 2, 255), 32, 3)));
  EXPECT_EQ(table.groups_in_use(), 1U);
  ASSERT_TRUE(table.add(route(ip(10, 1, 3, 0), 25, 4)));
  EXPECT_EQ(table.groups_in_use(), 2U);
  for (const Prefix p : {Prefix{ip(10, 1, 2, 0), 25}, Prefix{ip(10, 1, 2, 128), 26},
                         Prefix{ip(10, 1, 2, 255), 32}}) {
    ASSERT_TRUE(table.remove(p));
  }
  EXPECT_EQ(table.groups_in_use(), 1U);
  // Groups given back are taken again: churn does not grow the table.
  const std::size_t settled = table.memory_bytes();
  for (std::uint32_t i = 0; i < 1000; ++i) {
    ASSERT_TRUE(table.add(route(ip(10, 2, 0, 0) + (i << 8U), 25, 4)));
    ASSERT_TRUE(table.remove({ip(10, 2, 0, 0) + (i << 8U), 25}));
  }
  EXPECT_EQ(table.groups_in_use(), 1U);
  EXPECT_EQ(table.memory_bytes(), settled);
}

TEST(Dir24_8Lpm, ItHasRoomForExactly32768Groups) {
  Dir24_8Lpm table;
  for (std::uint32_t g = 0; g < Dir24_8Lpm::kMaxGroups; ++g) {
    ASSERT_TRUE(table.add(route(g << 8U, 25, 1))) << g;
  }
  EXPECT_EQ(table.groups_in_use(), Dir24_8Lpm::kMaxGroups);
  const std::uint32_t one_more = static_cast<std::uint32_t>(Dir24_8Lpm::kMaxGroups) << 8U;
  EXPECT_FALSE(table.add(route(one_more, 25, 1)));  // a new /24: no group for it
  EXPECT_FALSE(table.lookup(one_more).has_value());
  EXPECT_EQ(table.size(), Dir24_8Lpm::kMaxGroups);
  EXPECT_TRUE(table.add(route(128, 25, 2)));  // the other half of a /24 that has one: fine
  std::vector<Route> too_many;
  for (std::uint32_t g = 0; g <= Dir24_8Lpm::kMaxGroups; ++g) {
    too_many.push_back(route(g << 8U, 25, 1));
  }
  EXPECT_FALSE(table.build(too_many));
  EXPECT_EQ(table.size(), Dir24_8Lpm::kMaxGroups + 1);  // unchanged
}

TEST(Dir24_8Lpm, ItHasRoomForExactly32767NextHops) {
  Dir24_8Lpm table;
  for (std::uint32_t i = 1; i <= Dir24_8Lpm::kMaxNextHops; ++i) {
    ASSERT_TRUE(table.add({{ip(10, 0, 0, 0) + (i << 8U), 24}, i, 0})) << i;
  }
  EXPECT_FALSE(table.add({{ip(11, 0, 0, 0), 24}, 0xFFFFFFFFU, 0}));  // a next hop too many
  EXPECT_FALSE(table.lookup(ip(11, 0, 0, 1)).has_value());
  EXPECT_TRUE(table.add({{ip(11, 0, 0, 0), 24}, 1, 0}));  // one it already has: fine
  EXPECT_EQ(table.lookup(ip(11, 0, 0, 1)), (NextHop{1, 0}));
}

}  // namespace
