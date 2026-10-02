#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <iterator>
#include <map>
#include <npf/table/fib.hpp>
#include <npf/table/lpm_linear.hpp>
#include <optional>
#include <ostream>
#include <random>
#include <string>
#include <utility>
#include <vector>

#include "support/alloc_counter.hpp"
#include "support/proto_helpers.hpp"

namespace {

std::string dotted(std::uint32_t a) {
  return std::to_string(a >> 24U) + '.' + std::to_string(a >> 16U & 0xFFU) + '.' +
         std::to_string(a >> 8U & 0xFFU) + '.' + std::to_string(a & 0xFFU);
}

}  // namespace

namespace npf::table {

// Found by argument-dependent lookup, so GoogleTest prints "192.0.2.1 port 1", not raw bytes.
void PrintTo(const NextHop& nh, std::ostream* os) {
  *os << dotted(nh.ip) << " port " << nh.port;
}

}  // namespace npf::table

namespace {

using npf::table::Fib;
using npf::table::is_valid;
using npf::table::LinearLpm;
using npf::table::NextHop;
using npf::table::Prefix;
using npf::table::prefix_mask;
using npf::table::Route;
using npf::test::AllocCounter;
using npf::test::ip4;

constexpr NextHop kA{ip4(192, 0, 2, 1), 1};
constexpr NextHop kB{ip4(192, 0, 2, 2), 2};

constexpr Route route(std::uint32_t addr, std::uint8_t len, NextHop via) {
  return {{addr, len}, via.ip, via.port};
}

// --- the mask helper -----------------------------------------------------------------------------

TEST(PrefixMask, IsRightAtEveryLength) {
  for (unsigned len = 0; len <= 32; ++len) {
    // Computed in 64 bits, where neither end of the range is a shift by the operand's full width.
    const auto expected = static_cast<std::uint32_t>(0xFFFF'FFFF'0000'0000ULL >> len);
    EXPECT_EQ(prefix_mask(static_cast<std::uint8_t>(len)), expected) << "/" << len;
  }
}

static_assert(is_valid({0, 0}) && is_valid({ip4(10, 0, 0, 0), 8}) &&
              is_valid({ip4(255, 255, 255, 255), 32}));
static_assert(!is_valid({ip4(10, 0, 0, 1), 8}));  // a host bit set past the length
static_assert(!is_valid({ip4(0, 0, 0, 1), 0}));   // a /0 has no address bits at all
static_assert(!is_valid({0, 33}));

// --- exit test: the table in docs/BUILD_PLAN.md, phase 5 -----------------------------------------

enum class Op : std::uint8_t { Add, Remove };

struct Step {
  Op op;
  Route route;  // a removal uses only the prefix
};

constexpr Step add_route(std::uint32_t addr, std::uint8_t len, NextHop via) {
  return {Op::Add, route(addr, len, via)};
}
constexpr Step remove_prefix(std::uint32_t addr, std::uint8_t len) {
  return {Op::Remove, route(addr, len, {})};
}

struct Probe {
  std::uint32_t dst;
  std::optional<NextHop> expect;
};

struct LpmCase {
  const char* name;
  std::vector<Step> steps;
  std::vector<Probe> probes;
  std::size_t routes_left;
};

void PrintTo(const LpmCase& c, std::ostream* os) {
  *os << c.name;
}

const std::vector<LpmCase> kCases{
    {"DefaultRoute", {add_route(0, 0, kA)}, {{ip4(1, 2, 3, 4), kA}}, 1},
    {"LongerPrefixWins",
     {add_route(ip4(10, 0, 0, 0), 8, kA), add_route(ip4(10, 1, 0, 0), 16, kB)},
     {{ip4(10, 1, 2, 3), kB}},
     2},
    {"ShorterPrefixCatchesTheRest",
     {add_route(ip4(10, 0, 0, 0), 8, kA), add_route(ip4(10, 1, 0, 0), 16, kB)},
     {{ip4(10, 2, 0, 1), kA}},
     2},
    {"HostRouteInsideAPrefix",
     {add_route(ip4(10, 0, 0, 0), 24, kA), add_route(ip4(10, 0, 0, 7), 32, kB)},
     {{ip4(10, 0, 0, 7), kB}},
     2},
    {"PrefixAroundAHostRoute",
     {add_route(ip4(10, 0, 0, 0), 24, kA), add_route(ip4(10, 0, 0, 7), 32, kB)},
     {{ip4(10, 0, 0, 8), kA}},
     2},
    {"EmptyTable", {}, {{ip4(1, 1, 1, 1), std::nullopt}}, 0},
    {"RemovedRoute",
     {add_route(0, 0, kA), remove_prefix(0, 0)},
     {{ip4(1, 1, 1, 1), std::nullopt}},
     0},
    {"ReAddReplacesRatherThanDuplicates",
     {add_route(ip4(10, 0, 0, 0), 8, kA), add_route(ip4(10, 0, 0, 0), 8, kB)},
     {{ip4(10, 1, 1, 1), kB}},
     1},
    {"AllOnesHostRoute",  // no shift UB at length 32
     {add_route(ip4(255, 255, 255, 255), 32, kA)},
     {{ip4(255, 255, 255, 255), kA}, {ip4(255, 255, 255, 254), std::nullopt}},
     1},
    {"ZeroLengthPrefixMatchesAnything",  // no shift UB at length 0
     {add_route(0, 0, kA)},
     {{ip4(0, 0, 0, 0), kA},
      {ip4(10, 0, 0, 1), kA},
      {ip4(127, 0, 0, 1), kA},
      {ip4(255, 255, 255, 255), kA}},
     1},
    // Beyond the table: the order the routes arrive in makes no difference.
    {"LongerPrefixAddedFirstStillWins",
     {add_route(ip4(10, 1, 0, 0), 16, kB), add_route(ip4(10, 0, 0, 0), 8, kA)},
     {{ip4(10, 1, 2, 3), kB}, {ip4(10, 2, 0, 1), kA}},
     2},
};

class LpmTable : public ::testing::TestWithParam<LpmCase> {};

TEST_P(LpmTable, FindsTheLongestMatchingPrefix) {
  const LpmCase& c = GetParam();
  LinearLpm lpm;
  Fib& fib = lpm;  // changed through the interface, the way tests and benchmarks use any FIB
  for (const Step& s : c.steps) {
    if (s.op == Op::Add) {
      ASSERT_TRUE(fib.add(s.route));
    } else {
      ASSERT_TRUE(fib.remove(s.route.prefix));
    }
  }
  EXPECT_EQ(fib.size(), c.routes_left);
  for (const Probe& p : c.probes) {
    EXPECT_EQ(lpm.lookup(p.dst), p.expect) << "lookup(" << dotted(p.dst) << ")";
    EXPECT_EQ(fib.lookup_v(p.dst), p.expect) << "lookup_v(" << dotted(p.dst) << ")";
  }
}

INSTANTIATE_TEST_SUITE_P(ExitTest, LpmTable, ::testing::ValuesIn(kCases),
                         [](const auto& test) { return std::string{test.param.name}; });

// --- the rest of the contract --------------------------------------------------------------------

TEST(LinearLpm, RefusesAnInvalidPrefix) {
  LinearLpm lpm;
  EXPECT_FALSE(lpm.add(route(ip4(10, 0, 0, 1), 8, kA)));  // host bits set
  EXPECT_FALSE(lpm.add(route(0, 33, kA)));                // longer than an address
  EXPECT_EQ(lpm.size(), 0U);
  EXPECT_FALSE(lpm.lookup(ip4(10, 0, 0, 1)).has_value());
}

TEST(LinearLpm, RemoveTakesOnlyTheExactPrefix) {
  LinearLpm lpm;
  ASSERT_TRUE(lpm.add(route(ip4(10, 0, 0, 0), 8, kA)));
  ASSERT_TRUE(lpm.add(route(ip4(10, 1, 0, 0), 16, kB)));
  EXPECT_FALSE(lpm.remove({ip4(10, 0, 0, 0), 9}));  // inside the /8, but not the /8
  EXPECT_FALSE(lpm.remove({ip4(10, 2, 0, 0), 16}));
  EXPECT_EQ(lpm.size(), 2U);
  EXPECT_TRUE(lpm.remove({ip4(10, 1, 0, 0), 16}));
  EXPECT_FALSE(lpm.remove({ip4(10, 1, 0, 0), 16}));  // already gone
  EXPECT_EQ(lpm.size(), 1U);
  EXPECT_EQ(lpm.lookup(ip4(10, 1, 2, 3)), kA);  // the /8 takes over
}

TEST(LinearLpm, ClearEmptiesTheTable) {
  LinearLpm lpm;
  ASSERT_TRUE(lpm.add(route(0, 0, kA)));
  ASSERT_TRUE(lpm.add(route(ip4(10, 0, 0, 0), 8, kB)));
  lpm.clear();
  EXPECT_EQ(lpm.size(), 0U);
  EXPECT_FALSE(lpm.lookup(ip4(10, 0, 0, 1)).has_value());
  ASSERT_TRUE(lpm.add(route(ip4(10, 0, 0, 0), 8, kB)));  // and it is usable afterwards
  EXPECT_EQ(lpm.lookup(ip4(10, 0, 0, 1)), kB);
}

TEST(LinearLpm, ConnectedRouteComesBackWithNextHopZero) {
  LinearLpm lpm;
  ASSERT_TRUE(lpm.add({{ip4(10, 0, 1, 0), 24}, 0, 3}));
  // What was stored, unchanged: turning 0 into the packet's own destination is the caller's job.
  EXPECT_EQ(lpm.lookup(ip4(10, 0, 1, 7)), (NextHop{0, 3}));
}

TEST(LinearLpm, ReportsItsNameAndTheMemoryItHolds) {
  LinearLpm lpm;
  EXPECT_STREQ(lpm.name(), "linear");
  EXPECT_GE(lpm.memory_bytes(), sizeof(LinearLpm));
  for (std::uint32_t i = 0; i < 100; ++i) {
    ASSERT_TRUE(lpm.add(route(ip4(10, i, 0, 0), 16, kA)));
  }
  EXPECT_GE(lpm.memory_bytes(), sizeof(LinearLpm) + (100 * sizeof(Route)));
}

// Longest-prefix match exactly as it is defined, sharing no code with LinearLpm: of the routes
// whose prefix contains dst, the one with the longest prefix.
std::optional<NextHop> longest_match(
    const std::map<std::pair<std::uint32_t, unsigned>, NextHop>& routes, std::uint32_t dst) {
  std::optional<NextHop> best;
  int best_len = -1;
  for (const auto& [prefix, next_hop] : routes) {
    const auto& [addr, len] = prefix;
    // The leading len bits agree. In 64 bits, so that len 0, a shift by 32, is well defined.
    const bool contains = (std::uint64_t{dst ^ addr} >> (32U - len)) == 0;
    if (contains && static_cast<int>(len) > best_len) {
      best = next_hop;
      best_len = static_cast<int>(len);
    }
  }
  return best;
}

TEST(LinearLpm, AgreesWithTheDefinitionOfLongestPrefixMatch) {
  std::mt19937 rng(5);
  const auto random32 = [&rng] { return static_cast<std::uint32_t>(rng()); };
  // Prefixes inside 10.0.0.0/8 nest and overlap, which is where an ordering mistake would show.
  const auto random_prefix = [&random32] {
    const auto len = static_cast<std::uint8_t>(random32() % 33);
    return Prefix{(ip4(10, 0, 0, 0) | (random32() & 0x00FF'FFFFU)) & prefix_mask(len), len};
  };
  LinearLpm lpm;
  std::map<std::pair<std::uint32_t, unsigned>, NextHop> model;
  const auto some_route = [&] {
    return std::next(model.begin(), static_cast<std::ptrdiff_t>(random32() % model.size()))->first;
  };

  for (int step = 1; step <= 2000; ++step) {
    if (random32() % 4 == 0 && !model.empty()) {
      // Half the time a prefix the table holds, half the time one it probably does not.
      Prefix p = random_prefix();
      if (random32() % 2 == 0) {
        const auto [addr, len] = some_route();
        p = {addr, static_cast<std::uint8_t>(len)};
      }
      const bool present = model.erase({p.addr, p.len}) == 1;
      ASSERT_EQ(lpm.remove(p), present) << "step " << step;
    } else {
      const Prefix p = random_prefix();
      const NextHop nh{random32(), static_cast<std::uint16_t>(random32())};
      model[{p.addr, p.len}] = nh;
      ASSERT_TRUE(lpm.add({p, nh.ip, nh.port})) << "step " << step;
    }
    ASSERT_EQ(lpm.size(), model.size()) << "step " << step;

    if (step % 100 == 0) {
      for (int i = 0; i < 300; ++i) {
        std::uint32_t dst = random32();  // anywhere
        if (i % 3 == 1) {
          dst = ip4(10, 0, 0, 0) | (dst & 0x00FF'FFFFU);  // inside the /8
        } else if (i % 3 == 2 && !model.empty()) {
          const auto [addr, len] = some_route();  // inside a route, however long its prefix
          dst = addr | (dst & ~prefix_mask(static_cast<std::uint8_t>(len)));
        }
        ASSERT_EQ(lpm.lookup(dst), longest_match(model, dst))
            << "step " << step << ", " << dotted(dst);
      }
    }
  }
}

// CLAUDE.md rule 4. The datapath calls lookup() for every packet.
TEST(LinearLpm, LookupNeverAllocates) {
  LinearLpm lpm;
  ASSERT_TRUE(lpm.add(route(0, 0, kA)));
  for (std::uint32_t i = 0; i < 256; ++i) {
    ASSERT_TRUE(lpm.add(route(ip4(10, i, 0, 0), 16, kB)));
  }
  AllocCounter::reset();
  std::size_t via_b = 0;
  for (std::uint32_t i = 0; i < 100'000; ++i) {
    // Multiplying by an odd constant spreads consecutive i over the whole address space.
    via_b += lpm.lookup(i * 2'654'435'761U) == kB ? 1U : 0U;
  }
  EXPECT_EQ(AllocCounter::allocations(), 0U);
  EXPECT_EQ(AllocCounter::deallocations(), 0U);
  EXPECT_GT(via_b, 0U);  // some lookups really did reach the /16s

  // That zero means something only if this binary counts allocations: a growing table makes one.
  LinearLpm fresh;
  AllocCounter::reset();
  ASSERT_TRUE(fresh.add(route(0, 0, kA)));
  EXPECT_GT(AllocCounter::allocations(), 0U);
}

}  // namespace
