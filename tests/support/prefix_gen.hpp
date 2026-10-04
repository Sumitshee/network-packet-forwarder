#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <npf/table/fib.hpp>
#include <random>
#include <string>
#include <vector>

namespace npf::test {

// Random route tables for testing the LPM implementations against the oracle (docs/BUILD_PLAN.md
// phase 10). Everything here draws on std::mt19937's raw output alone, never a std::*_distribution,
// whose results differ between standard libraries: a seed reproduces a failure anywhere.

struct RouteOp {
  enum class Kind : std::uint8_t { Add, Remove };
  Kind kind{Kind::Add};
  table::Route route;  // for a Remove, only route.prefix counts
};

inline std::string ip_to_string(std::uint32_t a) {
  return std::format("{}.{}.{}.{}", a >> 24U, a >> 16U & 0xFFU, a >> 8U & 0xFFU, a & 0xFFU);
}

inline std::string to_string(table::Prefix p) {
  return std::format("{}/{}", ip_to_string(p.addr), p.len);
}

// One line per operation, enough to replay a failing case by hand.
inline std::string dump(const std::vector<RouteOp>& ops) {
  std::string out;
  for (const RouteOp& op : ops) {
    if (op.kind == RouteOp::Kind::Add) {
      out += std::format("  add {} via {} port {}\n", to_string(op.route.prefix),
                         ip_to_string(op.route.next_hop), op.route.out_port);
    } else {
      out += std::format("  remove {}\n", to_string(op.route.prefix));
    }
  }
  return out;
}

// std::mt19937 makes 32-bit values, in a result type that is 64 bits wide on Linux.
inline std::uint32_t next32(std::mt19937& rng) {
  return static_cast<std::uint32_t>(rng());
}

inline std::uint32_t below(std::mt19937& rng, std::uint32_t bound) {
  return next32(rng) % bound;
}

inline table::Prefix masked(std::uint32_t addr, std::uint32_t len) {
  const auto l = static_cast<std::uint8_t>(len);
  return {addr & table::prefix_mask(l), l};
}

// n adds of the prefixes that break LPM code, and in a quarter of sets removes interleaved among
// them:
//   - the default route, and prefixes of length 0 and 32;
//   - lengths at and either side of /8, /16 and /24, where shift arithmetic goes wrong, at
//     addresses at the start and the end of their /8 or /16;
//   - prefixes nested in ones already added, /32 host routes in their /24s among them, and runs
//     longer than /24 that share or fill a /24;
//   - the same prefix again, mostly with another next hop: the last one added wins;
//   - removes of prefixes there, already removed, or never added.
// Addresses cluster in a few /8s, because random 32-bit ones would almost never overlap. Next hops
// come from a small pool, so that different prefixes share one, as they do in a real table.
//
// Prefixes shorter than /8 are rare, the default route among them: Dir24_8Lpm writes up to all of
// its 16.7 million entries for each, and a few per set already check their arithmetic, which is
// all that frequency would buy.
inline std::vector<RouteOp> adversarial_prefix_set(std::mt19937& rng, std::size_t n) {
  const bool interleaved = below(rng, 4) == 0;
  const std::array<std::uint32_t, 4> anchors{0x0A000000U, 0xC0A80000U, next32(rng) & 0xFF000000U,
                                             next32(rng)};
  const auto near_anchor = [&] {
    const std::uint32_t a = anchors.at(below(rng, 4));
    switch (below(rng, 4)) {
      case 0:
        return a;  // the start of the /8
      case 1:
        return (a & 0xFF000000U) | 0x00FFFF00U;  // the last /24 of the /8
      case 2:
        return (a & 0xFFFF0000U) | 0x0000FF00U;  // the last /24 of the /16
      default:
        return a ^ (next32(rng) >> (8U + below(rng, 24)));  // somewhere in it
    }
  };
  std::vector<RouteOp> ops;
  std::vector<table::Prefix> added;
  const auto add = [&](table::Prefix p) {
    const std::uint32_t hop = below(rng, 8);
    ops.push_back(
        {RouteOp::Kind::Add, {p, 0x0B000000U + hop, static_cast<std::uint16_t>(hop % 4)}});
    added.push_back(p);
  };
  const auto inside = [&](table::Prefix outer, std::uint32_t len) {
    return masked(outer.addr | (next32(rng) & ~table::prefix_mask(outer.len)), len);
  };
  if (below(rng, 4) == 0) {
    add({0, 0});
  }
  // From /8 to /32, and once in a while from /0 to /7.
  const auto any_length = [&] { return below(rng, 256) == 0 ? below(rng, 8) : 8 + below(rng, 25); };
  constexpr std::array<std::uint32_t, 9> kBoundaries{7, 8, 9, 15, 16, 17, 23, 24, 25};
  std::size_t adds = 0;
  while (adds < n) {
    const table::Prefix some = added.empty()
                                   ? masked(near_anchor(), 16)
                                   : added[below(rng, static_cast<std::uint32_t>(added.size()))];
    switch (below(rng, 10)) {
      case 0:
        add(masked(near_anchor(),
                   kBoundaries.at(below(rng, static_cast<std::uint32_t>(kBoundaries.size())))));
        break;
      case 1:
        add(inside(some, 32));  // a host route, inside a prefix already there
        break;
      case 2:
        add(inside(some, some.len + (some.len < 32 ? 1 + below(rng, 32U - some.len) : 0)));
        break;
      case 3:
        add(some);  // again: most likely with another next hop
        break;
      case 4:  // a /32 at an edge of a /8 or a /16, or the default route
        add(below(rng, 256) == 0 ? table::Prefix{0, 0} : masked(near_anchor(), 32));
        break;
      case 5:  // longer than /24, in a /24 that may already hold some
        add(inside(masked(some.addr, std::min<std::uint32_t>(some.len, 24)), 25 + below(rng, 8)));
        break;
      default:
        add(masked(near_anchor(), any_length()));
        break;
    }
    ++adds;
    if (interleaved && below(rng, 3) == 0) {
      const table::Prefix gone = below(rng, 6) == 0
                                     ? masked(next32(rng), any_length())
                                     : added[below(rng, static_cast<std::uint32_t>(added.size()))];
      ops.push_back({RouteOp::Kind::Remove, {gone, 0, 0}});
    }
  }
  return ops;
}

// n routes shaped roughly like the Internet's table -- most of them /24s, then /22s and /23s, the
// rest shorter, a few longer -- at random addresses, with a handful of next hops. For tests that
// need size, not adversity.
inline std::vector<table::Route> internet_like_routes(std::mt19937& rng, std::size_t n) {
  std::vector<table::Route> routes;
  routes.reserve(n);
  for (std::size_t i = 0; i < n; ++i) {
    const std::uint32_t pick = below(rng, 100);
    const std::uint32_t len = pick < 60   ? 24
                              : pick < 80 ? 22 + below(rng, 2)
                              : pick < 97 ? 16 + below(rng, 6)
                              : pick < 98 ? 8 + below(rng, 8)
                                          : 25 + below(rng, 8);
    const std::uint32_t hop = below(rng, 16);
    routes.push_back(
        {masked(next32(rng), len), 0x0B000000U + hop, static_cast<std::uint16_t>(hop % 4)});
  }
  return routes;
}

// Addresses to look up in a table built from ops: a third anywhere at all, a third inside one of
// its prefixes, and a third at a prefix's first or last address or one beyond either.
inline std::vector<std::uint32_t> probe_keys(std::mt19937& rng, const std::vector<RouteOp>& ops,
                                             std::size_t n) {
  std::vector<std::uint32_t> keys;
  keys.reserve(n);
  for (std::size_t i = 0; i < n; ++i) {
    const table::Prefix p =
        ops.empty() ? table::Prefix{}
                    : ops[below(rng, static_cast<std::uint32_t>(ops.size()))].route.prefix;
    const std::uint32_t first = p.addr;
    const std::uint32_t last = p.addr | ~table::prefix_mask(p.len);
    switch (below(rng, 3)) {
      case 0:
        keys.push_back(next32(rng));
        break;
      case 1:
        keys.push_back(first | (next32(rng) & ~table::prefix_mask(p.len)));
        break;
      default: {
        const std::array<std::uint32_t, 4> edges{first, last, first - 1, last + 1};
        keys.push_back(edges.at(below(rng, 4)));
        break;
      }
    }
  }
  return keys;
}

}  // namespace npf::test
