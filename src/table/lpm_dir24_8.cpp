#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <npf/table/fib.hpp>
#include <npf/table/lpm_dir24_8.hpp>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace npf::table {
namespace {

bool hop_less(const NextHop& a, const NextHop& b) noexcept {
  return a.ip != b.ip ? a.ip < b.ip : a.port < b.port;
}

// The order routes_ keeps: by length, then by address, which is also the order build() writes in.
bool prefix_less(const Prefix& a, const Prefix& b) noexcept {
  return a.len != b.len ? a.len < b.len : a.addr < b.addr;
}

NextHop hop_of(const Route& r) noexcept {
  return {r.next_hop, r.out_port};
}

// Consecutive entries of one group of tbl_long: where they start in it, and how many.
struct Run {
  std::size_t first;
  std::size_t count;
};

template <class T>
std::size_t bytes(const std::vector<T>& v) noexcept {
  return v.capacity() * sizeof(T);
}

template <class T>
void release(std::vector<T>& v) noexcept {
  std::vector<T>().swap(v);
}

}  // namespace

Dir24_8Lpm::Dir24_8Lpm() : tbl24_(kTbl24Size, kNoRoute), nexthops_(1) {}

std::optional<std::uint16_t> Dir24_8Lpm::find_id(const NextHop& hop) const {
  const auto it = std::ranges::lower_bound(hop_order_, hop, hop_less,
                                           [this](std::uint16_t id) { return nexthops_[id]; });
  if (it != hop_order_.end() && nexthops_[*it] == hop) {
    return *it;
  }
  return std::nullopt;
}

std::optional<std::uint16_t> Dir24_8Lpm::id_for(const NextHop& hop) {
  const auto it = std::ranges::lower_bound(hop_order_, hop, hop_less,
                                           [this](std::uint16_t id) { return nexthops_[id]; });
  if (it != hop_order_.end() && nexthops_[*it] == hop) {
    return *it;
  }
  if (nexthops_.size() - 1 == kMaxNextHops) {
    return std::nullopt;
  }
  const auto id = static_cast<std::uint16_t>(nexthops_.size());
  nexthops_.push_back(hop);
  hop_order_.insert(it, id);
  return id;
}

std::vector<Route>::const_iterator Dir24_8Lpm::find_route(Prefix p) const {
  const auto it = std::ranges::lower_bound(routes_, p, prefix_less, &Route::prefix);
  return it != routes_.end() && it->prefix == p ? it : routes_.end();
}

// A prefix longer than /24 needs a group, unless its /24 already has one.
bool Dir24_8Lpm::can_take(Prefix p) const {
  return p.len <= 24 || (tbl24_[p.addr >> 8U] & kGroupBit) != 0 || !free_groups_.empty() ||
         groups_ < kMaxGroups;
}

// The /24's group, made if it has none: 256 entries, each holding what the single entry held.
std::uint16_t Dir24_8Lpm::group_for(std::size_t block) {
  const std::uint16_t entry = tbl24_[block];
  if ((entry & kGroupBit) != 0) {
    return entry & kIdMask;
  }
  std::uint16_t g = 0;
  if (!free_groups_.empty()) {
    g = free_groups_.back();
    free_groups_.pop_back();
  } else {
    assert(groups_ < kMaxGroups && "can_take() said there was room");
    g = static_cast<std::uint16_t>(groups_++);
    tbl_long_.resize(groups_ * kGroupSize);
    if (!len24_.empty()) {
      len_long_.resize(groups_ * kGroupSize);
    }
  }
  const std::size_t first = std::size_t{g} * kGroupSize;
  std::ranges::fill(std::span(tbl_long_).subspan(first, kGroupSize), entry);
  if (!len24_.empty()) {
    std::ranges::fill(std::span(len_long_).subspan(first, kGroupSize), len24_[block]);
  }
  tbl24_[block] = static_cast<std::uint16_t>(kGroupBit | g);
  return g;
}

// Writes owner.id into every entry p covers -- with Over::ShorterOnly, as add() calls it, only
// those no longer prefix wrote -- and records owner.len as its length, if there are length tables.
void Dir24_8Lpm::write(Prefix p, Owner owner, Over over) {
  const bool lengths = !len24_.empty();
  const bool keep_longer = over == Over::ShorterOnly;
  const auto write_group = [&](std::uint16_t g, Run run) {
    for (std::size_t j = run.first; j < run.first + run.count; ++j) {
      const std::size_t k = (std::size_t{g} << 8U) | j;
      if (!keep_longer || len_long_[k] <= owner.len) {
        tbl_long_[k] = owner.id;
        if (lengths) {
          len_long_[k] = owner.len;
        }
      }
    }
  };
  if (p.len <= 24) {
    const std::size_t first = p.addr >> 8U;
    const std::size_t end = first + (std::size_t{1} << (24U - p.len));
    for (std::size_t i = first; i < end; ++i) {
      if ((tbl24_[i] & kGroupBit) != 0) {
        write_group(tbl24_[i] & kIdMask, Run{0, kGroupSize});
      } else if (!keep_longer || len24_[i] <= owner.len) {
        tbl24_[i] = owner.id;
        if (lengths) {
          len24_[i] = owner.len;
        }
      }
    }
    return;
  }
  const std::uint16_t g = group_for(p.addr >> 8U);
  write_group(g, Run{p.addr & 0xFFU, std::size_t{1} << (32U - p.len)});
}

// For remove(): every entry p wrote -- its recorded length is p's, and no other prefix of that
// length overlaps p -- goes to `next`, what covers p now.
void Dir24_8Lpm::rewrite_owned(Prefix p, Owner next) {
  const auto rewrite_group = [&](std::uint16_t g, Run run) {
    for (std::size_t j = run.first; j < run.first + run.count; ++j) {
      const std::size_t k = (std::size_t{g} << 8U) | j;
      if (len_long_[k] == p.len) {
        tbl_long_[k] = next.id;
        len_long_[k] = next.len;
      }
    }
  };
  if (p.len <= 24) {
    const std::size_t first = p.addr >> 8U;
    const std::size_t end = first + (std::size_t{1} << (24U - p.len));
    for (std::size_t i = first; i < end; ++i) {
      if ((tbl24_[i] & kGroupBit) != 0) {
        rewrite_group(tbl24_[i] & kIdMask, Run{0, kGroupSize});
      } else if (len24_[i] == p.len) {
        tbl24_[i] = next.id;
        len24_[i] = next.len;
      }
    }
    return;
  }
  const std::uint16_t entry = tbl24_[p.addr >> 8U];
  assert((entry & kGroupBit) != 0 && "a prefix longer than /24 has a group");
  rewrite_group(entry & kIdMask, Run{p.addr & 0xFFU, std::size_t{1} << (32U - p.len)});
}

// A group with nothing longer than /24 left in it holds one value 256 times: tbl24 can hold it
// again, and the group can go back for reuse.
void Dir24_8Lpm::collapse_if_short(std::size_t block) {
  const std::uint16_t entry = tbl24_[block];
  if ((entry & kGroupBit) == 0) {
    return;
  }
  const std::size_t first = static_cast<std::size_t>(entry & kIdMask) * kGroupSize;
  const std::span<const std::uint8_t> lens = std::span(len_long_).subspan(first, kGroupSize);
  if (std::ranges::any_of(lens, [](std::uint8_t l) { return l > 24; })) {
    return;
  }
  tbl24_[block] = tbl_long_[first];
  len24_[block] = lens.front();
  free_groups_.push_back(entry & kIdMask);
}

// The length tables, built the first time add() or remove() needs them: replaying the routes
// shortest first, as build() wrote them, records the length of the route each entry came from.
void Dir24_8Lpm::ensure_lengths() {
  if (!len24_.empty()) {
    return;
  }
  len24_.assign(kTbl24Size, 0);
  len_long_.assign(tbl_long_.size(), 0);
  for (const Route& r : routes_) {
    const Prefix p = r.prefix;
    if (p.len <= 24) {
      const std::size_t first = p.addr >> 8U;
      const std::size_t end = first + (std::size_t{1} << (24U - p.len));
      for (std::size_t i = first; i < end; ++i) {
        len24_[i] = p.len;
        if ((tbl24_[i] & kGroupBit) != 0) {
          const std::size_t group = static_cast<std::size_t>(tbl24_[i] & kIdMask) * kGroupSize;
          std::ranges::fill(std::span(len_long_).subspan(group, kGroupSize), p.len);
        }
      }
    } else {
      assert((tbl24_[p.addr >> 8U] & kGroupBit) != 0 && "a prefix longer than /24 has a group");
      const std::size_t group =
          static_cast<std::size_t>(tbl24_[p.addr >> 8U] & kIdMask) * kGroupSize;
      const std::size_t count = std::size_t{1} << (32U - p.len);
      std::ranges::fill(std::span(len_long_).subspan(group + (p.addr & 0xFFU), count), p.len);
    }
  }
}

bool Dir24_8Lpm::add(const Route& route) {
  const Prefix p = route.prefix;
  // Everything that can fail is checked before anything changes.
  if (!is_valid(p) || !can_take(p)) {
    return false;
  }
  const std::optional<std::uint16_t> id = id_for(hop_of(route));
  if (!id) {
    return false;
  }
  ensure_lengths();
  const auto at = std::ranges::lower_bound(routes_, p, prefix_less, &Route::prefix);
  if (at != routes_.end() && at->prefix == p) {
    *at = route;
  } else {
    routes_.insert(at, route);
  }
  write(p, Owner{*id, p.len}, Over::ShorterOnly);
  return true;
}

bool Dir24_8Lpm::remove(Prefix prefix) {
  if (!is_valid(prefix)) {
    return false;
  }
  const auto at = find_route(prefix);
  if (at == routes_.end()) {
    return false;
  }
  ensure_lengths();
  routes_.erase(at);
  // Its entries go to the longest remaining route that covers it, if there is one.
  Owner next;
  for (std::uint8_t l = prefix.len; l-- > 0;) {
    const auto cover = find_route(Prefix{prefix.addr & prefix_mask(l), l});
    if (cover == routes_.end()) {
      continue;
    }
    const std::optional<std::uint16_t> cover_id = find_id(hop_of(*cover));
    assert(cover_id && "every route's next hop has an id");
    next = Owner{cover_id.value_or(kNoRoute), l};
    break;
  }
  rewrite_owned(prefix, next);
  if (prefix.len > 24) {
    collapse_if_short(prefix.addr >> 8U);
  }
  return true;
}

// Like a vector's clear(): every route goes, but the memory stays, for the routes to come. A table
// cleared and filled again does not pay to allocate its 32 MiB, and the page faults, a second time.
void Dir24_8Lpm::clear() {
  std::ranges::fill(tbl24_, kNoRoute);
  tbl_long_.clear();
  nexthops_.resize(1);
  hop_order_.clear();
  routes_.clear();
  std::ranges::fill(len24_, 0);  // still right, if there are length tables: an empty table's are 0
  len_long_.clear();
  free_groups_.clear();
  groups_ = 0;
}

bool Dir24_8Lpm::build(std::span<const Route> routes) {
  if (!std::ranges::all_of(routes, [](const Route& r) { return is_valid(r.prefix); })) {
    return false;
  }
  // Shortest first and, for one prefix, in the order given, so that the last of them can win.
  std::vector<Route> sorted(routes.begin(), routes.end());
  std::ranges::stable_sort(sorted, prefix_less, &Route::prefix);
  std::vector<Route> unique;
  unique.reserve(sorted.size());
  for (std::size_t i = 0; i < sorted.size(); ++i) {
    if (i + 1 == sorted.size() || sorted[i + 1].prefix != sorted[i].prefix) {
      unique.push_back(sorted[i]);
    }
  }
  // What they need of the 15-bit ids, checked before anything changes.
  std::vector<NextHop> hops;
  hops.reserve(unique.size());
  std::vector<std::uint32_t> blocks;  // each /24 holding a longer prefix needs a group
  for (const Route& r : unique) {
    hops.push_back(hop_of(r));
    if (r.prefix.len > 24) {
      blocks.push_back(r.prefix.addr >> 8U);
    }
  }
  std::ranges::sort(hops, hop_less);
  const auto [hops_end, hops_last] = std::ranges::unique(hops);
  hops.erase(hops_end, hops_last);
  std::ranges::sort(blocks);
  const auto [blocks_end, blocks_last] = std::ranges::unique(blocks);
  if (hops.size() > kMaxNextHops ||
      static_cast<std::size_t>(blocks_end - blocks.begin()) > kMaxGroups) {
    return false;
  }

  clear();
  release(len24_);  // build() does not keep lengths: the next add() or remove() makes them anew
  release(len_long_);
  // Ids in next-hop order, so hop_order_ is sorted from the start.
  nexthops_.insert(nexthops_.end(), hops.begin(), hops.end());
  hop_order_.resize(hops.size());
  for (std::size_t i = 0; i < hops.size(); ++i) {
    hop_order_[i] = static_cast<std::uint16_t>(i + 1);
  }
  for (const Route& r : unique) {
    const auto at = std::ranges::lower_bound(hops, hop_of(r), hop_less);
    const auto id = static_cast<std::uint16_t>(at - hops.begin() + 1);
    write(r.prefix, Owner{id, r.prefix.len}, Over::Everything);
  }
  routes_ = std::move(unique);
  routes_.shrink_to_fit();
  tbl_long_.shrink_to_fit();
  nexthops_.shrink_to_fit();
  hop_order_.shrink_to_fit();
  free_groups_.shrink_to_fit();
  return true;
}

std::size_t Dir24_8Lpm::memory_bytes() const noexcept {
  // Every allocation, spare capacity included, as LinearLpm counts its own.
  return sizeof(*this) + bytes(tbl24_) + bytes(tbl_long_) + bytes(nexthops_) + bytes(hop_order_) +
         bytes(routes_) + bytes(len24_) + bytes(len_long_) + bytes(free_groups_);
}

}  // namespace npf::table
