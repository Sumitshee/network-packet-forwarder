#pragma once

#include <cstddef>
#include <cstdint>
#include <npf/table/fib.hpp>
#include <optional>
#include <span>
#include <vector>

namespace npf::table {

// DIR-24-8 (Gupta, Lin and McKeown, 1998): the address's top 24 bits index a table of 2^24 two-byte
// entries, so a match of /24 or shorter takes one load, and a longer one a second load from a group
// of 256 entries for that /24.
//
//   tbl24     2^24 x uint16_t = 32 MiB, indexed by dst >> 8
//             bit 15 clear: the low 15 bits are a next-hop id (0: no route)
//             bit 15 set:   the low 15 bits are a group in tbl_long
//   tbl_long  groups of 256 x uint16_t, indexed by (group << 8) | (dst & 0xFF); next-hop ids only
//
// Next-hop ids index a small vector of NextHop, so the big tables stay two bytes an entry. 15 bits
// name 32,767 next hops and 32,768 groups: a change that needs more fails, changing nothing.
//
// Writing a prefix must not overwrite what a longer one wrote. build() avoids it by writing the
// shortest prefixes first, so the longer ones overwrite them: fast, and nothing extra to keep, but
// only for a whole table at once. add() and remove() keep, for every entry, the length of the
// prefix it came from, and only write over an equal or shorter one: a byte an entry, 16 MiB more,
// made the first time either is called. A removed prefix's entries go to the longest remaining
// prefix that covers it, found in a sorted list of the routes kept alongside -- off the hot path.
// Ids are not reclaimed when the last route using one goes; the groups of tbl_long are.
class Dir24_8Lpm final : public Fib {
 public:
  static constexpr std::size_t kMaxNextHops = 0x7FFF;  // ids 1 to 32,767
  static constexpr std::size_t kMaxGroups = 0x8000;    // groups 0 to 32,767

  Dir24_8Lpm();  // allocates tbl24: 32 MiB, every entry written

  bool add(const Route& route) override;
  bool remove(Prefix prefix) override;
  void clear() override;

  // Replaces every route with these, shortest prefix first; a later route for a prefix wins, as
  // with add(). Frees the length tables, if add() or remove() had made them. False, changing
  // nothing, if a prefix is invalid or the routes need more next hops or groups than there are.
  bool build(std::span<const Route> routes);

  [[nodiscard]] std::optional<NextHop> lookup(std::uint32_t dst) const noexcept {
    std::uint16_t e = tbl24_[dst >> 8U];
    if ((e & kGroupBit) != 0) [[unlikely]] {
      e = tbl_long_[(static_cast<std::size_t>(e & kIdMask) << 8U) | (dst & 0xFFU)];
    }
    return e == kNoRoute ? std::nullopt : std::optional<NextHop>{nexthops_[e]};
  }
  [[nodiscard]] std::optional<NextHop> lookup_v(std::uint32_t dst) const noexcept override {
    return lookup(dst);
  }
  [[nodiscard]] std::size_t size() const noexcept override { return routes_.size(); }
  [[nodiscard]] std::size_t memory_bytes() const noexcept override;
  [[nodiscard]] const char* name() const noexcept override { return "dir24_8"; }

  // Groups of tbl_long holding a /24's longer prefixes now; for tests.
  [[nodiscard]] std::size_t groups_in_use() const noexcept { return groups_ - free_groups_.size(); }

 private:
  static constexpr std::size_t kTbl24Size = std::size_t{1} << 24U;
  static constexpr std::size_t kGroupSize = 256;
  static constexpr std::uint16_t kGroupBit = 0x8000;
  static constexpr std::uint16_t kIdMask = 0x7FFF;
  static constexpr std::uint16_t kNoRoute = 0;  // nexthops_[0] is a placeholder, never returned

  [[nodiscard]] std::optional<std::uint16_t> find_id(const NextHop& hop) const;
  [[nodiscard]] std::optional<std::uint16_t> id_for(const NextHop& hop);
  [[nodiscard]] std::vector<Route>::const_iterator find_route(Prefix p) const;
  [[nodiscard]] bool can_take(Prefix p) const;
  std::uint16_t group_for(std::size_t block);
  void ensure_lengths();
  // What an entry holds -- a next-hop id -- and, for add() and remove(), the length of the prefix
  // that wrote it.
  struct Owner {
    std::uint16_t id{kNoRoute};
    std::uint8_t len{0};
  };
  // Whether a write passes over what longer prefixes wrote. build() writes the shortest prefixes
  // first, and so may overwrite everything; add() must keep what longer ones wrote.
  enum class Over : std::uint8_t { Everything, ShorterOnly };

  void write(Prefix p, Owner owner, Over over);
  void rewrite_owned(Prefix p, Owner next);
  void collapse_if_short(std::size_t block);

  std::vector<std::uint16_t> tbl24_;
  std::vector<std::uint16_t> tbl_long_;
  std::vector<NextHop> nexthops_;         // by id
  std::vector<std::uint16_t> hop_order_;  // ids sorted by their NextHop, to find a hop's id
  std::vector<Route> routes_;             // one per prefix, sorted by length, then address
  // The lengths add() and remove() need: of the prefix each entry's value came from. Empty until
  // the first call to either.
  std::vector<std::uint8_t> len24_;
  std::vector<std::uint8_t> len_long_;
  std::vector<std::uint16_t> free_groups_;  // groups given back, for reuse
  std::size_t groups_{0};                   // groups in tbl_long_, in use or free
};

}  // namespace npf::table
