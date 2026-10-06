#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <npf/proto/mac.hpp>
#include <optional>
#include <vector>

namespace npf::table {

// ARCHITECTURE.md §7: the port each station was last heard on, for the L2 path.
//
// Open addressing with linear probing, over a power-of-two array of entries stored inline, so
// learning or looking up a MAC is a multiply and a scan of a few adjacent slots, and never an
// allocation. Not std::unordered_map: it allocates a node per entry, so learning a new station
// would allocate on the datapath, and every lookup would chase a pointer to wherever that node was
// put.
//
// A MAC is kept at most kWindow slots past its home, the slot its hash names. When those slots are
// all taken by other MACs, learning a new one evicts the entry among them heard from longest ago,
// rather than fail: a full switch keeps learning the stations that are talking now. Removing an
// entry moves the later entries of its run back into the gap, so a run never has a hole in it, and
// a lookup can stop at the first empty slot.
class MacTable {
 public:
  using TimePoint = std::chrono::steady_clock::time_point;

  static constexpr std::size_t kWindow = 16;

  // capacity is rounded up to a power of two, and to at least kWindow.
  explicit MacTable(std::size_t capacity, std::chrono::seconds max_age = std::chrono::seconds{300});

  // src was heard on port at now.
  void learn(proto::MacAddr src, std::uint16_t port, TimePoint now) noexcept;
  [[nodiscard]] std::optional<std::uint16_t> lookup(proto::MacAddr dst) const noexcept;
  // Removes every entry last heard more than max_age before now.
  void age(TimePoint now) noexcept;

  [[nodiscard]] std::size_t size() const noexcept { return size_; }
  [[nodiscard]] std::size_t capacity() const noexcept { return slots_.size(); }
  [[nodiscard]] std::chrono::seconds max_age() const noexcept { return max_age_; }

  struct Station {
    proto::MacAddr mac;
    std::uint16_t port{0};
    TimePoint last_seen;
  };
  // Every entry, in no particular order: for npf show mac, never the datapath, as it allocates.
  [[nodiscard]] std::vector<Station> list() const;

 private:
  struct Slot {
    proto::MacAddr mac{};
    std::uint16_t port{0};
    bool used{false};
    TimePoint last_seen;
  };

  [[nodiscard]] std::size_t home(proto::MacAddr mac) const noexcept;
  void remove(std::size_t gap) noexcept;

  std::vector<Slot> slots_;  // allocated once
  std::size_t mask_;         // capacity - 1
  unsigned shift_;           // 64 - log2(capacity): the hash is the product's top bits
  std::chrono::seconds max_age_;
  std::size_t size_{0};
};

}  // namespace npf::table
