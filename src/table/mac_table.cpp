#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <npf/proto/mac.hpp>
#include <npf/table/mac_table.hpp>
#include <optional>
#include <vector>

namespace npf::table {
namespace {

std::size_t rounded(std::size_t capacity) {
  return std::bit_ceil(capacity < MacTable::kWindow ? MacTable::kWindow : capacity);
}

}  // namespace

MacTable::MacTable(std::size_t capacity, std::chrono::seconds max_age)
    : slots_(rounded(capacity)),
      mask_{slots_.size() - 1},
      shift_{64U - static_cast<unsigned>(std::countr_zero(slots_.size()))},
      max_age_{max_age} {}

// Multiply-shift: the 48 bits of the MAC times an odd constant, keeping the product's top bits.
// The top bits are the ones every bit of the MAC has a hand in, so MACs that differ only in their
// last octet, as one vendor's often do, still land far apart.
std::size_t MacTable::home(proto::MacAddr mac) const noexcept {
  std::uint64_t key = 0;
  for (const std::uint8_t octet : mac.b) {
    key = key << 8U | octet;
  }
  return static_cast<std::size_t>((key * 0x9E3779B97F4A7C15ULL) >> shift_);
}

void MacTable::learn(proto::MacAddr src, std::uint16_t port, TimePoint now) noexcept {
  const std::size_t h = home(src);
  std::size_t oldest = h;
  for (std::size_t k = 0; k < kWindow; ++k) {
    Slot& s = slots_[(h + k) & mask_];
    if (!s.used) {  // a run has no holes: src is not further on
      s = Slot{.mac = src, .port = port, .used = true, .last_seen = now};
      ++size_;
      return;
    }
    if (s.mac == src) {
      s.port = port;  // it may have moved
      s.last_seen = now;
      return;
    }
    if (s.last_seen < slots_[oldest].last_seen) {
      oldest = (h + k) & mask_;
    }
  }
  // Every slot src may use holds another MAC: the one heard from longest ago makes room.
  slots_[oldest] = Slot{.mac = src, .port = port, .used = true, .last_seen = now};
}

std::optional<std::uint16_t> MacTable::lookup(proto::MacAddr dst) const noexcept {
  const std::size_t h = home(dst);
  for (std::size_t k = 0; k < kWindow; ++k) {
    const Slot& s = slots_[(h + k) & mask_];
    if (!s.used) {
      return std::nullopt;
    }
    if (s.mac == dst) {
      return s.port;
    }
  }
  return std::nullopt;
}

// Empties the slot, then walks the rest of its run moving back into the gap each entry that may
// go there: one whose home is not between the gap and where it is now. Entries only ever move
// nearer their home, so each stays within kWindow of it. The walk ends at an empty slot, which the
// gap itself is if the table was full.
void MacTable::remove(std::size_t gap) noexcept {
  slots_[gap].used = false;
  --size_;
  for (std::size_t j = (gap + 1) & mask_; slots_[j].used; j = (j + 1) & mask_) {
    const std::size_t k = home(slots_[j].mac);
    const bool home_after_gap = gap <= j ? (gap < k && k <= j) : (gap < k || k <= j);
    if (!home_after_gap) {
      slots_[gap] = slots_[j];
      slots_[j].used = false;
      gap = j;
    }
  }
}

void MacTable::age(TimePoint now) noexcept {
  for (std::size_t i = 0; i < slots_.size(); ++i) {
    // remove() may move a later entry into slot i, which has to be looked at in its turn. It never
    // moves one not yet looked at into a slot before i.
    while (slots_[i].used && now - slots_[i].last_seen > max_age_) {
      remove(i);
    }
  }
}

std::vector<MacTable::Station> MacTable::list() const {
  std::vector<Station> out;
  out.reserve(size_);
  for (const Slot& s : slots_) {
    if (s.used) {
      out.push_back({s.mac, s.port, s.last_seen});
    }
  }
  return out;
}

}  // namespace npf::table
