#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <npf/proto/mac.hpp>
#include <optional>

namespace npf::table {

// ARCHITECTURE.md §7. PHASE 6 STUB: phase 12 fills it in -- open-addressed, linear probing,
// power-of-two capacity, entries stored inline. Until then it learns nothing and knows nothing,
// so a frame on a bridged port always misses and is dropped as UnknownDestPort.
//
// NOLINTBEGIN(readability-convert-member-functions-to-static): the final, non-static signatures
class MacTable {
 public:
  explicit MacTable([[maybe_unused]] std::size_t capacity) noexcept {}
  void learn([[maybe_unused]] proto::MacAddr src, [[maybe_unused]] std::uint16_t port,
             [[maybe_unused]] std::chrono::steady_clock::time_point now) noexcept {}
  [[nodiscard]] std::optional<std::uint16_t> lookup(
      [[maybe_unused]] proto::MacAddr dst) const noexcept {
    return std::nullopt;
  }
  void age([[maybe_unused]] std::chrono::steady_clock::time_point now) noexcept {}  // default 300 s
  [[nodiscard]] std::size_t size() const noexcept { return 0; }
};
// NOLINTEND(readability-convert-member-functions-to-static)

}  // namespace npf::table
