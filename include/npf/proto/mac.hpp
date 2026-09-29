#pragma once

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <npf/core/byte_span.hpp>

namespace npf::proto {

struct MacAddr {
  std::array<std::uint8_t, 6> b{};

  [[nodiscard]] constexpr bool is_broadcast() const noexcept {  // ff:ff:ff:ff:ff:ff
    return std::ranges::all_of(b, [](std::uint8_t octet) { return octet == 0xFF; });
  }
  // The group bit is the low bit of the first octet, so broadcast is multicast too.
  [[nodiscard]] constexpr bool is_multicast() const noexcept { return (b[0] & 0x01U) != 0; }
  [[nodiscard]] constexpr bool is_zero() const noexcept {
    return std::ranges::all_of(b, [](std::uint8_t octet) { return octet == 0; });
  }
  friend bool operator==(const MacAddr&, const MacAddr&) noexcept = default;
};

inline constexpr MacAddr kBroadcastMac{{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};

// Byte at a time, like the integer helpers in core/byte_span.hpp. The caller has validated that
// six bytes are there; this only asserts it, in debug builds.
[[nodiscard]] constexpr MacAddr rd_mac(core::CBytes b, std::size_t off) noexcept {
  assert(off <= b.size() && b.size() - off >= 6);
  MacAddr m;
  std::ranges::transform(b.subspan(off, m.b.size()), m.b.begin(),
                         [](std::byte octet) { return std::to_integer<std::uint8_t>(octet); });
  return m;
}

constexpr void wr_mac(core::Bytes b, std::size_t off, const MacAddr& m) noexcept {
  assert(off <= b.size() && b.size() - off >= 6);
  std::ranges::transform(m.b, b.subspan(off, m.b.size()).begin(),
                         [](std::uint8_t octet) { return std::byte{octet}; });
}

}  // namespace npf::proto
