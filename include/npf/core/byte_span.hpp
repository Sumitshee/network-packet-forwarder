#pragma once

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>

namespace npf::core {

using CBytes = std::span<const std::byte>;
using Bytes = std::span<std::byte>;

// Wire-format access, one byte at a time. A packet buffer carries no alignment guarantee for
// uint16_t or uint32_t, and reading one through a cast pointer is also undefined behaviour under
// strict aliasing; assembling the value from bytes is neither.
//
// Values are host order; the wire is big-endian. Callers validate lengths once, in a view's
// parse() factory, so these only assert them, in debug builds.

[[nodiscard]] constexpr std::uint8_t rd_u8(CBytes b, std::size_t off) noexcept {
  assert(off < b.size());
  return std::to_integer<std::uint8_t>(b[off]);
}

[[nodiscard]] constexpr std::uint16_t rd_be16(CBytes b, std::size_t off) noexcept {
  assert(off <= b.size() && b.size() - off >= 2);
  return static_cast<std::uint16_t>(std::to_integer<std::uint16_t>(b[off]) << 8U |
                                    std::to_integer<std::uint16_t>(b[off + 1]));
}

[[nodiscard]] constexpr std::uint32_t rd_be32(CBytes b, std::size_t off) noexcept {
  assert(off <= b.size() && b.size() - off >= 4);
  return std::to_integer<std::uint32_t>(b[off]) << 24U |
         std::to_integer<std::uint32_t>(b[off + 1]) << 16U |
         std::to_integer<std::uint32_t>(b[off + 2]) << 8U |
         std::to_integer<std::uint32_t>(b[off + 3]);
}

constexpr void wr_u8(Bytes b, std::size_t off, std::uint8_t v) noexcept {
  assert(off < b.size());
  b[off] = std::byte{v};
}

constexpr void wr_be16(Bytes b, std::size_t off, std::uint16_t v) noexcept {
  assert(off <= b.size() && b.size() - off >= 2);
  b[off] = static_cast<std::byte>(v >> 8U);
  b[off + 1] = static_cast<std::byte>(v & 0xFFU);
}

constexpr void wr_be32(Bytes b, std::size_t off, std::uint32_t v) noexcept {
  assert(off <= b.size() && b.size() - off >= 4);
  b[off] = static_cast<std::byte>(v >> 24U);
  b[off + 1] = static_cast<std::byte>(v >> 16U & 0xFFU);
  b[off + 2] = static_cast<std::byte>(v >> 8U & 0xFFU);
  b[off + 3] = static_cast<std::byte>(v & 0xFFU);
}

// Evaluated by the compiler in every translation unit that includes this header: proves the
// helpers work at compile time and fails the build on a byte-order mistake without running
// anything.
static_assert([] {
  std::array<std::byte, 4> buf{std::byte{0x12}, std::byte{0x34}, std::byte{0x56}, std::byte{0x78}};
  return rd_be16(buf, 0) == 0x1234 && rd_be32(buf, 0) == 0x12345678U;
}());

}  // namespace npf::core
