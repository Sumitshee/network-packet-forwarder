#pragma once

// What the vector sums share once their lanes are added up: the bytes left over, the fold, the
// swap back to wire order (checksum_simd.hpp says why). Private to src/proto.

#include <bit>
#include <cstddef>
#include <cstdint>
#include <npf/core/byte_span.hpp>

namespace npf::proto::lanes {

static_assert(std::endian::native == std::endian::little,
              "the vector sums read words in the CPU's order, and assume it is little-endian");

// The little-endian sum of data[from..], word by word, the odd byte last as a word's low byte.
[[nodiscard]] constexpr std::uint64_t tail_le(core::CBytes data, std::size_t from) noexcept {
  std::uint64_t sum = 0;
  std::size_t i = from;
  for (; i + 1 < data.size(); i += 2) {
    sum += core::rd_le16(data, i);
  }
  if (i < data.size()) {
    sum += core::rd_u8(data, i);
  }
  return sum;
}

// Folds a little-endian sum to 16 bits, and returns it in wire order.
[[nodiscard]] constexpr std::uint16_t fold_and_swap(std::uint64_t sum) noexcept {
  while (sum > 0xFFFFU) {
    sum = (sum & 0xFFFFU) + (sum >> 16U);
  }
  return static_cast<std::uint16_t>((sum << 8U | sum >> 8U) & 0xFFFFU);
}

}  // namespace npf::proto::lanes
