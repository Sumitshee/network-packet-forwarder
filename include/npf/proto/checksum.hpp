#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <npf/core/byte_span.hpp>

namespace npf::proto {

// The Internet checksum (RFC 1071) is the one's complement of the one's complement sum of the data,
// read as big-endian 16-bit words, with an odd trailing byte padded by a zero.
//
// checksum_reference() and ones_complement_sum() compute the same thing, the sum, and must agree
// exactly on every input: the first is the oracle the tests hold the second to.

// 1. Reference: byte at a time, obviously correct. Never optimise it -- its only job is to be
//    trusted.
[[nodiscard]] constexpr std::uint16_t checksum_reference(core::CBytes data) noexcept {
  std::uint64_t sum = 0;
  for (std::size_t i = 0; i < data.size(); ++i) {
    const auto octet = std::to_integer<std::uint64_t>(data[i]);
    sum += i % 2 == 0 ? octet << 8U : octet;  // even offsets are the high byte of a word
  }
  while (sum > 0xFFFF) {
    sum = (sum & 0xFFFFU) + (sum >> 16U);
  }
  return static_cast<std::uint16_t>(sum);
}

// A 32-bit accumulator of 16-bit words cannot overflow below this: 65,537 words of 0xFFFF sum to
// exactly 0xFFFFFFFF. Far above any frame this project handles.
inline constexpr std::size_t kMaxSummedBytes = 131'074;

// 2. Production: a 32-bit accumulator over 16-bit words, folded twice at the end. After the first
//    fold the value is at most 0x1FFFE, so a second fold always brings it within 16 bits.
[[nodiscard]] constexpr std::uint16_t ones_complement_sum(core::CBytes data) noexcept {
  assert(data.size() <= kMaxSummedBytes);
  std::uint32_t sum = 0;
  std::size_t i = 0;
  for (; i + 1 < data.size(); i += 2) {
    sum += core::rd_be16(data, i);
  }
  if (i < data.size()) {
    sum += std::uint32_t{core::rd_u8(data, i)} << 8U;
  }
  sum = (sum & 0xFFFFU) + (sum >> 16U);
  sum = (sum & 0xFFFFU) + (sum >> 16U);
  return static_cast<std::uint16_t>(sum);
}

// The value an IPv4 header's checksum field must hold. The field's current contents are ignored
// (taken as zero), so a header need not be cleared first.
[[nodiscard]] constexpr std::uint16_t ipv4_header_checksum(core::CBytes hdr) noexcept {
  assert(hdr.size() >= 20);
  std::uint32_t sum =
      std::uint32_t{ones_complement_sum(hdr.first(10))} + ones_complement_sum(hdr.subspan(12));
  sum = (sum & 0xFFFFU) + (sum >> 16U);
  return static_cast<std::uint16_t>(~sum);
}

// A correct header, checksum field included, sums to 0xFFFF.
[[nodiscard]] constexpr bool ipv4_checksum_valid(core::CBytes hdr) noexcept {
  return ones_complement_sum(hdr) == 0xFFFF;
}

// 3. Incremental update after one 16-bit word of the header changes from m to m_prime, without
//    re-summing the header: RFC 1624 eqn. 3, HC' = ~(~HC + ~m + m'), in one's complement addition.
//
//    The older RFC 1141 form, HC' = HC - ~m - m', gives 0xFFFF where the right answer is 0x0000:
//    whenever the new sum reaches 0xFFFF. 0xFFFF is a value no correct IPv4 header checksum can
//    take, since that would need the header's sum to be +0, and a version-4 header never sums to
//    +0.
[[nodiscard]] constexpr std::uint16_t checksum_update16(std::uint16_t hc, std::uint16_t m,
                                                        std::uint16_t m_prime) noexcept {
  std::uint32_t sum =
      std::uint32_t{static_cast<std::uint16_t>(~hc)} + static_cast<std::uint16_t>(~m) + m_prime;
  sum = (sum & 0xFFFFU) + (sum >> 16U);
  sum = (sum & 0xFFFFU) + (sum >> 16U);
  return static_cast<std::uint16_t>(~sum);
}

}  // namespace npf::proto
