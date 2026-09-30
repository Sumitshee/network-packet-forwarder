#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <npf/core/byte_span.hpp>
#include <npf/proto/checksum.hpp>
#include <random>
#include <vector>

namespace {

using npf::core::CBytes;
using npf::core::rd_be16;
using npf::core::rd_u8;
using npf::core::wr_be16;
using npf::core::wr_u8;
using npf::proto::checksum_reference;
using npf::proto::checksum_update16;
using npf::proto::ipv4_checksum_valid;
using npf::proto::ipv4_header_checksum;
using npf::proto::ones_complement_sum;

template <class... Octets>
constexpr std::array<std::byte, sizeof...(Octets)> bytes(Octets... octets) {
  return {static_cast<std::byte>(octets)...};
}

// RFC 1071 §3's worked example: the words 0001 f203 f4f5 f6f7 sum to 0x2DDF0, which folds to
// 0xDDF2.
constexpr auto kRfc1071 = bytes(0x00, 0x01, 0xF2, 0x03, 0xF4, 0xF5, 0xF6, 0xF7);
static_assert(checksum_reference(kRfc1071) == 0xDDF2);
static_assert(ones_complement_sum(kRfc1071) == 0xDDF2);

// A widely published IPv4 header (192.168.0.1 -> 192.168.0.199, UDP) whose checksum is 0xB861.
constexpr auto kHeader = bytes(0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xB8,
                               0x61, 0xC0, 0xA8, 0x00, 0x01, 0xC0, 0xA8, 0x00, 0xC7);
static_assert(ipv4_header_checksum(kHeader) == 0xB861);
static_assert(ipv4_checksum_valid(kHeader));

// The update RFC 1141 specified, HC' = HC - ~m - m', which is HC + m + ~m' in one's complement
// arithmetic. Kept only to show the case it gets wrong.
constexpr std::uint16_t rfc1141_update(std::uint16_t hc, std::uint16_t m, std::uint16_t m_prime) {
  std::uint32_t sum = std::uint32_t{hc} + m + static_cast<std::uint16_t>(~m_prime);
  sum = (sum & 0xFFFFU) + (sum >> 16U);
  sum = (sum & 0xFFFFU) + (sum >> 16U);
  return static_cast<std::uint16_t>(sum);
}

// RFC 1624 §4: the other header words sum to 0xCD7A, and a word changes from 0x5555 to 0x3285. So
// HC = ~(0xCD7A + 0x5555) = 0xDD2F, and recomputing gives ~(0xCD7A + 0x3285) = ~0xFFFF = 0x0000.
static_assert(checksum_update16(0xDD2F, 0x5555, 0x3285) == 0x0000);
static_assert(rfc1141_update(0xDD2F, 0x5555, 0x3285) == 0xFFFF);  // the bug eqn. 3 exists to fix

// A valid IPv4 header of 20 to 60 bytes (ihl 5 to 15), random everywhere else. Its checksum is set
// by the reference implementation, not by the code under test.
std::vector<std::byte> random_ipv4_header(std::mt19937& rng) {
  const std::size_t ihl = 5 + rng() % 11;
  std::vector<std::byte> hdr(ihl * 4);
  for (std::byte& b : hdr) {
    b = static_cast<std::byte>(rng());
  }
  wr_u8(hdr, 0, static_cast<std::uint8_t>(0x40U | ihl));
  wr_u8(hdr, 8, static_cast<std::uint8_t>(1 + rng() % 255));  // TTL >= 1: decrementing never wraps
  wr_be16(hdr, 10, 0);
  wr_be16(hdr, 10, static_cast<std::uint16_t>(~checksum_reference(hdr)));
  return hdr;
}

std::uint8_t ttl(CBytes hdr) {
  return rd_u8(hdr, 8);
}
void set_ttl(npf::core::Bytes hdr, std::uint8_t value) {
  wr_u8(hdr, 8, value);
}

// --- exit test 1 --------------------------------------------------------------------------------

TEST(Checksum, ProductionSumMatchesReferenceOnAMillionHeaders) {
  std::mt19937 rng(7);
  for (int i = 0; i < 1'000'000; ++i) {
    const std::vector<std::byte> hdr = random_ipv4_header(rng);
    ASSERT_EQ(ones_complement_sum(hdr), checksum_reference(hdr)) << "i=" << i;
  }
}

// Beyond the exit test: any length up to an MTU, odd ones included, where the last byte is padded.
TEST(Checksum, ProductionSumMatchesReferenceOnArbitraryBuffers) {
  std::mt19937 rng(11);
  for (int i = 0; i < 100'000; ++i) {
    std::vector<std::byte> buf(rng() % 1501);
    for (std::byte& b : buf) {
      b = static_cast<std::byte>(rng());
    }
    ASSERT_EQ(ones_complement_sum(buf), checksum_reference(buf))
        << "i=" << i << " length " << buf.size();
  }
}

TEST(Checksum, SumsOfEmptyAndAllOnesInputs) {
  EXPECT_EQ(ones_complement_sum({}), 0x0000);
  EXPECT_EQ(checksum_reference({}), 0x0000);
  const std::vector<std::byte> ones(1500, std::byte{0xFF});
  EXPECT_EQ(ones_complement_sum(ones), 0xFFFF);  // negative zero: never folds to +0
  EXPECT_EQ(checksum_reference(ones), 0xFFFF);
}

TEST(Checksum, HeaderChecksumIgnoresWhateverTheFieldHolds) {
  auto hdr = kHeader;
  for (const std::uint16_t junk : std::array<std::uint16_t, 3>{0x0000, 0xFFFF, 0x1234}) {
    wr_be16(hdr, 10, junk);
    EXPECT_EQ(ipv4_header_checksum(hdr), 0xB861);
    EXPECT_FALSE(ipv4_checksum_valid(hdr));
  }
}

// --- exit test 2: RFC 1624
// ------------------------------------------------------------------------

TEST(Checksum, IncrementalMatchesFullRecompute) {
  std::mt19937 rng(42);
  for (int i = 0; i < 1'000'000; ++i) {
    auto hdr = random_ipv4_header(rng);              // valid, checksum already correct
    const std::uint16_t old_word = rd_be16(hdr, 8);  // TTL:protocol
    set_ttl(hdr, static_cast<std::uint8_t>(ttl(hdr) - 1));
    const std::uint16_t new_word = rd_be16(hdr, 8);
    const std::uint16_t incremental = checksum_update16(rd_be16(hdr, 10), old_word, new_word);
    wr_be16(hdr, 10, 0);
    ASSERT_EQ(incremental, ipv4_header_checksum(hdr)) << "i=" << i;
  }
}

// The hand-written case: a TTL decrement after which the header sums to exactly 0xFFFF, so the new
// checksum must be 0x0000 -- the case the RFC 1141 form gets wrong.
TEST(Checksum, IncrementalHandlesTheSumReaching0xFFFF) {
  auto after = kHeader;
  wr_be16(after, 10, 0);
  set_ttl(after, 0x3F);  // 0x40 decremented
  wr_be16(after, 4, 0);
  // Choose the identification so the header, checksum field zeroed, sums to 0xFFFF.
  wr_be16(after, 4, static_cast<std::uint16_t>(~ones_complement_sum(after)));
  ASSERT_EQ(ones_complement_sum(after), 0xFFFF);

  auto before = after;
  set_ttl(before, 0x40);
  const std::uint16_t hc = ipv4_header_checksum(before);
  wr_be16(before, 10, hc);
  ASSERT_TRUE(ipv4_checksum_valid(before));

  const std::uint16_t old_word = rd_be16(before, 8);
  const std::uint16_t new_word = rd_be16(after, 8);
  EXPECT_EQ(ipv4_header_checksum(after), 0x0000);
  EXPECT_EQ(checksum_update16(hc, old_word, new_word), 0x0000);
  EXPECT_EQ(rfc1141_update(hc, old_word, new_word), 0xFFFF);  // what eqn. 3 avoids
}

}  // namespace
