#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <npf/core/byte_span.hpp>
#include <random>
#include <vector>

namespace {

using npf::core::rd_be16;
using npf::core::rd_be32;
using npf::core::rd_u8;
using npf::core::wr_be16;
using npf::core::wr_be32;
using npf::core::wr_u8;

// 10.0.1.2 as it appears on the wire.
constexpr std::array<std::byte, 4> kWire{std::byte{0x0A}, std::byte{0x00}, std::byte{0x01},
                                         std::byte{0x02}};

// Checked by the compiler: a byte-order mistake fails the build before any test runs.
static_assert(rd_u8(kWire, 0) == 0x0A);
static_assert(rd_be16(kWire, 0) == 0x0A00);
static_assert(rd_be16(kWire, 2) == 0x0102);
static_assert(rd_be32(kWire, 0) == 0x0A000102U);
static_assert([] {
  std::array<std::byte, 7> buf{};
  wr_u8(buf, 0, 0xFE);
  wr_be16(buf, 1, 0xBEEF);
  wr_be32(buf, 3, 0xDEADBEEFU);
  return rd_u8(buf, 0) == 0xFE && rd_be16(buf, 1) == 0xBEEF && rd_be32(buf, 3) == 0xDEADBEEFU &&
         buf[1] == std::byte{0xBE} && buf[2] == std::byte{0xEF} && buf[3] == std::byte{0xDE};
}());

TEST(ByteSpan, WritesMostSignificantByteFirst) {
  std::array<std::byte, 6> buf{};
  wr_be16(buf, 0, 0x1234);
  wr_be32(buf, 2, 0x0A000102U);
  const std::array<std::byte, 6> expected{std::byte{0x12}, std::byte{0x34}, std::byte{0x0A},
                                          std::byte{0x00}, std::byte{0x01}, std::byte{0x02}};
  EXPECT_EQ(buf, expected);
}

// Packet fields sit at arbitrary offsets, so nothing may assume alignment, and a write must touch
// exactly its own bytes.
TEST(ByteSpan, RoundTripsAtEveryOffsetWithoutTouchingNeighbours) {
  constexpr auto kFill = std::byte{0xA5};
  std::mt19937 rng(20260929);
  for (std::size_t off = 0; off < 8; ++off) {
    for (int trial = 0; trial < 1000; ++trial) {
      std::array<std::byte, 16> buf{};
      buf.fill(kFill);
      const auto v16 = static_cast<std::uint16_t>(rng());
      const auto v32 = static_cast<std::uint32_t>(rng());
      const auto v8 = static_cast<std::uint8_t>(rng());

      wr_be16(buf, off, v16);
      ASSERT_EQ(rd_be16(buf, off), v16) << "off " << off;
      wr_be32(buf, off + 2, v32);
      ASSERT_EQ(rd_be32(buf, off + 2), v32) << "off " << off;
      wr_u8(buf, off + 6, v8);
      ASSERT_EQ(rd_u8(buf, off + 6), v8) << "off " << off;

      ASSERT_EQ(rd_be16(buf, off), v16) << "the be32 write clobbered its neighbour";
      for (std::size_t i = 0; i < buf.size(); ++i) {
        if (i < off || i >= off + 7) {
          ASSERT_EQ(buf[i], kFill) << "byte " << i << " written, off " << off;
        }
      }
    }
  }
}

// Heap-allocated and exactly sized, so ASan reports a read even one byte past the end.
TEST(ByteSpan, ReadsEndingExactlyAtTheEndOfTheSpan) {
  const std::vector<std::byte> v{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
  EXPECT_EQ(rd_be32(v, 0), 0x01020304U);
  EXPECT_EQ(rd_be16(v, 2), 0x0304);
  EXPECT_EQ(rd_u8(v, 3), 4);
}

}  // namespace
