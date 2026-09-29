#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <npf/proto/mac.hpp>

#include "support/proto_helpers.hpp"

namespace {

using npf::proto::kBroadcastMac;
using npf::proto::MacAddr;
using npf::proto::rd_mac;
using npf::proto::wr_mac;

constexpr MacAddr kUnicast{{0x02, 0x00, 0x00, 0x00, 0x01, 0x02}};   // locally administered
constexpr MacAddr kAllHosts{{0x01, 0x00, 0x5E, 0x00, 0x00, 0x01}};  // 224.0.0.1

static_assert(kBroadcastMac.is_broadcast());
static_assert(kBroadcastMac.is_multicast());  // ff has the group bit set
static_assert(!kBroadcastMac.is_zero());
static_assert(kAllHosts.is_multicast() && !kAllHosts.is_broadcast());
static_assert(!kUnicast.is_multicast() && !kUnicast.is_broadcast() && !kUnicast.is_zero());
static_assert(MacAddr{}.is_zero());
static_assert(kUnicast == kUnicast && kUnicast != kAllHosts);

TEST(Mac, OnlyTheLowBitOfTheFirstOctetMakesAnAddressMulticast) {
  MacAddr m = kUnicast;  // 0x02 is the locally-administered bit, not the group bit
  EXPECT_FALSE(m.is_multicast());
  m.b[0] = 0x03;
  EXPECT_TRUE(m.is_multicast());
  m = kUnicast;
  m.b[5] = 0x01;  // the group bit lives in the first octet only
  EXPECT_FALSE(m.is_multicast());
}

TEST(Mac, BroadcastAndZeroRequireEveryOctet) {
  for (std::size_t i = 0; i < 6; ++i) {
    MacAddr almost_broadcast = kBroadcastMac;
    almost_broadcast.b[i] = 0xFE;
    EXPECT_FALSE(almost_broadcast.is_broadcast()) << "octet " << i;
    MacAddr almost_zero{};
    almost_zero.b[i] = 0x01;
    EXPECT_FALSE(almost_zero.is_zero()) << "octet " << i;
  }
}

TEST(Mac, ReadsAndWritesAtAnyOffsetWithoutTouchingNeighbours) {
  for (std::size_t off = 0; off <= 4; ++off) {
    std::array<std::byte, 10> buf{};
    buf.fill(std::byte{0xA5});
    wr_mac(buf, off, kUnicast);
    EXPECT_EQ(rd_mac(buf, off), kUnicast) << "off " << off;
    for (std::size_t i = 0; i < buf.size(); ++i) {
      if (i < off || i >= off + 6) {
        EXPECT_EQ(buf[i], std::byte{0xA5}) << "byte " << i << " written, off " << off;
      }
    }
  }
}

}  // namespace
