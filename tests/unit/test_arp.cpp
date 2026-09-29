#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <npf/core/byte_span.hpp>
#include <npf/core/packet.hpp>
#include <npf/core/pool.hpp>
#include <npf/proto/arp.hpp>
#include <npf/proto/ethernet.hpp>
#include <npf/proto/mac.hpp>
#include <ostream>
#include <string>
#include <vector>

#include "support/proto_helpers.hpp"
#include "support/truncation_sweep.hpp"

namespace {

using npf::core::Packet;
using npf::core::PacketPool;
using npf::proto::ArpView;
using npf::proto::EthView;
using npf::proto::kBroadcastMac;
using npf::proto::MacAddr;
using npf::test::fixture_frame;
using npf::test::ip4;
using npf::test::TruncationSweep;

// Addresses from scripts/make_fixtures.py.
constexpr MacAddr kClient{{0x02, 0x00, 0x00, 0x00, 0x01, 0x02}};
constexpr MacAddr kRouter{{0x02, 0x00, 0x00, 0x00, 0x01, 0x01}};
constexpr MacAddr kServer{{0x02, 0x00, 0x00, 0x00, 0x02, 0x02}};
constexpr MacAddr kZero{};

// The ARP payload of a fixture frame, found through its Ethernet header.
std::vector<std::byte> arp_payload(const std::string& fixture) {
  const std::vector<std::byte> frame = fixture_frame(fixture);
  const auto eth = EthView::parse(frame);
  if (!eth || eth->ethertype() != npf::proto::kEtherTypeArp) {
    ADD_FAILURE() << fixture << " is not an ARP frame";
    return {};
  }
  return std::vector<std::byte>(eth->payload().begin(), eth->payload().end());
}

struct ArpCase {
  const char* fixture;
  std::uint16_t oper;
  MacAddr sha;
  std::uint32_t spa;
  MacAddr tha;
  std::uint32_t tpa;
};

void PrintTo(const ArpCase& c, std::ostream* os) {
  *os << c.fixture;
}

const std::array<ArpCase, 5> kCases{{
    {"arp_request", ArpView::kOpRequest, kClient, ip4(10, 0, 1, 2), kZero, ip4(10, 0, 1, 1)},
    {"arp_reply", ArpView::kOpReply, kRouter, ip4(10, 0, 1, 1), kClient, ip4(10, 0, 1, 2)},
    {"arp_gratuitous", ArpView::kOpRequest, kServer, ip4(10, 0, 2, 2), kZero, ip4(10, 0, 2, 2)},
    {"arp_reply_padded_60", ArpView::kOpReply, kRouter, ip4(10, 0, 1, 1), kClient,
     ip4(10, 0, 1, 2)},
    {"dot1ad_arp", ArpView::kOpRequest, kClient, ip4(10, 0, 1, 2), kZero, ip4(10, 0, 1, 1)},
}};

class ArpFixture : public ::testing::TestWithParam<ArpCase> {};

TEST_P(ArpFixture, ParsesToTheExpectedFields) {
  const ArpCase& c = GetParam();
  const std::vector<std::byte> payload = arp_payload(c.fixture);
  const auto arp = ArpView::parse(payload);
  ASSERT_TRUE(arp.has_value());
  EXPECT_EQ(arp->oper(), c.oper);
  EXPECT_EQ(arp->sha(), c.sha);
  EXPECT_EQ(arp->spa(), c.spa);
  EXPECT_EQ(arp->tha(), c.tha);
  EXPECT_EQ(arp->tpa(), c.tpa);
}

INSTANTIATE_TEST_SUITE_P(Fixtures, ArpFixture, ::testing::ValuesIn(kCases),
                         [](const auto& test) { return std::string{test.param.fixture}; });

// Each of the four fields parse() validates, broken one at a time.
TEST(Arp, RejectsAnythingButIpv4OverEthernet) {
  struct Mutation {
    const char* what;
    std::size_t offset;
    bool wide;  // a 16-bit field rather than an 8-bit one
    std::uint16_t value;
  };
  const std::array<Mutation, 4> mutations{{
      {"htype 6 (IEEE 802)", 0, true, 6},
      {"ptype 0x86DD (IPv6)", 2, true, 0x86DD},
      {"hlen 8", 4, false, 8},
      {"plen 16", 5, false, 16},
  }};
  for (const Mutation& m : mutations) {
    std::vector<std::byte> payload = arp_payload("arp_request");
    if (m.wide) {
      npf::core::wr_be16(payload, m.offset, m.value);
    } else {
      npf::core::wr_u8(payload, m.offset, static_cast<std::uint8_t>(m.value));
    }
    EXPECT_FALSE(ArpView::parse(payload).has_value()) << m.what;
  }
}

TEST(Arp, LeavesTheOperationForTheCallerToJudge) {
  std::vector<std::byte> payload = arp_payload("arp_request");
  npf::core::wr_be16(payload, 6, 3);  // RARP request: not ours to act on, but not malformed
  const auto arp = ArpView::parse(payload);
  ASSERT_TRUE(arp.has_value());
  EXPECT_EQ(arp->oper(), 3);
}

// Reads every accessor, so ASan sees any read the factory did not validate.
void touch(const ArpView& arp) {
  static_cast<void>(arp.oper());
  static_cast<void>(arp.sha());
  static_cast<void>(arp.spa());
  static_cast<void>(arp.tha());
  static_cast<void>(arp.tpa());
}

TEST(Arp, TruncationSweep) {
  TruncationSweep<ArpView>(arp_payload("arp_request"), touch);
}

TEST(Arp, TruncationSweepPadded) {
  TruncationSweep<ArpView>(arp_payload("arp_reply_padded_60"), touch);
}

// --- builders
// -------------------------------------------------------------------------------------

// Fills the packet with junk first, so a builder that forgets to write a byte cannot pass.
Packet* dirty_packet(PacketPool& pool) {
  Packet* p = pool.acquire();
  if (p != nullptr) {
    p->resize(100);
    std::fill(p->data().begin(), p->data().end(), std::byte{0xEE});
  }
  return p;
}

TEST(ArpBuilder, RequestRoundTripsAndMatchesScapyByteForByte) {
  PacketPool pool(1);
  Packet* p = dirty_packet(pool);
  ASSERT_NE(p, nullptr);
  ASSERT_TRUE(npf::proto::build_arp_request(*p, kClient, ip4(10, 0, 1, 2), ip4(10, 0, 1, 1)));
  ASSERT_EQ(p->size(), npf::proto::kArpFrameSize);

  const auto eth = EthView::parse(p->data());
  ASSERT_TRUE(eth.has_value());
  EXPECT_EQ(eth->dst(), kBroadcastMac);
  EXPECT_EQ(eth->src(), kClient);
  EXPECT_EQ(eth->ethertype(), npf::proto::kEtherTypeArp);
  EXPECT_FALSE(eth->has_vlan());
  const auto arp = ArpView::parse(eth->payload());
  ASSERT_TRUE(arp.has_value());
  EXPECT_EQ(arp->oper(), ArpView::kOpRequest);
  EXPECT_EQ(arp->sha(), kClient);
  EXPECT_EQ(arp->spa(), ip4(10, 0, 1, 2));
  EXPECT_EQ(arp->tha(), kZero);
  EXPECT_EQ(arp->tpa(), ip4(10, 0, 1, 1));

  // An independent implementation, scapy, built the fixture from the same fields.
  const std::vector<std::byte> built(p->data().begin(), p->data().end());
  EXPECT_EQ(built, fixture_frame("arp_request"));
  pool.release(p);
}

TEST(ArpBuilder, ReplyRoundTripsAndMatchesScapyByteForByte) {
  PacketPool pool(1);
  Packet* p = dirty_packet(pool);
  ASSERT_NE(p, nullptr);
  ASSERT_TRUE(
      npf::proto::build_arp_reply(*p, kRouter, ip4(10, 0, 1, 1), kClient, ip4(10, 0, 1, 2)));
  ASSERT_EQ(p->size(), npf::proto::kArpFrameSize);

  const auto eth = EthView::parse(p->data());
  ASSERT_TRUE(eth.has_value());
  EXPECT_EQ(eth->dst(), kClient);
  EXPECT_EQ(eth->src(), kRouter);
  const auto arp = ArpView::parse(eth->payload());
  ASSERT_TRUE(arp.has_value());
  EXPECT_EQ(arp->oper(), ArpView::kOpReply);
  EXPECT_EQ(arp->sha(), kRouter);
  EXPECT_EQ(arp->spa(), ip4(10, 0, 1, 1));
  EXPECT_EQ(arp->tha(), kClient);
  EXPECT_EQ(arp->tpa(), ip4(10, 0, 1, 2));

  const std::vector<std::byte> built(p->data().begin(), p->data().end());
  EXPECT_EQ(built, fixture_frame("arp_reply"));
  pool.release(p);
}

TEST(ArpBuilder, RefusesAPacketTooSmallAndLeavesItUntouched) {
  PacketPool pool(1);
  Packet* p = pool.acquire();
  ASSERT_NE(p, nullptr);
  // Move the start so that only 41 bytes remain before the end of the buffer.
  p->resize(p->capacity());
  ASSERT_TRUE(p->pull(p->capacity() - (npf::proto::kArpFrameSize - 1)));
  ASSERT_EQ(p->capacity(), npf::proto::kArpFrameSize - 1);
  std::fill(p->data().begin(), p->data().end(), std::byte{0xEE});

  EXPECT_FALSE(npf::proto::build_arp_request(*p, kClient, ip4(10, 0, 1, 2), ip4(10, 0, 1, 1)));
  EXPECT_FALSE(
      npf::proto::build_arp_reply(*p, kRouter, ip4(10, 0, 1, 1), kClient, ip4(10, 0, 1, 2)));
  EXPECT_EQ(p->size(), npf::proto::kArpFrameSize - 1);
  EXPECT_TRUE(std::all_of(p->data().begin(), p->data().end(),
                          [](std::byte b) { return b == std::byte{0xEE}; }));
  pool.release(p);
}

}  // namespace
