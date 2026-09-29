#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <npf/core/byte_span.hpp>
#include <npf/proto/ethernet.hpp>
#include <npf/proto/mac.hpp>
#include <ostream>
#include <string>
#include <vector>

#include "support/proto_helpers.hpp"
#include "support/truncation_sweep.hpp"

namespace {

using npf::proto::EthView;
using npf::proto::kBroadcastMac;
using npf::proto::MacAddr;
using npf::test::fixture_frame;
using npf::test::TruncationSweep;

// Addresses from scripts/make_fixtures.py.
constexpr MacAddr kClient{{0x02, 0x00, 0x00, 0x00, 0x01, 0x02}};
constexpr MacAddr kRouter{{0x02, 0x00, 0x00, 0x00, 0x01, 0x01}};
constexpr MacAddr kServer{{0x02, 0x00, 0x00, 0x00, 0x02, 0x02}};
constexpr MacAddr kLldpMulticast{{0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E}};

struct EthCase {
  const char* fixture;
  MacAddr dst, src;
  std::uint16_t ethertype;
  std::uint16_t vlan_id;  // 0 means untagged
  std::size_t header_len;
  std::size_t payload_len;
};

void PrintTo(const EthCase& c, std::ostream* os) {
  *os << c.fixture;
}

const std::array<EthCase, 8> kCases{{
    {"arp_request", kBroadcastMac, kClient, 0x0806, 0, 14, 28},
    {"arp_reply", kClient, kRouter, 0x0806, 0, 14, 28},
    {"arp_gratuitous", kBroadcastMac, kServer, 0x0806, 0, 14, 28},
    // The 18 bytes of padding stay in the payload; ArpView ignores what follows its 28 bytes.
    {"arp_reply_padded_60", kClient, kRouter, 0x0806, 0, 14, 46},
    // TCI 0xA064 is priority 5, VLAN 100: the priority must be masked off.
    {"vlan_ipv4", kRouter, kClient, 0x0800, 100, 18, 39},
    {"dot1ad_arp", kBroadcastMac, kClient, 0x0806, 300, 18, 28},
    // One tag is unwrapped; the second one's TPID is reported as the EtherType, which the
    // pipeline will count as BadEtherType.
    {"qinq_double_tag", kRouter, kClient, 0x8100, 200, 18, 43},
    {"lldp", kLldpMulticast, kServer, 0x88CC, 0, 14, 24},
}};

class EthFixture : public ::testing::TestWithParam<EthCase> {};

TEST_P(EthFixture, ParsesToTheExpectedFields) {
  const EthCase& c = GetParam();
  const std::vector<std::byte> frame = fixture_frame(c.fixture);
  const auto eth = EthView::parse(frame);
  ASSERT_TRUE(eth.has_value());
  EXPECT_EQ(eth->dst(), c.dst);
  EXPECT_EQ(eth->src(), c.src);
  EXPECT_EQ(eth->ethertype(), c.ethertype);
  EXPECT_EQ(eth->has_vlan(), c.vlan_id != 0);
  EXPECT_EQ(eth->vlan_id(), c.vlan_id);
  EXPECT_EQ(eth->header_len(), c.header_len);
  EXPECT_EQ(eth->payload().size(), c.payload_len);
  EXPECT_EQ(eth->payload().data(), frame.data() + c.header_len);
}

INSTANTIATE_TEST_SUITE_P(Fixtures, EthFixture, ::testing::ValuesIn(kCases),
                         [](const auto& test) { return std::string{test.param.fixture}; });

TEST(Ethernet, RejectsTheThirteenByteRunt) {
  EXPECT_FALSE(EthView::parse(fixture_frame("runt_13")).has_value());
}

// Reads every accessor, so ASan sees any read the factory did not validate.
void touch(const EthView& eth) {
  EXPECT_TRUE(eth.header_len() == 14 || eth.header_len() == 18);
  static_cast<void>(eth.dst());
  static_cast<void>(eth.src());
  static_cast<void>(eth.ethertype());
  static_cast<void>(eth.vlan_id());
  for (const std::byte b : eth.payload()) {
    static_cast<void>(b);
  }
}

TEST(Ethernet, TruncationSweepUntagged) {
  TruncationSweep<EthView>(fixture_frame("arp_request"), touch);
}

TEST(Ethernet, TruncationSweepTagged) {
  TruncationSweep<EthView>(fixture_frame("vlan_ipv4"), touch);
}

TEST(Ethernet, TruncationSweepDoubleTagged) {
  TruncationSweep<EthView>(fixture_frame("qinq_double_tag"), touch);
}

// A tag announces an 18-byte header, so 14 to 17 bytes is truncated, not an untagged frame.
TEST(Ethernet, RejectsATaggedFrameCutInsideTheTag) {
  const std::vector<std::byte> frame = fixture_frame("vlan_ipv4");
  for (std::size_t n = EthView::kMinSize; n < EthView::kTaggedSize; ++n) {
    const std::vector<std::byte> prefix(frame.begin(),
                                        frame.begin() + static_cast<std::ptrdiff_t>(n));
    EXPECT_FALSE(EthView::parse(prefix).has_value()) << n << " bytes";
  }
}

TEST(Ethernet, ExactlyAHeaderParsesWithAnEmptyPayload) {
  std::vector<std::byte> frame = fixture_frame("arp_request");
  frame.resize(EthView::kMinSize);
  const auto eth = EthView::parse(frame);
  ASSERT_TRUE(eth.has_value());
  EXPECT_TRUE(eth->payload().empty());
}

// Below 0x0600 the field is an 802.3 length, not an EtherType. It is reported unchanged, and the
// pipeline's dispatch rejects it like any other value it does not handle.
TEST(Ethernet, ReportsAn8023LengthFieldAsIs) {
  std::vector<std::byte> frame = fixture_frame("lldp");
  npf::core::wr_be16(frame, 12, 0x0026);
  const auto eth = EthView::parse(frame);
  ASSERT_TRUE(eth.has_value());
  EXPECT_EQ(eth->ethertype(), 0x0026);
  EXPECT_FALSE(eth->has_vlan());
}

}  // namespace
