#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <npf/core/byte_span.hpp>
#include <npf/proto/checksum.hpp>
#include <npf/proto/ethernet.hpp>
#include <npf/proto/ipv4.hpp>
#include <ostream>
#include <string>
#include <vector>

#include "support/proto_helpers.hpp"
#include "support/truncation_sweep.hpp"

namespace {

using npf::core::wr_be16;
using npf::core::wr_be32;
using npf::core::wr_u8;
using npf::proto::EthView;
using npf::proto::ipv4_checksum_valid;
using npf::proto::ipv4_header_checksum;
using npf::proto::Ipv4View;
using npf::proto::is_martian_dest;
using npf::proto::is_martian_source;
using npf::test::fixture_frame;
using npf::test::ip4;
using npf::test::TruncationSweep;

constexpr auto kPayloadByte = std::byte{0xAB};
constexpr auto kPaddingByte = std::byte{0xEE};

// The IPv4 datagram a fixture frame carries: its Ethernet payload, link-layer padding included.
std::vector<std::byte> ip_packet(const std::string& fixture) {
  const std::vector<std::byte> frame = fixture_frame(fixture);
  const auto eth = EthView::parse(frame);
  if (!eth || eth->ethertype() != npf::proto::kEtherTypeIpv4) {
    ADD_FAILURE() << fixture << " is not an IPv4 frame";
    return {};
  }
  return std::vector<std::byte>(eth->payload().begin(), eth->payload().end());
}

// A datagram with an ihl*4-byte header (any options are zero, a run of End-of-Option-List octets),
// `payload` bytes after it, then `padding` bytes that total_length does not cover.
std::vector<std::byte> datagram(std::size_t ihl, std::size_t payload, std::size_t padding = 0) {
  const std::size_t hdr_len = ihl * 4;
  std::vector<std::byte> d(hdr_len + payload + padding, std::byte{0});
  std::fill(d.begin() + static_cast<std::ptrdiff_t>(hdr_len),
            d.begin() + static_cast<std::ptrdiff_t>(hdr_len + payload), kPayloadByte);
  std::fill(d.begin() + static_cast<std::ptrdiff_t>(hdr_len + payload), d.end(), kPaddingByte);
  wr_u8(d, 0, static_cast<std::uint8_t>(0x40U | ihl));
  wr_be16(d, 2, static_cast<std::uint16_t>(hdr_len + payload));
  wr_u8(d, 8, 64);
  wr_u8(d, 9, 17);
  wr_be32(d, 12, ip4(10, 0, 1, 2));
  wr_be32(d, 16, ip4(10, 0, 2, 2));
  wr_be16(d, 10, ipv4_header_checksum(npf::core::CBytes{d}.first(hdr_len)));
  return d;
}

// --- fixtures -----------------------------------------------------------------------------------

struct Ipv4Case {
  const char* fixture;
  std::uint8_t ihl;
  std::uint16_t total_length;
  std::uint16_t id;
  bool df;
  std::size_t span_len;  // the Ethernet payload handed to parse(), padding included
};

void PrintTo(const Ipv4Case& c, std::ostream* os) {
  *os << c.fixture;
}

// Values from scripts/make_fixtures.py. Every one is UDP, TTL 64, 10.0.1.2 -> 10.0.2.2,
// unfragmented.
const std::array<Ipv4Case, 3> kCases{{
    {"vlan_ipv4", 5, 39, 0x0001, false, 39},
    {"ipv4_udp_padded_60", 5, 30, 0x1234, true, 46},  // 16 bytes of Ethernet padding
    {"ipv4_options_rr", 9, 47, 0x5678, false, 47},    // a Record Route option
}};

class Ipv4Fixture : public ::testing::TestWithParam<Ipv4Case> {};

TEST_P(Ipv4Fixture, ParsesToTheExpectedFields) {
  const Ipv4Case& c = GetParam();
  const std::vector<std::byte> packet = ip_packet(c.fixture);
  ASSERT_EQ(packet.size(), c.span_len);
  const auto ip = Ipv4View::parse(packet);
  ASSERT_TRUE(ip.has_value());
  EXPECT_EQ(ip->ihl(), c.ihl);
  EXPECT_EQ(ip->header_len(), std::size_t{c.ihl} * 4);
  EXPECT_EQ(ip->total_length(), c.total_length);
  EXPECT_EQ(ip->identification(), c.id);
  EXPECT_EQ(ip->df(), c.df);
  EXPECT_FALSE(ip->mf());
  EXPECT_EQ(ip->frag_offset(), 0);
  EXPECT_FALSE(ip->is_fragment());
  EXPECT_TRUE(ip->is_first_fragment());
  EXPECT_EQ(ip->ttl(), 64);
  EXPECT_EQ(ip->protocol(), 17);
  EXPECT_EQ(ip->src(), ip4(10, 0, 1, 2));
  EXPECT_EQ(ip->dst(), ip4(10, 0, 2, 2));
  EXPECT_EQ(ip->header().data(), packet.data());
  EXPECT_EQ(ip->header().size(), ip->header_len());
  EXPECT_EQ(ip->payload().data(), packet.data() + ip->header_len());
  EXPECT_EQ(ip->payload().size(), c.total_length - ip->header_len());
  EXPECT_TRUE(ipv4_checksum_valid(ip->header()));
}

INSTANTIATE_TEST_SUITE_P(Fixtures, Ipv4Fixture, ::testing::ValuesIn(kCases),
                         [](const auto& test) { return std::string{test.param.fixture}; });

// --- exit test 3: options
// ---------------------------------------------------------------------------

TEST(Ipv4, HeaderLengthFollowsIhlFrom6To15) {
  for (std::size_t ihl = 6; ihl <= 15; ++ihl) {
    const std::vector<std::byte> d = datagram(ihl, 8);
    const auto ip = Ipv4View::parse(d);
    ASSERT_TRUE(ip.has_value()) << "ihl " << ihl;
    EXPECT_EQ(ip->ihl(), ihl);
    EXPECT_EQ(ip->header_len(), ihl * 4);
    EXPECT_EQ(ip->header().size(), ihl * 4);
    EXPECT_EQ(ip->payload().data(), d.data() + ihl * 4) << "ihl " << ihl;
    EXPECT_EQ(ip->payload().size(), 8U);
    EXPECT_TRUE(ipv4_checksum_valid(ip->header())) << "ihl " << ihl;
  }
}

// --- exit tests 4 and 5: total_length against the span
// ----------------------------------------------

TEST(Ipv4, PayloadIsSizedByTotalLengthNotByTheSpan) {
  const std::vector<std::byte> d = datagram(5, 10, 16);  // as in a 60-byte Ethernet frame
  const auto ip = Ipv4View::parse(d);
  ASSERT_TRUE(ip.has_value());
  EXPECT_EQ(ip->payload().size(), 10U);
  EXPECT_TRUE(std::all_of(ip->payload().begin(), ip->payload().end(), [](std::byte b) {
    return b == kPayloadByte;
  })) << "padding leaked into the payload";
}

TEST(Ipv4, RejectsTotalLengthLongerThanTheSpan) {
  std::vector<std::byte> d = datagram(5, 10);
  for (std::size_t extra = 1; extra <= 20; ++extra) {
    wr_be16(d, 2, static_cast<std::uint16_t>(d.size() + extra));
    EXPECT_FALSE(Ipv4View::parse(d).has_value()) << "total_length " << d.size() + extra;
  }
}

// --- the rest of what parse() validates ---------------------------------------------------------

TEST(Ipv4, RejectsEveryVersionButFour) {
  for (unsigned version = 0; version <= 15; ++version) {
    std::vector<std::byte> d = datagram(5, 8);
    wr_u8(d, 0, static_cast<std::uint8_t>(version << 4U | 5U));
    EXPECT_EQ(Ipv4View::parse(d).has_value(), version == 4) << "version " << version;
  }
}

TEST(Ipv4, RejectsIhlBelowFive) {
  for (unsigned ihl = 0; ihl < 5; ++ihl) {
    std::vector<std::byte> d = datagram(5, 8);
    wr_u8(d, 0, static_cast<std::uint8_t>(0x40U | ihl));
    EXPECT_FALSE(Ipv4View::parse(d).has_value()) << "ihl " << ihl;
  }
}

TEST(Ipv4, RejectsTotalLengthShorterThanTheHeader) {
  std::vector<std::byte> d = datagram(6, 0);  // a 24-byte header and nothing else
  for (std::uint16_t total = 0; total < 24; ++total) {
    wr_be16(d, 2, total);
    EXPECT_FALSE(Ipv4View::parse(d).has_value()) << "total_length " << total;
  }
  wr_be16(d, 2, 24);
  EXPECT_TRUE(Ipv4View::parse(d).has_value());  // exactly a header, empty payload
}

TEST(Ipv4, RejectsAHeaderLongerThanTheSpan) {
  std::vector<std::byte> d = datagram(5, 20);  // 40 bytes
  wr_u8(d, 0, 0x4F);                           // claims a 60-byte header
  EXPECT_FALSE(Ipv4View::parse(d).has_value());
}

// The pipeline counts BadChecksum separately from BadIpv4Header, so parse() must not judge it.
TEST(Ipv4, LeavesTheChecksumToTheCaller) {
  std::vector<std::byte> d = datagram(5, 8);
  wr_be16(d, 10, static_cast<std::uint16_t>(npf::core::rd_be16(d, 10) ^ 0x0101U));
  const auto ip = Ipv4View::parse(d);
  ASSERT_TRUE(ip.has_value());
  EXPECT_FALSE(ipv4_checksum_valid(ip->header()));
}

TEST(Ipv4, FragmentFlagsAndOffset) {
  struct Case {
    std::uint16_t flags_frag;
    bool df, mf;
    std::uint16_t offset;
    bool is_fragment, is_first;
  };
  const std::array<Case, 6> cases{{
      {0x0000, false, false, 0, false, true},     // unfragmented
      {0x4000, true, false, 0, false, true},      // don't fragment
      {0x2000, false, true, 0, true, true},       // first fragment
      {0x20B9, false, true, 185, true, false},    // a middle fragment
      {0x00B9, false, false, 185, true, false},   // the last fragment
      {0xFFFF, true, true, 0x1FFF, true, false},  // every bit set, reserved bit included
  }};
  for (const Case& c : cases) {
    std::vector<std::byte> d = datagram(5, 8);
    wr_be16(d, 6, c.flags_frag);
    const auto ip = Ipv4View::parse(d);
    ASSERT_TRUE(ip.has_value());
    EXPECT_EQ(ip->df(), c.df) << std::hex << c.flags_frag;
    EXPECT_EQ(ip->mf(), c.mf) << std::hex << c.flags_frag;
    EXPECT_EQ(ip->frag_offset(), c.offset) << std::hex << c.flags_frag;
    EXPECT_EQ(ip->is_fragment(), c.is_fragment) << std::hex << c.flags_frag;
    EXPECT_EQ(ip->is_first_fragment(), c.is_first) << std::hex << c.flags_frag;
  }
}

// --- exit test 6: truncation
// ----------------------------------------------------------------------

// Reads every accessor, so ASan sees any read the factory did not validate.
void touch(const Ipv4View& ip) {
  EXPECT_GE(ip.header_len(), Ipv4View::kMinSize);
  static_cast<void>(ip.total_length());
  static_cast<void>(ip.identification());
  static_cast<void>(ip.df());
  static_cast<void>(ip.mf());
  static_cast<void>(ip.frag_offset());
  static_cast<void>(ip.ttl());
  static_cast<void>(ip.protocol());
  static_cast<void>(ip.checksum());
  static_cast<void>(ip.src());
  static_cast<void>(ip.dst());
  static_cast<void>(ipv4_checksum_valid(ip.header()));
  for (const std::byte b : ip.payload()) {
    static_cast<void>(b);
  }
}

TEST(Ipv4, TruncationSweep) {
  TruncationSweep<Ipv4View>(ip_packet("vlan_ipv4"), touch);
}

TEST(Ipv4, TruncationSweepWithOptions) {
  TruncationSweep<Ipv4View>(ip_packet("ipv4_options_rr"), touch);
}

// Stronger than the sweep's check: nothing shorter than total_length may parse at all.
TEST(Ipv4, RejectsEveryPrefixShorterThanTotalLength) {
  const std::vector<std::byte> packet = ip_packet("ipv4_options_rr");
  for (std::size_t n = 0; n < 47; ++n) {
    const std::vector<std::byte> prefix(packet.begin(),
                                        packet.begin() + static_cast<std::ptrdiff_t>(n));
    EXPECT_FALSE(Ipv4View::parse(prefix).has_value()) << n << " bytes";
  }
}

// --- martians (RFC 1812 §5.3.7) ------------------------------------------------------------------

static_assert(is_martian_source(ip4(0, 0, 0, 0)) && is_martian_source(ip4(0, 255, 255, 255)));
static_assert(!is_martian_source(ip4(1, 0, 0, 0)));
static_assert(!is_martian_source(ip4(126, 255, 255, 255)) && is_martian_source(ip4(127, 0, 0, 0)));
static_assert(is_martian_source(ip4(127, 255, 255, 255)) && !is_martian_source(ip4(128, 0, 0, 0)));
static_assert(!is_martian_source(ip4(223, 255, 255, 255)) && is_martian_source(ip4(224, 0, 0, 0)));
static_assert(is_martian_source(ip4(239, 255, 255, 255)) && is_martian_source(ip4(240, 0, 0, 0)));
static_assert(is_martian_source(ip4(255, 255, 255, 254)) &&
              is_martian_source(ip4(255, 255, 255, 255)));
static_assert(!is_martian_source(ip4(10, 0, 1, 2)) && !is_martian_source(ip4(192, 168, 0, 1)));

static_assert(is_martian_dest(ip4(0, 0, 0, 0)) && is_martian_dest(ip4(0, 255, 255, 255)));
static_assert(is_martian_dest(ip4(127, 0, 0, 1)) && is_martian_dest(ip4(127, 255, 255, 255)));
static_assert(!is_martian_dest(ip4(1, 0, 0, 0)) && !is_martian_dest(ip4(128, 0, 0, 0)));
// Multicast and broadcast are not martian as destinations; what to do with them is decided later.
static_assert(!is_martian_dest(ip4(224, 0, 0, 1)) && !is_martian_dest(ip4(255, 255, 255, 255)));

}  // namespace
