#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <npf/core/byte_span.hpp>
#include <npf/proto/checksum.hpp>
#include <npf/proto/ethernet.hpp>
#include <npf/proto/icmp.hpp>
#include <npf/proto/ipv4.hpp>
#include <npf/proto/l4.hpp>
#include <optional>
#include <ostream>
#include <span>
#include <string>
#include <vector>

#include "support/pcap_reader.hpp"
#include "support/proto_helpers.hpp"
#include "support/truncation_sweep.hpp"

namespace {

using npf::core::CBytes;
using npf::core::wr_be16;
using npf::core::wr_be32;
using npf::core::wr_u8;
using npf::proto::IcmpView;
using npf::proto::Ipv4View;
using npf::proto::kIpProtoIcmp;
using npf::proto::kIpProtoTcp;
using npf::proto::kIpProtoUdp;
using npf::proto::L4Info;
using npf::proto::parse_l4;
using npf::test::ip4;

// A 20-byte IPv4 header carrying `l4` exactly: total_length covers it and nothing follows, so any
// read past the end of `l4` leaves the heap allocation, where ASan is watching.
std::vector<std::byte> ipv4_packet(std::uint8_t protocol, CBytes l4, std::uint16_t flags_frag = 0) {
  std::array<std::byte, 20> hdr{};
  wr_u8(hdr, 0, 0x45);
  wr_be16(hdr, 2, static_cast<std::uint16_t>(hdr.size() + l4.size()));
  wr_be16(hdr, 6, flags_frag);
  wr_u8(hdr, 8, 64);
  wr_u8(hdr, 9, protocol);
  wr_be32(hdr, 12, ip4(10, 0, 1, 2));
  wr_be32(hdr, 16, ip4(10, 0, 2, 2));
  wr_be16(hdr, 10, npf::proto::ipv4_header_checksum(hdr));
  // Reserved exactly, so no spare capacity lies past the end where an over-read could hide.
  std::vector<std::byte> packet;
  packet.reserve(hdr.size() + l4.size());
  packet.insert(packet.end(), hdr.begin(), hdr.end());
  packet.insert(packet.end(), l4.begin(), l4.end());
  return packet;
}

// parse_l4 on a packet that must itself be a valid IPv4 datagram.
std::optional<L4Info> l4_of(CBytes packet) {
  const auto ip = Ipv4View::parse(packet);
  if (!ip) {
    ADD_FAILURE() << "not a valid IPv4 packet";
    return std::nullopt;
  }
  return parse_l4(*ip);
}

std::vector<std::byte> tcp_header(std::uint16_t sport, std::uint16_t dport, std::size_t doff,
                                  std::size_t total_len) {
  std::vector<std::byte> t(total_len, std::byte{0});
  wr_be16(t, 0, sport);
  wr_be16(t, 2, dport);
  wr_u8(t, 12, static_cast<std::uint8_t>(doff << 4U));
  return t;
}

std::vector<std::byte> udp_header(std::uint16_t sport, std::uint16_t dport, std::uint16_t length) {
  std::vector<std::byte> u(8, std::byte{0});
  wr_be16(u, 0, sport);
  wr_be16(u, 2, dport);
  wr_be16(u, 4, length);
  return u;
}

// The IPv4 packet inside a fixture frame.
std::vector<std::byte> ip_packet(const std::vector<std::byte>& frame) {
  const auto eth = npf::proto::EthView::parse(frame);
  if (!eth || eth->ethertype() != npf::proto::kEtherTypeIpv4) {
    ADD_FAILURE() << "not an IPv4 frame";
    return {};
  }
  return std::vector<std::byte>(eth->payload().begin(), eth->payload().end());
}

// --- fixtures -----------------------------------------------------------------------------------

struct L4Case {
  const char* fixture;
  std::uint8_t protocol;
  bool ports_valid;
  std::uint16_t sport, dport;
  std::uint8_t tcp_flags;
  std::uint32_t seq;
  std::uint8_t icmp_type, icmp_code;
};

void PrintTo(const L4Case& c, std::ostream* os) {
  *os << c.fixture;
}

// Values from scripts/make_fixtures.py.
const std::array<L4Case, 6> kCases{{
    {"tcp_syn", kIpProtoTcp, true, 40001, 443, 0x02, 0x12345678, 0, 0},  // SYN, data offset 6
    {"vlan_ipv4", kIpProtoUdp, true, 40000, 9, 0, 0, 0, 0},
    {"ipv4_udp_padded_60", kIpProtoUdp, true, 40000, 9, 0, 0, 0, 0},
    {"ipv4_options_rr", kIpProtoUdp, true, 40000, 9, 0, 0, 0, 0},  // L4 starts after ihl*4 = 36
    {"icmp_echo_request", kIpProtoIcmp, false, 0, 0, 0, 0, 8, 0},
    {"icmp_time_exceeded", kIpProtoIcmp, false, 0, 0, 0, 0, 11, 0},
}};

class L4Fixture : public ::testing::TestWithParam<L4Case> {};

TEST_P(L4Fixture, ParsesToTheExpectedFields) {
  const L4Case& c = GetParam();
  const std::vector<std::byte> packet = ip_packet(npf::test::fixture_frame(c.fixture));
  const auto l4 = l4_of(packet);
  ASSERT_TRUE(l4.has_value());
  EXPECT_EQ(l4->protocol, c.protocol);
  EXPECT_EQ(l4->ports_valid, c.ports_valid);
  EXPECT_EQ(l4->sport, c.sport);
  EXPECT_EQ(l4->dport, c.dport);
  EXPECT_EQ(l4->tcp_flags, c.tcp_flags);
  EXPECT_EQ(l4->seq, c.seq);
  EXPECT_EQ(l4->ack, 0U);
  EXPECT_EQ(l4->icmp_type, c.icmp_type);
  EXPECT_EQ(l4->icmp_code, c.icmp_code);
}

INSTANTIATE_TEST_SUITE_P(Fixtures, L4Fixture, ::testing::ValuesIn(kCases),
                         [](const auto& test) { return std::string{test.param.fixture}; });

// --- exit test 1 --------------------------------------------------------------------------------

TEST(L4, OnlyTheFirstFragmentOfAFragmentedDatagramHasPorts) {
  const auto frames =
      npf::test::read_pcap(std::filesystem::path{NPF_FIXTURE_DIR} / "udp_fragmented.pcap");
  ASSERT_EQ(frames.size(), 3U);
  for (std::size_t i = 0; i < frames.size(); ++i) {
    const std::vector<std::byte> packet = ip_packet(frames[i]);
    const auto ip = Ipv4View::parse(packet);
    ASSERT_TRUE(ip.has_value()) << "fragment " << i + 1;
    ASSERT_TRUE(ip->is_fragment()) << "fragment " << i + 1;
    const auto l4 = parse_l4(*ip);
    ASSERT_TRUE(l4.has_value()) << "fragment " << i + 1;
    EXPECT_EQ(l4->protocol, kIpProtoUdp);
    if (i == 0) {
      EXPECT_TRUE(l4->ports_valid);
      EXPECT_EQ(l4->sport, 40000);
      EXPECT_EQ(l4->dport, 9);
    } else {
      EXPECT_FALSE(l4->ports_valid) << "fragment " << i + 1;
      EXPECT_EQ(l4->sport, 0) << "fragment " << i + 1;
      EXPECT_EQ(l4->dport, 0) << "fragment " << i + 1;
    }
  }
  // The fixture is only a fair test if fragment 2 really does start with bytes that look like
  // ports 443 -> 8080.
  const std::vector<std::byte> second = ip_packet(frames[1]);
  const auto ip = Ipv4View::parse(second);
  ASSERT_TRUE(ip.has_value());
  EXPECT_EQ(npf::core::rd_be16(ip->payload(), 0), 443);
  EXPECT_EQ(npf::core::rd_be16(ip->payload(), 2), 8080);
}

// --- exit test 2 --------------------------------------------------------------------------------

TEST(L4, RejectsPortsFromNonInitialFragment) {
  // frag_offset 185 is byte 1480, where a 1500-byte MTU puts the second fragment. Its payload
  // starts with bytes that would decode as ports 443 -> 8080: they are not ports.
  const std::array<std::byte, 16> looks_like_ports{std::byte{0x01}, std::byte{0xBB},
                                                   std::byte{0x1F}, std::byte{0x90}};
  for (const std::uint8_t protocol : {kIpProtoTcp, kIpProtoUdp}) {
    for (const std::uint16_t flags_frag : {std::uint16_t{0x2000U | 185U}, std::uint16_t{185U}}) {
      const auto packet = ipv4_packet(protocol, looks_like_ports, flags_frag);
      const auto l4 = l4_of(packet);
      ASSERT_TRUE(l4.has_value());
      EXPECT_EQ(l4->protocol, protocol);
      EXPECT_FALSE(l4->ports_valid)
          << "protocol " << int{protocol} << " MF " << ((flags_frag & 0x2000U) != 0);
      EXPECT_EQ(l4->sport, 0);
      EXPECT_EQ(l4->dport, 0);
    }
  }
}

// The hard rule says a non-initial fragment's payload is not read at all. With nothing after the
// IP header, any read would leave the allocation (ASan), and a parser that checked the L4 length
// before the fragment offset would wrongly call the packet malformed.
TEST(L4, ReadsNothingFromANonInitialFragment) {
  for (const std::uint8_t protocol : {kIpProtoTcp, kIpProtoUdp, kIpProtoIcmp}) {
    const auto packet = ipv4_packet(protocol, {}, 185);
    ASSERT_EQ(packet.capacity(), packet.size());  // nothing past the IP header for a read to hit
    const auto l4 = l4_of(packet);
    ASSERT_TRUE(l4.has_value()) << "protocol " << int{protocol};
    EXPECT_EQ(l4->protocol, protocol);
    EXPECT_FALSE(l4->ports_valid);
    EXPECT_EQ(l4->tcp_flags, 0);
    EXPECT_EQ(l4->icmp_type, 0);
  }
}

TEST(L4, AFirstFragmentCarriesTheHeaderAndItsPorts) {
  const auto packet = ipv4_packet(kIpProtoUdp, udp_header(53, 5353, 200), 0x2000);  // MF, offset 0
  const auto l4 = l4_of(packet);
  ASSERT_TRUE(l4.has_value());
  EXPECT_TRUE(l4->ports_valid);
  EXPECT_EQ(l4->sport, 53);
  EXPECT_EQ(l4->dport, 5353);
}

// RFC 1858's tiny fragment: a first fragment carrying only part of the TCP header.
TEST(L4, AFirstFragmentTooShortForTheTcpHeaderIsMalformed) {
  const auto packet = ipv4_packet(kIpProtoTcp, tcp_header(1, 2, 5, 20), 0x2000);
  const auto whole = l4_of(packet);
  ASSERT_TRUE(whole.has_value());
  for (std::size_t n = 0; n < 20; ++n) {
    const auto tiny = ipv4_packet(kIpProtoTcp, CBytes{tcp_header(1, 2, 5, 20)}.first(n), 0x2000);
    EXPECT_FALSE(l4_of(tiny).has_value()) << n << " bytes of TCP header";
  }
}

// --- exit test 3: TCP data offset
// -----------------------------------------------------------------

TEST(L4, TcpDataOffsetBelowFiveIsMalformed) {
  for (std::size_t doff = 0; doff < 5; ++doff) {
    const auto packet = ipv4_packet(kIpProtoTcp, tcp_header(1, 2, doff, 20));
    EXPECT_FALSE(l4_of(packet).has_value()) << "doff " << doff;
  }
}

TEST(L4, TcpDataOffsetMustFitInThePayload) {
  EXPECT_FALSE(l4_of(ipv4_packet(kIpProtoTcp, tcp_header(1, 2, 6, 20))).has_value());
  EXPECT_FALSE(l4_of(ipv4_packet(kIpProtoTcp, tcp_header(1, 2, 15, 59))).has_value());
  EXPECT_TRUE(l4_of(ipv4_packet(kIpProtoTcp, tcp_header(1, 2, 15, 60))).has_value());
  EXPECT_TRUE(l4_of(ipv4_packet(kIpProtoTcp, tcp_header(1, 2, 5, 20))).has_value());
}

TEST(L4, TcpFieldsAfterOptions) {
  std::vector<std::byte> tcp = tcp_header(49152, 22, 8, 40);  // 12 bytes of options
  wr_be32(tcp, 4, 0xDEADBEEFU);
  wr_be32(tcp, 8, 0x01020304U);
  wr_u8(tcp, 13, 0x12);  // SYN|ACK
  const auto l4 = l4_of(ipv4_packet(kIpProtoTcp, tcp));
  ASSERT_TRUE(l4.has_value());
  EXPECT_TRUE(l4->ports_valid);
  EXPECT_EQ(l4->sport, 49152);
  EXPECT_EQ(l4->dport, 22);
  EXPECT_EQ(l4->seq, 0xDEADBEEFU);
  EXPECT_EQ(l4->ack, 0x01020304U);
  EXPECT_EQ(l4->tcp_flags, 0x12);
}

// --- exit test 4: UDP length
// ----------------------------------------------------------------------

TEST(L4, UdpLengthBelowEightIsMalformed) {
  for (std::uint16_t length = 0; length < 8; ++length) {
    EXPECT_FALSE(l4_of(ipv4_packet(kIpProtoUdp, udp_header(1, 2, length))).has_value())
        << "length " << length;
  }
  EXPECT_TRUE(l4_of(ipv4_packet(kIpProtoUdp, udp_header(1, 2, 8))).has_value());
}

TEST(L4, UdpNeedsAllEightHeaderBytes) {
  const std::vector<std::byte> udp = udp_header(1, 2, 8);
  EXPECT_FALSE(l4_of(ipv4_packet(kIpProtoUdp, CBytes{udp}.first(7))).has_value());
}

// --- ICMP, and everything else ------------------------------------------------------------------

TEST(L4, IcmpHasATypeAndCodeButNoPorts) {
  std::vector<std::byte> icmp(8, std::byte{0});
  wr_u8(icmp, 0, 3);  // destination unreachable
  wr_u8(icmp, 1, 1);  // host unreachable
  const auto l4 = l4_of(ipv4_packet(kIpProtoIcmp, icmp));
  ASSERT_TRUE(l4.has_value());
  EXPECT_FALSE(l4->ports_valid);
  EXPECT_EQ(l4->icmp_type, 3);
  EXPECT_EQ(l4->icmp_code, 1);
  EXPECT_FALSE(l4_of(ipv4_packet(kIpProtoIcmp, CBytes{icmp}.first(7))).has_value());
}

TEST(L4, AProtocolWithoutPortsIsNotMalformed) {
  for (const std::uint8_t protocol : {std::uint8_t{47}, std::uint8_t{89}, std::uint8_t{255}}) {
    for (const std::size_t payload : {std::size_t{0}, std::size_t{3}, std::size_t{40}}) {
      const std::vector<std::byte> data(payload, std::byte{0xAB});
      const auto l4 = l4_of(ipv4_packet(protocol, data));
      ASSERT_TRUE(l4.has_value()) << "protocol " << int{protocol} << ", " << payload << " bytes";
      EXPECT_EQ(l4->protocol, protocol);
      EXPECT_FALSE(l4->ports_valid);
      EXPECT_EQ(l4->sport, 0);
    }
  }
}

// --- exit test 5: truncation
// ----------------------------------------------------------------------

// Every length of L4 data from nothing up to the whole of a real packet's, each behind a
// consistent IP header in an exactly-sized buffer: short headers must be rejected, and nothing
// may be read past the end.
void sweep_l4(const std::string& fixture, std::size_t min_header) {
  const std::vector<std::byte> packet = ip_packet(npf::test::fixture_frame(fixture));
  const auto ip = Ipv4View::parse(packet);
  ASSERT_TRUE(ip.has_value());
  const CBytes l4 = ip->payload();
  for (std::size_t n = 0; n <= l4.size(); ++n) {
    const auto truncated = ipv4_packet(ip->protocol(), l4.first(n));
    const auto parsed = l4_of(truncated);
    if (n < min_header) {
      EXPECT_FALSE(parsed.has_value()) << fixture << ": accepted " << n << " bytes";
    }
  }
}

TEST(L4, TruncationSweepTcp) {
  sweep_l4("tcp_syn", 24);
}  // data offset 6: 24-byte header
TEST(L4, TruncationSweepUdp) {
  sweep_l4("vlan_ipv4", 8);
}
TEST(L4, TruncationSweepIcmp) {
  sweep_l4("icmp_echo_request", 8);
}

// --- IcmpView
// -------------------------------------------------------------------------------------

std::vector<std::byte> icmp_message(const std::string& fixture) {
  const std::vector<std::byte> packet = ip_packet(npf::test::fixture_frame(fixture));
  const auto ip = Ipv4View::parse(packet);
  if (!ip) {
    ADD_FAILURE() << fixture << " is not IPv4";
    return {};
  }
  return std::vector<std::byte>(ip->payload().begin(), ip->payload().end());
}

TEST(Icmp, EchoRequestFixture) {
  const std::vector<std::byte> msg = icmp_message("icmp_echo_request");
  const auto icmp = IcmpView::parse(msg);
  ASSERT_TRUE(icmp.has_value());
  EXPECT_EQ(icmp->type(), npf::proto::kIcmpEchoRequest);
  EXPECT_EQ(icmp->code(), 0);
  EXPECT_EQ(icmp->echo_id(), 0x0457);
  EXPECT_EQ(icmp->echo_seq(), 1);
  EXPECT_FALSE(icmp->is_error());
  EXPECT_EQ(icmp->payload().size(), std::string{"npf-ping-payload"}.size());
}

TEST(Icmp, TimeExceededCarriesTheOriginalHeaderAndEightBytes) {
  const std::vector<std::byte> msg = icmp_message("icmp_time_exceeded");
  const auto icmp = IcmpView::parse(msg);
  ASSERT_TRUE(icmp.has_value());
  EXPECT_EQ(icmp->type(), npf::proto::kIcmpTimeExceeded);
  EXPECT_EQ(icmp->code(), 0);
  EXPECT_TRUE(icmp->is_error());
  ASSERT_EQ(icmp->payload().size(), 28U);  // the expired datagram's 20-byte header, plus 8
  EXPECT_EQ(npf::core::rd_u8(icmp->payload(), 0), 0x45);
  EXPECT_EQ(npf::core::rd_u8(icmp->payload(), 8), 1);  // its TTL, which ran out
  EXPECT_EQ(npf::core::rd_be32(icmp->payload(), 16), ip4(10, 0, 2, 2));
}

TEST(Icmp, RejectsABadChecksumAndAShortMessage) {
  std::vector<std::byte> msg = icmp_message("icmp_echo_request");
  ASSERT_TRUE(IcmpView::parse(msg).has_value());
  msg.back() ^= std::byte{0x01};
  EXPECT_FALSE(IcmpView::parse(msg).has_value());
  EXPECT_FALSE(IcmpView::parse(CBytes{msg}.first(7)).has_value());
}

TEST(Icmp, OnlyTheErrorTypesAreErrors) {
  for (unsigned type = 0; type <= 255; ++type) {
    std::array<std::byte, 8> msg{};
    wr_u8(msg, 0, static_cast<std::uint8_t>(type));
    wr_be16(msg, 2, static_cast<std::uint16_t>(~npf::proto::ones_complement_sum(msg)));
    const auto icmp = IcmpView::parse(msg);
    ASSERT_TRUE(icmp.has_value()) << "type " << type;
    const bool expected = type == 3 || type == 4 || type == 5 || type == 11 || type == 12;
    EXPECT_EQ(icmp->is_error(), expected) << "type " << type;
  }
}

void touch(const IcmpView& icmp) {
  static_cast<void>(icmp.type());
  static_cast<void>(icmp.code());
  static_cast<void>(icmp.checksum());
  static_cast<void>(icmp.echo_id());
  static_cast<void>(icmp.echo_seq());
  static_cast<void>(icmp.is_error());
  for (const std::byte b : icmp.payload()) {
    static_cast<void>(b);
  }
}

TEST(Icmp, TruncationSweep) {
  npf::test::TruncationSweep<IcmpView>(icmp_message("icmp_time_exceeded"), touch);
}

}  // namespace
