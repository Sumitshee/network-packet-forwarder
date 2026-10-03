#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <npf/core/byte_span.hpp>
#include <npf/core/config.hpp>
#include <npf/core/packet.hpp>
#include <npf/core/pool.hpp>
#include <npf/pipe/decision.hpp>
#include <npf/pipe/filter.hpp>
#include <npf/pipe/forward.hpp>
#include <npf/proto/arp.hpp>
#include <npf/proto/checksum.hpp>
#include <npf/proto/ethernet.hpp>
#include <npf/proto/ipv4.hpp>
#include <npf/proto/l4.hpp>
#include <npf/proto/mac.hpp>
#include <npf/stat/counters.hpp>
#include <npf/table/arp_cache.hpp>
#include <npf/table/fib.hpp>
#include <npf/table/lpm_linear.hpp>
#include <npf/table/mac_table.hpp>
#include <optional>
#include <ostream>
#include <set>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

#include "support/alloc_counter.hpp"
#include "support/proto_helpers.hpp"

namespace npf {

// Found by argument-dependent lookup, so GoogleTest prints names instead of numbers.
void PrintTo(Verdict v, std::ostream* os) {
  constexpr std::array<const char*, 4> kNames{"Forward", "Flood", "ToHost", "Drop"};
  *os << kNames.at(static_cast<std::size_t>(v));
}

void PrintTo(DropReason r, std::ostream* os) {
  *os << to_string(r);
}

}  // namespace npf

namespace {

using npf::Decision;
using npf::DropReason;
using npf::PortMode;
using npf::Verdict;
using npf::core::CBytes;
using npf::core::Config;
using npf::core::Packet;
using npf::core::PacketPool;
using npf::core::rd_be16;
using npf::core::wr_be16;
using npf::core::wr_be32;
using npf::core::wr_u8;
using npf::pipe::Forwarder;
using npf::proto::ArpView;
using npf::proto::EthView;
using npf::proto::Ipv4View;
using npf::proto::kBroadcastMac;
using npf::proto::kEtherTypeArp;
using npf::proto::kEtherTypeIpv4;
using npf::proto::MacAddr;
using npf::stat::Counters;
using npf::table::LinearLpm;
using npf::test::AllocCounter;
using npf::test::ip4;

using Frame = std::vector<std::byte>;
using Request = std::pair<std::uint32_t, std::uint16_t>;  // target address, port

constexpr MacAddr kPort0Mac{{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}};
constexpr MacAddr kPort1Mac{{0x02, 0x00, 0x00, 0x00, 0x00, 0x11}};
constexpr MacAddr kPort2Mac{{0x02, 0x00, 0x00, 0x00, 0x00, 0x12}};
constexpr MacAddr kClientMac{{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01}};
constexpr MacAddr kServerMac{{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02}};
constexpr MacAddr kStrangerMac{{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x99}};

constexpr std::uint32_t kPort0Ip = ip4(10, 0, 1, 1);
constexpr std::uint32_t kPort1Ip = ip4(10, 0, 2, 1);
constexpr std::uint32_t kPort2Ip = ip4(10, 0, 3, 1);
constexpr std::uint32_t kClient = ip4(10, 0, 1, 2);
constexpr std::uint32_t kServer = ip4(10, 0, 2, 2);
constexpr std::uint32_t kGateway = ip4(10, 0, 2, 254);
constexpr std::uint32_t kNowhere = ip4(10, 9, 9, 9);

constexpr std::uint16_t kEtherTypeIpv6 = 0x86DD;
constexpr std::uint16_t kVlan = 10;

// --- frames --------------------------------------------------------------------------------------

Frame ethernet(MacAddr dst, MacAddr src, std::uint16_t type, CBytes payload,
               std::optional<std::uint16_t> vlan = std::nullopt) {
  Frame f(vlan ? 18 : 14);
  npf::proto::wr_mac(f, 0, dst);
  npf::proto::wr_mac(f, 6, src);
  if (vlan) {
    wr_be16(f, 12, npf::proto::kEtherTypeVlan);
    wr_be16(f, 14, *vlan);
  }
  wr_be16(f, f.size() - 2, type);
  f.insert(f.end(), payload.begin(), payload.end());
  return f;
}

// An ICMP echo request with eight bytes of data and a correct checksum.
Frame echo_request() {
  Frame m(16, std::byte{0x5A});
  wr_u8(m, 0, npf::proto::kIcmpEchoRequest);
  wr_u8(m, 1, 0);
  wr_be16(m, 2, 0);
  wr_be32(m, 4, 0x12340001);  // id 0x1234, seq 1
  wr_be16(m, 2, static_cast<std::uint16_t>(~npf::proto::ones_complement_sum(m)));
  return m;
}

// A 20-byte IPv4 header with a correct checksum, then `l4`.
Frame ipv4(std::uint32_t src, std::uint32_t dst, std::uint8_t ttl, CBytes l4,
           std::uint8_t protocol = npf::proto::kIpProtoIcmp) {
  Frame p(20);
  wr_u8(p, 0, 0x45);
  wr_be16(p, 2, static_cast<std::uint16_t>(20 + l4.size()));
  wr_u8(p, 8, ttl);
  wr_u8(p, 9, protocol);
  wr_be32(p, 12, src);
  wr_be32(p, 16, dst);
  wr_be16(p, 10, npf::proto::ipv4_header_checksum(p));
  p.insert(p.end(), l4.begin(), l4.end());
  return p;
}

// A ping, arriving on port 0 from the client unless told otherwise.
struct Ping {
  std::uint32_t src = kClient;
  std::uint32_t dst = kServer;
  std::uint8_t ttl = 64;
  MacAddr eth_dst = kPort0Mac;
  std::optional<std::uint16_t> vlan = std::nullopt;
};

Frame ping(const Ping& p = {}) {
  return ethernet(p.eth_dst, kClientMac, kEtherTypeIpv4, ipv4(p.src, p.dst, p.ttl, echo_request()),
                  p.vlan);
}

struct Arp {
  std::uint16_t oper = ArpView::kOpRequest;
  MacAddr eth_dst = kBroadcastMac;
  MacAddr sha = kClientMac;
  std::uint32_t spa = kClient;
  MacAddr tha{};
  std::uint32_t tpa = kPort0Ip;
  std::optional<std::uint16_t> vlan = std::nullopt;
  std::size_t padding = 0;  // zeros after the ARP body, as a 60-byte minimum frame carries
};

Frame arp(const Arp& a = {}) {
  Frame body(28 + a.padding);
  wr_be16(body, 0, ArpView::kHtypeEthernet);
  wr_be16(body, 2, kEtherTypeIpv4);
  wr_u8(body, 4, 6);
  wr_u8(body, 5, 4);
  wr_be16(body, 6, a.oper);
  npf::proto::wr_mac(body, 8, a.sha);
  wr_be32(body, 14, a.spa);
  npf::proto::wr_mac(body, 18, a.tha);
  wr_be32(body, 24, a.tpa);
  return ethernet(a.eth_dst, a.sha, kEtherTypeArp, body, a.vlan);
}

// --- the pipeline under test ---------------------------------------------------------------------

// The two routed ports of the phase 0.5 topology, and a bridged third.
Config topology() {
  Config c;
  c.interfaces = {
      {"veth-cr", 0, kPort0Ip, 24, PortMode::Routed, kPort0Mac},
      {"veth-sr", 1, kPort1Ip, 24, PortMode::Routed, kPort1Mac},
      {"br0", 2, kPort2Ip, 24, PortMode::Bridged, kPort2Mac},
  };
  return c;
}

class RecordingEvents final : public npf::table::ArpEvents {
 public:
  RecordingEvents() { requests.reserve(16); }  // so that asking never allocates in a test
  void send_arp_request(std::uint32_t target_ip, std::uint16_t out_port) override {
    requests.emplace_back(target_ip, out_port);
  }
  void unresolved(Packet* /*p*/) override {
    ADD_FAILURE() << "the phase 6 ARP cache never gives up on a packet";
  }
  std::vector<Request> requests;
};

class ForwarderTest : public ::testing::Test {
 protected:
  ForwarderTest() {
    EXPECT_TRUE(fib_.add({{ip4(10, 0, 1, 0), 24}, 0, 0}));
    EXPECT_TRUE(fib_.add({{ip4(10, 0, 2, 0), 24}, 0, 1}));
    EXPECT_TRUE(fib_.add({{ip4(172, 16, 0, 0), 16}, kGateway, 1}));
    arp_.insert_static(kServer, kServerMac, 1);
  }

  ~ForwarderTest() override {
    for (Packet* p : held_) {
      pool_.release(p);
    }
    EXPECT_EQ(pool_.available(), pool_.capacity());
  }

  ForwarderTest(const ForwarderTest&) = delete;
  ForwarderTest& operator=(const ForwarderTest&) = delete;
  ForwarderTest(ForwarderTest&&) = delete;
  ForwarderTest& operator=(ForwarderTest&&) = delete;

  // The frame as a packet that arrived on in_port. Held, for inspection, until the test ends.
  Packet* packet(CBytes frame, std::uint16_t in_port = 0) {
    Packet* p = pool_.acquire();
    if (p == nullptr) {
      throw std::runtime_error("the test pool is too small");
    }
    held_.push_back(p);
    p->resize(frame.size());
    std::ranges::copy(frame, p->data().begin());
    p->set_in_port(in_port);
    return p;
  }

  Decision process(CBytes frame, std::uint16_t in_port = 0) {
    return fwd_.process(*packet(frame, in_port));
  }

  // Packets the pipeline has counted itself: each Drop or ToHost adds exactly one, a Forward none.
  [[nodiscard]] std::uint64_t counted() const { return stats_.total_drops() + stats_.to_host; }

  PacketPool pool_{64};
  Config cfg_ = topology();
  LinearLpm fib_;
  RecordingEvents events_;
  npf::table::ArpCache arp_{events_, 64};
  npf::table::MacTable macs_{64};
  npf::pipe::Filter filter_{{}, npf::pipe::Action::Allow};
  Counters stats_;
  Forwarder<LinearLpm> fwd_{cfg_, fib_, arp_, macs_, filter_, stats_};
  std::vector<Packet*> held_;
};

void expect_drop(const Decision& d, DropReason reason) {
  EXPECT_EQ(d.verdict, Verdict::Drop);
  EXPECT_EQ(d.reason, reason);
}

// --- one test per step of ARCHITECTURE.md §11, in the order process() takes them -----------------

TEST_F(ForwarderTest, Step1ShortFrame) {
  expect_drop(process(Frame(13)), DropReason::ShortFrame);
  EXPECT_EQ(stats_.drop(DropReason::ShortFrame), 1U);
}

TEST_F(ForwarderTest, Step2OnlyIpv4AndArpPassTheEtherType) {
  expect_drop(process(ethernet(kPort0Mac, kClientMac, kEtherTypeIpv6, Frame(40))),
              DropReason::BadEtherType);
  expect_drop(process(npf::test::fixture_frame("lldp")), DropReason::BadEtherType);
  // A second VLAN tag is not unwrapped, so the inner tag is what the dispatch sees.
  expect_drop(process(npf::test::fixture_frame("qinq_double_tag")), DropReason::BadEtherType);
  EXPECT_EQ(stats_.drop(DropReason::BadEtherType), 3U);
}

TEST_F(ForwarderTest, Step3ArpForTheRouterGoesToTheHost) {
  EXPECT_EQ(process(arp()).verdict, Verdict::ToHost);                                 // broadcast
  EXPECT_EQ(process(arp({.eth_dst = kPort0Mac})).verdict, Verdict::ToHost);           // our MAC
  expect_drop(process(arp({.eth_dst = kStrangerMac})), DropReason::UnknownDestPort);  // not ours
  EXPECT_EQ(stats_.to_host, 2U);
}

TEST_F(ForwarderTest, Step4TransitFrameOnARoutedPortIsDropped) {
  expect_drop(process(ping({.eth_dst = kStrangerMac})), DropReason::UnknownDestPort);
}

TEST_F(ForwarderTest, Step4BroadcastIsRoutedOnlyWhenItIsForTheRouter) {
  EXPECT_EQ(process(ping({.dst = kPort0Ip, .eth_dst = kBroadcastMac})).verdict, Verdict::ToHost);
  expect_drop(process(ping({.eth_dst = kBroadcastMac})), DropReason::UnknownDestPort);
}

TEST_F(ForwarderTest, Step4BridgedPortCannotSwitchUntilPhase12) {
  expect_drop(process(ping({.src = ip4(10, 0, 3, 9), .eth_dst = kStrangerMac}), 2),
              DropReason::UnknownDestPort);
  // Addressed to the router itself, a frame on a bridged port is routed like any other.
  EXPECT_EQ(process(ping({.src = ip4(10, 0, 3, 9), .eth_dst = kPort2Mac}), 2).verdict,
            Verdict::Forward);
}

TEST_F(ForwarderTest, Step5MalformedIpv4Header) {
  Frame version6 = ping();
  wr_u8(version6, 14, 0x65);
  expect_drop(process(version6), DropReason::BadIpv4Header);
  Frame cut = ping();
  cut.resize(14 + 19);
  expect_drop(process(cut), DropReason::BadIpv4Header);
}

TEST_F(ForwarderTest, Step6BadChecksum) {
  Frame f = ping();
  wr_be16(f, 24, static_cast<std::uint16_t>(rd_be16(f, 24) ^ 0x0101U));
  expect_drop(process(f), DropReason::BadChecksum);
}

TEST_F(ForwarderTest, Step7MartianSource) {
  expect_drop(process(ping({.src = ip4(127, 0, 0, 1)})), DropReason::MartianSource);
  expect_drop(process(ping({.src = ip4(224, 0, 0, 5)})), DropReason::MartianSource);
}

TEST_F(ForwarderTest, Step8PacketsForTheRouterGoToTheHost) {
  EXPECT_EQ(process(ping({.dst = kPort0Ip})).verdict, Verdict::ToHost);
  EXPECT_EQ(process(ping({.dst = kPort1Ip})).verdict, Verdict::ToHost);  // another port's address
  EXPECT_EQ(stats_.to_host, 2U);
}

TEST_F(ForwarderTest, Step9TtlOfOneOrZeroExpires) {
  expect_drop(process(ping({.ttl = 1})), DropReason::TtlExpired);
  expect_drop(process(ping({.ttl = 0})), DropReason::TtlExpired);
  EXPECT_EQ(process(ping({.ttl = 2})).verdict, Verdict::Forward);
}

TEST_F(ForwarderTest, Step10MalformedL4HeaderIsStillForwardedUntilPhase11) {
  Frame udp(8);
  wr_be16(udp, 4, 4);  // a UDP length below its own header: parse_l4 refuses it
  const Frame f = ethernet(kPort0Mac, kClientMac, kEtherTypeIpv4,
                           ipv4(kClient, kServer, 64, udp, npf::proto::kIpProtoUdp));
  EXPECT_EQ(process(f).verdict, Verdict::Forward);
}

TEST_F(ForwarderTest, Step11NoRoute) {
  expect_drop(process(ping({.dst = kNowhere})), DropReason::NoRoute);
}

TEST_F(ForwarderTest, Step12UnresolvedNeighbourIsAskedForThenDropped) {
  const Frame f = ping({.dst = ip4(10, 0, 2, 3)});
  expect_drop(process(f), DropReason::ArpUnresolved);
  ASSERT_EQ(events_.requests.size(), 1U);
  EXPECT_EQ(events_.requests[0], (Request{ip4(10, 0, 2, 3), 1}));
  // Once a second, not once a packet.
  expect_drop(process(f), DropReason::ArpUnresolved);
  EXPECT_EQ(events_.requests.size(), 1U);
  arp_.tick(std::chrono::steady_clock::time_point{} + npf::table::kArpProbeInterval);
  expect_drop(process(f), DropReason::ArpUnresolved);
  EXPECT_EQ(events_.requests.size(), 2U);
}

TEST_F(ForwarderTest, Step12ARouteViaAGatewayAsksForTheGateway) {
  expect_drop(process(ping({.dst = ip4(172, 16, 5, 5)})), DropReason::ArpUnresolved);
  ASSERT_EQ(events_.requests.size(), 1U);
  EXPECT_EQ(events_.requests[0], (Request{kGateway, 1}));
}

TEST_F(ForwarderTest, Steps13And14RewriteAndForward) {
  const Frame in = ping();
  Packet* p = packet(in);
  const Decision d = fwd_.process(*p);
  ASSERT_EQ(d.verdict, Verdict::Forward);
  EXPECT_EQ(d.reason, DropReason::None);
  EXPECT_EQ(d.out_port, 1);

  const CBytes out = std::as_const(*p).data();
  ASSERT_EQ(out.size(), in.size());
  const std::optional<EthView> eth = EthView::parse(out);
  ASSERT_TRUE(eth.has_value());
  EXPECT_EQ(eth->dst(), kServerMac);
  EXPECT_EQ(eth->src(), kPort1Mac);
  const std::optional<Ipv4View> ip = Ipv4View::parse(eth->payload());
  ASSERT_TRUE(ip.has_value());
  EXPECT_EQ(ip->ttl(), 63);
  EXPECT_TRUE(npf::proto::ipv4_checksum_valid(ip->header()));
  // Nothing else changed: everything but the MACs, the TTL (byte 22) and the checksum (24, 25).
  for (std::size_t i = 12; i < in.size(); ++i) {
    if (i != 22 && i != 24 && i != 25) {
      EXPECT_EQ(out[i], in[i]) << "byte " << i;
    }
  }
  EXPECT_EQ(p->l3_offset(), 14);
  EXPECT_EQ(p->l4_offset(), 34);
  EXPECT_EQ(counted(), 0U);  // a Forward is counted by whoever transmits it
}

TEST_F(ForwarderTest, VlanTaggedFrameIsForwardedWithItsTag) {
  Packet* p = packet(ping({.vlan = kVlan}));
  ASSERT_EQ(fwd_.process(*p).verdict, Verdict::Forward);
  const std::optional<EthView> eth = EthView::parse(std::as_const(*p).data());
  ASSERT_TRUE(eth.has_value());
  EXPECT_EQ(eth->vlan_id(), kVlan);
  EXPECT_EQ(eth->dst(), kServerMac);
  const std::optional<Ipv4View> ip = Ipv4View::parse(eth->payload());
  ASSERT_TRUE(ip.has_value());
  EXPECT_EQ(ip->ttl(), 63);
  EXPECT_TRUE(npf::proto::ipv4_checksum_valid(ip->header()));
  EXPECT_EQ(p->l3_offset(), 18);
}

// Each frame fails two checks, and the earlier step is the one that names the reason.
TEST_F(ForwarderTest, StepsRunInTheirFixedOrder) {
  Frame martian_bad_sum = ping({.src = ip4(127, 0, 0, 1)});
  wr_be16(martian_bad_sum, 24, static_cast<std::uint16_t>(rd_be16(martian_bad_sum, 24) ^ 1U));
  expect_drop(process(martian_bad_sum), DropReason::BadChecksum);  // 6, not 7
  expect_drop(process(ping({.src = ip4(127, 0, 0, 1), .ttl = 1})),
              DropReason::MartianSource);                                           // 7, not 9
  EXPECT_EQ(process(ping({.dst = kPort0Ip, .ttl = 1})).verdict, Verdict::ToHost);   // 8, not 9
  expect_drop(process(ping({.dst = kNowhere, .ttl = 1})), DropReason::TtlExpired);  // 9, not 11
}

TEST_F(ForwarderTest, EveryPacketIsCountedExactlyOnce) {
  const std::vector<std::pair<Frame, std::uint16_t>> frames{
      {Frame(5), 0},
      {ethernet(kPort0Mac, kClientMac, kEtherTypeIpv6, Frame(40)), 0},
      {arp(), 0},
      {ping({.eth_dst = kStrangerMac}), 0},
      {ping({.src = ip4(127, 0, 0, 1)}), 0},
      {ping({.dst = kPort1Ip}), 0},
      {ping({.ttl = 1}), 0},
      {ping({.dst = kNowhere}), 0},
      {ping({.dst = ip4(10, 0, 2, 3)}), 0},
      {ping(), 0},
      {ping({.src = ip4(10, 0, 3, 9), .eth_dst = kStrangerMac}), 2},
  };
  std::size_t forwards = 0;
  for (const auto& [frame, port] : frames) {
    const std::uint64_t before = counted();
    const Decision d = process(frame, port);
    if (d.verdict == Verdict::Forward) {
      ++forwards;
      EXPECT_EQ(counted(), before);
    } else {
      EXPECT_EQ(counted(), before + 1);
    }
  }
  EXPECT_EQ(counted() + forwards, frames.size());
  EXPECT_EQ(stats_.drop(DropReason::None), 0U);
}

// --- the host's half: deliver_to_host ------------------------------------------------------------

TEST_F(ForwarderTest, ArpRequestForThePortsAddressIsAnsweredInPlace) {
  Packet* p = packet(arp({.padding = 18}));  // a 60-byte frame, as it arrives off a wire
  ASSERT_EQ(fwd_.process(*p).verdict, Verdict::ToHost);
  EXPECT_EQ(fwd_.deliver_to_host(*p), std::optional<std::uint16_t>{0});
  EXPECT_EQ(stats_.arp_requests_rx, 1U);

  EXPECT_EQ(p->size(), npf::proto::kArpFrameSize);  // the padding is not sent back
  const std::optional<EthView> eth = EthView::parse(std::as_const(*p).data());
  ASSERT_TRUE(eth.has_value());
  EXPECT_EQ(eth->dst(), kClientMac);
  EXPECT_EQ(eth->src(), kPort0Mac);
  EXPECT_EQ(eth->ethertype(), kEtherTypeArp);
  const std::optional<ArpView> reply = ArpView::parse(eth->payload());
  ASSERT_TRUE(reply.has_value());
  EXPECT_EQ(reply->oper(), ArpView::kOpReply);
  EXPECT_EQ(reply->sha(), kPort0Mac);
  EXPECT_EQ(reply->spa(), kPort0Ip);
  EXPECT_EQ(reply->tha(), kClientMac);
  EXPECT_EQ(reply->tpa(), kClient);
}

TEST_F(ForwarderTest, ArpReplyKeepsTheRequestsVlanTag) {
  Packet* p = packet(arp({.vlan = kVlan}));
  ASSERT_EQ(fwd_.process(*p).verdict, Verdict::ToHost);
  ASSERT_EQ(fwd_.deliver_to_host(*p), std::optional<std::uint16_t>{0});
  const std::optional<EthView> eth = EthView::parse(std::as_const(*p).data());
  ASSERT_TRUE(eth.has_value());
  EXPECT_EQ(eth->vlan_id(), kVlan);
  const std::optional<ArpView> reply = ArpView::parse(eth->payload());
  ASSERT_TRUE(reply.has_value());
  EXPECT_EQ(reply->oper(), ArpView::kOpReply);
  EXPECT_EQ(reply->spa(), kPort0Ip);
}

TEST_F(ForwarderTest, EachPortAnswersOnlyForItsOwnAddress) {
  for (const std::uint32_t target : {kPort1Ip, ip4(10, 0, 1, 77)}) {
    Packet* p = packet(arp({.tpa = target}));
    ASSERT_EQ(fwd_.process(*p).verdict, Verdict::ToHost);
    EXPECT_FALSE(fwd_.deliver_to_host(*p).has_value());
  }
}

TEST_F(ForwarderTest, ArpReplyCompletesTheEntryTheCacheAskedFor) {
  // The server answering the client: the router does not know the client's MAC yet.
  const Frame back =
      ethernet(kPort1Mac, kServerMac, kEtherTypeIpv4, ipv4(kServer, kClient, 64, echo_request()));
  expect_drop(process(back, 1), DropReason::ArpUnresolved);
  ASSERT_EQ(events_.requests.size(), 1U);
  EXPECT_EQ(events_.requests[0], (Request{kClient, 0}));

  Packet* reply = packet(
      arp({.oper = ArpView::kOpReply, .eth_dst = kPort0Mac, .tha = kPort0Mac, .tpa = kPort0Ip}));
  ASSERT_EQ(fwd_.process(*reply).verdict, Verdict::ToHost);
  EXPECT_FALSE(fwd_.deliver_to_host(*reply).has_value());
  EXPECT_EQ(stats_.arp_replies_rx, 1U);

  Packet* p = packet(back, 1);
  const Decision d = fwd_.process(*p);
  ASSERT_EQ(d.verdict, Verdict::Forward);
  EXPECT_EQ(d.out_port, 0);
  EXPECT_EQ(EthView::parse(std::as_const(*p).data())->dst(), kClientMac);
}

TEST_F(ForwarderTest, ArpReplyNobodyAskedForIsIgnored) {
  // Believing this would let anyone on the segment point any address at any MAC.
  Packet* reply = packet(arp({.oper = ArpView::kOpReply,
                              .eth_dst = kPort0Mac,
                              .sha = kStrangerMac,
                              .spa = ip4(10, 0, 1, 99),
                              .tha = kPort0Mac,
                              .tpa = kPort0Ip}));
  ASSERT_EQ(fwd_.process(*reply).verdict, Verdict::ToHost);
  EXPECT_FALSE(fwd_.deliver_to_host(*reply).has_value());
  EXPECT_EQ(arp_.size(), 1U);  // the static entry for the server, and nothing else
  expect_drop(process(ping({.dst = ip4(10, 0, 1, 99)})), DropReason::ArpUnresolved);
}

TEST_F(ForwarderTest, GratuitousArpRefreshesButNeverCreates) {
  const auto gratuitous = [this](MacAddr sha, std::uint32_t addr) {
    Packet* p = packet(arp({.sha = sha, .spa = addr, .tpa = addr}));
    ASSERT_EQ(fwd_.process(*p).verdict, Verdict::ToHost);
    EXPECT_FALSE(fwd_.deliver_to_host(*p).has_value());
  };
  gratuitous(kStrangerMac, ip4(10, 0, 1, 77));  // unknown: not created
  EXPECT_EQ(arp_.size(), 1U);
  gratuitous(kStrangerMac, kServer);  // static: not overwritten
  EXPECT_EQ(arp_.lookup(kServer), kServerMac);

  expect_drop(process(ping({.dst = kClient})), DropReason::ArpUnresolved);  // now the cache asks...
  gratuitous(kClientMac, kClient);  // ...and an announcement may complete what it asked for
  EXPECT_EQ(arp_.lookup(kClient), kClientMac);
}

// --- the rules every datapath function lives by --------------------------------------------------

// CLAUDE.md rule 4, for the pipeline and the host path, across every kind of outcome.
TEST_F(ForwarderTest, ProcessBurstAndTheHostPathNeverAllocate) {
  std::vector<Packet*> burst{
      packet(ping()),                           // forwarded
      packet(ping({.ttl = 1})),                 // dropped
      packet(ping({.dst = kNowhere})),          // no route
      packet(ping({.dst = ip4(10, 0, 2, 3)})),  // ARP miss: a request goes out
      packet(arp()),                            // to the host, answered in place
  };
  std::array<Decision, 5> out{};
  AllocCounter::reset();
  fwd_.process_burst(burst.data(), burst.size(), out.data());
  const std::optional<std::uint16_t> answer = fwd_.deliver_to_host(*burst.back());
  EXPECT_EQ(AllocCounter::allocations(), 0U);
  EXPECT_EQ(AllocCounter::deallocations(), 0U);

  EXPECT_EQ(out[0].verdict, Verdict::Forward);
  EXPECT_EQ(out[1].reason, DropReason::TtlExpired);
  EXPECT_EQ(out[2].reason, DropReason::NoRoute);
  EXPECT_EQ(out[3].reason, DropReason::ArpUnresolved);
  EXPECT_EQ(out[4].verdict, Verdict::ToHost);
  EXPECT_EQ(answer, std::optional<std::uint16_t>{0});
  EXPECT_EQ(events_.requests.size(), 1U);

  // Those zeros mean something only if this binary counts allocations at all.
  AllocCounter::reset();
  int* volatile probe = new int{1};
  delete probe;
  EXPECT_EQ(AllocCounter::allocations(), 1U);
}

TEST(PortTable, NeedsPortIdsFromZeroAndEveryMac) {
  Config gap = topology();
  gap.interfaces[2].port = 5;
  EXPECT_THROW((void)npf::pipe::make_port_table(gap), std::invalid_argument);
  Config twice = topology();
  twice.interfaces[2].port = 0;
  EXPECT_THROW((void)npf::pipe::make_port_table(twice), std::invalid_argument);
  Config unresolved = topology();
  unresolved.interfaces[1].mac.reset();
  EXPECT_THROW((void)npf::pipe::make_port_table(unresolved), std::invalid_argument);
  EXPECT_EQ(npf::pipe::make_port_table(topology()).size(), 3U);
}

TEST(Filter, TheStubRefusesRulesRatherThanIgnoreThem) {
  EXPECT_THROW(npf::pipe::Filter({npf::pipe::Rule{}}, npf::pipe::Action::Allow),
               std::invalid_argument);
}

TEST(Counters, MergeAddsEveryCounter) {
  Counters a;
  Counters b;
  b.rx_packets = 3;
  b.tx_bytes = 100;
  b.to_host = 2;
  b.drop(DropReason::NoRoute) = 4;
  b.count_protocol(17);
  a.merge(b);
  a.merge(b);
  EXPECT_EQ(a.rx_packets, 6U);
  EXPECT_EQ(a.tx_bytes, 200U);
  EXPECT_EQ(a.to_host, 4U);
  EXPECT_EQ(a.drop(DropReason::NoRoute), 8U);
  EXPECT_EQ(a.total_drops(), 8U);
  EXPECT_EQ(a.by_protocol[17], 2U);
}

TEST(DropReason, EveryReasonHasANameOfItsOwn) {
  std::set<std::string_view> names;
  for (std::size_t r = 0; r < npf::kDropReasons; ++r) {
    const std::string_view name = npf::to_string(static_cast<DropReason>(r));
    EXPECT_NE(name, "?");
    names.insert(name);
  }
  EXPECT_EQ(names.size(), npf::kDropReasons);
}

}  // namespace
