#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <npf/core/byte_span.hpp>
#include <npf/core/config.hpp>
#include <npf/core/packet.hpp>
#include <npf/core/pool.hpp>
#include <npf/core/time.hpp>
#include <npf/pipe/decision.hpp>
#include <npf/pipe/filter.hpp>
#include <npf/pipe/forward.hpp>
#include <npf/proto/arp.hpp>
#include <npf/proto/checksum.hpp>
#include <npf/proto/ethernet.hpp>
#include <npf/proto/icmp.hpp>
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

// Filter rules here are designated initializers naming only the fields a rule constrains. C++20
// gives the rest their default, nullopt, which is "any" -- but GCC 13 warns of each.
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"

namespace npf {

// Found by argument-dependent lookup, so GoogleTest prints names instead of numbers.
void PrintTo(Verdict v, std::ostream* os) {
  constexpr std::array<const char*, 5> kNames{"Forward", "Flood", "ToHost", "Drop", "Queued"};
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
using npf::pipe::Action;
using npf::pipe::Filter;
using npf::pipe::Forwarder;
using npf::pipe::PortRange;
using npf::pipe::Reply;
using npf::pipe::Rule;
using npf::proto::ArpView;
using npf::proto::EthView;
using npf::proto::IcmpView;
using npf::proto::Ipv4View;
using npf::proto::kBroadcastMac;
using npf::proto::kEtherTypeArp;
using npf::proto::kEtherTypeIpv4;
using npf::proto::MacAddr;
using npf::stat::Counters;
using npf::table::LinearLpm;
using npf::table::Prefix;
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

constexpr npf::core::Clock::time_point kNow{std::chrono::hours{1}};

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

// An ICMP message with `data` bytes after its header and a correct checksum.
Frame icmp(std::uint8_t type, std::uint8_t code, std::size_t data = 8) {
  Frame m(8 + data, std::byte{0x5A});
  wr_u8(m, 0, type);
  wr_u8(m, 1, code);
  wr_be16(m, 2, 0);
  wr_be32(m, 4, 0x12340001);  // for an echo: id 0x1234, seq 1
  wr_be16(m, 2, static_cast<std::uint16_t>(~npf::proto::ones_complement_sum(m)));
  return m;
}

// An ICMP echo request with eight bytes of data.
Frame echo_request() {
  return icmp(npf::proto::kIcmpEchoRequest, 0);
}

// An untagged IPv4 frame with its flags and fragment offset replaced, and its checksum redone.
Frame with_flags_frag(Frame f, std::uint16_t flags_frag) {
  const std::span<std::byte> header = std::span(f).subspan(14, 20);
  wr_be16(header, 6, flags_frag);
  wr_be16(header, 10, 0);
  wr_be16(header, 10, npf::proto::ipv4_header_checksum(header));
  return f;
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

// Every packet in these tests is the fixture's, held until the test ends, so when the ARP cache
// lets go of one, that is only written down.
class RecordingEvents final : public npf::table::ArpEvents {
 public:
  RecordingEvents() {  // so that recording never allocates in a test
    requests.reserve(16);
    unresolved_heads.reserve(16);
    discarded.reserve(16);
  }
  void send_arp_request(std::uint32_t target_ip, std::uint16_t out_port) override {
    requests.emplace_back(target_ip, out_port);
  }
  void unresolved(Packet* p) override { unresolved_heads.push_back(p); }
  void discard(Packet* p) override { discarded.push_back(p); }
  std::vector<Request> requests;
  std::vector<Packet*> unresolved_heads;
  std::vector<Packet*> discarded;
};

class ForwarderTest : public ::testing::Test {
 protected:
  ForwarderTest() {
    EXPECT_TRUE(fib_.add({{ip4(10, 0, 1, 0), 24}, 0, 0}));
    EXPECT_TRUE(fib_.add({{ip4(10, 0, 2, 0), 24}, 0, 1}));
    EXPECT_TRUE(fib_.add({{ip4(172, 16, 0, 0), 16}, kGateway, 1}));
    arp_.insert_static(kServer, kServerMac, 1);
    arp_.tick(kNow);
  }

  ~ForwarderTest() override {
    arp_.flush();  // what it still holds is in held_ too
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

  // deliver_to_host(), holding any new packet it answers with until the test ends.
  std::optional<Reply> answer(Packet* p) {
    std::optional<Reply> reply = fwd_.deliver_to_host(*p, pool_, kNow);
    if (reply && reply->packet != p) {
      held_.push_back(reply->packet);
    }
    return reply;
  }

  // error_for(), holding the error, if there is one, until the test ends.
  Packet* error_for(Packet* p, DropReason reason) {
    Packet* error = fwd_.error_for(*p, reason, pool_, kNow);
    if (error != nullptr) {
      held_.push_back(error);
    }
    return error;
  }

  // host_unreachable(), the same way.
  Packet* host_unreachable(Packet* p) {
    Packet* error = fwd_.host_unreachable(*p, pool_, kNow);
    if (error != nullptr) {
      held_.push_back(error);
    }
    return error;
  }

  // Lets the ARP cache's clock run until it has given up on every neighbour it is asking for.
  void wait_out_arp() {
    for (std::uint8_t s = 1; s <= npf::table::kArpMaxProbes; ++s) {
      arp_.tick(kNow + std::chrono::seconds{s});
    }
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

TEST_F(ForwarderTest, Step10ADeniedPacketIsDroppedAsFilterDeny) {
  filter_ = Filter({{.action = Action::Deny, .protocol = npf::proto::kIpProtoIcmp}}, Action::Allow);
  expect_drop(process(ping()), DropReason::FilterDeny);
  EXPECT_EQ(stats_.drop(DropReason::FilterDeny), 1U);
  EXPECT_EQ(counted(), 1U);
}

TEST_F(ForwarderTest, Step10TheFilterSeesThePortAPacketArrivedOn) {
  filter_ = Filter({{.action = Action::Deny, .in_port = std::uint16_t{1}}}, Action::Allow);
  expect_drop(process(ping({.eth_dst = kPort1Mac}), 1), DropReason::FilterDeny);
  EXPECT_EQ(process(ping()).verdict, Verdict::Forward);  // the same ping, on port 0
}

// A UDP datagram whose length field is below its own header's size: parse_l4 refuses it.
Frame malformed_udp() {
  Frame udp(8);
  wr_be16(udp, 2, 53);
  wr_be16(udp, 4, 4);
  return ethernet(kPort0Mac, kClientMac, kEtherTypeIpv4,
                  ipv4(kClient, kServer, 64, udp, npf::proto::kIpProtoUdp));
}

TEST_F(ForwarderTest, Step10AMalformedHeaderIsDeniedWhileThereArePortRules) {
  // The port rule is for another port, and the policy allows: only the malformed header denies it.
  filter_ = Filter({{.action = Action::Deny, .dport = PortRange{9, 9}}}, Action::Allow);
  expect_drop(process(malformed_udp()), DropReason::FilterDeny);
}

TEST_F(ForwarderTest, Step10AMalformedHeaderIsForwardedWithoutPortRules) {
  EXPECT_EQ(process(malformed_udp()).verdict, Verdict::Forward);  // no rules at all
  filter_ = Filter({{.action = Action::Deny, .src = Prefix{kNowhere, 32}}}, Action::Allow);
  EXPECT_EQ(process(malformed_udp()).verdict, Verdict::Forward);
}

TEST_F(ForwarderTest, Step10AMalformedIcmpHeaderIsNotDeniedForPortRules) {
  // ICMP has no ports, so no port rule could have matched it anyway.
  filter_ = Filter({{.action = Action::Deny, .dport = PortRange{9, 9}}}, Action::Allow);
  const Frame truncated(4, std::byte{0});  // an ICMP header needs 8
  EXPECT_EQ(process(ethernet(kPort0Mac, kClientMac, kEtherTypeIpv4,
                             ipv4(kClient, kServer, 64, truncated)))
                .verdict,
            Verdict::Forward);
}

TEST_F(ForwarderTest, Step10Rfc1858sTinyFragmentIsDeniedNotLetThrough) {
  // The first fragment of a telnet SYN, cut after 8 bytes of TCP header: the ports, no flags. A
  // filter that relied on the port rule alone would let it through to "allow tcp".
  Frame tcp(8);
  wr_be16(tcp, 0, 40000);
  wr_be16(tcp, 2, 23);
  const Frame tiny =
      with_flags_frag(ethernet(kPort0Mac, kClientMac, kEtherTypeIpv4,
                               ipv4(kClient, kServer, 64, tcp, npf::proto::kIpProtoTcp)),
                      0x2000);  // more fragments, offset 0
  const Rule allow_tcp{.action = Action::Allow, .protocol = npf::proto::kIpProtoTcp};
  filter_ = Filter(
      {{.action = Action::Deny, .protocol = npf::proto::kIpProtoTcp, .dport = PortRange{23, 23}},
       allow_tcp},
      Action::Deny);
  expect_drop(process(tiny), DropReason::FilterDeny);
  filter_ = Filter({allow_tcp}, Action::Deny);  // with no port rules, nothing to evade
  EXPECT_EQ(process(tiny).verdict, Verdict::Forward);
}

TEST_F(ForwarderTest, Step10ComesAfterPacketsForTheRouterAndExpiringOnes) {
  filter_ = Filter({}, Action::Deny);
  EXPECT_EQ(process(ping({.dst = kPort0Ip})).verdict, Verdict::ToHost);  // step 8
  expect_drop(process(ping({.ttl = 1})), DropReason::TtlExpired);        // step 9
  expect_drop(process(ping({.ttl = 2})), DropReason::FilterDeny);        // step 10
}

TEST_F(ForwarderTest, Step11NoRoute) {
  expect_drop(process(ping({.dst = kNowhere})), DropReason::NoRoute);
}

TEST_F(ForwarderTest, Step12AnUnresolvedNeighbourIsAskedForWhileThePacketWaits) {
  const Frame f = ping({.dst = ip4(10, 0, 2, 3)});
  const Decision d = process(f);
  EXPECT_EQ(d.verdict, Verdict::Queued);
  EXPECT_EQ(d.reason, DropReason::None);
  EXPECT_EQ(d.out_port, 1);
  ASSERT_EQ(events_.requests.size(), 1U);
  EXPECT_EQ(events_.requests[0], (Request{ip4(10, 0, 2, 3), 1}));
  // Two more wait with it, asking nothing: the cache repeats its question once a second.
  EXPECT_EQ(process(f).verdict, Verdict::Queued);
  EXPECT_EQ(process(f).verdict, Verdict::Queued);
  EXPECT_EQ(events_.requests.size(), 1U);
  arp_.tick(kNow + npf::table::kArpProbeInterval);
  EXPECT_EQ(events_.requests.size(), 2U);
  EXPECT_EQ(counted(), 0U);  // a queued packet is counted once the cache lets go of it
}

TEST_F(ForwarderTest, Step12AFullQueueDropsThePacketWithoutAnError) {
  const Frame f = ping({.dst = ip4(10, 0, 2, 3)});
  for (std::size_t i = 0; i < npf::table::kArpQueueDepth; ++i) {
    ASSERT_EQ(process(f).verdict, Verdict::Queued);
  }
  Packet* p = packet(f);
  const Decision d = fwd_.process(*p);
  expect_drop(d, DropReason::ArpUnresolved);
  EXPECT_EQ(stats_.drop(DropReason::ArpUnresolved), 1U);
  // The neighbour may answer yet, so this is no reason to tell the sender it is unreachable.
  EXPECT_EQ(error_for(p, d.reason), nullptr);
}

TEST_F(ForwarderTest, Step12ARouteViaAGatewayAsksForTheGateway) {
  EXPECT_EQ(process(ping({.dst = ip4(172, 16, 5, 5)})).verdict, Verdict::Queued);
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
  std::size_t not_yet = 0;  // forwarded or queued: counted by whoever sends or drops them
  for (const auto& [frame, port] : frames) {
    const std::uint64_t before = counted();
    const Decision d = process(frame, port);
    if (d.verdict == Verdict::Forward || d.verdict == Verdict::Queued) {
      ++not_yet;
      EXPECT_EQ(counted(), before);
    } else {
      EXPECT_EQ(counted(), before + 1);
    }
  }
  EXPECT_EQ(counted() + not_yet, frames.size());
  EXPECT_EQ(stats_.drop(DropReason::None), 0U);
}

// --- the host's half: deliver_to_host ------------------------------------------------------------

TEST_F(ForwarderTest, ArpRequestForThePortsAddressIsAnsweredInPlace) {
  Packet* p = packet(arp({.padding = 18}));  // a 60-byte frame, as it arrives off a wire
  ASSERT_EQ(fwd_.process(*p).verdict, Verdict::ToHost);
  const std::optional<Reply> answered = answer(p);
  ASSERT_TRUE(answered.has_value());
  EXPECT_EQ(answered->packet, p);  // turned around in place
  EXPECT_EQ(answered->port, 0);
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
  const std::optional<Reply> answered = answer(p);
  ASSERT_TRUE(answered.has_value());
  ASSERT_EQ(answered->packet, p);
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
    EXPECT_FALSE(answer(p).has_value());
  }
}

// An ARP reply from a neighbour of port 1's, to the router.
Frame reply_on_port1(std::uint32_t spa, MacAddr sha) {
  return arp({.oper = ArpView::kOpReply,
              .eth_dst = kPort1Mac,
              .sha = sha,
              .spa = spa,
              .tha = kPort1Mac,
              .tpa = kPort1Ip});
}

TEST_F(ForwarderTest, ArpReplyReleasesThePacketThatWaitedForIt) {
  // The server answering the client: the router does not know the client's MAC yet.
  const Frame back =
      ethernet(kPort1Mac, kServerMac, kEtherTypeIpv4, ipv4(kServer, kClient, 64, echo_request()));
  Packet* waiting = packet(back, 1);
  const Decision d = fwd_.process(*waiting);
  ASSERT_EQ(d.verdict, Verdict::Queued);
  EXPECT_EQ(d.out_port, 0);
  ASSERT_EQ(events_.requests.size(), 1U);
  EXPECT_EQ(events_.requests[0], (Request{kClient, 0}));

  Packet* reply = packet(
      arp({.oper = ArpView::kOpReply, .eth_dst = kPort0Mac, .tha = kPort0Mac, .tpa = kPort0Ip}));
  ASSERT_EQ(fwd_.process(*reply).verdict, Verdict::ToHost);
  EXPECT_FALSE(answer(reply).has_value());
  EXPECT_EQ(stats_.arp_replies_rx, 1U);
  ASSERT_EQ(fwd_.released().size(), 1U);
  EXPECT_EQ(fwd_.released()[0].packet, waiting);
  EXPECT_EQ(fwd_.released()[0].port, 0);
  // Steps 13 and 14, now: the client's MAC, port 0's, one hop less to live.
  const std::optional<EthView> eth = EthView::parse(std::as_const(*waiting).data());
  ASSERT_TRUE(eth.has_value());
  EXPECT_EQ(eth->dst(), kClientMac);
  EXPECT_EQ(eth->src(), kPort0Mac);
  const std::optional<Ipv4View> ip = Ipv4View::parse(eth->payload());
  ASSERT_TRUE(ip.has_value());
  EXPECT_EQ(ip->ttl(), 63);
  EXPECT_TRUE(npf::proto::ipv4_checksum_valid(ip->header()));
  EXPECT_EQ(waiting->l3_offset(), 14);

  // The next packet goes straight through.
  Packet* p = packet(back, 1);
  const Decision next = fwd_.process(*p);
  ASSERT_EQ(next.verdict, Verdict::Forward);
  EXPECT_EQ(next.out_port, 0);
  EXPECT_EQ(EthView::parse(std::as_const(*p).data())->dst(), kClientMac);
}

TEST_F(ForwarderTest, TheWaitingPacketsLeaveInTheOrderTheyCame) {
  std::array<Packet*, npf::table::kArpQueueDepth> waiting{};
  std::uint8_t ttl = 10;  // tells them apart
  for (Packet*& p : waiting) {
    p = packet(ping({.dst = ip4(10, 0, 2, 3), .ttl = ttl++}));
    ASSERT_EQ(fwd_.process(*p).verdict, Verdict::Queued);
  }
  Packet* reply = packet(reply_on_port1(ip4(10, 0, 2, 3), kStrangerMac), 1);
  ASSERT_EQ(fwd_.process(*reply).verdict, Verdict::ToHost);
  EXPECT_FALSE(answer(reply).has_value());
  const std::span<const Reply> released = fwd_.released();
  ASSERT_EQ(released.size(), waiting.size());
  for (std::size_t i = 0; i < waiting.size(); ++i) {
    EXPECT_EQ(released[i].packet, waiting.at(i));
    EXPECT_EQ(released[i].port, 1);
    const std::optional<Ipv4View> ip =
        Ipv4View::parse(EthView::parse(std::as_const(*waiting.at(i)).data())->payload());
    ASSERT_TRUE(ip.has_value());
    EXPECT_EQ(ip->ttl(), static_cast<std::uint8_t>(9 + i));
  }
}

// The cache is keyed by address alone. Were an answer taken from any port, a station on another
// segment could answer for a neighbour, and steer its traffic.
TEST_F(ForwarderTest, AnArpAnswerCountsOnlyFromThePortTheCacheAskedOn) {
  const std::uint32_t neighbour = ip4(10, 0, 2, 3);  // asked for on port 1
  Packet* waiting = packet(ping({.dst = neighbour}));
  ASSERT_EQ(fwd_.process(*waiting).verdict, Verdict::Queued);
  const std::array<Frame, 2> from_port0{
      arp({.oper = ArpView::kOpReply,
           .eth_dst = kPort0Mac,
           .sha = kStrangerMac,
           .spa = neighbour,
           .tha = kPort0Mac,
           .tpa = kPort0Ip}),
      arp({.sha = kStrangerMac, .spa = neighbour, .tpa = neighbour}),  // an announcement
  };
  for (const Frame& f : from_port0) {
    Packet* p = packet(f, 0);
    ASSERT_EQ(fwd_.process(*p).verdict, Verdict::ToHost);
    EXPECT_FALSE(answer(p).has_value());
    EXPECT_TRUE(fwd_.released().empty());
  }
  EXPECT_EQ(arp_.peek(neighbour)->state, npf::table::ArpState::Incomplete);

  Packet* real = packet(reply_on_port1(neighbour, kServerMac), 1);
  ASSERT_EQ(fwd_.process(*real).verdict, Verdict::ToHost);
  EXPECT_FALSE(answer(real).has_value());
  ASSERT_EQ(fwd_.released().size(), 1U);
  EXPECT_EQ(EthView::parse(std::as_const(*waiting).data())->dst(), kServerMac);
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
  EXPECT_FALSE(answer(reply).has_value());
  EXPECT_EQ(arp_.size(), 1U);  // the static entry for the server, and nothing else
  EXPECT_EQ(process(ping({.dst = ip4(10, 0, 1, 99)})).verdict, Verdict::Queued);  // still asks
}

TEST_F(ForwarderTest, GratuitousArpRefreshesButNeverCreates) {
  const auto gratuitous = [this](MacAddr sha, std::uint32_t addr, std::uint16_t in_port) {
    Packet* p = packet(arp({.sha = sha, .spa = addr, .tpa = addr}), in_port);
    ASSERT_EQ(fwd_.process(*p).verdict, Verdict::ToHost);
    EXPECT_FALSE(answer(p).has_value());
  };
  gratuitous(kStrangerMac, ip4(10, 0, 1, 77), 0);  // unknown: not created
  EXPECT_EQ(arp_.size(), 1U);
  gratuitous(kStrangerMac, kServer, 1);  // static: not overwritten
  EXPECT_EQ(arp_.lookup(kServer), kServerMac);

  Packet* waiting = packet(ping({.dst = kClient}));
  ASSERT_EQ(fwd_.process(*waiting).verdict, Verdict::Queued);  // now the cache asks...
  gratuitous(kClientMac, kClient, 0);  // ...and an announcement answers, freeing what waited
  ASSERT_EQ(fwd_.released().size(), 1U);
  EXPECT_EQ(fwd_.released()[0].packet, waiting);
  EXPECT_EQ(arp_.lookup(kClient), kClientMac);
  gratuitous(kStrangerMac, kClient, 0);  // once known, an announcement refreshes it
  EXPECT_EQ(arp_.lookup(kClient), kStrangerMac);
}

// --- ICMP: what the router says back -------------------------------------------------------------

struct IcmpFrame {
  EthView eth;
  Ipv4View ip;
  IcmpView icmp;
};

// An ICMP message the router built, parsed from Ethernet down; nullopt if any layer fails to.
std::optional<IcmpFrame> parse_icmp(const Packet& p) {
  const std::optional<EthView> eth = EthView::parse(p.data());
  const std::optional<Ipv4View> ip = eth ? Ipv4View::parse(eth->payload()) : std::nullopt;
  const std::optional<IcmpView> icmp = ip ? IcmpView::parse(ip->payload()) : std::nullopt;
  if (!icmp || !npf::proto::ipv4_checksum_valid(ip->header())) {
    return std::nullopt;
  }
  return IcmpFrame{*eth, *ip, *icmp};
}

TEST_F(ForwarderTest, TtlExpiryEarnsTimeExceededFromTheArrivalPort) {
  Packet* p = packet(ping({.ttl = 1}));
  const Decision d = fwd_.process(*p);
  ASSERT_EQ(d.reason, DropReason::TtlExpired);
  Packet* error = error_for(p, d.reason);
  ASSERT_NE(error, nullptr);
  const std::optional<IcmpFrame> m = parse_icmp(*error);
  ASSERT_TRUE(m.has_value());
  EXPECT_EQ(m->eth.dst(), kClientMac);
  EXPECT_EQ(m->eth.src(), kPort0Mac);
  EXPECT_EQ(m->ip.src(), kPort0Ip);
  EXPECT_EQ(m->ip.dst(), kClient);
  EXPECT_EQ(m->icmp.type(), npf::proto::kIcmpTimeExceeded);
  EXPECT_EQ(m->icmp.code(), 0);
  // The original's header exactly as it arrived, TTL 1 and all.
  const std::optional<Ipv4View> orig =
      Ipv4View::parse(EthView::parse(std::as_const(*p).data())->payload());
  ASSERT_TRUE(orig.has_value());
  EXPECT_TRUE(std::ranges::equal(m->icmp.payload().first(20), orig->header()));
  EXPECT_EQ(stats_.icmp_generated, 1U);
}

TEST_F(ForwarderTest, AnErrorComesFromThePortThePacketArrivedOn) {
  // From the server's side, toward the client, with no hops left: 10.0.2.1 is the hop.
  Packet* p = packet(
      ethernet(kPort1Mac, kServerMac, kEtherTypeIpv4, ipv4(kServer, kClient, 1, echo_request())),
      1);
  const Decision d = fwd_.process(*p);
  ASSERT_EQ(d.reason, DropReason::TtlExpired);
  Packet* error = error_for(p, d.reason);
  ASSERT_NE(error, nullptr);
  const std::optional<IcmpFrame> m = parse_icmp(*error);
  ASSERT_TRUE(m.has_value());
  EXPECT_EQ(m->ip.src(), kPort1Ip);
  EXPECT_EQ(m->eth.src(), kPort1Mac);
  EXPECT_EQ(m->eth.dst(), kServerMac);
}

TEST_F(ForwarderTest, NoRouteEarnsNetUnreachable) {
  Packet* p = packet(ping({.dst = kNowhere}));
  const Decision d = fwd_.process(*p);
  ASSERT_EQ(d.reason, DropReason::NoRoute);
  Packet* error = error_for(p, d.reason);
  ASSERT_NE(error, nullptr);
  const std::optional<IcmpFrame> m = parse_icmp(*error);
  ASSERT_TRUE(m.has_value());
  EXPECT_EQ(m->icmp.type(), npf::proto::kIcmpDestUnreachable);
  EXPECT_EQ(m->icmp.code(), 0);
}

TEST_F(ForwarderTest, OtherDropsEarnNoError) {
  Frame bad_sum = ping();
  wr_be16(bad_sum, 24, static_cast<std::uint16_t>(rd_be16(bad_sum, 24) ^ 1U));
  const std::vector<std::pair<Frame, DropReason>> cases{
      {Frame(5), DropReason::ShortFrame},
      {bad_sum, DropReason::BadChecksum},
      {ping({.src = ip4(127, 0, 0, 1)}), DropReason::MartianSource},
      {ping({.eth_dst = kStrangerMac}), DropReason::UnknownDestPort},
  };
  for (const auto& [frame, reason] : cases) {
    Packet* p = packet(frame);
    ASSERT_EQ(fwd_.process(*p).reason, reason);
    EXPECT_EQ(error_for(p, reason), nullptr) << npf::to_string(reason);
  }
  EXPECT_EQ(stats_.icmp_generated, 0U);
}

// Each of these expires in transit, and none may earn a Time Exceeded (RFC 1812 §4.3.2.7).
TEST_F(ForwarderTest, NoErrorWhereRfc1812ForbidsOne) {
  const std::array<Frame, 3> frames{
      ethernet(kPort0Mac, kClientMac, kEtherTypeIpv4,  // an ICMP error itself
               ipv4(kClient, kServer, 1, icmp(npf::proto::kIcmpTimeExceeded, 0, 28))),
      with_flags_frag(ping({.ttl = 1}), 185),      // a fragment other than the first
      ping({.dst = ip4(224, 0, 0, 9), .ttl = 1}),  // to a multicast group
  };
  for (const Frame& f : frames) {
    Packet* p = packet(f);
    const Decision d = fwd_.process(*p);
    ASSERT_EQ(d.reason, DropReason::TtlExpired);
    EXPECT_EQ(error_for(p, d.reason), nullptr);
  }
  EXPECT_EQ(stats_.icmp_generated, 0U);
}

TEST_F(ForwarderTest, ANeighbourThatNeverAnswersEarnsHostUnreachable) {
  Packet* p = packet(ping({.dst = ip4(10, 0, 2, 3)}));
  ASSERT_EQ(fwd_.process(*p).verdict, Verdict::Queued);
  wait_out_arp();
  ASSERT_EQ(events_.unresolved_heads, std::vector<Packet*>{p});
  Packet* error = host_unreachable(p);
  ASSERT_NE(error, nullptr);
  const std::optional<IcmpFrame> m = parse_icmp(*error);
  ASSERT_TRUE(m.has_value());
  EXPECT_EQ(m->icmp.type(), npf::proto::kIcmpDestUnreachable);
  EXPECT_EQ(m->icmp.code(), 1);
  EXPECT_EQ(m->ip.src(), kPort0Ip);  // from the port the packet came in on, back out of it
  EXPECT_EQ(m->ip.dst(), kClient);
  EXPECT_EQ(m->eth.src(), kPort0Mac);
  EXPECT_EQ(m->eth.dst(), kClientMac);
  // The original as it arrived: a queued packet is rewritten only once its neighbour answers.
  const std::optional<Ipv4View> orig =
      Ipv4View::parse(EthView::parse(std::as_const(*p).data())->payload());
  ASSERT_TRUE(orig.has_value());
  EXPECT_EQ(orig->ttl(), 64);
  EXPECT_TRUE(std::ranges::equal(m->icmp.payload().first(20), orig->header()));
  EXPECT_EQ(stats_.icmp_generated, 1U);
}

// RFC 1812 §4.3.2.7: no error for a packet to a broadcast address. No host answers ARP for a
// subnet's broadcast address, so the cache always gives up on one.
TEST_F(ForwarderTest, NoHostUnreachableForTheBroadcastAddressOfAnAttachedSubnet) {
  Packet* broadcast = packet(ping({.dst = ip4(10, 0, 2, 255)}));
  ASSERT_EQ(fwd_.process(*broadcast).verdict, Verdict::Queued);
  Packet* host = packet(ping({.dst = ip4(10, 0, 2, 254)}));
  ASSERT_EQ(fwd_.process(*host).verdict, Verdict::Queued);
  wait_out_arp();
  ASSERT_EQ(events_.unresolved_heads.size(), 2U);
  EXPECT_EQ(host_unreachable(broadcast), nullptr);
  EXPECT_NE(host_unreachable(host), nullptr);
}

TEST_F(ForwarderTest, ErrorsAreLimitedToAHundredASecond) {
  Packet* p = packet(ping({.ttl = 1}));
  ASSERT_EQ(fwd_.process(*p).reason, DropReason::TtlExpired);
  int sent = 0;
  for (int i = 0; i < 150; ++i) {
    if (Packet* error = fwd_.error_for(*p, DropReason::TtlExpired, pool_, kNow); error != nullptr) {
      ++sent;
      pool_.release(error);
    }
  }
  EXPECT_EQ(sent, 100);
  // A second later the first token is back.
  Packet* later = fwd_.error_for(*p, DropReason::TtlExpired, pool_, kNow + std::chrono::seconds{1});
  EXPECT_NE(later, nullptr);
  if (later != nullptr) {
    pool_.release(later);
  }
}

TEST_F(ForwarderTest, PingToTheRouterGetsAnEchoReply) {
  Packet* p = packet(ping({.dst = kPort0Ip}));
  ASSERT_EQ(fwd_.process(*p).verdict, Verdict::ToHost);
  const std::optional<Reply> reply = answer(p);
  ASSERT_TRUE(reply.has_value());
  EXPECT_NE(reply->packet, p);  // a new packet; the request is still the caller's
  EXPECT_EQ(reply->port, 0);
  const std::optional<IcmpFrame> m = parse_icmp(*reply->packet);
  ASSERT_TRUE(m.has_value());
  EXPECT_EQ(m->eth.dst(), kClientMac);
  EXPECT_EQ(m->eth.src(), kPort0Mac);
  EXPECT_EQ(m->ip.src(), kPort0Ip);
  EXPECT_EQ(m->ip.dst(), kClient);
  EXPECT_EQ(m->icmp.type(), npf::proto::kIcmpEchoReply);
  EXPECT_EQ(m->icmp.echo_id(), 0x1234);
  EXPECT_EQ(m->icmp.echo_seq(), 1);
  EXPECT_EQ(stats_.icmp_generated, 1U);
}

TEST_F(ForwarderTest, PingToAnotherPortsAddressIsAnsweredFromThatAddress) {
  Packet* p = packet(ping({.dst = kPort1Ip}));  // 10.0.2.1, asked on the 10.0.1.0/24 side
  ASSERT_EQ(fwd_.process(*p).verdict, Verdict::ToHost);
  const std::optional<Reply> reply = answer(p);
  ASSERT_TRUE(reply.has_value());
  EXPECT_EQ(reply->port, 0);  // back the way it came
  const std::optional<IcmpFrame> m = parse_icmp(*reply->packet);
  ASSERT_TRUE(m.has_value());
  EXPECT_EQ(m->ip.src(), kPort1Ip);  // RFC 1812 §4.3.3.6: the address the request was sent to
  EXPECT_EQ(m->eth.src(), kPort0Mac);
}

TEST_F(ForwarderTest, UdpForTheRouterGetsProtocolUnreachable) {
  Frame udp(8);
  wr_be16(udp, 0, 40000);
  wr_be16(udp, 2, 33434);  // where traceroute aims
  wr_be16(udp, 4, 8);
  Packet* p = packet(ethernet(kPort0Mac, kClientMac, kEtherTypeIpv4,
                              ipv4(kClient, kPort0Ip, 64, udp, npf::proto::kIpProtoUdp)));
  ASSERT_EQ(fwd_.process(*p).verdict, Verdict::ToHost);
  const std::optional<Reply> reply = answer(p);
  ASSERT_TRUE(reply.has_value());
  const std::optional<IcmpFrame> m = parse_icmp(*reply->packet);
  ASSERT_TRUE(m.has_value());
  EXPECT_EQ(m->icmp.type(), npf::proto::kIcmpDestUnreachable);
  EXPECT_EQ(m->icmp.code(), 2);
  EXPECT_EQ(m->ip.src(), kPort0Ip);
}

TEST_F(ForwarderTest, OtherIcmpForTheRouterIsConsumedSilently) {
  const std::array<Frame, 3> messages{icmp(npf::proto::kIcmpEchoReply, 0),
                                      icmp(npf::proto::kIcmpDestUnreachable, 3, 28),
                                      icmp(42, 0)};  // a type no one knows (RFC 1812 §4.3.2.1)
  for (const Frame& message : messages) {
    Packet* p = packet(
        ethernet(kPort0Mac, kClientMac, kEtherTypeIpv4, ipv4(kClient, kPort0Ip, 64, message)));
    ASSERT_EQ(fwd_.process(*p).verdict, Verdict::ToHost);
    EXPECT_FALSE(answer(p).has_value());
  }
  EXPECT_EQ(stats_.icmp_generated, 0U);
}

TEST_F(ForwarderTest, AFragmentedPingToTheRouterGoesUnanswered) {
  Packet* p = packet(with_flags_frag(ping({.dst = kPort0Ip}), 0x2000));  // MF: more to come
  ASSERT_EQ(fwd_.process(*p).verdict, Verdict::ToHost);
  EXPECT_FALSE(answer(p).has_value());
}

// RFC 1812 §5.3.5.1: never forwarded, never discarded -- delivered to the router, which has
// nothing to say to it: no echo reply (§4.3.3.6 allows that), and no error (§4.3.2.7 forbids one).
TEST_F(ForwarderTest, TheLimitedBroadcastIsDeliveredLocallyAndNeverForwarded) {
  ASSERT_TRUE(fib_.add({{0, 0}, kGateway, 1}));  // a default route, which covers it too
  for (const MacAddr eth_dst : {kBroadcastMac, kPort0Mac}) {
    Packet* p = packet(ping({.dst = npf::pipe::kLimitedBroadcast, .eth_dst = eth_dst}));
    EXPECT_EQ(fwd_.process(*p).verdict, Verdict::ToHost);
    EXPECT_FALSE(answer(p).has_value());
  }
  EXPECT_TRUE(events_.requests.empty());  // nothing was routed toward the gateway
}

// RFC 1812 §5.2.6: a router never reassembles before forwarding. Each fragment goes on as it is.
TEST_F(ForwarderTest, FragmentsAreForwardedAsTheyAre) {
  for (const std::uint16_t flags_frag :
       {std::uint16_t{0x2000}, std::uint16_t{0x2000 | 185}, std::uint16_t{185}}) {
    Packet* p = packet(with_flags_frag(ping(), flags_frag));
    ASSERT_EQ(fwd_.process(*p).verdict, Verdict::Forward) << flags_frag;
    const std::optional<Ipv4View> ip =
        Ipv4View::parse(EthView::parse(std::as_const(*p).data())->payload());
    ASSERT_TRUE(ip.has_value());
    EXPECT_EQ(rd_be16(ip->header(), 6), flags_frag);  // flags and offset untouched
    EXPECT_EQ(ip->ttl(), 63);
    EXPECT_TRUE(npf::proto::ipv4_checksum_valid(ip->header()));
  }
}

// RFC 1812 §5.3.13.1: options a router does not recognize -- here, all of them -- pass unchanged.
TEST_F(ForwarderTest, IpOptionsAreForwardedUntouched) {
  const Frame message = echo_request();
  Frame ip(24, std::byte{0x01});  // a 20-byte header and one word of NOP options
  wr_u8(ip, 0, 0x46);
  wr_be16(ip, 2, static_cast<std::uint16_t>(24 + message.size()));
  wr_u8(ip, 8, 64);
  wr_u8(ip, 9, npf::proto::kIpProtoIcmp);
  wr_be16(ip, 10, 0);
  wr_be32(ip, 12, kClient);
  wr_be32(ip, 16, kServer);
  wr_be16(ip, 10, npf::proto::ipv4_header_checksum(ip));
  ip.insert(ip.end(), message.begin(), message.end());
  Packet* p = packet(ethernet(kPort0Mac, kClientMac, kEtherTypeIpv4, ip));
  ASSERT_EQ(fwd_.process(*p).verdict, Verdict::Forward);
  const std::optional<Ipv4View> out =
      Ipv4View::parse(EthView::parse(std::as_const(*p).data())->payload());
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(out->header_len(), 24U);
  EXPECT_EQ(out->ttl(), 63);
  EXPECT_TRUE(npf::proto::ipv4_checksum_valid(out->header()));
  EXPECT_TRUE(std::ranges::all_of(out->header().subspan(20),
                                  [](std::byte b) { return b == std::byte{0x01}; }));
  EXPECT_EQ(p->l4_offset(), 14 + 24);
}

// --- the rules every datapath function lives by --------------------------------------------------

// CLAUDE.md rule 4, for the pipeline and the control plane, across every kind of outcome.
TEST_F(ForwarderTest, ProcessBurstAndTheControlPlaneNeverAllocate) {
  std::vector<Packet*> burst{
      packet(ping()),                           // forwarded
      packet(ping({.ttl = 1})),                 // expired: earns a Time Exceeded
      packet(ping({.dst = kNowhere})),          // no route: earns a Net Unreachable
      packet(ping({.dst = ip4(10, 0, 2, 3)})),  // ARP miss: queued, and a request goes out
      packet(arp()),                            // to the host, answered in place
      packet(ping({.dst = kPort0Ip})),          // to the host, answered with an Echo Reply
      packet(ping({.dst = ip4(10, 0, 2, 4)})),  // ARP miss, never answered: Host Unreachable
      packet(reply_on_port1(ip4(10, 0, 2, 3), kStrangerMac), 1),  // frees the first miss
  };
  std::array<Decision, 8> out{};
  AllocCounter::reset();
  fwd_.process_burst(burst.data(), burst.size(), out.data());
  Packet* time_exceeded = fwd_.error_for(*burst[1], out[1].reason, pool_, kNow);
  Packet* net_unreachable = fwd_.error_for(*burst[2], out[2].reason, pool_, kNow);
  const std::optional<Reply> arp_reply = fwd_.deliver_to_host(*burst[4], pool_, kNow);
  const std::optional<Reply> echo_reply = fwd_.deliver_to_host(*burst[5], pool_, kNow);
  const std::optional<Reply> no_answer = fwd_.deliver_to_host(*burst[7], pool_, kNow);
  const std::span<const Reply> freed = fwd_.released();
  wait_out_arp();
  Packet* host_unreachable = fwd_.host_unreachable(*burst[6], pool_, kNow);
  EXPECT_EQ(AllocCounter::allocations(), 0U);
  EXPECT_EQ(AllocCounter::deallocations(), 0U);
  for (Packet* made : {time_exceeded, net_unreachable, host_unreachable,
                       echo_reply ? echo_reply->packet : static_cast<Packet*>(nullptr)}) {
    EXPECT_NE(made, nullptr);
    if (made != nullptr) {
      held_.push_back(made);
    }
  }

  EXPECT_EQ(out[0].verdict, Verdict::Forward);
  EXPECT_EQ(out[1].reason, DropReason::TtlExpired);
  EXPECT_EQ(out[2].reason, DropReason::NoRoute);
  EXPECT_EQ(out[3].verdict, Verdict::Queued);
  EXPECT_EQ(out[4].verdict, Verdict::ToHost);
  EXPECT_EQ(out[5].verdict, Verdict::ToHost);
  EXPECT_EQ(out[6].verdict, Verdict::Queued);
  EXPECT_EQ(out[7].verdict, Verdict::ToHost);
  ASSERT_TRUE(arp_reply.has_value());
  EXPECT_EQ(arp_reply->packet, burst[4]);
  EXPECT_FALSE(no_answer.has_value());
  ASSERT_EQ(freed.size(), 1U);
  EXPECT_EQ(freed[0].packet, burst[3]);
  EXPECT_EQ(events_.unresolved_heads, std::vector<Packet*>{burst[6]});
  // One request each, and two more for the neighbour that never answered.
  EXPECT_EQ(events_.requests.size(), 4U);

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

TEST(PortTable, ADirectedBroadcastIsAllOnesInTheHostPartOfAnAttachedSubnet) {
  Config c = topology();
  c.interfaces.push_back({"p2p", 3, ip4(192, 0, 2, 0), 31, PortMode::Routed, kPort0Mac});
  c.interfaces.push_back({"host", 4, ip4(198, 51, 100, 7), 32, PortMode::Routed, kPort0Mac});
  const std::vector<npf::pipe::PortState> ports = npf::pipe::make_port_table(c);
  using npf::pipe::is_directed_broadcast;
  EXPECT_TRUE(is_directed_broadcast(ports, ip4(10, 0, 1, 255)));
  EXPECT_TRUE(is_directed_broadcast(ports, ip4(10, 0, 3, 255)));  // a bridged port's subnet too
  EXPECT_FALSE(is_directed_broadcast(ports, ip4(10, 0, 1, 254)));
  EXPECT_FALSE(is_directed_broadcast(ports, ip4(10, 0, 9, 255)));    // not attached
  EXPECT_FALSE(is_directed_broadcast(ports, ip4(192, 0, 2, 1)));     // a /31 has none (RFC 3021)
  EXPECT_FALSE(is_directed_broadcast(ports, ip4(198, 51, 100, 7)));  // nor has a /32
  EXPECT_FALSE(is_directed_broadcast(ports, npf::pipe::kLimitedBroadcast));  // not a subnet's
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
