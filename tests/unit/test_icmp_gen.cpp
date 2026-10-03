#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <npf/core/byte_span.hpp>
#include <npf/core/packet.hpp>
#include <npf/core/pool.hpp>
#include <npf/pipe/icmp_gen.hpp>
#include <npf/proto/checksum.hpp>
#include <npf/proto/ethernet.hpp>
#include <npf/proto/icmp.hpp>
#include <npf/proto/ipv4.hpp>
#include <npf/proto/l4.hpp>
#include <npf/proto/mac.hpp>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

#include "support/proto_helpers.hpp"

namespace {

using npf::core::CBytes;
using npf::core::Packet;
using npf::core::PacketPool;
using npf::core::wr_be16;
using npf::core::wr_be32;
using npf::core::wr_u8;
using npf::pipe::build_echo_reply;
using npf::pipe::build_icmp_error;
using npf::pipe::IcmpError;
using npf::pipe::IcmpRateLimiter;
using npf::pipe::may_send_icmp_error;
using npf::proto::EthView;
using npf::proto::IcmpView;
using npf::proto::Ipv4View;
using npf::proto::MacAddr;
using npf::test::ip4;
using Clock = std::chrono::steady_clock;
using Frame = std::vector<std::byte>;

constexpr MacAddr kRouterMac{{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}};
constexpr MacAddr kHostMac{{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01}};
constexpr std::uint32_t kRouter = ip4(10, 0, 1, 1);
constexpr std::uint32_t kHost = ip4(10, 0, 1, 2);
constexpr std::uint32_t kServer = ip4(10, 0, 2, 2);
constexpr std::uint16_t kMoreFragments = 0x2000;

// An ICMP message with a correct checksum.
Frame icmp_message(std::uint8_t type, std::uint8_t code, std::uint32_t rest, std::size_t data) {
  Frame m(8 + data, std::byte{0x5A});
  wr_u8(m, 0, type);
  wr_u8(m, 1, code);
  wr_be16(m, 2, 0);
  wr_be32(m, 4, rest);
  wr_be16(m, 2, static_cast<std::uint16_t>(~npf::proto::ones_complement_sum(m)));
  return m;
}

struct Datagram {
  std::uint32_t src = kHost;
  std::uint32_t dst = kServer;
  std::uint8_t ttl = 1;
  std::uint8_t protocol = npf::proto::kIpProtoUdp;
  std::uint8_t tos = 0;
  std::uint16_t flags_frag = 0;
  std::size_t option_words = 0;  // 4-byte words of NOP options
  Frame payload = Frame(12, std::byte{0x77});
  std::optional<std::uint16_t> vlan = std::nullopt;
};

// An Ethernet frame from the host to the router, carrying the datagram with a correct checksum.
Frame frame(const Datagram& d) {
  const std::size_t ihl = 20 + (4 * d.option_words);
  Frame f(d.vlan ? 18 : 14);
  npf::proto::wr_mac(f, 0, kRouterMac);
  npf::proto::wr_mac(f, 6, kHostMac);
  if (d.vlan) {
    wr_be16(f, 12, npf::proto::kEtherTypeVlan);
    wr_be16(f, 14, *d.vlan);
  }
  wr_be16(f, f.size() - 2, npf::proto::kEtherTypeIpv4);
  // Written into a fixed array rather than a vector sized at run time, which GCC suspects of
  // being empty (and its data() null) at every write.
  std::array<std::byte, 60> longest{};
  std::ranges::fill(longest, std::byte{0x01});  // option bytes are NOPs
  const std::span<std::byte> ip = std::span(longest).first(ihl);
  wr_u8(ip, 0, static_cast<std::uint8_t>(0x40 | (ihl / 4)));
  wr_u8(ip, 1, d.tos);
  wr_be16(ip, 2, static_cast<std::uint16_t>(ihl + d.payload.size()));
  wr_be16(ip, 4, 0x1234);
  wr_be16(ip, 6, d.flags_frag);
  wr_u8(ip, 8, d.ttl);
  wr_u8(ip, 9, d.protocol);
  wr_be16(ip, 10, 0);
  wr_be32(ip, 12, d.src);
  wr_be32(ip, 16, d.dst);
  wr_be16(ip, 10, npf::proto::ipv4_header_checksum(ip));
  f.insert(f.end(), ip.begin(), ip.end());
  f.insert(f.end(), d.payload.begin(), d.payload.end());
  return f;
}

Ipv4View ipv4_of(CBytes f) {
  const std::optional<EthView> eth = EthView::parse(f);
  const std::optional<Ipv4View> ip = eth ? Ipv4View::parse(eth->payload()) : std::nullopt;
  if (!ip) {
    throw std::runtime_error("not an IPv4 frame");
  }
  return *ip;
}

npf::proto::L4Info l4_of(const Ipv4View& ip) {
  const std::optional<npf::proto::L4Info> l4 = npf::proto::parse_l4(ip);
  if (!l4) {
    throw std::runtime_error("malformed L4 header");
  }
  return *l4;
}

class IcmpGen : public ::testing::Test {
 protected:
  Packet* out() {
    Packet* p = pool_.acquire();
    if (p == nullptr) {
      throw std::runtime_error("the test pool is too small");
    }
    held_.push_back(p);
    return p;
  }

  ~IcmpGen() override {
    for (Packet* p : held_) {
      pool_.release(p);
    }
  }

  IcmpGen() = default;
  IcmpGen(const IcmpGen&) = delete;
  IcmpGen& operator=(const IcmpGen&) = delete;
  IcmpGen(IcmpGen&&) = delete;
  IcmpGen& operator=(IcmpGen&&) = delete;

  PacketPool pool_{16};
  std::vector<Packet*> held_;
};

// --- build_icmp_error ----------------------------------------------------------------------------

// Exit test: the output parses back through EthView -> Ipv4View -> IcmpView, its IPv4 checksum
// validates, and the embedded payload is the original header plus exactly 8 bytes.
TEST_F(IcmpGen, ErrorParsesBackThroughEveryView) {
  const Frame in = frame({.payload = Frame(20, std::byte{0x77})});
  const Ipv4View orig = ipv4_of(in);
  Packet* p = out();
  ASSERT_TRUE(
      build_icmp_error(*p, orig, in, IcmpError::TimeExceeded, kRouter, kRouterMac, kHostMac));

  const std::optional<EthView> eth = EthView::parse(std::as_const(*p).data());
  ASSERT_TRUE(eth.has_value());
  EXPECT_EQ(eth->dst(), kHostMac);
  EXPECT_EQ(eth->src(), kRouterMac);
  EXPECT_FALSE(eth->has_vlan());
  ASSERT_EQ(eth->ethertype(), npf::proto::kEtherTypeIpv4);

  const std::optional<Ipv4View> ip = Ipv4View::parse(eth->payload());
  ASSERT_TRUE(ip.has_value());
  EXPECT_TRUE(npf::proto::ipv4_checksum_valid(ip->header()));
  EXPECT_EQ(ip->header_len(), 20U);
  EXPECT_EQ(ip->src(), kRouter);
  EXPECT_EQ(ip->dst(), kHost);
  EXPECT_EQ(ip->protocol(), npf::proto::kIpProtoIcmp);
  EXPECT_EQ(ip->ttl(), npf::pipe::kIcmpTtl);
  EXPECT_TRUE(ip->df());
  EXPECT_FALSE(ip->is_fragment());

  const std::optional<IcmpView> icmp = IcmpView::parse(ip->payload());  // checks its checksum
  ASSERT_TRUE(icmp.has_value());
  EXPECT_EQ(icmp->type(), npf::proto::kIcmpTimeExceeded);
  EXPECT_EQ(icmp->code(), 0);
  const CBytes quoted = icmp->payload();
  ASSERT_EQ(quoted.size(), orig.header_len() + 8);
  EXPECT_TRUE(std::ranges::equal(quoted.first(orig.header_len()), orig.header()));
  EXPECT_TRUE(std::ranges::equal(quoted.subspan(orig.header_len()), orig.payload().first(8)));
}

TEST_F(IcmpGen, EachErrorHasItsTypeAndCode) {
  const Frame in = frame({});
  const std::array<std::pair<IcmpError, std::pair<int, int>>, 4> cases{{
      {IcmpError::TimeExceeded, {11, 0}},
      {IcmpError::NetUnreachable, {3, 0}},
      {IcmpError::HostUnreachable, {3, 1}},
      {IcmpError::ProtoUnreachable, {3, 2}},
  }};
  for (const auto& [err, type_code] : cases) {
    Packet* p = out();
    ASSERT_TRUE(build_icmp_error(*p, ipv4_of(in), in, err, kRouter, kRouterMac, kHostMac));
    const std::optional<IcmpView> icmp =
        IcmpView::parse(ipv4_of(std::as_const(*p).data()).payload());
    ASSERT_TRUE(icmp.has_value());
    EXPECT_EQ(icmp->type(), type_code.first);
    EXPECT_EQ(icmp->code(), type_code.second);
  }
}

TEST_F(IcmpGen, ErrorQuotesOptionsAndAShortPayloadAsTheyAre) {
  const Frame in = frame({.option_words = 4, .payload = Frame(3, std::byte{0x77})});
  const Ipv4View orig = ipv4_of(in);
  ASSERT_EQ(orig.header_len(), 36U);
  Packet* p = out();
  ASSERT_TRUE(
      build_icmp_error(*p, orig, in, IcmpError::NetUnreachable, kRouter, kRouterMac, kHostMac));
  const std::optional<IcmpView> icmp = IcmpView::parse(ipv4_of(std::as_const(*p).data()).payload());
  ASSERT_TRUE(icmp.has_value());
  ASSERT_EQ(icmp->payload().size(), 36U + 3U);  // the whole header, and all the data there was
  EXPECT_TRUE(std::ranges::equal(icmp->payload().first(36), orig.header()));
}

// RFC 1812 §4.3.2.5: precedence 6, and the original's four TOS bits.
TEST_F(IcmpGen, ErrorHasPrecedenceSixAndTheOriginalsTosBits) {
  const Frame in = frame({.tos = 0x1F});
  Packet* p = out();
  ASSERT_TRUE(build_icmp_error(*p, ipv4_of(in), in, IcmpError::TimeExceeded, kRouter, kRouterMac,
                               kHostMac));
  EXPECT_EQ(ipv4_of(std::as_const(*p).data()).tos(), 0xDE);
}

TEST_F(IcmpGen, ErrorKeepsTheVlanTag) {
  const Frame in = frame({.vlan = 10});
  Packet* p = out();
  ASSERT_TRUE(build_icmp_error(*p, ipv4_of(in), in, IcmpError::TimeExceeded, kRouter, kRouterMac,
                               kHostMac));
  const std::optional<EthView> eth = EthView::parse(std::as_const(*p).data());
  ASSERT_TRUE(eth.has_value());
  EXPECT_EQ(eth->vlan_id(), 10);
  EXPECT_TRUE(npf::proto::ipv4_checksum_valid(ipv4_of(std::as_const(*p).data()).header()));
}

TEST_F(IcmpGen, ErrorRefusesAPacketWithTooLittleRoom) {
  const Frame in = frame({});
  Packet* p = out();
  p->resize(p->capacity());
  ASSERT_TRUE(p->pull(p->size() - 40));  // leaves room for 40 bytes; the error needs 70
  EXPECT_FALSE(build_icmp_error(*p, ipv4_of(in), in, IcmpError::TimeExceeded, kRouter, kRouterMac,
                                kHostMac));
  EXPECT_EQ(p->size(), 40U);  // untouched
}

// --- build_echo_reply ----------------------------------------------------------------------------

TEST_F(IcmpGen, EchoReplyReturnsTheRequestFromTheAddressItWasSentTo) {
  const Frame request_icmp = icmp_message(npf::proto::kIcmpEchoRequest, 0, 0x12340007, 32);
  const Frame in = frame({.dst = kRouter,
                          .ttl = 64,
                          .protocol = npf::proto::kIpProtoIcmp,
                          .tos = 0x10,
                          .payload = request_icmp});
  const Ipv4View req = ipv4_of(in);
  Packet* p = out();
  ASSERT_TRUE(build_echo_reply(*p, req, in, kRouterMac, kHostMac));

  const std::optional<EthView> eth = EthView::parse(std::as_const(*p).data());
  ASSERT_TRUE(eth.has_value());
  EXPECT_EQ(eth->dst(), kHostMac);
  EXPECT_EQ(eth->src(), kRouterMac);
  const Ipv4View ip = ipv4_of(std::as_const(*p).data());
  EXPECT_TRUE(npf::proto::ipv4_checksum_valid(ip.header()));
  EXPECT_EQ(ip.src(), kRouter);
  EXPECT_EQ(ip.dst(), kHost);
  EXPECT_EQ(ip.tos(), 0x10);
  EXPECT_EQ(ip.ttl(), npf::pipe::kIcmpTtl);
  const std::optional<IcmpView> reply = IcmpView::parse(ip.payload());
  ASSERT_TRUE(reply.has_value());
  EXPECT_EQ(reply->type(), npf::proto::kIcmpEchoReply);
  EXPECT_EQ(reply->code(), 0);
  EXPECT_EQ(reply->echo_id(), 0x1234);
  EXPECT_EQ(reply->echo_seq(), 7);
  EXPECT_TRUE(std::ranges::equal(reply->payload(), IcmpView::parse(req.payload())->payload()));
}

TEST_F(IcmpGen, EchoReplyOnlyForAWholeValidEchoRequest) {
  const auto to_router = [](Frame message, std::uint16_t flags_frag = 0) {
    return frame({.dst = kRouter,
                  .ttl = 64,
                  .protocol = npf::proto::kIpProtoIcmp,
                  .flags_frag = flags_frag,
                  .payload = std::move(message)});
  };
  Frame bad_sum = icmp_message(npf::proto::kIcmpEchoRequest, 0, 1, 8);
  wr_u8(bad_sum, 8, 0x00);  // data changed after the checksum was computed
  const std::array<Frame, 4> refused{
      to_router(icmp_message(npf::proto::kIcmpEchoReply, 0, 1, 8)),
      to_router(icmp_message(npf::proto::kIcmpDestUnreachable, 1, 0, 28)),
      to_router(bad_sum),
      to_router(icmp_message(npf::proto::kIcmpEchoRequest, 0, 1, 8), kMoreFragments),
  };
  for (const Frame& in : refused) {
    Packet* p = out();
    EXPECT_FALSE(build_echo_reply(*p, ipv4_of(in), in, kRouterMac, kHostMac));
    EXPECT_EQ(p->size(), 0U);  // untouched
  }
}

// --- may_send_icmp_error: the four cases of the plan, one test each ------------------------------

bool may_send(const Datagram& d) {
  const Frame f = frame(d);
  const Ipv4View ip = ipv4_of(f);
  return may_send_icmp_error(ip, l4_of(ip));
}

TEST(MaySendIcmpError, YesForAnOrdinaryDatagram) {
  EXPECT_TRUE(may_send({}));
  EXPECT_TRUE(may_send({.protocol = npf::proto::kIpProtoIcmp,
                        .payload = icmp_message(npf::proto::kIcmpEchoRequest, 0, 1, 8)}));
}

TEST(MaySendIcmpError, NotForAnIcmpError) {
  for (const std::uint8_t type : std::array<std::uint8_t, 5>{3, 4, 5, 11, 12}) {
    EXPECT_FALSE(
        may_send({.protocol = npf::proto::kIpProtoIcmp, .payload = icmp_message(type, 0, 0, 28)}))
        << "type " << int{type};
  }
}

TEST(MaySendIcmpError, NotForAFragmentOtherThanTheFirst) {
  EXPECT_FALSE(may_send({.flags_frag = 185}));
  EXPECT_FALSE(may_send({.flags_frag = kMoreFragments | 1}));
  EXPECT_TRUE(may_send({.flags_frag = kMoreFragments}));  // the first fragment may
}

TEST(MaySendIcmpError, NotForABroadcastOrMulticastDestination) {
  for (const std::uint32_t dst : {ip4(255, 255, 255, 255), ip4(224, 0, 0, 5), ip4(239, 1, 2, 3)}) {
    EXPECT_FALSE(may_send({.dst = dst})) << std::hex << dst;
  }
}

TEST(MaySendIcmpError, NotForASourceThatIsNotOneHost) {
  for (const std::uint32_t src : {ip4(0, 0, 0, 0), ip4(127, 0, 0, 1), ip4(224, 0, 0, 1),
                                  ip4(240, 0, 0, 1), ip4(255, 255, 255, 255)}) {
    EXPECT_FALSE(may_send({.src = src})) << std::hex << src;
  }
}

// --- IcmpRateLimiter -----------------------------------------------------------------------------

const Clock::time_point kStart = Clock::time_point{} + std::chrono::hours{1};

// Exit test: at most 100 in a simulated second. A request every millisecond for ten seconds,
// and the most any one-second window lets through is counted from every error that went out.
TEST(IcmpRateLimiter, AtMost100InAnySimulatedSecond) {
  IcmpRateLimiter limiter;  // the default: 100 a second
  std::vector<Clock::time_point> sent;
  for (int ms = 0; ms < 10'000; ++ms) {
    const Clock::time_point t = kStart + std::chrono::milliseconds{ms};
    if (limiter.allow(t)) {
      sent.push_back(t);
    }
  }
  for (auto it = sent.begin(); it != sent.end(); ++it) {
    const auto window_end = std::lower_bound(it, sent.end(), *it + std::chrono::seconds{1});
    ASSERT_LE(window_end - it, 100)
        << "in the second from " << (*it - kStart) / std::chrono::milliseconds{1} << " ms";
  }
  EXPECT_EQ(sent.size(), 1000U);  // and no fewer: 100 a second, for ten seconds
}

TEST(IcmpRateLimiter, ABurstOfAHundredThenNothingForASecond) {
  IcmpRateLimiter limiter;
  int allowed = 0;
  for (int i = 0; i < 1000; ++i) {
    allowed += limiter.allow(kStart) ? 1 : 0;
  }
  EXPECT_EQ(allowed, 100);
  EXPECT_FALSE(limiter.allow(kStart + std::chrono::milliseconds{999}));
  EXPECT_TRUE(limiter.allow(kStart + std::chrono::seconds{1}));
}

TEST(IcmpRateLimiter, ARateOfZeroAllowsNothing) {
  IcmpRateLimiter limiter(0);
  EXPECT_FALSE(limiter.allow(kStart));
  EXPECT_FALSE(limiter.allow(kStart + std::chrono::hours{1}));
}

}  // namespace
