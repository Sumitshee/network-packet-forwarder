#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <npf/core/byte_span.hpp>
#include <npf/core/config.hpp>
#include <npf/pipe/filter.hpp>
#include <npf/proto/checksum.hpp>
#include <npf/proto/ipv4.hpp>
#include <npf/proto/l4.hpp>
#include <npf/table/fib.hpp>
#include <optional>
#include <ostream>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "support/alloc_counter.hpp"
#include "support/proto_helpers.hpp"

// Rules here are designated initializers naming only the fields a rule constrains. C++20 gives the
// rest their default, nullopt, which is "any" -- exactly what is meant -- but GCC 13 warns of each.
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"

namespace npf::pipe {

// Found by argument-dependent lookup, so GoogleTest prints names instead of numbers.
void PrintTo(Action a, std::ostream* os) {
  *os << (a == Action::Allow ? "Allow" : "Deny");
}

}  // namespace npf::pipe

namespace {

using npf::core::wr_be16;
using npf::core::wr_be32;
using npf::core::wr_u8;
using npf::pipe::Action;
using npf::pipe::Filter;
using npf::pipe::PortRange;
using npf::pipe::Rule;
using npf::proto::kIpProtoIcmp;
using npf::proto::kIpProtoTcp;
using npf::proto::kIpProtoUdp;
using npf::table::Prefix;
using npf::test::AllocCounter;
using npf::test::ip4;

constexpr std::uint32_t kClient = ip4(10, 0, 1, 2);
constexpr std::uint32_t kServer = ip4(10, 0, 2, 2);
constexpr std::uint8_t kIpProtoGre = 47;

// A packet as the filter sees it: an IPv4 header, then 20 bytes of TCP header or 8 of anything
// else.
struct Pkt {
  std::uint8_t protocol = kIpProtoUdp;
  std::uint32_t src = kClient;
  std::uint16_t sport = 40000;
  std::uint32_t dst = kServer;
  std::uint16_t dport = 53;
  std::uint16_t in_port = 0;
  // Nonzero: a non-initial fragment, at this offset in 8-byte units. Its first bytes are payload,
  // here payload that looks exactly like the header with sport and dport, which must not be
  // believed.
  std::uint16_t frag_offset = 0;
};

std::vector<std::byte> bytes_of(const Pkt& p) {
  std::vector<std::byte> b(20 + (p.protocol == kIpProtoTcp ? 20 : 8));
  wr_u8(b, 0, 0x45);
  wr_be16(b, 2, static_cast<std::uint16_t>(b.size()));
  wr_be16(b, 6, p.frag_offset);  // no flags: a last fragment, if it is a fragment at all
  wr_u8(b, 8, 64);
  wr_u8(b, 9, p.protocol);
  wr_be32(b, 12, p.src);
  wr_be32(b, 16, p.dst);
  wr_be16(b, 10, npf::proto::ipv4_header_checksum(std::span(b).first(20)));
  const std::span<std::byte> l4 = std::span(b).subspan(20);
  if (p.protocol == kIpProtoIcmp) {
    wr_u8(l4, 0, 8);  // an echo request
    return b;
  }
  wr_be16(l4, 0, p.sport);
  wr_be16(l4, 2, p.dport);
  if (p.protocol == kIpProtoTcp) {
    wr_u8(l4, 12, std::uint8_t{5 << 4});  // data offset: 5 words, no options
  } else {
    wr_be16(l4, 4, 8);  // a UDP length that covers just the header
  }
  return b;
}

// The filter's verdict on p, which is a well-formed packet: parse_l4 accepts it.
Action decide(const Filter& filter, const Pkt& p) {
  const std::vector<std::byte> b = bytes_of(p);
  const std::optional<npf::proto::Ipv4View> ip = npf::proto::Ipv4View::parse(b);
  const std::optional<npf::proto::L4Info> l4 = ip ? npf::proto::parse_l4(*ip) : std::nullopt;
  if (!l4) {
    ADD_FAILURE() << "the test built a packet the parsers refuse";
    return Action::Allow;
  }
  return filter.evaluate(*ip, *l4, p.in_port);
}

// --- exit test: the rule matrix ------------------------------------------------------------------

struct Case {
  const char* name;
  std::vector<Rule> rules;
  Action policy;
  Pkt packet;
  Action expected;
};

void PrintTo(const Case& c, std::ostream* os) {
  *os << c.name;
}

const Rule kDenyDns{.action = Action::Deny, .protocol = kIpProtoUdp, .dport = PortRange{53, 53}};
const Rule kAllowUdp{.action = Action::Allow, .protocol = kIpProtoUdp};
const Rule kDenyAnything{.action = Action::Deny};  // nullopt in every field
const Rule kDenyFromSubnet{.action = Action::Deny, .src = Prefix{ip4(10, 0, 1, 0), 24}};
const Rule kDenyToSubnet{.action = Action::Deny, .dst = Prefix{ip4(10, 0, 2, 0), 24}};
const Rule kDenyPortRange{.action = Action::Deny, .dport = PortRange{1024, 2048}};
const Rule kDenyEverySpecific{.action = Action::Deny,
                              .src = Prefix{ip4(10, 0, 1, 0), 24},
                              .dst = Prefix{ip4(10, 0, 2, 0), 24},
                              .protocol = kIpProtoUdp,
                              .sport = PortRange{40000, 40000},
                              .dport = PortRange{53, 53},
                              .in_port = std::uint16_t{0}};

std::vector<Case> cases() {
  constexpr Action kAllow = Action::Allow;
  constexpr Action kDeny = Action::Deny;
  return {
      // First match wins, in both orders.
      {"AllowBeforeDenyAllows", {kAllowUdp, kDenyDns}, kDeny, {}, kAllow},
      {"DenyBeforeAllowDenies", {kDenyDns, kAllowUdp}, kAllow, {}, kDeny},
      // nullopt fields match anything.
      {"NothingButNulloptMatchesUdp", {kDenyAnything}, kAllow, {}, kDeny},
      {"NothingButNulloptMatchesTcp", {kDenyAnything}, kAllow, {.protocol = kIpProtoTcp}, kDeny},
      {"NothingButNulloptMatchesIcmp", {kDenyAnything}, kAllow, {.protocol = kIpProtoIcmp}, kDeny},
      {"NothingButNulloptMatchesGre", {kDenyAnything}, kAllow, {.protocol = kIpProtoGre}, kDeny},
      {"NothingButNulloptMatchesAFragment", {kDenyAnything}, kAllow, {.frag_offset = 64}, kDeny},
      {"NothingButNulloptMatchesAnyAddressAndPort",
       {kDenyAnything},
       kAllow,
       {.src = ip4(203, 0, 113, 9), .dst = ip4(198, 51, 100, 1), .in_port = 7},
       kDeny},
      // The default policy, both ways.
      {"NoMatchGetsADefaultAllow", {kDenyDns}, kAllow, {.dport = 54}, kAllow},
      {"NoMatchGetsADefaultDeny",
       {{.action = Action::Allow, .protocol = kIpProtoTcp}},
       kDeny,
       {},
       kDeny},
      {"NoRulesAtAllAllowByDefault", {}, kAllow, {}, kAllow},
      {"NoRulesAtAllDenyByDefault", {}, kDeny, {}, kDeny},
      // A port rule cannot match a non-initial fragment; a rule without ports can.
      {"ADestinationPortRuleSkipsAFragment", {kDenyDns}, kAllow, {.frag_offset = 64}, kAllow},
      {"ASourcePortRuleSkipsAFragment",
       {{.action = Action::Deny, .sport = PortRange{40000, 40000}}},
       kAllow,
       {.frag_offset = 64},
       kAllow},
      // A fragment's ports are unread, not zero: even every port at all does not match it.
      {"AnyPortAtAllStillSkipsAFragment",
       {{.action = Action::Deny, .dport = PortRange{0, 65535}}},
       kAllow,
       {.frag_offset = 64},
       kAllow},
      {"AFragmentFallsThroughAPortRuleToTheNext",
       {kDenyDns, kAllowUdp},
       kDeny,
       {.frag_offset = 64},
       kAllow},
      {"AProtocolOnlyRuleMatchesAFragment",
       {{.action = Action::Deny, .protocol = kIpProtoUdp}},
       kAllow,
       {.frag_offset = 64},
       kDeny},
      {"AnAddressRuleMatchesAFragment", {kDenyToSubnet}, kAllow, {.frag_offset = 64}, kDeny},
      // in_port.
      {"InPortMatchesItsPort",
       {{.action = Action::Deny, .in_port = std::uint16_t{1}}},
       kAllow,
       {.in_port = 1},
       kDeny},
      {"InPortSkipsAnotherPort",
       {{.action = Action::Deny, .in_port = std::uint16_t{1}}},
       kAllow,
       {.in_port = 0},
       kAllow},
      // Prefix boundaries, at either end, for the source and the destination.
      {"TheLastAddressOfASourcePrefixIsInIt",
       {kDenyFromSubnet},
       kAllow,
       {.src = ip4(10, 0, 1, 255)},
       kDeny},
      {"TheFirstAddressOfASourcePrefixIsInIt",
       {kDenyFromSubnet},
       kAllow,
       {.src = ip4(10, 0, 1, 0)},
       kDeny},
      {"TheAddressAfterASourcePrefixIsNot",
       {kDenyFromSubnet},
       kAllow,
       {.src = ip4(10, 0, 2, 0)},
       kAllow},
      {"TheAddressBeforeASourcePrefixIsNot",
       {kDenyFromSubnet},
       kAllow,
       {.src = ip4(10, 0, 0, 255)},
       kAllow},
      {"TheLastAddressOfADestinationPrefixIsInIt",
       {kDenyToSubnet},
       kAllow,
       {.dst = ip4(10, 0, 2, 255)},
       kDeny},
      {"TheFirstAddressOfADestinationPrefixIsInIt",
       {kDenyToSubnet},
       kAllow,
       {.dst = ip4(10, 0, 2, 0)},
       kDeny},
      {"TheAddressAfterADestinationPrefixIsNot",
       {kDenyToSubnet},
       kAllow,
       {.dst = ip4(10, 0, 3, 0)},
       kAllow},
      {"TheAddressBeforeADestinationPrefixIsNot",
       {kDenyToSubnet},
       kAllow,
       {.dst = ip4(10, 0, 1, 255)},
       kAllow},
      {"AHostRouteMatchesItsAddress",
       {{.action = Action::Deny, .dst = Prefix{kServer, 32}}},
       kAllow,
       {.dst = kServer},
       kDeny},
      {"AHostRouteMatchesNoOtherAddress",
       {{.action = Action::Deny, .dst = Prefix{kServer, 32}}},
       kAllow,
       {.dst = kServer + 1},
       kAllow},
      {"ZeroLengthMatchesEveryAddress",
       {{.action = Action::Deny, .src = Prefix{0, 0}}},
       kAllow,
       {.src = ip4(203, 0, 113, 9)},
       kDeny},
      // Port ranges include both ends and nothing past them.
      {"APortRangeIncludesItsLowEnd", {kDenyPortRange}, kAllow, {.dport = 1024}, kDeny},
      {"APortRangeIncludesItsHighEnd", {kDenyPortRange}, kAllow, {.dport = 2048}, kDeny},
      {"APortRangeExcludesThePortBelow", {kDenyPortRange}, kAllow, {.dport = 1023}, kAllow},
      {"APortRangeExcludesThePortAbove", {kDenyPortRange}, kAllow, {.dport = 2049}, kAllow},
      // Protocols, and ports without one.
      {"AProtocolRuleSkipsAnotherProtocol",
       {{.action = Action::Deny, .protocol = kIpProtoTcp}},
       kAllow,
       {},
       kAllow},
      {"APortRuleForAnyProtocolMatchesTcp",
       {{.action = Action::Deny, .dport = PortRange{53, 53}}},
       kAllow,
       {.protocol = kIpProtoTcp},
       kDeny},
      {"APortRuleForAnyProtocolSkipsIcmp",
       {{.action = Action::Deny, .dport = PortRange{53, 53}}},
       kAllow,
       {.protocol = kIpProtoIcmp},
       kAllow},
      // Every field of a rule must match.
      {"EveryFieldMatching", {kDenyEverySpecific}, kAllow, {}, kDeny},
      {"AllButTheSourcePort", {kDenyEverySpecific}, kAllow, {.sport = 40001}, kAllow},
      {"AllButTheInPort", {kDenyEverySpecific}, kAllow, {.in_port = 1}, kAllow},
  };
}

class RuleMatrix : public ::testing::TestWithParam<Case> {};

TEST_P(RuleMatrix, DecidesAsTheRulesSay) {
  const Case& c = GetParam();
  const Filter filter(c.rules, c.policy);
  EXPECT_EQ(decide(filter, c.packet), c.expected);
}

INSTANTIATE_TEST_SUITE_P(ExitTest, RuleMatrix, ::testing::ValuesIn(cases()),
                         [](const auto& test) { return std::string{test.param.name}; });

// --- the rest of the contract --------------------------------------------------------------------

TEST(Filter, HasPortRulesOnlyWhileARuleConstrainsAPort) {
  EXPECT_FALSE(Filter({}, Action::Allow).has_port_rules());
  EXPECT_FALSE(Filter({kAllowUdp, kDenyFromSubnet, kDenyAnything}, Action::Deny).has_port_rules());
  EXPECT_TRUE(Filter({kAllowUdp, kDenyDns}, Action::Allow).has_port_rules());
  EXPECT_TRUE(Filter({{.sport = PortRange{1, 1}}}, Action::Allow).has_port_rules());
}

TEST(Filter, RefusesARuleThatIsMalformedOrCouldNeverMatch) {
  const auto make = [](const Rule& r) { return Filter({kAllowUdp, r}, Action::Allow); };
  EXPECT_THROW(make({.src = Prefix{ip4(10, 0, 1, 1), 24}}), std::invalid_argument);
  EXPECT_THROW(make({.dst = Prefix{ip4(10, 0, 2, 0), 33}}), std::invalid_argument);
  EXPECT_THROW(make({.dport = PortRange{2, 1}}), std::invalid_argument);
  EXPECT_THROW(make({.protocol = kIpProtoIcmp, .dport = PortRange{53, 53}}), std::invalid_argument);
  EXPECT_THROW(make({.protocol = kIpProtoGre, .sport = PortRange{1, 2}}), std::invalid_argument);
  EXPECT_THROW(make({.action = static_cast<Action>(7)}), std::invalid_argument);
  EXPECT_THROW(Filter({}, static_cast<Action>(7)), std::invalid_argument);
  // Ports with tcp, udp, or any protocol at all.
  EXPECT_NO_THROW(make({.protocol = kIpProtoTcp, .dport = PortRange{1, 65535}}));
  EXPECT_NO_THROW(make({.protocol = kIpProtoUdp, .sport = PortRange{0, 0}}));
  EXPECT_NO_THROW(make({.dport = PortRange{53, 53}}));
}

TEST(Filter, EvaluatingAllocatesNothing) {
  const Filter filter({kDenyEverySpecific, kDenyPortRange, kDenyFromSubnet, kAllowUdp},
                      Action::Deny);
  const std::vector<std::byte> b = bytes_of({.src = ip4(192, 0, 2, 1), .dport = 9});
  const std::optional<npf::proto::Ipv4View> ip = npf::proto::Ipv4View::parse(b);
  ASSERT_TRUE(ip.has_value());
  const std::optional<npf::proto::L4Info> l4 = npf::proto::parse_l4(*ip);
  ASSERT_TRUE(l4.has_value());
  AllocCounter::reset();
  std::size_t allowed = 0;
  for (std::uint16_t in_port = 0; in_port < 1000; ++in_port) {
    allowed += filter.evaluate(*ip, *l4, in_port) == Action::Allow ? 1U : 0U;
  }
  EXPECT_EQ(AllocCounter::allocations(), 0U);
  EXPECT_EQ(AllocCounter::deallocations(), 0U);
  EXPECT_EQ(allowed, 1000U);  // every one reached the last rule

  // That zero means something only if this binary counts allocations: a filter makes one.
  AllocCounter::reset();
  [[maybe_unused]] const Filter another({kAllowUdp}, Action::Allow);
  EXPECT_GT(AllocCounter::allocations(), 0U);
}

// configs/filter.conf, the plan's example, read for configs/router.conf's router.
TEST(Filter, TheExampleFilterDoesWhatItsRulesSay) {
  const std::filesystem::path dir{NPF_CONFIG_DIR};
  const npf::core::ParseResult router = npf::core::load_config(dir / "router.conf");
  ASSERT_TRUE(router.value.has_value()) << router.error;
  const npf::core::FilterParseResult parsed =
      npf::core::load_filter(dir / "filter.conf", *router.value);
  ASSERT_TRUE(parsed.value.has_value()) << parsed.error;
  ASSERT_EQ(parsed.value->rules.size(), 4U);
  EXPECT_EQ(parsed.value->policy, Action::Allow);
  const Filter filter(parsed.value->rules, parsed.value->policy);

  // deny udp any -> 10.0.2.10 port 53
  EXPECT_EQ(decide(filter, {.dst = ip4(10, 0, 2, 10)}), Action::Deny);
  EXPECT_EQ(decide(filter, {.dst = ip4(10, 0, 2, 10), .frag_offset = 64}), Action::Allow);
  EXPECT_EQ(decide(filter, {.protocol = kIpProtoTcp, .dst = ip4(10, 0, 2, 10)}), Action::Allow);
  // deny icmp 10.0.3.0/24 -> any, unless allow tcp 10.0.1.0/24 -> 10.0.2.0/24 came first
  EXPECT_EQ(decide(filter, {.protocol = kIpProtoIcmp, .src = ip4(10, 0, 3, 7)}), Action::Deny);
  EXPECT_EQ(decide(filter, {.protocol = kIpProtoIcmp, .src = ip4(10, 0, 3, 7), .frag_offset = 8}),
            Action::Deny);
  EXPECT_EQ(decide(filter, {.protocol = kIpProtoIcmp, .src = ip4(10, 0, 4, 7)}), Action::Allow);
}

}  // namespace
