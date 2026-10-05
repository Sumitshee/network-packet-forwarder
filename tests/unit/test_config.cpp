#include <gtest/gtest.h>

#include <array>
#include <filesystem>
#include <npf/core/config.hpp>
#include <npf/core/packet.hpp>
#include <npf/pipe/filter.hpp>
#include <npf/proto/l4.hpp>
#include <npf/proto/mac.hpp>
#include <npf/table/fib.hpp>
#include <optional>
#include <ostream>
#include <stdexcept>
#include <string>
#include <string_view>

#include "support/proto_helpers.hpp"

namespace npf::core {

// Found by argument-dependent lookup, so GoogleTest prints a Config as the file text it stands for.
void PrintTo(const Config& cfg, std::ostream* os) {
  *os << '\n' << to_string(cfg);
}

}  // namespace npf::core

namespace {

using npf::PortMode;
using npf::core::Config;
using npf::core::FibKind;
using npf::core::filter_path;
using npf::core::FilterConfig;
using npf::core::FilterParseResult;
using npf::core::IoKind;
using npf::core::kBurst;
using npf::core::load_config;
using npf::core::load_filter;
using npf::core::parse_config;
using npf::core::parse_filter;
using npf::core::ParseResult;
using npf::core::RunMode;
using npf::core::to_string;
using npf::pipe::Action;
using npf::pipe::Rule;
using npf::proto::MacAddr;
using npf::table::Prefix;
using npf::test::ip4;

// The Config that text parses to. A parse error fails the test.
Config parsed(std::string_view text) {
  const ParseResult r = parse_config(text);
  if (!r.value) {
    ADD_FAILURE() << r.error << "\nin:\n" << text;
    return {};
  }
  return *r.value;
}

// --- exit test: a valid file round-trips --------------------------------------------------------

// What configs/router.conf says, written out by hand.
Config router_conf() {
  Config c;
  c.interfaces = {
      {"veth-cr", 0, ip4(10, 0, 1, 1), 24, PortMode::Routed, std::nullopt},
      {"veth-sr", 1, ip4(10, 0, 2, 1), 24, PortMode::Routed, std::nullopt},
  };
  c.routes = {
      {{ip4(10, 0, 1, 0), 24}, 0, 0},
      {{ip4(10, 0, 2, 0), 24}, 0, 1},
      {{0, 0}, ip4(10, 0, 2, 254), 1},
  };
  c.arp = {{ip4(10, 0, 2, 2), MacAddr{{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02}}, 1}};
  c.pool_size = 4096;
  c.burst = 32;
  c.mode = RunMode::Rtc;
  c.workers = 1;
  c.io = IoKind::AfPacket;
  c.fib = FibKind::Linear;
  return c;
}

TEST(Config, RouterConfRoundTrips) {
  const ParseResult loaded = load_config(std::filesystem::path{NPF_CONFIG_DIR} / "router.conf");
  ASSERT_TRUE(loaded.value.has_value()) << loaded.error;
  EXPECT_TRUE(loaded.error.empty());
  EXPECT_EQ(loaded.line, 0);
  // Every field first: a parser that dropped lines would otherwise round-trip just as well.
  EXPECT_EQ(*loaded.value, router_conf());

  const std::string text = to_string(*loaded.value);
  const ParseResult again = parse_config(text);
  ASSERT_TRUE(again.value.has_value()) << again.error << "\nin:\n" << text;
  EXPECT_EQ(*again.value, *loaded.value);
  EXPECT_EQ(to_string(*again.value), text);
}

TEST(Config, EveryChoiceSurvivesTheRoundTrip) {
  // No value here is a default, so none can round-trip merely by being left out.
  constexpr std::string_view kText =
      R"(interface br0 port 7 ip 192.0.2.1/25 mode bridged mac 02:00:00:00:00:FF
interface uplink port 65535 ip 198.51.100.2/31 mode routed mac auto
route 0.0.0.0/0 via 198.51.100.3 dev 65535
route 192.0.2.0/25 dev 7
route 203.0.113.7/32 via 192.0.2.2 dev 7
arp 192.0.2.2 02:00:00:00:00:02 dev 7
arp 198.51.100.3 02:00:00:00:00:03 dev 65535
filter rules/edge.filter
pool_size 1
burst 64
mode pipeline
workers 4
io xdp
fib dir24_8
)";
  const Config cfg = parsed(kText);
  ASSERT_EQ(cfg.interfaces.size(), 2U);
  EXPECT_EQ(cfg.interfaces[0].mode, PortMode::Bridged);
  EXPECT_EQ(cfg.interfaces[0].mac, (MacAddr{{0x02, 0, 0, 0, 0, 0xFF}}));  // either case is read
  EXPECT_FALSE(cfg.interfaces[1].mac.has_value());                        // mac auto
  ASSERT_EQ(cfg.routes.size(), 3U);
  EXPECT_EQ(cfg.routes[1], (npf::table::Route{{ip4(192, 0, 2, 0), 25}, 0, 7}));
  EXPECT_EQ(cfg.arp.size(), 2U);
  EXPECT_EQ(cfg.filter, "rules/edge.filter");
  EXPECT_EQ(cfg.pool_size, 1U);
  EXPECT_EQ(cfg.burst, 64U);
  EXPECT_EQ(cfg.mode, RunMode::Pipeline);
  EXPECT_EQ(cfg.workers, 4U);
  EXPECT_EQ(cfg.io, IoKind::Xdp);
  EXPECT_EQ(cfg.fib, FibKind::Dir24_8);

  const std::string text = to_string(cfg);
  EXPECT_EQ(parsed(text), cfg);
  EXPECT_EQ(to_string(parsed(text)), text);
}

// --- the format ----------------------------------------------------------------------------------

TEST(Config, AFileWithNoSettingsGetsTheDefaults) {
  const Config cfg = parsed("# nothing but a comment\n\n");
  EXPECT_TRUE(cfg.interfaces.empty());
  EXPECT_TRUE(cfg.routes.empty());
  EXPECT_TRUE(cfg.arp.empty());
  EXPECT_EQ(cfg.pool_size, 4096U);
  EXPECT_EQ(cfg.burst, kBurst);
  EXPECT_EQ(cfg.mode, RunMode::Rtc);
  EXPECT_EQ(cfg.workers, 1U);
  EXPECT_EQ(cfg.io, IoKind::AfPacket);
  EXPECT_EQ(cfg.fib, FibKind::Linear);
}

TEST(Config, AcceptsEveryWordTheFormatDefines) {
  EXPECT_EQ(parsed("mode rtc").mode, RunMode::Rtc);
  EXPECT_EQ(parsed("mode pipeline").mode, RunMode::Pipeline);
  EXPECT_EQ(parsed("io af_packet").io, IoKind::AfPacket);
  EXPECT_EQ(parsed("io mmap").io, IoKind::Mmap);
  EXPECT_EQ(parsed("io xdp").io, IoKind::Xdp);
  EXPECT_EQ(parsed("io pcap").io, IoKind::Pcap);
  EXPECT_EQ(parsed("fib linear").fib, FibKind::Linear);
  EXPECT_EQ(parsed("fib trie").fib, FibKind::Trie);
  EXPECT_EQ(parsed("fib patricia").fib, FibKind::Patricia);
  EXPECT_EQ(parsed("fib dir24_8").fib, FibKind::Dir24_8);
  for (const auto& [word, mode] :
       {std::pair{"routed", PortMode::Routed}, std::pair{"bridged", PortMode::Bridged}}) {
    const Config cfg = parsed(std::string{"interface eth0 port 0 ip 10.0.0.1/8 mode "} + word);
    ASSERT_EQ(cfg.interfaces.size(), 1U);
    EXPECT_EQ(cfg.interfaces[0].mode, mode) << word;
  }
}

TEST(Config, MacAutoMeansTheSameAsNoMac) {
  EXPECT_EQ(parsed("interface eth0 port 0 ip 10.0.0.1/8 mode routed mac auto"),
            parsed("interface eth0 port 0 ip 10.0.0.1/8 mode routed"));
}

TEST(Config, IgnoresCommentsBlankLinesTabsAndCarriageReturns) {
  // As saved on Windows: every line ends in \r\n.
  const Config cfg = parsed(
      "# router\r\n\r\ninterface\tveth-cr port 0 ip 10.0.1.1/24 mode routed\r\n"
      "  burst 16   # a comment after a value\r\n");
  ASSERT_EQ(cfg.interfaces.size(), 1U);
  EXPECT_EQ(cfg.interfaces[0].name, "veth-cr");
  EXPECT_EQ(cfg.burst, 16U);
  // ... and line numbers still count \r\n lines, comment and blank lines included.
  EXPECT_EQ(parse_config("# router\r\n\r\nburst 99\r\n").line, 3);
}

TEST(Config, ARouteMayComeBeforeTheInterfaceItUses) {
  const Config cfg =
      parsed("route 10.0.0.0/8 dev 4\ninterface eth4 port 4 ip 10.0.0.1/8 mode routed\n");
  EXPECT_EQ(cfg.routes.size(), 1U);
}

TEST(Config, AFileThatCannotBeOpenedIsAnErrorOnLineZero) {
  const ParseResult r = load_config(std::filesystem::path{NPF_CONFIG_DIR} / "no-such-file.conf");
  EXPECT_FALSE(r.value.has_value());
  EXPECT_EQ(r.line, 0);
  EXPECT_NE(r.error.find("cannot open"), std::string::npos) << r.error;
  EXPECT_NE(r.error.find("no-such-file.conf"), std::string::npos) << r.error;
}

TEST(Config, AFilterPathIsReadFromTheConfigurationsDirectory) {
  const std::filesystem::path conf = std::filesystem::path{"/etc"} / "npf" / "router.conf";
  EXPECT_EQ(filter_path(parsed("filter filter.conf"), conf),
            std::filesystem::path{"/etc/npf/filter.conf"});
  EXPECT_EQ(filter_path(parsed("filter rules/edge.filter"), conf),
            std::filesystem::path{"/etc/npf/rules/edge.filter"});
  EXPECT_EQ(filter_path(parsed("filter /srv/edge.filter"), conf),
            std::filesystem::path{"/srv/edge.filter"});
  EXPECT_EQ(filter_path(parsed("filter filter.conf"), "router.conf"),
            std::filesystem::path{"filter.conf"});  // the working directory's, like router.conf
  EXPECT_TRUE(filter_path(parsed("burst 8"), conf).empty());
}

TEST(Config, ToStringRefusesAFilterPathTheFormatCannotHold) {
  Config cfg;
  cfg.filter = "my rules.filter";
  EXPECT_THROW((void)to_string(cfg), std::invalid_argument);
  cfg.filter = "rules#1.filter";  // '#' would start a comment
  EXPECT_THROW((void)to_string(cfg), std::invalid_argument);
}

// --- filter files --------------------------------------------------------------------------------

// The router the filter tests' in-ports refer to: ports 0 and 1.
Config two_ports() {
  return parsed(
      "interface veth-cr port 0 ip 10.0.1.1/24 mode routed\n"
      "interface veth-sr port 1 ip 10.0.2.1/24 mode routed\n");
}

FilterConfig parsed_filter(std::string_view text) {
  const FilterParseResult r = parse_filter(text, two_ports());
  if (!r.value) {
    ADD_FAILURE() << r.error << "\nin:\n" << text;
    return {};
  }
  return *r.value;
}

TEST(FilterFile, ReadsEveryFormOfEveryField) {
  const FilterConfig f = parsed_filter(R"(# rules first; the policy may come anywhere
allow tcp 10.0.1.0/24 port 1024-65535 -> 10.0.2.10 port 443 in-port 0
deny  udp any -> any port 53
deny  icmp 10.0.3.0/24 -> any
allow 47 any -> 192.0.2.0/24 in-port 1
deny  any any -> any   # nothing else
policy deny
)");
  EXPECT_EQ(f.policy, Action::Deny);
  ASSERT_EQ(f.rules.size(), 5U);
  const Rule& web = f.rules[0];
  EXPECT_EQ(web.action, Action::Allow);
  EXPECT_EQ(web.protocol, npf::proto::kIpProtoTcp);
  EXPECT_EQ(web.src, (Prefix{ip4(10, 0, 1, 0), 24}));
  ASSERT_TRUE(web.sport.has_value());
  EXPECT_EQ(web.sport->lo, 1024);
  EXPECT_EQ(web.sport->hi, 65535);
  EXPECT_EQ(web.dst, (Prefix{ip4(10, 0, 2, 10), 32}));  // a bare address is a /32
  ASSERT_TRUE(web.dport.has_value());
  EXPECT_EQ(web.dport->lo, 443);
  EXPECT_EQ(web.dport->hi, 443);
  EXPECT_EQ(web.in_port, 0);

  const Rule& dns = f.rules[1];
  EXPECT_EQ(dns.action, Action::Deny);
  EXPECT_EQ(dns.protocol, npf::proto::kIpProtoUdp);
  EXPECT_FALSE(dns.src.has_value());  // any
  EXPECT_FALSE(dns.sport.has_value());
  EXPECT_FALSE(dns.dst.has_value());
  EXPECT_FALSE(dns.in_port.has_value());

  EXPECT_EQ(f.rules[2].protocol, npf::proto::kIpProtoIcmp);
  EXPECT_EQ(f.rules[3].protocol, 47);
  EXPECT_EQ(f.rules[3].in_port, 1);

  const Rule& rest = f.rules[4];
  EXPECT_FALSE(rest.protocol || rest.src || rest.dst || rest.sport || rest.dport || rest.in_port);
}

TEST(FilterFile, AZeroLengthPrefixIsAcceptedAsWellAsAny) {
  const FilterConfig f = parsed_filter("policy allow\ndeny any 0.0.0.0/0 -> any\n");
  ASSERT_EQ(f.rules.size(), 1U);
  EXPECT_EQ(f.rules[0].src, (Prefix{0, 0}));
  EXPECT_FALSE(f.rules[0].dst.has_value());
}

TEST(FilterFile, APolicyAloneIsAFilterWithNoRules) {
  const FilterConfig f = parsed_filter("policy allow\n");
  EXPECT_EQ(f.policy, Action::Allow);
  EXPECT_TRUE(f.rules.empty());
}

TEST(FilterFile, AFileWithoutAPolicyIsAnErrorOnLineZero) {
  const FilterParseResult r = parse_filter("deny udp any -> any port 53\n", two_ports());
  EXPECT_FALSE(r.value.has_value());
  EXPECT_EQ(r.line, 0);
  EXPECT_NE(r.error.find("no 'policy allow' or 'policy deny' line"), std::string::npos) << r.error;
}

TEST(FilterFile, AFileThatCannotBeOpenedIsAnErrorOnLineZero) {
  const FilterParseResult r =
      load_filter(std::filesystem::path{NPF_CONFIG_DIR} / "no-such-file.filter", two_ports());
  EXPECT_FALSE(r.value.has_value());
  EXPECT_EQ(r.line, 0);
  EXPECT_NE(r.error.find("cannot open"), std::string::npos) << r.error;
}

TEST(FilterFile, TheExampleParsesForTheExampleRouter) {
  const ParseResult router = load_config(std::filesystem::path{NPF_CONFIG_DIR} / "router.conf");
  ASSERT_TRUE(router.value.has_value()) << router.error;
  const FilterParseResult r =
      load_filter(std::filesystem::path{NPF_CONFIG_DIR} / "filter.conf", *router.value);
  ASSERT_TRUE(r.value.has_value()) << r.error;
  EXPECT_EQ(r.value->rules.size(), 4U);
}

// --- exit test: malformed files name the right line ----------------------------------------------

struct BadConfig {
  const char* name;
  const char* text;
  int line;              // where the mistake is, counting from 1
  const char* expected;  // part of the error: what the parser wanted, and what it found instead
};

void PrintTo(const BadConfig& c, std::ostream* os) {
  *os << c.name;
}

const std::array<BadConfig, 23> kBadConfigs{{
    {"UnknownKeyword", R"(# two interfaces, then a typo
interface veth-cr port 0 ip 10.0.1.1/24 mode routed

rout 10.0.1.0/24 dev 0
)",
     4,
     "unknown keyword 'rout'; expected interface, route, arp, filter, pool_size, burst, mode, "
     "workers, io or fib"},
    {"PrefixLongerThan32", R"(interface veth-cr port 0 ip 10.0.1.1/24 mode routed
route 10.0.1.0/33 dev 0
)",
     2, "expected a prefix such as 10.0.1.0/24, got '10.0.1.0/33'"},
    {"HostBitsSetInARoute", R"(interface veth-cr port 0 ip 10.0.1.1/24 mode routed
route 10.0.1.0/24 dev 0
route 10.0.2.1/24 dev 0
)",
     3, "10.0.2.1/24 has bits set past its prefix length; did you mean 10.0.2.0/24?"},
    {"MacMissingAnOctet", R"(interface veth-cr port 0 ip 10.0.1.1/24 mode routed
interface veth-sr port 1 ip 10.0.2.1/24 mode routed mac aa:bb:cc:dd:ee
)",
     2, "expected a MAC address such as aa:bb:cc:dd:ee:02, or 'auto', got 'aa:bb:cc:dd:ee'"},
    {"RouteThroughAPortNoInterfaceHas", R"(interface veth-cr port 0 ip 10.0.1.1/24 mode routed
route 10.0.2.0/24 dev 1
interface veth-x port 2 ip 10.0.3.1/24 mode routed
)",
     2, "route 10.0.2.0/24 uses dev 1, but no interface has port 1"},
    {"PortUsedTwice", R"(interface veth-cr port 0 ip 10.0.1.1/24 mode routed
# the second interface reuses port 0
interface veth-sr port 0 ip 10.0.2.1/24 mode routed
)",
     3, "port 0 is already used by interface 'veth-cr' on line 1"},
    {"InterfaceNameUsedTwice", R"(interface veth-cr port 0 ip 10.0.1.1/24 mode routed
interface veth-cr port 1 ip 10.0.2.1/24 mode routed
)",
     2, "interface 'veth-cr' is already defined on line 1"},
    {"PortIdTooLarge", R"(# port ids are 16 bits
interface veth-cr port 65536 ip 10.0.1.1/24 mode routed
)",
     2, "expected a port id from 0 to 65535, got '65536'"},
    {"AddressWithoutAPrefixLength", R"(interface veth-cr port 0 ip 10.0.1.1 mode routed
)",
     1, "expected an address and prefix length such as 10.0.1.1/24, got '10.0.1.1'"},
    {"InterfaceWordsOutOfOrder", R"(interface veth-cr ip 10.0.1.1/24 port 0 mode routed
)",
     1, "expected 'port', got 'ip'"},
    {"BurstAboveTheMaximum", R"(pool_size 4096
burst 65
)",
     2, "expected a burst size from 1 to 64, got '65'"},
    {"SettingGivenTwice", R"(burst 32
mode rtc
burst 16
)",
     3, "'burst' is already set on line 1"},
    {"UnknownFib", R"(io af_packet
fib radix
)",
     2, "expected a FIB (linear, trie, patricia or dir24_8), got 'radix'"},
    {"ValueMissing", R"(burst 32
pool_size
)",
     2, "expected a packet count, got end of line"},
    {"WordAfterTheValue", R"(mode rtc
workers 1 2
)",
     2, "expected end of line, got '2'"},
    {"ViaZero", R"(interface veth-sr port 1 ip 10.0.2.1/24 mode routed
route 0.0.0.0/0 via 0.0.0.0 dev 1
)",
     2, "'via 0.0.0.0' is not a next hop; a directly connected route has no 'via'"},
    {"OctetWithALeadingZero", R"(interface veth-cr port 0 ip 10.0.1.1/24 mode routed
route 10.0.0.0/8 via 10.0.01.254 dev 0
)",
     2, "expected a next hop such as 10.0.2.254, got '10.0.01.254'"},
    {"RouteGivenTwice", R"(interface veth-cr port 0 ip 10.0.1.1/24 mode routed
route 10.0.0.0/8 dev 0
route 10.1.0.0/16 dev 0
route 10.0.0.0/8 via 10.0.1.254 dev 0
)",
     4, "a route for 10.0.0.0/8 is already defined on line 2"},
    {"ArpEntryWithoutAMac", R"(interface veth-sr port 1 ip 10.0.2.1/24 mode routed
arp 10.0.2.2 auto dev 1
)",
     2, "expected a MAC address such as aa:bb:cc:dd:ee:02, got 'auto'"},
    {"ArpAddressGivenTwice", R"(interface veth-sr port 1 ip 10.0.2.1/24 mode routed
arp 10.0.2.2 aa:bb:cc:dd:ee:02 dev 1
arp 10.0.2.2 aa:bb:cc:dd:ee:03 dev 1
)",
     3, "an ARP entry for 10.0.2.2 is already defined on line 2"},
    {"ArpThroughAPortNoInterfaceHas", R"(interface veth-sr port 1 ip 10.0.2.1/24 mode routed
arp 10.0.2.2 aa:bb:cc:dd:ee:02 dev 0
)",
     2, "the ARP entry for 10.0.2.2 uses dev 0, but no interface has port 0"},
    {"FilterGivenTwice", R"(filter a.filter
burst 8
filter b.filter
)",
     3, "'filter' is already set on line 1"},
    {"FilterWithoutAPath", R"(filter
)",
     1, "expected a filter file's path, got end of line"},
}};

class MalformedConfig : public ::testing::TestWithParam<BadConfig> {};

TEST_P(MalformedConfig, NamesTheLineAndWhatWasExpected) {
  const BadConfig& c = GetParam();
  const ParseResult r = parse_config(c.text);
  EXPECT_FALSE(r.value.has_value());
  EXPECT_EQ(r.line, c.line) << r.error;
  EXPECT_TRUE(r.error.starts_with("line " + std::to_string(c.line) + ": ")) << r.error;
  EXPECT_NE(r.error.find(c.expected), std::string::npos) << r.error;
}

INSTANTIATE_TEST_SUITE_P(ExitTest, MalformedConfig, ::testing::ValuesIn(kBadConfigs),
                         [](const auto& test) { return std::string{test.param.name}; });

// --- malformed filter files name the right line too ----------------------------------------------

const std::array<BadConfig, 15> kBadFilters{{
    {"UnknownKeyword", "policy allow\npermit tcp any -> any\n", 2,
     "unknown keyword 'permit'; expected policy, allow or deny"},
    {"PolicyGivenTwice", "policy allow\ndeny udp any -> any\npolicy deny\n", 3,
     "'policy' is already set on line 1"},
    {"UnknownPolicy", "policy reject\n", 1, "expected a policy (allow or deny), got 'reject'"},
    {"UnknownProtocol", "policy allow\ndeny sctpx any -> any\n", 2,
     "expected a protocol (any, tcp, udp, icmp or a number from 0 to 255), got 'sctpx'"},
    {"ProtocolNumberTooLarge", "policy allow\ndeny 256 any -> any\n", 2,
     "expected a protocol (any, tcp, udp, icmp or a number from 0 to 255), got '256'"},
    {"NoArrow", "policy allow\ndeny udp any 10.0.2.10 port 53\n", 2,
     "expected '->', got '10.0.2.10'"},
    {"AddressMissingAnOctet", "policy allow\ndeny udp 10.0.1 -> any\n", 2,
     "expected a source: any, an address such as 10.0.2.10 or a prefix such as 10.0.1.0/24, got "
     "'10.0.1'"},
    {"BitsSetPastThePrefixLength", "policy allow\ndeny udp any -> 10.0.2.5/24\n", 2,
     "10.0.2.5/24 has bits set past its prefix length; did you mean 10.0.2.0/24?"},
    {"PortRangeBackwards", "policy allow\ndeny udp any -> any port 60-50\n", 2,
     "the port range 60-50 ends before it starts"},
    {"PortTooLarge", "policy allow\ndeny udp any port 65536 -> any\n", 2,
     "expected a port such as 53 or a range such as 1024-65535, got '65536'"},
    {"PortForIcmp", "policy allow\ndeny icmp any -> any port 53\n", 2,
     "only tcp and udp have ports, so a rule for icmp with a port could never match"},
    {"PortForAProtocolNumber", "policy allow\ndeny 47 any port 1 -> any\n", 2,
     "only tcp and udp have ports, so a rule for protocol 47 with a port could never match"},
    {"InPortNoInterfaceHas", "policy allow\nallow any any -> any in-port 2\n", 2,
     "the rule is for in-port 2, but no interface has port 2"},
    {"WordAfterTheRule", "policy allow\nallow any any -> any in-port 0 now\n", 2,
     "expected end of line, got 'now'"},
    {"DestinationMissing", "policy deny\n# web\nallow tcp any ->\n", 3,
     "expected a destination, got end of line"},
}};

class MalformedFilter : public ::testing::TestWithParam<BadConfig> {};

TEST_P(MalformedFilter, NamesTheLineAndWhatWasExpected) {
  const BadConfig& c = GetParam();
  const FilterParseResult r = parse_filter(c.text, two_ports());
  EXPECT_FALSE(r.value.has_value());
  EXPECT_EQ(r.line, c.line) << r.error;
  EXPECT_TRUE(r.error.starts_with("line " + std::to_string(c.line) + ": ")) << r.error;
  EXPECT_NE(r.error.find(c.expected), std::string::npos) << r.error;
}

INSTANTIATE_TEST_SUITE_P(ExitTest, MalformedFilter, ::testing::ValuesIn(kBadFilters),
                         [](const auto& test) { return std::string{test.param.name}; });

}  // namespace
