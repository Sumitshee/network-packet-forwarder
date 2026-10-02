#include <gtest/gtest.h>

#include <array>
#include <filesystem>
#include <npf/core/config.hpp>
#include <npf/core/packet.hpp>
#include <npf/proto/mac.hpp>
#include <npf/table/fib.hpp>
#include <optional>
#include <ostream>
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
using npf::core::IoKind;
using npf::core::kBurst;
using npf::core::load_config;
using npf::core::parse_config;
using npf::core::ParseResult;
using npf::core::RunMode;
using npf::core::to_string;
using npf::proto::MacAddr;
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

const std::array<BadConfig, 21> kBadConfigs{{
    {"UnknownKeyword", R"(# two interfaces, then a typo
interface veth-cr port 0 ip 10.0.1.1/24 mode routed

rout 10.0.1.0/24 dev 0
)",
     4,
     "unknown keyword 'rout'; expected interface, route, arp, pool_size, burst, mode, workers, io "
     "or fib"},
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

}  // namespace
