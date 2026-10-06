#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <npf/core/packet.hpp>
#include <npf/pipe/filter.hpp>
#include <npf/proto/mac.hpp>
#include <npf/table/fib.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace npf {

// ARCHITECTURE.md §2: a routed port drops a transit frame that is not addressed to the router; a
// bridged port switches it (phase 12).
enum class PortMode : std::uint8_t { Routed, Bridged };

}  // namespace npf

namespace npf::core {

// The start-up configuration, as configs/router.conf states it. The file is read one line at a
// time; '#' starts a comment, and blank lines are skipped. Every other line is one of these, its
// words in exactly this order:
//
//   interface <name> port <id> [ip <address>/<len>] mode routed|bridged
//             [bridge-domain <1 to 65535>] [mac <mac>|auto]
//   route <prefix>/<len> [via <next hop>] dev <port id>
//   arp <address> <mac> dev <port id>
//   filter <path>
//   pool_size <packets>              burst <1 to 64>
//   mode rtc|pipeline                workers <threads>
//   io af_packet|mmap|xdp|pcap       fib linear|trie|patricia|dir24_8
//   mac_age <seconds>
//
// An interface is one line. A routed interface has an address, and a bridged one a bridge domain,
// which a routed one has not; a bridged interface's address is optional, and with none the router
// takes no part in the bridge's IP subnet. A missing mac, or mac auto, means the MAC is read from
// the interface at start-up. Interface names and port ids are unique, and every dev names the port
// of an interface with an address, somewhere in the file. A route's prefix has no bits set past its
// length and appears once; a directly connected route has no via, so "via 0.0.0.0" is refused.
// filter names a filter file (below), by a path without whitespace that filter_path() resolves.
// It and each of the last seven settings may appear once, anywhere; one that is left out keeps the
// default given in Config.

enum class RunMode : std::uint8_t { Rtc, Pipeline };                    // threading: phase 13
enum class IoKind : std::uint8_t { AfPacket, Mmap, Xdp, Pcap };         // phases 6, 16, 17, 9
enum class FibKind : std::uint8_t { Linear, Trie, Patricia, Dir24_8 };  // phases 5, 10

inline constexpr std::size_t kMaxBurst = 64;  // the largest batch the datapath handles

struct InterfaceConfig {
  std::string name;            // the kernel's name for it, e.g. "veth-cr"
  std::uint16_t port{0};       // the id that routes and ARP entries name with dev
  std::uint32_t ip{0};         // the router's own address on this port, host order; 0: none
  std::uint8_t prefix_len{0};  // of the subnet that address is in
  PortMode mode{PortMode::Routed};
  std::optional<proto::MacAddr> mac;  // nullopt: read it from the interface at start-up
  std::uint16_t bridge_domain{0};     // a bridged interface's, from 1; 0 for a routed one
  friend bool operator==(const InterfaceConfig&, const InterfaceConfig&) = default;
};

// A neighbour whose MAC is fixed rather than learned, so a replay is deterministic (phase 9).
struct StaticArp {
  std::uint32_t ip{0};  // host order
  proto::MacAddr mac;
  std::uint16_t port{0};
  friend bool operator==(const StaticArp&, const StaticArp&) noexcept = default;
};

struct Config {
  std::vector<InterfaceConfig> interfaces;
  std::vector<table::Route> routes;
  std::vector<StaticArp> arp;
  std::string filter;           // the filter file's path as written; empty: no packet filter
  std::size_t pool_size{4096};  // the defaults are the values configs/router.conf sets
  std::size_t burst{kBurst};
  RunMode mode{RunMode::Rtc};
  std::size_t workers{1};
  IoKind io{IoKind::AfPacket};
  FibKind fib{FibKind::Linear};
  std::chrono::seconds mac_age{300};  // how long a station is remembered after it last sent
  friend bool operator==(const Config&, const Config&) = default;
};

// ARCHITECTURE.md §14. On success: value is set, error is empty, line is 0. On failure: value is
// empty, error reads "line N: " and then what was expected and what was there instead, and line
// is N, counting from 1 -- or 0 if the file could not be read at all.
struct ParseResult {
  std::optional<Config> value;
  std::string error;
  int line{0};
};

// Malformed text is an error result, never an exception; only running out of memory throws.
[[nodiscard]] ParseResult parse_config(std::string_view text);
[[nodiscard]] ParseResult load_config(const std::filesystem::path& path);

// cfg written out in the file format above: parse_config gives back an equal Config for any cfg it
// produced itself. Throws std::invalid_argument if an enum field holds no value of its type, or
// cfg.filter is a path the format cannot hold.
[[nodiscard]] std::string to_string(const Config& cfg);

// The filter file that cfg, read from config_file, names: relative to config_file's directory, if
// it is not absolute. Empty if cfg names none.
[[nodiscard]] std::filesystem::path filter_path(const Config& cfg,
                                                const std::filesystem::path& config_file);

// A filter file: the packet filter's rules (ARCHITECTURE.md §8), as in configs/filter.conf. It is
// read like the file above, one line at a time, with '#' comments. One line says what happens to a
// packet that no rule matches, and is required:
//
//   policy allow|deny
//
// Every other line is a rule. Rules are tried in the file's order, and the first that matches
// decides:
//
//   allow|deny <protocol> <source> [port <ports>] -> <destination> [port <ports>] [in-port <id>]
//
//   <protocol>       any, tcp, udp, icmp, or a protocol number from 0 to 255
//   <source>,        any, an address such as 10.0.2.10 (a /32), or a prefix such as 10.0.1.0/24,
//   <destination>    with no bits set past its length
//   <ports>          a port such as 53, or an inclusive range such as 1024-65535, of the TCP or UDP
//                    header: so only for tcp, udp or any, and never matched by a non-initial
//                    fragment, which has no TCP or UDP header
//   in-port <id>     the port the packet arrived on: one of the router's interfaces
struct FilterConfig {
  std::vector<pipe::Rule> rules;             // in the file's order
  pipe::Action policy{pipe::Action::Allow};  // for a packet no rule matches
};

// As ParseResult. A file without a policy line is an error on line 0, like one that cannot be read:
// neither has a line to blame.
struct FilterParseResult {
  std::optional<FilterConfig> value;
  std::string error;
  int line{0};
};

// router is the configuration the filter is for: every in-port must be a port of its interfaces.
[[nodiscard]] FilterParseResult parse_filter(std::string_view text, const Config& router);
[[nodiscard]] FilterParseResult load_filter(const std::filesystem::path& path,
                                            const Config& router);

}  // namespace npf::core
