#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <npf/core/packet.hpp>
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
//   interface <name> port <id> ip <address>/<len> mode routed|bridged [mac <mac>|auto]
//   route <prefix>/<len> [via <next hop>] dev <port id>
//   arp <address> <mac> dev <port id>
//   pool_size <packets>              burst <1 to 64>
//   mode rtc|pipeline                workers <threads>
//   io af_packet|mmap|xdp|pcap       fib linear|trie|patricia|dir24_8
//
// A missing mac, or mac auto, means the MAC is read from the interface at start-up. Interface names
// and port ids are unique, and every dev names the port of an interface somewhere in the file. A
// route's prefix has no bits set past its length and appears once; a directly connected route has
// no via, so "via 0.0.0.0" is refused. Each of the last six settings may appear once, anywhere; one
// that is left out keeps the default given in Config.

enum class RunMode : std::uint8_t { Rtc, Pipeline };                    // threading: phase 13
enum class IoKind : std::uint8_t { AfPacket, Mmap, Xdp, Pcap };         // phases 6, 16, 17, 9
enum class FibKind : std::uint8_t { Linear, Trie, Patricia, Dir24_8 };  // phases 5, 10

inline constexpr std::size_t kMaxBurst = 64;  // the largest batch the datapath handles

struct InterfaceConfig {
  std::string name;            // the kernel's name for it, e.g. "veth-cr"
  std::uint16_t port{0};       // the id that routes and ARP entries name with dev
  std::uint32_t ip{0};         // the router's own address on this port, host order
  std::uint8_t prefix_len{0};  // of the subnet that address is in
  PortMode mode{PortMode::Routed};
  std::optional<proto::MacAddr> mac;  // nullopt: read it from the interface at start-up
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
  std::size_t pool_size{4096};  // the defaults are the values configs/router.conf sets
  std::size_t burst{kBurst};
  RunMode mode{RunMode::Rtc};
  std::size_t workers{1};
  IoKind io{IoKind::AfPacket};
  FibKind fib{FibKind::Linear};
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
// produced itself. Throws std::invalid_argument if an enum field holds no value of its type.
[[nodiscard]] std::string to_string(const Config& cfg);

}  // namespace npf::core
