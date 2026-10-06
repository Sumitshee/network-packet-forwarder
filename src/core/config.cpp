#include <algorithm>
#include <array>
#include <cassert>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <limits>
#include <npf/core/config.hpp>
#include <npf/pipe/filter.hpp>
#include <npf/proto/format.hpp>
#include <npf/proto/l4.hpp>
#include <npf/proto/mac.hpp>
#include <npf/table/fib.hpp>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace npf::core {
namespace {

// Thrown anywhere in the parser and caught in one place, parse_config, so that no helper has to
// pass an error back up through its callers. It never leaves this file.
class ConfigError : public std::runtime_error {
 public:
  ConfigError(int line, const std::string& message)
      : std::runtime_error(std::format("line {}: {}", line, message)), line_{line} {}
  [[nodiscard]] int line() const noexcept { return line_; }

 private:
  int line_;
};

// The word the file uses for each value of an enumeration; one table serves parsing and printing.
template <class E>
struct Word {
  std::string_view text;
  E value;
};

constexpr std::array<Word<PortMode>, 2> kPortModes{{
    {"routed", PortMode::Routed},
    {"bridged", PortMode::Bridged},
}};
constexpr std::array<Word<RunMode>, 2> kRunModes{{
    {"rtc", RunMode::Rtc},
    {"pipeline", RunMode::Pipeline},
}};
constexpr std::array<Word<IoKind>, 4> kIoKinds{{
    {"af_packet", IoKind::AfPacket},
    {"mmap", IoKind::Mmap},
    {"xdp", IoKind::Xdp},
    {"pcap", IoKind::Pcap},
}};
constexpr std::array<Word<FibKind>, 4> kFibKinds{{
    {"linear", FibKind::Linear},
    {"trie", FibKind::Trie},
    {"patricia", FibKind::Patricia},
    {"dir24_8", FibKind::Dir24_8},
}};

constexpr std::array<std::string_view, 7> kSettings{"pool_size", "burst", "mode",   "workers",
                                                    "io",        "fib",   "mac_age"};

constexpr std::array<Word<pipe::Action>, 2> kActions{{
    {"allow", pipe::Action::Allow},
    {"deny", pipe::Action::Deny},
}};
constexpr std::array<Word<std::uint8_t>, 3> kProtocols{{
    {"tcp", proto::kIpProtoTcp},
    {"udp", proto::kIpProtoUdp},
    {"icmp", proto::kIpProtoIcmp},
}};

constexpr std::uint64_t kMaxCount = std::numeric_limits<std::uint32_t>::max();

// --- values: text to number, and back ------------------------------------------------------------

// Decimal digits and nothing else: no sign, no spaces, no base prefix.
std::optional<std::uint64_t> to_number(std::string_view s, std::uint64_t max) {
  std::uint64_t value = 0;
  const char* end = s.data() + s.size();
  const auto [ptr, ec] = std::from_chars(s.data(), end, value);
  if (ec != std::errc{} || ptr != end || value > max) {
    return std::nullopt;
  }
  return value;
}

// Dotted quad, to host order. An octet with a leading zero is refused: inet_aton reads "010" as
// octal 8 and inet_pton rejects it, and the file must not mean different things to different tools.
std::optional<std::uint32_t> to_ipv4(std::string_view s) {
  std::uint32_t addr = 0;
  for (int i = 0; i < 4; ++i) {
    const std::size_t dot = s.find('.');
    if ((dot != std::string_view::npos) != (i < 3)) {  // exactly three dots
      return std::nullopt;
    }
    const std::string_view octet = s.substr(0, dot);
    const auto value = to_number(octet, 255);
    if (!value || (octet.size() > 1 && octet.front() == '0')) {
      return std::nullopt;
    }
    addr = addr << 8U | static_cast<std::uint32_t>(*value);
    s.remove_prefix(dot == std::string_view::npos ? s.size() : dot + 1);
  }
  return addr;
}

// "<address>/<len>". Whether the address may have bits set past len is the caller's decision.
std::optional<std::pair<std::uint32_t, std::uint8_t>> to_address_and_len(std::string_view s) {
  const std::size_t slash = s.find('/');
  if (slash == std::string_view::npos) {
    return std::nullopt;
  }
  const auto addr = to_ipv4(s.substr(0, slash));
  const auto len = to_number(s.substr(slash + 1), 32);
  if (!addr || !len) {
    return std::nullopt;
  }
  return std::pair{*addr, static_cast<std::uint8_t>(*len)};
}

// Six two-digit hex octets separated by colons, in either case: aa:bb:cc:dd:ee:02.
std::optional<proto::MacAddr> to_mac(std::string_view s) {
  proto::MacAddr mac;
  for (std::size_t i = 0; i < mac.b.size(); ++i) {
    const std::size_t colon = s.find(':');
    if ((colon != std::string_view::npos) != (i + 1 < mac.b.size())) {  // exactly five colons
      return std::nullopt;
    }
    const std::string_view hex = s.substr(0, colon);
    const char* end = hex.data() + hex.size();
    std::uint8_t octet = 0;
    const auto [ptr, ec] = std::from_chars(hex.data(), end, octet, 16);
    if (hex.size() != 2 || ec != std::errc{} || ptr != end) {
      return std::nullopt;
    }
    mac.b.at(i) = octet;
    s.remove_prefix(colon == std::string_view::npos ? s.size() : colon + 1);
  }
  return mac;
}

using proto::format_ipv4;
using proto::format_mac;

std::string format_prefix(table::Prefix p) {
  return std::format("{}/{}", format_ipv4(p.addr), p.len);
}

template <class E, std::size_t N>
std::string_view word_for(const std::array<Word<E>, N>& words, E value) {
  for (const Word<E>& w : words) {
    if (w.value == value) {
      return w.text;
    }
  }
  throw std::invalid_argument("to_string: a Config field holds a value its enumeration lacks");
}

// "linear, trie, patricia or dir24_8"
template <class E, std::size_t N>
std::string list_of(const std::array<Word<E>, N>& words) {
  std::string out;
  std::size_t i = 0;
  for (const Word<E>& w : words) {
    if (i > 0) {
      out += i + 1 < N ? ", " : " or ";
    }
    out += w.text;
    ++i;
  }
  return out;
}

// --- one line ------------------------------------------------------------------------------------

// The words of one line, taken from left to right. Running out of words, or finding the wrong one,
// is an error that names the line.
class Words {
 public:
  Words(std::string_view text, int line) : line_{line} {
    constexpr std::string_view kBlank = " \t\r\v\f";  // \r too: a file saved with CRLF endings
    for (std::size_t pos = text.find_first_not_of(kBlank); pos != std::string_view::npos;
         pos = text.find_first_not_of(kBlank, pos)) {
      const std::size_t end = std::min(text.find_first_of(kBlank, pos), text.size());
      words_.push_back(text.substr(pos, end - pos));
      pos = end;
    }
  }

  [[nodiscard]] int line() const noexcept { return line_; }
  [[nodiscard]] bool at_end() const noexcept { return next_ == words_.size(); }

  // The next word, which the caller is about to read as `what`.
  std::string_view take(std::string_view what) {
    if (at_end()) {
      fail(std::format("expected {}, got end of line", what));
    }
    return words_[next_++];
  }

  // Takes the next word only if it is `word`.
  bool accept(std::string_view word) {
    if (at_end() || words_[next_] != word) {
      return false;
    }
    ++next_;
    return true;
  }

  void expect(std::string_view word) {
    const std::string_view got = take(std::format("'{}'", word));
    if (got != word) {
      fail(std::format("expected '{}', got '{}'", word, got));
    }
  }

  void expect_end() const {
    if (!at_end()) {
      fail(std::format("expected end of line, got '{}'", words_[next_]));
    }
  }

  [[noreturn]] void fail(const std::string& message) const { throw ConfigError(line_, message); }

 private:
  std::vector<std::string_view> words_;
  std::size_t next_{0};
  int line_;
};

struct Bounds {
  std::uint64_t min;
  std::uint64_t max;
};

std::uint64_t take_number(Words& w, std::string_view what, Bounds bounds) {
  const std::string_view word = w.take(what);
  if (const auto value = to_number(word, bounds.max); value && *value >= bounds.min) {
    return *value;
  }
  w.fail(std::format("expected {} from {} to {}, got '{}'", what, bounds.min, bounds.max, word));
}

std::uint16_t take_port(Words& w) {
  return static_cast<std::uint16_t>(
      take_number(w, "a port id", {0, std::numeric_limits<std::uint16_t>::max()}));
}

std::uint32_t take_ipv4(Words& w, std::string_view what) {
  const std::string_view word = w.take(what);
  if (const auto addr = to_ipv4(word)) {
    return *addr;
  }
  w.fail(std::format("expected {} such as 10.0.2.254, got '{}'", what, word));
}

std::pair<std::uint32_t, std::uint8_t> take_interface_address(Words& w) {
  const std::string_view word = w.take("an address and prefix length");
  if (const auto addr = to_address_and_len(word)) {
    return *addr;
  }
  w.fail(std::format("expected an address and prefix length such as 10.0.1.1/24, got '{}'", word));
}

// word, read as addr/len, as a prefix. Bits set past len are refused, not cleared: more often than
// not they are a typo, in the address or the length.
table::Prefix exact_prefix(const Words& w, std::string_view word, std::uint32_t addr,
                           std::uint8_t len) {
  const table::Prefix prefix{addr & table::prefix_mask(len), len};
  if (prefix.addr != addr) {
    w.fail(std::format("{} has bits set past its prefix length; did you mean {}?", word,
                       format_prefix(prefix)));
  }
  return prefix;
}

table::Prefix take_route_prefix(Words& w) {
  const std::string_view word = w.take("a prefix");
  const auto parsed = to_address_and_len(word);
  if (!parsed) {
    w.fail(std::format("expected a prefix such as 10.0.1.0/24, got '{}'", word));
  }
  return exact_prefix(w, word, parsed->first, parsed->second);
}

proto::MacAddr take_mac(Words& w) {
  const std::string_view word = w.take("a MAC address");
  if (const auto mac = to_mac(word)) {
    return *mac;
  }
  w.fail(std::format("expected a MAC address such as aa:bb:cc:dd:ee:02, got '{}'", word));
}

std::optional<proto::MacAddr> take_mac_or_auto(Words& w) {
  const std::string_view word = w.take("a MAC address or 'auto'");
  if (word == "auto") {
    return std::nullopt;
  }
  if (const auto mac = to_mac(word)) {
    return mac;
  }
  w.fail(
      std::format("expected a MAC address such as aa:bb:cc:dd:ee:02, or 'auto', got '{}'", word));
}

template <class E, std::size_t N>
E take_word(Words& w, const std::array<Word<E>, N>& words, std::string_view what) {
  const std::string_view word = w.take(what);
  for (const Word<E>& candidate : words) {
    if (candidate.text == word) {
      return candidate.value;
    }
  }
  w.fail(std::format("expected {} ({}), got '{}'", what, list_of(words), word));
}

// A filter rule's protocol: nullopt for any.
std::optional<std::uint8_t> take_protocol(Words& w) {
  const std::string_view word = w.take("a protocol");
  if (word == "any") {
    return std::nullopt;
  }
  for (const Word<std::uint8_t>& p : kProtocols) {
    if (p.text == word) {
      return p.value;
    }
  }
  if (const auto number = to_number(word, std::numeric_limits<std::uint8_t>::max())) {
    return static_cast<std::uint8_t>(*number);
  }
  w.fail(std::format(
      "expected a protocol (any, tcp, udp, icmp or a number from 0 to 255), got '{}'", word));
}

// A filter rule's source or destination: nullopt for any, and a bare address is a /32.
std::optional<table::Prefix> take_match(Words& w, std::string_view what) {
  const std::string_view word = w.take(what);
  if (word == "any") {
    return std::nullopt;
  }
  if (word.find('/') == std::string_view::npos) {
    if (const auto addr = to_ipv4(word)) {
      return table::Prefix{*addr, 32};
    }
  } else if (const auto parsed = to_address_and_len(word)) {
    return exact_prefix(w, word, parsed->first, parsed->second);
  }
  w.fail(std::format(
      "expected {}: any, an address such as 10.0.2.10 or a prefix such as 10.0.1.0/24, got '{}'",
      what, word));
}

// A port, or an inclusive range of them: 53, 1024-65535.
pipe::PortRange take_ports(Words& w) {
  const std::string_view word = w.take("a port or a range of ports");
  constexpr std::uint64_t kMaxPort = std::numeric_limits<std::uint16_t>::max();
  const std::size_t dash = word.find('-');
  const auto lo = to_number(word.substr(0, dash), kMaxPort);
  const auto hi = dash == std::string_view::npos ? lo : to_number(word.substr(dash + 1), kMaxPort);
  if (!lo || !hi) {
    w.fail(std::format("expected a port such as 53 or a range such as 1024-65535, got '{}'", word));
  }
  if (*lo > *hi) {
    w.fail(std::format("the port range {} ends before it starts", word));
  }
  return {static_cast<std::uint16_t>(*lo), static_cast<std::uint16_t>(*hi)};
}

// "icmp", or "protocol 47": what the file would have said.
std::string protocol_name(std::uint8_t protocol) {
  for (const Word<std::uint8_t>& p : kProtocols) {
    if (p.value == protocol) {
      return std::string{p.text};
    }
  }
  return std::format("protocol {}", protocol);
}

// --- the whole file ------------------------------------------------------------------------------

class Parser {
 public:
  void parse_line(Words& w) {
    const std::string_view keyword = w.take("a keyword");
    if (keyword == "interface") {
      interface_line(w);
    } else if (keyword == "route") {
      route_line(w);
    } else if (keyword == "arp") {
      arp_line(w);
    } else if (keyword == "filter") {
      filter_line(w);
    } else if (std::ranges::find(kSettings, keyword) != kSettings.end()) {
      setting_line(w, keyword);
    } else {
      w.fail(
          std::format("unknown keyword '{}'; expected interface, route, arp, filter, pool_size, "
                      "burst, mode, workers, io, fib or mac_age",
                      keyword));
    }
  }

  // The checks that need the whole file, so a route may come before the interface it uses.
  Config result() {
    // What is wrong with a dev naming port, if anything: through a port with no address, the router
    // could neither ask for a neighbour's MAC nor answer as itself.
    const auto dev_fault = [this](std::uint16_t port) -> std::string {
      const auto it = std::ranges::find(cfg_.interfaces, port, &InterfaceConfig::port);
      if (it == cfg_.interfaces.end()) {
        return std::format("no interface has port {}", port);
      }
      return it->ip == 0 ? std::format("interface '{}' has no address", it->name) : std::string{};
    };
    for (std::size_t i = 0; i < cfg_.routes.size(); ++i) {
      const table::Route& r = cfg_.routes[i];
      if (const std::string why = dev_fault(r.out_port); !why.empty()) {
        throw ConfigError(route_lines_[i], std::format("route {} uses dev {}, but {}",
                                                       format_prefix(r.prefix), r.out_port, why));
      }
    }
    for (std::size_t i = 0; i < cfg_.arp.size(); ++i) {
      const StaticArp& a = cfg_.arp[i];
      if (const std::string why = dev_fault(a.port); !why.empty()) {
        throw ConfigError(arp_lines_[i], std::format("the ARP entry for {} uses dev {}, but {}",
                                                     format_ipv4(a.ip), a.port, why));
      }
    }
    return std::move(cfg_);
  }

 private:
  void interface_line(Words& w) {
    InterfaceConfig ifc;
    ifc.name = w.take("an interface name");
    w.expect("port");
    ifc.port = take_port(w);
    const bool has_ip = w.accept("ip");
    if (has_ip) {
      const auto [ip, prefix_len] = take_interface_address(w);
      if (ip == 0) {  // 0 is how an InterfaceConfig says "no address"
        w.fail("0.0.0.0 is not an address an interface can have");
      }
      ifc.ip = ip;
      ifc.prefix_len = prefix_len;
    }
    w.expect("mode");
    ifc.mode = take_word(w, kPortModes, "a port mode");
    if (w.accept("bridge-domain")) {
      if (ifc.mode != PortMode::Bridged) {
        w.fail("only a bridged interface is in a bridge domain");
      }
      ifc.bridge_domain = static_cast<std::uint16_t>(
          take_number(w, "a bridge domain", {1, std::numeric_limits<std::uint16_t>::max()}));
    }
    if (w.accept("mac")) {
      ifc.mac = take_mac_or_auto(w);
    }
    w.expect_end();
    if (ifc.mode == PortMode::Routed && !has_ip) {
      w.fail(
          std::format("interface '{}' is routed, so it needs an address: ip <address>/<len>, "
                      "after its port",
                      ifc.name));
    }
    if (ifc.mode == PortMode::Bridged && ifc.bridge_domain == 0) {
      w.fail(
          std::format("interface '{}' is bridged, so it needs a bridge domain: bridge-domain "
                      "<1 to 65535>, after its mode",
                      ifc.name));
    }
    for (std::size_t i = 0; i < cfg_.interfaces.size(); ++i) {
      const InterfaceConfig& other = cfg_.interfaces[i];
      if (other.name == ifc.name) {
        w.fail(std::format("interface '{}' is already defined on line {}", ifc.name,
                           interface_lines_[i]));
      }
      if (other.port == ifc.port) {
        w.fail(std::format("port {} is already used by interface '{}' on line {}", ifc.port,
                           other.name, interface_lines_[i]));
      }
    }
    cfg_.interfaces.push_back(std::move(ifc));
    interface_lines_.push_back(w.line());
  }

  void route_line(Words& w) {
    table::Route r;
    r.prefix = take_route_prefix(w);
    if (w.accept("via")) {
      r.next_hop = take_ipv4(w, "a next hop");
      if (r.next_hop == 0) {  // next_hop 0 is how a Route spells "directly connected"
        w.fail("'via 0.0.0.0' is not a next hop; a directly connected route has no 'via'");
      }
    }
    w.expect("dev");
    r.out_port = take_port(w);
    w.expect_end();
    for (std::size_t i = 0; i < cfg_.routes.size(); ++i) {
      if (cfg_.routes[i].prefix == r.prefix) {
        w.fail(std::format("a route for {} is already defined on line {}", format_prefix(r.prefix),
                           route_lines_[i]));
      }
    }
    cfg_.routes.push_back(r);
    route_lines_.push_back(w.line());
  }

  void arp_line(Words& w) {
    StaticArp a;
    a.ip = take_ipv4(w, "a neighbour's address");
    a.mac = take_mac(w);
    w.expect("dev");
    a.port = take_port(w);
    w.expect_end();
    for (std::size_t i = 0; i < cfg_.arp.size(); ++i) {
      if (cfg_.arp[i].ip == a.ip) {
        w.fail(std::format("an ARP entry for {} is already defined on line {}", format_ipv4(a.ip),
                           arp_lines_[i]));
      }
    }
    cfg_.arp.push_back(a);
    arp_lines_.push_back(w.line());
  }

  // A line for a setting the file may give once.
  void once(const Words& w, std::string_view key) {
    for (const auto& [seen, seen_on] : settings_) {
      if (seen == key) {
        w.fail(std::format("'{}' is already set on line {}", key, seen_on));
      }
    }
    settings_.emplace_back(key, w.line());
  }

  void filter_line(Words& w) {
    once(w, "filter");
    cfg_.filter = w.take("a filter file's path");
    w.expect_end();
  }

  void setting_line(Words& w, std::string_view key) {
    once(w, key);
    if (key == "pool_size") {
      cfg_.pool_size = take_number(w, "a packet count", {1, kMaxCount});
    } else if (key == "burst") {
      cfg_.burst = take_number(w, "a burst size", {1, kMaxBurst});
    } else if (key == "mode") {
      cfg_.mode = take_word(w, kRunModes, "a threading mode");
    } else if (key == "workers") {
      cfg_.workers = take_number(w, "a worker count", {1, kMaxCount});
    } else if (key == "io") {
      cfg_.io = take_word(w, kIoKinds, "an I/O backend");
    } else if (key == "fib") {
      cfg_.fib = take_word(w, kFibKinds, "a FIB");
    } else {
      assert(key == "mac_age" && "kSettings names a setting this function does not handle");
      cfg_.mac_age = std::chrono::seconds{static_cast<std::chrono::seconds::rep>(
          take_number(w, "a number of seconds", {1, kMaxCount}))};
    }
    w.expect_end();
  }

  Config cfg_;
  // The line each interface, route and ARP entry came from, index for index, and each setting's.
  std::vector<int> interface_lines_;
  std::vector<int> route_lines_;
  std::vector<int> arp_lines_;
  std::vector<std::pair<std::string_view, int>> settings_;
};

// --- a filter file -------------------------------------------------------------------------------

class FilterParser {
 public:
  explicit FilterParser(const Config& router) : router_{&router} {}

  void parse_line(Words& w) {
    const std::string_view keyword = w.take("a keyword");
    if (keyword == "policy") {
      policy_line(w);
    } else if (keyword == "allow" || keyword == "deny") {
      rule_line(w, keyword == "allow" ? pipe::Action::Allow : pipe::Action::Deny);
    } else {
      w.fail(std::format("unknown keyword '{}'; expected policy, allow or deny", keyword));
    }
  }

  [[nodiscard]] bool has_policy() const noexcept { return policy_line_ != 0; }
  FilterConfig result() { return std::move(filter_); }

 private:
  void policy_line(Words& w) {
    if (has_policy()) {
      w.fail(std::format("'policy' is already set on line {}", policy_line_));
    }
    policy_line_ = w.line();
    filter_.policy = take_word(w, kActions, "a policy");
    w.expect_end();
  }

  void rule_line(Words& w, pipe::Action action) {
    pipe::Rule r;
    r.action = action;
    r.protocol = take_protocol(w);
    r.src = take_match(w, "a source");
    if (w.accept("port")) {
      r.sport = take_ports(w);
    }
    w.expect("->");
    r.dst = take_match(w, "a destination");
    if (w.accept("port")) {
      r.dport = take_ports(w);
    }
    if (w.accept("in-port")) {
      const std::uint16_t port = take_port(w);
      if (std::ranges::none_of(router_->interfaces,
                               [port](const InterfaceConfig& i) { return i.port == port; })) {
        w.fail(std::format("the rule is for in-port {}, but no interface has port {}", port, port));
      }
      r.in_port = port;
    }
    w.expect_end();
    if ((r.sport || r.dport) && r.protocol && *r.protocol != proto::kIpProtoTcp &&
        *r.protocol != proto::kIpProtoUdp) {
      w.fail(
          std::format("only tcp and udp have ports, so a rule for {} with a port could never "
                      "match",
                      protocol_name(*r.protocol)));
    }
    filter_.rules.push_back(r);
  }

  const Config* router_;  // borrowed, for its interfaces
  FilterConfig filter_;
  int policy_line_{0};  // 0 until the policy line
};

// --- both files ----------------------------------------------------------------------------------

// Hands parse_line the words of each line of text that has any, its comment removed. Line numbers
// count from 1.
template <class F>
void each_line(std::string_view text, const F& parse_line) {
  int line = 0;
  while (!text.empty()) {
    ++line;
    const std::size_t eol = std::min(text.find('\n'), text.size());
    const std::string_view content = text.substr(0, eol);
    text.remove_prefix(std::min(eol + 1, text.size()));
    Words words(content.substr(0, content.find('#')), line);
    if (!words.at_end()) {
      parse_line(words);
    }
  }
}

// The file's whole text, or nullopt if it cannot be opened.
std::optional<std::string> read_text(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return std::nullopt;
  }
  std::ostringstream text;
  text << in.rdbuf();
  return std::move(text).str();
}

}  // namespace

ParseResult parse_config(std::string_view text) {
  try {
    Parser parser;
    each_line(text, [&parser](Words& w) { parser.parse_line(w); });
    return {parser.result(), {}, 0};
  } catch (const ConfigError& e) {
    return {std::nullopt, e.what(), e.line()};
  }
}

ParseResult load_config(const std::filesystem::path& path) {
  const std::optional<std::string> text = read_text(path);
  if (!text) {
    return {std::nullopt, std::format("cannot open {}", path.string()), 0};
  }
  return parse_config(*text);
}

std::filesystem::path filter_path(const Config& cfg, const std::filesystem::path& config_file) {
  if (cfg.filter.empty()) {
    return {};
  }
  const std::filesystem::path path{cfg.filter};
  return path.is_absolute() ? path : config_file.parent_path() / path;
}

FilterParseResult parse_filter(std::string_view text, const Config& router) {
  try {
    FilterParser parser(router);
    each_line(text, [&parser](Words& w) { parser.parse_line(w); });
    if (!parser.has_policy()) {
      return {std::nullopt,
              "no 'policy allow' or 'policy deny' line: a filter file must say what happens to a "
              "packet that no rule matches",
              0};
    }
    return {parser.result(), {}, 0};
  } catch (const ConfigError& e) {
    return {std::nullopt, e.what(), e.line()};
  }
}

FilterParseResult load_filter(const std::filesystem::path& path, const Config& router) {
  const std::optional<std::string> text = read_text(path);
  if (!text) {
    return {std::nullopt, std::format("cannot open {}", path.string()), 0};
  }
  return parse_filter(*text, router);
}

std::string to_string(const Config& cfg) {
  std::string out;
  for (const InterfaceConfig& i : cfg.interfaces) {
    out += std::format("interface {} port {}", i.name, i.port);
    if (i.ip != 0) {
      out += std::format(" ip {}/{}", format_ipv4(i.ip), i.prefix_len);
    }
    out += std::format(" mode {}", word_for(kPortModes, i.mode));
    if (i.mode == PortMode::Bridged) {
      out += std::format(" bridge-domain {}", i.bridge_domain);
    }
    if (i.mac) {
      out += std::format(" mac {}", format_mac(*i.mac));
    }
    out += '\n';
  }
  for (const table::Route& r : cfg.routes) {
    out += std::format("route {}", format_prefix(r.prefix));
    if (r.next_hop != 0) {
      out += std::format(" via {}", format_ipv4(r.next_hop));
    }
    out += std::format(" dev {}\n", r.out_port);
  }
  for (const StaticArp& a : cfg.arp) {
    out += std::format("arp {} {} dev {}\n", format_ipv4(a.ip), format_mac(a.mac), a.port);
  }
  if (!cfg.filter.empty()) {
    if (cfg.filter.find_first_of(" \t\r\v\f\n#") != std::string::npos) {
      throw std::invalid_argument(
          "to_string: a filter path with whitespace or '#' in it cannot "
          "be written in the file format");
    }
    out += std::format("filter {}\n", cfg.filter);
  }
  out += std::format("pool_size {}\nburst {}\nmode {}\nworkers {}\nio {}\nfib {}\nmac_age {}\n",
                     cfg.pool_size, cfg.burst, word_for(kRunModes, cfg.mode), cfg.workers,
                     word_for(kIoKinds, cfg.io), word_for(kFibKinds, cfg.fib), cfg.mac_age.count());
  return out;
}

}  // namespace npf::core
