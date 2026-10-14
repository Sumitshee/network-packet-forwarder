#pragma once

#include <cstdint>
#include <npf/proto/ipv4.hpp>
#include <npf/proto/l4.hpp>
#include <npf/table/fib.hpp>
#include <optional>
#include <vector>

namespace npf::pipe {

// ARCHITECTURE.md §8. The rules are scanned in order, every packet: no classification structure
// until a benchmark shows the filter matters (phase 15).

enum class Action : std::uint8_t { Allow, Deny };
struct PortRange {
  std::uint16_t lo{0}, hi{65535};
};

struct Rule {
  Action action{Action::Allow};
  std::optional<table::Prefix> src, dst;  // nullopt == any
  std::optional<std::uint8_t> protocol;
  std::optional<PortRange> sport, dport;
  std::optional<std::uint16_t> in_port;
};

class Filter {
 public:
  // Throws std::invalid_argument for a rule that is malformed -- an action or default that is
  // neither Allow nor Deny, a prefix with bits set past its length, a port range whose lo is above
  // its hi -- or that could never match: one constraining the ports of a protocol other than TCP
  // or UDP, the only two whose ports parse_l4 reads.
  explicit Filter(std::vector<Rule> rules, Action default_action);

  // First match wins. If l4.ports_valid is false (a non-initial fragment), any rule that
  // constrains sport or dport CANNOT match and is skipped. This is a deliberate, documented
  // limitation with a security implication -- see README "Known limitations".
  [[nodiscard]] Action evaluate(const proto::Ipv4View& ip, const proto::L4Info& l4,
                                std::uint16_t in_port) const noexcept;

  // True if any rule constrains sport or dport. While it is, the pipeline denies a TCP or UDP
  // packet whose header parse_l4 rejects (§11, step 10) rather than let it fall through those
  // rules for want of ports: a first fragment too short to hold the TCP header is RFC 1858's
  // tiny-fragment attack on exactly such rules.
  [[nodiscard]] bool has_port_rules() const noexcept { return port_rules_; }

 private:
  std::vector<Rule> rules_;
  Action default_;
  bool port_rules_;
};

}  // namespace npf::pipe
