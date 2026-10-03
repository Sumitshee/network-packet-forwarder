#pragma once

#include <cstdint>
#include <npf/proto/ipv4.hpp>
#include <npf/proto/l4.hpp>
#include <npf/table/fib.hpp>
#include <optional>
#include <stdexcept>
#include <utility>
#include <vector>

namespace npf::pipe {

// ARCHITECTURE.md §8.

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

// PHASE 6 STUB: phase 11 adds the matching. It holds no rules -- the constructor refuses any,
// rather than accept rules it would silently ignore -- so every packet gets the default action,
// which the pipeline sets to Allow.
class Filter {
 public:
  explicit Filter(std::vector<Rule> rules, Action default_action)
      : rules_{std::move(rules)}, default_{default_action} {
    if (!rules_.empty()) {
      throw std::invalid_argument("packet filter rules are not implemented yet (phase 11)");
    }
  }

  // TODO(phase-11): first match wins, and a rule that constrains sport or dport cannot match a
  // packet whose l4.ports_valid is false (a non-initial fragment).
  [[nodiscard]] Action evaluate([[maybe_unused]] const proto::Ipv4View& ip,
                                [[maybe_unused]] const proto::L4Info& l4,
                                [[maybe_unused]] std::uint16_t in_port) const noexcept {
    return default_;
  }

 private:
  std::vector<Rule> rules_;  // always empty until phase 11
  Action default_;
};

}  // namespace npf::pipe
