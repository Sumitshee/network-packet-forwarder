#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <format>
#include <npf/pipe/filter.hpp>
#include <npf/proto/ipv4.hpp>
#include <npf/proto/l4.hpp>
#include <npf/table/fib.hpp>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace npf::pipe {
namespace {

bool is_action(Action a) noexcept {
  return a == Action::Allow || a == Action::Deny;
}

bool constrains_ports(const Rule& r) noexcept {
  return r.sport.has_value() || r.dport.has_value();
}

// Why the rule cannot be used, or empty if it can.
std::string_view fault(const Rule& r) noexcept {
  if (!is_action(r.action)) {
    return "its action is neither allow nor deny";
  }
  if ((r.src && !table::is_valid(*r.src)) || (r.dst && !table::is_valid(*r.dst))) {
    return "an address has bits set past its prefix length";
  }
  if ((r.sport && r.sport->lo > r.sport->hi) || (r.dport && r.dport->lo > r.dport->hi)) {
    return "a port range ends before it starts";
  }
  if (constrains_ports(r) && r.protocol && *r.protocol != proto::kIpProtoTcp &&
      *r.protocol != proto::kIpProtoUdp) {
    return "it constrains ports of a protocol that has none, so it could never match";
  }
  return {};
}

bool in_range(const std::optional<PortRange>& range, std::uint16_t port) noexcept {
  return !range || (range->lo <= port && port <= range->hi);
}

}  // namespace

Filter::Filter(std::vector<Rule> rules, Action default_action)
    : rules_{std::move(rules)},
      default_{default_action},
      port_rules_{std::ranges::any_of(rules_, constrains_ports)} {
  if (!is_action(default_)) {
    throw std::invalid_argument("the filter's default action is neither allow nor deny");
  }
  for (std::size_t i = 0; i < rules_.size(); ++i) {
    if (const std::string_view why = fault(rules_[i]); !why.empty()) {
      throw std::invalid_argument(std::format("filter rule {}: {}", i + 1, why));
    }
  }
}

Action Filter::evaluate(const proto::Ipv4View& ip, const proto::L4Info& l4,
                        std::uint16_t in_port) const noexcept {
  const std::uint32_t src = ip.src();
  const std::uint32_t dst = ip.dst();
  const std::uint8_t protocol = ip.protocol();
  for (const Rule& r : rules_) {
    if ((r.in_port && *r.in_port != in_port) || (r.protocol && *r.protocol != protocol) ||
        (r.src && !table::contains(*r.src, src)) || (r.dst && !table::contains(*r.dst, dst))) {
      continue;
    }
    if (constrains_ports(r) &&
        (!l4.ports_valid || !in_range(r.sport, l4.sport) || !in_range(r.dport, l4.dport))) {
      continue;
    }
    return r.action;
  }
  return default_;
}

}  // namespace npf::pipe
