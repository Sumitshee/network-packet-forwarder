#pragma once

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <npf/core/byte_span.hpp>
#include <npf/core/config.hpp>
#include <npf/core/packet.hpp>
#include <npf/pipe/decision.hpp>
#include <npf/pipe/filter.hpp>
#include <npf/proto/checksum.hpp>
#include <npf/proto/ethernet.hpp>
#include <npf/proto/ipv4.hpp>
#include <npf/proto/l4.hpp>
#include <npf/proto/mac.hpp>
#include <npf/stat/counters.hpp>
#include <npf/table/arp_cache.hpp>
#include <npf/table/fib.hpp>
#include <npf/table/mac_table.hpp>
#include <optional>
#include <span>
#include <vector>

namespace npf::pipe {

// The router's own presence on one port, as configured.
struct PortState {
  proto::MacAddr mac;
  std::uint32_t ip{0};  // host order
  PortMode mode{PortMode::Routed};
};

// The port table, indexed by port id. Throws std::invalid_argument unless the ids run from 0 to
// N-1 and every port's MAC is known: "mac auto" must be read from the interface first.
[[nodiscard]] std::vector<PortState> make_port_table(const core::Config& cfg);

// The control-plane half of a packet that process() handed up as ToHost. An ARP request for the
// address of the port it came in on is turned into the reply, in place, and the port to send it
// back out of is returned. An ARP reply completes the cache entry that asked for it; gratuitous
// ARP refreshes an existing one. Anything else is consumed. nullopt: the caller releases p.
[[nodiscard]] std::optional<std::uint16_t> deliver_to_host(
    core::Packet& p, std::span<const PortState> ports, table::ArpCache& arp, stat::Counters& stats,
    std::vector<core::Packet*>& ready) noexcept;

// Step 13 on a frame that passed steps 1 to 12: the next hop's MAC as destination, the output
// port's as source, TTL down by one, and the header checksum patched for that one changed word
// (RFC 1624) instead of summed again. Caches the parse offsets on the packet.
inline void rewrite_for_forwarding(core::Packet& p, const proto::EthView& eth,
                                   const proto::Ipv4View& ip, const proto::MacAddr& next_hop_mac,
                                   const PortState& out) noexcept {
  const core::Bytes frame = p.data();
  proto::wr_mac(frame, 0, next_hop_mac);
  proto::wr_mac(frame, 6, out.mac);
  const core::Bytes hdr = frame.subspan(eth.header_len(), ip.header_len());
  // The TTL shares a 16-bit word with the protocol, and words are what the checksum sums.
  const std::uint16_t before = core::rd_be16(hdr, 8);
  core::wr_u8(hdr, 8, static_cast<std::uint8_t>(core::rd_u8(hdr, 8) - 1));
  core::wr_be16(hdr, 10,
                proto::checksum_update16(core::rd_be16(hdr, 10), before, core::rd_be16(hdr, 8)));
  p.set_offsets(static_cast<std::uint16_t>(eth.header_len()),
                static_cast<std::uint16_t>(eth.header_len() + ip.header_len()));
}

// ARCHITECTURE.md §11. Templated on the FIB type, so the datapath's lookup is a direct call.
template <class FibT>
class Forwarder {
 public:
  // Every dependency is borrowed: the caller owns it and keeps it alive for as long as this.
  Forwarder(const core::Config& cfg, FibT& fib, table::ArpCache& arp, table::MacTable& macs,
            const Filter& filter, stat::Counters& stats)
      : fib_{&fib},
        arp_{&arp},
        macs_{&macs},
        filter_{&filter},
        stats_{&stats},
        ports_{make_port_table(cfg)} {
    ready_.reserve(table::kArpQueueDepth);
  }

  // The whole datapath for one packet: the fourteen steps of ARCHITECTURE.md §11, in order. No
  // allocation, no locks, no system calls. It counts its own drops and ToHost packets; a Forward
  // is counted by the caller, once the backend has accepted the packet.
  [[nodiscard]] Decision process(core::Packet& p) noexcept {
    const Decision d = steps(p);
    assert((d.verdict == Verdict::Drop) == (d.reason != DropReason::None) &&
           "a Drop needs a reason, and nothing else may have one");
    return d;
  }

  // Batched entry point used by the worker loop.
  void process_burst(core::Packet** pkts, std::size_t n, Decision* out) noexcept {
    for (std::size_t i = 0; i < n; ++i) {
      out[i] = process(*pkts[i]);
    }
  }

  // See the free function above. The caller runs it after process() returns ToHost.
  [[nodiscard]] std::optional<std::uint16_t> deliver_to_host(core::Packet& p) noexcept {
    return pipe::deliver_to_host(p, ports_, *arp_, *stats_, ready_);
  }

  [[nodiscard]] std::span<const PortState> ports() const noexcept { return ports_; }

 private:
  [[nodiscard]] Decision steps(core::Packet& p) noexcept;

  [[nodiscard]] const PortState* port(std::uint16_t id) const noexcept {
    return id < ports_.size() ? &ports_[id] : nullptr;
  }
  [[nodiscard]] bool is_ours(std::uint32_t ip) const noexcept {
    return ip != 0 && std::ranges::any_of(ports_, [ip](const PortState& s) { return s.ip == ip; });
  }
  [[nodiscard]] Decision drop(DropReason reason) noexcept {
    ++stats_->drop(reason);
    return {Verdict::Drop, reason, 0};
  }
  [[nodiscard]] Decision to_host() noexcept {
    ++stats_->to_host;
    return {Verdict::ToHost, DropReason::None, 0};
  }

  FibT* fib_;
  table::ArpCache* arp_;
  [[maybe_unused]] table::MacTable* macs_;  // TODO(phase-12): the L2 path learns and switches
  const Filter* filter_;
  stat::Counters* stats_;
  std::vector<PortState> ports_;      // indexed by port id
  std::vector<core::Packet*> ready_;  // ArpCache::on_reply's out-parameter, reserved once
};

template <class FibT>
Decision Forwarder<FibT>::steps(core::Packet& p) noexcept {
  // 1. Ethernet.
  const std::optional<proto::EthView> eth = proto::EthView::parse(p.data());
  if (!eth) {
    return drop(DropReason::ShortFrame);
  }
  const PortState* in = port(p.in_port());
  assert(in != nullptr && "a packet from a port the configuration does not have");
  if (in == nullptr) {
    return drop(DropReason::NoOutPort);
  }

  // 2. EtherType dispatch.
  const std::uint16_t type = eth->ethertype();
  if (type != proto::kEtherTypeIpv4 && type != proto::kEtherTypeArp) {
    return drop(DropReason::BadEtherType);
  }

  // 3. ARP addressed to the router, or broadcast, goes to the ARP handler: deliver_to_host().
  const proto::MacAddr dst_mac = eth->dst();
  const bool to_our_mac = dst_mac == in->mac;
  if (type == proto::kEtherTypeArp && (to_our_mac || dst_mac.is_broadcast())) {
    return to_host();
  }

  // 4. The L2/L3 rule (ARCHITECTURE.md §2). A broadcast is routed only if it is for one of the
  // router's addresses, which means reading that address before step 5 would.
  std::optional<proto::Ipv4View> ip;
  bool route_it = to_our_mac;
  if (!route_it && dst_mac.is_broadcast() && type == proto::kEtherTypeIpv4) {
    ip = proto::Ipv4View::parse(eth->payload());
    route_it = ip.has_value() && is_ours(ip->dst());
  }
  if (!route_it) {
    // A transit frame. Only a bridged port would switch it, and until phase 12 fills the MAC
    // table even that has nowhere to send it.
    return drop(DropReason::UnknownDestPort);
  }

  // 5. IPv4 header. Steps 3 and 4 leave only IPv4 frames here.
  if (!ip) {
    ip = proto::Ipv4View::parse(eth->payload());
    if (!ip) {
      return drop(DropReason::BadIpv4Header);
    }
  }

  // 6. Header checksum.
  if (!proto::ipv4_checksum_valid(ip->header())) {
    return drop(DropReason::BadChecksum);
  }
  stats_->count_protocol(ip->protocol());

  // 7. Martian source (RFC 1812 §5.3.7).
  if (proto::is_martian_source(ip->src())) {
    return drop(DropReason::MartianSource);
  }

  // 8. For the router itself. TODO(phase-7): answer pings.
  if (is_ours(ip->dst())) {
    return to_host();
  }

  // 9. TTL. TODO(phase-7): send ICMP Time Exceeded.
  if (ip->ttl() <= 1) {
    return drop(DropReason::TtlExpired);
  }

  // 10. Filter. A malformed L4 header still has a protocol, only no ports for a rule to match.
  // TODO(phase-11): decide whether the filter drops such a packet outright.
  const proto::L4Info l4 = proto::parse_l4(*ip).value_or(proto::L4Info{.protocol = ip->protocol()});
  if (filter_->evaluate(*ip, l4, p.in_port()) == Action::Deny) {
    return drop(DropReason::FilterDeny);
  }

  // 11. Route. TODO(phase-7): send ICMP Net Unreachable.
  const std::optional<table::NextHop> next = fib_->lookup(ip->dst());
  if (!next) {
    return drop(DropReason::NoRoute);
  }
  const PortState* out = port(next->port);
  if (out == nullptr) {
    return drop(DropReason::NoOutPort);
  }

  // 12. The next hop's MAC. A next hop of 0 is a directly connected route: deliver to the
  // destination itself.
  const std::uint32_t neighbour = next->ip != 0 ? next->ip : ip->dst();
  const std::optional<proto::MacAddr> neighbour_mac = arp_->lookup(neighbour);
  if (!neighbour_mac) {
    // The phase 6 cache sends a request but never keeps the packet. TODO(phase-8): a queued
    // packet belongs to the cache from then on, and needs a verdict of its own.
    [[maybe_unused]] const bool queued = arp_->resolve_and_queue(neighbour, next->port, &p);
    assert(!queued);
    return drop(DropReason::ArpUnresolved);
  }

  // 13. Rewrite, and 14. forward.
  rewrite_for_forwarding(p, *eth, *ip, *neighbour_mac, *out);
  return {Verdict::Forward, DropReason::None, next->port};
}

}  // namespace npf::pipe
