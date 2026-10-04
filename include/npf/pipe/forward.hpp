#pragma once

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <npf/core/byte_span.hpp>
#include <npf/core/config.hpp>
#include <npf/core/packet.hpp>
#include <npf/core/pool.hpp>
#include <npf/core/time.hpp>
#include <npf/pipe/decision.hpp>
#include <npf/pipe/filter.hpp>
#include <npf/pipe/icmp_gen.hpp>
#include <npf/proto/arp.hpp>
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
  std::uint8_t prefix_len{0};
  PortMode mode{PortMode::Routed};
};

// The port table, indexed by port id. Throws std::invalid_argument unless the ids run from 0 to
// N-1 and every port's MAC is known: "mac auto" must be read from the interface first.
[[nodiscard]] std::vector<PortState> make_port_table(const core::Config& cfg);

inline constexpr std::uint32_t kLimitedBroadcast = 0xFFFFFFFFU;

// True if ip is exactly one of the router's own addresses, on any port.
[[nodiscard]] inline bool is_router_address(std::span<const PortState> ports,
                                            std::uint32_t ip) noexcept {
  return ip != 0 && std::ranges::any_of(ports, [ip](const PortState& s) { return s.ip == ip; });
}

// True if a packet to ip is delivered to the router itself, never forwarded (RFC 1812 §5.2.3):
// one of its own addresses, or the limited broadcast -- which a router must neither forward nor
// discard (§5.3.5.1), and which a covering route, a default route say, would otherwise forward.
[[nodiscard]] inline bool is_local_destination(std::span<const PortState> ports,
                                               std::uint32_t ip) noexcept {
  return ip == kLimitedBroadcast || is_router_address(ports, ip);
}

// True if ip is the broadcast address of a subnet the router is attached to: all ones in the host
// part of a port's prefix. A /31 (RFC 3021) or a /32 has no broadcast address.
[[nodiscard]] inline bool is_directed_broadcast(std::span<const PortState> ports,
                                                std::uint32_t ip) noexcept {
  return std::ranges::any_of(ports, [ip](const PortState& s) {
    if (s.ip == 0 || s.prefix_len >= 31) {
      return false;
    }
    const std::uint32_t host = ~table::prefix_mask(s.prefix_len);
    return (ip & ~host) == (s.ip & ~host) && (ip & host) == host;
  });
}

// A packet the router sends in answer to one it received: `packet` leaves from `port`.
struct Reply {
  core::Packet* packet;
  std::uint16_t port;
};

// The part of the pipeline that answers packets instead of forwarding them -- ARP for the
// router's addresses, echo replies, ICMP errors -- run by the caller after process() has decided,
// and the way out of the ARP cache for the packets that waited in it. Compiled once, in
// forward.cpp; every Forwarder owns one. Nothing here allocates: a new packet comes from the pool
// the caller passes in, and goes out of the port the original arrived on.
class ControlPlane {
 public:
  ControlPlane(const core::Config& cfg, table::ArpCache& arp, stat::Counters& stats);

  // For a packet process() returned as ToHost.
  //  - An ARP request for the port's own address is turned into its reply in place: the Reply's
  //    packet is p itself.
  //  - An ARP reply, or an announcement (gratuitous ARP), updates what the cache holds for its
  //    sender, if it arrived on the port the cache asks for that neighbour on. One the cache was
  //    waiting for frees the packets queued on it: see released().
  //  - An echo request to any of the router's addresses gets an Echo Reply, and a packet of any
  //    protocol but ICMP a Protocol Unreachable: a new packet, with p still the caller's.
  //  - Anything else is consumed silently, other ICMP types included (RFC 1812 §4.3.2.1).
  // nullopt: no answer, and the caller releases p.
  [[nodiscard]] std::optional<Reply> deliver_to_host(core::Packet& p, core::PacketPool& pool,
                                                     core::Clock::time_point now) noexcept;

  // The packets the last deliver_to_host() took back from the ARP cache, oldest first, each
  // rewritten for its next hop (step 13) and to be sent from `port`. They are the caller's now:
  // it takes them before calling deliver_to_host() again, and counts each as it would a Forward.
  [[nodiscard]] std::span<const Reply> released() const noexcept {
    return {released_.data(), n_released_};
  }

  // For a packet process() dropped: Time Exceeded for TtlExpired, Net Unreachable for NoRoute --
  // if RFC 1812 §4.3.2.7 allows an error and the rate limiter has a token -- as a new packet to
  // send from p's in_port. nullptr for every other reason, or when no error may be sent. p is
  // still the caller's either way.
  [[nodiscard]] core::Packet* error_for(const core::Packet& p, DropReason reason,
                                        core::PacketPool& pool,
                                        core::Clock::time_point now) noexcept;

  // For the head of a queue the ARP cache gave up on (ArpEvents::unresolved): a Host Unreachable,
  // on the same terms as error_for(), except for a packet to the broadcast address of an attached
  // subnet, which no host answers ARP for and which may earn no error (RFC 1812 §4.3.2.7). p is
  // still the caller's either way.
  [[nodiscard]] core::Packet* host_unreachable(const core::Packet& p, core::PacketPool& pool,
                                               core::Clock::time_point now) noexcept;

  [[nodiscard]] std::span<const PortState> ports() const noexcept { return ports_; }

 private:
  [[nodiscard]] std::optional<Reply> answer_arp(core::Packet& p, const proto::EthView& eth,
                                                core::PacketPool& pool) noexcept;
  void learn(std::uint16_t port, const proto::ArpView& msg, core::PacketPool& pool) noexcept;
  [[nodiscard]] core::Packet* make_error(const core::Packet& p, const proto::EthView& eth,
                                         const proto::Ipv4View& ip, IcmpError err,
                                         core::PacketPool& pool,
                                         core::Clock::time_point now) noexcept;

  std::vector<PortState> ports_;  // indexed by port id
  table::ArpCache* arp_;          // borrowed, like the counters
  stat::Counters* stats_;
  std::vector<core::Packet*> ready_;  // ArpCache::on_reply's out-parameter, reserved once
  std::array<Reply, table::kArpQueueDepth> released_{};
  std::size_t n_released_{0};
  IcmpRateLimiter limiter_;  // RFC 1812 §4.3.2.8: errors only, not echo replies
};

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
      : control_{cfg, arp, stats},
        fib_{&fib},
        arp_{&arp},
        macs_{&macs},
        filter_{&filter},
        stats_{&stats} {}

  // The whole datapath for one packet: the fourteen steps of ARCHITECTURE.md §11, in order. No
  // allocation, no locks, no system calls. It counts its own drops and ToHost packets; a Forward
  // is counted by the caller, once the backend has accepted the packet, and a Queued packet when
  // the ARP cache lets go of it. ICMP is not sent from here: the Decision carries the reason, and
  // the caller asks error_for() for the message.
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

  // See ControlPlane.
  [[nodiscard]] std::optional<Reply> deliver_to_host(core::Packet& p, core::PacketPool& pool,
                                                     core::Clock::time_point now) noexcept {
    return control_.deliver_to_host(p, pool, now);
  }
  [[nodiscard]] std::span<const Reply> released() const noexcept { return control_.released(); }
  [[nodiscard]] core::Packet* error_for(const core::Packet& p, DropReason reason,
                                        core::PacketPool& pool,
                                        core::Clock::time_point now) noexcept {
    return control_.error_for(p, reason, pool, now);
  }
  [[nodiscard]] core::Packet* host_unreachable(const core::Packet& p, core::PacketPool& pool,
                                               core::Clock::time_point now) noexcept {
    return control_.host_unreachable(p, pool, now);
  }

  [[nodiscard]] std::span<const PortState> ports() const noexcept { return control_.ports(); }

 private:
  [[nodiscard]] Decision steps(core::Packet& p) noexcept;

  [[nodiscard]] const PortState* port(std::uint16_t id) const noexcept {
    const std::span<const PortState> ports = control_.ports();
    return id < ports.size() ? &ports[id] : nullptr;
  }
  [[nodiscard]] Decision drop(DropReason reason) noexcept {
    ++stats_->drop(reason);
    return {Verdict::Drop, reason, 0};
  }
  [[nodiscard]] Decision to_host() noexcept {
    ++stats_->to_host;
    return {Verdict::ToHost, DropReason::None, 0};
  }

  ControlPlane control_;
  FibT* fib_;  // all borrowed
  table::ArpCache* arp_;
  [[maybe_unused]] table::MacTable* macs_;  // TODO(phase-12): the L2 path learns and switches
  const Filter* filter_;
  stat::Counters* stats_;
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

  // 4. The L2/L3 rule (ARCHITECTURE.md §2). A broadcast is routed only if it is for the router
  // itself, which means reading its destination before step 5 would.
  std::optional<proto::Ipv4View> ip;
  bool route_it = to_our_mac;
  if (!route_it && dst_mac.is_broadcast() && type == proto::kEtherTypeIpv4) {
    ip = proto::Ipv4View::parse(eth->payload());
    route_it = ip.has_value() && is_local_destination(control_.ports(), ip->dst());
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

  // 8. For the router itself: deliver_to_host() answers pings.
  if (is_local_destination(control_.ports(), ip->dst())) {
    return to_host();
  }

  // 9. TTL. error_for() turns the drop into an ICMP Time Exceeded.
  if (ip->ttl() <= 1) {
    return drop(DropReason::TtlExpired);
  }

  // 10. Filter. A malformed L4 header still has a protocol, only no ports for a rule to match.
  // TODO(phase-11): decide whether the filter drops such a packet outright.
  const proto::L4Info l4 = proto::parse_l4(*ip).value_or(proto::L4Info{.protocol = ip->protocol()});
  if (filter_->evaluate(*ip, l4, p.in_port()) == Action::Deny) {
    return drop(DropReason::FilterDeny);
  }

  // 11. Route. error_for() turns the drop into an ICMP Net Unreachable.
  const std::optional<table::NextHop> next = fib_->lookup(ip->dst());
  if (!next) {
    return drop(DropReason::NoRoute);
  }
  const PortState* out = port(next->port);
  if (out == nullptr) {
    return drop(DropReason::NoOutPort);
  }

  // 12. The next hop's MAC. A next hop of 0 is a directly connected route: deliver to the
  // destination itself. Unresolved, the packet waits in the ARP cache, which owns it from then on;
  // deliver_to_host() takes it back when the neighbour answers, and rewrites it then.
  const std::uint32_t neighbour = next->ip != 0 ? next->ip : ip->dst();
  const std::optional<proto::MacAddr> neighbour_mac = arp_->lookup(neighbour);
  if (!neighbour_mac) {
    if (!arp_->resolve_and_queue(neighbour, next->port, &p)) {
      return drop(DropReason::ArpUnresolved);  // its queue is full, or the cache is
    }
    return {Verdict::Queued, DropReason::None, next->port};
  }

  // 13. Rewrite, and 14. forward.
  rewrite_for_forwarding(p, *eth, *ip, *neighbour_mac, *out);
  return {Verdict::Forward, DropReason::None, next->port};
}

}  // namespace npf::pipe
