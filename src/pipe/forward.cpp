#include <cassert>
#include <cstddef>
#include <cstdint>
#include <format>
#include <npf/core/byte_span.hpp>
#include <npf/core/config.hpp>
#include <npf/core/packet.hpp>
#include <npf/core/pool.hpp>
#include <npf/core/time.hpp>
#include <npf/pipe/decision.hpp>
#include <npf/pipe/forward.hpp>
#include <npf/pipe/icmp_gen.hpp>
#include <npf/proto/arp.hpp>
#include <npf/proto/ethernet.hpp>
#include <npf/proto/icmp.hpp>
#include <npf/proto/ipv4.hpp>
#include <npf/proto/l4.hpp>
#include <npf/proto/mac.hpp>
#include <npf/stat/counters.hpp>
#include <npf/table/arp_cache.hpp>
#include <npf/table/lpm_linear.hpp>
#include <optional>
#include <span>
#include <stdexcept>
#include <vector>

namespace npf::pipe {

std::vector<PortState> make_port_table(const core::Config& cfg) {
  std::vector<PortState> ports(cfg.interfaces.size());
  std::vector<bool> seen(cfg.interfaces.size(), false);
  for (const core::InterfaceConfig& iface : cfg.interfaces) {
    if (iface.port >= ports.size() || seen[iface.port]) {
      throw std::invalid_argument(
          std::format("port ids must run from 0 to {}, each used once; interface {} has port {}",
                      ports.size() - 1, iface.name, iface.port));
    }
    if (!iface.mac) {
      throw std::invalid_argument(std::format(
          "interface {} has no MAC address yet: read 'mac auto' from the interface first",
          iface.name));
    }
    seen[iface.port] = true;
    ports[iface.port] = PortState{.mac = *iface.mac,
                                  .ip = iface.ip,
                                  .prefix_len = iface.prefix_len,
                                  .mode = iface.mode,
                                  .bridge_domain = iface.bridge_domain};
  }
  return ports;
}

std::vector<std::vector<std::uint16_t>> make_flood_sets(std::span<const PortState> ports,
                                                        const std::vector<bool>& up) {
  if (up.size() != ports.size()) {
    throw std::invalid_argument(
        std::format("{} link states for {} ports", up.size(), ports.size()));
  }
  const auto bridged_in = [ports](std::size_t i, std::uint16_t domain) {
    return ports[i].mode == PortMode::Bridged && ports[i].bridge_domain == domain;
  };
  std::vector<std::vector<std::uint16_t>> sets(ports.size());
  for (std::size_t i = 0; i < ports.size(); ++i) {
    if (ports[i].mode != PortMode::Bridged) {
      continue;
    }
    for (std::size_t j = 0; j < ports.size(); ++j) {
      if (j != i && up[j] && bridged_in(j, ports[i].bridge_domain)) {
        sets[i].push_back(static_cast<std::uint16_t>(j));
      }
    }
  }
  return sets;
}

ControlPlane::ControlPlane(const core::Config& cfg, table::ArpCache& arp, stat::Counters& stats)
    : ports_{make_port_table(cfg)}, arp_{&arp}, stats_{&stats} {
  ready_.reserve(table::kArpQueueDepth);
}

std::optional<Reply> ControlPlane::deliver_to_host(core::Packet& p, core::PacketPool& pool,
                                                   core::Clock::time_point now) noexcept {
  n_released_ = 0;
  const std::optional<proto::EthView> eth = proto::EthView::parse(p.data());
  if (!eth || p.in_port() >= ports_.size()) {
    return std::nullopt;
  }
  if (eth->ethertype() == proto::kEtherTypeArp) {
    return answer_arp(p, *eth, pool);
  }
  const std::optional<proto::Ipv4View> ip = proto::Ipv4View::parse(eth->payload());
  if (!ip || !is_router_address(ports_, ip->dst())) {
    return std::nullopt;
  }
  if (ip->protocol() != proto::kIpProtoIcmp) {
    // No transport protocol runs on the router: RFC 1812 §5.2.7.1's code 2.
    core::Packet* error = make_error(p, *eth, *ip, IcmpError::ProtoUnreachable, pool, now);
    return error != nullptr ? std::optional<Reply>{Reply{error, p.in_port()}} : std::nullopt;
  }
  const std::optional<proto::IcmpView> icmp = proto::IcmpView::parse(ip->payload());
  if (!icmp || icmp->type() != proto::kIcmpEchoRequest || ip->is_fragment()) {
    return std::nullopt;  // nothing to answer; a fragmented request cannot be, without reassembly
  }
  core::Packet* reply = pool.acquire();
  if (reply == nullptr) {
    return std::nullopt;
  }
  const PortState& in = ports_[p.in_port()];
  if (!build_echo_reply(*reply, *ip, p.data(), in.mac, eth->src())) {
    pool.release(reply);
    return std::nullopt;
  }
  ++stats_->icmp_generated;
  return Reply{reply, p.in_port()};
}

core::Packet* ControlPlane::error_for(const core::Packet& p, DropReason reason,
                                      core::PacketPool& pool,
                                      core::Clock::time_point now) noexcept {
  IcmpError err{};
  switch (reason) {
    case DropReason::TtlExpired:
      err = IcmpError::TimeExceeded;
      break;
    case DropReason::NoRoute:
      err = IcmpError::NetUnreachable;
      break;
    default:
      // ArpUnresolved among them: a full queue says nothing about whether the neighbour is there.
      // A neighbour that never answers earns its Host Unreachable from host_unreachable().
      return nullptr;
  }
  // Steps 1 to 8 passed before either of those drops, so both headers parse again.
  const std::optional<proto::EthView> eth = proto::EthView::parse(p.data());
  if (!eth || p.in_port() >= ports_.size()) {
    return nullptr;
  }
  const std::optional<proto::Ipv4View> ip = proto::Ipv4View::parse(eth->payload());
  return ip ? make_error(p, *eth, *ip, err, pool, now) : nullptr;
}

core::Packet* ControlPlane::host_unreachable(const core::Packet& p, core::PacketPool& pool,
                                             core::Clock::time_point now) noexcept {
  // A queued packet passed steps 1 to 12 and was left untouched, so both headers parse again.
  const std::optional<proto::EthView> eth = proto::EthView::parse(p.data());
  if (!eth || p.in_port() >= ports_.size()) {
    return nullptr;
  }
  const std::optional<proto::Ipv4View> ip = proto::Ipv4View::parse(eth->payload());
  if (!ip || is_directed_broadcast(ports_, ip->dst())) {
    return nullptr;
  }
  return make_error(p, *eth, *ip, IcmpError::HostUnreachable, pool, now);
}

core::Packet* ControlPlane::make_error(const core::Packet& p, const proto::EthView& eth,
                                       const proto::Ipv4View& ip, IcmpError err,
                                       core::PacketPool& pool,
                                       core::Clock::time_point now) noexcept {
  const PortState& in = ports_[p.in_port()];
  // A malformed transport header leaves no telling whether the packet is itself an ICMP error,
  // so it earns none. The error goes back to the frame's sender, which must be one station.
  const std::optional<proto::L4Info> l4 = proto::parse_l4(ip);
  if (!l4 || !may_send_icmp_error(ip, *l4) || eth.src().is_multicast() || in.ip == 0 ||
      !limiter_.allow(now)) {
    return nullptr;
  }
  core::Packet* out = pool.acquire();
  if (out == nullptr) {
    return nullptr;
  }
  // Back out of the port the packet came in on, so the source address is that port's own, as
  // RFC 1812 §4.3.2.4 requires -- and the one traceroute should show for this hop.
  if (!build_icmp_error(*out, ip, p.data(), err, in.ip, in.mac, eth.src())) {
    pool.release(out);
    return nullptr;
  }
  ++stats_->icmp_generated;
  return out;
}

std::optional<Reply> ControlPlane::answer_arp(core::Packet& p, const proto::EthView& eth,
                                              core::PacketPool& pool) noexcept {
  const std::optional<proto::ArpView> msg = proto::ArpView::parse(eth.payload());
  if (!msg) {
    return std::nullopt;  // malformed: nothing to answer, nothing to learn
  }
  const PortState& in = ports_[p.in_port()];
  const proto::MacAddr sha = msg->sha();
  const std::uint32_t spa = msg->spa();
  const std::uint32_t tpa = msg->tpa();
  // A sender announcing its own address -- gratuitous ARP, as a request or a reply -- may
  // refresh what the cache already knows, never add to it.
  const bool gratuitous = spa == tpa;

  if (msg->oper() == proto::ArpView::kOpReply) {
    ++stats_->arp_replies_rx;
    learn(p.in_port(), *msg, pool);
    return std::nullopt;
  }
  if (msg->oper() != proto::ArpView::kOpRequest) {
    return std::nullopt;
  }
  ++stats_->arp_requests_rx;
  if (gratuitous) {
    learn(p.in_port(), *msg, pool);
    return std::nullopt;
  }
  // Each port answers for its own address only, like Linux with arp_ignore=1.
  if (in.ip == 0 || tpa != in.ip) {
    return std::nullopt;
  }

  // The reply is the request turned around in place: same buffer, same VLAN tag if there was one.
  const core::Bytes frame = p.data();
  proto::wr_mac(frame, 0, sha);
  proto::wr_mac(frame, 6, in.mac);
  const core::Bytes body = frame.subspan(eth.header_len(), proto::ArpView::kMinSize);
  core::wr_be16(body, 6, proto::ArpView::kOpReply);
  proto::wr_mac(body, 8, in.mac);
  core::wr_be32(body, 14, in.ip);
  proto::wr_mac(body, 18, sha);
  core::wr_be32(body, 24, spa);
  p.resize(eth.header_len() + proto::ArpView::kMinSize);  // the request's padding is not sent back
  return Reply{&p, p.in_port()};
}

// What a reply, or an announcement, arriving on port tells the cache about its sender. Only news
// from the port the cache asks for that neighbour on counts: the cache is keyed by address alone,
// and a station on another segment must not steer the neighbour's traffic. A reply answers the
// cache's question, and so does an announcement while the cache is still waiting for an answer;
// either completes the entry and frees the packets queued on it. Otherwise an announcement only
// refreshes.
void ControlPlane::learn(std::uint16_t port, const proto::ArpView& msg,
                         core::PacketPool& pool) noexcept {
  const std::uint32_t neighbour = msg.spa();
  const proto::MacAddr mac = msg.sha();
  const std::optional<table::ArpNeighbour> known = arp_->peek(neighbour);
  if (!known || known->port != port) {
    return;
  }
  const bool answer = msg.oper() == proto::ArpView::kOpReply && msg.tpa() != neighbour;
  if (!answer && known->state != table::ArpState::Incomplete) {
    arp_->on_unsolicited(neighbour, mac);
    return;
  }
  arp_->on_reply(neighbour, mac, ready_);
  const PortState& out = ports_[port];
  for (core::Packet* q : ready_) {
    // Steps 1 to 12 passed before it was queued, and nothing has touched it since.
    const std::optional<proto::EthView> eth = proto::EthView::parse(q->data());
    const std::optional<proto::Ipv4View> ip =
        eth ? proto::Ipv4View::parse(eth->payload()) : std::nullopt;
    if (!eth || !ip) {
      pool.release(q);
      ++stats_->drop(DropReason::ArpUnresolved);
      continue;
    }
    rewrite_for_forwarding(*q, *eth, *ip, mac, out);
    assert(n_released_ < released_.size() && "one entry's queue at most");
    // The assertion is the bounds check: on_reply() hands back at most one queue.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
    released_[n_released_++] = Reply{q, port};
  }
  ready_.clear();
}

// Compiled here once, and checked here by clang-tidy, which only reads src/.
template class Forwarder<table::LinearLpm>;

}  // namespace npf::pipe
