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
    ports[iface.port] = PortState{.mac = *iface.mac, .ip = iface.ip, .mode = iface.mode};
  }
  return ports;
}

ControlPlane::ControlPlane(const core::Config& cfg, table::ArpCache& arp, stat::Counters& stats)
    : ports_{make_port_table(cfg)}, arp_{&arp}, stats_{&stats} {
  ready_.reserve(table::kArpQueueDepth);
}

std::optional<Reply> ControlPlane::deliver_to_host(core::Packet& p, core::PacketPool& pool,
                                                   core::Clock::time_point now) noexcept {
  const std::optional<proto::EthView> eth = proto::EthView::parse(p.data());
  if (!eth || p.in_port() >= ports_.size()) {
    return std::nullopt;
  }
  if (eth->ethertype() == proto::kEtherTypeArp) {
    return answer_arp(p, *eth);
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
      return nullptr;  // TODO(phase-8): Host Unreachable, once the ARP cache gives up on a host
  }
  // Steps 1 to 8 passed before either of those drops, so both headers parse again.
  const std::optional<proto::EthView> eth = proto::EthView::parse(p.data());
  if (!eth || p.in_port() >= ports_.size()) {
    return nullptr;
  }
  const std::optional<proto::Ipv4View> ip = proto::Ipv4View::parse(eth->payload());
  return ip ? make_error(p, *eth, *ip, err, pool, now) : nullptr;
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

std::optional<Reply> ControlPlane::answer_arp(core::Packet& p, const proto::EthView& eth) noexcept {
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
    if (gratuitous) {
      arp_->on_unsolicited(spa, sha);
    } else {
      arp_->on_reply(spa, sha, ready_);
      assert(ready_.empty() && "the phase 6 cache never queues");  // TODO(phase-8): send them
    }
    return std::nullopt;
  }
  if (msg->oper() != proto::ArpView::kOpRequest) {
    return std::nullopt;
  }
  ++stats_->arp_requests_rx;
  if (gratuitous) {
    arp_->on_unsolicited(spa, sha);
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

// Compiled here once, and checked here by clang-tidy, which only reads src/.
template class Forwarder<table::LinearLpm>;

}  // namespace npf::pipe
