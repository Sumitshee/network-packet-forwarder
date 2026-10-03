#include <cassert>
#include <cstddef>
#include <cstdint>
#include <format>
#include <npf/core/byte_span.hpp>
#include <npf/core/config.hpp>
#include <npf/core/packet.hpp>
#include <npf/pipe/forward.hpp>
#include <npf/proto/arp.hpp>
#include <npf/proto/ethernet.hpp>
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
    ports[iface.port] = PortState{.mac = *iface.mac, .ip = iface.ip, .mode = iface.mode};
  }
  return ports;
}

std::optional<std::uint16_t> deliver_to_host(core::Packet& p, std::span<const PortState> ports,
                                             table::ArpCache& arp, stat::Counters& stats,
                                             std::vector<core::Packet*>& ready) noexcept {
  const std::optional<proto::EthView> eth = proto::EthView::parse(p.data());
  if (!eth || p.in_port() >= ports.size() || eth->ethertype() != proto::kEtherTypeArp) {
    return std::nullopt;  // an IPv4 packet for the router itself. TODO(phase-7): answer pings.
  }
  const std::optional<proto::ArpView> msg = proto::ArpView::parse(eth->payload());
  if (!msg) {
    return std::nullopt;  // malformed: nothing to answer, nothing to learn
  }
  const PortState& in = ports[p.in_port()];
  const proto::MacAddr sha = msg->sha();
  const std::uint32_t spa = msg->spa();
  const std::uint32_t tpa = msg->tpa();
  // A sender announcing its own address -- gratuitous ARP, as a request or a reply -- may
  // refresh what the cache already knows, never add to it.
  const bool gratuitous = spa == tpa;

  if (msg->oper() == proto::ArpView::kOpReply) {
    ++stats.arp_replies_rx;
    if (gratuitous) {
      arp.on_unsolicited(spa, sha);
    } else {
      arp.on_reply(spa, sha, ready);
      assert(ready.empty() && "the phase 6 cache never queues");  // TODO(phase-8): send them
    }
    return std::nullopt;
  }
  if (msg->oper() != proto::ArpView::kOpRequest) {
    return std::nullopt;
  }
  ++stats.arp_requests_rx;
  if (gratuitous) {
    arp.on_unsolicited(spa, sha);
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
  const core::Bytes body = frame.subspan(eth->header_len(), proto::ArpView::kMinSize);
  core::wr_be16(body, 6, proto::ArpView::kOpReply);
  proto::wr_mac(body, 8, in.mac);
  core::wr_be32(body, 14, in.ip);
  proto::wr_mac(body, 18, sha);
  core::wr_be32(body, 24, spa);
  p.resize(eth->header_len() + proto::ArpView::kMinSize);  // the request's padding is not sent back
  return p.in_port();
}

// Compiled here once, and checked here by clang-tidy, which only reads src/.
template class Forwarder<table::LinearLpm>;

}  // namespace npf::pipe
