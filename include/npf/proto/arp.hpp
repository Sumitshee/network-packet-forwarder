#pragma once

#include <cstddef>
#include <cstdint>
#include <npf/core/byte_span.hpp>
#include <npf/core/packet.hpp>
#include <npf/proto/ethernet.hpp>
#include <npf/proto/mac.hpp>
#include <optional>

namespace npf::proto {

// ARP for IPv4 over Ethernet (RFC 826), the only kind a router on Ethernet needs. The span is the
// Ethernet payload.
class ArpView {
 public:
  static constexpr std::size_t kMinSize = 28;
  static constexpr std::uint16_t kHtypeEthernet = 1;
  static constexpr std::uint16_t kOpRequest = 1;
  static constexpr std::uint16_t kOpReply = 2;

  // Validates htype==1, ptype==0x0800, hlen==6, plen==4, and total length >= 28. The operation is
  // deliberately not validated: what to do with one other than request or reply is the caller's
  // decision, not a malformed packet.
  [[nodiscard]] static constexpr std::optional<ArpView> parse(core::CBytes buf) noexcept {
    if (buf.size() < kMinSize) {
      return std::nullopt;
    }
    if (core::rd_be16(buf, 0) != kHtypeEthernet || core::rd_be16(buf, 2) != kEtherTypeIpv4 ||
        core::rd_u8(buf, 4) != 6 || core::rd_u8(buf, 5) != 4) {
      return std::nullopt;
    }
    return ArpView{buf};
  }

  [[nodiscard]] constexpr std::uint16_t oper() const noexcept {  // 1 request, 2 reply
    return core::rd_be16(buf_, 6);
  }
  [[nodiscard]] constexpr MacAddr sha() const noexcept { return rd_mac(buf_, 8); }
  [[nodiscard]] constexpr std::uint32_t spa() const noexcept {  // host order
    return core::rd_be32(buf_, 14);
  }
  [[nodiscard]] constexpr MacAddr tha() const noexcept { return rd_mac(buf_, 18); }
  [[nodiscard]] constexpr std::uint32_t tpa() const noexcept { return core::rd_be32(buf_, 24); }

 private:
  constexpr explicit ArpView(core::CBytes buf) noexcept : buf_{buf} {}

  core::CBytes buf_;
};

// 14 bytes of Ethernet header and 28 of ARP, unpadded. Padding a short frame up to the 60-byte
// Ethernet minimum is left to the transmitting device.
inline constexpr std::size_t kArpFrameSize = EthView::kMinSize + ArpView::kMinSize;

namespace detail {

struct ArpFrame {
  std::uint16_t oper{};
  MacAddr eth_dst;
  MacAddr sha;
  std::uint32_t spa{};
  MacAddr tha;
  std::uint32_t tpa{};
};

[[nodiscard]] inline bool build_arp(core::Packet& p, const ArpFrame& f) noexcept {
  if (p.capacity() < kArpFrameSize) {
    return false;
  }
  p.resize(kArpFrameSize);
  const core::Bytes out = p.data();
  wr_mac(out, 0, f.eth_dst);
  wr_mac(out, 6, f.sha);
  core::wr_be16(out, 12, kEtherTypeArp);
  const core::Bytes arp = out.subspan(EthView::kMinSize);
  core::wr_be16(arp, 0, ArpView::kHtypeEthernet);
  core::wr_be16(arp, 2, kEtherTypeIpv4);
  core::wr_u8(arp, 4, 6);
  core::wr_u8(arp, 5, 4);
  core::wr_be16(arp, 6, f.oper);
  wr_mac(arp, 8, f.sha);
  core::wr_be32(arp, 14, f.spa);
  wr_mac(arp, 18, f.tha);
  core::wr_be32(arp, 24, f.tpa);
  return true;
}

}  // namespace detail

// Write a complete ARP request/reply into p, sizing it to 42 bytes. Returns false if p is too
// small, leaving it untouched. Addresses are host order. A request is broadcast, and its target
// hardware address is zero: RFC 826 says the target ignores it.
[[nodiscard]] inline bool build_arp_request(core::Packet& p, MacAddr src_mac, std::uint32_t src_ip,
                                            std::uint32_t target_ip) noexcept {
  return detail::build_arp(p, {.oper = ArpView::kOpRequest,
                               .eth_dst = kBroadcastMac,
                               .sha = src_mac,
                               .spa = src_ip,
                               .tha = MacAddr{},
                               .tpa = target_ip});
}

[[nodiscard]] inline bool build_arp_reply(core::Packet& p, MacAddr src_mac, std::uint32_t src_ip,
                                          MacAddr dst_mac, std::uint32_t dst_ip) noexcept {
  return detail::build_arp(p, {.oper = ArpView::kOpReply,
                               .eth_dst = dst_mac,
                               .sha = src_mac,
                               .spa = src_ip,
                               .tha = dst_mac,
                               .tpa = dst_ip});
}

}  // namespace npf::proto
