#pragma once

#include <cstddef>
#include <cstdint>
#include <npf/core/byte_span.hpp>
#include <npf/proto/icmp.hpp>
#include <npf/proto/ipv4.hpp>
#include <optional>

namespace npf::proto {

inline constexpr std::uint8_t kIpProtoIcmp = 1;
inline constexpr std::uint8_t kIpProtoTcp = 6;
inline constexpr std::uint8_t kIpProtoUdp = 17;

inline constexpr std::size_t kTcpMinHeader = 20;
inline constexpr std::size_t kUdpHeader = 8;

// Layer 4. One struct rather than three view types: the pipeline only needs the fields.
struct L4Info {
  std::uint8_t protocol{0};
  bool ports_valid{false};  // FALSE for every non-initial fragment
  std::uint16_t sport{0}, dport{0};
  std::uint8_t tcp_flags{0};
  std::uint32_t seq{0}, ack{0};
  std::uint8_t icmp_type{0}, icmp_code{0};
};

// HARD RULE: if !ip.is_first_fragment(), this sets protocol and leaves ports_valid == false. It
// must not read a single byte of the L4 header in that case: a non-initial fragment carries only
// payload, so bytes that happen to look like ports are data, and trusting them would let a
// fragment match port-based rules it has nothing to do with.
//
// Otherwise nullopt means the L4 header is malformed or cut short:
//   TCP  fewer than 20 bytes, data offset below 5, or a header longer than the payload
//   UDP  fewer than 8 bytes, or a length field below 8
//   ICMP fewer than 8 bytes
// A first fragment too short for the whole TCP header therefore counts as malformed. That is the
// tiny-fragment attack of RFC 1858, which moves the TCP flags into the second fragment.
//
// Any other protocol gets protocol set and nothing else: its header is not read, and not having
// ports is not an error. The ICMP checksum is not checked here; IcmpView does that.
[[nodiscard]] constexpr std::optional<L4Info> parse_l4(const Ipv4View& ip) noexcept {
  L4Info out;
  out.protocol = ip.protocol();
  if (!ip.is_first_fragment()) {
    out.ports_valid = false;
    return out;  // do NOT read the payload. The ports are not there.
  }

  const core::CBytes l4 = ip.payload();
  switch (out.protocol) {
    case kIpProtoTcp: {
      if (l4.size() < kTcpMinHeader) {
        return std::nullopt;
      }
      const std::size_t header_len = (std::size_t{core::rd_u8(l4, 12)} >> 4U) * 4;
      if (header_len < kTcpMinHeader || header_len > l4.size()) {
        return std::nullopt;
      }
      out.sport = core::rd_be16(l4, 0);
      out.dport = core::rd_be16(l4, 2);
      out.seq = core::rd_be32(l4, 4);
      out.ack = core::rd_be32(l4, 8);
      out.tcp_flags = core::rd_u8(l4, 13);
      out.ports_valid = true;
      return out;
    }
    case kIpProtoUdp: {
      // The length field covers the whole datagram, which a first fragment does not hold, so it
      // can only be checked against the minimum.
      if (l4.size() < kUdpHeader || core::rd_be16(l4, 4) < kUdpHeader) {
        return std::nullopt;
      }
      out.sport = core::rd_be16(l4, 0);
      out.dport = core::rd_be16(l4, 2);
      out.ports_valid = true;
      return out;
    }
    case kIpProtoIcmp: {
      if (l4.size() < IcmpView::kMinSize) {
        return std::nullopt;
      }
      out.icmp_type = core::rd_u8(l4, 0);
      out.icmp_code = core::rd_u8(l4, 1);
      return out;
    }
    default:
      return out;
  }
}

}  // namespace npf::proto
