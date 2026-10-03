#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <npf/core/byte_span.hpp>
#include <npf/core/packet.hpp>
#include <npf/pipe/icmp_gen.hpp>
#include <npf/proto/checksum.hpp>
#include <npf/proto/ethernet.hpp>
#include <npf/proto/icmp.hpp>
#include <npf/proto/ipv4.hpp>
#include <npf/proto/l4.hpp>
#include <npf/proto/mac.hpp>
#include <optional>

namespace npf::pipe {
namespace {

constexpr std::size_t kIpv4HeaderSize = 20;  // what the router writes: no options
constexpr std::size_t kQuotedData = 8;       // RFC 792: the first 64 bits of the original's data
constexpr std::uint8_t kPrecedenceInternetControl = 0xC0;  // precedence 6, in the top 3 bits
constexpr std::uint8_t kTosBits = 0x1E;                    // the 4 TOS bits of RFC 1349
constexpr std::uint16_t kDontFragment = 0x4000;

struct TypeCode {
  std::uint8_t type;
  std::uint8_t code;
};

constexpr TypeCode type_code(IcmpError err) noexcept {
  switch (err) {
    case IcmpError::TimeExceeded:
      return {proto::kIcmpTimeExceeded, 0};
    case IcmpError::NetUnreachable:
      return {proto::kIcmpDestUnreachable, 0};
    case IcmpError::HostUnreachable:
      return {proto::kIcmpDestUnreachable, 1};
    case IcmpError::ProtoUnreachable:
      return {proto::kIcmpDestUnreachable, 2};
  }
  return {proto::kIcmpDestUnreachable, 0};  // not reached for any value of the enumeration
}

// 18 bytes with a VLAN tag, 14 without: the answer to a frame keeps the frame's tag.
std::size_t ethernet_header_len(core::CBytes received) noexcept {
  const std::optional<proto::EthView> eth = proto::EthView::parse(received);
  return eth ? eth->header_len() : proto::EthView::kMinSize;
}

struct MacPair {
  proto::MacAddr src;
  proto::MacAddr dst;
};

// The Ethernet header of the answer to `received`: the given addresses, and `received`'s VLAN
// tag if it had one.
void write_ethernet(core::Bytes frame, core::CBytes received, const MacPair& macs) noexcept {
  proto::wr_mac(frame, 0, macs.dst);
  proto::wr_mac(frame, 6, macs.src);
  const std::optional<proto::EthView> eth = proto::EthView::parse(received);
  if (eth && eth->has_vlan()) {
    std::ranges::copy(received.subspan(12, 4), frame.subspan(12).begin());  // TPID and tag
  }
  core::wr_be16(frame, ethernet_header_len(received) - 2, proto::kEtherTypeIpv4);
}

struct Ipv4Fields {
  std::uint8_t tos;
  std::size_t total_length;
  std::uint32_t src;
  std::uint32_t dst;
};

void write_ipv4(core::Bytes hdr, const Ipv4Fields& f) noexcept {
  core::wr_u8(hdr, 0, 0x45);
  core::wr_u8(hdr, 1, f.tos);
  core::wr_be16(hdr, 2, static_cast<std::uint16_t>(f.total_length));
  core::wr_be16(hdr, 4, 0);  // identification
  core::wr_be16(hdr, 6, kDontFragment);
  core::wr_u8(hdr, 8, kIcmpTtl);
  core::wr_u8(hdr, 9, proto::kIpProtoIcmp);
  core::wr_be16(hdr, 10, 0);
  core::wr_be32(hdr, 12, f.src);
  core::wr_be32(hdr, 16, f.dst);
  core::wr_be16(hdr, 10, proto::ipv4_header_checksum(hdr));
}

void write_icmp_checksum(core::Bytes message) noexcept {
  core::wr_be16(message, 2, 0);
  core::wr_be16(message, 2, static_cast<std::uint16_t>(~proto::ones_complement_sum(message)));
}

}  // namespace

// The parameters are ARCHITECTURE.md §8b's, so their order is not this file's to change.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
bool build_icmp_error(core::Packet& out, const proto::Ipv4View& orig, core::CBytes orig_frame,
                      IcmpError err, std::uint32_t src_ip, proto::MacAddr src_mac,
                      proto::MacAddr dst_mac) noexcept {
  const core::CBytes quoted_header = orig.header();
  const core::CBytes data = orig.payload();
  const core::CBytes quoted_data = data.first(std::min(data.size(), kQuotedData));
  const std::size_t l2 = ethernet_header_len(orig_frame);
  const std::size_t icmp_len =
      proto::IcmpView::kMinSize + quoted_header.size() + quoted_data.size();
  const std::size_t ip_len = kIpv4HeaderSize + icmp_len;
  if (out.capacity() < l2 + ip_len) {
    return false;
  }
  out.resize(l2 + ip_len);
  const core::Bytes frame = out.data();
  write_ethernet(frame, orig_frame, {.src = src_mac, .dst = dst_mac});
  write_ipv4(
      frame.subspan(l2, kIpv4HeaderSize),
      {.tos = static_cast<std::uint8_t>(kPrecedenceInternetControl | (orig.tos() & kTosBits)),
       .total_length = ip_len,
       .src = src_ip,
       .dst = orig.src()});
  const core::Bytes icmp = frame.subspan(l2 + kIpv4HeaderSize);
  const TypeCode tc = type_code(err);
  core::wr_u8(icmp, 0, tc.type);
  core::wr_u8(icmp, 1, tc.code);
  core::wr_be32(icmp, 4, 0);  // unused by these types
  const core::Bytes quote = icmp.subspan(proto::IcmpView::kMinSize);
  std::ranges::copy(quoted_header, quote.begin());
  std::ranges::copy(quoted_data, quote.subspan(quoted_header.size()).begin());
  write_icmp_checksum(icmp);
  return true;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters): ARCHITECTURE.md §8b's signature
bool build_echo_reply(core::Packet& out, const proto::Ipv4View& req, core::CBytes req_frame,
                      proto::MacAddr src_mac, proto::MacAddr dst_mac) noexcept {
  // A fragment holds only part of the data, and a reply must hold all of it (RFC 1812 §4.3.3.6).
  // Without reassembly, a fragmented request goes unanswered.
  if (req.is_fragment()) {
    return false;
  }
  const core::CBytes message = req.payload();
  const std::optional<proto::IcmpView> icmp = proto::IcmpView::parse(message);
  if (!icmp || icmp->type() != proto::kIcmpEchoRequest) {
    return false;
  }
  const std::size_t l2 = ethernet_header_len(req_frame);
  const std::size_t ip_len = kIpv4HeaderSize + message.size();
  if (out.capacity() < l2 + ip_len) {
    return false;
  }
  out.resize(l2 + ip_len);
  const core::Bytes frame = out.data();
  write_ethernet(frame, req_frame, {.src = src_mac, .dst = dst_mac});
  write_ipv4(frame.subspan(l2, kIpv4HeaderSize),
             {.tos = req.tos(), .total_length = ip_len, .src = req.dst(), .dst = req.src()});
  const core::Bytes reply = frame.subspan(l2 + kIpv4HeaderSize);
  std::ranges::copy(message, reply.begin());
  core::wr_u8(reply, 0, proto::kIcmpEchoReply);
  core::wr_u8(reply, 1, 0);
  write_icmp_checksum(reply);
  return true;
}

bool may_send_icmp_error(const proto::Ipv4View& orig, const proto::L4Info& l4) noexcept {
  if (orig.frag_offset() != 0) {
    return false;  // only a first (or only) fragment may earn an error
  }
  if (l4.protocol == proto::kIpProtoIcmp && proto::is_icmp_error_type(l4.icmp_type)) {
    return false;
  }
  const std::uint32_t dst = orig.dst();
  if (dst == 0xFFFFFFFFU || (dst >> 28U) == 0xEU) {
    return false;  // the limited broadcast, or a multicast group
  }
  // 0/8, 127/8, multicast and class E sources, 255.255.255.255 among them: not one host.
  return !proto::is_martian_source(orig.src());
}

IcmpRateLimiter::IcmpRateLimiter(std::uint32_t per_second) : spent_(per_second) {}

bool IcmpRateLimiter::allow(std::chrono::steady_clock::time_point now) noexcept {
  if (used_ < spent_.size()) {
    spent_[used_++] = now;
    return true;
  }
  if (spent_.empty() || now - spent_[oldest_] < std::chrono::seconds{1}) {
    return false;
  }
  spent_[oldest_] = now;
  oldest_ = (oldest_ + 1) % spent_.size();
  return true;
}

}  // namespace npf::pipe
