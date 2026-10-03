#pragma once

#include <cstddef>
#include <cstdint>
#include <npf/core/byte_span.hpp>
#include <optional>

namespace npf::proto {

// An IPv4 header and the datagram it describes. Read-only: rewriting the TTL and checksum is the
// forwarder's business, not the view's.
class Ipv4View {
 public:
  static constexpr std::size_t kMinSize = 20;

  // Validates: size >= 20, version == 4, ihl >= 5, ihl*4 <= size, total_length >= ihl*4,
  // total_length <= size.
  //
  // Does NOT validate the checksum -- call ipv4_checksum_valid() on header() -- so the pipeline can
  // count BadChecksum separately from BadIpv4Header. Options are skipped via ihl, never
  // interpreted.
  [[nodiscard]] static constexpr std::optional<Ipv4View> parse(core::CBytes buf) noexcept {
    if (buf.size() < kMinSize) {
      return std::nullopt;
    }
    const std::uint8_t version_ihl = core::rd_u8(buf, 0);
    const std::size_t hdr_len = std::size_t{version_ihl & 0x0FU} * 4;
    const std::size_t total_len = core::rd_be16(buf, 2);
    if ((version_ihl >> 4U) != 4 || hdr_len < kMinSize || hdr_len > buf.size() ||
        total_len < hdr_len || total_len > buf.size()) {
      return std::nullopt;
    }
    // Anything past total_length is link-layer padding; cutting it off here means nothing
    // downstream can mistake it for payload.
    return Ipv4View{buf.first(total_len), hdr_len};
  }

  [[nodiscard]] constexpr std::uint8_t ihl() const noexcept {
    return static_cast<std::uint8_t>(hdr_len_ / 4);
  }
  [[nodiscard]] constexpr std::size_t header_len() const noexcept {  // ihl * 4, never assumed 20
    return hdr_len_;
  }
  // The whole second byte: precedence and TOS bits in RFC 1812's terms, DSCP and ECN in today's.
  [[nodiscard]] constexpr std::uint8_t tos() const noexcept { return core::rd_u8(buf_, 1); }
  [[nodiscard]] constexpr std::uint16_t total_length() const noexcept {
    return core::rd_be16(buf_, 2);
  }
  [[nodiscard]] constexpr std::uint16_t identification() const noexcept {
    return core::rd_be16(buf_, 4);
  }
  [[nodiscard]] constexpr bool df() const noexcept { return (flags_frag() & 0x4000U) != 0; }
  [[nodiscard]] constexpr bool mf() const noexcept { return (flags_frag() & 0x2000U) != 0; }
  // In units of 8 bytes, as on the wire.
  [[nodiscard]] constexpr std::uint16_t frag_offset() const noexcept {
    return static_cast<std::uint16_t>(flags_frag() & 0x1FFFU);
  }
  [[nodiscard]] constexpr std::uint8_t ttl() const noexcept { return core::rd_u8(buf_, 8); }
  [[nodiscard]] constexpr std::uint8_t protocol() const noexcept { return core::rd_u8(buf_, 9); }
  [[nodiscard]] constexpr std::uint16_t checksum() const noexcept {
    return core::rd_be16(buf_, 10);
  }
  [[nodiscard]] constexpr std::uint32_t src() const noexcept {  // host order
    return core::rd_be32(buf_, 12);
  }
  [[nodiscard]] constexpr std::uint32_t dst() const noexcept { return core::rd_be32(buf_, 16); }

  [[nodiscard]] constexpr bool is_fragment() const noexcept { return mf() || frag_offset() != 0; }
  // True for an unfragmented datagram too: only a first (or only) fragment carries the L4 header.
  [[nodiscard]] constexpr bool is_first_fragment() const noexcept { return frag_offset() == 0; }

  // Sized by total_length, not by the input span, so a padded Ethernet frame's padding never
  // reaches the payload.
  [[nodiscard]] constexpr core::CBytes payload() const noexcept { return buf_.subspan(hdr_len_); }
  [[nodiscard]] constexpr core::CBytes header() const noexcept { return buf_.first(hdr_len_); }

 private:
  constexpr Ipv4View(core::CBytes buf, std::size_t hdr_len) noexcept
      : buf_{buf}, hdr_len_{hdr_len} {}

  [[nodiscard]] constexpr std::uint16_t flags_frag() const noexcept {
    return core::rd_be16(buf_, 6);
  }

  core::CBytes buf_;  // exactly total_length bytes
  std::size_t hdr_len_;
};

// RFC 1812 §5.3.7: source addresses that must never be forwarded. Each range is a whole /8 or /4,
// so comparing the leading bits is the entire test.
[[nodiscard]] constexpr bool is_martian_source(std::uint32_t ip) noexcept {
  return (ip >> 24U) == 0       // 0.0.0.0/8
         || (ip >> 24U) == 127  // 127.0.0.0/8
         || (ip >> 28U) == 0xE  // 224.0.0.0/4
         || (ip >> 28U) == 0xF  // 240.0.0.0/4
         || ip == 0xFFFFFFFFU;  // 255.255.255.255, already inside 240/4; listed as the RFC lists it
}

// RFC 1812 §5.3.7: destination addresses that must never be forwarded.
[[nodiscard]] constexpr bool is_martian_dest(std::uint32_t ip) noexcept {
  return (ip >> 24U) == 0        // 0.0.0.0/8
         || (ip >> 24U) == 127;  // 127.0.0.0/8
}

}  // namespace npf::proto
