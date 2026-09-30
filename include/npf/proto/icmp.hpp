#pragma once

#include <cstddef>
#include <cstdint>
#include <npf/core/byte_span.hpp>
#include <npf/proto/checksum.hpp>
#include <optional>

namespace npf::proto {

inline constexpr std::uint8_t kIcmpEchoReply = 0;
inline constexpr std::uint8_t kIcmpDestUnreachable = 3;
inline constexpr std::uint8_t kIcmpSourceQuench = 4;
inline constexpr std::uint8_t kIcmpRedirect = 5;
inline constexpr std::uint8_t kIcmpEchoRequest = 8;
inline constexpr std::uint8_t kIcmpTimeExceeded = 11;
inline constexpr std::uint8_t kIcmpParameterProblem = 12;

// An ICMP message: the IPv4 payload, sized by total_length. It gets a view of its own because it
// carries more than L4Info can hold -- an echo's identifier and sequence number, and an error's
// copy of the datagram that caused it.
class IcmpView {
 public:
  static constexpr std::size_t kMinSize = 8;

  // Validates the length and the checksum, which covers the whole message, header and data.
  [[nodiscard]] static constexpr std::optional<IcmpView> parse(core::CBytes buf) noexcept {
    if (buf.size() < kMinSize || ones_complement_sum(buf) != 0xFFFF) {
      return std::nullopt;
    }
    return IcmpView{buf};
  }

  [[nodiscard]] constexpr std::uint8_t type() const noexcept { return core::rd_u8(buf_, 0); }
  [[nodiscard]] constexpr std::uint8_t code() const noexcept { return core::rd_u8(buf_, 1); }
  [[nodiscard]] constexpr std::uint16_t checksum() const noexcept { return core::rd_be16(buf_, 2); }
  // Meaningful for echo request and reply (types 8 and 0) only; for any other type these are
  // whatever bytes 4 to 7 hold.
  [[nodiscard]] constexpr std::uint16_t echo_id() const noexcept { return core::rd_be16(buf_, 4); }
  [[nodiscard]] constexpr std::uint16_t echo_seq() const noexcept { return core::rd_be16(buf_, 6); }
  // The types that report a problem with some other datagram, and so must never trigger an ICMP
  // error of their own (RFC 1812 §4.3.2.7).
  [[nodiscard]] constexpr bool is_error() const noexcept {
    const std::uint8_t t = type();
    return t == kIcmpDestUnreachable || t == kIcmpSourceQuench || t == kIcmpRedirect ||
           t == kIcmpTimeExceeded || t == kIcmpParameterProblem;
  }
  // Everything after the 8-byte header. For an error, the start of the datagram that caused it:
  // its IP header and at least the first 8 bytes of its payload.
  [[nodiscard]] constexpr core::CBytes payload() const noexcept { return buf_.subspan(kMinSize); }

 private:
  constexpr explicit IcmpView(core::CBytes buf) noexcept : buf_{buf} {}

  core::CBytes buf_;
};

}  // namespace npf::proto
