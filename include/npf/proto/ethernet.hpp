#pragma once

#include <cstddef>
#include <cstdint>
#include <npf/core/byte_span.hpp>
#include <npf/proto/mac.hpp>
#include <optional>

namespace npf::proto {

inline constexpr std::uint16_t kEtherTypeIpv4 = 0x0800;
inline constexpr std::uint16_t kEtherTypeArp = 0x0806;
inline constexpr std::uint16_t kEtherTypeVlan = 0x8100;  // IEEE 802.1Q customer tag
inline constexpr std::uint16_t kEtherTypeQinQ = 0x88A8;  // IEEE 802.1ad service (outer) tag

// An Ethernet II header, with at most one VLAN tag unwrapped.
//
// Exactly one tag is skipped, either 802.1Q (0x8100) or 802.1ad (0x88A8). If a second tag
// follows, it is not unwrapped: ethertype() reports that second tag's 0x8100 and the pipeline
// drops the frame as an unsupported EtherType. One level of tagging is all this project supports.
class EthView {
 public:
  static constexpr std::size_t kMinSize = 14;
  static constexpr std::size_t kTaggedSize = 18;

  // nullopt if the span is shorter than the header it announces: 14 bytes, or 18 with a tag.
  // Values below 0x0600 are 802.3 lengths, not EtherTypes; they are reported as-is and are
  // rejected by the pipeline's EtherType dispatch like any other unsupported value.
  [[nodiscard]] static constexpr std::optional<EthView> parse(core::CBytes buf) noexcept {
    if (buf.size() < kMinSize) {
      return std::nullopt;
    }
    const std::uint16_t outer = core::rd_be16(buf, 12);
    if (outer != kEtherTypeVlan && outer != kEtherTypeQinQ) {
      return EthView{buf, kMinSize};
    }
    if (buf.size() < kTaggedSize) {
      return std::nullopt;
    }
    return EthView{buf, kTaggedSize};
  }

  [[nodiscard]] constexpr MacAddr dst() const noexcept { return rd_mac(buf_, 0); }
  [[nodiscard]] constexpr MacAddr src() const noexcept { return rd_mac(buf_, 6); }
  // The EtherType after any tag: what the payload is.
  [[nodiscard]] constexpr std::uint16_t ethertype() const noexcept {
    return core::rd_be16(buf_, hdr_len_ - 2);
  }
  [[nodiscard]] constexpr bool has_vlan() const noexcept { return hdr_len_ == kTaggedSize; }
  // The 12-bit VLAN identifier, without the priority and drop-eligible bits; 0 if untagged.
  [[nodiscard]] constexpr std::uint16_t vlan_id() const noexcept {
    if (!has_vlan()) {
      return 0;
    }
    return static_cast<std::uint16_t>(core::rd_be16(buf_, 14) & 0x0FFFU);
  }
  [[nodiscard]] constexpr std::size_t header_len() const noexcept { return hdr_len_; }
  // Everything after the header, Ethernet padding included: an upper-layer view sizes itself by
  // its own length field, never by this span.
  [[nodiscard]] constexpr core::CBytes payload() const noexcept { return buf_.subspan(hdr_len_); }

 private:
  constexpr EthView(core::CBytes buf, std::size_t hdr_len) noexcept
      : buf_{buf}, hdr_len_{hdr_len} {}

  core::CBytes buf_;
  std::size_t hdr_len_;
};

}  // namespace npf::proto
