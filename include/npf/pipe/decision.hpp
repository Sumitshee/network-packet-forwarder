#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace npf {

// ARCHITECTURE.md §1. The whole engine exists to produce one of these per packet.

enum class Verdict : std::uint8_t {
  Forward,  // out_port is set; transmit it
  Flood,    // L2: transmit on every port in the bridge domain except in_port
  ToHost,   // addressed to this router itself (ICMP echo, ARP request for us)
  Drop,     // drop_reason is set
  Queued,   // held by the ARP cache until the next hop resolves; out_port is set. The cache owns
            // the packet now: the caller must neither transmit nor release it.
};

enum class DropReason : std::uint8_t {
  None = 0,
  ShortFrame,       // frame shorter than a minimal Ethernet header
  BadEtherType,     // not IPv4, not ARP, not a VLAN tag we handle
  BadIpv4Header,    // version != 4, ihl < 5, total_length inconsistent, truncated
  BadChecksum,      // IPv4 header checksum mismatch
  MartianSource,    // RFC 1812 §5.3.7 source address that must never be forwarded
  TtlExpired,       // TTL <= 1 on receipt; an ICMP Time Exceeded may have been generated
  NoRoute,          // FIB miss; an ICMP Net Unreachable may have been generated
  ArpUnresolved,    // next hop never resolved, or the pending queue was full
  FilterDeny,       // packet filter said no
  NoOutPort,        // route named a port that does not exist or is down
  UnknownDestPort,  // L2 lookup miss on a port with no bridge domain
  TxFull,           // transmit ring or socket buffer full
  PoolExhausted,    // no free packet buffer
  // ARCHITECTURE.md §1 fixes this name. An underscore and a capital reserve an identifier for the
  // implementation; no header this project includes defines it (checked for GCC 13, Clang 18).
  _Count  // NOLINT(bugprone-reserved-identifier)
};

inline constexpr std::size_t kDropReasons = static_cast<std::size_t>(DropReason::_Count);

// Result of processing one packet. Fits in 4 bytes; returned by value.
//
// Invariant: every packet leaving the pipeline produces exactly one Decision, and a Drop always
// carries a reason other than None. Forwarder::process() asserts it in debug builds. A Queued
// packet has not left yet: it is counted when the ARP cache lets go of it, sent or dropped.
struct Decision {
  Verdict verdict{Verdict::Drop};
  DropReason reason{DropReason::None};
  std::uint16_t out_port{0};
};

static_assert(sizeof(Decision) == 4);

// The reason's name, as the counter tables print it.
[[nodiscard]] constexpr std::string_view to_string(DropReason r) noexcept {
  switch (r) {
    case DropReason::None:
      return "None";
    case DropReason::ShortFrame:
      return "ShortFrame";
    case DropReason::BadEtherType:
      return "BadEtherType";
    case DropReason::BadIpv4Header:
      return "BadIpv4Header";
    case DropReason::BadChecksum:
      return "BadChecksum";
    case DropReason::MartianSource:
      return "MartianSource";
    case DropReason::TtlExpired:
      return "TtlExpired";
    case DropReason::NoRoute:
      return "NoRoute";
    case DropReason::ArpUnresolved:
      return "ArpUnresolved";
    case DropReason::FilterDeny:
      return "FilterDeny";
    case DropReason::NoOutPort:
      return "NoOutPort";
    case DropReason::UnknownDestPort:
      return "UnknownDestPort";
    case DropReason::TxFull:
      return "TxFull";
    case DropReason::PoolExhausted:
      return "PoolExhausted";
    case DropReason::_Count:
      break;
  }
  return "?";
}

}  // namespace npf
