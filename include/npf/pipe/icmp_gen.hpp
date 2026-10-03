#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <npf/core/byte_span.hpp>
#include <npf/core/packet.hpp>
#include <npf/proto/ipv4.hpp>
#include <npf/proto/l4.hpp>
#include <npf/proto/mac.hpp>
#include <vector>

namespace npf::pipe {

// ARCHITECTURE.md §8b: what the router says back -- ICMP errors for packets it cannot deliver,
// and echo replies to pings addressed to it. docs/rfc1812-conformance.md lists the RFC 1812
// requirements these meet, and the ones they do not.

enum class IcmpError : std::uint8_t {
  TimeExceeded,      // type 11 code 0 -- TTL expired in transit
  NetUnreachable,    // type  3 code 0 -- FIB miss
  HostUnreachable,   // type  3 code 1 -- ARP never resolved
  ProtoUnreachable,  // type  3 code 2
};

// The TTL of every ICMP message the router originates: set by it, never copied from the packet
// that provoked it (RFC 1812 §4.3.2.2).
inline constexpr std::uint8_t kIcmpTtl = 64;

// Builds a complete Ethernet + IPv4 + ICMP error frame into `out`.
// ICMP payload = the original IP header + the first 8 bytes of its payload (RFC 792).
// src_ip MUST be the router's address on the interface the ORIGINAL packet arrived on --
// that is what makes traceroute print the correct hop.
//
// The frame keeps the original's VLAN tag, if it had one. Its IPv4 header has precedence 6 with
// the original's TOS bits (RFC 1812 §4.3.2.5), TTL kIcmpTtl, and DF with identification 0: an
// atomic datagram, which needs no unique ID (RFC 6864). False, leaving `out` untouched, if `out`
// is too small.
[[nodiscard]] bool build_icmp_error(core::Packet& out, const proto::Ipv4View& orig,
                                    core::CBytes orig_frame, IcmpError err, std::uint32_t src_ip,
                                    proto::MacAddr src_mac, proto::MacAddr dst_mac) noexcept;

// Builds an Echo Reply for a ping addressed to one of this router's own interface IPs: every byte
// of the request's ICMP message but the type and checksum, sent from the address the request was
// sent to (RFC 1812 §4.3.3.6), with the request's TOS. False, leaving `out` untouched, unless
// `req` is a whole echo request -- not a fragment -- with a valid checksum, and `out` has room.
[[nodiscard]] bool build_echo_reply(core::Packet& out, const proto::Ipv4View& req,
                                    core::CBytes req_frame, proto::MacAddr src_mac,
                                    proto::MacAddr dst_mac) noexcept;

// RFC 1812 §4.3.2.7. False means an ICMP error must NOT be generated for this packet: it is an
// ICMP error itself, a fragment other than the first, addressed to a broadcast or multicast IP
// address, or from a source that is not a single host. `l4` is what parse_l4 returned for `orig`.
//
// The rule's link-layer half -- no error for a packet that arrived as a link-layer broadcast or
// multicast -- needs the Ethernet header, which this does not see. The pipeline keeps it: it
// routes such a frame only when it is addressed to the router itself, which never earns an error.
[[nodiscard]] bool may_send_icmp_error(const proto::Ipv4View& orig,
                                       const proto::L4Info& l4) noexcept;

// RFC 1812 §4.3.2.8. Token bucket, default 100 errors/second.
//
// A bucket of `per_second` tokens, each one returned exactly a second after it is spent. That
// allows a burst of up to `per_second` at once -- traceroute sends its probes together -- and never
// more than `per_second` in any one-second window. A bucket refilled at a steady rate would let a
// full bucket and a second's refill through within the same second: twice the limit.
class IcmpRateLimiter {
 public:
  explicit IcmpRateLimiter(std::uint32_t per_second = 100);

  [[nodiscard]] bool allow(std::chrono::steady_clock::time_point now) noexcept;

 private:
  std::vector<std::chrono::steady_clock::time_point> spent_;  // when each token was last spent
  std::size_t used_{0};    // tokens spent at least once; they are spent in index order
  std::size_t oldest_{0};  // once all have been, the one spent longest ago
};

}  // namespace npf::pipe
