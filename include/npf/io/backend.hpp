#pragma once

#include <cstddef>
#include <cstdint>
#include <npf/core/config.hpp>
#include <npf/core/packet.hpp>
#include <npf/proto/mac.hpp>
#include <span>
#include <string>

namespace npf::io {

// ARCHITECTURE.md §9.

struct PortInfo {
  std::uint16_t id{0};
  std::string name;  // "veth-cr"
  proto::MacAddr mac;
  std::uint32_t ip{0};  // the router's address on this port, host order; 0 if bridged-only
  std::uint8_t prefix_len{0};
  PortMode mode{PortMode::Routed};
  std::uint16_t bridge_domain{0};
  bool up{false};
};

// ONE virtual call per burst. Never per packet.
class IoBackend {
 public:
  virtual ~IoBackend() = default;
  // A backend owns sockets or files, and copying one through an IoBackend& would slice besides.
  IoBackend(const IoBackend&) = delete;
  IoBackend(IoBackend&&) = delete;
  IoBackend& operator=(const IoBackend&) = delete;
  IoBackend& operator=(IoBackend&&) = delete;

  // Fills 'out' with up to 'max' received packets, taken from the pool the backend was
  // constructed with. Returns the count. Non-blocking; returns 0 when nothing is ready.
  [[nodiscard]] virtual std::size_t rx_burst(core::Packet** out, std::size_t max) = 0;

  // Queues packets for transmission on 'port'. Takes ownership: transmitted packets are
  // released back to the pool by the backend. Returns how many were accepted; the caller
  // releases the remainder and counts DropReason::TxFull.
  [[nodiscard]] virtual std::size_t tx_burst(core::Packet* const* in, std::size_t n,
                                             std::uint16_t port) = 0;

  virtual void tx_flush() = 0;
  [[nodiscard]] virtual std::span<const PortInfo> ports() const noexcept = 0;
  [[nodiscard]] virtual const char* name() const noexcept = 0;

 protected:
  IoBackend() = default;
};

// Implementations, in build order:
//   AfPacketBackend    [phase 6]  -- recvfrom/sendto, one socket per port
//   PcapFileBackend    [phase 9]  -- reads one pcap, writes another; deterministic
//   PacketMmapBackend  [phase 16] -- TPACKET_V3 RX ring + TX ring, PACKET_QDISC_BYPASS
//   AfXdpBackend       [phase 17] -- UMEM + XSK rings

}  // namespace npf::io
