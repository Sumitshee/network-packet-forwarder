#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <npf/core/config.hpp>
#include <npf/core/packet.hpp>
#include <npf/core/pool.hpp>
#include <npf/io/af_packet.hpp>
#include <npf/io/backend.hpp>
#include <span>
#include <vector>

namespace npf::io {

// [phase 17] Where the XDP program runs: in the kernel's generic receive path, on any interface
// (skb), or in the driver (native), on one that supports it -- veth does.
enum class XdpMode : std::uint8_t { Skb, Native };

// AF_XDP (ARCHITECTURE.md §9): on each port an XDP program redirects every frame into an AF_XDP
// socket bound to queue 0, whose rings point into a UMEM -- memory this process registered with
// the kernel. With XDP_COPY, the only mode veth has, the kernel copies a frame into the UMEM on
// the way in and out of it on the way out; what AF_XDP saves over the socket backends is the
// kernel's network stack, skb and all, on receive.
//
// One socket per port, so one queue and no fanout: the engine runs it with one worker, run to
// completion. Built only when libbpf and libxdp are (NPF_HAVE_XDP).
class AfXdpBackend final : public IoBackend {
 public:
  // Start-up code: throws std::system_error when the kernel refuses -- no CAP_NET_ADMIN and
  // CAP_BPF, or a program already attached to an interface -- and std::invalid_argument for an
  // unusable configuration, which includes options.fanout and receive-only ports.
  AfXdpBackend(std::span<const core::InterfaceConfig> interfaces, core::PacketPool& pool,
               const AfPacketOptions& options = {}, XdpMode mode = XdpMode::Skb);
  AfXdpBackend(const AfXdpBackend&) = delete;
  AfXdpBackend& operator=(const AfXdpBackend&) = delete;
  AfXdpBackend(AfXdpBackend&&) = delete;
  AfXdpBackend& operator=(AfXdpBackend&&) = delete;
  ~AfXdpBackend() override;  // detaches the program from every port

  [[nodiscard]] std::size_t rx_burst(core::Packet** out, std::size_t max) noexcept override;
  [[nodiscard]] std::size_t tx_burst(core::Packet* const* in, std::size_t n,
                                     std::uint16_t port) noexcept override;
  void tx_flush() noexcept override;
  [[nodiscard]] std::span<const PortInfo> ports() const noexcept override { return ports_; }
  [[nodiscard]] const char* name() const noexcept override { return "xdp"; }

  // As AfPacketBackend's: queue frames without giving up their buffers.
  [[nodiscard]] std::size_t send(const core::Packet* const* in, std::size_t n,
                                 std::uint16_t port) noexcept;
  [[nodiscard]] std::vector<int> fds() const;
  [[nodiscard]] const std::vector<std::uint16_t>& fanout_groups() const noexcept {
    return fanout_groups_;  // always empty: AF_XDP has no fanout
  }
  [[nodiscard]] std::uint64_t rx_oversized() const noexcept { return rx_oversized_; }
  // XDP_STATISTICS' rx_dropped + rx_ring_full, summed over the ports: frames the kernel had for a
  // socket and could not give it. The kernel keeps these cumulative.
  [[nodiscard]] std::uint64_t kernel_rx_drops() noexcept;

 private:
  struct Port;  // a socket, its UMEM and rings: libxdp's types, kept out of this header

  std::size_t drain(Port& s, std::uint16_t id, core::Packet** out, std::size_t budget) noexcept;
  static void reap(Port& s) noexcept;

  core::PacketPool* pool_;  // borrowed: owned by the caller, which outlives this backend
  std::vector<PortInfo> ports_;
  std::vector<std::unique_ptr<Port>> sockets_;  // by port id
  std::vector<std::uint16_t> fanout_groups_;
  std::size_t next_port_{0};
  std::uint64_t rx_oversized_{0};
};

}  // namespace npf::io
