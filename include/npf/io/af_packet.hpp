#pragma once

#include <cstddef>
#include <cstdint>
#include <npf/core/config.hpp>
#include <npf/core/packet.hpp>
#include <npf/core/pool.hpp>
#include <npf/core/unique_fd.hpp>
#include <npf/io/backend.hpp>
#include <span>
#include <vector>

namespace npf::io {

// The simplest backend that works: one AF_PACKET socket per port, one system call per frame --
// recvfrom() to receive, sendto() to transmit. The faster backends are measured against it.
class AfPacketBackend final : public IoBackend {
 public:
  // Opens, binds and sizes one socket per interface, and reads each one's ifindex, MAC and link
  // state. Port ids must run from 0 to N-1, each used once. Start-up code: throws
  // std::system_error when the kernel refuses -- most often for want of CAP_NET_RAW, or an
  // interface that does not exist -- and std::invalid_argument for an unusable configuration.
  AfPacketBackend(std::span<const core::InterfaceConfig> interfaces, core::PacketPool& pool);

  [[nodiscard]] std::size_t rx_burst(core::Packet** out, std::size_t max) noexcept override;
  [[nodiscard]] std::size_t tx_burst(core::Packet* const* in, std::size_t n,
                                     std::uint16_t port) noexcept override;
  void tx_flush() noexcept override {}  // sendto() has already handed every frame to the kernel
  [[nodiscard]] std::span<const PortInfo> ports() const noexcept override { return ports_; }
  [[nodiscard]] const char* name() const noexcept override { return "af_packet"; }

  // Not part of IoBackend: the sockets, in port order, for the caller's poll() set.
  [[nodiscard]] std::vector<int> fds() const;

  // Frames thrown away before the pipeline saw them, because they did not fit in a buffer.
  [[nodiscard]] std::uint64_t rx_oversized() const noexcept { return rx_oversized_; }

 private:
  struct Socket {
    core::UniqueFd fd;
    int ifindex{0};
  };

  // Receives from one port until it is drained, the budget is spent or the pool is empty.
  std::size_t drain(std::uint16_t port, core::Packet** out, std::size_t budget) noexcept;

  core::PacketPool* pool_;       // borrowed: owned by the caller, which outlives this backend
  std::vector<PortInfo> ports_;  // indexed by port id
  std::vector<Socket> sockets_;  // indexed by port id
  std::size_t next_port_{0};     // the port the next rx_burst starts at, so none is always last
  std::uint64_t rx_oversized_{0};
};

}  // namespace npf::io
