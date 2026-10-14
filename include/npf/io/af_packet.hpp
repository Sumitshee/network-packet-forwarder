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

// [phase 13] How one backend's sockets share the ports with other backends' (ARCHITECTURE.md §12).
// The default is phase 6's: one backend, receiving on every port.
struct AfPacketOptions {
  // Run-to-completion: every worker has a backend, and each joins its socket on a port to that
  // port's PACKET_FANOUT_HASH group, so the kernel hands each flow to one of them. The first
  // backend creates the groups, with fanout_groups empty, and the others join by passing the ids
  // that its fanout_groups() reports.
  bool fanout{false};
  std::vector<std::uint16_t> fanout_groups;  // by port id
  // Pipeline: which ports this backend receives on, by port id; the sockets of the others are
  // never bound, receive nothing, and only transmit. Empty: every port.
  std::vector<bool> receive;
  // No log line per port: another backend on the same ports has already said it all.
  bool quiet{false};
};

// The simplest backend that works: one AF_PACKET socket per port, one system call per frame --
// recvfrom() to receive, sendto() to transmit. The faster backends are measured against it.
class AfPacketBackend final : public IoBackend {
 public:
  // Opens, binds and sizes one socket per interface, and reads each one's ifindex, MAC and link
  // state. Port ids must run from 0 to N-1, each used once. Start-up code: throws
  // std::system_error when the kernel refuses -- most often for want of CAP_NET_RAW, or an
  // interface that does not exist -- and std::invalid_argument for an unusable configuration.
  AfPacketBackend(std::span<const core::InterfaceConfig> interfaces, core::PacketPool& pool,
                  const AfPacketOptions& options = {});

  [[nodiscard]] std::size_t rx_burst(core::Packet** out, std::size_t max) noexcept override;
  [[nodiscard]] std::size_t tx_burst(core::Packet* const* in, std::size_t n,
                                     std::uint16_t port) noexcept override;
  void tx_flush() noexcept override {}  // sendto() has already handed every frame to the kernel
  [[nodiscard]] std::span<const PortInfo> ports() const noexcept override { return ports_; }
  [[nodiscard]] const char* name() const noexcept override { return "af_packet"; }

  // [phase 13] Not part of IoBackend: transmits as tx_burst() does, but leaves every packet the
  // caller's, sent or not -- for a pipeline worker, whose packets belong to other threads' pools.
  // Returns how many were sent, the first ones.
  [[nodiscard]] std::size_t send(const core::Packet* const* in, std::size_t n,
                                 std::uint16_t port) noexcept;

  // Not part of IoBackend: the sockets that receive, in port order, for the caller's poll() set.
  [[nodiscard]] std::vector<int> fds() const;

  // [phase 13] The PACKET_FANOUT group of each port's socket, by port id, for the other workers'
  // backends to join. Empty unless this backend was opened with fanout.
  [[nodiscard]] const std::vector<std::uint16_t>& fanout_groups() const noexcept {
    return fanout_groups_;
  }

  // Frames thrown away before the pipeline saw them, because they did not fit in a buffer.
  [[nodiscard]] std::uint64_t rx_oversized() const noexcept { return rx_oversized_; }

  // [phase 16] Frames the kernel dropped before this backend could read them -- its receive
  // buffers full -- since the sockets were opened: PACKET_STATISTICS, summed over the receiving
  // sockets. Not on the datapath: a system call per socket. Not const: the kernel resets its count
  // on every read, so the backend keeps the running total.
  [[nodiscard]] std::uint64_t kernel_rx_drops() noexcept;

 private:
  struct Socket {
    core::UniqueFd fd;
    int ifindex{0};
  };

  // Binds a socket to its port so that it receives, and joins it to the port's fanout group.
  void receive_on(int fd, unsigned ifindex, const core::InterfaceConfig& iface,
                  const AfPacketOptions& options);
  // Receives from one port until it is drained, the budget is spent or the pool is empty.
  std::size_t drain(std::uint16_t port, core::Packet** out, std::size_t budget) noexcept;

  core::PacketPool* pool_;       // borrowed: owned by the caller, which outlives this backend
  std::vector<PortInfo> ports_;  // indexed by port id
  std::vector<Socket> sockets_;  // indexed by port id
  std::vector<std::uint16_t> rx_ports_;       // the ports that receive, in order
  std::vector<std::uint16_t> fanout_groups_;  // by port id; empty without fanout
  std::size_t next_port_{0};  // the index in rx_ports_ the next rx_burst starts at, so none is
                              // always last
  std::uint64_t rx_oversized_{0};
  std::uint64_t kernel_rx_drops_{0};
};

}  // namespace npf::io
