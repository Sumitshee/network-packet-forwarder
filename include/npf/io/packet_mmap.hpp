#pragma once

#include <cstddef>
#include <cstdint>
#include <npf/core/config.hpp>
#include <npf/core/packet.hpp>
#include <npf/core/pool.hpp>
#include <npf/core/unique_fd.hpp>
#include <npf/io/af_packet.hpp>
#include <npf/io/backend.hpp>
#include <span>
#include <vector>

namespace npf::io {

// [phase 16] The rings' shapes. The defaults are docs/BUILD_PLAN.md's: a 32 MiB RX ring of 8 blocks
// of 4 MiB, and a TX ring of 512 slots of 2048 bytes.
struct MmapRingSizes {
  std::size_t rx_block_size{std::size_t{1} << 22U};  // a multiple of the page size
  std::size_t rx_block_nr{8};
  std::size_t rx_frame_size{2048};  // divides rx_block_size; V3 packs frames, this sizes the count
  unsigned rx_retire_ms{10};        // how long before the kernel hands back a partial block
  std::size_t tx_frame_size{2048};
  std::size_t tx_frame_nr{512};

  // The plan's RX ring, split between the sockets that share a port under fanout, so that the
  // memory per port stays the same: blocks = max(2, 8 / sockets).
  [[nodiscard]] static MmapRingSizes shared_by(std::size_t sockets_per_port);
};

// PACKET_MMAP (ARCHITECTURE.md §9): the kernel writes received frames straight into a ring this
// process has mapped, and sends what it writes into another. Per frame that saves the system call,
// with its two context switches, and one copy, on each side; it costs a look at a block's status
// instead, and a kick of the TX ring once per burst per port.
//
// Two sockets per port, since PACKET_VERSION belongs to a socket:
//  - RX: TPACKET_V3. The kernel fills a block with as many frames as fit, then hands the whole
//    block over (or after rx_retire_ms, partly full). rx_burst() copies frames out of the block
//    into pool buffers, and gives the block back -- block_status = TP_STATUS_KERNEL -- when it has
//    read the last of them. Forgetting that stalls the ring for good.
//  - TX: TPACKET_V2, fixed slots, PACKET_QDISC_BYPASS. send() copies frames into free slots and
//    marks them TP_STATUS_SEND_REQUEST; tx_flush() kicks each port that has some with one send().
//    V3's blocks buy nothing here: the sender fills every slot either way.
//
// The same options as AfPacketBackend: fanout groups, receive-only and transmit-only ports.
class PacketMmapBackend final : public IoBackend {
 public:
  // Start-up code: throws std::system_error when the kernel refuses a socket, a ring or a mapping,
  // and std::invalid_argument for an unusable configuration.
  PacketMmapBackend(std::span<const core::InterfaceConfig> interfaces, core::PacketPool& pool,
                    const AfPacketOptions& options = {}, const MmapRingSizes& sizes = {});

  [[nodiscard]] std::size_t rx_burst(core::Packet** out, std::size_t max) noexcept override;
  [[nodiscard]] std::size_t tx_burst(core::Packet* const* in, std::size_t n,
                                     std::uint16_t port) noexcept override;
  void tx_flush() noexcept override;
  [[nodiscard]] std::span<const PortInfo> ports() const noexcept override { return ports_; }
  [[nodiscard]] const char* name() const noexcept override { return "mmap"; }

  // As AfPacketBackend's: queue frames without giving up their buffers, for a pipeline worker.
  [[nodiscard]] std::size_t send(const core::Packet* const* in, std::size_t n,
                                 std::uint16_t port) noexcept;
  [[nodiscard]] std::vector<int> fds() const;
  [[nodiscard]] const std::vector<std::uint16_t>& fanout_groups() const noexcept {
    return fanout_groups_;
  }
  [[nodiscard]] std::uint64_t rx_oversized() const noexcept { return rx_oversized_; }
  [[nodiscard]] std::uint64_t kernel_rx_drops() noexcept;

 private:
  // A shared mapping of a ring, unmapped when it goes.
  class Mapping {
   public:
    Mapping() = default;
    Mapping(std::byte* base, std::size_t len) noexcept : base_{base}, len_{len} {}
    Mapping(const Mapping&) = delete;
    Mapping& operator=(const Mapping&) = delete;
    Mapping(Mapping&& other) noexcept;
    Mapping& operator=(Mapping&& other) noexcept;
    ~Mapping();
    [[nodiscard]] std::byte* base() const noexcept { return base_; }

   private:
    std::byte* base_{nullptr};
    std::size_t len_{0};
  };

  struct RxRing {
    core::UniqueFd fd;
    Mapping map;
    std::size_t block_size{0};
    std::size_t block_nr{0};
    std::size_t block{0};      // the block being read, or to be read next
    std::byte* next{nullptr};  // the next frame's header in it; nullptr: not yet opened
    std::uint32_t left{0};     // frames still to read in it
  };

  struct TxRing {
    core::UniqueFd fd;
    Mapping map;
    std::size_t frame_size{0};
    std::size_t frame_nr{0};
    std::size_t next{0};  // the next slot to fill
    bool pending{false};  // slots filled since the last kick
  };

  std::size_t drain(std::uint16_t port, core::Packet** out, std::size_t budget) noexcept;
  void open_rx(std::uint16_t port, unsigned ifindex, const core::InterfaceConfig& iface,
               const AfPacketOptions& options, const MmapRingSizes& sizes);
  void open_tx(std::uint16_t port, unsigned ifindex, const core::InterfaceConfig& iface,
               const MmapRingSizes& sizes);

  core::PacketPool* pool_;  // borrowed: owned by the caller, which outlives this backend
  std::vector<PortInfo> ports_;
  std::vector<RxRing> rx_;  // indexed by port id; a transmit-only port's is unopened
  std::vector<TxRing> tx_;  // indexed by port id
  std::vector<std::uint16_t> rx_ports_;
  std::vector<std::uint16_t> fanout_groups_;
  std::size_t next_port_{0};
  std::uint64_t rx_oversized_{0};
  std::uint64_t kernel_rx_drops_{0};
};

}  // namespace npf::io
