// The kernel's PACKET_MMAP ABI: <linux/if_packet.h> alone, which also defines sockaddr_ll, so not
// beside glibc's <netpacket/packet.h> (see link.cpp). The ring headers are the kernel's own
// structures, laid out and aligned by it in memory it maps for us: they are reached through casts
// of the mapping, as the ABI intends. The frames inside them are only ever copied, never parsed
// in place.

#include <linux/if_packet.h>
#include <sys/mman.h>
#include <sys/socket.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <format>
#include <iterator>
#include <npf/core/config.hpp>
#include <npf/core/log.hpp>
#include <npf/core/packet.hpp>
#include <npf/core/pool.hpp>
#include <npf/core/time.hpp>
#include <npf/core/unique_fd.hpp>
#include <npf/io/backend.hpp>
#include <npf/io/packet_mmap.hpp>
#include <npf/proto/format.hpp>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

#include "link.hpp"

// NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast,cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-pro-type-union-access)
namespace npf::io {
namespace {

constexpr std::size_t kPageSize = 4096;
constexpr std::size_t kTxBlockSize =
    std::size_t{64} * 1024;  // V2's TX ring is in blocks too; 32 slots each

// TPACKET_ALIGN, without the macro's signed mask.
constexpr std::size_t tpacket_align(std::size_t n) noexcept {
  constexpr std::size_t kAlign = TPACKET_ALIGNMENT;
  return (n + kAlign - 1) / kAlign * kAlign;
}

// Where a TX frame's data starts in its slot: the kernel reads it from tp_hdrlen minus the
// sockaddr_ll it reserves there, which is the aligned size of the V2 header.
constexpr std::size_t kTxDataOffset = tpacket_align(sizeof(tpacket2_hdr));

// The kernel writes a status word, then reads it again; both sides must see each other's writes
// in order. acquire on our reads, release on our writes, as with any shared ring.
std::uint32_t load_status(std::uint32_t& status) noexcept {
  return std::atomic_ref<std::uint32_t>(status).load(std::memory_order_acquire);
}
void store_status(std::uint32_t& status, std::uint32_t value) noexcept {
  std::atomic_ref<std::uint32_t>(status).store(value, std::memory_order_release);
}

void set_int(int fd, int option, int value, const std::string& what) {
  if (::setsockopt(fd, SOL_PACKET, option, &value, sizeof(value)) < 0) {
    link::throw_errno(what);
  }
}

// MAP_LOCKED keeps the ring from being paged out, but needs CAP_IPC_LOCK or a memlock limit as
// large as the ring. Without either, the ring works unlocked.
std::byte* map_ring(int fd, std::size_t len, const std::string& name) {
  void* p = ::mmap(nullptr, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd, 0);
  if (p == MAP_FAILED && (errno == EAGAIN || errno == EPERM || errno == ENOMEM)) {
    core::log_warn("{}: the ring could not be locked in memory ({}); mapping it unlocked", name,
                   std::strerror(errno));
    p = ::mmap(nullptr, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  }
  if (p == MAP_FAILED) {
    link::throw_errno("mmap of the ring on " + name);
  }
  return static_cast<std::byte*>(p);
}

tpacket_block_desc* block_at(std::byte* base, std::size_t block_size, std::size_t i) noexcept {
  return reinterpret_cast<tpacket_block_desc*>(base + (i * block_size));
}

}  // namespace

MmapRingSizes MmapRingSizes::shared_by(std::size_t sockets_per_port) {
  MmapRingSizes s;
  s.rx_block_nr = std::max<std::size_t>(2, 8 / std::max<std::size_t>(sockets_per_port, 1));
  return s;
}

PacketMmapBackend::Mapping::Mapping(Mapping&& other) noexcept
    : base_{std::exchange(other.base_, nullptr)}, len_{std::exchange(other.len_, 0)} {}

PacketMmapBackend::Mapping& PacketMmapBackend::Mapping::operator=(Mapping&& other) noexcept {
  if (this != &other) {
    if (base_ != nullptr) {
      ::munmap(base_, len_);
    }
    base_ = std::exchange(other.base_, nullptr);
    len_ = std::exchange(other.len_, 0);
  }
  return *this;
}

PacketMmapBackend::Mapping::~Mapping() {
  if (base_ != nullptr) {
    ::munmap(base_, len_);
  }
}

PacketMmapBackend::PacketMmapBackend(std::span<const core::InterfaceConfig> interfaces,
                                     core::PacketPool& pool, const AfPacketOptions& options,
                                     const MmapRingSizes& sizes)
    : pool_{&pool}, ports_(interfaces.size()), rx_(interfaces.size()), tx_(interfaces.size()) {
  link::check_shape(interfaces, options, "mmap");
  if (sizes.rx_block_size % kPageSize != 0 || sizes.rx_block_size % sizes.rx_frame_size != 0 ||
      sizes.tx_frame_size % TPACKET_ALIGNMENT != 0 || kTxBlockSize % sizes.tx_frame_size != 0 ||
      sizes.tx_frame_nr % (kTxBlockSize / sizes.tx_frame_size) != 0) {
    throw std::invalid_argument("mmap: ring sizes that do not divide as the kernel requires");
  }
  if (options.fanout) {
    fanout_groups_.resize(interfaces.size());
  }
  for (const core::InterfaceConfig& iface : interfaces) {
    const unsigned ifindex = link::ifindex_of(iface.name);
    if (options.receive.empty() || options.receive[iface.port]) {
      open_rx(iface.port, ifindex, iface, options, sizes);
    }
    open_tx(iface.port, ifindex, iface, sizes);
    const link::LinkFacts facts = link::read_link(tx_[iface.port].fd.get(), iface.name);
    const proto::MacAddr mac = link::effective_mac(iface, facts);
    if (!options.quiet) {
      core::log_info(
          "port {} {}: ifindex {}, mac {}, link {}, PACKET_MMAP: RX ring {} blocks of {} KiB per "
          "receiving socket (TPACKET_V3), TX ring {} slots of {} bytes (TPACKET_V2, qdisc bypass)",
          iface.port, iface.name, ifindex, proto::format_mac(mac), facts.up ? "up" : "DOWN",
          sizes.rx_block_nr, sizes.rx_block_size / 1024, sizes.tx_frame_nr, sizes.tx_frame_size);
    }
    ports_[iface.port] = PortInfo{.id = iface.port,
                                  .name = iface.name,
                                  .mac = mac,
                                  .ip = iface.ip,
                                  .prefix_len = iface.prefix_len,
                                  .mode = iface.mode,
                                  .bridge_domain = iface.bridge_domain,
                                  .up = facts.up};
  }
  std::ranges::sort(rx_ports_);
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void PacketMmapBackend::open_rx(std::uint16_t port, unsigned ifindex,
                                const core::InterfaceConfig& iface, const AfPacketOptions& options,
                                const MmapRingSizes& sizes) {
  RxRing& r = rx_[port];
  r.fd = link::open_packet_socket();
  set_int(r.fd.get(), PACKET_VERSION, TPACKET_V3, "TPACKET_V3 on " + iface.name);
  tpacket_req3 req{};
  req.tp_block_size = static_cast<unsigned>(sizes.rx_block_size);
  req.tp_block_nr = static_cast<unsigned>(sizes.rx_block_nr);
  req.tp_frame_size = static_cast<unsigned>(sizes.rx_frame_size);
  req.tp_frame_nr =
      static_cast<unsigned>((sizes.rx_block_size / sizes.rx_frame_size) * sizes.rx_block_nr);
  req.tp_retire_blk_tov = sizes.rx_retire_ms;
  req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;
  if (::setsockopt(r.fd.get(), SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0) {
    link::throw_errno("PACKET_RX_RING on " + iface.name);
  }
  r.block_size = sizes.rx_block_size;
  r.block_nr = sizes.rx_block_nr;
  r.map = Mapping(map_ring(r.fd.get(), r.block_size * r.block_nr, iface.name),
                  r.block_size * r.block_nr);
  link::bind_to(r.fd.get(), ifindex, iface);
  rx_ports_.push_back(port);
  if (options.fanout) {
    fanout_groups_[port] = link::join_fanout(
        r.fd.get(),
        options.fanout_groups.empty() ? std::nullopt
                                      : std::optional<std::uint16_t>{options.fanout_groups[port]},
        iface.name);
  }
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void PacketMmapBackend::open_tx(std::uint16_t port, unsigned ifindex,
                                const core::InterfaceConfig& iface, const MmapRingSizes& sizes) {
  TxRing& t = tx_[port];
  t.fd = link::open_packet_socket();
  set_int(t.fd.get(), PACKET_VERSION, TPACKET_V2, "TPACKET_V2 on " + iface.name);
  set_int(t.fd.get(), PACKET_QDISC_BYPASS, 1, "PACKET_QDISC_BYPASS on " + iface.name);
  tpacket_req req{};
  req.tp_block_size = static_cast<unsigned>(kTxBlockSize);
  req.tp_frame_size = static_cast<unsigned>(sizes.tx_frame_size);
  req.tp_frame_nr = static_cast<unsigned>(sizes.tx_frame_nr);
  req.tp_block_nr = static_cast<unsigned>(sizes.tx_frame_nr / (kTxBlockSize / sizes.tx_frame_size));
  if (::setsockopt(t.fd.get(), SOL_PACKET, PACKET_TX_RING, &req, sizeof(req)) < 0) {
    link::throw_errno("PACKET_TX_RING on " + iface.name);
  }
  t.frame_size = sizes.tx_frame_size;
  t.frame_nr = sizes.tx_frame_nr;
  t.map = Mapping(map_ring(t.fd.get(), kTxBlockSize * req.tp_block_nr, iface.name),
                  kTxBlockSize * req.tp_block_nr);
  // Bound with protocol 0: the socket names its interface for send(), and receives nothing.
  sockaddr_ll sll{};
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = 0;
  sll.sll_ifindex = static_cast<int>(ifindex);
  if (::bind(t.fd.get(), reinterpret_cast<const sockaddr*>(&sll), sizeof(sll)) < 0) {
    link::throw_errno("bind of the TX socket to " + iface.name);
  }
}

std::size_t PacketMmapBackend::rx_burst(core::Packet** out, std::size_t max) noexcept {
  std::size_t got = 0;
  const std::size_t n = rx_ports_.size();
  if (n == 0) {
    return 0;
  }
  for (std::size_t k = 0; k < n && got < max; ++k) {
    got += drain(rx_ports_[(next_port_ + k) % n], out + got, max - got);
  }
  next_port_ = (next_port_ + 1) % n;
  return got;
}

// Frames out of the port's ring, up to budget: from the block being read, then the next ones the
// kernel has handed over. A block goes back to the kernel once its last frame is read.
std::size_t PacketMmapBackend::drain(std::uint16_t port, core::Packet** out,
                                     std::size_t budget) noexcept {
  RxRing& r = rx_[port];
  std::size_t got = 0;
  while (got < budget) {
    tpacket_block_desc* block = block_at(r.map.base(), r.block_size, r.block);
    if (r.next == nullptr) {  // open the block, if the kernel has finished with it
      if ((load_status(block->hdr.bh1.block_status) & TP_STATUS_USER) == 0) {
        break;
      }
      r.left = block->hdr.bh1.num_pkts;
      r.next = reinterpret_cast<std::byte*>(block) + block->hdr.bh1.offset_to_first_pkt;
    }
    if (r.left == 0) {  // every frame read: the block goes back, the next one is up
      store_status(block->hdr.bh1.block_status, TP_STATUS_KERNEL);
      r.next = nullptr;
      r.block = (r.block + 1) % r.block_nr;
      continue;
    }
    core::Packet* p = pool_->acquire();
    if (p == nullptr) {
      break;  // the pool is empty: the frame waits in the ring until buffers come back
    }
    const auto* hdr = reinterpret_cast<const tpacket3_hdr*>(r.next);
    const auto* from =
        reinterpret_cast<const sockaddr_ll*>(r.next + tpacket_align(sizeof(tpacket3_hdr)));
    const std::size_t len = hdr->tp_snaplen;
    const bool outgoing = from->sll_pkttype == PACKET_OUTGOING;  // as AfPacketBackend
    const bool oversized = hdr->tp_len != hdr->tp_snaplen || len > p->capacity();
    if (!outgoing && !oversized) {
      p->resize(len);
      std::memcpy(p->data().data(), r.next + hdr->tp_mac, len);
      p->set_in_port(port);
      p->set_rx_tsc(core::rdtsc());
      out[got++] = p;
    } else {
      rx_oversized_ += oversized && !outgoing ? 1 : 0;
      pool_->release(p);
    }
    r.next += hdr->tp_next_offset;
    --r.left;
  }
  return got;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
std::size_t PacketMmapBackend::tx_burst(core::Packet* const* in, std::size_t n,
                                        std::uint16_t port) noexcept {
  const std::size_t sent = send(in, n, port);
  for (std::size_t i = 0; i < sent; ++i) {
    pool_->release(in[i]);
  }
  return sent;
}

// Into free slots, in order, until the frames or the free slots run out. A slot is free when the
// kernel has set it back to TP_STATUS_AVAILABLE after sending it; one it refused
// (TP_STATUS_WRONG_FORMAT) is reclaimed, as the kernel will not touch it again.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
std::size_t PacketMmapBackend::send(const core::Packet* const* in, std::size_t n,
                                    std::uint16_t port) noexcept {
  if (port >= tx_.size() || !tx_[port].fd.valid()) {
    return 0;
  }
  TxRing& t = tx_[port];
  std::size_t sent = 0;
  for (; sent < n; ++sent) {
    std::byte* slot = t.map.base() + (t.next * t.frame_size);
    auto* hdr = reinterpret_cast<tpacket2_hdr*>(slot);
    const std::uint32_t status = load_status(hdr->tp_status);
    if (status != TP_STATUS_AVAILABLE && status != TP_STATUS_WRONG_FORMAT) {
      break;  // the ring is full of frames still being sent
    }
    const core::CBytes frame = in[sent]->data();
    if (frame.size() > t.frame_size - kTxDataOffset) {
      break;  // cannot happen with kMaxFrame buffers; refused like a full ring if it does
    }
    std::memcpy(slot + kTxDataOffset, frame.data(), frame.size());
    hdr->tp_len = static_cast<std::uint32_t>(frame.size());
    store_status(hdr->tp_status, TP_STATUS_SEND_REQUEST);
    t.next = (t.next + 1) % t.frame_nr;
  }
  t.pending = t.pending || sent != 0;
  return sent;
}

// One send() per port with frames waiting: the kernel sends every slot marked for it. A kick that
// finds the device busy leaves the slots marked, and the next one sends them.
void PacketMmapBackend::tx_flush() noexcept {
  for (TxRing& t : tx_) {
    if (t.pending && ::send(t.fd.get(), nullptr, 0, MSG_DONTWAIT) >= 0) {
      t.pending = false;
    }
  }
}

std::vector<int> PacketMmapBackend::fds() const {
  std::vector<int> out;
  out.reserve(rx_ports_.size());
  std::ranges::transform(rx_ports_, std::back_inserter(out),
                         [this](std::uint16_t port) { return rx_[port].fd.get(); });
  return out;
}

std::uint64_t PacketMmapBackend::kernel_rx_drops() noexcept {
  for (const std::uint16_t port : rx_ports_) {
    kernel_rx_drops_ += link::kernel_drops(rx_[port].fd.get(), true);
  }
  return kernel_rx_drops_;
}

}  // namespace npf::io
// NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast,cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-pro-type-union-access)
