// AF_XDP through libbpf (the program) and libxdp (the socket, the UMEM, the rings). The rings'
// descriptors and the UMEM are the kernel's ABI, reached through libxdp's accessors and pointer
// arithmetic on the region this process registered; frames inside it are only ever copied.

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <xdp/xsk.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <npf/core/config.hpp>
#include <npf/core/log.hpp>
#include <npf/core/packet.hpp>
#include <npf/core/pool.hpp>
#include <npf/core/time.hpp>
#include <npf/core/unique_fd.hpp>
#include <npf/io/af_xdp.hpp>
#include <npf/io/backend.hpp>
#include <npf/proto/format.hpp>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

#include "link.hpp"
#include "xdp_redirect_object.hpp"  // generated from bpf/xdp_redirect.c: kXdpRedirectObject

// NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-pro-type-reinterpret-cast)
namespace npf::io {
namespace {

constexpr std::uint32_t kFrameSize = 2048;
constexpr std::uint32_t kFrames = 4096;
constexpr std::uint32_t kRxFrames = kFrames / 2;  // kept in the fill ring
constexpr std::uint32_t kTxFrames = kFrames - kRxFrames;
constexpr std::uint32_t kRingSize = 2048;  // every ring; each holds all the frames it can be given
constexpr int kKicksPerFlush = 8;          // copy mode sends a bounded batch per sendto()

[[noreturn]] void throw_error(int err, const std::string& what) {
  throw std::system_error(err, std::generic_category(), what);
}

const char* mode_name(XdpMode mode) noexcept {
  return mode == XdpMode::Native ? "native" : "skb";
}

}  // namespace

struct AfXdpBackend::Port {
  Port() = default;
  Port(const Port&) = delete;
  Port& operator=(const Port&) = delete;
  Port(Port&&) = delete;
  Port& operator=(Port&&) = delete;
  ~Port() {
    if (xsk != nullptr) {
      xsk_socket__delete(xsk);
    }
    if (umem != nullptr) {
      xsk_umem__delete(umem);
    }
    if (attached) {
      bpf_xdp_detach(static_cast<int>(ifindex), attach_flags, nullptr);
    }
    if (obj != nullptr) {
      bpf_object__close(obj);
    }
    if (area != nullptr) {
      ::munmap(area, kFrames * std::size_t{kFrameSize});
    }
  }

  unsigned ifindex{0};
  std::uint32_t attach_flags{0};
  bool attached{false};
  bpf_object* obj{nullptr};
  std::byte* area{nullptr};  // the UMEM: kFrames frames of kFrameSize bytes
  xsk_umem* umem{nullptr};
  xsk_socket* xsk{nullptr};
  xsk_ring_prod fq{};  // fill: frames the kernel may receive into
  xsk_ring_cons cq{};  // completion: frames the kernel has sent
  xsk_ring_cons rx{};
  xsk_ring_prod tx{};
  std::array<std::uint64_t, kTxFrames> free_tx{};  // UMEM addresses of TX frames not in flight
  std::size_t n_free{0};
  bool pending{false};  // TX descriptors posted since the last kick

  // Start-up, in order. Each throws on the kernel's refusal; the destructor undoes what was done.
  int attach(const std::string& name, XdpMode mode);  // returns the XSKMAP's fd
  void bind(const std::string& name, int map_fd);
  void give_frames(const std::string& name);
};

int AfXdpBackend::Port::attach(const std::string& name, XdpMode mode) {
  ifindex = link::ifindex_of(name);
  obj = bpf_object__open_mem(kXdpRedirectObject.data(), kXdpRedirectObject.size(), nullptr);
  if (obj == nullptr) {
    throw_error(errno, "xdp: opening the embedded XDP program");
  }
  if (const int err = bpf_object__load(obj); err != 0) {
    throw_error(-err, "xdp: loading the XDP program (root, or CAP_BPF and CAP_NET_ADMIN?)");
  }
  bpf_program* prog = bpf_object__find_program_by_name(obj, "npf_xdp_redirect");
  const int map_fd = bpf_object__find_map_fd_by_name(obj, "xsks_map");
  if (prog == nullptr || map_fd < 0) {
    throw std::runtime_error("xdp: the embedded program has no npf_xdp_redirect or xsks_map");
  }
  attach_flags = mode == XdpMode::Native ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
  // UPDATE_IF_NOEXIST: refuse, rather than replace, a program someone else attached.
  if (const int err = bpf_xdp_attach(static_cast<int>(ifindex), bpf_program__fd(prog),
                                     attach_flags | XDP_FLAGS_UPDATE_IF_NOEXIST, nullptr);
      err != 0) {
    throw_error(-err, "xdp: attaching the program to " + name + " in " + mode_name(mode) +
                          " mode (if one is attached already: ip link set dev " + name +
                          " xdp off)");
  }
  attached = true;
  return map_fd;
}

void AfXdpBackend::Port::bind(const std::string& name, int map_fd) {
  void* mapped = ::mmap(nullptr, kFrames * std::size_t{kFrameSize}, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mapped == MAP_FAILED) {
    throw_error(errno, "xdp: mapping the UMEM for " + name);
  }
  area = static_cast<std::byte*>(mapped);
  xsk_umem_config umem_cfg{};
  umem_cfg.fill_size = kRingSize;
  umem_cfg.comp_size = kRingSize;
  umem_cfg.frame_size = kFrameSize;
  if (const int err =
          xsk_umem__create(&umem, area, kFrames * std::size_t{kFrameSize}, &fq, &cq, &umem_cfg);
      err != 0) {
    throw_error(-err, "xdp: registering the UMEM for " + name);
  }
  xsk_socket_config sock_cfg{};
  sock_cfg.rx_size = kRingSize;
  sock_cfg.tx_size = kRingSize;
  // libxdp's own program is not loaded: ours is attached already. (libxdp_flags shares a union
  // with the older libbpf_flags; the field is set, never read, here.)
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
  sock_cfg.libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD;
  sock_cfg.xdp_flags = attach_flags;
  sock_cfg.bind_flags = XDP_COPY;
  if (const int err = xsk_socket__create(&xsk, name.c_str(), 0, umem, &rx, &tx, &sock_cfg);
      err != 0) {
    throw_error(-err, "xdp: binding an AF_XDP socket to " + name + " queue 0");
  }
  if (const int err = xsk_socket__update_xskmap(xsk, map_fd); err != 0) {
    throw_error(-err, "xdp: pointing the XSKMAP of " + name + " at its socket");
  }
}

// The first half of the UMEM to the kernel, to receive into; the second half to send from.
void AfXdpBackend::Port::give_frames(const std::string& name) {
  std::uint32_t idx = 0;
  if (xsk_ring_prod__reserve(&fq, kRxFrames, &idx) != kRxFrames) {
    throw std::runtime_error("xdp: the fill ring of " + name + " would not take the frames");
  }
  for (std::uint32_t i = 0; i < kRxFrames; ++i) {
    *xsk_ring_prod__fill_addr(&fq, idx + i) = std::uint64_t{i} * kFrameSize;
  }
  xsk_ring_prod__submit(&fq, kRxFrames);
  for (std::uint32_t i = 0; i < kTxFrames; ++i) {
    free_tx.at(i) = std::uint64_t{kRxFrames + i} * kFrameSize;
  }
  n_free = kTxFrames;
}

AfXdpBackend::AfXdpBackend(std::span<const core::InterfaceConfig> interfaces,
                           core::PacketPool& pool, const AfPacketOptions& options, XdpMode mode)
    : pool_{&pool}, ports_(interfaces.size()) {
  link::check_shape(interfaces, options, "xdp");
  if (options.fanout || std::ranges::find(options.receive, false) != options.receive.end()) {
    throw std::invalid_argument(
        "xdp: one AF_XDP socket per port, on one queue, with no fanout: --io xdp runs one worker, "
        "run to completion");
  }
  sockets_.resize(interfaces.size());
  for (const core::InterfaceConfig& iface : interfaces) {
    sockets_[iface.port] = std::make_unique<Port>();
    Port& s = *sockets_[iface.port];
    const core::UniqueFd control = link::open_packet_socket();  // for the link's ioctls only
    const link::LinkFacts facts = link::read_link(control.get(), iface.name);
    s.bind(iface.name, s.attach(iface.name, mode));
    s.give_frames(iface.name);

    const proto::MacAddr mac = link::effective_mac(iface, facts);
    if (!options.quiet) {
      core::log_info(
          "port {} {}: ifindex {}, mac {}, link {}, AF_XDP: {} mode, queue 0, XDP_COPY, UMEM {} "
          "frames of {} bytes",
          iface.port, iface.name, s.ifindex, proto::format_mac(mac), facts.up ? "up" : "DOWN",
          mode_name(mode), kFrames, kFrameSize);
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
}

AfXdpBackend::~AfXdpBackend() = default;

std::size_t AfXdpBackend::rx_burst(core::Packet** out, std::size_t max) noexcept {
  const std::size_t n = sockets_.size();
  std::size_t got = 0;
  for (std::size_t k = 0; k < n && got < max; ++k) {
    const std::size_t id = (next_port_ + k) % n;
    got += drain(*sockets_[id], static_cast<std::uint16_t>(id), out + got, max - got);
  }
  next_port_ = n == 0 ? 0 : (next_port_ + 1) % n;
  return got;
}

// Received frames, copied into pool buffers, each UMEM frame straight back to the fill ring. No
// more than the pool can take, so none has to be put back.
std::size_t AfXdpBackend::drain(Port& s, std::uint16_t id, core::Packet** out,
                                std::size_t budget) noexcept {
  budget = std::min({budget, core::kMaxBurst, pool_->available()});
  std::uint32_t ri = 0;
  std::uint32_t n = xsk_ring_cons__peek(&s.rx, static_cast<std::uint32_t>(budget), &ri);
  if (n == 0) {
    return 0;
  }
  std::uint32_t fi = 0;
  const std::uint32_t refill = xsk_ring_prod__reserve(&s.fq, n, &fi);
  if (refill < n) {  // cannot happen: the fill ring has a place for every RX frame
    xsk_ring_cons__cancel(&s.rx, n - refill);
    n = refill;
  }
  std::size_t got = 0;
  for (std::uint32_t i = 0; i < n; ++i) {
    const xdp_desc* d = xsk_ring_cons__rx_desc(&s.rx, ri + i);
    const std::uint64_t addr = xsk_umem__extract_addr(d->addr);
    const auto* frame = static_cast<const std::byte*>(
        xsk_umem__get_data(s.area, xsk_umem__add_offset_to_addr(d->addr)));
    core::Packet* p = pool_->acquire();
    if (p != nullptr && d->len <= p->capacity()) {
      p->resize(d->len);
      std::memcpy(p->data().data(), frame, d->len);
      p->set_in_port(id);
      p->set_rx_tsc(core::rdtsc());
      out[got++] = p;
    } else {
      rx_oversized_ += p != nullptr ? 1 : 0;
      if (p != nullptr) {
        pool_->release(p);
      }
    }
    *xsk_ring_prod__fill_addr(&s.fq, fi + i) = addr;
  }
  xsk_ring_prod__submit(&s.fq, n);
  xsk_ring_cons__release(&s.rx, n);
  return got;
}

// Frames the kernel has finished sending, back to the free list.
void AfXdpBackend::reap(Port& s) noexcept {
  std::uint32_t ci = 0;
  const std::uint32_t n = xsk_ring_cons__peek(&s.cq, kTxFrames, &ci);
  for (std::uint32_t i = 0; i < n && s.n_free < s.free_tx.size(); ++i) {
    // n_free stays below free_tx.size(): the loop's condition.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
    s.free_tx[s.n_free++] = *xsk_ring_cons__comp_addr(&s.cq, ci + i);
  }
  xsk_ring_cons__release(&s.cq, n);
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
std::size_t AfXdpBackend::tx_burst(core::Packet* const* in, std::size_t n,
                                   std::uint16_t port) noexcept {
  const std::size_t sent = send(in, n, port);
  for (std::size_t i = 0; i < sent; ++i) {
    pool_->release(in[i]);
  }
  return sent;
}

// Into free UMEM frames, in order, until the frames or the free ones run out.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
std::size_t AfXdpBackend::send(const core::Packet* const* in, std::size_t n,
                               std::uint16_t port) noexcept {
  if (port >= sockets_.size()) {
    return 0;
  }
  Port& s = *sockets_[port];
  reap(s);
  // The frames that fit a UMEM frame, in order -- all of them, with kMaxFrame buffers -- and no
  // more than there are free frames: so every descriptor reserved is filled.
  std::size_t fit = 0;
  while (fit < std::min(n, s.n_free) && in[fit]->data().size() <= kFrameSize) {
    ++fit;
  }
  std::uint32_t ti = 0;
  const std::uint32_t sent =
      fit == 0 ? 0 : xsk_ring_prod__reserve(&s.tx, static_cast<std::uint32_t>(fit), &ti);
  for (std::uint32_t i = 0; i < sent; ++i) {
    const core::CBytes frame = in[i]->data();
    // sent <= fit <= n_free, so n_free never goes below 0.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
    const std::uint64_t addr = s.free_tx[--s.n_free];
    std::memcpy(xsk_umem__get_data(s.area, addr), frame.data(), frame.size());
    xdp_desc* d = xsk_ring_prod__tx_desc(&s.tx, ti + i);
    d->addr = addr;
    d->len = static_cast<std::uint32_t>(frame.size());
  }
  xsk_ring_prod__submit(&s.tx, sent);
  s.pending = s.pending || sent != 0;
  return sent;
}

// A sendto() per port with descriptors posted. In copy mode the kernel sends a bounded batch per
// call and says EAGAIN while there are more; a busy device leaves them posted for the next kick.
void AfXdpBackend::tx_flush() noexcept {
  for (const std::unique_ptr<Port>& p : sockets_) {
    Port& s = *p;
    if (!s.pending) {
      continue;
    }
    for (int k = 0; k < kKicksPerFlush; ++k) {
      if (::sendto(xsk_socket__fd(s.xsk), nullptr, 0, MSG_DONTWAIT, nullptr, 0) >= 0) {
        s.pending = false;
        break;
      }
      if (errno != EAGAIN) {
        break;  // EBUSY or ENOBUFS: the next flush tries again
      }
    }
    reap(s);
  }
}

std::vector<int> AfXdpBackend::fds() const {
  std::vector<int> out;
  out.reserve(sockets_.size());
  for (const std::unique_ptr<Port>& p : sockets_) {
    out.push_back(xsk_socket__fd(p->xsk));
  }
  return out;
}

std::uint64_t AfXdpBackend::kernel_rx_drops() noexcept {
  std::uint64_t total = 0;
  for (const std::unique_ptr<Port>& p : sockets_) {
    xdp_statistics st{};
    socklen_t len = sizeof(st);
    if (::getsockopt(xsk_socket__fd(p->xsk), SOL_XDP, XDP_STATISTICS, &st, &len) == 0) {
      total += st.rx_dropped + st.rx_ring_full;
    }
  }
  return total;
}

}  // namespace npf::io
// NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-pro-type-reinterpret-cast)
