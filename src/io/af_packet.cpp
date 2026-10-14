#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <npf/core/config.hpp>
#include <npf/core/log.hpp>
#include <npf/core/packet.hpp>
#include <npf/core/pool.hpp>
#include <npf/core/time.hpp>
#include <npf/core/unique_fd.hpp>
#include <npf/io/af_packet.hpp>
#include <npf/io/backend.hpp>
#include <npf/proto/format.hpp>
#include <npf/proto/mac.hpp>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include "link.hpp"

namespace npf::io {

AfPacketBackend::AfPacketBackend(std::span<const core::InterfaceConfig> interfaces,
                                 core::PacketPool& pool, const AfPacketOptions& options)
    : pool_{&pool}, ports_(interfaces.size()), sockets_(interfaces.size()) {
  link::check_shape(interfaces, options, "af_packet");
  if (options.fanout) {
    fanout_groups_.resize(interfaces.size());
  }
  for (const core::InterfaceConfig& iface : interfaces) {
    core::UniqueFd fd = link::open_packet_socket();
    const unsigned ifindex = link::ifindex_of(iface.name);
    // A socket that only transmits is never bound, and so never receives: sendto() names the
    // interface with each frame.
    if (options.receive.empty() || options.receive[iface.port]) {
      receive_on(fd.get(), ifindex, iface, options);
    }

    const link::LinkFacts facts = link::read_link(fd.get(), iface.name);
    const proto::MacAddr mac = link::effective_mac(iface, facts);
    const int rcvbuf = link::grow_buffer(fd.get(), SO_RCVBUF);
    const int sndbuf = link::grow_buffer(fd.get(), SO_SNDBUF);
    if (!options.quiet) {
      core::log_info(
          "port {} {}: ifindex {}, mac {}, link {}, socket buffers {} rx and {} tx bytes "
          "(asked for {})",
          iface.port, iface.name, ifindex, proto::format_mac(mac), facts.up ? "up" : "DOWN", rcvbuf,
          sndbuf, link::kSocketBufferBytes);
    }

    ports_[iface.port] = PortInfo{.id = iface.port,
                                  .name = iface.name,
                                  .mac = mac,
                                  .ip = iface.ip,
                                  .prefix_len = iface.prefix_len,
                                  .mode = iface.mode,
                                  .bridge_domain = iface.bridge_domain,
                                  .up = facts.up};
    sockets_[iface.port] = Socket{std::move(fd), static_cast<int>(ifindex)};
  }
  std::ranges::sort(rx_ports_);
}

// A descriptor and an index, both the kernel's.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void AfPacketBackend::receive_on(int fd, unsigned ifindex, const core::InterfaceConfig& iface,
                                 const AfPacketOptions& options) {
  link::bind_to(fd, ifindex, iface);
  rx_ports_.push_back(iface.port);
  if (options.fanout) {
    fanout_groups_[iface.port] =
        link::join_fanout(fd,
                          options.fanout_groups.empty()
                              ? std::nullopt
                              : std::optional<std::uint16_t>{options.fanout_groups[iface.port]},
                          iface.name);
  }
}

std::size_t AfPacketBackend::rx_burst(core::Packet** out, std::size_t max) noexcept {
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

std::size_t AfPacketBackend::drain(std::uint16_t port, core::Packet** out,
                                   std::size_t budget) noexcept {
  const int fd = sockets_[port].fd.get();
  std::size_t got = 0;
  while (got < budget) {
    core::Packet* p = pool_->acquire();
    if (p == nullptr) {
      break;  // the pool is empty: the frame waits in the socket until buffers come back
    }
    p->resize(p->capacity());
    const core::Bytes buf = p->data();
    sockaddr_ll from{};
    socklen_t from_len = sizeof(from);
    // MSG_TRUNC makes the result the frame's real length, even when the buffer was shorter.
    const ssize_t n = ::recvfrom(fd, buf.data(), buf.size(), MSG_TRUNC,
                                 reinterpret_cast<sockaddr*>(&from), &from_len);
    if (n < 0) {
      // EAGAIN: drained. Any other error -- the link went down -- is reported to exactly one
      // read, this one, and cleared by it, so poll() does not keep waking up for it.
      pool_->release(p);
      break;
    }
    // ETH_P_ALL also delivers every frame transmitted on the interface, this router's own
    // included. Forwarding those again is a loop that saturates a core.
    if (from.sll_pkttype == PACKET_OUTGOING) {
      pool_->release(p);
      continue;
    }
    const auto len = static_cast<std::size_t>(n);
    if (len > buf.size()) {
      ++rx_oversized_;
      pool_->release(p);
      continue;
    }
    p->resize(len);
    p->set_in_port(port);
    p->set_rx_tsc(core::rdtsc());
    out[got++] = p;
  }
  return got;
}

// The parameters are ARCHITECTURE.md §9's, so their order is not this file's to change.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
std::size_t AfPacketBackend::tx_burst(core::Packet* const* in, std::size_t n,
                                      std::uint16_t port) noexcept {
  const std::size_t sent = send(in, n, port);
  for (std::size_t i = 0; i < sent; ++i) {
    pool_->release(in[i]);
  }
  return sent;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
std::size_t AfPacketBackend::send(const core::Packet* const* in, std::size_t n,
                                  std::uint16_t port) noexcept {
  if (port >= sockets_.size()) {
    return 0;
  }
  const Socket& s = sockets_[port];
  sockaddr_ll to{};
  to.sll_family = AF_PACKET;
  to.sll_ifindex = s.ifindex;
  std::size_t sent = 0;
  for (; sent < n; ++sent) {
    const core::CBytes frame = in[sent]->data();
    const ssize_t r = ::sendto(s.fd.get(), frame.data(), frame.size(), 0,
                               reinterpret_cast<const sockaddr*>(&to), sizeof(to));
    if (r < 0 || static_cast<std::size_t>(r) != frame.size()) {
      break;  // ENOBUFS or EAGAIN: the device queue is full, and the caller drops the rest
    }
  }
  return sent;
}

std::vector<int> AfPacketBackend::fds() const {
  std::vector<int> out;
  out.reserve(rx_ports_.size());
  std::ranges::transform(rx_ports_, std::back_inserter(out),
                         [this](std::uint16_t port) { return sockets_[port].fd.get(); });
  return out;
}

std::uint64_t AfPacketBackend::kernel_rx_drops() noexcept {
  for (const std::uint16_t port : rx_ports_) {
    kernel_rx_drops_ += link::kernel_drops(sockets_[port].fd.get(), false);
  }
  return kernel_rx_drops_;
}

}  // namespace npf::io
