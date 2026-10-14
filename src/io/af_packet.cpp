#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <format>
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
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace npf::io {
namespace {

// Asked for on every socket. The kernel doubles whatever it is given, to cover its own
// bookkeeping, and caps the request at net.core.rmem_max or wmem_max first -- so the size it
// grants is read back and logged rather than assumed.
constexpr int kSocketBufferBytes = 4 * 1024 * 1024;

// From the kernel's <linux/if_packet.h>, which cannot be included beside glibc's
// <netpacket/packet.h>: both define sockaddr_ll. glibc defines PACKET_FANOUT itself, not these.
constexpr std::uint32_t kFanoutHash = 0;               // PACKET_FANOUT_HASH
constexpr std::uint32_t kFanoutFlagUniqueId = 0x2000;  // PACKET_FANOUT_FLAG_UNIQUEID

[[noreturn]] void throw_errno(const std::string& what) {
  throw std::system_error(errno, std::generic_category(), what);
}

struct LinkFacts {
  proto::MacAddr mac;
  bool up{false};
};

// ifreq is the kernel's ioctl ABI -- a union, filled in place by a variadic call -- and every
// access to one is in these two functions.
// NOLINTBEGIN(cppcoreguidelines-pro-type-union-access,cppcoreguidelines-pro-type-vararg)
ifreq request_for(const std::string& name) {
  ifreq ifr{};
  if (name.empty() || name.size() >= sizeof(ifr.ifr_name)) {
    throw std::invalid_argument(std::format("interface name '{}' must be 1 to {} characters", name,
                                            sizeof(ifr.ifr_name) - 1));
  }
  std::ranges::copy(name, std::begin(ifr.ifr_name));
  return ifr;
}

LinkFacts read_link(int fd, const std::string& name) {
  ifreq ifr = request_for(name);
  if (::ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
    throw_errno("SIOCGIFHWADDR " + name);
  }
  if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
    throw std::invalid_argument(name + " is not an Ethernet interface");
  }
  LinkFacts facts;
  std::ranges::transform(std::span(ifr.ifr_hwaddr.sa_data).first(facts.mac.b.size()),
                         facts.mac.b.begin(), [](char c) { return static_cast<std::uint8_t>(c); });
  ifr = request_for(name);
  if (::ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
    throw_errno("SIOCGIFFLAGS " + name);
  }
  facts.up = (ifr.ifr_flags & IFF_UP) != 0;
  return facts;
}
// NOLINTEND(cppcoreguidelines-pro-type-union-access,cppcoreguidelines-pro-type-vararg)

// Returns the size the kernel granted, or -1 if it would not say. A refusal is not fatal: the
// default buffer works, it only overflows sooner under a burst.
int grow_buffer(int fd, int option) {
  const int want = kSocketBufferBytes;
  int granted = -1;
  socklen_t len = sizeof(granted);
  if (::setsockopt(fd, SOL_SOCKET, option, &want, sizeof(want)) < 0 ||
      ::getsockopt(fd, SOL_SOCKET, option, &granted, &len) < 0) {
    return -1;
  }
  return granted;
}

// Joins fd, bound to an interface, to a PACKET_FANOUT_HASH group: group's, or else a new one with
// an id the kernel picks, so no other process's group on the same interface can be joined by
// mistake. Returns the group's id.
std::uint16_t join_fanout(int fd, std::optional<std::uint16_t> group, const std::string& name) {
  // The low 16 bits are the group id, the next 8 the mode, the top 8 its flags. A group made with
  // PACKET_FANOUT_FLAG_UNIQUEID does not keep the flag, so the others join with the mode alone.
  const std::uint32_t arg =
      group ? (*group | (kFanoutHash << 16U)) : ((kFanoutHash | kFanoutFlagUniqueId) << 16U);
  if (::setsockopt(fd, SOL_PACKET, PACKET_FANOUT, &arg, sizeof(arg)) < 0) {
    throw_errno("PACKET_FANOUT on " + name);
  }
  std::uint32_t joined = 0;
  socklen_t len = sizeof(joined);
  if (::getsockopt(fd, SOL_PACKET, PACKET_FANOUT, &joined, &len) < 0) {
    throw_errno("reading back PACKET_FANOUT on " + name);
  }
  return static_cast<std::uint16_t>(joined & 0xFFFFU);
}

// A descriptor and an index, both the kernel's.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void bind_to(int fd, unsigned ifindex, const core::InterfaceConfig& iface) {
  sockaddr_ll sll{};
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = htons(ETH_P_ALL);
  sll.sll_ifindex = static_cast<int>(ifindex);
  if (::bind(fd, reinterpret_cast<const sockaddr*>(&sll), sizeof(sll)) < 0) {
    throw_errno("bind to " + iface.name);
  }
  // A bridged port must see frames for every station, not only for its own MAC: a NIC filters
  // the rest unless promiscuous. The kernel undoes this when the socket closes.
  if (iface.mode == PortMode::Bridged) {
    packet_mreq promisc{};
    promisc.mr_ifindex = static_cast<int>(ifindex);
    promisc.mr_type = PACKET_MR_PROMISC;
    if (::setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &promisc, sizeof(promisc)) < 0) {
      throw_errno("promiscuous mode on " + iface.name);
    }
  }
}

void check_shape(std::span<const core::InterfaceConfig> interfaces,
                 const AfPacketOptions& options) {
  if (interfaces.empty()) {
    throw std::invalid_argument("af_packet: no interfaces to open");
  }
  if (!options.receive.empty() && options.receive.size() != interfaces.size()) {
    throw std::invalid_argument("af_packet: one receive flag per interface");
  }
  if (!options.fanout_groups.empty() && options.fanout_groups.size() != interfaces.size()) {
    throw std::invalid_argument("af_packet: one fanout group per interface");
  }
}

// The configured MAC wins over the interface's own, with a warning.
proto::MacAddr effective_mac(const core::InterfaceConfig& iface, const LinkFacts& link) {
  if (iface.mac && *iface.mac != link.mac) {
    core::log_warn("{}: the configured mac {} is not the interface's own ({}); using {}",
                   iface.name, proto::format_mac(*iface.mac), proto::format_mac(link.mac),
                   proto::format_mac(*iface.mac));
    return *iface.mac;
  }
  return link.mac;
}

}  // namespace

AfPacketBackend::AfPacketBackend(std::span<const core::InterfaceConfig> interfaces,
                                 core::PacketPool& pool, const AfPacketOptions& options)
    : pool_{&pool}, ports_(interfaces.size()), sockets_(interfaces.size()) {
  check_shape(interfaces, options);
  if (options.fanout) {
    fanout_groups_.resize(interfaces.size());
  }
  std::vector<bool> seen(interfaces.size(), false);
  for (const core::InterfaceConfig& iface : interfaces) {
    if (iface.port >= interfaces.size() || seen[iface.port]) {
      throw std::invalid_argument(
          std::format("port ids must run from 0 to {}, each used once; interface {} has port {}",
                      interfaces.size() - 1, iface.name, iface.port));
    }
    seen[iface.port] = true;

    // Protocol 0 receives nothing until bind() names the interface. A socket opened with
    // ETH_P_ALL would collect frames from every interface from the moment it exists, and the
    // first few could be taken for this port's.
    core::UniqueFd fd{::socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)};
    if (!fd.valid()) {
      throw_errno("socket(AF_PACKET) needs CAP_NET_RAW; run npf with sudo");
    }
    const unsigned ifindex = ::if_nametoindex(iface.name.c_str());
    if (ifindex == 0) {
      throw_errno("interface " + iface.name);
    }
    // A socket that only transmits is never bound, and so never receives: sendto() names the
    // interface with each frame.
    if (options.receive.empty() || options.receive[iface.port]) {
      receive_on(fd.get(), ifindex, iface, options);
    }

    const LinkFacts link = read_link(fd.get(), iface.name);
    const proto::MacAddr mac = effective_mac(iface, link);
    const int rcvbuf = grow_buffer(fd.get(), SO_RCVBUF);
    const int sndbuf = grow_buffer(fd.get(), SO_SNDBUF);
    if (!options.quiet) {
      core::log_info(
          "port {} {}: ifindex {}, mac {}, link {}, socket buffers {} rx and {} tx bytes "
          "(asked for {})",
          iface.port, iface.name, ifindex, proto::format_mac(mac), link.up ? "up" : "DOWN", rcvbuf,
          sndbuf, kSocketBufferBytes);
    }

    ports_[iface.port] = PortInfo{.id = iface.port,
                                  .name = iface.name,
                                  .mac = mac,
                                  .ip = iface.ip,
                                  .prefix_len = iface.prefix_len,
                                  .mode = iface.mode,
                                  .bridge_domain = iface.bridge_domain,
                                  .up = link.up};
    sockets_[iface.port] = Socket{std::move(fd), static_cast<int>(ifindex)};
  }
  std::ranges::sort(rx_ports_);
}

// A descriptor and an index, both the kernel's.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void AfPacketBackend::receive_on(int fd, unsigned ifindex, const core::InterfaceConfig& iface,
                                 const AfPacketOptions& options) {
  bind_to(fd, ifindex, iface);
  rx_ports_.push_back(iface.port);
  if (options.fanout) {
    fanout_groups_[iface.port] =
        join_fanout(fd,
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

}  // namespace npf::io
