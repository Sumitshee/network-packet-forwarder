#include "link.hpp"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <format>
#include <iterator>
#include <npf/core/config.hpp>
#include <npf/core/log.hpp>
#include <npf/core/unique_fd.hpp>
#include <npf/io/af_packet.hpp>
#include <npf/proto/format.hpp>
#include <npf/proto/mac.hpp>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

namespace npf::io::link {
namespace {

// From the kernel's <linux/if_packet.h>, which cannot be included beside glibc's
// <netpacket/packet.h>: both define sockaddr_ll. glibc defines PACKET_FANOUT itself, not these.
constexpr std::uint32_t kFanoutHash = 0;               // PACKET_FANOUT_HASH
constexpr std::uint32_t kFanoutFlagUniqueId = 0x2000;  // PACKET_FANOUT_FLAG_UNIQUEID

// struct tpacket_stats and struct tpacket_stats_v3, as <linux/if_packet.h> lays them out.
struct StatsV2 {
  unsigned int packets;
  unsigned int drops;
};
struct StatsV3 {
  unsigned int packets;
  unsigned int drops;
  unsigned int freeze_q_cnt;
};

}  // namespace

void throw_errno(const std::string& what) {
  throw std::system_error(errno, std::generic_category(), what);
}

core::UniqueFd open_packet_socket() {
  core::UniqueFd fd{::socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)};
  if (!fd.valid()) {
    throw_errno("socket(AF_PACKET) needs CAP_NET_RAW; run npf with sudo");
  }
  return fd;
}

unsigned ifindex_of(const std::string& name) {
  const unsigned ifindex = ::if_nametoindex(name.c_str());
  if (ifindex == 0) {
    throw_errno("interface " + name);
  }
  return ifindex;
}

// ifreq is the kernel's ioctl ABI -- a union, filled in place by a variadic call -- and every
// access to one is in these two functions.
// NOLINTBEGIN(cppcoreguidelines-pro-type-union-access,cppcoreguidelines-pro-type-vararg)
namespace {
ifreq request_for(const std::string& name) {
  ifreq ifr{};
  if (name.empty() || name.size() >= sizeof(ifr.ifr_name)) {
    throw std::invalid_argument(std::format("interface name '{}' must be 1 to {} characters", name,
                                            sizeof(ifr.ifr_name) - 1));
  }
  std::ranges::copy(name, std::begin(ifr.ifr_name));
  return ifr;
}
}  // namespace

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

void check_shape(std::span<const core::InterfaceConfig> interfaces, const AfPacketOptions& options,
                 const char* backend) {
  if (interfaces.empty()) {
    throw std::invalid_argument(std::format("{}: no interfaces to open", backend));
  }
  if (!options.receive.empty() && options.receive.size() != interfaces.size()) {
    throw std::invalid_argument(std::format("{}: one receive flag per interface", backend));
  }
  if (!options.fanout_groups.empty() && options.fanout_groups.size() != interfaces.size()) {
    throw std::invalid_argument(std::format("{}: one fanout group per interface", backend));
  }
  std::vector<bool> seen(interfaces.size(), false);
  for (const core::InterfaceConfig& iface : interfaces) {
    if (iface.port >= interfaces.size() || seen[iface.port]) {
      throw std::invalid_argument(
          std::format("port ids must run from 0 to {}, each used once; interface {} has port {}",
                      interfaces.size() - 1, iface.name, iface.port));
    }
    seen[iface.port] = true;
  }
}

proto::MacAddr effective_mac(const core::InterfaceConfig& iface, const LinkFacts& link) {
  if (iface.mac && *iface.mac != link.mac) {
    core::log_warn("{}: the configured mac {} is not the interface's own ({}); using {}",
                   iface.name, proto::format_mac(*iface.mac), proto::format_mac(link.mac),
                   proto::format_mac(*iface.mac));
    return *iface.mac;
  }
  return link.mac;
}

std::uint64_t kernel_drops(int fd, bool v3) noexcept {
  if (v3) {
    StatsV3 stats{};
    socklen_t len = sizeof(stats);
    return ::getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &stats, &len) == 0 ? stats.drops : 0;
  }
  StatsV2 stats{};
  socklen_t len = sizeof(stats);
  return ::getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &stats, &len) == 0 ? stats.drops : 0;
}

}  // namespace npf::io::link
