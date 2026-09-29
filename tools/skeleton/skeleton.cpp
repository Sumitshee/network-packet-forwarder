// Phase 0.5 walking skeleton -- THROWAWAY. Never build on it, never link it into anything.
//
// It exists to get one ping across two network namespaces through code written here, before any
// abstraction exists, so the AF_PACKET and netns surprises surface while they are cheap. It stays
// in the tree as a reference and as evidence in the history; phase 1 starts again from an empty
// include/npf/. See docs/BUILD_PLAN.md, "Phase 0.5".
//
//   usage, inside ns-router:   skeleton <port0-ifname> <port1-ifname>
//
// Port 0 owns 10.0.1.1/24 and port 1 owns 10.0.2.1/24. Both subnets are directly connected, and
// the only neighbours it can resolve are 10.0.1.2 and 10.0.2.2.

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <span>

namespace {

using Mac = std::array<std::uint8_t, 6>;
using Bytes = std::span<std::uint8_t>;
using CBytes = std::span<const std::uint8_t>;

constexpr std::uint32_t ip4(std::uint32_t a, std::uint32_t b, std::uint32_t c, std::uint32_t d) {
  return a << 24 | b << 16 | c << 8 | d;
}

constexpr std::size_t kEthHdr = 14;
constexpr std::size_t kArpFrame = kEthHdr + 28;
constexpr std::uint16_t kTypeIpv4 = 0x0800;
constexpr std::uint16_t kTypeArp = 0x0806;
constexpr std::uint16_t kArpRequest = 1;
constexpr std::uint16_t kArpReply = 2;
constexpr Mac kBroadcast{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

struct Port {
  const char* name;
  std::uint32_t ip;  // host byte order, like every address in this file
  int fd;
  int ifindex;
  Mac mac;
};

struct Route {
  std::uint32_t net, mask;
  std::size_t port;
};
constexpr std::array<Route, 2> kRoutes{
    {{ip4(10, 0, 1, 0), 0xFFFFFF00u, 0}, {ip4(10, 0, 2, 0), 0xFFFFFF00u, 1}}};

struct Neighbour {
  std::uint32_t ip;
  Mac mac;
  bool valid;
};

struct Stats {
  unsigned long rx, forwarded, tx_errors;
  unsigned long arp_replies_tx, arp_requests_tx, arp_resolved, arp_other;
  unsigned long drop_not_ipv4, drop_not_our_mac, drop_bad_header, drop_bad_checksum;
  unsigned long drop_to_router, drop_ttl, drop_no_route, drop_unresolved, drop_while_resolving;
};

// Everything main() owns, handed to the free functions below by reference.
struct State {
  std::array<Port, 2> ports{};
  std::array<Neighbour, 2> arp{{{ip4(10, 0, 1, 2), {}, false}, {ip4(10, 0, 2, 2), {}, false}}};
  Stats st{};
  std::array<std::uint8_t, 2048> rx_buf{};   // the frame being processed
  std::array<std::uint8_t, 2048> scratch{};  // ARP frames sent and received while it waits
};

struct Arp {
  std::uint16_t oper;
  Mac sha;
  std::uint32_t spa, tpa;
};

// Big-endian, one byte at a time, and only after the caller has checked the length. Casting a
// header struct onto the buffer would be alignment and strict-aliasing UB, and would hide a
// missing length check.
std::uint16_t rd16(CBytes b, std::size_t off) {
  return static_cast<std::uint16_t>(b[off] << 8 | b[off + 1]);
}
std::uint32_t rd32(CBytes b, std::size_t off) {
  return std::uint32_t{rd16(b, off)} << 16 | std::uint32_t{rd16(b, off + 2)};
}
void wr16(Bytes b, std::size_t off, std::uint16_t v) {
  b[off] = static_cast<std::uint8_t>(v >> 8);
  b[off + 1] = static_cast<std::uint8_t>(v & 0xFF);
}
void wr32(Bytes b, std::size_t off, std::uint32_t v) {
  wr16(b, off, static_cast<std::uint16_t>(v >> 16));
  wr16(b, off + 2, static_cast<std::uint16_t>(v & 0xFFFF));
}
Mac rd_mac(CBytes b, std::size_t off) {
  Mac m{};
  const CBytes src = b.subspan(off, m.size());
  std::copy(src.begin(), src.end(), m.begin());
  return m;
}
void wr_mac(Bytes b, std::size_t off, const Mac& m) {
  std::copy(m.begin(), m.end(), b.subspan(off, m.size()).begin());
}

// RFC 1071: the complement of the one's-complement sum of the header's 16-bit words. Over a
// header whose stored checksum is right, the result is zero.
std::uint16_t ip_checksum(CBytes hdr) {
  std::uint32_t sum = 0;
  for (std::size_t i = 0; i + 1 < hdr.size(); i += 2) sum += rd16(hdr, i);
  while (sum > 0xFFFF) sum = (sum & 0xFFFF) + (sum >> 16);
  return static_cast<std::uint16_t>(~sum & 0xFFFF);
}

std::array<char, 16> ip_str(std::uint32_t ip) {
  std::array<char, 16> s{};
  std::snprintf(s.data(), s.size(), "%u.%u.%u.%u", ip >> 24, ip >> 16 & 0xFF, ip >> 8 & 0xFF,
                ip & 0xFF);
  return s;
}
std::array<char, 18> mac_str(const Mac& m) {
  std::array<char, 18> s{};
  std::snprintf(s.data(), s.size(), "%02x:%02x:%02x:%02x:%02x:%02x", unsigned{m[0]}, unsigned{m[1]},
                unsigned{m[2]}, unsigned{m[3]}, unsigned{m[4]}, unsigned{m[5]});
  return s;
}

[[noreturn]] void die(const char* what) {
  std::fprintf(stderr, "skeleton: %s: %s\n", what, std::strerror(errno));
  std::exit(1);
}

Port open_port(const char* name, std::uint32_t ip) {
  Port p{name, ip, -1, 0, {}};
  const std::size_t name_len = std::strlen(name);
  if (name_len >= IFNAMSIZ) {
    errno = ENAMETOOLONG;
    die(name);
  }
  p.ifindex = static_cast<int>(::if_nametoindex(name));
  if (p.ifindex == 0) die(name);

  // A socket opened with ETH_P_ALL receives from EVERY interface from the moment it exists, so
  // frames from the other port could queue on it before bind() narrows it to this one, and be
  // read as if they had arrived here. Protocol 0 receives nothing until bind() sets both.
  p.fd = ::socket(AF_PACKET, SOCK_RAW, 0);
  if (p.fd < 0) die("socket(AF_PACKET) needs CAP_NET_RAW; run under sudo");
  sockaddr_ll sll{};
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = htons(ETH_P_ALL);
  sll.sll_ifindex = p.ifindex;
  if (::bind(p.fd, reinterpret_cast<const sockaddr*>(&sll), sizeof(sll)) < 0) die("bind");

  ifreq ifr{};
  std::memcpy(ifr.ifr_name, name, name_len + 1);
  if (::ioctl(p.fd, SIOCGIFHWADDR, &ifr) < 0) die("ioctl(SIOCGIFHWADDR)");
  for (std::size_t i = 0; i < p.mac.size(); ++i) {
    p.mac[i] = static_cast<std::uint8_t>(ifr.ifr_hwaddr.sa_data[i]);
  }
  return p;
}

[[nodiscard]] bool send_frame(const Port& port, CBytes f) {
  sockaddr_ll to{};
  to.sll_family = AF_PACKET;
  to.sll_ifindex = port.ifindex;
  to.sll_halen = 6;
  const CBytes dst = f.first(6);
  std::copy(dst.begin(), dst.end(), std::begin(to.sll_addr));
  const ssize_t n =
      ::sendto(port.fd, f.data(), f.size(), 0, reinterpret_cast<const sockaddr*>(&to), sizeof(to));
  return n >= 0 && static_cast<std::size_t>(n) == f.size();
}

// Returns the length of the next frame received on the port, 0 for one to skip, or -1 once the
// socket is drained.
[[nodiscard]] ssize_t recv_frame(const Port& port, Bytes buf, Stats& st) {
  sockaddr_ll from{};
  socklen_t from_len = sizeof(from);
  const ssize_t n = ::recvfrom(port.fd, buf.data(), buf.size(), MSG_DONTWAIT | MSG_TRUNC,
                               reinterpret_cast<sockaddr*>(&from), &from_len);
  if (n < 0) return -1;
  // An ETH_P_ALL socket also sees every frame the host transmits on its interface, ours
  // included. Processing those again would be a forwarding loop that saturates a core.
  if (from.sll_pkttype == PACKET_OUTGOING) return 0;
  ++st.rx;
  if (static_cast<std::size_t>(n) > buf.size()) {  // MSG_TRUNC reports the untruncated length
    ++st.drop_bad_header;
    return 0;
  }
  return n;
}

// Only IPv4-over-Ethernet ARP; anything else is not ours to answer.
[[nodiscard]] std::optional<Arp> parse_arp(CBytes f) {
  if (f.size() < kArpFrame || rd16(f, 12) != kTypeArp) return std::nullopt;
  const CBytes a = f.subspan(kEthHdr);
  if (rd16(a, 0) != 1 || rd16(a, 2) != kTypeIpv4 || a[4] != 6 || a[5] != 4) return std::nullopt;
  return Arp{rd16(a, 6), rd_mac(a, 8), rd32(a, 14), rd32(a, 24)};
}

// Writes a 42-byte Ethernet + ARP frame at the start of buf and returns its length.
[[nodiscard]] std::size_t build_arp(Bytes buf, std::uint16_t oper, const Mac& eth_dst,
                                    const Mac& sha, std::uint32_t spa, const Mac& tha,
                                    std::uint32_t tpa) {
  wr_mac(buf, 0, eth_dst);
  wr_mac(buf, 6, sha);
  wr16(buf, 12, kTypeArp);
  const Bytes a = buf.subspan(kEthHdr);
  wr16(a, 0, 1);  // hardware type Ethernet
  wr16(a, 2, kTypeIpv4);
  a[4] = 6;
  a[5] = 4;
  wr16(a, 6, oper);
  wr_mac(a, 8, sha);
  wr32(a, 14, spa);
  wr_mac(a, 18, tha);
  wr32(a, 24, tpa);
  return kArpFrame;
}

void answer_arp(const Port& port, const Arp& req, Bytes buf, Stats& st) {
  const std::size_t len = build_arp(buf, kArpReply, req.sha, port.mac, port.ip, req.sha, req.spa);
  if (!send_frame(port, buf.first(len))) {
    ++st.tx_errors;
    return;
  }
  ++st.arp_replies_tx;
  std::printf("arp  %s is-at %s, told %s on %s\n", ip_str(port.ip).data(), mac_str(port.mac).data(),
              ip_str(req.spa).data(), port.name);
}

// Crude on purpose: blocks the whole process until the neighbour answers. Anything else arriving
// on the port meanwhile is dropped -- except ARP requests for us, because a neighbour resolving
// us at the same moment must not be left waiting.
[[nodiscard]] std::optional<Mac> resolve(State& s, const Port& port, std::uint32_t ip) {
  using Clock = std::chrono::steady_clock;
  for (int attempt = 1; attempt <= 3; ++attempt) {
    const std::size_t len =
        build_arp(s.scratch, kArpRequest, kBroadcast, port.mac, port.ip, Mac{}, ip);
    if (!send_frame(port, std::span(s.scratch).first(len))) {
      ++s.st.tx_errors;
      continue;
    }
    ++s.st.arp_requests_tx;
    const auto deadline = Clock::now() + std::chrono::milliseconds(300);
    for (auto now = Clock::now(); now < deadline; now = Clock::now()) {
      pollfd pfd{port.fd, POLLIN, 0};
      const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
      if (::poll(&pfd, 1, static_cast<int>(left.count()) + 1) <= 0) continue;
      ssize_t n = 0;
      while ((n = recv_frame(port, s.scratch, s.st)) >= 0) {
        const auto arp = parse_arp(std::span(s.scratch).first(static_cast<std::size_t>(n)));
        if (arp && arp->oper == kArpReply && arp->spa == ip) {
          ++s.st.arp_resolved;
          std::printf("arp  resolved %s is-at %s on %s, attempt %d\n", ip_str(ip).data(),
                      mac_str(arp->sha).data(), port.name, attempt);
          return arp->sha;
        }
        if (arp && arp->oper == kArpRequest && arp->tpa == port.ip) {
          answer_arp(port, *arp, s.scratch, s.st);
        } else if (n > 0) {
          ++s.st.drop_while_resolving;
        }
      }
    }
  }
  return std::nullopt;
}

void handle_frame(State& s, std::size_t in, Bytes f) {
  Stats& st = s.st;
  const Port& port = s.ports[in];
  if (f.size() < kEthHdr) {
    ++st.drop_bad_header;
    return;
  }
  const std::uint16_t type = rd16(f, 12);
  if (type == kTypeArp) {
    // Only a request for our own address needs anything from us. Replies are consumed by
    // resolve(), and the rest of the segment's ARP traffic is none of our business.
    const auto arp = parse_arp(f);
    if (arp && arp->oper == kArpRequest && arp->tpa == port.ip) {
      answer_arp(port, *arp, s.scratch, st);
    } else {
      ++st.arp_other;
    }
    return;
  }
  if (type != kTypeIpv4) {  // IPv6 neighbour discovery, VLAN tags, LLDP, ...
    ++st.drop_not_ipv4;
    return;
  }
  if (rd_mac(f, 0) != port.mac) {
    ++st.drop_not_our_mac;
    return;
  }

  // Nothing past the fixed 20 bytes is trusted until checked: the header is ihl * 4 long, and
  // total_length must fit inside what actually arrived. Ethernet padding after it rides along.
  const Bytes ip = f.subspan(kEthHdr);
  if (ip.size() < 20) {
    ++st.drop_bad_header;
    return;
  }
  const std::size_t hdr_len = std::size_t{ip[0] & 0x0Fu} * 4;
  const std::size_t total_len = rd16(ip, 2);
  if ((ip[0] >> 4) != 4 || hdr_len < 20 || hdr_len > ip.size() || total_len < hdr_len ||
      total_len > ip.size()) {
    ++st.drop_bad_header;
    return;
  }
  if (ip_checksum(ip.first(hdr_len)) != 0) {
    ++st.drop_bad_checksum;
    return;
  }

  const std::uint32_t src = rd32(ip, 12);
  const std::uint32_t dst = rd32(ip, 16);
  if (dst == s.ports[0].ip || dst == s.ports[1].ip) {  // echo replies are phase 7
    ++st.drop_to_router;
    return;
  }
  const std::uint8_t ttl = ip[8];
  if (ttl <= 1) {  // Time Exceeded is phase 7
    ++st.drop_ttl;
    return;
  }

  const auto route = std::find_if(kRoutes.begin(), kRoutes.end(),
                                  [dst](const Route& r) { return (dst & r.mask) == r.net; });
  if (route == kRoutes.end()) {
    ++st.drop_no_route;
    return;
  }
  const Port& out = s.ports[route->port];

  // Both routes are directly connected, so the next hop is the destination itself.
  const auto nb =
      std::find_if(s.arp.begin(), s.arp.end(), [dst](const Neighbour& n) { return n.ip == dst; });
  if (nb == s.arp.end()) {
    ++st.drop_unresolved;
    return;
  }
  if (!nb->valid) {
    const auto mac = resolve(s, out, dst);
    if (!mac) {
      ++st.drop_unresolved;
      return;
    }
    nb->mac = *mac;
    nb->valid = true;
  }

  wr_mac(f, 0, nb->mac);
  wr_mac(f, 6, out.mac);
  ip[8] = static_cast<std::uint8_t>(ttl - 1);
  wr16(ip, 10, 0);
  wr16(ip, 10, ip_checksum(ip.first(hdr_len)));  // full recompute; the incremental form is phase 3
  if (!send_frame(out, f)) {
    ++st.tx_errors;
    return;
  }
  ++st.forwarded;
  std::printf("fwd  %s -> %s  ttl %u->%u  %s -> %s  %zu bytes\n", ip_str(src).data(),
              ip_str(dst).data(), unsigned{ttl}, unsigned{ttl} - 1, port.name, out.name, f.size());
}

int open_signalfd() {
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGTERM);
  // Blocked signals are delivered through the descriptor instead, so the poll() loop sees Ctrl-C
  // as one more readable fd and no global flag is needed.
  if (::sigprocmask(SIG_BLOCK, &mask, nullptr) < 0) die("sigprocmask");
  const int fd = ::signalfd(-1, &mask, 0);
  if (fd < 0) die("signalfd");
  return fd;
}

void print_stats(const Stats& st) {
  std::printf(
      "--- skeleton stats ---\n"
      "rx %lu  forwarded %lu  tx_errors %lu\n"
      "arp: replies_tx %lu  requests_tx %lu  resolved %lu  other %lu\n"
      "drops: not_ipv4 %lu  not_our_mac %lu  bad_header %lu  bad_checksum %lu  to_router %lu  "
      "ttl %lu  no_route %lu  unresolved %lu  while_resolving %lu\n",
      st.rx, st.forwarded, st.tx_errors, st.arp_replies_tx, st.arp_requests_tx, st.arp_resolved,
      st.arp_other, st.drop_not_ipv4, st.drop_not_our_mac, st.drop_bad_header, st.drop_bad_checksum,
      st.drop_to_router, st.drop_ttl, st.drop_no_route, st.drop_unresolved,
      st.drop_while_resolving);
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 3) {
    std::fprintf(stderr, "usage: %s <port0-ifname> <port1-ifname>\n", argv[0]);
    return 2;
  }
  std::setvbuf(stdout, nullptr, _IOLBF, 0);  // line by line, even when redirected to a log

  State s;
  const std::array<const char*, 2> names{argv[1], argv[2]};
  const std::array<std::uint32_t, 2> ips{ip4(10, 0, 1, 1), ip4(10, 0, 2, 1)};
  for (std::size_t i = 0; i < s.ports.size(); ++i) {
    s.ports[i] = open_port(names[i], ips[i]);
    const Port& p = s.ports[i];
    std::printf("port %zu  %-8s  ifindex %d  mac %s  ip %s/24\n", i, p.name, p.ifindex,
                mac_str(p.mac).data(), ip_str(p.ip).data());
  }
  const int sig_fd = open_signalfd();
  std::printf("forwarding; Ctrl-C to stop\n");

  std::array<pollfd, 3> fds{
      {{s.ports[0].fd, POLLIN, 0}, {s.ports[1].fd, POLLIN, 0}, {sig_fd, POLLIN, 0}}};
  for (;;) {
    if (::poll(fds.data(), fds.size(), -1) < 0) {
      if (errno == EINTR) continue;
      die("poll");
    }
    if ((fds[2].revents & POLLIN) != 0) break;
    for (std::size_t i = 0; i < s.ports.size(); ++i) {
      // A pending socket error (the interface went down, say) is only cleared by reading it;
      // skipping POLLERR would make every later poll() return at once and spin a core.
      if ((fds[i].revents & (POLLIN | POLLERR)) == 0) continue;
      ssize_t n = 0;
      while ((n = recv_frame(s.ports[i], s.rx_buf, s.st)) >= 0) {
        if (n > 0) handle_frame(s, i, std::span(s.rx_buf).first(static_cast<std::size_t>(n)));
      }
    }
  }

  print_stats(s.st);
  for (const Port& p : s.ports) ::close(p.fd);
  ::close(sig_fd);
  return 0;
}
