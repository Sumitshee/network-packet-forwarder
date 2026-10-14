// gen -- the minimal phase 13 load generator: UDP datagrams over N flows, each carrying its flow
// and a sequence number, so that a capture taken past the router shows whether any flow's packets
// were reordered (scripts/check_ordering.py). Phase 14 extends it with rate control and
// timestamps.
//
//   gen --dst <address> [--src <address>] [--flows <n>] [--count <n> | --duration <seconds>]
//       [--ip-id-sequence] [--dport <port>]
//
// Flow f, from 0, is source port 10000 + f to --dport (5001). Flows take turns, one datagram
// each. The payload is the magic "NPFGEN01", the flow (32 bits) and its sequence number (64 bits,
// from 0), big-endian. --ip-id-sequence makes the IP ID follow the sequence too, as
// seq % 65535 + 1: never 0, which the kernel would replace with an ID of its own choosing. Without
// it the kernel picks every ID.
//
// The datagrams go out of a raw IP socket, so the kernel routes them and resolves the next hop
// itself, and fills in the header checksum; the UDP checksum is left 0, which IPv4 allows. Needs
// CAP_NET_RAW. Not part of the router: it runs inside the client namespace of the test topology.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <npf/core/byte_span.hpp>
#include <npf/core/unique_fd.hpp>
#include <npf/proto/l4.hpp>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace {

constexpr std::uint16_t kFirstSourcePort = 10000;
constexpr std::array<char, 8> kMagic{'N', 'P', 'F', 'G', 'E', 'N', '0', '1'};
constexpr std::size_t kIpHeader = 20;
constexpr std::size_t kUdpHeader = 8;
constexpr std::size_t kPayload = kMagic.size() + 4 + 8;

struct Options {
  std::uint32_t dst{0};
  std::uint32_t src{0};  // 0: the kernel's choice, the outgoing interface's address
  std::uint32_t flows{1};
  std::optional<std::uint64_t> count;
  std::optional<double> duration;
  bool ip_id_sequence{false};
  std::uint16_t dport{5001};
};

std::uint32_t parse_ipv4(std::string_view text) {
  in_addr a{};
  const std::string s(text);
  if (::inet_pton(AF_INET, s.c_str(), &a) != 1) {
    throw std::invalid_argument("not an IPv4 address: " + s);
  }
  return ntohl(a.s_addr);
}

template <class T>
T parse_number(std::string_view text, std::string_view what) {
  T n{};
  const auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), n);
  if (ec != std::errc{} || end != text.data() + text.size()) {
    throw std::invalid_argument(std::string(what) + " needs a number, not '" + std::string(text) +
                                "'");
  }
  return n;
}

Options parse_args(std::span<char* const> argv) {
  Options o;
  bool have_dst = false;
  for (std::size_t i = 1; i < argv.size(); ++i) {
    const std::string_view arg = argv[i];
    if (arg == "--ip-id-sequence") {
      o.ip_id_sequence = true;
      continue;
    }
    if (i + 1 == argv.size()) {
      throw std::invalid_argument(std::string(arg) + " needs a value");
    }
    const std::string_view value = argv[++i];
    if (arg == "--dst") {
      o.dst = parse_ipv4(value);
      have_dst = true;
    } else if (arg == "--src") {
      o.src = parse_ipv4(value);
    } else if (arg == "--flows") {
      o.flows = parse_number<std::uint32_t>(value, "--flows");
    } else if (arg == "--count") {
      o.count = parse_number<std::uint64_t>(value, "--count");
    } else if (arg == "--duration") {
      o.duration = parse_number<double>(value, "--duration");
    } else if (arg == "--dport") {
      o.dport = parse_number<std::uint16_t>(value, "--dport");
    } else {
      throw std::invalid_argument("unknown option " + std::string(arg));
    }
  }
  if (!have_dst || o.flows == 0 || o.flows > 65535 - kFirstSourcePort ||
      o.count.has_value() == o.duration.has_value()) {
    throw std::invalid_argument(
        "usage: gen --dst <address> [--src <address>] [--flows <n>] "
        "(--count <n> | --duration <seconds>) [--ip-id-sequence] [--dport <port>]");
  }
  return o;
}

// One datagram of flow `flow`, number `seq` in it, in `out`: the IPv4 header, UDP, the payload.
void build(std::span<std::byte> out, const Options& o, std::uint32_t flow, std::uint64_t seq) {
  using npf::core::wr_be16;
  using npf::core::wr_be32;
  using npf::core::wr_u8;
  const std::uint16_t id =
      o.ip_id_sequence ? static_cast<std::uint16_t>((seq % 65535) + 1) : std::uint16_t{0};
  wr_u8(out, 0, 0x45);
  wr_be16(out, 2, static_cast<std::uint16_t>(out.size()));
  wr_be16(out, 4, id);
  wr_be16(out, 6, 0x4000);  // DF: a router that fragmented these would be another test's business
  wr_u8(out, 8, 64);
  wr_u8(out, 9, npf::proto::kIpProtoUdp);
  wr_be16(out, 10, 0);  // the kernel fills it in
  wr_be32(out, 12, o.src);
  wr_be32(out, 16, o.dst);
  const std::span<std::byte> udp = out.subspan(kIpHeader);
  wr_be16(udp, 0, static_cast<std::uint16_t>(kFirstSourcePort + flow));
  wr_be16(udp, 2, o.dport);
  wr_be16(udp, 4, static_cast<std::uint16_t>(kUdpHeader + kPayload));
  wr_be16(udp, 6, 0);
  const std::span<std::byte> payload = udp.subspan(kUdpHeader);
  for (std::size_t i = 0; i < kMagic.size(); ++i) {
    payload[i] = static_cast<std::byte>(kMagic.at(i));
  }
  wr_be32(payload, kMagic.size(), flow);
  wr_be32(payload, kMagic.size() + 4, static_cast<std::uint32_t>(seq >> 32U));
  wr_be32(payload, kMagic.size() + 8, static_cast<std::uint32_t>(seq));
}

int run(const Options& o) {
  const npf::core::UniqueFd fd{::socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW)};
  if (!fd.valid()) {
    throw std::system_error(errno, std::generic_category(), "raw socket (needs CAP_NET_RAW)");
  }
  sockaddr_in to{};
  to.sin_family = AF_INET;
  to.sin_addr.s_addr = htonl(o.dst);
  std::array<std::byte, kIpHeader + kUdpHeader + kPayload> datagram{};
  std::vector<std::uint64_t> next_seq(o.flows, 0);
  const auto start = std::chrono::steady_clock::now();
  const auto deadline = start + std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                                    std::chrono::duration<double>(o.duration.value_or(0)));
  std::uint64_t sent = 0;
  std::uint64_t retries = 0;
  for (std::uint32_t flow = 0;; flow = (flow + 1) % o.flows) {
    if (o.count ? sent == *o.count
                : (sent % 1024 == 0 && std::chrono::steady_clock::now() >= deadline)) {
      break;
    }
    build(datagram, o, flow, next_seq[flow]);
    // A full device queue says ENOBUFS: wait for room rather than lose the datagram here, so that
    // every gap a capture shows is the router's doing.
    while (::sendto(fd.get(), datagram.data(), datagram.size(), 0,
                    reinterpret_cast<const sockaddr*>(&to), sizeof(to)) < 0) {
      if (errno != ENOBUFS && errno != EAGAIN && errno != EINTR) {
        throw std::system_error(errno, std::generic_category(), "sendto");
      }
      ++retries;
      ::usleep(50);
    }
    ++next_seq[flow];
    ++sent;
  }
  const std::chrono::duration<double> took = std::chrono::steady_clock::now() - start;
  std::printf("gen: sent %llu datagrams over %u flows in %.3f s (%.0f per second; %llu retries)\n",
              static_cast<unsigned long long>(sent), o.flows, took.count(),
              took.count() > 0 ? static_cast<double>(sent) / took.count() : 0.0,
              static_cast<unsigned long long>(retries));
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    return run(parse_args(std::span(argv, static_cast<std::size_t>(argc))));
  } catch (const std::exception& e) {
    std::fprintf(stderr, "gen: %s\n", e.what());
    return 1;
  }
}
