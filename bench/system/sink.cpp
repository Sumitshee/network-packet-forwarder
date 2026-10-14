// sink -- the receiving end of the tier B benchmarks (docs/BUILD_PLAN.md phase 14). It takes the
// datagrams bench/system/gen sends on a UDP socket, counts them, finds the gaps in each flow's
// sequence numbers, and times each one from the TSC gen stamped it with to the TSC when sink
// received it.
//
//   sink [--port <port>] [--duration <seconds>] [--json]
//
// Runs until SIGINT or SIGTERM, or for --duration seconds, then prints what it saw: as one JSON
// object with --json. A datagram without gen's magic is counted as foreign and otherwise ignored.
//
// Latency is one way, gen to sink, through whatever lies between -- the router under test, and the
// kernel on both sides. Both ends read the same counter on the same machine, so no clocks are
// compared. Ticks become nanoseconds at the rate measured against CLOCK_MONOTONIC_RAW over the
// whole run, from start to finish. recvmmsg() hands over up to 64 datagrams at once and the TSC
// is read once per batch, as soon as it returns: a datagram's time includes the wait for the
// others of its batch, which is none at a low rate. A negative latency would mean the counter is
// not the same on every CPU; each one is counted, and left out of the percentiles.
//
// Per flow, the next sequence number expected is the last one seen plus one. A higher one counts
// the numbers skipped as missing; a lower one counts as late or duplicate, which only a record of
// every number could tell apart. Needs no privilege.

#include <netinet/in.h>
#include <poll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <exception>
#include <npf/core/byte_span.hpp>
#include <npf/core/time.hpp>
#include <npf/core/unique_fd.hpp>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace {

constexpr std::array<char, 8> kMagic{'N', 'P', 'F', 'G', 'E', 'N', '0', '1'};
constexpr std::size_t kPayload = kMagic.size() + 4 + 8 + 8;
constexpr std::size_t kBatch = 64;
constexpr std::size_t kMaxDatagram = 2048;
constexpr std::size_t kMaxFlows = 65536;
constexpr int kReceiveBuffer = 16 * 1024 * 1024;
constexpr int kPollMs = 100;

struct Options {
  std::uint16_t port{5001};
  std::optional<double> duration;
  bool json{false};
};

[[noreturn]] void throw_errno(const std::string& what) {
  throw std::system_error(errno, std::generic_category(), what);
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
  for (std::size_t i = 1; i < argv.size(); ++i) {
    const std::string_view arg = argv[i];
    if (arg == "--json") {
      o.json = true;
    } else if (arg == "--port" && i + 1 < argv.size()) {
      o.port = parse_number<std::uint16_t>(argv[++i], "--port");
    } else if (arg == "--duration" && i + 1 < argv.size()) {
      o.duration = parse_number<double>(argv[++i], "--duration");
    } else {
      throw std::invalid_argument("usage: sink [--port <port>] [--duration <seconds>] [--json]");
    }
  }
  return o;
}

std::int64_t monotonic_raw_ns() {
  timespec ts{};
  ::clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
  return (static_cast<std::int64_t>(ts.tv_sec) * 1'000'000'000) + ts.tv_nsec;
}

struct Flow {
  std::uint64_t expected{0};
  bool seen{false};
};

struct Tally {
  std::uint64_t received{0};
  std::uint64_t bytes{0};
  std::uint64_t foreign{0};
  std::uint64_t missing{0};
  std::uint64_t late_or_duplicate{0};
  std::uint64_t negative{0};
  std::size_t flows_seen{0};
  std::vector<Flow> flows = std::vector<Flow>(kMaxFlows);
  std::vector<std::int64_t> ticks;  // receive TSC minus send TSC, one per datagram
  std::optional<std::int64_t> first_ns, last_ns;
};

void count(Tally& t, std::span<const std::byte> payload, std::uint64_t rx_tsc) {
  if (payload.size() < kPayload ||
      !std::equal(kMagic.begin(), kMagic.end(), payload.begin(),
                  [](char c, std::byte b) { return static_cast<std::byte>(c) == b; })) {
    ++t.foreign;
    return;
  }
  using npf::core::rd_be32;
  const std::uint32_t flow = rd_be32(payload, 8);
  const std::uint64_t seq = (std::uint64_t{rd_be32(payload, 12)} << 32U) | rd_be32(payload, 16);
  const std::uint64_t tx = (std::uint64_t{rd_be32(payload, 20)} << 32U) | rd_be32(payload, 24);
  ++t.received;
  t.bytes += payload.size();
  if (flow < kMaxFlows) {
    Flow& f = t.flows[flow];
    if (!f.seen) {
      f.seen = true;
      ++t.flows_seen;
      t.missing += seq;  // the flow's first datagrams never came
      f.expected = seq + 1;
    } else if (seq >= f.expected) {
      t.missing += seq - f.expected;
      f.expected = seq + 1;
    } else {
      ++t.late_or_duplicate;
    }
  }
  const auto delta = static_cast<std::int64_t>(rx_tsc - tx);
  if (delta < 0) {
    ++t.negative;
  } else {
    t.ticks.push_back(delta);
  }
}

double percentile(const std::vector<std::int64_t>& sorted, double q) {
  if (sorted.empty()) {
    return 0;
  }
  const auto rank = static_cast<std::size_t>(std::ceil(q * static_cast<double>(sorted.size())));
  return static_cast<double>(sorted[std::max<std::size_t>(rank, 1) - 1]);
}

int run(const Options& o) {
  sigset_t mask{};
  sigemptyset(&mask);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGTERM);
  if (::sigprocmask(SIG_BLOCK, &mask, nullptr) != 0) {
    throw_errno("sigprocmask");
  }
  const npf::core::UniqueFd signals{::signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC)};
  const npf::core::UniqueFd fd{::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)};
  if (!signals.valid() || !fd.valid()) {
    throw_errno("socket");
  }
  // Root may go past net.core.rmem_max; anyone else gets what the limit allows.
  if (::setsockopt(fd.get(), SOL_SOCKET, SO_RCVBUFFORCE, &kReceiveBuffer, sizeof(int)) != 0) {
    ::setsockopt(fd.get(), SOL_SOCKET, SO_RCVBUF, &kReceiveBuffer, sizeof(int));
  }
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(o.port);
  if (::bind(fd.get(), reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
    throw_errno("bind");
  }

  Tally t;
  t.ticks.reserve(std::size_t{32} << 20U);
  std::vector<std::array<std::byte, kMaxDatagram>> buffers(kBatch);
  std::array<iovec, kBatch> iov{};
  std::array<mmsghdr, kBatch> msgs{};
  for (std::size_t i = 0; i < kBatch; ++i) {
    iov.at(i) = {buffers[i].data(), buffers[i].size()};
    msgs.at(i).msg_hdr.msg_iov = &iov.at(i);
    msgs.at(i).msg_hdr.msg_iovlen = 1;
  }
  std::array<pollfd, 2> fds{{{fd.get(), POLLIN, 0}, {signals.get(), POLLIN, 0}}};
  const std::uint64_t tsc_start = npf::core::rdtsc();
  const std::int64_t ns_start = monotonic_raw_ns();
  const std::int64_t deadline =
      o.duration ? ns_start + static_cast<std::int64_t>(*o.duration * 1e9) : INT64_MAX;
  if (!o.json) {
    std::printf("sink: listening on port %u\n", o.port);
  }
  std::fflush(stdout);
  while (monotonic_raw_ns() < deadline) {
    if (::poll(fds.data(), fds.size(), kPollMs) < 0 && errno != EINTR) {
      throw_errno("poll");
    }
    if ((fds[1].revents & POLLIN) != 0) {
      break;
    }
    for (;;) {
      const int n = ::recvmmsg(fd.get(), msgs.data(), kBatch, MSG_DONTWAIT, nullptr);
      if (n <= 0) {
        break;
      }
      const std::uint64_t rx = npf::core::rdtsc();
      const std::int64_t now = monotonic_raw_ns();
      t.first_ns = t.first_ns.value_or(now);
      t.last_ns = now;
      for (std::size_t i = 0; i < static_cast<std::size_t>(n); ++i) {
        count(t, std::span(buffers[i]).first(msgs.at(i).msg_len), rx);
      }
    }
  }
  const std::uint64_t tsc_end = npf::core::rdtsc();
  const std::int64_t ns_end = monotonic_raw_ns();
  const double ticks_per_ns =
      static_cast<double>(tsc_end - tsc_start) / static_cast<double>(ns_end - ns_start);

  std::ranges::sort(t.ticks);
  const auto ns = [&](double ticks) { return ticks / ticks_per_ns; };
  const double window_s = t.first_ns ? static_cast<double>(*t.last_ns - *t.first_ns) / 1e9 : 0.0;
  if (o.json) {
    std::printf(
        "{\"received\": %llu, \"bytes\": %llu, \"flows_seen\": %zu, \"missing\": %llu, "
        "\"late_or_duplicate\": %llu, \"foreign\": %llu, \"negative_latencies\": %llu, "
        "\"receive_window_s\": %.6f, \"tsc_ticks_per_ns\": %.6f, \"calibration_s\": %.3f, "
        "\"latency_ns\": {\"min\": %.1f, \"p50\": %.1f, \"p95\": %.1f, \"p99\": %.1f, "
        "\"p999\": %.1f, \"max\": %.1f}}\n",
        static_cast<unsigned long long>(t.received), static_cast<unsigned long long>(t.bytes),
        t.flows_seen, static_cast<unsigned long long>(t.missing),
        static_cast<unsigned long long>(t.late_or_duplicate),
        static_cast<unsigned long long>(t.foreign), static_cast<unsigned long long>(t.negative),
        window_s, ticks_per_ns, static_cast<double>(ns_end - ns_start) / 1e9,
        ns(percentile(t.ticks, 0.0)), ns(percentile(t.ticks, 0.50)), ns(percentile(t.ticks, 0.95)),
        ns(percentile(t.ticks, 0.99)), ns(percentile(t.ticks, 0.999)),
        ns(percentile(t.ticks, 1.0)));
  } else {
    std::printf(
        "sink: %llu datagrams in %zu flows, %llu missing, %llu late or duplicate; latency p50 "
        "%.0f ns, p99 %.0f ns\n",
        static_cast<unsigned long long>(t.received), t.flows_seen,
        static_cast<unsigned long long>(t.missing),
        static_cast<unsigned long long>(t.late_or_duplicate), ns(percentile(t.ticks, 0.50)),
        ns(percentile(t.ticks, 0.99)));
  }
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    return run(parse_args(std::span(argv, static_cast<std::size_t>(argc))));
  } catch (const std::exception& e) {
    std::fprintf(stderr, "sink: %s\n", e.what());
    return 1;
  }
}
