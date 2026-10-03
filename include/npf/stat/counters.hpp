#pragma once

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <npf/pipe/decision.hpp>
#include <numeric>

namespace npf::stat {

// ARCHITECTURE.md §10. Each worker owns one, alignas(64) so no two workers' counters share a
// cache line; the reporter sums them on demand. Plain uint64_t, not atomic: a torn read of a
// statistic does not matter, and atomics on the hot path do.
//
// Every received packet lands in exactly one of forwarded, flooded, to_host or one drops[]
// bucket, so rx_packets == forwarded + flooded + to_host + total_drops() whenever no packet is in
// flight. The worker counts rx_*, tx_*, forwarded and TxFull, because only it sees a frame
// arrive and the backend accept or refuse it; Forwarder counts everything it decides itself.
struct alignas(64) Counters {
  std::uint64_t rx_packets{0}, rx_bytes{0};
  std::uint64_t tx_packets{0}, tx_bytes{0};
  std::uint64_t forwarded{0}, flooded{0}, to_host{0};
  std::uint64_t arp_requests_rx{0}, arp_replies_rx{0}, arp_requests_tx{0}, arp_replies_tx{0};
  std::uint64_t icmp_generated{0};
  std::array<std::uint64_t, kDropReasons> drops{};
  std::array<std::uint64_t, 256> by_protocol{};  // indexed by IP protocol number

  // The enum is the index, and the assertion its bounds check.
  [[nodiscard]] std::uint64_t& drop(DropReason r) noexcept {
    assert(r < DropReason::_Count);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
    return drops[static_cast<std::size_t>(r)];
  }

  [[nodiscard]] std::uint64_t drop(DropReason r) const noexcept {
    assert(r < DropReason::_Count);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
    return drops[static_cast<std::size_t>(r)];
  }

  // An 8-bit protocol number cannot index past 256 slots.
  void count_protocol(std::uint8_t protocol) noexcept {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
    ++by_protocol[protocol];
  }

  [[nodiscard]] std::uint64_t total_drops() const noexcept {
    return std::accumulate(drops.begin(), drops.end(), std::uint64_t{0});
  }

  // Aggregation only, never on the hot path.
  void merge(const Counters& other) noexcept {
    rx_packets += other.rx_packets;
    rx_bytes += other.rx_bytes;
    tx_packets += other.tx_packets;
    tx_bytes += other.tx_bytes;
    forwarded += other.forwarded;
    flooded += other.flooded;
    to_host += other.to_host;
    arp_requests_rx += other.arp_requests_rx;
    arp_replies_rx += other.arp_replies_rx;
    arp_requests_tx += other.arp_requests_tx;
    arp_replies_tx += other.arp_replies_tx;
    icmp_generated += other.icmp_generated;
    std::ranges::transform(drops, other.drops, drops.begin(), std::plus<>{});
    std::ranges::transform(by_protocol, other.by_protocol, by_protocol.begin(), std::plus<>{});
  }
};

static_assert(alignof(Counters) == 64);

}  // namespace npf::stat
