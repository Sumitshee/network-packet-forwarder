#pragma once

#include <chrono>
#include <cstdint>

#if defined(__x86_64__)
#include <x86intrin.h>
#endif

namespace npf::core {

// Every interval the router measures -- the stats period, ARP timers -- is on this clock, which
// never jumps when the wall clock is set.
using Clock = std::chrono::steady_clock;

// A per-packet timestamp, for Packet::rx_tsc. On x86-64 it is the time-stamp counter, a few dozen
// cycles to read where clock_gettime() costs several times that. Only the difference between two
// readings on one machine means anything, and turning it into time needs the TSC's frequency.
// Elsewhere it falls back to the steady clock, in nanoseconds.
[[nodiscard]] inline std::uint64_t rdtsc() noexcept {
#if defined(__x86_64__)
  return static_cast<std::uint64_t>(__rdtsc());
#else
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now().time_since_epoch())
          .count());
#endif
}

}  // namespace npf::core
