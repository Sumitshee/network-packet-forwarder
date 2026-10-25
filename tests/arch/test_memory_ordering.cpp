// [phase 18] The memory-ordering demonstration (ARCHITECTURE.md §13): why SpscRing stores its head
// with release, shown rather than argued.
//
// A ring like SpscRing, whose producer stores its index with the memory order it is given. Its
// slots are relaxed atomics, so there is no data race and no undefined behaviour anywhere: the only
// question is in what order another core sees two stores -- a slot's value, then the index that
// says the slot is full.
//
//  - With release, the index cannot become visible before the value: the consumer, which loads
//    the index with acquire, always reads the value the producer wrote. The control.
//  - With relaxed, nothing orders the two stores. x86 keeps stores in order anyway (TSO), so the
//    consumer is not expected to see the difference there. aarch64 may make the index visible
//    first, and then the consumer reads the slot's previous value: a stale read.
//
// The consumer counts stale reads. Both tests expect none, so the relaxed one failing is the
// demonstration succeeding. A store reordering is probabilistic: not seeing one in N items shows
// only that, and the result is reported either way (docs/performance.md, phase 18).
//
// Disabled by default: they run for seconds and prove nothing on x86. Run them with
//   build/ci/tests/test_memory_ordering --gtest_also_run_disabled_tests
// and NPF_ORDERING_ITEMS=<n> for more than 100 million items each.

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>

namespace {

template <std::memory_order kPublish>
class OrderingRing {
 public:
  // Small, so the consumer is always close behind the producer, reading slots just written.
  static constexpr std::size_t kSize = 64;

  bool push(std::uint64_t v) noexcept {
    const std::size_t head = head_.load(std::memory_order_relaxed);
    if (head - tail_.load(std::memory_order_acquire) == kSize) {
      return false;
    }
    slot(head).store(v, std::memory_order_relaxed);
    head_.store(head + 1, kPublish);  // the store under test
    return true;
  }

  bool pop(std::uint64_t& v) noexcept {
    const std::size_t tail = tail_.load(std::memory_order_relaxed);
    if (head_.load(std::memory_order_acquire) == tail) {
      return false;
    }
    v = slot(tail).load(std::memory_order_relaxed);
    tail_.store(tail + 1, std::memory_order_release);  // correct: the slot may be reused
    return true;
  }

 private:
  std::atomic<std::uint64_t>& slot(std::size_t i) noexcept { return slots_.at(i % kSize); }

  alignas(64) std::atomic<std::size_t> head_{0};
  alignas(64) std::atomic<std::size_t> tail_{0};
  alignas(64) std::array<std::atomic<std::uint64_t>, kSize> slots_{};
};

std::uint64_t items() {
  const char* env = std::getenv("NPF_ORDERING_ITEMS");
  return env != nullptr ? std::stoull(env) : 100'000'000;
}

// Pushes 1..n through the ring on one thread and pops them on this one; returns how many popped
// values were not the next in sequence -- a slot read before its value arrived.
template <std::memory_order kPublish>
std::uint64_t stale_reads(std::uint64_t n) {
  OrderingRing<kPublish> ring;
  std::thread producer([&ring, n] {
    for (std::uint64_t v = 1; v <= n; ++v) {
      while (!ring.push(v)) {
      }
    }
  });
  std::uint64_t stale = 0;
  for (std::uint64_t want = 1; want <= n; ++want) {
    std::uint64_t got = 0;
    while (!ring.pop(got)) {
    }
    stale += got != want ? 1 : 0;
  }
  producer.join();
  return stale;
}

TEST(MemoryOrdering, DISABLED_ReleasePublishNeverShowsAStaleSlot) {
  const std::uint64_t n = items();
  const std::uint64_t stale = stale_reads<std::memory_order_release>(n);
  std::cout << "release: " << stale << " stale reads in " << n << " items\n";
  EXPECT_EQ(stale, 0U);
}

TEST(MemoryOrdering, DISABLED_RelaxedPublishShowsStaleSlotsOnWeakHardware) {
  const std::uint64_t n = items();
  const std::uint64_t stale = stale_reads<std::memory_order_relaxed>(n);
  std::cout << "relaxed: " << stale << " stale reads in " << n << " items\n";
  EXPECT_EQ(stale, 0U) << "a store reordering, seen: the consumer read a slot before its value";
}

}  // namespace
