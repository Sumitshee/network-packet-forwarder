#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <type_traits>

namespace npf::core {

// ARCHITECTURE.md §13. A bounded, lock-free queue between exactly one producer thread and exactly
// one consumer thread: an RX thread and a worker, a worker and the RX thread its packets go home
// to, one worker and another.
//
// head_ and tail_ count every element ever pushed and popped, and are never wrapped; a slot is
// buf_[count & (N - 1)]. head_ - tail_ is the number of elements in the ring, from 0 to N, so all N
// slots are usable and full and empty are never confused. A 64-bit count does not wrap in the
// lifetime of a machine.
//
// Memory ordering -- the reasoning, since it is the whole point of the class:
//
//  - Each index has one writer. The producer reads head_ relaxed, because nobody else writes it,
//    and the consumer does the same with tail_.
//  - The producer fills a slot, and only then stores head_ with release. The consumer loads head_
//    with acquire. A release store and the acquire load that reads it form a happens-before edge:
//    everything the producer wrote before the store -- the slot, and anything the slot points to,
//    such as a packet's bytes -- is visible to the consumer once it has seen the new head_. The
//    release is what publishes the slot's contents, not just the index. Were the store relaxed, a
//    consumer that had already seen the new index could read a slot the producer had not finished
//    writing. x86's store order usually hides that mistake; aarch64's does not (phase 18).
//  - The consumer reads a slot, and only then stores tail_ with release. The producer loads tail_
//    with acquire before reusing slots. That edge runs the other way: the consumer's read of a
//    slot happens before the producer overwrites it. Without it the producer could overwrite an
//    element the consumer has not read yet -- the same race, on the way back.
//  - Each side keeps a stale copy of the other's index, cached_tail_ and cached_head_, and reloads
//    the real one only when the copy says the ring is full (producer) or empty (consumer). The
//    copy is never ahead of the real index, so the worst it can do is say "full" or "empty" too
//    early, and a reload corrects that. So in a busy ring the acquire loads, and the cache-line
//    transfers they cause, happen once per lap rather than once per element.
//
// The alignas(64) keep the two indexes on separate cache lines: otherwise every push would
// invalidate the line the consumer is reading tail_ from, and every pop the producer's. The two
// caches share one line, as §13 lays them out -- each is written only on a reload; phase 15
// measures whether that line is worth splitting too.
//
// T is copied in and out by value, so it must be trivially copyable: a pointer, or a small record.
template <class T, std::size_t N>
class SpscRing {
  static_assert(N >= 2 && (N & (N - 1)) == 0, "N must be a power of two");
  static_assert(std::is_trivially_copyable_v<T>, "elements are copied in and out of slots");

 public:
  SpscRing() = default;
  SpscRing(const SpscRing&) = delete;
  SpscRing& operator=(const SpscRing&) = delete;
  SpscRing(SpscRing&&) = delete;
  SpscRing& operator=(SpscRing&&) = delete;
  ~SpscRing() = default;

  // Producer thread only. False if the ring is full; v is then not queued.
  [[nodiscard]] bool push(T v) noexcept { return push_bulk(&v, 1) == 1; }

  // Consumer thread only. False if the ring is empty; out is then untouched.
  [[nodiscard]] bool pop(T& out) noexcept { return pop_bulk(&out, 1) == 1; }

  // Producer thread only. Queues as many of v[0..n) as there is room for, in order, and returns
  // how many: a partial result, not all or nothing. One release store publishes them all.
  [[nodiscard]] std::size_t push_bulk(const T* v, std::size_t n) noexcept {
    const std::size_t head = head_.load(std::memory_order_relaxed);
    if (N - (head - cached_tail_) < n) {
      cached_tail_ = tail_.load(std::memory_order_acquire);
    }
    n = std::min(n, N - (head - cached_tail_));
    if (n == 0) {
      return 0;
    }
    for (std::size_t i = 0; i < n; ++i) {
      // The mask is the bounds check.
      // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index,cppcoreguidelines-pro-bounds-pointer-arithmetic)
      buf_[(head + i) & kMask] = v[i];
    }
    head_.store(head + n, std::memory_order_release);
    return n;
  }

  // Consumer thread only. Takes up to n elements, oldest first, into out[0..n), and returns how
  // many. One release store frees all their slots.
  [[nodiscard]] std::size_t pop_bulk(T* out, std::size_t n) noexcept {
    const std::size_t tail = tail_.load(std::memory_order_relaxed);
    if (cached_head_ - tail < n) {
      cached_head_ = head_.load(std::memory_order_acquire);
    }
    n = std::min(n, cached_head_ - tail);
    if (n == 0) {
      return 0;
    }
    for (std::size_t i = 0; i < n; ++i) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index,cppcoreguidelines-pro-bounds-pointer-arithmetic)
      out[i] = buf_[(tail + i) & kMask];
    }
    tail_.store(tail + n, std::memory_order_release);
    return n;
  }

  // Consumer thread only: whether there is nothing to pop, read afresh -- for a consumer deciding
  // whether it may sleep. The acquire makes a "no" safe to act on at once with a pop.
  [[nodiscard]] bool empty() const noexcept {
    return head_.load(std::memory_order_acquire) == tail_.load(std::memory_order_relaxed);
  }

  // [phase 16] Producer thread only: how many of want elements a push_bulk would take now. The
  // stale view of tail_ is reloaded only when it says there is less room than wanted, as in
  // push_bulk; it can only under-report, so a push of that many always succeeds.
  [[nodiscard]] std::size_t room(std::size_t want) noexcept {
    const std::size_t head = head_.load(std::memory_order_relaxed);
    if (N - (head - cached_tail_) < want) {
      cached_tail_ = tail_.load(std::memory_order_acquire);
    }
    return std::min(want, N - (head - cached_tail_));
  }

  [[nodiscard]] static constexpr std::size_t capacity() noexcept { return N; }

 private:
  static constexpr std::size_t kMask = N - 1;

  alignas(64) std::atomic<std::size_t> head_{0};  // written by the producer
  alignas(64) std::atomic<std::size_t> tail_{0};  // written by the consumer
  alignas(64) std::size_t cached_tail_{0};        // the producer's stale view of tail_
  std::size_t cached_head_{0};                    // the consumer's stale view of head_
  alignas(64) std::array<T, N> buf_{};
};

}  // namespace npf::core
