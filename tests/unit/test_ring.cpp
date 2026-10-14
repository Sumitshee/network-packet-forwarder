#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <npf/core/ring.hpp>
#include <thread>
#include <vector>

namespace {

using npf::core::SpscRing;

// --- one thread: the edge cases ------------------------------------------------------------------

TEST(SpscRing, StartsEmpty) {
  SpscRing<int, 8> ring;
  int out = -1;
  EXPECT_TRUE(ring.empty());
  EXPECT_FALSE(ring.pop(out));
  EXPECT_EQ(out, -1);  // untouched
  EXPECT_EQ(ring.capacity(), 8U);
}

TEST(SpscRing, PopsInPushOrder) {
  SpscRing<int, 8> ring;
  for (int i = 0; i < 5; ++i) {
    ASSERT_TRUE(ring.push(i));
  }
  EXPECT_FALSE(ring.empty());
  for (int i = 0; i < 5; ++i) {
    int out = -1;
    ASSERT_TRUE(ring.pop(out));
    EXPECT_EQ(out, i);
  }
  EXPECT_TRUE(ring.empty());
}

TEST(SpscRing, HoldsExactlyCapacityThenRefuses) {
  SpscRing<int, 8> ring;
  for (int i = 0; i < 8; ++i) {
    ASSERT_TRUE(ring.push(i)) << i;
  }
  EXPECT_FALSE(ring.push(99));
  int out = -1;
  ASSERT_TRUE(ring.pop(out));
  EXPECT_EQ(out, 0);
  EXPECT_TRUE(ring.push(8));  // one slot freed, one slot taken
  EXPECT_FALSE(ring.push(100));
  for (int i = 1; i <= 8; ++i) {
    ASSERT_TRUE(ring.pop(out));
    EXPECT_EQ(out, i);
  }
  EXPECT_FALSE(ring.pop(out));
}

// Many laps round an 8-slot ring, with the fill level moving, so the indexes cross the
// power-of-two boundary at every offset into the array.
TEST(SpscRing, WrapsAroundThePowerOfTwoBoundary) {
  SpscRing<std::uint32_t, 8> ring;
  std::uint32_t next_in = 0;
  std::uint32_t next_out = 0;
  for (int round = 0; round < 200; ++round) {
    const int pushes = 1 + (round % 7);
    for (int i = 0; i < pushes; ++i) {
      if (ring.push(next_in)) {
        ++next_in;
      }
    }
    const int pops = 1 + ((round * 3) % 8);
    for (int i = 0; i < pops; ++i) {
      std::uint32_t out = 0;
      if (!ring.pop(out)) {
        break;
      }
      ASSERT_EQ(out, next_out);
      ++next_out;
    }
  }
  EXPECT_GT(next_in, 8U * 50);  // it really did lap
  std::uint32_t out = 0;
  while (ring.pop(out)) {
    ASSERT_EQ(out, next_out);
    ++next_out;
  }
  EXPECT_EQ(next_out, next_in);
}

TEST(SpscRing, PushBulkTakesWhatFits) {
  SpscRing<int, 8> ring;
  const std::array<int, 6> first{0, 1, 2, 3, 4, 5};
  EXPECT_EQ(ring.push_bulk(first.data(), first.size()), 6U);
  const std::array<int, 6> second{6, 7, 8, 9, 10, 11};
  EXPECT_EQ(ring.push_bulk(second.data(), second.size()), 2U);  // 2 slots left
  EXPECT_EQ(ring.push_bulk(second.data(), second.size()), 0U);  // none
  EXPECT_EQ(ring.push_bulk(second.data(), 0), 0U);
  std::array<int, 16> out{};
  EXPECT_EQ(ring.pop_bulk(out.data(), out.size()), 8U);
  for (int i = 0; i < 8; ++i) {
    EXPECT_EQ(out.at(static_cast<std::size_t>(i)), i);
  }
}

TEST(SpscRing, PopBulkTakesWhatThereIs) {
  SpscRing<int, 8> ring;
  std::array<int, 4> out{};
  EXPECT_EQ(ring.pop_bulk(out.data(), out.size()), 0U);
  ASSERT_TRUE(ring.push(1));
  ASSERT_TRUE(ring.push(2));
  ASSERT_TRUE(ring.push(3));
  EXPECT_EQ(ring.pop_bulk(out.data(), 2), 2U);
  EXPECT_EQ(out[0], 1);
  EXPECT_EQ(out[1], 2);
  EXPECT_EQ(ring.pop_bulk(out.data(), out.size()), 1U);
  EXPECT_EQ(out[0], 3);
  EXPECT_TRUE(ring.empty());
}

// The bulk calls wrap mid-batch: a batch that starts at slot 6 of 8 continues at slot 0.
TEST(SpscRing, BulkCallsWrapMidBatch) {
  SpscRing<int, 8> ring;
  std::array<int, 8> out{};
  const std::array<int, 6> six{0, 1, 2, 3, 4, 5};
  ASSERT_EQ(ring.push_bulk(six.data(), six.size()), 6U);
  ASSERT_EQ(ring.pop_bulk(out.data(), 6), 6U);
  const std::array<int, 5> five{10, 11, 12, 13, 14};
  ASSERT_EQ(ring.push_bulk(five.data(), five.size()), 5U);  // slots 6, 7, 0, 1, 2
  ASSERT_EQ(ring.pop_bulk(out.data(), out.size()), 5U);
  for (std::size_t i = 0; i < five.size(); ++i) {
    EXPECT_EQ(out.at(i), five.at(i));
  }
}

// --- two threads
// ----------------------------------------------------------------------------------

constexpr std::uint64_t kCount = 4'000'000;

// The plan's test: every integer arrives exactly once, in order, none lost, none duplicated.
// Run under ThreadSanitizer (the tsan preset) and AddressSanitizer as well as plainly.
TEST(SpscRingThreads, FourMillionIntegersArriveOnceAndInOrder) {
  auto ring = std::make_unique<SpscRing<std::uint64_t, 1024>>();
  std::thread producer([&ring] {
    for (std::uint64_t i = 0; i < kCount; ++i) {
      while (!ring->push(i)) {
        std::this_thread::yield();
      }
    }
  });
  std::uint64_t expected = 0;
  bool in_order = true;
  while (expected < kCount) {
    std::uint64_t v = 0;
    if (!ring->pop(v)) {
      std::this_thread::yield();
      continue;
    }
    in_order = in_order && v == expected;
    ++expected;
  }
  producer.join();
  EXPECT_TRUE(in_order);
  std::uint64_t extra = 0;
  EXPECT_FALSE(ring->pop(extra)) << "an element arrived twice";
}

// The same through the bulk calls, with batch sizes that keep changing on both sides, so partial
// results are the rule rather than the exception.
TEST(SpscRingThreads, FourMillionIntegersThroughBulkCalls) {
  auto ring = std::make_unique<SpscRing<std::uint64_t, 1024>>();
  std::thread producer([&ring] {
    std::array<std::uint64_t, 64> batch{};
    std::uint64_t next = 0;
    std::size_t size = 1;
    while (next < kCount) {
      const std::size_t n = std::min<std::uint64_t>(size, kCount - next);
      for (std::size_t i = 0; i < n; ++i) {
        batch.at(i) = next + i;
      }
      const std::size_t pushed = ring->push_bulk(batch.data(), n);
      next += pushed;
      if (pushed == 0) {
        std::this_thread::yield();
      }
      size = size % 64 + 1;
    }
  });
  std::array<std::uint64_t, 64> got{};
  std::uint64_t expected = 0;
  std::uint64_t misplaced = 0;
  std::size_t size = 37;
  while (expected < kCount) {
    const std::size_t n = ring->pop_bulk(got.data(), size);
    for (std::size_t i = 0; i < n; ++i) {
      misplaced += got.at(i) == expected ? 0U : 1U;
      ++expected;
    }
    if (n == 0) {
      std::this_thread::yield();
    }
    size = size % 64 + 1;
  }
  producer.join();
  EXPECT_EQ(misplaced, 0U);
  EXPECT_TRUE(ring->empty());
}

// What the release store publishes is the slot's contents and everything they point to: here a
// record written, non-atomically, just before its pointer is pushed. ThreadSanitizer reports a
// data race on the record if head_ is ever stored relaxed; a plain build checks the values.
TEST(SpscRingThreads, PublishesWhatTheSlotPointsTo) {
  struct Record {
    std::uint64_t id;
    std::array<std::uint64_t, 7> words;
  };
  constexpr std::size_t kRecords = 200'000;
  std::vector<Record> records(kRecords);
  auto ring = std::make_unique<SpscRing<Record*, 64>>();
  std::thread producer([&] {
    for (std::size_t i = 0; i < kRecords; ++i) {
      Record& r = records[i];
      r.id = i;
      r.words.fill(i * 3);
      while (!ring->push(&r)) {
        std::this_thread::yield();
      }
    }
  });
  std::size_t seen = 0;
  std::size_t wrong = 0;
  while (seen < kRecords) {
    Record* r = nullptr;
    if (!ring->pop(r)) {
      std::this_thread::yield();
      continue;
    }
    wrong += r->id == seen && r->words[6] == seen * 3 ? 0U : 1U;
    ++seen;
  }
  producer.join();
  EXPECT_EQ(wrong, 0U);
}

}  // namespace
