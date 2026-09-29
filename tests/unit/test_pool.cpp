#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <new>
#include <npf/core/packet.hpp>
#include <npf/core/pool.hpp>
#include <set>
#include <stdexcept>
#include <vector>

#include "support/alloc_counter.hpp"

namespace {

using npf::core::kHeadroom;
using npf::core::kMaxFrame;
using npf::core::Packet;
using npf::core::PacketPool;
using npf::test::AllocCounter;

static_assert(sizeof(Packet) <= 64);

// --- the counter itself --------------------------------------------------------------------------
// Every zero-allocation assertion below is only as good as the counter behind it. These prove the
// replacement operators are linked into this binary and see each form the pool could use.

TEST(AllocCounter, CountsEveryAllocationAndDeallocation) {
  AllocCounter::reset();
  // volatile: the compiler may not elide an allocation whose result it must actually store.
  int* volatile scalar = new int{1};
  delete scalar;
  void* volatile raw = ::operator new(24);
  ::operator delete(raw);
  void* volatile aligned = ::operator new(4096, std::align_val_t{64});
  ::operator delete(aligned, std::align_val_t{64});
  void* volatile block = ::operator new[](16, std::nothrow);
  ::operator delete[](block);
  EXPECT_EQ(AllocCounter::allocations(), 4U);
  EXPECT_EQ(AllocCounter::deallocations(), 4U);
}

TEST(AllocCounter, SeesThePoolsOneAllocation) {
  AllocCounter::reset();
  {
    const PacketPool pool(16);
    EXPECT_EQ(AllocCounter::allocations(), 1U);
  }
  EXPECT_EQ(AllocCounter::deallocations(), 1U);
}

// --- the phase 1 exit test (docs/BUILD_PLAN.md), plus its deallocation twin ----------------------

TEST(Pool, ZeroAllocationsInSteadyState) {
  PacketPool pool(1024);
  AllocCounter::reset();
  for (int i = 0; i < 1'000'000; ++i) {
    Packet* p = pool.acquire();
    ASSERT_NE(p, nullptr);
    p->resize(64);
    ASSERT_NE(p->push(14), nullptr);
    ASSERT_TRUE(p->pull(14));
    pool.release(p);
  }
  EXPECT_EQ(AllocCounter::allocations(), 0u);
  EXPECT_EQ(AllocCounter::deallocations(), 0U);
  EXPECT_EQ(pool.available(), pool.capacity());
}

TEST(Pool, ExhaustionReturnsNullRatherThanGrowing) {
  PacketPool pool(8);
  std::array<Packet*, 8> held{};
  AllocCounter::reset();
  for (Packet*& p : held) {
    p = pool.acquire();
    ASSERT_NE(p, nullptr);
  }
  EXPECT_EQ(pool.available(), 0U);
  EXPECT_EQ(pool.acquire(), nullptr);
  EXPECT_EQ(pool.acquire(), nullptr);  // a failed acquire changes nothing
  EXPECT_EQ(AllocCounter::allocations(), 0U);
  EXPECT_EQ(pool.capacity(), 8U);

  const std::set<Packet*> distinct(held.begin(), held.end());
  EXPECT_EQ(distinct.size(), held.size());
  for (Packet* p : held) {
    pool.release(p);
  }
  EXPECT_EQ(pool.available(), pool.capacity());
}

TEST(Pool, AvailableCountsPacketsNotHandedOut) {
  PacketPool pool(3);
  EXPECT_EQ(pool.available(), 3U);
  Packet* a = pool.acquire();
  Packet* b = pool.acquire();
  EXPECT_EQ(pool.available(), 1U);
  pool.release(a);
  EXPECT_EQ(pool.available(), 2U);
  pool.release(b);
  EXPECT_EQ(pool.available(), 3U);
}

TEST(Pool, MostRecentlyReleasedPacketIsReusedFirst) {
  PacketPool pool(4);
  Packet* a = pool.acquire();
  Packet* b = pool.acquire();
  pool.release(a);
  pool.release(b);
  // LIFO: the buffer handed out next is the one most likely to still be in cache.
  Packet* first = pool.acquire();
  Packet* second = pool.acquire();
  EXPECT_EQ(first, b);
  EXPECT_EQ(second, a);
  pool.release(first);
  pool.release(second);
}

TEST(Pool, AcquiredPacketIsEmptyWithFullHeadroomAndNoMetadata) {
  PacketPool pool(1);
  Packet* p = pool.acquire();
  ASSERT_NE(p, nullptr);
  p->resize(100);
  ASSERT_TRUE(p->pull(20));
  p->set_in_port(7);
  p->set_rx_tsc(12345);
  p->set_offsets(14, 34);
  pool.release(p);

  Packet* q = pool.acquire();
  ASSERT_EQ(q, p);  // a pool of one can only hand the same packet back
  EXPECT_EQ(q->size(), 0U);
  EXPECT_EQ(q->in_port(), 0);
  EXPECT_EQ(q->rx_tsc(), 0U);
  EXPECT_EQ(q->l3_offset(), 0);
  EXPECT_EQ(q->l4_offset(), 0);
  EXPECT_NE(q->push(kHeadroom), nullptr);  // all of the headroom is back
  EXPECT_EQ(q->push(1), nullptr);
  pool.release(q);
}

// Stamps the whole of every buffer, headroom included, then checks each stamp survived. Catches
// slot arithmetic that lets buffers overlap each other or the next packet's metadata; ASan catches
// the last buffer running off the end of the allocation.
TEST(Pool, EveryPacketOwnsAWholeBufferOfItsOwn) {
  PacketPool pool(64);
  std::vector<Packet*> held;
  for (Packet* p = pool.acquire(); p != nullptr; p = pool.acquire()) {
    held.push_back(p);
  }
  ASSERT_EQ(held.size(), pool.capacity());
  for (std::size_t i = 0; i < held.size(); ++i) {
    ASSERT_NE(held[i]->push(kHeadroom), nullptr);
    held[i]->resize(kMaxFrame);
    ASSERT_EQ(held[i]->size(), kMaxFrame);
    for (std::byte& b : held[i]->data()) {
      b = static_cast<std::byte>(i);
    }
  }
  for (std::size_t i = 0; i < held.size(); ++i) {
    ASSERT_EQ(held[i]->size(), kMaxFrame) << "metadata of packet " << i << " was overwritten";
    for (const std::byte b : held[i]->data()) {
      ASSERT_EQ(b, static_cast<std::byte>(i)) << "buffer of packet " << i << " was overwritten";
    }
  }
  for (Packet* p : held) {
    pool.release(p);
  }
}

TEST(Pool, PacketMetadataStartsOnACacheLine) {
  PacketPool pool(16);
  std::vector<Packet*> held;
  for (Packet* p = pool.acquire(); p != nullptr; p = pool.acquire()) {
    EXPECT_EQ(reinterpret_cast<std::uintptr_t>(p) % 64, 0U);
    held.push_back(p);
  }
  for (Packet* p : held) {
    pool.release(p);
  }
}

TEST(Pool, RejectsZeroCapacity) {
  EXPECT_THROW(PacketPool pool(0), std::invalid_argument);
}

// --- Packet
// ---------------------------------------------------------------------------------------

TEST(Packet, PushPastHeadroomReturnsNull) {
  PacketPool pool(1);
  Packet* p = pool.acquire();
  ASSERT_NE(p, nullptr);
  p->resize(64);
  EXPECT_EQ(p->push(kHeadroom + 1), nullptr);
  EXPECT_EQ(p->size(), 64U);  // a refused push changes nothing
  std::byte* start = p->push(kHeadroom);
  ASSERT_NE(start, nullptr);
  EXPECT_EQ(start, p->data().data());
  EXPECT_EQ(p->size(), 64U + kHeadroom);
  EXPECT_EQ(p->push(1), nullptr);  // the headroom is used up
  pool.release(p);
}

TEST(Packet, PullPastSizeReturnsFalse) {
  PacketPool pool(1);
  Packet* p = pool.acquire();
  ASSERT_NE(p, nullptr);
  p->resize(20);
  EXPECT_FALSE(p->pull(21));
  EXPECT_EQ(p->size(), 20U);  // a refused pull changes nothing
  EXPECT_TRUE(p->pull(20));
  EXPECT_EQ(p->size(), 0U);
  EXPECT_FALSE(p->pull(1));
  pool.release(p);
}

TEST(Packet, PushAfterPullReclaimsTheSameBytesWithoutCopying) {
  PacketPool pool(1);
  Packet* p = pool.acquire();
  ASSERT_NE(p, nullptr);
  p->resize(64);
  const std::byte* frame_start = p->data().data();
  p->data()[14] = std::byte{0x45};  // where an IPv4 header would begin
  ASSERT_TRUE(p->pull(14));
  EXPECT_EQ(p->data()[0], std::byte{0x45});
  EXPECT_EQ(p->size(), 50U);
  ASSERT_EQ(p->push(14), frame_start);
  EXPECT_EQ(p->data()[14], std::byte{0x45});
  EXPECT_EQ(p->size(), 64U);
  pool.release(p);
}

TEST(Packet, ResizeCanFillTheBufferFromTheCurrentStart) {
  PacketPool pool(1);
  Packet* p = pool.acquire();
  ASSERT_NE(p, nullptr);
  p->resize(kMaxFrame - kHeadroom);
  EXPECT_EQ(p->size(), kMaxFrame - kHeadroom);
  ASSERT_TRUE(p->pull(10));
  p->resize(kMaxFrame - kHeadroom - 10);
  EXPECT_EQ(p->size(), kMaxFrame - kHeadroom - 10);
  pool.release(p);
}

TEST(Packet, CapacityIsTheRoomFromTheCurrentStartToTheEndOfTheBuffer) {
  PacketPool pool(1);
  Packet* p = pool.acquire();
  ASSERT_NE(p, nullptr);
  EXPECT_EQ(p->capacity(), kMaxFrame - kHeadroom);
  p->resize(20);
  EXPECT_EQ(p->capacity(), kMaxFrame - kHeadroom);  // the frame's length does not change it
  ASSERT_NE(p->push(10), nullptr);
  EXPECT_EQ(p->capacity(), kMaxFrame - kHeadroom + 10);
  ASSERT_TRUE(p->pull(15));
  EXPECT_EQ(p->capacity(), kMaxFrame - kHeadroom - 5);
  p->resize(p->capacity());  // exactly capacity() is accepted
  EXPECT_EQ(p->size(), p->capacity());
  pool.release(p);
}

// --- misuse: asserted in debug builds
// -------------------------------------------------------------

TEST(PacketDeathTest, ResizeBeyondTheBufferIsCaughtOrClamped) {
  PacketPool pool(1);
  Packet* p = pool.acquire();
  ASSERT_NE(p, nullptr);
#ifdef NDEBUG
  p->resize(kMaxFrame);  // release builds clamp instead of creating a view past the buffer
  EXPECT_EQ(p->size(), kMaxFrame - kHeadroom);
#else
  EXPECT_DEATH(p->resize(kMaxFrame), "beyond the end of the buffer");
#endif
  pool.release(p);
}

TEST(PoolDeathTest, DoubleReleaseIsCaughtInDebugBuilds) {
#ifdef NDEBUG
  GTEST_SKIP() << "assertions are compiled out in this build (NDEBUG)";
#else
  PacketPool pool(2);
  Packet* p = pool.acquire();
  ASSERT_NE(p, nullptr);
  pool.release(p);
  EXPECT_DEATH(pool.release(p), "double release");
#endif
}

TEST(PoolDeathTest, ReleaseToTheWrongPoolIsCaughtInDebugBuilds) {
#ifdef NDEBUG
  GTEST_SKIP() << "assertions are compiled out in this build (NDEBUG)";
#else
  PacketPool mine(1);
  PacketPool other(1);
  Packet* p = mine.acquire();
  ASSERT_NE(p, nullptr);
  EXPECT_DEATH(other.release(p), "does not belong to this pool");
  mine.release(p);
#endif
}

}  // namespace
