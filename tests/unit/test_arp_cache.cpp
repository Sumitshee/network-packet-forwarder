#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <npf/core/packet.hpp>
#include <npf/core/pool.hpp>
#include <npf/proto/mac.hpp>
#include <npf/table/arp_cache.hpp>
#include <optional>
#include <ostream>
#include <stdexcept>
#include <utility>
#include <vector>

#include "support/alloc_counter.hpp"
#include "support/proto_helpers.hpp"

namespace npf::table {

// Found by argument-dependent lookup, so GoogleTest prints names instead of numbers.
void PrintTo(ArpState s, std::ostream* os) {
  constexpr std::array<const char*, 3> kNames{"Incomplete", "Reachable", "Stale"};
  *os << kNames.at(static_cast<std::size_t>(s));
}

}  // namespace npf::table

namespace {

using npf::core::Packet;
using npf::core::PacketPool;
using npf::proto::MacAddr;
using npf::table::ArpCache;
using npf::table::ArpNeighbour;
using npf::table::ArpState;
using npf::table::kArpMaxProbes;
using npf::table::kArpQueueDepth;
using npf::table::kArpReachable;
using npf::table::kArpStaleTimeout;
using npf::test::AllocCounter;
using npf::test::ip4;
using std::chrono::milliseconds;
using std::chrono::seconds;

using Packets = std::vector<Packet*>;
using Request = std::pair<std::uint32_t, std::uint16_t>;  // target address, port
using TimePoint = std::chrono::steady_clock::time_point;

constexpr std::uint32_t kNeighbour = ip4(10, 0, 2, 2);
constexpr std::uint32_t kOther = ip4(10, 0, 2, 3);
constexpr std::uint16_t kPort = 1;
constexpr MacAddr kMac{{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02}};
constexpr MacAddr kNewMac{{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x03}};
constexpr TimePoint kT0{std::chrono::hours{1}};
constexpr std::size_t kPoolSize = 16;
constexpr std::size_t kCapacity = 4;

// The build plan's mock ArpEvents: it records every call, and releases what the cache lets go
// of, as the router does.
class RecordingEvents final : public npf::table::ArpEvents {
 public:
  explicit RecordingEvents(PacketPool& pool) : pool_{&pool} {
    // So that recording never allocates in a test that counts allocations.
    requests.reserve(64);
    heads.reserve(16);
    discarded.reserve(16);
  }

  void send_arp_request(std::uint32_t target_ip, std::uint16_t out_port) override {
    requests.emplace_back(target_ip, out_port);
  }
  void unresolved(Packet* p) override {
    heads.push_back(p);
    pool_->release(p);
  }
  void discard(Packet* p) override {
    discarded.push_back(p);
    pool_->release(p);
  }

  std::vector<Request> requests;
  Packets heads;      // given to unresolved(), in order
  Packets discarded;  // given to discard(), in order

 private:
  PacketPool* pool_;
};

class ArpCacheTest : public ::testing::Test {
 protected:
  ArpCacheTest() {
    ready_.reserve(kArpQueueDepth);
    cache_.tick(kT0);
  }

  // Exit test item 5, for every test: each buffer is back in the pool by the end, released by the
  // test after on_reply() handed it back, as a transmitter would, or let go of through the events.
  // Checked before the cache's destructor could tidy anything up.
  ~ArpCacheTest() override { EXPECT_EQ(pool_.available(), kPoolSize); }

  ArpCacheTest(const ArpCacheTest&) = delete;
  ArpCacheTest& operator=(const ArpCacheTest&) = delete;
  ArpCacheTest(ArpCacheTest&&) = delete;
  ArpCacheTest& operator=(ArpCacheTest&&) = delete;

  Packet* packet() {
    Packet* p = pool_.acquire();
    if (p == nullptr) {
      throw std::runtime_error("the test pool is too small");
    }
    return p;
  }

  // n new packets queued for ip, oldest first.
  Packets queue(std::size_t n, std::uint32_t ip = kNeighbour) {
    Packets queued;
    for (std::size_t i = 0; i < n; ++i) {
      Packet* p = packet();
      EXPECT_TRUE(cache_.resolve_and_queue(ip, kPort, p));
      queued.push_back(p);
    }
    return queued;
  }

  // on_reply(), then the packets it hands back are sent: released, as the backend would after
  // transmitting them. Returns them, in the order handed back.
  Packets reply(std::uint32_t ip, MacAddr mac) {
    cache_.on_reply(ip, mac, ready_);
    Packets sent(ready_.begin(), ready_.end());
    for (Packet* p : ready_) {
      pool_.release(p);
    }
    ready_.clear();
    return sent;
  }

  // A neighbour asked for and answered, now.
  void resolve(std::uint32_t ip = kNeighbour, MacAddr mac = kMac) {
    queue(1, ip);
    EXPECT_EQ(reply(ip, mac).size(), 1U);
  }

  [[nodiscard]] std::optional<ArpState> state(std::uint32_t ip = kNeighbour) const {
    const std::optional<ArpNeighbour> n = cache_.peek(ip);
    return n ? std::optional<ArpState>{n->state} : std::nullopt;
  }

  PacketPool pool_{kPoolSize};
  RecordingEvents events_{pool_};
  ArpCache cache_{events_, kCapacity};
  Packets ready_;
};

// --- the build plan's exit test: items 1 to 7 (item 5 is the fixture's destructor) --------------

TEST_F(ArpCacheTest, Item1ThreePacketsQueueBehindOneProbe) {
  const Packets queued = queue(3);
  EXPECT_EQ(events_.requests, (std::vector<Request>{{kNeighbour, kPort}}));
  const std::optional<ArpNeighbour> n = cache_.peek(kNeighbour);
  ASSERT_TRUE(n.has_value());
  EXPECT_EQ(n->state, ArpState::Incomplete);
  EXPECT_EQ(n->queued, 3U);
  EXPECT_EQ(n->port, kPort);
  EXPECT_FALSE(cache_.lookup(kNeighbour).has_value());  // nothing to forward on yet
  EXPECT_EQ(pool_.available(), kPoolSize - 3);
  cache_.flush();
  EXPECT_EQ(events_.discarded, queued);
}

TEST_F(ArpCacheTest, Item2AFourthPacketIsRefusedAndAsksNothing) {
  const Packets queued = queue(3);
  Packet* fourth = packet();
  EXPECT_FALSE(cache_.resolve_and_queue(kNeighbour, kPort, fourth));
  EXPECT_EQ(cache_.peek(kNeighbour)->queued, 3U);
  EXPECT_EQ(events_.requests.size(), 1U);
  pool_.release(fourth);  // refused, so still the caller's: dropped as ArpUnresolved
  cache_.flush();
  EXPECT_EQ(events_.discarded, queued);
}

TEST_F(ArpCacheTest, Item3AReplyHandsBackEveryQueuedPacketInOrder) {
  const Packets queued = queue(3);
  EXPECT_EQ(reply(kNeighbour, kMac), queued);
  EXPECT_EQ(state(), ArpState::Reachable);
  EXPECT_EQ(cache_.peek(kNeighbour)->queued, 0U);
  EXPECT_EQ(cache_.lookup(kNeighbour), kMac);
  EXPECT_TRUE(events_.heads.empty());
  EXPECT_TRUE(events_.discarded.empty());
}

TEST_F(ArpCacheTest, Item4ThreeUnansweredProbesGiveUpOnTheQueue) {
  const Packets queued = queue(3);  // the first probe goes now, at kT0
  cache_.tick(kT0 + seconds{1} - milliseconds{1});
  EXPECT_EQ(events_.requests.size(), 1U);  // one a second, no faster
  cache_.tick(kT0 + seconds{1});
  cache_.tick(kT0 + seconds{2});
  EXPECT_EQ(events_.requests, std::vector<Request>(kArpMaxProbes, {kNeighbour, kPort}));
  cache_.tick(kT0 + seconds{3} - milliseconds{1});  // the last probe still has time
  EXPECT_TRUE(events_.heads.empty());
  EXPECT_EQ(pool_.available(), kPoolSize - 3);

  cache_.tick(kT0 + seconds{3});
  EXPECT_EQ(events_.heads, Packets{queued[0]});  // exactly one unresolved(), for the head
  EXPECT_EQ(events_.discarded, (Packets{queued[1], queued[2]}));
  EXPECT_EQ(pool_.available(), kPoolSize);            // all three buffers released
  EXPECT_FALSE(cache_.peek(kNeighbour).has_value());  // and the entry deleted
  EXPECT_EQ(events_.requests.size(), kArpMaxProbes);  // no fourth probe
}

TEST_F(ArpCacheTest, Item6UnsolicitedArpForAnUnknownAddressCreatesNothing) {
  resolve();
  cache_.on_unsolicited(kOther, kNewMac);
  EXPECT_EQ(cache_.size(), 1U);
  EXPECT_FALSE(cache_.peek(kOther).has_value());
  EXPECT_FALSE(cache_.lookup(kOther).has_value());
}

TEST_F(ArpCacheTest, Item7UnsolicitedArpRefreshesAKnownEntry) {
  resolve();  // answered at kT0
  cache_.tick(kT0 + kArpReachable);
  ASSERT_EQ(state(), ArpState::Stale);
  cache_.on_unsolicited(kNeighbour, kNewMac);
  EXPECT_EQ(state(), ArpState::Reachable);
  EXPECT_EQ(cache_.lookup(kNeighbour), kNewMac);  // the MAC updated; and used, so not idle
  // The timer restarted with the announcement: Reachable for kArpReachable from then.
  cache_.tick(kT0 + 2 * kArpReachable - milliseconds{1});
  EXPECT_EQ(state(), ArpState::Reachable);
  cache_.tick(kT0 + 2 * kArpReachable);
  EXPECT_EQ(state(), ArpState::Stale);
  EXPECT_EQ(cache_.size(), 1U);
  EXPECT_EQ(events_.requests.size(), 1U);  // none of that asked anything
}

// --- the rest of the state machine ---------------------------------------------------------------

TEST_F(ArpCacheTest, AReachableHitReturnsTheMacAndAsksNothing) {
  resolve();
  EXPECT_EQ(cache_.lookup(kNeighbour), kMac);
  EXPECT_EQ(cache_.lookup(kNeighbour), kMac);
  EXPECT_EQ(events_.requests.size(), 1U);
}

TEST_F(ArpCacheTest, TrafficDoesNotKeepAnEntryReachable) {
  resolve();
  cache_.tick(kT0 + kArpReachable - milliseconds{1});
  EXPECT_EQ(cache_.lookup(kNeighbour), kMac);
  EXPECT_EQ(state(), ArpState::Reachable);
  cache_.tick(kT0 + kArpReachable);
  EXPECT_EQ(state(), ArpState::Stale);  // used a moment ago, but not heard from for 30 s
}

TEST_F(ArpCacheTest, AStaleHitForwardsNowAndRevalidates) {
  resolve();
  cache_.tick(kT0 + kArpReachable);
  ASSERT_EQ(state(), ArpState::Stale);
  EXPECT_EQ(cache_.lookup(kNeighbour), kMac);  // forward now...
  EXPECT_EQ(events_.requests.size(), 2U);      // ...and ask in the background
  EXPECT_EQ(cache_.lookup(kNeighbour), kMac);
  EXPECT_EQ(events_.requests.size(), 2U);  // one probe, however many packets
  EXPECT_TRUE(reply(kNeighbour, kNewMac).empty());
  EXPECT_EQ(state(), ArpState::Reachable);
  EXPECT_EQ(cache_.lookup(kNeighbour), kNewMac);
}

TEST_F(ArpCacheTest, AnUnansweredRevalidationDeletesTheEntry) {
  resolve();
  const TimePoint stale = kT0 + kArpReachable;
  cache_.tick(stale);
  EXPECT_EQ(cache_.lookup(kNeighbour), kMac);  // the revalidation's first probe
  cache_.tick(stale + seconds{1});
  cache_.tick(stale + seconds{2});
  EXPECT_EQ(events_.requests.size(), 1U + kArpMaxProbes);
  EXPECT_EQ(cache_.lookup(kNeighbour), kMac);  // still forwarding meanwhile
  cache_.tick(stale + seconds{3});
  EXPECT_FALSE(cache_.peek(kNeighbour).has_value());
  EXPECT_TRUE(events_.heads.empty());  // nothing was waiting on it, so no one to tell
}

TEST_F(ArpCacheTest, SixtySecondsIdleDeletesTheEntry) {
  resolve();  // and last used now, by the packet that asked
  cache_.tick(kT0 + kArpStaleTimeout - milliseconds{1});
  EXPECT_EQ(state(), ArpState::Stale);
  cache_.tick(kT0 + kArpStaleTimeout);
  EXPECT_FALSE(cache_.peek(kNeighbour).has_value());
  EXPECT_EQ(events_.requests.size(), 1U);  // gone without a probe: nobody was using it
}

TEST_F(ArpCacheTest, AHitRestartsTheIdleTimer) {
  resolve();
  const TimePoint used = kT0 + seconds{20};
  cache_.tick(used);
  EXPECT_EQ(cache_.lookup(kNeighbour), kMac);
  cache_.tick(used + kArpStaleTimeout - milliseconds{1});
  EXPECT_TRUE(cache_.peek(kNeighbour).has_value());
  cache_.tick(used + kArpStaleTimeout);
  EXPECT_FALSE(cache_.peek(kNeighbour).has_value());
}

TEST_F(ArpCacheTest, AReplyNobodyAskedForCreatesNothing) {
  EXPECT_TRUE(reply(kOther, kNewMac).empty());
  EXPECT_EQ(cache_.size(), 0U);
}

// RFC 1812 §3.3.2. Believed, it would send the neighbour's traffic to every station on the segment.
TEST_F(ArpCacheTest, NoAnswerNamingABroadcastOrMulticastMacIsBelieved) {
  const Packets queued = queue(2);
  for (const MacAddr bad :
       {npf::proto::kBroadcastMac, MacAddr{{0x01, 0x00, 0x5E, 0x00, 0x00, 0x01}}}) {
    EXPECT_TRUE(reply(kNeighbour, bad).empty());
    EXPECT_EQ(state(), ArpState::Incomplete);
  }
  EXPECT_EQ(reply(kNeighbour, kMac), queued);  // the real answer still completes it
  cache_.on_unsolicited(kNeighbour, npf::proto::kBroadcastMac);
  EXPECT_EQ(cache_.lookup(kNeighbour), kMac);
}

TEST_F(ArpCacheTest, AnAnnouncementDoesNotCompleteAnEntryStillAsking) {
  const Packets queued = queue(2);
  cache_.on_unsolicited(kNeighbour, kMac);
  EXPECT_EQ(state(), ArpState::Incomplete);
  EXPECT_EQ(cache_.peek(kNeighbour)->queued, 2U);  // only on_reply() can hand them back
  EXPECT_EQ(reply(kNeighbour, kMac), queued);
}

TEST_F(ArpCacheTest, EachNeighbourHasItsOwnQueueAndPort) {
  const Packets first = queue(3, kNeighbour);
  Packet* other = packet();
  ASSERT_TRUE(cache_.resolve_and_queue(kOther, 0, other));
  EXPECT_EQ(events_.requests, (std::vector<Request>{{kNeighbour, kPort}, {kOther, 0}}));
  EXPECT_EQ(reply(kOther, kNewMac), Packets{other});
  EXPECT_EQ(state(kNeighbour), ArpState::Incomplete);
  EXPECT_EQ(reply(kNeighbour, kMac), first);
}

TEST_F(ArpCacheTest, StaticEntriesNeverAgeAndIgnoreWhatTheyHear) {
  cache_.insert_static(kNeighbour, kMac, kPort);
  cache_.tick(kT0 + std::chrono::hours{24});
  EXPECT_EQ(state(), ArpState::Reachable);
  EXPECT_TRUE(reply(kNeighbour, kNewMac).empty());
  cache_.on_unsolicited(kNeighbour, kNewMac);
  EXPECT_EQ(cache_.lookup(kNeighbour), kMac);
  cache_.flush();
  ASSERT_TRUE(cache_.peek(kNeighbour).has_value());
  EXPECT_TRUE(cache_.peek(kNeighbour)->is_static);
  EXPECT_TRUE(events_.requests.empty());
}

TEST_F(ArpCacheTest, FlushDiscardsEveryQueueAndKeepsOnlyStaticEntries) {
  cache_.insert_static(kOther, kNewMac, 0);
  resolve(ip4(10, 0, 2, 4));
  const Packets queued = queue(2);
  cache_.flush();
  EXPECT_EQ(events_.discarded, queued);
  EXPECT_TRUE(events_.heads.empty());  // a flush earns nobody an ICMP error
  EXPECT_EQ(cache_.size(), 1U);
  EXPECT_TRUE(cache_.peek(kOther).has_value());
}

TEST_F(ArpCacheTest, AFullCacheRefusesANewNeighbourWithoutAsking) {
  for (std::uint32_t i = 0; i < kCapacity; ++i) {
    resolve(ip4(10, 0, 2, 10 + i));
  }
  Packet* p = packet();
  EXPECT_FALSE(cache_.resolve_and_queue(kOther, kPort, p));
  pool_.release(p);
  EXPECT_FALSE(cache_.peek(kOther).has_value());
  EXPECT_EQ(events_.requests.size(), kCapacity);  // one each for the four, none for the fifth
}

TEST_F(ArpCacheTest, DestroyingTheCacheLetsGoOfWhatItHolds) {
  Packets queued;
  {
    ArpCache cache{events_, kCapacity};
    cache.tick(kT0);
    for (int i = 0; i < 2; ++i) {
      queued.push_back(packet());
      ASSERT_TRUE(cache.resolve_and_queue(kOther, kPort, queued.back()));
    }
  }
  EXPECT_EQ(events_.discarded, queued);
}

// CLAUDE.md rule 4: what the worker calls every iteration, or for every packet, never allocates.
TEST_F(ArpCacheTest, NothingAllocatesAfterConstruction) {
  const std::array<Packet*, 3> p{packet(), packet(), packet()};
  AllocCounter::reset();
  const bool queued = cache_.resolve_and_queue(kNeighbour, kPort, p[0]) &&
                      cache_.resolve_and_queue(kNeighbour, kPort, p[1]) &&
                      cache_.resolve_and_queue(kOther, kPort, p[2]);
  cache_.tick(kT0 + seconds{1});
  const std::optional<MacAddr> miss = cache_.lookup(kNeighbour);
  cache_.on_reply(kNeighbour, kMac, ready_);
  const std::size_t handed_back = ready_.size();
  const std::optional<MacAddr> hit = cache_.lookup(kNeighbour);
  cache_.on_unsolicited(kNeighbour, kNewMac);
  for (int s = 2; s <= 4; ++s) {
    cache_.tick(kT0 + seconds{s});  // gives up on kOther
  }
  cache_.flush();
  EXPECT_EQ(AllocCounter::allocations(), 0U);
  EXPECT_EQ(AllocCounter::deallocations(), 0U);
  for (Packet* sent : ready_) {
    pool_.release(sent);
  }
  ready_.clear();

  EXPECT_TRUE(queued);
  EXPECT_FALSE(miss.has_value());
  EXPECT_EQ(handed_back, 2U);
  EXPECT_EQ(hit, kMac);
  EXPECT_EQ(events_.heads, Packets{p[2]});
  // Those zeros mean something only if this binary counts allocations at all.
  AllocCounter::reset();
  int* volatile probe = new int{1};
  delete probe;
  EXPECT_EQ(AllocCounter::allocations(), 1U);
}

}  // namespace
