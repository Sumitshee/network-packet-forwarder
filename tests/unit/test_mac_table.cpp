#include <gtest/gtest.h>

#include <algorithm>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <npf/proto/mac.hpp>
#include <npf/table/mac_table.hpp>
#include <optional>
#include <random>
#include <utility>
#include <vector>

#include "support/alloc_counter.hpp"

namespace {

using npf::proto::MacAddr;
using npf::table::MacTable;
using npf::test::AllocCounter;
using TimePoint = MacTable::TimePoint;
using std::chrono::seconds;

constexpr TimePoint kT0{std::chrono::hours{1}};

seconds secs(std::uint64_t n) {
  return seconds{static_cast<seconds::rep>(n)};
}

// A locally administered unicast MAC made from n: 02:00 and n's four bytes.
MacAddr mac(std::uint32_t n) {
  return MacAddr{{0x02, 0x00, static_cast<std::uint8_t>(n >> 24U),
                  static_cast<std::uint8_t>(n >> 16U), static_cast<std::uint8_t>(n >> 8U),
                  static_cast<std::uint8_t>(n)}};
}

std::uint64_t key_of(MacAddr m) {
  std::uint64_t key = 0;
  for (const std::uint8_t octet : m.b) {
    key = key << 8U | octet;
  }
  return key;
}

// The table's hash as mac_table.cpp documents it -- the MAC's 48 bits times 0x9E3779B97F4A7C15,
// keeping the product's top log2(capacity) bits -- to build MACs known to share a home slot. If
// the hash changed, the eviction tests below would notice: they need the collisions to evict.
std::size_t home_of(MacAddr m, std::size_t capacity) {
  return static_cast<std::size_t>((key_of(m) * 0x9E3779B97F4A7C15ULL) >>
                                  (64 - std::countr_zero(capacity)));
}

// n MACs whose home in a table of this capacity is one and the same slot.
std::vector<MacAddr> colliding(std::size_t n, std::size_t capacity) {
  std::vector<MacAddr> out;
  const std::size_t target = home_of(mac(1), capacity);
  for (std::uint32_t i = 1; out.size() < n; ++i) {
    if (home_of(mac(i), capacity) == target) {
      out.push_back(mac(i));
    }
  }
  return out;
}

TEST(MacTable, CapacityIsAPowerOfTwoAndAtLeastTheProbeWindow) {
  EXPECT_EQ(MacTable(0).capacity(), MacTable::kWindow);
  EXPECT_EQ(MacTable(5).capacity(), MacTable::kWindow);
  EXPECT_EQ(MacTable(17).capacity(), 32U);
  EXPECT_EQ(MacTable(4096).capacity(), 4096U);
  EXPECT_EQ(MacTable(4097).capacity(), 8192U);
  EXPECT_EQ(MacTable(64).max_age(), seconds{300});  // a real switch's default
  EXPECT_EQ(MacTable(64, seconds{10}).max_age(), seconds{10});
}

TEST(MacTable, LearnsAndLooksUp) {
  MacTable t(64);
  EXPECT_EQ(t.size(), 0U);
  EXPECT_EQ(t.lookup(mac(1)), std::nullopt);
  t.learn(mac(1), 3, kT0);
  EXPECT_EQ(t.lookup(mac(1)), 3);
  EXPECT_EQ(t.lookup(mac(2)), std::nullopt);
  EXPECT_EQ(t.size(), 1U);
}

TEST(MacTable, AStationThatMovesIsFoundOnItsNewPort) {
  MacTable t(64);
  t.learn(mac(1), 3, kT0);
  t.learn(mac(1), 5, kT0 + seconds{1});
  EXPECT_EQ(t.lookup(mac(1)), 5);
  EXPECT_EQ(t.size(), 1U);
}

TEST(MacTable, CollidingMacsAreEachFoundOnTheirOwnPort) {
  MacTable t(64);
  const std::vector<MacAddr> same_home = colliding(MacTable::kWindow, t.capacity());
  for (std::size_t i = 0; i < same_home.size(); ++i) {
    t.learn(same_home[i], static_cast<std::uint16_t>(i), kT0 + secs(i));
  }
  EXPECT_EQ(t.size(), same_home.size());
  for (std::size_t i = 0; i < same_home.size(); ++i) {
    EXPECT_EQ(t.lookup(same_home[i]), static_cast<std::uint16_t>(i)) << i;
  }
}

TEST(MacTable, AFullWindowEvictsItsOldestEntry) {
  MacTable t(64);
  const std::vector<MacAddr> same_home = colliding(MacTable::kWindow + 1, t.capacity());
  for (std::size_t i = 0; i < same_home.size(); ++i) {
    t.learn(same_home[i], static_cast<std::uint16_t>(i), kT0 + secs(i));
  }
  // The window held the first kWindow; the last one took the place of the first, the oldest.
  EXPECT_EQ(t.size(), MacTable::kWindow);
  EXPECT_EQ(t.lookup(same_home[0]), std::nullopt);
  for (std::size_t i = 1; i < same_home.size(); ++i) {
    EXPECT_EQ(t.lookup(same_home[i]), static_cast<std::uint16_t>(i)) << i;
  }
}

TEST(MacTable, AStationHeardAgainIsNotTheOneEvicted) {
  MacTable t(64);
  const std::vector<MacAddr> same_home = colliding(MacTable::kWindow + 1, t.capacity());
  for (std::size_t i = 0; i < MacTable::kWindow; ++i) {
    t.learn(same_home[i], 1, kT0 + secs(i));
  }
  t.learn(same_home[0], 1, kT0 + seconds{100});  // the oldest speaks up
  t.learn(same_home[MacTable::kWindow], 1, kT0 + seconds{101});
  EXPECT_EQ(t.lookup(same_home[0]), 1);
  EXPECT_EQ(t.lookup(same_home[1]), std::nullopt);  // now the oldest, so the one evicted
}

TEST(MacTable, TwiceTheCapacityEvictsRatherThanCorrupts) {
  MacTable t(64);
  const std::size_t n = 2 * t.capacity();
  for (std::uint32_t i = 0; i < n; ++i) {
    t.learn(mac(i), static_cast<std::uint16_t>(i % 7), kT0 + secs(i));
  }
  EXPECT_LE(t.size(), t.capacity());
  std::size_t found = 0;
  for (std::uint32_t i = 0; i < n; ++i) {
    if (const std::optional<std::uint16_t> port = t.lookup(mac(i))) {
      EXPECT_EQ(*port, i % 7) << i;  // a MAC is found on its own port, or not at all
      ++found;
    }
  }
  EXPECT_EQ(found, t.size());
  EXPECT_GE(found, t.capacity() / 2);  // the table did fill up, and kept learning

  // And it stays sound through aging: half the stations fall silent.
  t.age(kT0 + secs(n / 2) + t.max_age());
  for (std::uint32_t i = 0; i < n; ++i) {
    if (const std::optional<std::uint16_t> port = t.lookup(mac(i))) {
      EXPECT_EQ(*port, i % 7) << i;
      EXPECT_GE(i, n / 2) << "should have aged out";
    }
  }
}

TEST(MacTable, AgeRemovesExactlyTheExpiredEntries) {
  MacTable t(64, seconds{300});
  t.learn(mac(1), 1, kT0);                                             // 301 s old: expired
  t.learn(mac(2), 2, kT0 + seconds{1} - std::chrono::nanoseconds{1});  // a hair over 300 s
  t.learn(mac(3), 3, kT0 + seconds{1});                                // exactly 300 s: kept
  t.learn(mac(4), 4, kT0 + seconds{200});                              // 101 s
  t.age(kT0 + seconds{301});
  EXPECT_EQ(t.lookup(mac(1)), std::nullopt);
  EXPECT_EQ(t.lookup(mac(2)), std::nullopt);
  EXPECT_EQ(t.lookup(mac(3)), 3);
  EXPECT_EQ(t.lookup(mac(4)), 4);
  EXPECT_EQ(t.size(), 2U);
}

TEST(MacTable, AgingInsideARunKeepsTheRestOfItFindable) {
  // A run of MACs sharing a home slot, two of every three silent for too long. Removing one shifts
  // those after it back: a hole left behind would hide every MAC beyond it, and the entry shifted
  // into a slot just emptied -- here, often expired too -- must be looked at in its turn.
  MacTable t(64, seconds{60});
  const std::vector<MacAddr> same_home = colliding(12, t.capacity());
  const auto heard_lately = [](std::size_t i) { return i % 3 == 2; };
  for (std::size_t i = 0; i < same_home.size(); ++i) {
    t.learn(same_home[i], static_cast<std::uint16_t>(i),
            heard_lately(i) ? kT0 + seconds{100} : kT0);
  }
  t.age(kT0 + seconds{120});
  EXPECT_EQ(t.size(), same_home.size() / 3);
  for (std::size_t i = 0; i < same_home.size(); ++i) {
    EXPECT_EQ(t.lookup(same_home[i]),
              heard_lately(i) ? std::optional<std::uint16_t>(static_cast<std::uint16_t>(i))
                              : std::nullopt)
        << i;
  }
  // The freed slots are used again, and nothing is learned twice.
  for (std::size_t i = 0; i < same_home.size(); ++i) {
    t.learn(same_home[i], 9, kT0 + seconds{130});
  }
  EXPECT_EQ(t.size(), same_home.size());
  for (const MacAddr& m : same_home) {
    EXPECT_EQ(t.lookup(m), 9);
  }
}

// A deliberately simple reference: a map, with the same aging rule. Below the load at which a
// window ever fills, the table must agree with it exactly.
class Reference {
 public:
  explicit Reference(seconds max_age) : max_age_{max_age} {}
  void learn(MacAddr m, std::uint16_t port, TimePoint now) { entries_[key_of(m)] = {port, now}; }
  [[nodiscard]] std::optional<std::uint16_t> lookup(MacAddr m) const {
    const auto it = entries_.find(key_of(m));
    return it == entries_.end() ? std::nullopt : std::optional{it->second.first};
  }
  void age(TimePoint now) {
    std::erase_if(entries_, [&](const auto& e) { return now - e.second.second > max_age_; });
  }
  [[nodiscard]] std::size_t size() const { return entries_.size(); }

 private:
  seconds max_age_;
  std::map<std::uint64_t, std::pair<std::uint16_t, TimePoint>> entries_;
};

TEST(MacTable, AgreesWithASimpleReferenceUnderRandomUse) {
  constexpr seconds kMaxAge{120};
  MacTable t(1024, kMaxAge);
  Reference ref(kMaxAge);
  std::mt19937 rng(20261006);
  const auto below = [&rng](std::uint32_t n) { return static_cast<std::uint32_t>(rng()) % n; };
  std::vector<MacAddr> stations;
  for (std::uint32_t i = 0; i < 300; ++i) {  // at most 300 of 1024 slots: no window fills
    stations.push_back(mac(below(0xFFFFFFFFU)));
  }
  TimePoint now = kT0;
  for (int op = 0; op < 20000; ++op) {
    const std::uint32_t pick = below(10);
    if (pick < 7) {
      now += std::chrono::milliseconds{below(2000)};
      const MacAddr m = stations[below(300)];
      const auto port = static_cast<std::uint16_t>(below(8));
      t.learn(m, port, now);
      ref.learn(m, port, now);
    } else if (pick < 8) {
      now += seconds{below(60)};
      t.age(now);
      ref.age(now);
    } else {
      const MacAddr m = stations[below(300)];
      ASSERT_EQ(t.lookup(m), ref.lookup(m)) << "op " << op;
    }
    ASSERT_EQ(t.size(), ref.size()) << "op " << op;
  }
  for (const MacAddr& m : stations) {
    EXPECT_EQ(t.lookup(m), ref.lookup(m));
  }
}

TEST(MacTable, LearningLookingUpAndAgingAllocateNothing) {
  MacTable t(256, seconds{10});
  AllocCounter::reset();
  for (std::uint32_t i = 0; i < 1000; ++i) {
    t.learn(mac(i % 300), static_cast<std::uint16_t>(i % 4), kT0 + secs(i / 100));
    (void)t.lookup(mac(i));
  }
  t.age(kT0 + seconds{9});
  t.age(kT0 + seconds{100});
  EXPECT_EQ(AllocCounter::allocations(), 0U);
  EXPECT_EQ(AllocCounter::deallocations(), 0U);
  // That zero means something only if this binary counts allocations: a list makes one.
  AllocCounter::reset();
  t.learn(mac(1), 1, kT0);
  EXPECT_FALSE(t.list().empty());
  EXPECT_GT(AllocCounter::allocations(), 0U);
}

TEST(MacTable, ListHasEveryStation) {
  MacTable t(64);
  for (std::uint32_t i = 0; i < 10; ++i) {
    t.learn(mac(i), static_cast<std::uint16_t>(i), kT0 + secs(i));
  }
  std::vector<MacTable::Station> all = t.list();
  ASSERT_EQ(all.size(), 10U);
  std::ranges::sort(all, {}, &MacTable::Station::port);
  for (std::uint32_t i = 0; i < 10; ++i) {
    EXPECT_EQ(all[i].mac, mac(i));
    EXPECT_EQ(all[i].port, i);
    EXPECT_EQ(all[i].last_seen, kT0 + secs(i));
  }
}

}  // namespace
