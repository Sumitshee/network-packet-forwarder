#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <npf/core/packet.hpp>
#include <npf/proto/mac.hpp>
#include <optional>
#include <vector>

namespace npf::table {

// ARCHITECTURE.md §6.

enum class ArpState : std::uint8_t { Incomplete, Reachable, Stale };

inline constexpr std::size_t kArpQueueDepth = 3;  // matches Linux's unresolved queue
inline constexpr std::uint8_t kArpMaxProbes = 3;
inline constexpr auto kArpProbeInterval = std::chrono::seconds{1};
inline constexpr auto kArpReachable = std::chrono::seconds{30};
inline constexpr auto kArpStaleTimeout = std::chrono::seconds{60};

// Callback the cache uses to emit ARP requests and ICMP errors; injected so the cache has no
// dependency on the I/O layer and stays unit-testable. The cache calls these from inside its own
// functions, so they must not call back into it.
class ArpEvents {
 public:
  virtual ~ArpEvents() = default;
  virtual void send_arp_request(std::uint32_t target_ip, std::uint16_t out_port) = 0;
  virtual void unresolved(core::Packet* p) = 0;  // emit ICMP 3/1 for the head, then release
  // Release a queued packet with no ICMP, counting it as ArpUnresolved: the packets behind the
  // head of a failed queue, and every packet flush() lets go of.
  virtual void discard(core::Packet* p) = 0;

 protected:
  ArpEvents() = default;
  ArpEvents(const ArpEvents&) = default;
  ArpEvents(ArpEvents&&) = default;
  ArpEvents& operator=(const ArpEvents&) = default;
  ArpEvents& operator=(ArpEvents&&) = default;
};

// One entry, as peek() reports it.
struct ArpNeighbour {
  proto::MacAddr mac;  // meaningless while Incomplete
  std::uint16_t port{0};
  ArpState state{ArpState::Incomplete};
  bool is_static{false};
  std::size_t queued{0};  // packets waiting for the neighbour to answer
};

// The neighbour cache. Only resolve_and_queue() creates an entry, as Incomplete, and only an
// answer completes one:
//
//   resolve_and_queue -> Incomplete --on_reply--> Reachable --kArpReachable later--> Stale
//                                                    ^                                 |
//                                                    +--- on_reply, on_unsolicited ----+
//
// - A probe is an ARP request, at most one per kArpProbeInterval per entry. resolve_and_queue()
//   sends the first for a new entry, and a lookup() that hits a Stale entry the first of a
//   revalidation; tick() repeats either until kArpMaxProbes have gone unanswered, then gives up
//   kArpProbeInterval after the last: the head of the queue goes to ArpEvents::unresolved(), the
//   rest to discard(), and the entry is deleted. An unanswered revalidation deletes the entry the
//   same way, with no queue to let go of: the next packet to the neighbour starts a resolution of
//   its own, and if that fails too, its sender gets the Host Unreachable.
// - Each entry keeps two times. When the neighbour last answered decides Reachable or Stale, so
//   an entry in use is revalidated at least every kArpReachable. When the router last used the
//   entry decides when an idle one is deleted, kArpStaleTimeout later. A lookup() hit refreshes
//   only the second: traffic shows that the router needs a neighbour, not that it is still there.
// - Static entries are always Reachable. They never age, are never probed, and only another
//   insert_static() changes one.
// - Time is whatever the last tick() said; nothing here reads a clock.
//
// Entries live inline, queue and all, in an array sized once by the constructor, and are found by
// walking the ones in use: nothing after the constructor allocates, and a lookup costs time in
// proportion to the number of neighbours. Fine for the handful of a small router's subnets; a
// router with thousands would want a hash table.
class ArpCache {
 public:
  ArpCache(ArpEvents& ev, std::size_t capacity);
  // The cache owns the packets in its queues, so a copy would hand each of them out twice.
  ArpCache(const ArpCache&) = delete;
  ArpCache(ArpCache&&) = delete;
  ArpCache& operator=(const ArpCache&) = delete;
  ArpCache& operator=(ArpCache&&) = delete;
  ~ArpCache();  // discards whatever is still queued, as flush() does

  // Hit refreshes the entry's timer. Miss does NOT create an entry -- the caller decides.
  // The timer is the idle one; a hit on a Stale entry also starts its revalidation.
  [[nodiscard]] std::optional<proto::MacAddr> lookup(std::uint32_t ip) noexcept;

  // Creates an Incomplete entry if absent, sends a probe, and queues the packet.
  // Returns false if the queue is full; the caller must then release the packet and
  // count DropReason::ArpUnresolved.
  // Also false, with nothing created, when every entry is in use. A queued packet is the cache's
  // until on_reply() hands it back or it is given up on; it leaves from out_port as given when
  // the entry was created.
  [[nodiscard]] bool resolve_and_queue(std::uint32_t ip, std::uint16_t out_port,
                                       core::Packet* p) noexcept;

  // Called on a received ARP reply. Fills 'ready' with the packets that can now be sent.
  // They replace whatever 'ready' held, oldest first. Room for kArpQueueDepth of them, reserved
  // once, keeps this from allocating. A reply for an address the cache never asked about creates
  // nothing, and a static entry ignores it. No entry believes a reply naming a broadcast or
  // multicast MAC, which RFC 1812 §3.3.2 forbids; nor does on_unsolicited().
  void on_reply(std::uint32_t ip, proto::MacAddr mac, std::vector<core::Packet*>& ready) noexcept;

  // Unsolicited/gratuitous ARP: refreshes an EXISTING entry only. Never creates one --
  // creating on unsolicited ARP is trivial cache poisoning.
  // Nor does it complete an Incomplete entry: only on_reply() can hand back the packets queued
  // there. A caller that takes an announcement as the answer it was waiting for calls that.
  void on_unsolicited(std::uint32_t ip, proto::MacAddr mac) noexcept;

  // Retransmits probes, expires entries, fails exhausted ones. Called once per loop
  // iteration from the worker, not from a timer thread.
  void tick(std::chrono::steady_clock::time_point now) noexcept;

  // Fails silently when every entry is in use: the caller sizes the cache for its static entries.
  void insert_static(std::uint32_t ip, proto::MacAddr mac, std::uint16_t port) noexcept;

  // Deletes every entry except the static ones, discarding the packets queued on them through
  // ArpEvents::discard. For a test's SIGUSR2, and at shutdown, so no buffer stays held.
  void flush() noexcept;

  // What the cache holds for ip, untouched: unlike lookup(), this refreshes nothing and never
  // probes.
  [[nodiscard]] std::optional<ArpNeighbour> peek(std::uint32_t ip) const noexcept;

  [[nodiscard]] std::size_t size() const noexcept { return size_; }

 private:
  using TimePoint = std::chrono::steady_clock::time_point;

  struct Entry {
    std::uint32_t ip{0};
    proto::MacAddr mac{};
    std::uint16_t port{0};
    ArpState state{ArpState::Incomplete};
    bool is_static{false};
    std::uint8_t probes{0};  // sent since the neighbour last answered
    std::uint8_t queued{0};
    std::array<core::Packet*, kArpQueueDepth> queue{};  // the oldest first
    TimePoint last_probe;
    TimePoint answered;  // when the neighbour last answered
    TimePoint used;      // when the router last needed the entry
  };

  [[nodiscard]] Entry* find(std::uint32_t ip) noexcept;
  [[nodiscard]] const Entry* find(std::uint32_t ip) const noexcept;
  void probe(Entry& e) noexcept;
  void confirm(Entry& e, proto::MacAddr mac) noexcept;
  void give_up(Entry& e) noexcept;
  void discard_queue(Entry& e) noexcept;
  void erase(std::size_t i) noexcept;

  ArpEvents* events_;           // borrowed: owned by the caller, which outlives the cache
  std::vector<Entry> entries_;  // allocated once; the first size_ are in use
  std::size_t size_{0};
  TimePoint now_;  // as of the last tick()
};

}  // namespace npf::table
