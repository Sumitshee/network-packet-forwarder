#pragma once

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
// dependency on the I/O layer and stays unit-testable.
class ArpEvents {
 public:
  virtual ~ArpEvents() = default;
  virtual void send_arp_request(std::uint32_t target_ip, std::uint16_t out_port) = 0;
  virtual void unresolved(core::Packet* p) = 0;  // emit ICMP 3/1 for the head, then release

 protected:
  ArpEvents() = default;
  ArpEvents(const ArpEvents&) = default;
  ArpEvents(ArpEvents&&) = default;
  ArpEvents& operator=(const ArpEvents&) = default;
  ArpEvents& operator=(ArpEvents&&) = default;
};

// PHASE 6 STUB: phase 8 replaces the inside of this class, not its interface. It does the least
// that lets the pipeline forward:
//   - lookup() finds resolved entries, static ones included. Nothing ages; there are no timers.
//   - resolve_and_queue() remembers that it asked, sends a request at most once a second per
//     address, and never keeps the packet: it always returns false, so the caller drops it as
//     ArpUnresolved. The first packet to an unresolved neighbour is lost; phase 8 queues it.
//   - on_reply() completes an entry the cache asked for, and ignores a reply nobody asked for.
//   - on_unsolicited() refreshes an existing entry and never creates one.
// Lookups walk a vector: the stub is for a handful of neighbours, not a data centre.
class ArpCache {
 public:
  ArpCache(ArpEvents& ev, std::size_t capacity);

  // Hit refreshes the entry's timer. Miss does NOT create an entry -- the caller decides.
  [[nodiscard]] std::optional<proto::MacAddr> lookup(std::uint32_t ip) noexcept;

  // Creates an Incomplete entry if absent, sends a probe, and queues the packet.
  // Returns false if the queue is full; the caller must then release the packet and
  // count DropReason::ArpUnresolved.
  [[nodiscard]] bool resolve_and_queue(std::uint32_t ip, std::uint16_t out_port,
                                       core::Packet* p) noexcept;

  // Called on a received ARP reply. Fills 'ready' with the packets that can now be sent.
  void on_reply(std::uint32_t ip, proto::MacAddr mac, std::vector<core::Packet*>& ready) noexcept;

  // Unsolicited/gratuitous ARP: refreshes an EXISTING entry only. Never creates one --
  // creating on unsolicited ARP is trivial cache poisoning.
  void on_unsolicited(std::uint32_t ip, proto::MacAddr mac) noexcept;

  // Retransmits probes, expires entries, fails exhausted ones. Called once per loop
  // iteration from the worker, not from a timer thread.
  void tick(std::chrono::steady_clock::time_point now) noexcept;

  void insert_static(std::uint32_t ip, proto::MacAddr mac, std::uint16_t port) noexcept;

  [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }

 private:
  struct Entry {
    std::uint32_t ip{0};
    proto::MacAddr mac{};
    std::uint16_t port{0};
    ArpState state{ArpState::Incomplete};
    bool is_static{false};
    bool probed{false};
    std::chrono::steady_clock::time_point last_probe;
  };

  [[nodiscard]] Entry* find(std::uint32_t ip) noexcept;

  ArpEvents* events_;  // borrowed: owned by the caller, which outlives the cache
  // Reserved at construction and never grown past it, so adding an entry never allocates.
  std::vector<Entry> entries_;
  std::size_t capacity_;
  std::chrono::steady_clock::time_point now_;  // as of the last tick()
};

}  // namespace npf::table
