// The neighbour cache's state machine. arp_cache.hpp states the rules this follows.

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <npf/core/packet.hpp>
#include <npf/proto/mac.hpp>
#include <npf/table/arp_cache.hpp>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace npf::table {
namespace {

// RFC 1812 §3.3.2: a router MUST NOT believe an ARP message that gives another station a broadcast
// or multicast MAC. Sent there, a neighbour's traffic would reach every station on the segment.
bool believable(proto::MacAddr mac) noexcept {
  return !mac.is_multicast();  // the broadcast address among them
}

}  // namespace

ArpCache::ArpCache(ArpEvents& ev, std::size_t capacity) : events_{&ev}, entries_(capacity) {}

ArpCache::~ArpCache() {
  flush();
}

ArpCache::Entry* ArpCache::find(std::uint32_t ip) noexcept {
  const std::span<Entry> live(entries_.data(), size_);
  const auto it = std::ranges::find(live, ip, &Entry::ip);
  return it == live.end() ? nullptr : &*it;
}

const ArpCache::Entry* ArpCache::find(std::uint32_t ip) const noexcept {
  const std::span<const Entry> live(entries_.data(), size_);
  const auto it = std::ranges::find(live, ip, &Entry::ip);
  return it == live.end() ? nullptr : &*it;
}

std::optional<proto::MacAddr> ArpCache::lookup(std::uint32_t ip) noexcept {
  Entry* e = find(ip);
  if (e == nullptr || e->state == ArpState::Incomplete) {
    return std::nullopt;
  }
  e->used = now_;
  // Forward on the MAC the cache has, and ask in the background whether it still holds. tick()
  // sends the rest of the revalidation's probes, so a stream of packets is not a stream of them.
  if (e->state == ArpState::Stale && e->probes == 0) {
    probe(*e);
  }
  return e->mac;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters): ARCHITECTURE.md §6's signature
bool ArpCache::resolve_and_queue(std::uint32_t ip, std::uint16_t out_port,
                                 core::Packet* p) noexcept {
  Entry* e = find(ip);
  if (e == nullptr) {
    if (size_ == entries_.size()) {
      return false;  // no room to remember the question, so its answer could not be taken
    }
    e = &entries_[size_++];
    *e = Entry{};
    e->ip = ip;
    e->port = out_port;
    e->used = now_;
    probe(*e);
  }
  assert(e->state == ArpState::Incomplete && "lookup() would have answered for this neighbour");
  if (e->state != ArpState::Incomplete || e->queued == kArpQueueDepth) {
    return false;
  }
  // The check above is the bounds check.
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
  e->queue[e->queued++] = p;
  return true;
}

void ArpCache::on_reply(std::uint32_t ip, proto::MacAddr mac,
                        std::vector<core::Packet*>& ready) noexcept {
  ready.clear();
  Entry* e = find(ip);
  // A reply to a question this cache never asked is not one to learn from, and a static entry is
  // fixed by the configuration.
  if (e == nullptr || e->is_static || !believable(mac)) {
    return;
  }
  confirm(*e, mac);
  if (e->queued != 0) {
    e->used = now_;  // the packets handed back are about to be sent to it
  }
  const std::span<core::Packet* const> waiting = std::span(e->queue).first(e->queued);
  assert(ready.capacity() >= waiting.size() && "reserve kArpQueueDepth in 'ready' once");
  ready.assign(waiting.begin(), waiting.end());
  e->queued = 0;
}

void ArpCache::on_unsolicited(std::uint32_t ip, proto::MacAddr mac) noexcept {
  Entry* e = find(ip);
  if (e == nullptr || e->is_static || e->state == ArpState::Incomplete || !believable(mac)) {
    return;
  }
  confirm(*e, mac);
}

void ArpCache::tick(std::chrono::steady_clock::time_point now) noexcept {
  now_ = now;
  for (std::size_t i = 0; i < size_;) {
    Entry& e = entries_[i];
    if (e.is_static) {
      ++i;
      continue;
    }
    if (e.probes != 0 && now - e.last_probe >= kArpProbeInterval) {
      if (e.probes < kArpMaxProbes) {
        probe(e);
      } else {
        give_up(e);
        erase(i);
        continue;
      }
    }
    if (e.state == ArpState::Reachable && now - e.answered >= kArpReachable) {
      e.state = ArpState::Stale;
    }
    if (e.state != ArpState::Incomplete && now - e.used >= kArpStaleTimeout) {
      erase(i);
      continue;
    }
    ++i;
  }
}

void ArpCache::insert_static(std::uint32_t ip, proto::MacAddr mac, std::uint16_t port) noexcept {
  Entry* e = find(ip);
  if (e == nullptr) {
    if (size_ == entries_.size()) {
      return;
    }
    e = &entries_[size_++];
  } else {
    // Packets waiting on a resolution this replaces are dropped: on_reply() is the only way
    // back out for them. Static entries are made at start-up, before any packet could wait.
    discard_queue(*e);
  }
  *e = Entry{};
  e->ip = ip;
  e->mac = mac;
  e->port = port;
  e->state = ArpState::Reachable;
  e->is_static = true;
}

void ArpCache::flush() noexcept {
  for (std::size_t i = 0; i < size_;) {
    if (entries_[i].is_static) {
      ++i;
      continue;
    }
    discard_queue(entries_[i]);
    erase(i);
  }
}

std::optional<ArpNeighbour> ArpCache::peek(std::uint32_t ip) const noexcept {
  const Entry* e = find(ip);
  if (e == nullptr) {
    return std::nullopt;
  }
  return ArpNeighbour{.mac = e->mac,
                      .port = e->port,
                      .state = e->state,
                      .is_static = e->is_static,
                      .queued = e->queued};
}

std::vector<std::pair<std::uint32_t, ArpNeighbour>> ArpCache::list() const {
  std::vector<std::pair<std::uint32_t, ArpNeighbour>> out;
  out.reserve(size_);
  for (const Entry& e : std::span(entries_).first(size_)) {
    out.emplace_back(e.ip, ArpNeighbour{.mac = e.mac,
                                        .port = e.port,
                                        .state = e.state,
                                        .is_static = e.is_static,
                                        .queued = e.queued});
  }
  return out;
}

void ArpCache::probe(Entry& e) noexcept {
  ++e.probes;
  e.last_probe = now_;
  events_->send_arp_request(e.ip, e.port);
}

void ArpCache::confirm(Entry& e, proto::MacAddr mac) noexcept {
  e.mac = mac;
  e.state = ArpState::Reachable;
  e.answered = now_;
  e.probes = 0;
}

// RFC 1812 §3.3.2: when resolution fails, tell the sender of one of the queued packets that its
// destination is unreachable. That one is the head; the packets behind it are dropped silently.
void ArpCache::give_up(Entry& e) noexcept {
  const std::span<core::Packet* const> waiting = std::span(e.queue).first(e.queued);
  if (!waiting.empty()) {
    events_->unresolved(waiting.front());
    for (core::Packet* p : waiting.subspan(1)) {
      events_->discard(p);
    }
  }
  e.queued = 0;
}

void ArpCache::discard_queue(Entry& e) noexcept {
  for (core::Packet* p : std::span(e.queue).first(e.queued)) {
    events_->discard(p);
  }
  e.queued = 0;
}

// The last entry in use takes the erased one's place: entries keep no order.
void ArpCache::erase(std::size_t i) noexcept {
  entries_[i] = entries_[--size_];
}

}  // namespace npf::table
