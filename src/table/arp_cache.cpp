// The phase 6 stub; see arp_cache.hpp for what it does and does not do. Phase 8 rewrites this file.

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <npf/core/packet.hpp>
#include <npf/proto/mac.hpp>
#include <npf/table/arp_cache.hpp>
#include <optional>
#include <vector>

namespace npf::table {

ArpCache::ArpCache(ArpEvents& ev, std::size_t capacity) : events_{&ev}, capacity_{capacity} {
  entries_.reserve(capacity);
}

ArpCache::Entry* ArpCache::find(std::uint32_t ip) noexcept {
  const auto it = std::ranges::find(entries_, ip, &Entry::ip);
  return it == entries_.end() ? nullptr : &*it;
}

std::optional<proto::MacAddr> ArpCache::lookup(std::uint32_t ip) noexcept {
  const Entry* e = find(ip);
  if (e == nullptr || e->state == ArpState::Incomplete) {
    return std::nullopt;
  }
  return e->mac;
}

bool ArpCache::resolve_and_queue(std::uint32_t ip, std::uint16_t out_port,
                                 [[maybe_unused]] core::Packet* p) noexcept {
  Entry* e = find(ip);
  if (e == nullptr) {
    if (entries_.size() == capacity_) {
      return false;  // no room to remember the question, so a reply could not be accepted
    }
    e = &entries_.emplace_back();
    e->ip = ip;
    e->port = out_port;
  }
  // One request a second is enough: a packet stream to a silent neighbour must not become a
  // stream of broadcasts.
  if (!e->probed || now_ - e->last_probe >= kArpProbeInterval) {
    e->probed = true;
    e->last_probe = now_;
    events_->send_arp_request(ip, out_port);
  }
  return false;  // TODO(phase-8): queue p (up to kArpQueueDepth) instead of dropping it
}

void ArpCache::on_reply(std::uint32_t ip, proto::MacAddr mac,
                        [[maybe_unused]] std::vector<core::Packet*>& ready) noexcept {
  Entry* e = find(ip);
  // A reply to a question this cache never asked is not one to learn from, and a static entry is
  // fixed by the configuration. Nothing is ever queued, so nothing goes into `ready`.
  if (e == nullptr || e->is_static) {
    return;
  }
  e->mac = mac;
  e->state = ArpState::Reachable;
}

void ArpCache::on_unsolicited(std::uint32_t ip, proto::MacAddr mac) noexcept {
  Entry* e = find(ip);
  if (e == nullptr || e->is_static) {
    return;
  }
  e->mac = mac;
  e->state = ArpState::Reachable;
}

void ArpCache::tick(std::chrono::steady_clock::time_point now) noexcept {
  now_ = now;  // TODO(phase-8): retransmit probes, age entries, fail exhausted ones
}

void ArpCache::insert_static(std::uint32_t ip, proto::MacAddr mac, std::uint16_t port) noexcept {
  Entry* e = find(ip);
  if (e == nullptr) {
    if (entries_.size() == capacity_) {
      return;  // the caller sizes the cache for its static entries before inserting them
    }
    e = &entries_.emplace_back();
  }
  *e = Entry{};
  e->ip = ip;
  e->mac = mac;
  e->port = port;
  e->state = ArpState::Reachable;
  e->is_static = true;
}

}  // namespace npf::table
