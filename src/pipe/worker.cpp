#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <npf/core/config.hpp>
#include <npf/core/packet.hpp>
#include <npf/core/pool.hpp>
#include <npf/core/time.hpp>
#include <npf/io/backend.hpp>
#include <npf/pipe/decision.hpp>
#include <npf/pipe/filter.hpp>
#include <npf/pipe/forward.hpp>
#include <npf/pipe/hash.hpp>
#include <npf/pipe/worker.hpp>
#include <npf/proto/arp.hpp>
#include <npf/proto/ethernet.hpp>
#include <npf/proto/ipv4.hpp>
#include <npf/proto/l4.hpp>
#include <npf/stat/counters.hpp>
#include <npf/table/arp_cache.hpp>
#include <npf/table/lpm_linear.hpp>
#include <optional>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

namespace npf::pipe {
namespace {

core::UniqueFd make_eventfd() {
  core::UniqueFd fd{::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC)};
  if (!fd.valid()) {
    throw std::system_error(errno, std::generic_category(), "eventfd");
  }
  return fd;
}

void bump(int fd) noexcept {
  const std::uint64_t one = 1;
  [[maybe_unused]] const ssize_t n = ::write(fd, &one, sizeof(one));
}

// Takes the eventfd's count back to zero, so poll() stops reporting it readable.
void drain(int fd) noexcept {
  std::uint64_t count = 0;
  [[maybe_unused]] const ssize_t n = ::read(fd, &count, sizeof(count));
}

}  // namespace

// --- ArpCacheEvents ------------------------------------------------------------------------------

ArpCacheEvents::ArpCacheEvents(Recycler& recycler, std::vector<PortState> ports,
                               std::vector<TxQueue>& queues, stat::Counters& stats,
                               std::size_t capacity)
    : recycler_{&recycler},
      ports_{std::move(ports)},
      queues_{&queues},
      stats_{&stats},
      unresolved_(capacity) {}

void ArpCacheEvents::send_arp_request(std::uint32_t target_ip, std::uint16_t out_port) noexcept {
  if (out_port >= ports_.size()) {
    return;
  }
  core::Packet* p = recycler_->pool().acquire();
  if (p == nullptr) {
    return;  // no buffer to spare: the next packet for this neighbour asks again
  }
  const PortState& port = ports_[out_port];
  if (!proto::build_arp_request(*p, port.mac, port.ip, target_ip) ||
      !(*queues_)[out_port].push(p)) {
    recycler_->release(p);
  }
}

void ArpCacheEvents::unresolved(core::Packet* p) noexcept {
  if (n_unresolved_ == unresolved_.size()) {
    discard(p);  // not reached: see the constructor
    return;
  }
  unresolved_[n_unresolved_++] = p;
}

void ArpCacheEvents::discard(core::Packet* p) noexcept {
  recycler_->release(p);
  ++stats_->drop(DropReason::ArpUnresolved);
}

// --- Worker --------------------------------------------------------------------------------------

Worker::Worker(const core::Config& cfg, table::LinearLpm& fib, const Filter& filter,
               io::IoBackend& backend, Recycler& recycler, FloodSets flood_sets)
    : backend_{&backend},
      recycler_{&recycler},
      burst_{cfg.burst},
      requests_(cfg.interfaces.size()),
      arp_events_(recycler, make_port_table(cfg), requests_, stats_, kArpCapacity),
      arp_(arp_events_, kArpCapacity),
      macs_(kMacCapacity, cfg.mac_age),
      pipeline_(cfg, fib, arp_, macs_, filter, stats_),
      flood_sets_{std::move(flood_sets)},
      forward_(cfg.interfaces.size()),
      flood_(cfg.interfaces.size()),
      arp_replies_(cfg.interfaces.size()),
      icmp_(cfg.interfaces.size()) {
  for (const core::StaticArp& a : cfg.arp) {
    arp_.insert_static(a.ip, a.mac, a.port);
  }
}

std::size_t Worker::run_one_burst(core::Clock::time_point now) noexcept {
  pipeline_.set_time(now);
  arp_.tick(now);
  if (now >= next_mac_age_) {  // a scan of the whole table: once a second is plenty
    macs_.age(now);
    next_mac_age_ = now + kMacAgeInterval;
  }
  answer_unresolved(now);
  apply_news();
  const std::size_t n = backend_->rx_burst(rx_.data(), burst_);
  const std::span<core::Packet* const> got(rx_.data(), n);
  for (const core::Packet* p : got) {
    ++stats_.rx_packets;
    stats_.rx_bytes += p->size();
  }
  pipeline_.process_burst(rx_.data(), n, decisions_.data());
  const std::span<const Decision> decided(decisions_.data(), n);
  for (std::size_t i = 0; i < n; ++i) {
    dispatch(got[i], decided[i], now);
  }
  transmit();
  return n;
}

// The heads of the queues tick() gave up on: a Host Unreachable each, out of the port each
// arrived on, then dropped, as the packets queued behind them already were.
void Worker::answer_unresolved(core::Clock::time_point now) noexcept {
  for (core::Packet* p : arp_events_.unresolved_heads()) {
    if (core::Packet* error = pipeline_.host_unreachable(*p, recycler_->pool(), now);
        error != nullptr) {
      queue(icmp_[p->in_port()], error);
    }
    recycler_->release(p);
    ++stats_.drop(DropReason::ArpUnresolved);
  }
  arp_events_.clear_unresolved();
}

// What the other workers heard, applied as if this one had: a neighbour this worker was waiting
// for frees its queue.
void Worker::apply_news() noexcept {
  std::array<ArpNews, 8> batch{};  // news is rare: what is left waits for the next burst
  for (NewsRing* ring : news_in_) {
    const std::size_t n = ring->pop_bulk(batch.data(), batch.size());
    for (const ArpNews& news : std::span(batch.data(), n)) {
      pipeline_.apply(news);
      take_released();
    }
  }
}

// What this worker just heard, for the others. A full ring loses it: that worker's next probe
// asks the neighbour again.
void Worker::publish_news() noexcept {
  if (const std::optional<ArpNews> news = pipeline_.news()) {
    for (NewsRing* ring : news_out_) {
      [[maybe_unused]] const bool sent = ring->push(*news);
    }
  }
}

// The packets the ARP cache just let go of: rewritten and on their way, or, unrewritable, dropped.
void Worker::take_released() noexcept {
  for (const Reply& freed : pipeline_.released()) {
    forward(freed.packet, freed.port);
  }
  for (core::Packet* p : pipeline_.discarded()) {
    recycler_->release(p);
  }
}

// Every packet leaves here queued for transmission, released, or held by the ARP cache: exactly
// one of those. So does every answer the control plane hands back.
void Worker::dispatch(core::Packet* p, Decision d, core::Clock::time_point now) noexcept {
  switch (d.verdict) {
    case Verdict::Forward:
      forward(p, d.out_port);
      return;
    case Verdict::ToHost: {
      const std::optional<Reply> reply = pipeline_.deliver_to_host(*p, recycler_->pool(), now);
      take_released();  // an ARP answer's doing
      publish_news();
      if (reply && reply->packet == p) {  // an ARP request, turned into its reply in place
        queue(arp_replies_[reply->port], p);
        return;
      }
      if (reply) {
        queue(icmp_[reply->port], reply->packet);
      }
      recycler_->release(p);
      return;
    }
    case Verdict::Drop:
      if (core::Packet* error = pipeline_.error_for(*p, d.reason, recycler_->pool(), now);
          error != nullptr) {
        queue(icmp_[p->in_port()], error);
      }
      recycler_->release(p);
      return;
    case Verdict::Queued:  // the ARP cache's now, until deliver_to_host() or tick() lets it go
      return;
    case Verdict::Flood:
      flood(p);
      return;
  }
}

// Out of every port of the frame's flood set: a copy each for all but the last, which takes the
// frame itself. The pipeline counted the frame, once, as flooded; a copy that finds no free
// buffer is not made, and shows only as one transmission fewer. A flood queue cannot overflow:
// a burst gives each port at most one copy of each frame.
void Worker::flood(core::Packet* p) noexcept {
  const std::span<const std::uint16_t> out = flood_sets_[p->in_port()];
  if (out.empty()) {  // the only port of its bridge domain that is up
    recycler_->release(p);
    return;
  }
  for (const std::uint16_t port : out.first(out.size() - 1)) {
    core::Packet* copy = recycler_->pool().acquire();
    if (copy == nullptr) {
      continue;
    }
    copy->resize(p->size());
    std::ranges::copy(std::as_const(*p).data(), copy->data().begin());
    copy->set_in_port(p->in_port());
    copy->set_rx_tsc(p->rx_tsc());  // a replay stamps what it writes with the input's time
    queue(flood_[port], copy);
  }
  queue(flood_[out.back()], p);
}

void Worker::forward(core::Packet* p, std::uint16_t port) noexcept {
  if (!forward_[port].push(p)) {
    recycler_->release(p);
    ++stats_.drop(DropReason::TxFull);
  }
}

void Worker::queue(TxQueue& q, core::Packet* p) noexcept {
  if (!q.push(p)) {
    recycler_->release(p);
  }
}

// One tx_burst per queue per port: what the router says itself goes first, since traffic waits
// on ARP and senders wait on ICMP.
void Worker::transmit() noexcept {
  for (std::size_t i = 0; i < forward_.size(); ++i) {
    const auto port = static_cast<std::uint16_t>(i);
    stats_.arp_replies_tx += send(port, arp_replies_[i]);
    stats_.arp_requests_tx += send(port, requests_[i]);
    send(port, icmp_[i]);  // counted as generated already, and in tx_packets once sent
    const std::size_t queued = forward_[i].packets().size();
    const std::size_t sent = send(port, forward_[i]);
    stats_.forwarded += sent;
    stats_.drop(DropReason::TxFull) += queued - sent;
    send(port, flood_[i]);  // counted as flooded already, and in tx_packets once sent
  }
  backend_->tx_flush();
}

// Hands a queue to the backend, and releases what it refuses. Returns how many it took.
std::size_t Worker::send(std::uint16_t port, TxQueue& q) noexcept {
  const std::span<core::Packet* const> pkts = q.packets();
  if (pkts.empty()) {
    return 0;
  }
  std::size_t bytes = 0;  // summed first: the backend releases what it sends
  for (const core::Packet* p : pkts) {
    bytes += p->size();
  }
  const std::size_t sent = backend_->tx_burst(pkts.data(), pkts.size(), port);
  for (core::Packet* p : pkts.subspan(sent)) {
    bytes -= p->size();
    recycler_->release(p);
  }
  stats_.tx_packets += sent;
  stats_.tx_bytes += bytes;
  q.clear();
  return sent;
}

// --- pipeline mode -------------------------------------------------------------------------------

std::size_t steer(const core::Packet& p, std::size_t workers) noexcept {
  if (workers <= 1) {
    return 0;
  }
  const std::optional<proto::EthView> eth = proto::EthView::parse(p.data());
  if (!eth || eth->ethertype() != proto::kEtherTypeIpv4) {
    return 0;
  }
  const std::optional<proto::Ipv4View> ip = proto::Ipv4View::parse(eth->payload());
  if (!ip) {
    return 0;
  }
  std::uint16_t sport = 0;
  std::uint16_t dport = 0;
  if (!ip->is_fragment() &&
      (ip->protocol() == proto::kIpProtoTcp || ip->protocol() == proto::kIpProtoUdp)) {
    if (const std::optional<proto::L4Info> l4 = proto::parse_l4(*ip)) {
      sport = l4->sport;
      dport = l4->dport;
    }
  }
  return symmetric_hash_5tuple(ip->src(), ip->dst(), sport, dport, ip->protocol()) & (workers - 1);
}

Doorbell::Doorbell() : fd_{make_eventfd()} {}

void Doorbell::ring() noexcept {
  if (state_.exchange(kAwake, std::memory_order_acq_rel) == kAsleep) {
    bump(fd_.get());
  }
}

void Doorbell::arm() noexcept {
  state_.exchange(kAsleep, std::memory_order_acq_rel);
}

void Doorbell::disarm() noexcept {
  state_.exchange(kAwake, std::memory_order_acq_rel);
  drain(fd_.get());
}

PipelineRings::PipelineRings(std::size_t rx_threads, std::size_t workers)
    : rx_threads_{rx_threads}, workers_{workers} {
  for (std::size_t i = 0; i < rx_threads * workers; ++i) {
    to_worker_.push_back(std::make_unique<PacketRing>());
    home_.push_back(std::make_unique<ReturnRing>());
  }
}

NewsRings::NewsRings(std::size_t workers) : workers_{workers} {
  for (std::size_t i = 0; i < workers * workers; ++i) {
    rings_.push_back(std::make_unique<NewsRing>());
  }
}

void NewsRings::connect(std::span<Worker* const> workers) {
  for (std::size_t from = 0; from < workers.size(); ++from) {
    for (std::size_t to = 0; to < workers.size(); ++to) {
      if (from != to) {
        workers[from]->add_news_out(between(from, to));
        workers[to]->add_news_in(between(from, to));
      }
    }
  }
}

RxStage::RxStage(io::IoBackend& rx, core::PacketPool& pool, PipelineRings& rings, std::size_t index,
                 std::span<Doorbell* const> bells, std::size_t burst)
    : source_{&rx},
      pool_{&pool},
      bells_(bells.begin(), bells.end()),
      burst_{burst},
      staged_(bells.size()),
      n_staged_(bells.size(), 0) {
  for (std::size_t w = 0; w < bells.size(); ++w) {
    out_.push_back(&rings.to_worker(index, w));
    home_.push_back(&rings.home(w, index));
  }
}

std::size_t RxStage::run_once() noexcept {
  take_home();  // first: every buffer back is one more to receive into
  const std::size_t n = source_->rx_burst(rx_.data(), burst_);
  for (core::Packet* p : std::span(rx_.data(), n)) {
    const std::size_t w = steer(*p, out_.size());
    // A burst is at most kMaxBurst, so no worker's staging can overflow.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
    staged_[w][n_staged_[w]++] = p;
  }
  for (std::size_t w = 0; w < out_.size(); ++w) {
    const std::span<core::Packet* const> staged(staged_[w].data(), n_staged_[w]);
    if (staged.empty()) {
      continue;
    }
    const std::size_t pushed = out_[w]->push_bulk(staged.data(), staged.size());
    if (pushed != 0) {
      bells_[w]->ring();
    }
    for (core::Packet* p : staged.subspan(pushed)) {
      ++stats_.rx_packets;
      stats_.rx_bytes += p->size();
      ++stats_.drop(DropReason::RingFull);
      pool_->release(p);
    }
    n_staged_[w] = 0;
  }
  return n;
}

void RxStage::take_home() noexcept {
  std::array<core::Packet*, core::kMaxBurst> batch{};
  for (ReturnRing* ring : home_) {
    for (std::size_t n = ring->pop_bulk(batch.data(), batch.size()); n != 0;
         n = ring->pop_bulk(batch.data(), batch.size())) {
      for (core::Packet* p : std::span(batch.data(), n)) {
        pool_->release(p);
      }
    }
  }
}

void RxStage::reclaim() noexcept {
  take_home();
  core::Packet* p = nullptr;
  for (PacketRing* ring : out_) {
    while (ring->pop(p)) {
      pool_->release(p);
    }
  }
}

// --- Rendezvous ----------------------------------------------------------------------------------

Rendezvous::Rendezvous(std::size_t parties) : parties_{parties}, wake_{make_eventfd()} {}

void Rendezvous::park_all() noexcept {
  ++generation_;
  requested_.store(generation_, std::memory_order_release);
  bump(wake_.get());  // whoever is asleep in poll() wakes, and sees the request
  for (std::uint32_t n = parked_.load(std::memory_order_acquire); n != parties_;
       n = parked_.load(std::memory_order_acquire)) {
    parked_.wait(n, std::memory_order_acquire);
  }
}

void Rendezvous::resume_all() noexcept {
  drain(wake_.get());  // before the release: no party may see it readable afterwards
  parked_.store(0, std::memory_order_relaxed);  // published by the release store below
  released_.store(generation_, std::memory_order_release);
  released_.notify_all();
}

void Rendezvous::stop_all() noexcept {
  stop_.store(true, std::memory_order_release);
  bump(wake_.get());  // left readable: every party wakes, now and at every poll() until it ends
}

bool Rendezvous::checkpoint(std::uint32_t& seen) noexcept {
  const std::uint32_t requested = requested_.load(std::memory_order_acquire);
  if (requested != seen) [[unlikely]] {
    seen = requested;
    parked_.fetch_add(1, std::memory_order_acq_rel);
    parked_.notify_all();
    for (std::uint32_t r = released_.load(std::memory_order_acquire); r != requested;
         r = released_.load(std::memory_order_acquire)) {
      released_.wait(r, std::memory_order_acquire);
    }
  }
  return !stop_.load(std::memory_order_acquire);
}

}  // namespace npf::pipe
