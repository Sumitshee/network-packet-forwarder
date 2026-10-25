#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <npf/core/config.hpp>
#include <npf/core/packet.hpp>
#include <npf/core/pool.hpp>
#include <npf/core/ring.hpp>
#include <npf/core/time.hpp>
#include <npf/core/unique_fd.hpp>
#include <npf/io/backend.hpp>
#include <npf/pipe/decision.hpp>
#include <npf/pipe/filter.hpp>
#include <npf/pipe/forward.hpp>
#include <npf/stat/counters.hpp>
#include <npf/table/arp_cache.hpp>
#include <npf/table/lpm_linear.hpp>
#include <npf/table/mac_table.hpp>
#include <span>
#include <vector>

namespace npf::pipe {

// The threads of ARCHITECTURE.md §12. Two execution models share one Worker:
//
//  - Run-to-completion (mode rtc): N workers, each with its own sockets in the ports' fanout
//    groups, its own pool and its own tables, each receiving, deciding and transmitting entirely
//    in its own thread. No ring carries a packet.
//  - Pipeline (mode pipeline): one RxStage thread per port receives and steers each packet, by its
//    flow's symmetric hash, through a PacketRing to one of N workers, which decide and transmit
//    through sockets of their own. A packet the worker has finished with goes back to the RX
//    thread through a ReturnRing, so a pool is only ever touched by its own thread.
//
// Either way, workers tell each other about the ARP replies and announcements they receive, through
// a NewsRing per ordered pair, and the control thread reads their counters and tables only while
// a Rendezvous holds them all parked between bursts.

inline constexpr std::size_t kArpCapacity = 1024;                 // neighbours per worker
inline constexpr std::size_t kMacCapacity = 4096;                 // stations per worker
inline constexpr auto kMacAgeInterval = std::chrono::seconds{1};  // how often a MAC table is aged
inline constexpr std::size_t kMaxWorkers = 64;

inline constexpr std::size_t kWorkerRingSize = 1024;  // RX thread to worker, the plan's
// Worker to RX thread. As large as the largest pool pipeline mode allows, so it can hold every
// packet of one, and handing a packet home never fails.
inline constexpr std::size_t kReturnRingSize = 16384;
inline constexpr std::size_t kNewsRingSize = 64;

using PacketRing = core::SpscRing<core::Packet*, kWorkerRingSize>;
using ReturnRing = core::SpscRing<core::Packet*, kReturnRingSize>;
using NewsRing = core::SpscRing<ArpNews, kNewsRingSize>;

// Packets waiting to go out of one port: at most one burst's worth.
class TxQueue {
 public:
  [[nodiscard]] bool push(core::Packet* p) noexcept {
    if (size_ == slots_.size()) {
      return false;
    }
    // The check above is the bounds check.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
    slots_[size_++] = p;
    return true;
  }
  [[nodiscard]] std::span<core::Packet* const> packets() const noexcept {
    return {slots_.data(), size_};
  }
  void clear() noexcept { size_ = 0; }

 private:
  std::array<core::Packet*, core::kMaxBurst> slots_{};
  std::size_t size_{0};
};

// Where a worker's packets come from and go back to. New ones -- ARP requests, ICMP, flood
// copies -- come from the worker's own pool. A finished one goes back to the pool it came from:
// the worker's own, or in pipeline mode an RX thread's, through the ring home to that thread.
class Recycler {
 public:
  explicit Recycler(core::PacketPool& own) : own_{&own} {}

  // Pipeline mode, at start-up: packets of `pool` go home through `ring`, of which this worker is
  // the producer.
  void add_home(const core::PacketPool& pool, ReturnRing& ring) {
    homes_.push_back({&pool, &ring});
  }

  [[nodiscard]] core::PacketPool& pool() const noexcept { return *own_; }

  void release(core::Packet* p) noexcept {
    if (homes_.empty() || own_->owns(p)) {
      own_->release(p);
      return;
    }
    for (const Home& h : homes_) {
      if (h.pool->owns(p)) {
        [[maybe_unused]] const bool ok = h.ring->push(p);
        assert(ok && "a return ring holds a whole pool, so it is never full");
        return;
      }
    }
    assert(false && "a packet from a pool this worker was never told about");
  }

 private:
  struct Home {
    const core::PacketPool* pool;  // borrowed, as is the ring: both outlive the worker's thread
    ReturnRing* ring;
  };
  core::PacketPool* own_;
  std::vector<Home> homes_;
};

// What the ARP cache asks of the worker. A request is built in a fresh buffer and queued on its
// port, to leave with the rest of the burst. A packet the cache gives up on is released and
// counted as ArpUnresolved -- but the head of a queue first earns its sender a Host Unreachable,
// which takes the control plane, built after the cache. So a head waits here, and the worker
// answers it straight after the tick() that gave it up.
class ArpCacheEvents final : public table::ArpEvents {
 public:
  // capacity: the ARP cache's. One tick() gives up on each entry at most once.
  ArpCacheEvents(Recycler& recycler, std::vector<PortState> ports, std::vector<TxQueue>& queues,
                 stat::Counters& stats, std::size_t capacity);

  void send_arp_request(std::uint32_t target_ip, std::uint16_t out_port) noexcept override;
  void unresolved(core::Packet* p) noexcept override;
  void discard(core::Packet* p) noexcept override;

  // The heads given up on since the last clear_unresolved(), still to be answered and dropped.
  [[nodiscard]] std::span<core::Packet* const> unresolved_heads() const noexcept {
    return {unresolved_.data(), n_unresolved_};
  }
  void clear_unresolved() noexcept { n_unresolved_ = 0; }

 private:
  Recycler* recycler_;  // borrowed, like everything the worker uses
  std::vector<PortState> ports_;
  std::vector<TxQueue>* queues_;
  stat::Counters* stats_;
  std::vector<core::Packet*> unresolved_;  // sized once; the first n_unresolved_ are waiting
  std::size_t n_unresolved_{0};
};

// One worker: its tables, its counters, the pipeline over them, and the loop body that drives them
// -- run the ARP cache's and the MAC table's timers, apply the other workers' ARP news, receive a
// burst, decide every packet, send the answers, the forwarded and the flooded. The FIB and the
// filter are shared, and only read.
class Worker {
 public:
  using Pipeline = Forwarder<table::LinearLpm>;
  using FloodSets = std::vector<std::vector<std::uint16_t>>;  // make_flood_sets()'

  // Everything passed in is borrowed, and outlives the worker. cfg's interfaces must have their
  // MACs. Fills the ARP cache with cfg's static entries.
  Worker(const core::Config& cfg, table::LinearLpm& fib, const Filter& filter,
         io::IoBackend& backend, Recycler& recycler, FloodSets flood_sets);
  // Its members point at each other.
  Worker(const Worker&) = delete;
  Worker(Worker&&) = delete;
  Worker& operator=(const Worker&) = delete;
  Worker& operator=(Worker&&) = delete;
  ~Worker() = default;

  // Several workers, at start-up: what this one hears goes out on every ring added with
  // add_news_out(), and what the others hear comes in on those added with add_news_in().
  void add_news_out(NewsRing& ring) { news_out_.push_back(&ring); }
  void add_news_in(NewsRing& ring) { news_in_.push_back(&ring); }

  // One pass of the loop. Returns how many packets it received: 0 tells the caller it may wait.
  std::size_t run_one_burst(core::Clock::time_point now) noexcept;

  // For the control thread, while the worker is parked or its thread has ended.
  [[nodiscard]] const stat::Counters& stats() const noexcept { return stats_; }
  [[nodiscard]] table::ArpCache& arp() noexcept { return arp_; }
  [[nodiscard]] const table::MacTable& macs() const noexcept { return macs_; }
  [[nodiscard]] const core::PacketPool& pool() const noexcept { return recycler_->pool(); }

 private:
  void answer_unresolved(core::Clock::time_point now) noexcept;
  void apply_news() noexcept;
  void publish_news() noexcept;
  void take_released() noexcept;
  void dispatch(core::Packet* p, Decision d, core::Clock::time_point now) noexcept;
  void flood(core::Packet* p) noexcept;
  void forward(core::Packet* p, std::uint16_t port) noexcept;
  void queue(TxQueue& q, core::Packet* p) noexcept;
  void transmit() noexcept;
  std::size_t send(std::uint16_t port, TxQueue& q) noexcept;

  io::IoBackend* backend_;  // borrowed: its owner outlives the worker
  Recycler* recycler_;
  std::size_t burst_;
  stat::Counters stats_;
  std::vector<TxQueue> requests_;  // per port, filled by the ARP cache through ArpCacheEvents
  ArpCacheEvents arp_events_;
  table::ArpCache arp_;
  table::MacTable macs_;
  Pipeline pipeline_;
  FloodSets flood_sets_;              // per port: where a frame it floods goes
  std::vector<TxQueue> forward_;      // per port
  std::vector<TxQueue> flood_;        // per port: flooded frames and their copies
  std::vector<TxQueue> arp_replies_;  // per port: the ARP requests deliver_to_host() turned around
  std::vector<TxQueue> icmp_;         // per port: echo replies and ICMP errors
  std::vector<NewsRing*> news_out_;   // borrowed, like the rings below
  std::vector<NewsRing*> news_in_;
  std::array<core::Packet*, core::kMaxBurst> rx_{};
  std::array<Decision, core::kMaxBurst> decisions_{};
  core::Clock::time_point next_mac_age_;
};

// --- pipeline mode -------------------------------------------------------------------------------

// The worker a packet goes to in pipeline mode: its flow's symmetric hash, kept to the low bits.
// workers is a power of two. A fragment has its addresses hashed with no ports, whether it carries
// the transport header or not, so all of a datagram's fragments go to one worker -- as the kernel's
// own flow hash treats them. Anything that is not IPv4, ARP included, goes to worker 0.
[[nodiscard]] std::size_t steer(const core::Packet& p, std::size_t workers) noexcept;

// How a producer wakes a consumer that ran out of work and went to sleep, without a system call
// while the consumer is busy. The consumer arms the bell, checks its rings one last time, and only
// then sleeps in poll() on fd(); a producer, after each push, takes the state back to awake and
// writes the eventfd only if it was asleep. Every change of the state is an acq_rel exchange, so
// all of them form one release sequence: either the producer's exchange comes after the
// consumer's arm in that order, and the producer sees "asleep" and writes, or it comes before,
// and the consumer's arm synchronizes with it -- so the push happened before the consumer's last
// check, which sees the packet. A wake-up cannot be lost between the check and the sleep.
class Doorbell {
 public:
  Doorbell();  // start-up: throws std::system_error if the eventfd cannot be made

  // Producer, after a push.
  void ring() noexcept;
  // Consumer: arm() before its last check of the rings, disarm() once awake again.
  void arm() noexcept;
  void disarm() noexcept;
  [[nodiscard]] int fd() const noexcept { return fd_.get(); }

 private:
  static constexpr std::uint32_t kAwake = 0;
  static constexpr std::uint32_t kAsleep = 1;
  std::atomic<std::uint32_t> state_{kAwake};
  core::UniqueFd fd_;
};

// The rings of pipeline mode: from each RX thread to each worker, and from each worker home to
// each RX thread. Made at start-up, in one place, so both ends find the same ring.
class PipelineRings {
 public:
  PipelineRings(std::size_t rx_threads, std::size_t workers);
  [[nodiscard]] PacketRing& to_worker(std::size_t rx, std::size_t worker) noexcept {
    return *to_worker_[(rx * workers_) + worker];
  }
  [[nodiscard]] ReturnRing& home(std::size_t worker, std::size_t rx) noexcept {
    return *home_[(worker * rx_threads_) + rx];
  }

 private:
  std::size_t rx_threads_;
  std::size_t workers_;
  std::vector<std::unique_ptr<PacketRing>> to_worker_;
  std::vector<std::unique_ptr<ReturnRing>> home_;
};

// The news rings between n workers, one for each ordered pair.
class NewsRings {
 public:
  explicit NewsRings(std::size_t workers);
  [[nodiscard]] NewsRing& between(std::size_t from, std::size_t to) noexcept {
    return *rings_[(from * workers_) + to];
  }
  // Connects every worker to every other.
  void connect(std::span<Worker* const> workers);

 private:
  std::size_t workers_;
  std::vector<std::unique_ptr<NewsRing>> rings_;  // [from][to]; from == to unused
};

// One pipeline RX thread's work: take home the packets the workers have finished with, receive a
// burst on its port, and steer each packet to its worker. A packet whose worker's ring is full is
// dropped here, counted in this stage's own counters as received and as RingFull.
// [phase 16] What an RX stage does when a worker's ring cannot take what it receives
// (ARCHITECTURE.md §12): drop the packet as RingFull, or receive no more than every ring can take,
// leaving the rest in the kernel.
enum class RxOverflow : std::uint8_t { Drop, HoldBack };

class RxStage {
 public:
  // rx receives on one port, into pool. rings: this stage's rings. bells: each worker's.
  RxStage(io::IoBackend& rx, core::PacketPool& pool, PipelineRings& rings, std::size_t index,
          std::span<Doorbell* const> bells, std::size_t burst,
          RxOverflow overflow = RxOverflow::Drop);

  std::size_t run_once() noexcept;

  // After every thread has ended: every packet of this stage's pool still in a ring -- waiting for
  // a worker that has stopped, or on its way home -- is put back in the pool.
  void reclaim() noexcept;

  [[nodiscard]] const stat::Counters& stats() const noexcept { return stats_; }
  [[nodiscard]] const core::PacketPool& pool() const noexcept { return *pool_; }

 private:
  void take_home() noexcept;

  io::IoBackend* source_;  // all borrowed, and outliving the stage's thread
  core::PacketPool* pool_;
  std::vector<PacketRing*> out_;   // by worker
  std::vector<ReturnRing*> home_;  // by worker
  std::vector<Doorbell*> bells_;   // by worker
  std::size_t burst_;
  RxOverflow overflow_;
  stat::Counters stats_;
  std::array<core::Packet*, core::kMaxBurst> rx_{};
  std::vector<std::array<core::Packet*, core::kMaxBurst>> staged_;  // by worker
  std::vector<std::size_t> n_staged_;
};

// A pipeline worker's backend: it receives from the rings its RX threads fill, and transmits
// through Tx -- anything with AfPacketBackend's send() and ports() -- handing each packet it sent
// to the Recycler, which takes it home. Tx is a template parameter so that a test can stand in for
// the sockets.
template <class Tx>
class RingBackend final : public io::IoBackend {
 public:
  RingBackend(std::vector<PacketRing*> in, Tx& tx, Recycler& recycler, Doorbell& bell)
      : in_{std::move(in)}, tx_{&tx}, recycler_{&recycler}, bell_{&bell} {}

  [[nodiscard]] std::size_t rx_burst(core::Packet** out, std::size_t max) noexcept override {
    std::size_t got = 0;
    const std::size_t n = in_.size();
    for (std::size_t k = 0; k < n && got < max; ++k) {
      got += in_[(next_ + k) % n]->pop_bulk(out + got, max - got);
    }
    next_ = n == 0 ? 0 : (next_ + 1) % n;
    return got;
  }

  // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
  [[nodiscard]] std::size_t tx_burst(core::Packet* const* in, std::size_t n,
                                     std::uint16_t port) noexcept override {
    const std::size_t sent = tx_->send(in, n, port);
    for (std::size_t i = 0; i < sent; ++i) {
      recycler_->release(in[i]);
    }
    return sent;
  }

  // Tx's own: a ring backend sends what send() queued only when kicked.
  void tx_flush() noexcept override { tx_->tx_flush(); }
  [[nodiscard]] std::span<const io::PortInfo> ports() const noexcept override {
    return tx_->ports();
  }
  [[nodiscard]] const char* name() const noexcept override { return "pipeline"; }

  // The consumer's half of the Doorbell, for the thread's idle wait: arms the bell and says
  // whether the rings are still empty, so that it may sleep.
  [[nodiscard]] bool arm_and_check_empty() noexcept {
    bell_->arm();
    return std::ranges::all_of(in_, [](const PacketRing* r) { return r->empty(); });
  }
  [[nodiscard]] Doorbell& bell() noexcept { return *bell_; }

 private:
  std::vector<PacketRing*> in_;  // by RX thread; all borrowed
  Tx* tx_;
  Recycler* recycler_;
  Doorbell* bell_;
  std::size_t next_{0};
};

// --- the control thread's hold on the others -----------------------------------------------------

// How the control thread gets every worker and RX thread to stand still between two bursts, so it
// may read their counters and tables, or flush their ARP caches, without racing them (§10).
//
// park_all() raises the request and wakes any party asleep in poll() through wake_fd(), which
// every party polls. Each party, at its next checkpoint(), sees the new request, counts itself
// parked, and waits for the release. park_all() returns once all are parked: the acquire that
// reads the last count synchronizes with every party's increment, so everything the parties
// wrote is visible. resume_all() releases them; their acquire of the release makes everything the
// control thread did visible to them in turn. A party pays one acquire load per burst when no one
// asks.
class Rendezvous {
 public:
  explicit Rendezvous(std::size_t parties);  // start-up: throws if the eventfd cannot be made

  // Control thread.
  void park_all() noexcept;
  void resume_all() noexcept;
  void stop_all() noexcept;  // the parties' next checkpoint() returns false; not while parked

  // Each party, between bursts. Parks if asked; false once the parties are to stop.
  [[nodiscard]] bool checkpoint(std::uint32_t& seen) noexcept;

  [[nodiscard]] int wake_fd() const noexcept { return wake_.get(); }

 private:
  std::size_t parties_;
  std::uint32_t generation_{0};  // the control thread's
  std::atomic<std::uint32_t> requested_{0};
  std::atomic<std::uint32_t> released_{0};
  std::atomic<std::uint32_t> parked_{0};
  std::atomic<bool> stop_{false};
  core::UniqueFd wake_;
};

// The loop each thread runs: checkpoint, a burst, and when the burst found nothing, idle() -- a
// wait in poll() for the thread's descriptors and the rendezvous's, or nothing when busy-polling.
template <class Burst, class Idle>
void serve_loop(Rendezvous& rv, Burst burst, Idle idle) noexcept {
  std::uint32_t seen = 0;
  while (rv.checkpoint(seen)) {
    if (burst() == 0) {
      idle();
    }
  }
}

}  // namespace npf::pipe
