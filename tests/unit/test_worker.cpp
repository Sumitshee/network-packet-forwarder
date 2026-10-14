// The worker threads of phase 13, in process, with fake backends standing in for the sockets: the
// pieces one at a time, then both execution models running on real threads. Run under
// ThreadSanitizer (the tsan preset) these are the race checks on the threading code that CI can
// make without root; the netns tests make the rest.

#include <gtest/gtest.h>
#include <poll.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <npf/core/byte_span.hpp>
#include <npf/core/config.hpp>
#include <npf/core/packet.hpp>
#include <npf/core/pool.hpp>
#include <npf/core/time.hpp>
#include <npf/io/backend.hpp>
#include <npf/pipe/decision.hpp>
#include <npf/pipe/filter.hpp>
#include <npf/pipe/forward.hpp>
#include <npf/pipe/worker.hpp>
#include <npf/proto/arp.hpp>
#include <npf/proto/checksum.hpp>
#include <npf/proto/ethernet.hpp>
#include <npf/proto/ipv4.hpp>
#include <npf/proto/l4.hpp>
#include <npf/proto/mac.hpp>
#include <npf/stat/counters.hpp>
#include <npf/table/arp_cache.hpp>
#include <npf/table/lpm_linear.hpp>
#include <optional>
#include <span>
#include <thread>
#include <vector>

#include "support/proto_helpers.hpp"

namespace {

using npf::DropReason;
using npf::core::CBytes;
using npf::core::Config;
using npf::core::Packet;
using npf::core::PacketPool;
using npf::core::rd_be16;
using npf::core::rd_be32;
using npf::core::wr_be16;
using npf::core::wr_be32;
using npf::core::wr_u8;
using npf::io::PortInfo;
using npf::pipe::Doorbell;
using npf::pipe::NewsRings;
using npf::pipe::PipelineRings;
using npf::pipe::Recycler;
using npf::pipe::Rendezvous;
using npf::pipe::ReturnRing;
using npf::pipe::RingBackend;
using npf::pipe::RxStage;
using npf::pipe::Worker;
using npf::proto::ArpView;
using npf::proto::MacAddr;
using npf::stat::Counters;
using npf::test::ip4;

using Frame = std::vector<std::byte>;

constexpr MacAddr kPort0Mac{{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}};
constexpr MacAddr kPort1Mac{{0x02, 0x00, 0x00, 0x00, 0x00, 0x11}};
constexpr MacAddr kClientMac{{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01}};
constexpr MacAddr kServerMac{{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02}};
constexpr MacAddr kLateMac{{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x03}};
constexpr std::uint32_t kPort0Ip = ip4(10, 0, 1, 1);
constexpr std::uint32_t kPort1Ip = ip4(10, 0, 2, 1);
constexpr std::uint32_t kClient = ip4(10, 0, 1, 2);
constexpr std::uint32_t kServer = ip4(10, 0, 2, 2);
constexpr std::uint32_t kLate = ip4(10, 0, 2, 3);  // a neighbour with no static ARP entry
constexpr std::uint16_t kServerPort = 5001;
constexpr std::uint16_t kFirstFlowPort = 10000;
constexpr auto kDeadline = std::chrono::seconds{60};  // generous: TSan is slow

// The phase 0.5 topology: client on port 0, server on port 1, both with static ARP entries.
Config topology() {
  Config c;
  c.interfaces = {
      {"veth-cr", 0, kPort0Ip, 24, npf::PortMode::Routed, kPort0Mac},
      {"veth-sr", 1, kPort1Ip, 24, npf::PortMode::Routed, kPort1Mac},
  };
  c.routes = {{{ip4(10, 0, 1, 0), 24}, 0, 0}, {{ip4(10, 0, 2, 0), 24}, 0, 1}};
  c.arp = {{kClient, kClientMac, 0}, {kServer, kServerMac, 1}};
  c.pool_size = 512;
  c.burst = 32;
  return c;
}

std::vector<PortInfo> port_infos(const Config& c) {
  std::vector<PortInfo> out;
  for (const npf::core::InterfaceConfig& i : c.interfaces) {
    out.push_back({.id = i.port,
                   .name = i.name,
                   .mac = *i.mac,
                   .ip = i.ip,
                   .prefix_len = i.prefix_len,
                   .mode = i.mode,
                   .bridge_domain = i.bridge_domain,
                   .up = true});
  }
  return out;
}

struct LinkSide {
  MacAddr dst;  // the router's port
  MacAddr src;  // the host's
};

// A UDP datagram of flow `flow`, its sequence number in the IP ID and in the payload: the frame
// bench/system/gen sends, near enough. From the client on port 0 unless reverse.
Frame udp(std::uint16_t flow, std::uint32_t seq, bool reverse = false, std::uint32_t dst = kServer,
          std::uint16_t flags_frag = 0) {
  const LinkSide side = reverse ? LinkSide{kPort1Mac, kServerMac} : LinkSide{kPort0Mac, kClientMac};
  Frame f(14 + 20 + 8 + 8);
  npf::proto::wr_mac(f, 0, side.dst);
  npf::proto::wr_mac(f, 6, side.src);
  wr_be16(f, 12, npf::proto::kEtherTypeIpv4);
  const std::span<std::byte> ip = std::span(f).subspan(14, 20);
  wr_u8(ip, 0, 0x45);
  wr_be16(ip, 2, 20 + 8 + 8);
  wr_be16(ip, 4, static_cast<std::uint16_t>(seq));
  wr_be16(ip, 6, flags_frag);
  wr_u8(ip, 8, 64);
  wr_u8(ip, 9, npf::proto::kIpProtoUdp);
  wr_be32(ip, 12, reverse ? kServer : kClient);
  wr_be32(ip, 16, reverse ? kClient : dst);
  wr_be16(ip, 10, npf::proto::ipv4_header_checksum(ip));
  const std::span<std::byte> l4 = std::span(f).subspan(34);
  const auto flow_port = static_cast<std::uint16_t>(kFirstFlowPort + flow);
  wr_be16(l4, 0, reverse ? kServerPort : flow_port);
  wr_be16(l4, 2, reverse ? flow_port : kServerPort);
  wr_be16(l4, 4, 16);
  wr_be32(l4, 12, seq);
  return f;
}

Frame arp_reply_from_late() {
  Frame f(14 + 28);
  npf::proto::wr_mac(f, 0, kPort1Mac);
  npf::proto::wr_mac(f, 6, kLateMac);
  wr_be16(f, 12, npf::proto::kEtherTypeArp);
  const std::span<std::byte> body = std::span(f).subspan(14);
  wr_be16(body, 0, ArpView::kHtypeEthernet);
  wr_be16(body, 2, npf::proto::kEtherTypeIpv4);
  wr_u8(body, 4, 6);
  wr_u8(body, 5, 4);
  wr_be16(body, 6, ArpView::kOpReply);
  npf::proto::wr_mac(body, 8, kLateMac);
  wr_be32(body, 14, kLate);
  npf::proto::wr_mac(body, 18, kPort1Mac);
  wr_be32(body, 24, kPort1Ip);
  return f;
}

// What a transmitted frame of udp() says about itself.
struct Sent {
  std::uint16_t port;
  std::uint16_t flow;  // 0xFFFF: not one of udp()'s
  std::uint32_t seq;
};

Sent describe(CBytes frame, std::uint16_t port) {
  if (frame.size() < 50 || rd_be16(frame, 12) != npf::proto::kEtherTypeIpv4) {
    return {port, 0xFFFF, 0};
  }
  const std::uint16_t sport = rd_be16(frame, 34);
  const std::uint16_t dport = rd_be16(frame, 36);
  const std::uint16_t flow_port = sport == kServerPort ? dport : sport;
  return {port, static_cast<std::uint16_t>(flow_port - kFirstFlowPort), rd_be32(frame, 46)};
}

struct Arrival {
  Frame frame;
  std::uint16_t port;
};

// A backend that receives a fixed list of frames, as far as the test allows, and writes down what
// it is asked to send. Its own thread's only, but for allow(), which the test may call from any.
class FakeBackend final : public npf::io::IoBackend {
 public:
  FakeBackend(PacketPool& pool, std::vector<PortInfo> ports, std::vector<Arrival> arrivals)
      : pool_{&pool}, ports_{std::move(ports)}, arrivals_{std::move(arrivals)} {
    sent_.reserve(arrivals_.size() + 64);
  }

  void allow(std::size_t n) { allowed_.store(n, std::memory_order_release); }
  void allow_all() { allow(arrivals_.size()); }

  std::size_t rx_burst(Packet** out, std::size_t max) noexcept override {
    const std::size_t limit = std::min(allowed_.load(std::memory_order_acquire), arrivals_.size());
    std::size_t got = 0;
    while (got < max && next_ < limit) {
      Packet* p = pool_->acquire();
      if (p == nullptr) {
        break;
      }
      const Arrival& a = arrivals_[next_++];
      p->resize(a.frame.size());
      std::ranges::copy(a.frame, p->data().begin());
      p->set_in_port(a.port);
      out[got++] = p;
    }
    return got;
  }

  std::size_t tx_burst(Packet* const* in, std::size_t n, std::uint16_t port) noexcept override {
    const std::size_t sent = send(in, n, port);
    for (std::size_t i = 0; i < sent; ++i) {
      pool_->release(in[i]);
    }
    return sent;
  }

  // RingBackend's Tx: writes down, never releases.
  std::size_t send(const Packet* const* in, std::size_t n, std::uint16_t port) noexcept {
    for (std::size_t i = 0; i < n; ++i) {
      sent_.push_back(describe(in[i]->data(), port));  // reserved: test-only, and seldom grows
    }
    return n;
  }

  void tx_flush() noexcept override {}
  [[nodiscard]] std::span<const PortInfo> ports() const noexcept override { return ports_; }
  [[nodiscard]] const char* name() const noexcept override { return "fake"; }

  // Once the thread that used it has ended.
  [[nodiscard]] const std::vector<Sent>& sent() const { return sent_; }
  [[nodiscard]] bool drained() const { return next_ == arrivals_.size(); }

 private:
  PacketPool* pool_;
  std::vector<PortInfo> ports_;
  std::vector<Arrival> arrivals_;
  std::atomic<std::size_t> allowed_{0};
  std::size_t next_{0};
  std::vector<Sent> sent_;
};

npf::pipe::Worker::FloodSets no_flooding(const Config& c) {
  return Worker::FloodSets(c.interfaces.size());
}

// Every packet received is forwarded, flooded, delivered or dropped -- exactly once.
std::uint64_t accounted(const Counters& c) {
  return c.forwarded + c.flooded + c.to_host + c.total_drops();
}

// --- the pieces, on one thread -------------------------------------------------------------------

TEST(Steer, BothDirectionsOfAFlowGoToOneWorker) {
  PacketPool pool(4);
  for (std::uint16_t flow = 0; flow < 64; ++flow) {
    Packet* there = pool.acquire();
    Packet* back = pool.acquire();
    const Frame a = udp(flow, 1);
    const Frame b = udp(flow, 1, true);
    there->resize(a.size());
    std::ranges::copy(a, there->data().begin());
    back->resize(b.size());
    std::ranges::copy(b, back->data().begin());
    EXPECT_EQ(npf::pipe::steer(*there, 8), npf::pipe::steer(*back, 8)) << "flow " << flow;
    pool.release(there);
    pool.release(back);
  }
}

TEST(Steer, FlowsSpreadOverWorkers) {
  PacketPool pool(1);
  Packet* p = pool.acquire();
  std::array<int, 8> load{};
  for (std::uint16_t flow = 0; flow < 800; ++flow) {
    const Frame f = udp(flow, 1);
    p->resize(f.size());
    std::ranges::copy(f, p->data().begin());
    ++load.at(npf::pipe::steer(*p, load.size()));
  }
  for (const int n : load) {
    EXPECT_GT(n, 60);  // 100 each on average
  }
  pool.release(p);
}

// A fragment carries no ports a later fragment could repeat, so every fragment hashes on its
// addresses alone: the first, with its UDP header, goes where the second does.
TEST(Steer, FragmentsOfADatagramGoTogether) {
  PacketPool pool(2);
  Packet* first = pool.acquire();
  Packet* second = pool.acquire();
  for (std::uint16_t flow = 0; flow < 64; ++flow) {
    const Frame a = udp(flow, 1, false, kServer, 0x2000);  // MF, offset 0
    const Frame b = udp(flow, 1, false, kServer, 0x0002);  // offset 16
    first->resize(a.size());
    std::ranges::copy(a, first->data().begin());
    second->resize(b.size());
    std::ranges::copy(b, second->data().begin());
    EXPECT_EQ(npf::pipe::steer(*first, 8), npf::pipe::steer(*second, 8));
  }
  pool.release(first);
  pool.release(second);
}

TEST(Steer, AnythingButIpv4GoesToWorkerZero) {
  PacketPool pool(1);
  Packet* p = pool.acquire();
  const Frame arp = arp_reply_from_late();
  p->resize(arp.size());
  std::ranges::copy(arp, p->data().begin());
  EXPECT_EQ(npf::pipe::steer(*p, 8), 0U);
  p->resize(5);  // a runt
  EXPECT_EQ(npf::pipe::steer(*p, 8), 0U);
  pool.release(p);
}

TEST(Recycler, SendsEachPacketHomeToItsOwnPool) {
  PacketPool own(4);
  PacketPool rx(4);
  auto home = std::make_unique<ReturnRing>();
  Recycler recycler(own);
  recycler.add_home(rx, *home);
  Packet* mine = own.acquire();
  Packet* theirs = rx.acquire();
  recycler.release(mine);
  recycler.release(theirs);
  EXPECT_EQ(own.available(), own.capacity());
  EXPECT_EQ(rx.available(), rx.capacity() - 1);  // on its way home
  Packet* back = nullptr;
  ASSERT_TRUE(home->pop(back));
  EXPECT_EQ(back, theirs);
  rx.release(back);
}

// A worker that never takes its packets: the ring fills, and every packet after that is dropped
// by the RX stage -- counted as received and as RingFull, its buffer straight back in the pool.
TEST(RxStage, APacketForAFullRingIsCountedAsRingFull) {
  const Config cfg = topology();
  constexpr std::size_t kSent = npf::pipe::kWorkerRingSize + 300;
  PacketPool pool(kSent + 16);
  std::vector<Arrival> arrivals;
  for (std::uint32_t seq = 0; seq < kSent; ++seq) {
    arrivals.push_back({udp(0, seq), 0});
  }
  FakeBackend source(pool, port_infos(cfg), std::move(arrivals));
  source.allow_all();
  PipelineRings rings(1, 1);
  Doorbell bell;
  std::array<Doorbell*, 1> bells{&bell};
  RxStage stage(source, pool, rings, 0, bells, cfg.burst);
  while (!source.drained()) {
    stage.run_once();
  }
  EXPECT_EQ(stage.stats().rx_packets, kSent - npf::pipe::kWorkerRingSize);
  EXPECT_EQ(stage.stats().drop(DropReason::RingFull), kSent - npf::pipe::kWorkerRingSize);
  EXPECT_EQ(pool.available(), pool.capacity() - npf::pipe::kWorkerRingSize);  // in the ring
  stage.reclaim();
  EXPECT_EQ(pool.available(), pool.capacity());
}

bool readable(int fd) {
  pollfd p{fd, POLLIN, 0};
  return ::poll(&p, 1, 0) == 1;
}

TEST(Doorbell, RingsOnlyASleepingConsumer) {
  Doorbell bell;
  bell.ring();  // awake: no write
  EXPECT_FALSE(readable(bell.fd()));
  bell.arm();
  bell.ring();
  EXPECT_TRUE(readable(bell.fd()));
  bell.disarm();
  EXPECT_FALSE(readable(bell.fd()));
  bell.ring();  // awake again
  EXPECT_FALSE(readable(bell.fd()));
}

// Two workers, one thread, driven by hand: worker B has packets waiting on a neighbour, the
// neighbour's reply reaches only worker A, and B learns of it through the news ring.
TEST(ArpNews, AReplyOneWorkerHearsReleasesAnothersQueue) {
  const Config cfg = topology();
  npf::table::LinearLpm fib;
  for (const npf::table::Route& r : cfg.routes) {
    ASSERT_TRUE(fib.add(r));
  }
  const npf::pipe::Filter filter({}, npf::pipe::Action::Allow);
  PacketPool pool_a(64);
  PacketPool pool_b(64);
  FakeBackend backend_a(pool_a, port_infos(cfg), {{arp_reply_from_late(), 1}});
  FakeBackend backend_b(pool_b, port_infos(cfg),
                        {{udp(1, 1, false, kLate), 0}, {udp(1, 2, false, kLate), 0}});
  Recycler recycler_a(pool_a);
  Recycler recycler_b(pool_b);
  Worker a(cfg, fib, filter, backend_a, recycler_a, no_flooding(cfg));
  Worker b(cfg, fib, filter, backend_b, recycler_b, no_flooding(cfg));
  NewsRings news(2);
  std::array<Worker*, 2> workers{&a, &b};
  news.connect(workers);
  const npf::core::Clock::time_point now{std::chrono::hours{1}};

  backend_b.allow_all();
  b.run_one_burst(now);
  ASSERT_EQ(b.arp().peek(kLate)->queued, 2U);
  EXPECT_EQ(b.stats().arp_requests_tx, 1U);

  backend_a.allow_all();
  a.run_one_burst(now);  // A hears the reply: its own cache never asked, so it learns nothing
  EXPECT_EQ(a.stats().arp_replies_rx, 1U);
  EXPECT_FALSE(a.arp().peek(kLate).has_value());

  b.run_one_burst(now);  // B applies A's news
  EXPECT_EQ(b.stats().arp_replies_rx, 0U);
  EXPECT_EQ(b.stats().forwarded, 2U);
  EXPECT_EQ(b.arp().peek(kLate)->state, npf::table::ArpState::Reachable);
  ASSERT_EQ(backend_b.sent().size(), 3U);  // the request, then the two packets in order
  EXPECT_EQ(backend_b.sent()[1].seq, 1U);
  EXPECT_EQ(backend_b.sent()[2].seq, 2U);
  EXPECT_EQ(pool_b.available(), pool_b.capacity());
}

// News for a neighbour no worker asked about creates nothing: unsolicited ARP must not fill a
// cache, whichever worker heard it.
TEST(ArpNews, NewsOfANeighbourNoOneAskedAboutCreatesNothing) {
  const Config cfg = topology();
  npf::table::LinearLpm fib;
  const npf::pipe::Filter filter({}, npf::pipe::Action::Allow);
  PacketPool pool(16);
  FakeBackend backend(pool, port_infos(cfg), {});
  Recycler recycler(pool);
  Worker w(cfg, fib, filter, backend, recycler, no_flooding(cfg));
  auto ring = std::make_unique<npf::pipe::NewsRing>();
  w.add_news_in(*ring);
  ASSERT_TRUE(ring->push({.ip = kLate, .mac = kLateMac, .port = 1, .answer = true}));
  w.run_one_burst(npf::core::Clock::time_point{});
  EXPECT_FALSE(w.arp().peek(kLate).has_value());
}

// --- on real threads -----------------------------------------------------------------------------

// Polls cond, with the threads parked for each look, until it holds or the deadline passes.
bool eventually(Rendezvous& rv, const std::function<bool()>& cond) {
  const auto deadline = std::chrono::steady_clock::now() + kDeadline;
  while (std::chrono::steady_clock::now() < deadline) {
    rv.park_all();
    const bool done = cond();
    rv.resume_all();
    if (done) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{2});
  }
  return false;
}

// Per flow, the order in which its packets left: every flow must go out of one worker, its
// sequence numbers increasing.
void expect_flows_in_order(std::span<const std::vector<Sent>* const> per_worker) {
  std::map<std::uint16_t, std::size_t> owner;  // flow -> worker
  std::map<std::uint16_t, std::uint32_t> last;
  std::size_t out_of_order = 0;
  for (std::size_t w = 0; w < per_worker.size(); ++w) {
    for (const Sent& s : *per_worker[w]) {
      if (s.flow == 0xFFFF) {
        continue;
      }
      const std::uint16_t key = s.flow | static_cast<std::uint16_t>(s.port << 15U);
      const auto [it, fresh] = owner.emplace(key, w);
      EXPECT_EQ(it->second, w) << "flow " << s.flow << " left from two workers";
      if (!fresh && s.seq <= last[key]) {
        ++out_of_order;
      }
      last[key] = s.seq;
    }
  }
  EXPECT_EQ(out_of_order, 0U);
}

// Pipeline mode, whole: two RX stages, one per port, steer 15 flows each way to four workers on
// their own threads; the test thread parks them all, again and again, to watch. Every packet must
// be accounted for once, every flow must leave in order from a single worker, and every buffer
// must end up back in the pool it came from.
TEST(PipelineThreads, FlowsStayInOrderAndEveryBufferGoesHome) {
  constexpr std::size_t kWorkers = 4;
  constexpr std::size_t kPorts = 2;
  constexpr std::uint32_t kPerFlow = 1500;
  constexpr std::uint16_t kFlows = 15;  // not a multiple of the workers, so no accident of
                                        // arrival order can keep a flow on one worker
  const Config cfg = topology();
  npf::table::LinearLpm fib;
  for (const npf::table::Route& r : cfg.routes) {
    ASSERT_TRUE(fib.add(r));
  }
  const npf::pipe::Filter filter({}, npf::pipe::Action::Allow);

  std::vector<std::unique_ptr<PacketPool>> rx_pools;
  std::vector<std::unique_ptr<FakeBackend>> sources;
  for (std::size_t k = 0; k < kPorts; ++k) {
    std::vector<Arrival> arrivals;
    for (std::uint32_t seq = 1; seq <= kPerFlow; ++seq) {
      for (std::uint16_t flow = 0; flow < kFlows; ++flow) {
        arrivals.push_back({udp(flow, seq, k == 1), static_cast<std::uint16_t>(k)});
      }
    }
    rx_pools.push_back(std::make_unique<PacketPool>(cfg.pool_size));
    sources.push_back(
        std::make_unique<FakeBackend>(*rx_pools.back(), port_infos(cfg), std::move(arrivals)));
  }
  PipelineRings rings(kPorts, kWorkers);
  std::vector<std::unique_ptr<PacketPool>> pools;
  std::vector<std::unique_ptr<FakeBackend>> txs;
  std::vector<std::unique_ptr<Recycler>> recyclers;
  std::vector<std::unique_ptr<Doorbell>> bells;
  std::vector<Doorbell*> bell_ptrs;
  std::vector<std::unique_ptr<RingBackend<FakeBackend>>> backends;
  std::vector<std::unique_ptr<Worker>> workers;
  for (std::size_t w = 0; w < kWorkers; ++w) {
    pools.push_back(std::make_unique<PacketPool>(cfg.pool_size));
    txs.push_back(
        std::make_unique<FakeBackend>(*pools.back(), port_infos(cfg), std::vector<Arrival>{}));
    recyclers.push_back(std::make_unique<Recycler>(*pools.back()));
    std::vector<npf::pipe::PacketRing*> in;
    for (std::size_t k = 0; k < kPorts; ++k) {
      recyclers.back()->add_home(*rx_pools[k], rings.home(w, k));
      in.push_back(&rings.to_worker(k, w));
    }
    bells.push_back(std::make_unique<Doorbell>());
    bell_ptrs.push_back(bells.back().get());
    backends.push_back(std::make_unique<RingBackend<FakeBackend>>(
        std::move(in), *txs.back(), *recyclers.back(), *bells.back()));
    workers.push_back(std::make_unique<Worker>(cfg, fib, filter, *backends.back(),
                                               *recyclers.back(), no_flooding(cfg)));
  }
  std::vector<Worker*> worker_ptrs;
  for (const auto& w : workers) {
    worker_ptrs.push_back(w.get());
  }
  NewsRings news(kWorkers);
  news.connect(worker_ptrs);
  std::vector<std::unique_ptr<RxStage>> stages;
  for (std::size_t k = 0; k < kPorts; ++k) {
    stages.push_back(
        std::make_unique<RxStage>(*sources[k], *rx_pools[k], rings, k, bell_ptrs, cfg.burst));
  }

  Rendezvous rv(kWorkers + kPorts);
  {
    std::vector<std::jthread> threads;
    for (std::size_t w = 0; w < kWorkers; ++w) {
      threads.emplace_back([&rv, &worker = *workers[w], &backend = *backends[w]] {
        std::array<pollfd, 2> fds{{{backend.bell().fd(), POLLIN, 0}, {rv.wake_fd(), POLLIN, 0}}};
        npf::pipe::serve_loop(
            rv, [&worker] { return worker.run_one_burst(npf::core::Clock::now()); },
            [&backend, &fds] {
              if (backend.arm_and_check_empty()) {
                ::poll(fds.data(), fds.size(), 100);
              }
              backend.bell().disarm();
            });
      });
    }
    for (std::size_t k = 0; k < kPorts; ++k) {
      threads.emplace_back([&rv, &stage = *stages[k]] {
        pollfd wake{rv.wake_fd(), POLLIN, 0};
        npf::pipe::serve_loop(
            rv, [&stage] { return stage.run_once(); }, [&wake] { ::poll(&wake, 1, 1); });
      });
    }
    for (const auto& s : sources) {
      s->allow_all();
    }
    const std::uint64_t total = std::uint64_t{kPorts} * kFlows * kPerFlow;
    const bool all_accounted = eventually(rv, [&] {
      Counters sum;
      for (const auto& w : workers) {
        sum.merge(w->stats());
      }
      for (const auto& s : stages) {
        sum.merge(s->stats());
      }
      return sum.rx_packets == total && accounted(sum) == total;
    });
    EXPECT_TRUE(all_accounted) << "not every packet was accounted for within the deadline";
    rv.stop_all();
  }  // joined

  for (Worker* w : worker_ptrs) {
    w->arp().flush();
  }
  for (const auto& s : stages) {
    s->reclaim();
  }
  Counters sum;
  for (const auto& w : workers) {
    sum.merge(w->stats());
  }
  for (const auto& s : stages) {
    sum.merge(s->stats());
  }
  EXPECT_EQ(sum.rx_packets, accounted(sum));
  EXPECT_EQ(sum.forwarded + sum.drop(DropReason::RingFull), sum.rx_packets)
      << "a packet was dropped for a reason other than a full ring";
  EXPECT_GT(sum.forwarded, 0U);
  std::vector<const std::vector<Sent>*> sent;
  for (const auto& t : txs) {
    sent.push_back(&t->sent());
  }
  expect_flows_in_order(sent);
  for (const auto& p : rx_pools) {
    EXPECT_EQ(p->available(), p->capacity());
  }
  for (const auto& p : pools) {
    EXPECT_EQ(p->available(), p->capacity());
  }
}

// Run-to-completion, threaded: two workers with sources of their own each have packets waiting
// on a neighbour, and its reply reaches only the first. The second learns of it through the news
// ring, between bursts, while the test thread watches through the rendezvous.
TEST(RtcThreads, ArpNewsCrossesBetweenRunningWorkers) {
  const Config cfg = topology();
  npf::table::LinearLpm fib;
  for (const npf::table::Route& r : cfg.routes) {
    ASSERT_TRUE(fib.add(r));
  }
  const npf::pipe::Filter filter({}, npf::pipe::Action::Allow);
  PacketPool pool_a(64);
  PacketPool pool_b(64);
  FakeBackend backend_a(pool_a, port_infos(cfg),
                        {{udp(1, 1, false, kLate), 0}, {arp_reply_from_late(), 1}});
  FakeBackend backend_b(pool_b, port_infos(cfg),
                        {{udp(2, 1, false, kLate), 0}, {udp(2, 2, false, kLate), 0}});
  Recycler recycler_a(pool_a);
  Recycler recycler_b(pool_b);
  Worker a(cfg, fib, filter, backend_a, recycler_a, no_flooding(cfg));
  Worker b(cfg, fib, filter, backend_b, recycler_b, no_flooding(cfg));
  NewsRings news(2);
  std::array<Worker*, 2> workers{&a, &b};
  news.connect(workers);

  Rendezvous rv(2);
  {
    std::vector<std::jthread> threads;
    for (Worker* w : workers) {
      threads.emplace_back([&rv, w] {
        pollfd wake{rv.wake_fd(), POLLIN, 0};
        npf::pipe::serve_loop(
            rv, [w] { return w->run_one_burst(npf::core::Clock::now()); },
            [&wake] { ::poll(&wake, 1, 1); });
      });
    }
    backend_a.allow(1);
    backend_b.allow_all();
    EXPECT_TRUE(eventually(rv, [&] {
      const auto qa = a.arp().peek(kLate);
      const auto qb = b.arp().peek(kLate);
      return qa && qa->queued == 1 && qb && qb->queued == 2;
    }));
    backend_a.allow_all();  // now the reply
    EXPECT_TRUE(
        eventually(rv, [&] { return a.stats().forwarded == 1 && b.stats().forwarded == 2; }));
    rv.stop_all();
  }
  EXPECT_EQ(b.stats().arp_replies_rx, 0U);
  EXPECT_EQ(pool_a.available(), pool_a.capacity());
  EXPECT_EQ(pool_b.available(), pool_b.capacity());
}

// The rendezvous itself: while the threads are parked, nothing they own changes, and every one of
// them runs again after each release.
TEST(RendezvousThreads, ParkedThreadsStandStill) {
  constexpr std::size_t kThreads = 4;
  std::array<std::uint64_t, kThreads> counts{};  // plain: written only by its thread, between parks
  Rendezvous rv(kThreads);
  {
    std::vector<std::jthread> threads;
    for (std::size_t i = 0; i < kThreads; ++i) {
      threads.emplace_back([&rv, &count = counts.at(i)] {
        pollfd wake{rv.wake_fd(), POLLIN, 0};
        npf::pipe::serve_loop(
            rv,
            [&count] {
              ++count;
              return std::size_t{count % 3 == 0 ? 0U : 1U};  // idle now and then
            },
            [&wake] { ::poll(&wake, 1, 1); });
      });
    }
    std::array<std::uint64_t, kThreads> before{};
    for (int round = 0; round < 200; ++round) {
      rv.park_all();
      const std::array<std::uint64_t, kThreads> now = counts;
      for (std::size_t i = 0; i < kThreads; ++i) {
        EXPECT_GE(now.at(i), before.at(i));
      }
      std::this_thread::yield();
      EXPECT_EQ(counts, now) << "a parked thread ran";
      before = now;
      rv.resume_all();
    }
    rv.stop_all();
  }
  for (const std::uint64_t c : counts) {
    EXPECT_GT(c, 0U);
  }
}

}  // namespace
