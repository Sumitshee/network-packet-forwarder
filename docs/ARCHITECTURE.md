# Architecture and interface contracts

These interfaces are **fixed across phases**. A phase may add to them; a phase must not change a
signature that an earlier phase already implemented against. If a signature genuinely has to
change, change it here first, in its own commit, and say why in `docs/design-decisions.md`.

Phase numbers in brackets indicate when each type first appears.

---

## 1. The forwarding decision

The whole engine exists to produce one of these per packet.

```cpp
namespace npf {

enum class Verdict : std::uint8_t {
  Forward,   // out_port is set; transmit it
  Flood,     // L2: transmit on every port in the bridge domain except in_port
  ToHost,    // addressed to this router itself (ICMP echo, ARP request for us)
  Drop,      // drop_reason is set
  Queued,    // [phase 8] held by the ARP cache until the next hop resolves; out_port is set.
             // The cache owns the packet now: the caller must neither transmit nor release it.
};

enum class DropReason : std::uint8_t {
  None = 0,
  ShortFrame,        // frame shorter than a minimal Ethernet header
  BadEtherType,      // not IPv4, not ARP, not a VLAN tag we handle
  BadIpv4Header,     // version != 4, ihl < 5, total_length inconsistent, truncated
  BadChecksum,       // IPv4 header checksum mismatch
  MartianSource,     // RFC 1812 §5.3.7 source address that must never be forwarded
  TtlExpired,        // TTL <= 1 on receipt; an ICMP Time Exceeded may have been generated
  NoRoute,           // FIB miss; an ICMP Net Unreachable may have been generated
  ArpUnresolved,     // next hop never resolved, or the pending queue was full
  FilterDeny,        // packet filter said no
  NoOutPort,         // route named a port that does not exist or is down
  UnknownDestPort,   // L2 lookup miss on a port with no bridge domain
  TxFull,            // transmit ring or socket buffer full
  PoolExhausted,     // no free packet buffer
  _Count
};

// Result of processing one packet. Fits in 4 bytes; returned by value.
struct Decision {
  Verdict     verdict{Verdict::Drop};
  DropReason  reason{DropReason::None};
  std::uint16_t out_port{0};
};

}  // namespace npf
```

**Invariant:** every packet leaving the pipeline produces exactly one `Decision`, and every
`Verdict::Drop` carries a `reason != None`. Assert this in debug builds.

A `Queued` packet has not left yet. It leaves when the ARP cache lets go of it (§6): handed back
for transmission when the neighbour answers, or given up on and dropped as `ArpUnresolved`. It is
counted then, once, like any other packet.

---

## 2. The L2-versus-L3 rule  [phase 6, completed phase 12]

This is the single most important behavioural rule in the project. Implement it literally.

```cpp
// Ports are configured as one or the other.
enum class PortMode : std::uint8_t { Routed, Bridged };

// In Forwarder::process(), immediately after Ethernet parsing:
//
//   if (eth.dst() == port.mac || (eth.dst().is_broadcast() && dst_ip_is_ours))
//        -> L3 path: this frame is addressed to the router, route it
//   else if (port.mode == PortMode::Bridged)
//        -> L2 path: transit frame on a bridged port, switch it
//   else
//        -> Drop(UnknownDestPort)
//
// ARP frames addressed to this router's MAC or to broadcast go to the ARP handler
// before either path.
```

Write this rule verbatim in the README. You will be asked to explain it.

---

## 3. Packet buffers  [phase 1]

```cpp
namespace npf::core {

inline constexpr std::size_t kMaxFrame  = 2048;  // 1500 MTU + VLAN + slack, power-of-two friendly
inline constexpr std::size_t kHeadroom  = 64;    // room to prepend headers without copying
inline constexpr std::size_t kBurst     = 32;    // default batch size; tunable, measured in phase 15

// A borrowed, pool-owned frame buffer plus its metadata.
// Never constructed directly; never deleted. Acquire from a PacketPool, release to the same pool.
class Packet {
 public:
  [[nodiscard]] std::span<std::byte>       data() noexcept;
  [[nodiscard]] std::span<const std::byte> data() const noexcept;
  [[nodiscard]] std::size_t size() const noexcept;

  // Set the frame length. Must fit within the buffer from the current start offset.
  void resize(std::size_t n) noexcept;

  // Grow the frame at the front by n bytes, consuming headroom. Returns the new start,
  // or nullptr if there is not enough headroom. Does not copy.
  [[nodiscard]] std::byte* push(std::size_t n) noexcept;

  // Shrink the frame at the front by n bytes. Returns false if n > size().
  [[nodiscard]] bool pull(std::size_t n) noexcept;

  [[nodiscard]] std::uint16_t in_port() const noexcept;
  void set_in_port(std::uint16_t p) noexcept;

  [[nodiscard]] std::uint64_t rx_tsc() const noexcept;   // set by the backend at RX, for latency
  void set_rx_tsc(std::uint64_t t) noexcept;

  // Cached parse offsets, filled by the pipeline so later stages do not re-parse.
  [[nodiscard]] std::uint16_t l3_offset() const noexcept;
  [[nodiscard]] std::uint16_t l4_offset() const noexcept;
  void set_offsets(std::uint16_t l3, std::uint16_t l4) noexcept;

 private:
  friend class PacketPool;
  std::byte*    base_;      // start of this packet's slot in the pool's backing storage
  Packet*       free_next_; // intrusive free-list link, valid only while in the pool
  std::uint16_t off_;       // frame start offset within the slot (>= kHeadroom initially)
  std::uint16_t len_;
  std::uint16_t in_port_;
  std::uint16_t l3_off_, l4_off_;
  std::uint64_t rx_tsc_;
};

static_assert(sizeof(Packet) <= 64, "Packet metadata must fit in one cache line");

// One contiguous allocation, made once in the constructor. Not thread-safe by design:
// every worker owns its own pool, so no synchronisation is needed on the hot path.
class PacketPool {
 public:
  explicit PacketPool(std::size_t count);
  PacketPool(const PacketPool&) = delete;
  PacketPool& operator=(const PacketPool&) = delete;
  ~PacketPool();

  [[nodiscard]] Packet* acquire() noexcept;   // nullptr when exhausted; never allocates
  void release(Packet* p) noexcept;           // never deallocates

  [[nodiscard]] std::size_t capacity()  const noexcept;
  [[nodiscard]] std::size_t available() const noexcept;   // for leak assertions in tests
};

}  // namespace npf::core
```

**Ownership:** a `Packet*` is borrowed. Exactly one of these things happens to every acquired
packet: it is transmitted (and released by the backend after transmission completes), it is
released explicitly on a drop, or it is handed to the ARP pending queue which becomes responsible
for releasing it. Nothing else.

---

## 4. Protocol views  [phases 2–4]

All in `namespace npf::proto`, all header-only, all constructed through a validating factory.
`CBytes` / `Bytes` are the `std::span<const std::byte>` / `std::span<std::byte>` aliases from
`core/byte_span.hpp`; the two spellings are interchangeable throughout this document.

```cpp
struct MacAddr {
  std::array<std::uint8_t, 6> b{};
  [[nodiscard]] bool is_broadcast() const noexcept;   // ff:ff:ff:ff:ff:ff
  [[nodiscard]] bool is_multicast() const noexcept;   // low bit of the first octet
  [[nodiscard]] bool is_zero()      const noexcept;
  friend bool operator==(const MacAddr&, const MacAddr&) noexcept = default;
};

class EthView {
 public:
  static constexpr std::size_t kMinSize = 14;
  [[nodiscard]] static std::optional<EthView> parse(std::span<const std::byte>) noexcept;
  [[nodiscard]] MacAddr       dst() const noexcept;
  [[nodiscard]] MacAddr       src() const noexcept;
  [[nodiscard]] std::uint16_t ethertype() const noexcept;   // VLAN already unwrapped
  [[nodiscard]] bool          has_vlan() const noexcept;
  [[nodiscard]] std::uint16_t vlan_id()  const noexcept;
  [[nodiscard]] std::size_t   header_len() const noexcept;  // 14, or 18 with one VLAN tag
  [[nodiscard]] std::span<const std::byte> payload() const noexcept;
};

class ArpView {
 public:
  static constexpr std::size_t kMinSize = 28;
  // Validates htype==1, ptype==0x0800, hlen==6, plen==4, and total length >= 28.
  [[nodiscard]] static std::optional<ArpView> parse(std::span<const std::byte>) noexcept;
  [[nodiscard]] std::uint16_t oper() const noexcept;   // 1 request, 2 reply
  [[nodiscard]] MacAddr       sha()  const noexcept;
  [[nodiscard]] std::uint32_t spa()  const noexcept;   // host order
  [[nodiscard]] MacAddr       tha()  const noexcept;
  [[nodiscard]] std::uint32_t tpa()  const noexcept;
};

class Ipv4View {
 public:
  static constexpr std::size_t kMinSize = 20;
  // Validates: size >= 20, version == 4, ihl >= 5, ihl*4 <= size,
  //            total_length >= ihl*4, total_length <= size.
  // Does NOT validate the checksum — call ipv4_checksum_valid() separately, so the
  // pipeline can count BadChecksum distinctly from BadIpv4Header.
  [[nodiscard]] static std::optional<Ipv4View> parse(std::span<const std::byte>) noexcept;

  [[nodiscard]] std::uint8_t  ihl()          const noexcept;
  [[nodiscard]] std::size_t   header_len()   const noexcept;   // ihl * 4 — never hardcode 20
  [[nodiscard]] std::uint16_t total_length() const noexcept;
  [[nodiscard]] std::uint16_t identification() const noexcept;
  [[nodiscard]] bool          df() const noexcept;
  [[nodiscard]] bool          mf() const noexcept;
  [[nodiscard]] std::uint16_t frag_offset() const noexcept;    // in units of 8 bytes, as on the wire
  [[nodiscard]] std::uint8_t  ttl()      const noexcept;
  [[nodiscard]] std::uint8_t  protocol() const noexcept;
  [[nodiscard]] std::uint16_t checksum() const noexcept;
  [[nodiscard]] std::uint32_t src() const noexcept;            // host order
  [[nodiscard]] std::uint32_t dst() const noexcept;

  [[nodiscard]] bool is_fragment()       const noexcept;       // mf() || frag_offset() != 0
  [[nodiscard]] bool is_first_fragment() const noexcept;       // frag_offset() == 0

  // Sized by total_length, not by the input span — a padded Ethernet frame must not
  // leak padding into the payload.
  [[nodiscard]] std::span<const std::byte> payload() const noexcept;
  [[nodiscard]] std::span<const std::byte> header()  const noexcept;
};

// Layer 4. One struct rather than three view types: the pipeline only needs the fields.
struct L4Info {
  std::uint8_t  protocol{0};
  bool          ports_valid{false};   // FALSE for every non-initial fragment
  std::uint16_t sport{0}, dport{0};
  std::uint8_t  tcp_flags{0};
  std::uint32_t seq{0}, ack{0};
  std::uint8_t  icmp_type{0}, icmp_code{0};
};

// HARD RULE: if !ip.is_first_fragment(), this sets protocol and leaves ports_valid == false.
// It must not read a single byte of the L4 header in that case.
[[nodiscard]] std::optional<L4Info> parse_l4(const Ipv4View& ip) noexcept;

// ICMP needs more than L4Info can carry (echo id/seq, and the original datagram embedded in an
// error), so it gets a view of its own.
class IcmpView {
 public:
  static constexpr std::size_t kMinSize = 8;
  [[nodiscard]] static std::optional<IcmpView> parse(CBytes) noexcept;   // validates the checksum
  [[nodiscard]] std::uint8_t  type() const noexcept;
  [[nodiscard]] std::uint8_t  code() const noexcept;
  [[nodiscard]] std::uint16_t checksum() const noexcept;
  [[nodiscard]] std::uint16_t echo_id()  const noexcept;   // types 0 and 8 only
  [[nodiscard]] std::uint16_t echo_seq() const noexcept;
  [[nodiscard]] bool          is_error() const noexcept;   // types 3, 4, 5, 11, 12
  [[nodiscard]] CBytes        payload() const noexcept;    // for errors: the original datagram
};
```

### Checksums  [phase 3]

```cpp
[[nodiscard]] std::uint16_t ones_complement_sum(std::span<const std::byte>) noexcept;
[[nodiscard]] std::uint16_t ipv4_header_checksum(std::span<const std::byte> hdr) noexcept;
[[nodiscard]] bool          ipv4_checksum_valid(std::span<const std::byte> hdr) noexcept;

// RFC 1624 eqn. 3:  HC' = ~(~HC + ~m + m')
// Used after decrementing TTL so the whole header is never re-summed.
[[nodiscard]] std::uint16_t checksum_update16(std::uint16_t old_sum,
                                              std::uint16_t old_word,
                                              std::uint16_t new_word) noexcept;
```

---

## 5. Forwarding information base  [phase 5, implementations phase 10]

```cpp
namespace npf::table {

struct Prefix { std::uint32_t addr; std::uint8_t len; };   // addr is masked, host order

struct Route {
  Prefix        prefix;
  std::uint32_t next_hop;   // 0 means "directly connected, next hop is the packet's dst"
  std::uint16_t out_port;
};

struct NextHop {
  std::uint32_t ip;
  std::uint16_t port;
  friend bool operator==(const NextHop&, const NextHop&) noexcept = default;
};

// The polymorphic interface exists for tests and benchmarks, which iterate over
// implementations. The DATAPATH does not use it: Forwarder is templated on the concrete
// FIB type so the lookup is a direct call. Each implementation therefore provides
// lookup() as a non-virtual member, and the virtual override simply forwards to it.
class Fib {
 public:
  virtual ~Fib() = default;
  virtual bool add(const Route&) = 0;
  virtual bool remove(Prefix) = 0;
  virtual void clear() = 0;
  [[nodiscard]] virtual std::optional<NextHop> lookup_v(std::uint32_t dst) const noexcept = 0;
  [[nodiscard]] virtual std::size_t size() const noexcept = 0;
  [[nodiscard]] virtual std::size_t memory_bytes() const noexcept = 0;   // reported by bench_lpm
  [[nodiscard]] virtual const char* name() const noexcept = 0;
};

// Every implementation:
//   class LinearLpm final : public Fib {
//    public:
//     [[nodiscard]] std::optional<NextHop> lookup(std::uint32_t) const noexcept;  // hot path
//     std::optional<NextHop> lookup_v(std::uint32_t d) const noexcept override { return lookup(d); }
//   };
//
// Implementations, in build order:
//   LinearLpm    [phase 5]  — the oracle. Never optimise it.
//   BinaryTrie   [phase 10] — uncompressed, the cache-behaviour baseline.
//   PatriciaLpm  [phase 10] — path-compressed.
//   Dir24_8Lpm   [phase 10] — the fast one; see BUILD_PLAN phase 10 for the layout.

}  // namespace npf::table
```

---

## 6. ARP cache  [phase 6 minimal, phase 8 full]

```cpp
namespace npf::table {

enum class ArpState : std::uint8_t { Incomplete, Reachable, Stale };

inline constexpr std::size_t kArpQueueDepth = 3;      // matches Linux's unresolved queue
inline constexpr std::uint8_t kArpMaxProbes = 3;
inline constexpr auto kArpProbeInterval = std::chrono::seconds{1};
inline constexpr auto kArpReachable     = std::chrono::seconds{30};
inline constexpr auto kArpStaleTimeout  = std::chrono::seconds{60};

// Callback the cache uses to emit ARP requests and ICMP errors; injected so the
// cache has no dependency on the I/O layer and stays unit-testable.
class ArpEvents {
 public:
  virtual ~ArpEvents() = default;
  virtual void send_arp_request(std::uint32_t target_ip, std::uint16_t out_port) = 0;
  virtual void unresolved(core::Packet* p) = 0;   // emit ICMP 3/1 for the head, then release
  // [phase 8] Release a queued packet with no ICMP, counting it as ArpUnresolved: the packets
  // behind the head of a failed queue, and every packet flush() lets go of.
  virtual void discard(core::Packet* p) = 0;
};

class ArpCache {
 public:
  ArpCache(ArpEvents& ev, std::size_t capacity);

  // Hit refreshes the entry's timer. Miss does NOT create an entry — the caller decides.
  [[nodiscard]] std::optional<MacAddr> lookup(std::uint32_t ip) noexcept;

  // Creates an Incomplete entry if absent, sends a probe, and queues the packet.
  // Returns false if the queue is full; the caller must then release the packet and
  // count DropReason::ArpUnresolved.
  [[nodiscard]] bool resolve_and_queue(std::uint32_t ip, std::uint16_t out_port,
                                       core::Packet* p) noexcept;

  // Called on a received ARP reply. Fills 'ready' with the packets that can now be sent.
  void on_reply(std::uint32_t ip, MacAddr mac, std::vector<core::Packet*>& ready) noexcept;

  // Unsolicited/gratuitous ARP: refreshes an EXISTING entry only. Never creates one —
  // creating on unsolicited ARP is trivial cache poisoning. Documented in design-decisions.md.
  void on_unsolicited(std::uint32_t ip, MacAddr mac) noexcept;

  // Retransmits probes, expires entries, fails exhausted ones. Called once per loop
  // iteration from the worker, not from a timer thread.
  void tick(std::chrono::steady_clock::time_point now) noexcept;

  void insert_static(std::uint32_t ip, MacAddr mac, std::uint16_t port) noexcept;  // for replay determinism

  // [phase 8] Deletes every entry except the static ones, discarding the packets queued on them
  // through ArpEvents::discard. For a test's SIGUSR2, and at shutdown, so no buffer stays held.
  void flush() noexcept;
};

}  // namespace npf::table
```

---

## 7. MAC table  [phase 12]

```cpp
class MacTable {
 public:
  explicit MacTable(std::size_t capacity);   // rounded up to a power of two
  void learn(MacAddr src, std::uint16_t port, std::chrono::steady_clock::time_point now) noexcept;
  [[nodiscard]] std::optional<std::uint16_t> lookup(MacAddr dst) const noexcept;
  void age(std::chrono::steady_clock::time_point now) noexcept;   // default 300 s
  [[nodiscard]] std::size_t size() const noexcept;
};
```

Open-addressed, linear probing, power-of-two capacity, entries stored inline. No
`std::unordered_map` — node-per-entry means an allocation and a pointer chase per learn.

---

## 8. Packet filter  [phase 11]

```cpp
namespace npf::pipe {

enum class Action : std::uint8_t { Allow, Deny };
struct PortRange { std::uint16_t lo{0}, hi{65535}; };

struct Rule {
  Action action{Action::Allow};
  std::optional<table::Prefix> src, dst;          // nullopt == any
  std::optional<std::uint8_t>  protocol;
  std::optional<PortRange>     sport, dport;
  std::optional<std::uint16_t> in_port;
};

class Filter {
 public:
  explicit Filter(std::vector<Rule> rules, Action default_action);

  // First match wins. If l4.ports_valid is false (a non-initial fragment), any rule that
  // constrains sport or dport CANNOT match and is skipped. This is a deliberate, documented
  // limitation with a security implication — see README "Known limitations".
  [[nodiscard]] Action evaluate(const proto::Ipv4View& ip, const proto::L4Info& l4,
                                std::uint16_t in_port) const noexcept;
};

}  // namespace npf::pipe
```

---

## 8b. ICMP generation  [phase 7]

```cpp
namespace npf::pipe {

enum class IcmpError : std::uint8_t {
  TimeExceeded,      // type 11 code 0 — TTL expired in transit
  NetUnreachable,    // type  3 code 0 — FIB miss
  HostUnreachable,   // type  3 code 1 — ARP never resolved
  ProtoUnreachable,  // type  3 code 2
};

// Builds a complete Ethernet + IPv4 + ICMP error frame into `out`.
// ICMP payload = the original IP header + the first 8 bytes of its payload (RFC 792).
// src_ip MUST be the router's address on the interface the ORIGINAL packet arrived on —
// that is what makes traceroute print the correct hop.
[[nodiscard]] bool build_icmp_error(core::Packet& out,
                                    const proto::Ipv4View& orig, core::CBytes orig_frame,
                                    IcmpError err, std::uint32_t src_ip,
                                    proto::MacAddr src_mac, proto::MacAddr dst_mac) noexcept;

// Builds an Echo Reply for a ping addressed to one of this router's own interface IPs.
[[nodiscard]] bool build_echo_reply(core::Packet& out, const proto::Ipv4View& req,
                                    core::CBytes req_frame,
                                    proto::MacAddr src_mac, proto::MacAddr dst_mac) noexcept;

// RFC 1812 §4.3.2.7. False means an ICMP error must NOT be generated for this packet.
[[nodiscard]] bool may_send_icmp_error(const proto::Ipv4View& orig,
                                       const proto::L4Info& l4) noexcept;

// RFC 1812 §4.3.2.8. Token bucket, default 100 errors/second.
class IcmpRateLimiter {
 public:
  explicit IcmpRateLimiter(std::uint32_t per_second = 100);
  [[nodiscard]] bool allow(std::chrono::steady_clock::time_point now) noexcept;
};

}  // namespace npf::pipe
```

---

## 9. I/O backends  [phase 6, extended 9/16/17]

```cpp
namespace npf::io {

struct PortInfo {
  std::uint16_t id;
  std::string   name;        // "veth-cr"
  proto::MacAddr mac;
  std::uint32_t ip;          // the router's address on this port, host order; 0 if bridged-only
  std::uint8_t  prefix_len;
  PortMode      mode;
  std::uint16_t bridge_domain;
  bool          up;
};

// ONE virtual call per burst. Never per packet.
class IoBackend {
 public:
  virtual ~IoBackend() = default;

  // Fills 'out' with up to 'max' received packets, taken from the pool the backend was
  // constructed with. Returns the count. Non-blocking; returns 0 when nothing is ready.
  [[nodiscard]] virtual std::size_t rx_burst(core::Packet** out, std::size_t max) = 0;

  // Queues packets for transmission on 'port'. Takes ownership: transmitted packets are
  // released back to the pool by the backend. Returns how many were accepted; the caller
  // releases the remainder and counts DropReason::TxFull.
  [[nodiscard]] virtual std::size_t tx_burst(core::Packet* const* in, std::size_t n,
                                             std::uint16_t port) = 0;

  virtual void tx_flush() = 0;
  [[nodiscard]] virtual std::span<const PortInfo> ports() const noexcept = 0;
  [[nodiscard]] virtual const char* name() const noexcept = 0;
};

// Implementations, in build order:
//   AfPacketBackend    [phase 6]  — recvfrom/sendto, one socket per port
//   PcapFileBackend    [phase 9]  — reads one pcap, writes another; deterministic
//   PacketMmapBackend  [phase 16] — TPACKET_V3 RX ring + TX ring, PACKET_QDISC_BYPASS
//   AfXdpBackend       [phase 17] — UMEM + XSK rings

}  // namespace npf::io
```

---

## 10. Statistics  [phase 6]

```cpp
namespace npf::stat {

struct alignas(64) Counters {
  std::uint64_t rx_packets{0}, rx_bytes{0};
  std::uint64_t tx_packets{0}, tx_bytes{0};
  std::uint64_t forwarded{0}, flooded{0}, to_host{0};
  std::uint64_t arp_requests_rx{0}, arp_replies_rx{0}, arp_requests_tx{0}, arp_replies_tx{0};
  std::uint64_t icmp_generated{0};
  std::array<std::uint64_t, static_cast<std::size_t>(DropReason::_Count)> drops{};
  std::array<std::uint64_t, 256> by_protocol{};   // indexed by IP protocol number

  void merge(const Counters& other) noexcept;     // aggregation only, never on the hot path
};

static_assert(alignof(Counters) == 64);

}  // namespace npf::stat
```

Each worker owns one `Counters`. The stats reporter sums them on demand. Plain `uint64_t`, not
`atomic` — a torn read of a statistic does not matter, and atomics on the hot path do.

---

## 11. The pipeline  [phase 6, extended 7/11/12]

```cpp
namespace npf::pipe {

// Templated on the FIB type so the datapath lookup is a direct, inlinable call.
template <class FibT>
class Forwarder {
 public:
  Forwarder(const core::Config& cfg, FibT& fib, table::ArpCache& arp,
            table::MacTable& macs, const Filter& filter, stat::Counters& stats);

  // The whole datapath for one packet. noexcept, no allocation, no locks, no syscalls.
  [[nodiscard]] Decision process(core::Packet& p) noexcept;

  // Batched entry point used by the worker loop.
  void process_burst(core::Packet** pkts, std::size_t n, Decision* out) noexcept;
};

}  // namespace npf::pipe
```

**The constructor takes every dependency from phase 6 onward, so the signature never changes.**
`Filter` and `MacTable` are created as minimal headers in phase 6 — a `Filter` with no rules that
always returns `Allow`, and an empty `MacTable` — and filled in at phases 11 and 12 respectively.
This is why the phase-6 "do not build yet" fence says *no filter logic*, not *no filter type*.

Order of operations inside `process()` — do not reorder, each step depends on the last:

```
 1. EthView::parse                     -> ShortFrame
 2. ethertype dispatch                 -> BadEtherType
 3. ARP? -> ARP handler, return ToHost
 4. L2/L3 rule (§2)                    -> UnknownDestPort, or the L2 path
 5. Ipv4View::parse                    -> BadIpv4Header
 6. ipv4_checksum_valid                -> BadChecksum
 7. martian source check               -> MartianSource
 8. destination is ours? -> ToHost (ICMP echo)
 9. TTL <= 1                           -> TtlExpired  (+ generate ICMP 11/0)
10. parse_l4 + Filter::evaluate        -> FilterDeny
11. fib.lookup                         -> NoRoute     (+ generate ICMP 3/0)
12. resolve next-hop MAC via ArpCache  -> Queued, or ArpUnresolved if the queue is full
                                          (a queue the cache gives up on: ICMP 3/1, §6)
13. rewrite: dst MAC, src MAC, TTL--, checksum_update16
14. return Forward with out_port
```

---

## 12. Thread ownership

| State | Owner | Sharing | Rule |
|---|---|---|---|
| `PacketPool` | one per worker | none | Never crosses threads in run-to-completion mode |
| `Counters` | one per worker | none | `alignas(64)`; summed only when stats are read |
| `Fib` | control thread | read-mostly, shared | Built at start-up. Live updates use a pointer swap, never a mutex in `lookup()` |
| `ArpCache` | shared | sharded by `next_hop & (kShards-1)` | Writes are rare; reads are per-packet |
| `MacTable` | shared | sharded by MAC hash | Learning writes on every frame — sharding matters more here |
| `SpscRing` | one producer, one consumer | lock-free | See §13 |
| `IoBackend` sockets | one per worker in fanout mode | none | `PACKET_FANOUT_HASH` distributes in-kernel |

---

## 13. SPSC ring  [phase 13]

```cpp
namespace npf::core {

template <class T, std::size_t N>
class SpscRing {
  static_assert((N & (N - 1)) == 0, "N must be a power of two");
 public:
  [[nodiscard]] bool push(T v) noexcept;                                  // producer thread only
  [[nodiscard]] bool pop(T& out) noexcept;                                // consumer thread only
  [[nodiscard]] std::size_t push_bulk(const T* v, std::size_t n) noexcept;
  [[nodiscard]] std::size_t pop_bulk(T* out, std::size_t n) noexcept;
 private:
  alignas(64) std::atomic<std::size_t> head_{0};   // written by producer
  alignas(64) std::atomic<std::size_t> tail_{0};   // written by consumer
  alignas(64) std::size_t cached_tail_{0};         // producer's stale view of tail_
  std::size_t cached_head_{0};                     // consumer's stale view of head_
  alignas(64) std::array<T, N> buf_{};
};

}  // namespace npf::core
```

Memory ordering — write this out in a comment in the header, because it is the question you will
be asked:

- Producer reads its own `head_` **relaxed** (nobody else writes it).
- Producer reads `tail_` **acquire**, and only when `cached_tail_` suggests the ring is full.
- Producer writes the slot, then stores `head_` **release**. The release is what publishes the
  slot's *contents*, not just the index.
- Consumer mirrors this: `tail_` relaxed, `head_` acquire, store `tail_` release.
- `relaxed` on the producer's `head_` store would let a consumer that has already acquired the new
  index read a slot the producer has not finished writing. On x86 the store buffer usually hides
  this; on aarch64 it does not. Phase 18 exists partly to demonstrate exactly that.

The three `alignas(64)` are not decoration: without them `head_` and `tail_` share a cache line and
every push invalidates the consumer's line. Measure it in phase 15.

---

## 14. Error handling convention

| Layer | Convention |
|---|---|
| Start-up (config, sockets, pool) | Exceptions are fine. Fail loudly and exit non-zero. |
| Parsers | `std::optional<View>`; `nullopt` means "malformed", never an exception |
| FIB / tables | `std::optional<T>` for lookups, `bool` for mutations |
| Datapath | `Decision` by value. `noexcept` throughout. |
| Config parsing | `struct ParseResult { std::optional<Config> value; std::string error; int line; }` — errors must name the offending line number |

No error codes, no `errno` leaking upward, no `std::error_code`. Keep it small.
