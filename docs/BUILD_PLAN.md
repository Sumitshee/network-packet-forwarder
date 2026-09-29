# Build plan

Twenty phases. Each one is a session's worth of work with a falsifiable exit test.

**How to run a phase.** Start a fresh Claude Code session and paste this:

> Read `CLAUDE.md` and `docs/ARCHITECTURE.md` completely before starting.
> Then implement **ONLY Phase N** from `docs/BUILD_PLAN.md`.
>
> Do not implement, stub, design, or partially prepare anything listed under
> "Do not build yet" for Phase N.
>
> Before making changes:
> 1. Inspect the current repository state.
> 2. Verify that the previous phase's exit test passes. If it cannot be run in this session
>    — several need root — say so and stop. Do not assume it passes.
> 3. Do not modify previously completed behaviour unless required by an explicitly
>    documented contract change in `docs/ARCHITECTURE.md`.
> 4. If anything in the phase spec is ambiguous, contradictory, or appears wrong, stop and
>    ask. Do not guess, and do not invent a design to fill the gap.
>
> After implementation:
> 1. Run the complete exit test for Phase N.
> 2. Run the relevant existing tests from previous phases.
> 3. Show the exact commands and their full output.
> 4. Do not claim success if an exit test fails.
> 5. Do not commit until the exit test passes.

Once the repository exists, the short form carries the same weight — the fences and exit tests are
already written down, and Claude Code loads `CLAUDE.md` from the repository root automatically:

> Read `CLAUDE.md` and `docs/ARCHITECTURE.md` completely. Implement only Phase N from
> `docs/BUILD_PLAN.md`. Respect all "Do not build yet" fences. Run the phase exit test and
> show me the output.

Do not run two phases in one session. The scope fences are the point.

**One thing to keep out of that prompt.** Never ask the agent to write
`docs/design-decisions.md`. Write those entries yourself, by hand, at the end of each phase — what
you decided, what the alternatives were, why you chose one, and what it cost. That file is the part
of this project that survives contact with an interviewer, and an entry you did not write yourself
is worse than no entry at all, because it sets an expectation you will then miss.

**Estimates** assume roughly 15 focused hours a week and are generous where you will be learning
rather than typing. Total: about 100 working days at that pace, so 5–6 months of evenings, or
3 months if you push. Phases 0–15 are a complete project; 16–18 are the differentiators.

| | Phase | Days | | Phase | Days |
|---|---|---|---|---|---|
|0|Repo, CMake, CI|3|10|Patricia + DIR-24-8 + BGP|8|
|0.5|Walking skeleton|3|11|Packet filter|4|
|1|Buffer pool|4|12|MAC learning / L2|5|
|2|Ethernet + ARP parse|4|13|Threading|9|
|3|IPv4 + checksum|4|14|Benchmark harness|6|
|4|L4 + fragments|3|15|Optimization pass|10|
|5|FIB + linear LPM + config|3|16|PACKET_MMAP|7|
|6|AF_PACKET + netns + pipeline|6|17|AF_XDP *(stretch)*|10|
|7|ICMP generation + RFC 1812|4|18|aarch64 + NEON *(stretch)*|5|
|8|ARP state machine|5|19|Documentation|4|
|9|pcap replay + golden tests|4| | | |

---

## Phase 0 — Repository, build system, CI

**Goal.** A repository that builds nothing useful but builds it correctly on two compilers, under
three sanitizers, with warnings as errors, and proves it in CI.

**Files.**
```
CMakeLists.txt              CMakePresets.json       .gitignore
.clang-format               .clang-tidy             LICENSE (MIT)
README.md                   (stub: title + one paragraph + build instructions)
cmake/CompilerWarnings.cmake  cmake/Sanitizers.cmake  cmake/Dependencies.cmake
tests/CMakeLists.txt        tests/unit/test_smoke.cpp
.github/workflows/ci.yml
```

**Contract.**

- CMake ≥ 3.20. `set(CMAKE_CXX_STANDARD 20)`, `CXX_STANDARD_REQUIRED ON`, `CXX_EXTENSIONS OFF`.
- `cmake/Dependencies.cmake` uses `FetchContent` with **pinned tags**: `googletest v1.15.2`,
  `google/benchmark v1.9.0`. Set `BENCHMARK_ENABLE_TESTING OFF` before adding benchmark.
- `cmake/CompilerWarnings.cmake` defines an `INTERFACE` target `npf_warnings` carrying the warning
  list from `CLAUDE.md` §6, plus `-Werror` gated behind `option(NPF_WERROR "" OFF)` (CI turns it on;
  local development does not, so a warning never blocks you mid-thought).
- `cmake/Sanitizers.cmake` defines `npf_asan` (`-fsanitize=address,undefined
  -fno-omit-frame-pointer -fno-sanitize-recover=all`) and `npf_tsan` (`-fsanitize=thread`) as
  interface targets.
- Options: `NPF_BUILD_TESTS` (ON), `NPF_BUILD_BENCH` (OFF), `NPF_NATIVE` (OFF, adds
  `-march=native`), `NPF_LTO` (OFF).
- `CMakePresets.json` defines `dev`, `asan`, `tsan`, `release`, `bench`, `ci` exactly as named in
  `CLAUDE.md` §3.
- Release-type builds keep `-g`. You cannot profile a binary without symbols.
- `.clang-format`: base `Google`, `ColumnLimit: 100`, `PointerAlignment: Left`,
  `AllowShortFunctionsOnASingleLine: Inline`.
- `.clang-tidy`: enable `bugprone-*`, `performance-*`, `readability-*`, `modernize-*`,
  `cppcoreguidelines-*`; disable `modernize-use-trailing-return-type`,
  `readability-magic-numbers`, `cppcoreguidelines-avoid-magic-numbers`,
  `cppcoreguidelines-pro-bounds-pointer-arithmetic`, `cppcoreguidelines-pro-type-reinterpret-cast`
  (needed at the socket boundary), `readability-identifier-length`.
- CI matrix on `ubuntu-24.04`: `{gcc-13, clang-18}` × `{dev}`, plus one `asan` job, one `tsan` job,
  one format-check job, one clang-tidy job. Cache the FetchContent downloads.

**Do not build yet.** No `include/npf/` files. No `src/`. The smoke test asserts `1 + 1 == 2`.

**Exit test.**
```bash
cmake --preset ci && cmake --build --preset ci -j && ctest --preset ci --output-on-failure
cmake --preset asan && cmake --build --preset asan -j && ctest --preset asan --output-on-failure
cmake --preset tsan && cmake --build --preset tsan -j && ctest --preset tsan --output-on-failure
clang-format --dry-run --Werror $(git ls-files '*.hpp' '*.cpp')
```
All five green, on both gcc-13 and clang-18, locally and in GitHub Actions.

**Commit.** `phase(0): project skeleton, CMake presets, CI, sanitizers` → `git tag phase-00`

---

## Phase 0.5 — Walking skeleton *(throwaway)*

**Goal.** Get one `ping` across two namespaces through code you wrote, in three days, before any
abstraction exists. This exists to surface the AF_PACKET and netns surprises while they are cheap.

**Depends on.** Phase 0 (only for the repo; the skeleton does not use the build system's targets).

**Files.**
```
tools/skeleton/skeleton.cpp     one file, ~300 lines, no headers, no tests
scripts/setup_netns.sh
scripts/cleanup_netns.sh
```

**Topology.** Three namespaces. The router's interfaces carry **no IP addresses** — the forwarder
owns L3 entirely.

```
  ns-client                     ns-router                      ns-server
 ┌──────────┐  veth-c ── veth-cr ┌──────────┐ veth-sr ── veth-s ┌──────────┐
 │10.0.1.2/24│◄─────────────────►│ no IPs    │◄────────────────►│10.0.2.2/24│
 │ gw 10.0.1.1│                  │ npf runs  │                  │ gw 10.0.2.1│
 └──────────┘                    │  here     │                  └──────────┘
                                 └──────────┘
   router's L3 identities, owned by the forwarder, not the kernel:
     port 0 (veth-cr) = 10.0.1.1     port 1 (veth-sr) = 10.0.2.1
```

`setup_netns.sh` must do:
```bash
ip netns add ns-client; ip netns add ns-router; ip netns add ns-server
ip link add veth-c type veth peer name veth-cr
ip link add veth-s type veth peer name veth-sr
ip link set veth-c  netns ns-client; ip link set veth-cr netns ns-router
ip link set veth-s  netns ns-server; ip link set veth-sr netns ns-router

ip netns exec ns-client ip addr add 10.0.1.2/24 dev veth-c
ip netns exec ns-client ip link set veth-c up
ip netns exec ns-client ip link set lo up
ip netns exec ns-client ip route add default via 10.0.1.1 dev veth-c

ip netns exec ns-server ip addr add 10.0.2.2/24 dev veth-s
ip netns exec ns-server ip link set veth-s up
ip netns exec ns-server ip link set lo up
ip netns exec ns-server ip route add default via 10.0.2.1 dev veth-s

# router side: links up, NO addresses, kernel forwarding OFF
ip netns exec ns-router ip link set veth-cr up
ip netns exec ns-router ip link set veth-sr up
ip netns exec ns-router sysctl -qw net.ipv4.ip_forward=0
ip netns exec ns-router sysctl -qw net.ipv4.conf.all.arp_ignore=8
ip netns exec ns-router sysctl -qw net.ipv4.conf.all.rp_filter=0
# checksum offload confuses userspace parsers on veth — turn it off on every veth end
for ns in ns-client ns-router ns-server; do
  ip netns exec $ns sh -c 'for i in $(ls /sys/class/net | grep veth); do
      ethtool -K $i tx off rx off tso off gso off gro off 2>/dev/null; done'
done
```

### Four gotchas that will eat a day each if you do not know them

1. **The kernel will race you.** If the router's interfaces have IP addresses and
   `ip_forward=1`, the kernel answers ARP and forwards packets behind your back, and you will
   spend a day debugging replies you did not send. No addresses on the router side, forwarding
   off, `arp_ignore=8`.
2. **You will receive your own transmissions.** `AF_PACKET` with `ETH_P_ALL` delivers outgoing
   frames too. Check `sll_pkttype != PACKET_OUTGOING` on every `recvfrom`, or you build a
   forwarding loop that saturates a core.
3. **Checksum offload lies to you.** On veth the kernel may hand you a frame with a zero or
   partial checksum because it expects hardware to fill it in. `ethtool -K … rx off tx off` on
   every veth, or your checksum validation rejects perfectly good packets.
4. **You need `CAP_NET_RAW`.** Run under `sudo`, or
   `sudo setcap cap_net_raw,cap_net_admin+ep ./skeleton`.

**Skeleton scope.** One `main()`. Two `AF_PACKET`/`SOCK_RAW` sockets bound to `veth-cr` and
`veth-sr`. A `poll()` loop. Answer ARP requests for `10.0.1.1` and `10.0.2.1`. Hardcode a two-entry
route table and a two-entry ARP cache (populate it by sending a request and blocking for the reply
— crudely is fine). Forward IPv4: decrement TTL, recompute the full checksum, swap the Ethernet
addresses, `sendto`. No tests, no CMake target beyond a one-line `add_executable`, no abstractions.

**Do not build yet.** Everything. This file is a scratchpad.

**Exit test.**
```bash
sudo ./scripts/setup_netns.sh
sudo ip netns exec ns-router ./build/dev/skeleton veth-cr veth-sr &
sudo ip netns exec ns-client ping -c 5 10.0.2.2          # 0% packet loss
sudo ip netns exec ns-server tcpdump -n -c 3 -v icmp     # shows ttl 63, not 64
```

**Commit.** `phase(0.5): throwaway walking skeleton, ping crosses two namespaces` → `git tag phase-00.5`

Then **stop building on it.** Phase 1 starts from an empty `include/npf/`. Keep the file as a
reference and as evidence in the git history.

---

## Phase 1 — Packet buffers and pool

**Goal.** A zero-allocation packet buffer abstraction, proven zero by a test.

**Files.**
```
include/npf/core/byte_span.hpp    read/write big-endian helpers, span aliases
include/npf/core/packet.hpp
include/npf/core/pool.hpp
src/core/pool.cpp
tests/support/alloc_counter.hpp   tests/support/alloc_counter.cpp
tests/unit/test_pool.cpp
tests/unit/test_byte_span.cpp
```

**Contract.** Exactly as `ARCHITECTURE.md` §3. Plus in `byte_span.hpp`:

```cpp
namespace npf::core {
using CBytes = std::span<const std::byte>;
using Bytes  = std::span<std::byte>;

[[nodiscard]] constexpr std::uint8_t  rd_u8 (CBytes b, std::size_t off) noexcept;
[[nodiscard]] constexpr std::uint16_t rd_be16(CBytes b, std::size_t off) noexcept;
[[nodiscard]] constexpr std::uint32_t rd_be32(CBytes b, std::size_t off) noexcept;
constexpr void wr_u8  (Bytes b, std::size_t off, std::uint8_t  v) noexcept;
constexpr void wr_be16(Bytes b, std::size_t off, std::uint16_t v) noexcept;
constexpr void wr_be32(Bytes b, std::size_t off, std::uint32_t v) noexcept;
}
```
Byte-by-byte, no casts. Mark them `constexpr` and add a `static_assert` that
`rd_be16(...) == 0x1234` for a known array — that proves they are usable at compile time and
catches endianness mistakes without running anything.

`PacketPool` implementation notes:
- One `::operator new` (or `aligned_alloc` to 64 bytes) in the constructor sized
  `count * (sizeof(Packet) + kMaxFrame)`. Nothing else ever allocates.
- Intrusive free list through `Packet::free_next_`. `acquire()` pops the head, `release()` pushes.
- Not thread-safe. Put that in a comment at the top of the class with the reason (per-worker
  ownership), not just as a fact.
- `available()` exists so tests can assert no buffer leaked.

`alloc_counter`: override the global `operator new`/`operator delete` (all sized and aligned
overloads) in a test-only translation unit, incrementing `std::atomic<std::size_t>` counters.
Provide `AllocCounter::reset()` and `AllocCounter::allocations()`.

**Do not build yet.** No protocol parsers. No I/O.

**Exit test.**
```cpp
TEST(Pool, ZeroAllocationsInSteadyState) {
  PacketPool pool(1024);
  AllocCounter::reset();
  for (int i = 0; i < 1'000'000; ++i) {
    Packet* p = pool.acquire();
    ASSERT_NE(p, nullptr);
    p->resize(64);
    ASSERT_NE(p->push(14), nullptr);
    ASSERT_TRUE(p->pull(14));
    pool.release(p);
  }
  EXPECT_EQ(AllocCounter::allocations(), 0u);
  EXPECT_EQ(pool.available(), pool.capacity());
}
```
Plus: `push()` past `kHeadroom` returns `nullptr`; `pull()` past `size()` returns false;
exhausting the pool returns `nullptr` rather than growing; `static_assert(sizeof(Packet) <= 64)`
holds. ASan clean.

**Commit.** `phase(1): packet buffer pool with zero-allocation datapath guarantee` → `git tag phase-01`

---

## Phase 2 — Ethernet and ARP parsing

**Goal.** Two bounds-checked, fuzz-tested view types and an ARP builder.

**Files.**
```
include/npf/proto/mac.hpp   ethernet.hpp   arp.hpp
tests/unit/test_ethernet.cpp   test_arp.cpp   test_mac.cpp
tests/fuzz/fuzz_ethernet.cpp   fuzz_arp.cpp   tests/fuzz/CMakeLists.txt
tests/fixtures/*.pcap          tests/support/pcap_reader.hpp   (minimal, test-only)
scripts/make_fixtures.py       (scapy; generates the pcaps, which ARE committed)
```

**Contract.** `ARCHITECTURE.md` §4 for `MacAddr`, `EthView`, `ArpView`. Plus builders:

```cpp
// Write a complete ARP request/reply into p, sizing it to 42 bytes. Returns false if p is too small.
[[nodiscard]] bool build_arp_request(core::Packet& p, MacAddr src_mac, std::uint32_t src_ip,
                                     std::uint32_t target_ip) noexcept;
[[nodiscard]] bool build_arp_reply  (core::Packet& p, MacAddr src_mac, std::uint32_t src_ip,
                                     MacAddr dst_mac, std::uint32_t dst_ip) noexcept;
```

VLAN handling: recognise `0x8100` (and `0x88a8` for QinQ outer), skip **one** tag, expose
`vlan_id()`, and report the inner ethertype. A second stacked tag is `BadEtherType` — support one
level and say so in the README rather than pretending to full QinQ.

`make_fixtures.py` generates at minimum: an ARP request, an ARP reply, a gratuitous ARP, a
VLAN-tagged IPv4 frame, a 60-byte padded frame, a runt (13 bytes), and a frame with ethertype
`0x88cc` (LLDP, unsupported).

Fuzz harnesses use `-fsanitize=fuzzer,address,undefined` in a dedicated CMake target that only
builds under clang. Seed corpus is generated from the fixture frames by a small CMake custom
command.

**Do not build yet.** No IPv4, no ARP *cache* (that is phase 6/8) — this phase is the wire format
only.

**Exit test.**

1. Truncation sweep, as a reusable helper since every later parser needs it:
   ```cpp
   template <class View>
   void TruncationSweep(std::span<const std::byte> good) {
     for (std::size_t n = 0; n < good.size(); ++n) {
       auto v = View::parse(good.first(n));   // must not crash, must not read OOB
       if (n < View::kMinSize) EXPECT_FALSE(v.has_value()) << "accepted " << n << " bytes";
     }
   }
   ```
   Run under ASan — that is what proves "must not read OOB".
2. Every fixture frame parses to the expected field values (table-driven test).
3. `build_arp_request` output round-trips through `ArpView::parse` with identical fields.
4. `fuzz_ethernet` and `fuzz_arp` each run `-max_total_time=60` with no crash, in CI.

**Commit.** `phase(2): bounds-checked Ethernet and ARP views with fuzz harnesses` → `git tag phase-02`

---

## Phase 3 — IPv4 and checksums

**Goal.** IPv4 parsing that never assumes a 20-byte header, plus three checksum implementations,
one of which is the RFC 1624 incremental update.

**Files.**
```
include/npf/proto/ipv4.hpp     include/npf/proto/checksum.hpp
tests/unit/test_ipv4.cpp       tests/unit/test_checksum.cpp
tests/fuzz/fuzz_ipv4.cpp
bench/micro/bench_checksum.cpp bench/CMakeLists.txt
```

**Contract.** `ARCHITECTURE.md` §4. Three checksum paths in `checksum.hpp`:

```cpp
// 1. Reference: byte-at-a-time, obviously correct, used as the oracle in tests. Never optimised.
[[nodiscard]] std::uint16_t checksum_reference(CBytes) noexcept;

// 2. Production: 32-bit accumulator over 16-bit words, folded twice at the end.
[[nodiscard]] std::uint16_t ones_complement_sum(CBytes) noexcept;

// 3. Incremental, RFC 1624 eqn. 3:  HC' = ~(~HC + ~m + m')
//    Careful: the naive HC' = HC - ~m - m' form (RFC 1141) is wrong when the sum
//    hits 0xFFFF. Implement eqn. 3, and add a test for exactly that case.
[[nodiscard]] std::uint16_t checksum_update16(std::uint16_t hc, std::uint16_t m,
                                              std::uint16_t m_prime) noexcept;
```

Also in `ipv4.hpp`:
```cpp
// RFC 1812 §5.3.7. Source addresses that must never be forwarded.
[[nodiscard]] constexpr bool is_martian_source(std::uint32_t ip) noexcept;
//   0.0.0.0/8, 127.0.0.0/8, 224.0.0.0/4, 240.0.0.0/4, 255.255.255.255
[[nodiscard]] constexpr bool is_martian_dest(std::uint32_t ip) noexcept;
//   0.0.0.0/8, 127.0.0.0/8
```

**Do not build yet.** No SIMD checksum (phase 18). No forwarding logic. No TTL decrement in the
parser — the view is read-only.

**Exit test.**

1. **Checksum property test.** 1,000,000 random headers of length 20–60: `ones_complement_sum`
   must equal `checksum_reference` exactly.
2. **RFC 1624 property test** — the important one:
   ```cpp
   TEST(Checksum, IncrementalMatchesFullRecompute) {
     std::mt19937 rng(42);
     for (int i = 0; i < 1'000'000; ++i) {
       auto hdr = random_ipv4_header(rng);          // valid, checksum already correct
       const std::uint16_t old_word = rd_be16(hdr, 8);   // TTL:protocol
       set_ttl(hdr, ttl(hdr) - 1);
       const std::uint16_t new_word = rd_be16(hdr, 8);
       const std::uint16_t incremental =
           checksum_update16(rd_be16(hdr, 10), old_word, new_word);
       wr_be16(hdr, 10, 0);
       ASSERT_EQ(incremental, ipv4_header_checksum(hdr)) << "i=" << i;
     }
   }
   ```
   Include a hand-written case where the intermediate sum is `0xFFFF`.
3. Options-bearing headers: for `ihl` 6..15, `header_len()` is `ihl*4` and `payload()` starts
   there.
4. `total_length` shorter than the span (Ethernet padding) → `payload()` is sized by
   `total_length`, not by the span.
5. `total_length` longer than the span → `parse` returns `nullopt`.
6. Truncation sweep, fuzzer 60 s.
7. `bench_checksum` runs and emits the three implementations' ns/op. **Record the numbers in
   `docs/performance.md` — this is your first real measurement.**

**Commit.** `phase(3): IPv4 view and checksums incl. RFC 1624 incremental update` → `git tag phase-03`

---

## Phase 4 — TCP, UDP, ICMP and fragment semantics

**Goal.** Expose L4 fields, and get the fragment rule right the first time.

**Files.**
```
include/npf/proto/l4.hpp   include/npf/proto/icmp.hpp
tests/unit/test_l4.cpp     tests/fuzz/fuzz_l4.cpp
scripts/make_fixtures.py   (extend: fragmented UDP, TCP SYN, ICMP echo)
```

**Contract.** `ARCHITECTURE.md` §4, `L4Info` and `parse_l4`.

The rule, stated as code so there is no ambiguity:
```cpp
std::optional<L4Info> parse_l4(const Ipv4View& ip) noexcept {
  L4Info out;
  out.protocol = ip.protocol();
  if (!ip.is_first_fragment()) {
    out.ports_valid = false;
    return out;                     // <-- do NOT read the payload. The ports are not there.
  }
  ...
}
```

TCP: source/dest port, seq, ack, `doff` (validate `doff >= 5` and `doff*4 <= payload size`),
flags byte. UDP: ports and length (validate `length >= 8`). ICMP: type, code, and for echo,
identifier and sequence.

**Do not build yet.** No reassembly. No TCP state. No filtering (phase 11).

**Exit test.**

1. From the fixture pcap of a fragmented UDP datagram: fragment 1 gives `ports_valid == true` with
   the real ports; fragments 2..n give `ports_valid == false`.
2. **The adversarial case.** Hand-craft a packet with `frag_offset = 185` whose payload begins
   with bytes that would decode as ports 443 and 8080. `parse_l4` must still report
   `ports_valid == false`. Name the test `RejectsPortsFromNonInitialFragment`.
3. A TCP header with `doff = 4` (illegal, below the 20-byte minimum) → `nullopt`.
4. A UDP header claiming `length = 4` → `nullopt`.
5. Truncation sweep, fuzzer 60 s.

**Commit.** `phase(4): L4 parsing with strict non-initial-fragment handling` → `git tag phase-04`

---

## Phase 5 — FIB interface, linear oracle, configuration

**Goal.** The routing table interface and the deliberately simple implementation that every later
one is tested against. Plus config parsing, so phase 6 has something to read.

**Files.**
```
include/npf/table/fib.hpp   include/npf/table/lpm_linear.hpp
src/table/lpm_linear.cpp
include/npf/core/config.hpp src/core/config.cpp
configs/router.conf
tests/unit/test_lpm_linear.cpp   tests/unit/test_config.cpp
```

**Contract.** `ARCHITECTURE.md` §5.

`LinearLpm`: a `std::vector<Route>` kept sorted by descending prefix length. `lookup` walks it and
returns the first match. `O(n)`, deliberately. **Never optimise this file** — add a comment saying
so at the top, because a future session will be tempted.

Config format — line-oriented, hand-parsed, no dependency:
```
# configs/router.conf
interface veth-cr port 0 ip 10.0.1.1/24 mode routed
interface veth-sr port 1 ip 10.0.2.1/24 mode routed

route 10.0.1.0/24 dev 0
route 10.0.2.0/24 dev 1
route 0.0.0.0/0   via 10.0.2.254 dev 1

# optional, for deterministic replay in phase 9
arp 10.0.2.2 aa:bb:cc:dd:ee:02 dev 1

pool_size 4096
burst 32
mode rtc          # rtc | pipeline   (phase 13)
workers 1         # (phase 13)
io af_packet      # af_packet | mmap | xdp | pcap
fib linear        # linear | trie | patricia | dir24_8
```
Parser returns `ParseResult` per `ARCHITECTURE.md` §14. Every error names the line number and what
was expected. A MAC of `auto` (or an omitted `mac`) means "read it from the interface at start-up".

**Do not build yet.** No trie. No sockets. No forwarding.

**Exit test.**

Table-driven, covering the cases that break naive implementations:
```
routes                                      lookup        expect
--------------------------------------------------------------------
0.0.0.0/0 -> A                              1.2.3.4       A
10.0.0.0/8 -> A, 10.1.0.0/16 -> B           10.1.2.3      B      (longer wins)
10.0.0.0/8 -> A, 10.1.0.0/16 -> B           10.2.0.1      A
10.0.0.0/24 -> A, 10.0.0.7/32 -> B          10.0.0.7      B      (host route inside)
10.0.0.0/24 -> A, 10.0.0.7/32 -> B          10.0.0.8      A
(empty)                                     1.1.1.1       nullopt
0.0.0.0/0 -> A  then remove 0.0.0.0/0       1.1.1.1       nullopt
10.0.0.0/8 -> A  then add 10.0.0.0/8 -> B   10.1.1.1      B      (replace, not duplicate)
255.255.255.255/32 -> A                     255.255.255.255  A   (no shift UB at len 32)
0.0.0.0/0 with a /0 mask                    anything      A      (no shift UB at len 0)
```
The last two matter: `1u << 32` and `~0u >> 32` are undefined behaviour. Write the mask helper as
`len == 0 ? 0u : (~0u << (32 - len))` and test both ends. UBSan will catch it if you don't.

Config: a valid file round-trips; each of six malformed files produces an error naming the right
line number.

**Commit.** `phase(5): FIB interface, linear LPM oracle, configuration parser` → `git tag phase-05`

---

## Phase 6 — AF_PACKET backend, netns topology, forwarding pipeline

**Goal.** The first real end-to-end forward. A ping crosses the topology through the actual engine.

This is the biggest phase before phase 13. If it needs two sessions, split it at "backend works,
`npf dump` prints received frames" and "pipeline forwards".

**Files.**
```
include/npf/core/unique_fd.hpp   include/npf/core/log.hpp   include/npf/core/time.hpp
include/npf/io/backend.hpp       include/npf/io/af_packet.hpp   src/io/af_packet.cpp
include/npf/table/arp_cache.hpp  src/table/arp_cache.cpp        (stub, see below)
include/npf/table/mac_table.hpp                                 (stub: empty, lookup -> nullopt)
include/npf/pipe/filter.hpp                                     (stub: no rules, always Allow)
include/npf/stat/counters.hpp
include/npf/pipe/forward.hpp     src/pipe/forward.cpp
src/main.cpp                     (subcommands: run, dump, show)
scripts/setup_netns.sh           scripts/cleanup_netns.sh       (promote from phase 0.5)
tests/integration/test_forward_netns.sh
```

**Contract.** `ARCHITECTURE.md` §9 (`IoBackend`, `PortInfo`), §10 (`Counters`), §11 (`Forwarder`
and the fourteen-step order), §2 (the L2/L3 rule — the L2 branch just drops until phase 12).

`AfPacketBackend` implementation notes:
```cpp
// one socket per port
int fd = ::socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ALL));
sockaddr_ll sll{};
sll.sll_family   = AF_PACKET;
sll.sll_protocol = htons(ETH_P_ALL);
sll.sll_ifindex  = static_cast<int>(::if_nametoindex(name));
::bind(fd, reinterpret_cast<sockaddr*>(&sll), sizeof(sll));
```
- `rx_burst` calls `recvfrom` up to `max` times, filling packets from the pool, and **skips every
  frame whose `sll_pkttype == PACKET_OUTGOING`** (see phase 0.5, gotcha 2). Stop early on `EAGAIN`.
- `tx_burst` calls `sendto` with a `sockaddr_ll` naming the output ifindex. Handle short writes and
  `ENOBUFS` by returning a count below `n`; the caller counts `TxFull`.
- Read each port's MAC with `SIOCGIFHWADDR` and its ifindex with `if_nametoindex` at construction.
- Increase `SO_RCVBUF`/`SO_SNDBUF` (say 4 MB) and log the value the kernel actually granted — it
  halves your request and doubles it back, which is confusing the first time.
- `poll()` across all port fds with a short timeout in the main loop, so an idle router does not
  spin a core. Make busy-polling an option for phase 14.
- RAII: `unique_fd`, not a raw `int`.

`Forwarder::process` implements steps 1–14 exactly. Steps 9 and 11 count the drop but do **not**
generate ICMP yet — that is phase 7. Step 12 uses the stub ARP cache: it implements the full
`ARCHITECTURE.md` §6 interface, but `resolve_and_queue` sends a request, returns `false`, and never
queues; the caller releases the packet and counts `ArpUnresolved`. Real queueing is phase 8.

`Filter` and `MacTable` are created here as **stubs with their final signatures** — a filter with
no rules that always returns `Allow`, and an empty MAC table — so the `Forwarder` constructor is
correct from the start and never changes. See `ARCHITECTURE.md` §11.

`main.cpp` subcommands:
- `npf run --config configs/router.conf` — the forwarding loop, with a stats line every 5 s.
- `npf dump --iface veth-cr` — print parsed headers of received frames. Invaluable for debugging;
  keep it.
- `SIGUSR1` dumps the full counter table; `SIGINT` shuts down cleanly and prints final stats.

**Do not build yet.** No ICMP generation. No ARP queueing. No filter *logic* (the type exists, it
just always allows). No MAC *learning* (the type exists, it is always empty, so the L2 branch always
drops). No threads — one loop, one thread.

**Exit test.** `tests/integration/test_forward_netns.sh`, run as root, asserting each of:

```bash
1. ip netns exec ns-client ping -c 10 10.0.2.2                 -> 0% loss
2. ip netns exec ns-server tcpdump shows ttl 63                 -> decremented exactly once
3. ip netns exec ns-client ping -c 3 -t 1 10.0.2.2              -> 100% loss,
     and `npf show stats` TtlExpired == 3
4. ip netns exec ns-client ping -c 3 -W 1 10.9.9.9              -> 100% loss,
     and NoRoute == 3
5. a frame with ethertype 0x88cc injected on veth-c             -> BadEtherType == 1
6. a frame with a corrupted IPv4 checksum                       -> BadChecksum == 1
7. after the run, pool.available() == pool.capacity()           -> no leaked buffers
8. rx_packets == forwarded + to_host + sum(drops)               -> every packet accounted for
```
Assertion 8 is the one that catches real bugs. Make it a hard failure, and keep it correct as the
project grows — from phase 12 it becomes `forwarded + flooded + to_host + sum(drops)`.

**Commit.** `phase(6): AF_PACKET backend, netns topology, IPv4 forwarding pipeline` → `git tag phase-06`

**This is the milestone.** Record a terminal capture. Update the README stub with a real
description and the setup instructions.

---

## Phase 7 — ICMP generation and RFC 1812 conformance

**Goal.** `traceroute` works through your router.

**Files.**
```
include/npf/pipe/icmp_gen.hpp   src/pipe/icmp_gen.cpp
docs/rfc1812-conformance.md
tests/unit/test_icmp_gen.cpp
tests/integration/test_traceroute.sh
```

**Contract.**
```cpp
namespace npf::pipe {

enum class IcmpError : std::uint8_t {
  TimeExceeded,        // type 11 code 0
  NetUnreachable,      // type  3 code 0
  HostUnreachable,     // type  3 code 1
  ProtoUnreachable,    // type  3 code 2
  FragNeeded,          // type  3 code 4   (only if you implement MTU checks; otherwise omit)
};

// Builds a complete Ethernet+IPv4+ICMP error frame into `out`.
// ICMP payload = the original IP header + the first 8 bytes of its payload (RFC 792).
// src_ip must be the address of the interface the ORIGINAL packet arrived on — that is
// what makes traceroute print the right hop.
[[nodiscard]] bool build_icmp_error(core::Packet& out,
                                    const proto::Ipv4View& orig, core::CBytes orig_frame,
                                    IcmpError err,
                                    std::uint32_t src_ip, proto::MacAddr src_mac,
                                    proto::MacAddr dst_mac) noexcept;

// RFC 1812 §4.3.2.7. Returns false if an ICMP error must NOT be generated.
[[nodiscard]] bool may_send_icmp_error(const proto::Ipv4View& orig,
                                       const proto::L4Info& l4) noexcept;

// Token bucket, default 100 errors/second, per RFC 1812 §4.3.2.8.
class IcmpRateLimiter {
 public:
  [[nodiscard]] bool allow(std::chrono::steady_clock::time_point now) noexcept;
};

}  // namespace npf::pipe
```

`may_send_icmp_error` must return **false** when the original packet:
- is itself an ICMP error message (types 3, 11, 12, 5 — not echo request/reply),
- has a non-zero fragment offset,
- was sent to a broadcast or multicast IP or L2 address,
- has a source address that is not a single host (0.0.0.0, loopback, broadcast, multicast).

Also implement **ICMP Echo Reply** for pings addressed to one of the router's own configured
interface IPs (`Verdict::ToHost` from step 8 of the pipeline). Without it `traceroute` never
terminates and `ping 10.0.1.1` fails.

`docs/rfc1812-conformance.md` is a table: requirement, RFC section, status (`implemented` /
`deferred` / `n-a`), and where. Cover at minimum §4.2.2.1 (martian source), §4.3.2.7 (ICMP
suppression), §4.3.2.8 (rate limit), §5.2.1.1 (options via IHL), §5.3.1 (TTL), §5.3.4 (directed
broadcast), §5.2.3 (loopback). Mark ICMP Redirect (§5.3.2), source routing and reassembly as
deferred with one line saying why. **An honest deferred list is worth more than a padded
implemented list.**

**Do not build yet.** No PMTU discovery. No IP option processing beyond skipping them.

**Exit test.**
```bash
sudo ip netns exec ns-client traceroute -n -q 1 -m 5 10.0.2.2
#   1  10.0.1.1   <- your router
#   2  10.0.2.2   <- the server
sudo ip netns exec ns-client ping -c 3 10.0.1.1     # 0% loss, router answers for itself
```
Plus unit tests:
- `build_icmp_error` output parses back through `EthView` → `Ipv4View` → `IcmpView`, and the
  embedded payload equals the original header plus exactly 8 bytes.
- The generated IPv4 checksum validates.
- `may_send_icmp_error` returns false for each of the four suppression cases above (one test each).
- The rate limiter emits at most 100 in a simulated second.

**Commit.** `phase(7): ICMP error generation and RFC 1812 conformance` → `git tag phase-07`

**Record the traceroute.** `asciinema rec` or a GIF. It goes at the top of the README.

---

## Phase 8 — ARP state machine

**Goal.** Replace the phase-6 stub with a real neighbour cache: states, bounded queueing,
retransmission, aging, and a defined failure path.

**Files.**
```
include/npf/table/arp_cache.hpp   src/table/arp_cache.cpp        (rewrite)
tests/unit/test_arp_cache.cpp
tests/integration/test_arp_resolution.sh
```

**Contract.** `ARCHITECTURE.md` §6, in full. The behaviours that matter:

| Event | Behaviour |
|---|---|
| Lookup hit, `Reachable` | Return the MAC, refresh the timer |
| Lookup hit, `Stale` | Return the MAC **and** send a probe (forward now, revalidate in the background) |
| Lookup miss | Create `Incomplete`, send a probe, queue the packet |
| Queue full (3 packets) | Return false; caller releases the packet and counts `ArpUnresolved` |
| Reply received | Transition to `Reachable`, hand back every queued packet for transmission |
| 3 probes, no reply | Emit ICMP 3/1 for the **head** packet only, release all queued buffers, count the rest as `ArpUnresolved`, delete the entry |
| Unsolicited / gratuitous ARP | Refresh an **existing** entry. Never create one. |
| 60 s idle | Delete the entry |

Why unsolicited ARP must not create an entry: an attacker on the segment could otherwise populate
your cache for any IP with any MAC at zero cost. Refreshing an entry you already asked for is
bounded; creating one is not. Write that reasoning into `docs/design-decisions.md` — it is a
question you will be asked.

`tick()` is called from the worker loop once per iteration, not from a timer thread. Take the
current time once per iteration and pass it in; do not call `steady_clock::now()` per packet.

**Do not build yet.** No sharding (phase 13). No IPv6 neighbour discovery, ever.

**Exit test.**

Unit, with a mock `ArpEvents` that records calls:
1. `resolve_and_queue` three times → all queued, one probe sent (not three).
2. The fourth → returns false, nothing queued, no extra probe.
3. `on_reply` → all three come back in `ready`, in FIFO order, entry is `Reachable`.
4. Three `tick`s at 1 s intervals with no reply → three probes total, then on the next tick exactly
   one `unresolved()` call and all three buffers released.
5. **Buffer accounting:** in every one of the above, `pool.available()` returns to its starting
   value. Run the whole suite under ASan and LSan.
6. `on_unsolicited` for an unknown IP → cache size unchanged.
7. `on_unsolicited` for a known IP → timer refreshed, MAC updated.

Integration:
```bash
sudo ip netns exec ns-client ip neigh flush all
sudo kill -USR2 $NPF_PID          # add a signal that flushes the ARP cache, for testing
sudo ip netns exec ns-client ping -c 1 -W 3 10.0.2.2   # must succeed: the FIRST packet is
                                                        # queued and delivered, not dropped
```
That last assertion is the whole point of the phase. Before this phase it fails.

**Commit.** `phase(8): ARP state machine with bounded pending queue and retransmission` → `git tag phase-08`

---

## Phase 9 — pcap replay and golden-file tests

**Goal.** Hermetic integration tests that run in CI without root, and a realistic traffic source
for tier-A benchmarks.

**Files.**
```
include/npf/io/pcap_file.hpp   src/io/pcap_file.cpp
src/main.cpp                   (add: npf replay <in.pcap> <out.pcap> --config <f>)
tests/integration/test_golden.cpp
tests/fixtures/golden/*.pcap   *.expected.pcap   *.expected.json   *.conf
scripts/make_fixtures.py       (extend to generate every golden input)
```

**Contract.** Write the pcap reader and writer **by hand**. Do not link libpcap — the format is
trivial and the dependency is not worth it:

```
global header, 24 bytes:
  u32 magic 0xa1b2c3d4   u16 major 2   u16 minor 4
  i32 thiszone 0         u32 sigfigs 0
  u32 snaplen 65535      u32 network 1 (LINKTYPE_ETHERNET)
per-record header, 16 bytes:
  u32 ts_sec  u32 ts_usec  u32 incl_len  u32 orig_len
then incl_len bytes of frame
```
Accept the swapped magic `0xd4c3b2a1` on read. Reject `0xa1b23c4d` (nanosecond pcap) with a clear
error, or support it — but do not silently misread it.

`PcapFileBackend implements IoBackend`: `rx_burst` reads the next N records, `tx_burst` writes them
to the output file, tagged with the output port in a comment sidecar or simply written in order.
For determinism:
- Output record timestamps are the input timestamps, not wall-clock.
- The ARP cache is preloaded from `arp` lines in the config, so no probe is ever sent.
- The ICMP rate limiter is given a fixed clock.
- Any field that would otherwise vary (IP ID of generated ICMP, for instance) is set from a
  deterministic counter seeded per run.

**Golden cases** — at minimum these eight, each an input pcap, a config, and an expected output
pcap, all committed:

| Case | Input | Expected output |
|---|---|---|
| `basic_fwd` | one IPv4 TCP packet, route present, ARP preloaded | one packet, TTL−1, MACs rewritten, checksum valid |
| `ttl_expired` | same with TTL=1 | one ICMP 11/0 back toward the source |
| `no_route` | destination outside every prefix | one ICMP 3/0 |
| `bad_checksum` | corrupted header checksum | empty output, `BadChecksum == 1` |
| `martian` | source 127.0.0.1 | empty output, `MartianSource == 1` |
| `fragment` | 3-fragment UDP datagram | all three forwarded, none reassembled |
| `arp_request` | ARP who-has for the router's IP | one ARP reply |
| `vlan` | VLAN-tagged IPv4 | forwarded, tag handling as documented |

Each case has **two** expectations: the output pcap (bytes) and an `.expected.json` snapshot of the
counters after the run. Several cases produce no output packets at all, so without the counter
snapshot they would pass trivially. `npf replay --stats-json out.json` writes it.

`test_golden.cpp` iterates the directory, runs replay, and compares both. On a pcap mismatch it
prints the first differing offset and a hexdump of both sides — you will need that. On a counter
mismatch it prints the full diff of the two counter tables.

**Do not build yet.** Nothing new in the datapath. This phase adds a backend and tests only.

**Exit test.**
```bash
ctest --preset ci -R golden --output-on-failure     # all 8 pass, as a normal user, in CI
```
Add the golden suite to the CI workflow. From here on, **every later phase must keep it green**,
and phases 11, 12 and 16 add cases to it.

**Commit.** `phase(9): pcap replay backend and golden-file integration tests` → `git tag phase-09`

---

## Phase 10 — Patricia trie, DIR-24-8, and a real BGP table

**Goal.** The algorithmic centrepiece. Three more LPM implementations, all property-tested against
the phase-5 oracle, benchmarked at internet scale.

**Files.**
```
include/npf/table/lpm_trie.hpp      src/table/lpm_trie.cpp
include/npf/table/lpm_patricia.hpp  src/table/lpm_patricia.cpp
include/npf/table/lpm_dir24_8.hpp   src/table/lpm_dir24_8.cpp
tests/unit/test_lpm_property.cpp    tests/support/prefix_gen.hpp
bench/micro/bench_lpm.cpp
scripts/fetch_bgp_table.sh
```

### `BinaryTrie`
Uncompressed, one node per bit. Node holds two child indices (into a `std::vector<Node>`, not raw
pointers — indices are half the size and relocate cleanly) and an optional next-hop. Lookup walks
up to 32 levels, remembering the deepest node that had a next-hop. Its terrible cache behaviour is
the point; it is the baseline the others improve on.

### `PatriciaLpm`
Path-compressed: each node stores a bit position and a skipped-bits value, so chains of
single-child nodes collapse. Fewer nodes, fewer levels, still a pointer (index) chase per level.

### `Dir24_8Lpm` — the fast one

```
tbl24:  2^24 entries × uint16_t = 32 MiB, indexed by dst >> 8
        bit 15 == 0  ->  low 15 bits are a next-hop id (the match is /24 or shorter)
        bit 15 == 1  ->  low 15 bits are a group index into tbl_long
tbl_long: groups of 256 uint16_t, indexed by (group << 8) | (dst & 0xFF)
          entries are always next-hop ids

std::optional<NextHop> lookup(std::uint32_t dst) const noexcept {
  std::uint16_t e = tbl24_[dst >> 8];
  if (e & 0x8000u) [[unlikely]]
    e = tbl_long_[(static_cast<std::size_t>(e & 0x7FFFu) << 8) | (dst & 0xFFu)];
  return e == kInvalidNextHop ? std::nullopt : std::optional{nexthops_[e]};
}
```
One load for a /24-or-shorter match, two otherwise. Next-hop ids index a small
`std::vector<NextHop>`, so the big tables stay 2 bytes per entry.

Insertion is the interesting part and is where the design decision lives:
- Inserting a `/16` writes 256 `tbl24` entries; a `/8` writes 65,536. That is fine.
- It must **not** overwrite entries already claimed by a longer prefix. Two options:
  1. **Build from sorted input** — insert shortest prefix first, so longer ones naturally
     overwrite. Fast bulk build, but no correct incremental insert.
  2. **Length shadow table** — a parallel `std::vector<std::uint8_t>` of 2^24 entries (16 MiB)
     holding the prefix length that owns each slot; only overwrite when the new length is greater
     or equal. Supports incremental insert and delete, costs 16 MiB.

  Implement **both**: bulk `build(std::span<const Route>)` using option 1, and `add()`/`remove()`
  using option 2, with the shadow table allocated lazily only if `add()` is called. Then write the
  trade-off up in `docs/design-decisions.md` — memory versus update cost is exactly the kind of
  decision worth a paragraph.
- Deleting requires recomputing the covered range from the next-shortest covering prefix. Keep a
  sorted route list alongside for that; it is not on the hot path.

### Property test — the centrepiece

```cpp
template <class T> class LpmConformance : public ::testing::Test {};
using Impls = ::testing::Types<BinaryTrie, PatriciaLpm, Dir24_8Lpm>;
TYPED_TEST_SUITE(LpmConformance, Impls);

TYPED_TEST(LpmConformance, AgreesWithOracle) {
  std::mt19937 rng(1234);
  for (int trial = 0; trial < 1000; ++trial) {
    const auto routes = adversarial_prefix_set(rng, 1 + rng() % 500);
    LinearLpm oracle; TypeParam impl;
    for (const auto& r : routes) { oracle.add(r); impl.add(r); }
    for (int k = 0; k < 1000; ++k) {
      const std::uint32_t key = rng();
      ASSERT_EQ(oracle.lookup(key), impl.lookup(key))
          << "trial " << trial << " key " << ip_to_string(key)
          << "\nroutes:\n" << dump(routes);          // must print enough to reproduce
    }
  }
}
```

`adversarial_prefix_set` must deliberately generate: the default route; prefixes at /8, /16, /24
boundaries (where naive shift code breaks); /32 host routes nested inside /24s; duplicate prefixes
with different next-hops (last write wins); prefixes of length 0 and 32; and, in a quarter of
trials, a sequence of interleaved adds and removes rather than adds only.

### `fetch_bgp_table.sh`

```bash
# Downloads a RouteViews MRT RIB dump and flattens it to "prefix/len nexthop_id" lines.
#   archive.routeviews.org/bgpdata/YYYY.MM/RIBS/rib.YYYYMMDD.HHMM.bz2
# Parse with bgpdump, bgpreader (CAIDA) or python3 -m mrtparse.
# Output: data/bgp_prefixes.txt   (gitignored — the script is the artefact, not the data)
# Global IPv4 table size for reference: ~1.08 M prefixes as of August 2026.
# Also emit truncated tables at 10 / 1k / 100k prefixes by uniform sampling, for the bench sweep.
```

### `bench_lpm.cpp`

Axes: implementation × table size {10, 1k, 100k, full} × key distribution {uniform random, Zipf
α=0.99 over the prefix set, sequential}. Report ns/lookup (median and p95 over 7 repetitions),
`memory_bytes()`, and build time. Emit JSON into `bench/results/`.

The Zipf case is not decoration. DIR-24-8's table is 32 MiB and does not fit in cache, so under
uniform keys every lookup is a DRAM access and a compact Patricia trie can be competitive. Under
skewed keys the hot slice stays cached and DIR-24-8 wins outright. **Plot both.** That contrast is
the most interesting result in the whole project.

**Do not build yet.** No SIMD. No multibit trie beyond DIR-24-8 unless you have spare time. No
IPv6 — but check that the trie types compile if templated on a 128-bit address, or drop the claim.

**Exit test.**
1. `TYPED_TEST` conformance suite green for all three implementations. This is non-negotiable —
   if the trie disagrees with the oracle once, the trie is wrong.
2. `bench_lpm` completes at the full BGP table size and emits valid JSON with no NaNs.
3. `memory_bytes()` is within 5% of the measured RSS delta when the table is built.
4. ASan clean (the DIR-24-8 index arithmetic is exactly where an off-by-one hides).

**Commit.** `phase(10): binary trie, Patricia trie and DIR-24-8 LPM with conformance tests` → `git tag phase-10`

---

## Phase 11 — Packet filter

**Goal.** A configurable first-match-wins filter with defined fragment behaviour.

**Files.**
```
include/npf/pipe/filter.hpp   src/pipe/filter.cpp
src/core/config.cpp           (extend: parse filter.conf)
configs/filter.conf
tests/unit/test_filter.cpp
tests/fixtures/golden/filter_deny.pcap + .expected.pcap
```

**Contract.** `ARCHITECTURE.md` §8. Config:
```
policy allow
deny  udp any            -> 10.0.2.10 port 53
allow tcp 10.0.1.0/24    -> 10.0.2.0/24
deny  icmp 10.0.3.0/24   -> any
allow any  any           -> any in-port 0
```

The fragment rule, restated because it is the part that gets asked about: if
`l4.ports_valid == false`, any rule constraining `sport` or `dport` **cannot match** and is skipped.
A non-initial fragment therefore falls through port-based rules to whatever follows.

Add this to the README under "Known limitations", in these words or close to them:

> Non-initial fragments carry no L4 header, so port-based filter rules cannot apply to them. This
> forwarder does not reassemble, so an attacker can evade a port rule by fragmenting the packet.
> Real firewalls reassemble before classification precisely for this reason. The trade-off here is
> deliberate: reassembly is stateful, memory-unbounded without careful limits, and out of scope.

That paragraph is worth more in an interview than the filter itself.

**Do not build yet.** No classification optimisation — linear rule scan only. Tuple-space search or
a flow cache belongs in phase 15, and only if the benchmark shows the filter matters.

**Exit test.** Table-driven rule matrix, at minimum:
- First match wins when two rules both match (order matters, test both orders).
- `nullopt` fields match anything.
- Default policy applies when no rule matches, for both `allow` and `deny` defaults.
- A port-constrained rule does not match a non-initial fragment (`ports_valid == false`).
- A protocol-only rule **does** match a non-initial fragment.
- `in_port` discriminates correctly.
- Prefix boundaries: `10.0.1.255` matches `10.0.1.0/24`, `10.0.2.0` does not.

Plus the new golden case passes.

**Commit.** `phase(11): configurable packet filter with documented fragment semantics` → `git tag phase-11`

---

## Phase 12 — MAC learning and L2 switching

**Goal.** The bridged path, and the L2/L3 rule wired up for real.

**Files.**
```
include/npf/table/mac_table.hpp   src/table/mac_table.cpp
src/pipe/forward.cpp              (implement the L2 branch)
src/core/config.cpp               (extend: mode bridged, bridge-domain N)
scripts/setup_bridge_netns.sh     scripts/cleanup_bridge_netns.sh
configs/bridge.conf
tests/unit/test_mac_table.cpp
tests/integration/test_switching.sh
tests/fixtures/golden/l2_flood.pcap + .expected.pcap
```

**Contract.** `ARCHITECTURE.md` §7 and §2.

`MacTable`: open-addressed, linear probing, power-of-two capacity. Hash the 6-byte MAC with a
cheap mixer (multiply-shift on the 48 bits packed into a `uint64_t`). Entries stored inline:
`{MacAddr mac; uint16_t port; TimePoint last_seen;}`. On a full table, evict the oldest entry in
the probe sequence rather than failing. **Never `std::unordered_map`** — say why in a comment.

Forwarding rules:
- Learn `src MAC → in_port` on every frame arriving on a bridged port.
- Known destination → forward to that port. If it equals `in_port`, drop and count (a station
  should not be sending to itself through the bridge).
- Unknown destination, or broadcast, or multicast → `Verdict::Flood`: every other **up** port in
  the same bridge domain. Never the ingress port.
- Age entries out at 300 s (configurable), matching a real switch's default.

`setup_bridge_netns.sh` builds a separate three-port topology: `ns-h1`, `ns-h2`, `ns-h3` all in one
IP subnet, three veths into `ns-router`, all three ports `mode bridged bridge-domain 1`.

Config additions:
```
interface veth-h1 port 0 mode bridged bridge-domain 1
interface veth-h2 port 1 mode bridged bridge-domain 1
interface veth-h3 port 2 mode bridged bridge-domain 1
mac_age 300
```

Add `npf show mac` and `npf show arp` subcommands.

**Do not build yet.** No STP. No VLAN-aware bridging (one flat domain per bridge-domain id). No
per-VLAN MAC tables.

**Exit test.**
```bash
sudo ./scripts/setup_bridge_netns.sh
sudo ip netns exec ns-router ./build/dev/npf run --config configs/bridge.conf &

1. ip netns exec ns-h1 ping -c 5 10.0.9.2                -> 0% loss
2. npf show mac                                          -> h1's MAC on port 0, h2's on port 1
3. tcpdump on veth-h1 while h1 pings h2                  -> h1 never sees its own frame back
4. tcpdump on veth-h3 during the first ping              -> sees the flooded ARP,
                                                            not the subsequent unicast ICMP
5. wait mac_age+5, npf show mac                          -> table empty
```
Assertion 4 is the one that proves learning actually works rather than everything being flooded.

Unit tests: insert 2× capacity entries and confirm eviction rather than corruption; hash collisions
resolve correctly; `age()` removes exactly the expired entries.

**Commit.** `phase(12): MAC learning, bridge domains and the L2/L3 decision rule` → `git tag phase-12`

---

## Phase 13 — Multithreading

**Goal.** Two execution models, a lock-free ring you wrote yourself, and a proof that per-flow
ordering survives.

**Files.**
```
include/npf/core/ring.hpp
include/npf/io/af_packet.cpp      (add PACKET_FANOUT support)
include/npf/pipe/worker.hpp       src/pipe/worker.cpp
include/npf/pipe/hash.hpp         (5-tuple, symmetric; also a mix32 avalanche helper)
src/main.cpp                      (honour mode= and workers=)
bench/system/gen.cpp              minimal version: N flows, sequence number in the payload
                                  (phase 14 extends it with rate control and timestamps)
scripts/check_ordering.py         reads a pcap, asserts per-flow IP IDs are monotonic
tests/unit/test_ring.cpp          tests/unit/test_hash.cpp
tests/integration/test_ordering.sh
```

**Contract.** `ARCHITECTURE.md` §12 and §13.

### Model 1 — run-to-completion (the default)

N worker threads. Each has: its own `AF_PACKET` socket joined to a `PACKET_FANOUT` group, its own
`PacketPool`, its own `Counters`. Each does RX → process → TX entirely in its own thread. **No ring
at all.** This is what production DPDK applications do and it is usually the faster of the two.

```cpp
// every socket in the group is bound to the same interface first
const int fanout_arg = (group_id & 0xFFFF) | (PACKET_FANOUT_HASH << 16);
::setsockopt(fd, SOL_PACKET, PACKET_FANOUT, &fanout_arg, sizeof(fanout_arg));
```
One fanout group per interface. `PACKET_FANOUT_HASH` distributes by the kernel's flow hash, which
keeps a flow on one socket — but it is **not guaranteed symmetric**, so the two directions of a
TCP connection may land on different workers. Note that in `design-decisions.md`; it is fine for
this project (each direction is still ordered) but it is a real difference from a symmetric RSS
setup and you should be able to say so.

### Model 2 — pipeline

One RX thread per port → an `SpscRing<Packet*, 1024>` per worker, selected by
`symmetric_hash_5tuple(pkt) & (workers-1)` → N workers → each worker transmits directly. Exists to
be compared against model 1.

```cpp
// pipe/hash.hpp — symmetric so both directions of a flow choose the same worker
[[nodiscard]] std::uint32_t symmetric_hash_5tuple(std::uint32_t sip, std::uint32_t dip,
                                                  std::uint16_t sp, std::uint16_t dp,
                                                  std::uint8_t proto) noexcept {
  const std::uint32_t a = sip ^ dip;          // order-independent
  const std::uint32_t b = (std::uint32_t{sp} ^ dp) | (std::uint32_t{proto} << 16);
  return mix32(a * 0x9E3779B1u ^ mix32(b));
}
```
XOR is order-independent, which is what makes it symmetric. Be able to explain why a naive
`hash(sip, dip, sp, dp)` is not. `mix32` is a standard 32-bit avalanche finaliser (the
`x ^= x >> 16; x *= 0x7feb352d; …` shape) — write it in `hash.hpp` and unit-test that flipping any
single input bit changes roughly half the output bits, or the low-order worker index will be
badly distributed.

### The ring

`ARCHITECTURE.md` §13 gives the layout and the ordering. Write the memory-ordering reasoning as a
comment block in the header — the comment is a deliverable, not decoration.

**Do not build yet.** No NUMA awareness (a laptop has one node — say so rather than faking it).
No work stealing. No dynamic worker scaling.

**Exit test.**

1. **Ring, single-threaded:** push/pop ordering, wrap-around at the power-of-two boundary, full and
   empty edge cases, `push_bulk`/`pop_bulk` partial results.
2. **Ring, two threads:** producer pushes 4,000,000 monotonically increasing integers; consumer
   pops them all and asserts they arrive exactly once, in order, none lost, none duplicated. Run
   under **TSan** and under ASan.
3. **Ordering, end to end:**
   ```bash
   # one flow, 100k packets, N workers -- IP IDs must arrive monotonically
   for w in 1 2 4 8; do
     npf run --config configs/router.conf --workers $w --mode rtc &
     ./bench/system/gen --flows 1 --count 100000 --ip-id-sequence
     tcpdump -w /tmp/out.pcap ... ; ./scripts/check_ordering.py /tmp/out.pcap  # must pass
   done
   ```
   Repeat for `--mode pipeline`.
4. **TSan on the running forwarder:** build with the `tsan` preset, run 60 s of sustained traffic
   through the netns topology, exit clean. This will find the bug you did not know you had.
5. Counters still balance: `sum over workers of rx_packets == forwarded + drops + to_host`.

**Commit.** `phase(13): run-to-completion and pipeline execution models, SPSC ring` → `git tag phase-13`

---

## Phase 14 — Benchmark harness and baseline

**Goal.** Reproducible measurement at both tiers, with the kernel control. **No optimisation in
this phase** — you are building the instrument and taking the baseline reading.

**Files.**
```
bench/micro/bench_datapath.cpp  bench_pool.cpp  bench_ring.cpp
     (bench_checksum.cpp and bench_lpm.cpp already exist)
bench/system/gen.cpp            EXTEND the phase-13 generator: rate control, TSC timestamps,
                                configurable flow count and packet size
bench/system/sink.cpp           a receiver that counts, detects gaps and computes latency
scripts/run_bench.sh
bench/plot.py                   bench/results/.gitkeep
docs/performance.md
```

**Contract.**

Tier A, Google Benchmark, no I/O at all. Packets pre-built in a pool, the real `Forwarder::process`
called in a loop:
- `BM_ParseOnly` — Ethernet + IPv4 + L4 parse
- `BM_ParseAndLookup` — the above plus a FIB lookup, parameterised over FIB type
- `BM_FullDatapath` — the complete `process()` including rewrite and checksum
- `BM_PoolAcquireRelease`, `BM_RingRoundTrip`
Run with `--benchmark_repetitions=7 --benchmark_report_aggregates_only=true
--benchmark_format=json`. Report median and stddev.

Tier B, through the namespaces:
- `gen` sends at a configurable rate (or as fast as it can) with a sequence number and a TSC
  timestamp in the UDP payload.
- `sink` counts received, detects gaps, and computes latency from the echoed timestamp.
- Metrics: delivered pps, loss %, p50/p95/p99 latency, CPU% (from `/proc/self/stat`), peak RSS.

**The kernel control.** `run_bench.sh --kernel-baseline` must:
```bash
ip netns exec ns-router ip addr add 10.0.1.1/24 dev veth-cr
ip netns exec ns-router ip addr add 10.0.2.1/24 dev veth-sr
ip netns exec ns-router sysctl -qw net.ipv4.ip_forward=1
# ... run the same gen/sink measurement ...
# then TEAR IT ALL DOWN AGAIN, or every later run is wrong
```
This is the denominator that makes every tier-B number mean something.

Every result JSON records, without exception: git SHA, ISO date, `uname -r`, CPU model from
`lscpu`, compiler and version, CMake preset and the actual flags, worker count, batch size, whether
`perf stat -e cycles` succeeded on this machine.

`docs/performance.md` starts with a **Methodology** section (the two tiers, the control, the
repetition and reporting rules, and an explicit statement of what these numbers do *not* measure)
and a **Baseline** section with the phase-14 numbers. Every later entry appends.

**Do not build yet.** No optimisations. If you find yourself wanting to change datapath code in
this phase, write the idea down in `docs/performance.md` under "candidates" and move on.

**Exit test.**
```bash
git clean -xdf && cmake --preset bench && cmake --build --preset bench -j
sudo ./scripts/run_bench.sh --all
```
produces `bench/results/<date>-<sha>.json` with every field populated, no NaNs, no zeros where a
measurement was supposed to happen; `python3 bench/plot.py` renders the charts; `docs/performance.md`
contains the baseline table with real numbers.

**Commit.** `phase(14): two-tier benchmark harness, traffic generator, kernel control baseline` → `git tag phase-14`

---

## Phase 15 — Optimization pass

**Goal.** A sequence of individually-measured improvements. Not "make it fast" — one change, one
measurement, one commit, one entry in `docs/performance.md`.

**Files.** No new modules. This phase edits existing ones — mostly `src/pipe/forward.cpp`,
`include/npf/core/packet.hpp`, `include/npf/stat/counters.hpp`, `src/io/af_packet.cpp` and
`src/table/lpm_dir24_8.cpp` — plus one appended section per optimisation in
`docs/performance.md`, and CMake options for the build-flag experiments (`NPF_NATIVE`, `NPF_LTO`,
already defined in phase 0).

**Rules for this phase, without exception:**
- One optimisation per commit. The commit message carries the before and after numbers.
- If the measured delta falls inside the noise band (median difference smaller than the p95 spread
  of either run), **revert the change** and write the negative result down anyway.
- Re-run the golden tests after every change. A faster forwarder that drops a packet is worthless.

**Candidates, in the order to try them:**

| # | Change | What to measure | Expect |
|---|---|---|---|
| 1 | Batch size sweep: 1, 4, 8, 16, 32, 64, 128 | tier A ns/pkt and tier B pps | A curve with a knee; pick from it, don't guess |
| 2 | RFC 1624 incremental checksum in the live path | tier A `BM_FullDatapath` | Real but small; it is a few ops out of a hundred |
| 3 | `alignas(64)` on `Counters` — the false-sharing experiment | tier B pps at 4 and 8 workers | Often large. Do it as an explicit before/after; it is a great story |
| 4 | `__builtin_prefetch` the next packet's L2/L3 header during the current one | tier A | Classic DPDK trick; measurable at batch ≥ 8 |
| 5 | `[[likely]]`/`[[unlikely]]` on the drop branches; reorder so the common path falls through | tier A, plus branch-misses if the PMU works | Small |
| 6 | Reorder `Packet` fields so the hot ones share a line; verify with `pahole` | tier A | Small but free |
| 7 | Devirtualise the FIB in `Forwarder` (template it) — measure with and without | tier A `BM_ParseAndLookup` | This is the abstraction-cost measurement |
| 8 | Replace any surviving `std::unordered_map` with the open-addressed table | tier A | Depends where it was |
| 9 | `-march=native`, then LTO, then both | everything | Report all four combinations |
| 10 | `madvise(MADV_HUGEPAGE)` on the DIR-24-8 tables | `bench_lpm` uniform-key case | TLB effect; `MAP_HUGETLB` may not work in WSL2, THP usually does |
| 11 | Busy-poll instead of `poll()` when a load threshold is exceeded | tier B pps and CPU% | Trades CPU for latency; report both |

Aim for **at least eight entries, including at least one honest negative result.** A performance
document with only wins reads as either lucky or dishonest.

**Do not build yet.** No new I/O backend — that is phase 16, and mixing it in here would make every
number ambiguous.

**Exit test.**
- `docs/performance.md` has ≥ 8 entries in the format from `CLAUDE.md` §9, each with before, after,
  delta, method and caveat.
- At least one entry is a reverted change with the negative result recorded.
- Every number is reproducible: `run_bench.sh` at the tagged commit produces it again within the
  reported spread.
- The full golden suite and every integration test are still green.

**Commit.** One per optimisation, then `phase(15): optimization pass complete` → `git tag phase-15`

**Stopping here is a complete project.** Phases 16–18 are upside.

---

## Phase 16 — PACKET_MMAP

**Goal.** Remove the per-packet syscall and copy. The largest single I/O improvement available
without leaving standard Linux.

**Files.**
```
include/npf/io/packet_mmap.hpp   src/io/packet_mmap.cpp
scripts/run_bench.sh             (add --compare-io)
docs/design-decisions.md         (add: why V3 for RX, and the TX choice)
```

**Contract.**

RX, `TPACKET_V3`:
```cpp
int ver = TPACKET_V3;
::setsockopt(fd, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver));

tpacket_req3 req{};
req.tp_block_size = 1 << 22;                    // 4 MiB, must be a multiple of the page size
req.tp_block_nr   = 8;
req.tp_frame_size = 2048;                       // must divide tp_block_size
req.tp_frame_nr   = (req.tp_block_size / req.tp_frame_size) * req.tp_block_nr;
req.tp_retire_blk_tov = 10;                     // ms before the kernel hands back a partial block
req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;
::setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));

void* ring = ::mmap(nullptr, req.tp_block_size * req.tp_block_nr,
                    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd, 0);
```
Then: `poll()` on the fd; walk blocks whose `block_status & TP_STATUS_USER`; within a block iterate
`tpacket3_hdr` records via `tp_next_offset`; when finished with a block set
`block_status = TP_STATUS_KERNEL` to hand it back. **Forgetting that last step stalls the ring
silently** — it is the classic mistake.

TX: `PACKET_TX_RING` with a `tpacket_req` (V2) or `tpacket_req3` (V3). TPACKET_V3 does support TX
rings — the semantics mirror V2, using `tpacket3_hdr` with `tp_next_offset` set to zero — but V3's
block-based design buys nothing on TX. **Pick one, and write the reason down.** Copy the frame into
the ring slot, set `tp_status = TP_STATUS_SEND_REQUEST`, then kick with
`::send(fd, nullptr, 0, MSG_DONTWAIT)`.

Also set `PACKET_QDISC_BYPASS` on the TX socket:
```cpp
int one = 1;
::setsockopt(fd, SOL_PACKET, PACKET_QDISC_BYPASS, &one, sizeof(one));
```

Be able to say, mechanically, what this buys: the kernel writes received frames directly into a
memory region shared with your process, so per packet you save two context switches and one copy;
you pay with a `poll()` per block rather than per packet. That sentence is the phase's real
deliverable.

**Do not build yet.** No AF_XDP. No zero-copy in the pipeline — you still copy out of the ring into
a pool buffer at first. (Making the `Packet` point *into* the ring is a legitimate follow-up
optimisation; measure it separately if you attempt it.)

**Exit test.**
1. Every golden test passes with `--io mmap` — same bytes out as with `--io af_packet`.
2. The phase 6, 7, 8 and 12 integration tests pass with `--io mmap`.
3. `run_bench.sh --compare-io` produces a table: kernel control, `af_packet`, `mmap` — same
   topology, same generator, same run. Numbers go into `docs/performance.md`.
4. Run it for 60 s under load and confirm no ring stall (rx rate stays flat, does not drop to zero).

**Commit.** `phase(16): PACKET_MMAP backend with TPACKET_V3 RX ring and qdisc bypass` → `git tag phase-16`

---

## Phase 17 — AF_XDP *(stretch)*

**Goal.** The backend that turns heads. Also the one with a real prerequisite: the stock WSL2
kernel does not ship XDP.

**Files.**
```
docs/wsl2-custom-kernel.md      write this FIRST — it is a deliverable in its own right
bpf/xdp_redirect.c              minimal XDP program: bpf_redirect_map into an XSKMAP
include/npf/io/af_xdp.hpp       src/io/af_xdp.cpp
cmake/FindLibbpf.cmake
```

**Prerequisite: a custom WSL2 kernel.**
```bash
git clone --depth 1 https://github.com/microsoft/WSL2-Linux-Kernel
cd WSL2-Linux-Kernel
cp Microsoft/config-wsl .config
scripts/config --enable CONFIG_BPF_SYSCALL --enable CONFIG_BPF_JIT \
               --enable CONFIG_XDP_SOCKETS --enable CONFIG_XDP_SOCKETS_DIAG \
               --enable CONFIG_BPF_EVENTS --enable CONFIG_DEBUG_INFO_BTF
make -j$(nproc) && cp arch/x86/boot/bzImage /mnt/c/wsl-kernel/bzImage
```
Then in `C:\Users\<you>\.wslconfig`:
```ini
[wsl2]
kernel=C:\\wsl-kernel\\bzImage
```
`wsl --shutdown`, restart, verify with
`zcat /proc/config.gz | grep XDP_SOCKETS` and `uname -r`.

Document the whole procedure, including what broke and how you fixed it. "I rebuilt the WSL2
kernel to get AF_XDP" is a sentence worth having.

**Contract.**
- Use `libbpf` and `libxdp` (`apt install libbpf-dev libxdp-dev`) rather than hand-rolling the
  socket setup. Writing the XSK ring logic from scratch is a week you do not need to spend.
- UMEM: one `mmap`'d region of `N * 2048` frames, registered with `XDP_UMEM_REG`. Four rings: fill,
  completion, RX, TX. Bind the socket to `(ifindex, queue_id)`.
- The XDP program is minimal — `bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0)` — loaded onto
  the interface and pinned.
- On veth: `ethtool -K veth-x gro off` first. Native XDP on veth requires an XDP program on the
  **peer** interface in many kernels; if that fights you, use generic/SKB mode
  (`XDP_FLAGS_SKB_MODE`), which always works. **Measure both and report both** — the difference
  between generic and native XDP is itself an interesting number.
- Zero-copy (`XDP_ZEROCOPY`) will not work on veth. Use `XDP_COPY` and say so.

**Do not build yet.** No AF_XDP-specific datapath changes. Same `IoBackend`, same pipeline.

**Exit test.**
1. `docs/wsl2-custom-kernel.md` is complete enough that someone else could follow it from a stock
   WSL2 install.
2. All golden tests pass with `--io xdp`.
3. Phase 6/7/8/12 integration tests pass with `--io xdp`.
4. `run_bench.sh --compare-io` now shows four rows: kernel control, af_packet, mmap, xdp
   (generic and native separately if both work).

**Commit.** `phase(17): AF_XDP backend and custom WSL2 kernel procedure` → `git tag phase-17`

---

## Phase 18 — aarch64 and NEON *(stretch)*

**Goal.** Prove the code is architecture-portable, and turn the ring's memory ordering from a
claim into a demonstration.

**Files.**
```
include/npf/proto/checksum_simd.hpp     src/proto/checksum_neon.cpp  checksum_avx2.cpp
tests/arch/test_memory_ordering.cpp     (disabled by default)
.github/workflows/ci.yml                (add an arm64 job)
docs/performance.md                     (add the cross-architecture table)
```

**Contract.**
- Runtime dispatch for the checksum: `__builtin_cpu_supports("avx2")` on x86, compile-time on
  aarch64 (NEON is baseline on ARMv8, no dispatch needed). Fall back to the scalar version.
- A GitHub Actions `ubuntu-24.04-arm` runner builds and runs the full suite. If the runner is not
  available, cross-compile with `aarch64-linux-gnu-g++` and run the unit tests under
  `qemu-aarch64-static` — note in the README that qemu does not model the memory ordering, so the
  ordering test needs real hardware.
- Benchmark all three checksum implementations on both architectures and put both columns in
  `docs/performance.md`.

**Do not build yet.** No architecture-specific datapath beyond the checksum. Do not write a NEON
packet parser — the checksum is the one place SIMD clearly pays, and a vectorised parser would be
a lot of unsafe code for an unmeasured gain. Do not chase aarch64-specific optimisations; the point
of this phase is portability and the memory model, not another speedup.

**The memory-ordering demonstration.** In `tests/arch/`, add a deliberately-wrong ring variant
using `memory_order_relaxed` on the producer's index store, plus a test that hammers it. On x86 it
will almost certainly pass. On real aarch64 it should eventually fail. Keep the test disabled by
default (`DISABLED_` prefix) and document how to run it and what it demonstrates. If it never fails
even on aarch64, say that too — a store-buffer race is probabilistic, and reporting "I could not
reproduce it in N iterations" is honest and still shows you understood the hazard.

**Exit test.**
1. Full test suite green on aarch64.
2. Checksum benchmark numbers for both architectures in `docs/performance.md`.
3. The ordering demonstration documented, with whatever result you actually got.

**Commit.** `phase(18): aarch64 support, NEON/AVX2 checksums, memory-ordering demonstration` → `git tag phase-18`

---

## Phase 19 — Documentation

**Goal.** Someone who has never seen the project can understand it in five minutes and run it in
fifteen.

**Files.**
```
README.md                     (the real one)
docs/architecture.md          docs/packet-flow.md      docs/design-decisions.md
docs/performance.md           (final pass)             docs/architecture.svg
demo/traceroute.gif           demo/setup.gif
```

**README structure, in this order:**
1. One paragraph: what it is and what it does.
2. The traceroute GIF. Lead with the thing that works.
3. Quick start: five commands from clone to a ping crossing the topology.
4. Architecture diagram (SVG, committed, not a PNG screenshot of one).
5. The packet pipeline — the fourteen steps, with the drop reasons.
6. **Supported protocols**, and immediately after it, **Not implemented**: no TCP stack, no
   fragment reassembly, no IPv6, no STP, no ICMP redirect, no PMTU discovery, one VLAN tag only.
   The honest list is the credible one.
7. The L2/L3 decision rule, quoted verbatim.
8. LPM comparison table with the real measured numbers and the uniform-vs-skewed contrast.
9. Threading model: the two execution models, and how per-flow ordering is preserved.
10. Performance: the methodology first (two tiers, the kernel control, the caveats), then the
    numbers, then the optimisation table.
11. Testing: unit, property, fuzz, golden pcap, netns integration, sanitizers. Give the counts.
12. Build, run, topology, benchmark instructions.
13. Known limitations, including the fragment-evasion paragraph from phase 11.
14. References: RFC 791, 792, 826, 1624, 1812; the DIR-24-8 paper (Gupta, Lin, McKeown, 1998);
    DPDK's `rte_lpm` and `l3fwd` as prior art you read but did not copy.

`docs/design-decisions.md` should by now have at least fifteen entries accumulated across the
phases. If it does not, that is a signal you skipped the part that actually matters. Each entry:
what was decided, what the alternatives were, why, and what it cost.

**Exit test.** On a fresh WSL2 Ubuntu install, following only the README, a person who has not seen
the project gets from `git clone` to a successful ping through the forwarder in under fifteen
minutes. Test this literally — use a fresh WSL distro (`wsl --install -d Ubuntu-24.04 --name test`)
and follow your own instructions without improvising. You will find three things wrong.

**Commit.** `phase(19): documentation, architecture diagram, demo recordings` → `git tag v1.0`

---

## After v1.0

Only now, with `bench/results/` full of real measurements, write the resume bullets — and write
them from the numbers that are actually in the repository, not from the ones you hoped for.
