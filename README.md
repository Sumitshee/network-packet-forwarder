# network-packet-forwarder

A userspace Layer-2/Layer-3 packet forwarding engine — a software router — written in C++20 for
Linux. It receives raw Ethernet frames from network interfaces, parses them, makes forwarding
decisions, rewrites headers and transmits them out of the correct interface.

**Status: phase 17 of 19.** `npf` routes IPv4 between Linux interfaces. It runs every packet
through a fixed fourteen-step pipeline: parse, validate, route,
resolve the next hop, rewrite the MAC addresses, decrement the TTL and patch the checksum. Every
packet it drops is counted under a reason. It resolves its neighbours with ARP itself: a packet
for a neighbour it has not resolved yet waits, up to three per neighbour, while it asks, and goes
out when the answer comes; entries age, and are checked again before they are trusted for long.
It answers like a router: ICMP Time Exceeded when a packet's TTL runs out, so `traceroute` works
through it; Destination Unreachable when there is no route, or when a neighbour never answers ARP;
and echo replies when it is pinged itself. Integration tests run it between three network
namespaces: the first ping through a router that knows no one gets its answer, pings cross it with
their TTL decremented exactly once, traceroute shows it as the first hop, no buffer leaks, and
every packet received is accounted for as forwarded, delivered to the router itself, or dropped.
[`docs/rfc1812-conformance.md`](docs/rfc1812-conformance.md) lists which requirements of RFC 1812,
*Requirements for IP Version 4 Routers*, it meets and which it does not yet.

It filters what it forwards, when its configuration names a filter file. Rules match source and
destination prefixes, the protocol, TCP and UDP ports, and the port a packet arrived on; they are
tried in order until one matches, and a policy decides the rest. What a rule about ports cannot do
with a fragment is under [Known limitations](#known-limitations).

It switches, too. A port configured as bridged learns the MAC address of every station it hears,
forwards a frame to a station it has learned out of that station's port, unchanged, and floods
broadcasts, multicasts and frames to stations it has not learned yet out of every other port of
the same bridge domain. Stations are forgotten after `mac_age` seconds of silence, 300 by default.
An integration test runs it as a three-port switch between three hosts in one subnet: the hosts
ping one another through it, the third host sees the first ARP request flooded but none of the
unicast traffic that follows, and the table empties once the hosts fall silent.

It runs on as many worker threads as it is told, in one of two models. In run-to-completion
(`mode rtc`, the default) each worker has its own AF_PACKET socket on every port, all of a port's
sockets joined in one `PACKET_FANOUT_HASH` group, so the kernel hands each flow to one worker, which
receives, decides and transmits it without ever touching another thread's memory. In the pipeline
model (`mode pipeline`) one thread per port receives, and steers each packet by a symmetric hash of
its flow -- the same for both directions -- through a lock-free single-producer, single-consumer
ring to a worker, which transmits it and sends the buffer home on a second ring. Workers keep their
own ARP caches and pass each other the ARP replies they hear. An integration test sends 100,000
datagrams of one flow through 1, 2, 4 and 8 workers in each model and checks that they arrive in
the order sent; another runs the router built with ThreadSanitizer under a minute of sustained
traffic in each model.

It reads and writes the wire through either of two socket backends, chosen with `io` in the
configuration or `--io` on the command line. `af_packet` makes a system call per frame. `mmap`
(PACKET_MMAP) shares rings with the kernel. On receive, the kernel fills 4 MiB blocks of a
TPACKET_V3 ring and hands each one over when it is full, or after 10 ms. On transmit, frames go
into the slots of a TPACKET_V2 ring that bypasses the queueing discipline, with one system call
per burst. Both backends copy each frame into a pool buffer and out again; neither is zero-copy.
An integration test runs every golden case live through both and requires byte-identical frames
out of every port. In pipeline mode on `mmap`, the RX threads receive only what the workers'
rings can take, and leave the rest waiting in the kernel. That measured as a large gain on
`mmap` and a loss on `af_packet`, so `af_packet` keeps dropping as `RingFull`. The kernel's own
receive drops are reported beside npf's counters as `kernel_rx_drops`. The 10 ms is a latency
cost at low rates: a block that never fills waits for its timer.
[`docs/performance.md`](docs/performance.md) compares the backends.

A third backend, `xdp`, uses AF_XDP:

- On each port npf attaches a one-line XDP program, `bpf/xdp_redirect.c`, compiled with clang
  and embedded in the binary. It hands every frame to an AF_XDP socket whose rings point into
  memory npf registered with the kernel (a UMEM).
- `--xdp-mode skb` runs the program in the kernel's generic receive path, and `native` in the
  veth driver. Both work on veth, and are measured separately.
- veth has no zero-copy, so the kernel copies each frame into the UMEM and out again. What
  AF_XDP saves on receive is the kernel's network stack.
- It runs one worker, run to completion: one socket per port, on one queue, with no fanout.
- It is built only when libbpf and libxdp are installed.

The stock WSL2 kernel already has AF_XDP, so no custom kernel was built.
[`docs/wsl2-custom-kernel.md`](docs/wsl2-custom-kernel.md) says how to check, and how one would
be built for a kernel that lacks it. The same integration test runs every golden case through
`xdp` in both modes too.

It is measured at two tiers, kept apart. Tier A times the forwarding code in process, with no I/O:
parsing, FIB lookups in each of the four tables, the whole fourteen-step pipeline, the packet pool
and the ring. Tier B sends numbered, timestamped UDP flows through the namespaces and measures what
arrives -- datagrams per second, loss, one-way latency, CPU time -- for each threading model and
worker count, and for the same topology forwarded by the Linux kernel instead, the control every npf
number is read against. `scripts/run_bench.sh --all` runs both and writes one JSON with the context
of the run; [`docs/performance.md`](docs/performance.md) gives the method, the baseline, and what
the numbers do not measure. Phase 15 measured twelve changes one at a time, each before and after
on the same machine: most were noise and were reverted, and the document says so, entry by entry.
Link-time optimisation measured faster and is on in the `release` preset. `--busy-poll` cuts
latency at a low rate, at the price of a CPU per thread kept spinning, so it stays a switch.

`npf replay` runs the same router over a pcap file instead of live interfaces, and writes what it
sends to another: deterministically, and with no root. The golden-file tests use it in CI. Each
case is a pcap, a configuration, and the frames and counters the router must end with, which
`scripts/make_fixtures.py` builds from a separate model of what a router must do, never from
npf's own output.

Underneath are a zero-allocation packet buffer pool; bounds-checked, fuzz-tested parsers for
Ethernet, ARP, IPv4 and the TCP, UDP and ICMP headers, and for pcap files; the Internet checksum
with the RFC 1624 incremental update; and the configuration file parser. Longest-prefix match comes
four ways: a deliberately simple linear table, the oracle, and a binary trie, a Patricia trie and
DIR-24-8, each held to the oracle on a thousand adversarial random tables. `bench_lpm` times them on
a full Internet routing table, a RouteViews snapshot of 1.13 million prefixes, which
`scripts/fetch_bgp_table.sh` downloads; [`docs/performance.md`](docs/performance.md) has the
results, and what they do not measure. The router itself still uses the linear table.

## How a frame is handled

Each port is configured as routed or bridged, and this rule (`docs/ARCHITECTURE.md` §2) decides
which path a frame takes:

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

On a bridged port, a broadcast is the router's only when it asks for that port's own address: an
ARP request for its IP, or an IPv4 packet to it. Every other frame not addressed to the port's MAC
-- any broadcast, any multicast, any EtherType -- takes the L2 path, so the hosts on a bridge can
ARP for one another, and an IPv6 frame crosses it although the router does not route IPv6. On
that path the frame's source is learned, and then:

- a broadcast, a multicast, or a destination not learned yet is flooded out of every other port
  of the bridge domain that was up at start-up;
- a destination learned on another port of the bridge domain is forwarded out of that port, the
  frame unchanged;
- a destination learned on the port the frame came in on is dropped, as `SamePort`.

A routed port works exactly as before: a frame not addressed to the router is dropped as
`UnknownDestPort`.

## Running it

Root is needed for the network namespaces and for AF_PACKET sockets.
`scripts/setup_netns.sh` builds three namespaces, ns-client, ns-router and ns-server; the header
of the script draws the topology.

```bash
sudo ./scripts/setup_netns.sh
sudo ip netns exec ns-router ./build/dev/npf run --config configs/router.conf
```

Then, from a second terminal:

```bash
sudo ip netns exec ns-client ping 10.0.2.2
```

```bash
sudo ./build/dev/npf show stats
```

```bash
sudo ./scripts/cleanup_netns.sh
```

`--workers`, `--mode` and `--io` override the configuration's `workers`, `mode` and `io`:

```bash
sudo ip netns exec ns-router ./build/dev/npf run --config configs/router.conf --workers 4 --mode pipeline
```

```bash
sudo ip netns exec ns-router ./build/dev/npf run --config configs/router.conf --io mmap
```

```bash
sudo ip netns exec ns-router ./build/dev/npf run --config configs/router.conf --io xdp --xdp-mode native
```

`bench/system/gen` sends numbered UDP flows from the client, and `scripts/check_ordering.py` checks a
capture of them for reordering:

```bash
sudo ip netns exec ns-client ./build/dev/bench/system/gen --dst 10.0.2.2 --flows 4 --count 100000 --ip-id-sequence
```

To filter, uncomment `filter filter.conf` in `configs/router.conf`:
[`configs/filter.conf`](configs/filter.conf) has the rules, and the comments in
`include/npf/core/config.hpp` give the format. A packet the filter denies is counted as
`FilterDeny`.

To run it as a switch instead, `scripts/setup_bridge_netns.sh` builds three hosts, ns-h1, ns-h2 and
ns-h3, all in 10.0.9.0/24 and each a veth away from ns-router, and
[`configs/bridge.conf`](configs/bridge.conf) bridges the router's three ports:

```bash
sudo ./scripts/setup_bridge_netns.sh
sudo ip netns exec ns-router ./build/dev/npf run --config configs/bridge.conf
```

```bash
sudo ip netns exec ns-h1 ping 10.0.9.2
```

```bash
sudo ./build/dev/npf show mac
```

```bash
sudo ./scripts/cleanup_bridge_netns.sh
```

`npf run` prints a stats line every 5 seconds. `npf show stats` signals it (`SIGUSR1`) to write out
every counter, summed over every thread, and Ctrl-C stops it and prints them one last time.
`npf show mac` and `npf show arp` do the same for its MAC tables and its ARP caches, a section per
worker when there are several. `SIGUSR2` empties the ARP caches of everything but the static
entries, which is how a test starts it from cold. Each of these is answered with every thread
parked between two bursts, so nothing is read while it is being written.
`npf dump --iface <name>` prints the parsed headers of every frame an interface receives.

The integration tests set all of this up, make their checks and tear it down again:

```bash
sudo tests/integration/test_forward_netns.sh build/dev/npf
```

```bash
sudo tests/integration/test_traceroute.sh build/dev/npf
```

```bash
sudo tests/integration/test_arp_resolution.sh build/dev/npf
```

```bash
sudo tests/integration/test_switching.sh build/dev/npf
```

```bash
sudo tests/integration/test_ordering.sh build/dev/npf
```

```bash
sudo tests/integration/test_soak.sh build/tsan/npf
```

### Benchmarking

The bench preset builds the microbenchmarks and the bench/system tools; tier B needs root, for the
namespaces. `git clean` keeps `data/`, the routing table `bench_lpm` reads, and `.deps-cache/`.

```bash
git clean -xdf -e data -e .deps-cache && cmake --preset bench && cmake --build --preset bench -j
```

```bash
sudo ./scripts/run_bench.sh --all
```

```bash
python3 bench/plot.py
```

`--tier-a`, `--tier-b` and `--kernel-baseline` run one part; `--quick` is a short rehearsal whose
result stays in `bench/results/raw/`.

### Replaying a pcap

No root, and no interfaces: every frame of the input arrives on port 0, and every frame the router
sends is written to the output, in the order sent. The configuration must give each interface's
MAC (`mac <address>`) and say `io pcap`; `tests/fixtures/golden/*.conf` are examples.

```bash
./build/dev/npf replay in.pcap out.pcap --config tests/fixtures/golden/basic_fwd.conf --stats-json counters.json
```

The golden-file tests replay every case in `tests/fixtures/golden/` and compare both outputs, the
frames and the counters, with what the case expects:

```bash
ctest --preset dev -R golden --output-on-failure
```

## Not implemented

- **Some of ICMP.** No Redirect, Parameter Problem or Fragmentation Needed. ICMP errors quote the
  original header and 8 bytes of its data, not as much as fits in 576 bytes. A ping that arrives
  fragmented goes unanswered.
- **Some of RFC 1812.** Besides the above: IP options are passed through but never interpreted;
  packets are never fragmented or reassembled; and a packet to a martian destination such as
  127.0.0.1 is routed if a route, a default route say, covers it. The full list is in
  [`docs/rfc1812-conformance.md`](docs/rfc1812-conformance.md).
- **Some of ARP.** Its timers are fixed: an entry is checked again after 30 s, deleted after 60 s
  unused, and given up on after three requests a second apart. When three packets already wait on
  a neighbour, the next one is dropped, not the oldest. The router learns a neighbour's address
  from its replies and announcements, never from its requests, and creates an entry only for a
  neighbour it has asked about itself. Requests are always broadcast, even when checking an entry
  it already has. One cache per worker serves every port, searched entry by entry. No proxy ARP.
- **Some of replay.** Only classic pcap is read: not pcapng, and not the nanosecond-resolution
  variant, which is refused rather than misread. Every input frame arrives on port 0, and the output
  does not record which port a frame left by. No time passes during a replay, so an ARP request is
  never answered or repeated, and at most 100 ICMP errors are sent, the rate limiter's allowance
  for one second.
- **Some of packet filtering.** The filter keeps no state: a reply is judged like any other packet,
  so it needs a rule of its own. Rules match addresses, the protocol, ports and the port a packet
  arrived on, not TCP flags or ICMP types, and are tried one at a time, in order. The filter sees
  only what the router forwards: not packets addressed to the router itself, not ARP, and not a
  packet whose TTL runs out, which is answered with Time Exceeded before the filter would see it.
  A denied packet is dropped silently, with no ICMP Communication Administratively Prohibited, and
  counted in total, not per rule; nothing is logged.
- **Some of switching.** No spanning tree: bridged ports joined in a loop flood a broadcast round it
  for ever. No VLAN-aware bridging: a tag is carried, never looked at, so a bridge domain is one
  flat segment whatever its frames' tags. One MAC table serves every bridge domain, so a MAC heard
  in two is learned in whichever it spoke in last, and a frame for it in the other is flooded. The
  group addresses IEEE 802.1D reserves, 01:80:c2:00:00:00 to 0f (spanning tree, LLDP, pause
  frames), which a bridge must not forward, are flooded like any multicast. A flood copy that finds
  no free buffer is not sent; the frame is still counted once, as flooded. An address on a bridged
  port is answered on that port alone: the router has no address for a bridge domain as a whole.
- **Some of threading.** No NUMA awareness, CPU pinning, work stealing or change in the number of
  workers while running. The kernel's fanout hash is not symmetric, so in run-to-completion the two
  directions of a connection may be handled by different workers; each direction stays in order.
  Each worker resolves its neighbours for itself, so several may ask for the same one, and has its
  own ICMP rate limiter, so the router as a whole sends up to N times one limiter's allowance.
  Pipeline mode needs a power-of-two number of workers and a `pool_size` of at most 16384. On
  `af_packet` it drops a packet whose worker's ring is full, as `RingFull`. On `mmap`, while any
  worker's ring is full, its RX threads receive nothing: they spin in `poll()` on a readable
  socket until there is room, and the kernel drops what overflows. Bridged ports need `workers 1`: each worker
  would keep a MAC table of its own. The routing table cannot change while the router runs.
- **IPv6.** Not routed: an IPv6 frame for the router is dropped as an unsupported EtherType, while
  one crossing a bridge is switched like any other frame. The longest-prefix match tables are
  IPv4's alone too; none is written to take a wider address.
- **Link state.** A port's link is checked once, at start-up. If it goes down later, frames sent to
  it are counted as `TxFull`, and a bridge goes on flooding to it; one down at start-up is never
  flooded to.
- **VLANs.** One 802.1Q (`0x8100`) or 802.1ad (`0x88a8`) tag is parsed and carried, not
  interpreted: the frame is routed as if it were untagged and leaves with the same tag, or is
  switched with the tag untouched. A second tag (QinQ) is not unwrapped, and a frame for the router
  with one is dropped as an unsupported EtherType. That is what `npf replay` does. **Live, on
  either socket backend, the tag is lost:** the kernel takes it out of a received frame before a
  packet socket reads it, passing it alongside instead (`PACKET_AUXDATA`, or the TPACKET_V3
  header), and npf does not read it back, so a tagged frame is forwarded untagged.
  `tests/integration/test_io_equivalence.sh` checks exactly this.
- **Zero-copy.** Both socket backends copy every frame between the kernel's memory and a pool
  buffer, once on the way in and once on the way out. PACKET_MMAP saves the system call per
  frame, not the copies. With `mmap`, the 10 ms block timeout is fixed, as are the ring sizes:
  8 blocks of 4 MiB per port, shared between the sockets of a fanout group, and 512 TX slots.
- **AF_XDP beyond one queue.** `--io xdp` binds one socket to queue 0 of each port: no
  multi-queue, no shared UMEM, no fanout, so one worker, run to completion. It copies
  (`XDP_COPY`), as it must on veth; zero-copy on a NIC that supports it is not tried. Native XDP
  was only ever run on veth. The XDP program is not pinned: it lives as long as npf does.
- **IPv4 options.** A header's options are skipped using its length field; none is interpreted.
- **Fragment reassembly.** Fragments are never reassembled. Only a first (or only) fragment carries
  the transport header, so every other fragment is handled with no ports at all.
- **TCP.** Only the header's fields are read: ports, sequence and acknowledgement numbers, flags.
  There is no connection state.
- **Most configuration choices.** The configuration parser accepts every value the file format
  defines, but `npf run` runs only `io af_packet`, `io mmap` and `io xdp` (the last with one
  worker, and only when built with libbpf and libxdp), and `npf replay` only `io pcap`, on one
  thread (`mode rtc`, `workers 1`); both only with `fib linear`. They refuse the rest: `fib trie`, `patricia` and
  `dir24_8` name tables that exist and are tested, but the router is not built on them yet.

## Known limitations

Non-initial fragments carry no L4 header, so port-based filter rules cannot apply to them. This
forwarder does not reassemble, so an attacker can evade a port rule by fragmenting the packet. Real
firewalls reassemble before classification precisely for this reason. The trade-off here is
deliberate: reassembly is stateful, memory-unbounded without careful limits, and out of scope.

One fragment attack is closed off. A TCP or UDP packet whose header cannot be read is denied while
any rule constrains ports, rather than falling through those rules for want of ports; that covers
RFC 1858's tiny fragment, a first fragment cut too short to hold the whole TCP header. RFC 1858's
other attack, overlapping fragments that rewrite the TCP header when the destination reassembles
them, is not covered.

## Building

Requires Linux (developed on WSL2 Ubuntu 24.04), CMake ≥ 3.20, Ninja, and GCC 13 or Clang 18.
The AF_XDP backend also needs `libbpf-dev`, `libxdp-dev` and clang, to compile its XDP program;
without them it is left out, and `--io xdp` says so.

```bash
cmake --preset dev && cmake --build --preset dev -j && ctest --preset dev
```

The binary is `build/dev/npf`. Other presets: `ci` (warnings as errors),
`asan` (AddressSanitizer + UBSan), `tsan` (ThreadSanitizer), `release` (`-O2 -g`, LTO),
`bench` (`-O2 -g -march=native`, benchmarks on). Select the compiler with `CXX`, e.g.
`CXX=clang++-18 cmake --preset dev`. Tests that need root are skipped when `ctest` is not run as
root.

## License

MIT — see [LICENSE](LICENSE).
