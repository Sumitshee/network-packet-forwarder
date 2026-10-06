# network-packet-forwarder

A userspace Layer-2/Layer-3 packet forwarding engine — a software router — written in C++20 for
Linux. It receives raw Ethernet frames from network interfaces, parses them, makes forwarding
decisions, rewrites headers and transmits them out of the correct interface.

**Status: phase 12 of 19.** `npf` routes IPv4 between Linux interfaces. It has one AF_PACKET socket
per port and runs every packet through a fixed fourteen-step pipeline: parse, validate, route,
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
every counter, and Ctrl-C stops it and prints them one last time. `npf show mac` and
`npf show arp` do the same for its MAC table and its ARP cache. `SIGUSR2` empties the ARP cache of
everything but the static entries, which is how a test starts it from cold.
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
  it already has. One cache serves every port, searched entry by entry. No proxy ARP.
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
- **Threads.** One worker forwards everything (phase 13).
- **IPv6.** Not routed: an IPv6 frame for the router is dropped as an unsupported EtherType, while
  one crossing a bridge is switched like any other frame. The longest-prefix match tables are
  IPv4's alone too; none is written to take a wider address.
- **Link state.** A port's link is checked once, at start-up. If it goes down later, frames sent to
  it are counted as `TxFull`, and a bridge goes on flooding to it; one down at start-up is never
  flooded to.
- **VLANs.** One 802.1Q (`0x8100`) or 802.1ad (`0x88a8`) tag is parsed and carried, not
  interpreted: the frame is routed as if it were untagged and leaves with the same tag, or is
  switched with the tag untouched. A second tag (QinQ) is not unwrapped, and a frame for the router
  with one is dropped as an unsupported EtherType.
- **IPv4 options.** A header's options are skipped using its length field; none is interpreted.
- **Fragment reassembly.** Fragments are never reassembled. Only a first (or only) fragment carries
  the transport header, so every other fragment is handled with no ports at all.
- **TCP.** Only the header's fields are read: ports, sequence and acknowledgement numbers, flags.
  There is no connection state.
- **Most configuration choices.** The configuration parser accepts every value the file format
  defines, but `npf run` runs only `io af_packet`, and `npf replay` only `io pcap`; both only with
  `fib linear`, `mode rtc` and `workers 1`. They refuse the rest: `fib trie`, `patricia` and
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

```bash
cmake --preset dev && cmake --build --preset dev -j && ctest --preset dev
```

The binary is `build/dev/npf`. Other presets: `ci` (warnings as errors),
`asan` (AddressSanitizer + UBSan), `tsan` (ThreadSanitizer), `release` (`-O2 -g`),
`bench` (`-O2 -g -march=native`, benchmarks on). Select the compiler with `CXX`, e.g.
`CXX=clang++-18 cmake --preset dev`. Tests that need root are skipped when `ctest` is not run as
root.

## License

MIT — see [LICENSE](LICENSE).
