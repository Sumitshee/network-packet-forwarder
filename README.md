# network-packet-forwarder

A userspace Layer-2/Layer-3 packet forwarding engine — a software router — written in C++20 for
Linux. It receives raw Ethernet frames from network interfaces, parses them, makes forwarding
decisions, rewrites headers and transmits them out of the correct interface.

**Status: phase 7 of 19.** `npf` routes IPv4 between Linux interfaces. It has one AF_PACKET socket
per port and runs every packet through a fixed fourteen-step pipeline: parse, validate, route,
resolve the next hop, rewrite the MAC addresses, decrement the TTL and patch the checksum. Every
packet it drops is counted under a reason. It answers like a router: ICMP Time Exceeded when a
packet's TTL runs out, so `traceroute` works through it; Destination Unreachable when there is no
route; and echo replies when it is pinged itself. Integration tests run it between three network
namespaces: pings cross it with their TTL decremented exactly once, traceroute shows it as the
first hop, no buffer leaks, and every packet received is accounted for as forwarded, delivered to
the router itself, or dropped. [`docs/rfc1812-conformance.md`](docs/rfc1812-conformance.md) lists
which requirements of RFC 1812, *Requirements for IP Version 4 Routers*, it meets and which it
does not yet.

Underneath are a zero-allocation packet buffer pool; bounds-checked, fuzz-tested parsers for
Ethernet, ARP, IPv4 and the TCP, UDP and ICMP headers; the Internet checksum with the RFC 1624
incremental update; a deliberately simple longest-prefix-match routing table; and the
configuration file parser.

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

Until switching exists (phase 12), the L2 path has nowhere to send a frame either, so a transit
frame is dropped on a bridged port too.

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

`npf run` prints a stats line every 5 seconds. `npf show stats` signals it (`SIGUSR1`) to write out
every counter, and Ctrl-C stops it and prints them one last time.
`npf dump --iface <name>` prints the parsed headers of every frame an interface receives.

The integration tests set all of this up, make their checks and tear it down again:

```bash
sudo tests/integration/test_forward_netns.sh build/dev/npf
```

```bash
sudo tests/integration/test_traceroute.sh build/dev/npf
```

## Not implemented

- **Some of ICMP.** No Host Unreachable when a neighbour never answers ARP (phase 8), and no
  Redirect, Parameter Problem or Fragmentation Needed. ICMP errors quote the original header and
  8 bytes of its data, not as much as fits in 576 bytes. A ping that arrives fragmented goes
  unanswered.
- **Some of RFC 1812.** Besides the above: IP options are passed through but never interpreted;
  packets are never fragmented or reassembled; and a packet to a martian destination such as
  127.0.0.1 is routed if a route, a default route say, covers it. The full list is in
  [`docs/rfc1812-conformance.md`](docs/rfc1812-conformance.md).
- **Queueing during ARP resolution.** The packet that starts a resolution is dropped, not queued,
  so the first packet to a neighbour the router has not resolved yet is lost. Entries never expire,
  and a request is only repeated when more traffic for the neighbour arrives (phase 8).
- **Packet filtering.** There are no filter rules; everything that can be routed is (phase 11).
- **Switching.** Bridged ports drop transit frames (phase 12).
- **Threads.** One worker forwards everything (phase 13).
- **IPv6.** Not routed: an IPv6 frame is dropped as an unsupported EtherType.
- **Link state.** A port's link is checked once, at start-up. If it goes down later, frames sent to
  it are counted as `TxFull`.
- **VLANs.** One 802.1Q (`0x8100`) or 802.1ad (`0x88a8`) tag is parsed and carried, not
  interpreted: the frame is routed as if it were untagged and leaves with the same tag. A second tag
  (QinQ) is not unwrapped, and the frame is dropped as an unsupported EtherType.
- **IPv4 options.** A header's options are skipped using its length field; none is interpreted.
- **Fragment reassembly.** Fragments are never reassembled. Only a first (or only) fragment carries
  the transport header, so every other fragment is handled with no ports at all.
- **TCP.** Only the header's fields are read: ports, sequence and acknowledgement numbers, flags.
  There is no connection state.
- **Most configuration choices.** The configuration parser accepts every value the file format
  defines, but `npf run` runs only `io af_packet`, `fib linear`, `mode rtc` and `workers 1`, and
  refuses the rest.

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
