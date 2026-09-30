# network-packet-forwarder

A userspace Layer-2/Layer-3 packet forwarding engine — a software router — written in C++20 for
Linux. It receives raw Ethernet frames from network interfaces, parses them, makes forwarding
decisions, rewrites headers and transmits them out of the correct interface.

**Status: phase 3 of 19.** So far: the build system and CI, a zero-allocation packet buffer pool,
bounds-checked, fuzz-tested parsers for Ethernet, ARP and IPv4, and the Internet checksum with the
RFC 1624 incremental update. Nothing forwards packets yet, so no protocol should be assumed to work
end to end.

## Not implemented

- **Stacked VLAN tags.** Exactly one 802.1Q (`0x8100`) or 802.1ad (`0x88a8`) tag is parsed. A
  second tag (QinQ) is not unwrapped: the frame is treated as carrying an unsupported EtherType.
- **IPv4 options.** A header's options are skipped using its length field; none is interpreted.

## Building

Requires Linux (developed on WSL2 Ubuntu 24.04), CMake ≥ 3.20, Ninja, and GCC 13 or Clang 18.

```bash
cmake --preset dev && cmake --build --preset dev -j && ctest --preset dev
```

Other presets: `ci` (warnings as errors), `asan` (AddressSanitizer + UBSan), `tsan`
(ThreadSanitizer), `release` (`-O2 -g`), `bench` (`-O2 -g -march=native`, benchmarks on).
Select the compiler with `CXX`, e.g. `CXX=clang++-18 cmake --preset dev`.

## License

MIT — see [LICENSE](LICENSE).
