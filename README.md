# network-packet-forwarder

A userspace Layer-2/Layer-3 packet forwarding engine — a software router — written in C++20 for
Linux. It receives raw Ethernet frames from network interfaces, parses them, makes forwarding
decisions, rewrites headers and transmits them out of the correct interface.

**Status: phase 0 of 19.** The build system, sanitizer configurations and CI exist. There is no
forwarding code yet, so nothing is supported and nothing should be assumed to work.

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
