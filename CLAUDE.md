# network-packet-forwarder — project constitution

Read this file at the start of every session. It overrides your defaults.
Implementation work is driven by `docs/BUILD_PLAN.md` (what to build, in what order).
Type and interface contracts live in `docs/ARCHITECTURE.md` and **must not drift** between phases.

---

## 1. What this is

A userspace Layer-2/Layer-3 packet forwarding engine — a software router — written in C++20 on
Linux. It receives raw Ethernet frames from network interfaces, parses them, makes forwarding
decisions, rewrites headers, and transmits them out the correct interface. It is a portfolio
project whose purpose is to demonstrate systems programming, networking, concurrency, data
structures and performance engineering to interviewers at semiconductor and networking companies.

**Naming.** The repository is `network-packet-forwarder`. Everything inside it uses the
abbreviation `npf`:

| Thing | Value |
|---|---|
| Repository / GitHub name | `network-packet-forwarder` |
| Root namespace | `npf` (nested: `npf::core`, `npf::proto`, `npf::table`, `npf::io`, `npf::pipe`, `npf::stat`) |
| Include prefix | `#include <npf/proto/ipv4.hpp>` |
| Binary | `npf` |
| CMake project | `project(network-packet-forwarder ...)`, targets `npf_core`, `npf_proto`, … |

Never rename these. Never introduce a second spelling.

---

## 2. Non-negotiable rules

These are the rules that make the project worth building. Violating one silently is worse than
not finishing a phase.

1. **Never fabricate a benchmark number.** Not a placeholder, not an estimate, not "approximately".
   If a number is not the output of a run that actually happened on this machine, it does not go in
   a document, a commit message, a comment or a README. Write `TBD` and leave it.
2. **Never claim a protocol or feature is supported unless it is implemented and tested.**
   The README carries an explicit "Not implemented" list. Keep it accurate and keep it honest.
3. **Never parse a packet without bounds checking.** No `reinterpret_cast` of a buffer pointer to a
   packed header struct. See §5.
4. **No allocation on the datapath.** Not `new`, not `malloc`, not `std::vector::push_back`, not
   `std::string`, not `std::function`, not `shared_ptr`. Buffers come from a pre-allocated pool.
   This is enforced by a test — see `tests/support/alloc_counter.hpp`.
5. **No exceptions on the datapath.** Every hot-path function is `noexcept` and returns a value
   (`std::optional`, an enum, a bool). Exceptions are permitted only in start-up code:
   configuration parsing, socket setup, pool construction.
6. **Optimize only after a baseline exists.** No performance change lands without a before number
   and an after number from the same harness on the same machine.
7. **Every phase ends with a green exit test.** The exit test in `docs/BUILD_PLAN.md` is the
   definition of done. "It compiles" is not an exit test.
8. **Do not build ahead.** Each phase has a "Do not build yet" fence. Respect it — building phase
   N+3's abstraction during phase N is how this project dies.

---

## 3. Build and test

```bash
# configure (presets live in CMakePresets.json)
cmake --preset dev          # RelWithDebInfo, warnings on, tests on
cmake --preset asan         # ASan + UBSan
cmake --preset tsan         # ThreadSanitizer
cmake --preset release      # -O2 -g, LTO optional
cmake --preset bench        # -O2 -g -march=native, benchmarks on

cmake --build --preset dev -j
ctest --preset dev --output-on-failure

# formatting and lint
clang-format --dry-run --Werror $(git ls-files '*.hpp' '*.cpp')
clang-tidy -p build/dev $(git ls-files 'src/*.cpp')

# the network topology (needs root)
sudo ./scripts/setup_netns.sh
sudo ./scripts/cleanup_netns.sh
```

**Environment: WSL2 Ubuntu.** Network namespaces, veth, AF_PACKET and PACKET_MMAP all work.
Hardware performance counters may or may not — check once with
`perf stat -e cycles,instructions /bin/true` and record the answer in `docs/performance.md`.
If they are unavailable, use `__rdtsc()` for cycle proxies, `valgrind --tool=cachegrind` for
cache behaviour, and `perf record -e cpu-clock` for flamegraphs. Do not pretend a counter worked.

Root is required for AF_PACKET and for namespace manipulation. Either run under `sudo` or grant
the binary `sudo setcap cap_net_raw,cap_net_admin+ep build/dev/npf`.

---

## 4. Repository layout

```
network-packet-forwarder/
├─ CMakeLists.txt  CMakePresets.json  CLAUDE.md  README.md  LICENSE
├─ cmake/          CompilerWarnings.cmake  Sanitizers.cmake  Dependencies.cmake
├─ include/npf/
│  ├─ core/        byte_span.hpp  packet.hpp  pool.hpp  ring.hpp  config.hpp  log.hpp  time.hpp
│  ├─ proto/       mac.hpp  ethernet.hpp  arp.hpp  ipv4.hpp  icmp.hpp  l4.hpp  checksum.hpp
│  ├─ table/       fib.hpp  lpm_linear.hpp  lpm_trie.hpp  lpm_patricia.hpp  lpm_dir24_8.hpp
│  │               arp_cache.hpp  mac_table.hpp
│  ├─ io/          backend.hpp  af_packet.hpp  packet_mmap.hpp  af_xdp.hpp  pcap_file.hpp
│  ├─ pipe/        forward.hpp  filter.hpp  icmp_gen.hpp  worker.hpp
│  └─ stat/        counters.hpp
├─ src/            mirrors include/npf/ (header-only modules have no .cpp)  +  main.cpp
├─ tests/          unit/  integration/  fuzz/  fixtures/  support/
├─ bench/          micro/  system/  results/  plot.py
├─ scripts/        setup_netns.sh  cleanup_netns.sh  run_bench.sh  fetch_bgp_table.sh
├─ configs/        router.conf  filter.conf
├─ tools/skeleton/ the throwaway phase-0.5 prototype — never link it into anything
└─ docs/           BUILD_PLAN.md  ARCHITECTURE.md  packet-flow.md  performance.md
                   design-decisions.md  rfc1812-conformance.md
```

Protocol parsers are **header-only** so they inline into the datapath. Everything else compiles
into a library target. Do not create a directory per protocol; `proto/` holds them all.

---

## 5. How to parse a packet

This is the single most scrutinised part of the codebase. The pattern is a **view type** that can
only be created through a validating factory:

```cpp
class Ipv4View {
 public:
  // The only constructor. Returns nullopt if the span is too short or the header is invalid.
  [[nodiscard]] static std::optional<Ipv4View> parse(std::span<const std::byte> buf) noexcept;
  [[nodiscard]] std::uint32_t src() const noexcept;
  // ...
 private:
  explicit Ipv4View(std::span<const std::byte> buf, std::uint8_t hdr_len) noexcept;
  std::span<const std::byte> buf_;
  std::uint8_t hdr_len_;
};
```

Rules:

- **Read fields byte-by-byte**, then combine. Do not cast the buffer to a struct — packet buffers
  are not guaranteed to be aligned for `uint32_t`, and type-punning through a struct pointer is
  undefined behaviour under strict aliasing:

  ```cpp
  // correct
  [[nodiscard]] constexpr std::uint16_t rd_be16(std::span<const std::byte> b, std::size_t off) noexcept {
    return static_cast<std::uint16_t>(std::to_integer<std::uint16_t>(b[off]) << 8 |
                                      std::to_integer<std::uint16_t>(b[off + 1]));
  }
  // wrong — alignment and aliasing UB, and it hides the missing length check
  auto* h = reinterpret_cast<const iphdr*>(buf.data());
  ```
  A good compiler folds `rd_be16` into a single `movbe`/`ldrh`+`rev16`. Verify this once on
  godbolt and note it in `docs/design-decisions.md`; do not assume it.
- **Check length before every read.** The factory validates the whole header once; accessors may
  then read within the validated region without re-checking.
- **Never hardcode a header size that is variable.** IPv4 header length is `ihl * 4`, not 20.
  TCP data offset is `doff * 4`, not 20.
- **Every accessor is `[[nodiscard]] const noexcept`**, and `constexpr` where it can be.
- **Host byte order at the boundary.** Views return host order. The wire is big-endian. Convert
  once, in the accessor, using `std::byteswap` (C++23) or `__builtin_bswap*` behind a small helper
  in `core/byte_span.hpp` — the project targets C++20, so do not use `std::byteswap` directly.

---

## 6. C++ style

- **C++20.** `std::span`, `std::optional`, `std::bit_cast`, concepts, designated initialisers,
  `[[likely]]`/`[[unlikely]]`, `<bit>`. No compiler extensions (`CXX_EXTENSIONS OFF`).
- `#pragma once` in every header.
- Types `PascalCase`, functions and variables `snake_case`, members `trailing_`, constants
  `kCamelCase`, macros only where genuinely unavoidable.
- `const` everywhere it applies. `[[nodiscard]]` on every function that returns a value the caller
  must act on. `explicit` on every single-argument constructor.
- RAII for every OS resource — file descriptors, mmap regions, threads. Write a small
  `core/unique_fd.hpp` rather than a bare `int fd`.
- Smart pointers for ownership at start-up. **Raw pointers on the datapath**, with the owner
  documented in a comment. `Packet*` is always borrowed from a pool; never `delete` one.
- No global mutable state. No singletons. Dependencies are passed in by reference at construction.
- Prefer free functions over classes when there is no state.
- Comments explain *why*, never *what*. Do not narrate the code.

Warnings, all treated as errors in CI:
```
-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
-Wcast-align -Wold-style-cast -Wnon-virtual-dtor -Wnull-dereference
-Wdouble-promotion -Wformat=2 -Wimplicit-fallthrough
```

---

## 7. Testing

- **GoogleTest** for unit and integration tests, **Google Benchmark** for microbenchmarks. Both
  pinned by version via `FetchContent`.
- Every parser gets a **truncation sweep**: for a known-good frame of length `L`, calling
  `parse()` on every prefix length `0..L-1` must return `nullopt` where the header is incomplete
  and must never read out of bounds. ASan proves the second half.
- Every parser gets a **libFuzzer harness** in `tests/fuzz/`, run for 60 s in CI with a seed corpus
  built from the fixture pcaps.
- Every optimised data structure is **property-tested against a deliberately simple reference
  implementation**, not against hand-written expectations. The reference is the oracle and is
  never optimised.
- Integration tests that need root live in `tests/integration/*.sh` and are skipped (not failed)
  when not root. Integration tests that do **not** need root use pcap replay and always run in CI.
- Sanitizer builds are part of CI, not an afterthought: ASan+UBSan on the whole suite, TSan on the
  concurrency tests.

---

## 8. Datapath invariants

Anything reachable from `Forwarder::process()` or a worker loop:

- `noexcept`, no allocation, no locks, no syscalls except the batched RX/TX calls.
- Works on **batches** of up to 64 packets. The `IoBackend` virtual call happens once per batch,
  never once per packet.
- Per-thread counters, `alignas(64)`. Never a shared counter without padding.
- Every drop increments exactly one `DropReason` counter. A packet that leaves the pipeline without
  being forwarded or counted is a bug; assert this in debug builds.
- Every `Packet*` acquired from a pool is either transmitted or released. Leaking one is a bug the
  pool's `available()` count will catch — assert the count returns to baseline in tests.

---

## 9. Benchmarking rules

- **Two tiers, always reported separately.** Tier A is in-process with no I/O and measures the
  forwarding logic (ns/packet). Tier B is end-to-end through namespaces and measures the whole
  pipeline (pps, latency, loss). Never present a tier-B number as evidence about code quality.
- **Always run the kernel control.** `net.ipv4.ip_forward=1` on the same topology is the
  denominator that makes tier B meaningful.
- Warm up, then ≥ 5 repetitions. Report **median and p95**, never the mean alone, and always
  report the spread.
- Every result JSON records: git SHA, date, `uname -r`, CPU model, compiler and version, CMake
  preset and flags, thread count, whether PMU counters were available.
- A change whose measured delta falls inside the noise band **is reverted**, and the negative
  result is written down in `docs/performance.md`. Negative results are part of the deliverable.

---

## 10. Git

- One logical change per commit. The history is read by interviewers as evidence the project was
  built incrementally — make it tell that story.
- Conventional-ish subject lines: `phase(N): <what>`, e.g. `phase(3): add RFC 1624 incremental
  checksum update`.
- Tag the end of each phase: `git tag phase-03`.
- Never commit: `bench/results/` raw MRT dumps, `data/bgp_prefixes.txt` (check in the fetch script
  instead), build directories, `.pcap` files over 1 MB.
- Commit `bench/results/*.json` — they are the evidence.

---

## 11. Never do

- Never add a dependency that is not: GoogleTest, Google Benchmark, libbpf/libxdp (phase 17 only).
  No Boost, no fmt, no yaml-cpp, no libpcap — the pcap file format is 24 + 16 bytes of header and
  is written by hand in phase 9.
- Never turn this into a web application, a GUI, or an HTTP service. There is no metrics endpoint.
  Statistics are exposed via periodic console output and a `SIGUSR1` dump.
- Never implement TCP. Parse its header, expose the fields, stop there.
- Never copy code from DPDK, VPP, the Linux kernel, or any other project. Read them for ideas,
  cite them in `docs/design-decisions.md`, write your own.
- Never use `std::unordered_map`, `std::map`, `std::function` or `std::string` on the datapath.
- Never leave a `TODO` without a phase number: `// TODO(phase-11): honour in_port in filter rules`.
- Never write a resume bullet, a README performance claim, or a percentage into any file before
  the measurement that supports it exists in `bench/results/`.
