# Performance

Every number in this file is the output of a run on the machine described below; the JSON each
table came from is in `bench/results/`. Nothing here is estimated or rounded up. What a set of
numbers does *not* measure is stated next to it. The full methodology (the two tiers, the kernel
control, the repetition rules) arrives with the benchmark harness in phase 14.

## Environment

Recorded 2026-09-30.

| | |
|---|---|
| CPU | 11th Gen Intel Core i5-1135G7 @ 2.40 GHz, 4 cores / 8 threads |
| Caches (as reported by Google Benchmark) | L1d 48 KiB ×4, L1i 32 KiB ×4, L2 1280 KiB ×4, L3 8192 KiB |
| Host | Windows 11 laptop on mains power, power plan "Balanced" |
| Guest | WSL2, kernel `6.6.87.2-microsoft-standard-WSL2`, Ubuntu 24.04 |
| Compiler | GCC 13.3.0 |

### Hardware performance counters: available

`CLAUDE.md` §3 asks for this to be checked once and recorded. The `perf` tool is not installed:
Ubuntu's `linux-tools` packages are built for Ubuntu kernels, not the WSL kernel. The check used the
system call `perf` itself uses instead: `perf_event_open` with `PERF_TYPE_HARDWARE`, counting user
space only (`exclude_kernel = 1`), which `kernel.perf_event_paranoid = 2` allows without privileges.

Over a 10,000,000-iteration loop it counted **60,000,036 instructions** and 51,169,370 cycles. The
kernel also lists `branch-instructions`, `branch-misses`, `bus-cycles`, `cache-misses`,
`cache-references`, `cpu-cycles`, `instructions` and `ref-cycles` under
`/sys/bus/event_source/devices/cpu/events`. Counting kernel-mode events, and the `perf` tool itself,
were not tried.

## Phase 3: checksum microbenchmark (tier A)

**What.** `bench/micro/bench_checksum.cpp` times the three checksum paths in
`include/npf/proto/checksum.hpp`, in process, with no I/O:

- `BM_ChecksumReference/N` and `BM_OnesComplementSum/N`: the one's complement sum of N random bytes.
  20 and 60 are the smallest and largest IPv4 headers; 1500 is an MTU-sized buffer, the scale of an
  L4 checksum.
- `BM_ChecksumUpdate16`: one RFC 1624 incremental update per call, with the operands cycling
  through a 1024-entry table so that none of them is a compile-time constant.

**Code measured:** commit `906c1f3`, built from a clean tree with the `bench` preset (GCC 13.3.0,
`-O2 -g -DNDEBUG -std=c++20 -march=native`, plus the project's warning flags; the exact command is
in `build/bench/compile_commands.json`).

**How.** Pinned to one CPU. Each benchmark runs 0.5 s of warm-up, then 20 repetitions of at least
0.5 s each. Times are wall-clock per call. The matching CPU times, also in the JSON, are at most
2.9% lower in any cell of the tables below.

```bash
cmake --preset bench && cmake --build --preset bench -j
taskset -c 2 build/bench/bench/bench_checksum \
  --benchmark_repetitions=20 --benchmark_min_warmup_time=0.5 \
  --benchmark_report_aggregates_only=false --benchmark_display_aggregates_only=true \
  --benchmark_out=bench/results/<date>-<sha>-bench_checksum.json --benchmark_out_format=json \
  --benchmark_context="git_sha=<sha>,uname_r=$(uname -r),cpu_model=<model>,pmu_counters=available,cmake_preset=bench,threads=1,pinned_cpu=2"
```

### Results: run 2, started on an idle machine

`bench/results/2026-09-30-906c1f3-bench_checksum-run2.json`. Load average at the start: 0.29.

| Benchmark | Median | p95 | Min – max | CV |
|---|---:|---:|---:|---:|
| `BM_ChecksumReference/20` | 11.9 ns | 13.2 ns | 11.7 – 13.5 ns | 4.3% |
| `BM_ChecksumReference/60` | 41.3 ns | 43.3 ns | 40.5 – 45.2 ns | 2.7% |
| `BM_ChecksumReference/1500` | 917 ns | 928 ns | 901 – 931 ns | 0.9% |
| `BM_OnesComplementSum/20` | 6.16 ns | 6.78 ns | 6.01 – 6.79 ns | 4.1% |
| `BM_OnesComplementSum/60` | 19.3 ns | 20.3 ns | 19.1 – 20.6 ns | 2.2% |
| `BM_OnesComplementSum/1500` | 410 ns | 474 ns | 392 – 479 ns | 5.8% |
| `BM_ChecksumUpdate16` | 1.52 ns | 2.07 ns | 1.45 – 2.43 ns | 16.1% |

p95 is the nearest-rank 95th percentile of the 20 repetitions (the 19th fastest). CV is the standard
deviation over the mean.

### Results: run 1, started straight after a parallel build

`bench/results/2026-09-30-906c1f3-bench_checksum.json`. Same binary, same flags. Load average at
the start: 2.86. The measurement script had just rebuilt the benchmark on every core.

| Benchmark | Median | p95 | Min – max | CV |
|---|---:|---:|---:|---:|
| `BM_ChecksumReference/20` | 20.4 ns | 21.2 ns | 11.8 – 22.7 ns | 24.0% |
| `BM_ChecksumReference/60` | 52.3 ns | 55.5 ns | 40.7 – 56.2 ns | 9.3% |
| `BM_ChecksumReference/1500` | 1055 ns | 1189 ns | 987 – 1203 ns | 5.7% |
| `BM_OnesComplementSum/20` | 7.24 ns | 8.01 ns | 6.66 – 8.25 ns | 5.8% |
| `BM_OnesComplementSum/60` | 20.0 ns | 21.7 ns | 18.7 – 24.0 ns | 5.5% |
| `BM_OnesComplementSum/1500` | 423 ns | 460 ns | 396 – 473 ns | 4.6% |
| `BM_ChecksumUpdate16` | 1.47 ns | 1.52 ns | 1.45 – 1.57 ns | 1.9% |

### Why run 2 is the one quoted

In run 1 the same code ran at two distinct speeds, switching partway through a benchmark, in
either direction. In order of repetition, `BM_ChecksumReference/20` took 20.2 to 22.7 ns for its
first twelve repetitions, then 17.0 and 14.6 ns, then 11.8 ns for the last six. Straight after it,
`BM_ChecksumReference/60` went the other way: 40.7 to 41.1 ns for three repetitions, then 49.9 to
56.2 ns for the remaining seventeen. The code and its input did not change between repetitions, so
the machine did.

Taking each group's median, `BM_ChecksumReference/20`'s two levels (20.7 and 11.8 ns) are about
1.75× apart: the ratio of this CPU's base and maximum turbo clocks, 2.4 and 4.2 GHz.
`BM_ChecksumReference/60`'s (52.6 and 40.9 ns) are only about 1.3× apart. A clock changing speed,
by different amounts at different moments, would explain both, plausibly because the build that
ran just before had used up the package's power budget. That cause is a hypothesis, not something
measured from inside the VM.

Run 2 used the same binary but waited for the one-minute load average to fall below 0.3 before
starting. Its sums stayed at the fast level throughout (`BM_ChecksumReference/20`: 11.7 to
13.5 ns). It was not free of variation either: `BM_ChecksumUpdate16` had slow repetitions at the
start (1.98 ns) and at the end (2.07, 2.43, 1.91 ns), hence its 16.1% CV against run 1's 1.9%. The
two runs' medians for it still differ by only 0.06 ns.

Run 1's file is kept because it is a real run.

**Consequence for every later measurement.** Wall-clock time on this machine is only as steady as
the CPU clock, which Windows controls. So: build first, wait for the machine to go quiet, then
measure, and compare runs taken the same way.

### What these numbers do not measure

- **The forwarding path.** This is tier A in isolation. Each loop reads the same buffer, which sits
  in L1 cache the whole time, so no cache miss is ever timed. The cost of an incremental update
  inside the real pipeline is phase 15's `BM_FullDatapath`, not this.
- **A fixed clock.** WSL2 on a laptop: the CPU's frequency follows turbo and the Windows power
  plan. The JSON's `cpu_scaling_enabled: false` only means the VM has no cpufreq interface to read.
- **Generated code.** With `-march=native` the compiler is free to vectorise both sums; the
  assembly was not inspected, so nothing here says whether it did.
- **Anything but this machine and this compiler.** One CPU, GCC 13.3.0 only.

## Candidates

Ideas noted for later phases, not done.

- **Count cycles, not only wall time** (phase 14). The hardware counters work here, see above.
  Reporting cycles per call next to nanoseconds would remove clock-speed swings like run 1's from
  comparisons of code.
