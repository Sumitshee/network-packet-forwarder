#!/usr/bin/env bash
# The benchmark harness (docs/BUILD_PLAN.md phase 14; the method is docs/performance.md's).
#
#   ./scripts/run_bench.sh --tier-a                  the microbenchmarks; no root needed
#   sudo ./scripts/run_bench.sh --kernel-baseline    the kernel control alone
#   sudo ./scripts/run_bench.sh --tier-b             npf through the namespaces, every model
#   sudo ./scripts/run_bench.sh --all                all three, into one result
#   ... [--quick]                                    a rehearsal: 2 short repetitions, no
#                                                    bench_lpm; written to bench/results/raw only
#
# Runs the binaries of the bench preset (build/bench; NPF_BENCH_BUILD names another tree). The
# raw output of every tool goes to bench/results/raw/<date>-<sha>/, which is not committed; then
# scripts/bench_combine.py checks it -- no NaN, no zero where a measurement belongs -- and writes
# bench/results/<date>-<sha>.json, the evidence, with the context CLAUDE.md §9 requires.
#
# Tier A: each microbenchmark pinned with taskset (bench_ring's two threads to CPUs on different
# cores), 7 repetitions, aggregates only, started once the one-minute load average is below 0.5.
#
# Tier B: 16 flows of 70-byte frames from ns-client (bench/system/gen, CPU 6) to ns-server
# (bench/system/sink, CPU 7), through ns-router -- the kernel, or npf confined to CPUs 0-5 -- in
# two scenarios: as fast as gen can send, and 20,000 datagrams a second. Each scenario: a 2 s
# warm-up, then 5 repetitions of 10 s, each measured by a fresh sink. Per repetition: datagrams
# sent and received, the latencies, npf's CPU time (from /proc/<pid>/stat) and the whole machine's
# busy time (from /proc/stat) over the window. Per configuration: npf's peak RSS and final
# counters.
#
# The kernel control is the same measurement with npf replaced by the kernel's own forwarding:
# addresses on ns-router's veths, ip_forward on, and arp_ignore back to 0 so that the router's
# kernel answers ARP. It runs in a topology built for it and torn down after, and npf's runs get a
# fresh one, so nothing the control changes can leak into them.
set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BUILD=${NPF_BENCH_BUILD:-$ROOT/build/bench}
NPF="$BUILD/npf"
GEN="$BUILD/bench/system/gen"
SINK="$BUILD/bench/system/sink"
CONFIG="$ROOT/configs/router.conf"

TIER_A=0
TIER_B=0
KERNEL=0
QUICK=0
for arg in "$@"; do
  case "$arg" in
    --tier-a) TIER_A=1 ;;
    --tier-b) TIER_B=1 ;;
    --kernel-baseline) KERNEL=1 ;;
    --all) TIER_A=1 TIER_B=1 KERNEL=1 ;;
    --quick) QUICK=1 ;;
    *)
      sed -n '2,10p' "${BASH_SOURCE[0]}" >&2
      exit 2
      ;;
  esac
done
if ((TIER_A + TIER_B + KERNEL == 0)); then
  sed -n '2,10p' "${BASH_SOURCE[0]}" >&2
  exit 2
fi

REPS=5
SECONDS_PER_REP=10
WARMUP=2
A_REPS=7
A_EXTRA=()
if ((QUICK)); then
  REPS=2
  SECONDS_PER_REP=2
  WARMUP=1
  A_REPS=2
  A_EXTRA=(--benchmark_min_time=0.05s)
fi
FLOWS=16
FRAME=70
LATENCY_RATE=20000
GEN_CPU=6
SINK_CPU=7
NPF_CPUS=0-5
CONFIGS=("rtc 1" "rtc 2" "rtc 4" "pipeline 1" "pipeline 2" "pipeline 4")

# Under sudo, git refuses a repository root does not own unless told it is safe.
SHA=$(git -c safe.directory="$ROOT" -C "$ROOT" rev-parse --short HEAD)
DATE=$(date -u +%F)
RAW="$ROOT/bench/results/raw/$DATE-$SHA"
OUT="$ROOT/bench/results/$DATE-$SHA.json"
NPF_PID=""
SINK_PID=""

log() { echo "run_bench: $*"; }

die() {
  echo "run_bench: $*" >&2
  exit 1
}

cleanup() {
  [[ -n $SINK_PID ]] && kill -KILL "$SINK_PID" 2>/dev/null
  if [[ -n $NPF_PID ]] && kill -0 "$NPF_PID" 2>/dev/null; then
    kill -KILL "$NPF_PID"
  fi
  if ((TIER_B + KERNEL)); then
    "$ROOT/scripts/cleanup_netns.sh" > /dev/null 2>&1
  fi
  # Files written under sudo belong to whoever ran sudo, not to root.
  if [[ -n ${SUDO_UID:-} ]]; then
    chown -R "$SUDO_UID:$SUDO_GID" "$ROOT/bench/results" 2>/dev/null
  fi
}
trap cleanup EXIT

wait_for_idle() { # until the one-minute load average is below 0.5, for at most 5 minutes
  local load
  for _ in $(seq 60); do
    load=$(cut -d' ' -f1 /proc/loadavg)
    awk -v l="$load" 'BEGIN { exit !(l < 0.5) }' && break
    sleep 5
  done
  cut -d' ' -f1 /proc/loadavg
}

# --- tier A --------------------------------------------------------------------------------------

tier_a() {
  local benches=(bench_checksum bench_pool bench_ring bench_datapath bench_lpm) b cpus
  ((QUICK)) && benches=(bench_checksum bench_pool bench_ring bench_datapath)
  mkdir -p "$RAW/tier_a"
  for b in "${benches[@]}"; do
    [[ -x $BUILD/bench/$b ]] || die "no $BUILD/bench/$b: cmake --preset bench && cmake --build --preset bench -j"
  done
  for b in "${benches[@]}"; do
    # One CPU, or for the ring's two threads two CPUs on different cores (lscpu -e: CPUs 2 and 4).
    cpus=2
    [[ $b == bench_ring ]] && cpus=2,4
    log "tier A: $b on CPUs $cpus, load average $(wait_for_idle)"
    (cd "$ROOT" && taskset -c "$cpus" "$BUILD/bench/$b" \
      --benchmark_repetitions="$A_REPS" --benchmark_report_aggregates_only=true \
      --benchmark_min_warmup_time=0.5 "${A_EXTRA[@]}" \
      --benchmark_out="$RAW/tier_a/$b.json" --benchmark_out_format=json \
      --benchmark_context="git_sha=$SHA,pinned_cpus=${cpus//,/+}") > "$RAW/tier_a/$b.txt" 2>&1 ||
      die "$b failed: see $RAW/tier_a/$b.txt"
  done
}

# --- tier B --------------------------------------------------------------------------------------

proc_cpu() { # the "cpu" line of /proc/stat: user nice system idle iowait irq softirq steal
  awk '$1 == "cpu" { print $2, $3, $4, $5, $6, $7, $8, $9 }' /proc/stat
}

proc_ticks() { # utime + stime of a process, in clock ticks
  awk '{ print $14 + $15 }' "/proc/$1/stat" 2>/dev/null || echo 0
}

start_sink() { # start_sink <output file>
  ip netns exec ns-server taskset -c "$SINK_CPU" "$SINK" --json > "$1" 2>&1 &
  SINK_PID=$!
  for _ in $(seq 50); do
    ip netns exec ns-server ss -Hlun 'sport = :5001' | grep -q . && return 0
    sleep 0.1
  done
  die "sink did not start: $(cat "$1")"
}

stop_sink() {
  sleep 0.5  # the last datagrams through the router
  kill -TERM "$SINK_PID"
  wait "$SINK_PID"
  SINK_PID=""
}

gen() { # gen <duration> <rate or 0> <output file>
  local rate=()
  [[ $2 != 0 ]] && rate=(--rate "$2")
  ip netns exec ns-client taskset -c "$GEN_CPU" "$GEN" --dst 10.0.2.2 --flows "$FLOWS" \
    --size "$FRAME" --duration "$1" "${rate[@]}" --json > "$3" 2>&1 ||
    die "gen failed: $(cat "$3")"
}

# One scenario of one configuration: a warm-up, then the measured repetitions.
scenario() { # scenario <dir> <name> <rate or 0>
  local dir="$1/$2" rep cpu0 cpu1 t0 t1 n0 n1 clk
  clk=$(getconf CLK_TCK)
  mkdir -p "$dir"
  start_sink "$dir/warmup.sink.json"
  gen "$WARMUP" "$3" "$dir/warmup.gen.json"
  stop_sink
  for rep in $(seq "$REPS"); do
    start_sink "$dir/$rep.sink.json"
    cpu0=$(proc_cpu)
    n0=$([[ -n $NPF_PID ]] && proc_ticks "$NPF_PID" || echo 0)
    t0=$(date +%s.%N)
    gen "$SECONDS_PER_REP" "$3" "$dir/$rep.gen.json"
    t1=$(date +%s.%N)
    n1=$([[ -n $NPF_PID ]] && proc_ticks "$NPF_PID" || echo 0)
    cpu1=$(proc_cpu)
    stop_sink
    python3 - "$cpu0" "$cpu1" "$t0" "$t1" "$n0" "$n1" "$clk" "$(nproc)" "${NPF_PID:+npf}" \
      > "$dir/$rep.cpu.json" <<'PY'
import json, sys
c0, c1 = [list(map(int, a.split())) for a in sys.argv[1:3]]
t0, t1 = float(sys.argv[3]), float(sys.argv[4])
n0, n1, clk, cpus = int(sys.argv[5]), int(sys.argv[6]), int(sys.argv[7]), int(sys.argv[8])
d = [b - a for a, b in zip(c0, c1)]
idle = d[3] + d[4]
out = {"window_s": t1 - t0, "system_busy_pct": 100.0 * (sum(d) - idle) / sum(d), "cpus": cpus}
if len(sys.argv) > 9 and sys.argv[9] == "npf":
    out["npf_cpu_pct"] = 100.0 * (n1 - n0) / clk / (t1 - t0)
print(json.dumps(out))
PY
    log "  $2 repetition $rep: $(cat "$dir/$rep.gen.json")"
  done
}

measure() { # measure <dir>: both scenarios
  scenario "$1" throughput 0
  scenario "$1" latency "$LATENCY_RATE"
}

fresh_topology() {
  "$ROOT/scripts/cleanup_netns.sh" > /dev/null 2>&1
  "$ROOT/scripts/setup_netns.sh" || die "scripts/setup_netns.sh failed"
}

kernel_baseline() {
  local dir="$RAW/tier_b/kernel"
  mkdir -p "$dir"
  log "tier B: the kernel control"
  fresh_topology
  ip netns exec ns-router ip addr add 10.0.1.1/24 dev veth-cr
  ip netns exec ns-router ip addr add 10.0.2.1/24 dev veth-sr
  ip netns exec ns-router sysctl -qw net.ipv4.ip_forward=1
  ip netns exec ns-router sysctl -qw net.ipv4.conf.all.arp_ignore=0
  ip netns exec ns-client ping -c 2 -W 1 10.0.2.2 > /dev/null || die "the kernel control does not forward"
  echo '{"config": "kernel", "mode": null, "workers": null}' > "$dir/meta.json"
  measure "$dir"
  # Every change undone, by building the topology again from nothing.
  fresh_topology
}

npf_config() { # npf_config <mode> <workers>
  local dir="$RAW/tier_b/npf-$1-$2" log
  mkdir -p "$dir"
  log="$dir/npf.log"
  log "tier B: npf, mode $1, $2 workers"
  ip netns exec ns-router taskset -c "$NPF_CPUS" "$NPF" run --config "$CONFIG" --mode "$1" \
    --workers "$2" --pidfile "$dir/npf.pid" --stats-file "$dir/npf.stats" > "$log" 2>&1 &
  NPF_PID=$!
  for _ in $(seq 100); do
    grep -qs 'forwarding on' "$log" && break
    kill -0 "$NPF_PID" 2>/dev/null || break
    sleep 0.1
  done
  grep -q 'forwarding on' "$log" || die "npf did not start: $(cat "$log")"
  ip netns exec ns-client ping -c 2 -W 1 10.0.2.2 > /dev/null || die "npf does not forward"
  measure "$dir"
  local hwm
  hwm=$(awk '/^VmHWM:/ { print $2 }' "/proc/$NPF_PID/status")
  kill -TERM "$NPF_PID"
  wait "$NPF_PID"
  NPF_PID=""
  python3 -c 'import json, sys; print(json.dumps({"config": "npf", "mode": sys.argv[1], "workers": int(sys.argv[2]), "npf_peak_rss_kib": int(sys.argv[3])}))' \
    "$1" "$2" "$hwm" > "$dir/meta.json"
}

tier_b() {
  local c
  log "tier B: load average $(wait_for_idle)"
  fresh_topology
  for c in "${CONFIGS[@]}"; do
    # shellcheck disable=SC2086
    npf_config $c
  done
}

# --- main ----------------------------------------------------------------------------------------

if ((TIER_B + KERNEL)) && [[ $(id -u) -ne 0 ]]; then
  die "tier B needs root, for the network namespaces: sudo $0 $*"
fi
if ((TIER_B + KERNEL)); then
  for f in "$NPF" "$GEN" "$SINK"; do
    [[ -x $f ]] || die "no $f: cmake --preset bench && cmake --build --preset bench -j"
  done
fi
rm -rf "$RAW"
mkdir -p "$RAW"
log "raw results in $RAW"
((TIER_A)) && tier_a
if ((TIER_B + KERNEL)); then
  mkdir -p "$RAW/tier_b"
  printf '{"flows": %d, "frame_bytes": %d, "latency_scenario_rate": %d, "repetitions": %d, ' \
    "$FLOWS" "$FRAME" "$LATENCY_RATE" "$REPS" > "$RAW/tier_b/method.json"
  printf '"seconds_per_repetition": %d, "warmup_s": %d, ' "$SECONDS_PER_REP" "$WARMUP" \
    >> "$RAW/tier_b/method.json"
  printf '"cpus": {"gen": %d, "sink": %d, "npf": "%s"}}\n' "$GEN_CPU" "$SINK_CPU" "$NPF_CPUS" \
    >> "$RAW/tier_b/method.json"
fi
((KERNEL)) && kernel_baseline
((TIER_B)) && tier_b

if ((QUICK)); then
  python3 "$ROOT/scripts/bench_combine.py" "$RAW" --build "$BUILD" --quick \
    --out "$RAW/combined.json" || die "the results did not pass their checks"
  log "a rehearsal: $RAW/combined.json, not for bench/results"
else
  python3 "$ROOT/scripts/bench_combine.py" "$RAW" --build "$BUILD" --out "$OUT" ||
    die "the results did not pass their checks"
  log "wrote $OUT"
fi
