#!/usr/bin/env bash
# Phase 16 exit test, step 4 (docs/BUILD_PLAN.md): the PACKET_MMAP backend under sustained load
# keeps forwarding -- no ring stalls.
#
#   sudo tests/integration/test_mmap_soak.sh build/dev/npf [seconds] [mode] [workers]
#
# [phase 17] NPF_SOAK_IO_ARGS soaks another backend: "--io xdp --xdp-mode native", say. The
# default is "--io mmap".
#
# Runs `npf run --io mmap` on configs/router.conf in ns-router (by default rtc, one worker), sends
# 16 flows of UDP from ns-client through it as fast as bench/system/gen can for 60 s, and reads
# `npf show stats` every 5 s. A ring that stalls -- an RX block never handed back to the kernel, or
# TX slots never sent -- shows as an interval in which nothing is received or nothing is forwarded.
# The run fails if any interval's rx_packets or forwarded is 0, or less than half the median
# interval's; and, at the end, unless npf exits with status 0, its counters balance and every
# buffer is back in its pool.
#
# Not root: exit status 77, which CTest reports as skipped.
set -uo pipefail

if [[ $(id -u) -ne 0 ]]; then
  echo "SKIP: needs root, for network namespaces and AF_PACKET"
  exit 77
fi
NPF=$(realpath "${1:?usage: $0 <path to the npf binary> [seconds] [mode] [workers]}")
DURATION=${2:-60}
MODE=${3:-rtc}
WORKERS=${4:-1}
INTERVAL=5
GEN="$(dirname "$NPF")/bench/system/gen"
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
WORK=$(mktemp -d)
NPF_PID=""
GEN_PID=""
DROPS=(ShortFrame BadEtherType BadIpv4Header BadChecksum MartianSource TtlExpired
  NoRoute ArpUnresolved FilterDeny NoOutPort UnknownDestPort SamePort RingFull TxFull PoolExhausted)
failures=0

pass() { echo "PASS  $*"; }
fail() {
  echo "FAIL  $*"
  failures=$((failures + 1))
}

cleanup() {
  [[ -n $GEN_PID ]] && kill -KILL "$GEN_PID" 2>/dev/null
  if [[ -n $NPF_PID ]] && kill -0 "$NPF_PID" 2>/dev/null; then
    kill -KILL "$NPF_PID"
  fi
  "$ROOT/scripts/cleanup_netns.sh"
  rm -rf "$WORK"
}
trap cleanup EXIT

if [[ ! -x $GEN ]]; then
  echo "FAIL  no load generator at $GEN: build the preset first"
  exit 1
fi
"$ROOT/scripts/cleanup_netns.sh"
if ! "$ROOT/scripts/setup_netns.sh"; then
  echo "FAIL  scripts/setup_netns.sh"
  exit 1
fi

LOG="$WORK/npf.log"
read -ra IO_ARGS <<< "${NPF_SOAK_IO_ARGS:---io mmap}"
echo "\$ ip netns exec ns-router npf run ${IO_ARGS[*]} --config configs/router.conf --mode $MODE --workers $WORKERS &"
ip netns exec ns-router "$NPF" run "${IO_ARGS[@]}" --config "$ROOT/configs/router.conf" --mode "$MODE" \
  --workers "$WORKERS" --pidfile "$WORK/npf.pid" --stats-file "$WORK/npf.stats" > "$LOG" 2>&1 &
NPF_PID=$!
for _ in $(seq 100); do
  grep -q 'forwarding on' "$LOG" && break
  kill -0 "$NPF_PID" 2>/dev/null || break
  sleep 0.1
done
if ! grep -q 'forwarding on' "$LOG"; then
  echo "FAIL  npf run did not start"
  sed 's/^/    /' "$LOG"
  exit 1
fi
sed 's/^/    /' "$LOG"
ip netns exec ns-client ping -c 1 -W 2 10.0.2.2 > /dev/null

stat_of() { # stat_of <name>: from a fresh `npf show stats`
  "$NPF" show stats --pidfile "$WORK/npf.pid" --stats-file "$WORK/npf.stats" 2>/dev/null |
    awk -v k="$1" '$1 == k { print $2 }'
}

ip netns exec ns-client "$GEN" --dst 10.0.2.2 --flows 16 --duration "$DURATION" \
  > "$WORK/gen.log" 2>&1 &
GEN_PID=$!
rx_deltas=()
fwd_deltas=()
last_rx=$(stat_of rx_packets)
last_fwd=$(stat_of forwarded)
echo
printf '    %8s %14s %14s\n' "t (s)" "rx_packets" "forwarded"
for ((t = INTERVAL; t <= DURATION; t += INTERVAL)); do
  sleep "$INTERVAL"
  rx=$(stat_of rx_packets)
  fwd=$(stat_of forwarded)
  if [[ -z $rx || -z $fwd ]]; then
    fail "npf show stats gave no counters at $t s"
    break
  fi
  rx_deltas+=($((rx - last_rx)))
  fwd_deltas+=($((fwd - last_fwd)))
  printf '    %8d %14d %14d\n' "$t" "$((rx - last_rx))" "$((fwd - last_fwd))"
  last_rx=$rx
  last_fwd=$fwd
done
wait "$GEN_PID"
GEN_PID=""
sed 's/^/    /' "$WORK/gen.log"

median() { printf '%s\n' "$@" | sort -n | awk '{ v[NR] = $1 } END { print v[int((NR + 1) / 2)] }'; }

check_intervals() { # check_intervals <name> <delta>...
  local name=$1 med low=0 d
  shift
  med=$(median "$@")
  for d in "$@"; do
    if ((d == 0 || 2 * d < med)); then
      low=$((low + 1))
    fi
  done
  if [[ $# -gt 0 && $med -gt 0 && $low -eq 0 ]]; then
    pass "$name: every one of $# intervals of ${INTERVAL} s at least half the median ($med); none 0"
  else
    fail "$name: $low of $# intervals of ${INTERVAL} s were 0 or under half the median (${med:-none})"
  fi
}
echo
check_intervals rx_packets "${rx_deltas[@]}"
check_intervals forwarded "${fwd_deltas[@]}"

kill -TERM "$NPF_PID"
wait "$NPF_PID"
status=$?
NPF_PID=""
if [[ $status -eq 0 ]]; then
  pass "npf exited with status 0"
else
  fail "npf exited with status $status"
fi

counter() { sed -n '/final counters/,$p' "$LOG" | awk -v k="$1" '$1 == k { print $2 }'; }
rx=$(counter rx_packets)
fwd=$(counter forwarded)
flood=$(counter flooded)
host=$(counter to_host)
drops=0
for d in "${DROPS[@]}"; do
  n=$(counter "$d")
  drops=$((drops + ${n:-0}))
done
if [[ -n $rx && $rx -gt 0 && $rx -eq $((fwd + flood + host + drops)) ]]; then
  pass "rx_packets $rx == forwarded $fwd + flooded $flood + to_host $host + drops $drops"
else
  fail "rx_packets ${rx:-missing} != forwarded ${fwd:-?} + flooded ${flood:-?} + to_host ${host:-?} + drops $drops"
fi
avail=$(counter pool_available)
cap=$(counter pool_capacity)
if [[ -n $cap && $avail == "$cap" ]]; then
  pass "every buffer back in its pool ($avail of $cap)"
else
  fail "pool_available ${avail:-missing} of ${cap:-missing}: buffers leaked"
fi
sed -n '/final counters/,$p' "$LOG" | grep -E '^(rx_packets|forwarded|RingFull|TxFull|PoolExhausted|kernel_rx_drops)' |
  sed 's/^/    /'

echo
if [[ $failures -eq 0 ]]; then
  echo "SOAK (${IO_ARGS[*]}): PASS"
  exit 0
fi
echo "SOAK (${IO_ARGS[*]}): FAIL ($failures check(s) failed)"
exit 1
