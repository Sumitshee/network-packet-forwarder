#!/usr/bin/env bash
# Phase 13 exit test, step 4 (docs/BUILD_PLAN.md): the running forwarder, built with
# ThreadSanitizer, under sustained traffic, exits clean.
#
#   sudo tests/integration/test_soak.sh build/tsan/npf [seconds per mode] [workers]
#
# For each mode (rtc, pipeline): runs `npf run` on configs/router.conf in ns-router with 4 workers,
# and for 60 s keeps every path between threads busy at once --
#   - 16 flows of UDP from ns-client (bench/system/gen), which spread over the workers;
#   - pings from ns-server back to ns-client, whose replies need the router to resolve 10.0.1.2
#     for itself, and pings to the router's own addresses;
#   - every 5 s, SIGUSR2, which flushes every worker's ARP cache, so the next packet to a
#     neighbour waits on a fresh resolution and the reply reaches the other workers as ARP news;
#   - every second, `npf show stats`, `show mac` or `show arp`, each of which parks every thread.
# Then SIGTERM. The run passes if npf exits with status 0, ThreadSanitizer reported nothing, and
# the final counters balance with every buffer back in its pool. A ThreadSanitizer report makes
# npf exit with status 66 (halt_on_error), so the first race found ends the run.
#
# Any npf binary will do -- a plain build soaks too -- but only a tsan one checks for races.
# Not root: exit status 77, which CTest reports as skipped.
set -uo pipefail

if [[ $(id -u) -ne 0 ]]; then
  echo "SKIP: needs root, for network namespaces and AF_PACKET"
  exit 77
fi
NPF=$(realpath "${1:?usage: $0 <path to the npf binary> [seconds per mode] [workers]}")
SECONDS_PER_MODE=${2:-60}
WORKERS=${3:-4}
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

counter() { # counter <log> <name>
  sed -n '/final counters/,$p' "$1" | awk -v k="$2" '$1 == k { print $2 }'
}

soak() { # soak <mode>
  local mode=$1 log="$WORK/npf-$1.log" show=(stats mac arp) tick=0 status pings=()
  echo
  echo "--- $mode, $WORKERS workers, ${SECONDS_PER_MODE} s"
  TSAN_OPTIONS="halt_on_error=1 exitcode=66 second_deadlock_stack=1" \
    ip netns exec ns-router "$NPF" run --config "$ROOT/configs/router.conf" --mode "$mode" \
    --workers "$WORKERS" --pidfile "$WORK/npf.pid" --stats-file "$WORK/npf.stats" > "$log" 2>&1 &
  NPF_PID=$!
  for _ in $(seq 300); do  # a TSan build starts slowly
    grep -q 'forwarding on' "$log" && break
    kill -0 "$NPF_PID" 2>/dev/null || break
    sleep 0.1
  done
  if ! grep -q 'forwarding on' "$log"; then
    fail "$mode: npf run did not start"
    sed 's/^/    /' "$log"
    return
  fi
  grep 'forwarding on' "$log" | sed 's/^/    /'
  ip netns exec ns-client ping -c 1 -W 2 10.0.2.2 > /dev/null
  ip netns exec ns-client "$GEN" --dst 10.0.2.2 --flows 16 --duration "$SECONDS_PER_MODE" \
    > "$WORK/gen.log" 2>&1 &
  GEN_PID=$!
  local end=$((SECONDS + SECONDS_PER_MODE))
  while ((SECONDS < end)) && kill -0 "$NPF_PID" 2>/dev/null; do
    "$NPF" show "${show[$((tick % 3))]}" --pidfile "$WORK/npf.pid" \
      --stats-file "$WORK/npf.stats" > /dev/null 2>&1 || echo "    (npf show ${show[$((tick % 3))]} failed at ${tick} s)"
    if ((tick % 5 == 4)); then
      kill -USR2 "$NPF_PID"
    fi
    ip netns exec ns-server ping -c 4 -i 0.2 -W 1 10.0.1.2 > /dev/null 2>&1 &
    pings+=($!)
    ip netns exec ns-client ping -c 2 -i 0.2 -W 1 10.0.1.1 > /dev/null 2>&1 &
    pings+=($!)
    sleep 1
    tick=$((tick + 1))
  done
  wait "$GEN_PID" 2>/dev/null
  GEN_PID=""
  sed 's/^/    /' "$WORK/gen.log"
  wait "${pings[@]}" 2>/dev/null  # the last pings
  if kill -0 "$NPF_PID" 2>/dev/null; then
    kill -TERM "$NPF_PID"
  fi
  wait "$NPF_PID"
  status=$?
  NPF_PID=""
  if [[ $status -eq 0 ]]; then
    pass "$mode: npf exited with status 0 after ${tick} s of traffic"
  else
    fail "$mode: npf exited with status $status (66: ThreadSanitizer found a race)"
  fi
  if grep -q 'ThreadSanitizer' "$log"; then
    fail "$mode: ThreadSanitizer reported:"
    grep -A30 'WARNING: ThreadSanitizer' "$log" | head -60 | sed 's/^/    /'
  else
    pass "$mode: no ThreadSanitizer report"
  fi
  local rx fwd flood host drops=0 n avail cap
  rx=$(counter "$log" rx_packets)
  fwd=$(counter "$log" forwarded)
  flood=$(counter "$log" flooded)
  host=$(counter "$log" to_host)
  for d in "${DROPS[@]}"; do
    n=$(counter "$log" "$d")
    drops=$((drops + ${n:-0}))
  done
  avail=$(counter "$log" pool_available)
  cap=$(counter "$log" pool_capacity)
  if [[ -n $rx && $rx -gt 0 && $rx -eq $((fwd + flood + host + drops)) ]]; then
    pass "$mode: rx_packets $rx == forwarded $fwd + flooded $flood + to_host $host + drops $drops"
  else
    fail "$mode: rx_packets ${rx:-missing} != forwarded ${fwd:-?} + flooded ${flood:-?} + to_host ${host:-?} + drops $drops"
  fi
  if [[ -n $cap && $avail == "$cap" ]]; then
    pass "$mode: every buffer back in its pool ($avail of $cap)"
  else
    fail "$mode: pool_available ${avail:-missing} of ${cap:-missing}: buffers leaked"
  fi
  sed -n '/final counters/,$p' "$log" | grep -E '^(rx_packets|forwarded|to_host|ArpUnresolved|RingFull|TxFull|arp_)' |
    sed 's/^/    /'
}

soak rtc
soak pipeline

echo
if [[ $failures -eq 0 ]]; then
  echo "test_soak: all checks passed"
  exit 0
fi
echo "test_soak: $failures check(s) failed"
exit 1
