#!/usr/bin/env bash
# Phase 13 exit test, steps 3 and 5 (docs/BUILD_PLAN.md): per-flow ordering survives every worker
# count in both execution models, and the counters still balance.
#
#   sudo tests/integration/test_ordering.sh build/dev/npf
#
# For each mode (rtc, pipeline) and each worker count (1, 2, 4, 8): runs `npf run` on
# configs/router.conf in ns-router, sends one flow of 100,000 UDP datagrams from ns-client with
# bench/system/gen --ip-id-sequence, captures them arriving in ns-server, and has
# scripts/check_ordering.py assert that their sequence numbers and IP IDs only ever increase.
# Then, for each mode, the same with 16 flows on 4 workers, every flow checked. After every run
# the final counters must balance: rx_packets == forwarded + flooded + to_host + every drop, and
# every buffer back in its pool. The router may drop under load -- gaps are reported, not failed
# -- but it must never reorder a flow.
#
# gen is the one next to npf: build/<preset>/bench/system/gen. Not root: exit status 77, which
# CTest reports as skipped. NPF_CAPTURE=python captures with a raw socket instead of tcpdump,
# which cannot drop privileges inside an unprivileged user namespace.
set -uo pipefail
# NPF_RUN_ARGS: more for npf run, such as "--io mmap" to run the same test on PACKET_MMAP.
read -ra RUN_ARGS <<< "${NPF_RUN_ARGS:-}"

if [[ $(id -u) -ne 0 ]]; then
  echo "SKIP: needs root, for network namespaces and AF_PACKET"
  exit 77
fi
NPF=$(realpath "${1:?usage: $0 <path to the npf binary>}")
GEN="$(dirname "$NPF")/bench/system/gen"
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
CHECK="$ROOT/scripts/check_ordering.py"
FRAMES="$ROOT/tests/integration/netns_frames.py"
WORK=$(mktemp -d)
NPF_PID=""
CAPTURE_PID=""
COUNT=${NPF_ORDERING_COUNT:-100000}
DROPS=(ShortFrame BadEtherType BadIpv4Header BadChecksum MartianSource TtlExpired
  NoRoute ArpUnresolved FilterDeny NoOutPort UnknownDestPort SamePort RingFull TxFull PoolExhausted)
failures=0

pass() { echo "PASS  $*"; }
fail() {
  echo "FAIL  $*"
  failures=$((failures + 1))
}

cleanup() {
  [[ -n $CAPTURE_PID ]] && kill -KILL "$CAPTURE_PID" 2>/dev/null
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

start_npf() { # start_npf <mode> <workers> <log>
  ip netns exec ns-router "$NPF" run "${RUN_ARGS[@]}" --config "$ROOT/configs/router.conf" --mode "$1" \
    --workers "$2" --pidfile "$WORK/npf.pid" --stats-file "$WORK/npf.stats" > "$3" 2>&1 &
  NPF_PID=$!
  for _ in $(seq 100); do
    grep -q 'forwarding on' "$3" && return 0
    kill -0 "$NPF_PID" 2>/dev/null || break
    sleep 0.1
  done
  return 1
}

stop_npf() { # stop_npf: SIGTERM, then the exit status
  kill -TERM "$NPF_PID"
  wait "$NPF_PID"
  local status=$?
  NPF_PID=""
  return $status
}

start_capture() { # start_capture <pcap> <log>
  if [[ ${NPF_CAPTURE:-tcpdump} == python ]]; then
    ip netns exec ns-server python3 "$FRAMES" pcap veth-s 600 "$1" > "$2" 2>&1 &
  else
    ip netns exec ns-server tcpdump -n -U -B 65536 -i veth-s -w "$1" 'udp and dst port 5001' \
      > "$2" 2>&1 &
  fi
  CAPTURE_PID=$!
  for _ in $(seq 50); do
    grep -q 'listening' "$2" && return 0
    sleep 0.1
  done
  return 1
}

stop_capture() {
  sleep 1  # the last datagrams through the router
  if [[ ${NPF_CAPTURE:-tcpdump} == python ]]; then
    kill -TERM "$CAPTURE_PID"
  else
    kill -INT "$CAPTURE_PID"
  fi
  wait "$CAPTURE_PID" 2>/dev/null
  CAPTURE_PID=""
}

counter() { # counter <log> <name>: from the final table npf prints when it stops
  sed -n '/final counters/,$p' "$1" | awk -v k="$2" '$1 == k { print $2 }'
}

check_balance() { # check_balance <label> <log>
  local rx fwd flood host drops=0 n avail cap
  rx=$(counter "$2" rx_packets)
  fwd=$(counter "$2" forwarded)
  flood=$(counter "$2" flooded)
  host=$(counter "$2" to_host)
  for d in "${DROPS[@]}"; do
    n=$(counter "$2" "$d")
    drops=$((drops + ${n:-0}))
    [[ ${n:-0} -ne 0 ]] && echo "    dropped as $d: $n"
  done
  avail=$(counter "$2" pool_available)
  cap=$(counter "$2" pool_capacity)
  if [[ -n $rx && $rx -gt 0 && $rx -eq $((fwd + flood + host + drops)) ]]; then
    pass "$1: rx_packets $rx == forwarded $fwd + flooded $flood + to_host $host + drops $drops"
  else
    fail "$1: rx_packets ${rx:-missing} != forwarded ${fwd:-?} + flooded ${flood:-?} + to_host ${host:-?} + drops $drops"
  fi
  if [[ -n $cap && $avail == "$cap" ]]; then
    pass "$1: every buffer back in its pool ($avail of $cap)"
  else
    fail "$1: pool_available ${avail:-missing} of ${cap:-missing}: buffers leaked"
  fi
}

# One run: npf with this mode and worker count, gen with this many flows, and the checks.
run_case() { # run_case <mode> <workers> <flows>
  local label="$1, $2 workers, $3 flow(s)" log="$WORK/npf-$1-$2-$3.log" pcap="$WORK/out-$1-$2-$3.pcap"
  echo
  echo "--- $label: \$ npf run --config configs/router.conf --mode $1 --workers $2"
  if ! start_npf "$1" "$2" "$log"; then
    fail "$label: npf run did not start"
    sed 's/^/    /' "$log"
    return
  fi
  grep 'forwarding on' "$log" | sed 's/^/    /'
  # The client's first datagram makes it ask for its gateway's MAC; the router answers.
  ip netns exec ns-client ping -c 1 -W 2 10.0.2.2 > /dev/null ||
    fail "$label: warm-up ping did not get through"
  if ! start_capture "$pcap" "$WORK/capture.log"; then
    fail "$label: the capture did not start"
    cat "$WORK/capture.log"
    stop_npf
    return
  fi
  ip netns exec ns-client "$GEN" --dst 10.0.2.2 --flows "$3" --count "$COUNT" --ip-id-sequence |
    sed 's/^/    /'
  stop_capture
  if python3 "$CHECK" "$pcap" --flows "$3" --min-packets $((COUNT / 10)) > "$WORK/check.txt"; then
    pass "$label: $(grep -v PASS "$WORK/check.txt" | head -1)"
  else
    fail "$label: per-flow order"
    sed 's/^/    /' "$WORK/check.txt"
  fi
  if stop_npf; then
    pass "$label: npf exited cleanly"
  else
    fail "$label: npf exited with status $?"
  fi
  check_balance "$label" "$log"
}

for mode in rtc pipeline; do
  for workers in 1 2 4 8; do
    run_case "$mode" "$workers" 1
  done
  run_case "$mode" 4 16
done

echo
if [[ $failures -eq 0 ]]; then
  echo "test_ordering: all checks passed"
  exit 0
fi
echo "test_ordering: $failures check(s) failed"
exit 1
