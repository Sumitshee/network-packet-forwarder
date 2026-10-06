#!/usr/bin/env bash
# Phase 8 exit test (docs/BUILD_PLAN.md): the first packet to a neighbour the router has not
# resolved waits for ARP, and is delivered, not dropped. And a neighbour that never answers earns
# its sender a Host Unreachable.
#
#   sudo tests/integration/test_arp_resolution.sh build/dev/npf
#
# Builds the topology with scripts/setup_netns.sh, runs `npf run` in ns-router with no static ARP
# entries, makes the checks below and tears it all down again, whatever happens. Every check runs
# even after one fails; the exit status is non-zero if any did. Not root: exit status 77, which
# CTest reports as skipped.
set -uo pipefail

if [[ $(id -u) -ne 0 ]]; then
  echo "SKIP: needs root, for network namespaces and AF_PACKET"
  exit 77
fi
NPF=$(realpath "${1:?usage: $0 <path to the npf binary>}")
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
WORK=$(mktemp -d)
NPF_PID=""
failures=0

pass() { echo "PASS  $*"; }
fail() {
  echo "FAIL  $*"
  failures=$((failures + 1))
}

cleanup() {
  if [[ -n $NPF_PID ]] && kill -0 "$NPF_PID" 2>/dev/null; then
    kill -KILL "$NPF_PID"
  fi
  "$ROOT/scripts/cleanup_netns.sh"
  rm -rf "$WORK"
}
trap cleanup EXIT

"$ROOT/scripts/cleanup_netns.sh"
if ! "$ROOT/scripts/setup_netns.sh"; then
  echo "FAIL  scripts/setup_netns.sh"
  exit 1
fi

# No static ARP, so every neighbour is one the router must resolve itself.
cat > "$WORK/router.conf" <<'EOF'
interface veth-cr port 0 ip 10.0.1.1/24 mode routed
interface veth-sr port 1 ip 10.0.2.1/24 mode routed
route 10.0.1.0/24 dev 0
route 10.0.2.0/24 dev 1
EOF

echo "\$ ip netns exec ns-router $NPF run --config router.conf &"
ip netns exec ns-router "$NPF" run --config "$WORK/router.conf" --pidfile "$WORK/npf.pid" \
  --stats-file "$WORK/npf.stats" > "$WORK/npf.log" 2>&1 &
NPF_PID=$!
for _ in $(seq 50); do
  grep -q 'forwarding on' "$WORK/npf.log" && break
  sleep 0.1
done
sed 's/^/    /' "$WORK/npf.log"
if ! grep -q 'forwarding on' "$WORK/npf.log"; then
  echo "FAIL  npf run did not start"
  exit 1
fi

counter() { # counter <name>: its value now, from npf show stats
  "$NPF" show stats --pidfile "$WORK/npf.pid" --stats-file "$WORK/npf.stats" |
    awk -v k="$1" '$1 == k { print $2 }'
}
expect_delta() { # expect_delta <check> <counter> <value before> <expected increase> <why>
  local now
  now=$(counter "$2")
  if [[ -n $now && $((now - $3)) == "$4" ]]; then
    pass "$1: $2 went up by $4: $5"
  else
    fail "$1: $2 went from $3 to ${now:-missing}, expected an increase of $4: $5"
  fi
}

# SIGUSR2 empties the router's ARP cache. Returns once npf has said it did, so no packet sent
# afterwards can find the cache as it was.
flush_router() {
  local before
  before=$(grep -c 'ARP cache flushed' "$WORK/npf.log")
  kill -USR2 "$NPF_PID"
  for _ in $(seq 50); do
    (($(grep -c 'ARP cache flushed' "$WORK/npf.log") > before)) && return 0
    sleep 0.1
  done
  return 1
}

# The plan's exit test, three times over: the first round on a router that has just started, the
# others on one that knew both hosts until a moment before. The plan empties the client's ARP
# cache and the router's; the server's goes too, so that nobody on the way knows anybody.
for round in 1 2 3; do
  echo
  echo "--- 1.$round: the first ping, with every ARP cache on the way emptied first"
  echo "\$ ip netns exec ns-client ip neigh flush all"
  ip netns exec ns-client ip neigh flush all
  echo "\$ ip netns exec ns-server ip neigh flush all"
  ip netns exec ns-server ip neigh flush all
  echo "\$ kill -USR2 \$NPF_PID"
  if ! flush_router; then
    fail "1.$round: npf did not report flushing its ARP cache"
    continue
  fi
  requests=$(counter arp_requests_tx)
  forwarded=$(counter forwarded)
  unresolved=$(counter ArpUnresolved)
  echo "\$ ip netns exec ns-client ping -c 1 -W 3 10.0.2.2"
  if ip netns exec ns-client ping -c 1 -W 3 10.0.2.2 | tee "$WORK/ping-$round.txt"; then
    pass "1.$round: the ping got through: its first packet waited for ARP, and was delivered"
  else
    fail "1.$round: the ping got no reply"
  fi
  expect_delta "1.$round" arp_requests_tx "$requests" 2 \
    "the router asked once for each host, so it had to resolve both"
  expect_delta "1.$round" forwarded "$forwarded" 2 "the echo request and its reply"
  expect_delta "1.$round" ArpUnresolved "$unresolved" 0 "no packet was dropped for want of ARP"
done

echo
echo "--- 2: a neighbour that never answers"
echo "\$ ip netns exec ns-client ping -c 4 -i 0.2 -W 5 10.0.2.99"
requests=$(counter arp_requests_tx)
unresolved=$(counter ArpUnresolved)
generated=$(counter icmp_generated)
ip netns exec ns-client ping -c 4 -i 0.2 -W 5 10.0.2.99 | tee "$WORK/ping-absent.txt"
if grep -q 'From 10.0.1.1 icmp_seq=1 Destination Host Unreachable' "$WORK/ping-absent.txt"; then
  pass "2: the first ping was answered with Host Unreachable, from 10.0.1.1: the port it came in on"
else
  fail "2: no 'From 10.0.1.1 icmp_seq=1 Destination Host Unreachable' in ping's output"
fi
expect_delta 2 arp_requests_tx "$requests" 3 "three probes, a second apart, and then it gave up"
expect_delta 2 icmp_generated "$generated" 1 "one Host Unreachable, for the head of the queue only"
expect_delta 2 ArpUnresolved "$unresolved" 4 \
  "three dropped when it gave up, and the fourth refused by a full queue"

echo
echo "--- stopping npf with SIGINT"
kill -INT "$NPF_PID"
for _ in $(seq 50); do
  kill -0 "$NPF_PID" 2>/dev/null || break
  sleep 0.1
done
wait "$NPF_PID"
status=$?
NPF_PID=""
sed -n '/stopped; final counters/,$p' "$WORK/npf.log" | sed 's/^/    /'
[[ $status == 0 ]] || fail "npf exited with status $status"

value() { awk -v k="$1" '$1 == k { print $2 }' "$WORK/npf.stats"; }
available=$(value pool_available)
capacity=$(value pool_capacity)
if [[ -n $available && $available == "$capacity" ]]; then
  pass "3: after the run, pool_available == pool_capacity == $capacity: no leaked buffers"
else
  fail "3: after the run, pool_available ${available:-missing}, pool_capacity ${capacity:-missing}"
fi

drops=0
for reason in ShortFrame BadEtherType BadIpv4Header BadChecksum MartianSource TtlExpired \
  NoRoute ArpUnresolved FilterDeny NoOutPort UnknownDestPort SamePort TxFull PoolExhausted; do
  n=$(value "$reason")
  if [[ -z $n ]]; then
    fail "4: $reason is missing from the final counters"
    n=0
  fi
  drops=$((drops + n))
done
rx=$(value rx_packets)
forwarded=$(value forwarded)
flooded=$(value flooded)
to_host=$(value to_host)
accounted=$((${forwarded:-0} + ${flooded:-0} + ${to_host:-0} + drops))
if [[ -n $rx && $rx -gt 0 && $rx == "$accounted" ]]; then
  pass "4: rx_packets $rx == forwarded $forwarded + flooded $flooded + to_host $to_host + drops $drops"
else
  fail "4: rx_packets ${rx:-missing}, but forwarded + flooded + to_host + drops == $accounted"
fi

echo
if [[ $failures == 0 ]]; then
  echo "PHASE 8 EXIT TEST: PASS"
  exit 0
fi
echo "PHASE 8 EXIT TEST: FAIL ($failures check(s) failed)"
exit 1
