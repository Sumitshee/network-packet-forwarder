#!/usr/bin/env bash
# Phase 7 exit test (docs/BUILD_PLAN.md): traceroute through the router, and the router answering
# pings for itself.
#
#   sudo tests/integration/test_traceroute.sh build/dev/npf
#
# Builds the topology with scripts/setup_netns.sh, runs `npf run` in ns-router, makes the checks
# below and tears it all down again, whatever happens. Every check runs even after one fails; the
# exit status is non-zero if any did. Not root: exit status 77, which CTest reports as skipped.
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

# The two interfaces and their subnets, nothing else: the hops are the router and the server.
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

# Both hosts resolved before the trace begins, so that no probe waits on ARP. Since phase 8 the
# first ping does it; before, the ARP cache dropped the packet that started a resolution, and a
# probe sent then was lost.
echo
echo "--- warm-up"
warm=0
for i in 1 2 3 4 5; do
  if ip netns exec ns-client ping -c 1 -W 1 10.0.2.2 > /dev/null; then
    echo "a ping got through on try $i"
    warm=1
    break
  fi
done
[[ $warm == 1 ]] || fail "warm-up: no ping got through in 5 tries"

echo
echo "--- 1: \$ ip netns exec ns-client traceroute -n -q 1 -m 5 10.0.2.2"
ip netns exec ns-client traceroute -n -q 1 -m 5 10.0.2.2 | tee "$WORK/traceroute.txt"
hop() { awk -v n="$1" '$1 == n { print $2 }' "$WORK/traceroute.txt"; }
hops=$(awk '$1 ~ /^[0-9]+$/' "$WORK/traceroute.txt" | wc -l)
if [[ $(hop 1) == 10.0.1.1 ]]; then
  pass "1: hop 1 is 10.0.1.1, the router: its Time Exceeded came from the port the probe reached"
else
  fail "1: hop 1 is '$(hop 1)', expected 10.0.1.1"
fi
if [[ $(hop 2) == 10.0.2.2 && $hops == 2 ]]; then
  pass "1: hop 2 is 10.0.2.2, the server, and the trace ends there"
else
  fail "1: hop 2 is '$(hop 2)' of $hops hops, expected 10.0.2.2 and 2 hops"
fi

echo
echo "--- 2: \$ ip netns exec ns-client ping -c 3 10.0.1.1"
ip netns exec ns-client ping -c 3 10.0.1.1 | tee "$WORK/ping.txt"
loss=$(grep -o '[0-9.]*% packet loss' "$WORK/ping.txt")
if [[ $loss == "0% packet loss" ]]; then
  pass "2: $loss: the router answers for itself"
else
  fail "2: ${loss:-no ping summary}, expected 0% packet loss"
fi

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
generated=$(value icmp_generated)
if [[ -n $generated && $generated -ge 4 ]]; then
  pass "3: icmp_generated $generated: at least the Time Exceeded and the three Echo Replies"
else
  fail "3: icmp_generated is ${generated:-missing}, expected at least 4"
fi

available=$(value pool_available)
capacity=$(value pool_capacity)
if [[ -n $available && $available == "$capacity" ]]; then
  pass "4: after the run, pool_available == pool_capacity == $capacity: no leaked buffers"
else
  fail "4: after the run, pool_available ${available:-missing}, pool_capacity ${capacity:-missing}"
fi

drops=0
for reason in ShortFrame BadEtherType BadIpv4Header BadChecksum MartianSource TtlExpired \
  NoRoute ArpUnresolved FilterDeny NoOutPort UnknownDestPort SamePort TxFull PoolExhausted; do
  n=$(value "$reason")
  if [[ -z $n ]]; then
    fail "5: $reason is missing from the final counters"
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
  pass "5: rx_packets $rx == forwarded $forwarded + flooded $flooded + to_host $to_host + drops $drops"
else
  fail "5: rx_packets ${rx:-missing}, but forwarded + flooded + to_host + drops == $accounted"
fi

echo
if [[ $failures == 0 ]]; then
  echo "PHASE 7 EXIT TEST: PASS"
  exit 0
fi
echo "PHASE 7 EXIT TEST: FAIL ($failures check(s) failed)"
exit 1
