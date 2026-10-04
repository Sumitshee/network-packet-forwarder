#!/usr/bin/env bash
# Phase 6 exit test (docs/BUILD_PLAN.md): the forwarder, for real, between network namespaces.
#
#   sudo tests/integration/test_forward_netns.sh build/dev/npf
#
# Builds the topology with scripts/setup_netns.sh, runs `npf run` in ns-router, makes the plan's
# eight assertions and tears it all down again, whatever happens. Every assertion is checked even
# after one fails; the exit status is non-zero if any did. Not root: exit status 77, which CTest
# reports as skipped. NPF_CAPTURE=python reads the TTLs with a raw socket instead of tcpdump,
# which cannot drop privileges inside an unprivileged user namespace.
set -uo pipefail

if [[ $(id -u) -ne 0 ]]; then
  echo "SKIP: needs root, for network namespaces and AF_PACKET"
  exit 77
fi
NPF=$(realpath "${1:?usage: $0 <path to the npf binary>}")
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
FRAMES="$ROOT/tests/integration/netns_frames.py"
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

# The test's own configuration. configs/router.conf has a default route, under which 10.9.9.9
# would be routed toward 10.0.2.254 rather than have no route at all; and no static ARP here, so
# the forwarder resolves both hosts itself.
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

npf_show() { "$NPF" show stats --pidfile "$WORK/npf.pid" --stats-file "$WORK/npf.stats"; }
expect_counter() { # expect_counter <assertion> <counter> <value>
  local got
  got=$(npf_show | awk -v k="$2" '$1 == k { print $2 }')
  if [[ $got == "$3" ]]; then
    pass "$1: npf show stats: $2 == $3"
  else
    fail "$1: npf show stats: $2 is ${got:-missing}, expected $3"
  fi
}
expect_loss() { # expect_loss <assertion> <ping output file> <loss>
  local got
  got=$(grep -o '[0-9.]*% packet loss' "$2")
  if [[ $got == "$3% packet loss" ]]; then
    pass "$1: $got"
  else
    fail "$1: ${got:-no ping summary}, expected $3% packet loss"
  fi
}

# Both hosts resolved before the checks begin. Since phase 8 the first ping does it, its packets
# waiting while the router asks; phase 6's ARP cache dropped the packet that started a resolution,
# so it took a few.
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
echo "--- 1, 2: \$ ip netns exec ns-client ping -c 10 10.0.2.2, watched from ns-server"
if [[ ${NPF_CAPTURE:-tcpdump} == python ]]; then
  ip netns exec ns-server python3 "$FRAMES" echo-ttls veth-s 10 20 > "$WORK/capture.txt" 2>&1 &
else
  ip netns exec ns-server timeout 20 tcpdump -n -l -v -c 10 -i veth-s \
    'icmp[icmptype] == icmp-echo' > "$WORK/capture.txt" 2>&1 &
fi
CAPTURE_PID=$!
for _ in $(seq 50); do
  grep -q 'listening' "$WORK/capture.txt" && break
  sleep 0.1
done
ip netns exec ns-client ping -c 10 10.0.2.2 | tee "$WORK/ping.txt"
wait "$CAPTURE_PID"
echo "    --- what ns-server saw ---"
sed 's/^/    /' "$WORK/capture.txt"
expect_loss 1 "$WORK/ping.txt" 0
ttls=$(grep -o 'ttl [0-9]*' "$WORK/capture.txt" | awk '{ print $2 }' | sort | uniq -c | xargs)
if [[ $ttls == "10 63" ]]; then
  pass "2: all 10 echo requests reached ns-server with ttl 63: decremented exactly once"
else
  fail "2: echo requests seen at ns-server, as 'count ttl': [$ttls]; expected [10 63]"
fi

echo
echo "--- 3: \$ ip netns exec ns-client ping -c 3 -t 1 10.0.2.2"
ip netns exec ns-client ping -c 3 -t 1 -W 1 10.0.2.2 | tee "$WORK/ping-ttl1.txt"
expect_loss 3 "$WORK/ping-ttl1.txt" 100
expect_counter 3 TtlExpired 3

echo
echo "--- 4: \$ ip netns exec ns-client ping -c 3 -W 1 10.9.9.9"
ip netns exec ns-client ping -c 3 -W 1 10.9.9.9 | tee "$WORK/ping-noroute.txt"
expect_loss 4 "$WORK/ping-noroute.txt" 100
expect_counter 4 NoRoute 3

echo
echo "--- 5: an LLDP frame (EtherType 0x88cc) injected on veth-c"
ip netns exec ns-client python3 "$FRAMES" lldp veth-c
sleep 0.5
expect_counter 5 BadEtherType 1

echo
echo "--- 6: an IPv4 frame with a corrupted header checksum, to the router's MAC"
router_mac=$(ip netns exec ns-router cat /sys/class/net/veth-cr/address)
ip netns exec ns-client python3 "$FRAMES" bad-checksum veth-c "$router_mac" 10.0.1.2 10.0.2.2
sleep 0.5
expect_counter 6 BadChecksum 1

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
sed 's/^/    /' "$WORK/npf.log"
[[ $status == 0 ]] || fail "npf exited with status $status"

value() { awk -v k="$1" '$1 == k { print $2 }' "$WORK/npf.stats"; }
available=$(value pool_available)
capacity=$(value pool_capacity)
if [[ -n $available && $available == "$capacity" ]]; then
  pass "7: after the run, pool_available == pool_capacity == $capacity: no leaked buffers"
else
  fail "7: after the run, pool_available ${available:-missing}, pool_capacity ${capacity:-missing}"
fi

drops=0
for reason in ShortFrame BadEtherType BadIpv4Header BadChecksum MartianSource TtlExpired \
  NoRoute ArpUnresolved FilterDeny NoOutPort UnknownDestPort TxFull PoolExhausted; do
  n=$(value "$reason")
  if [[ -z $n ]]; then
    fail "8: $reason is missing from the final counters"
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
  pass "8: rx_packets $rx == forwarded $forwarded + flooded $flooded + to_host $to_host + drops $drops"
else
  fail "8: rx_packets ${rx:-missing}, but forwarded + flooded + to_host + drops == $accounted"
fi

echo
if [[ $failures == 0 ]]; then
  echo "PHASE 6 EXIT TEST: PASS"
  exit 0
fi
echo "PHASE 6 EXIT TEST: FAIL ($failures assertion(s) failed)"
exit 1
