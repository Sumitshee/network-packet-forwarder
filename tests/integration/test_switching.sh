#!/usr/bin/env bash
# Phase 12 exit test (docs/BUILD_PLAN.md): the router as a learning switch between three hosts.
#
#   sudo tests/integration/test_switching.sh build/dev/npf
#
# Builds the topology with scripts/setup_bridge_netns.sh, runs `npf run` on configs/bridge.conf in
# ns-router, makes the plan's five assertions, and tears it all down again, whatever happens. The
# configuration is the plan's, except mac_age 10 for 300, so that assertion 5 waits 15 s, not
# 305. Every assertion is checked even after one fails; the exit status is non-zero if any did.
# Not root: exit status 77, which CTest reports as skipped. NPF_CAPTURE=python captures with a raw
# socket instead of tcpdump, which cannot drop privileges inside an unprivileged user namespace.
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
MAC_AGE=10
H1_MAC=aa:bb:cc:00:09:01
H2_MAC=aa:bb:cc:00:09:02
H3_MAC=aa:bb:cc:00:09:03
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
  "$ROOT/scripts/cleanup_bridge_netns.sh"
  rm -rf "$WORK"
}
trap cleanup EXIT

"$ROOT/scripts/cleanup_bridge_netns.sh"
if ! "$ROOT/scripts/setup_bridge_netns.sh"; then
  echo "FAIL  scripts/setup_bridge_netns.sh"
  exit 1
fi

sed "s/^mac_age .*/mac_age $MAC_AGE/" "$ROOT/configs/bridge.conf" > "$WORK/bridge.conf"
grep -qx "mac_age $MAC_AGE" "$WORK/bridge.conf" || { echo "FAIL  configs/bridge.conf has no mac_age"; exit 1; }

echo "\$ ip netns exec ns-router $NPF run --config bridge.conf &   (mac_age $MAC_AGE)"
ip netns exec ns-router "$NPF" run --config "$WORK/bridge.conf" --pidfile "$WORK/npf.pid" \
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

npf_show() { "$NPF" show "$1" --pidfile "$WORK/npf.pid" --stats-file "$WORK/npf.stats"; }
port_of() { npf_show mac | awk -v m="$1" '$1 == m { print $2 }'; }  # where the switch has m

# capture <namespace> <file>: what the host's eth0 receives, for 6 s, in the background.
capture() {
  if [[ ${NPF_CAPTURE:-tcpdump} == python ]]; then
    ip netns exec "$1" python3 "$FRAMES" frames eth0 6 > "$2" 2>&1 &
  else
    ip netns exec "$1" timeout 6 tcpdump -t -e -n -l -Q in -i eth0 > "$2" 2>&1 &
  fi
  CAPTURES+=($!)
  for _ in $(seq 50); do
    grep -q 'listening' "$2" && break
    sleep 0.1
  done
}

echo
echo "--- 1: \$ ip netns exec ns-h1 ping -c 5 10.0.9.2, watched from h1 and h3"
CAPTURES=()
capture ns-h1 "$WORK/h1.txt"
capture ns-h3 "$WORK/h3.txt"
ip netns exec ns-h1 ping -c 5 -i 0.2 -W 2 10.0.9.2 | tee "$WORK/ping.txt"
wait "${CAPTURES[@]}"
loss=$(grep -o '[0-9.]*% packet loss' "$WORK/ping.txt")
if [[ $loss == "0% packet loss" ]]; then
  pass "1: $loss"
else
  fail "1: ${loss:-no ping summary}, expected 0% packet loss"
fi

echo
echo "--- 2: \$ npf show mac"
npf_show mac | sed 's/^/    /'
h1_port=$(port_of "$H1_MAC")
h2_port=$(port_of "$H2_MAC")
if [[ $h1_port == 0 && $h2_port == 1 ]]; then
  pass "2: h1's MAC on port 0, h2's on port 1"
else
  fail "2: h1's MAC on port '${h1_port:-none}', h2's on port '${h2_port:-none}'; expected 0 and 1"
fi
[[ -z $(port_of "$H3_MAC") ]] || fail "2: h3 sent nothing, yet the switch has learned it"

echo
echo "--- 3: what h1 received while it pinged h2"
sed 's/^/    /' "$WORK/h1.txt"
own=$(grep -c "^$H1_MAC > " "$WORK/h1.txt")
replies=$(grep -c "ICMP echo reply" "$WORK/h1.txt")
if [[ $own == 0 && $replies -ge 5 ]]; then
  pass "3: h1 received its $replies echo replies, and never a frame of its own back"
else
  fail "3: h1 received $own frame(s) from itself and $replies echo reply(s); expected 0 and 5"
fi

echo
echo "--- 4: what h3 received meanwhile"
sed 's/^/    /' "$WORK/h3.txt"
asked=$(grep -c "Request who-has 10.0.9.2 tell 10.0.9.1" "$WORK/h3.txt")
echoes=$(grep -c "ICMP echo" "$WORK/h3.txt")
if [[ $asked -ge 1 && $echoes == 0 ]]; then
  pass "4: h3 saw h1's ARP request flooded ($asked), and none of the unicast ICMP that followed"
else
  fail "4: h3 saw $asked flooded ARP request(s) and $echoes ICMP echo frame(s); expected >= 1 and 0"
fi

echo
echo "--- 5: wait mac_age + 5 = $((MAC_AGE + 5)) s, then \$ npf show mac"
sleep $((MAC_AGE + 5))
npf_show mac | sed 's/^/    /'
stations=$(npf_show mac | grep -vc '^#')
if [[ $stations == 0 ]]; then
  pass "5: the table is empty: every station aged out"
else
  fail "5: $stations station(s) still in the table after mac_age + 5 s"
fi

echo
echo "--- \$ npf show arp: the router has no address on a bridge, so nothing to resolve"
if npf_show arp > "$WORK/arp.txt"; then
  sed 's/^/    /' "$WORK/arp.txt"
  [[ $(grep -vc '^#' "$WORK/arp.txt") == 0 ]] || fail "show arp: entries, on a router with no address"
else
  fail "npf show arp failed"
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
sed 's/^/    /' "$WORK/npf.log"
[[ $status == 0 ]] || fail "npf exited with status $status"

value() { awk -v k="$1" '$1 == k { print $2 }' "$WORK/npf.stats"; }
available=$(value pool_available)
capacity=$(value pool_capacity)
if [[ -n $available && $available == "$capacity" ]]; then
  pass "after the run, pool_available == pool_capacity == $capacity: no leaked buffers"
else
  fail "after the run, pool_available ${available:-missing}, pool_capacity ${capacity:-missing}"
fi
drops=0
for reason in ShortFrame BadEtherType BadIpv4Header BadChecksum MartianSource TtlExpired \
  NoRoute ArpUnresolved FilterDeny NoOutPort UnknownDestPort SamePort TxFull PoolExhausted; do
  n=$(value "$reason")
  if [[ -z $n ]]; then
    fail "$reason is missing from the final counters"
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
  pass "rx_packets $rx == forwarded $forwarded + flooded $flooded + to_host $to_host + drops $drops"
else
  fail "rx_packets ${rx:-missing}, but forwarded + flooded + to_host + drops == $accounted"
fi

echo
if [[ $failures == 0 ]]; then
  echo "PHASE 12 EXIT TEST: PASS"
  exit 0
fi
echo "PHASE 12 EXIT TEST: FAIL ($failures assertion(s) failed)"
exit 1
