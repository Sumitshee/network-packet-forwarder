#!/usr/bin/env bash
# Phase 16 exit test, step 2 (docs/BUILD_PLAN.md): the golden cases, live, give byte-identical
# output with --io af_packet and with --io mmap.
#
#   sudo tests/integration/test_io_equivalence.sh build/dev/npf
#
# For every case in tests/fixtures/golden: builds a topology of its own -- ns-eqr holds the router's
# interfaces, named and addressed as the case's configuration says, and ns-eqp a peer for each, pN
# for port N -- runs `npf run` on the case's configuration with each backend in turn, sends the
# case's input frames into port 0's peer, and captures what leaves by every peer for 0.5 s after the
# last of them: less than the ARP cache's 1 s between retries, so an unanswered request is seen
# once. The peers have no addresses, ARP and IPv6 off: nothing in the capture is the kernel's own.
# Checksum and VLAN offloads are off on both ends, so every frame is on the wire as npf wrote it.
#
# Per case it checks that each port's frames are identical, in the same order, between the two
# backends; that the final counters are the same; and, as a check on the topology rather than the
# backends, that af_packet's frames are the ones `npf replay` is expected to write.
#
# Not root: exit status 77, which CTest reports as skipped.
set -uo pipefail

if [[ $(id -u) -ne 0 ]]; then
  echo "SKIP: needs root, for network namespaces and AF_PACKET"
  exit 77
fi
NPF=$(realpath "${1:?usage: $0 <path to the npf binary>}")
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
GOLDEN="$ROOT/tests/fixtures/golden"
FRAMES=(python3 "$HERE/netns_frames.py")
WORK=$(mktemp -d)
NPF_PID=""
CAPTURES=()
failures=0

pass() { echo "PASS  $*"; }
fail() {
  echo "FAIL  $*"
  failures=$((failures + 1))
}

teardown() {
  ip netns del ns-eqr 2>/dev/null
  ip netns del ns-eqp 2>/dev/null
}
cleanup() {
  for pid in "${CAPTURES[@]}"; do
    kill -KILL "$pid" 2>/dev/null
  done
  if [[ -n $NPF_PID ]] && kill -0 "$NPF_PID" 2>/dev/null; then
    kill -KILL "$NPF_PID"
  fi
  teardown
  rm -rf "$WORK"
}
trap cleanup EXIT

quiet_end() { # quiet_end <netns> <iface>: no ARP, no IPv6 of its own, no offloads
  ip -n "$1" link set "$2" arp off
  ip netns exec "$1" ethtool -K "$2" rx off tx off tso off gso off gro off rxvlan off txvlan off \
    > /dev/null 2>&1
}

# The case's interfaces, as "name port mac" lines.
interfaces() {
  awk '$1 == "interface" {
    name = $2; port = ""; mac = ""
    for (i = 3; i < NF; i++) { if ($i == "port") port = $(i + 1); if ($i == "mac") mac = $(i + 1) }
    print name, port, mac
  }' "$1"
}

topology() { # topology <conf>
  teardown
  ip netns add ns-eqr && ip netns add ns-eqp || return 1
  for ns in ns-eqr ns-eqp; do
    ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
  done
  local name port mac
  while read -r name port mac; do
    ip -n ns-eqr link add "$name" type veth peer name "p$port" netns ns-eqp || return 1
    [[ -n $mac ]] && ip -n ns-eqr link set "$name" address "$mac"
    quiet_end ns-eqr "$name"
    quiet_end ns-eqp "p$port"
    ip -n ns-eqr link set "$name" up
    ip -n ns-eqp link set "p$port" up
  done < <(interfaces "$1")
}

# Runs the case once on one backend: its frames go to $WORK/<case>.<io>.p<N>.pcap, its final
# counters to $WORK/<case>.<io>.stats.
live() { # live <case> <io>
  local name=$1 io=$2 log="$WORK/$1.$2.log" port
  rm -f "$WORK/npf.pid"
  ip netns exec ns-eqr "$NPF" run --io "$io" --config "$WORK/$name.conf" --pidfile "$WORK/npf.pid" \
    --stats-file "$WORK/npf.stats" > "$log" 2>&1 &
  NPF_PID=$!
  for _ in $(seq 100); do
    grep -q 'forwarding on' "$log" && break
    kill -0 "$NPF_PID" 2>/dev/null || break
    sleep 0.05
  done
  if ! grep -q 'forwarding on' "$log"; then
    fail "$name, $io: npf run did not start"
    sed 's/^/    /' "$log"
    NPF_PID=""
    return 1
  fi
  CAPTURES=()
  for port in "${PORTS[@]}"; do
    ip netns exec ns-eqp "${FRAMES[@]}" pcap "p$port" 30 "$WORK/$name.$io.p$port.pcap" \
      > "$WORK/cap.p$port" 2>&1 &
    CAPTURES+=($!)
  done
  for port in "${PORTS[@]}"; do
    for _ in $(seq 100); do
      grep -q listening "$WORK/cap.p$port" 2>/dev/null && break
      sleep 0.05
    done
  done
  ip netns exec ns-eqp "${FRAMES[@]}" send-pcap p0 "$GOLDEN/$name.pcap"
  sleep 0.5
  kill -TERM "${CAPTURES[@]}" 2>/dev/null
  wait "${CAPTURES[@]}" 2>/dev/null
  CAPTURES=()
  kill -INT "$NPF_PID"
  wait "$NPF_PID"
  NPF_PID=""
  sed -n '/final counters/,$p' "$log" | grep -v -e 'final counters' -e kernel_rx_drops \
    > "$WORK/$name.$io.stats"
}

for conf in "$GOLDEN"/*.conf; do
  name=$(basename "$conf" .conf)
  echo
  echo "--- $name"
  sed 's/^io pcap$/io af_packet/' "$conf" > "$WORK/$name.conf"
  cp "$GOLDEN/$name".filter "$WORK/" 2>/dev/null
  mapfile -t PORTS < <(interfaces "$conf" | awk '{ print $2 }')
  if ! topology "$conf"; then
    fail "$name: could not build the topology"
    continue
  fi
  live "$name" af_packet || continue
  live "$name" mmap || continue

  same=1
  for port in "${PORTS[@]}"; do
    a="$WORK/$name.af_packet.p$port.pcap" b="$WORK/$name.mmap.p$port.pcap"
    if ! diff=$("${FRAMES[@]}" same-frames "$a" "$b"); then
      fail "$name: port $port's frames differ between af_packet and mmap"
      echo "$diff" | sed 's/^/    /'
      same=0
    fi
  done
  counts=""
  for port in "${PORTS[@]}"; do
    counts+="p$port: $("${FRAMES[@]}" count "$WORK/$name.af_packet.p$port.pcap"), "
  done
  ((same)) && pass "$name: each port's frames byte-identical between af_packet and mmap (${counts%, })"
  if diff -q "$WORK/$name.af_packet.stats" "$WORK/$name.mmap.stats" > /dev/null; then
    pass "$name: the same final counters"
  else
    fail "$name: the final counters differ (af_packet <, mmap >)"
    diff "$WORK/$name.af_packet.stats" "$WORK/$name.mmap.stats" | sed 's/^/    /'
  fi
  af_files=()
  for port in "${PORTS[@]}"; do
    af_files+=("$WORK/$name.af_packet.p$port.pcap")
  done
  if [[ $name == vlan ]]; then
    # The kernel takes the tag out of a frame before any packet socket reads it, and neither
    # backend reads it back (README, "Not implemented"): live, the frame leaves untagged.
    if out=$("${FRAMES[@]}" same-frame-set-untagged "$GOLDEN/$name.expected.pcap" "${af_files[@]}"); then
      pass "$name: the frames are the golden case's expected output, less the VLAN tag, as documented"
    else
      fail "$name: the live frames are not the golden case's expected output, even untagged"
      echo "$out" | sed 's/^/    /'
    fi
  elif out=$("${FRAMES[@]}" same-frame-set "$GOLDEN/$name.expected.pcap" "${af_files[@]}"); then
    pass "$name: the frames are the golden case's expected output"
  else
    fail "$name: the live frames are not the golden case's expected output"
    echo "$out" | sed 's/^/    /'
  fi
done

echo
if [[ $failures -eq 0 ]]; then
  echo "PHASE 16 IO EQUIVALENCE: PASS"
  exit 0
fi
echo "PHASE 16 IO EQUIVALENCE: FAIL ($failures check(s) failed)"
exit 1
