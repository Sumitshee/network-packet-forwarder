#!/usr/bin/env bash
# Phase 16 exit test, step 2, and phase 17's, step 2 (docs/BUILD_PLAN.md): the golden cases, live,
# give byte-identical output on every backend -- --io af_packet, --io mmap, and, when npf was
# built with AF_XDP, --io xdp in each --xdp-mode.
#
#   sudo tests/integration/test_io_equivalence.sh build/dev/npf
#
# NPF_IO_BACKENDS names the backends instead: "af_packet mmap xdp:skb xdp:native" is the default
# with AF_XDP, "af_packet mmap" without. af_packet comes first: the others are compared with it.
#
# For every case in tests/fixtures/golden: builds a topology of its own -- ns-eqr holds the router's
# interfaces, named and addressed as the case's configuration says, and ns-eqp a peer for each, pN
# for port N -- runs `npf run` on the case's configuration with each backend in turn, sends the
# case's input frames into port 0's peer, and captures what leaves by every peer for 0.5 s after the
# last of them: less than the ARP cache's 1 s between retries, so an unanswered request is seen
# once. The peers have no addresses, ARP and IPv6 off: nothing in the capture is the kernel's own.
# Checksum and VLAN offloads are off on both ends, so every frame is on the wire as npf wrote it.
#
# Per case it checks that each port's frames are identical, in the same order, on every backend
# and af_packet; that the final counters are the same; and, as a check on the topology rather than
# the backends, that af_packet's frames are the ones `npf replay` is expected to write.
#
# The vlan case is compared with each frame's VLAN tag taken out. The kernel takes a tag out of a
# frame before a packet socket reads it, so af_packet and mmap forward the frame untagged
# (README, "Not implemented"). XDP sees the frame before that, and may keep it. Which each
# backend did is reported.
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
if [[ -n ${NPF_IO_BACKENDS:-} ]]; then
  read -ra BACKENDS <<< "$NPF_IO_BACKENDS"
elif ldd "$NPF" 2>/dev/null | grep -q libxdp; then
  BACKENDS=(af_packet mmap xdp:skb xdp:native)
else
  BACKENDS=(af_packet mmap)
fi
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
# A backend's name in the files and messages, "xdp-skb" for "xdp:skb", and its npf run flags.
label_of() { echo "${1/:/-}"; }
args_of() { # args_of <backend>
  if [[ $1 == *:* ]]; then
    echo "--io ${1%%:*} --xdp-mode ${1#*:}"
  else
    echo "--io $1"
  fi
}

live() { # live <case> <backend>
  local name=$1 io args log port
  io=$(label_of "$2")
  read -ra args <<< "$(args_of "$2")"
  log="$WORK/$name.$io.log"
  rm -f "$WORK/npf.pid"
  ip netns exec ns-eqr "$NPF" run "${args[@]}" --config "$WORK/$name.conf" --pidfile "$WORK/npf.pid" \
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
  started=1
  for backend in "${BACKENDS[@]}"; do
    live "$name" "$backend" || started=0
  done
  ((started)) || continue

  reference=$(label_of "${BACKENDS[0]}")
  for backend in "${BACKENDS[@]:1}"; do
    io=$(label_of "$backend")
    same=1
    compare=same-frames
    [[ $name == vlan ]] && compare=same-frames-untagged
    for port in "${PORTS[@]}"; do
      a="$WORK/$name.$reference.p$port.pcap" b="$WORK/$name.$io.p$port.pcap"
      if ! diff=$("${FRAMES[@]}" "$compare" "$a" "$b"); then
        fail "$name: port $port's frames differ between $reference and $io"
        echo "$diff" | sed 's/^/    /'
        same=0
      fi
    done
    counts=""
    for port in "${PORTS[@]}"; do
      counts+="p$port: $("${FRAMES[@]}" count "$WORK/$name.$io.p$port.pcap"), "
    done
    if ((same)); then
      what="byte-identical"
      [[ $name == vlan ]] && what="identical but for any VLAN tag"
      pass "$name: each port's frames $what between $reference and $io (${counts%, })"
    fi
    if diff -q "$WORK/$name.$reference.stats" "$WORK/$name.$io.stats" > /dev/null; then
      pass "$name: the same final counters on $reference and $io"
    else
      fail "$name: the final counters differ ($reference <, $io >)"
      diff "$WORK/$name.$reference.stats" "$WORK/$name.$io.stats" | sed 's/^/    /'
    fi
  done

  for backend in "${BACKENDS[@]}"; do
    io=$(label_of "$backend")
    files=()
    for port in "${PORTS[@]}"; do
      files+=("$WORK/$name.$io.p$port.pcap")
    done
    if [[ $name == vlan ]]; then
      if "${FRAMES[@]}" same-frame-set "$GOLDEN/$name.expected.pcap" "${files[@]}" > /dev/null; then
        pass "$name, $io: the frames are the golden case's expected output, VLAN tag kept"
      elif out=$("${FRAMES[@]}" same-frame-set-untagged "$GOLDEN/$name.expected.pcap" "${files[@]}"); then
        pass "$name, $io: the frames are the golden case's expected output less the VLAN tag"
      else
        fail "$name, $io: the live frames are not the golden case's expected output, even untagged"
        echo "$out" | sed 's/^/    /'
      fi
    elif [[ $io == "$reference" ]]; then
      if out=$("${FRAMES[@]}" same-frame-set "$GOLDEN/$name.expected.pcap" "${files[@]}"); then
        pass "$name: the frames are the golden case's expected output"
      else
        fail "$name: the live frames are not the golden case's expected output"
        echo "$out" | sed 's/^/    /'
      fi
    fi
  done
done

echo
if [[ $failures -eq 0 ]]; then
  echo "IO EQUIVALENCE (${BACKENDS[*]}): PASS"
  exit 0
fi
echo "IO EQUIVALENCE (${BACKENDS[*]}): FAIL ($failures check(s) failed)"
exit 1
