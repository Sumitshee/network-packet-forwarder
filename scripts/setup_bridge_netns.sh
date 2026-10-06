#!/usr/bin/env bash
# Builds the phase 12 switching topology (docs/BUILD_PLAN.md): three hosts in one IP subnet, each
# a veth away from the router, which bridges all three ports (configs/bridge.conf).
#
#   ns-h1  10.0.9.1/24  eth0 <-> veth-h1 \
#   ns-h2  10.0.9.2/24  eth0 <-> veth-h2 -- ns-router [npf, ports 0 to 2, bridge domain 1]
#   ns-h3  10.0.9.3/24  eth0 <-> veth-h3 /
#
#   h1 aa:bb:cc:00:09:01   h2 aa:bb:cc:00:09:02   h3 aa:bb:cc:00:09:03
#
# The router's interfaces carry no addresses and its kernel neither forwards nor bridges: frames
# cross only if npf switches them. The hosts' MACs are fixed so tests can recognise their frames,
# and IPv6 is off everywhere, so the hosts send nothing a test did not ask for, and a station falls
# silent when the test does. Needs root. Undo with scripts/cleanup_bridge_netns.sh.
set -euo pipefail

if [[ $(id -u) -ne 0 ]]; then
  echo "setup_bridge_netns.sh: must run as root (sudo)" >&2
  exit 1
fi
for ns in ns-h1 ns-h2 ns-h3 ns-router; do
  if ip netns list | awk '{print $1}' | grep -qx "$ns"; then
    echo "setup_bridge_netns.sh: $ns already exists; run scripts/cleanup_bridge_netns.sh first," \
      "or scripts/cleanup_netns.sh if it is the routing topology's" >&2
    exit 1
  fi
done

ip netns add ns-router
for n in 1 2 3; do
  ip netns add "ns-h$n"
  ip link add "veth-h$n" type veth peer name "h$n-eth0"
  ip link set "veth-h$n" netns ns-router
  ip link set "h$n-eth0" netns "ns-h$n"
done

# Before any link comes up: a host with IPv6 sends router solicitations and duplicate-address
# probes as soon as its link is up, and every one would teach the switch, or refresh, its MAC.
for ns in ns-h1 ns-h2 ns-h3 ns-router; do
  ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 \
    net.ipv6.conf.default.disable_ipv6=1 2>/dev/null || true
done

for n in 1 2 3; do
  ip netns exec "ns-h$n" ip link set "h$n-eth0" name eth0
  ip netns exec "ns-h$n" ip link set eth0 address "aa:bb:cc:00:09:0$n"
  ip netns exec "ns-h$n" ip addr add "10.0.9.$n/24" dev eth0
  ip netns exec "ns-h$n" ip link set eth0 up
  ip netns exec "ns-h$n" ip link set lo up
  ip netns exec ns-router ip link set "veth-h$n" up
done
ip netns exec ns-router sysctl -qw net.ipv4.ip_forward=0

# With offload on, veth hands over frames with zero or partial checksums, expecting hardware that
# does not exist to fill them in. Some features cannot be changed on some kernels; that must not
# abort the setup.
for ns in ns-h1 ns-h2 ns-h3 ns-router; do
  ip netns exec "$ns" sh -c 'for i in $(ls /sys/class/net | grep -E "veth|eth0"); do
      ethtool -K "$i" tx off rx off tso off gso off gro off 2>/dev/null || true; done'
done
