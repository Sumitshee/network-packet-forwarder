#!/usr/bin/env bash
# Builds the three-namespace test topology (docs/BUILD_PLAN.md, phase 0.5):
#
#   ns-client                 ns-router                ns-server
#   10.0.1.2/24    veth-c <-> veth-cr  [npf]  veth-sr <-> veth-s    10.0.2.2/24
#   gw 10.0.1.1                no IP addresses                     gw 10.0.2.1
#   aa:bb:cc:dd:ee:01                                     aa:bb:cc:dd:ee:02
#
# The router's interfaces carry no addresses and kernel forwarding is off: the forwarder owns L3,
# answering ARP for 10.0.1.1 (port 0) and 10.0.2.1 (port 1) itself. The hosts' MACs are fixed,
# so the static ARP entry in configs/router.conf is true and captures are reproducible, and IPv6
# is off everywhere, so the router sees only the traffic a test sends it. Needs root.
# Undo with scripts/cleanup_netns.sh.
set -euo pipefail

if [[ $(id -u) -ne 0 ]]; then
  echo "setup_netns.sh: must run as root (sudo)" >&2
  exit 1
fi
for ns in ns-client ns-router ns-server; do
  if ip netns list | awk '{print $1}' | grep -qx "$ns"; then
    echo "setup_netns.sh: $ns already exists; run scripts/cleanup_netns.sh first" >&2
    exit 1
  fi
done

ip netns add ns-client
ip netns add ns-router
ip netns add ns-server
ip link add veth-c type veth peer name veth-cr
ip link add veth-s type veth peer name veth-sr
ip link set veth-c netns ns-client
ip link set veth-cr netns ns-router
ip link set veth-s netns ns-server
ip link set veth-sr netns ns-router

# Before any link comes up. A host with IPv6 sends router solicitations and duplicate-address
# probes the moment its link is up, and the router would count every one as a bad EtherType.
# Applying it to "all" covers the veths already moved in. A kernel without IPv6 sends none anyway.
for ns in ns-client ns-router ns-server; do
  ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 \
    net.ipv6.conf.default.disable_ipv6=1 2>/dev/null || true
done
ip netns exec ns-client ip link set veth-c address aa:bb:cc:dd:ee:01
ip netns exec ns-server ip link set veth-s address aa:bb:cc:dd:ee:02

ip netns exec ns-client ip addr add 10.0.1.2/24 dev veth-c
ip netns exec ns-client ip link set veth-c up
ip netns exec ns-client ip link set lo up
ip netns exec ns-client ip route add default via 10.0.1.1 dev veth-c

ip netns exec ns-server ip addr add 10.0.2.2/24 dev veth-s
ip netns exec ns-server ip link set veth-s up
ip netns exec ns-server ip link set lo up
ip netns exec ns-server ip route add default via 10.0.2.1 dev veth-s

# If the router's kernel had addresses here it would answer ARP and forward packets behind the
# forwarder's back, and replies it did not send would appear to work.
ip netns exec ns-router ip link set veth-cr up
ip netns exec ns-router ip link set veth-sr up
ip netns exec ns-router sysctl -qw net.ipv4.ip_forward=0
ip netns exec ns-router sysctl -qw net.ipv4.conf.all.arp_ignore=8
ip netns exec ns-router sysctl -qw net.ipv4.conf.all.rp_filter=0

# With offload on, veth hands over frames with zero or partial checksums, expecting hardware that
# does not exist to fill them in, and a userspace parser rejects perfectly good packets. Some
# features cannot be changed on some kernels; that must not abort the setup.
for ns in ns-client ns-router ns-server; do
  ip netns exec "$ns" sh -c 'for i in $(ls /sys/class/net | grep veth); do
      ethtool -K "$i" tx off rx off tso off gso off gro off 2>/dev/null || true; done'
done
