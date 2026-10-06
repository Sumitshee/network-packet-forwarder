#!/usr/bin/env bash
# Removes everything scripts/setup_bridge_netns.sh creates. Safe to run when none of it exists.
# Needs root.
set -uo pipefail

if [[ $(id -u) -ne 0 ]]; then
  echo "cleanup_bridge_netns.sh: must run as root (sudo)" >&2
  exit 1
fi

for ns in ns-h1 ns-h2 ns-h3 ns-router; do
  ip netns del "$ns" 2>/dev/null || true
done

# Deleting a namespace destroys the veths inside it, and a veth pair dies with either end. These
# survive only if setup failed before moving them out of the root namespace.
for n in 1 2 3; do
  ip link del "veth-h$n" 2>/dev/null || true
done
