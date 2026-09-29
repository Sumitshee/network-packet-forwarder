#!/usr/bin/env bash
# Removes everything scripts/setup_netns.sh creates. Safe to run when none of it exists. Needs root.
set -uo pipefail

if [[ $(id -u) -ne 0 ]]; then
  echo "cleanup_netns.sh: must run as root (sudo)" >&2
  exit 1
fi

for ns in ns-client ns-router ns-server; do
  ip netns del "$ns" 2>/dev/null || true
done

# Deleting a namespace destroys the veths inside it, and a veth pair dies with either end. These
# two survive only if setup failed before moving them out of the root namespace.
for link in veth-c veth-s; do
  ip link del "$link" 2>/dev/null || true
done
