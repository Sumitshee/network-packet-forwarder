#!/usr/bin/env bash
# Downloads a RouteViews MRT RIB dump and flattens it to "prefix/len nexthop_id" lines, for
# bench/micro/bench_lpm.cpp (docs/BUILD_PLAN.md phase 10).
#
#   scripts/fetch_bgp_table.sh [YYYYMMDD.HHMM]
#
# The default is the dump the phase 10 measurements used: the route-views2 collector's RIB of
# 2026-10-04 00:00 UTC, archive.routeviews.org/bgpdata/2026.10/RIBS/rib.20261004.0000.bz2, 78.8 MiB.
# RouteViews writes one every two hours. Everything lands in data/, which is gitignored: the script
# is the artefact, not the data. scripts/mrt_to_prefixes.py does the flattening, and draws the
# smaller tables of the benchmark's size sweep from the full one.
set -euo pipefail

stamp=${1:-20261004.0000}
if [[ ! $stamp =~ ^[0-9]{8}\.[0-9]{4}$ ]]; then
  echo "usage: $0 [YYYYMMDD.HHMM]" >&2
  exit 2
fi
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
url="https://archive.routeviews.org/bgpdata/${stamp:0:4}.${stamp:4:2}/RIBS/rib.$stamp.bz2"
dump="$root/data/rib.$stamp.bz2"
mkdir -p "$root/data"

if [[ -s $dump ]]; then
  echo "$dump is already here; not downloading it again"
else
  echo "downloading $url"
  curl --fail --location --retry 3 --output "$dump.part" "$url"
  mv "$dump.part" "$dump"
fi
python3 "$root/scripts/mrt_to_prefixes.py" "$dump" "$root/data"
