#!/usr/bin/env bash
# One tier A comparison for docs/performance.md (docs/BUILD_PLAN.md phase 15): the same
# microbenchmarks built twice, before and after one change, run in turn on the same machine.
#
#   scripts/ab_bench.sh <name> --bench <bench_x> [--filter <regex>] [--before <ref>]
#                       [--after <ref>] [--cmake-before "<-D...>"] [--cmake-after "<-D...>"]
#
# The before side is <ref> (HEAD by default), checked out in a git worktree. The after side is
# --after <ref> the same way, or else the working tree as it is, uncommitted change and all; the
# result records the diff. Each side is built with the bench preset, plus its --cmake-* arguments,
# into build/ab/<name>/. They then run in the order before, after, after, before -- two rounds, so
# that drift during the run shows as rounds that disagree -- each pinned to CPU 2 (bench_ring: CPUs
# 2 and 4), 7 repetitions, started once the one-minute load average is below 0.5.
# scripts/bench_compare.py turns the four runs into bench/results/<date>-<before sha>-ab-<name>.json
# and prints the comparison, with its verdict by the phase 15 noise rule.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
NAME=""
BENCH=""
FILTER="."
BEFORE=HEAD
AFTER=""
CMAKE_BEFORE=""
CMAKE_AFTER=""
while (($#)); do
  case "$1" in
    --bench) BENCH=$2; shift 2 ;;
    --filter) FILTER=$2; shift 2 ;;
    --before) BEFORE=$2; shift 2 ;;
    --after) AFTER=$2; shift 2 ;;
    --cmake-before) CMAKE_BEFORE=$2; shift 2 ;;
    --cmake-after) CMAKE_AFTER=$2; shift 2 ;;
    -*) echo "ab_bench: unknown option $1" >&2; exit 2 ;;
    *) NAME=$1; shift ;;
  esac
done
[[ -n $NAME && -n $BENCH ]] || { sed -n '2,8p' "${BASH_SOURCE[0]}" >&2; exit 2; }

WORK="$ROOT/build/ab/$NAME"
git_() { git -c safe.directory="$ROOT" -C "$ROOT" "$@"; }

# A side's source tree: a worktree at a ref, or the working tree itself.
source_for() { # source_for <side> <ref or empty>
  if [[ -z $2 ]]; then
    echo "$ROOT"
    return
  fi
  local sha dir
  sha=$(git_ rev-parse "$2")
  dir="$ROOT/build/ab/src/${sha:0:12}"
  # Kept from an earlier comparison when it is already at the ref, so its build is reused.
  if [[ $(git -c safe.directory="$dir" -C "$dir" rev-parse HEAD 2> /dev/null) != "$sha" ]]; then
    git_ worktree remove --force "$dir" > /dev/null 2>&1 || rm -rf "$dir"
    git_ worktree prune
    git_ worktree add --detach "$dir" "$sha" > /dev/null 2>&1
  fi
  echo "$dir"
}

# A ref's build is shared by every comparison that builds it with the same arguments; the working
# tree's is this comparison's own.
build_dir() { # build_dir <side> <ref or empty> <extra cmake arguments>
  if [[ -z $2 ]]; then
    echo "$WORK/$1"
  else
    echo "$ROOT/build/ab/cache/$(git_ rev-parse --short=12 "$2")-$(echo "$3" | md5sum | cut -c1-8)"
  fi
}

build() { # build <side> <source> <extra cmake arguments> <build dir>
  local dir="$4"
  # shellcheck disable=SC2086
  cmake -S "$2" -B "$dir" --preset bench -DNPF_DEPS_DOWNLOAD_DIR="$ROOT/.deps-cache" $3 \
    > "$WORK/$1.configure.log" 2>&1 || { cat "$WORK/$1.configure.log"; exit 1; }
  cmake --build "$dir" -j --target "$BENCH" > "$WORK/$1.build.log" 2>&1 ||
    { tail -30 "$WORK/$1.build.log"; exit 1; }
}

wait_for_idle() {
  for _ in $(seq 60); do
    awk -v l="$(cut -d' ' -f1 /proc/loadavg)" 'BEGIN { exit !(l < 0.5) }' && return
    sleep 5
  done
}

run() { # run <side> <round>
  local cpus=2
  [[ $BENCH == bench_ring ]] && cpus=2,4
  wait_for_idle
  echo "ab_bench: $1, round $2, load $(cut -d' ' -f1 /proc/loadavg)"
  local dir="$BEFORE_DIR"
  [[ $1 == after ]] && dir="$AFTER_DIR"
  (cd "$ROOT" && NPF_BGP_DATA="$ROOT/data" taskset -c "$cpus" "$dir/bench/$BENCH" \
    --benchmark_filter="$FILTER" --benchmark_repetitions=7 --benchmark_min_warmup_time=0.5 \
    --benchmark_report_aggregates_only=false --benchmark_display_aggregates_only=true \
    --benchmark_out="$WORK/$1-$2.json" --benchmark_out_format=json) > "$WORK/$1-$2.txt" 2>&1
}

mkdir -p "$WORK"
BEFORE_SHA=$(git_ rev-parse "$BEFORE")
AFTER_DESC=${AFTER:+$(git_ rev-parse "$AFTER")}
if [[ -z $AFTER ]]; then
  git_ diff "$BEFORE_SHA" -- include src bench CMakeLists.txt cmake configs > "$WORK/after.diff"
  AFTER_DESC="working tree on $(git_ rev-parse HEAD)"
fi
BEFORE_DIR=$(build_dir before "$BEFORE" "$CMAKE_BEFORE")
AFTER_DIR=$(build_dir after "$AFTER" "$CMAKE_AFTER")
build before "$(source_for before "$BEFORE")" "$CMAKE_BEFORE" "$BEFORE_DIR"
build after "$(source_for after "$AFTER")" "$CMAKE_AFTER" "$AFTER_DIR"
run before 1
run after 1
run after 2
run before 2

OUT="$ROOT/bench/results/$(date -u +%F)-${BEFORE_SHA:0:7}-ab-$NAME.json"
python3 "$ROOT/scripts/bench_compare.py" --name "$NAME" --before-ref "$BEFORE_SHA" \
  --after-ref "$AFTER_DESC" --cmake-before "$CMAKE_BEFORE" --cmake-after "$CMAKE_AFTER" \
  --diff "$WORK/after.diff" --out "$OUT" \
  "$WORK/before-1.json" "$WORK/after-1.json" "$WORK/after-2.json" "$WORK/before-2.json"
if [[ -n ${SUDO_UID:-} ]]; then
  chown "$SUDO_UID:$SUDO_GID" "$OUT"
fi
