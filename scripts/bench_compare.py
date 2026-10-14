#!/usr/bin/env python3
"""Compares a before and an after build of the same microbenchmarks, by the phase 15 noise rule.

    bench_compare.py --name <name> --before-ref <sha> --after-ref <text> --out <result.json>
                     [--cmake-before ...] [--cmake-after ...] [--diff <file>]
                     before-1.json after-1.json after-2.json before-2.json

Takes the four Google Benchmark JSONs scripts/ab_bench.sh writes -- before, after, after, before,
each 7 repetitions -- and for every benchmark and both metrics, ns per packet (the iteration's
real time divided by its `packets` counter, 1 where there is none) and cycles per packet (where
the benchmark counts them):

  - each side's 14 repetitions: median, p95 (nearest rank), min and max;
  - the delta, the after median minus the before median, in units and in percent;
  - each round's delta on its own, from its 7 repetitions a side;
  - the verdict. The change is NOISE if |delta| is smaller than the larger of the two sides'
    p95 - median, or if the two rounds' deltas differ in sign; otherwise it is FASTER or SLOWER.

Writes all of it, with the four inputs whole, to --out, and prints a table. Standard library only.
"""

import argparse
import json
import math
import statistics
import sys


def nearest_rank(values, q):
    s = sorted(values)
    return s[max(math.ceil(q * len(s)), 1) - 1]


def repetitions(path):
    """{benchmark: {"ns": [...], "cycles": [...]}} from one run's per-repetition rows."""
    with open(path) as f:
        data = json.load(f)
    out = {}
    for b in data["benchmarks"]:
        if b.get("run_type") != "iteration" or b.get("error_occurred"):
            continue
        assert b["time_unit"] == "ns", b["name"]
        packets = b.get("packets", 1)
        reps = out.setdefault(b["run_name"], {"ns": [], "cycles": []})
        reps["ns"].append(b["real_time"] / packets)
        if "cycles_per_packet" in b:
            reps["cycles"].append(b["cycles_per_packet"])
    return out, data


def side(values):
    median = statistics.median(values)
    return {"median": median, "p95": nearest_rank(values, 0.95), "min": min(values),
            "max": max(values), "n": len(values)}


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--name", required=True)
    parser.add_argument("--before-ref", required=True)
    parser.add_argument("--after-ref", required=True)
    parser.add_argument("--cmake-before", default="")
    parser.add_argument("--cmake-after", default="")
    parser.add_argument("--diff")
    parser.add_argument("--out", required=True)
    parser.add_argument("runs", nargs=4)
    args = parser.parse_args()

    (b1, b1_raw), (a1, a1_raw), (a2, a2_raw), (b2, b2_raw) = map(repetitions, args.runs)
    results = {}
    for bench in b1:
        results[bench] = {}
        for metric in ("cycles", "ns"):
            before = b1[bench][metric] + b2[bench][metric]
            after = a1[bench][metric] + a2[bench][metric]
            if not before or not after:
                continue
            sb, sa = side(before), side(after)
            delta = sa["median"] - sb["median"]
            band = max(sb["p95"] - sb["median"], sa["p95"] - sa["median"])
            rounds = [statistics.median(a1[bench][metric]) - statistics.median(b1[bench][metric]),
                      statistics.median(a2[bench][metric]) - statistics.median(b2[bench][metric])]
            agree = (rounds[0] > 0) == (rounds[1] > 0)
            verdict = "NOISE" if abs(delta) < band or not agree else (
                "FASTER" if delta < 0 else "SLOWER")
            results[bench][metric] = {"before": sb, "after": sa, "delta": delta,
                                      "delta_pct": 100.0 * delta / sb["median"], "noise_band": band,
                                      "round_deltas": rounds, "verdict": verdict}

    diff = open(args.diff).read() if args.diff else ""
    out = {
        "name": args.name,
        "before": {"git_sha": args.before_ref, "cmake_args": args.cmake_before},
        "after": {"source": args.after_ref, "cmake_args": args.cmake_after, "diff": diff},
        "order": ["before", "after", "after", "before"],
        "comparison": results,
        "runs": [b1_raw, a1_raw, a2_raw, b2_raw],
    }
    text = json.dumps(out, indent=1, allow_nan=False)
    with open(args.out, "w") as f:
        f.write(text + "\n")

    print(f"{'benchmark':44s} {'metric':6s} {'before':>9s} {'after':>9s} {'delta':>9s} "
          f"{'%':>7s} {'band':>8s}  rounds            verdict")
    for bench, metrics in results.items():
        for metric, r in metrics.items():
            print(f"{bench:44s} {metric:6s} {r['before']['median']:9.2f} {r['after']['median']:9.2f} "
                  f"{r['delta']:9.2f} {r['delta_pct']:7.1f} {r['noise_band']:8.2f}  "
                  f"{r['round_deltas'][0]:7.2f} {r['round_deltas'][1]:7.2f}  {r['verdict']}")
    print(f"bench_compare: wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
