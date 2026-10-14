#!/usr/bin/env python3
"""A tier B before/after comparison, from run_bench.sh results run in one session.

    scripts/bench_compare_tier_b.py --before <a.json> [<a.json> ...] --after <b.json> [...]

The session runs the before build, then the after build, then the before build again: a
sandwich, so that drift during the session shows as before runs that disagree. For every npf
configuration (mode, workers, io) present on both sides, and for each metric, it prints each
side's median, and the range of its repetitions (all before runs pooled, all after runs pooled):

  - delivered datagrams a second, and loss, as fast as gen can send;
  - p50 and p99 latency at 20,000 datagrams a second;
  - and, from npf's final counters, RingFull and kernel_rx_drops, summed over the runs.

The verdict, tier B's version of the phase 15 noise rule:
  - NOISE if the after median lies inside the before repetitions' range, or if the before runs'
    own medians lie on both sides of it;
  - otherwise HIGHER or LOWER.

Prints only what the files hold; it measures nothing. Standard library only.
"""

import argparse
import json
import statistics
import sys

METRICS = [
    ("throughput", "delivered_pps", "delivered, pps", 1),
    ("throughput", "loss_pct", "loss, %", 1),
    ("latency", "latency_p50_ns", "p50 latency at 20 kpps, us", 1000),
    ("latency", "latency_p99_ns", "p99 latency at 20 kpps, us", 1000),
]


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def configurations(result):
    out = {}
    for c in result.get("tier_b", {}).get("configurations", []):
        if c["config"] == "npf":
            out[(c["mode"], c["workers"], c.get("io", "af_packet"))] = c
    return out


def values(c, scenario, metric):
    """Every repetition's value of one metric."""
    out = []
    for rep in c["scenarios"][scenario]["repetitions"]:
        if metric in rep:
            out.append(rep[metric])
        elif metric.startswith("latency_"):
            out.append(rep["sink"]["latency_ns"][metric[len("latency_"):-len("_ns")]])
    return out


def verdict(before_runs, after_values):
    pooled = [v for run in before_runs for v in run]
    after = statistics.median(after_values)
    if min(pooled) <= after <= max(pooled):
        return "NOISE"
    medians = [statistics.median(run) for run in before_runs]
    if any(m < after for m in medians) and any(m > after for m in medians):
        return "NOISE"
    return "HIGHER" if after > max(pooled) else "LOWER"


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--before", nargs="+", required=True)
    parser.add_argument("--after", nargs="+", required=True)
    args = parser.parse_args(argv[1:])
    before = [configurations(load(p)) for p in args.before]
    after = [configurations(load(p)) for p in args.after]
    keys = sorted(set().union(*before) & set().union(*after))
    if not keys:
        print("no configuration is on both sides", file=sys.stderr)
        return 1
    print("| configuration | metric | before: median (min-max) | after: median (min-max) | verdict |")
    print("|---|---|---|---|---|")
    for key in keys:
        name = f"{key[0]}:{key[1]}, {key[2]}"
        b_configs = [b[key] for b in before if key in b]
        a_configs = [a[key] for a in after if key in a]
        for scenario, metric, unit, scale in METRICS:
            b_runs = [values(c, scenario, metric) for c in b_configs]
            a_values = [v for c in a_configs for v in values(c, scenario, metric)]
            pooled = [v for run in b_runs for v in run]
            print(f"| {name} | {unit} | {statistics.median(pooled) / scale:.1f} "
                  f"({min(pooled) / scale:.1f}-{max(pooled) / scale:.1f}) | "
                  f"{statistics.median(a_values) / scale:.1f} "
                  f"({min(a_values) / scale:.1f}-{max(a_values) / scale:.1f}) | "
                  f"{verdict(b_runs, a_values)} |")
        for counter in ("RingFull", "kernel_rx_drops"):
            b_sum = sum(c.get("npf_final_counters", {}).get(counter, 0) for c in b_configs)
            a_sum = sum(c.get("npf_final_counters", {}).get(counter, 0) for c in a_configs)
            print(f"| {name} | {counter}, summed over the runs | {b_sum} | {a_sum} | |")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
