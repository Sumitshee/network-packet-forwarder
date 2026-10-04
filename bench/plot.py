#!/usr/bin/env python3
"""Plots bench_lpm's lookup times from the Google Benchmark JSON it writes.

    python3 bench/plot.py bench/results/<date>-<sha>-bench_lpm.json docs/img/bench_lpm.svg

One panel per key distribution -- uniform, Zipf, sequential -- each showing the median ns per
lookup of every implementation against the table's size, with the band from the fastest to the
slowest repetition shaded. The y axis is logarithmic: the times span three orders of magnitude.
"""

import json
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402  (the backend must be chosen first)

SIZES = ["10", "1k", "100k", "full"]
KEYS = [("uniform", "uniform keys"), ("zipf", "Zipf keys, alpha 0.99"), ("sequential", "sequential keys")]
IMPLS = [("linear", "LinearLpm (oracle)"), ("binary_trie", "BinaryTrie"),
         ("patricia", "PatriciaLpm"), ("dir24_8", "Dir24_8Lpm")]


def main():
    if len(sys.argv) != 3:
        sys.exit(f"usage: {sys.argv[0]} <bench_lpm.json> <out.svg>")
    with open(sys.argv[1]) as f:
        results = json.load(f)
    stats = {}  # (impl, size, keys) -> {"median": ns, "min": ns, "max": ns}
    for b in results["benchmarks"]:
        if b.get("run_type") != "aggregate" or not b["run_name"].startswith("lookup/"):
            continue
        assert b["time_unit"] == "ns", b["name"]
        _, impl, size, keys = b["run_name"].split("/")
        stats.setdefault((impl, size, keys), {})[b["aggregate_name"]] = b["real_time"]

    fig, axes = plt.subplots(1, len(KEYS), figsize=(13, 4.2), sharey=True)
    for ax, (keys, title) in zip(axes, KEYS):
        for impl, label in IMPLS:
            points = [(i, stats[(impl, s, keys)]) for i, s in enumerate(SIZES)
                      if (impl, s, keys) in stats]
            if not points:
                continue
            xs = [i for i, _ in points]
            ax.plot(xs, [p["median"] for _, p in points], marker="o", label=label)
            ax.fill_between(xs, [p["min"] for _, p in points], [p["max"] for _, p in points],
                            alpha=0.2)
        ax.set_title(title)
        ax.set_xticks(range(len(SIZES)), [f"{s} routes" if s != "full" else "full table" for s in SIZES])
        ax.set_yscale("log")
        ax.grid(True, which="both", alpha=0.3)
    axes[0].set_ylabel("ns per lookup (median of the repetitions)")
    axes[-1].legend(loc="upper left", fontsize="small")
    context = results["context"]
    fig.suptitle(f"bench_lpm, commit {context.get('git_sha', '?')}, {context.get('cpu_model', '?')}",
                 fontsize="medium")
    fig.tight_layout()
    fig.savefig(sys.argv[2], metadata={"Date": None})  # no timestamp: the same JSON, the same file


if __name__ == "__main__":
    main()
