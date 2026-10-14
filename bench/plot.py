#!/usr/bin/env python3
"""Plots benchmark results.

    python3 bench/plot.py
        The baseline charts of the newest bench/results/<date>-<sha>.json that scripts/run_bench.sh
        wrote, into docs/img/:
          baseline_tier_a.svg      tier A: ns per packet of every bench_datapath benchmark, the
                                   median of the repetitions, with their min to max as a bar
          baseline_throughput.svg  tier B: datagrams per second offered and delivered, and loss,
                                   for every configuration, the kernel control first
          baseline_latency.svg     tier B: one-way latency at 20,000 datagrams a second, p50, p95
                                   and p99, for every configuration
    python3 bench/plot.py <result.json>
        The same, from that file.
    python3 bench/plot.py <date>-<sha>-bench_lpm.json <out.svg>
        bench_lpm's lookup times (phase 10): one panel per key distribution -- uniform, Zipf,
        sequential -- each showing the median ns per lookup of every implementation against the
        table's size, with the band from the fastest to the slowest repetition shaded, on a
        logarithmic axis.

Every SVG is written without a timestamp and with fixed element ids, so the same JSON gives the
same files, byte for byte.
"""

import glob
import json
import os
import sys

import matplotlib

matplotlib.use("Agg")
matplotlib.rcParams["svg.hashsalt"] = "npf"  # else the SVG's element ids are random per run
import matplotlib.pyplot as plt  # noqa: E402  (the backend must be chosen first)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SIZES = ["10", "1k", "100k", "full"]
KEYS = [("uniform", "uniform keys"), ("zipf", "Zipf keys, alpha 0.99"), ("sequential", "sequential keys")]
IMPLS = [("linear", "LinearLpm (oracle)"), ("binary_trie", "BinaryTrie"),
         ("patricia", "PatriciaLpm"), ("dir24_8", "Dir24_8Lpm")]


def save(fig, path):
    fig.tight_layout()
    fig.savefig(path, metadata={"Date": None})  # no timestamp: the same JSON, the same file
    plt.close(fig)
    print(f"plot.py: wrote {os.path.relpath(path, ROOT)}")


# --- bench_lpm (phase 10) ------------------------------------------------------------------------

def plot_lpm(json_path, out):
    matplotlib.rcParams["svg.hashsalt"] = "bench_lpm"
    with open(json_path) as f:
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
    axes[-1].legend(loc="upper right", fontsize="small")  # clear of the lines in that corner
    context = results["context"]
    fig.suptitle(f"bench_lpm, commit {context.get('git_sha', '?')}, {context.get('cpu_model', '?')}",
                 fontsize="medium")
    save(fig, out)


# --- the baseline (phase 14) ---------------------------------------------------------------------

def newest_result():
    paths = [p for p in glob.glob(os.path.join(ROOT, "bench", "results", "*.json"))
             if "bench_" not in os.path.basename(p)]
    if not paths:
        sys.exit("plot.py: no bench/results/<date>-<sha>.json: run scripts/run_bench.sh --all first")
    return max(paths, key=os.path.getmtime)


def title(result, what):
    c = result["context"]
    return f"{what}\ncommit {c['git_sha'][:7]}, {c['cpu_model']}"


def plot_tier_a(result, out):
    gb = result["tier_a"]["bench_datapath"]
    stats = {}
    for b in gb["benchmarks"]:
        if b.get("run_type") == "aggregate" and b["aggregate_name"] in ("median", "min", "max"):
            per_packet = b["real_time"] / b.get("packets", 1)  # every iteration is one burst
            stats.setdefault(b["run_name"], {})[b["aggregate_name"]] = per_packet
    names = list(stats)
    fig, ax = plt.subplots(figsize=(10, 0.32 * len(names) + 1.2))
    ys = range(len(names))
    medians = [stats[n]["median"] for n in names]
    ax.barh(ys, medians, color="#4c72b0")
    ax.errorbar(medians, ys, xerr=[[m - stats[n]["min"] for n, m in zip(names, medians)],
                                   [stats[n]["max"] - m for n, m in zip(names, medians)]],
                fmt="none", ecolor="black", capsize=2, linewidth=0.8)
    for y, n, m in zip(ys, names, medians):  # past the end of the error bar, clear of it
        ax.text(stats[n]["max"], y, f"  {m:.1f}", va="center", fontsize="x-small")
    ax.set_yticks(list(ys), names, fontsize="small")
    ax.invert_yaxis()
    ax.set_xlabel("ns per packet (median of the repetitions; bar: min to max)")
    ax.grid(True, axis="x", alpha=0.3)
    ax.set_title(title(result, "bench_datapath, tier A"), fontsize="medium")
    save(fig, out)


def label(config):
    if config["config"] == "kernel":
        return "kernel control"
    return f"npf {config['mode']}, {config['workers']} worker{'s' if config['workers'] > 1 else ''}"


def ordered(result):
    configs = result["tier_b"]["configurations"]
    return sorted(configs, key=lambda c: (c["config"] != "kernel", c.get("mode") or "",
                                         c.get("workers") or 0))


def plot_throughput(result, out):
    configs = ordered(result)
    names = [label(c) for c in configs]
    summaries = [c["scenarios"]["throughput"]["summary"] for c in configs]
    fig, (ax, ax_loss) = plt.subplots(1, 2, figsize=(12, 0.45 * len(names) + 1.5),
                                      gridspec_kw={"width_ratios": [3, 1]}, sharey=True)
    ys = list(range(len(names)))
    offered = [s["offered_pps"]["median"] / 1e3 for s in summaries]
    delivered = [s["delivered_pps"]["median"] / 1e3 for s in summaries]
    ax.barh([y - 0.2 for y in ys], offered, height=0.4, color="#c0c0c0", label="offered by gen")
    ax.barh([y + 0.2 for y in ys], delivered, height=0.4, color="#4c72b0", label="delivered to sink")
    ax.errorbar(delivered, [y + 0.2 for y in ys],
                xerr=[[d - s["delivered_pps"]["min"] / 1e3 for d, s in zip(delivered, summaries)],
                      [s["delivered_pps"]["max"] / 1e3 - d for d, s in zip(delivered, summaries)]],
                fmt="none", ecolor="black", capsize=2, linewidth=0.8)
    for y, d, s in zip(ys, delivered, summaries):
        ax.text(s["delivered_pps"]["max"] / 1e3, y + 0.2, f"  {d:.0f}k", va="center",
                fontsize="x-small")
    ax.set_yticks(ys, names)
    ax.invert_yaxis()
    ax.set_xlabel("thousand datagrams per second (median of the repetitions; bar: min to max)")
    ax.legend(loc="lower right", fontsize="small")
    ax.grid(True, axis="x", alpha=0.3)
    loss = [s["loss_pct"]["median"] for s in summaries]
    ax_loss.barh(ys, loss, color="#dd8452")
    for y, v in zip(ys, loss):
        ax_loss.text(v, y, f" {v:.1f}%", va="center", fontsize="x-small")
    ax_loss.set_xlabel("loss, % (median)")
    ax_loss.grid(True, axis="x", alpha=0.3)
    fig.suptitle(title(result, "tier B, gen as fast as it can, 16 flows, 70-byte frames"),
                 fontsize="medium")
    save(fig, out)


def plot_latency(result, out):
    configs = ordered(result)
    names = [label(c) for c in configs]
    summaries = [c["scenarios"]["latency"]["summary"] for c in configs]
    fig, ax = plt.subplots(figsize=(10, 0.45 * len(names) + 1.5))
    ys = list(range(len(names)))
    for offset, (q, colour) in zip((-0.27, 0, 0.27),
                                   (("p50", "#4c72b0"), ("p95", "#55a868"), ("p99", "#c44e52"))):
        values = [s[f"latency_{q}_ns"]["median"] / 1e3 for s in summaries]
        ax.barh([y + offset for y in ys], values, height=0.27, color=colour, label=q)
        for y, v in zip(ys, values):
            ax.text(v, y + offset, f" {v:.0f}", va="center", fontsize="xx-small")
    ax.set_xscale("log")
    ticks = [10, 20, 50, 100, 200, 500, 1000]
    ax.set_xticks(ticks, [str(t) for t in ticks])
    ax.set_yticks(ys, names)
    ax.invert_yaxis()
    ax.set_xlabel("one-way latency, µs, log scale (median over the repetitions of each percentile)")
    ax.legend(loc="lower right", fontsize="small")
    ax.grid(True, axis="x", which="both", alpha=0.3)
    ax.set_title(title(result, "tier B, 20,000 datagrams a second, 16 flows, 70-byte frames"),
                 fontsize="medium")
    save(fig, out)


def plot_baseline(path):
    with open(path) as f:
        result = json.load(f)
    img = os.path.join(ROOT, "docs", "img")
    if "tier_a" in result and "bench_datapath" in result["tier_a"]:
        plot_tier_a(result, os.path.join(img, "baseline_tier_a.svg"))
    if "tier_b" in result:
        plot_throughput(result, os.path.join(img, "baseline_throughput.svg"))
        plot_latency(result, os.path.join(img, "baseline_latency.svg"))


def main():
    if len(sys.argv) == 3:
        plot_lpm(sys.argv[1], sys.argv[2])
    elif len(sys.argv) == 2:
        plot_baseline(sys.argv[1])
    elif len(sys.argv) == 1:
        plot_baseline(newest_result())
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
