#!/usr/bin/env python3
"""The phase 16 comparison of the socket backends, from run_bench.sh --compare-io results.

    scripts/bench_compare_io.py <result.json> [<result.json> ...]

For each result -- one session -- a Markdown table: per configuration, af_packet's and mmap's
delivered rate as fast as gen can send (median, with the repetitions' min-max), loss, npf's CPU
and the latency at 20,000 datagrams a second, with the kernel control above them, and mmap's
delivered rate as a ratio of af_packet's in the same session. Given more than one result, a last
table sets the sessions' medians side by side as a range: comparisons are made within a session,
and the range is how far one session's numbers can be trusted to stand for another's
(docs/performance.md, phase 15).

Prints only what the files hold; it measures nothing.
"""

import json
import sys


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def configurations(result):
    """{(mode, workers, io): configuration}, the kernel control under (None, None, "kernel")."""
    out = {}
    for c in result.get("tier_b", {}).get("configurations", []):
        if c["config"] == "kernel":
            out[(None, None, "kernel")] = c
        else:
            out[(c["mode"], c["workers"], c.get("io", "af_packet"))] = c
    return out


def summary(c, scenario, metric):
    return c["scenarios"][scenario]["summary"].get(metric)


def kpps(s):
    return f"{s['median'] / 1000:.1f} ({s['min'] / 1000:.1f}-{s['max'] / 1000:.1f})"


def micros(s):
    return f"{s['median'] / 1000:.1f}"


def row(name, c):
    delivered = summary(c, "throughput", "delivered_pps")
    loss = summary(c, "throughput", "loss_pct")
    cpu = summary(c, "throughput", "npf_cpu_pct")
    p50 = summary(c, "latency", "latency_p50_ns")
    p99 = summary(c, "latency", "latency_p99_ns")
    cpu_text = f"{cpu['median']:.0f}" if cpu else "-"
    return (f"| {name} | {kpps(delivered)} | {loss['median']:.1f} | {cpu_text} | "
            f"{micros(p50)} | {micros(p99)} |")


def label(key):
    mode, workers, io = key
    return "kernel control" if io == "kernel" else f"{mode}:{workers}, {io}"


def session_table(path, result):
    configs = configurations(result)
    ctx = result.get("context", {})
    print(f"### {path}")
    print()
    print(f"git {ctx.get('git_sha', '?')[:12]}, {ctx.get('date_utc', '?')}")
    print()
    print("| configuration | delivered, kpps: median (min-max) | loss, % | npf CPU, % "
          "| p50 latency at 20 kpps, us | p99, us |")
    print("|---|---|---|---|---|---|")
    for key in sorted(configs, key=lambda k: (k[2] != "kernel", k[0] or "", k[1] or 0, k[2])):
        print(row(label(key), configs[key]))
    print()
    ratios = []
    for (mode, workers, io), c in sorted(configs.items(), key=lambda kv: str(kv[0])):
        if io != "mmap" or (mode, workers, "af_packet") not in configs:
            continue
        a = summary(configs[(mode, workers, "af_packet")], "throughput", "delivered_pps")["median"]
        m = summary(c, "throughput", "delivered_pps")["median"]
        ratios.append(f"{mode}:{workers} {m / a:.2f}x")
    if ratios:
        print("mmap's delivered median over af_packet's, this session: " + ", ".join(ratios))
        print()
    return configs


def range_table(sessions):
    keys = sorted(set().union(*[set(s) for s in sessions]),
                  key=lambda k: (k[2] != "kernel", k[0] or "", k[1] or 0, k[2]))
    print(f"### Across {len(sessions)} sessions: the range of the session medians")
    print()
    print("| configuration | delivered, kpps | p50 latency at 20 kpps, us | p99, us |")
    print("|---|---|---|---|")
    for key in keys:
        present = [s[key] for s in sessions if key in s]
        if len(present) < len(sessions):
            continue

        def span(scenario, metric, scale):
            values = [summary(c, scenario, metric)["median"] / scale for c in present]
            return f"{min(values):.1f}-{max(values):.1f}"

        print(f"| {label(key)} | {span('throughput', 'delivered_pps', 1000)} | "
              f"{span('latency', 'latency_p50_ns', 1000)} | {span('latency', 'latency_p99_ns', 1000)} |")
    print()


def main(argv):
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    sessions = [session_table(path, load(path)) for path in argv[1:]]
    if len(sessions) > 1:
        range_table(sessions)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
