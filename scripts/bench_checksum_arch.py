#!/usr/bin/env python3
"""The phase 18 cross-architecture checksum table, from bench_checksum results.

    scripts/bench_checksum_arch.py <name>=<bench_checksum.json> [<name>=<bench_checksum.json> ...]

For each machine, a Markdown table of BM_SumScalar, BM_SumVector (AVX2 or NEON) and BM_SumFast:
the median of the repetitions in ns, with the p95 and the min-max beside it. Then one table across
the machines: the vector sum's median as a speed-up over the scalar one on the same machine. The
vector sum is called faster or slower only where the two ranges do not overlap; otherwise, noise.

Prints only what the files hold; it measures nothing.
"""

import json
import sys

SIZES = (20, 60, 576, 1500)
KINDS = ("BM_SumScalar", "BM_SumVector", "BM_SumFast")


def stats(result):
    """{(kind, size): {"median": ns, "p95": ns, "min": ns, "max": ns, "label": text}}."""
    out = {}
    for b in result["benchmarks"]:
        if b.get("run_type") != "aggregate" or b.get("error_occurred"):
            continue
        kind, _, size = b["run_name"].partition("/")
        if kind not in KINDS:
            continue
        entry = out.setdefault((kind, int(size)), {})
        entry[b["aggregate_name"]] = b["real_time"]
        entry["label"] = b.get("label", "")
    return out


def ns(v):
    return f"{v:.1f}"


def machine_table(name, result):
    s = stats(result)
    c = result["context"]
    print(f"### {name}")
    print()
    print(f"`{c.get('host_name')}`, {c.get('num_cpus')} CPUs at {c.get('mhz_per_cpu')} MHz, "
          f"{c.get('npf_compiler')}, `{c.get('npf_cxx_flags')}`, git {c.get('git_sha')}")
    print()
    print("| bytes | scalar, ns: median (p95; min-max) | vector, ns | fast, ns |")
    print("|---|---|---|---|")
    for size in SIZES:
        cells = []
        for kind in KINDS:
            e = s.get((kind, size))
            if e is None:
                cells.append("-")
                continue
            label = f" {e['label']}" if kind != "BM_SumScalar" and e.get("label") else ""
            cells.append(f"{ns(e['median'])} ({ns(e['p95'])}; {ns(e['min'])}-{ns(e['max'])}){label}")
        print(f"| {size} | " + " | ".join(cells) + " |")
    print()
    return s


def verdict(scalar, vector):
    if vector["max"] < scalar["min"]:
        return "faster"
    if vector["min"] > scalar["max"]:
        return "slower"
    return "noise"


def main(argv):
    if len(argv) < 2 or any("=" not in a for a in argv[1:]):
        print(__doc__, file=sys.stderr)
        return 2
    machines = []
    for arg in argv[1:]:
        name, path = arg.split("=", 1)
        with open(path, encoding="utf-8") as f:
            machines.append((name, machine_table(name, json.load(f))))
    print("### The vector sum against the scalar one, on each machine")
    print()
    print("| bytes | " + " | ".join(name for name, _ in machines) + " |")
    print("|---|" + "---|" * len(machines))
    for size in SIZES:
        cells = []
        for _, s in machines:
            sc, vec = s.get(("BM_SumScalar", size)), s.get(("BM_SumVector", size))
            if sc is None or vec is None:
                cells.append("-")
                continue
            cells.append(f"{sc['median'] / vec['median']:.2f}x, {verdict(sc, vec)} ({vec['label']})")
        print(f"| {size} | " + " | ".join(cells) + " |")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
