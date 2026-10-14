#!/usr/bin/env python3
"""Turns one run of scripts/run_bench.sh into the result file that is committed as evidence.

    bench_combine.py <raw dir> --build <build tree> --out <result.json> [--quick]

Reads what the run left in bench/results/raw/<date>-<sha>/ -- tier_a/<bench>.json, Google
Benchmark's output, and tier_b/<config>/<scenario>/<rep>.{gen,sink,cpu}.json with each
configuration's meta.json and npf.log -- and writes one JSON object:

  context  everything CLAUDE.md section 9 and docs/BUILD_PLAN.md phase 14 require of a result:
           git SHA, ISO date, uname -r, the CPU model from lscpu, the compiler and its version, the
           CMake preset and the compile command actually used, burst and pool size, whether
           `perf stat -e cycles` succeeded, and the rest
  tier_a   each microbenchmark's Google Benchmark JSON, whole
  tier_b   the method, then per configuration and scenario every repetition, as measured and as
           derived (delivered datagrams per second, loss), and their median, p95, min and max

Before writing, it checks the run: no NaN or infinity anywhere, every benchmark free of errors with
a time above zero, and every tier B repetition with datagrams sent and received, every flow seen,
latencies above zero and none negative, npf's CPU time and peak RSS measured, and npf's final
counters balanced. A run that fails a check is reported, and nothing is written. Standard library
only.
"""

import argparse
import glob
import json
import math
import os
import re
import shlex
import statistics
import subprocess
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DROPS = ["ShortFrame", "BadEtherType", "BadIpv4Header", "BadChecksum", "MartianSource",
         "TtlExpired", "NoRoute", "ArpUnresolved", "FilterDeny", "NoOutPort", "UnknownDestPort",
         "SamePort", "RingFull", "TxFull", "PoolExhausted"]
EXPECTED_FLOWS = 16

problems = []


def problem(text):
    problems.append(text)


def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return p.returncode, (p.stdout + p.stderr).strip()


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# --- context -------------------------------------------------------------------------------------

def cmake_cache(build):
    cache = {}
    with open(os.path.join(build, "CMakeCache.txt"), encoding="utf-8") as f:
        for line in f:
            m = re.match(r"^([A-Za-z_]+):[A-Z]+=(.*)$", line.strip())
            if m:
                cache[m.group(1)] = m.group(2)
    return cache


def compile_command(build, source):
    for entry in load(os.path.join(build, "compile_commands.json")):
        if entry["file"].endswith(source):
            return entry.get("command") or shlex.join(entry["arguments"])
    return None


def router_setting(name, raw):
    # The configuration npf ran, as run_bench.sh copied it into the raw directory; before that copy
    # existed, configs/router.conf.
    path = os.path.join(raw, "router.conf")
    if not os.path.exists(path):
        path = os.path.join(ROOT, "configs", "router.conf")
    with open(path, encoding="utf-8") as f:
        for line in f:
            words = line.split("#")[0].split()
            if len(words) == 2 and words[0] == name:
                return int(words[1])
    return None


def lscpu_model():
    _, out = run(["lscpu"])
    for line in out.splitlines():
        if line.startswith("Model name:"):
            return line.split(":", 1)[1].strip()
    return None


def tsc_flags():
    with open("/proc/cpuinfo", encoding="utf-8") as f:
        for line in f:
            if line.startswith("flags"):
                return sorted(set(line.split(":", 1)[1].split()) &
                              {"tsc", "constant_tsc", "nonstop_tsc", "tsc_reliable", "tsc_known_freq"})
    return []


def context(args, tier_a):
    cache = cmake_cache(args.build)
    compiler = cache.get("CMAKE_CXX_COMPILER")
    _, version = run([compiler, "--version"]) if compiler else (1, "")
    src = args.source
    _, sha = run(["git", "-c", f"safe.directory={src}", "-C", src, "rev-parse", "HEAD"])
    _, dirty = run(["git", "-c", f"safe.directory={src}", "-C", src, "status", "--porcelain", "--", ".", ":!bench/results",
                    ":!docs/performance.md", ":!docs/img"])
    code, perf = run(["sh", "-c", "perf stat -e cycles true"])
    datapath = tier_a.get("bench_datapath", {}).get("context", {})
    return {
        "git_sha": sha,
        "git_tree_clean": dirty == "",
        "date_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "uname_r": os.uname().release,
        "cpu_model": lscpu_model(),
        "cpus_online": os.cpu_count(),
        "tsc_flags": tsc_flags(),
        "compiler": version.splitlines()[0] if version else None,
        "cmake_preset": os.path.basename(os.path.normpath(args.build)),
        "cmake_build_type": cache.get("CMAKE_BUILD_TYPE"),
        "compile_command_npf": compile_command(args.build, "src/main.cpp"),
        "compile_command_bench_datapath": compile_command(args.build, "bench/micro/bench_datapath.cpp"),
        "burst": router_setting("burst", args.raw),
        "pool_size": router_setting("pool_size", args.raw),
        "perf_stat_cycles": {"succeeded": code == 0, "output": perf[-300:]},
        "perf_event_open_cycles": datapath.get("npf_perf_event_open_cycles"),
        "quick_rehearsal": args.quick,
    }


# --- tier A --------------------------------------------------------------------------------------

def tier_a(raw):
    out = {}
    for path in sorted(glob.glob(os.path.join(raw, "tier_a", "*.json"))):
        name = os.path.splitext(os.path.basename(path))[0]
        results = load(path)
        for b in results["benchmarks"]:
            if b.get("error_occurred"):
                problem(f"tier A {name}: {b['name']}: {b.get('error_message')}")
            elif b.get("aggregate_name") in ("mean", "median", "min", "max", "p95") and \
                    not b.get("real_time", 0) > 0:
                problem(f"tier A {name}: {b['name']} has no time")
        out[name] = results
    return out


# --- tier B --------------------------------------------------------------------------------------

def nearest_rank(values, q):
    s = sorted(values)
    return s[max(math.ceil(q * len(s)), 1) - 1]


def spread(values):
    return {"median": statistics.median(values), "p95": nearest_rank(values, 0.95),
            "min": min(values), "max": max(values), "n": len(values)}


def final_counters(log_path):
    counters = {}
    seen = False
    with open(log_path, encoding="utf-8") as f:
        for line in f:
            if "final counters" in line:
                seen = True
                continue
            words = line.split()
            if seen and len(words) == 2 and words[1].isdigit():
                counters[words[0]] = int(words[1])
    return counters


def repetition(where, gen, sink, cpu, npf):
    rep = {"gen": gen, "sink": sink, "cpu": cpu}
    sent, received = gen["sent"], sink["received"]
    if sent <= 0 or received <= 0:
        problem(f"{where}: {sent} sent, {received} received")
        return rep
    rep["offered_pps"] = gen["per_second"]
    rep["delivered_pps"] = received / gen["seconds"]
    rep["loss_pct"] = 100.0 * (sent - received) / sent
    if sink["flows_seen"] != EXPECTED_FLOWS:
        problem(f"{where}: {sink['flows_seen']} flows seen, not {EXPECTED_FLOWS}")
    if sink["negative_latencies"] != 0:
        problem(f"{where}: {sink['negative_latencies']} negative latencies: the TSC is not usable")
    if not sink["latency_ns"]["p50"] > 0:
        problem(f"{where}: no latency measured")
    if npf and not cpu.get("npf_cpu_pct", 0) > 0:
        problem(f"{where}: npf's CPU time was not measured")
    return rep


def tier_b(raw):
    out = {"configurations": []}
    for config_dir in sorted(glob.glob(os.path.join(raw, "tier_b", "*", ""))):
        config_dir = os.path.dirname(config_dir)
        meta = load(os.path.join(config_dir, "meta.json"))
        npf = meta["config"] == "npf"
        entry = dict(meta)
        if npf:
            counters = final_counters(os.path.join(config_dir, "npf.log"))
            entry["npf_final_counters"] = counters
            accounted = sum(counters.get(k, 0) for k in ["forwarded", "flooded", "to_host"] + DROPS)
            if not counters or counters.get("rx_packets") != accounted:
                problem(f"{config_dir}: npf's final counters do not balance")
            if counters.get("pool_available") != counters.get("pool_capacity"):
                problem(f"{config_dir}: npf's buffers were not all back in their pools")
            if not meta.get("npf_peak_rss_kib", 0) > 0:
                problem(f"{config_dir}: npf's peak RSS was not measured")
        entry["scenarios"] = {}
        for scenario in ("throughput", "latency"):
            reps = []
            for gen_path in sorted(glob.glob(os.path.join(config_dir, scenario, "[0-9]*.gen.json")),
                                   key=lambda p: int(os.path.basename(p).split(".")[0])):
                stem = gen_path[:-len(".gen.json")]
                where = f"{os.path.basename(config_dir)} {scenario} {os.path.basename(stem)}"
                reps.append(repetition(where, load(gen_path), load(stem + ".sink.json"),
                                       load(stem + ".cpu.json"), npf))
            if not reps:
                problem(f"{config_dir}: no {scenario} repetitions")
                continue
            summary = {}
            for key in ("offered_pps", "delivered_pps", "loss_pct"):
                values = [r[key] for r in reps if key in r]
                if values:
                    summary[key] = spread(values)
            for q in ("p50", "p95", "p99", "p999", "max"):
                summary[f"latency_{q}_ns"] = spread([r["sink"]["latency_ns"][q] for r in reps])
            summary["system_busy_pct"] = spread([r["cpu"]["system_busy_pct"] for r in reps])
            if npf:
                summary["npf_cpu_pct"] = spread([r["cpu"].get("npf_cpu_pct", 0) for r in reps])
            entry["scenarios"][scenario] = {"summary": summary, "repetitions": reps}
        out["configurations"].append(entry)
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("raw")
    parser.add_argument("--build", required=True)
    parser.add_argument("--source", default=ROOT,
                        help="the source tree npf was built from (default: this checkout)")
    parser.add_argument("--out", required=True)
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()

    result = {}
    a = tier_a(args.raw)
    result["context"] = context(args, a)
    if a:
        result["tier_a"] = a
    if os.path.isdir(os.path.join(args.raw, "tier_b")):
        method_path = os.path.join(args.raw, "tier_b", "method.json")
        result["tier_b"] = tier_b(args.raw)
        if os.path.exists(method_path):
            result["tier_b"]["method"] = load(method_path)
    if not result["context"]["compile_command_npf"]:
        problem("no compile command for src/main.cpp in the build tree")
    try:
        text = json.dumps(result, indent=1, allow_nan=False)
    except ValueError as e:
        problem(f"a NaN or an infinity: {e}")
        text = None
    if problems:
        print("bench_combine: the run failed its checks:", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(text + "\n")
    print(f"bench_combine: wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
