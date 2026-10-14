#!/usr/bin/env python3
"""Checks whether one run of scripts/run_bench.sh reproduces another, number by number.

    bench_reproduce.py <baseline.json> <rerun.json> [--json <out.json>]

For every number the baseline reports -- tier A: each benchmark's cycles per packet and ns per
packet or operation; tier B: each configuration's and scenario's delivered rate, loss, p50 and p99
latency -- whether the rerun's median lies inside the baseline's own range, min to max. That is the
phase 15 exit criterion: "run_bench.sh at the tagged commit produces it again within the reported
spread". Prints every number and a count per tier; --json writes them too. Exits 0 whatever the
count: a result, not a test. Standard library only.
"""

import argparse
import json
import sys


def aggs(d, bench):
    rows = {}
    for b in d.get('tier_a', {}).get(bench, {}).get('benchmarks', []):
        if b.get('run_type') == 'aggregate':
            rows.setdefault(b['run_name'], {})[b['aggregate_name']] = b
    return rows


def tier_a(base, rerun):
    out = []
    for bench in sorted(base.get('tier_a', {})):
        if bench == 'bench_lpm':
            continue  # phase 10's numbers; its own section reports them
        a, b = aggs(base, bench), aggs(rerun, bench)
        for name in a:
            if name not in b or 'median' not in a[name] or 'median' not in b[name]:
                continue
            for metric, unit in (('cycles_per_packet', 'cycles'), ('real_time', 'ns')):
                if metric not in a[name]['median'] or metric not in b[name]['median']:
                    continue
                per = a[name]['median'].get('packets', 1) if metric == 'real_time' else 1
                lo, hi = a[name]['min'][metric] / per, a[name]['max'][metric] / per
                new = b[name]['median'][metric] / per
                out.append({'tier': 'A', 'what': f"{bench} {name}", 'metric': unit,
                            'baseline': a[name]['median'][metric] / per, 'min': lo, 'max': hi,
                            'rerun': new, 'inside': lo <= new <= hi})
    return out


def tier_b(base, rerun):
    out = []

    def by_key(d):
        return {(c['config'], c.get('mode'), c.get('workers')): c
                for c in d.get('tier_b', {}).get('configurations', [])}

    ca, cb = by_key(base), by_key(rerun)
    for key, c in ca.items():
        if key not in cb:
            continue
        label = 'kernel control' if key[0] == 'kernel' else f"npf {key[1]}, {key[2]} workers"
        for scen in ('throughput', 'latency'):
            metrics = [('latency_p50_ns', 'p50 latency, ns'), ('latency_p99_ns', 'p99 latency, ns')]
            if scen == 'throughput':  # at a fixed rate, what is delivered is what was sent
                metrics = [('delivered_pps', 'delivered, pps'), ('loss_pct', 'loss, %')] + metrics
            for metric, unit in metrics:
                sa = c['scenarios'][scen]['summary'][metric]
                sb = cb[key]['scenarios'][scen]['summary'][metric]
                out.append({'tier': 'B', 'what': f"{label}, {scen}", 'metric': unit,
                            'baseline': sa['median'], 'min': sa['min'], 'max': sa['max'],
                            'rerun': sb['median'], 'inside': sa['min'] <= sb['median'] <= sa['max']})
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument('baseline')
    parser.add_argument('rerun')
    parser.add_argument('--json')
    args = parser.parse_args()
    with open(args.baseline) as f:
        base = json.load(f)
    with open(args.rerun) as f:
        rerun = json.load(f)
    rows = tier_a(base, rerun) + tier_b(base, rerun)
    for r in rows:
        print(f"{r['tier']} {r['what']:60s} {r['metric']:16s} baseline {r['baseline']:12.1f} "
              f"[{r['min']:.1f}, {r['max']:.1f}]  rerun {r['rerun']:12.1f}  "
              f"{'inside' if r['inside'] else 'OUTSIDE'}")
    counts = {}
    for tier in ('A', 'B'):
        t = [r for r in rows if r['tier'] == tier]
        counts[tier] = {'inside': sum(r['inside'] for r in t), 'of': len(t)}
        print(f"tier {tier}: {counts[tier]['inside']} of {counts[tier]['of']} inside the baseline's range")
    if args.json:
        with open(args.json, 'w') as f:
            json.dump({'baseline': {'path': args.baseline, 'git_sha': base['context']['git_sha']},
                       'rerun': {'path': args.rerun, 'git_sha': rerun['context']['git_sha']},
                       'counts': counts, 'numbers': rows}, f, indent=1, allow_nan=False)
            f.write("\n")
    return 0


if __name__ == '__main__':
    sys.exit(main())
