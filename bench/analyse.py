#!/usr/bin/env python3
"""Turns one bench/run.py directory into the numbers the course project cites.

    analyse.py DIR [--latex FILE]

Statistics, stated so they can be checked:

* Percentiles use the nearest-rank method: the p-th percentile of n sorted values is the
  value at position ceil(p/100 * n), counting from one.
* The warm-up connections of every server process are dropped: the first WARMUP rows of
  each (arm, repetition) in server.csv, which are the warm-up requests run.py sent first.
* The effect of detection is the difference of medians, detect minus dedicated, for each
  transport. Its 95% interval is a percentile bootstrap: 2000 resamples, each drawing
  connections with replacement inside every repetition separately, so each resample keeps
  the design of the run. The seed is fixed, so the interval is reproducible.
* The spread of the five per-repetition medians is reported beside it. When repetitions
  differ from each other by more than the interval is wide, the interval understates the
  uncertainty, and the text has to say so.
"""

import argparse
import csv
import json
import math
import os
import random
import statistics
import sys

WARMUP = 20
ITERATIONS = 2000
SEED = 7


def pct(values, p):
    s = sorted(values)
    k = max(1, math.ceil(p / 100 * len(s)))
    return s[k - 1]


def load(directory):
    rows = {}
    with open(os.path.join(directory, "server.csv"), encoding="utf-8") as f:
        for r in csv.reader(f):
            arm, rep = r[0], int(r[1])
            rows.setdefault((arm, rep), []).append(r)
    kept = {}
    outcomes = {}
    for key, group in rows.items():
        measured = group[WARMUP:]
        for r in measured:
            outcomes[r[3]] = outcomes.get(r[3], 0) + 1
        kept[key] = [r for r in measured if r[3] == "served"]
    return kept, outcomes


def column(kept, arm, index):
    return {rep: [int(r[index]) for r in group] for (a, rep), group in kept.items() if a == arm}


def bootstrap_diff(a_by_rep, b_by_rep, rng):
    diffs = []
    reps = sorted(a_by_rep)
    for _ in range(ITERATIONS):
        a = [x for rep in reps for x in rng.choices(a_by_rep[rep], k=len(a_by_rep[rep]))]
        b = [x for rep in reps for x in rng.choices(b_by_rep[rep], k=len(b_by_rep[rep]))]
        diffs.append(statistics.median(a) - statistics.median(b))
    diffs.sort()
    return diffs[int(0.025 * ITERATIONS)], diffs[int(0.975 * ITERATIONS) - 1]


def summarise(by_rep):
    pooled = [x for rep in sorted(by_rep) for x in by_rep[rep]]
    rep_medians = [statistics.median(by_rep[rep]) for rep in sorted(by_rep)]
    return {
        "n": len(pooled),
        "p50": statistics.median(pooled),
        "p90": pct(pooled, 90),
        "p99": pct(pooled, 99),
        "rep_median_min": min(rep_medians),
        "rep_median_max": max(rep_medians),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("directory")
    ap.add_argument("--latex")
    args = ap.parse_args()

    kept, outcomes = load(args.directory)
    meta = json.load(open(os.path.join(args.directory, "meta.json"), encoding="utf-8"))
    rng = random.Random(SEED)

    # server.csv columns after the label split: arm, rep, wire, outcome, decide_us,
    # ready_us, served_us, first_read, tls_version, alpn
    served_col, ready_col, first_col = 6, 5, 7
    result = {"meta": meta, "outcomes": outcomes, "arms": {}, "effects": {}}
    for arm in ("tls-detect", "tls-dedicated", "clear-detect", "clear-dedicated"):
        result["arms"][arm] = {
            "served_us": summarise(column(kept, arm, served_col)),
            "ready_us": summarise(column(kept, arm, ready_col)),
            # Accept to the end of the first read: on the detect arms this is the wait
            # for the client first bytes, which places any tail on the client side.
            "decide_us": summarise(column(kept, arm, 4)),
        }
    for transport in ("tls", "clear"):
        a = column(kept, f"{transport}-detect", served_col)
        b = column(kept, f"{transport}-dedicated", served_col)
        point = statistics.median([x for v in a.values() for x in v]) - statistics.median(
            [x for v in b.values() for x in v])
        low, high = bootstrap_diff(a, b, rng)
        base = statistics.median([x for v in b.values() for x in v])
        result["effects"][transport] = {"diff_p50_us": point, "ci_low": low, "ci_high": high,
                                        "relative_pct": 100.0 * point / base}

    first_reads = [int(r[first_col]) for (arm, _), g in kept.items() if arm == "tls-detect" for r in g]
    result["tls_detect_first_read"] = {"min": min(first_reads), "p50": statistics.median(first_reads),
                                       "max": max(first_reads)}

    print(json.dumps(result, indent=2))
    with open(os.path.join(args.directory, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    if args.latex:
        write_latex(result, args.latex)


def fmt(us):
    return f"{us / 1000:.3f}".replace(".", "{,}")


def write_latex(result, path):
    names = {"tls-detect": "TLS, с разпознаване", "tls-dedicated": "TLS, отделен слушател",
             "clear-detect": "HTTP, с разпознаване", "clear-dedicated": "HTTP, отделен слушател"}
    lines = ["% Generated by bench/analyse.py. Do not edit by hand.",
             "\\begin{tabular}{lrrrrr}", "\\toprule",
             "Рамо & $n$ & p50 & p90 & p99 & медиани по повторения \\\\", "\\midrule"]
    for arm, label in names.items():
        s = result["arms"][arm]["served_us"]
        lines.append(f"{label} & {s['n']} & {fmt(s['p50'])} & {fmt(s['p90'])} & {fmt(s['p99'])} & "
                     f"{fmt(s['rep_median_min'])}\\,--\\,{fmt(s['rep_median_max'])} \\\\")
    lines += ["\\bottomrule", "\\end{tabular}"]
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")

    macros = os.path.splitext(path)[0] + "_macros.tex"
    out = ["% Generated by bench/analyse.py. Do not edit by hand."]
    for transport, name in (("tls", "Tls"), ("clear", "Clear")):
        e = result["effects"][transport]
        out.append(f"\\newcommand{{\\bench{name}Diff}}{{{e['diff_p50_us']:.1f}}}")
        out.append(f"\\newcommand{{\\bench{name}Low}}{{{e['ci_low']:.1f}}}")
        out.append(f"\\newcommand{{\\bench{name}High}}{{{e['ci_high']:.1f}}}")
        out.append(f"\\newcommand{{\\bench{name}Rel}}{{{e['relative_pct']:.1f}}}")
    m = result["meta"]
    out.append(f"\\newcommand{{\\benchReps}}{{{m['reps']}}}")
    out.append(f"\\newcommand{{\\benchConns}}{{{m['conns_per_arm_per_rep']}}}")
    out.append(f"\\newcommand{{\\benchRate}}{{{int(m['offered_rate_per_s'])}}}")
    out.append(f"\\newcommand{{\\benchDuration}}{{{m['duration_s']:.0f}}}")
    out.append(f"\\newcommand{{\\benchCommit}}{{{m['commit']}}}")
    out.append(f"\\newcommand{{\\benchSeed}}{{{m['seed']}}}")
    fr = result["tls_detect_first_read"]
    out.append(f"\\newcommand{{\\benchFirstReadMedian}}{{{fr['p50']:.0f}}}")
    with open(macros, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(out) + "\n")


if __name__ == "__main__":
    sys.exit(main())
