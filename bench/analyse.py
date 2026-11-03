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
        for r in group:
            # Derived: served and ready measured from the moment the connection thread
            # started, which removes thread start-up, the same in every arm.
            if len(r) > 11 and r[11] not in ("", "-1"):
                start = int(r[11])
                r.append(str(int(r[6]) - start))  # index 12: served_from_start_us
                r.append(str(int(r[5]) - start))  # index 13: ready_from_start_us
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
    ap.add_argument("--prefix", default="bench", help="macro name prefix, letters only")
    args = ap.parse_args()

    kept, outcomes = load(args.directory)
    meta = json.load(open(os.path.join(args.directory, "meta.json"), encoding="utf-8"))
    rng = random.Random(SEED)

    # server.csv columns after the label split: arm, rep, wire, outcome, decide_us,
    # ready_us, served_us, first_read, tls_version, alpn
    served_col, ready_col, first_col = 6, 5, 7
    has_start = all(len(r) > 12 for g in kept.values() for r in g)
    result = {"meta": meta, "outcomes": outcomes, "arms": {}, "effects": {}}
    for arm in ("tls-detect", "tls-dedicated", "clear-detect", "clear-dedicated"):
        result["arms"][arm] = {
            "served_us": summarise(column(kept, arm, served_col)),
            "ready_us": summarise(column(kept, arm, ready_col)),
            # Accept to the end of the first read: on the detect arms this is the wait
            # for the client first bytes, which places any tail on the client side.
            "decide_us": summarise(column(kept, arm, 4)),
        }
        if has_start:
            result["arms"][arm]["start_us"] = summarise(column(kept, arm, 11))
            result["arms"][arm]["served_from_start_us"] = summarise(column(kept, arm, 12))
    metrics = [("from_accept", served_col)] + ([("from_thread_start", 12)] if has_start else [])
    for metric, col in metrics:
        for transport in ("tls", "clear"):
            a = column(kept, f"{transport}-detect", col)
            b = column(kept, f"{transport}-dedicated", col)
            point = statistics.median([x for v in a.values() for x in v]) - statistics.median(
                [x for v in b.values() for x in v])
            low, high = bootstrap_diff(a, b, rng)
            base = statistics.median([x for v in b.values() for x in v])
            result["effects"].setdefault(metric, {})[transport] = {
                "diff_p50_us": point, "ci_low": low, "ci_high": high, "relative_pct": 100.0 * point / base}

    first_reads = [int(r[first_col]) for (arm, _), g in kept.items() if arm == "tls-detect" for r in g]
    result["tls_detect_first_read"] = {"min": min(first_reads), "p50": statistics.median(first_reads),
                                       "max": max(first_reads)}

    print(json.dumps(result, indent=2))
    with open(os.path.join(args.directory, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    if args.latex:
        write_latex(result, args.latex, args.prefix)


def fmt(us):
    """Microseconds as milliseconds with three decimals and a decimal comma."""
    return f"{us / 1000:.3f}".replace(".", "{,}")


def num(x, digits=1):
    """A number with a decimal comma, for Bulgarian text."""
    return f"{x:.{digits}f}".replace(".", "{,}")


def write_latex(result, path, prefix):
    """Writes a table and a macro file. Every macro starts with `prefix` so that runs
    from different machines can be included in one document side by side."""
    names = {"tls-detect": "TLS, с разпознаване", "tls-dedicated": "TLS, отделен слушател",
             "clear-detect": "HTTP, с разпознаване", "clear-dedicated": "HTTP, отделен слушател"}
    metric = "served_from_start_us" if "served_from_start_us" in result["arms"]["tls-detect"] else "served_us"
    lines = ["% Generated by bench/analyse.py. Do not edit by hand.",
             f"% metric: {metric}, milliseconds",
             r"\begin{tabular}{lrrrrr}", r"\toprule",
             r"Рамо & $n$ & p50 & p90 & p99 & медиани по повторения \\", r"\midrule"]
    for arm, label in names.items():
        s = result["arms"][arm][metric]
        lines.append(f"{label} & {s['n']} & {fmt(s['p50'])} & {fmt(s['p90'])} & {fmt(s['p99'])} & "
                     f"{fmt(s['rep_median_min'])}" + r"\,\dots\," + f"{fmt(s['rep_median_max'])}" + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")

    out = ["% Generated by bench/analyse.py. Do not edit by hand."]

    def macro(name, value):
        out.append("\\newcommand{\\" + prefix + name + "}{" + str(value) + "}")

    # A: from accept. S: from the start of the connection thread.
    for metric_key, tag in (("from_accept", "A"), ("from_thread_start", "S")):
        for transport, name in (("tls", "Tls"), ("clear", "Clear")):
            e = result["effects"].get(metric_key, {}).get(transport)
            if e is None:
                continue
            macro(f"{name}Diff{tag}", num(e["diff_p50_us"]))
            macro(f"{name}Low{tag}", num(e["ci_low"]))
            macro(f"{name}High{tag}", num(e["ci_high"]))
            macro(f"{name}Rel{tag}", num(e["relative_pct"]))
    for arm, name in (("tls-detect", "TlsDetect"), ("tls-dedicated", "TlsDedicated"),
                      ("clear-detect", "ClearDetect"), ("clear-dedicated", "ClearDedicated")):
        a = result["arms"][arm]
        macro(f"{name}Median", fmt(a[metric]["p50"]))
        macro(f"{name}DecideMedian", fmt(a["decide_us"]["p50"]))
        if "start_us" in a:
            macro(f"{name}StartMedian", fmt(a["start_us"]["p50"]))
            macro(f"{name}StartNinety", fmt(a["start_us"]["p90"]))
    m = result["meta"]
    macro("Reps", m["reps"])
    macro("Conns", m["conns_per_arm_per_rep"])
    macro("Total", m["reps"] * m["conns_per_arm_per_rep"])
    macro("Rate", int(m["offered_rate_per_s"]))
    macro("Duration", f"{m['duration_s']:.0f}")
    macro("Commit", m["commit"])
    macro("Seed", m["seed"])
    macro("Platform", m["platform"].replace("_", r"\_"))
    macro("FirstReadMedian", f"{result['tls_detect_first_read']['p50']:.0f}")
    macro("Served", result["outcomes"].get("served", 0))
    macro("Measured", sum(result["outcomes"].values()))
    macros = os.path.splitext(path)[0] + "_macros.tex"
    with open(macros, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(out) + "\n")


if __name__ == "__main__":
    sys.exit(main())
