#!/usr/bin/env python3
"""
Score a DNSGuard lab run against ground truth. Standard library only.

Inputs
  --db      dnsguard_events.sqlite written by the live system (--db ...), for the same run window
  --truth   ground_truth.csv written by dnslab.py (attack + benign runs with start/end timestamps)
  --received received.csv written by `dnslab.py sink` (optional: measures data that reached the attacker)
  --run     which detector run_id to score (default: the most recent in the db)

What it reports
  Detection (recall): share of attack runs in ground_truth.csv that raised at least one incident while they were active.
  False alarms (FPR): incidents whose (client, domain, time) fall in a benign run and match no attack run.
  Prevention: for a block-mode run, how many attacker-received queries arrived AFTER the domain was blocked.
"""
from __future__ import annotations

import argparse
import csv
import os
import sqlite3
import sys


def load_truth(path):
    rows = []
    with open(path, newline="") as fh:
        for r in csv.DictReader(fh):
            try:
                r["start"] = float(r["start"]); r["end"] = float(r["end"] or r["start"])
            except (ValueError, KeyError):
                continue
            rows.append(r)
    return rows


def overlaps(a0, a1, b0, b1):
    return a0 <= b1 and b0 <= a1


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default="dnsguard_events.sqlite")
    ap.add_argument("--truth", default="ground_truth.csv")
    ap.add_argument("--received", default="received.csv")
    ap.add_argument("--run")
    ap.add_argument("--grace", type=float, default=5.0, help="seconds of slack around each run window")
    a = ap.parse_args()
    for f in (a.db, a.truth):
        if not os.path.exists(f):
            sys.exit(f"missing {f}")
    truth = load_truth(a.truth)
    if not truth:
        sys.exit("ground_truth.csv has no usable rows")

    con = sqlite3.connect(a.db); con.row_factory = sqlite3.Row
    run = a.run or (con.execute("SELECT run FROM incidents ORDER BY last DESC LIMIT 1").fetchone() or [None])[0]
    incs = [dict(r) for r in con.execute("SELECT * FROM incidents WHERE run=?", (run,))]
    acts = [dict(r) for r in con.execute("SELECT * FROM actions WHERE run=? AND action='block' AND ok=1", (run,))]
    print(f"== DNSGuard lab evaluation ==\nrun: {run}\nincidents: {len(incs)} · ground-truth entries: {len(truth)}\n")

    attacks = [t for t in truth if t["kind"] == "attack"]
    benigns = [t for t in truth if t["kind"] == "benign"]
    g = a.grace

    # ---- recall ----
    detected, missed = [], []
    for t in attacks:
        hit = next((i for i in incs if (not t.get("client") or i["client"] == t["client"])
                    and (not t.get("domain") or t["domain"] == "*" or i["domain"] == t["domain"])
                    and overlaps(t["start"] - g, t["end"] + g, i["first"], i["last"])), None)
        (detected if hit else missed).append(t)
    if attacks:
        print(f"-- Detection (recall) --\n  detected {len(detected)}/{len(attacks)} attack runs "
              f"= {len(detected) / len(attacks):.1%}")
        for t in missed:
            print(f"    MISSED: {t['tool']} {t['domain']} ({t['client']})")
    else:
        print("-- Detection --\n  no attack runs in ground truth")

    # ---- false alarms ----
    def in_attack(i):
        return any((not t.get("client") or i["client"] == t["client"])
                   and (t["domain"] in ("*", i["domain"]))
                   and overlaps(t["start"] - g, t["end"] + g, i["first"], i["last"]) for t in attacks)
    fp = [i for i in incs if not in_attack(i)]
    fp_benign = [i for i in fp if any(overlaps(b["start"] - g, b["end"] + g, i["first"], i["last"]) for b in benigns)] if benigns else fp
    print(f"\n-- False alarms --\n  {len(fp)} incident(s) match no attack run"
          + (f", {len(fp_benign)} of them during benign traffic" if benigns else ""))
    for i in fp[:10]:
        print(f"    FP: {i['client']} -> {i['domain']} ({i['alerts']} alerts)")

    # ---- prevention ----
    if acts and os.path.exists(a.received):
        print("\n-- Prevention (data that still reached the attacker after blocking) --")
        blocked_at = {}
        for ac in acts:
            blocked_at[ac["domain"]] = min(ac["ts"], blocked_at.get(ac["domain"], ac["ts"]))
        recv = list(csv.DictReader(open(a.received, newline="")))
        for dom, bts in sorted(blocked_at.items()):
            rows = [r for r in recv if r.get("zone") == dom or r.get("name", "").endswith("." + dom)]
            before = [r for r in rows if float(r["ts"]) < bts]
            after = [r for r in rows if float(r["ts"]) >= bts]
            cb = sum(int(r.get("sub_chars", 0) or 0) for r in before)
            ca = sum(int(r.get("sub_chars", 0) or 0) for r in after)
            print(f"  {dom}: {len(before)} queries (~{cb} sub-chars) before block, "
                  f"{len(after)} (~{ca}) after  → stopped {cb / max(cb + ca, 1):.0%} of the channel")
    elif acts:
        print("\n-- Prevention --\n  (give --received received.csv from the sink to measure leaked volume)")

    con.close()


if __name__ == "__main__":
    main()
