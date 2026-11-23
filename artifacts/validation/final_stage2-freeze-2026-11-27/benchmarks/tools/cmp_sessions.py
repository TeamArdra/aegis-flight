"""Per-session decision diff of two extended-benchmark dirs. usage: cmp_sessions.py A B"""
import csv
import gzip
import sys
from collections import defaultdict
from pathlib import Path


def load(d):
    out = defaultdict(list)
    with gzip.open(Path(d) / "decisions.csv.gz", "rt", encoding="utf-8", newline="") as fh:
        for r in csv.DictReader(fh):
            out[(int(r["session"]), r["key"])].append(r)
    return out


def nograce_fp(rows):
    return sum(1 for r in rows if r["true"] == "BENIGN" and r["pred"] != "BENIGN" and r["warmup"] == "0")


a, b = load(sys.argv[1]), load(sys.argv[2])
tot_diff = 0
for k in sorted(set(a) | set(b)):
    ra, rb = a.get(k, []), b.get(k, [])
    d = sum(x != y for x, y in zip(ra, rb)) + abs(len(ra) - len(rb))
    if d:
        tot_diff += d
        print(f"session {k[0]:3d} {k[1]:40s} differing rows {d:3d}  no-grace FP-rows {nograce_fp(ra)} -> {nograce_fp(rb)}  "
              f"in_grace-only changes {sum(1 for x, y in zip(ra, rb) if x != y and x['in_grace'] == '1' and y['in_grace'] == '1')}")
print("total differing rows:", tot_diff, "sessions", len(a), len(b))
fa = sum(nograce_fp(v) for v in a.values())
fb = sum(nograce_fp(v) for v in b.values())
print("no-grace FP-rows (all sessions, incl. combo): ", fa, "->", fb)
