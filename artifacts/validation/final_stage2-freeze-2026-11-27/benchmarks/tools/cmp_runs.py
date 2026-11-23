"""Compare two extended-benchmark output dirs decision by decision. usage: cmp_runs.py A B [--json OUT]"""
import gzip
import hashlib
import json
import sys
from pathlib import Path


def rows(p):
    with gzip.open(p, "rt", encoding="utf-8", newline="") as fh:
        return fh.read()


def strip_timing(o):
    if isinstance(o, dict):
        return {k: strip_timing(v) for k, v in o.items()
                if k not in ("wall_time_s", "workers", "compute_ms_mean", "compute_ms_p95", "wall_s")
                and "latency" not in k and "throughput" not in k and "compute" not in k}
    if isinstance(o, list):
        return [strip_timing(v) for v in o]
    return o


a, b = Path(sys.argv[1]), Path(sys.argv[2])
da, db = rows(a / "decisions.csv.gz"), rows(b / "decisions.csv.gz")
sa, sb = (a / "sessions.csv").read_bytes(), (b / "sessions.csv").read_bytes()
ra, rb = json.loads((a / "results.json").read_text("utf-8")), json.loads((b / "results.json").read_text("utf-8"))
la, lb = da.splitlines(), db.splitlines()
ndiff = sum(x != y for x, y in zip(la, lb)) + abs(len(la) - len(lb))
res = {
    "a": str(a), "b": str(b),
    "decisions_rows": [len(la) - 1, len(lb) - 1],
    "decisions_csv_md5": [hashlib.md5(da.encode()).hexdigest(), hashlib.md5(db.encode()).hexdigest()],
    "decisions_identical": da == db, "differing_decision_rows": ndiff,
    "sessions_csv_md5": [hashlib.md5(sa).hexdigest(), hashlib.md5(sb).hexdigest()],
    "sessions_csv_identical": sa == sb,
    "results_json_identical_modulo_timing_and_workers": strip_timing(ra) == strip_timing(rb),
    "workers": [ra["config"]["workers"], rb["config"]["workers"]],
}
print(json.dumps(res, indent=2))
if "--json" in sys.argv:
    Path(sys.argv[sys.argv.index("--json") + 1]).write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")
