"""Audit the ML-on golden cases whose alert summary changed between a base tree and this tree (SIM / REPLAY).

    git worktree add --detach <dir> <base-commit>          # the tree the OLD ML-on golden was recorded on
    cp models/isoforest.joblib <dir>/models/               # the canonical model (git-ignored)
    python scripts/hardware/golden_ml_audit.py --base-tree <dir> --out <scratch>.md

For every golden case it runs the ML-on pipeline on both trees and reports the alert count, alert types and first
alert at/after the fault onset. For each case that changed it then re-runs THIS tree with the two configuration
changes that explain the drift reverted one at a time and together:

* ``rw0``        ``features.reorder_window = 0``  (issue #14 off: late frames count as sequence gaps again)
* ``ml_uncorr``  ``anomaly.enabled = true`` and ``fusion.ml_require_corroboration = false`` (issue #49 off)

A case is *explained* when one of those variants reproduces the base tree's (alerts, attack types, threat decisions).
Nothing is written to ``tests/`` or ``artifacts/``.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ONSET = {  # fault onset (s) per golden case, from scripts/make_golden.py; None = no injected fault
    "live/spoof_drift/profile": 25.0, "live/mission/profile": 30.0, "live/ekf_gate/profile": 25.0,
    "live/flood/profile": 25.0, "live/dropout/profile": 30.0, "live/seq/profile": 20.0, "live/seq/default": 20.0,
    "sim/mavlink_anomaly:rate_spike/s3": 17.0, "sim/dos:latency/s3": 17.0,
}
VARIANTS = (("base", {}), ("rw0", {"rw0": 1}), ("ml_uncorr", {"ml_uncorr": 1}), ("rw0+ml_uncorr", {"rw0": 1, "ml_uncorr": 1}))


def _run_tree(tree: Path, only: list[str] | None) -> dict:
    """Run in a child interpreter so each tree imports its own ``aegisflight``."""
    code = (
        "import sys, json\n"
        f"sys.path.insert(0, {str(tree / 'scripts')!r}); sys.path.insert(0, {str(tree / 'src')!r})\n"
        "import make_golden as mg\n"
        "orig = mg.CaseRecorder.tick\n"
        "cur = []\n"
        "def tick(self, t):\n"
        "    n0 = self.n; orig(self, t)\n"
        "    if self.n > n0: cur.append((self.last['t'], self.alerts, self.last['attack_type']))\n"
        "mg.CaseRecorder.tick = tick\n"
        f"only = {only!r}\n"
        "out = {}\n"
        "for name in [n for n, _ in mg.sim_cases() if not n.endswith('/s11')] + [n for n, _, _ in mg.live_cases()]:\n"
        "    if only and name not in only: continue\n"
        "    cur.clear()\n"
        "    if name.startswith('sim/'): r = mg.run_sim_case(dict(mg.sim_cases())[name], True)\n"
        "    else:\n"
        "        _, scn, var = [c for c in mg.live_cases() if c[0] == name][0]; r = mg.run_live_case(scn, var, True)\n"
        "    out[name] = {'alerts': r['alerts'], 'types': r['attack_types'], 'thr': r['threat_decisions'], 'rows': list(cur)}\n"
        "print(json.dumps(out))\n"
    )
    res = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, check=True, cwd=tree)
    return json.loads(res.stdout.strip().splitlines()[-1])


def _variants(only: list[str]) -> dict:
    code = (
        "import sys, json\n"
        f"sys.path.insert(0, {str(REPO / 'scripts')!r}); sys.path.insert(0, {str(REPO / 'src')!r})\n"
        "import make_golden as mg\n"
        "orig = mg.load_config\n"
        "MOD = {}\n"
        "def load(*a, **k):\n"
        "    cfg = orig(*a, **k); det = cfg.detector\n"
        "    if MOD.get('rw0'): det.setdefault('features', {})['reorder_window'] = 0\n"
        "    if MOD.get('ml_uncorr'):\n"
        "        det.setdefault('anomaly', {})['enabled'] = True; det.setdefault('fusion', {})['ml_require_corroboration'] = False\n"
        "    return cfg\n"
        "mg.load_config = load\n"
        f"only = {only!r}; variants = {list(VARIANTS)!r}; out = {{}}\n"
        "for name in only:\n"
        "    for label, mod in variants:\n"
        "        MOD.clear(); MOD.update(mod)\n"
        "        if name.startswith('sim/'): r = mg.run_sim_case(dict(mg.sim_cases())[name], True)\n"
        "        else:\n"
        "            _, scn, var = [c for c in mg.live_cases() if c[0] == name][0]; r = mg.run_live_case(scn, var, True)\n"
        "        out.setdefault(name, {})[label] = [r['alerts'], r['attack_types'], r['threat_decisions']]\n"
        "print(json.dumps(out))\n"
    )
    res = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, check=True, cwd=REPO)
    return json.loads(res.stdout.strip().splitlines()[-1])


def _first(rows: list, onset: float | None) -> str:
    p = 0
    for t, n, typ in rows:
        if n > p and (onset is None or t >= onset):
            return f"{t:.1f}s {typ}"
        p = n
    return "none"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base-tree", required=True, type=Path)
    ap.add_argument("--out", type=Path)
    a = ap.parse_args()
    if not (a.base_tree / "models" / "isoforest.joblib").exists() or not (REPO / "models" / "isoforest.joblib").exists():
        print("both trees need models/isoforest.joblib", file=sys.stderr)
        return 2
    base, head = _run_tree(a.base_tree.resolve(), None), _run_tree(REPO, None)
    changed = [k for k in head if (base[k]["alerts"], base[k]["types"], base[k]["thr"]) != (head[k]["alerts"], head[k]["types"], head[k]["thr"])]
    var = _variants(changed)
    lines = ["| case | base alerts / types | head alerts / types | first alert at/after onset (base -> head) | explained by |", "|---|---|---|---|---|"]
    for k in changed:
        want = [base[k]["alerts"], base[k]["types"], base[k]["thr"]]
        why = [lab for lab, v in var[k].items() if v == want and lab != "base"]
        lines.append(f"| `{k}` | {base[k]['alerts']} {base[k]['types']} | {head[k]['alerts']} {head[k]['types']} | "
                     f"{_first(base[k]['rows'], ONSET.get(k))} -> {_first(head[k]['rows'], ONSET.get(k))} | {', '.join(why) or 'UNEXPLAINED'} |")
    out = "\n".join(lines)
    print(f"{len(changed)} changed case(s)")
    print(out)
    if a.out:
        a.out.write_text(out + "\n")
    return 0 if "UNEXPLAINED" not in out else 1


if __name__ == "__main__":
    raise SystemExit(main())
