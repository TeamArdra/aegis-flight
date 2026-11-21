#!/usr/bin/env python
"""Benign link-stress sweep (``SIM``): decision false-positive rate and alert events/hour per grid cell (issue #27, item 2).

Grid (defaults = the full #27 grid): packet loss {0, 1, 2, 5, 10} % x ordering {fifo, reorder} x ML {off, on} x detector
profile {stage1 = built-in ``configs/``, px4 = ``configs/px4_sitl``, ardupilot = ``configs/ardupilot_copter``}, 6 benign
sessions per cell. Every session uses the unchanged benchmark session runner (``benchmark.runner.run_session``) and the
extended benchmark's link model (mean delay 25 ms; ``fifo`` = in-order delivery, ``reorder`` = delay jitter may reorder).
Nothing is tuned here. Session ``i`` has the same route / speed / altitude / noise scale / seed in every cell, so cells
are paired and differ only in loss, ordering, ML and profile.

Per-profile handling (nothing is cross-paired):
  stage1    -> ML on uses models/isoforest.joblib (docs/ML_PIPELINE.md).
  px4       -> NEVER executed: every px4 cell (ML off and on) is reported ``n/a``. The px4_sitl profile is calibrated for PX4
               SITL traffic (sysid 3, ~378 msg/s); the simulator emits sysid 1 at ~28 msg/s, so "rogue telemetry source"
               fires on every decision and such a cell would measure the mismatch, not the profile. Measure that profile on
               PX4 SITL replays (#27 items 3-4). There is deliberately no opt-in.
  ardupilot -> ML off runs on the simulator's traffic (a threshold override, not a link model). ML on is ``n/a``: no
               ArduPilot-benign model exists and the Stage-1 model is documented not to transfer (docs/ARDUPILOT_SITL.md),
               unless ``--model-ardupilot`` is given explicitly.

Definitions (also written into ``sweep_table.md``):
  decision       one fusion decision (``decision_rate_hz``, default 5 Hz); only scored decisions count (t >= 5 s warm-up).
  alarm decision a scored decision with ``threat == True`` (every session is benign, so each one is a false positive).
  decision FPR   alarm decisions / scored decisions in the cell.
  alert event    a maximal run of consecutive alarm decisions within one session (a scored non-alarm decision, or the
                 end of the session, closes it). Runs never span sessions.
  events / hour  alert events / observed hours, observed = scored decisions x decision period (1 / decision_rate_hz).
  dominant evidence  the most frequent normalised evidence string over the cell's alarm decisions, each distinct string
                 counted once per decision; digits are collapsed to ``#`` and ``coverage...`` notes are ignored.

Outputs in ``--out``: ``decisions.csv.gz`` (one row per decision, raw + normalised evidence), ``cell_summary.csv``,
``sweep_table.md``, ``run_manifest.json`` (schema ``aegisflight.run_manifest/1`` plus the sweep's own fields). Refuses a
dirty tree unless ``--allow-dirty`` (output is then stamped NOT-REPRODUCIBLE, issue #25). The default ``--out`` is a fresh
temporary directory; nothing is written to the repository unless ``--out`` points there.

Usage: python scripts/sweep_link_stress.py [--out DIR] [--loss 0 1 2 5 10] [--ordering fifo reorder] [--ml off on]
           [--profiles stage1 px4 ardupilot] [--sessions 6] [--seed 70000] [--workers 1] [--duration-s S] [--allow-dirty]
"""

from __future__ import annotations

import argparse
import copy
import csv
import gzip
import io
import itertools
import json
import re
import sys
import tempfile
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np

from aegisflight import run_provenance as prov
from aegisflight.benchmark.extended import LINK_STRESS, ROUTES
from aegisflight.benchmark.runner import run_session
from aegisflight.config import load_config
from aegisflight.detectors.anomaly import AnomalyDetector

REPO = Path(__file__).resolve().parents[1]
ENVIRONMENT = "SIM"
SEED0 = 70_000  # distinct from training (101-124), baseline (42), extended (30,000+) and sweep_gps_drift (50,000+)
WARMUP_S = 5.0

DEFAULT_LOSS = (0.0, 1.0, 2.0, 5.0, 10.0)  # percent
ORDERINGS = ("fifo", "reorder")
ML_MODES = ("off", "on")
PROFILES = {"stage1": None, "px4": "configs/px4_sitl", "ardupilot": "configs/ardupilot_copter"}
DEFAULT_MODELS = {"stage1": "models/isoforest.joblib", "ardupilot": None}  # px4: never executed (NA_PX4_ON_SIM)
NA_PX4_ON_SIM = ("the px4_sitl profile is calibrated for PX4 SITL traffic (sysid 3, ~378 msg/s); the simulator emits sysid 1 "
                 "at ~28 msg/s, so 'rogue telemetry source' fires on every decision and the cell measures the mismatch, "
                 "not the profile. Measure this profile on PX4 SITL replays (#27 items 3-4).")
NA_NO_MODEL = ("no ArduPilot-benign ML model exists; the Stage-1 model is documented not to transfer to ArduPilot "
               "(docs/ARDUPILOT_SITL.md) - pass --model-ardupilot to force a model")

# the link model is the extended benchmark's; only loss and ordering vary
_BASE_LINK = {k: v for k, v in LINK_STRESS["link_fifo_benign"].items() if k not in ("loss_prob", "fifo")}

DECISION_FIELDS = ["profile", "ordering", "loss_pct", "ml", "session", "seed", "t", "scored", "alarm", "severity",
                   "attack_type", "threat_score", "detectors", "evidence", "evidence_key"]
SUMMARY_FIELDS = ["profile", "ordering", "loss_pct", "ml", "status", "model", "sessions", "scored_decisions",
                  "alarm_decisions", "decision_fpr", "sessions_with_alarm", "alert_events", "observed_hours",
                  "alert_events_per_hour", "dominant_evidence", "dominant_evidence_count", "dominant_detector", "note"]


@dataclass(frozen=True)
class Cell:
    profile: str
    ordering: str
    loss_pct: float
    ml: str

    @property
    def cid(self) -> str:
        return f"{self.profile}/{self.ordering}/loss{self.loss_pct:g}/ml_{self.ml}"


def expand_grid(losses, orderings, ml_modes, profiles) -> list[Cell]:
    """Cartesian product in a fixed order (profile, ordering, loss, ml), de-duplicated, independent of argv order."""
    cells = {Cell(p, o, float(lo), m) for p, o, lo, m in itertools.product(profiles, orderings, losses, ml_modes)}
    return sorted(cells, key=lambda c: (list(PROFILES).index(c.profile), ORDERINGS.index(c.ordering), c.loss_pct,
                                        ML_MODES.index(c.ml)))


def resolve_model(cell: Cell, models: dict[str, str | None]) -> tuple[str | None, str | None]:
    """``(model_path, None)`` for ML-on / ``(None, None)`` for ML-off, or ``(None, reason)`` when the cell is not run
    (every px4 cell, and ML-on without a model)."""
    if cell.profile == "px4":
        return None, NA_PX4_ON_SIM
    if cell.ml == "off":
        return None, None
    path = models.get(cell.profile)
    return (path, None) if path else (None, NA_NO_MODEL)


def model_loads(path: str) -> bool:
    """True only if the anomaly detector can actually load ``path``.

    ``AnomalyDetector`` degrades to ML off when ``joblib.load`` fails (corrupt, truncated or sklearn-incompatible file), so
    a file that merely exists would yield cells labelled ``ml=on`` with ML-off numbers.
    """
    return AnomalyDetector({}, path).available


def session_params(seed0: int, i: int) -> dict[str, Any]:
    """Session ``i``'s trajectory, identical in every cell (extended-benchmark ranges: 8-16 m/s, 35-90 m, noise 0.7-1.6x)."""
    rng = np.random.default_rng([seed0, i])
    return {"seed": seed0 + i, "route": ROUTES[i % len(ROUTES)], "speed": float(rng.uniform(8, 16)),
            "alt": float(rng.uniform(35, 90)), "noise_scale": float(rng.uniform(0.7, 1.6))}


def normalise_evidence(e: str) -> str:
    return re.sub(r"[-\d.]+", "#", e)[:90]


def evidence_keys(evidence: list[str]) -> list[str]:
    return [normalise_evidence(e) for e in evidence if not e.startswith("coverage")]


def count_alert_events(alarms: list[bool]) -> int:
    """Maximal runs of consecutive ``True`` in one session's scored decisions."""
    return sum(1 for i, a in enumerate(alarms) if a and (i == 0 or not alarms[i - 1]))


def dominant_evidence(per_decision_keys: list[list[str]]) -> tuple[str, int]:
    """Most frequent evidence key over alarm decisions (once per decision); ties break alphabetically. ``("-", 0)`` if none."""
    c: Counter[str] = Counter()
    for keys in per_decision_keys:
        c.update(set(keys))
    if not c:
        return "-", 0
    return min(c.items(), key=lambda kv: (-kv[1], kv[0]))


def _run_task(task: dict[str, Any]) -> dict[str, Any]:
    """One benign session of one cell. Module-level and picklable for the process pool."""
    p = task["params"]
    cfg = load_config(task["profile_dir"])
    sim = cfg.simulation
    sim.update(route=p["route"], cruise_speed_ms=p["speed"], cruise_alt_m=p["alt"], seed=p["seed"])
    sim["noise"] = {k: v * p["noise_scale"] for k, v in sim.get("noise", {}).items()}
    sim["link"] = {**_BASE_LINK, "loss_prob": task["loss_pct"] / 100.0, "fifo": task["ordering"] == "fifo"}
    if task.get("duration_s"):
        sim["duration_s"] = float(task["duration_s"])
    res = run_session(copy.deepcopy(cfg), "benign", seed=p["seed"], model_path=task["model"], warmup_s=WARMUP_S)
    rows = []
    for rec, a in zip(res.records, res.assessments, strict=True):
        rows.append({
            "t": round(rec.t, 3), "scored": bool(rec.scored), "alarm": bool(rec.threat), "severity": rec.severity,
            "attack_type": rec.pred_label.value, "threat_score": round(a.threat_score, 4),
            "detectors": "|".join(a.contributing_detectors), "evidence": " | ".join(a.evidence),
            "evidence_key": " | ".join(evidence_keys(a.evidence))})
    return {"cell": task["cell"], "session": task["session"], "seed": p["seed"], "rows": rows,
            "decision_period_s": 1.0 / float(cfg.simulation.get("decision_rate_hz", 5.0))}


def summarise_cell(cell: Cell, model: str | None, sessions: list[dict[str, Any]]) -> dict[str, Any]:
    n_scored = n_alarm = events = sess_alarm = 0
    keys: list[list[str]] = []
    dets: Counter[str] = Counter()
    hours = 0.0
    for s in sessions:
        scored = [r for r in s["rows"] if r["scored"]]
        alarms = [r["alarm"] for r in scored]
        n_scored += len(scored)
        n_alarm += sum(alarms)
        events += count_alert_events(alarms)
        sess_alarm += int(any(alarms))
        hours += len(scored) * s["decision_period_s"] / 3600.0
        for r in scored:
            if r["alarm"]:
                keys.append([k for k in r["evidence_key"].split(" | ") if k])
                dets.update(d for d in r["detectors"].split("|") if d)
    dom, dom_n = dominant_evidence(keys)
    return {"profile": cell.profile, "ordering": cell.ordering, "loss_pct": f"{cell.loss_pct:g}", "ml": cell.ml,
            "status": "ok", "model": Path(model).name if model else "none", "sessions": len(sessions),
            "scored_decisions": n_scored, "alarm_decisions": n_alarm,
            "decision_fpr": f"{n_alarm / n_scored:.4f}" if n_scored else "", "sessions_with_alarm": sess_alarm,
            "alert_events": events, "observed_hours": f"{hours:.4f}",
            "alert_events_per_hour": f"{events / hours:.1f}" if hours else "", "dominant_evidence": dom,
            "dominant_evidence_count": dom_n, "dominant_detector": dets.most_common(1)[0][0] if dets else "-", "note": ""}


def na_row(cell: Cell, reason: str) -> dict[str, Any]:
    row = dict.fromkeys(SUMMARY_FIELDS, "")
    row.update(profile=cell.profile, ordering=cell.ordering, loss_pct=f"{cell.loss_pct:g}", ml=cell.ml, status="n/a",
               model="none", note=reason)
    return row


DEFINITIONS = """\
**Definitions.** *Decision*: one fusion decision (5 Hz); only scored decisions count (t >= 5 s warm-up). *Alarm decision*:
scored decision with `threat == True`; every session is benign, so each is a false positive. *Decision FPR*: alarm
decisions / scored decisions. *Alert event*: a maximal run of consecutive alarm decisions inside one session (a scored
non-alarm decision or the session end closes it). *Events/h*: alert events / (scored decisions x decision period / 3600).
*Dominant evidence*: most frequent normalised evidence string over the cell's alarm decisions (once per decision, digits
collapsed to `#`, `coverage...` notes ignored); the per-decision raw strings are in `decisions.csv.gz`.
"""


def render_markdown(rows: list[dict[str, Any]], meta: dict[str, Any]) -> str:
    out = [f"# Link-stress sweep ({ENVIRONMENT}, benign sessions)", "",
           f"Sessions per cell: {meta['sessions']} (seeds {meta['seed0']}..{meta['seed0'] + meta['sessions'] - 1}); "
           f"session length: {meta['duration_s']}; link: {meta['link_base']} + loss/ordering per row.", "", DEFINITIONS,
           "| profile | order | loss % | ML | decision FPR | alarm/scored | events/h | events | dominant evidence (count) |",
           "|---|---|---:|---|---:|---:|---:|---:|---|"]
    for r in rows:
        if r["status"] != "ok":
            out.append(f"| {r['profile']} | {r['ordering']} | {r['loss_pct']} | {r['ml']} | n/a | n/a | n/a | n/a | "
                       f"n/a: {r['note']} |")
            continue
        dom = r["dominant_evidence"].replace("|", "\\|")
        out.append(f"| {r['profile']} | {r['ordering']} | {r['loss_pct']} | {r['ml']} | {float(r['decision_fpr']):.4f} | "
                   f"{r['alarm_decisions']}/{r['scored_decisions']} | {r['alert_events_per_hour']} | {r['alert_events']} | "
                   f"{dom} ({r['dominant_evidence_count']}) |")
    return "\n".join(out) + "\n"


def write_decisions_gz(path: Path, rows: list[dict[str, Any]]) -> None:
    """Deterministic gzip (fixed mtime, no filename) so identical rows give identical bytes."""
    with open(path, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as gz:
        text = io.TextIOWrapper(gz, encoding="utf-8", newline="")
        w = csv.DictWriter(text, fieldnames=DECISION_FIELDS, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
        text.flush()
        text.detach()


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=None, help="output directory (default: a fresh temporary directory)")
    ap.add_argument("--loss", type=float, nargs="+", default=list(DEFAULT_LOSS), help="loss levels in percent")
    ap.add_argument("--ordering", nargs="+", choices=ORDERINGS, default=list(ORDERINGS))
    ap.add_argument("--ml", nargs="+", choices=ML_MODES, default=list(ML_MODES))
    ap.add_argument("--profiles", nargs="+", choices=list(PROFILES), default=list(PROFILES))
    ap.add_argument("--sessions", type=int, default=6, help="sessions per cell")
    ap.add_argument("--seed", type=int, default=SEED0, help="first session seed (session i uses seed+i)")
    ap.add_argument("--duration-s", type=float, default=None, help="session length in s (default: the simulator's 120 s)")
    ap.add_argument("--workers", type=int, default=1, help="parallel session processes (results are order-independent)")
    for name, dflt in DEFAULT_MODELS.items():
        ap.add_argument(f"--model-{name}", default=dflt, help=f"ML model for the {name} profile (default: {dflt})")
    prov.add_provenance_args(ap)
    return ap


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    start_state = prov.require_clean_tree(a.allow_dirty)  # refuses (exit 2) before any output unless --allow-dirty
    cells = expand_grid(a.loss, a.ordering, a.ml, a.profiles)
    models = {p: getattr(a, f"model_{p}") for p in DEFAULT_MODELS}
    models = {p: (m if not m or Path(m).is_absolute() else str(REPO / m)) for p, m in models.items()}

    plan: list[tuple[Cell, str | None, str | None]] = []  # (cell, model, na_reason)
    for c in cells:
        m, na = resolve_model(c, models)
        if m and not Path(m).exists():
            print(f"ERROR: model for ML-on cell {c.cid} not found: {m}", file=sys.stderr)
            return 2
        plan.append((c, m, na))
    for m in sorted({m for _, m, _ in plan if m}):  # fail closed before any output exists
        if not model_loads(m):
            print(f"ERROR: ML model could not be loaded (corrupt or incompatible): {m}", file=sys.stderr)
            return 2

    out = Path(a.out) if a.out else Path(tempfile.mkdtemp(prefix="aegis_link_stress_"))
    out.mkdir(parents=True, exist_ok=True)
    names = ("decisions.csv.gz", "cell_summary.csv", "sweep_table.md", prov.MANIFEST_NAME)
    clash = [n for n in names if (out / n).exists()]
    if clash:
        print(f"ERROR: refusing to overwrite existing output in {out}: {', '.join(clash)}", file=sys.stderr)
        return 2
    prof_dirs = {p: (str(REPO / d) if d else None) for p, d in PROFILES.items()}
    params = [session_params(a.seed, i) for i in range(a.sessions)]
    tasks = [{"cell": c.cid, "session": i, "params": params[i], "profile_dir": prof_dirs[c.profile], "model": m,
              "loss_pct": c.loss_pct, "ordering": c.ordering, "duration_s": a.duration_s}
             for c, m, na in plan if not na for i in range(a.sessions)]
    started = datetime.now(UTC).isoformat()
    if a.workers > 1:
        with ProcessPoolExecutor(max_workers=a.workers) as ex:
            results = list(ex.map(_run_task, tasks, chunksize=1))
    else:
        results = [_run_task(t) for t in tasks]
    by_cell: dict[str, list[dict[str, Any]]] = {}
    for r in sorted(results, key=lambda r: (r["cell"], r["session"])):
        by_cell.setdefault(r["cell"], []).append(r)

    summary, decisions = [], []
    for c, m, na in plan:
        if na:
            summary.append(na_row(c, na))
            continue
        sess = by_cell[c.cid]
        summary.append(summarise_cell(c, m, sess))
        for s in sess:
            decisions.extend({"profile": c.profile, "ordering": c.ordering, "loss_pct": f"{c.loss_pct:g}", "ml": c.ml,
                              "session": s["session"], "seed": s["seed"], **r} for r in s["rows"])

    write_decisions_gz(out / "decisions.csv.gz", decisions)
    with open(out / "cell_summary.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=SUMMARY_FIELDS, lineterminator="\n")
        w.writeheader()
        w.writerows(summary)
    meta = {"sessions": a.sessions, "seed0": a.seed, "link_base": json.dumps(_BASE_LINK),
            "duration_s": f"{a.duration_s:g} s" if a.duration_s else "simulator default (120 s)"}
    (out / "sweep_table.md").write_text(render_markdown(summary, meta), encoding="utf-8", newline="\n")

    ml_cells = {c.profile for c, _, na in plan if c.ml == "on" and not na}
    used_models = {p: m for p, m in models.items() if m and p in ml_cells}
    manifest = prov.collect_run_provenance(
        allow_dirty=a.allow_dirty, start_state=start_state, started_utc=started,
        command_line=" ".join(["python", "scripts/sweep_link_stress.py", *(sys.argv[1:] if argv is None else argv)]), ml_enabled=bool(used_models),
        extra={
            "script": "scripts/sweep_link_stress.py", "environment": ENVIRONMENT,
            "model_path": "per-profile, see models",
            "models": {p: {"path": Path(m).as_posix(), "sha256": prov.sha256_file(m)} for p, m in used_models.items()},
            "profiles": {p: {"dir": PROFILES[p] or "configs", "sha256": prov.sha256_dir(prof_dirs[p] or REPO / "configs")}
                         for p in a.profiles},
            "cli_args": vars(a), "seeds": [p["seed"] for p in params], "sessions_per_cell": a.sessions,
            "grid": [c.cid for c, _, _ in plan], "na_cells": {c.cid: na for c, _, na in plan if na},
            "link_base": _BASE_LINK, "warmup_s": WARMUP_S,
            "definitions": {"alert_event": "maximal run of consecutive scored alarm decisions within one session",
                            "decision_fpr": "alarm decisions / scored decisions (all sessions benign)"},
        })
    prov.finish_run(manifest)
    prov.write_manifest(out, manifest)
    if hasattr(sys.stdout, "reconfigure"):  # evidence strings contain non-ASCII (>=); Windows consoles default to cp1252
        sys.stdout.reconfigure(encoding="utf-8")
    print((out / "sweep_table.md").read_text(encoding="utf-8"))
    print(f"output: {out}  ({manifest['status']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
