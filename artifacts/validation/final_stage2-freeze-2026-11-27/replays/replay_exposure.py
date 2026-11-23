#!/usr/bin/env python
"""Per-log replay table for issue #27 item 3 (REPLAY): decisions, alerts, alert events/hour, exposure, dominant evidence.

    python artifacts/validation/final_stage2-freeze-2026-11-27/replays/replay_exposure.py --out <dir> [--workers 6]

Run from the repository root on a clean tree at the freeze tag. This is a SEPARATE small script (not under scripts/):
the replay tools it wraps print aggregate counts but do not report alert events per hour of exposure. It calls the
unchanged replay functions of the existing tools and only adds the arithmetic:

  * ``scripts/ardupilot/replay_ap_tlog.py : replay``   bench captures, the 28 Oct run, the 5 ArduCopter benign tlogs
  * ``scripts/sitl/replay_benign.py       : replay``   PX4 SITL benign tlogs (Stage-1 tlog adapter)
  * ``scripts/external_validation.py      : _alfa_one``  ALFA real tlogs (full IDSPipeline), as in E2; with
    ``--e2b-results`` also as in E2b (rate thresholds from that run's ``protocol_overrides``, ML off, test dates only)

Every log is replayed under the DEFAULT live profile (``configs/``), ML off and ML on (``models/isoforest.joblib``).
The PX4 Flight Review ULog replay (E1) is not here: it has no decision-level alarm stream (navigation features only); its
per-flight output is taken from ``scripts/external_validation.py`` unchanged.

Definitions (same as ``scripts/sweep_link_stress.py``):
  decision        one fusion decision (5 Hz; the median decision spacing of each replay is recorded). For the ALFA
                  groups, overlapping recordings of the same flight are de-duplicated exactly as
                  ``scripts/external_validation.py`` does (``alfa.dedup_overlapping_recordings``, largest recording
                  first); ``decisions_before_dedup`` is the raw count of that log.
  alert decision ``is_alert`` of the pipeline's assessment (the pipeline's own alert flag); only the
                  ``replay_ap_tlog`` replays carry it, so it is empty for PX4 SITL and ALFA rows.
  threat decision ``threat == True`` (every replayed log is treated as benign unless noted, so each is a false-alarm
                  candidate; ALFA fault periods are reported separately via the ``gt`` columns).
  alert event     maximal run of consecutive threat decisions inside one stream (an ALFA stream is one segment).
  exposure        decisions x 0.2 s (the decision period); ``link_span_s`` is last-first decision time for reference.
  events / hour   alert events / exposure hours.
  dominant evidence  most frequent normalised evidence string over the threat decisions, once per decision
                  (digits collapsed to ``#``; ``coverage...`` notes ignored; ties alphabetical).
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
import sys
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

REPO = Path.cwd()
for sub in ("src", "scripts", "scripts/sitl", "scripts/ardupilot"):
    sys.path.insert(0, str(REPO / sub))

MODEL = "models/isoforest.joblib"
PERIOD_S = 0.2

SUMMARY_FIELDS = ["group", "env", "log", "bytes", "sha256", "ml", "decisions_before_dedup", "decisions", "threat_decisions", "alert_decisions",
                  "alert_events", "exposure_s", "exposure_h", "link_span_s", "median_dt_s", "events_per_hour",
                  "dominant_evidence", "dominant_evidence_count", "dominant_detector", "note"]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _norm(e: str) -> str:
    import re
    return re.sub(r"[-\d.]+", "#", e)[:90]


def _keys(evidence) -> list[str]:
    ev = evidence if isinstance(evidence, list) else [evidence]
    return [_norm(str(e)) for e in ev if not str(e).startswith("coverage")]


def _runs(flags: list[bool]) -> int:
    return sum(1 for i, a in enumerate(flags) if a and (i == 0 or not flags[i - 1]))


def summarise(rows: list[dict], streams: list[list[dict]] | None = None) -> dict:
    """rows: one dict per decision with ``t``, ``threat``, ``evidence`` (list), optional ``alert``/``det``."""
    streams = streams if streams is not None else [rows]
    n = sum(len(s) for s in streams)
    events = sum(_runs([bool(r["threat"]) for r in s]) for s in streams)
    thr = [r for s in streams for r in s if r["threat"]]
    keys: Counter[str] = Counter()
    dets: Counter[str] = Counter()
    for r in thr:
        keys.update(set(_keys(r["evidence"])))
        dets.update(r.get("dets", []))
    ts = sorted(r["t"] for s in streams for r in s)
    dts = sorted(b - a for a, b in zip(ts, ts[1:], strict=False) if b > a)
    dom = min(keys.items(), key=lambda kv: (-kv[1], kv[0])) if keys else ("-", 0)
    expo = n * PERIOD_S
    return {"decisions": n, "threat_decisions": len(thr), "alert_decisions": (sum(bool(r.get("alert")) for s in streams for r in s)
                        if any("alert" in r for s in streams for r in s) else ""), "alert_events": events, "exposure_s": f"{expo:.1f}", "exposure_h": f"{expo / 3600:.5f}",
            "link_span_s": f"{(ts[-1] - ts[0]) if ts else 0:.1f}",
            "median_dt_s": f"{dts[len(dts) // 2]:.3f}" if dts else "",
            "events_per_hour": f"{events / (expo / 3600):.1f}" if expo else "",
            "dominant_evidence": dom[0], "dominant_evidence_count": dom[1],
            "dominant_detector": dets.most_common(1)[0][0] if dets else "-", "_keys": keys.most_common(8)}


def _job(task: dict) -> dict:
    from aegisflight.config import load_config
    path = Path(task["path"])
    model = MODEL if task["ml"] == "on" else None
    cfg = load_config(None)
    kind = task["kind"]
    gt_split = None
    if kind == "ap":
        import replay_ap_tlog
        rows, _ = replay_ap_tlog.replay(path, cfg, model, float(cfg.simulation.get("sample_rate_hz", 10.0)))
        dec = [{"t": r["t"], "threat": r["threat"], "alert": r["alert"], "evidence": r["evidence"],
                "dets": [k for k, v in r["detector_scores"].items() if v >= 0.5]} for r in rows]
        streams = [dec]
    elif kind == "px4sitl":
        import replay_benign
        rows = replay_benign.replay(str(path), cfg, model, "tlog")
        dec = [{"t": r["t"] + 100000 * r["seg"], "threat": r["threat"], "evidence": r["evidence"],
                "dets": [d for d in ("det_protocol_rule", "det_physics_consistency", "det_ml_anomaly")
                         if r.get(d, 0.0) >= (0.62 if d == "det_ml_anomaly" else 0.5)]} for r in rows]
        by: dict[int, list[dict]] = {}
        for r, d in zip(rows, dec, strict=True):
            by.setdefault(r["seg"], []).append(d)
        streams = list(by.values())
    elif kind == "alfa":
        import external_validation as ev
        out = ev._alfa_one((str(path), task.get("over"), task["ml"] == "on"))
        if "excluded" in out:
            return {"task": task, "excluded": out["excluded"]}
        light = [(r["t_unix"], r["seg"], bool(r["threat"]), r["gt"],
                  tuple(sys.intern(k) for k in _keys(r["evidence"])) if r["threat"] else (),
                  tuple(k for k in ("det_protocol_rule", "det_physics_consistency", "det_ml_anomaly")
                        if r[k] >= (0.62 if k == "det_ml_anomaly" else 0.5)) if r["threat"] else ())
                 for r in out["rows"]]
        return {"task": task, "alfa_light": light}
    else:
        raise ValueError(kind)
    s = summarise([], streams)
    thr_rows = [{"t": d["t"], "evidence": " | ".join(map(str, d["evidence"]))} for d in dec if d["threat"]]
    return {"task": task, "summary": s, "gt_split": gt_split, "threat_rows": thr_rows if kind != "alfa" else []}


def _alfa_dedup(results: list[dict]) -> tuple[list[dict], list[dict]]:
    """ALFA ships overlapping GCS recordings of one flight. As the tool does (``alfa.dedup_overlapping_recordings``,
    per experiment), count each instant once, largest recording first, then summarise the kept decisions per log.
    ``decisions_before_dedup`` keeps the raw count. Also returns per-(group, ML, ground truth) totals BEFORE
    de-duplication, so the effect of the tool's keep-the-largest rule is visible."""
    from aegisflight.external import alfa
    out = [r for r in results if "alfa_light" not in r]
    raw_split: list[dict] = []
    groups: dict[tuple[str, str], list[dict]] = {}
    for r in results:
        if "alfa_light" in r:
            groups.setdefault((r["task"]["group"], r["task"]["ml"]), []).append(r)
    for (_g, _ml), rs in sorted(groups.items()):
        flights = [{"r": r, "rows": [{"t_unix": t, "seg": seg, "threat": thr, "gt": gt, "keys": k, "dets": d}
                                     for t, seg, thr, gt, k, d in r["alfa_light"]]} for r in rs]
        n_raw = {id(f["r"]): len(f["rows"]) for f in flights}
        for cat in ("benign_gt", "fault", "unlabelled"):
            allr = [x for f in flights for x in f["rows"] if x["gt"] == cat]
            raw_split.append({"group": _g, "ml": _ml, "gt": cat, "decisions_before_dedup": len(allr),
                              "threat_decisions_before_dedup": sum(x["threat"] for x in allr)})
        kept, _n_drop = alfa.dedup_overlapping_recordings(flights)
        for f in kept:
            by: dict[int, list[dict]] = {}
            for x in f["rows"]:
                by.setdefault(x["seg"], []).append({"t": x["t_unix"], "threat": x["threat"], "evidence": list(x["keys"]),
                                                    "dets": list(x["dets"]), "gt": x["gt"]})
            streams = list(by.values())
            gt_split = {}
            for cat in ("benign_gt", "fault", "unlabelled"):
                sub = [s2 for s2 in ([d for d in st if d["gt"] == cat] for st in streams) if s2]
                gt_split[cat] = {k: v for k, v in summarise([], sub).items() if k != "_keys"} if sub else None
            out.append({"task": f["r"]["task"], "summary": summarise([], streams) if streams else summarise([], [[]]),
                        "gt_split": gt_split, "threat_rows": [], "n_raw": n_raw[id(f["r"])]})
    return out, raw_split


def build_tasks(raw: Path, ap_raw: Path, hw_raw: Path, px4_sitl: Path, e2b: Path | None = None) -> list[dict]:
    t: list[dict] = []

    def add(group, env, kind, path: Path, note=""):
        for ml in ("off", "on"):
            t.append({"group": group, "env": env, "kind": kind, "path": str(path),
                      "log": path.relative_to(raw / "alfa").as_posix() if kind == "alfa" else path.name, "ml": ml,
                      "note": note})

    for n in ("005", "006", "007", "008", "009"):
        add("bench_capture", "REPLAY of BENCH", "ap", hw_raw / f"telemetry_radio_{n}.tlog")
    add("bench_28oct_run", "REPLAY of BENCH", "ap", hw_raw / "gps_hw_verify_20261029.tlog",
        "capture of 2026-10-28 (filename date 20261029)")
    for n in ("ap_benign_six_001", "ap_benign_six_002", "ap_benign_six_003", "ap_benign_six_004",
              "ap_benign_groups_001"):
        add("arducopter_benign", "REPLAY of SITL", "ap", ap_raw / f"{n}.clean.tlog",
            "clean.tlog; observed.tlog is byte-identical for these runs")
    for i in range(1, 11):
        add("px4_sitl_benign", "REPLAY of SITL", "px4sitl", px4_sitl / f"benign_{i:03d}.tlog")
    for p in sorted((raw / "alfa" / "telemetry").rglob("*.tlog")):
        add("alfa", "REPLAY", "alfa", p, "ALFA fixed-wing ArduPlane; includes fault periods")
    if e2b is not None and e2b.exists():  # E2b of scripts/external_validation.py: per-vehicle rate thresholds, ML off
        import external_validation as ev
        over = json.loads(e2b.read_text(encoding="utf-8"))["calibration"]["protocol_overrides"]
        for p in sorted((raw / "alfa" / "telemetry").rglob("*.tlog")):
            if p.parent.parent.name in ev.CALIBRATION_DATES:
                continue  # calibration dates are not test data in E2b
            t.append({"group": "alfa_e2b_calibrated", "env": "REPLAY", "kind": "alfa", "path": str(p),
                      "log": p.relative_to(raw / "alfa").as_posix(), "ml": "off", "over": over,
                      "note": "ALFA test dates; protocol rate thresholds calibrated per vehicle on the calibration "
                              f"dates (nominal_msg_rate_hz={over['nominal_msg_rate_hz']:.1f}); ML off"})
    return t


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--raw", type=Path, default=Path("data/external/raw"))
    ap.add_argument("--hw-raw", type=Path, default=Path("data/hardware/raw"))
    ap.add_argument("--ap-raw", type=Path, default=Path("data/ardupilot/raw"))
    ap.add_argument("--px4-sitl-raw", type=Path, default=Path("data/sitl/raw"))
    ap.add_argument("--e2b-results", type=Path, default=None,
                    help="results.json of the tool's E2b run; adds the calibrated ALFA group (read-only use of its "
                         "protocol_overrides)")
    ap.add_argument("--only", nargs="*", default=None, help="restrict to these groups")
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    tasks = build_tasks(a.raw, a.ap_raw, a.hw_raw, a.px4_sitl_raw, a.e2b_results)
    missing = sorted({t["path"] for t in tasks if not Path(t["path"]).exists()})
    present = [t for t in tasks if Path(t["path"]).exists() and (not a.only or t["group"] in a.only)]
    sha: dict[str, tuple[int, str]] = {}
    for t in present:
        if t["path"] not in sha:
            p = Path(t["path"])
            sha[t["path"]] = (p.stat().st_size, sha256_file(p))
    with ProcessPoolExecutor(max_workers=a.workers) as ex:
        results = list(ex.map(_job, present, chunksize=1))
    results, raw_split = _alfa_dedup(results)
    rows_out, ev_rows, thr_out, split_rows = [], [], [], []
    for r in results:
        t = r["task"]
        size, h = sha[t["path"]]
        base = {"group": t["group"], "env": t["env"], "log": t["log"], "bytes": size, "sha256": h, "ml": t["ml"],
                "note": t["note"]}
        if "excluded" in r:
            rows_out.append({**dict.fromkeys(SUMMARY_FIELDS, ""), **base, "note": f"excluded by tool: {r['excluded']}"})
            continue
        s = r["summary"]
        rows_out.append({**base, "decisions_before_dedup": r.get("n_raw", s["decisions"]),
                         **{k: v for k, v in s.items() if not k.startswith("_")}})
        for k, c in s["_keys"]:
            ev_rows.append({"group": t["group"], "log": t["log"], "ml": t["ml"], "evidence": k, "threat_decisions": c})
        for x in r["threat_rows"]:
            thr_out.append({"group": t["group"], "log": t["log"], "ml": t["ml"], **x})
        for cat, v in (r["gt_split"] or {}).items():
            if v:
                split_rows.append({"group": t["group"], "log": t["log"], "ml": t["ml"], "gt": cat,
                                   **{k: v[k] for k in ("decisions", "threat_decisions", "alert_events", "exposure_h",
                                                        "events_per_hour", "dominant_evidence")}})
    key = lambda r: (r["group"], r["log"], r["ml"])  # noqa: E731
    rows_out.sort(key=key)
    with open(a.out / "replay_table.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=SUMMARY_FIELDS, lineterminator="\n")
        w.writeheader()
        w.writerows(rows_out)
    with open(a.out / "replay_evidence_counts.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["group", "log", "ml", "evidence", "threat_decisions"], lineterminator="\n")
        w.writeheader()
        w.writerows(sorted(ev_rows, key=lambda r: (r["group"], r["log"], r["ml"], -r["threat_decisions"], r["evidence"])))
    with open(a.out / "alfa_by_ground_truth.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["group", "log", "ml", "gt", "decisions", "threat_decisions", "alert_events",
                                          "exposure_h", "events_per_hour", "dominant_evidence"], lineterminator="\n")
        w.writeheader()
        w.writerows(sorted(split_rows, key=lambda r: (r["log"], r["ml"], r["gt"])))
    with open(a.out / "alfa_before_dedup_by_ground_truth.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["group", "ml", "gt", "decisions_before_dedup",
                                          "threat_decisions_before_dedup"], lineterminator="\n")
        w.writeheader()
        w.writerows(sorted(raw_split, key=lambda r: (r["group"], r["ml"], r["gt"])))
    with open(a.out / "replay_threat_decisions.csv.gz", "wb") as raw_f, \
            gzip.GzipFile(fileobj=raw_f, mode="wb", mtime=0, filename="") as gz:
        text = io.TextIOWrapper(gz, encoding="utf-8", newline="")
        w = csv.DictWriter(text, fieldnames=["group", "log", "ml", "t", "evidence"], lineterminator="\n")
        w.writeheader()
        w.writerows(sorted(thr_out, key=lambda r: (r["group"], r["log"], r["ml"], r["t"])))
        text.flush()
        text.detach()
    (a.out / "replay_missing.json").write_text(json.dumps({"not_available_on_this_host": missing}, indent=2),
                                              encoding="utf-8", newline="\n")
    print(f"replayed {len(present)} (log, ML) jobs; missing paths: {missing}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
