"""Stage 2 metrics (issue #28) from committed artifacts only; nothing is re-run.

Writes ``artifacts/validation/stage2_metrics_<tag>/metrics.json`` and ``metrics.md``. Every number carries the path of
the artifact it was computed from. Every input is named in this file (``required_inputs``): if any named input is
absent the script lists every absent path, exits with status 2 and writes nothing, so no figure is silently dropped or
shown with n = 0. ``missing_inputs`` in the output lists what the repository does not contain by design (uncommitted
tlogs, external raw data, per-decision alert flags), which is why those sources stay decision level instead of being
estimated. Metric definitions: ``src/aegisflight/metrics/stage2.py`` (module docstring) and ``docs/BENCHMARKING.md``.

    python scripts/make_stage2_metrics.py --tag 2026-11-17
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "sitl"))

from make_p2_summary import load_trial  # noqa: E402

from aegisflight.metrics import stage2 as m  # noqa: E402

PERIOD_S = 0.2                                     # decision spacing: every committed decisions log steps t by 0.2 s
EXT = "artifacts/benchmarks_extended"
AP_BENIGN = ["ap_benign_final_noml_001", "ap_benign_final_noml_002", "ap_benign_groups_001",
             "ap_benign_six_001", "ap_benign_six_002", "ap_benign_six_003", "ap_benign_six_004"]
AP_DRIFT = ["ap_attack_final_drift_001", "ap_attack_final_drift_002", "ap_attack_final_drift_003"]
PRE_ARM = {"boot", "await_gps", "post_link"}
CLAIM = "link-level detection (false-alarm reference); not flight-hour or real-world validation"
CLAIM_BENCH = "link-level detection on a disarmed, props-off bench FC; exposure is wall time, not flight time"
PX4_LIVE = ["artifacts/sitl/live_run_001.jsonl", "artifacts/sitl/live_run_002.jsonl"]
BENCH = ["artifacts/hardware/serial_ids_com7_001", "artifacts/hardware/serial_ids_com7_002"]
PX4_P2 = ["artifacts/sitl/p2_final_trial_001", "artifacts/sitl/p2_final_trial_002", "artifacts/sitl/p2_final_trial_003"]
REPLAY_TLOG = "artifacts/sitl/benign_replay_stage1_default.json"
ALFA = "artifacts/external/alfa/results.json"


class MissingInputError(FileNotFoundError):
    """A named input is absent: the run stops instead of reporting a source with fewer (or zero) inputs."""


def required_inputs() -> list[str]:
    """Every file the generator reads, relative to the repository root."""
    return ([f"{EXT}/{f}" for f in ("decisions.csv.gz", "sessions.csv", "results.json")]
            + [f"artifacts/ardupilot/{d}/decisions.jsonl" for d in AP_BENIGN]
            + [f"artifacts/ardupilot/{d}/evaluation.json" for d in AP_DRIFT]
            + PX4_LIVE
            + [f"{d}{ext}" for d in PX4_P2 for ext in (".manifest.json", ".ids_decisions.jsonl")]
            + [f"{d}/summary.json" for d in BENCH]
            + [REPLAY_TLOG, ALFA])


def check_inputs(root: Path) -> None:
    absent = [p for p in required_inputs() if not (root / p).is_file()]
    if absent:
        raise MissingInputError(f"{len(absent)} named input(s) absent under {root}: " + ", ".join(absent))


def r6(x):
    return None if x is None else round(float(x), 6)


def rate_block(events: int, decisions: int, threats: int, src: str, note: str = "") -> dict:
    exp = decisions * PERIOD_S
    out = {"source": src, "alert_events": events, "decisions": decisions, "exposure_h": r6(exp / 3600),
           "false_alerts_per_h": r6(m.rate_per_hour(events, exp)) if exp else None,
           "false_alerts_per_h_upper95": r6(m.rate_upper_per_hour(events, exp)) if exp else None,
           "threat_decisions": threats, "decision_fpr": r6(threats / decisions) if decisions else None}
    if note:
        out["note"] = note
    return out


def load_sim(root: Path):
    rows = defaultdict(list)
    with gzip.open(root / EXT / "decisions.csv.gz", "rt", newline="") as f:
        for r in csv.DictReader(f):
            rows[int(r["session"])].append(r)
    with open(root / EXT / "sessions.csv", newline="") as f:
        sess = {int(r["idx"]): r for r in csv.DictReader(f)}
    for rs in rows.values():
        rs.sort(key=lambda r: float(r["t"]))
        ev = m.alert_events([(float(r["t"]), r["threat"] == "1", r["pred"]) for r in rs])
        for r, a in zip(rs, ev, strict=True):
            r["alert"] = a
    return rows, sess


def sim_false_alerts(rows, sess) -> dict:
    src = f"{EXT}/decisions.csv.gz"
    out: dict = {}
    for kind in ("benign", "link_fifo_benign", "link_reorder_benign"):
        rs = [r for i, s in sess.items() if s["kind"] == kind for r in rows[i] if r["warmup"] == "0"]
        out[kind] = rate_block(sum(r["alert"] for r in rs), len(rs), sum(r["threat"] == "1" for r in rs), src)
    for kind in ("single", "combo"):
        for g, grace in (("grace5", True), ("grace0", False)):
            rs = [r for i, s in sess.items() if s["kind"] == kind for r in rows[i]
                  if r["warmup"] == "0" and r["true"] == "BENIGN" and not (grace and r["in_grace"] == "1")]
            out[f"{kind}_attack_sessions_benign_decisions_{g}"] = rate_block(
                sum(r["alert"] for r in rs), len(rs), sum(r["threat"] == "1" for r in rs), src)
    return out


def confusion_crosscheck(fa: dict, root: Path) -> dict:
    """results.json scores benign + single sessions; the recomputed benign-row totals must match it exactly."""
    j = json.loads((root / EXT / "results.json").read_text())
    out = {}
    for g in ("grace5", "grace0"):
        row = j[f"confusion_{g}"]["BENIGN"]
        n = fa["benign"]["decisions"] + fa[f"single_attack_sessions_benign_decisions_{g}"]["decisions"]
        th = fa["benign"]["threat_decisions"] + fa[f"single_attack_sessions_benign_decisions_{g}"]["threat_decisions"]
        out[g] = {"recomputed": [n, th], "results_json": [sum(row.values()), sum(row.values()) - row["BENIGN"]],
                  "match": [n, th] == [sum(row.values()), sum(row.values()) - row["BENIGN"]]}
    return out


def sim_sessions(rows, sess) -> dict:
    src = f"{EXT}/sessions.csv"
    det = defaultdict(list)
    ttd = defaultdict(list)
    for s in sess.values():
        if s["kind"] in ("single", "combo"):
            cls = s["key"].split(":")[0] if s["kind"] == "single" else "combo:" + s["key"]
            det[cls].append(s["detected"] == "True")
            if s["ttd_s"]:
                ttd[cls].append(float(s["ttd_s"]))
    out: dict = {"detection": {}, "benign_session_fpr": {}}
    for cls, d in sorted(det.items()):
        k, n = sum(d), len(d)
        lo, hi = m.wilson(k, n)
        lat = ttd[cls]
        out["detection"][cls] = {"source": src, "detected": k, "sessions": n, "rate": r6(k / n), "wilson95": [r6(lo), r6(hi)],
                                 "latency_from_onset_s": {"n": len(lat), "median": r6(m.nearest_rank(lat, 50)),
                                                          "p95": r6(m.nearest_rank(lat, 95))}}
    for kind in ("benign", "link_fifo_benign", "link_reorder_benign"):
        ids = [i for i, s in sess.items() if s["kind"] == kind]
        for label, hit in (("any_threat_decision", lambda i: int(sess[i]["fp_decisions"]) > 0),
                           ("any_alert_event", lambda i: any(r["alert"] for r in rows[i] if r["warmup"] == "0"))):
            k = sum(hit(i) for i in ids)
            lo, hi = m.wilson(k, len(ids))
            out["benign_session_fpr"][f"{kind}/{label}"] = {
                "source": src if label == "any_threat_decision" else f"{EXT}/decisions.csv.gz",
                "sessions_flagged": k, "sessions": len(ids), "rate": r6(k / len(ids)), "wilson95": [r6(lo), r6(hi)]}
    return out


def ttd_crosscheck(rows, sess) -> dict:
    """Recompute time_to_detect from the decisions and compare with sessions.csv."""
    worst, n = 0.0, 0
    for i, s in sess.items():
        if s["kind"] == "single" and s["ttd_s"]:
            lat = m.onset_latency([(float(r["t"]), r["true"] != "BENIGN" and r["warmup"] == "0", r["threat"] == "1")
                                   for r in rows[i]])
            if lat["from_onset_s"] is not None:
                worst, n = max(worst, abs(lat["from_onset_s"] - float(s["ttd_s"]))), n + 1
    return {"sessions_compared": n, "max_abs_diff_s": r6(worst)}


def drift_latency(root: Path) -> dict:
    ap = []
    for d in AP_DRIFT:
        p = f"artifacts/ardupilot/{d}/evaluation.json"
        e = json.loads((root / p).read_text())
        w, fa = e["window_decision_time"], e["observed_arm"]["first_alert"]
        ap.append({"source": p, "from_onset_s": r6(fa["t"] - w["onset_t_s"]) if fa else None,
                   "from_release_s": r6(fa["t"] - w["end_t_s"]) if fa else None})
    px = []
    for d in PX4_P2:
        t = load_trial(root / f"{d}.manifest.json")
        px.append({"source": f"{d}.manifest.json", "from_onset_s": t["time_to_detection_from_onset_s"],
                   "from_release_s": t["time_to_detection_from_end_s"],
                   "note": "detection counted only after the attack window ends (preregistered P2 rule)"})

    def summ(xs, key):
        v = [x[key] for x in xs if x[key] is not None]
        return {"n": len(v), "of": len(xs), "median": r6(m.nearest_rank(v, 50)), "p95": r6(m.nearest_rank(v, 95))}
    return {"sitl_ardupilot": {"trials": ap, "from_onset": summ(ap, "from_onset_s"), "from_release": summ(ap, "from_release_s")},
            "sitl_px4": {"trials": px, "from_onset": summ(px, "from_onset_s"), "from_release": summ(px, "from_release_s")}}


def sitl_benign(root: Path) -> dict:
    out = {}
    for d in AP_BENIGN:
        p = f"artifacts/ardupilot/{d}/decisions.jsonl"
        rs = [json.loads(ln) for ln in (root / p).read_text().splitlines() if ln]
        rs = [r for r in rs if r.get("phase") != "post_link"]
        fl = [r for r in rs if r.get("phase") not in PRE_ARM]
        out[d] = {"all_phases": rate_block(sum(r["alert"] for r in rs), len(rs), sum(r["threat"] for r in rs), p),
                  "armed_phases": rate_block(sum(r["alert"] for r in fl), len(fl), sum(r["threat"] for r in fl), p,
                                             "excludes boot / await_gps (pre-arm GPS convergence)")}
    tot = {}
    for part in ("all_phases", "armed_phases"):
        ev = sum(v[part]["alert_events"] for v in out.values())
        n = sum(v[part]["decisions"] for v in out.values())
        th = sum(v[part]["threat_decisions"] for v in out.values())
        tot[part] = rate_block(ev, n, th, "artifacts/ardupilot/{" + ",".join(AP_BENIGN) + "}/decisions.jsonl")
    return {"runs": out, "pooled": tot}


def px4_live(root: Path) -> dict:
    """PX4 live-UDP benign runs log (t, threat, type) per decision; alert events are re-derived with the engine rule."""
    out = {}
    for p in PX4_LIVE:
        rs = [json.loads(ln) for ln in (root / p).read_text().splitlines() if ln]
        ev = m.alert_events([(float(r["t"]), bool(r["threat"]), r["type"]) for r in rs])
        out[Path(p).stem] = rate_block(sum(ev), len(rs), sum(bool(r["threat"]) for r in rs), p,
                                       "alert events re-derived (severity not logged; shipped config: threat implies "
                                       ">= SUSPICIOUS); run predates per-vehicle calibration")
    return out


def bench(root: Path) -> dict:
    out = {}
    for d in BENCH:
        p = f"{d}/summary.json"
        s = json.loads((root / p).read_text())
        exp = float(s["wall_s"])
        out[Path(d).name] = {"source": p, "alert_events": s["alert_decisions"], "exposure_h": r6(exp / 3600),
                             "false_alerts_per_h": r6(m.rate_per_hour(s["alert_decisions"], exp)),
                             "false_alerts_per_h_upper95": r6(m.rate_upper_per_hour(s["alert_decisions"], exp)),
                             "decisions": s["decisions"], "threat_decisions": s["threat_decisions"],
                             "decision_fpr": r6(s["threat_decisions"] / s["decisions"]),
                             "note": CLAIM_BENCH}
    return out


def replay(root: Path) -> dict:
    p = REPLAY_TLOG
    j = json.loads((root / p).read_text())
    runs = [{"source": p, "flight": r["flight"], "decisions": r["decisions"], "threat_decisions": r["false_alarm_decisions"],
             "decision_fpr": r6(r["false_alarm_rate"])} for r in j["runs"]]
    pa = ALFA
    a = json.loads((root / pa).read_text())
    return {"benign_tlog_replay": runs,
            "alfa": {"source": pa, "decision_hours": a["total_decision_hours"], "note": "decision-level only; see file"}}


def classification(root: Path) -> dict:
    p = f"{EXT}/results.json"
    j = json.loads((root / p).read_text())
    out = {}
    for g in ("grace5", "grace0"):
        cm = j[f"confusion_{g}"]
        prf = m.per_class_prf(cm)
        out[g] = {"source": f"{p}#confusion_{g}", "confusion": cm,
                  "per_class": {c: {k: r6(v) if isinstance(v, float) else v for k, v in d.items()} for c, d in prf.items()},
                  "macro_f1": r6(m.macro_f1(prf)),
                  "binary": {k: r6(v) if isinstance(v, float) else v for k, v in j[f"binary_{g}"].items()},
                  "accuracy": r6(m.accuracy(cm))}
    return out


MISSING = [
    {"source": "REPLAY data/sitl/raw/benign_00*.tlog", "missing": "the tlogs are not committed (only their .json metadata)",
     "effect": "replay alert events cannot be re-derived; replay figure stays decision level"},
    {"source": "REPLAY ALFA raw tlogs", "missing": "external dataset not in the repository",
     "effect": "ALFA alert events cannot be re-derived"},
    {"source": "REPLAY artifacts/sitl/benign_replay_stage1_default.json", "missing": "per-decision alert flags",
     "effect": "decision-level FPR only"},
    {"source": "REPLAY artifacts/external/alfa/results.json", "missing": "per-decision alert flags",
     "effect": "decision-level only"},
    {"source": "BENCH", "missing": "any airborne exposure", "effect": "bench rate is per wall hour on a disarmed FC"},
    {"source": "REAL flight", "missing": "everything", "effect": "no real-flight figure exists; none is claimed"},
]


def build(root: Path) -> dict:
    check_inputs(root)
    rows, sess = load_sim(root)
    sim = sim_false_alerts(rows, sess)
    return {
        "schema": "aegisflight.stage2_metrics/1",
        "definitions": "src/aegisflight/metrics/stage2.py; docs/BENCHMARKING.md#stage-2-metrics",
        "decision_period_s": PERIOD_S,
        "claim_class": CLAIM, "claim_class_bench": CLAIM_BENCH,
        "false_alerts_per_hour": {"SIM": sim, "SITL_ardupilot": sitl_benign(root), "SITL_px4_live": px4_live(root),
                                  "REPLAY": replay(root), "BENCH": bench(root)},
        "sessions": sim_sessions(rows, sess),
        "confusion_crosscheck_vs_results_json": confusion_crosscheck(sim, root),
        "latency_crosscheck_vs_sessions_csv": ttd_crosscheck(rows, sess),
        "drift_latency": drift_latency(root),
        "classification": classification(root),
        "missing_inputs": MISSING,
    }


def fmt(x):
    return "-" if x is None else (f"{x:.4g}" if isinstance(x, float) else str(x))


def to_md(r: dict) -> str:
    L = ["# Stage 2 metrics", "", f"Definitions: `{r['definitions']}`. Decision period {r['decision_period_s']} s.", "",
         f"**Claim class (every SIM / SITL / REPLAY figure): {r['claim_class']}.** "
         f"BENCH: {r['claim_class_bench']}. No figure here is real-flight evidence.", "",
         "## 1. False alerts per hour (alert events after cooldown, benign ground truth)", "",
         "| source | set | events | exposure h | per h | 95% upper | decision FPR | artifact |", "|---|---|---|---|---|---|---|---|"]

    def row(src, name, b):
        L.append(f"| {src} | {name} | {b['alert_events']} | {fmt(b['exposure_h'])} | {fmt(b['false_alerts_per_h'])} | "
                 f"{fmt(b['false_alerts_per_h_upper95'])} | {fmt(b['decision_fpr'])} | `{b['source']}` |")
    fa = r["false_alerts_per_hour"]
    for k, b in fa["SIM"].items():
        row("SIM", k, b)
    for k, b in fa["SITL_ardupilot"]["runs"].items():
        row("SITL", f"{k} all", b["all_phases"])
        row("SITL", f"{k} armed", b["armed_phases"])
    for k, b in fa["SITL_ardupilot"]["pooled"].items():
        row("SITL", f"pooled {k}", b)
    for k, b in fa["SITL_px4_live"].items():
        row("SITL-PX4", k, b)
    for k, b in fa["BENCH"].items():
        row("BENCH", k, b)
    L += ["", "REPLAY (decision level only, no alert flags logged):", ""]
    L += [f"- {x['flight']}: decision FPR {fmt(x['decision_fpr'])} ({x['threat_decisions']}/{x['decisions']}), `{x['source']}`"
          for x in fa["REPLAY"]["benign_tlog_replay"]]
    L += ["", "## 2. Grace (with vs without)", "",
          "Grace excludes benign decisions in the 5 s after an attack stops: the recovery tail, where the detector state "
          "(residual windows, rate counters) still reflects the attack, so a threat there is late attribution of a real "
          "attack, not a false alarm on benign traffic. Both are shown; grace0 is the conservative figure.", ""]
    for kind in ("single", "combo"):
        for g in ("grace5", "grace0"):
            b = fa["SIM"][f"{kind}_attack_sessions_benign_decisions_{g}"]
            L.append(f"- {kind} {g}: {b['alert_events']} events / {fmt(b['exposure_h'])} h "
                     f"({fmt(b['false_alerts_per_h'])}/h, upper {fmt(b['false_alerts_per_h_upper95'])}), "
                     f"decision FPR {fmt(b['decision_fpr'])}")
    L += ["", f"Recomputed benign row vs `{EXT}/results.json` (benign + single sessions): "
          f"{r['confusion_crosscheck_vs_results_json']}."]
    L += ["", "## 3. Session-level detection (Wilson 95%) and onset latency", "",
          "| class | detected/n | rate | 95% CI | latency n | median s | p95 s |", "|---|---|---|---|---|---|---|"]
    for c, d in r["sessions"]["detection"].items():
        lat = d["latency_from_onset_s"]
        L.append(f"| {c} | {d['detected']}/{d['sessions']} | {fmt(d['rate'])} | {fmt(d['wilson95'][0])}-{fmt(d['wilson95'][1])} | "
                 f"{lat['n']} | {fmt(lat['median'])} | {fmt(lat['p95'])} |")
    L += ["", f"Source: `{EXT}/sessions.csv`. Recomputed latency vs `ttd_s`: {r['latency_crosscheck_vs_sessions_csv']}.", "",
          "Benign session FPR:", ""]
    for k, d in r["sessions"]["benign_session_fpr"].items():
        L.append(f"- {k}: {d['sessions_flagged']}/{d['sessions']}, CI {fmt(d['wilson95'][0])}-{fmt(d['wilson95'][1])} (`{d['source']}`)")
    L += ["", "## 4. Drift latency (from onset and from release)", ""]
    for env, d in r["drift_latency"].items():
        L.append(f"- {env}: from onset {d['from_onset']}, from release {d['from_release']}")
        L += [f"  - `{t['source']}`: onset {fmt(t['from_onset_s'])} s, release {fmt(t['from_release_s'])} s" for t in d["trials"]]
    L += ["", "## 5. Per-class precision / recall / F1 (extended benchmark)", ""]
    for g, c in r["classification"].items():
        L += [f"### {g} (`{c['source']}`)", "", "| class | P | R | F1 | support |", "|---|---|---|---|---|"]
        L += [f"| {k} | {fmt(v['precision'])} | {fmt(v['recall'])} | {fmt(v['f1'])} | {v['support']} |" for k, v in c["per_class"].items()]
        labels = list(c["confusion"])
        L += ["", f"Macro-F1 {fmt(c['macro_f1'])}.", "", "Confusion (rows true, columns predicted):", "",
              "| true \\ pred | " + " | ".join(labels) + " |", "|---" * (len(labels) + 1) + "|"]
        L += [f"| {t} | " + " | ".join(str(c["confusion"][t].get(p, 0)) for p in labels) + " |" for t in labels]
        L.append("")
    L += ["## 6. Accuracy (last; dominated by the benign majority)", ""]
    L += [f"- {g}: {fmt(c['accuracy'])} (`{c['source']}`)" for g, c in r["classification"].items()]
    L += ["", "## Missing inputs", ""] + [f"- {x['source']}: missing {x['missing']} -> {x['effect']}" for x in r["missing_inputs"]]
    return "\n".join(L) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--root", default=str(ROOT))
    ap.add_argument("--out-dir", default=None)
    a = ap.parse_args(argv)
    root = Path(a.root)
    try:
        res = build(root)
    except MissingInputError as e:
        print(f"error: {e}; nothing written", file=sys.stderr)
        return 2
    out = Path(a.out_dir) if a.out_dir else root / "artifacts" / "validation" / f"stage2_metrics_{a.tag}"
    out.mkdir(parents=True, exist_ok=True)
    # newline="\n": LF on every OS, so a regeneration on Windows is byte-identical to the committed (eol=lf) evidence
    (out / "metrics.json").write_text(json.dumps(res, separators=(",", ":")) + "\n", encoding="utf-8", newline="\n")
    (out / "metrics.md").write_text(to_md(res), encoding="utf-8", newline="\n")
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
