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
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "sitl"))

from make_p2_summary import load_trial  # noqa: E402

from aegisflight.metrics import stage2 as m  # noqa: E402

PERCENTILES = ("nearest rank, no interpolation: the median is the lower middle value for even n, and with n < 20 the "
               "nearest-rank p95 is the maximum")
RULE_SIM = ("first threat decision (any type) among the decisions labelled with the attack; onset = the first labelled "
            "decision (benchmark ttd_s; sessions.csv)")
RULE_AP = ("first is_alert decision (any type) in [window onset, window end + post_window_grace_s]; onset and release = "
           "evaluation.json window_decision_time onset_t_s / end_t_s (scripts/ardupilot/evaluate_ap_attack.py)")
RULE_P2 = ("first GPS_SPOOFING threat decision at or after the window end (onset_s + duration_s); onset = manifest "
           "onset_s (scripts/sitl/make_p2_summary.py load_trial; preregistered P2 rule)")
PERIOD_S = 0.2                                     # decision spacing: every committed decisions log steps t by 0.2 s
EXT = "artifacts/benchmarks_extended"
AP_BENIGN = ["ap_benign_final_noml_001", "ap_benign_final_noml_002", "ap_benign_groups_001",
             "ap_benign_six_001", "ap_benign_six_002", "ap_benign_six_003", "ap_benign_six_004"]
AP_DRIFT = ["ap_attack_final_drift_001", "ap_attack_final_drift_002", "ap_attack_final_drift_003"]
# ArduPilot phases: boot, await_gps, arm, takeoff, square, rtl, landed, post_link (decisions after the link span, which
# the run's own summary.json also excludes). artifacts/ardupilot/BASELINE_SUMMARY.md counts arm as ground.
BEFORE_ARM = {"boot", "await_gps"}
CLAIM = ("per row, in each source's own words (\"not recorded\" where the source states none); no figure here is "
         "flight-hour, real-flight or real-world validation")
BENCH_DOC = "docs/HARDWARE_BENCH_PIXHAWK6X.md"      # the bench write-up: states the claim class of runs without a manifest
PX4_LIVE = ["artifacts/sitl/live_run_001.jsonl", "artifacts/sitl/live_run_002.jsonl"]
BENCH = ["artifacts/hardware/serial_ids_com7_001", "artifacts/hardware/serial_ids_com7_002",
         "artifacts/hardware/gps_hw_verify_20261029/live_capture"]
# BENCH runs whose own manifest states their environment and claim class; the others take BENCH_DOC's header
BENCH_MANIFEST = {"artifacts/hardware/gps_hw_verify_20261029/live_capture": "artifacts/hardware/gps_hw_verify_20261029/manifest.json"}
PX4_P2 = ["artifacts/sitl/p2_final_trial_001", "artifacts/sitl/p2_final_trial_002", "artifacts/sitl/p2_final_trial_003"]
REPLAY_TLOG = "artifacts/sitl/benign_replay_stage1_default.json"
ALFA = "artifacts/external/alfa/results.json"
NR = "not recorded"
# BENCH runs whose summary.json records no commit: only what the bench write-up (BENCH_DOC) states about them. The
# 001 alert counts are filled in from its alerts.jsonl evidence text (bench_notes).
BENCH_NOTES = {
    "artifacts/hardware/serial_ids_com7_001": (
        "not comparable with serial_ids_com7_002: run 2026-10-14 on 6b21d1f plus uncommitted src/aegisflight/"
        "{{detectors/protocol.py, features/extractor.py, sources/mavlink_serial.py}} changes, on an indoor desk with no GPS "
        "fix (docs/HARDWARE_BENCH_PIXHAWK6X.md section 6.8). Of its {total} alerts, {never} (never-received streams at "
        "t = 0) would not be raised after the 2026-10-15 policy P1 (section 6.8 alert #1, section 6.5); the other {nofix} "
        "are the no-fix rule (\"GNSS fix lost\"), whose score, DOS vote and timing that policy left unchanged (section 6.5, "
        "P3.4). The GNSS state during serial_ids_com7_002 is not recorded (section 6.10), so the difference between the "
        "two runs is not attributable to the policy"),
    "artifacts/hardware/serial_ids_com7_002": (
        "run 2026-10-25 (started_utc), after the 2026-10-15 policy date; its code commit and its GNSS state are not "
        "recorded (docs/HARDWARE_BENCH_PIXHAWK6X.md section 6.10)"),
}
BENCH_001_ALERTS = "artifacts/hardware/serial_ids_com7_001/alerts.jsonl"
SNAPSHOT = ("Every figure describes the code that produced its source artifact (per-source commit, config, ML state and "
            "date under provenance), not the tree this file was generated on. Later live-source/detector changes (e.g. "
            "PR #39, pending) are not reflected: this is a dated snapshot of committed evidence.")
RERUN = "artifacts/validation/submission_rerun_20261029/extended_rerun"     # committed re-run of the extended benchmark
RERUN_README = "artifacts/validation/submission_rerun_20261029/README.md"  # dates the committed SIM artifact (2026-09-24)
# Decision-level re-run of every extended session on the current tree with the committed model (sha256 3fe74cdd...):
# not a committed artifact, so it is quoted with its provenance, not computed here.
DECISION_RERUN = {"date": "2026-11-18", "sessions_not_reproducing": [76, 77, 78, 79],
                  "by": "PR #48 re-verification (two independent re-runs); not a committed artifact"}
MIXED = ("WARNING: pools ML-on and ML-off runs recorded at different commits; it describes no single detector "
         "configuration. Use the per-group pools")


class MissingInputError(FileNotFoundError):
    """A named input is absent: the run stops instead of reporting a source with fewer (or zero) inputs."""


class BadInputError(ValueError):
    """A named input is present but cannot be scored as the definitions require (e.g. off-grid decision times)."""


def events_of(rows: list, where: str) -> list[bool]:
    """``stage2.alert_events`` with the input named in the error if a decision time is off the engine's tick grid."""
    try:
        return m.alert_events(rows)
    except m.OffGridTimeError as e:
        raise BadInputError(f"{where}: {e}") from None


def required_inputs() -> list[str]:
    """Every file the generator reads, relative to the repository root."""
    return ([f"{EXT}/{f}" for f in ("decisions.csv.gz", "sessions.csv", "results.json")]
            + [f"artifacts/ardupilot/{d}/decisions.jsonl" for d in AP_BENIGN]
            + [f"artifacts/ardupilot/{d}/evaluation.json" for d in AP_DRIFT]
            + [f"artifacts/ardupilot/{d}/{f}" for d in AP_BENIGN + AP_DRIFT for f in ("manifest.json", "summary.json")]
            + PX4_LIVE + [px4_summary(p) for p in PX4_LIVE]
            + [f"{d}{ext}" for d in PX4_P2 for ext in (".manifest.json", ".ids_decisions.jsonl")]
            + [f"{d}/summary.json" for d in BENCH] + list(BENCH_MANIFEST.values()) + [BENCH_DOC, BENCH_001_ALERTS]
            + [f"{RERUN}/sessions.csv", f"{RERUN}/results.json", RERUN_README]
            + [REPLAY_TLOG, ALFA])


def px4_summary(p: str) -> str:
    return p.removesuffix(".jsonl") + ".summary.json"


def check_inputs(root: Path) -> None:
    absent = [p for p in required_inputs() if not (root / p).is_file()]
    if absent:
        raise MissingInputError(f"{len(absent)} named input(s) absent under {root}: " + ", ".join(absent))


def r6(x):
    return None if x is None else round(float(x), 6)


def _prov(commit=NR, dirty=NR, config=NR, ml=NR, utc=NR, utc_field=NR, note=None, **extra) -> dict:
    out = {"commit": commit, "working_tree_dirty": dirty, "config": config, "ml": ml, "utc": utc, "utc_field": utc_field}
    out.update(extra)
    if note:
        out["note"] = note
    return out


def bench_doc_claim(root: Path) -> str:
    """The claim class the bench write-up states in its header (``**Claim class: none.**``); "not recorded" if absent."""
    hit = re.search(r"^\*\*Claim class: ([^*]+?)\.\*\*", (root / BENCH_DOC).read_text(encoding="utf-8"), re.M)
    return hit.group(1) if hit else NR


def provenance(root: Path) -> dict:
    """What each source's own committed metadata records about the code, config, ML state and claim class that produced
    it. An absent value is "not recorded"; nothing is inferred."""
    def rd(p: str) -> dict:
        return json.loads((root / p).read_text())

    def cc(src: dict, field: str, where: str) -> dict:
        return ({"claim_class": src[field], "claim_class_field": f"{where} {field}"} if field in src
                else {"claim_class": NR, "claim_class_field": f"{where}: no claim class"})

    j = rd(f"{EXT}/results.json")["config"]
    rj = rd(f"{EXT}/results.json")
    j = rj["config"]
    out = {EXT: _prov(ml=j["model_used"], note=f"results.json records python {j.get('python', NR)} and the grid only",
                      **cc(rj, "claim_class", f"{EXT}/results.json"))}
    for d in AP_BENIGN + AP_DRIFT:
        pv, sm = rd(f"artifacts/ardupilot/{d}/manifest.json")["provenance"], rd(f"artifacts/ardupilot/{d}/summary.json")
        # benign rows come from decisions.jsonl (described by summary.json); drift rows from evaluation.json
        cs = (cc(sm, "claim_class", f"artifacts/ardupilot/{d}/summary.json") if d in AP_BENIGN else
              cc(rd(f"artifacts/ardupilot/{d}/evaluation.json"), "claim_class", f"artifacts/ardupilot/{d}/evaluation.json"))
        out[f"artifacts/ardupilot/{d}"] = _prov(pv["aegisflight_commit"], pv["working_tree_dirty"],
                                                f"{sm['config_dir']}; configs_sha256 {pv['configs_sha256']}",
                                                sm["ml_enabled"], pv["collected_utc"], "provenance.collected_utc",
                                                stream_config=sm["stream_config"], **cs)
    for p in PX4_LIVE:
        sm = rd(px4_summary(p))
        pv = sm["provenance"]
        out[p] = _prov(pv["aegisflight_commit"], pv["working_tree_dirty"], f"configs_sha256 {pv['configs_sha256']}",
                       sm["ml_enabled"], sm["started_utc"], "started_utc", note=pv.get("note"),
                       **cc(sm, "claim_class", px4_summary(p)))
    for d in PX4_P2:
        man = rd(f"{d}.manifest.json")
        pv, par = man["full_provenance"], man["parameters"]
        out[f"{d}.manifest.json"] = _prov(pv["aegisflight_commit"], pv["working_tree_dirty"],
                                          f"{par['detector_profile']}; configs_sha256 {pv['configs_sha256']}",
                                          f"model_choice {par['model_choice']}", pv["collected_utc"],
                                          "full_provenance.collected_utc", **cc(man, "claim_class", f"{d}.manifest.json"))
    for d in BENCH:
        sm = rd(f"{d}/summary.json")
        if d in BENCH_MANIFEST:
            man = rd(BENCH_MANIFEST[d])
            pv = man["provenance"]
            out[d] = _prov(pv["git_head"], pv["working_tree_at_capture"],
                           f"{sm['config_dir']}; configs/detector.yaml sha256 {pv['config_detector_yaml_sha256']}",
                           sm["ml_enabled"], sm["started_utc"], "started_utc",
                           **cc(man, "claim_class", BENCH_MANIFEST[d]))
        else:
            out[d] = _prov(config=sm["config_dir"], ml=sm["ml_enabled"], utc=sm["started_utc"], utc_field="started_utc",
                           note="commit not in summary.json; see the BENCH row note" if d in BENCH_NOTES else None,
                           claim_class=bench_doc_claim(root),
                           claim_class_field=f"{BENCH_DOC} header (summary.json has no claim class)")
    r = rd(REPLAY_TLOG)
    out[REPLAY_TLOG] = _prov(ml=r["ml_enabled"], note=f"model {r['model']}", **cc(r, "claim_class", REPLAY_TLOG))
    a = rd(ALFA)
    out[ALFA] = _prov(note=f"experiment: {a['experiment']}; python {a.get('python', NR)}", **cc(a, "claim_class", ALFA))
    return out


def claim_of(prov: dict, keys: list[str]) -> str:
    """The claim class of the sources behind a row (a pool of runs that disagree lists each wording)."""
    return " | ".join(dict.fromkeys(prov[k]["claim_class"] for k in keys))


def snapshot(prov: dict) -> dict:
    dates = sorted(v["utc"][:10] for v in prov.values() if v["utc"] != NR)
    return {"note": SNAPSHOT, "recorded_dates": [dates[0], dates[-1]] if dates else None,
            "sources_without_commit": [k for k, v in prov.items() if v["commit"] == NR],
            "sources_without_date": [k for k, v in prov.items() if v["utc"] == NR]}


def sim_reproducibility(root: Path, sess: dict) -> dict:
    """How far the committed SIM artifact reproduces: the committed 2026-10-29 re-run compared with it (computed), and the
    decision-level re-run (quoted, see DECISION_RERUN). Every SIM figure here is still computed from the committed decisions."""
    with open(root / RERUN / "sessions.csv", newline="") as f:
        rerun = {int(r["idx"]): r for r in csv.DictReader(f)}
    differ = sorted(i for i in sess if sess[i] != rerun.get(i))
    a, b = (json.loads((root / q).read_text()) for q in (f"{EXT}/results.json", f"{RERUN}/results.json"))
    nd = DECISION_RERUN["sessions_not_reproducing"]
    return {"committed_rerun": RERUN, "rerun_session_rows_differing": differ,
            "rerun_differing_keys": sorted({sess[i]["key"] for i in differ}),
            "grace5_binary_identical": a["binary_grace5"] == b["binary_grace5"],
            "grace0_fp_committed_vs_rerun": [a["binary_grace0"]["fp"], b["binary_grace0"]["fp"]],
            "decision_rerun": {**DECISION_RERUN, "keys": sorted({sess[i]["key"] for i in nd}),
                               "sessions_reproducing": len(sess) - len(nd), "sessions": len(sess)},
            "note": "every SIM figure here is computed from the committed decisions, not from a re-run"}


def rate_block(events: int, decisions: int, threats: int, src: str, note: str = "", claim: str = NR) -> dict:
    exp = decisions * PERIOD_S
    out = {"source": src, "claim_class": claim, "alert_events": events, "decisions": decisions, "exposure_h": r6(exp / 3600),
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
    for i, rs in rows.items():
        rs.sort(key=lambda r: float(r["t"]))
        ev = events_of([(float(r["t"]), r["threat"] == "1", r["pred"]) for r in rs], f"{EXT}/decisions.csv.gz session {i}")
        for r, a in zip(rs, ev, strict=True):
            r["alert"] = a
    return rows, sess


def sim_false_alerts(rows, sess, claim: str = NR) -> dict:
    src = f"{EXT}/decisions.csv.gz"
    out: dict = {}
    for kind in ("benign", "link_fifo_benign", "link_reorder_benign"):
        rs = [r for i, s in sess.items() if s["kind"] == kind for r in rows[i] if r["warmup"] == "0"]
        out[kind] = rate_block(sum(r["alert"] for r in rs), len(rs), sum(r["threat"] == "1" for r in rs), src, claim=claim)
    for kind in ("single", "combo"):
        for g, grace in (("grace5", True), ("grace0", False)):
            rs = [r for i, s in sess.items() if s["kind"] == kind for r in rows[i]
                  if r["warmup"] == "0" and r["true"] == "BENIGN" and not (grace and r["in_grace"] == "1")]
            out[f"{kind}_attack_sessions_benign_decisions_{g}"] = rate_block(
                sum(r["alert"] for r in rs), len(rs), sum(r["threat"] == "1" for r in rs), src, claim=claim)
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


def sim_sessions(rows, sess, claim: str = NR) -> dict:
    src = f"{EXT}/sessions.csv"
    det = defaultdict(list)
    ttd = defaultdict(list)
    for s in sess.values():
        if s["kind"] in ("single", "combo"):
            cls = s["key"].split(":")[0] if s["kind"] == "single" else "combo:" + s["key"]
            det[cls].append(s["detected"] == "True")
            if s["ttd_s"]:
                ttd[cls].append(float(s["ttd_s"]))
    out: dict = {"claim_class": claim, "latency_detection_rule": RULE_SIM, "detection": {}, "benign_session_fpr": {}}
    for cls, d in sorted(det.items()):
        k, n = sum(d), len(d)
        lo, hi = m.wilson(k, n)
        lat = ttd[cls]
        out["detection"][cls] = {"source": src, "detected": k, "sessions": n, "rate": r6(k / n), "wilson95": [r6(lo), r6(hi)],
                                 "latency_from_onset_s": {"n": len(lat), "median": r6(m.nearest_rank(lat, 50)),
                                                          "p95": r6(m.nearest_rank(lat, 95)), "p95_is_max": len(lat) < 20}}
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


def drift_latency(root: Path, prov: dict) -> dict:
    ap = []
    for d in AP_DRIFT:
        p = f"artifacts/ardupilot/{d}/evaluation.json"
        e = json.loads((root / p).read_text())
        w, fa = e["window_decision_time"], e["observed_arm"]["first_alert"]
        ap.append({"source": p, "claim_class": prov[f"artifacts/ardupilot/{d}"]["claim_class"],
                   "from_onset_s": r6(fa["t"] - w["onset_t_s"]) if fa else None,
                   "from_release_s": r6(fa["t"] - w["end_t_s"]) if fa else None})
    px = []
    for d in PX4_P2:
        t = load_trial(root / f"{d}.manifest.json")
        px.append({"source": f"{d}.manifest.json", "claim_class": prov[f"{d}.manifest.json"]["claim_class"],
                   "from_onset_s": t["time_to_detection_from_onset_s"],
                   "from_release_s": t["time_to_detection_from_end_s"],
                   "note": "detection counted only after the attack window ends (preregistered P2 rule)"})

    def summ(xs, key):
        v = [x[key] for x in xs if x[key] is not None]
        return {"n": len(v), "of": len(xs), "median": r6(m.nearest_rank(v, 50)), "p95": r6(m.nearest_rank(v, 95)),
                "p95_is_max": len(v) < 20}
    return {"sitl_ardupilot": {"detection_rule": RULE_AP, "trials": ap, "from_onset": summ(ap, "from_onset_s"),
                               "from_release": summ(ap, "from_release_s")},
            "sitl_px4": {"detection_rule": RULE_P2, "trials": px, "from_onset": summ(px, "from_onset_s"),
                         "from_release": summ(px, "from_release_s")}}


def sitl_benign(root: Path, prov: dict) -> dict:
    out = {}
    for d in AP_BENIGN:
        p = f"artifacts/ardupilot/{d}/decisions.jsonl"
        rs = [json.loads(ln) for ln in (root / p).read_text().splitlines() if ln]
        rs = [r for r in rs if r.get("phase") != "post_link"]
        fl = [r for r in rs if r.get("phase") not in BEFORE_ARM]
        cl = prov[f"artifacts/ardupilot/{d}"]["claim_class"]
        out[d] = {"in_link_span": rate_block(sum(r["alert"] for r in rs), len(rs), sum(r["threat"] for r in rs), p,
                                             "every phase inside the link span (post_link excluded, as in summary.json)", cl),
                  "from_arm_phase": rate_block(sum(r["alert"] for r in fl), len(fl), sum(r["threat"] for r in fl), p,
                                               "arm, takeoff, square, rtl, landed: excludes boot / await_gps and post_link; "
                                               "includes the on-ground arm phase, so it is not an in-flight figure", cl)}
    def pool(runs: list[str], note: str = "") -> dict:
        res: dict = {"runs": runs,
                     "stream_configs": sorted({prov[f"artifacts/ardupilot/{d}"]["stream_config"] for d in runs})}
        for part in ("in_link_span", "from_arm_phase"):
            ev = sum(out[d][part]["alert_events"] for d in runs)
            n = sum(out[d][part]["decisions"] for d in runs)
            th = sum(out[d][part]["threat_decisions"] for d in runs)
            res[part] = rate_block(ev, n, th, "artifacts/ardupilot/{" + ",".join(runs) + "}/decisions.jsonl",
                                   note or out[runs[0]][part]["note"],
                                   claim_of(prov, [f"artifacts/ardupilot/{d}" for d in runs]))
        return res

    groups: dict = defaultdict(list)             # pool only like with like: same ML state and same recorded commit
    for d in AP_BENIGN:
        pv = prov[f"artifacts/ardupilot/{d}"]
        groups[(pv["ml"], pv["commit"])].append(d)
    label = {True: "on", False: "off"}
    tot = {f"ml_{label.get(ml, 'unknown')}@{str(c)[:7]}": pool(runs) for (ml, c), runs in sorted(groups.items(), key=str)}
    if len(groups) > 1:
        tot["all_runs_mixed"] = pool(AP_BENIGN, MIXED)
    return {"runs": out, "pooled": tot}


def px4_live(root: Path, prov: dict) -> dict:
    """PX4 live-UDP benign runs log (t, threat, type) per decision; alert events are re-derived with the engine rule."""
    out = {}
    for p in PX4_LIVE:
        rs = [json.loads(ln) for ln in (root / p).read_text().splitlines() if ln]
        ev = events_of([(float(r["t"]), bool(r["threat"]), r["type"]) for r in rs], p)
        out[Path(p).stem] = rate_block(sum(ev), len(rs), sum(bool(r["threat"]) for r in rs), p,
                                       "alert events re-derived (severity not logged; shipped config: threat implies "
                                       ">= SUSPICIOUS); run predates per-vehicle calibration", prov[p]["claim_class"])
    return out


def bench_notes(root: Path) -> dict:
    """BENCH_NOTES with the serial_ids_com7_001 alert split counted from its alerts.jsonl evidence."""
    al = [json.loads(ln) for ln in (root / BENCH_001_ALERTS).read_text().splitlines() if ln.strip()]
    never = sum(any("never received" in e for e in a["evidence"]) for a in al)
    nofix = sum(any(e.startswith("GNSS fix") for e in a["evidence"]) for a in al)
    return {d: n.format(total=len(al), never=never, nofix=nofix) for d, n in BENCH_NOTES.items()}


def bench(root: Path, prov: dict | None = None) -> dict:
    """Serial-monitor runs: ``alert_decisions`` in summary.json is the engine's own ``is_alert`` count
    (``scripts/hardware/run_serial_ids.py``), i.e. alert events; exposure is the run's wall time."""
    prov = prov if prov is not None else provenance(root)
    out = {}
    for d in BENCH:
        p = f"{d}/summary.json"
        s = json.loads((root / p).read_text())
        exp = float(s["wall_s"])
        env = json.loads((root / BENCH_MANIFEST[d]).read_text())["environment"]["live"] if d in BENCH_MANIFEST else "BENCH"
        claim, cs = prov[d]["claim_class"], prov[d]["claim_class_field"]
        out[d.removeprefix("artifacts/hardware/")] = {
            "source": p, "alert_events": s["alert_decisions"], "exposure_h": r6(exp / 3600),
            "false_alerts_per_h": r6(m.rate_per_hour(s["alert_decisions"], exp)),
            "false_alerts_per_h_upper95": r6(m.rate_upper_per_hour(s["alert_decisions"], exp)),
            "decisions": s["decisions"], "threat_decisions": s["threat_decisions"],
            "decision_fpr": r6(s["threat_decisions"] / s["decisions"]),
            "environment": env, "claim_class": claim, "claim_class_source": cs,
            "alert_events_from": "summary.json alert_decisions (engine is_alert count, not re-derived); exposure = wall_s"}
        if d in BENCH_NOTES:
            out[d.removeprefix("artifacts/hardware/")]["note"] = bench_notes(root)[d]
    return out


def replay(root: Path, prov: dict) -> dict:
    p = REPLAY_TLOG
    j = json.loads((root / p).read_text())
    runs = [{"source": p, "claim_class": prov[p]["claim_class"], "flight": r["flight"], "decisions": r["decisions"],
             "threat_decisions": r["false_alarm_decisions"], "decision_fpr": r6(r["false_alarm_rate"])} for r in j["runs"]]
    pa = ALFA
    a = json.loads((root / pa).read_text())
    return {"benign_tlog_replay": runs,
            "alfa": {"source": pa, "claim_class": prov[pa]["claim_class"], "decision_hours": a["total_decision_hours"],
                     "note": "decision-level only; see file"}}


def classification(root: Path, claim: str = NR) -> dict:
    p = f"{EXT}/results.json"
    j = json.loads((root / p).read_text())
    out: dict = {"claim_class": claim}
    for g in ("grace5", "grace0"):
        cm = j[f"confusion_{g}"]
        prf = m.per_class_prf(cm)
        attacks = [c for c in prf if c != "BENIGN" and prf[c]["support"]]
        acc_bin = r6(m.binary_accuracy(cm))
        out[g] = {"source": f"{p}#confusion_{g}", "confusion": cm,
                  "per_class": {c: {k: r6(v) if isinstance(v, float) else v for k, v in d.items()} for c, d in prf.items()},
                  "macro_f1_attack_classes": r6(m.macro_f1(prf, attacks)),
                  "macro_f1_incl_benign": r6(m.macro_f1(prf)),
                  "binary": {k: r6(v) if isinstance(v, float) else v for k, v in j[f"binary_{g}"].items()},
                  "accuracy_binary": acc_bin,
                  "accuracy_binary_matches_results_json": acc_bin == r6(j[f"binary_{g}"]["accuracy"]),
                  "accuracy_multiclass": r6(m.accuracy(cm))}
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
    prov = provenance(root)
    sim = sim_false_alerts(rows, sess, prov[EXT]["claim_class"])
    return {
        "schema": "aegisflight.stage2_metrics/1",
        "definitions": "src/aegisflight/metrics/stage2.py; docs/BENCHMARKING.md#stage-2-metrics",
        "decision_period_s": PERIOD_S,
        "percentile_method": PERCENTILES,
        "claim_class": CLAIM,
        "snapshot": {**snapshot(prov), "sim_reproducibility": sim_reproducibility(root, sess)},
        "provenance": prov,
        "false_alerts_per_hour": {"SIM": sim, "SITL_ardupilot": sitl_benign(root, prov),
                                  "SITL_px4_live": px4_live(root, prov), "REPLAY": replay(root, prov),
                                  "BENCH": bench(root, prov)},
        "sessions": sim_sessions(rows, sess, prov[EXT]["claim_class"]),
        "confusion_crosscheck_vs_results_json": confusion_crosscheck(sim, root),
        "latency_crosscheck_vs_sessions_csv": ttd_crosscheck(rows, sess),
        "drift_latency": drift_latency(root, prov),
        "classification": classification(root, prov[EXT]["claim_class"]),
        "missing_inputs": MISSING,
    }


def fmt(x):
    return "-" if x is None else (f"{x:.4g}" if isinstance(x, float) else str(x))


def short(x) -> str:
    """Shorten hex digests in a markdown cell (the JSON keeps them whole)."""
    return re.sub(r"\b([0-9a-f]{12})[0-9a-f]{28,52}\b", r"\1...", str(x))


def p95_txt(d: dict) -> str:
    return f"max {fmt(d['p95'])} (n={d['n']})" if d["p95_is_max"] else fmt(d["p95"])


def lat_txt(d: dict) -> str:
    return f"n {d['n']} of {d['of']}, median {fmt(d['median'])} s, p95 {p95_txt(d)} s"


def to_md(r: dict) -> str:
    sn = r["snapshot"]
    sr = sn["sim_reproducibility"]
    dr = sr["decision_rerun"]
    L = ["# Stage 2 metrics", "", f"Definitions: `{r['definitions']}`. Decision period {r['decision_period_s']} s.", "",
         f"**Claim class: {r['claim_class']}.** Each row's claim class is its source's own wording (section 0 and the "
         "`claim class` column).", "",
         f"**Dated snapshot.** {sn['note']} Recorded source dates: {sn['recorded_dates'][0]} to {sn['recorded_dates'][1]}. "
         "No recorded commit: " + ", ".join(f"`{k}`" for k in sn["sources_without_commit"]) + ". "
         "No recorded date: " + ", ".join(f"`{k}`" for k in sn["sources_without_date"]) + ".", "",
         f"**SIM reproducibility.** `{EXT}` is a 2026-09-24 snapshot of pre-Stage-2 code (`{RERUN_README}`). "
         f"A decision-level re-run of all {dr['sessions']} sessions on the current tree ({dr['date']}; {dr['by']}) "
         f"found sessions {', '.join(map(str, dr['sessions_not_reproducing']))} ({', '.join(dr['keys'])}) do not "
         f"reproduce their committed decisions; the other {dr['sessions_reproducing']} of {dr['sessions']} do. "
         f"The gap predates PR #48: the committed 2026-10-29 re-run (`{sr['committed_rerun']}`) already differs in "
         f"session rows {', '.join(map(str, sr['rerun_session_rows_differing']))} ({', '.join(sr['rerun_differing_keys'])}) "
         f"and in no-grace false positives ({sr['grace0_fp_committed_vs_rerun'][0]} committed vs "
         f"{sr['grace0_fp_committed_vs_rerun'][1]} re-run); 5 s-grace binary rows identical: "
         f"{sr['grace5_binary_identical']}. Note: {sr['note']}.", "",
         "## 0. Provenance per source (as each source's own metadata records it; \"not recorded\" = absent)", "",
         "| source | claim class (source's words; field) | commit | dirty tree | config | ML | UTC (field) | note |",
         "|---|---|---|---|---|---|---|---|"]
    L += [f"| `{k}` | {v['claim_class']} ({v['claim_class_field']}) | {short(v['commit'])} | {v['working_tree_dirty']} | "
          f"{short(v['config'])} | {v['ml']} | {v['utc']} ({v['utc_field']}) | {v.get('note', '')} |"
          for k, v in r["provenance"].items()]
    L += ["", "## 1. False alerts per hour (alert events after cooldown, benign ground truth)", "",
         "| source | set | claim class | events | exposure h | per h | 95% upper (one-sided Poisson) | decision FPR | artifact |",
         "|---|---|---|---|---|---|---|---|---|"]

    def row(src, name, b):
        L.append(f"| {src} | {name} | {b['claim_class']} | {b['alert_events']} | {fmt(b['exposure_h'])} | "
                 f"{fmt(b['false_alerts_per_h'])} | {fmt(b['false_alerts_per_h_upper95'])} | {fmt(b['decision_fpr'])} | "
                 f"`{b['source']}` |")
    fa = r["false_alerts_per_hour"]
    for k, b in fa["SIM"].items():
        row("SIM", k, b)
    for k, b in fa["SITL_ardupilot"]["runs"].items():
        row("SITL", f"{k} in_link_span", b["in_link_span"])
        row("SITL", f"{k} from_arm_phase", b["from_arm_phase"])
    for k, g in fa["SITL_ardupilot"]["pooled"].items():
        for part in ("in_link_span", "from_arm_phase"):
            row("SITL", f"pooled {k} ({len(g['runs'])} runs) {part}", g[part])
    for k, b in fa["SITL_px4_live"].items():
        row("SITL-PX4", k, b)
    for k, b in fa["BENCH"].items():
        row("BENCH", k, b)
    L += ["", "SITL ArduPilot pools (runs grouped by recorded ML state and commit, see section 0):", ""]
    L += [f"- {k}: {', '.join(g['runs'])}; stream configs {', '.join(g['stream_configs'])}"
          + (f". {g['in_link_span']['note']}" if g["in_link_span"]["note"].startswith("WARNING") else "") + "."
          for k, g in fa["SITL_ardupilot"]["pooled"].items()]
    first = next(iter(fa["SITL_ardupilot"]["runs"].values()))
    L += ["", "SITL ArduPilot phase sets: `in_link_span` = " + first["in_link_span"]["note"] + "; `from_arm_phase` = "
          + first["from_arm_phase"]["note"] + "."]
    L += ["", "BENCH runs (environment; claim class; source of that statement):", ""]
    L += [f"- {k}: {b['environment']}; {b['claim_class']} (`{b['claim_class_source']}`). Events: {b['alert_events_from']}."
          + (f" Note: {b['note']}." if b.get("note") else "") for k, b in fa["BENCH"].items()]
    L += ["", "REPLAY (decision level only, no alert flags logged):", ""]
    L += [f"- {x['flight']}: decision FPR {fmt(x['decision_fpr'])} ({x['threat_decisions']}/{x['decisions']}), claim class "
          f"{x['claim_class']}, `{x['source']}`" for x in fa["REPLAY"]["benign_tlog_replay"]]
    L += ["", "## 2. Grace (with vs without)", "",
          "Grace excludes benign decisions in the 5 s after an attack stops: the recovery tail, where the detector state "
          "(residual windows, rate counters) still reflects the attack, so a threat there is late attribution of a real "
          "attack, not a false alarm on benign traffic. Both are shown; grace0 is the conservative figure.", ""]
    for kind in ("single", "combo"):
        for g in ("grace5", "grace0"):
            b = fa["SIM"][f"{kind}_attack_sessions_benign_decisions_{g}"]
            L.append(f"- {kind} {g}: {b['alert_events']} events / {fmt(b['exposure_h'])} h "
                     f"({fmt(b['false_alerts_per_h'])}/h, one-sided 95% upper {fmt(b['false_alerts_per_h_upper95'])}), "
                     f"decision FPR {fmt(b['decision_fpr'])} (`{b['source']}`)")
    L += ["", f"Recomputed benign row vs `{EXT}/results.json` (benign + single sessions): "
          f"{r['confusion_crosscheck_vs_results_json']}."]
    L += ["", "## 3. Session-level detection (two-sided Wilson 95%) and onset latency", "",
          f"Claim class (`{EXT}`): {r['sessions']['claim_class']}. Percentiles: {r['percentile_method']}. "
          f"Detection rule: {r['sessions']['latency_detection_rule']}.", "",
          "| class | detected/n | rate | two-sided 95% Wilson CI | latency n | median s (nearest rank) | p95 s (nearest rank) |",
          "|---|---|---|---|---|---|---|"]
    for c, d in r["sessions"]["detection"].items():
        lat = d["latency_from_onset_s"]
        L.append(f"| {c} | {d['detected']}/{d['sessions']} | {fmt(d['rate'])} | {fmt(d['wilson95'][0])}-{fmt(d['wilson95'][1])} | "
                 f"{lat['n']} | {fmt(lat['median'])} | {p95_txt(lat)} |")
    L += ["", f"Source: `{EXT}/sessions.csv`. Recomputed latency vs `ttd_s`: {r['latency_crosscheck_vs_sessions_csv']}.", "",
          "Benign session FPR:", ""]
    for k, d in r["sessions"]["benign_session_fpr"].items():
        L.append(f"- {k}: {d['sessions_flagged']}/{d['sessions']}, two-sided Wilson 95% CI "
                 f"{fmt(d['wilson95'][0])}-{fmt(d['wilson95'][1])} (`{d['source']}`)")
    L += ["", "## 4. Drift latency (from onset and from release)", ""]
    for env, d in r["drift_latency"].items():
        L.append(f"- {env}: from onset {lat_txt(d['from_onset'])}; from release {lat_txt(d['from_release'])}. "
                 f"Detection rule: {d['detection_rule']}.")
        L += [f"  - `{t['source']}`: onset {fmt(t['from_onset_s'])} s, release {fmt(t['from_release_s'])} s; claim class "
              f"{t['claim_class']}" for t in d["trials"]]
    L += ["", "## 5. Per-class precision / recall / F1 (extended benchmark)", "",
          f"Claim class (`{EXT}`): {r['classification']['claim_class']}.", ""]
    for g, c in ((g, c) for g, c in r["classification"].items() if g != "claim_class"):
        L += [f"### {g} (`{c['source']}`)", "", "| class | P | R | F1 | support |", "|---|---|---|---|---|"]
        L += [f"| {k} | {fmt(v['precision'])} | {fmt(v['recall'])} | {fmt(v['f1'])} | {v['support']} |" for k, v in c["per_class"].items()]
        labels = list(c["confusion"])
        L += ["", f"Macro-F1, attack classes only (the class set of `metrics/scoring.py` `Evaluation.macro()`): "
              f"{fmt(c['macro_f1_attack_classes'])}. Macro-F1 including BENIGN: {fmt(c['macro_f1_incl_benign'])}. "
              "Which one is the headline needs definition sign-off (#28 AC4).", "", "Confusion (rows true, columns predicted):", "",
              "| true \\ pred | " + " | ".join(labels) + " |", "|---" * (len(labels) + 1) + "|"]
        L += [f"| {t} | " + " | ".join(str(c["confusion"][t].get(p, 0)) for p in labels) + " |" for t in labels]
        L.append("")
    L += ["## 6. Accuracy (last; dominated by the benign majority)", ""]
    L += [f"- {g}: binary accuracy (attack = positive, as `docs/BENCHMARKING.md` defines accuracy) {fmt(c['accuracy_binary'])} "
          f"(equals `{EXT}/results.json` `binary_{g}.accuracy`: {c['accuracy_binary_matches_results_json']}); "
          f"multiclass (attribution) accuracy {fmt(c['accuracy_multiclass'])} (`{c['source']}`)"
          for g, c in r["classification"].items() if g != "claim_class"]
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
    except (MissingInputError, BadInputError) as e:
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
