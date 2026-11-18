"""Stage 2 metric functions (issue #28) against hand-computed fixtures, and the alert-event reconstruction against the
real fusion engine."""

from __future__ import annotations

import math

import pytest

from aegisflight.metrics import stage2 as m


def test_rate_per_hour():
    assert m.rate_per_hour(3, 1800.0) == pytest.approx(6.0)        # 3 events in 0.5 h
    assert m.rate_per_hour(0, 7200.0) == 0.0
    with pytest.raises(ValueError):
        m.rate_per_hour(1, 0.0)


def test_poisson_upper_bound_matches_hand_values():
    # k = 0: solve P(X = 0) = exp(-mu) = 0.05  ->  mu = -ln 0.05 = 2.995732 (the "rule of three")
    assert m.poisson_upper(0) == pytest.approx(-math.log(0.05), abs=1e-9)
    # k = 1: P(X <= 1) = exp(-mu)(1 + mu) = 0.05 at mu = 4.743865 (checked by substitution below)
    mu1 = m.poisson_upper(1)
    assert mu1 == pytest.approx(4.743865, abs=1e-6)
    assert math.exp(-mu1) * (1 + mu1) == pytest.approx(0.05, abs=1e-9)
    # k = 3: P(X <= 3) = exp(-mu)(1 + mu + mu^2/2 + mu^3/6) = 0.05 at mu = 7.753657
    mu3 = m.poisson_upper(3)
    assert mu3 == pytest.approx(7.753657, abs=1e-6)
    assert math.exp(-mu3) * (1 + mu3 + mu3**2 / 2 + mu3**3 / 6) == pytest.approx(0.05, abs=1e-9)
    # 0 events in 0.5 h: rate <= 2.995732 / 0.5 = 5.991465 per hour
    assert m.rate_upper_per_hour(0, 1800.0) == pytest.approx(5.991465, abs=1e-6)


def test_wilson_interval_hand_values():
    # 5/10: z^2 = 3.841459; centre = (0.5 + 0.192073) / 1.384146 = 0.5;
    # half = 1.959964 * sqrt(0.025 + 0.0096037) / 1.384146 = 1.959964 * 0.186021 / 1.384146 = 0.263407
    #   ->  [0.236593, 0.763407]  (published tables: 0.2366 - 0.7634)
    lo, hi = m.wilson(5, 10)
    assert lo == pytest.approx(0.236593, abs=1e-6) and hi == pytest.approx(0.763407, abs=1e-6)
    # 0/10: centre = 0.192073 / 1.384146 = 0.138767 = half  ->  [0, 0.277533]
    lo, hi = m.wilson(0, 10)
    assert lo == 0.0 and hi == pytest.approx(0.277533, abs=1e-6)
    lo, hi = m.wilson(10, 10)                                         # mirror image of 0/10
    assert lo == pytest.approx(1 - 0.277533, abs=1e-6) and hi == 1.0
    with pytest.raises(ValueError):
        m.wilson(3, 2)


def test_per_class_prf_and_macro_f1_hand_values():
    cm = {"A": {"A": 8, "B": 2}, "B": {"A": 1, "B": 9}, "C": {"A": 5}}  # C has support 5, never predicted
    prf = m.per_class_prf(cm)
    # A: tp 8, predicted 8 + 1 + 5 = 14 -> P 8/14 = 0.571429, R 8/10 = 0.8, F1 = 2PR / (P + R) = 0.666667
    assert prf["A"]["precision"] == pytest.approx(8 / 14) and prf["A"]["recall"] == pytest.approx(0.8)
    assert prf["A"]["f1"] == pytest.approx(2 / 3)
    # B: tp 9, predicted 2 + 9 = 11 -> P 0.818182, R 0.9, F1 = 0.857143
    assert prf["B"]["f1"] == pytest.approx(6 / 7)
    # C: never predicted -> precision 0 (not NaN), recall 0, F1 0
    assert prf["C"] == {"precision": 0.0, "recall": 0.0, "f1": 0.0, "support": 5, "predicted": 0, "tp": 0}
    # macro = (2/3 + 6/7 + 0) / 3 = 0.507937
    assert m.macro_f1(prf) == pytest.approx((2 / 3 + 6 / 7) / 3)
    assert m.macro_f1(prf, ["A", "B"]) == pytest.approx((2 / 3 + 6 / 7) / 2)
    # accuracy = (8 + 9 + 0) / 25 = 0.68
    assert m.accuracy(cm) == pytest.approx(0.68)


def test_onset_and_release_latency_hand_values():
    # 5 Hz decisions 0.0 .. 20.0 s; attack labelled 10.0 .. 14.8 s; first threat inside the window at 11.4 s
    dec = []
    for i in range(101):
        t = round(i * 0.2, 1)
        inw = 10.0 <= t <= 14.8
        dec.append((t, inw, t >= 11.4 or t == 3.0))                  # the threat at 3.0 s is outside the window
    lat = m.onset_latency(dec)
    assert lat["onset_t"] == 10.0 and lat["release_t"] == 14.8 and lat["detect_t"] == 11.4
    assert lat["from_onset_s"] == pytest.approx(1.4)
    assert lat["from_release_s"] == pytest.approx(-3.4)             # detected before the attacker stopped
    none = m.onset_latency([(t, inw, False) for t, inw, _ in dec])
    assert none["from_onset_s"] is None and none["onset_t"] == 10.0
    assert m.onset_latency([(0.0, False, True)])["onset_t"] is None


def test_nearest_rank_percentile():
    v = [float(x) for x in range(1, 11)]
    assert m.nearest_rank(v, 50) == 5.0 and m.nearest_rank(v, 95) == 10.0 and m.nearest_rank(v, 10) == 1.0
    assert m.nearest_rank([], 50) is None


def test_alert_events_hand_sequence():
    # The rule itself on exact times (tick_s=None: t used as given). cooldown 4 s, clear after 4 non-threat decisions
    rows = [(0, True, "A"),   # first threat: alert
            (1, True, "A"),   # same type, active, 1 s < cooldown: suppressed
            (2, False, "-"), (3, False, "-"), (4, False, "-"),
            (5, False, "-"),  # 4th consecutive non-threat: state clears
            (6, True, "A"),   # not active any more: alert again despite 6 - 0 ... (cooldown would have allowed anyway)
            (7, True, "B"),   # a different type has its own cooldown: alert
            (8, True, "A"),   # A again, active, 8 - 6 = 2 s: suppressed
            (10, True, "A")]  # 10 - 6 = 4 s >= cooldown: alert
    assert m.alert_events(rows, tick_s=None) == [True, False, False, False, False, False, True, True, False, True]
    # a short gap (< clear_ticks) keeps the state active, so the cooldown applies
    rows2 = [(0, True, "A"), (1, False, "-"), (2, True, "A")]
    assert m.alert_events(rows2, tick_s=None) == [True, False, False]


def test_engine_tick_time_float_facts_and_grid_check():
    # The engine stamps tick k as k * 0.1; logs keep round(t, 2). At a 40-tick (4.0 s) gap the two disagree by one ulp,
    # in both directions (hand-checked IEEE-754 values):
    assert 646 * 0.1 - 606 * 0.1 == 4.000000000000007 and 64.6 - 60.6 == 3.999999999999993
    assert 648 * 0.1 - 608 * 0.1 == 3.999999999999993 and 64.8 - 60.8 == 4.0
    assert m.engine_tick_time(64.6) == 646 * 0.1 and m.engine_tick_time(646 * 0.1) == 646 * 0.1   # idempotent on raw t
    assert m.engine_tick_time(64.6) != 64.6
    with pytest.raises(ValueError):
        m.engine_tick_time(64.65)                                     # off the 0.1 s grid: refuse to guess


@pytest.mark.parametrize("k0", [606, 608])
def test_alert_events_exact_cooldown_boundary_matches_the_real_engine(k0):
    """F1 regression (#48 audit): a 4.0 s gap decided on rounded logged t, as the PR's first version did, puts the
    alert one decision early or late. Session 51 of the extended benchmark is the k0 = 606 case (engine alert at 64.6,
    rounded-t rule at 64.8). Ground truth is the real FusionEngine fed its raw tick times."""
    from aegisflight.config import load_config
    from aegisflight.core.enums import AttackType, DetectorName, IntegrityStatus
    from aegisflight.core.types import DetectorResult
    from aegisflight.fusion.engine import FusionEngine

    eng = FusionEngine(load_config().detector["fusion"])
    hit = [DetectorResult(DetectorName.PHYSICS, 1.0, True, attack_votes={AttackType.COMMAND_INJECTION: 1.0})]
    ks = range(k0, k0 + 46, 2)                                         # a decision every 2nd tick, threat throughout
    want = [eng.fuse(k * 0.1, 0.0, hit, IntegrityStatus.VALID).is_alert for k in ks]
    logged = [(round(k * 0.1, 2), True, "COMMAND_INJECTION") for k in ks]   # what decisions.csv / the jsonl logs keep
    assert m.alert_events(logged) == want
    # hand-derived: the engine re-alerts at tick k0 + 40 when the raw gap is >= 4.0, else at k0 + 42
    second = k0 + 40 if (k0 + 40) * 0.1 - k0 * 0.1 >= 4.0 else k0 + 42
    assert [k for k, a in zip(ks, want, strict=True) if a][:2] == [k0, second]
    assert m.alert_events(logged, tick_s=None) != want                 # the old rule (rounded t as given) is wrong here


AP_RUNS = ["ap_benign_final_noml_001", "ap_benign_final_noml_002", "ap_benign_groups_001", "ap_benign_six_001",
           "ap_benign_six_002", "ap_benign_six_003", "ap_benign_six_004", "ap_attack_final_drift_001",
           "ap_attack_final_drift_002", "ap_attack_final_drift_003"]


@pytest.mark.parametrize("run", AP_RUNS)
def test_alert_reconstruction_matches_logged_engine_alerts(run):
    """ArduPilot decision logs record the engine's own ``alert`` next to the rounded ``t``: the re-derivation must
    reproduce it row for row (the first version mismatched 62 rows of groups_001 and 1 event of six_001)."""
    import json
    from pathlib import Path

    p = Path(__file__).resolve().parents[2] / "artifacts" / "ardupilot" / run / "decisions.jsonl"
    rs = [json.loads(ln) for ln in p.read_text().splitlines() if ln]
    assert m.alert_events([(float(r["t"]), bool(r["threat"]), r["type"]) for r in rs]) == [bool(r["alert"]) for r in rs]


def test_alert_rule_defaults_match_the_shipped_config():
    import inspect

    from aegisflight.config import load_config

    cfg = load_config()
    sig = inspect.signature(m.alert_events).parameters
    assert sig["cooldown_s"].default == float(cfg.detector["fusion"]["cooldown_s"])
    assert sig["clear_ticks"].default == int(cfg.detector["fusion"]["clear_ticks"])
    assert m.TICK_S == 1.0 / float(cfg.simulation["sample_rate_hz"])


@pytest.mark.parametrize("scenario", ["benign", "gps_spoofing", "dos", "command_injection"])
def test_alert_reconstruction_matches_the_fusion_engine(scenario):
    """The engine's own is_alert, recomputed from (t, threat, attack_type) only, with t rounded as decisions.csv logs it."""
    from aegisflight.benchmark.runner import run_session
    from aegisflight.config import load_config

    cfg = load_config()
    res = run_session(cfg, scenario, seed=7, model_path=None)
    fus = cfg.detector["fusion"]
    rows = [(round(a.t, 2), bool(a.threat), a.attack_type.value) for a in res.assessments]
    got = m.alert_events(rows, cooldown_s=float(fus["cooldown_s"]), clear_ticks=int(fus["clear_ticks"]))
    want = [bool(a.is_alert) for a in res.assessments]
    assert sum(want) > 0 or scenario == "benign"
    assert got == want


def test_make_stage2_metrics_reconciles_with_committed_results(tmp_path):
    """End to end on the committed artifacts: recomputed counts must agree with what the benchmark wrote."""
    import json
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    subprocess.run([sys.executable, str(root / "scripts" / "make_stage2_metrics.py"), "--tag", "t", "--out-dir", str(tmp_path)],
                   check=True, cwd=root)
    r = json.loads((tmp_path / "metrics.json").read_text())
    committed = root / "artifacts" / "validation" / "stage2_metrics_2026-11-17"
    assert r == json.loads((committed / "metrics.json").read_text())          # committed evidence = generator output
    assert (tmp_path / "metrics.md").read_bytes() == (committed / "metrics.md").read_bytes().replace(b"\r\n", b"\n")
    assert not any(b"\r" in (tmp_path / f).read_bytes() for f in ("metrics.json", "metrics.md"))   # LF on every OS
    assert all(v["match"] for v in r["confusion_crosscheck_vs_results_json"].values())
    assert r["latency_crosscheck_vs_sessions_csv"]["max_abs_diff_s"] == 0.0
    assert r["false_alerts_per_hour"]["SIM"]["benign"]["decision_fpr"] == pytest.approx(4 / 6900, abs=1e-6)
    assert "each source's own words" in r["claim_class"] and "claim class" in (tmp_path / "metrics.md").read_text().lower()
    assert set(r["false_alerts_per_hour"]["SITL_px4_live"]) == {"live_run_001", "live_run_002"}
    assert r["missing_inputs"] and (tmp_path / "metrics.md").read_text().rstrip().endswith("none is claimed")


def _generator():
    import importlib.util
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location("make_stage2_metrics", root / "scripts" / "make_stage2_metrics.py")
    g = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(g)
    return root, g


def test_make_stage2_metrics_fails_loudly_on_a_missing_named_input(tmp_path, capsys):
    """F11 regression (#48 audit): with the P2 trial manifests removed the first version exited 0 and printed an
    empty PX4 drift row (n = 0). Now every input is named; an absent one stops the run and nothing is written."""
    import json
    import shutil

    root, g = _generator()
    src = tmp_path / "root"
    for p in g.required_inputs():                                       # exactly the named inputs, nothing else
        (src / p).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / p, src / p)
    assert g.main(["--tag", "t", "--root", str(src), "--out-dir", str(tmp_path / "full")]) == 0
    committed = root / "artifacts" / "validation" / "stage2_metrics_2026-11-17" / "metrics.json"
    assert json.loads((tmp_path / "full" / "metrics.json").read_text()) == json.loads(committed.read_text())
    gone = [p for p in g.required_inputs() if "p2_final_trial_" in p and p.endswith(".manifest.json")]
    assert len(gone) == 3
    for p in gone:
        (src / p).unlink()
    assert g.main(["--tag", "t", "--root", str(src), "--out-dir", str(tmp_path / "partial")]) == 2
    err = capsys.readouterr().err
    assert all(p in err for p in gone) and not (tmp_path / "partial").exists()


def test_bench_covers_every_live_serial_monitor_run_with_its_own_claim_class():
    """F15 regression (#48 audit): the 90 s gps_hw_verify_20261029 live capture was omitted. Every committed serial-monitor
    run on a physical port (``socket://`` ports are loopback replays) must be a BENCH row, labelled by its own manifest
    where it has one."""
    import json

    root, g = _generator()
    hw = root / "artifacts" / "hardware"
    live = sorted(p.parent.relative_to(root).as_posix() for p in hw.rglob("summary.json")
                  if json.loads(p.read_text()).get("schema") == "aegisflight.serial_monitor_run/1"
                  and not str(json.loads(p.read_text()).get("port", "")).startswith("socket://"))
    assert sorted(g.BENCH) == live
    b = g.bench(root)
    for d in g.BENCH:
        s = json.loads((root / d / "summary.json").read_text())
        row = b[d.removeprefix("artifacts/hardware/")]
        assert (row["alert_events"], row["decisions"], row["exposure_h"]) == (s["alert_decisions"], s["decisions"],
                                                                                round(s["wall_s"] / 3600, 6))
        if d in g.BENCH_MANIFEST:
            man = json.loads((root / g.BENCH_MANIFEST[d]).read_text())
            assert (row["claim_class"], row["environment"]) == (man["claim_class"], man["environment"]["live"])


def test_macro_f1_and_accuracy_definitions_hand_values():
    """F2 / F3 (#48 audit): both definitions are reported, so both are pinned. Hand fixture (rows true, cols predicted):
    BENIGN 8 -> BENIGN, 2 -> A; A: 1 -> BENIGN, 3 -> A, 1 -> B; B: 5 -> B.  N = 20."""
    cm = {"BENIGN": {"BENIGN": 8, "A": 2}, "A": {"BENIGN": 1, "A": 3, "B": 1}, "B": {"B": 5}}
    prf = m.per_class_prf(cm)
    # BENIGN P 8/9, R 8/10 -> F1 16/19; A P 3/5, R 3/5 -> F1 0.6; B P 5/6, R 1 -> F1 10/11
    assert prf["BENIGN"]["f1"] == pytest.approx(16 / 19) and prf["A"]["f1"] == pytest.approx(0.6)
    assert prf["B"]["f1"] == pytest.approx(10 / 11)
    assert m.macro_f1(prf, ["A", "B"]) == pytest.approx((0.6 + 10 / 11) / 2)              # attack classes only: 0.754545
    assert m.macro_f1(prf) == pytest.approx((16 / 19 + 0.6 + 10 / 11) / 3)                # including BENIGN: 0.783732
    assert m.accuracy(cm) == pytest.approx((8 + 3 + 5) / 20)                              # multiclass: 0.80
    # binary, attack = positive: TN 8, TP = 3 + 1 (A -> B is detected, misattributed) + 5 = 9  ->  17 / 20
    assert m.binary_accuracy(cm) == pytest.approx(17 / 20)


@pytest.mark.parametrize("g", ["grace5", "grace0"])
def test_reported_macro_f1_and_accuracy_match_the_repo_definitions(g):
    """The attack-only macro-F1 equals ``metrics/scoring.py`` ``Evaluation.macro()`` on the same confusion matrix, and
    the binary accuracy equals the benchmark's own ``results.json`` value."""
    import json

    from aegisflight.core.enums import AttackType
    from aegisflight.metrics.scoring import ClassScore, Evaluation

    root, gen = _generator()
    c = gen.classification(root)[g]
    cm = c["confusion"]
    per = {}
    for a in AttackType:
        tp, support = cm[a.value].get(a.value, 0), sum(cm[a.value].values())
        predicted = sum(cm[t].get(a.value, 0) for t in cm)
        per[a] = ClassScore(a, tp=tp, fp=predicted - tp, fn=support - tp, support=support)
    assert Evaluation(binary=None, per_class=per, confusion={}, n=0).macro()["f1"] == round(c["macro_f1_attack_classes"], 4)
    assert c["macro_f1_incl_benign"] > c["macro_f1_attack_classes"]           # BENIGN F1 ~0.98 lifts the mean
    j = json.loads((root / "artifacts" / "benchmarks_extended" / "results.json").read_text())
    assert c["accuracy_binary_matches_results_json"] and c["accuracy_binary"] == round(j[f"binary_{g}"]["accuracy"], 6)
    assert c["accuracy_multiclass"] < c["accuracy_binary"]


def test_provenance_is_copied_from_each_sources_own_metadata():
    """F12 / F7 (#48 audit): per-source commit, config, ML state and date are what the source recorded; an absent value
    is "not recorded", never inferred."""
    import json

    root, g = _generator()
    prov = g.provenance(root)
    assert set(prov) >= {f"artifacts/ardupilot/{d}" for d in g.AP_BENIGN + g.AP_DRIFT} | set(g.PX4_LIVE) | set(g.BENCH)
    for d in g.AP_BENIGN + g.AP_DRIFT:
        man = json.loads((root / "artifacts" / "ardupilot" / d / "manifest.json").read_text())["provenance"]
        sm = json.loads((root / "artifacts" / "ardupilot" / d / "summary.json").read_text())
        v = prov[f"artifacts/ardupilot/{d}"]
        assert (v["commit"], v["working_tree_dirty"], v["ml"], v["utc"]) == (
            man["aegisflight_commit"], man["working_tree_dirty"], sm["ml_enabled"], man["collected_utc"])
    for p in g.PX4_LIVE:
        pv = json.loads((root / g.px4_summary(p)).read_text())["provenance"]
        assert prov[p]["commit"] == pv["aegisflight_commit"] and prov[p].get("note") == pv.get("note")
    for d in ("artifacts/hardware/serial_ids_com7_001", "artifacts/hardware/serial_ids_com7_002"):
        assert prov[d]["commit"] == g.NR                              # summary.json records none: not invented
    assert all(x is not None for v in prov.values() for x in v.values())
    snap = g.snapshot(prov)
    assert "dated snapshot" in snap["note"] and g.EXT in snap["sources_without_commit"]


def test_ardupilot_pools_only_like_with_like():
    """F4 (#48 audit): ML-on and ML-off runs from different commits are pooled per group; the all-runs pool, kept for
    comparison, carries an explicit warning."""
    root, g = _generator()
    prov = g.provenance(root)
    pools = g.sitl_benign(root, prov)["pooled"]
    for name, pool in pools.items():
        keys = {(prov[f"artifacts/ardupilot/{d}"]["ml"], prov[f"artifacts/ardupilot/{d}"]["commit"]) for d in pool["runs"]}
        if name == "all_runs_mixed":
            assert len(keys) > 1 and pool["in_link_span"]["note"].startswith("WARNING")
        else:
            assert len(keys) == 1 and not pool["in_link_span"]["note"].startswith("WARNING")
    groups = [p for n, p in pools.items() if n != "all_runs_mixed"]
    assert sorted(d for p in groups for d in p["runs"]) == sorted(g.AP_BENIGN)
    for part in ("in_link_span", "from_arm_phase"):
        assert sum(p[part]["alert_events"] for p in groups) == pools["all_runs_mixed"][part]["alert_events"]


def test_bench_001_note_states_only_what_the_bench_doc_and_alerts_support():
    """F6 / re-verification item 2: 001 is not comparable with 002, but the cited write-up does not let the 16 -> 0
    difference be blamed on the 2026-10-15 policy. The policy removes only the t = 0 never-received alert; the other 15 are
    the unchanged no-fix rule, and 002's GNSS state was not recorded. The note's counts come from 001's alerts.jsonl."""
    import json

    root, g = _generator()
    b = g.bench(root)
    al = [json.loads(ln) for ln in (root / g.BENCH_001_ALERTS).read_text().splitlines() if ln.strip()]
    never = [a for a in al if any("never received" in e for e in a["evidence"])]
    nofix = [a for a in al if any(e.startswith("GNSS fix") for e in a["evidence"])]
    assert (len(al), len(never), len(nofix)) == (16, 1, 15) and never[0]["t"] == 0.0     # 1 + 15 = 16, as section 6.8
    note = b["serial_ids_com7_001"]["note"]
    assert f"Of its {len(al)} alerts, {len(never)} " in note and f"the other {len(nofix)} " in note
    assert "not attributable to the policy" in note and "not run-to-run variation" not in note
    doc = (root / g.BENCH_DOC).read_text(encoding="utf-8")
    assert "the GNSS state during this run is **not recorded**" in doc                   # section 6.10, about 002
    assert "The score, the `DOS` vote and the timing are unchanged" in doc                 # section 6.5, P3.4
    assert "section 6.10" in b["serial_ids_com7_002"]["note"]


def test_nearest_rank_labels_lower_median_and_p95_max_below_20():
    """F8 (#48 audit): the labels printed next to the percentiles must be true of the function."""
    assert m.nearest_rank([1.0, 2.0, 3.0, 4.0], 50) == 2.0                     # lower middle value, not 2.5
    for n in range(1, 20):
        assert m.nearest_rank([float(x) for x in range(n)], 95) == n - 1        # n < 20: p95 is the maximum
    assert m.nearest_rank([float(x) for x in range(20)], 95) == 18.0            # n = 20: it is not


def test_every_latency_row_states_its_detection_rule_and_sidedness_is_printed():
    """F9 / F10 (#48 audit): three different "detection" definitions feed the latency rows; each is stated, and the md
    says which interval is one-sided (Poisson) and which two-sided (Wilson)."""
    root, g = _generator()
    r = g.build(root)
    assert r["sessions"]["latency_detection_rule"] == g.RULE_SIM
    assert {k: v["detection_rule"] for k, v in r["drift_latency"].items()} == {"sitl_ardupilot": g.RULE_AP,
                                                                              "sitl_px4": g.RULE_P2}
    md = g.to_md(r)
    assert "95% upper (one-sided Poisson)" in md and "two-sided Wilson 95% CI" in md and "two-sided 95% Wilson CI" in md
    assert all(rule in md for rule in (g.RULE_SIM, g.RULE_AP, g.RULE_P2))


def test_single_attack_grace0_is_53_because_session_51_alerts_on_its_attack_decision():
    """F1 (#48 audit), pinned. The first version reported 54 single-attack no-grace benign alert events. In session 51
    (command_injection:arm_disarm_burst) the engine re-alerts at t = 64.6 s, the last COMMAND_INJECTION decision, since
    646*0.1 - 606*0.1 = 4.000000000000007 >= cooldown; the rounded-t rule (64.6 - 60.6 = 3.999999999999993) moved that
    alert onto the benign in-grace decision at 64.8 s, counting one benign event too many. The real-engine check is
    the next test."""
    root, g = _generator()
    rows, sess = g.load_sim(root)
    s51 = {float(r["t"]): r for r in rows[51]}
    assert sess[51]["key"] == "command_injection:arm_disarm_burst"
    assert (s51[64.6]["true"], s51[64.6]["alert"]) == ("COMMAND_INJECTION", True)
    assert (s51[64.8]["true"], s51[64.8]["in_grace"], s51[64.8]["alert"]) == ("BENIGN", "1", False)
    fa = g.sim_false_alerts(rows, sess)
    assert fa["single_attack_sessions_benign_decisions_grace0"]["alert_events"] == 53
    assert fa["single_attack_sessions_benign_decisions_grace5"]["alert_events"] == 26     # in grace: unaffected
    old = {i: m.alert_events([(float(r["t"]), r["threat"] == "1", r["pred"]) for r in rows[i]], tick_s=None)
           for i, s in sess.items() if s["kind"] == "single"}
    assert sum(a for i, al in old.items() for r, a in zip(rows[i], al, strict=True)
               if r["warmup"] == "0" and r["true"] == "BENIGN") == 54                    # what the first version reported


def test_session_51_real_engine_alert_matches_the_re_derivation(monkeypatch):
    """The ground truth behind the 53: re-run extended-benchmark session 51 with the real pipeline and the committed
    model. The decision sequence must equal decisions.csv.gz, and the engine's own is_alert must equal alert_events on
    the logged (rounded) t. Needs models/isoforest.joblib (gitignored), so it is skipped where the model is absent."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    model = root / "models" / "isoforest.joblib"
    if not model.is_file():
        pytest.skip("models/isoforest.joblib not present (gitignored; run `aegis train`)")
    from aegisflight.benchmark.extended import build_grid, session_config
    from aegisflight.benchmark.runner import run_session
    from aegisflight.config import load_config

    monkeypatch.chdir(root)
    _, g = _generator()
    rows, _ = g.load_sim(root)
    spec = next(s for s in build_grid() if s.idx == 51)
    res = run_session(session_config(load_config(), spec), spec.scenario, seed=spec.seed, model_path=str(model), grace_s=5.0)
    assert [(round(r.t, 2), int(r.threat), r.pred_label.value) for r in res.records] == \
        [(float(r["t"]), int(r["threat"]), r["pred"]) for r in rows[51]]
    engine = {round(a.t, 2): bool(a.is_alert) for a in res.assessments}
    assert [engine[round(r.t, 2)] for r in res.records] == [r["alert"] for r in rows[51]]
    assert engine[64.6] is True and engine[64.8] is False


def test_every_row_claim_class_is_its_sources_own_wording():
    """Re-verification item 1: rows were labelled "link-level detection" while their sources say "none" (benign SITL,
    REPLAY, and the bench write-up for BENCH 001/002). Each row's claim class must be read from its own source, verbatim,
    and "not recorded" where the source states none."""
    import json
    import re

    root, g = _generator()
    r = g.build(root)
    rd = lambda p: json.loads((root / p).read_text(encoding="utf-8"))  # noqa: E731

    def has_claim(o) -> bool:
        return any("claim" in k.lower() or has_claim(v) for k, v in o.items()) if isinstance(o, dict) else (
            any(has_claim(v) for v in o) if isinstance(o, list) else False)

    fa = r["false_alerts_per_hour"]
    for d, run in fa["SITL_ardupilot"]["runs"].items():
        want = rd(f"artifacts/ardupilot/{d}/summary.json")["claim_class"]
        assert run["in_link_span"]["claim_class"] == run["from_arm_phase"]["claim_class"] == want
        assert want.startswith("none")
    for pool in fa["SITL_ardupilot"]["pooled"].values():
        assert pool["in_link_span"]["claim_class"] == " | ".join(dict.fromkeys(
            rd(f"artifacts/ardupilot/{d}/summary.json")["claim_class"] for d in pool["runs"]))
    for t in r["drift_latency"]["sitl_ardupilot"]["trials"]:
        assert t["claim_class"] == rd(t["source"])["claim_class"]                         # evaluation.json
    for t in r["drift_latency"]["sitl_px4"]["trials"]:
        assert t["claim_class"] == rd(t["source"])["claim_class"]                         # P2 manifest
    for x in fa["REPLAY"]["benign_tlog_replay"]:
        assert x["claim_class"] == rd(g.REPLAY_TLOG)["claim_class"]
    doc = (root / g.BENCH_DOC).read_text(encoding="utf-8")
    assert re.search(r"^\*\*Claim class: none\.\*\*", doc, re.M)                     # the bench write-up's header
    for d in g.BENCH:
        row = fa["BENCH"][d.removeprefix("artifacts/hardware/")]
        want = rd(g.BENCH_MANIFEST[d])["claim_class"] if d in g.BENCH_MANIFEST else "none"
        assert row["claim_class"] == want
    # sources that state no claim class are labelled "not recorded", never given one
    for src, rows in ((f"{g.EXT}/results.json", list(fa["SIM"].values()) + [r["sessions"], r["classification"]]),
                      (g.ALFA, [fa["REPLAY"]["alfa"]])):
        assert not has_claim(rd(src)) and all(x["claim_class"] == g.NR for x in rows)
    for p in g.PX4_LIVE:
        assert not has_claim(rd(g.px4_summary(p))) and fa["SITL_px4_live"][p.split("/")[-1].removesuffix(".jsonl")]["claim_class"] == g.NR
    # "link-level" appears only where the source itself says so (the drift latency rows)
    def claims(o):
        if isinstance(o, dict):
            for k, v in o.items():
                yield from ([(k, v)] if k == "claim_class" else claims(v))
        elif isinstance(o, list):
            for v in o:
                yield from claims(v)
    link = [v for k, v in claims({k: v for k, v in r.items() if k not in ("drift_latency", "provenance")})
            if "link-level" in str(v)]
    assert link == []
    drift_sources = {f"artifacts/ardupilot/{d}" for d in g.AP_DRIFT} | {f"{d}.manifest.json" for d in g.PX4_P2}
    assert {k for k, v in r["provenance"].items() if "link-level" in v["claim_class"]} == drift_sources
