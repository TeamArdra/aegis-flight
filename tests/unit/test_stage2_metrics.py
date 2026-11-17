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
    assert r["claim_class"].startswith("link-level") and "claim class" in (tmp_path / "metrics.md").read_text().lower()
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
