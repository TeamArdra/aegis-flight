"""Bit-exact equivalence guard for the detection pipeline (see scripts/make_golden.py).

Every case recomputes per-layer sha256 digests of the ThreatAssessments, FeatureFrames and
DetectorResults (floats via ``repr``) and compares them with ``tests/golden/golden.json``, which was
generated from the pre-optimisation code. Any change in a decision, score, evidence string,
attribution, alert or feature value -- down to the last bit -- fails here. ML cases are skipped when
``models/isoforest.joblib`` is absent or is not the model the fixture was built with.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import platform
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("make_golden", REPO / "scripts" / "make_golden.py")
mg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mg)  # type: ignore[union-attr]

GOLD = json.loads(mg.GOLDEN_PATH.read_text(encoding="utf-8"))
_MODEL_OK = (mg.MODEL_PATH.exists()
             and hashlib.sha256(mg.MODEL_PATH.read_bytes()).hexdigest() == GOLD.get("ml_model_sha256"))
_SIM = dict(mg.sim_cases())
_LIVE = {n: (s, v) for n, s, v in mg.live_cases()}


# The fixture was generated on x86-64. Float results can differ in the last bit on another CPU / libm (measured on a
# Raspberry Pi 3B+: ML-off decisions of all 48 simulator cases were byte-identical to x86, but ~1% of the
# internal feature values differ by <= 4.4e-16), so off x86 the guard compares what is portable: the parsed messages,
# the parser statistics, the decision summary (counts, attack types, alerts) and, with ML off, the full
# ThreatAssessment hashes. The detector / feature layers and the ML-on assessments stay bit-exact on x86 only.
_STRICT = platform.machine().lower() in ("x86_64", "amd64")


def _compare(got: dict, want: dict, ml: bool) -> None:
    if _STRICT:
        assert got == want
        return
    portable = ("parse", "stats") if ml else ("parse", "stats", "assess")
    for k in portable:
        assert got["digests"].get(k) == want["digests"].get(k), k
    summary = ("alerts", "attack_types", "n_decisions", "n_messages", "threat_decisions")
    for k in summary:
        assert got.get(k) == want.get(k), k


def _run(name: str, ml: bool) -> dict:
    if name in _SIM:
        return mg.run_sim_case(_SIM[name], ml)
    scn, var = _LIVE[name]
    return mg.run_live_case(scn, var, ml)


def _params(key: str):
    marks = [pytest.mark.skipif(not _MODEL_OK, reason="ML model missing or differs")] if key == "ml" else []
    return [pytest.param(n, id=n, marks=marks) for n in GOLD.get(key, {})]


@pytest.mark.parametrize("name", _params("no_ml"))
def test_golden_ml_off(name):
    _compare(_run(name, False), GOLD["no_ml"][name], ml=False)


@pytest.mark.parametrize("name", _params("ml"))
def test_golden_ml_on(name):
    _compare(_run(name, True), GOLD["ml"][name], ml=True)


def test_fixture_covers_every_attack_mode_and_live_scenario():
    cases = set(GOLD["no_ml"])
    for atk, modes in mg.MODES.items():
        for m in modes:
            assert any(c.startswith(f"sim/{atk}:{m}/") for c in cases), (atk, m)
    assert any(c.startswith("sim/benign/") for c in cases)
    assert sum(c.startswith("sim/combo/") for c in cases) == 4
    for s in mg.SCENARIOS:
        assert f"live/{s}/profile" in cases and f"live/{s}/default" in cases
    assert len(cases) >= 76


def test_explicit_expected_values():
    """A few readable anchors (also catches a regenerated-but-wrong fixture)."""
    g = GOLD["no_ml"]
    assert g["live/benign/profile"]["threat_decisions"] == 0
    assert g["live/mgmt/profile"]["threat_decisions"] == 0
    assert "COMMAND_INJECTION" in g["live/cmds/profile"]["attack_types"]
    assert "DOS" in g["live/flood/profile"]["attack_types"]
    assert "TELEMETRY_MANIPULATION" in g["live/crossend/profile"]["attack_types"]
    assert "MAVLINK_ANOMALY" in g["live/seq/profile"]["attack_types"]
    assert "GPS_SPOOFING" in g["sim/gps_spoofing:gradual_drift/s3"]["attack_types"]


# --- the guard must actually catch a change ------------------------------------------------- #

def test_guard_detects_perturbed_extractor_constant(monkeypatch):
    from aegisflight.features import extractor
    monkeypatch.setattr(extractor, "_RESID_CLAMP_M", 30.0 - 1e-9)
    assert _run("sim/gps_spoofing:sudden_offset/s3", False) != GOLD["no_ml"]["sim/gps_spoofing:sudden_offset/s3"]


def test_guard_detects_perturbed_fusion_threshold(monkeypatch):
    from aegisflight.fusion import engine
    orig = engine.FusionEngine.__init__

    def init(self, cfg):
        orig(self, cfg)
        self.threat_threshold = 0.9

    monkeypatch.setattr(engine.FusionEngine, "__init__", init)
    assert _run("live/cmds/profile", False) != GOLD["no_ml"]["live/cmds/profile"]


def test_guard_detects_last_bit_float_change(monkeypatch):
    """A 1-ulp change of one feature value (far below any rounding) changes the frame digest."""
    from aegisflight.features import extractor
    orig = extractor.FeatureExtractor._position_residual

    def nudged(self):
        return orig(self) * (1.0 + 2.0 ** -52)

    monkeypatch.setattr(extractor.FeatureExtractor, "_position_residual", nudged)
    got = _run("live/spoof_drift/profile", False)
    want = GOLD["no_ml"]["live/spoof_drift/profile"]
    assert got["digests"]["frame"] != want["digests"]["frame"]


# --- ML fast path: bit-identical to sklearn, and falls back cleanly ---------------------------- #

@pytest.mark.skipif(not _MODEL_OK, reason="ML model missing or differs")
def test_fast_isoforest_equals_sklearn_bitwise_and_fallback_is_identical():
    import numpy as np

    from aegisflight.core.types import TelemetrySnapshot
    from aegisflight.detectors.anomaly import AnomalyDetector, combined_anomaly_raw
    from aegisflight.features.extractor import ML_FEATURES, FeatureFrame

    cfg = mg.load_config().detector["anomaly"]
    fast_det = AnomalyDetector(cfg, mg.MODEL_PATH)
    slow_det = AnomalyDetector(cfg, mg.MODEL_PATH)
    assert fast_det._fast is not None, "fast scorer should verify against sklearn at load"
    slow_det._fast = None
    for d in (fast_det, slow_det):
        d.warmup_ticks = 0
    b = fast_det.bundle
    rs = np.random.RandomState(99)
    mean, scale = b["scaler"].mean_, b["scaler"].scale_
    for i in range(300):
        vec = mean + rs.randn(len(ML_FEATURES)) * scale * rs.choice([0.5, 1, 3, 10, 200])
        if i % 50 == 0:
            vec[3] = float("nan")  # non-finite input must take the sklearn path in both
            nan_frame = FeatureFrame(t=0.0, snapshot=TelemetrySnapshot(t=0.0),
                                     **dict(zip(ML_FEATURES, vec.tolist(), strict=True)))
            try:
                want = mg.ser(slow_det.process(nan_frame))
            except Exception as exc:  # the sklearn path decides; the fast detector must do the same
                with pytest.raises(type(exc)):
                    fast_det.process(nan_frame)
            else:
                assert mg.ser(fast_det.process(nan_frame)) == want
            continue
        fr = FeatureFrame(t=0.0, snapshot=TelemetrySnapshot(t=0.0),
                          **dict(zip(ML_FEATURES, vec.tolist(), strict=True)))
        a, s = fast_det.process(fr), slow_det.process(fr)
        assert mg.ser(a) == mg.ser(s)
        assert np.array_equal(combined_anomaly_raw(b, vec[None, :]),
                              np.array([a.signals["anomaly_raw"]]))
