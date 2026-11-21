"""Equivalence guard for the detection pipeline (see scripts/make_golden.py).

Every case recomputes per-layer sha256 digests of the ThreatAssessments, FeatureFrames and
DetectorResults (floats via ``repr``) and compares them with ``tests/golden/golden.json``.

What the fixture is: a snapshot of the CURRENT code's results, not proof of equivalence to the
pre-optimisation code. It was added in ``15c3aaf`` (per that commit, from the pre-optimisation code), regenerated in
``7ff7ab2`` AFTER the speed-ups (new FeatureFrame fields; the live-profile detection changes), extended with
the rounded layers in ``14e629e``, and its ML-on section was regenerated from the canonical team model
afterwards. That the speed-ups did not change a result was established separately (old-vs-new runs of
make_golden.py on one Windows host in the PR #39 audit), not by this file.

How strict it is, by default (every host, CI included): a change in a decision, alert, attack type,
parsed message or parser statistic fails, and so does any change in a feature / detector value beyond 9
significant digits (``frame_r`` / ``detectors_r``); with ML off also any change in the full
ThreatAssessments (exact; with ML on the anomaly score enters them, so ``assess`` is strict-only). A
last-bit float change in a feature or detector value does NOT fail by default: those bits differ between
hosts (Linux CI; a second Windows CPython 3.13 host even with the recording numpy).

Bit-exact mode is opt-in: ``AEGIS_GOLDEN_STRICT=1`` compares every digest bit for bit. Use it on the host that
regenerates the fixture (its ``recorded_env``); elsewhere a strict failure confined to ``frame`` /
``detectors`` is a host difference, not a regression. ``test_bit_exact_layers_compared_here`` reports, as a
skip reason (``pytest -r s``), when only the default layers were compared.

ML cases need the canonical team model: ``models/isoforest.joblib`` with the fixture's ``ml_model_sha256``. It is
git-ignored and ``aegis train`` cannot reproduce it byte for byte (it stamps a creation time), so the ML cases
skip without it on a developer machine (the skip reason says why). CI fetches and verifies it
(``scripts/fetch_models.py``) and sets ``AEGIS_REQUIRE_MODEL=1``, which turns that skip into a hard failure so the ML-on
coverage can never silently vanish. ``test_fast_isoforest_equals_sklearn_*`` does not need it (it trains a small model).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path

import pytest

from aegisflight.model_integrity import parse_manifest

REPO = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("make_golden", REPO / "scripts" / "make_golden.py")
mg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mg)  # type: ignore[union-attr]

GOLD = json.loads(mg.GOLDEN_PATH.read_text(encoding="utf-8"))
CANONICAL_ML_SHA256 = parse_manifest(REPO / "models" / "MODELS.sha256")["isoforest.joblib"]
_MODEL_PRESENT = mg.MODEL_PATH.exists()
_MODEL_ACTUAL_SHA = hashlib.sha256(mg.MODEL_PATH.read_bytes()).hexdigest() if _MODEL_PRESENT else None
_MODEL_OK = bool(_MODEL_PRESENT and _MODEL_ACTUAL_SHA == GOLD.get("ml_model_sha256") == CANONICAL_ML_SHA256)
_MODEL_REASON = "canonical team model models/isoforest.joblib missing or differs (fixture notes.ml)"
_SIM = dict(mg.sim_cases())
_LIVE = {n: (s, v) for n, s, v in mg.live_cases()}


# Float results can differ in the last bit with another host, CPU or C maths library. Measured: on a Raspberry Pi 3B+
# ~1% of the internal feature values differ by <= 4.4e-16; on Linux x86-64 CI (Python 3.13) the frame / detector
# digests of every ML-off case differ while parse / stats / assess match; on a second Windows CPython 3.13 host the frame
# digest of 4 ML-off cases differs with numpy 2.5.3, 2.5.4 (the recording version) and 2.5.5 alike. The old
# OS-arch-pyX.Y ``strict_envs`` tag could not tell such hosts apart, so the bit-exact comparison is opt-in
# (AEGIS_GOLDEN_STRICT=1). By default the guard compares the parsed messages, the parser statistics, the decision
# summary, with ML off the full ThreatAssessment hashes, and the feature / detector layers with floats rounded to 9
# significant digits (``frame_r`` / ``detectors_r``) -- the same layers Linux CI always compared.
_STRICT = os.environ.get("AEGIS_GOLDEN_STRICT") == "1"


def _env_diff(section: str) -> str:
    """Difference between this environment and the one ``section`` was recorded in (``make_golden.env_fingerprint``)."""
    fp = mg.env_fingerprint()
    rec = GOLD.get("recorded_env", {}).get(section) or {}
    diff = [f"{k} {fp[k]} here, {rec[k]} recorded" for k in sorted(rec) if k in fp and rec[k] != fp[k]]
    if not diff:
        return "same OS / Python / library versions as recorded" if rec == fp else f"recorded in (partly known) {rec}"
    return "; ".join(diff)


def _default_layers(ml: bool) -> tuple[str, ...]:
    # ML on: the anomaly score enters the ThreatAssessment, so ``assess`` is compared only in strict mode. The rounded
    # layers are compared (they matched between the author's host and this one, under numpy 2.5.3 and 2.5.5).
    return ("parse", "stats", *mg.PORTABLE) if ml else ("parse", "stats", "assess", *mg.PORTABLE)


def _compare(got: dict, want: dict, ml: bool) -> None:
    if _STRICT:
        assert got == want
        return
    for k in _default_layers(ml):
        assert got["digests"].get(k) == want["digests"].get(k), k
    summary = ("alerts", "attack_types", "n_decisions", "n_messages", "threat_decisions")
    for k in summary:
        assert got.get(k) == want.get(k), k


def _run(name: str, ml: bool) -> dict:
    if name in _SIM:
        return mg.run_sim_case(_SIM[name], ml)
    scn, var = _LIVE[name]
    return mg.run_live_case(scn, var, ml)


def _need_model(reason: str) -> None:
    """The canonical model is unusable: skip on a developer machine, but fail when ``AEGIS_REQUIRE_MODEL=1`` (CI).

    Read at call time, not import time, so the behaviour is testable and cannot be frozen by an early import."""
    if os.environ.get("AEGIS_REQUIRE_MODEL") == "1":
        pytest.fail(f"AEGIS_REQUIRE_MODEL=1 but {reason}; ML-on coverage would be skipped", pytrace=False)
    pytest.skip(reason)


def _params(key: str):
    return [pytest.param(n, id=n) for n in GOLD.get(key, {})]


@pytest.mark.parametrize("name", _params("no_ml"))
def test_golden_ml_off(name):
    _compare(_run(name, False), GOLD["no_ml"][name], ml=False)


@pytest.mark.parametrize("name", _params("ml"))
def test_golden_ml_on(name):
    if not _MODEL_OK:
        _need_model(_MODEL_REASON)
    _compare(_run(name, True), GOLD["ml"][name], ml=True)


@pytest.mark.parametrize("section", ["no_ml", "ml"])
def test_bit_exact_layers_compared_here(section):
    """Says (as a skip reason, listed by ``pytest -r s``) when only the default layers were compared above."""
    if section == "ml" and not _MODEL_OK:
        _need_model("ml: canonical team model missing or differs, ML cases not run")
    if not _STRICT:
        pytest.skip(f"{section}: bit-exact layers NOT compared (opt-in: AEGIS_GOLDEN_STRICT=1); compared "
                    f"{', '.join(_default_layers(section == 'ml'))} and the decision summary. "
                    f"Recording environment vs here: {_env_diff(section)}.")
    assert GOLD[section], "strict mode on an empty section"


def test_missing_model_skips_locally_and_fails_when_required(monkeypatch: pytest.MonkeyPatch) -> None:
    """AEGIS_REQUIRE_MODEL=1 (set in CI) turns the model-missing skip of the ML-on golden tests into a failure."""
    monkeypatch.delenv("AEGIS_REQUIRE_MODEL", raising=False)
    with pytest.raises(pytest.skip.Exception, match="model gone"):
        _need_model("model gone")
    monkeypatch.setenv("AEGIS_REQUIRE_MODEL", "0")
    with pytest.raises(pytest.skip.Exception):
        _need_model("model gone")
    monkeypatch.setenv("AEGIS_REQUIRE_MODEL", "1")
    with pytest.raises(pytest.fail.Exception, match="AEGIS_REQUIRE_MODEL=1.*model gone"):
        _need_model("model gone")


def test_golden_ml_sha_matches_canonical_manifest() -> None:
    """Guard against committing a retrained non-canonical SHA into golden.json (never skip silently)."""
    assert GOLD.get("ml_model_sha256") == CANONICAL_ML_SHA256, (
        f"tests/golden/golden.json ml_model_sha256={GOLD.get('ml_model_sha256')!r} "
        f"does not match canonical models/MODELS.sha256={CANONICAL_ML_SHA256!r}"
    )
    if _MODEL_PRESENT:
        assert _MODEL_ACTUAL_SHA == CANONICAL_ML_SHA256, (
            f"models/isoforest.joblib has sha256 {_MODEL_ACTUAL_SHA}, expected canonical {CANONICAL_ML_SHA256}"
        )


def test_seeded_ml_exercises_all_55_golden_cases(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Exercise all 55 ML golden scenarios with the deterministic seed-100 bundle even when canonical binary is absent."""
    import joblib
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    from aegisflight.benchmark.dataset import collect_benign_dataset
    from aegisflight.config import load_config
    from aegisflight.detectors.anomaly import combined_anomaly_raw
    from aegisflight.features.extractor import ML_FEATURES

    cfg = load_config()
    acfg = cfg.detector["anomaly"]
    ds = collect_benign_dataset(cfg, n_sessions=24, seed=100)
    split = ds.split_by_session(train_frac=0.6, val_frac=0.2, seed=100)
    Xtr, Xva = split["train"], split["val"]
    scaler = StandardScaler().fit(Xtr)
    Xtr_s = scaler.transform(Xtr)
    model = IsolationForest(
        n_estimators=int(acfg.get("n_estimators", 200)),
        contamination=float(acfg.get("contamination", 0.02)),
        random_state=100,
        n_jobs=-1,
    ).fit(Xtr_s)
    iso_tr = -model.score_samples(Xtr_s)
    maha_tr = np.linalg.norm(Xtr_s, axis=1)
    bundle = {
        "model": model,
        "scaler": scaler,
        "feature_names": list(ML_FEATURES),
        "iso_mean": float(iso_tr.mean()),
        "iso_std": float(iso_tr.std() or 1e-3),
        "maha_mean": float(maha_tr.mean()),
        "maha_std": float(maha_tr.std() or 1e-3),
    }
    va_raw = combined_anomaly_raw(bundle, Xva)
    bundle["score_thr"] = float(va_raw.mean() + 3.0 * va_raw.std())
    bundle["score_scale"] = float(max(va_raw.std(), 1e-3))

    model_file = tmp_path / "seeded_isoforest.joblib"
    joblib.dump(bundle, model_file)
    digest = hashlib.sha256(model_file.read_bytes()).hexdigest()
    (tmp_path / "MODELS.sha256").write_text(f"{digest}  seeded_isoforest.joblib\n", encoding="utf-8")
    monkeypatch.setattr(mg, "MODEL_PATH", model_file)

    ml_cases = sorted(GOLD["ml"])
    assert len(ml_cases) == 55
    for name in ml_cases:
        got = _run(name, True)
        assert got["n_decisions"] > 0, name
        want_no_ml = GOLD["no_ml"][name]
        # Adding ML must never alter message parsing/stats or drop decisions.
        assert got["n_decisions"] == want_no_ml["n_decisions"], name
        assert got["n_messages"] == want_no_ml["n_messages"], name
        for k in ("parse", "stats"):
            if k in want_no_ml["digests"]:
                assert got["digests"].get(k) == want_no_ml["digests"][k], (name, k)
        assert got["digests"]["frame_r"] == want_no_ml["digests"]["frame_r"], name
        if not name.endswith("/profile"):
            assert got["digests"]["detectors_r"] != want_no_ml["digests"]["detectors_r"], name


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

def _tiny_model(path: Path) -> Path:
    """A small model bundle in the layout ``aegis train`` writes (cli/main.py), trained here in well under a second.

    Heterogeneous feature scales and one constant column (unit scale in StandardScaler, as for zero-variance benign
    features) so the scaler replica in the fast scorer is exercised, not just the tree walk.
    """
    import joblib
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    from aegisflight.detectors.anomaly import combined_anomaly_raw
    from aegisflight.features.extractor import ML_FEATURES

    rs = np.random.RandomState(7)
    n = len(ML_FEATURES)
    X = rs.randn(600, n) * rs.uniform(0.05, 40.0, n) + rs.uniform(-50.0, 50.0, n)
    X[:, 0] = 2.5
    tr, va = X[:450], X[450:]
    scaler = StandardScaler().fit(tr)
    model = IsolationForest(n_estimators=24, max_samples=128, random_state=7).fit(scaler.transform(tr))
    trs = scaler.transform(tr)
    iso, maha = -model.score_samples(trs), np.linalg.norm(trs, axis=1)
    bundle = {"model": model, "scaler": scaler, "feature_names": list(ML_FEATURES),
              "iso_mean": float(iso.mean()), "iso_std": float(iso.std() or 1e-3),
              "maha_mean": float(maha.mean()), "maha_std": float(maha.std() or 1e-3)}
    v = combined_anomaly_raw(bundle, va)
    bundle["score_thr"] = float(v.mean() + 3.0 * v.std())
    bundle["score_scale"] = float(max(v.std(), 1e-3))
    joblib.dump(bundle, path)
    return path


@pytest.fixture(params=["tiny-in-test", "models/isoforest.joblib"])
def anomaly_model(request, tmp_path) -> Path:
    if request.param == "tiny-in-test":
        return _tiny_model(tmp_path / "tiny_isoforest.joblib")
    if not mg.MODEL_PATH.exists():
        _need_model("models/isoforest.joblib missing (git-ignored; `python scripts/fetch_models.py` fetches it)")
    return mg.MODEL_PATH


def test_fast_isoforest_equals_sklearn_bitwise_and_fallback_is_identical(anomaly_model):
    """Holds for any fitted model, so it runs on a model trained in-test (everywhere, CI included) and on the
    repository model when present (any model there, not only the one the golden fixture was built with)."""
    import numpy as np

    from aegisflight.core.types import TelemetrySnapshot
    from aegisflight.detectors.anomaly import AnomalyDetector, combined_anomaly_raw
    from aegisflight.features.extractor import ML_FEATURES, FeatureFrame

    cfg = mg.load_config().detector["anomaly"]
    fast_det = AnomalyDetector(cfg, anomaly_model, allow_unverified=True)
    slow_det = AnomalyDetector(cfg, anomaly_model, allow_unverified=True)
    assert fast_det.bundle is not None, f"{anomaly_model} did not load"
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
