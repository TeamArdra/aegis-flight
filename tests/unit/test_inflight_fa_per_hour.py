"""Unit and regression tests for in-flight false-alert mitigation and per-hour evaluation (#49)."""

from __future__ import annotations

import json
from pathlib import Path

from aegisflight.config import load_config
from aegisflight.core.enums import AttackType, DetectorName, IntegrityStatus, Severity
from aegisflight.core.types import DetectorResult
from aegisflight.detectors.anomaly import AnomalyDetector
from aegisflight.fusion.engine import FusionEngine

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_stage1_defaults_keep_ml_enabled_and_uncorroborated_ml_allowed() -> None:
    cfg = load_config()
    assert cfg.detector["anomaly"]["enabled"] is True
    assert cfg.detector["fusion"]["ml_require_corroboration"] is False

    engine = FusionEngine(cfg.detector["fusion"])
    res = [
        DetectorResult(detector=DetectorName.PROTOCOL, score=0.0, triggered=False),
        DetectorResult(detector=DetectorName.PHYSICS, score=0.0, triggered=False),
        DetectorResult(
            detector=DetectorName.ANOMALY,
            score=0.99,
            triggered=True,
            evidence=["ML anomaly score 0.99 >= 0.62"],
            attack_votes={AttackType.DOS: 0.99},
        ),
        DetectorResult(detector=DetectorName.INTEGRITY, score=0.0, triggered=False),
    ]
    asmt = engine.fuse(10.0, 10.0, res, IntegrityStatus.VALID)
    assert asmt.threat is True
    assert asmt.is_alert is True
    assert asmt.attack_type is AttackType.DOS


def test_ardupilot_profile_disables_uncalibrated_ml_and_requires_corroboration(tmp_path: Path) -> None:
    cfg = load_config(REPO_ROOT / "configs" / "ardupilot_copter")
    assert cfg.detector["anomaly"]["enabled"] is False
    assert cfg.detector["fusion"]["ml_require_corroboration"] is True

    # Even if a caller passes a model_path, anomaly.enabled=false prevents loading an uncalibrated model
    dummy_model = tmp_path / "dummy.joblib"
    dummy_model.write_bytes(b"not-a-valid-joblib")
    det = AnomalyDetector(cfg.detector["anomaly"], model_path=dummy_model)
    assert det.available is False
    assert det.model_path is None

    engine = FusionEngine(cfg.detector["fusion"])
    lone_ml = [
        DetectorResult(detector=DetectorName.PROTOCOL, score=0.0, triggered=False),
        DetectorResult(detector=DetectorName.PHYSICS, score=0.0, triggered=False),
        DetectorResult(
            detector=DetectorName.ANOMALY,
            score=1.0,
            triggered=True,
            evidence=["ML anomaly score 1.00 >= 0.62 (driver: interarrival_jitter_ms, z=+14.2)"],
            attack_votes={AttackType.DOS: 1.0},
        ),
        DetectorResult(detector=DetectorName.INTEGRITY, score=0.0, triggered=False),
    ]
    asmt_lone = engine.fuse(20.0, 20.0, lone_ml, IntegrityStatus.UNKNOWN)
    assert asmt_lone.threat is False
    assert asmt_lone.is_alert is False
    assert asmt_lone.severity is Severity.NORMAL

    # Corroborated by physics (e.g. position drift) -> threat and alert fire normally
    corroborated = [
        DetectorResult(detector=DetectorName.PROTOCOL, score=0.0, triggered=False),
        DetectorResult(
            detector=DetectorName.PHYSICS,
            score=0.55,
            triggered=True,
            evidence=["position residual 13.1 m > 12 m"],
            attack_votes={AttackType.GPS_SPOOFING: 0.55},
        ),
        DetectorResult(
            detector=DetectorName.ANOMALY,
            score=0.98,
            triggered=True,
            attack_votes={AttackType.DOS: 0.98},
        ),
        DetectorResult(detector=DetectorName.INTEGRITY, score=0.0, triggered=False),
    ]
    asmt_corr = engine.fuse(25.0, 25.0, corroborated, IntegrityStatus.UNKNOWN)
    assert asmt_corr.threat is True
    assert asmt_corr.is_alert is True


def test_committed_inflight_fa_per_hour_artifacts_and_heldout_lock() -> None:
    lock_path = REPO_ROOT / "artifacts" / "ardupilot" / "calibration" / "heldout_lock.json"
    metrics_path = REPO_ROOT / "artifacts" / "validation" / "inflight_fa_per_hour_20261119" / "metrics.json"
    assert lock_path.is_file()
    assert metrics_path.is_file()

    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    assert metrics["held_out_burned"] is False
    assert metrics["frozen_inputs"] == lock["frozen_inputs"]

    # Held-out ArduPilot SITL in-flight false alerts == 0
    ho = metrics["ardupilot"]["after_profile_heldout_4runs"]
    assert ho["from_arm_phase"]["alert_events"] == 0
    assert ho["airborne_only"]["alert_events"] == 0

    # All 6 ArduPilot drift trials detect with 0.0 s onset latency regression
    drift = metrics["drift_attack_regression"]
    assert drift["detected"] == drift["n_trials"] == 6
    assert drift["max_onset_latency_delta_s"] == 0.0
