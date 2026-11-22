"""Unit regression tests for optional hash-verified ML model loading in InlineIpsBridge."""

from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import patch

import numpy as np
import pytest

from aegisflight.cli.main import build_parser
from aegisflight.features.extractor import FeatureFrame
from aegisflight.hal.inline_ips import InlineIpsBridge


class _StubTransport:
    """Minimal BridgeTransport stub for unit tests."""

    def start(self) -> None:
        pass

    def close(self) -> None:
        pass

    def recv(self, timeout_s: float = 0.05) -> bytes | None:
        return None

    def send(self, data: bytes) -> None:
        pass


class _StubScaler:
    """Minimal StandardScaler-like stub."""

    def transform(self, x):
        return x


class _StubIsoForest:
    """Minimal IsolationForest-like scorer that flags large position drift."""

    def score_samples(self, x):
        # Flag any sample where pos_residual_m (index 3 in ML_FEATURES) > 10.0
        scores = []
        for row in x:
            scores.append(-0.8 if float(row[3]) > 10.0 else 0.1)
        return np.array(scores, dtype=float)


def _write_verified_model(tmp_path: Path, name: str = "test_model.joblib") -> Path:
    model_file = tmp_path / name
    model_file.write_bytes(b"dummy-model-bytes")
    digest = hashlib.sha256(model_file.read_bytes()).hexdigest()
    (tmp_path / "MODELS.sha256").write_text(f"{digest}  {name}\n", encoding="utf-8")
    return model_file


def test_bridge_ml_model_missing_fails_closed(tmp_path: Path) -> None:
    missing = tmp_path / "missing.joblib"
    with pytest.raises(ValueError, match="ML model check failed"):
        InlineIpsBridge(_StubTransport(), _StubTransport(), model_path=str(missing))


def test_bridge_ml_model_unlisted_fails_closed(tmp_path: Path) -> None:
    unlisted = tmp_path / "unlisted.joblib"
    unlisted.write_bytes(b"unlisted-bytes")
    with pytest.raises(ValueError, match="ML model check failed"):
        InlineIpsBridge(_StubTransport(), _StubTransport(), model_path=str(unlisted))


def test_bridge_ml_model_mismatch_fails_closed(tmp_path: Path) -> None:
    model_file = _write_verified_model(tmp_path)
    model_file.write_bytes(b"tampered-bytes")
    with pytest.raises(ValueError, match="ML model check failed"):
        InlineIpsBridge(_StubTransport(), _StubTransport(), model_path=str(model_file))


def test_bridge_ml_model_verified_detects_inflight_position_drift(tmp_path: Path) -> None:
    model_file = _write_verified_model(tmp_path)
    fake_bundle = {
        "model": _StubIsoForest(),
        "scaler": _StubScaler(),
        "score_min": -0.8,
        "score_max": 0.2,
        "score_thr": 0.62,
        "score_scale": 1.0,
        "iso_mean": -0.1,
        "iso_std": 0.1,
        "maha_mean": 0.0,
        "maha_std": 1.0,
        "maha_mu": np.zeros(11),
        "maha_inv_cov": np.eye(11),
    }
    with patch("joblib.load", return_value=fake_bundle):
        bridge = InlineIpsBridge(_StubTransport(), _StubTransport(), model_path=str(model_file))

    assert bridge.pipeline.anomaly.bundle is fake_bundle
    assert bridge.pipeline.anomaly.load_error is None

    # Feed a drifted FeatureFrame directly into AnomalyDetector after warmup
    bridge.pipeline.anomaly.warmup_ticks = 0
    normal_frame = FeatureFrame(t=1.0, snapshot={}, pos_residual_m=0.5)
    drifted_frame = FeatureFrame(t=2.0, snapshot={}, pos_residual_m=50.0)

    normal_res = bridge.pipeline.anomaly.process(normal_frame)
    drifted_res = bridge.pipeline.anomaly.process(drifted_frame)

    assert normal_res.score < bridge.pipeline.anomaly.threshold
    assert drifted_res.score >= bridge.pipeline.anomaly.threshold


def test_bridge_cli_model_flag_and_fail_closed(tmp_path: Path) -> None:
    parser = build_parser()
    unlisted = tmp_path / "unlisted.joblib"
    unlisted.write_bytes(b"unlisted")
    args = parser.parse_args([
        "ips-bridge",
        "--fc-port", "udp:127.0.0.1:14540",
        "--gcs-port", "udp:127.0.0.1:14550",
        "--model", str(unlisted),
    ])
    assert args.model == str(unlisted)
    with pytest.raises(SystemExit) as exc_info:
        args.func(args)
    assert exc_info.value.code == 2
