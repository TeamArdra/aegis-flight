"""Unit regression tests for optional hash-verified ML model loading in InlineIpsBridge."""

from __future__ import annotations

import hashlib
import importlib
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


def test_bridge_ml_model_corrupt_or_unloadable_fails_closed(tmp_path: Path) -> None:
    model_file = _write_verified_model(tmp_path)
    with patch("joblib.load", side_effect=RuntimeError("corrupt pickle")):
        with pytest.raises(ValueError, match="ML model failed to load"):
            InlineIpsBridge(_StubTransport(), _StubTransport(), model_path=str(model_file))

    unlisted = tmp_path / "unlisted_corrupt.joblib"
    unlisted.write_bytes(b"not-a-valid-joblib")
    with patch("joblib.load", side_effect=RuntimeError("corrupt pickle")):
        with pytest.raises(ValueError, match="ML model failed to load"):
            InlineIpsBridge(
                _StubTransport(),
                _StubTransport(),
                model_path=str(unlisted),
                allow_unverified_model=True,
            )


# --- evidence: the run manifest must record the model the bridge actually ran with ------------------------------

_RUN_ARGS = ["ips-bridge", "--fc-port", "socket://127.0.0.1:1", "--gcs-port", "socket://127.0.0.1:2", "--allow-url",
             "--seconds", "0.3", "--status-interval", "0.1"]


def _clean_tree(monkeypatch) -> None:
    from aegisflight import run_provenance

    monkeypatch.setattr(run_provenance, "tree_state",
                        lambda repo=None: {"commit": "c" * 40, "dirty": False, "dirty_paths": []})


def _fake_bundle() -> dict:
    return {
        "model": _StubIsoForest(), "scaler": _StubScaler(), "score_min": -0.8, "score_max": 0.2, "score_thr": 0.62,
        "score_scale": 1.0, "iso_mean": -0.1, "iso_std": 0.1, "maha_mean": 0.0, "maha_std": 1.0,
        "maha_mu": np.zeros(11), "maha_inv_cov": np.eye(11),
    }


def test_run_manifest_records_the_verified_model(tmp_path: Path, monkeypatch) -> None:
    import json

    cli_main = importlib.import_module("aegisflight.cli.main")

    _clean_tree(monkeypatch)
    model_file = _write_verified_model(tmp_path)
    run_dir = tmp_path / "run"
    with patch("joblib.load", return_value=_fake_bundle()):
        rc = cli_main.main([*_RUN_ARGS, "--model", str(model_file), "--run-dir", str(run_dir)])
    assert rc == 0
    m = json.loads((run_dir / "run_manifest.json").read_text())
    assert m["ml_enabled"] is True
    assert m["model_path"] == str(model_file).replace("\\", "/")
    assert m["model_sha256"] == hashlib.sha256(model_file.read_bytes()).hexdigest()
    assert m["model_verification"] == "ok"
    assert m["allow_unverified_model"] is False


def test_run_manifest_flags_an_unverified_model_override(tmp_path: Path, monkeypatch) -> None:
    import json

    cli_main = importlib.import_module("aegisflight.cli.main")

    _clean_tree(monkeypatch)
    model_file = tmp_path / "custom.joblib"
    model_file.write_bytes(b"custom")
    run_dir = tmp_path / "run"
    with patch("joblib.load", return_value=_fake_bundle()):
        rc = cli_main.main([*_RUN_ARGS, "--model", str(model_file), "--allow-unverified-model",
                            "--run-dir", str(run_dir)])
    assert rc == 0
    m = json.loads((run_dir / "run_manifest.json").read_text())
    assert m["ml_enabled"] is True and m["model_sha256"] == hashlib.sha256(b"custom").hexdigest()
    assert m["model_verification"] == "unlisted" and m["allow_unverified_model"] is True


def test_run_manifest_without_model_still_says_ml_off(tmp_path: Path, monkeypatch) -> None:
    import json

    cli_main = importlib.import_module("aegisflight.cli.main")

    _clean_tree(monkeypatch)
    run_dir = tmp_path / "run"
    assert cli_main.main([*_RUN_ARGS, "--run-dir", str(run_dir)]) == 0
    m = json.loads((run_dir / "run_manifest.json").read_text())
    assert m["ml_enabled"] is False and m["model_path"] == "none" and m["model_sha256"] is None
    assert "model_verification" not in m


def test_refused_model_creates_no_run_dir(tmp_path: Path, monkeypatch) -> None:
    cli_main = importlib.import_module("aegisflight.cli.main")

    _clean_tree(monkeypatch)
    unlisted = tmp_path / "unlisted.joblib"
    unlisted.write_bytes(b"x")
    run_dir = tmp_path / "run"
    with pytest.raises(SystemExit) as exc:
        cli_main.main([*_RUN_ARGS, "--model", str(unlisted), "--run-dir", str(run_dir)])
    assert exc.value.code == 2
    assert not run_dir.exists()
