"""Model integrity and loud ML-off behaviour (issue #11).

Environment: SIM / unit. No network: the fetch script is driven through a ``file://`` base URL.
"""

from __future__ import annotations

import hashlib
import importlib.util
import logging
from pathlib import Path

import joblib
import pytest

from aegisflight.cli.main import main as cli_main
from aegisflight.config import load_config
from aegisflight.detectors.anomaly import AnomalyDetector
from aegisflight.model_integrity import (
    MISMATCH,
    MISSING,
    OK,
    UNLISTED,
    check_model,
    model_sha256_or_none,
    parse_manifest,
)

REPO = Path(__file__).resolve().parents[2]
CFG = load_config().detector["anomaly"]


def _write_model(path: Path, payload: bytes = b"not-a-real-model") -> str:
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _manifest(d: Path, name: str, digest: str) -> None:
    (d / "MODELS.sha256").write_text(f"# comment\n\n{digest}  {name}\n", encoding="utf-8")


def test_committed_manifest_lists_both_models_with_64_hex_digests():
    entries = parse_manifest(REPO / "models" / "MODELS.sha256")
    assert set(entries) == {"isoforest.joblib", "isoforest_px4.joblib"}
    assert all(len(v) == 64 and int(v, 16) >= 0 for v in entries.values())


def test_check_model_statuses(tmp_path):
    digest = _write_model(tmp_path / "m.joblib")
    assert check_model(tmp_path / "m.joblib").status == UNLISTED  # no manifest
    _manifest(tmp_path, "m.joblib", digest)
    assert check_model(tmp_path / "m.joblib").status == OK
    _manifest(tmp_path, "m.joblib", "0" * 64)
    chk = check_model(tmp_path / "m.joblib")
    assert chk.status == MISMATCH and chk.sha256 == digest and chk.expected == "0" * 64
    assert check_model(tmp_path / "gone.joblib").status == MISSING
    assert model_sha256_or_none(tmp_path / "gone.joblib") == "none" == model_sha256_or_none(None)
    assert model_sha256_or_none(tmp_path / "m.joblib") == digest


def test_missing_model_file_warns_and_stays_ml_off(tmp_path, caplog):
    with caplog.at_level(logging.WARNING, logger="aegisflight.detectors.anomaly"):
        det = AnomalyDetector(CFG, tmp_path / "absent.joblib")
    assert det.bundle is None
    assert any("absent.joblib" in r.getMessage() and "does not exist" in r.getMessage() for r in caplog.records)


def test_corrupt_model_file_warns_with_reason_and_stays_ml_off(tmp_path, caplog):
    bad = tmp_path / "corrupt.joblib"
    bad.write_bytes(b"this is not a joblib file")
    with caplog.at_level(logging.WARNING, logger="aegisflight.detectors.anomaly"):
        det = AnomalyDetector(CFG, bad, allow_unverified=True)
    assert det.bundle is None
    msgs = [r.getMessage() for r in caplog.records]
    assert any("corrupt.joblib" in m and "unreadable" in m for m in msgs)


def test_anomaly_detector_refuses_tampered_and_unlisted_models_before_joblib_load(tmp_path, monkeypatch, caplog):
    """P1 security boundary: tampered or unlisted models must be rejected BEFORE joblib.load deserialization."""
    import joblib as _joblib

    def _boom(*_a, **_kw):
        raise AssertionError("joblib.load MUST NOT be called on unverified/tampered models")

    monkeypatch.setattr(_joblib, "load", _boom)

    # 1. Tampered model (hash mismatch against MODELS.sha256)
    tampered = tmp_path / "tampered.joblib"
    tampered.write_bytes(b"evil-payload")
    _manifest(tmp_path, "tampered.joblib", "a" * 64)
    with caplog.at_level(logging.WARNING, logger="aegisflight.detectors.anomaly"):
        det_t = AnomalyDetector(CFG, tampered)
    assert det_t.available is False
    assert det_t.load_error is not None and "mismatch" in det_t.load_error

    # 2. Unlisted model (no manifest entry)
    unlisted = tmp_path / "unlisted.joblib"
    unlisted.write_bytes(b"unlisted-payload")
    with caplog.at_level(logging.WARNING, logger="aegisflight.detectors.anomaly"):
        det_u = AnomalyDetector(CFG, unlisted)
    assert det_u.available is False
    assert det_u.load_error is not None and "unlisted" in det_u.load_error


def test_anomaly_detector_loads_manifest_verified_model(tmp_path):
    """A model whose SHA-256 matches MODELS.sha256 loads cleanly."""
    from aegisflight.features.extractor import ML_FEATURES

    m = tmp_path / "valid.joblib"
    joblib.dump(
        {
            "model": None,
            "scaler": None,
            "feature_names": list(ML_FEATURES),
            "iso_mean": 0.0,
            "iso_std": 1.0,
            "maha_mean": 0.0,
            "maha_std": 1.0,
            "score_thr": 3.0,
            "score_scale": 1.0,
        },
        m,
    )
    digest = hashlib.sha256(m.read_bytes()).hexdigest()
    _manifest(tmp_path, "valid.joblib", digest)
    det = AnomalyDetector(CFG, m)
    assert det.available is True
    assert det.load_error is None


def test_no_model_path_is_silent_explicit_opt_out(caplog):
    with caplog.at_level(logging.WARNING, logger="aegisflight.detectors.anomaly"):
        det = AnomalyDetector(CFG, None)
    assert det.bundle is None and not caplog.records


def test_cli_benchmark_exits_nonzero_and_names_fetch_command_when_model_missing(tmp_path, capsys):
    with pytest.raises(SystemExit) as e:
        cli_main(["benchmark", "--model", str(tmp_path / "m.joblib"), "--out", str(tmp_path / "o"),
                  "--no-figures"])
    assert e.value.code == 2
    assert "python scripts/fetch_models.py" in capsys.readouterr().err
    assert not (tmp_path / "o" / "summary.md").exists()


def test_cli_simulate_exits_nonzero_on_sha_mismatch(tmp_path, capsys):
    m = tmp_path / "m.joblib"
    joblib.dump({"not": "a bundle"}, m)
    _manifest(tmp_path, "m.joblib", "0" * 64)
    with pytest.raises(SystemExit) as e:
        cli_main(["simulate", "--model", str(m), "--attack", "benign"])
    assert e.value.code == 2
    err = capsys.readouterr().err
    assert "mismatch" in err and "python scripts/fetch_models.py" in err


def test_cli_no_model_is_the_explicit_opt_out_and_still_runs(tmp_path, capsys):
    rc = cli_main(["simulate", "--no-model", "--attack", "benign", "--model", str(tmp_path / "absent.joblib")])
    assert rc == 0
    assert "model=off" in capsys.readouterr().out


def test_benchmark_summary_header_records_model_sha256_none_for_ml_off(tmp_path):
    from aegisflight.benchmark.harness import run_benchmark

    res = run_benchmark(load_config(), seeds=[1], model_path=None, out_dir=tmp_path)
    assert res["config"]["model_sha256"] == "none" and res["config"]["model_used"] is False
    assert "model_sha256: none" in (tmp_path / "summary.md").read_text(encoding="utf-8")


def _fetch_module():
    spec = importlib.util.spec_from_file_location("fetch_models", REPO / "scripts" / "fetch_models.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_fetch_models_downloads_verifies_and_rejects_a_bad_file(tmp_path, capsys):
    fm = _fetch_module()
    src, dst = tmp_path / "src", tmp_path / "models"
    src.mkdir()
    dst.mkdir()
    good = _write_model(src / "a.joblib", b"model-a")
    _write_model(src / "b.joblib", b"tampered")
    (dst / "MODELS.sha256").write_text(f"{good}  a.joblib\n{'1' * 64}  b.joblib\n", encoding="utf-8")
    rc = fm.main(["--models-dir", str(dst), "--base-url", src.as_uri()])
    assert rc == 1
    assert (dst / "a.joblib").read_bytes() == b"model-a"  # verified file installed
    assert not (dst / "b.joblib").exists()  # mismatching download discarded
    assert not list(dst.glob("*.part"))
    assert "discarded" in capsys.readouterr().err
    assert fm.main(["--models-dir", str(dst), "--verify-only"]) == 1  # b is still missing


def test_fetch_models_corrupt_file_is_refetched_and_verified(tmp_path):
    fm = _fetch_module()
    src, dst = tmp_path / "src", tmp_path / "models"
    src.mkdir()
    dst.mkdir()
    good = _write_model(src / "a.joblib", b"model-a")
    (dst / "MODELS.sha256").write_text(f"{good}  a.joblib\n", encoding="utf-8")
    (dst / "a.joblib").write_bytes(b"corrupt")
    assert fm.main(["--models-dir", str(dst), "--verify-only"]) == 1
    assert fm.main(["--models-dir", str(dst), "--base-url", src.as_uri()]) == 0
    assert fm.main(["--models-dir", str(dst), "--verify-only"]) == 0


# --- R5: CLI, detector and benchmark metadata agree on every model state ---------------------------------

def _valid_bundle(path: Path) -> None:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    from aegisflight.features.extractor import ML_FEATURES

    X = np.random.default_rng(0).normal(size=(200, len(ML_FEATURES)))
    scaler = StandardScaler().fit(X)
    model = IsolationForest(n_estimators=10, random_state=0).fit(scaler.transform(X))
    joblib.dump({"model": model, "scaler": scaler, "feature_names": list(ML_FEATURES), "iso_mean": 0.0,
                 "iso_std": 1.0, "maha_mean": 0.0, "maha_std": 1.0, "score_thr": 3.0, "score_scale": 1.0}, path)


def _bench(tmp_path, monkeypatch, model, allow=False):
    from aegisflight.benchmark import harness

    monkeypatch.setattr(harness, "SCENARIOS", ["benign"])
    return harness.run_benchmark(load_config(), seeds=[1], model_path=str(model),
                                 out_dir=tmp_path / "out", allow_unverified_model=allow)


def _setup(tmp_path, state):
    m = tmp_path / "m.joblib"
    if state == "missing":
        return m
    if state == "corrupt":  # listed + hash matches, but not a joblib file
        digest = _write_model(m, b"not a joblib file")
        _manifest(tmp_path, "m.joblib", digest)
        return m
    _valid_bundle(m)
    digest = hashlib.sha256(m.read_bytes()).hexdigest()
    if state == "canonical":
        _manifest(tmp_path, "m.joblib", digest)
    elif state == "mismatch":
        _manifest(tmp_path, "m.joblib", "0" * 64)
    return m  # "unlisted": no manifest


@pytest.mark.parametrize("state", ["missing", "mismatch", "unlisted"])
def test_cli_refuses_non_ok_models_without_the_override(tmp_path, capsys, state):
    m = _setup(tmp_path, state)
    with pytest.raises(SystemExit) as e:
        cli_main(["simulate", "--model", str(m), "--attack", "benign"])
    assert e.value.code == 2
    err = capsys.readouterr().err
    assert (("fetch_models" in err) if state == "missing" else ("--allow-unverified-model" in err))


def test_cli_accepts_unlisted_model_with_override_and_ml_is_actually_on(tmp_path, capsys):
    m = _setup(tmp_path, "unlisted")
    assert cli_main(["simulate", "--model", str(m), "--attack", "benign", "--allow-unverified-model"]) == 0
    cap = capsys.readouterr()
    assert "UNVERIFIED" in cap.err


@pytest.mark.parametrize(("state", "allow", "used"), [
    ("missing", False, False),
    ("corrupt", False, False),  # listed+hash OK but unreadable: detector degrades, benchmark must say ML off
    ("mismatch", False, False),  # library path: detector refuses -> ML off, header must not claim it
    ("unlisted", False, False),
    ("unlisted", True, True),
    ("canonical", False, True),
])
def test_benchmark_metadata_reflects_what_the_pipeline_loaded(tmp_path, monkeypatch, state, allow, used):
    m = _setup(tmp_path, state)
    res = _bench(tmp_path, monkeypatch, m, allow)
    cfg = res["config"]
    assert cfg["model_used"] is used
    expected = hashlib.sha256(m.read_bytes()).hexdigest() if used else "none"
    assert cfg["model_sha256"] == expected
    summary = (tmp_path / "out" / "summary.md").read_text(encoding="utf-8")
    assert f"Model used: {used}. model_sha256: {expected}._" in summary
    assert "| TP / FP / TN / FN |" in summary


@pytest.mark.parametrize("state", ["canonical", "mismatch", "missing"])
def test_extended_benchmark_metadata_reflects_what_the_pipeline_loaded(tmp_path, monkeypatch, state):
    from aegisflight.benchmark import extended

    m = _setup(tmp_path, state)
    one = extended.build_grid()[:1]
    monkeypatch.setattr(extended, "build_grid", lambda **_kw: one)
    res = extended.run_extended(tmp_path / "out", model_path=str(m), workers=1)
    used = state == "canonical"
    assert res["config"]["model_used"] is used
    expected = hashlib.sha256(m.read_bytes()).hexdigest() if used else "none"
    assert res["config"]["model_sha256"] == expected
