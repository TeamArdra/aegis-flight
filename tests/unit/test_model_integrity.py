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
        det = AnomalyDetector(CFG, bad)
    assert det.bundle is None
    msgs = [r.getMessage() for r in caplog.records]
    assert any("corrupt.joblib" in m and "unreadable" in m for m in msgs)


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
