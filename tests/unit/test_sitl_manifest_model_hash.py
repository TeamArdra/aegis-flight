"""Issue #26: a SITL trial manifest hashes the model the run actually loaded, and a requested-but-missing model refuses.

Before the fix ``provenance_block`` called ``collect()`` without the resolved model, so ``full_provenance.model_sha256``
was the hash of the default ``models/isoforest.joblib`` whatever ``--model`` selected, and ``resolve_model`` returned
``model_choice="px4"`` with no model path when the PX4 file was missing (ML silently off).
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "sitl"))

import p2_trial_common  # noqa: E402

from aegisflight import run_provenance  # noqa: E402


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


@pytest.fixture()
def models(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Path]:
    px4, stage1 = tmp_path / "px4.joblib", tmp_path / "stage1.joblib"
    px4.write_bytes(b"px4-model-bytes")
    stage1.write_bytes(b"stage1-model-bytes")
    monkeypatch.setattr(p2_trial_common, "MODEL_PX4", str(px4))
    monkeypatch.setattr(p2_trial_common, "MODEL_STAGE1", str(stage1))
    monkeypatch.setattr(p2_trial_common, "px4_describe", lambda *a, **k: "v1.15.0")
    monkeypatch.setattr(run_provenance, "tree_state",
                        lambda repo=None: {"commit": "c" * 40, "dirty": False, "dirty_paths": []})
    return {"px4": px4, "stage1": stage1}


def _manifest_provenance(tmp_path: Path, *argv: str) -> dict:
    ap = p2_trial_common.build_argparser("t", default_seconds=1.0)
    ap.parse_args(["--seed", "1", "--out", str(tmp_path / "o"), *argv])
    return p2_trial_common.provenance_block("d", "/px4", {})


def test_manifest_hashes_stage1_model_passed(models, tmp_path):
    prov = _manifest_provenance(tmp_path, "--profile", "", "--model", "stage1")
    assert prov["full_provenance"]["model_sha256"] == _sha(models["stage1"])


def test_manifest_hashes_px4_model_passed(models, tmp_path):
    prov = _manifest_provenance(tmp_path, "--model", "px4")  # default profile configs/px4_sitl
    assert prov["full_provenance"]["model_sha256"] == _sha(models["px4"])
    assert prov["full_provenance"]["model_sha256"] != _sha(models["stage1"])


def test_manifest_records_no_model_when_ml_is_off(models, tmp_path):
    prov = _manifest_provenance(tmp_path, "--model", "none")
    assert prov["full_provenance"]["model_sha256"] is None


@pytest.mark.parametrize(("profile", "model"), [("configs/px4_sitl", "px4"), ("", "stage1")])
def test_missing_requested_model_refuses(models, profile, model, capsys):
    models[model].unlink()
    with pytest.raises(SystemExit) as ei:
        p2_trial_common.resolve_model(profile, model)
    assert ei.value.code == 2
    assert "does not exist" in capsys.readouterr().err


def test_model_none_still_runs_without_a_model(models):
    assert p2_trial_common.resolve_model("configs/px4_sitl", "none") == (None, "none")


def test_present_model_resolves_to_its_path(models):
    assert p2_trial_common.resolve_model("configs/px4_sitl", None) == (str(models["px4"]), "px4")
