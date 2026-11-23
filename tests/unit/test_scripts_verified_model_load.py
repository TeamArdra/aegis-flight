"""Validation scripts unpickle a model only after the manifest hash check (issue #155).

Environment: SIM / unit. The model is a tmp file; models/ is never touched. The "model" is a pickle whose
payload writes a marker file when it is deserialised, so a test that passes proves the bytes were refused
BEFORE ``joblib.load`` ran, not merely that an error surfaced afterwards.
"""

from __future__ import annotations

import hashlib
import importlib.util
import pickle
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


class _Payload:
    """Unpickling this writes ``marker`` (stand-in for arbitrary code execution)."""

    def __init__(self, marker: Path) -> None:
        self.marker = marker

    def __reduce__(self):
        return (Path.write_text, (self.marker, "executed"))


def _load_script(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def hostile_model(tmp_path):
    """A model file whose manifest lists a different hash, plus the marker its payload would write."""
    models = tmp_path / "models"
    models.mkdir()
    marker = tmp_path / "executed.marker"
    model = models / "isoforest.joblib"
    model.write_bytes(pickle.dumps(_Payload(marker)))
    (models / "MODELS.sha256").write_text(f"{hashlib.sha256(b'the shipped model').hexdigest()}  {model.name}\n",
                                          encoding="utf-8")
    return model, marker


@pytest.fixture
def unlisted_model(tmp_path):
    models = tmp_path / "models"
    models.mkdir()
    marker = tmp_path / "executed.marker"
    model = models / "isoforest.joblib"
    model.write_bytes(pickle.dumps(_Payload(marker)))  # no MODELS.sha256 at all
    return model, marker


@pytest.fixture
def ev():
    return _load_script("external_validation_under_test", "external_validation.py")


@pytest.fixture
def probe():
    return _load_script("calib_rtf_probe_under_test", "sitl/calib_rtf_probe.py")


# --- scripts/external_validation.py ------------------------------------------------------------

@pytest.mark.parametrize("fixture_name", ["hostile_model", "unlisted_model"])
def test_external_validation_sim_loader_refuses_unverified_model(ev, monkeypatch, request, fixture_name):
    model, marker = request.getfixturevalue(fixture_name)
    monkeypatch.setattr(ev, "MODEL", str(model))
    with pytest.raises(RuntimeError, match=r"mismatch|no entry"):
        ev._sim_one((9001, "survey_box", 12.0, 60.0, 1.0))
    assert not marker.exists(), "the pickle payload ran: the model was deserialised before verification"


def test_external_validation_px4_loader_refuses_mismatched_model(ev, monkeypatch, hostile_model):
    model, marker = hostile_model
    monkeypatch.setattr(ev, "MODEL", str(model))
    with pytest.raises(RuntimeError, match="mismatch"):
        ev._px4_one("flight.ulg")
    assert not marker.exists()


def test_external_validation_missing_model_stays_ml_off(ev, monkeypatch, tmp_path):
    monkeypatch.setattr(ev, "MODEL", str(tmp_path / "models" / "isoforest.joblib"))
    assert ev._load_bundle() is None  # unchanged behaviour: an absent model is an explicit ML-off run


def test_external_validation_loads_a_verified_model(ev, monkeypatch, tmp_path):
    import joblib

    model = tmp_path / "isoforest.joblib"
    joblib.dump({"score_thr": 1.0}, model)
    (tmp_path / "MODELS.sha256").write_text(f"{hashlib.sha256(model.read_bytes()).hexdigest()}  {model.name}\n",
                                            encoding="utf-8")
    monkeypatch.setattr(ev, "MODEL", str(model))
    assert ev._load_bundle() == {"score_thr": 1.0}


# --- scripts/sitl/calib_rtf_probe.py -----------------------------------------------------------

@pytest.mark.parametrize("fixture_name", ["hostile_model", "unlisted_model"])
def test_calib_rtf_probe_refuses_unverified_model(probe, monkeypatch, request, fixture_name):
    model, marker = request.getfixturevalue(fixture_name)
    monkeypatch.setattr(probe.cc, "PX4_MODEL", str(model))
    with pytest.raises(RuntimeError, match=r"mismatch|no entry"):
        probe.main()
    assert not marker.exists(), "the pickle payload ran: the model was deserialised before verification"


def test_calib_rtf_probe_missing_model_fails_closed(probe, monkeypatch, tmp_path):
    monkeypatch.setattr(probe.cc, "PX4_MODEL", str(tmp_path / "nope.joblib"))
    with pytest.raises(RuntimeError, match="not found"):
        probe.main()
