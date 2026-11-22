"""scripts/sitl/calib_derive.py regenerates configs/px4_sitl/detector.yaml exactly.

The profile header says "GENERATED - do not hand-edit". These tests hold the generator to that: rendering the
committed derivation (``artifacts/sitl/calibration/derivation.json``) must reproduce the committed YAML
byte-for-byte, including the explicit non-derived settings (``xmsg_checks``, ``heading_yaw_tolerance_deg``,
``gnss_never_acquired_policy``, ``fusion.ml_require_corroboration``). Rendering needs no tlogs (they are not
committed); only the derivation step does, and that is exercised by re-running the script on the raw flights.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "sitl"))

import calib_derive as cd  # noqa: E402

PROFILE = ROOT / "configs" / "px4_sitl" / "detector.yaml"
DERIVATION = ROOT / "artifacts" / "sitl" / "calibration" / "derivation.json"


def _rendered() -> str:
    return cd.render_yaml(json.loads(DERIVATION.read_text(encoding="utf-8")))


def test_regeneration_reproduces_committed_profile_byte_for_byte():
    # Tolerate CRLF only from a Windows autocrlf checkout; the generator itself always writes LF.
    committed = PROFILE.read_bytes().replace(b"\r\n", b"\n").decode("utf-8")
    assert _rendered() == committed


def test_regeneration_reproduces_committed_profile_key_for_key():
    assert yaml.safe_load(_rendered()) == yaml.safe_load(PROFILE.read_text(encoding="utf-8"))


def test_non_derived_settings_are_emitted_and_documented():
    doc = yaml.safe_load(_rendered())
    assert doc["physics"]["xmsg_checks"] is True
    assert doc["physics"]["heading_yaw_tolerance_deg"] == 20.0
    assert doc["protocol"]["gnss_never_acquired_policy"] == "coverage"
    assert doc["fusion"]["ml_require_corroboration"] is True
    text = _rendered()
    for _comment, key, _val in (s for sect in cd.FIXED_SETTINGS.values() for s in sect):
        line = next(ln for ln in text.splitlines() if ln.strip().startswith(f"{key}:"))
        prev = text.splitlines()[text.splitlines().index(line) - 1]
        assert prev.strip().startswith("#"), f"{key} must carry an explanatory comment"


def test_fixed_settings_do_not_collide_with_derived_keys():
    derived = json.loads(DERIVATION.read_text(encoding="utf-8"))["profile_overrides"]
    for section, items in cd.FIXED_SETTINGS.items():
        for _comment, key, _val in items:
            assert key not in derived.get(section, {}), f"{section}.{key} is both derived and fixed"
