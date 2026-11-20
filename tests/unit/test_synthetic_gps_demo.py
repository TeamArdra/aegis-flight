"""The SIMULATED GPS demo fixture (scripts/demo/make_synthetic_gps_tlog.py) and the indoor bench profile.

Environment: SIM (a synthetic fixture through the real pipeline, ML off). These tests pin that the demo is repeatable
and that its documented phase behaviour stays true. They are not spoofing-detection evidence: the fixture is the
team's own and separable by construction. Nothing here opens a port or touches hardware.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

from aegisflight.config import load_config

_REPO = Path(__file__).resolve().parents[2]
_SCRIPT = _REPO / "scripts" / "demo" / "make_synthetic_gps_tlog.py"
_spec = importlib.util.spec_from_file_location("make_synthetic_gps_tlog", _SCRIPT)
assert _spec is not None and _spec.loader is not None
demo = importlib.util.module_from_spec(_spec)
sys.modules["make_synthetic_gps_tlog"] = demo
_spec.loader.exec_module(demo)
_PROFILE = _REPO / "demo" / "indoor_bench_profile"


@pytest.fixture(scope="module")
def result() -> dict:
    return demo.evaluate(None)


def test_the_fixture_is_byte_identical_on_every_build():
    assert demo.build_tlog_bytes() == demo.build_tlog_bytes()


def test_the_file_name_and_sidecar_label_it_as_simulated(tmp_path):
    path = demo.generate(tmp_path)
    assert path.name.startswith("SIMULATED_GPS")
    assert "not_measured" in path.name
    truth = path.with_suffix(".groundtruth.json").read_text(encoding="utf-8")
    assert "SIMULATED GPS" in truth and "never measured" in truth


def test_a_committed_fixture_matches_the_generator_if_present():
    committed = _REPO / "demo" / "fixtures" / demo.FIXTURE_NAME
    if not committed.exists():
        pytest.skip("fixture not generated in this tree")
    assert committed.read_bytes() == demo.build_tlog_bytes()


def test_the_phases_cover_the_fixture_without_gaps():
    assert demo.PHASES[0].start_s == 0.0
    for a, b in zip(demo.PHASES, demo.PHASES[1:], strict=False):
        assert a.end_s == b.start_s
    assert demo.phase_at(demo.DURATION_S - 0.1) is demo.PHASES[-1]


def test_every_frame_decodes_with_a_valid_crc():
    from pymavlink.dialects.v20 import ardupilotmega as apm

    parser = apm.MAVLink(None)
    frames = demo.read_frames(demo.build_tlog_bytes())
    for _ts, frame in frames:
        assert parser.decode(bytearray(frame)) is not None


def test_nominal_and_recovery_stay_clear_and_alert_free(result):
    assert result["per_phase"]["NOMINAL"]["threat"] == 0
    assert result["per_phase"]["NOMINAL"]["alerts"] == 0
    assert result["per_phase"]["RECOVERY"]["alerts"] == 0


def test_slow_drift_is_the_documented_miss_with_ml_off(result):
    # KNOWN LIMITATION, shown on purpose in the demo: below the ~4 m/s floor nothing fires
    assert result["per_phase"]["SLOW_DRIFT"]["threat"] == 0
    assert result["per_phase"]["SLOW_DRIFT"]["alerts"] == 0


def test_fast_drift_and_the_jump_alert_gps_spoofing_only(result):
    for phase in ("FAST_DRIFT", "SUDDEN_JUMP"):
        assert set(result["per_phase"][phase]["alert_types"]) == {"GPS_SPOOFING"}
        assert result["per_phase"][phase]["alerts"] >= 1


def test_gnss_loss_alerts_as_a_lost_fix_and_never_claims_a_spoof_for_the_loss(result):
    rows = [r for r in result["alerts"] if r["phase"] == "GNSS_LOSS"]
    dos = [r for r in rows if r["type"] == "DOS"]
    assert dos
    assert all(any("GNSS fix lost" in e for e in r["evidence"]) for r in dos)
    # the only spoofing alert in this phase is the return jump at its very start
    assert all(r["t"] < demo.phase_at(85.0).start_s + 2.0 for r in rows if r["type"] == "GPS_SPOOFING")


def test_the_indoor_profile_differs_from_the_default_in_one_key_only():
    default = yaml.safe_load((_REPO / "configs" / "detector.yaml").read_text(encoding="utf-8"))
    indoor = yaml.safe_load((_PROFILE / "detector.yaml").read_text(encoding="utf-8"))
    assert indoor["protocol"]["gnss_loss_ticks"] > default["protocol"]["gnss_loss_ticks"]
    indoor["protocol"]["gnss_loss_ticks"] = default["protocol"]["gnss_loss_ticks"]
    assert indoor == default  # min_gnss_* unchanged: the dashboard's "usable fix" line stays truthful


def test_the_indoor_profile_loads_and_leaves_the_other_gps_rules_on():
    det = load_config(_PROFILE).detector
    assert det["protocol"]["gps_dropout_s"] == load_config().detector["protocol"]["gps_dropout_s"]
    assert det["physics"]["gps_pos_residual_m"] == load_config().detector["physics"]["gps_pos_residual_m"]
    result = demo.evaluate(None, config_dir=str(_PROFILE))
    assert result["per_phase"]["FAST_DRIFT"]["alert_types"].get("GPS_SPOOFING", 0) >= 1
    assert not any("GNSS fix" in e for r in result["alerts"] for e in r["evidence"])
