"""Unit tests for universal_flight pos_residual_min_streak persistence guard."""

from __future__ import annotations

from dataclasses import replace

from aegisflight.core.types import FlightState
from aegisflight.detectors.physics import PhysicsDetector
from aegisflight.features.extractor import FeatureFrame


def _make_frame(t: float, pos_residual_m: float) -> FeatureFrame:
    snap = FlightState(
        t=t,
        lat=12.97,
        lon=77.59,
        alt_msl=10.0,
        rel_alt=10.0,
        vx=0.0,
        vy=0.0,
        vz=0.0,
        groundspeed=0.0,
        vertical_speed=0.0,
        ax=0.0,
        ay=0.0,
        az=0.0,
        roll=0.0,
        pitch=0.0,
        yaw=0.0,
        rollspeed=0.0,
        pitchspeed=0.0,
        yawspeed=0.0,
        heading=0.0,
        throttle=0.5,
        battery_voltage=16.0,
        battery_remaining=80.0,
        satellites=10,
        gps_fix_type=3,
        hdop=1.0,
        baro_alt=10.0,
        flight_mode="GUIDED",
        armed=True,
        mission_seq=0,
    )
    return FeatureFrame(t=t, snapshot=snap, pos_residual_m=pos_residual_m)


def test_universal_pos_residual_persistence_suppresses_brief_spike() -> None:
    """Brief 2-frame pos_residual_m spike is suppressed when pos_residual_min_streak=3."""
    det = PhysicsDetector({"pos_residual_min_streak": 3})
    det.process(_make_frame(0.9, 0.5))  # warmup sample for pos_ready

    r1 = det.process(_make_frame(1.0, 12.4))
    r2 = det.process(_make_frame(1.1, 25.2))
    assert r1.score == 0.0
    assert r2.score == 0.0

    # Normal frame resets streak
    r_ok = det.process(_make_frame(1.2, 0.5))
    assert r_ok.score == 0.0

    # Sustained 3-frame excursion alerts on the 3rd frame
    assert det.process(_make_frame(1.3, 15.0)).score == 0.0
    assert det.process(_make_frame(1.4, 18.0)).score == 0.0
    r3 = det.process(_make_frame(1.5, 20.0))
    assert r3.score > 0.0
    assert any("position residual" in e for e in r3.evidence)


def test_stage1_default_pos_residual_alerts_immediately() -> None:
    """Default pos_residual_min_streak=1 preserves Stage-1 immediate alerting."""
    det = PhysicsDetector({})
    det.process(_make_frame(0.9, 0.5))  # warmup sample for pos_ready
    r = det.process(_make_frame(1.0, 15.0))
    assert r.score > 0.0
    assert any("position residual" in e for e in r.evidence)


def test_streak_restarts_after_a_frame_where_the_residual_rule_did_not_run() -> None:
    """Three over-threshold frames must be consecutive evaluations, not three spread over a no-fix gap."""
    det = PhysicsDetector({"pos_residual_min_streak": 3})
    det.process(_make_frame(0.9, 0.5))
    assert det.process(_make_frame(1.0, 14.0)).score == 0.0  # streak 1
    assert det.process(_make_frame(1.1, 14.0)).score == 0.0  # streak 2
    no_fix = _make_frame(1.2, 14.0)  # fix lost: the rule is not evaluated for this frame
    no_fix = replace(no_fix, snapshot=replace(no_fix.snapshot, gps_fix_type=1))
    assert det.process(no_fix).score == 0.0
    # the next valid frame is a new first excursion, not the third of a run
    assert det.process(_make_frame(1.3, 14.0)).score == 0.0
    assert det.process(_make_frame(1.4, 14.0)).score == 0.0
    assert det.process(_make_frame(1.5, 14.0)).score > 0.0
