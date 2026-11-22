"""Regression tests for PX4 GPS-spoof ladder fallback (ALTCTL -> AUTO_LAND) and latency."""

from __future__ import annotations

import pytest

from aegisflight.core.enums import AttackType, Severity
from aegisflight.core.types import TelemetrySnapshot, ThreatAssessment
from aegisflight.features.extractor import FeatureFrame
from aegisflight.mitigation.controller import DefenseMode, MitigationController


def _make_px4_frame(t: float, flight_mode: str = "POSCTL", pos_residual_m: float = 25.0) -> FeatureFrame:
    snap = TelemetrySnapshot(
        t=t,
        lat=12.9716,
        lon=77.5946,
        alt_msl=50.0,
        vx=0.0,
        vy=0.0,
        vz=0.0,
        groundspeed=0.5,
        flight_mode=flight_mode,
        armed=True,
    )
    return FeatureFrame(
        t=t,
        snapshot=snap,
        pos_residual_m=pos_residual_m,
        sources=((1, 1),),
    )


def _make_gps_spoof_assessment(t: float) -> ThreatAssessment:
    return ThreatAssessment(
        t=t,
        wall_time=t,
        threat=True,
        threat_score=0.92,
        confidence=0.95,
        severity=Severity.CRITICAL,
        attack_type=AttackType.GPS_SPOOFING,
    )


def _make_px4_controller(*, rc_present: bool = True, gps_escalate_s: float = 1.5) -> MitigationController:
    ctrl = MitigationController(
        mode=DefenseMode.ACTIVE_IPS,
        gps_confirm_ticks=2,
        gps_escalate_s=gps_escalate_s,
    )
    ctrl.actuator.ALLOW_NON_COPTER_DIALECTS = True
    ctrl.actuator.set_vehicle_dialect(autopilot_id=12, mav_type=2)  # PX4 Quadrotor
    ctrl.set_capabilities(ekf_secondary=False, rc_present=rc_present)
    return ctrl


def test_px4_primary_safe_mode_is_altctl_when_rc_present() -> None:
    ctrl = _make_px4_controller(rc_present=True)
    # Tick 1 & 2: confirm GPS fault
    ctrl.step(_make_px4_frame(1.0), _make_gps_spoof_assessment(1.0))
    ctrl.step(_make_px4_frame(1.2), _make_gps_spoof_assessment(1.2))
    # Escalate after gps_escalate_s (1.5s)
    act = ctrl.step(_make_px4_frame(3.0), _make_gps_spoof_assessment(3.0))
    assert act.last_command_sent == "SET_MODE_ALTCTL"
    assert len(act.counter_frames) == 1


@pytest.mark.parametrize("mav_result", [1, 2])  # TEMPORARILY_REJECTED, DENIED
def test_px4_altctl_rejected_falls_back_to_auto_land_never_rtl(mav_result: int) -> None:
    ctrl = _make_px4_controller(rc_present=True)
    ctrl.step(_make_px4_frame(1.0), _make_gps_spoof_assessment(1.0))
    ctrl.step(_make_px4_frame(1.2), _make_gps_spoof_assessment(1.2))
    act1 = ctrl.step(_make_px4_frame(3.0), _make_gps_spoof_assessment(3.0))
    assert act1.last_command_sent == "SET_MODE_ALTCTL"

    # PX4 rejects ALTCTL
    ctrl.record_command_ack(command=176, result=mav_result, t=3.2)
    act2 = ctrl.step(_make_px4_frame(4.5), _make_gps_spoof_assessment(4.5))
    assert act2.last_command_sent == "SET_MODE_AUTO_LAND"
    assert len(act2.counter_frames) == 1
    assert "RTL" not in (act2.last_command_sent or "")
    assert "TERMINATION" not in (act2.last_command_sent or "")


def test_px4_no_rc_falls_back_directly_to_auto_land() -> None:
    ctrl = _make_px4_controller(rc_present=False)
    ctrl.step(_make_px4_frame(1.0), _make_gps_spoof_assessment(1.0))
    ctrl.step(_make_px4_frame(1.2), _make_gps_spoof_assessment(1.2))
    act = ctrl.step(_make_px4_frame(3.0), _make_gps_spoof_assessment(3.0))
    assert act.last_command_sent == "SET_MODE_AUTO_LAND"
    assert len(act.counter_frames) == 1
    assert "RTL" not in (act.last_command_sent or "")


def test_gps_ladder_confirmation_window_tightened() -> None:
    ctrl = MitigationController(mode=DefenseMode.ACTIVE_IPS)
    assert ctrl.gps_escalate_s <= 2.0
    assert ctrl.gps_switch_check_s <= 3.0
