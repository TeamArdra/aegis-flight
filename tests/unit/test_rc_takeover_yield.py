"""Unit regression tests for pilot RC takeover yielding (anti-tug-of-war)."""

from __future__ import annotations

from aegisflight.core.types import AttackType, FlightState, Severity, ThreatAssessment
from aegisflight.features.extractor import FeatureFrame
from aegisflight.mitigation.controller import MitigationController
from aegisflight.mitigation.types import DefenseMode, MitigationState


def _gps_threat(t: float) -> ThreatAssessment:
    return ThreatAssessment(
        t=t,
        wall_time=t,
        threat=True,
        threat_score=0.95,
        severity=Severity.HIGH,
        confidence=0.95,
        attack_type=AttackType.GPS_SPOOFING,
        detector_scores={"physics": 0.9},
        evidence=["gps_spoofing"],
    )


def _snap(t: float, flight_mode: str = "AUTO") -> FlightState:
    return FlightState(
        t=t, lat=12.9, lon=77.6, alt_msl=920.0, rel_alt=20.0,
        vx=5.0, vy=0.0, vz=0.0, groundspeed=5.0, vertical_speed=0.0,
        ax=0.0, ay=0.0, az=9.81, roll=0.0, pitch=0.0, yaw=0.0,
        rollspeed=0.0, pitchspeed=0.0, yawspeed=0.0, heading=0.0,
        throttle=50.0, battery_voltage=16.0, battery_remaining=80.0,
        satellites=12, gps_fix_type=3, hdop=0.8, baro_alt=20.0,
        armed=True, flight_mode=flight_mode, mission_seq=0,
    )


def test_pilot_rc_mode_switch_yields_with_zero_counter_commands() -> None:
    ctrl = MitigationController(mode=DefenseMode.ACTIVE_IPS)
    # Bind ArduCopter dialect explicitly (fail-closed until primary vehicle HEARTBEAT on main)
    ctrl.actuator.set_vehicle_dialect(3, 2)
    ctrl.set_capabilities(ekf_secondary=False)

    # 1. Establish initial armed flight mode (AUTO)
    ctrl.step(
        FeatureFrame(t=1.0, snapshot=_snap(1.0, "AUTO")),
        ThreatAssessment(
            t=1.0,
            wall_time=1.0,
            threat=False,
            threat_score=0.0,
            severity=Severity.NORMAL,
            attack_type=None,
            confidence=0.0,
        ),
    )

    # 2. Confirm GPS spoofing (2 ticks) then escalate after gps_escalate_s (3.0 s) to ALT_HOLD
    ctrl.step(FeatureFrame(t=2.0, snapshot=_snap(2.0, "AUTO"), pos_residual_m=35.0), _gps_threat(2.0))
    ctrl.step(FeatureFrame(t=3.0, snapshot=_snap(3.0, "AUTO"), pos_residual_m=35.0), _gps_threat(3.0))
    act_esc = ctrl.step(FeatureFrame(t=6.5, snapshot=_snap(6.5, "AUTO"), pos_residual_m=35.0), _gps_threat(6.5))
    assert ctrl._gps_alt_hold_sent is True
    assert len(act_esc.counter_frames) >= 1

    # 3. Pilot switches RC to STABILIZE -> must yield immediately with 0 counter-commands
    act2 = ctrl.step(FeatureFrame(t=7.5, snapshot=_snap(7.5, "STABILIZE"), pos_residual_m=35.0), _gps_threat(7.5))
    assert ctrl.state == MitigationState.GCS_TAKEOVER
    assert len(act2.counter_frames) == 0

    # 4. Subsequent threat ticks must also emit 0 conflicting counter-commands
    act3 = ctrl.step(FeatureFrame(t=8.5, snapshot=_snap(8.5, "STABILIZE"), pos_residual_m=35.0), _gps_threat(8.5))
    assert len(act3.counter_frames) == 0


def test_manual_ack_takeover_yields_with_zero_counter_commands() -> None:
    ctrl = MitigationController(mode=DefenseMode.ACTIVE_IPS)
    ctrl.actuator.set_vehicle_dialect(3, 2)
    ctrl.set_capabilities(ekf_secondary=False)

    ctrl.step(FeatureFrame(t=1.0, snapshot=_snap(1.0, "AUTO"), pos_residual_m=35.0), _gps_threat(1.0))

    act = ctrl.manual_override("ack_takeover")
    assert ctrl.state == MitigationState.NOMINAL
    assert len(act.counter_frames) == 0
