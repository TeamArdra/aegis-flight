"""Unit regression tests for PX4 GPS-spoof ladder ALTCTL->AUTO_LAND fallback & COMMAND_ACK wiring."""

from __future__ import annotations

from unittest.mock import patch

from aegisflight.core.types import AttackType, FlightState, Severity, ThreatAssessment
from aegisflight.features.extractor import FeatureFrame
from aegisflight.hal.inline_ips import InlineIpsBridge
from aegisflight.mitigation.actuator import MavlinkActuator
from aegisflight.mitigation.controller import MitigationController
from aegisflight.mitigation.types import DefenseMode


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


def _snap(t: float, *, flight_mode: str = "POSCTL", armed: bool | None = True) -> FlightState:
    return FlightState(
        t=t, lat=12.9, lon=77.6, alt_msl=920.0, rel_alt=20.0,
        vx=5.0, vy=0.0, vz=0.0, groundspeed=5.0, vertical_speed=0.0,
        ax=0.0, ay=0.0, az=9.81, roll=0.0, pitch=0.0, yaw=0.0,
        rollspeed=0.0, pitchspeed=0.0, yawspeed=0.0, heading=0.0,
        throttle=50.0, battery_voltage=16.0, battery_remaining=80.0,
        satellites=12, gps_fix_type=3, hdop=0.8, baro_alt=20.0,
        armed=armed, flight_mode=flight_mode, mission_seq=0,
    )


def _px4_controller() -> MitigationController:
    ctrl = MitigationController(mode=DefenseMode.ACTIVE_IPS, gps_escalate_s=1.5, gps_switch_check_s=2.5)
    ctrl.actuator.set_vehicle_dialect(12, 2)  # PX4 quadrotor
    return ctrl


def test_px4_primary_altctl_when_rc_present() -> None:
    with patch.object(MavlinkActuator, "ALLOW_NON_COPTER_DIALECTS", True):
        ctrl = _px4_controller()
        ctrl.set_capabilities(ekf_secondary=False, rc_present=True)
        ctrl.step(FeatureFrame(t=1.0, snapshot=_snap(1.0), pos_residual_m=35.0), _gps_threat(1.0))
        ctrl.step(FeatureFrame(t=2.0, snapshot=_snap(2.0), pos_residual_m=35.0), _gps_threat(2.0))
        act = ctrl.step(FeatureFrame(t=4.0, snapshot=_snap(4.0), pos_residual_m=35.0), _gps_threat(4.0))
        assert ctrl._gps_alt_hold_sent is True
        assert ctrl._ips_requested_mode is not None
        assert ctrl._ips_requested_mode[0] == "ALTCTL"
        assert len(act.counter_frames) >= 1


def test_px4_altctl_rejected_falls_back_to_auto_land_when_armed() -> None:
    with patch.object(MavlinkActuator, "ALLOW_NON_COPTER_DIALECTS", True):
        ctrl = _px4_controller()
        ctrl.set_capabilities(ekf_secondary=False, rc_present=True)
        ctrl.step(FeatureFrame(t=1.0, snapshot=_snap(1.0), pos_residual_m=35.0), _gps_threat(1.0))
        ctrl.step(FeatureFrame(t=2.0, snapshot=_snap(2.0), pos_residual_m=35.0), _gps_threat(2.0))
        ctrl.step(FeatureFrame(t=4.0, snapshot=_snap(4.0), pos_residual_m=35.0), _gps_threat(4.0))
        assert ctrl._ips_requested_mode is not None and ctrl._ips_requested_mode[0] == "ALTCTL"

        # PX4 rejects DO_SET_MODE(ALTCTL) with MAV_RESULT_FAILED (4)
        ctrl.record_command_ack(176, 4, t=4.5)
        act_land = ctrl.step(FeatureFrame(t=5.5, snapshot=_snap(5.5, armed=True), pos_residual_m=35.0), _gps_threat(5.5))
        assert ctrl._gps_land_sent is True
        assert ctrl._ips_requested_mode[0] in ("AUTO_LAND", "AUTO.LAND", "LAND")
        assert len(act_land.counter_frames) >= 1


def test_px4_altctl_rejected_sends_zero_frames_when_disarmed() -> None:
    """Safety regression (#140/#139): rejected ALTCTL must never dispatch LAND to a disarmed vehicle."""
    with patch.object(MavlinkActuator, "ALLOW_NON_COPTER_DIALECTS", True):
        ctrl = _px4_controller()
        ctrl.set_capabilities(ekf_secondary=False, rc_present=True)
        ctrl.step(FeatureFrame(t=1.0, snapshot=_snap(1.0), pos_residual_m=35.0), _gps_threat(1.0))
        ctrl.step(FeatureFrame(t=2.0, snapshot=_snap(2.0), pos_residual_m=35.0), _gps_threat(2.0))
        ctrl.step(FeatureFrame(t=4.0, snapshot=_snap(4.0), pos_residual_m=35.0), _gps_threat(4.0))

        ctrl.record_command_ack(176, 4, t=4.5)
        act_disarmed = ctrl.step(
            FeatureFrame(t=5.5, snapshot=_snap(5.5, armed=False), pos_residual_m=35.0),
            _gps_threat(5.5),
        )
        assert ctrl._gps_land_sent is False
        assert len(act_disarmed.counter_frames) == 0


def test_px4_no_rc_uses_controlled_descent_directly() -> None:
    with patch.object(MavlinkActuator, "ALLOW_NON_COPTER_DIALECTS", True):
        ctrl = _px4_controller()
        ctrl.set_capabilities(ekf_secondary=False, rc_present=False)
        ctrl.step(FeatureFrame(t=1.0, snapshot=_snap(1.0), pos_residual_m=35.0), _gps_threat(1.0))
        ctrl.step(FeatureFrame(t=2.0, snapshot=_snap(2.0), pos_residual_m=35.0), _gps_threat(2.0))
        act = ctrl.step(FeatureFrame(t=4.0, snapshot=_snap(4.0), pos_residual_m=35.0), _gps_threat(4.0))
        assert ctrl._gps_land_sent is True
        assert ctrl._ips_requested_mode is not None
        assert ctrl._ips_requested_mode[0] in ("AUTO_LAND", "AUTO.LAND", "LAND")
        assert len(act.counter_frames) >= 1


def test_inline_ips_bridge_forwards_downlink_command_ack() -> None:
    """Verify InlineIpsBridge forwards downlink COMMAND_ACK (msgid 77) to controller.record_command_ack."""

    class _DummyLink:
        def send(self, data: bytes) -> bool:
            return True

        def recv(self) -> bytes:
            return b""

        def fileno(self) -> int:
            return -1

        def close(self) -> None:
            pass

    from pymavlink.dialects.v20 import common as mav2

    bridge = InlineIpsBridge(fc=_DummyLink(), gcs=_DummyLink(), mode=DefenseMode.ACTIVE_IPS)  # type: ignore[arg-type]
    bridge.controller._ips_requested_mode = ("ALTCTL", 1.0)
    mav = mav2.MAVLink(None, srcSystem=1, srcComponent=1)
    raw = mav.command_ack_encode(176, 4).pack(mav)
    bridge._handle(2_000_000_000, raw, "down")
    assert bridge.controller._gps_altctl_rejected is True
