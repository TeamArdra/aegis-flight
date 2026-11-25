"""Unit regression tests for PX4 GPS-spoof ladder ALTCTL->AUTO_LAND fallback & validated COMMAND_ACK wiring."""

from __future__ import annotations

from unittest.mock import patch

from pymavlink.dialects.v20 import common as mav2

from aegisflight.core.types import AttackType, FlightState, Severity, ThreatAssessment
from aegisflight.features.extractor import FeatureFrame
from aegisflight.hal.inline_ips import InlineIpsBridge
from aegisflight.mavlink.signing import sign_mavlink2_frame
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


class _DummyLink:
    def send(self, data: bytes) -> bool:
        return True

    def recv(self) -> bytes:
        return b""

    def fileno(self) -> int:
        return -1

    def close(self) -> None:
        pass


def test_px4_primary_altctl_and_armed_fallback_on_permanent_rejection() -> None:
    with patch.object(MavlinkActuator, "ALLOW_NON_COPTER_DIALECTS", True):
        ctrl = _px4_controller()
        ctrl.set_capabilities(ekf_secondary=False)
        ctrl.step(FeatureFrame(t=1.0, snapshot=_snap(1.0), pos_residual_m=35.0), _gps_threat(1.0))
        ctrl.step(FeatureFrame(t=2.0, snapshot=_snap(2.0), pos_residual_m=35.0), _gps_threat(2.0))
        act = ctrl.step(FeatureFrame(t=4.0, snapshot=_snap(4.0), pos_residual_m=35.0), _gps_threat(4.0))
        assert ctrl._gps_alt_hold_sent is True
        assert ctrl._ips_requested_mode is not None and ctrl._ips_requested_mode[0] == "ALTCTL"
        assert len(act.counter_frames) >= 1

        # PX4 rejects DO_SET_MODE(ALTCTL) with MAV_RESULT_FAILED (4) within freshness window
        ctrl.record_command_ack(176, 4, t=4.5)
        act_land = ctrl.step(FeatureFrame(t=5.5, snapshot=_snap(5.5, armed=True), pos_residual_m=35.0), _gps_threat(5.5))
        assert ctrl._gps_land_sent is True
        assert ctrl._ips_requested_mode[0] in ("AUTO_LAND", "AUTO.LAND", "LAND")
        assert len(act_land.counter_frames) >= 1


def test_px4_altctl_rejected_sends_zero_frames_when_disarmed() -> None:
    """Safety regression (#140/#139): rejected ALTCTL must never dispatch LAND to a disarmed vehicle."""
    with patch.object(MavlinkActuator, "ALLOW_NON_COPTER_DIALECTS", True):
        ctrl = _px4_controller()
        ctrl.set_capabilities(ekf_secondary=False)
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


def test_command_ack_rejects_transient_result1_stale_and_wrong_target() -> None:
    """Review R2: result=1 (TEMPORARILY_REJECTED), stale ACK, and other-GCS target_sysid must not arm LAND."""
    ctrl = _px4_controller()
    ctrl._ips_requested_mode = ("ALTCTL", 10.0)

    # Result 1 (TEMPORARILY_REJECTED)
    ctrl.record_command_ack(176, 1, t=10.5)
    assert ctrl._gps_altctl_rejected is False

    # Stale ACK (> 5.0 s after request) and predating ACK (< request time)
    ctrl.record_command_ack(176, 4, t=9.0)
    ctrl.record_command_ack(176, 4, t=16.0)
    assert ctrl._gps_altctl_rejected is False

    # ACK addressed to a different GCS (not the IPS actuator)
    ctrl.record_command_ack(176, 4, t=10.5, target_sysid=255)
    assert ctrl._gps_altctl_rejected is False


def test_inline_ips_bridge_validates_downlink_command_ack_sender_and_signature() -> None:
    """Review R2: forged sysid and unsigned/bad-sig ACKs on a keyed bridge must not arm LAND."""
    key = b"\x22" * 32
    wrong_key = b"\x99" * 32
    bridge = InlineIpsBridge(fc=_DummyLink(), gcs=_DummyLink(), mode=DefenseMode.ACTIVE_IPS, secret_key=key)  # type: ignore[arg-type]
    bridge.controller._ips_requested_mode = ("ALTCTL", 1.0)

    # 1. Forged sysid (99 not in vehicle_sysids=(1,))
    mav_rogue = mav2.MAVLink(None, srcSystem=99, srcComponent=1)
    raw_rogue = sign_mavlink2_frame(mav_rogue.command_ack_encode(176, 4).pack(mav_rogue), key, link_id=0, timestamp_10us=100)
    bridge._handle(2_000_000_000, raw_rogue, "down")
    assert bridge.controller._gps_altctl_rejected is False

    # 2. Unsigned ACK from vehicle sysid 1 on keyed bridge
    mav_veh = mav2.MAVLink(None, srcSystem=1, srcComponent=1)
    raw_unsigned = mav_veh.command_ack_encode(176, 4).pack(mav_veh)
    bridge._handle(2_000_000_000, raw_unsigned, "down")
    assert bridge.controller._gps_altctl_rejected is False

    # 3. Wrong-key signed ACK from vehicle sysid 1 on keyed bridge
    raw_badsig = sign_mavlink2_frame(raw_unsigned, wrong_key, link_id=0, timestamp_10us=200)
    bridge._handle(2_000_000_000, raw_badsig, "down")
    assert bridge.controller._gps_altctl_rejected is False

    # 4. Validly signed ACK from vehicle sysid 1 within freshness window -> arms fallback
    raw_good = sign_mavlink2_frame(raw_unsigned, key, link_id=0, timestamp_10us=300)
    bridge._handle(2_000_000_000, raw_good, "down")
    assert bridge.controller._gps_altctl_rejected is True
