"""Non-ArduCopter DO_SET_MODE actuation is gated OFF (Option A). SYNTHETIC frames; nothing opens a port.

A Plane / Rover / PX4 / VTOL / unknown heartbeat must produce no DO_SET_MODE bytes, while the ArduCopter behaviour is
unchanged. The mapping tables stay in ``mavlink/codec.py`` so a later, maintainer-approved Option B remains possible.
"""

from __future__ import annotations

import struct

import pytest

from aegisflight.core.enums import AttackType, IntegrityStatus, Severity
from aegisflight.core.types import TelemetrySnapshot, ThreatAssessment
from aegisflight.features.extractor import FeatureFrame
from aegisflight.mavlink.codec import PLANE_MODES, PX4_MAIN_MODES, ROVER_MODES, safe_gps_denied_mode
from aegisflight.mitigation.actuator import MavlinkActuator
from aegisflight.mitigation.controller import MitigationController
from aegisflight.mitigation.types import AttackSubMode, DefenseMode

MAV_CMD_DO_SET_MODE = 176


def _command_long(frame: bytes) -> tuple[int, tuple[float, ...]]:
    payload = frame[10:10 + frame[1]] + bytes(33)
    return struct.unpack_from("<H", payload, 28)[0], struct.unpack_from("<7f", payload, 0)


def _is_set_mode(frame: bytes) -> bool:
    return len(frame) > 10 and _command_long(frame)[0] == MAV_CMD_DO_SET_MODE


# (autopilot, mav_type, label) -- everything except a positively identified ArduCopter
NON_COPTER = [
    (3, 1, "plane"),
    (3, 10, "rover"),
    (3, 11, "boat"),
    (3, 20, "vtol_quad"),
    (3, 21, "vtol_tilt"),
    (3, 12, "ardusub"),
    (3, 5, "antenna_tracker"),
    (3, None, "ardupilot_unknown_type"),
    (12, 2, "px4_multicopter"),
    (12, 1, "px4_fixed_wing"),
    (12, 20, "px4_vtol"),
    (0, 2, "generic_autopilot"),
    (None, 2, "unknown_autopilot"),
    (None, None, "unknown_everything"),
]


@pytest.mark.parametrize(("ap", "mt", "label"), NON_COPTER, ids=[x[2] for x in NON_COPTER])
@pytest.mark.parametrize("mode", ["ALT_HOLD", "FBWA", "QHOVER", "HOLD", "ALTCTL", "AUTO_LOITER", "STABILIZE"])
def test_non_copter_dialect_encodes_no_set_mode(ap, mt, label, mode):
    act = MavlinkActuator()
    act.set_vehicle_dialect(ap, mt)
    assert act.knows_mode(mode) is False
    with pytest.raises(ValueError):
        act.encode_set_mode(mode)
    assert act.safe_hold_mode_name() is None


@pytest.mark.parametrize(("ap", "mt", "label"), NON_COPTER, ids=[x[2] for x in NON_COPTER])
def test_refusal_is_audit_logged_once(ap, mt, label):
    log: list[tuple[str, str, str]] = []
    act = MavlinkActuator(on_action=lambda a, t, d: log.append((a, t, d)))
    act.set_vehicle_dialect(ap, mt)
    for _ in range(5):
        act.knows_mode("ALT_HOLD")
        act.safe_hold_mode_name()
    refusals = [x for x in log if x[0] == "refuse_set_mode"]
    assert {x[1] for x in refusals} == {"ALT_HOLD", "safe_hold"}
    assert len(refusals) == 2  # deduplicated, not one entry per tick
    assert f"autopilot={ap}" in refusals[0][2]


@pytest.mark.parametrize("mt", [2, 3, 4, 13, 14, 15, 29])
def test_arducopter_unchanged(mt):
    act = MavlinkActuator()
    act.set_vehicle_dialect(3, mt)
    assert act.safe_hold_mode_name() == "ALT_HOLD"
    cmd, params = _command_long(act.encode_set_mode("ALT_HOLD"))
    assert cmd == MAV_CMD_DO_SET_MODE and params[:3] == (1.0, 2.0, 0.0)
    assert act.knows_mode("AUTO/LOITER") is False  # a PX4 name is still never guessed as a Copter mode


def test_default_actuator_is_the_arducopter_the_bridge_was_verified_on():
    act = MavlinkActuator()
    assert (act.autopilot_id, act.mav_type) == (3, 2)
    assert act.knows_mode("ALT_HOLD")


# ---- controller level: the actual actuation path (ACTIVE_IPS) ------------------------------------------------- #

def _frame(t, ap, mt, mode):
    snap = TelemetrySnapshot(t=t, lat=18.92, lon=72.83, alt_msl=25.0, rel_alt=25.0, vx=0.0, vy=5.0, vz=0.0,
                             groundspeed=5.0, roll=0.0, pitch=0.0, yaw=0.0, heading=90.0, flight_mode=mode,
                             armed=True, battery_remaining=90.0)
    return FeatureFrame(t=t, snapshot=snap, gps_seen=True, gps_raw_seen=True, heartbeat_seen=True,
                        msg_rate_hz=10.0, pos_residual_m=0.0, autopilot_id=ap, mav_type=mt)


def _asmt(t, attack):
    threat = attack != AttackType.BENIGN
    return ThreatAssessment(t=t, wall_time=t, threat=threat, threat_score=0.9 if threat else 0.0,
                            severity=Severity.CRITICAL if threat else Severity.NORMAL, attack_type=attack,
                            confidence=0.9 if threat else 0.0, evidence=[], detector_scores={},
                            contributing_detectors=[], integrity_status=IntegrityStatus.VALID,
                            latency_ms=1.0, is_alert=threat)


def _drive(ap, mt, mode, secs=30.0):
    c = MitigationController(mode=DefenseMode.ACTIVE_IPS)
    c.set_capabilities(ekf_secondary=None)
    c.classifier.classify = lambda f, s: AttackSubMode.GPS_GRADUAL_DRIFT
    frames: list[bytes] = []
    t = 100.0
    for _ in range(int(secs / 0.2)):
        frames += c.step(_frame(t, ap, mt, mode), _asmt(t, AttackType.GPS_SPOOFING)).counter_frames
        t = round(t + 0.2, 6)
    return c, frames


def test_positive_control_copter_gps_ladder_sends_alt_hold():
    _, frames = _drive(3, 2, "LOITER")
    assert [_command_long(f)[1][:3] for f in frames if _is_set_mode(f)][:1] == [(1.0, 2.0, 0.0)]


@pytest.mark.parametrize(("ap", "mt", "mode"), [
    (3, 1, "CRUISE"),      # Plane
    (3, 10, "AUTO"),       # Rover
    (3, 20, "QLOITER"),    # VTOL (ArduPilot QuadPlane)
    (12, 2, "POSCTL"),     # PX4 multicopter
    (12, 1, "AUTO_LOITER"),  # PX4 fixed wing
])
def test_non_copter_gps_ladder_emits_no_set_mode_bytes(ap, mt, mode):
    c, frames = _drive(ap, mt, mode)
    if ap is not None:  # a frame with no heartbeat info never re-binds the dialect
        assert (c.actuator.autopilot_id, c.actuator.mav_type) == (ap, mt)
    assert [f for f in frames if _is_set_mode(f)] == []


@pytest.mark.parametrize(("ap", "mt"), [(3, 1), (3, 10), (3, 20), (12, 2), (12, 1)])
def test_non_copter_manual_safe_hold_emits_no_set_mode_bytes(ap, mt):
    c = MitigationController(mode=DefenseMode.ACTIVE_IPS)
    c.step(_frame(10.0, ap, mt, "MANUAL"), _asmt(10.0, AttackType.BENIGN))
    act = c.manual_override("safe_hold")
    assert [f for f in act.counter_frames if _is_set_mode(f)] == []


@pytest.mark.xfail(strict=True, reason="OPEN MAINTAINER DECISION: with no heartbeat ever observed the controller keeps the "
                   "legacy default (autopilot 3, mav_type 2 = ArduCopter) and still actuates; fail-closed needs 8 legacy "
                   "controller test fixtures to carry an explicit dialect")
def test_no_heartbeat_seen_should_fail_closed():
    _, frames = _drive(None, None, "LOITER")
    assert [f for f in frames if _is_set_mode(f)] == []


def test_copter_manual_safe_hold_still_sends_alt_hold():
    c = MitigationController(mode=DefenseMode.ACTIVE_IPS)
    c.step(_frame(10.0, 3, 2, "STABILIZE"), _asmt(10.0, AttackType.BENIGN))
    act = c.manual_override("safe_hold")
    assert len([f for f in act.counter_frames if _is_set_mode(f)]) == 1


# ---- Option B stays possible: tables are kept and correct, but unreachable by default ---------------------------- #

def test_mapping_tables_are_kept(monkeypatch):
    # numbers cross-checked against ArduPilot ArduPlane/mode.h, Rover/mode.h and PX4 px4_custom_mode.h
    assert PLANE_MODES["FBWA"] == 5 and PLANE_MODES["QHOVER"] == 18 and PLANE_MODES["QRTL"] == 21
    assert ROVER_MODES["HOLD"] == 4 and ROVER_MODES["SMART_RTL"] == 12
    assert PX4_MAIN_MODES["ALTCTL"] == (2, 0) and PX4_MAIN_MODES["AUTO_LOITER"] == (4, 3)
    assert safe_gps_denied_mode(3, 1) == "FBWA" and safe_gps_denied_mode(12, 2) == "ALTCTL"

    monkeypatch.setattr(MavlinkActuator, "ALLOW_NON_COPTER_DIALECTS", True)
    plane = MavlinkActuator()
    plane.set_vehicle_dialect(3, 1)
    assert _command_long(plane.encode_set_mode("FBWA"))[1][:3] == (1.0, 5.0, 0.0)
    px4 = MavlinkActuator()
    px4.set_vehicle_dialect(12, 2)
    assert _command_long(px4.encode_set_mode("ALTCTL"))[1][:3] == (1.0, 2.0, 0.0)


def test_non_copter_flag_defaults_off():
    assert MavlinkActuator.ALLOW_NON_COPTER_DIALECTS is False
