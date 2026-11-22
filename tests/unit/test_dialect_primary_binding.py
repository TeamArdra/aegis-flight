"""The vehicle dialect (autopilot / mav_type -> mode table) is bound to ONE primary vehicle source. SYNTHETIC only.

A HEARTBEAT from another sysid/compid (spoofed, companion computer, gimbal, ...) must not switch the mode table, and a
controller that has never seen a vehicle HEARTBEAT must not encode DO_SET_MODE (fail-closed).
"""

from __future__ import annotations

import struct

from aegisflight.core.enums import AttackType, IntegrityStatus, Severity
from aegisflight.core.types import MessageEnvelope, TelemetrySnapshot, ThreatAssessment
from aegisflight.features.extractor import FeatureExtractor, FeatureFrame
from aegisflight.mitigation.controller import MitigationController
from aegisflight.mitigation.types import AttackSubMode, DefenseMode


def _hb(t: float, sysid: int, compid: int, mav_type: int, autopilot: int, custom_mode: int = 5) -> MessageEnvelope:
    return MessageEnvelope(recv_time=t, sysid=sysid, compid=compid, msgid=0, msgname="HEARTBEAT", seq=0, signed=False,
                           byte_len=21, fields={"type": mav_type, "autopilot": autopilot, "base_mode": 0x80,
                                                "custom_mode": custom_mode, "system_status": 4})


def test_dialect_unset_until_a_vehicle_heartbeat():
    ext = FeatureExtractor()
    f = ext.extract(0.5)
    assert (f.autopilot_id, f.mav_type) == (None, None)
    ext.update(_hb(1.0, 255, 190, 6, 8))  # GCS heartbeat: ignored
    assert ext.extract(1.1).autopilot_id is None


def test_spoofed_heartbeat_from_another_sysid_cannot_switch_the_mode_table():
    ext = FeatureExtractor()
    ext.update(_hb(1.0, 1, 1, 2, 3))  # the real ArduCopter
    assert (ext.extract(1.1).autopilot_id, ext.extract(1.1).mav_type) == (3, 2)
    for i, (sysid, compid) in enumerate([(2, 1), (99, 1), (1, 192), (1, 154)]):
        ext.update(_hb(2.0 + i, sysid, compid, 1, 12))  # claims PX4 fixed wing
        f = ext.extract(2.1 + i)
        assert (f.autopilot_id, f.mav_type) == (3, 2), (sysid, compid)
    ext.update(_hb(9.0, 1, 1, 2, 3))  # the primary keeps updating
    assert (ext.extract(9.1).autopilot_id, ext.extract(9.1).mav_type) == (3, 2)


def test_non_autopilot_component_heartbeat_first_does_not_bind():
    ext = FeatureExtractor()
    ext.update(_hb(1.0, 1, 192, 18, 8))  # companion computer (MAV_AUTOPILOT_INVALID)
    assert ext.extract(1.1).autopilot_id is None
    ext.update(_hb(2.0, 1, 1, 2, 3))
    assert (ext.extract(2.1).autopilot_id, ext.extract(2.1).mav_type) == (3, 2)


def _frame(t, ap, mt, mode):
    snap = TelemetrySnapshot(t=t, lat=18.92, lon=72.83, alt_msl=25.0, rel_alt=25.0, vx=0.0, vy=5.0, vz=0.0,
                             groundspeed=5.0, roll=0.0, pitch=0.0, yaw=0.0, heading=90.0, flight_mode=mode,
                             armed=True, battery_remaining=90.0)
    return FeatureFrame(t=t, snapshot=snap, gps_seen=True, gps_raw_seen=True, heartbeat_seen=True,
                        msg_rate_hz=10.0, pos_residual_m=0.0, autopilot_id=ap, mav_type=mt)


def _asmt(t):
    return ThreatAssessment(t=t, wall_time=t, threat=True, threat_score=0.9, severity=Severity.CRITICAL,
                            attack_type=AttackType.GPS_SPOOFING, confidence=0.9, evidence=[], detector_scores={},
                            contributing_detectors=[], integrity_status=IntegrityStatus.VALID, latency_ms=1.0,
                            is_alert=True)


def _is_set_mode(frame: bytes) -> bool:
    payload = frame[10:10 + frame[1]] + bytes(33)
    return len(frame) > 10 and struct.unpack_from("<H", payload, 28)[0] == 176


def test_controller_with_no_heartbeat_encodes_no_set_mode_even_on_manual_safe_hold():
    c = MitigationController(mode=DefenseMode.ACTIVE_IPS)
    c.set_capabilities(ekf_secondary=None)
    c.classifier.classify = lambda f, s: AttackSubMode.GPS_GRADUAL_DRIFT
    frames: list[bytes] = []
    t = 10.0
    while t < 40.0:
        frames += c.step(_frame(t, None, None, "LOITER"), _asmt(t)).counter_frames
        t = round(t + 0.2, 6)
    frames += c.manual_override("safe_hold").counter_frames
    assert [f for f in frames if _is_set_mode(f)] == []
    # once a vehicle heartbeat has fixed an ArduCopter dialect, the same controller may actuate
    t = 40.0
    while t < 70.0:
        frames += c.step(_frame(t, 3, 2, "LOITER"), _asmt(t)).counter_frames
        t = round(t + 0.2, 6)
    assert [f for f in frames if _is_set_mode(f)]
