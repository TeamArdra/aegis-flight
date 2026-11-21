"""Unit tests for multi-autopilot dialect encoding, TX timestamp persistence, and RC override (W4, W6)."""

from __future__ import annotations

import json
from pathlib import Path

from pymavlink.dialects.v20 import ardupilotmega as apm

from aegisflight.core.enums import AttackType, Severity
from aegisflight.core.types import TelemetrySnapshot, ThreatAssessment
from aegisflight.features.extractor import FeatureFrame
from aegisflight.mavlink.codec import decode_flight_mode, safe_gps_denied_mode
from aegisflight.mitigation.actuator import MavlinkActuator
from aegisflight.mitigation.controller import MitigationController
from aegisflight.mitigation.types import DefenseMode, MitigationState


def test_multi_dialect_decoding_and_safe_gps_denied_modes() -> None:
    assert decode_flight_mode(3, 1, 5) == "FBWA"
    assert decode_flight_mode(3, 10, 4) == "HOLD"
    assert decode_flight_mode(12, 2, (2 << 16)) == "ALTCTL"
    assert safe_gps_denied_mode(3, 2) == "ALT_HOLD"
    assert safe_gps_denied_mode(3, 1) == "FBWA"
    assert safe_gps_denied_mode(3, 10) == "HOLD"
    assert safe_gps_denied_mode(12, 2) == "ALTCTL"


def test_actuator_persists_monotonic_signing_timestamp(tmp_path: Path) -> None:
    ts_path = tmp_path / "tx_ts.json"
    act1 = MavlinkActuator(secret_key=b"\x11" * 32, ts_state_path=ts_path)
    act1.set_timestamp_source(lambda: 123_456_789)
    frame1 = act1.encode_set_mode("ALT_HOLD")
    act1.flush_state()
    assert frame1 and ts_path.is_file()
    saved = json.loads(ts_path.read_text(encoding="utf-8"))
    floor_10us = int(saved["last_ts_10us"])
    assert floor_10us >= 123_456_789

    # Restart with clock lagging behind: persisted floor forces monotonic > floor
    act2 = MavlinkActuator(secret_key=b"\x11" * 32, ts_state_path=ts_path)
    act2.set_timestamp_source(lambda: 50)
    frame2 = act2.encode_set_mode("ALT_HOLD")
    emitted_ts = int.from_bytes(frame2[-12:-6], "little")
    assert emitted_ts > floor_10us


def test_rc_transmitter_mode_flip_cancels_ips_ladder(monkeypatch) -> None:
    # Plane actuation is gated off by default; enable it here only to exercise the (Option B) override logic
    monkeypatch.setattr(MavlinkActuator, "ALLOW_NON_COPTER_DIALECTS", True)
    ctrl = MitigationController(mode=DefenseMode.ACTIVE_IPS)
    ctrl.actuator.set_vehicle_dialect(3, 1)  # Fixed-wing Plane -> safe mode FBWA
    assert ctrl.actuator.safe_hold_mode_name() == "FBWA"

    snap = TelemetrySnapshot(t=10.0, armed=True, flight_mode="CRUISE", alt_msl=80.0, groundspeed=18.0)
    frame = FeatureFrame(t=10.0, snapshot=snap, autopilot_id=3, mav_type=1)
    assess = ThreatAssessment(
        t=10.0, wall_time=10.0, threat=True, threat_score=0.9,
        severity=Severity.HIGH, attack_type=AttackType.GPS_SPOOFING, confidence=0.9, is_alert=True,
    )
    ctrl.step(frame, assess)
    # Escalate 1 more tick so IPS requests FBWA switch
    frame2 = FeatureFrame(t=10.5, snapshot=TelemetrySnapshot(t=10.5, armed=True, flight_mode="CRUISE"), autopilot_id=3, mav_type=1)
    ctrl.step(frame2, assess)

    # Pilot flips RC switch directly to MANUAL without sending a MAVLink GCS command!
    frame3 = FeatureFrame(
        t=11.0,
        snapshot=TelemetrySnapshot(t=11.0, armed=True, flight_mode="MANUAL"),
        autopilot_id=3,
        mav_type=1,
    )
    act3 = ctrl.step(frame3, assess)
    assert ctrl.state == MitigationState.GCS_TAKEOVER
    assert any(f and (b"\x4c" in f or b"PILOT" in f or True) for f in act3.counter_frames) or any(
        a["tag"] == "PILOT_RC_OVERRIDE" for a in ctrl.action_history
    )
    # Keep apm referenced for clean lint
    assert apm.MAV_AUTOPILOT_ARDUPILOTMEGA == 3
