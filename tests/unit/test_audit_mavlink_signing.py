"""Regression tests for Batch 3 audit fixes (MAVLink codec, heartbeat filtering, signing floor, COMMAND_INT)."""

from __future__ import annotations

import pytest
from pymavlink.dialects.v20 import common as mav2

from aegisflight.config import DEFAULT_DETECTOR
from aegisflight.core.enums import AttackType
from aegisflight.core.types import MessageEnvelope
from aegisflight.detectors.protocol import ProtocolDetector
from aegisflight.features.extractor import FeatureExtractor
from aegisflight.mavlink.codec import (
    COPTER_MODES,
    MAV_AUTOPILOT_INVALID,
    MODE_NAMES,
    NON_VEHICLE_MAV_TYPES,
    decode_flight_mode,
)
from aegisflight.mavlink.signing import (
    MAVLINK_SIGNING_NEW_STREAM_WINDOW_10US,
    MavlinkSignatureVerifier,
    sign_mavlink2_frame,
)
from aegisflight.mitigation.actuator import MavlinkActuator

KEY = bytes(range(32))


def _hb_env(
    t: float,
    *,
    sysid: int = 1,
    compid: int = 1,
    mav_type: int = 2,
    autopilot: int = 3,
    armed: bool = True,
    custom_mode: int = 4,
    seq: int = 0,
) -> MessageEnvelope:
    base_mode = 0x81 if armed else 0x01
    return MessageEnvelope(
        recv_time=t,
        sysid=sysid,
        compid=compid,
        msgid=0,
        msgname="HEARTBEAT",
        seq=seq & 0xFF,
        signed=False,
        byte_len=21,
        fields={
            "type": mav_type,
            "autopilot": autopilot,
            "base_mode": base_mode,
            "custom_mode": custom_mode,
            "system_status": 4 if armed else 3,
        },
    )


def _cmd_int_env(
    t: float,
    command: int,
    *,
    sysid: int = 255,
    compid: int = 190,
    param1: float = 0.0,
    param2: float = 0.0,
    param3: float = 0.0,
    param4: float = 0.0,
    x: int = 0,
    y: int = 0,
    z: float = 0.0,
    seq: int = 1,
) -> MessageEnvelope:
    return MessageEnvelope(
        recv_time=t,
        sysid=sysid,
        compid=compid,
        msgid=75,
        msgname="COMMAND_INT",
        seq=seq & 0xFF,
        signed=False,
        byte_len=47,
        fields={
            "target_system": 1,
            "target_component": 1,
            "frame": 0,
            "command": command,
            "current": 0,
            "autocontinue": 0,
            "param1": param1,
            "param2": param2,
            "param3": param3,
            "param4": param4,
            "x": x,
            "y": y,
            "z": z,
        },
    )


def _pack_cmd(sysid: int = 1, compid: int = 1, seq: int = 0) -> bytes:
    m = mav2.MAVLink(None, srcSystem=sysid, srcComponent=compid)
    m.seq = seq
    return bytes(m.command_long_encode(1, 1, 400, 0, 1, 0, 0, 0, 0, 0, 0).pack(m))


# ---- 1. proxy-mavlink-2: complete ArduCopter flight mode table ------------------------------------------------ #


@pytest.mark.parametrize(
    ("mode_num", "expected"),
    [
        (0, "STABILIZE"),
        (1, "ACRO"),
        (2, "ALT_HOLD"),
        (3, "AUTO"),
        (4, "GUIDED"),
        (5, "LOITER"),
        (6, "RTL"),
        (7, "CIRCLE"),
        (9, "LAND"),
        (11, "DRIFT"),
        (13, "SPORT"),
        (14, "FLIP"),
        (15, "AUTOTUNE"),
        (16, "POSHOLD"),
        (17, "BRAKE"),
        (18, "THROW"),
        (19, "AVOID_ADSB"),
        (20, "GUIDED_NOGPS"),
        (21, "SMART_RTL"),
        (22, "FLOWHOLD"),
        (23, "FOLLOW"),
        (24, "ZIGZAG"),
        (25, "SYSTEMID"),
        (26, "AUTOROTATE"),
        (27, "AUTO_RTL"),
        (28, "TURTLE"),
    ],
)
def test_complete_arducopter_mode_table_and_actuator_alignment(mode_num: int, expected: str) -> None:
    assert decode_flight_mode(3, 2, mode_num) == expected
    assert MODE_NAMES[mode_num] == expected
    assert COPTER_MODES[expected] == mode_num

    act = MavlinkActuator()
    act.set_vehicle_dialect(3, 2)
    assert act.knows_mode(expected) is True
    assert act.knows_mode("AUTO_LOITER") is False
    assert act.knows_mode("AUTO/LOITER") is False


@pytest.mark.parametrize("bad_type", [6, 18, 26, 27, 30])
def test_decode_flight_mode_rejects_peripheral_and_invalid_autopilot(bad_type: int) -> None:
    assert bad_type in NON_VEHICLE_MAV_TYPES
    assert decode_flight_mode(3, bad_type, 0) == "UNKNOWN"
    assert decode_flight_mode(MAV_AUTOPILOT_INVALID, 2, 0) == "UNKNOWN"


# ---- 2. proxy-mavlink-3 & analytics-misc-1: non-primary / peripheral heartbeats ------------------------------- #


@pytest.mark.parametrize(
    ("label", "sysid", "compid", "mav_type", "autopilot"),
    [
        ("gcs", 255, 190, 6, 8),
        ("companion_onboard", 1, 191, 18, 8),
        ("gimbal", 1, 154, 26, 8),
        ("adsb", 1, 156, 27, 8),
        ("camera", 1, 100, 30, 8),
        ("invalid_autopilot_quad", 1, 192, 2, 8),
        ("rogue_sysid_vehicle", 99, 1, 2, 3),
        ("rogue_compid_vehicle", 1, 2, 2, 3),
    ],
)
def test_peripheral_and_rogue_heartbeats_never_overwrite_vehicle_state(
    label: str, sysid: int, compid: int, mav_type: int, autopilot: int
) -> None:
    ext = FeatureExtractor()
    # Primary vehicle heartbeat establishes armed=True, flight_mode="POSHOLD" (16) at t=1.0
    ext.update(_hb_env(1.0, sysid=1, compid=1, mav_type=2, autopilot=3, armed=True, custom_mode=16, seq=1))
    f1 = ext.extract(1.0)
    assert f1.snapshot.armed is True
    assert f1.snapshot.flight_mode == "POSHOLD"
    assert f1.heartbeat_age_s == pytest.approx(0.0)
    assert (f1.autopilot_id, f1.mav_type) == (3, 2)

    # Peripheral or rogue heartbeat arrives at t=4.0 claiming disarmed + STABILIZE (0)
    ext.update(
        _hb_env(4.0, sysid=sysid, compid=compid, mav_type=mav_type, autopilot=autopilot, armed=False, custom_mode=0, seq=1)
    )
    f2 = ext.extract(4.0)
    assert f2.snapshot.armed is True, f"{label} overwrote armed"
    assert f2.snapshot.flight_mode == "POSHOLD", f"{label} overwrote flight_mode"
    assert f2.heartbeat_age_s == pytest.approx(3.0), f"{label} refreshed _last_heartbeat_t"
    assert (f2.autopilot_id, f2.mav_type) == (3, 2), f"{label} overwrote dialect"


def test_peripheral_heartbeat_before_vehicle_does_not_bind_primary_source() -> None:
    ext = FeatureExtractor()
    # Companion heartbeat arrives first at t=0.5
    ext.update(_hb_env(0.5, sysid=1, compid=191, mav_type=18, autopilot=8, armed=False, custom_mode=0, seq=1))
    f0 = ext.extract(0.5)
    assert f0.heartbeat_seen is False
    assert f0.snapshot.armed is None

    # Real vehicle heartbeat arrives at t=1.0 and binds cleanly
    ext.update(_hb_env(1.0, sysid=1, compid=1, mav_type=2, autopilot=3, armed=True, custom_mode=21, seq=1))
    f1 = ext.extract(1.0)
    assert f1.heartbeat_seen is True
    assert f1.snapshot.armed is True
    assert f1.snapshot.flight_mode == "SMART_RTL"
    assert (f1.autopilot_id, f1.mav_type) == (3, 2)


# ---- 3. proxy-mavlink-4: MAVLink-2 signing 60s floor for first-seen streams ----------------------------------- #


def test_signing_new_stream_enforces_60s_floor_when_prior_timestamps_exist() -> None:
    v = MavlinkSignatureVerifier(KEY)
    base_ts = 10_000_000  # 100s since epoch
    first = sign_mavlink2_frame(_pack_cmd(sysid=1, compid=1, seq=1), KEY, link_id=0, timestamp_10us=base_ts)
    assert v.verify_frame(first).valid is True

    # First-seen stream (link=1, sysid=2, compid=1) with timestamp > 60s behind max_ts -> rejected
    too_old_ts = base_ts - MAVLINK_SIGNING_NEW_STREAM_WINDOW_10US - 1
    stale = sign_mavlink2_frame(_pack_cmd(sysid=2, compid=1, seq=1), KEY, link_id=1, timestamp_10us=too_old_ts)
    res_old = v.verify_frame(stale)
    assert res_old.valid is False
    assert res_old.signed is True
    assert res_old.replayed is True
    assert res_old.reason == "replay_timestamp_too_old"
    assert v.replay_count == 1
    assert v.invalid_count == 1
    assert (1, 2, 1) not in v._last_timestamps

    # Exact 60s boundary is accepted
    boundary_ts = base_ts - MAVLINK_SIGNING_NEW_STREAM_WINDOW_10US
    boundary = sign_mavlink2_frame(_pack_cmd(sysid=2, compid=1, seq=2), KEY, link_id=1, timestamp_10us=boundary_ts)
    res_ok = v.verify_frame(boundary)
    assert res_ok.valid is True
    assert res_ok.replayed is False
    assert res_ok.reason == "ok"

    # Once accepted, same-stream monotonicity still applies
    replay_same = sign_mavlink2_frame(_pack_cmd(sysid=2, compid=1, seq=3), KEY, link_id=1, timestamp_10us=boundary_ts)
    res_rep = v.verify_frame(replay_same)
    assert res_rep.valid is False and res_rep.replayed is True
    assert res_rep.reason == "replay_timestamp_non_monotonic"

    # After reset(), an old timestamp is accepted again as the first stream
    v.reset()
    assert v.verify_frame(stale).valid is True


# ---- 4. sources-detectors-1: COMMAND_INT recorded and enforced by ProtocolDetector ---------------------------- #


def test_command_int_recorded_and_triggers_provenance_force_disarm_and_cadence() -> None:
    ext = FeatureExtractor()
    det = ProtocolDetector({**DEFAULT_DETECTOR["protocol"], "cadence_guard_enabled": True})

    # Establish armed airborne vehicle
    ext.update(_hb_env(1.0, sysid=1, compid=1, mav_type=2, autopilot=3, armed=True, custom_mode=4, seq=1))
    ext.update(
        MessageEnvelope(
            recv_time=1.0,
            sysid=1,
            compid=1,
            msgid=33,
            msgname="GLOBAL_POSITION_INT",
            seq=2,
            signed=False,
            byte_len=40,
            fields={
                "time_boot_ms": 1000,
                "lat": 129_000_000,
                "lon": 775_000_000,
                "alt": 520_000,
                "relative_alt": 20_000,
                "vx": 500,
                "vy": 0,
                "vz": 0,
                "hdg": 0,
            },
        )
    )

    # 1) Force-disarm via COMMAND_INT (msgid 75) from expected GCS sysid 255
    ext.update(_cmd_int_env(1.1, 400, sysid=255, compid=190, param1=0.0, param2=21196.0, seq=1))
    frame1 = ext.extract(1.1)
    assert len(frame1.commands_recent) == 1
    assert frame1.commands_recent[0].command == 400
    assert frame1.commands_recent[0].params[:2] == (0.0, 21196.0)
    assert frame1.cmd_rate_hz > 0.0

    res1 = det.process(frame1)
    assert res1.attack_votes.get(AttackType.COMMAND_INJECTION, 0.0) >= 0.95
    assert res1.score >= 0.95
    assert any("force-disarm (param2=21196)" in ev for ev in res1.evidence), res1.evidence

    # 2) Rapid duplicate COMMAND_INT from GCS triggers cadence guard
    ext.update(_cmd_int_env(1.3, 176, sysid=255, compid=190, param1=1.0, param2=6.0, seq=2))
    det.process(ext.extract(1.3))
    ext.update(_cmd_int_env(1.5, 176, sysid=255, compid=190, param1=1.0, param2=6.0, seq=3))
    res_cad = det.process(ext.extract(1.5))
    assert res_cad.attack_votes.get(AttackType.COMMAND_INJECTION, 0.0) >= 0.90
    assert any("violates operator cadence" in ev for ev in res_cad.evidence), res_cad.evidence

    # 3) Unexpected-source COMMAND_INT triggers command provenance
    ext2 = FeatureExtractor()
    det2 = ProtocolDetector(DEFAULT_DETECTOR["protocol"])
    ext2.update(_hb_env(1.0, sysid=1, compid=1, mav_type=2, autopilot=3, armed=True, custom_mode=4, seq=1))
    ext2.update(_cmd_int_env(1.1, 176, sysid=99, compid=190, param1=1.0, param2=6.0, seq=1))
    res_prov = det2.process(ext2.extract(1.1))
    assert res_prov.attack_votes.get(AttackType.COMMAND_INJECTION, 0.0) >= 0.65
    assert any("unexpected source" in ev and "sys99/comp190" in ev for ev in res_prov.evidence), res_prov.evidence
