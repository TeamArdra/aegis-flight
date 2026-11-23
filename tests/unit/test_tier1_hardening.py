"""Tier 1 & Tier 2 real-world flight hardening & extreme-volume flood stress tests."""

from __future__ import annotations

import math

from pymavlink.dialects.v20 import common as mav2

from aegisflight.config import load_config
from aegisflight.core.enums import AttackType
from aegisflight.core.types import MessageEnvelope
from aegisflight.detectors.physics import CusumDriftIntegrator
from aegisflight.detectors.protocol import ProtocolDetector
from aegisflight.features.extractor import FeatureExtractor
from aegisflight.logging.store import EventStore
from aegisflight.mavlink.signing import MavlinkSignatureVerifier, sign_mavlink2_frame
from aegisflight.mitigation.controller import MitigationController
from aegisflight.mitigation.inline_policy import InlinePolicy
from aegisflight.mitigation.types import DefenseMode
from aegisflight.proxy.hooks import FrameContext


def _env(
    recv_time: float,
    msgid: int,
    msgname: str,
    sysid: int,
    compid: int,
    seq: int,
    fields: dict,
) -> MessageEnvelope:
    return MessageEnvelope(
        recv_time=recv_time,
        msgid=msgid,
        msgname=msgname,
        sysid=sysid,
        compid=compid,
        seq=seq,
        signed=False,
        byte_len=24,
        fields=fields,
    )


def test_nan_and_inf_telemetry_cannot_poison_extractor_or_cusum_or_ml_vector() -> None:
    ext = FeatureExtractor(learn_baro_offset=True)
    # 1. Establish healthy disarmed baseline on the ground
    ext.update(
        _env(
            0.0,
            0,
            "HEARTBEAT",
            1,
            1,
            1,
            {"type": 2, "autopilot": 3, "base_mode": 0, "custom_mode": 0},
        )
    )
    ext.update(
        _env(
            0.1,
            24,
            "GPS_RAW_INT",
            1,
            1,
            2,
            {"fix_type": 3, "satellites_visible": 12, "eph": 100},
        )
    )
    ext.update(
        _env(
            0.1,
            33,
            "GLOBAL_POSITION_INT",
            1,
            1,
            3,
            {
                "lat": int(19.1334 * 1e7),
                "lon": int(72.9133 * 1e7),
                "alt": 50000,
                "relative_alt": 10000,
                "vx": 100,
                "vy": 0,
                "vz": 0,
            },
        )
    )
    ext.update(
        _env(
            0.1,
            74,
            "VFR_HUD",
            1,
            1,
            4,
            {"groundspeed": 1.0, "heading": 90.0, "throttle": 50.0, "alt": 40.0, "climb": 0.0},
        )
    )
    f0 = ext.extract(0.2)
    assert f0.learned_baro_offset_m == 10.0

    # 2. Inject hostile NaN / Inf floats across VFR_HUD, ATTITUDE, OPTICAL_FLOW, GPS_RAW_INT, PARAM_SET, COMMAND_LONG
    nan = float("nan")
    inf = float("inf")
    ext.update(
        _env(
            0.3,
            74,
            "VFR_HUD",
            1,
            1,
            5,
            {"groundspeed": nan, "heading": nan, "throttle": inf, "alt": nan, "climb": -inf},
        )
    )
    ext.update(
        _env(
            0.3,
            30,
            "ATTITUDE",
            1,
            1,
            6,
            {"roll": nan, "pitch": inf, "yaw": nan, "rollspeed": 0.0, "pitchspeed": 0.0, "yawspeed": 0.0},
        )
    )
    ext.update(
        _env(
            0.3,
            100,
            "OPTICAL_FLOW",
            1,
            1,
            7,
            {"flow_comp_m_x": nan, "flow_comp_m_y": inf},
        )
    )
    ext.update(
        _env(
            0.3,
            24,
            "GPS_RAW_INT",
            1,
            1,
            8,
            {"fix_type": 3, "satellites_visible": 12, "eph": nan, "vel": inf, "time_usec": nan},
        )
    )
    ext.update(
        _env(
            0.3,
            23,
            "PARAM_SET",
            255,
            190,
            9,
            {"param_id": "FENCE_ENABLE", "param_value": nan},
        )
    )
    ext.update(
        _env(
            0.3,
            76,
            "COMMAND_LONG",
            255,
            190,
            10,
            {"command": 400, "param1": nan, "param2": inf},
        )
    )

    f1 = ext.extract(0.4)
    assert all(math.isfinite(x) for x in f1.to_vector())
    assert f1.learned_baro_offset_m == 10.0  # never poisoned by NaN baro_alt
    assert f1.snapshot.baro_alt == 40.0

    # 3. CusumDriftIntegrator ignores NaN/Inf and keeps detecting real drift afterwards
    cusum = CusumDriftIntegrator(slack_ms=0.05, threshold_m=1.2)
    cusum.update_displacement(nan, 0.5, 0.2)
    cusum.update_displacement(0.5, inf, 0.2)
    cusum.update_displacement(0.5, 0.5, nan)
    assert math.isfinite(cusum.magnitude_m) and cusum.magnitude_m == 0.0
    for _ in range(15):
        cusum.update_displacement(0.15, 0.0, 0.2)
    assert cusum.triggered is True


def test_peripheral_and_gcs_heartbeats_cannot_flip_inline_policy_armed_state() -> None:
    pol = InlinePolicy(vehicle_sysids=(1,))
    m_fc = mav2.MAVLink(None, srcSystem=1, srcComponent=1)
    hb_armed = bytes(m_fc.heartbeat_encode(2, 3, 0x80, 0, 4).pack(m_fc))
    pol.down(FrameContext("down", hb_armed, 1_000_000_000, 1, 1, 1, 0, False))
    assert pol.armed is True

    # Onboard peripheral / companion (sysid=1, compid=191, autopilot=MAV_AUTOPILOT_INVALID=8) sends disarmed HEARTBEAT
    m_periph = mav2.MAVLink(None, srcSystem=1, srcComponent=191)
    hb_periph = bytes(m_periph.heartbeat_encode(18, 8, 0x00, 0, 4).pack(m_periph))
    pol.down(FrameContext("down", hb_periph, 1_100_000_000, 1, 191, 1, 0, False))
    assert pol.armed is True

    # Rogue sysid=66 sends disarmed HEARTBEAT
    m_rogue = mav2.MAVLink(None, srcSystem=66, srcComponent=200)
    hb_rogue = bytes(m_rogue.heartbeat_encode(2, 3, 0x00, 0, 4).pack(m_rogue))
    pol.down(FrameContext("down", hb_rogue, 1_200_000_000, 66, 200, 1, 0, False))
    assert pol.armed is True


def test_extreme_volume_spoofed_source_flood_bounds_memory_and_evidence() -> None:
    ext = FeatureExtractor()
    cfg = load_config().detector
    proto = ProtocolDetector(cfg["protocol"])

    # Flood 2,500 distinct spoofed (sysid, compid) pairs in a single decision window
    for i in range(2500):
        sid = 10 + (i // 50)
        cid = 1 + (i % 50)
        ext.update(
            _env(
                1.0 + i * 0.0001,
                30,
                "ATTITUDE",
                sid,
                cid,
                i & 0xFF,
                {"roll": 0.0, "pitch": 0.0, "yaw": 0.0, "rollspeed": 0.0, "pitchspeed": 0.0, "yawspeed": 0.0},
            )
        )
    assert len(ext._seq_state) <= 512
    assert len(ext._sources) <= 512

    frame = ext.extract(1.5)
    res = proto.process(frame)
    assert res.triggered is True
    assert AttackType.MAVLINK_ANOMALY in res.attack_votes or AttackType.DOS in res.attack_votes
    rogue_ev = [e for e in res.evidence if e.startswith("rogue telemetry source(s):")]
    assert len(rogue_ev) == 1
    assert "(+" in rogue_ev[0] and len(rogue_ev[0]) < 400


def test_manual_override_uses_latest_mission_timestamp_and_signing_verifier_bounds_streams() -> None:
    ctrl = MitigationController(mode=DefenseMode.ACTIVE_IPS)
    ext = FeatureExtractor()
    ext.update(
        _env(
            42.5,
            0,
            "HEARTBEAT",
            1,
            1,
            1,
            {"type": 2, "autopilot": 3, "base_mode": 0x80, "custom_mode": 3},
        )
    )
    frame = ext.extract(42.5)
    # Stamp mission clock t=42.5 via controller.step
    from aegisflight.core.enums import IntegrityStatus, Severity
    from aegisflight.core.types import ThreatAssessment

    ctrl.step(
        frame,
        ThreatAssessment(
            t=42.5,
            wall_time=1000.0,
            threat=False,
            severity=Severity.NORMAL,
            attack_type=AttackType.BENIGN,
            threat_score=0.0,
            confidence=1.0,
            detector_scores={},
            contributing_detectors=[],
            evidence=[],
            integrity_status=next(iter(IntegrityStatus)),
            latency_ms=0.1,
            telemetry={},
        ),
    )
    act = ctrl.manual_override("safe_hold")
    assert act.t == 42.5
    assert act.actions[-1]["t"] == 42.5

    # MavlinkSignatureVerifier bounds _last_timestamps to <= 1024 streams under stream-key flood
    key = b"\x42" * 32
    ver = MavlinkSignatureVerifier(key)
    base_frame = bytes([0xFD, 4, 0, 0, 1, 1, 1, 76, 0, 0, 0, 0, 0, 0, 0, 0])
    for i in range(1200):
        lid = (i >> 8) & 0xFF
        cid = i & 0xFF
        hdr = bytearray(base_frame)
        hdr[6] = cid
        signed = sign_mavlink2_frame(bytes(hdr), key, link_id=lid, timestamp_10us=1000 + i)
        chk = ver.verify_frame(signed)
        assert chk.valid is True
    assert len(ver._last_timestamps) <= 1024


def test_sqlite_composite_run_indexes_exist(tmp_path) -> None:
    store = EventStore(tmp_path / "idx.sqlite")
    idxs = {
        r["name"]: r["sql"]
        for r in store.conn.execute("SELECT name, sql FROM sqlite_master WHERE type='index'").fetchall()
        if r["sql"]
    }
    assert "events(run_id, id DESC)" in idxs.get("idx_events_run", "")
    assert "actions(run_id, id DESC)" in idxs.get("idx_actions_run", "")
    store.close()
