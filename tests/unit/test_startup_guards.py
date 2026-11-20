"""Unit tests for start-up false-alarm guards (issue #15):
- GNSS never-acquired policy ('coverage' default vs 'dos', plus lost/regained reset)
- PhysicsDetector first-sample guards for battery rise, altitude rate, and position residual
- Combined ArduPilot-style boot sequence (0 V -> 25 V, 0 m -> 584 m, (0,0) -> home, fix 0 -> 3)
"""

from __future__ import annotations

import pytest

from aegisflight.config import DEFAULT_DETECTOR, load_config
from aegisflight.core.enums import AttackType
from aegisflight.core.types import MessageEnvelope, TelemetrySnapshot
from aegisflight.detectors.physics import PhysicsDetector
from aegisflight.detectors.protocol import ProtocolDetector
from aegisflight.features.extractor import FeatureExtractor, FeatureFrame
from aegisflight.pipeline import IDSPipeline
from aegisflight.sources.stream import TelemetryTick


def _env(t: float, name: str, seq: int = 0, **fields) -> MessageEnvelope:
    return MessageEnvelope(
        recv_time=t,
        sysid=1,
        compid=1,
        msgid=0,
        msgname=name,
        seq=seq % 256,
        signed=False,
        byte_len=24,
        fields=fields,
    )


def _hb(t: float, seq: int = 0) -> MessageEnvelope:
    return _env(t, "HEARTBEAT", seq=seq, type=2, autopilot=3, base_mode=0, custom_mode=0, system_status=3)


def _raw(t: float, fix: int, sats: int, seq: int = 0) -> MessageEnvelope:
    return _env(t, "GPS_RAW_INT", seq=seq, fix_type=fix, satellites_visible=sats, eph=100)


def _gpi(
    t: float,
    lat_deg: float,
    lon_deg: float,
    vx: float = 0.0,
    vy: float = 0.0,
    seq: int = 0,
    alt_mm: int = 584000,
) -> MessageEnvelope:
    return _env(
        t,
        "GLOBAL_POSITION_INT",
        seq=seq,
        lat=int(lat_deg * 1e7),
        lon=int(lon_deg * 1e7),
        alt=alt_mm,
        relative_alt=0,
        vx=int(vx * 100),
        vy=int(vy * 100),
        vz=0,
        hdg=0,
    )


# ---- GNSS never-acquired policy --------------------------------------------------------------- #


def test_gnss_never_acquired_default_coverage_and_lost_regained_resets() -> None:
    assert DEFAULT_DETECTOR["protocol"]["gnss_never_acquired_policy"] == "dos"
    cfg = {**DEFAULT_DETECTOR["protocol"], "gnss_never_acquired_policy": "coverage"}
    det = ProtocolDetector(cfg)
    ex = FeatureExtractor()

    # Phase 1: never acquired (fix=0, sats=0) for 10 decisions -> coverage, score 0
    for k in range(10):
        t = k * 0.2
        ex.update(_hb(t, seq=k))
        ex.update(_raw(t, 0, 0, seq=k))
        res = det.process(ex.extract(t))
        ex.clear_window_counts()
        assert AttackType.DOS not in res.attack_votes
        assert res.score == 0.0

    # Phase 2: valid fix acquired -> clears streak
    t = 2.0
    ex.update(_hb(t, seq=10))
    ex.update(_raw(t, 3, 10, seq=10))
    res = det.process(ex.extract(t))
    ex.clear_window_counts()
    assert res.signals["gnss_bad_ticks"] == 0.0

    # Phase 3: fix lost -> DOS >= 0.7 after gnss_loss_ticks (5)
    lost_res = None
    for j in range(5):
        t = 2.2 + j * 0.2
        ex.update(_hb(t, seq=11 + j))
        ex.update(_raw(t, 1, 2, seq=11 + j))
        lost_res = det.process(ex.extract(t))
        ex.clear_window_counts()
    assert lost_res is not None
    assert lost_res.attack_votes[AttackType.DOS] >= 0.7
    assert any(e.startswith("GNSS fix lost:") for e in lost_res.evidence)

    # Phase 4: fix regained -> resets bad streak cleanly
    t = 3.2
    ex.update(_hb(t, seq=16))
    ex.update(_raw(t, 3, 9, seq=16))
    regained = det.process(ex.extract(t))
    ex.clear_window_counts()
    assert regained.signals["gnss_bad_ticks"] == 0.0
    assert regained.score == 0.0


def test_gnss_policy_validation() -> None:
    with pytest.raises(ValueError):
        ProtocolDetector({**DEFAULT_DETECTOR["protocol"], "gnss_never_acquired_policy": "invalid"})


# ---- PhysicsDetector first-sample guards ------------------------------------------------------ #


def test_physics_battery_first_sample_guard_suppresses_boot_jump_then_catches_attack() -> None:
    det = PhysicsDetector(DEFAULT_DETECTOR["physics"])
    # Boot placeholder 0.0 V -> never triggers
    r0 = det.process(
        FeatureFrame(
            t=0.0,
            snapshot=TelemetrySnapshot(t=0.0, battery_voltage=0.0),
            battery_v_rise=0.0,
            heartbeat_seen=True,
            gps_seen=False,
        )
    )
    assert r0.score == 0.0

    # First positive battery reading 25.4 V (rise from 0.0 V) -> suppressed (< 2 valid samples)
    r1 = det.process(
        FeatureFrame(
            t=0.2,
            snapshot=TelemetrySnapshot(t=0.2, battery_voltage=25.4),
            battery_v_rise=25.4,
            heartbeat_seen=True,
            gps_seen=False,
        )
    )
    assert r1.score == 0.0 and AttackType.TELEMETRY_MANIPULATION not in r1.attack_votes

    # Second positive sample + real attack jump -> caught
    r2 = det.process(
        FeatureFrame(
            t=0.4,
            snapshot=TelemetrySnapshot(t=0.4, battery_voltage=27.0),
            battery_v_rise=8.0,
            heartbeat_seen=True,
            gps_seen=False,
        )
    )
    assert AttackType.TELEMETRY_MANIPULATION in r2.attack_votes


def test_physics_altitude_rate_first_sample_guard_suppresses_boot_jump_then_catches_attack() -> None:
    det = PhysicsDetector(DEFAULT_DETECTOR["physics"])
    # Uninitialized baro_alt=0.0 for several ticks -> suppressed
    for k in range(3):
        r = det.process(
            FeatureFrame(
                t=k * 0.2,
                snapshot=TelemetrySnapshot(t=k * 0.2, baro_alt=0.0),
                alt_rate_ms=0.0,
                heartbeat_seen=True,
                gps_seen=False,
            )
        )
        assert r.score == 0.0

    # First real baro altitude 584.1 m (alt_rate_ms=2920.5) -> suppressed (< 2 valid samples)
    r_first = det.process(
        FeatureFrame(
            t=0.6,
            snapshot=TelemetrySnapshot(t=0.6, baro_alt=584.1),
            alt_rate_ms=2920.5,
            heartbeat_seen=True,
            gps_seen=False,
        )
    )
    assert r_first.score == 0.0 and AttackType.TELEMETRY_MANIPULATION not in r_first.attack_votes

    # Subsequent real implausible altitude jump -> detected
    r_atk = det.process(
        FeatureFrame(
            t=0.8,
            snapshot=TelemetrySnapshot(t=0.8, baro_alt=620.0),
            alt_rate_ms=179.5,
            heartbeat_seen=True,
            gps_seen=False,
        )
    )
    assert AttackType.TELEMETRY_MANIPULATION in r_atk.attack_votes


def test_physics_position_residual_first_sample_guard_suppresses_first_fix_then_catches_spoof() -> None:
    det = PhysicsDetector(DEFAULT_DETECTOR["physics"])
    # First valid fix sample -> suppressed
    r1 = det.process(
        FeatureFrame(
            t=0.0,
            snapshot=TelemetrySnapshot(t=0.0, lat=-35.363, lon=149.165, gps_fix_type=3),
            pos_residual_m=30.0,
            gps_age_s=0.0,
            heartbeat_seen=True,
            gps_seen=True,
        )
    )
    assert r1.score == 0.0 and AttackType.GPS_SPOOFING not in r1.attack_votes

    # Second valid fix sample with residual -> detected
    r2 = det.process(
        FeatureFrame(
            t=0.2,
            snapshot=TelemetrySnapshot(t=0.2, lat=-35.363, lon=149.165, gps_fix_type=3),
            pos_residual_m=30.0,
            gps_age_s=0.0,
            heartbeat_seen=True,
            gps_seen=True,
        )
    )
    assert r2.score == 1.0 and AttackType.GPS_SPOOFING in r2.attack_votes


def test_ardupilot_boot_sequence_produces_zero_startup_alerts() -> None:
    """Reproduce the ArduPilot SITL boot sequence:
    - t=0.0..2.0: 0 V battery, 0 m baro, (0,0) pos, fix_type=0 sats=0
    - t=2.4: battery jumps 0 -> 25.42 V
    - t=9.2: baro jumps 0 -> 584.08 m, GPS locks at (-35.363, 149.165) with fix_type=3 sats=10
    - t=9.4..12.0: nominal settled telemetry
    Must produce 0 alerts across the entire boot sequence.
    """
    cfg = load_config("configs/ardupilot_copter")
    pipe = IDSPipeline(cfg, model_path=None)
    seq = 0
    alerts = []
    for k in range(60):  # 0.0 .. 11.8 s at 5 Hz tick rate
        t = round(k * 0.2, 3)
        msgs = [_hb(t, seq=seq)]
        seq += 1
        batt_mv = 0 if t < 2.4 else 25420
        msgs.append(_env(t, "SYS_STATUS", seq=seq, voltage_battery=batt_mv, battery_remaining=100))
        seq += 1
        baro = 0.0 if t < 9.2 else 584.08
        msgs.append(_env(t, "VFR_HUD", seq=seq, groundspeed=0.0, heading=0, throttle=0, alt=baro, climb=0.0))
        seq += 1
        if t < 9.2:
            msgs.append(_raw(t, 0, 0, seq=seq))
            seq += 1
            msgs.append(_gpi(t, 0.0, 0.0, seq=seq, alt_mm=0))
            seq += 1
        else:
            msgs.append(_raw(t, 3, 10, seq=seq))
            seq += 1
            msgs.append(_gpi(t, -35.363261, 149.165230, seq=seq))
            seq += 1
        asmt = pipe.process_tick(TelemetryTick(t=t, tick=k * 2, messages=msgs))
        if asmt is not None and asmt.is_alert:
            alerts.append(asmt)
    assert alerts == [], [f"t={a.t}: {a.attack_type.value} {a.evidence}" for a in alerts]
