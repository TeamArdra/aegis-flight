"""Regression tests for Batch 2 mitigation controller & inline policy safety audit fixes.

Covers:
- mitigation-1: GCS_TAKEOVER / ack_takeover must deactivate FrameSanitizer and clear stale latches.
- mitigation-2: Command-injection RESTORE must not fight pilot RC takeover (GCS_TAKEOVER).
- mitigation-4: Unsigned _replay_filter must not drop constant streaming control frames across seq wraparound.
- mitigation-5: Flooding 256+ untrusted (sysid, compid) heartbeats must not evict trusted GCS SeqProvenance.
"""

from __future__ import annotations

import struct

from pymavlink.dialects.v20 import common as mav2

from aegisflight.core.enums import AttackType, IntegrityStatus, Severity
from aegisflight.core.types import TelemetrySnapshot, ThreatAssessment
from aegisflight.features.extractor import CommandEvent, FeatureFrame
from aegisflight.mitigation.controller import MitigationController
from aegisflight.mitigation.inline_policy import (
    MAV_CMD_DO_SET_MODE,
    MAV_CMD_NAV_RETURN_TO_LAUNCH,
    InlinePolicy,
)
from aegisflight.mitigation.types import DefenseMode, MitigationState
from aegisflight.proxy.hooks import FrameContext
from aegisflight.proxy.transport import split_frames


class _Clock:
    def __init__(self, t: float = 100.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def _snap(
    t: float,
    *,
    lat: float = 18.9220,
    lon: float = 72.8347,
    alt: float = 25.0,
    flight_mode: str = "AUTO",
    armed: bool = True,
) -> TelemetrySnapshot:
    return TelemetrySnapshot(
        t=t,
        lat=lat,
        lon=lon,
        alt_msl=alt,
        rel_alt=alt,
        vx=0.0,
        vy=5.0,
        vz=0.0,
        groundspeed=5.0,
        roll=0.0,
        pitch=0.0,
        yaw=0.0,
        heading=90.0,
        flight_mode=flight_mode,
        armed=armed,
        battery_remaining=90.0,
    )


def _frame(
    snap: TelemetrySnapshot,
    *,
    pos_residual_m: float = 0.0,
    commands: list[CommandEvent] | None = None,
) -> FeatureFrame:
    return FeatureFrame(
        autopilot_id=3,
        mav_type=2,
        t=snap.t,
        snapshot=snap,
        gps_seen=True,
        gps_raw_seen=True,
        heartbeat_seen=True,
        msg_rate_hz=10.0,
        pos_residual_m=pos_residual_m,
        commands_recent=commands or [],
    )


def _asmt(t: float, attack: AttackType, *, evidence: list[str] | None = None) -> ThreatAssessment:
    threat = attack != AttackType.BENIGN
    return ThreatAssessment(
        t=t,
        wall_time=t,
        threat=threat,
        threat_score=0.95 if threat else 0.0,
        severity=Severity.CRITICAL if threat else Severity.NORMAL,
        attack_type=attack,
        confidence=0.95 if threat else 0.0,
        evidence=evidence or (["synthetic attack"] if threat else []),
        detector_scores={"PHYSICS": 0.95} if threat else {},
        contributing_detectors=["PHYSICS"] if threat else [],
        integrity_status=IntegrityStatus.VALID,
        latency_ms=0.5,
        is_alert=threat,
    )


def _ctx(raw: bytes, direction: str = "up") -> FrameContext:
    fr = split_frames(raw)[0][0]
    return FrameContext(
        direction=direction,  # type: ignore[arg-type]
        raw=fr.raw,
        recv_ns=1_000_000_000,
        sysid=fr.sysid,
        compid=fr.compid,
        seq=fr.seq,
        msgid=fr.msgid,
        signed=fr.signed,
    )


def _enc(sysid: int, compid: int = 190, seq: int = 0) -> mav2.MAVLink:
    m = mav2.MAVLink(None, srcSystem=sysid, srcComponent=compid)
    m.robust_parsing = True
    m.seq = seq & 0xFF
    return m


def _gpi_frame(lat: float = 18.9250, lon: float = 72.8347, rel_alt_m: float = 25.0, seq: int = 1) -> bytes:
    m = _enc(1, 1, seq)
    return bytes(
        m.global_position_int_encode(
            10000,
            int(lat * 1e7),
            int(lon * 1e7),
            int(rel_alt_m * 1000),
            int(rel_alt_m * 1000),
            0,
            0,
            0,
            9000,
        ).pack(m)
    )


# --- mitigation-1: GCS_TAKEOVER / ack_takeover stale sanitizer deactivation ---


def test_gps_spoof_rc_takeover_clean_ticks_deactivates_sanitizer_and_stops_gpi_shift() -> None:
    """Clean ticks while in GCS_TAKEOVER must turn off FrameSanitizer so GPI is no longer shifted."""
    clock = _Clock()
    ctrl = MitigationController(mode=DefenseMode.ACTIVE_IPS)
    pol = InlinePolicy(ctrl.sanitizer, clock=clock)
    pol.set_enforce(True)

    # 1. Nominal anchor
    ctrl.step(_frame(_snap(1.0, lat=18.9220, flight_mode="AUTO")), _asmt(1.0, AttackType.BENIGN))

    # 2. GPS spoof activates sanitizer with a large latitude offset
    ctrl.step(
        _frame(_snap(2.0, lat=18.9250, flight_mode="AUTO"), pos_residual_m=300.0),
        _asmt(2.0, AttackType.GPS_SPOOFING, evidence=["horizontal position divergence > 200m"]),
    )
    ctrl.step(
        _frame(_snap(2.2, lat=18.9250, flight_mode="AUTO"), pos_residual_m=300.0),
        _asmt(2.2, AttackType.GPS_SPOOFING, evidence=["horizontal position divergence > 200m"]),
    )
    pol.touch()
    assert ctrl.sanitizer.active is True
    assert ctrl.sanitizer.sanitize_gps is True

    # Confirm InlinePolicy.down() currently shifts GLOBAL_POSITION_INT
    raw_gpi = _gpi_frame(lat=18.9250)
    shifted = pol.down(_ctx(raw_gpi, direction="down"))
    assert len(shifted) == 1 and shifted[0] != raw_gpi
    shifted_lat = struct.unpack_from("<i", shifted[0], 14)[0] / 1e7
    assert abs(shifted_lat - 18.9250) > 1e-4

    # 3. Pilot takes over via RC switch to STABILIZE -> GCS_TAKEOVER
    ctrl.step(
        _frame(_snap(2.4, lat=18.9250, flight_mode="STABILIZE"), pos_residual_m=300.0),
        _asmt(2.4, AttackType.GPS_SPOOFING, evidence=["horizontal position divergence > 200m"]),
    )
    assert ctrl.state == MitigationState.GCS_TAKEOVER

    # 4. Clean ticks arrive while in GCS_TAKEOVER: sanitizer must deactivate
    act_clean = ctrl.step(_frame(_snap(3.0, lat=18.9220, flight_mode="STABILIZE")), _asmt(3.0, AttackType.BENIGN))
    pol.touch()
    assert ctrl.state == MitigationState.GCS_TAKEOVER
    assert ctrl.sanitizer.active is False
    assert ctrl._sanitize_gps_latched is False
    assert act_clean.sanitize_gps is False

    # InlinePolicy.down() must now forward GLOBAL_POSITION_INT byte-identically
    unshifted = pol.down(_ctx(raw_gpi, direction="down"))
    assert unshifted == [raw_gpi]


def test_ack_takeover_deactivates_sanitizer_and_preserves_gps_cancellation() -> None:
    """ack_takeover must disable FrameSanitizer and stop GPI shifting while preserving IPS mode cancellation."""
    clock = _Clock()
    ctrl = MitigationController(mode=DefenseMode.ACTIVE_IPS)
    pol = InlinePolicy(ctrl.sanitizer, clock=clock)
    pol.set_enforce(True)

    # Nominal -> GPS spoof -> RC takeover
    ctrl.step(_frame(_snap(1.0, lat=18.9220, flight_mode="AUTO")), _asmt(1.0, AttackType.BENIGN))
    ctrl.step(
        _frame(_snap(2.0, lat=18.9250, flight_mode="AUTO"), pos_residual_m=300.0),
        _asmt(2.0, AttackType.GPS_SPOOFING, evidence=["horizontal position divergence > 200m"]),
    )
    ctrl.step(
        _frame(_snap(2.2, lat=18.9250, flight_mode="STABILIZE"), pos_residual_m=300.0),
        _asmt(2.2, AttackType.GPS_SPOOFING, evidence=["horizontal position divergence > 200m"]),
    )
    pol.touch()
    assert ctrl.state == MitigationState.GCS_TAKEOVER
    assert ctrl.sanitizer.active is True

    # Pilot acknowledges takeover -> NOMINAL, sanitizer off, IPS mode commands stay cancelled
    act_ack = ctrl.manual_override("ack_takeover")
    pol.touch()
    assert act_ack.state == MitigationState.NOMINAL
    assert ctrl.state == MitigationState.NOMINAL
    assert ctrl.sanitizer.active is False
    assert ctrl._sanitize_gps_latched is False
    assert ctrl._gps_cancelled is True
    assert ctrl._safe_hold_alt_hold_sent is True

    raw_gpi = _gpi_frame(lat=18.9250)
    assert pol.down(_ctx(raw_gpi, direction="down")) == [raw_gpi]

    # A subsequent GPS threat tick must emit 0 counter-commands because IPS mode commands remain cancelled
    for k in range(6):
        t = 10.0 + k * 2.0
        act_new = ctrl.step(
            _frame(_snap(t, lat=18.9280, flight_mode="AUTO"), pos_residual_m=300.0),
            _asmt(t, AttackType.GPS_SPOOFING, evidence=["horizontal position divergence > 200m"]),
        )
        assert act_new.counter_frames == []


# --- mitigation-2: Command-injection RESTORE must not fight pilot RC takeover ---


def test_command_injection_restore_stops_after_pilot_rc_takeover() -> None:
    """Once the pilot takes over via RC (STABILIZE), IPS must emit 0 RESTORE_* frames on subsequent threat ticks."""
    ctrl = MitigationController(mode=DefenseMode.ACTIVE_IPS, command_cooldown_s=0.1)

    # 1. Nominal anchor in AUTO
    ctrl.step(_frame(_snap(1.0, flight_mode="AUTO")), _asmt(1.0, AttackType.BENIGN))
    assert ctrl.golden.trusted_mode == "AUTO"

    # 2. Rogue command injection flips vehicle to GUIDED -> IPS emits RESTORE_AUTO
    rogue_cmd = [CommandEvent(recv_time=2.0, sysid=99, compid=190, command=MAV_CMD_DO_SET_MODE, params=(1.0, 4.0))]
    act1 = ctrl.step(
        _frame(_snap(2.0, flight_mode="GUIDED"), commands=rogue_cmd),
        _asmt(2.0, AttackType.COMMAND_INJECTION, evidence=["unauthorized SET_MODE command from sysid 99"]),
    )
    assert ctrl.state == MitigationState.AUTO_MITIGATING
    assert len(act1.counter_frames) == 1
    assert ctrl._last_cmd_name == "RESTORE_AUTO"

    # 3. Pilot flips RC switch to STABILIZE during ongoing command-injection threat
    act_rc = ctrl.step(
        _frame(_snap(3.0, flight_mode="STABILIZE"), commands=rogue_cmd),
        _asmt(3.0, AttackType.COMMAND_INJECTION, evidence=["unauthorized SET_MODE command from sysid 99"]),
    )
    assert ctrl.state == MitigationState.GCS_TAKEOVER
    assert act_rc.counter_frames == []

    # 4. Subsequent command-injection threat ticks (well past cooldown) emit 0 RESTORE_* frames
    for k in range(1, 6):
        t = 3.0 + k * 1.0
        act_k = ctrl.step(
            _frame(_snap(t, flight_mode="STABILIZE"), commands=rogue_cmd),
            _asmt(t, AttackType.COMMAND_INJECTION, evidence=["unauthorized SET_MODE command from sysid 99"]),
        )
        assert ctrl.state == MitigationState.GCS_TAKEOVER
        assert act_k.counter_frames == []


# --- mitigation-4: Unsigned _replay_filter exempts constant streaming control frames ---


def test_streaming_rc_override_survives_seq_wraparound_while_commands_still_blocked() -> None:
    """300+ constant RC_CHANNELS_OVERRIDE frames at 50 Hz across 8-bit seq wraparound must all forward,
    immediate back-to-back duplicates within the 2 s TTL must be dropped as replays, and replays of
    COMMAND_LONG and SET_MODE must still be dropped."""
    clock = _Clock()
    pol = InlinePolicy(clock=clock, cadence_s=0.0)
    pol.set_enforce(True)
    pol.armed = True
    pol.rel_alt_m = 30.0

    # Stream 320 identical RC_CHANNELS_OVERRIDE payloads at 50 Hz (0.02 s step; 256 frames = 5.12 s >= 2.0 s TTL)
    forwarded = 0
    for i in range(320):
        clock.t += 0.02
        m = _enc(255, 190, i)
        raw = bytes(m.rc_channels_override_encode(1, 1, 1500, 1500, 1500, 1500, 0, 0, 0, 0).pack(m))
        out = pol.up(_ctx(raw))
        assert out == [raw], f"RC_CHANNELS_OVERRIDE dropped at frame {i} (seq={i % 256})"
        forwarded += 1
    assert forwarded == 320
    assert pol.dropped_replay_unsigned == 0

    # Also verify SET_ATTITUDE_TARGET survives identical-payload seq wraparound at 50 Hz
    clock.t += 0.02
    m_att1 = _enc(255, 190, 64)
    att_raw = bytes(m_att1.set_attitude_target_encode(100, 1, 1, 0, [1.0, 0.0, 0.0, 0.0], 0.0, 0.0, 0.0, 0.5).pack(m_att1))
    assert pol.up(_ctx(att_raw)) == [att_raw]
    # Advance seq all the way around to 64 again using RC_CHANNELS_OVERRIDE at 50 Hz
    for s in range(65, 65 + 255):
        clock.t += 0.02
        m_rc = _enc(255, 190, s)
        rc = bytes(m_rc.rc_channels_override_encode(1, 1, 1500, 1500, 1500, 1500, 0, 0, 0, 0).pack(m_rc))
        assert pol.up(_ctx(rc)) == [rc]
    clock.t += 0.02
    assert pol.up(_ctx(att_raw)) == [att_raw]
    assert pol.dropped_replay_unsigned == 0

    # Untrusted RC_CHANNELS_OVERRIDE is still dropped
    m_rogue = _enc(77, 190, 1)
    rogue_rc = bytes(m_rogue.rc_channels_override_encode(1, 1, 1500, 1500, 1500, 1500, 0, 0, 0, 0).pack(m_rogue))
    assert pol.up(_ctx(rogue_rc)) == []
    assert pol.dropped_untrusted_control == 1

    # Replayed COMMAND_LONG is STILL blocked by _replay_filter (even well past 2 s)
    clock.t += 0.02
    m_cmd = _enc(255, 190, 65)
    cmd_raw = bytes(m_cmd.command_long_encode(1, 1, MAV_CMD_DO_SET_MODE, 0, 1.0, 4.0, 0, 0, 0, 0, 0).pack(m_cmd))
    assert pol.up(_ctx(cmd_raw)) == [cmd_raw]
    # Advance seq around the 8-bit ring so seq=65 is provenance-consistent again
    for s in range(66, 66 + 255):
        clock.t += 0.02
        m_hb = _enc(255, 190, s)
        pol.up(_ctx(bytes(m_hb.heartbeat_encode(6, 8, 0, 0, 4).pack(m_hb))))
    clock.t += 0.02
    assert pol.up(_ctx(cmd_raw)) == []
    assert pol.dropped_replay_unsigned == 1

    # Replayed SET_MODE is STILL blocked by _replay_filter
    clock.t += 0.02
    m_sm = _enc(255, 190, 66)
    sm_raw = bytes(m_sm.set_mode_encode(1, 1, 4).pack(m_sm))
    assert pol.up(_ctx(sm_raw)) == [sm_raw]
    for s in range(67, 67 + 255):
        clock.t += 0.02
        m_hb = _enc(255, 190, s)
        pol.up(_ctx(bytes(m_hb.heartbeat_encode(6, 8, 0, 0, 4).pack(m_hb))))
    clock.t += 0.02
    assert pol.up(_ctx(sm_raw)) == []
    assert pol.dropped_replay_unsigned == 2


def test_streaming_rc_override_back_to_back_duplicate_is_dropped_within_ttl() -> None:
    """An immediate back-to-back exact duplicate of RC_CHANNELS_OVERRIDE within the 2 s TTL must be dropped."""
    clock = _Clock()
    pol = InlinePolicy(clock=clock, cadence_s=0.0)
    pol.set_enforce(True)
    pol.armed = False  # ground: provenance does not drop duplicate seq, so _replay_filter is exercised directly

    m = _enc(255, 190, 10)
    raw = bytes(m.rc_channels_override_encode(1, 1, 1500, 1500, 1500, 1500, 0, 0, 0, 0).pack(m))
    assert pol.up(_ctx(raw)) == [raw]
    assert pol.dropped_replay_unsigned == 0

    # Immediate duplicate (0.05 s later, within 2.0 s TTL) -> dropped as unsigned replay
    clock.t += 0.05
    assert pol.up(_ctx(raw)) == []
    assert pol.dropped_replay_unsigned == 1

    # Still within 2.0 s TTL (1.5 s after original) -> dropped
    clock.t += 1.45
    assert pol.up(_ctx(raw)) == []
    assert pol.dropped_replay_unsigned == 2

    # Once >= 2.0 s has elapsed, same frame is allowed through again and refreshes its TTL
    clock.t += 0.55
    assert pol.up(_ctx(raw)) == [raw]
    assert pol.dropped_replay_unsigned == 2

    # Immediate duplicate right after refresh is dropped again
    clock.t += 0.1
    assert pol.up(_ctx(raw)) == []
    assert pol.dropped_replay_unsigned == 3


# --- mitigation-5: Untrusted heartbeat flood cannot evict trusted GCS SeqProvenance ---


def test_untrusted_heartbeat_flood_cannot_evict_trusted_gcs_seq_provenance() -> None:
    """300 throwaway untrusted (sysid, compid) heartbeats must not evict trusted GCS (sysid 255)
    from SeqProvenance, and 5/5 genuine GCS RTL commands must still forward."""
    clock = _Clock()
    pol = InlinePolicy(clock=clock, cadence_s=0.0)
    pol.set_enforce(True)
    pol.armed = True
    pol.rel_alt_m = 30.0

    # 1. Establish trusted GCS (255, 190) sequence provenance
    for seq in range(10, 15):
        m = _enc(255, 190, seq)
        hb = bytes(m.heartbeat_encode(6, 8, 0, 0, 4).pack(m))
        assert pol.up(_ctx(hb)) == [hb]
    assert (255, 190) in pol._seq and pol._seq[(255, 190)].known is True

    # 2. Flood 300 distinct throwaway untrusted (sysid, compid) heartbeats (> 256 table cap)
    for i in range(300):
        sysid = 10 + (i % 200)  # never 254 or 255
        compid = 1 + (i // 200)
        m = _enc(sysid, compid, 1)
        hb = bytes(m.heartbeat_encode(6, 8, 0, 0, 4).pack(m))
        pol.up(_ctx(hb))

    # Trusted GCS tracker must NEVER have been evicted and table must stay bounded
    assert len(pol._seq) <= 256
    assert (255, 190) in pol._seq
    assert pol._seq[(255, 190)].known is True
    assert pol._seq[(255, 190)].last == 14

    # 3. Genuine GCS (255, 190) sends 5 RTL commands with continuing sequence numbers -> 5/5 forward
    for k in range(5):
        seq = 15 + k
        m = _enc(255, 190, seq)
        rtl = bytes(
            m.command_long_encode(
                1, 1, MAV_CMD_NAV_RETURN_TO_LAUNCH, k, 0, 0, 0, 0, 0, 0, 0
            ).pack(m)
        )
        assert pol.up(_ctx(rtl)) == [rtl], f"Genuine GCS RTL #{k} was dropped!"
    assert pol.dropped_provenance == 0

    # 4. A forged RTL claiming sysid 255 with an out-of-window sequence number is still caught & dropped
    m_forged = _enc(255, 190, 200)
    forged_rtl = bytes(
        m_forged.command_long_encode(1, 1, MAV_CMD_NAV_RETURN_TO_LAUNCH, 0, 0, 0, 0, 0, 0, 0, 0).pack(m_forged)
    )
    assert pol.up(_ctx(forged_rtl)) == []
    assert pol.dropped_provenance == 1
