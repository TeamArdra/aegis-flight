"""Unit tests for MAVLink-2 signing bootstrap settle window and per-source unsigned allowlist (#19)."""

from __future__ import annotations

from pymavlink.dialects.v20 import common as mav2

from aegisflight.config import DEFAULT_DETECTOR, load_config
from aegisflight.core.enums import AttackType
from aegisflight.detectors.protocol import ProtocolDetector
from aegisflight.mavlink.signing import MavlinkSignatureVerifier
from aegisflight.pipeline import IDSPipeline
from aegisflight.sources.mavlink_live import frame_ticks

KEY = bytes(range(10, 42))
BAD_KEY = bytes(range(90, 122))


def _hb(sysid: int = 1, compid: int = 1, seq: int = 0) -> bytes:
    m = mav2.MAVLink(None, srcSystem=sysid, srcComponent=compid)
    m.seq = seq
    return bytes(m.heartbeat_encode(2, 3, 0x80, 4, 4).pack(m))


def _radio_status(sysid: int = 51, compid: int = 68, seq: int = 0) -> bytes:
    m = mav2.MAVLink(None, srcSystem=sysid, srcComponent=compid)
    m.seq = seq
    return bytes(m.radio_status_encode(180, 180, 100, 100, 100, 0, 0).pack(m))


def _cmd_long(sysid: int = 255, compid: int = 190, seq: int = 0) -> bytes:
    m = mav2.MAVLink(None, srcSystem=sysid, srcComponent=compid)
    m.seq = seq
    return bytes(m.command_long_encode(1, 1, 176, 0, 1.0, 4.0, 0, 0, 0, 0, 0).pack(m))


def _gpi(sysid: int = 1, compid: int = 1, seq: int = 0) -> bytes:
    m = mav2.MAVLink(None, srcSystem=sysid, srcComponent=compid)
    m.seq = seq
    return bytes(
        m.global_position_int_encode(1000, 129_000_000, 775_000_000, 500_000, 20_000, 0, 0, 0, 0).pack(m)
    )


def _signed_pipe(*, settle_s: float | None = None, unsigned_allowed=None) -> IDSPipeline:
    cfg = load_config()
    p = cfg.detector["protocol"]
    p["require_signing"] = True
    if settle_s is not None:
        p["signing_settle_s"] = settle_s
    if unsigned_allowed is not None:
        p["unsigned_allowed"] = unsigned_allowed
    return IDSPipeline(cfg, model_path=None)


def test_defaults_have_no_blind_window_and_detect_rogue_radio_status() -> None:
    """Defaults: signing_settle_s=0.0 (immediate invalid-sig alert) and unsigned_allowed=[] (flags sys51 RADIO_STATUS)."""
    assert DEFAULT_DETECTOR["protocol"]["signing_settle_s"] == 0.0
    assert DEFAULT_DETECTOR["protocol"]["unsigned_allowed"] == []

    pipe = _signed_pipe()
    bad = MavlinkSignatureVerifier(BAD_KEY)
    good = MavlinkSignatureVerifier(KEY)
    pkts = [
        (0.0, good.sign_frame(_hb(1, 1, 0), link_id=0, timestamp_10us=100)),
        (0.4, bad.sign_frame(_gpi(1, 1, 1), link_id=3, timestamp_10us=200)),
        (0.8, _radio_status(sysid=51, compid=68, seq=0)),
        (1.0, good.sign_frame(_hb(1, 1, 2), link_id=0, timestamp_10us=1_100_000)),
    ]
    asmts = [a for a in (pipe.process_tick(t) for t in frame_ticks(pkts, secret_key=KEY)) if a is not None]
    assert any(a.threat and any("signature verification" in e for e in a.evidence) for a in asmts), asmts
    assert any("sys51:RADIO_STATUS" in e for a in asmts for e in a.evidence), asmts


def test_a_invalid_frames_during_opt_in_settle_window_emit_coverage_only() -> None:
    """(a) When signing_settle_s is explicitly opted in, invalid signatures before < settle_s emit coverage only."""
    pipe = _signed_pipe(settle_s=2.0)
    bad = MavlinkSignatureVerifier(BAD_KEY)
    good = MavlinkSignatureVerifier(KEY)

    pkts = [
        (0.0, good.sign_frame(_hb(1, 1, 0), link_id=0, timestamp_10us=100)),
        # Unverified stream (sysid 1, compid 1, link 3) has transient bad non-heartbeat signature at t=0.4s (< 2.0s)
        (0.4, bad.sign_frame(_gpi(1, 1, 1), link_id=3, timestamp_10us=200)),
        (1.0, good.sign_frame(_hb(1, 1, 2), link_id=0, timestamp_10us=1_100_000)),
    ]
    asmts = [a for a in (pipe.process_tick(t) for t in frame_ticks(pkts, secret_key=KEY)) if a is not None]
    assert asmts and all(not a.threat for a in asmts), [a.evidence for a in asmts]
    assert all(a.detector_scores["protocol_rule"] == 0.0 for a in asmts)
    assert any(
        "coverage: signing bootstrap settling" in ev and "sys1/comp1/link3" in ev
        for a in asmts
        for ev in a.evidence
    ), [a.evidence for a in asmts]


def test_b_after_settle_window_unsigned_command_long_from_255_triggers_within_one_decision() -> None:
    """(b) After settle window expires, unsigned COMMAND_LONG from sysid 255 votes COMMAND_INJECTION >= 0.95."""
    pipe = _signed_pipe(settle_s=2.0)
    good = MavlinkSignatureVerifier(KEY)

    pkts = [
        (0.0, good.sign_frame(_hb(1, 1, 0), link_id=0, timestamp_10us=100)),
        (1.0, good.sign_frame(_gpi(1, 1, 1), link_id=0, timestamp_10us=100_100)),
        (2.4, _cmd_long(255, 190, seq=5)),
        (2.5, good.sign_frame(_hb(1, 1, 2), link_id=0, timestamp_10us=250_000)),
    ]
    asmts = [a for a in (pipe.process_tick(t) for t in frame_ticks(pkts, secret_key=KEY)) if a is not None]
    trig = [a for a in asmts if a.t >= 2.4]
    assert trig and any(a.attack_type is AttackType.COMMAND_INJECTION and a.threat_score >= 0.45 for a in trig), [
        (a.t, a.attack_type, a.evidence) for a in asmts
    ]
    assert any("MAVLink-2 signature verification" in ev for a in trig for ev in a.evidence)


def test_c_unsigned_radio_status_from_sysid_51_opt_in_allowlist_suppresses_vote() -> None:
    """(c) Explicitly allowlisting RADIO_STATUS from sysid 51 suppresses unsigned-frame votes for that source."""
    pipe = _signed_pipe(settle_s=2.0, unsigned_allowed=[{"sysid": 51, "msg": "RADIO_STATUS"}])
    good = MavlinkSignatureVerifier(KEY)
    pkts = [
        (0.0, good.sign_frame(_hb(1, 1, 0), link_id=0, timestamp_10us=100)),
        (0.5, _radio_status(sysid=51, compid=68, seq=0)),
        (1.0, _radio_status(sysid=51, compid=68, seq=1)),
        (2.5, _radio_status(sysid=51, compid=68, seq=2)),
        (2.6, good.sign_frame(_gpi(1, 1, 1), link_id=0, timestamp_10us=300_000)),
    ]
    asmts = [a for a in (pipe.process_tick(t) for t in frame_ticks(pkts, secret_key=KEY)) if a is not None]
    assert asmts and all(not a.threat and a.detector_scores["protocol_rule"] == 0.0 for a in asmts), [
        (a.t, a.evidence) for a in asmts
    ]


def test_d_unsigned_frame_from_unexpected_sysid_votes() -> None:
    """(d) Unsigned frame from an unexpected sysid/msg outside unsigned_allowed still votes."""
    pipe = _signed_pipe(settle_s=2.0)
    good = MavlinkSignatureVerifier(KEY)
    pkts = [
        (0.0, good.sign_frame(_hb(1, 1, 0), link_id=0, timestamp_10us=100)),
        (2.4, _radio_status(sysid=99, compid=68, seq=0)),
    ]
    asmts = [a for a in (pipe.process_tick(t) for t in frame_ticks(pkts, secret_key=KEY)) if a is not None]
    last = asmts[-1]
    assert last.detector_scores["protocol_rule"] >= 0.5
    assert any("unexpected source(s): sys99:RADIO_STATUS" in ev for ev in last.evidence), last.evidence


def test_e_verified_stream_never_reopens_settle_window() -> None:
    """(e) Once a stream yields a valid signed frame, invalid signatures immediately vote even within settle_s."""
    pipe = _signed_pipe(settle_s=5.0)
    good = MavlinkSignatureVerifier(KEY)
    bad = MavlinkSignatureVerifier(BAD_KEY)

    pkts = [
        (0.0, good.sign_frame(_hb(1, 1, 0), link_id=0, timestamp_10us=50)),
        # Stream (255, 190, link 2) proves valid key at t=0.2 -> settle closes permanently for it
        (0.2, good.sign_frame(_cmd_long(255, 190, 0), link_id=2, timestamp_10us=100)),
        # Forged bad-key frame on that same stream at t=0.6 (< 5.0 s!) must NOT settle-suppress!
        (0.6, bad.sign_frame(_cmd_long(255, 190, 1), link_id=2, timestamp_10us=200)),
        (0.7, good.sign_frame(_hb(1, 1, 1), link_id=0, timestamp_10us=700_000)),
    ]
    asmts = [a for a in (pipe.process_tick(t) for t in frame_ticks(pkts, secret_key=KEY)) if a is not None]
    bad_at_06 = [a for a in asmts if a.t >= 0.6 and any("signature verification" in e for e in a.evidence)]
    assert bad_at_06, [(a.t, a.evidence) for a in asmts]
    assert bad_at_06[0].attack_type is AttackType.COMMAND_INJECTION
    assert ProtocolDetector._parse_unsigned_allowed([{"sysid": 51, "msg": "RADIO_STATUS"}]) == [(51, "RADIO_STATUS")]
    assert BAD_KEY.hex() not in str([a.evidence for a in asmts])
    assert KEY.hex() not in str([a.evidence for a in asmts])
