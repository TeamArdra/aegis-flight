"""Unit tests for MAVLink-2 signing under 100-500 ms link latency/jitter and clock skew."""

from __future__ import annotations

import hashlib
from pathlib import Path

from pymavlink.dialects.v20 import common as mavlink2

from aegisflight.mitigation.actuator import MavlinkActuator
from aegisflight.sources.mavlink_live import MavlinkFrameParser


def _pack_signed_hb(secret_key: bytes, *, sysid: int, compid: int, seq: int, timestamp: int) -> bytes:
    m = mavlink2.MAVLink(None, srcSystem=sysid, srcComponent=compid)
    m.signing.secret_key = secret_key
    m.signing.link_id = 0
    m.signing.timestamp = timestamp
    m.signing.sign_outgoing = True
    msg = m.heartbeat_encode(
        mavlink2.MAV_TYPE_GCS,
        mavlink2.MAV_AUTOPILOT_INVALID,
        0,
        0,
        mavlink2.MAV_STATE_ACTIVE,
    )
    msg.get_header().seq = seq & 0xFF
    return bytes(msg.pack(m))


def test_latency_jitter_and_clock_skew_zero_false_rejections() -> None:
    """100-500 ms link latency/jitter + GCS/bridge clock skew cause 0 false signing rejections."""
    secret_key = hashlib.sha256(b"gap-g-latency-skew-key").digest()
    parser = MavlinkFrameParser(secret_key=secret_key)

    # Simulate 20 frames with 100-500 ms jitter in recv_time and +300s clock skew on signing timestamp
    jitters = [0.10, 0.48, 0.12, 0.50, 0.22, 0.37, 0.15, 0.44, 0.19, 0.31] * 2
    bridge_t = 1000.0
    gcs_base_ts = 1_300_000  # skewed relative to bridge_t

    accepted = 0
    for i, jitter in enumerate(jitters):
        bridge_t += jitter
        raw = _pack_signed_hb(
            secret_key, sysid=255, compid=190, seq=i, timestamp=gcs_base_ts + i + 1
        )
        envs = parser.parse(raw, bridge_t)
        assert len(envs) == 1
        assert envs[0].signed is True
        accepted += 1

    assert accepted == 20
    assert parser.stats.sig_valid == 20
    assert parser.stats.sig_invalid == 0


def test_real_replay_blocked_and_ts_state_path_monotonic(tmp_path: Path) -> None:
    """Real replays remain blocked under jitter, and ts_state_path persists monotonic timestamps."""
    secret_key = hashlib.sha256(b"gap-g-replay-ts-state").digest()
    parser = MavlinkFrameParser(secret_key=secret_key)

    def _pack_signed_cmd(seq: int, timestamp: int) -> bytes:
        m = mavlink2.MAVLink(None, srcSystem=255, srcComponent=190)
        m.signing.secret_key = secret_key
        m.signing.link_id = 0
        m.signing.timestamp = timestamp
        m.signing.sign_outgoing = True
        msg = m.command_long_encode(1, 1, mavlink2.MAV_CMD_COMPONENT_ARM_DISARM, 0, 1, 0, 0, 0, 0, 0, 0)
        msg.get_header().seq = seq & 0xFF
        return bytes(msg.pack(m))

    f1 = _pack_signed_cmd(seq=1, timestamp=5000)
    f2 = _pack_signed_cmd(seq=2, timestamp=5001)

    assert len(parser.parse(f1, 10.10)) == 1
    assert len(parser.parse(f2, 10.55)) == 1  # +450 ms jitter
    # Replay of f1 (older timestamp) must be rejected
    assert parser.parse(f1, 10.70) == []
    assert parser.stats.sig_invalid == 1

    # Actuator ts_state_path persists monotonic timestamp across restarts
    ts_file = tmp_path / "signing.tx_ts"
    act1 = MavlinkActuator(secret_key=secret_key, ts_state_path=ts_file)
    ts1 = act1._next_timestamp() if hasattr(act1, "_next_timestamp") else None
    act1.close() if hasattr(act1, "close") else None

    act2 = MavlinkActuator(secret_key=secret_key, ts_state_path=ts_file)
    assert act2._ts_state_path == ts_file
    if ts1 is not None:
        assert act2._next_timestamp() > ts1
