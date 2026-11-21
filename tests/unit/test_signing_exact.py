"""Golden-vector tests for MAVLink 2 signing, written against an independent reference.

The MAC, CRC and trailer layout are recomputed here straight from the MAVLink 2 specification (SHA-256 over key, frame,
link id and timestamp; X.25 CRC with the message's CRC_EXTRA), so a one-character change in `mavlink/signing.py` that the
behavioural tests would tolerate is caught here. The key is a throwaway test value.
"""

from __future__ import annotations

import hashlib
import struct
import time

import pytest
from pymavlink.dialects.v20 import common as mav2
from pymavlink.generator.mavcrc import x25crc

from aegisflight.mavlink import signing as sg
from aegisflight.mavlink.signing import (
    MAVLINK_EPOCH_UNIX_S,
    MavlinkSignatureVerifier,
    SignatureCheckResult,
    compute_mavlink2_mac,
    sign_mavlink2_frame,
    x25_crc,
)

KEY = bytes(range(32))
KEY_ERR = "MAVLink 2 secret_key must be exactly 32 bytes"


def reference_mac(key: bytes, frame: bytes, link_id: int, ts: int) -> bytes:
    return hashlib.sha256(key + frame + bytes([link_id]) + ts.to_bytes(6, "little")).digest()[:6]


def packed(msg_fn, *args, sysid: int = 1, comp: int = 1, seq: int = 7) -> bytes:
    m = mav2.MAVLink(None, srcSystem=sysid, srcComponent=comp)
    m.seq = seq
    return bytes(msg_fn(*args).pack(m))


def heartbeat(**kw) -> bytes:
    return packed(mav2.MAVLink_heartbeat_message, 2, 3, 0x81, 0, 4, 3, **kw)


def synthetic(msgid: int, payload: bytes = b"\x01\x02\x03", incompat: int = 0, crc: bytes = b"\xaa\xbb",
              sysid: int = 9, comp: int = 8) -> bytes:
    hdr = bytes([0xFD, len(payload), incompat, 0, 5, sysid, comp, msgid & 0xFF, (msgid >> 8) & 0xFF, msgid >> 16])
    return hdr + payload + crc


# -- X.25 CRC ------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("data", [b"", b"123456789", bytes(range(256)), bytearray(b"mavlink"), memoryview(b"abc"), [1, 2, 3]])
def test_x25_crc_matches_pymavlink_for_every_input_type(data) -> None:
    ref = x25crc()
    ref.accumulate(bytes(data))
    assert x25_crc(data) == ref.crc


def test_x25_crc_chains_through_initial() -> None:
    whole = x25_crc(b"hello world")
    first = x25_crc(b"hello ")
    assert x25_crc(b"world", initial=first) == whole
    assert x25_crc(b"world", initial=0x1234) == x25_crc(b"world", initial=0x1234) != x25_crc(b"world")
    assert x25_crc(b"", initial=0xBEEF) == 0xBEEF


# -- MAC -----------------------------------------------------------------------------------------------------------------

def test_mac_matches_the_specification_and_masks_the_timestamp_to_48_bits() -> None:
    frame = heartbeat()
    for link, ts in [(0, 1), (3, 0xABCDEF123456), (255, 2**47 + 5), (0, 2**48 + 9)]:
        assert compute_mavlink2_mac(KEY, frame, link, ts) == reference_mac(KEY, frame, link, ts & (2**48 - 1))
    assert compute_mavlink2_mac(KEY, frame, 0x1FF, 5) == reference_mac(KEY, frame, 0xFF, 5)  # link id is one byte


@pytest.mark.parametrize("bad", [b"", bytes(31), bytes(33)])
def test_every_entry_point_refuses_a_wrong_length_key_with_the_same_message(bad: bytes) -> None:
    with pytest.raises(ValueError, match=f"^{KEY_ERR}$"):
        compute_mavlink2_mac(bad, b"x", 0, 0)
    with pytest.raises(ValueError, match=f"^{KEY_ERR}$"):
        sign_mavlink2_frame(heartbeat(), bad)
    with pytest.raises(ValueError, match=f"^{KEY_ERR}$"):
        MavlinkSignatureVerifier(bad)


# -- signing -------------------------------------------------------------------------------------------------------------

def test_signed_frame_layout_is_byte_exact() -> None:
    raw = heartbeat()
    plen = raw[1]
    out = sign_mavlink2_frame(raw, KEY, link_id=2, timestamp_10us=0x0102030405)
    body = bytearray(raw[: 10 + plen + 2])
    body[2] |= 1
    crc_in = bytes(body[1 : 10 + plen]) + bytes([mav2.MAVLink_heartbeat_message.crc_extra])
    ref = x25crc()
    ref.accumulate(crc_in)
    body[10 + plen : 12 + plen] = struct.pack("<H", ref.crc)
    expect = bytes(body) + bytes([2]) + (0x0102030405).to_bytes(6, "little") + reference_mac(KEY, bytes(body), 2, 0x0102030405)
    assert out == expect and len(out) == len(raw) + 13


def test_default_link_id_is_zero_and_other_incompat_bits_are_kept() -> None:
    raw = bytearray(heartbeat())
    raw[2] = 0x02
    out = sign_mavlink2_frame(bytes(raw), KEY, timestamp_10us=5)
    assert out[2] == 0x03 and out[10 + out[1] + 2] == 0  # |= keeps bit 1, and the link id defaults to 0


def test_a_message_id_above_16_bits_is_composed_from_all_three_bytes() -> None:
    # msgid 0x010100 | 76 is unknown, so the original CRC must survive; a wrongly composed id (76) would recompute it
    out = sign_mavlink2_frame(synthetic(0x010100 | 76), KEY, timestamp_10us=1)
    assert out[13:15] == b"\xaa\xbb"
    # a real message with a two-byte id has its CRC recomputed with that message's CRC_EXTRA
    raw = packed(mav2.MAVLink_open_drone_id_basic_id_message, 1, 1, b"\0" * 20, 1, 1, b"\0" * 20)
    msgid = raw[7] | raw[8] << 8
    assert msgid == 12900
    signed = sign_mavlink2_frame(raw, KEY, timestamp_10us=1)
    plen = raw[1]
    body = bytearray(raw[: 12 + plen])
    body[2] |= 1
    ref = x25crc()
    ref.accumulate(bytes(body[1 : 10 + plen]) + bytes([mav2.mavlink_map[12900].crc_extra]))
    assert signed[10 + plen : 12 + plen] == struct.pack("<H", ref.crc)


def test_explicit_crc_extra_overrides_the_lookup() -> None:
    out = sign_mavlink2_frame(synthetic(0x7FFF00 | 1), KEY, timestamp_10us=1, crc_extra=0x55)
    ref = x25crc()
    body = bytearray(synthetic(0x7FFF00 | 1)[:13])
    body[2] |= 1
    ref.accumulate(bytes(body[1:13]) + bytes([0x55]))
    assert out[13:15] == struct.pack("<H", ref.crc)
    # an explicit extra wins over the table even for a known message
    known = sign_mavlink2_frame(heartbeat(), KEY, timestamp_10us=1, crc_extra=0x11)
    default = sign_mavlink2_frame(heartbeat(), KEY, timestamp_10us=1)
    hb_plen = heartbeat()[1]
    assert known[10 + hb_plen : 12 + hb_plen] != default[10 + hb_plen : 12 + hb_plen]


def test_sign_rejects_malformed_frames_with_specific_messages() -> None:
    with pytest.raises(ValueError, match="^raw_frame must be a valid MAVLink v2 frame starting with 0xFD$"):
        sign_mavlink2_frame(b"\xfe" + heartbeat()[1:], KEY)
    with pytest.raises(ValueError, match="^raw_frame must be a valid MAVLink v2 frame starting with 0xFD$"):
        sign_mavlink2_frame(synthetic(0, b"")[:11], KEY)  # one byte short of the 12-byte minimum
    assert len(sign_mavlink2_frame(synthetic(0, b""), KEY, timestamp_10us=1)) == 12 + 13  # exactly the minimum is fine
    with pytest.raises(ValueError, match="^Truncated MAVLink v2 frame$"):
        sign_mavlink2_frame(heartbeat()[:-1], KEY)
    with pytest.raises(ValueError, match="^Truncated MAVLink v2 frame$"):
        sign_mavlink2_frame(synthetic(0, b"\x01" * 5)[:-1], KEY)


def test_default_timestamp_is_wall_clock_in_10us_since_the_mavlink_epoch(monkeypatch: pytest.MonkeyPatch) -> None:
    before = (time.time() - MAVLINK_EPOCH_UNIX_S) * 100_000
    ts = int.from_bytes(sign_mavlink2_frame(heartbeat(), KEY)[-12:-6], "little")
    after = (time.time() - MAVLINK_EPOCH_UNIX_S) * 100_000
    assert before - 1 <= ts <= after + 1
    monkeypatch.setattr(sg.time, "time", lambda: float(MAVLINK_EPOCH_UNIX_S) - 50.0)  # a clock before the epoch clamps to 0
    assert int.from_bytes(sign_mavlink2_frame(heartbeat(), KEY)[-12:-6], "little") == 0
    monkeypatch.setattr(sg.time, "time", lambda: float(MAVLINK_EPOCH_UNIX_S) + 12.5)
    assert int.from_bytes(sign_mavlink2_frame(heartbeat(), KEY)[-12:-6], "little") == 1_250_000


# -- verifier: transmit side ---------------------------------------------------------------------------------------------

def test_verifier_starts_clean_and_tracks_a_strictly_monotonic_transmit_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sg.time, "time", lambda: float(MAVLINK_EPOCH_UNIX_S) + 10.0)
    v = MavlinkSignatureVerifier(KEY)
    assert (v.valid_count, v.invalid_count, v.replay_count) == (0, 0, 0) and v._last_timestamps == {}
    assert v._tx_timestamp_10us == 1_000_000
    stamps = []
    for _ in range(3):  # the clock is frozen, so every stamp must still advance by exactly one tick
        out = v.sign_frame(heartbeat())
        stamps.append(int.from_bytes(out[-12:-6], "little"))
    assert stamps == [1_000_001, 1_000_002, 1_000_003]
    out = v.sign_frame(heartbeat(), link_id=4, timestamp_10us=5_000_000)
    assert int.from_bytes(out[-12:-6], "little") == 5_000_000 and out[-13] == 4 and v._tx_timestamp_10us == 5_000_000
    v.sign_frame(heartbeat(), timestamp_10us=10)  # an older explicit stamp never moves the clock backwards
    assert v._tx_timestamp_10us == 5_000_000
    assert int.from_bytes(v.sign_frame(heartbeat())[-12:-6], "little") == 5_000_001
    assert v.sign_frame(heartbeat(), timestamp_10us=77) == sign_mavlink2_frame(heartbeat(), KEY, link_id=0, timestamp_10us=77)


def test_transmit_clock_clamps_a_pre_epoch_clock_to_one_second(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sg.time, "time", lambda: 0.0)
    v = MavlinkSignatureVerifier(KEY)
    assert v._tx_timestamp_10us == 100_000
    assert int.from_bytes(v.sign_frame(heartbeat())[-12:-6], "little") == 100_001


# -- verifier: receive side ----------------------------------------------------------------------------------------------

def result(**kw) -> SignatureCheckResult:
    return SignatureCheckResult(**kw)


def test_verify_results_are_exact_for_every_failure_and_success_path() -> None:
    v = MavlinkSignatureVerifier(KEY)
    # malformed: too short (11 bytes), wrong magic
    short = synthetic(0, b"")[:11]
    assert v.verify_frame(short) == result(valid=False, signed=False, replayed=False, reason="malformed_header")
    assert v.invalid_count == 1
    assert v.verify_frame(b"\xfe" + heartbeat()[1:]).reason == "malformed_header" and v.invalid_count == 2
    # exactly 12 bytes is a well-formed (unsigned) frame
    assert v.verify_frame(synthetic(0, b"")).reason == "unsigned_allowed" and v.invalid_count == 2
    # unsigned and allowed (heartbeat), unsigned and refused
    hb = heartbeat(sysid=3, comp=4)
    assert v.verify_frame(hb) == result(valid=True, signed=False, replayed=False, reason="unsigned_allowed",
                                        sysid=3, compid=4, msgid=0)
    cmd = packed(mav2.MAVLink_command_long_message, 1, 1, 400, 0, 1, 0, 0, 0, 0, 0, 0, sysid=6, comp=7)
    assert v.verify_frame(cmd) == result(valid=False, signed=False, replayed=False, reason="unsigned_frame",
                                         sysid=6, compid=7, msgid=76)
    assert (v.valid_count, v.invalid_count) == (0, 3)
    # truncated signature
    good = sign_mavlink2_frame(cmd, KEY, link_id=1, timestamp_10us=100)
    assert v.verify_frame(good[:-1]) == result(valid=False, signed=True, replayed=False, reason="truncated_signature",
                                               sysid=6, compid=7, msgid=76)
    assert v.invalid_count == 4
    # MAC mismatch (a flipped payload bit, and a wrong key)
    tampered = bytearray(good)
    tampered[11] ^= 1
    assert v.verify_frame(bytes(tampered)) == result(valid=False, signed=True, replayed=False, reason="mac_mismatch",
                                                     sysid=6, compid=7, msgid=76, link_id=1, timestamp_10us=100)
    assert v.invalid_count == 5
    assert MavlinkSignatureVerifier(bytes(range(1, 33))).verify_frame(good).reason == "mac_mismatch"
    # valid, then the same stamp again (replay), then an older one, then a newer one
    assert v.verify_frame(good) == result(valid=True, signed=True, replayed=False, reason="ok",
                                          sysid=6, compid=7, msgid=76, link_id=1, timestamp_10us=100)
    assert (v.valid_count, v.invalid_count, v.replay_count) == (1, 5, 0)
    assert v.verify_frame(good) == result(valid=False, signed=True, replayed=True,
                                          reason="replay_timestamp_non_monotonic",
                                          sysid=6, compid=7, msgid=76, link_id=1, timestamp_10us=100)
    assert (v.valid_count, v.invalid_count, v.replay_count) == (1, 6, 1)
    older = sign_mavlink2_frame(cmd, KEY, link_id=1, timestamp_10us=99)
    assert v.verify_frame(older).replayed is True and v.replay_count == 2
    newer = sign_mavlink2_frame(cmd, KEY, link_id=1, timestamp_10us=101)
    assert v.verify_frame(newer).valid and v.valid_count == 2
    # streams are independent per (link, sysid, compid)
    other_link = sign_mavlink2_frame(cmd, KEY, link_id=2, timestamp_10us=1)
    assert v.verify_frame(other_link).valid
    v.reset()
    assert (v.valid_count, v.invalid_count, v.replay_count) == (0, 0, 0) and v._last_timestamps == {}
    assert v.verify_frame(good).valid  # a reset forgets the stream


def test_message_ids_spanning_three_bytes_are_reported_exactly() -> None:
    v = MavlinkSignatureVerifier(KEY, unsigned_allowed_msgids=frozenset({0x030201}))
    assert v.verify_frame(synthetic(0x030201)).msgid == 0x030201 and v.verify_frame(synthetic(0x030201)).valid
    assert v.verify_frame(synthetic(0x030200)).valid is False
    signed = sign_mavlink2_frame(synthetic(0x010203), KEY, link_id=0, timestamp_10us=5)
    assert v.verify_frame(signed).msgid == 0x010203


def test_a_signed_frame_with_the_signed_flag_alone_is_judged_signed() -> None:
    v = MavlinkSignatureVerifier(KEY)
    raw = bytearray(heartbeat())
    raw[2] = 0x02  # an unrelated incompat bit is not the signed flag
    assert v.verify_frame(bytes(raw)).signed is False
    raw[2] = 0x03
    assert v.verify_frame(bytes(raw)).signed is True


def _stream_frame(link: int, sysid: int, ts: int) -> bytes:
    return sign_mavlink2_frame(heartbeat(sysid=sysid), KEY, link_id=link, timestamp_10us=ts)


def test_stream_table_is_bounded_at_1024_and_evicts_only_for_new_streams() -> None:
    v = MavlinkSignatureVerifier(KEY)
    for i in range(1023):
        assert v.verify_frame(_stream_frame(i % 256, i // 256 + 1, 10)).valid
    assert len(v._last_timestamps) == 1023
    oldest = next(iter(v._last_timestamps))
    # one slot left: a new stream is added without evicting anything
    assert v.verify_frame(_stream_frame(0, 100, 10)).valid
    assert len(v._last_timestamps) == 1024 and oldest in v._last_timestamps
    # the table is full: a new stream evicts exactly the oldest entry
    assert v.verify_frame(_stream_frame(1, 100, 10)).valid
    assert len(v._last_timestamps) == 1024 and oldest not in v._last_timestamps
    keys = set(v._last_timestamps)
    # a known stream advancing at a full table evicts nothing
    survivor = next(iter(v._last_timestamps))
    assert v.verify_frame(_stream_frame(survivor[0], survivor[1], 20)).valid
    assert set(v._last_timestamps) == keys and v._last_timestamps[survivor] == 20
    # the evicted stream is accepted again, as a new one
    assert v.verify_frame(_stream_frame(oldest[0], oldest[1], 5)).valid


def test_high_bit_timestamps_survive_signing_and_verification() -> None:
    ts = 2**47 + 12345  # needs all 48 bits: a signed 6-byte encoding would overflow
    signed = sign_mavlink2_frame(heartbeat(), KEY, timestamp_10us=ts)
    assert int.from_bytes(signed[-12:-6], "little") == ts
    res = MavlinkSignatureVerifier(KEY).verify_frame(signed)
    assert res.valid and res.timestamp_10us == ts


def test_transmit_clock_follows_wall_time_when_it_runs_ahead_of_the_counter(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = [float(MAVLINK_EPOCH_UNIX_S) + 10.0]
    monkeypatch.setattr(sg.time, "time", lambda: clock[0])
    v = MavlinkSignatureVerifier(KEY)
    assert int.from_bytes(v.sign_frame(heartbeat())[-12:-6], "little") == 1_000_001
    clock[0] += 20.0
    assert int.from_bytes(v.sign_frame(heartbeat())[-12:-6], "little") == 3_000_000
