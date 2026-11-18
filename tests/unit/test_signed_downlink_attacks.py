"""Unauthenticated frames must not change the analyser's signing state, and the unsigned-vehicle exemption is downlink-only.

Regression tests for the security review of PR #39 (signed downlink). In-process only: no network, serial or hardware.
Keys are generated per test and never printed.

* F1: pymavlink's ``check_signature`` stores the stream timestamp BEFORE it compares the MAC. One bad-MAC frame with the
  vehicle's (link_id, sysid, compid) and a far-future timestamp made every later genuine signed frame "old"; 10 s later the
  unsigned-vehicle exemption returned and an unsigned forgery was ingested.
* F2: a garbage-MAC HEARTBEAT (msgid 0, allowlisted unsigned) was counted as a valid signature and marked the vehicle as a
  signer, so an unsigned vehicle's genuine telemetry was dropped from the detectors.
* F3: one analyser tap serves both directions; an unsigned frame claiming the vehicle sysid that arrives from the GCS side was
  ingested as vehicle telemetry under the exemption and reported nowhere.
"""

from __future__ import annotations

import os
import struct

import pytest

os.environ.setdefault("MAVLINK20", "1")

from pymavlink.dialects.v20 import common as mv  # noqa: E402

from aegisflight.hal.inline_ips import InlineIpsBridge  # noqa: E402
from aegisflight.mavlink.signing import x25_crc  # noqa: E402
from aegisflight.sources.mavlink_live import MavlinkFrameParser  # noqa: E402

VEHICLE = frozenset({1})


class _Sink:
    def __init__(self) -> None:
        self.buf = b""

    def write(self, data: bytes) -> None:
        self.buf += bytes(data)


def _enc(sysid: int, key: bytes | None = None, ts: int = 1, link: int = 0) -> tuple[mv.MAVLink, _Sink]:
    sink = _Sink()
    m = mv.MAVLink(sink, srcSystem=sysid, srcComponent=1)
    if key is not None:
        m.signing.secret_key = key
        m.signing.sign_outgoing = True
        m.signing.link_id = link
        m.signing.timestamp = ts
    return m, sink


def _unsigned_gpi(sysid: int = 1, alt_mm: int = 50000) -> bytes:
    m, s = _enc(sysid)
    m.global_position_int_send(1000, 0, 0, alt_mm, alt_mm - 5000, 0, 0, 0, 0)
    return s.buf


def _unsigned_heartbeat(sysid: int = 1) -> bytes:
    m, s = _enc(sysid)
    m.heartbeat_send(2, 3, 0, 0, 0)
    return s.buf


def _unsigned_attitude(sysid: int = 1) -> bytes:
    m, s = _enc(sysid)
    m.attitude_send(1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
    return s.buf


def _signed_attitude_stream(n: int, key: bytes, ts0: int = 1_000_000) -> list[bytes]:
    m, s = _enc(1, key=key, ts=ts0)
    out = []
    for k in range(n):
        s.buf = b""
        m.attitude_send(1000 + k, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
        out.append(s.buf)
    return out


def _garbage_signed(frame_unsigned: bytes, link_id: int, ts: int) -> bytes:
    """Signed flag set, CRC recomputed, then link_id + timestamp + a 6-byte GARBAGE MAC: what anyone without the key can send."""
    buf = bytearray(frame_unsigned)
    buf[2] |= 0x01
    plen = buf[1]
    msgid = buf[7] | buf[8] << 8 | buf[9] << 16
    crc = x25_crc(bytes(buf[1 : 10 + plen]) + bytes([mv.mavlink_map[msgid].crc_extra]))
    struct.pack_into("<H", buf, 10 + plen, crc)
    return bytes(buf) + bytes([link_id]) + (ts & 0xFFFFFFFFFFFF).to_bytes(6, "little") + b"\x00" * 6


def _names(p: MavlinkFrameParser, data: bytes, t: float) -> list[str]:
    return [e.msgname for e in p.parse(data, t)]


# --------------------------------------------------------------------------- F1


def test_one_bad_mac_far_future_frame_neither_blinds_signed_telemetry_nor_reopens_the_exemption() -> None:
    key = os.urandom(32)
    p = MavlinkFrameParser(secret_key=key, unsigned_allowed_sysids=VEHICLE)
    stream = _signed_attitude_stream(60, key)
    t = 0.0
    for f in stream[:25]:
        t += 0.1
        assert _names(p, f, t) == ["ATTITUDE"]
    # vehicle sysid / compid / link_id (visible on air), timestamp 2^48-1, garbage MAC: no key needed
    t += 0.1
    _names(p, _garbage_signed(_unsigned_attitude(1), link_id=0, ts=(1 << 48) - 1), t)
    after = 0
    for f in stream[25:]:
        t += 0.1
        after += len(_names(p, f, t))
    assert after == 35, "the bad-MAC frame advanced the stream timestamp: genuine signed frames now look old"
    assert p.stats.sig_valid == 60
    # 10.5 s after the poison the vehicle is still signing, so an unsigned frame claiming its sysid is a forgery
    assert _names(p, _unsigned_gpi(1, 90000), 2.6 + 10.5) == []
    assert p.signing_lapses == 0


def test_a_bad_mac_frame_cannot_open_a_stream_ahead_of_the_genuine_one() -> None:
    key = os.urandom(32)
    p = MavlinkFrameParser(secret_key=key, unsigned_allowed_sysids=VEHICLE)
    _names(p, _garbage_signed(_unsigned_attitude(1), link_id=0, ts=(1 << 48) - 1), 0.0)  # before any genuine frame
    accepted = sum(len(_names(p, f, 0.1 * (i + 1))) for i, f in enumerate(_signed_attitude_stream(10, key)))
    assert accepted == 10
    assert p.stats.sig_valid == 10


# --------------------------------------------------------------------------- F2


def test_garbage_mac_heartbeats_never_count_as_valid_signatures_or_mark_the_vehicle_as_signing() -> None:
    key = os.urandom(32)
    p = MavlinkFrameParser(secret_key=key, unsigned_allowed_sysids=VEHICLE)
    t = 0.0
    assert _names(p, _unsigned_gpi(1, 10000), t) == ["GLOBAL_POSITION_INT"]  # an unsigned vehicle (ArduPilot over USB)
    for k in range(20):
        t += 0.1
        _names(p, _garbage_signed(_unsigned_heartbeat(1), link_id=7, ts=10 + k), t)
    t += 0.1
    assert _names(p, _unsigned_gpi(1, 10000), t) == ["GLOBAL_POSITION_INT"]
    kept = []
    for k in range(5):  # one fake heartbeat every 9 s must not keep the vehicle's telemetry out either
        t += 9.0
        _names(p, _garbage_signed(_unsigned_heartbeat(1), link_id=7, ts=1000 + k), t)
        kept += _names(p, _unsigned_gpi(1, 10000), t + 0.05)
    assert kept == ["GLOBAL_POSITION_INT"] * 5
    assert p.stats.sig_valid == 0


def test_a_replayed_signed_heartbeat_is_not_a_valid_signature_either() -> None:
    """A genuinely signed but replayed (old timestamp) allowlisted frame passes as unsigned; it is not a valid signature."""
    key = os.urandom(32)
    p = MavlinkFrameParser(secret_key=key)
    m, s = _enc(1, key=key, ts=5_000_000)
    m.heartbeat_send(2, 3, 0, 0, 0)
    hb = s.buf
    assert _names(p, hb, 0.0) == ["HEARTBEAT"] and p.stats.sig_valid == 1
    assert _names(p, hb, 0.1) == ["HEARTBEAT"]  # PX4 allowlist: still parseable ...
    assert p.stats.sig_valid == 1  # ... but not counted as a second valid signature


# --------------------------------------------------------------------------- F3


class _Link:
    connected = True
    port = "socket://127.0.0.1:1"

    def __init__(self) -> None:
        self.inbox: list[tuple[int, bytes]] = []
        self.sent: list[bytes] = []

    def poll(self):  # type: ignore[no-untyped-def]
        out, self.inbox = self.inbox, []
        return out

    def send(self, data: bytes) -> bool:
        self.sent.append(bytes(data))
        return True

    def start(self) -> None:
        pass

    def close(self) -> None:
        pass


def _statustexts(frames: list[bytes]) -> list[str]:
    dec = mv.MAVLink(None)
    dec.robust_parsing = True
    out = []
    for f in frames:
        try:
            msg = dec.decode(bytearray(f))
        except Exception:  # noqa: BLE001 - not every frame needs to decode here
            continue
        if msg.get_type() == "STATUSTEXT":
            out.append(msg.text)
    return out


def _forged_up_texts(frames: list[bytes]) -> list[str]:
    return [t for t in _statustexts(frames) if "forged-vehicle-up" in t]


@pytest.mark.parametrize("mode", ["passive", "advisory", "active-ips"])
def test_an_unsigned_vehicle_sysid_frame_from_the_gcs_side_is_reported_and_not_ingested(mode: str) -> None:
    key = os.urandom(32)
    clock = [1000.0]
    fc, gcs = _Link(), _Link()
    b = InlineIpsBridge(fc, gcs, mode=mode, secret_key=key, crossend_interval_s=0,  # type: ignore[arg-type]
                        mgmt_status_interval_s=0, mgmt_clock=lambda: clock[0])
    genuine, forged = _unsigned_gpi(1, alt_mm=10000), _unsigned_gpi(1, alt_mm=90000)
    fc.inbox.append((1_000_000_000, genuine))   # the (unsigned) vehicle's own telemetry, FC side
    gcs.inbox.append((1_100_000_000, forged))   # the attacker's frame claiming sysid 1, GCS / radio side
    while fc.inbox or gcs.inbox:
        b.pump_once()
    tap = b.tap.poll()
    assert [bytes(d) for _s, d in tap] == [genuine, forged]  # the analyser still gets both originals
    p = MavlinkFrameParser(secret_key=key, unsigned_allowed_sysids=frozenset(b.policy.vehicle_sysids))
    ingested = [(e.msgname, e.fields["alt"]) for s, d in tap for e in p.parse(d, s / 1e9)]
    assert ingested == [("GLOBAL_POSITION_INT", 10000)]
    assert p.stats.sig_invalid == 1  # counted as a signing violation (detector evidence), as without the exemption
    assert b.status()["frames"]["forged_vehicle_up"] == 1
    # forwarding is unchanged: the uplink frame still reaches the FC byte-identically and nothing else is sent to the FC
    assert fc.sent == [forged]
    assert gcs.sent[:1] == [genuine]
    clock[0] += 2.0  # next 1 s report window: the pilot's GCS is told
    b.pump_once()
    assert fc.sent == [forged]
    assert _forged_up_texts(gcs.sent[1:]) == ["AEGIS: forged-vehicle-up sys1 x1"]


def test_without_a_key_a_gcs_side_vehicle_sysid_frame_is_still_tagged_counted_and_not_ingested() -> None:
    from aegisflight.sources.mavlink_live import GcsSideDatagram

    fc, gcs = _Link(), _Link()
    b = InlineIpsBridge(fc, gcs, mode="passive", crossend_interval_s=0, mgmt_status_interval_s=0)  # type: ignore[arg-type]
    forged = _unsigned_gpi(1, alt_mm=90000)
    gcs.inbox.append((1_100_000_000, forged))
    b.pump_once()
    tap = b.tap.poll()
    assert [type(d) for _s, d in tap] == [GcsSideDatagram] and tap[0][1] == forged
    p = MavlinkFrameParser(unsigned_allowed_sysids=frozenset(b.policy.vehicle_sysids))  # no key, as the bridge builds it
    assert [e for s, d in tap for e in p.parse(d, s / 1e9)] == [] and p.gcs_side_vehicle_frames == 1
    assert b.status()["frames"]["forged_vehicle_up"] == 1
    assert fc.sent == [forged]  # forwarded unchanged


def test_the_parser_never_ingests_or_exempts_gcs_side_datagrams() -> None:
    # imported here, not at module level: the name is absent before the F3 fix, and the F1/F2 tests must still collect
    from aegisflight.sources.mavlink_live import GcsSideDatagram

    key = os.urandom(32)
    p = MavlinkFrameParser(secret_key=key, unsigned_allowed_sysids=VEHICLE)
    gpi = _unsigned_gpi(1)
    assert GcsSideDatagram(gpi) == gpi
    assert _names(p, GcsSideDatagram(gpi), 0.0) == []
    assert p.stats.sig_invalid == 1  # verified and rejected: the exemption is not applied
    assert _names(p, gpi, 0.1) == ["GLOBAL_POSITION_INT"]  # the same bytes from the FC side keep the exemption
    assert _names(p, GcsSideDatagram(_unsigned_heartbeat(1)), 0.2) == []  # accepted by the id allowlist, still not ingested
    assert p.gcs_side_vehicle_frames == 1


# --------------------------------------------------------------------------- N1(a): signed GCS-side frames, replays


def test_f1g_a_replayed_old_signed_recording_from_the_gcs_side_does_not_mark_an_unsigned_vehicle_as_signing() -> None:
    """Re-review variant F1.g, from the GCS side: 25 genuine signed frames recorded in an earlier session (same key)."""
    from aegisflight.sources.mavlink_live import GcsSideDatagram

    key = os.urandom(32)
    p = MavlinkFrameParser(secret_key=key, unsigned_allowed_sysids=VEHICLE)
    t = 0.1
    assert _names(p, _unsigned_gpi(1, 10000), t) == ["GLOBAL_POSITION_INT"]
    for f in _signed_attitude_stream(25, key, ts0=10_000):  # tiny timestamps: recorded long ago
        t += 0.1
        assert _names(p, GcsSideDatagram(f), t) == []  # valid MAC, still never the vehicle's telemetry
    assert _names(p, _unsigned_gpi(1, 10000), t + 0.1) == ["GLOBAL_POSITION_INT"]
    assert p.stats.sig_valid == 0 and (1, 1) not in p._signed_src and p.gcs_side_vehicle_frames == 25
    assert p._mav.signing.stream_timestamps == {}  # the replay left no signing state behind


def test_a_valid_signed_vehicle_sysid_frame_from_the_gcs_side_never_changes_the_vehicle_stream() -> None:
    from aegisflight.sources.mavlink_live import GcsSideDatagram

    key = os.urandom(32)
    p = MavlinkFrameParser(secret_key=key, unsigned_allowed_sysids=VEHICLE)
    genuine = _signed_attitude_stream(10, key, ts0=1_000_000)
    ahead = _signed_attitude_stream(1, key, ts0=9_000_000)[0]  # same link/sysid/compid, timestamp far ahead, valid MAC
    assert _names(p, GcsSideDatagram(ahead), 0.0) == []
    assert sum(len(_names(p, f, 0.1 * (i + 1))) for i, f in enumerate(genuine)) == 10  # not made "old" by it
    assert p.stats.sig_valid == 10


@pytest.mark.parametrize("mode", ["passive", "advisory", "active-ips"])
def test_f1h_a_signed_recording_replayed_from_the_gcs_side_through_the_bridge_neither_blinds_nor_is_ingested(mode: str) -> None:
    """Re-review variant F1.h (GCS-side arm) through the real forwarding path, staged so that arrival order is kept."""
    key = os.urandom(32)
    fc, gcs = _Link(), _Link()
    b = InlineIpsBridge(fc, gcs, mode=mode, secret_key=key, crossend_interval_s=0, mgmt_status_interval_s=0)  # type: ignore[arg-type]
    old = _signed_attitude_stream(25, key, ts0=10_000)  # an earlier session, same key
    t = 1_000_000_000
    fc.inbox.append((t, _unsigned_gpi(1, 10000)))
    b.pump_once()
    for k, f in enumerate(old):
        gcs.inbox.append((t + (k + 1) * 50_000_000, f))
    b.pump_once()
    fc.inbox.append((t + 2_000_000_000, _unsigned_gpi(1, 10001)))
    b.pump_once()
    p = MavlinkFrameParser(secret_key=key, unsigned_allowed_sysids=frozenset(b.policy.vehicle_sysids))
    tap = b.tap.poll()
    ingested = [(e.msgname, e.fields.get("alt")) for s, d in tap for e in p.parse(d, s / 1e9)]
    assert ingested == [("GLOBAL_POSITION_INT", 10000), ("GLOBAL_POSITION_INT", 10001)]
    assert p.stats.sig_valid == 0 and b.status()["frames"]["forged_vehicle_up"] == 25
    assert fc.sent == old  # forwarded byte-identically, nothing else toward the FC


# --------------------------------------------------------------------------- N2: the announcement cannot starve status


def _scalar_messages(n: int) -> list[bytes]:
    """``n`` frames of distinct NON-control message ids (all-scalar payloads), each claiming sysid 1 / compid 1. Control ids
    are left out so that the only announcements are the forged-vehicle ones (the policy reports control frames separately)."""
    from aegisflight.mitigation.inline_policy import _COMMAND_MSGIDS, CONTROL_MSGIDS

    enc = mv.MAVLink(None, srcSystem=1, srcComponent=1)
    out = []
    for msgid in sorted(mv.mavlink_map):
        cls = mv.mavlink_map[msgid]
        if msgid == 0 or msgid in CONTROL_MSGIDS or msgid in _COMMAND_MSGIDS or any(cls.array_lengths) or "char" in cls.fieldtypes:
            continue
        out.append(bytes(cls(*([0] * len(cls.fieldnames))).pack(enc)))
        if len(out) == n:
            return out
    raise AssertionError("not enough all-scalar message types")


def test_a_30_msgid_flood_claiming_the_vehicle_sysid_does_not_starve_the_status_vector() -> None:
    from aegisflight.hal.mgmt_channel import decode_mgmt_frame
    from aegisflight.proxy.transport import split_frames

    clock = [1000.0]
    fc, gcs = _Link(), _Link()
    b = InlineIpsBridge(fc, gcs, mode="passive", secret_key=os.urandom(32), crossend_interval_s=0,  # type: ignore[arg-type]
                        mgmt_status_interval_s=2.0, mgmt_clock=lambda: clock[0], clock_ns=lambda: int(clock[0] * 1e9))
    flood = _scalar_messages(30)
    for _step in range(200):  # 20 s, 30 message types every 0.1 s (300 frames/s)
        clock[0] += 0.1
        for f in flood:
            gcs.inbox.append((int(clock[0] * 1e9), f))
        b.pump_once()
    decoded = [d for f in gcs.sent for fr in split_frames(f)[0] if (d := decode_mgmt_frame(fr.raw))]
    status = [d for d in decoded if d["kind"] == "status"]
    announce = [d["text"] for d in decoded if d["kind"] == "text" and "forged-vehicle-up" in d["text"]]
    assert b.forged_vehicle_up == 6000
    assert len(status) >= 9  # one every 2 s
    assert 1 <= len(announce) <= 10  # at most one per alert interval (2 s), aggregated over all 30 message types
    assert all(t.startswith("AEGIS: forged-vehicle-up sys1 x") for t in announce)
    assert len(fc.sent) == 6000  # forwarding unchanged


# --------------------------------------------------------------------------- N4: the tag survives the real threads


@pytest.mark.parametrize("mode", ["passive", "active-ips"])
def test_the_gcs_side_tag_survives_the_real_bridge_threads(mode: str) -> None:
    """Drives InlineIpsBridge.start(): a future coalescing or copying tap must fail here, not silently drop the tag."""
    import threading
    import time
    from types import MethodType

    class _ThreadLink(_Link):
        def __init__(self) -> None:
            super().__init__()
            self.lock = threading.Lock()

        def poll(self):  # type: ignore[no-untyped-def]
            with self.lock:
                out, self.inbox = self.inbox, []
            return out

        def send(self, data: bytes) -> bool:
            with self.lock:
                self.sent.append(bytes(data))
            return True

    key = os.urandom(32)
    fc, gcs = _ThreadLink(), _ThreadLink()
    b = InlineIpsBridge(fc, gcs, mode=mode, secret_key=key, crossend_interval_s=0, mgmt_status_interval_s=0)  # type: ignore[arg-type]
    seen: list[tuple[str, int, object]] = []
    orig = b.analyse_tick

    def _record(self, tick, _o=orig):  # type: ignore[no-untyped-def]
        seen.extend((e.msgname, e.sysid, e.fields.get("alt")) for e in tick.messages)
        return _o(tick)

    b.analyse_tick = MethodType(_record, b)  # type: ignore[method-assign]
    m, sink = _enc(1, key=key, ts=10_000)
    m.global_position_int_send(1000, 0, 0, 70000, 65000, 0, 0, 0, 0)
    gcs_side = [_unsigned_gpi(1, 90000), sink.buf,  # an unsigned forgery; a genuinely signed (replayed) frame
                _garbage_signed(_unsigned_heartbeat(1), link_id=0, ts=6)]  # a bad-MAC HEARTBEAT
    b.start()
    try:
        now = time.monotonic_ns()
        with fc.lock:
            fc.inbox.append((now, _unsigned_gpi(1, 10000)))
        with gcs.lock:
            gcs.inbox.extend((now + 1 + i, f) for i, f in enumerate(gcs_side))
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline and not any(a == 10000 for _n, _s, a in seen):
            time.sleep(0.05)
        time.sleep(0.5)  # a few more ticks: anything wrongly ingested would show up by now
    finally:
        b.close()
    assert sorted(a for n, _s, a in seen if n == "GLOBAL_POSITION_INT") == [10000]
    assert not any(n == "HEARTBEAT" for n, _s, _a in seen)
    assert b.status()["frames"]["forged_vehicle_up"] == 3
    assert fc.sent == gcs_side  # forwarded unchanged; nothing else toward the FC
