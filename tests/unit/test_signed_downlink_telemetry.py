"""A vehicle whose own downlink is unsigned must not go blind once a signing key is configured.

Found on the real Pixhawk 6X bench (ArduCopter over USB, which is exempt from signing): with a key set, the verifying parser's
PX4 id allowlist dropped every unsigned GLOBAL_POSITION_INT / SYS_STATUS / ATTITUDE, so a +40 m altitude forgery raised no
alert on the signed link while the same forgery was detected in 0.2 s on the unsigned one."""

from __future__ import annotations

import os

os.environ.setdefault("MAVLINK20", "1")

from pymavlink.dialects.v20 import common as mv  # noqa: E402

from aegisflight.hal.inline_ips import InlineIpsBridge  # noqa: E402
from aegisflight.sources.mavlink_live import MavlinkFrameParser  # noqa: E402

KEY = bytes(range(32))
WRONG_KEY = bytes(range(1, 33))


class _Sink:
    def __init__(self) -> None:
        self.buf = b""

    def write(self, data: bytes) -> None:
        self.buf += bytes(data)


def _telemetry(sysid: int, key: bytes | None = None) -> bytes:
    sink = _Sink()
    m = mv.MAVLink(sink, srcSystem=sysid, srcComponent=1)
    if key is not None:
        m.signing.secret_key = key
        m.signing.sign_outgoing = True
        m.signing.link_id = 0
        m.signing.timestamp = 1
    m.global_position_int_send(1000, 0, 0, 10000, 5000, 0, 0, 0, 0)
    m.sys_status_send(0, 0, 0, 500, 15100, -1, 90, 0, 0, 0, 0, 0, 0)
    m.attitude_send(1000, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
    return sink.buf


def _names(parser: MavlinkFrameParser, data: bytes) -> list[str]:
    return [e.msgname for e in parser.parse(data, 0.0)]


def test_unsigned_vehicle_telemetry_is_dropped_by_default_once_a_key_is_set() -> None:
    p = MavlinkFrameParser(secret_key=KEY)
    assert _names(p, _telemetry(1)) == []
    assert p.stats.sig_invalid == 3


def test_unsigned_vehicle_telemetry_reaches_the_detectors_when_its_sysid_is_allowed() -> None:
    p = MavlinkFrameParser(secret_key=KEY, unsigned_allowed_sysids=frozenset({1}))
    assert _names(p, _telemetry(1)) == ["GLOBAL_POSITION_INT", "SYS_STATUS", "ATTITUDE"]
    assert p.stats.sig_invalid == 0


def test_unsigned_frames_from_any_other_sysid_are_still_dropped() -> None:
    p = MavlinkFrameParser(secret_key=KEY, unsigned_allowed_sysids=frozenset({1}))
    assert _names(p, _telemetry(255)) == []
    assert p.stats.sig_invalid == 3


def test_a_claimed_signature_is_still_verified_for_an_allowed_sysid() -> None:
    p = MavlinkFrameParser(secret_key=KEY, unsigned_allowed_sysids=frozenset({1}))
    assert _names(p, _telemetry(1, key=WRONG_KEY)) == []
    assert p.stats.sig_invalid == 3
    q = MavlinkFrameParser(secret_key=KEY, unsigned_allowed_sysids=frozenset({1}))
    assert _names(q, _telemetry(1, key=KEY)) == ["GLOBAL_POSITION_INT", "SYS_STATUS", "ATTITUDE"]
    assert q.stats.sig_valid == 3


def test_default_without_a_key_is_unchanged() -> None:
    p = MavlinkFrameParser()
    assert _names(p, _telemetry(1)) == ["GLOBAL_POSITION_INT", "SYS_STATUS", "ATTITUDE"]


def test_the_bridge_analyser_allows_its_vehicle_sysids(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """The bridge hands its analyser source the configured vehicle sysids (default 1), and only those."""
    import aegisflight.hal.inline_ips as ips

    seen: dict[str, object] = {}

    class _FakeSource:
        def __init__(self, *_a: object, **kw: object) -> None:
            seen.update(kw)

        def stream(self):  # type: ignore[no-untyped-def]
            return iter(())

    class _Null:
        port = "socket://x"

        def send(self, _data: bytes) -> bool:
            return True

        def recv(self, *_a: object, **_k: object) -> bytes:
            return b""

        def close(self) -> None:
            pass

    monkeypatch.setattr(ips, "LiveMavlinkSource", _FakeSource)
    bridge = InlineIpsBridge(_Null(), _Null(), mode="passive", secret_key=KEY)  # type: ignore[arg-type]
    bridge._analyse_loop()
    assert seen["secret_key"] == KEY
    assert seen["unsigned_allowed_sysids"] == frozenset({1})


# --------------------------------------------------------------------------- #
# review M8 / X1: once the vehicle has been seen signing, an unsigned frame claiming its sysid is a forgery
# --------------------------------------------------------------------------- #


def _signed_stream(sysid: int, n: int, key: bytes = KEY) -> list[bytes]:
    sink = _Sink()
    m = mv.MAVLink(sink, srcSystem=sysid, srcComponent=1)
    m.signing.secret_key = key
    m.signing.sign_outgoing = True
    m.signing.link_id = 0
    m.signing.timestamp = 1
    out = []
    for k in range(n):
        sink.buf = b""
        m.attitude_send(1000 + k, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
        out.append(sink.buf)
    return out


def _forged_position(sysid: int = 1) -> bytes:
    sink = _Sink()
    m = mv.MAVLink(sink, srcSystem=sysid, srcComponent=1)
    m.global_position_int_send(1000, 0, 0, 50000, 45000, 0, 0, 0, 0)  # +40 m: what the attacker wants believed
    return sink.buf


def test_an_unsigned_vehicle_frame_is_dropped_once_that_source_has_been_seen_signing() -> None:
    p = MavlinkFrameParser(secret_key=KEY, unsigned_allowed_sysids=frozenset({1}))
    for i, f in enumerate(_signed_stream(1, 20)):
        assert _names_at(p, f, i * 0.1) == ["ATTITUDE"]
    assert _names_at(p, _forged_position(), 2.1) == []
    assert p.stats.sig_invalid == 1


def test_a_vehicle_that_never_signed_stays_exempt() -> None:
    p = MavlinkFrameParser(secret_key=KEY, unsigned_allowed_sysids=frozenset({1}))
    for i in range(30):
        assert _names_at(p, _forged_position(), i * 0.1) == ["GLOBAL_POSITION_INT"]


def test_a_vehicle_that_stops_signing_is_not_blacked_out_after_the_lapse() -> None:
    p = MavlinkFrameParser(secret_key=KEY, unsigned_allowed_sysids=frozenset({1}))
    for i, f in enumerate(_signed_stream(1, 25)):
        _names_at(p, f, i * 0.1)
    assert _names_at(p, _forged_position(), 5.0) == []          # 2.6 s after the last signed frame: forgery
    assert _names_at(p, _forged_position(), 13.0) == ["GLOBAL_POSITION_INT"]  # > 10 s of no signed frame: lapse
    assert p.signing_lapses == 1


def _names_at(parser: MavlinkFrameParser, data: bytes, t: float) -> list[str]:
    return [e.msgname for e in parser.parse(data, t)]


class _Link:
    connected = True

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


def _run_bridge(mode: str):  # type: ignore[no-untyped-def]
    fc, gcs = _Link(), _Link()
    b = InlineIpsBridge(fc, gcs, mode=mode, secret_key=KEY, crossend_interval_s=0, mgmt_status_interval_s=0)  # type: ignore[arg-type]
    for i, f in enumerate(_signed_stream(1, 25)):
        fc.inbox.append((1_000_000_000 + i * 100_000_000, f))
    fc.inbox.append((4_000_000_000, _forged_position()))
    while fc.inbox:
        b.pump_once()
    analyser = MavlinkFrameParser(secret_key=KEY, unsigned_allowed_sysids=frozenset(b.policy.vehicle_sysids))
    ingested = [e.msgname for stamp, data in b.tap.poll() for e in analyser.parse(data, stamp / 1e9)]
    return b, gcs, ingested


def test_end_to_end_a_forged_unsigned_vehicle_frame_is_reported_and_not_ingested_in_every_posture() -> None:
    for mode in ("passive", "advisory", "active-ips"):
        b, gcs, ingested = _run_bridge(mode)
        obs = b.policy.observed_stats()
        assert obs["forged_down_observed"] + obs["forged_down_dropped"] == 1, mode
        assert "GLOBAL_POSITION_INT" not in ingested and ingested.count("ATTITUDE") == 25, mode
        forged_reached_gcs = any(f == _forged_position() for f in gcs.sent)
        assert forged_reached_gcs is (mode != "active-ips"), mode  # only active-ips may drop the vehicle's downlink


def test_active_ips_does_not_black_out_a_vehicle_that_stops_signing() -> None:
    # X1: 25 signed frames, then the FC's signing is turned off; after the 10 s lapse its telemetry flows again, loudly
    fc, gcs = _Link(), _Link()
    b = InlineIpsBridge(fc, gcs, mode="active-ips", secret_key=KEY, crossend_interval_s=0, mgmt_status_interval_s=0)  # type: ignore[arg-type]
    for i, f in enumerate(_signed_stream(1, 25)):
        fc.inbox.append((1_000_000_000 + i * 100_000_000, f))
    fc.inbox.append((5_000_000_000, _forged_position()))   # 1.6 s after the last signed frame: still a forgery
    fc.inbox.append((15_000_000_000, _forged_position()))  # 11.6 s: the source no longer counts as signing
    while fc.inbox:
        b.pump_once()
    assert b.policy.dropped_forged_down == 1 and b.policy.signing_lapsed == 1
    assert sum(f == _forged_position() for f in gcs.sent) == 1
