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
