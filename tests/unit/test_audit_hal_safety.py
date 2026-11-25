"""Regression tests for Batch 1 HAL & Pixhawk safety audit fixes.

Covers:
1. hal-1: NaN/inf param2 on COMMAND_LONG DO_SET_MODE in drop_label() and InlineIpsBridge.pump_once().
2. hal-2: SideTapRunner with secret_key set still accepts unsigned FC telemetry from expected_sysids.
3. px_restore_mode.py: fail-closed heartbeat check before transmitting DO_SET_MODE.
"""

from __future__ import annotations

import importlib.util
import math
import time
from pathlib import Path
from typing import Any

import pytest
from pymavlink.dialects.v20 import ardupilotmega as apm
from pymavlink.dialects.v20 import common as mav2

import aegisflight.hal.inline_ips as inline_ips_mod
from aegisflight.config import load_config
from aegisflight.hal.inline_ips import InlineIpsBridge
from aegisflight.hal.mgmt_channel import MSGID_COMMAND_LONG, drop_label
from aegisflight.hal.side_tap import SideTapRunner
from aegisflight.mitigation.types import DefenseMode
from aegisflight.sources.mavlink_live import LiveMavlinkSource


def _enc(sysid: int, compid: int = 1) -> mav2.MAVLink:
    m = mav2.MAVLink(None, srcSystem=sysid, srcComponent=compid)
    m.robust_parsing = True
    return m


def _command_long(sysid: int, command: int, p1: float = 0.0, p2: float = 0.0, comp: int = 190) -> bytes:
    m = _enc(sysid, comp)
    return bytes(m.command_long_encode(1, 1, command, 0, p1, p2, 0.0, 0.0, 0.0, 0.0, 0.0).pack(m))


def _rc_override(sysid: int, comp: int = 190) -> bytes:
    m = _enc(sysid, comp)
    return bytes(m.rc_channels_override_encode(1, 1, 1500, 1500, 1500, 1500, 0, 0, 0, 0).pack(m))


class _FakeTransport:
    def __init__(self, rx_batches: list[list[tuple[int, bytes]]] | None = None) -> None:
        self._batches = list(rx_batches or [])
        self.sent: list[bytes] = []
        self.connected = True
        self.datagrams_received = 0
        self.closed = False

    def poll(self) -> list[tuple[int, bytes]]:
        if not self._batches:
            return []
        batch = self._batches.pop(0)
        self.datagrams_received += len(batch)
        return batch

    recv = poll

    def send(self, frame: bytes) -> bool:
        self.sent.append(frame)
        return True

    def close(self) -> None:
        self.closed = True


# --------------------------------------------------------------------------- #
# hal-1: NaN / inf param2 in drop_label & InlineIpsBridge.pump_once
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("bad_p2", [math.nan, math.inf, -math.inf])
def test_drop_label_handles_non_finite_do_set_mode_param2(bad_p2: float) -> None:
    raw = _command_long(66, 176, p1=1.0, p2=bad_p2)
    lbl = drop_label(raw, 66, MSGID_COMMAND_LONG, "up")
    assert lbl == "DO_SET_MODE sys66"


def test_drop_label_preserves_valid_finite_mode_name() -> None:
    raw = _command_long(66, 176, p1=1.0, p2=9.0)  # 9 = LAND
    assert drop_label(raw, 66, MSGID_COMMAND_LONG, "up") == "DO_SET_MODE(LAND) sys66"


def test_pump_once_forwards_pilot_frames_after_nan_do_set_mode_in_same_batch() -> None:
    hostile_nan = _command_long(66, 176, p1=1.0, p2=math.nan)
    pilot_mode = _command_long(255, 176, p1=1.0, p2=4.0)
    pilot_rc = _rc_override(255)

    t0 = 1_000_000_000
    fc = _FakeTransport()
    gcs = _FakeTransport([[(t0, hostile_nan), (t0 + 1_000, pilot_mode), (t0 + 2_000, pilot_rc)]])

    bridge = InlineIpsBridge(fc, gcs, mode=DefenseMode.ACTIVE_IPS)
    try:
        processed = bridge.pump_once()
        assert processed == 3
        assert bridge.dropped_up == 1
        assert bridge.forwarded_up == 2
        assert fc.sent == [pilot_mode, pilot_rc]
    finally:
        bridge.close()


def test_pump_once_survives_unexpected_drop_label_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_args: Any, **_kwargs: Any) -> str:
        raise RuntimeError("label formatter exploded")

    monkeypatch.setattr(inline_ips_mod, "drop_label", _boom)

    hostile = _command_long(66, 176, p1=1.0, p2=9.0)
    pilot_rc = _rc_override(255)

    t0 = 1_000_000_000
    fc = _FakeTransport()
    gcs = _FakeTransport([[(t0, hostile), (t0 + 1_000, pilot_rc)]])

    actions: list[tuple[Any, ...]] = []
    bridge = InlineIpsBridge(fc, gcs, mode=DefenseMode.ACTIVE_IPS)
    monkeypatch.setattr(bridge, "_log_action", lambda *a: actions.append(a))
    try:
        processed = bridge.pump_once()
        assert processed == 2
        assert bridge.dropped_up == 1
        assert bridge.forwarded_up == 1
        assert fc.sent == [pilot_rc]
        assert any(a[2] == "drop_frame" and a[4] == f"MSG{MSGID_COMMAND_LONG} sys66" for a in actions)
    finally:
        bridge.close()


# --------------------------------------------------------------------------- #
# hal-2: SideTapRunner with signing key preserves unsigned FC telemetry
# --------------------------------------------------------------------------- #


def _fc_telemetry_batch(sysid: int, base_ns: int, count: int = 12) -> list[tuple[int, bytes]]:
    m = apm.MAVLink(file=None, srcSystem=sysid, srcComponent=1)
    out: list[tuple[int, bytes]] = []
    for i in range(count):
        ts = base_ns + i * 100_000_000  # 100 ms steps
        hb = bytes(m.heartbeat_encode(2, 3, 0x81, 4, 4).pack(m))
        gpi = bytes(
            m.global_position_int_encode(
                i * 100, 190_000_000, 729_000_000, 30_000, 20_000, 100, 0, 0, 0
            ).pack(m)
        )
        att = bytes(m.attitude_encode(i * 100, 0.01, -0.02, 0.5, 0.0, 0.0, 0.0).pack(m))
        out.append((ts, hb))
        out.append((ts + 10_000_000, gpi))
        out.append((ts + 20_000_000, att))
    return out


def test_side_tap_with_secret_key_parses_unsigned_fc_telemetry() -> None:
    secret_key = b"\x42" * 32
    cfg = load_config()
    cfg.detector.setdefault("protocol", {})["expected_sysids"] = [7]

    batch = _fc_telemetry_batch(sysid=7, base_ns=time.monotonic_ns(), count=12)
    fc = _FakeTransport([batch])

    runner = SideTapRunner(fc, cfg=cfg, sample_rate_hz=10.0, secret_key=secret_key)
    runner.start()
    try:
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and (runner._source is None or runner.decisions < 2):
            time.sleep(0.02)
        assert runner._source is not None
        assert runner._source._asm.parser._unsigned_sysids == frozenset((7,))
        assert runner._source._stats.frames_received == len(batch)
        assert runner._source._stats.sig_invalid == 0
        assert runner.decisions >= 2
        assert runner.analyser_errors == 0
    finally:
        runner.close()


def test_side_tap_default_expected_sysid_falls_back_to_1_and_blocks_rogue_unsigned() -> None:
    secret_key = b"\x42" * 32
    cfg = load_config()
    cfg.detector.setdefault("protocol", {})["expected_sysids"] = []

    batch = _fc_telemetry_batch(sysid=1, base_ns=time.monotonic_ns(), count=10)
    fc = _FakeTransport([batch])

    runner = SideTapRunner(fc, cfg=cfg, sample_rate_hz=10.0, secret_key=secret_key)
    runner.start()
    try:
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and (runner._source is None or runner.decisions < 2):
            time.sleep(0.02)
        assert runner._source is not None
        assert runner._source._asm.parser._unsigned_sysids == frozenset((1,))
        assert runner._source._stats.frames_received == len(batch)
        assert runner._source._stats.sig_invalid == 0
        assert runner.decisions >= 2
    finally:
        runner.close()

    # Verify LiveMavlinkSource still rejects unsigned frames from non-expected sysid 66
    rogue_batch = _fc_telemetry_batch(sysid=66, base_ns=1_000_000_000, count=5)
    rogue_src = LiveMavlinkSource(
        _FakeTransport([rogue_batch]),
        sample_rate_hz=10.0,
        origin="start",
        secret_key=secret_key,
        unsigned_allowed_sysids=frozenset((1,)),
    )
    parsed = [env for ts, raw in rogue_batch for env in rogue_src._asm.parser.parse(raw, ts / 1e9)]
    # HEARTBEAT (msgid 0) is in PX4_UNSIGNED_ALLOWED_MSGIDS, but GLOBAL_POSITION_INT & ATTITUDE must be rejected
    assert all(env.msgname == "HEARTBEAT" for env in parsed)
    assert rogue_src._stats.sig_invalid == 10


# --------------------------------------------------------------------------- #
# px_restore_mode.py: fail-closed heartbeat check
# --------------------------------------------------------------------------- #


def _load_px_restore_mode():
    script_path = Path(__file__).resolve().parents[2] / "scripts" / "ardupilot" / "real_pixhawk" / "px_restore_mode.py"
    spec = importlib.util.spec_from_file_location("px_restore_mode", script_path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _FakeSerialPort:
    def __init__(self, rx_bytes: bytes) -> None:
        self._buf = bytearray(rx_bytes)
        self.written: list[bytes] = []

    def read(self, n: int = 1024) -> bytes:
        if not self._buf:
            return b""
        chunk = bytes(self._buf[:n])
        del self._buf[:n]
        return chunk

    def write(self, data: bytes) -> int:
        self.written.append(bytes(data))
        return len(data)


def test_px_restore_mode_fails_closed_when_no_heartbeat(monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load_px_restore_mode()
    fake = _FakeSerialPort(b"")
    monkeypatch.setattr(mod.serial, "Serial", lambda *_a, **_kw: fake)

    with pytest.raises(SystemExit, match="NO HEARTBEAT"):
        mod.main(["/dev/ttyFAKE0"], wait_sec=0.05)

    assert fake.written == []


def test_px_restore_mode_refuses_when_armed(monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load_px_restore_mode()
    m = apm.MAVLink(None, srcSystem=1, srcComponent=1)
    armed_hb = bytes(m.heartbeat_encode(2, 3, 128, 4, 4).pack(m))
    fake = _FakeSerialPort(armed_hb)
    monkeypatch.setattr(mod.serial, "Serial", lambda *_a, **_kw: fake)

    with pytest.raises(SystemExit, match="ARMED"):
        mod.main(["/dev/ttyFAKE0"], wait_sec=0.05)

    assert fake.written == []


def test_px_restore_mode_sends_stabilize_when_disarmed_non_zero_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load_px_restore_mode()
    m = apm.MAVLink(None, srcSystem=1, srcComponent=1)
    disarmed_guided_hb = bytes(m.heartbeat_encode(2, 3, 0, 4, 4).pack(m))
    fake = _FakeSerialPort(disarmed_guided_hb)
    monkeypatch.setattr(mod.serial, "Serial", lambda *_a, **_kw: fake)

    mod.main(["/dev/ttyFAKE0"], wait_sec=0.05)

    assert len(fake.written) == 1
