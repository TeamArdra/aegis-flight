"""Unit tests for SideTapRunner and Zero-TX auto serial discovery (W5, W6)."""

from __future__ import annotations

import pytest
from pymavlink.dialects.v20 import ardupilotmega as apm

from aegisflight.hal.auto_port import capture_autopilot_version_passive, probe_serial_port_passive
from aegisflight.hal.discovery import PortInfo
from aegisflight.hal.side_tap import SideTapRunner


def _pack(msg: object, sysid: int, compid: int, seq: int = 1) -> bytes:
    m = apm.MAVLink(file=None, srcSystem=sysid, srcComponent=compid)
    m.seq = seq
    return bytes(msg.pack(m))


class _FakeSerial:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)
        self.tx_bytes: list[bytes] = []

    def read(self, _n: int = 4096) -> bytes:
        return self._chunks.pop(0) if self._chunks else b""

    def write(self, data: bytes) -> int:
        self.tx_bytes.append(data)
        raise AssertionError("auto_port must NEVER write bytes to serial device")

    def close(self) -> None:
        pass


class _DummyTapTransport:
    def __init__(self) -> None:
        self.connected = True
        self.datagrams_received = 0
        self.closed = False

    def recv(self) -> list[tuple[int, bytes]]:
        return []

    def send(self, _frame: bytes) -> bool:
        raise AssertionError("side-tap must never transmit")

    def close(self) -> None:
        self.closed = True


def test_probe_serial_port_passive_zero_tx_and_autobaud() -> None:
    hb_fc = _pack(apm.MAVLink_heartbeat_message(2, 3, 0x01, 5, 4, 3), 1, 1, seq=1)
    hb_fc2 = _pack(apm.MAVLink_heartbeat_message(2, 3, 0x01, 5, 4, 3), 1, 1, seq=2)
    serial_instances: list[_FakeSerial] = []

    def opener(_dev: str, baud: int, _timeout: float) -> _FakeSerial:
        # Only respond at 115200 baud
        s = _FakeSerial([hb_fc + hb_fc2] if baud == 115200 else [])
        serial_instances.append(s)
        return s

    info = PortInfo(device="/dev/ttyFAKE0", description="SiK Radio")
    found = probe_serial_port_passive(
        info,
        baud_candidates=(921600, 115200, 57600),
        probe_window_s=0.05,
        serial_opener=opener,
    )
    assert found is not None
    assert found.baudrate == 115200
    assert found.role == "fc"
    assert 1 in found.sysids
    assert all(not s.tx_bytes for s in serial_instances)


def test_capture_autopilot_version_passive_zero_tx() -> None:
    msg = apm.MAVLink_autopilot_version_message(
        0, 0x040507FF, 0, 0, 0, b"a1b2c3d4", b"0" * 8, b"0" * 8, 9900, 42, 123456789, b"0" * 18
    )
    frame = _pack(msg, 1, 1, seq=1)
    s = _FakeSerial([frame])
    entry = capture_autopilot_version_passive(
        "/dev/ttyFAKE1",
        baudrate=921600,
        timeout_s=1.0,
        serial_opener=lambda *_a: s,
    )
    assert entry is not None
    assert entry["vendor_id"] == 9900
    assert entry["uid"] == 123456789
    assert not s.tx_bytes


def test_side_tap_runner_is_strictly_passive() -> None:
    tr = _DummyTapTransport()
    runner = SideTapRunner(tr)
    try:
        with pytest.raises(ValueError, match="receive-only"):
            runner.set_mode("active-ips")
        st = runner.status()
        assert st["topology"]["receive_only"] is True
        assert st["mode"] == "passive"
    finally:
        runner.close()
    assert tr.closed is True


def test_side_tap_rotation_link_failure_adopts_reopened_store(tmp_path, monkeypatch) -> None:
    from aegisflight.logging.store import EventStore

    st = EventStore(tmp_path / "events.sqlite")
    st.start_run("r0", label="t")
    for i in range(10):
        st.log_action("r0", float(i), "t", "ROW", "x", "d" * 60)
    real = EventStore.log_action

    def flaky(self, run_id, t, actor, action, target, detail=""):
        if action == "ROTATION_LINK":
            raise OSError("disk hiccup writing the link row")
        return real(self, run_id, t, actor, action, target, detail)

    monkeypatch.setattr(EventStore, "log_action", flaky)
    runner = SideTapRunner(_DummyTapTransport(), store=st, run_id="r0")
    try:
        assert runner.rotate_store(max_bytes=1, max_rotations=3) is True  # segment really was rotated
        assert runner.rotation_failures == 1
        assert runner.store is not st
        runner.store.log_action(runner.run_id, 99.0, "t", "AFTER", "x")  # usable, not the closed old handle
        names = [a["action"] for a in runner.store.get_actions(limit=100)]
        assert "ROTATION_FAILED" in names and "AFTER" in names and "ROTATION_LINK" not in names
    finally:
        runner.store.close()
        runner.close()
