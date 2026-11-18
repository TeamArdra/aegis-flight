"""Offline tests for the real-radio ground hub (``scripts/radio_test/radio_hub.py``). Fake serial, loopback TCP only."""

from __future__ import annotations

import json
import queue
import socket
import sys
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from pymavlink.dialects.v20 import common as mav

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "radio_test"))

from radio_hub import RadioHub, StreamFramer, read_capture  # noqa: E402


class FakeSerial:
    """Stands in for ``serial.Serial``: ``feed`` makes bytes readable, ``fail`` simulates an unplug."""

    def __init__(self) -> None:
        self._rx: queue.Queue[bytes] = queue.Queue()
        self._buf = b""
        self.written: list[bytes] = []
        self.failed = False
        self.closed = False

    @property
    def in_waiting(self) -> int:
        return len(self._buf) + sum(len(x) for x in list(self._rx.queue))

    def feed(self, data: bytes) -> None:
        self._rx.put(data)

    def fail(self) -> None:
        self.failed = True

    def read(self, size: int = 1) -> bytes:
        if self.failed:
            raise OSError("device disconnected")
        if not self._buf:
            try:
                self._buf = self._rx.get(timeout=0.02)
            except queue.Empty:
                return b""
        out, self._buf = self._buf[:size], self._buf[size:]
        return out

    def write(self, data: bytes) -> int:
        if self.failed:
            raise OSError("device disconnected")
        self.written.append(bytes(data))
        return len(data)

    def close(self) -> None:
        self.closed = True


class Factory:
    """Hands out a new ``FakeSerial`` per open; raises while ``unplugged``."""

    def __init__(self) -> None:
        self.opened: list[FakeSerial] = []
        self.unplugged = False

    def __call__(self, port: str, baud: int) -> FakeSerial:
        if self.unplugged:
            raise OSError(f"could not open {port}")
        ser = FakeSerial()
        self.opened.append(ser)
        return ser

    @property
    def current(self) -> FakeSerial:
        return self.opened[-1]


def wait_for(pred: Callable[[], object], timeout: float = 5.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.01)
    return bool(pred())


def recv_exact(sock: socket.socket, n: int, timeout: float = 5.0) -> bytes:
    sock.settimeout(timeout)
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def heartbeat(seq: int) -> bytes:
    m = mav.MAVLink(None, srcSystem=1, srcComponent=1)
    m.seq = seq
    return bytes(m.heartbeat_encode(2, 3, 0, 0, 4).pack(m))


@pytest.fixture
def factory() -> Factory:
    return Factory()


@pytest.fixture
def make_hub(factory: Factory, tmp_path: Path) -> Iterator[Callable[..., RadioHub]]:
    hubs: list[RadioHub] = []

    def _make(**kw: object) -> RadioHub:
        args: dict = {"capture_dir": tmp_path / "cap", "gcs_port": 0, "obs_port": 0, "stats_port": 0,
                      "write_pause": 0.0, "retry_s": 0.02, "serial_factory": factory}
        args.update(kw)
        hub = RadioHub("FAKE", 57600, **args)
        hub.start()
        hubs.append(hub)
        assert wait_for(lambda: factory.opened)
        return hub

    yield _make
    for h in hubs:
        h.stop()


def connect(port: int) -> socket.socket:
    return socket.create_connection(("127.0.0.1", port), timeout=5)


def test_downlink_broadcast_to_gcs_and_observers(make_hub, factory):
    hub = make_hub()
    clients = [connect(hub.gcs_port), connect(hub.gcs_port), connect(hub.obs_port)]
    assert wait_for(lambda: len(hub.stats()["clients"]) == 3)
    payload = b"".join(heartbeat(i) for i in range(5))
    factory.current.feed(payload)
    for c in clients:
        assert recv_exact(c, len(payload)) == payload
    st = hub.stats()
    assert st["downlink"]["bytes"] == len(payload)
    assert st["downlink"]["frames"] == 5
    assert {c["kind"] for c in st["clients"]} == {"gcs", "obs"}
    # Each sender thread bumps tx_bytes only after sendall() returns, so a client can hold
    # every byte before its counter moves: poll (bounded) instead of reading once.
    assert wait_for(lambda: [c["tx_bytes"] for c in hub.stats()["clients"]] == [len(payload)] * 3)


def test_uplink_written_to_serial_in_chunks(make_hub, factory):
    hub = make_hub(write_chunk=8)
    g = connect(hub.gcs_port)
    data = b"".join(heartbeat(i) for i in range(3))
    g.sendall(data)
    ser = factory.current
    assert wait_for(lambda: b"".join(ser.written) == data)
    assert all(len(w) <= 8 for w in ser.written) and len(ser.written) > 1
    assert wait_for(lambda: hub.stats()["uplink"]["frames"] == 3)
    assert hub.stats()["uplink"]["bytes"] == len(data)


def test_observer_is_read_only(make_hub, factory):
    hub = make_hub()
    o, g = connect(hub.obs_port), connect(hub.gcs_port)
    o.sendall(b"observer-junk")
    time.sleep(0.2)
    g.sendall(b"from-gcs")
    ser = factory.current
    assert wait_for(lambda: b"".join(ser.written) == b"from-gcs")
    time.sleep(0.2)
    assert b"".join(ser.written) == b"from-gcs"
    # rx_bytes is bumped by the observer's recv thread; poll it instead of trusting the sleeps above.
    assert wait_for(lambda: [c["rx_bytes"] for c in hub.stats()["clients"] if c["kind"] == "obs"]
                    == [len(b"observer-junk")])


def test_reconnect_after_unplug_keeps_clients(make_hub, factory):
    hub = make_hub()
    g = connect(hub.gcs_port)
    assert wait_for(lambda: len(hub.stats()["clients"]) == 1)
    first = factory.current
    factory.unplugged = True
    first.fail()
    assert wait_for(lambda: not hub.stats()["serial_connected"])
    assert wait_for(lambda: "could not open" in hub.stats()["last_error"])
    assert hub.stats()["serial_reconnects"] == 0
    g.sendall(b"lost-while-down")  # port is down: dropped and counted, not queued for later
    assert wait_for(lambda: hub.stats()["uplink"]["dropped_serial_down"] >= 1)
    factory.unplugged = False
    assert wait_for(lambda: hub.stats()["serial_connected"] and hub.stats()["serial_reconnects"] == 1)
    assert len(hub.stats()["clients"]) == 1
    assert first.closed
    factory.current.feed(b"after-replug")
    assert recv_exact(g, 12) == b"after-replug"
    g.sendall(b"hello-again")
    assert wait_for(lambda: b"".join(factory.current.written) == b"hello-again")


def test_write_failure_triggers_reconnect(make_hub, factory):
    hub = make_hub()
    g = connect(hub.gcs_port)
    factory.current.failed = True
    g.sendall(b"x")
    assert wait_for(lambda: hub.stats()["serial_reconnects"] == 1 and hub.stats()["serial_connected"])
    assert "serial" in hub.stats()["last_error"]


def test_slow_client_does_not_block_serial_reader(make_hub, factory):
    hub = make_hub(client_queue=64, client_sndbuf=4096)
    slow = socket.socket()
    slow.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    slow.connect(("127.0.0.1", hub.gcs_port))  # never reads
    fast = connect(hub.obs_port)
    assert wait_for(lambda: len(hub.stats()["clients"]) == 2)
    ser = factory.current
    chunk = b"\xaa" * 2048
    total = 0
    got = [0]

    def drain() -> None:
        while got[0] < 600 * len(chunk):
            try:
                d = fast.recv(65536)
            except OSError:
                return
            if not d:
                return
            got[0] += len(d)

    t = threading.Thread(target=drain, daemon=True)
    t.start()
    for _ in range(600):
        ser.feed(chunk)
        total += len(chunk)
        time.sleep(0.001)
    assert wait_for(lambda: hub.stats()["downlink"]["bytes"] == total, 10)
    t.join(timeout=10)
    assert got[0] == total
    slow_info = next(c for c in hub.stats()["clients"] if c["kind"] == "gcs")
    assert slow_info["dropped_chunks"] > 0
    assert slow_info["queue_depth"] <= 64
    slow.close()


def test_capture_round_trip(make_hub, factory, tmp_path):
    hub = make_hub()
    g = connect(hub.gcs_port)
    down = [heartbeat(1), heartbeat(2)]
    for d in down:
        factory.current.feed(d)
        time.sleep(0.05)
    assert wait_for(lambda: hub.stats()["downlink"]["bytes"] == sum(map(len, down)))
    up = heartbeat(9)
    g.sendall(up)
    assert wait_for(lambda: hub.stats()["uplink"]["bytes"] == len(up))
    hub.stop()
    t0 = time.time()
    rd = read_capture(tmp_path / "cap" / "downlink.cap")
    ru = read_capture(tmp_path / "cap" / "uplink.cap")
    assert b"".join(d for _, d in rd) == b"".join(down)
    assert b"".join(d for _, d in ru) == up
    assert all(abs(t - t0) < 30 for t, _ in rd + ru)
    assert [t for t, _ in rd] == sorted(t for t, _ in rd)


def test_read_capture_ignores_truncated_tail(tmp_path):
    p = tmp_path / "x.cap"
    hub = RadioHub("FAKE", capture_dir=tmp_path / "c", gcs_port=0)
    assert hub._cap_down is not None
    hub._cap_down.write(b"abc", t=1.5)
    hub._cap_down.write(b"defg", t=2.5)
    hub._cap_down.close()
    raw = (tmp_path / "c" / "downlink.cap").read_bytes()
    p.write_bytes(raw[:-2])  # cut into the last record
    assert read_capture(p) == [(1.5, b"abc")]
    p.write_bytes(raw)
    assert read_capture(p) == [(1.5, b"abc"), (2.5, b"defg")]
    hub._cap_up.close()  # type: ignore[union-attr]


def test_stats_port_returns_one_json_line_then_closes(make_hub, factory):
    hub = make_hub()
    frame = heartbeat(1)
    factory.current.feed(frame[:7])  # a frame split across two serial reads is still one frame
    time.sleep(0.1)
    factory.current.feed(frame[7:] + heartbeat(2))
    assert wait_for(lambda: hub.stats()["downlink"]["frames"] == 2)
    s = connect(hub.stats_port)
    s.settimeout(5)
    buf = b""
    while True:
        d = s.recv(4096)
        if not d:
            break
        buf += d
    assert buf.endswith(b"\n") and buf.count(b"\n") == 1
    st = json.loads(buf)
    for key in ("uptime_s", "downlink", "uplink", "serial_reconnects", "last_error", "clients",
                "serial_write_queue"):
        assert key in st
    assert st["downlink"]["frames"] == 2 and st["downlink"]["bad_segments"] == 0
    assert st["serial_write_queue"] == 0


def test_stream_framer_handles_garbage_and_splits():
    f = StreamFramer()
    a, b = heartbeat(1), heartbeat(2)
    f.feed(b"\x00\x01" + a[:5])
    assert f.frames == 0
    f.feed(a[5:] + b)
    assert f.frames == 2
    assert f.bad_segments == 1  # the leading garbage run
