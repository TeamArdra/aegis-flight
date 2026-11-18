"""scripts/sitl/loopback_pair.py: the issue #25 bridge evidence relay pairs two loopback clients."""

from __future__ import annotations

import socket
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "sitl"))

from loopback_pair import LoopbackPair  # noqa: E402


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        assert chunk, "peer closed"
        buf += chunk
    return buf


def _wait_paired(pair: LoopbackPair) -> None:
    deadline = time.monotonic() + 5
    while any(p is None for p in pair._peer) and time.monotonic() < deadline:
        time.sleep(0.01)


def test_relays_both_directions_and_binds_loopback_only() -> None:
    pair = LoopbackPair(0, 0).start()
    try:
        assert all(s.getsockname()[0] == "127.0.0.1" for s in pair._listeners)
        a = socket.create_connection(("127.0.0.1", pair.ports[0]), timeout=5)
        b = socket.create_connection(("127.0.0.1", pair.ports[1]), timeout=5)
        _wait_paired(pair)
        a.sendall(b"\xfd" * 300)
        assert _recv_exactly(b, 300) == b"\xfd" * 300
        b.sendall(b"uplink")
        assert _recv_exactly(a, 6) == b"uplink"
        a.close()
        b.close()
    finally:
        pair.close()


def test_newest_connection_replaces_the_old_one() -> None:
    pair = LoopbackPair(0, 0).start()
    try:
        b = socket.create_connection(("127.0.0.1", pair.ports[1]), timeout=5)
        old = socket.create_connection(("127.0.0.1", pair.ports[0]), timeout=5)
        _wait_paired(pair)
        new = socket.create_connection(("127.0.0.1", pair.ports[0]), timeout=5)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and pair._peer[0] is not None and pair._peer[0].getpeername() != new.getsockname():
            time.sleep(0.01)
        b.sendall(b"x")
        assert _recv_exactly(new, 1) == b"x"
        old.settimeout(2)
        assert old.recv(1) == b""  # the replaced connection was closed
        for s in (b, old, new):
            s.close()
    finally:
        pair.close()
