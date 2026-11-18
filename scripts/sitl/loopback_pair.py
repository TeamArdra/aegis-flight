"""Loopback byte relay between two TCP clients (issue #25 bridge evidence run).

ArduPilot SITL's ``tcp:`` serial listeners bind every interface, so the evidence run makes SITL dial out instead
(``--serial1 tcpclient:127.0.0.1:A``). ``aegis ips-bridge`` is also a client (``socket://127.0.0.1:B``), so this relay
listens on 127.0.0.1:A and 127.0.0.1:B and copies bytes between the newest connection on each side. Bytes that arrive
while the other side is not connected are discarded (a serial line has no buffer either).

    python loopback_pair.py 5762 5772
"""

from __future__ import annotations

import argparse
import selectors
import socket
import threading


class LoopbackPair:
    """Two loopback listeners; port 0 picks a free port (see :attr:`ports`)."""

    def __init__(self, port_a: int, port_b: int, host: str = "127.0.0.1") -> None:
        self._sel = selectors.DefaultSelector()
        self._listeners = [self._listen(host, port_a, 0), self._listen(host, port_b, 1)]
        self.ports = tuple(s.getsockname()[1] for s in self._listeners)
        self._peer: list[socket.socket | None] = [None, None]
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _listen(self, host: str, port: int, side: int) -> socket.socket:
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(4)
        s.setblocking(False)
        self._sel.register(s, selectors.EVENT_READ, ("listen", side))
        return s

    def _drop(self, sock: socket.socket) -> None:
        try:
            self._sel.unregister(sock)
        except (KeyError, ValueError):
            pass
        sock.close()
        self._peer = [None if p is sock else p for p in self._peer]

    def poll(self, timeout: float = 0.5) -> None:
        for key, _ in self._sel.select(timeout=timeout):
            kind, side = key.data
            sock = key.fileobj
            if kind == "listen":
                conn, _addr = sock.accept()
                conn.setblocking(True)
                if self._peer[side] is not None:  # newest connection wins
                    self._drop(self._peer[side])
                self._peer[side] = conn
                self._sel.register(conn, selectors.EVENT_READ, ("conn", side))
                print(f"accepted side {'AB'[side]}", flush=True)
                continue
            try:
                data = sock.recv(65536)
            except OSError:
                data = b""
            if not data:
                self._drop(sock)
                continue
            other = self._peer[1 - side]
            if other is not None:
                try:
                    other.sendall(data)
                except OSError:
                    self._drop(other)

    def serve_forever(self) -> None:
        while not self._stop.is_set():
            self.poll()

    def start(self) -> LoopbackPair:
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()
        return self

    def close(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        for s in [*self._listeners, *(p for p in self._peer if p is not None)]:
            try:
                self._sel.unregister(s)
            except (KeyError, ValueError):
                pass
            s.close()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("port_a", type=int, help="loopback port for side A (e.g. SITL tcpclient)")
    ap.add_argument("port_b", type=int, help="loopback port for side B (e.g. aegis ips-bridge --fc-port)")
    a = ap.parse_args(argv)
    pair = LoopbackPair(a.port_a, a.port_b)
    print(f"pair up 127.0.0.1:{pair.ports[0]} <-> 127.0.0.1:{pair.ports[1]}", flush=True)
    try:
        pair.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        pair.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
