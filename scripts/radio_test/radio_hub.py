"""Ground-side hub for the real-radio test: a drop-in for ``inline_demo/hub.py`` whose bridge side is a serial port.

  radio (serial) <--> hub --5801--> GCS clients (read/write: pilot script, attacker script)
                          --5802--> observers (read-only copy of the downlink)
                          --5803--> stats (one JSON line per connection)

    python scripts/radio_test/radio_hub.py --port COM3 --baud 57600 --capture-dir run_001/hub

The hub owns the serial port, survives the radio being unplugged and replugged (0.5 s retry, TCP clients stay
connected, uplink arriving while the port is down is dropped and counted), and never lets a slow TCP client
block the serial reader (bounded per-client queue, drop-oldest). Raw bytes each way are captured to
``downlink.cap`` / ``uplink.cap`` (``read_capture`` reads them back). Binds to 127.0.0.1 unless ``--host``.
"""

from __future__ import annotations

import argparse
import collections
import json
import logging
import queue
import socket
import struct
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from aegisflight.proxy.transport import split_frames

log = logging.getLogger("radio_hub")

_V2, _V1 = 0xFD, 0xFE
_CAP_HEAD = struct.Struct("<dI")  # 8-byte float time + 4-byte length
_READ_MAX = 4096
_FRAMER_MAX_TAIL = 300  # > the longest MAVLink frame; a longer "tail" is garbage, not a partial frame


class SerialLike(Protocol):
    """The subset of ``serial.Serial`` the hub uses (tests inject a fake)."""

    def read(self, size: int = 1) -> bytes: ...
    def write(self, data: bytes) -> Any: ...
    def close(self) -> None: ...


SerialFactory = Callable[[str, int], SerialLike]


def open_serial(port: str, baud: int) -> SerialLike:
    """Default factory: a non-blocking-ish pyserial port (short read timeout so shutdown stays responsive)."""
    import serial  # imported lazily so the module and its tests do not need pyserial

    return serial.Serial(port, baud, timeout=0.05, write_timeout=2.0)  # type: ignore[no-any-return]


# --------------------------------------------------------------------------- #
# capture files
# --------------------------------------------------------------------------- #


class CaptureWriter:
    """Append ``<f8 time><u4 length><data>`` records; flushed per record so a crash loses nothing."""

    def __init__(self, path: Path):
        self.path = path
        self._fh = path.open("ab")
        self._lock = threading.Lock()

    def write(self, data: bytes, t: float | None = None) -> None:
        rec = _CAP_HEAD.pack(time.time() if t is None else t, len(data)) + data
        with self._lock:
            if self._fh.closed:
                return
            self._fh.write(rec)
            self._fh.flush()

    def close(self) -> None:
        with self._lock:
            self._fh.close()


def read_capture(path: str | Path) -> list[tuple[float, bytes]]:
    """Read a capture file into ``[(time, data), ...]``; a truncated last record is ignored."""
    raw = Path(path).read_bytes()
    out: list[tuple[float, bytes]] = []
    i, n = 0, len(raw)
    while i + _CAP_HEAD.size <= n:
        t, ln = _CAP_HEAD.unpack_from(raw, i)
        i += _CAP_HEAD.size
        if i + ln > n:
            break
        out.append((t, raw[i : i + ln]))
        i += ln
    return out


# --------------------------------------------------------------------------- #
# stream frame counting
# --------------------------------------------------------------------------- #


class StreamFramer:
    """Counts MAVLink frames in a byte stream that arrives in arbitrary chunks.

    Complete frames (plus any garbage before them) are handed to ``split_frames``; a partial frame at the
    end is held back until the rest arrives.
    """

    def __init__(self) -> None:
        self._buf = b""
        self.frames = 0
        self.bad_segments = 0

    def feed(self, data: bytes) -> None:
        buf = self._buf + data
        cut = self._complete_prefix(buf)
        if cut:
            frames, bad = split_frames(buf[:cut], max_frames=cut // 8 + 1)
            self.frames += len(frames)
            self.bad_segments += bad
        tail = buf[cut:]
        if len(tail) > _FRAMER_MAX_TAIL:
            self.bad_segments += 1
            tail = b""
        self._buf = tail

    @staticmethod
    def _complete_prefix(buf: bytes) -> int:
        """Length of the prefix that ends on a frame boundary (everything before an incomplete frame)."""
        n, i = len(buf), 0
        while i < n:
            magic = buf[i]
            if magic == _V2:
                if n - i < 3:
                    return i
                inc = buf[i + 2]
                if inc & 0xFE:
                    i += 1
                    continue
                total = 12 + buf[i + 1] + (13 if inc & 1 else 0)
            elif magic == _V1:
                if n - i < 2:
                    return i
                total = 8 + buf[i + 1]
            else:
                i += 1
                continue
            if i + total > n:
                return i
            i += total
        return n


# --------------------------------------------------------------------------- #
# TCP clients
# --------------------------------------------------------------------------- #


class _Client:
    """One TCP peer with its own bounded send queue and sender thread (drop-oldest when full)."""

    def __init__(self, cid: int, kind: str, sock: socket.socket, addr: Any, max_queue: int):
        self.cid, self.kind, self.sock, self.addr = cid, kind, sock, addr
        self.rx_bytes = 0  # received from the client
        self.tx_bytes = 0  # sent to the client
        self.dropped = 0  # chunks discarded because the client was too slow
        self._q: collections.deque[bytes] = collections.deque()
        self._max = max_queue
        self._cond = threading.Condition()
        self.closed = False

    def enqueue(self, data: bytes) -> None:
        with self._cond:
            if self.closed:
                return
            if len(self._q) >= self._max:
                self._q.popleft()
                self.dropped += 1
            self._q.append(data)
            self._cond.notify()

    def depth(self) -> int:
        with self._cond:
            return len(self._q)

    def send_loop(self) -> None:
        while True:
            with self._cond:
                while not self._q and not self.closed:
                    self._cond.wait()
                if self.closed:
                    return
                data = self._q.popleft()
            try:
                self.sock.sendall(data)
            except OSError:
                return
            self.tx_bytes += len(data)

    def close(self) -> None:
        with self._cond:
            self.closed = True
            self._cond.notify_all()
        for op in (lambda: self.sock.shutdown(socket.SHUT_RDWR), self.sock.close):
            try:
                op()
            except OSError:
                pass

    def info(self) -> dict[str, Any]:
        return {"id": self.cid, "kind": self.kind, "addr": f"{self.addr[0]}:{self.addr[1]}",
                "rx_bytes": self.rx_bytes, "tx_bytes": self.tx_bytes, "dropped_chunks": self.dropped,
                "queue_depth": self.depth()}


# --------------------------------------------------------------------------- #
# hub
# --------------------------------------------------------------------------- #


class RadioHub:
    """Owns the serial port and fans it out to TCP clients; see the module docstring."""

    def __init__(self, port: str, baud: int = 57600, capture_dir: str | Path | None = None, *,
                 host: str = "127.0.0.1", gcs_port: int = 5801, obs_port: int = 5802, stats_port: int = 5803,
                 write_chunk: int = 64, write_pause: float = 0.01, retry_s: float = 0.5,
                 client_queue: int = 512, uplink_queue: int = 1024, client_sndbuf: int = 65536,
                 serial_factory: SerialFactory | None = None):
        self.port, self.baud = port, baud
        self.host = host
        self.gcs_port, self.obs_port, self.stats_port = gcs_port, obs_port, stats_port  # updated at start()
        self.write_chunk = max(1, write_chunk)
        self.write_pause = write_pause
        self.retry_s = retry_s
        self.client_queue = client_queue
        self.client_sndbuf = client_sndbuf
        self._factory: SerialFactory = serial_factory or open_serial

        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._threads: list[threading.Thread] = []
        self._listeners: list[socket.socket] = []
        self._clients: dict[int, _Client] = {}
        self._next_id = 1
        self._accepted = 0

        self._ser: SerialLike | None = None
        self._uplink: queue.Queue[bytes] = queue.Queue(maxsize=uplink_queue)
        self._down_framer, self._up_framer = StreamFramer(), StreamFramer()
        self._down_bytes = self._up_bytes = 0
        self._up_dropped_down = 0  # uplink discarded because the serial port was down
        self._up_dropped_full = 0  # uplink discarded because the serial write queue was full
        self._reconnects = 0
        self._last_error = ""
        self._t0 = time.time()

        self._cap_down: CaptureWriter | None = None
        self._cap_up: CaptureWriter | None = None
        if capture_dir is not None:
            d = Path(capture_dir)
            d.mkdir(parents=True, exist_ok=True)
            self._cap_down = CaptureWriter(d / "downlink.cap")
            self._cap_up = CaptureWriter(d / "uplink.cap")

    # -- lifecycle ---------------------------------------------------------- #

    def start(self) -> None:
        """Bind the listeners and start all threads (returns immediately)."""
        self._t0 = time.time()
        self.gcs_port = self._listen(self.gcs_port, self._accept_loop, "gcs")
        self.obs_port = self._listen(self.obs_port, self._accept_loop, "obs")
        self.stats_port = self._listen(self.stats_port, self._stats_loop, "stats")
        self._spawn(self._serial_loop, "serial")
        self._spawn(self._uplink_loop, "uplink")

    def stop(self) -> None:
        self._stop.set()
        for s in self._listeners:
            try:
                s.close()
            except OSError:
                pass
        with self._lock:
            clients = list(self._clients.values())
            ser = self._ser
        for c in clients:
            c.close()
        if ser is not None:
            self._drop_serial(ser)
        for t in self._threads:
            t.join(timeout=2)
        for cap in (self._cap_down, self._cap_up):
            if cap is not None:
                cap.close()

    def wait(self) -> None:
        """Block until Ctrl+C, then stop."""
        try:
            while not self._stop.wait(0.5):
                pass
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def _spawn(self, fn: Callable[..., None], name: str, *args: Any) -> None:
        t = threading.Thread(target=fn, args=args, name=f"radio_hub-{name}", daemon=True)
        t.start()
        self._threads.append(t)

    def _listen(self, port: int, loop: Callable[..., None], tag: str) -> int:
        s = socket.socket()
        if sys.platform != "win32":  # on Windows SO_REUSEADDR would let a second process share the port
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, port))
        s.listen(8)
        self._listeners.append(s)
        self._spawn(loop, tag, s, tag)
        return int(s.getsockname()[1])

    # -- serial side -------------------------------------------------------- #

    def _set_error(self, msg: str) -> None:
        with self._lock:
            self._last_error = msg

    def _drop_serial(self, ser: SerialLike) -> None:
        with self._lock:
            if self._ser is ser:
                self._ser = None
        try:
            ser.close()
        except Exception:
            pass

    def _serial_loop(self, *_: Any) -> None:
        ever_connected = False
        while not self._stop.is_set():
            try:
                ser = self._factory(self.port, self.baud)
            except Exception as e:
                self._set_error(f"open {self.port}: {e}")
                self._stop.wait(self.retry_s)
                continue
            with self._lock:
                self._ser = ser
                if ever_connected:
                    self._reconnects += 1
            ever_connected = True
            log.info("serial %s open at %d baud", self.port, self.baud)
            try:
                while not self._stop.is_set() and self._ser is ser:
                    pending = int(getattr(ser, "in_waiting", 0))
                    data = ser.read(min(_READ_MAX, max(1, pending)))
                    if data:
                        self._on_downlink(bytes(data))
            except Exception as e:
                self._set_error(f"serial read: {e}")
                log.warning("serial lost: %s", e)
            finally:
                self._drop_serial(ser)
            self._stop.wait(self.retry_s)

    def _on_downlink(self, data: bytes) -> None:
        if self._cap_down is not None:
            self._cap_down.write(data)
        with self._lock:
            self._down_bytes += len(data)
            self._down_framer.feed(data)
            targets = list(self._clients.values())
        for c in targets:
            c.enqueue(data)

    def _uplink_loop(self, *_: Any) -> None:
        while not self._stop.is_set():
            try:
                item = self._uplink.get(timeout=0.2)
            except queue.Empty:
                continue
            with self._lock:
                ser = self._ser
            if ser is None:
                with self._lock:
                    self._up_dropped_down += 1
                continue
            try:
                for i in range(0, len(item), self.write_chunk):
                    if self._stop.is_set():
                        return
                    ser.write(item[i : i + self.write_chunk])
                    if self.write_pause > 0:
                        time.sleep(self.write_pause)
            except Exception as e:
                self._set_error(f"serial write: {e}")
                log.warning("serial write failed: %s", e)
                self._drop_serial(ser)
                with self._lock:
                    self._up_dropped_down += 1
                continue
            if self._cap_up is not None:
                self._cap_up.write(item)
            with self._lock:
                self._up_bytes += len(item)
                self._up_framer.feed(item)

    def _submit_uplink(self, data: bytes) -> None:
        try:
            self._uplink.put_nowait(data)
        except queue.Full:
            with self._lock:
                self._up_dropped_full += 1
            try:
                self._uplink.get_nowait()
            except queue.Empty:
                pass
            try:
                self._uplink.put_nowait(data)
            except queue.Full:
                pass

    # -- TCP side ----------------------------------------------------------- #

    def _accept_loop(self, lsock: socket.socket, tag: str) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = lsock.accept()
            except OSError:
                return
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if self.client_sndbuf:
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.client_sndbuf)
            with self._lock:
                cid = self._next_id
                self._next_id += 1
                self._accepted += 1
                client = _Client(cid, tag, conn, addr, self.client_queue)
                self._clients[cid] = client
            log.info("accepted %s #%d from %s:%s", tag, cid, addr[0], addr[1])
            self._spawn(self._client_send, f"send{cid}", client)
            self._spawn(self._client_recv, f"recv{cid}", client)

    def _client_send(self, client: _Client) -> None:
        client.send_loop()
        self._remove(client)

    def _client_recv(self, client: _Client) -> None:
        while not client.closed:
            try:
                data = client.sock.recv(_READ_MAX)
            except OSError:
                break
            if not data:
                break
            client.rx_bytes += len(data)
            if client.kind == "gcs":
                self._submit_uplink(data)  # observers are read-only: their bytes are discarded
        self._remove(client)

    def _remove(self, client: _Client) -> None:
        client.close()
        with self._lock:
            if self._clients.pop(client.cid, None) is not None:
                log.info("closed %s #%d", client.kind, client.cid)

    def _stats_loop(self, lsock: socket.socket, _tag: str) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = lsock.accept()
            except OSError:
                return
            try:
                conn.settimeout(2.0)
                conn.sendall((json.dumps(self.stats()) + "\n").encode())
            except OSError:
                pass
            finally:
                conn.close()

    # -- stats -------------------------------------------------------------- #

    def stats(self) -> dict[str, Any]:
        with self._lock:
            clients = [c.info() for c in self._clients.values()]
            return {
                "uptime_s": round(time.time() - self._t0, 3),
                "port": self.port, "baud": self.baud,
                "serial_connected": self._ser is not None,
                "serial_reconnects": self._reconnects,
                "last_error": self._last_error,
                "downlink": {"bytes": self._down_bytes, "frames": self._down_framer.frames,
                             "bad_segments": self._down_framer.bad_segments},
                "uplink": {"bytes": self._up_bytes, "frames": self._up_framer.frames,
                           "bad_segments": self._up_framer.bad_segments,
                           "dropped_serial_down": self._up_dropped_down,
                           "dropped_queue_full": self._up_dropped_full},
                "serial_write_queue": self._uplink.qsize(),
                "clients_accepted": self._accepted,
                "clients": clients,
            }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--port", required=True, help="serial port of the ground radio, e.g. COM3")
    ap.add_argument("--baud", type=int, default=57600)
    ap.add_argument("--capture-dir", required=True, help="directory for downlink.cap / uplink.cap")
    ap.add_argument("--host", default="127.0.0.1", help="bind address (default loopback only)")
    ap.add_argument("--gcs-port", type=int, default=5801)
    ap.add_argument("--obs-port", type=int, default=5802)
    ap.add_argument("--stats-port", type=int, default=5803)
    ap.add_argument("--write-chunk", type=int, default=64, help="bytes per serial write")
    ap.add_argument("--write-pause", type=float, default=0.01, help="seconds between serial write chunks")
    ap.add_argument("--client-queue", type=int, default=512, help="max queued chunks per TCP client")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    hub = RadioHub(a.port, a.baud, a.capture_dir, host=a.host, gcs_port=a.gcs_port, obs_port=a.obs_port,
                   stats_port=a.stats_port, write_chunk=a.write_chunk, write_pause=a.write_pause,
                   client_queue=a.client_queue)
    hub.start()
    print(f"hub up: gcs {a.host}:{hub.gcs_port} obs {a.host}:{hub.obs_port} stats {a.host}:{hub.stats_port}",
          flush=True)
    hub.wait()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
