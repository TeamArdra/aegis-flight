"""TCP server <-> PX4 SITL GCS UDP link, so `aegis onboard` (socket:// client) can sit on a PX4 SITL link. [SITL]

    python udp_tcp_shim.py --tcp-port 5762 --px4-port 18570

PX4 SITL speaks MAVLink over UDP only and locks its GCS link to the first sender, so this process is that one
sender. Uplink (TCP -> UDP) is re-framed so that every datagram holds whole MAVLink frames; downlink (UDP -> TCP)
is forwarded as received. Loopback only. It never alters a frame; counters are written to --stats on exit.
"""

from __future__ import annotations

import argparse
import json
import socket
import threading
import time


def frames(buf: bytearray) -> list[bytes]:
    """Pop complete MAVLink 1/2 frames off ``buf``; resync on garbage by dropping one byte."""
    out: list[bytes] = []
    while buf:
        if buf[0] == 0xFD and len(buf) >= 3:
            n = 12 + buf[1] + (13 if buf[2] & 1 else 0)
        elif buf[0] == 0xFE and len(buf) >= 2:
            n = 8 + buf[1]
        elif buf[0] in (0xFD, 0xFE):
            break
        else:
            del buf[0]
            continue
        if len(buf) < n:
            break
        out.append(bytes(buf[:n]))
        del buf[:n]
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tcp-port", type=int, default=5762)
    ap.add_argument("--px4-port", type=int, default=18570)
    ap.add_argument("--stats", default=None)
    a = ap.parse_args()
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", a.tcp_port))
    srv.listen(1)
    st = {"up_frames": 0, "up_bytes": 0, "down_datagrams": 0, "down_bytes": 0}
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    udp.settimeout(0.2)
    px4 = ("127.0.0.1", a.px4_port)
    conn: list[socket.socket | None] = [None]
    stop = threading.Event()

    def down() -> None:
        while not stop.is_set():
            try:
                d, _ = udp.recvfrom(65535)
            except TimeoutError:
                continue
            st["down_datagrams"] += 1
            st["down_bytes"] += len(d)
            c = conn[0]
            if c is not None:
                try:
                    c.sendall(d)
                except OSError:
                    conn[0] = None

    threading.Thread(target=down, daemon=True).start()
    try:
        while True:
            c, _ = srv.accept()
            conn[0] = c
            buf = bytearray()
            while True:
                try:
                    d = c.recv(65535)
                except OSError:
                    d = b""
                if not d:
                    break
                buf += d
                for f in frames(buf):
                    udp.sendto(f, px4)
                    st["up_frames"] += 1
                    st["up_bytes"] += len(f)
            conn[0] = None
            c.close()
    finally:
        stop.set()
        if a.stats:
            with open(a.stats, "w") as fh:
                json.dump({**st, "t": time.time()}, fh)


if __name__ == "__main__":
    main()
