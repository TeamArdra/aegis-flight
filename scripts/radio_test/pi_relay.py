"""Byte relay for the dumb (no IDS) radio baseline. Runs on the Pi; stdlib + pyserial only.

    python3 pi_relay.py --radio /dev/ttyUSB0 --baud 57600 --mode echo --stats-file relay_stats.json
    python3 pi_relay.py --radio /dev/ttyUSB0 --baud 57600 --mode pass --other socket://127.0.0.1:5760

``echo`` writes every byte read from the radio straight back. ``pass`` copies bytes both ways between the radio and
``--other`` (a serial path or ``socket://host:port``). Counters print every 5 s and land in ``--stats-file``.
Frame counts are header-based (no CRC check), so they are approximate on a noisy link.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from typing import Any

import serial

_V2, _V1 = 0xFD, 0xFE


class FrameCounter:
    """Counts MAVLink v1/v2 frames in a byte stream from the length byte (no CRC check)."""

    def __init__(self) -> None:
        self._buf = bytearray()
        self.frames = 0
        self.bad_bytes = 0

    def feed(self, data: bytes) -> int:
        buf = self._buf
        buf.extend(data)
        i, n, found = 0, len(buf), 0
        while i < n:
            magic = buf[i]
            if magic == _V2:
                if n - i < 3:
                    break
                total = 12 + buf[i + 1] + (13 if buf[i + 2] & 1 else 0)
            elif magic == _V1:
                if n - i < 2:
                    break
                total = 8 + buf[i + 1]
            else:
                self.bad_bytes += 1
                i += 1
                continue
            if n - i < total:
                break
            found += 1
            i += total
        del buf[:i]
        self.frames += found
        return found


class Relay:
    """Moves bytes between a radio port and an optional other endpoint, counting both directions."""

    def __init__(self, radio: Any, other: Any | None = None) -> None:
        self.radio = radio
        self.other = other
        self.counters = {"bytes_radio_rx": 0, "bytes_radio_tx": 0, "bytes_other_rx": 0, "bytes_other_tx": 0}
        self.radio_frames = FrameCounter()
        self.other_frames = FrameCounter()
        self.started = time.time()

    @staticmethod
    def _read(port: Any) -> bytes:
        n = port.in_waiting
        return port.read(n) if n else b""

    def pump_once(self) -> int:
        """One non-blocking cycle; returns bytes moved."""
        moved = 0
        data = self._read(self.radio)
        if data:
            moved += len(data)
            self.counters["bytes_radio_rx"] += len(data)
            self.radio_frames.feed(data)
            if self.other is None:
                self.radio.write(data)
                self.counters["bytes_radio_tx"] += len(data)
            else:
                self.other.write(data)
                self.counters["bytes_other_tx"] += len(data)
        if self.other is not None:
            data = self._read(self.other)
            if data:
                moved += len(data)
                self.counters["bytes_other_rx"] += len(data)
                self.other_frames.feed(data)
                self.radio.write(data)
                self.counters["bytes_radio_tx"] += len(data)
        return moved

    def stats(self, mode: str) -> dict[str, Any]:
        return {"mode": mode, "uptime_s": round(time.time() - self.started, 1), **self.counters,
                "frames_from_radio": self.radio_frames.frames, "frames_from_other": self.other_frames.frames,
                "radio_bad_bytes": self.radio_frames.bad_bytes, "other_bad_bytes": self.other_frames.bad_bytes,
                "updated": time.time()}


def write_stats(path: str, stats: dict[str, Any]) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(stats, fh, indent=2)
    os.replace(tmp, path)


def serve(relay: Relay, mode: str, stats_file: str, interval: float = 5.0,
          stop: Any = None) -> None:
    """Pump until ``stop()`` is true; print and persist counters every ``interval`` seconds."""
    next_report = time.monotonic() + interval
    while not (stop and stop()):
        if not relay.pump_once():
            time.sleep(0.001)
        if time.monotonic() >= next_report:
            next_report += interval
            s = relay.stats(mode)
            print(f"[{s['uptime_s']:.0f}s] radio rx {s['bytes_radio_rx']}B/{s['frames_from_radio']}f tx "
                  f"{s['bytes_radio_tx']}B | other rx {s['bytes_other_rx']}B/{s['frames_from_other']}f tx "
                  f"{s['bytes_other_tx']}B", flush=True)
            write_stats(stats_file, s)
    write_stats(stats_file, relay.stats(mode))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--radio", default="/dev/ttyUSB0")
    ap.add_argument("--baud", type=int, default=57600)
    ap.add_argument("--mode", choices=("echo", "pass"), required=True)
    ap.add_argument("--other", help="serial path or socket://host:port (required for --mode pass)")
    ap.add_argument("--other-baud", type=int, help="default: same as --baud")
    ap.add_argument("--stats-file", default="relay_stats.json")
    a = ap.parse_args(argv)
    if a.mode == "pass" and not a.other:
        ap.error("--mode pass needs --other")

    try:
        radio = serial.Serial(a.radio, a.baud, timeout=0)
        other = serial.serial_for_url(a.other, baudrate=a.other_baud or a.baud, timeout=0) if a.mode == "pass" else None
    except (serial.SerialException, OSError) as exc:
        print(f"ERROR: cannot open port: {exc}", file=sys.stderr)
        return 2

    stopping = False

    def _stop(*_: object) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    relay = Relay(radio, other)
    print(f"relay {a.mode}: radio {a.radio}@{a.baud}" + (f" <-> {a.other}" if other else ""), flush=True)
    rc = 0
    try:
        serve(relay, a.mode, a.stats_file, stop=lambda: stopping)
    except (serial.SerialException, OSError) as exc:
        print(f"ERROR: port failed: {exc}", file=sys.stderr)
        write_stats(a.stats_file, relay.stats(a.mode))
        rc = 1
    finally:
        radio.close()
        if other is not None:
            other.close()
    print("stopped; final counters in", a.stats_file)
    return rc


if __name__ == "__main__":
    sys.exit(main())
