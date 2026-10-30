"""Listen-only serial probe: find the baud at which a port carries valid MAVLink.

Never writes to the port. Opens it at each candidate baud, reads for a few seconds and counts frames whose CRC checks
out (v1 and v2, signed v2 included), then writes ``p0_probe.json``.

    python com_probe.py --port COM3 [--bauds 57600,115200,38400,9600] [--seconds 6] [--out radio_test_out]

Exit codes: 0 valid MAVLink found, 1 nothing valid at any baud, 2 port busy or missing.
"""

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any, NamedTuple

import serial
from results import PhaseResult

try:
    from pymavlink.dialects.v20.ardupilotmega import mavlink_map as _MSG_MAP
except ImportError:  # pragma: no cover
    from pymavlink.dialects.v20.common import mavlink_map as _MSG_MAP

_V2, _V1 = 0xFD, 0xFE
DEFAULT_BAUDS = (57600, 115200, 38400, 9600)


def crc16_x25(data: bytes | bytearray, crc: int = 0xFFFF) -> int:
    """MAVLink X.25 CRC."""
    for b in data:
        tmp = b ^ (crc & 0xFF)
        tmp = (tmp ^ (tmp << 4)) & 0xFF
        crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    return crc


class Frame(NamedTuple):
    msgid: int
    sysid: int
    compid: int
    seq: int
    payload: bytes
    total: int


class FrameScanner:
    """Streaming MAVLink v1/v2 parser that only yields frames with a valid CRC (known message ids only)."""

    def __init__(self) -> None:
        self._buf = bytearray()
        self.garbage_bytes = 0
        self.valid_bytes = 0

    def feed(self, data: bytes) -> list[Frame]:
        buf = self._buf
        buf.extend(data)
        out: list[Frame] = []
        i, n = 0, len(buf)
        while i < n:
            magic = buf[i]
            if magic == _V2:
                if n - i < 10:
                    break
                inc = buf[i + 2]
                total = 12 + buf[i + 1] + (13 if inc & 1 else 0)
                if inc & 0xFE:
                    total = 0
            elif magic == _V1:
                if n - i < 6:
                    break
                total = 8 + buf[i + 1]
            else:
                self.garbage_bytes += 1
                i += 1
                continue
            if total and n - i < total:
                break
            frame = self._parse(buf, i, total) if total else None
            if frame is None:
                self.garbage_bytes += 1
                i += 1
                continue
            out.append(frame)
            self.valid_bytes += total
            i += total
        del buf[:i]
        return out

    @staticmethod
    def _parse(buf: bytearray, i: int, total: int) -> Frame | None:
        plen = buf[i + 1]
        if buf[i] == _V2:
            hdr_end = i + 10
            msgid = buf[i + 7] | buf[i + 8] << 8 | buf[i + 9] << 16
            sysid, compid, seq = buf[i + 5], buf[i + 6], buf[i + 4]
        else:
            hdr_end = i + 6
            msgid = buf[i + 5]
            sysid, compid, seq = buf[i + 3], buf[i + 4], buf[i + 2]
        cls = _MSG_MAP.get(msgid)
        if cls is None:
            return None
        end = hdr_end + plen
        crc = crc16_x25(buf[i + 1 : end])
        crc = crc16_x25(bytes((cls.crc_extra,)), crc)
        if crc != (buf[end] | buf[end + 1] << 8):
            return None
        return Frame(msgid, sysid, compid, seq, bytes(buf[hdr_end:end]), total)


def msg_name(msgid: int) -> str:
    cls = _MSG_MAP.get(msgid)
    return str(getattr(cls, "msgname", None) or getattr(cls, "name", msgid)) if cls else str(msgid)


@dataclass
class BaudResult:
    baud: int
    opened: bool = False
    error: str = ""
    seconds: float = 0.0
    bytes: int = 0
    frames: int = 0
    garbage_bytes: int = 0
    msg_ids: list[int] = field(default_factory=list)
    sysids: list[int] = field(default_factory=list)

    @property
    def bytes_per_s(self) -> float:
        return self.bytes / self.seconds if self.seconds > 0 else 0.0

    @property
    def valid_ratio(self) -> float:
        return 1.0 - self.garbage_bytes / self.bytes if self.bytes else 0.0


class PortBusy(Exception):
    """The port exists but cannot be opened (another process owns it)."""


def _is_busy(exc: Exception) -> bool:
    text = str(exc).lower()
    return isinstance(exc, PermissionError) or any(
        k in text for k in ("access is denied", "permission", "busy", "in use", "resource temporarily"))


def probe_baud(port: str, baud: int, seconds: float,
               opener: Callable[..., Any] = serial.Serial,
               clock: Callable[[], float] = time.monotonic) -> BaudResult:
    """Read-only capture at one baud. Raises ``PortBusy`` when the port is owned by another process."""
    res = BaudResult(baud)
    try:
        ser = opener(port, baud, timeout=0.1)
    except (serial.SerialException, OSError) as exc:
        if _is_busy(exc):
            raise PortBusy(str(exc)) from exc
        res.error = str(exc)
        return res
    res.opened = True
    scanner = FrameScanner()
    ids: set[int] = set()
    sysids: set[int] = set()
    t0 = clock()
    try:
        while clock() - t0 < seconds:
            data = ser.read(ser.in_waiting or 1)
            if not data:
                continue
            res.bytes += len(data)
            for fr in scanner.feed(data):
                res.frames += 1
                ids.add(fr.msgid)
                sysids.add(fr.sysid)
    except (serial.SerialException, OSError) as exc:
        res.error = f"read failed: {exc}"
    finally:
        res.seconds = clock() - t0
        ser.close()
    res.garbage_bytes = scanner.garbage_bytes
    res.msg_ids = sorted(ids)
    res.sysids = sorted(sysids)
    return res


def best_result(results: list[BaudResult]) -> BaudResult | None:
    """Baud with the most valid frames (ties: cleaner stream, then higher baud); None if no frames anywhere."""
    good = [r for r in results if r.frames > 0]
    return max(good, key=lambda r: (r.frames, r.valid_ratio, r.baud)) if good else None


def format_table(results: list[BaudResult]) -> str:
    rows = [f"{'baud':>7} {'opened':>6} {'bytes':>8} {'B/s':>8} {'frames':>7} {'valid%':>7}  msg ids / sysids"]
    for r in results:
        ids = ",".join(msg_name(m) for m in r.msg_ids) or "-"
        sys_ids = ",".join(map(str, r.sysids)) or "-"
        rows.append(f"{r.baud:>7} {'yes' if r.opened else 'NO':>6} {r.bytes:>8} {r.bytes_per_s:>8.0f} {r.frames:>7} "
                    f"{r.valid_ratio * 100:>6.1f}%  {ids} / {sys_ids}" + (f"  [{r.error}]" if r.error else ""))
    return "\n".join(rows)


def run(port: str, bauds: list[int], seconds: float, out: str, min_frames: int = 3,
        opener: Callable[..., Any] = serial.Serial) -> int:
    res = PhaseResult("p0_probe", out)
    results: list[BaudResult] = []
    busy = ""
    for baud in bauds:
        print(f"listening on {port} @ {baud} for {seconds:g}s (no writes) ...", flush=True)
        try:
            results.append(probe_baud(port, baud, seconds, opener=opener))
        except PortBusy as exc:
            busy = str(exc)
            break
    print(format_table(results))
    best = best_result(results)
    res.metrics = {"port": port, "seconds_per_baud": seconds, "results": [asdict(r) | {"bytes_per_s": r.bytes_per_s}
                                                                          for r in results],
                   "best_baud": best.baud if best else None}
    if busy:
        print(f"ERROR: {port} is busy (another program owns it: GCS, Mission Planner, serial monitor?): {busy}",
              file=sys.stderr)
    res.check("port opened", any(r.opened for r in results), value=[r.baud for r in results if r.opened],
              note=f"busy: {busy}" if busy else "; ".join(r.error for r in results if r.error))
    res.check("valid mavlink at some baud", bool(best and best.frames >= min_frames),
              value={"baud": best.baud, "frames": best.frames} if best else None, threshold=f">= {min_frames} frames")
    path = res.save()
    if best:
        print(f"best baud {best.baud}: {best.frames} frames, {best.bytes_per_s:.0f} B/s, "
              f"msg ids {[msg_name(m) for m in best.msg_ids]}, sysids {best.sysids}")
    else:
        print("no valid MAVLink frames at any baud (check power/link, or the peer is silent)")
    print(f"wrote {path}")
    if busy:
        return 2
    return 0 if best and best.frames >= min_frames else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--port", default="COM3")
    ap.add_argument("--bauds", default=",".join(map(str, DEFAULT_BAUDS)))
    ap.add_argument("--seconds", type=float, default=6.0)
    ap.add_argument("--min-frames", type=int, default=3)
    ap.add_argument("--out", default="radio_test_out")
    a = ap.parse_args(argv)
    return run(a.port, [int(b) for b in a.bauds.split(",") if b.strip()], a.seconds, a.out, a.min_frames)


if __name__ == "__main__":
    sys.exit(main())
