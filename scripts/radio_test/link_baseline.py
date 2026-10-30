"""Laptop side of the dumb-link baseline: loss, round-trip latency and saturation of the radio pair.

Run ``pi_relay.py --mode echo`` on the Pi first, then:

    python link_baseline.py --port COM3 --baud 57600 [--rates 5,10,20,40] [--seconds-per-rate 15] [--out radio_test_out]

Sends numbered MAVLink v2 PING frames (26 bytes, seq + send time in the payload) at each offered rate and matches the
echoes. Writes ``p1_baseline.json`` and ``p1_baseline_raw.csv``. ``--port loop://`` does a hardware-free dry run.
Exit codes: 0 all checks passed, 1 a check failed, 2 port busy or missing.
"""

from __future__ import annotations

import argparse
import csv
import struct
import sys
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import serial
from com_probe import FrameScanner, _is_busy
from pymavlink.dialects.v20 import common as mav
from results import PhaseResult

PING_ID = 4
PING_FMT = "<QIBB"  # time_usec, seq, target_system, target_component
PING_LEN = struct.calcsize(PING_FMT)


class PingCodec:
    """Builds PING frames. target_system is non-zero so MAVLink 2 zero-truncation never changes the frame length."""

    def __init__(self, sysid: int = 255, compid: int = 190) -> None:
        self._mav = mav.MAVLink(None, srcSystem=sysid, srcComponent=compid)

    def encode(self, seq: int, t_us: int) -> bytes:
        return bytes(mav.MAVLink_ping_message(t_us, seq, 1, 1).pack(self._mav))

    @staticmethod
    def decode(payload: bytes) -> tuple[int, int]:
        """Returns ``(t_us, seq)``; tolerates v2 trailing-zero truncation."""
        t_us, seq, _, _ = struct.unpack(PING_FMT, payload.ljust(PING_LEN, b"\0")[:PING_LEN])
        return t_us, seq


FRAME_LEN = len(PingCodec().encode(0, 0))


def percentile(values: list[float], p: float) -> float | None:
    """Linear-interpolated percentile (0-100); None for an empty list."""
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * p / 100.0
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


@dataclass
class Sample:
    seq: int
    rate: float
    sent_s: float
    rtt_ms: float | None = None
    dups: int = 0


@dataclass
class RateResult:
    rate_fps: float
    sent: int
    received: int
    dups: int
    loss_pct: float
    rtt_p50_ms: float | None
    rtt_p95_ms: float | None
    rtt_p99_ms: float | None
    rtt_max_ms: float | None
    offered_Bps: float
    tx_Bps: float
    rx_Bps: float
    late_sends: int
    stray_bytes: int


def summarize_rate(rate: float, samples: list[Sample], frame_len: int, send_span_s: float, late_sends: int = 0,
                   stray_bytes: int = 0) -> RateResult:
    rtts = [s.rtt_ms for s in samples if s.rtt_ms is not None]
    sent = len(samples)
    span = max(send_span_s, 1e-9)
    return RateResult(
        rate_fps=rate, sent=sent, received=len(rtts), dups=sum(s.dups for s in samples),
        loss_pct=100.0 * (sent - len(rtts)) / sent if sent else 0.0,
        rtt_p50_ms=percentile(rtts, 50), rtt_p95_ms=percentile(rtts, 95), rtt_p99_ms=percentile(rtts, 99),
        rtt_max_ms=max(rtts) if rtts else None, offered_Bps=rate * frame_len,
        tx_Bps=sent * frame_len / span, rx_Bps=len(rtts) * frame_len / span,
        late_sends=late_sends, stray_bytes=stray_bytes)


def find_saturation(rows: list[RateResult], loss_limit_pct: float = 5.0, rtt_factor: float = 3.0) -> float | None:
    """First offered rate (ascending) with loss above the limit or p95 RTT above ``rtt_factor`` x the lowest rate's."""
    rows = sorted(rows, key=lambda r: r.rate_fps)
    base = rows[0].rtt_p95_ms if rows else None
    for r in rows:
        slow = base is not None and r.rtt_p95_ms is not None and r.rtt_p95_ms > rtt_factor * base
        if r.loss_pct > loss_limit_pct or slow:
            return r.rate_fps
    return None


class PingLink:
    """Owns the port: a reader thread matches echoes to sent pings while ``run_rate`` paces the sends."""

    def __init__(self, ser: Any) -> None:
        self.ser = ser
        self.codec = PingCodec()
        self.scanner = FrameScanner()
        self.samples: dict[int, Sample] = {}
        self.frame_len = FRAME_LEN
        self.error = ""
        self._seq = 0
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._reader, daemon=True)

    def start(self) -> None:
        self.ser.reset_input_buffer()
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)

    def _reader(self) -> None:
        try:
            while not self._stop.is_set():
                data = self.ser.read(max(1, self.ser.in_waiting))
                if not data:
                    continue
                now_us = time.perf_counter_ns() // 1000
                for fr in self.scanner.feed(data):
                    if fr.msgid == PING_ID:
                        self._on_ping(fr.payload, now_us)
        except (serial.SerialException, OSError) as exc:
            self.error = f"read failed: {exc}"

    def _on_ping(self, payload: bytes, now_us: int) -> None:
        t_us, seq = self.codec.decode(payload)
        with self._lock:
            s = self.samples.get(seq)
            if s is None:
                return
            if s.rtt_ms is None:
                s.rtt_ms = (now_us - t_us) / 1000.0
            else:
                s.dups += 1

    def run_rate(self, rate: float, seconds: float, drain_s: float) -> tuple[list[Sample], RateResult]:
        period = 1.0 / rate
        count = max(1, int(round(seconds * rate)))
        stray0 = self.scanner.garbage_bytes
        batch: list[Sample] = []
        late = 0
        t0 = time.perf_counter()
        for k in range(count):
            due = t0 + k * period
            while (remaining := due - time.perf_counter()) > 0:
                if remaining > 0.003:
                    time.sleep(remaining - 0.002)
            if time.perf_counter() - due > period:
                late += 1
            seq = self._seq
            self._seq += 1
            s = Sample(seq, rate, time.perf_counter() - t0)
            with self._lock:
                self.samples[seq] = s
            batch.append(s)
            self.ser.write(self.codec.encode(seq, time.perf_counter_ns() // 1000))
        span = batch[-1].sent_s + period
        deadline = time.perf_counter() + drain_s
        while time.perf_counter() < deadline and any(s.rtt_ms is None for s in batch) and not self.error:
            time.sleep(0.02)
        with self._lock:
            snap = [Sample(**asdict(s)) for s in batch]
        return snap, summarize_rate(rate, snap, self.frame_len, span, late, self.scanner.garbage_bytes - stray0)


def run_baseline(ser: Any, rates: list[float], seconds: float, drain_s: float = 2.0, warmup_s: float = 2.0,
                 log: Any = print) -> tuple[bool, list[RateResult], list[Sample], str]:
    """Warm up (proves the echo path), then one pass per rate. Returns ``(echo_alive, rows, samples, error)``."""
    link = PingLink(ser)
    link.start()
    try:
        _, warm = link.run_rate(5.0, warmup_s, drain_s)
        log(f"warm-up: {warm.received}/{warm.sent} echoes")
        if warm.received == 0:
            return False, [], [], link.error
        rows: list[RateResult] = []
        samples: list[Sample] = []
        for rate in rates:
            batch, row = link.run_rate(rate, seconds, drain_s)
            rows.append(row)
            samples.extend(batch)
            log(format_row(row))
        return True, rows, samples, link.error
    finally:
        link.close()


def _fmt(v: float | None) -> str:
    return "-" if v is None else f"{v:.1f}"


def format_row(r: RateResult) -> str:
    return (f"{r.rate_fps:>6g} fps  sent {r.sent:>4}  loss {r.loss_pct:5.1f}%  rtt p50/p95/p99/max "
            f"{_fmt(r.rtt_p50_ms)}/{_fmt(r.rtt_p95_ms)}/{_fmt(r.rtt_p99_ms)}/{_fmt(r.rtt_max_ms)} ms  "
            f"rx {r.rx_Bps:.0f} B/s (offered {r.offered_Bps:.0f})")


def write_csv(path: Path, samples: list[Sample]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["rate_fps", "seq", "sent_s", "rtt_ms", "dups"])
        for s in samples:
            w.writerow([s.rate, s.seq, f"{s.sent_s:.4f}", "" if s.rtt_ms is None else f"{s.rtt_ms:.3f}", s.dups])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--port", default="COM3", help="serial port, or loop:// for a dry run")
    ap.add_argument("--baud", type=int, default=57600)
    ap.add_argument("--rates", default="5,10,20,40", help="offered load, PING frames/s")
    ap.add_argument("--seconds-per-rate", type=float, default=15.0)
    ap.add_argument("--drain", type=float, default=2.0, help="seconds to wait for stragglers after each rate")
    ap.add_argument("--loss-limit", type=float, default=1.0, help="max loss %% at the lowest rate (check)")
    ap.add_argument("--sat-loss", type=float, default=5.0, help="loss %% that marks saturation")
    ap.add_argument("--out", default="radio_test_out")
    a = ap.parse_args(argv)
    rates = sorted(float(r) for r in a.rates.split(",") if r.strip())

    res = PhaseResult("p1_baseline", a.out)
    res.metrics = {"port": a.port, "baud": a.baud, "rates": rates, "seconds_per_rate": a.seconds_per_rate}
    try:
        ser = serial.serial_for_url(a.port, baudrate=a.baud, timeout=0.05, write_timeout=2)
    except (serial.SerialException, OSError) as exc:
        busy = _is_busy(exc)
        print(f"ERROR: cannot open {a.port}: {exc}" + (" (port is busy: close other programs using it)" if busy else ""),
              file=sys.stderr)
        res.check("port opened", False, note=str(exc))
        res.save()
        return 2
    res.check("port opened", True)

    try:
        alive, rows, samples, err = run_baseline(ser, rates, a.seconds_per_rate, a.drain)
    finally:
        ser.close()
    res.check("echo path alive", alive, note="" if alive else "no echoes in warm-up: is pi_relay.py --mode echo running, "
              "and is the baud right?" + (f" {err}" if err else ""))
    if alive:
        sat = find_saturation(rows, a.sat_loss)
        res.metrics["per_rate"] = {f"{r.rate_fps:g}": asdict(r) for r in rows}
        res.metrics["saturation_fps"] = sat
        res.metrics["max_clean_fps"] = max((r.rate_fps for r in rows if sat is None or r.rate_fps < sat), default=None)
        res.metrics["frame_bytes"] = FRAME_LEN
        low = rows[0]
        res.check("loss <= 1% at lowest rate", low.loss_pct <= a.loss_limit, value=round(low.loss_pct, 2),
                  threshold=a.loss_limit, note=f"{low.rate_fps:g} fps")
        res.check("rtt p50 recorded", low.rtt_p50_ms is not None, value=low.rtt_p50_ms, note=f"{low.rate_fps:g} fps")
        csv_path = Path(a.out) / "p1_baseline_raw.csv"
        write_csv(csv_path, samples)
        res.artifact(csv_path.name)
        print(f"saturation: {'not reached' if sat is None else f'{sat:g} fps'}")
    path = res.save()
    print(f"wrote {path}")
    return 0 if all(c["passed"] for c in res.checks) else 1


if __name__ == "__main__":
    sys.exit(main())
