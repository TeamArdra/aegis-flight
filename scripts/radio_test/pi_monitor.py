#!/usr/bin/env python3
"""Resource and bridge-counter monitor, run ON the Raspberry Pi next to ``aegis ips-bridge``.

    python3 pi_monitor.py --out run/pi_monitor.jsonl --status-url http://127.0.0.1:8765 [--pid N]
    python3 pi_monitor.py --summarize-only run/pi_monitor.jsonl

Every ``--interval`` seconds appends one JSON line (CPU % of one core, RSS, SoC temperature, decoded
``vcgencmd get_throttled``, load, and the bridge's own /status counters). On SIGTERM / Ctrl-C it writes
``<out stem>_summary.json``: peaks, means, throttling seen, counter deltas and an RSS growth flag.
stdlib only; psutil is used when installed, /proc otherwise.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

THROTTLE_BITS = {
    0: "under-voltage now", 1: "arm frequency capped now", 2: "throttled now", 3: "soft temperature limit now",
    16: "under-voltage occurred", 17: "arm frequency capped occurred", 18: "throttled occurred",
    19: "soft temperature limit occurred",
}
NOW_MASK = 0xF
EVER_MASK = 0xF0000
COUNTER_KEYS = ("frames_down", "frames_up", "dropped_down", "dropped_up", "send_failures", "tap_overflow",
                "analyser_decisions", "analyser_alerts", "analyser_errors")
DEFAULT_PATTERN = r"aegis.*ips-bridge"
_SHELLS = {"bash", "sh", "dash", "ssh", "sshd", "sudo", "timeout", "pi_monitor.py"}


def decode_throttled(value: int) -> list[str]:
    """Names of the flags set in a ``get_throttled`` bitmask."""
    return [name for bit, name in sorted(THROTTLE_BITS.items()) if value & (1 << bit)]


def parse_throttled(text: str) -> int | None:
    """Parse ``throttled=0x50000`` (or a bare hex number)."""
    m = re.search(r"(?:throttled=)?(0x[0-9a-fA-F]+)", text or "")
    return int(m.group(1), 16) if m else None


def parse_temp(text: str) -> float | None:
    """Parse ``temp=48.3'C``."""
    m = re.search(r"temp=(-?\d+(?:\.\d+)?)", text or "")
    return float(m.group(1)) if m else None


def parse_proc_stat(text: str) -> tuple[float, int] | None:
    """(utime+stime in clock ticks, rss in pages) from the contents of /proc/PID/stat."""
    try:
        rest = text[text.rindex(")") + 2:].split()
        return float(int(rest[11]) + int(rest[12])), int(rest[21])
    except (ValueError, IndexError):
        return None


def rss_slope(samples: list[tuple[float, float]], warmup_s: float = 0.0) -> float | None:
    """Least-squares RSS slope in MiB/min over ``(epoch_s, rss_mib)`` pairs, ignoring the first ``warmup_s``."""
    if len(samples) < 2:
        return None
    t0 = samples[0][0]
    use = [s for s in samples if s[0] - t0 >= warmup_s]
    if len(use) < 3:
        use = samples
    n = len(use)
    mt = sum(t for t, _ in use) / n
    mr = sum(r for _, r in use) / n
    var = sum((t - mt) ** 2 for t, _ in use)
    if var == 0:
        return None
    return 60.0 * sum((t - mt) * (r - mr) for t, r in use) / var


def extract_status(st: dict[str, Any]) -> dict[str, Any]:
    """Flatten the bridge /status JSON to the counters and gauges this tool tracks."""
    fr, an, lat = st.get("frames") or {}, st.get("analyser") or {}, st.get("latency_us") or {}
    return {
        "mode": st.get("mode"), "state": st.get("state"),
        "frames_down": fr.get("down"), "frames_up": fr.get("up"),
        "dropped_down": fr.get("dropped_down"), "dropped_up": fr.get("dropped_up"),
        "send_failures": fr.get("send_failures"), "tap_overflow": fr.get("tap_overflow"),
        "analyser_decisions": an.get("decisions"), "analyser_alerts": an.get("alerts"),
        "analyser_errors": an.get("errors"),
        "latency_p50_us": lat.get("p50"), "latency_p95_us": lat.get("p95"), "latency_max_us": lat.get("max"),
    }


def _stats(vals: list[float]) -> dict[str, float] | None:
    return {"mean": round(sum(vals) / len(vals), 2), "peak": round(max(vals), 2)} if vals else None


def summarize(samples: list[dict[str, Any]], warmup_s: float = 30.0, slope_limit: float = 1.0,
              min_window_s: float = 120.0) -> dict[str, Any]:
    """Build the end-of-run summary from the per-sample records."""
    out: dict[str, Any] = {"samples": len(samples)}
    if not samples:
        return out
    t0, t1 = samples[0]["t"], samples[-1]["t"]
    alive = [s for s in samples if s.get("pid") is not None]
    out |= {"start": t0, "end": t1, "duration_s": round(t1 - t0, 1), "process_lost_samples": len(samples) - len(alive)}
    out["cpu_percent"] = _stats([s["cpu_pct"] for s in alive if s.get("cpu_pct") is not None])
    out["temp_c"] = _stats([s["temp_c"] for s in samples if s.get("temp_c") is not None])
    out["load1"] = _stats([s["load"][0] for s in samples if s.get("load")])
    rss = [(s["t"], s["rss_mib"]) for s in alive if s.get("rss_mib") is not None]
    if rss:
        slope = rss_slope(rss, warmup_s)
        window = rss[-1][0] - rss[0][0]
        growth = None if slope is None else slope * window / 60.0
        out["rss_mib"] = {"mean": round(sum(r for _, r in rss) / len(rss), 1), "peak": round(max(r for _, r in rss), 1),
                          "first": rss[0][1], "last": rss[-1][1],
                          "slope_mib_per_min": None if slope is None else round(slope, 3),
                          "memory_growth_flag": bool(slope is not None and window >= min_window_s
                                                     and slope > slope_limit and (growth or 0) > 2.0),
                          "flag_rule": f"window>={min_window_s:.0f}s, slope>{slope_limit} MiB/min, warmup {warmup_s:.0f}s"}
    now_bits = 0
    ever = 0
    for s in samples:
        v = s.get("throttled")
        if v is None:
            continue
        now_bits |= v & NOW_MASK
        ever |= v & EVER_MASK
    raws = [s["throttled"] for s in samples if s.get("throttled") is not None]
    out["throttling"] = {"readable": bool(raws), "seen_now": bool(now_bits), "flags_seen_now": decode_throttled(now_bits),
                         "flags_since_boot": decode_throttled(ever), "final_raw": hex(raws[-1]) if raws else None}
    st = [s["status"] for s in samples if s.get("status")]
    out["status_errors"] = sum(1 for s in samples if s.get("status_error"))
    if st:
        first, last = st[0], st[-1]
        delta = {k: last[k] - first[k] for k in COUNTER_KEYS if isinstance(first.get(k), int) and isinstance(last.get(k), int)}
        resets = sum(1 for a, b in zip(st, st[1:], strict=False)
                     if isinstance(a.get("frames_down"), int) and isinstance(b.get("frames_down"), int)
                     and b["frames_down"] < a["frames_down"])
        out["counters"] = {"first": {k: first.get(k) for k in COUNTER_KEYS}, "last": {k: last.get(k) for k in COUNTER_KEYS},
                           "delta": delta, "counter_resets": resets}
        for key in ("latency_p95_us", "latency_max_us"):
            vals = [x[key] for x in st if x.get(key) is not None]
            out.setdefault("latency_us", {})[f"peak_{key[8:]}"] = max(vals) if vals else None
        out["final_mode"] = last.get("mode")
    return out


def load_samples(path: Path) -> list[dict[str, Any]]:
    """Read a JSONL sample file, skipping a torn last line."""
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    return rows


def find_pid(pattern: str = DEFAULT_PATTERN, proc_root: str = "/proc") -> int | None:
    """Oldest process whose command line matches ``pattern``, excluding this process and shells."""
    rx = re.compile(pattern)
    me = os.getpid()
    best: tuple[int, int] | None = None
    for entry in os.listdir(proc_root):
        if not entry.isdigit() or int(entry) == me:
            continue
        try:
            cmd = Path(proc_root, entry, "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace")
            comm = Path(proc_root, entry, "comm").read_text().strip()
        except OSError:
            continue
        if comm in _SHELLS or comm.startswith("pi_monitor") or not rx.search(cmd):
            continue
        pid = int(entry)
        if best is None or pid < best[0]:
            best = (pid, pid)
    return best[0] if best else None


class ProcReader:
    """CPU seconds and RSS of one pid (psutil when present, else /proc)."""

    def __init__(self) -> None:
        try:
            import psutil
        except ImportError:
            psutil = None
        self._psutil = psutil
        self._tick = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
        self._page = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096

    def read(self, pid: int) -> tuple[float, float] | None:
        """(cpu_seconds, rss_mib) or None when the process is gone."""
        try:
            if self._psutil is not None:
                p = self._psutil.Process(pid)
                return sum(p.cpu_times()[:2]), p.memory_info().rss / 2**20
            parsed = parse_proc_stat(Path(f"/proc/{pid}/stat").read_text())
        except (OSError, Exception):  # noqa: BLE001 - psutil.NoSuchProcess is not an OSError
            return None
        if parsed is None:
            return None
        return parsed[0] / self._tick, parsed[1] * self._page / 2**20


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=2.0).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def read_temp() -> float | None:
    t = parse_temp(_run(["vcgencmd", "measure_temp"]))
    if t is not None:
        return t
    try:
        return int(Path("/sys/class/thermal/thermal_zone0/temp").read_text()) / 1000.0
    except (OSError, ValueError):
        return None


def fetch_status(url: str, timeout: float = 1.5) -> dict[str, Any]:
    with urllib.request.urlopen(url.rstrip("/") + "/status", timeout=timeout) as r:  # noqa: S310 - loopback status API
        return json.loads(r.read().decode("utf-8"))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", default="pi_monitor.jsonl", help="JSONL sample file (appended)")
    ap.add_argument("--summary", default=None, help="summary JSON path (default: <out stem>_summary.json)")
    ap.add_argument("--interval", type=float, default=2.0)
    ap.add_argument("--pid", type=int, default=None, help="bridge pid (default: command-line match)")
    ap.add_argument("--pattern", default=DEFAULT_PATTERN, help="regex for the bridge command line")
    ap.add_argument("--status-url", default=None, help="bridge status API, e.g. http://127.0.0.1:8765")
    ap.add_argument("--seconds", type=float, default=None, help="stop after this long (default: until SIGTERM)")
    ap.add_argument("--warmup", type=float, default=30.0, help="seconds ignored at the start of the RSS slope")
    ap.add_argument("--rss-slope-limit", type=float, default=1.0, help="MiB/min above which growth is flagged")
    ap.add_argument("--summarize-only", metavar="JSONL", default=None, help="just (re)build the summary of a sample file")
    a = ap.parse_args(argv)

    if a.summarize_only:
        src = Path(a.summarize_only)
        summ = summarize(load_samples(src), a.warmup, a.rss_slope_limit)
        dest = Path(a.summary) if a.summary else src.with_name(src.stem + "_summary.json")
        dest.write_text(json.dumps(summ, indent=2), encoding="utf-8")
        print(json.dumps(summ, indent=2))
        return 0

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    dest = Path(a.summary) if a.summary else out.with_name(out.stem + "_summary.json")
    stop = {"flag": False}
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.__setitem__("flag", True))
    reader = ProcReader()
    samples: list[dict[str, Any]] = []
    prev: tuple[int, float, float] | None = None
    started = time.monotonic()
    with out.open("a", encoding="utf-8") as fh:
        while not stop["flag"] and (a.seconds is None or time.monotonic() - started < a.seconds):
            now, mono = time.time(), time.monotonic()
            pid = a.pid if a.pid is not None else find_pid(a.pattern)
            rec: dict[str, Any] = {"t": round(now, 3), "pid": None, "cpu_pct": None, "rss_mib": None}
            got = reader.read(pid) if pid is not None else None
            if got is not None and pid is not None:
                cpu_s, rss = got
                rec |= {"pid": pid, "rss_mib": round(rss, 2)}
                if prev is not None and prev[0] == pid and mono > prev[2]:
                    rec["cpu_pct"] = round(100.0 * (cpu_s - prev[1]) / (mono - prev[2]), 1)
                prev = (pid, cpu_s, mono)
            else:
                prev = None
            rec["temp_c"] = read_temp()
            thr = parse_throttled(_run(["vcgencmd", "get_throttled"]))
            rec["throttled"] = thr
            rec["throttled_flags"] = decode_throttled(thr) if thr else []
            rec["load"] = [round(x, 2) for x in os.getloadavg()] if hasattr(os, "getloadavg") else None
            if a.status_url:
                try:
                    rec["status"] = extract_status(fetch_status(a.status_url))
                except (OSError, ValueError) as exc:
                    rec["status_error"] = str(exc)[:80]
            fh.write(json.dumps(rec) + "\n")
            fh.flush()
            samples.append(rec)
            end = mono + a.interval
            while not stop["flag"] and time.monotonic() < end:
                time.sleep(min(0.2, max(0.0, end - time.monotonic())))
    summ = summarize(samples, a.warmup, a.rss_slope_limit)
    dest.write_text(json.dumps(summ, indent=2), encoding="utf-8")
    print(json.dumps(summ, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
