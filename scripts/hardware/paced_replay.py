"""Paced replay: a recorded tlog through the UNCHANGED pipeline at its recorded rate x factor, in real time.

    .venv/Scripts/python.exe scripts/hardware/paced_replay.py data/sitl/raw/benign_001.tlog \
        --config-dir configs/px4_sitl --model models/isoforest_px4.joblib \
        --factor 1 --factor 3 --ml both --label host --out artifacts/hardware/companion_host_<date>/paced.json

What it measures (issue #30, Part A). A feeder thread releases each raw frame at
``wall0 + (ts - ts0) / factor`` into a bounded queue (``--queue-frames``); the consumer is the same code
path as a live link: ``frame_ticks`` (framing, CRC, tick bucketing) -> ``IDSPipeline.process_tick``.
Per run (one per factor x ML mode) it reports:

* ``decision_compute_ms``: consumer work attributable to each decision (decode + bucketing + pipeline),
  i.e. consumer wall time between two decisions minus the time it spent blocked waiting for frames;
  ``pipeline_latency_ms`` is the pipeline's own ``latency_ms`` (``process_tick`` only). p50/p95/p99/max/mean.
* ``decision_lag_ms``: decision completion minus the wall instant its tick's data was complete
  (``wall0 + tick.t / factor``). A tick is only emitted when a frame of the NEXT tick arrives (data-driven
  ticks), so the lag includes one inter-frame gap; ``late_decisions`` counts lag > one tick period.
* frames: total, released, consumed, ``dropped`` (queue full at release time = lost, like a UART overrun),
  ``late`` (dequeued more than ``--late-ms`` after release; default one tick period at this factor),
  ``max_queue_depth``; ticks emitted vs expected (expected = drop-free count of the same frames);
* pacing: achieved speed vs the requested factor, release lateness of the feeder;
* process CPU % (of one core, over the paced window; includes the feeder thread) and RSS
  (sampled max during the run, and the OS-reported process-lifetime peak);
* determinism: a SHA-256 over the decision sequence (tick, threat, alert, type, score). With no drops it
  must equal the unpaced reference run of the same frames (``verdicts_identical_to_unpaced``).

Evidence class: environment REPLAY on whatever machine runs it. Run on the development host this is a
HOST measurement and says nothing about a Raspberry Pi or other companion computer; the JSON carries that
label (``evidence``). Only a run on the target board is target evidence.

Exit codes: 0 ok; 2 missing/malformed input or bad arguments (unreadable or corrupt tlog, no frames,
zero time span, factor <= 0, ML requested but model missing, ``--out`` already exists).
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata as md
import json
import os
import platform
import queue
import socket
import struct
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import psutil

from aegisflight.config import load_config
from aegisflight.pipeline import IDSPipeline
from aegisflight.sources.mavlink_live import frame_ticks

SCHEMA = "aegisflight.paced_replay/1"
REPO = Path(__file__).resolve().parents[2]
NOT_RECORDED = "not recorded"


class InputError(Exception):
    """Missing or malformed input: the CLI turns it into exit code 2."""


# --------------------------------------------------------------------------- #
# input
# --------------------------------------------------------------------------- #


def read_tlog(path: str | Path) -> list[tuple[float, bytes]]:
    """Strictly parse a tlog (8-byte big-endian microsecond stamp + one MAVLink v1/v2 frame, repeated).

    Unlike the tolerant readers used for statistics, ANY trailing garbage, unknown magic byte or truncated
    frame is an error: a measurement must not silently cover only part of the capture.
    """
    p = Path(path)
    if not p.is_file():
        raise InputError(f"tlog not found: {p}")
    data = p.read_bytes()
    out: list[tuple[float, bytes]] = []
    i, n = 0, len(data)
    while i < n:
        if i + 8 + 2 > n:
            raise InputError(f"truncated record at byte {i} of {n}")
        ts = struct.unpack(">Q", data[i:i + 8])[0] / 1e6
        f = i + 8
        magic = data[f]
        if magic == 0xFE:
            flen = 8 + data[f + 1]
        elif magic == 0xFD:
            flen = 12 + data[f + 1] + (13 if f + 2 < n and data[f + 2] & 1 else 0)
        else:
            raise InputError(f"not a tlog: bad MAVLink magic 0x{magic:02X} at byte {f}")
        if f + flen > n:
            raise InputError(f"truncated MAVLink frame at byte {f} (needs {flen} bytes, {n - f} left)")
        out.append((ts, data[f:f + flen]))
        i = f + flen
    if not out:
        raise InputError(f"tlog holds no frames: {p}")
    return out


def window(frames: list[tuple[float, bytes]], max_capture_s: float | None) -> list[tuple[float, bytes]]:
    if max_capture_s is None:
        return frames
    t0 = frames[0][0]
    return [fr for fr in frames if fr[0] - t0 <= max_capture_s]


def schedule(frames: Sequence[tuple[float, bytes]]) -> tuple[list[float], int]:
    """Capture-relative release offsets (non-decreasing: a stamp that goes backwards is released
    immediately after its predecessor, in file order) and the number of such backwards stamps."""
    t0 = frames[0][0]
    rel: list[float] = []
    back = 0
    prev = 0.0
    for ts, _ in frames:
        r = ts - t0
        if r < prev:
            back += 1
            r = prev
        rel.append(r)
        prev = r
    return rel, back


# --------------------------------------------------------------------------- #
# statistics
# --------------------------------------------------------------------------- #


def pct(sorted_v: Sequence[float], q: float) -> float:
    return sorted_v[min(len(sorted_v) - 1, round(q * (len(sorted_v) - 1)))]


def dist(v: Sequence[float], nd: int = 4) -> dict:
    if not v:
        return {"n": 0, "p50": None, "p95": None, "p99": None, "max": None, "mean": None}
    s = sorted(v)
    return {"n": len(s), "p50": round(pct(s, 0.50), nd), "p95": round(pct(s, 0.95), nd),
            "p99": round(pct(s, 0.99), nd), "max": round(s[-1], nd), "mean": round(sum(s) / len(s), nd)}


class DecisionDigest:
    """Order-sensitive digest of the verdict sequence (no timing in it: equal input -> equal digest)."""

    def __init__(self) -> None:
        self._h = hashlib.sha256()
        self.n = 0

    def add(self, tick: int, a) -> None:
        row = [tick, bool(a.threat), bool(a.is_alert), a.attack_type.value, round(float(a.threat_score), 6)]
        self._h.update(json.dumps(row, separators=(",", ":")).encode())
        self._h.update(b"\n")
        self.n += 1

    def hexdigest(self) -> str:
        return self._h.hexdigest()


# --------------------------------------------------------------------------- #
# runs
# --------------------------------------------------------------------------- #


def unpaced(frames: Sequence[tuple[float, bytes]], pipe, rate_hz: float) -> dict:
    """Reference: same frames, same consumer path, no pacing, no queue."""
    dg = DecisionDigest()
    ticks = 0
    for tick in frame_ticks(frames, sample_rate_hz=rate_hz):
        ticks += 1
        a = pipe.process_tick(tick)
        if a is not None:
            dg.add(tick.tick, a)
    return {"ticks": ticks, "decisions": dg.n, "digest": dg.hexdigest()}


def peak_rss_bytes(proc: psutil.Process) -> int | None:
    """OS-reported process-lifetime peak resident set (None if this platform does not expose it)."""
    mi = proc.memory_info()
    if hasattr(mi, "peak_wset"):  # Windows
        return int(mi.peak_wset)
    try:
        import resource
    except ImportError:
        return None
    ru = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(ru if sys.platform == "darwin" else ru * 1024)


@dataclass
class _Acct:
    released: int = 0
    dropped: int = 0
    consumed: int = 0
    late: int = 0
    max_depth: int = 0
    wait_s: float = 0.0
    release_late_s: list[float] = field(default_factory=list)
    first_release: float | None = None
    last_release: float | None = None
    rss_max: int = 0


def paced_run(frames: Sequence[tuple[float, bytes]], pipe, *, factor: float, rate_hz: float,
              queue_frames: int = 2048, late_ms: float | None = None, lead_s: float = 0.05,
              rss_sample_s: float = 0.5, proc: psutil.Process | None = None) -> dict:
    """Replay ``frames`` in real time at ``factor`` x their recorded rate through ``pipe``.

    ``pipe`` needs only ``process_tick(tick) -> assessment | None`` (the real ``IDSPipeline`` in the tool).
    """
    if factor <= 0:
        raise ValueError("factor must be > 0")
    if queue_frames < 1:
        raise ValueError("queue_frames must be >= 1")
    proc = proc or psutil.Process()
    rel, backwards = schedule(frames)
    period_wall_s = 1.0 / rate_hz / factor
    late_s = (late_ms / 1000.0) if late_ms is not None else period_wall_s
    q: queue.Queue = queue.Queue(maxsize=queue_frames)
    acct = _Acct()
    stop = threading.Event()
    wall0 = 0.0  # set just before the feeder starts, after all setup work

    def feeder() -> None:
        next_rss = time.perf_counter()
        for i, (ts, fb) in enumerate(frames):
            if stop.is_set():
                return
            due = wall0 + rel[i] / factor
            now = time.perf_counter()
            if due > now:
                time.sleep(due - now)
                now = time.perf_counter()
            acct.release_late_s.append(now - due)
            if acct.first_release is None:
                acct.first_release = now
            acct.last_release = now
            acct.released += 1
            try:
                q.put_nowait((now, ts, fb))
            except queue.Full:
                acct.dropped += 1
            acct.max_depth = max(acct.max_depth, q.qsize())
            if now >= next_rss:
                acct.rss_max = max(acct.rss_max, proc.memory_info().rss)
                next_rss = now + rss_sample_s
        q.put(None)  # blocking: the end marker is never dropped

    def consume() -> Iterator[tuple[float, bytes]]:
        while True:
            t_w = time.perf_counter()
            item = q.get()
            got = time.perf_counter()
            acct.wait_s += got - t_w
            if item is None:
                return
            released_at, ts, fb = item
            acct.consumed += 1
            if got - released_at > late_s:
                acct.late += 1
            yield ts, fb

    expected_ticks = sum(1 for _ in frame_ticks(frames, sample_rate_hz=rate_hz))
    dg = DecisionDigest()
    compute: list[float] = []
    pipe_lat: list[float] = []
    lag: list[float] = []
    ticks = 0
    th = threading.Thread(target=feeder, name="paced-replay-feeder", daemon=True)
    cpu0 = sum(proc.cpu_times()[:2])
    t_start = time.perf_counter()
    wall0 = t_start + lead_s
    th.start()
    try:
        acct.wait_s = 0.0
        last = time.perf_counter()
        for tick in frame_ticks(consume(), sample_rate_hz=rate_hz):
            ticks += 1
            a = pipe.process_tick(tick)
            if a is None:
                continue
            done = time.perf_counter()
            compute.append((done - last - acct.wait_s) * 1000.0)
            acct.wait_s = 0.0
            last = done
            lag.append((done - (wall0 + tick.t / factor)) * 1000.0)
            pipe_lat.append(float(a.latency_ms))
            dg.add(tick.tick, a)
    finally:
        stop.set()
        th.join(timeout=10)
    wall = time.perf_counter() - t_start
    cpu = sum(proc.cpu_times()[:2]) - cpu0
    acct.rss_max = max(acct.rss_max, proc.memory_info().rss)
    peak = peak_rss_bytes(proc)

    span = rel[-1]
    released_span = (acct.last_release - acct.first_release) if acct.first_release is not None else 0.0
    achieved = (span / released_span) if released_span > 0 else None
    period_ms = period_wall_s * 1000.0
    return {
        "factor": factor,
        "sample_rate_hz": rate_hz,
        "tick_period_wall_ms": round(period_ms, 3),
        "capture_span_s": round(span, 3),
        "wall_s": round(wall, 3),
        "pacing": {
            "achieved_speed": round(achieved, 4) if achieved is not None else None,
            "error_pct": round(100.0 * (achieved - factor) / factor, 3) if achieved is not None else None,
            "release_lateness_ms": dist([x * 1000.0 for x in acct.release_late_s], 3),
            "backwards_timestamps": backwards,
        },
        "frames": {
            "total": len(frames), "released": acct.released, "consumed": acct.consumed,
            "dropped": acct.dropped, "late": acct.late, "late_threshold_ms": round(late_s * 1000.0, 3),
            "queue_capacity": queue_frames, "max_queue_depth": acct.max_depth,
            "offered_rate_per_s": round(len(frames) / span * factor, 2) if span > 0 else None,
        },
        "ticks": {"expected": expected_ticks, "emitted": ticks},
        "decisions": dg.n,
        "decision_compute_ms": dist(compute),
        "pipeline_latency_ms": dist(pipe_lat),
        "decision_lag_ms": dist(lag, 3),
        "late_decisions": sum(1 for x in lag if x > period_ms),
        "cpu": {"cpu_s": round(cpu, 3),
                "pct_of_one_core": round(100.0 * cpu / wall, 2) if wall > 0 else None,
                "logical_cpus": os.cpu_count()},
        "memory": {"rss_mb_max_sampled": round(acct.rss_max / 2**20, 1),
                   "rss_mb_process_lifetime_peak": round(peak / 2**20, 1) if peak else NOT_RECORDED},
        "digest": dg.hexdigest(),
    }


# --------------------------------------------------------------------------- #
# provenance
# --------------------------------------------------------------------------- #


def _git(*args: str) -> str | None:
    try:
        r = subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout if r.returncode == 0 else None


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def provenance() -> dict:
    head = _git("rev-parse", "HEAD")
    status = _git("status", "--porcelain")
    pkgs = {}
    for name in ("numpy", "scikit-learn", "scipy", "joblib", "pymavlink", "psutil"):
        try:
            pkgs[name] = md.version(name)
        except md.PackageNotFoundError:
            pkgs[name] = NOT_RECORDED
    try:
        mem_total = round(psutil.virtual_memory().total / 2**30, 2)
    except (OSError, RuntimeError):
        mem_total = NOT_RECORDED
    return {
        "aegisflight_commit": head.strip() if head else NOT_RECORDED,
        "working_tree_dirty": bool(status.strip()) if status is not None else NOT_RECORDED,
        "dirty_paths_count": len(status.splitlines()) if status is not None else NOT_RECORDED,
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "packages": pkgs,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor() or NOT_RECORDED,
        "logical_cpus": os.cpu_count() or NOT_RECORDED,
        "physical_cpus": psutil.cpu_count(logical=False) or NOT_RECORDED,
        "memory_total_gib": mem_total,
        "hostname_sha256_8": hashlib.sha256(socket.gethostname().encode()).hexdigest()[:8],
        "board_model": NOT_RECORDED,
        "power": NOT_RECORDED,
        "run_provenance_helper": NOT_RECORDED + " (issue #25 helper not used; fields recorded directly)",
    }


def input_environment(tlog: Path) -> str:
    """Environment of the CAPTURE, from its sidecar JSON (``<name>.json``) if there is one."""
    side = tlog.with_suffix(".json")
    try:
        env = json.loads(side.read_text(encoding="utf-8")).get("environment")
    except (OSError, ValueError, AttributeError):
        return NOT_RECORDED
    return str(env) if env else NOT_RECORDED


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _parse(argv: list[str] | None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("tlog")
    ap.add_argument("--factor", type=float, action="append",
                    help="speed-up over the recorded rate; repeat for several (default: 1 and 3)")
    ap.add_argument("--ml", choices=["off", "on", "both"], default="both")
    ap.add_argument("--model", default="models/isoforest.joblib")
    ap.add_argument("--config-dir", default=None)
    ap.add_argument("--max-capture-s", type=float, default=None, help="replay only the first N capture seconds")
    ap.add_argument("--queue-frames", type=int, default=2048, help="frames buffered before new ones are dropped")
    ap.add_argument("--late-ms", type=float, default=None, help="frame lateness threshold (default: one tick period)")
    ap.add_argument("--label", default="host",
                    help="where this ran, e.g. 'host' (development machine) or the board name")
    ap.add_argument("--out", default=None, help="JSON output path (refuses to overwrite)")
    ap.add_argument("--no-reference", action="store_true", help="skip the unpaced determinism reference")
    return ap.parse_args(argv)


def run(a: argparse.Namespace, *, pipeline_factory: Callable[[object, str | None], object] | None = None) -> dict:
    factors = a.factor or [1.0, 3.0]
    if any(f <= 0 for f in factors):
        raise InputError(f"--factor must be > 0 (got {factors})")
    if a.queue_frames < 1:
        raise InputError("--queue-frames must be >= 1")
    if a.max_capture_s is not None and a.max_capture_s <= 0:
        raise InputError("--max-capture-s must be > 0")
    if a.out and Path(a.out).exists():
        raise InputError(f"--out {a.out} already exists (a measurement is never overwritten)")
    modes = {"off": [False], "on": [True], "both": [False, True]}[a.ml]
    model_path = Path(a.model) if a.model else None
    if True in modes and (model_path is None or not model_path.is_file()):
        raise InputError(f"ML requested but the model file is missing: {a.model}")
    if a.config_dir is not None and not Path(a.config_dir).is_dir():
        raise InputError(f"--config-dir not found: {a.config_dir}")

    tlog = Path(a.tlog)
    frames = window(read_tlog(tlog), a.max_capture_s)
    if len(frames) < 2 or frames[-1][0] - frames[0][0] <= 0:
        raise InputError("tlog needs at least two frames spanning a positive time")
    cfg = load_config(a.config_dir)
    rate = float(cfg.simulation.get("sample_rate_hz", 10.0))
    make = pipeline_factory or (lambda c, m: IDSPipeline(c, model_path=m, firmware_dir=None))

    runs = []
    for ml in modes:
        model = str(model_path) if ml else None
        ref = None if a.no_reference else unpaced(frames, make(cfg, model), rate)
        for f in factors:
            r = paced_run(frames, make(cfg, model), factor=f, rate_hz=rate, queue_frames=a.queue_frames,
                          late_ms=a.late_ms)
            r["ml_enabled"] = ml
            if ref is not None:
                r["unpaced_reference"] = ref
                r["verdicts_identical_to_unpaced"] = r["digest"] == ref["digest"]
            runs.append(r)

    label = a.label
    is_host = label.lower() == "host"
    return {
        "schema": SCHEMA,
        "utc": datetime.now(UTC).isoformat(),
        "evidence": {
            "environment": "REPLAY",
            "measured_on": label,
            "target_hardware": False if is_host else NOT_RECORDED,
            "claim": ("HOST measurement: paced REPLAY on the development host. NOT Raspberry Pi / "
                      "companion-computer evidence." if is_host else
                      f"paced REPLAY measured on '{label}' (as stated by the operator; board model {NOT_RECORDED})"),
            "input_capture_environment": input_environment(tlog),
            "scope": "IDS pipeline compute only (framing, features, detectors, fusion, optional ML); "
                     "no serial driver, no event store, no dashboard",
        },
        "input": {"tlog_name": tlog.name, "tlog_sha256": _sha256(tlog), "tlog_bytes": tlog.stat().st_size,
                  "frames_used": len(frames), "max_capture_s": a.max_capture_s,
                  "capture_span_s": round(frames[-1][0] - frames[0][0], 3)},
        "config": {"config_dir": a.config_dir or "configs (Stage-1 default)", "sample_rate_hz": rate,
                   "model_name": model_path.name if True in modes and model_path else None,
                   "model_sha256": _sha256(model_path) if True in modes and model_path else None,
                   "queue_frames": a.queue_frames, "late_ms": a.late_ms or "one tick period at each factor",
                   "factors": factors, "ml_modes": modes},
        "provenance": provenance(),
        "runs": runs,
    }


def _brief(out: dict) -> dict:
    return {"evidence": out["evidence"]["claim"], "runs": [
        {"factor": r["factor"], "ml": r["ml_enabled"], "decisions": r["decisions"],
         "compute_ms_p50_p95_max": [r["decision_compute_ms"][k] for k in ("p50", "p95", "max")],
         "lag_ms_p95": r["decision_lag_ms"]["p95"], "late_decisions": r["late_decisions"],
         "dropped": r["frames"]["dropped"], "late_frames": r["frames"]["late"],
         "ticks": r["ticks"], "cpu_pct": r["cpu"]["pct_of_one_core"], "pacing_error_pct": r["pacing"]["error_pct"],
         "identical_to_unpaced": r.get("verdicts_identical_to_unpaced")} for r in out["runs"]]}


def main(argv: list[str] | None = None) -> int:
    a = _parse(argv)
    try:
        out = run(a)
    except InputError as exc:
        print(f"paced_replay: {exc}", file=sys.stderr)
        return 2
    text = json.dumps(out, indent=2)
    if a.out:
        p = Path(a.out)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "x", encoding="utf-8") as fh:  # exclusive create: never overwrite a measurement
            fh.write(text + "\n")
    print(json.dumps(_brief(out), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
