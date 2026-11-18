"""Dashboard backend micro-benchmark: per-tick _process / _make_update time, JSON size+time, CPU, peak memory.

Deterministic SIM and REPLAY (synthetic tlog) runs, no sockets, no sleeping. Usage:
    python scripts/perf_bench_backend.py [--ticks 700] [--repeat 3]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics as st
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tests" / "integration"))
import dashboard_payload_driver as drv  # noqa: E402

from aegisflight.backend.engine import LiveEngine  # noqa: E402
from aegisflight.backend.sources import SourceSpec, iter_tlog_frames  # noqa: E402
from aegisflight.sources.mavlink_live import frame_ticks  # noqa: E402


def _ticks(eng: LiveEngine, tlog: Path, n: int):
    if eng.is_sim:
        return [next(eng._gen) for _ in range(n)]
    return list(frame_ticks(iter_tlog_frames(tlog), sample_rate_hz=1.0 / eng.dt))[:n]


def bench(kind: str, n: int, tlog: Path, tmp: str, trace_mem: bool = False) -> dict:
    spec = SourceSpec(kind="sim") if kind == "sim" else SourceSpec(kind="replay", tlog=str(tlog), speed=0)
    eng = LiveEngine(spec=spec, db_path=str(Path(tmp) / f"{kind}{time.perf_counter_ns()}.sqlite"))
    ticks = _ticks(eng, tlog, n)
    proc, mk, ser, sizes = [], [], [], []
    orig = eng._make_update

    def timed(t, a):
        s = time.perf_counter()
        r = orig(t, a)
        mk.append(time.perf_counter() - s)
        return r

    eng._make_update = timed  # type: ignore[method-assign]
    q = eng.subscribe()
    if trace_mem:  # tracemalloc distorts timings 5-10x, so memory is measured in its own pass
        tracemalloc.start()
    cpu0 = time.process_time()

    async def run() -> None:
        for tk in ticks:
            if eng.is_sim:
                eng._apply_pending_attack()
            s = time.perf_counter()
            await eng._process(tk)
            proc.append(time.perf_counter() - s)
            while not q.empty():
                m = q.get_nowait()
                s = time.perf_counter()
                b = drv.canonical(m)
                ser.append(time.perf_counter() - s)
                sizes.append(len(b.encode()))

    asyncio.run(run())
    cpu = time.process_time() - cpu0
    peak = 0
    if trace_mem:
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
    return {"ticks": len(ticks), "updates": len(sizes),
            "process_us_mean": st.mean(proc) * 1e6, "process_us_p95": sorted(proc)[int(.95 * len(proc))] * 1e6,
            "make_update_us_mean": st.mean(mk) * 1e6 if mk else 0.0,
            "json_us_mean": st.mean(ser) * 1e6, "json_bytes_mean": st.mean(sizes), "json_bytes_total": sum(sizes),
            "cpu_s": cpu, "peak_mem_kib": peak / 1024}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ticks", type=int, default=400)
    ap.add_argument("--repeat", type=int, default=3)
    a = ap.parse_args()
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        tlog = drv.synth_tlog(Path(tmp) / "s.tlog")
        out = {}
        for kind in ("sim", "replay"):
            runs = [bench(kind, a.ticks, tlog, tmp) for _ in range(a.repeat)]
            out[kind] = {k: round(min(r[k] for r in runs), 2) for k in runs[0]}
            out[kind]["peak_mem_kib"] = round(bench(kind, a.ticks, tlog, tmp, trace_mem=True)["peak_mem_kib"], 1)
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
