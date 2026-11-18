"""Reproducible micro-benchmark of the detection pipeline (host numbers, not a Raspberry Pi).

    python scripts/perf_bench.py --out artifacts/perf/before.json     # ML off and on (when a model exists)
    python scripts/perf_bench.py --profile                            # plus cProfile top functions

Workload (deterministic, built once, excluded from the timings): synthetic MAVLink datagrams from
``scripts/make_golden.py`` (benign / flood / commands / mission / garbage streams) for ``parse``, and SIM
sessions (benign + attack classes) plus those live streams for the pipeline stages. Per operation it reports
p50 / p95 / mean / max in microseconds, plus peak Python heap (tracemalloc) and process RSS.

Operations: parse (per datagram), extractor.update (per message), extract (per decision), protocol / physics /
anomaly / integrity detector (per decision), fusion (per decision), process_tick (decision ticks and all ticks).
"""

from __future__ import annotations

import argparse
import cProfile
import gc
import json
import pstats
import statistics
import sys
import time
import tracemalloc
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO / "src"))

import make_golden as mg  # noqa: E402
from aegisflight.attacks import build_attack  # noqa: E402
from aegisflight.config import load_config  # noqa: E402
from aegisflight.pipeline import IDSPipeline  # noqa: E402
from aegisflight.sources.mavlink_live import MavlinkFrameParser, frame_ticks  # noqa: E402
from aegisflight.sources.stream import SimulatedTelemetrySource  # noqa: E402

pc = time.perf_counter


def build_workload() -> dict:
    sim = []
    plan = [("benign", ""), ("gps_spoofing", "gradual_drift"), ("dos", "flood"),
            ("command_injection", "rogue_command"), ("mavlink_anomaly", "seq_scramble"),
            ("telemetry_manipulation", "altitude_bias")]
    for i, (scn, mode) in enumerate(plan):
        spec = mg._sim_spec(i, scn, mode, 3 + i, "benign" if scn == "benign" else "single")
        cfg = mg.session_config(load_config(), spec)
        cfg.simulation["duration_s"] = 60.0
        atk = build_attack(spec.scenario, cfg.attacks, np.random.default_rng(spec.seed + 99))
        sim.append((cfg, list(SimulatedTelemetrySource(cfg, atk, seed=spec.seed).stream())))
    live_cfg = load_config(REPO / "configs" / "ardupilot_copter")
    datagrams = []
    for scn in ("benign", "flood", "cmds", "mission", "garbage"):
        frames = mg.gen_stream(scn)
        datagrams += frames
        sim.append((live_cfg, list(frame_ticks(frames, 10.0))))
    return {"streams": sim, "datagrams": datagrams}


def stats_us(xs: list[float]) -> dict:
    a = np.asarray(xs) * 1e6
    return {"n": len(xs), "p50": float(np.percentile(a, 50)), "p95": float(np.percentile(a, 95)),
            "mean": float(a.mean()), "max": float(a.max())}


def timed_run(pipe: IDSPipeline, ticks, acc: dict[str, list[float]]) -> None:
    """Mirror of ``IDSPipeline.process_tick`` with a timer around each stage (same call order)."""
    ex, dec = pipe.extractor, pipe.decision_every
    for tick in ticks:
        for m in tick.messages:
            t0 = pc()
            ex.update(m)
            acc["extractor.update (per msg)"].append(pc() - t0)
        ex.note_sig_invalid(tick.sig_invalid)
        if tick.tick % dec != 0:
            continue
        t0 = pc()
        frame = ex.extract(tick.t)
        acc["extract (per decision)"].append(pc() - t0)
        pipe.last_frame = frame
        t0 = pc()
        r1 = pipe.protocol.process(frame)
        acc["protocol detector"].append(pc() - t0)
        t0 = pc()
        r2 = pipe.physics.process(frame)
        acc["physics detector"].append(pc() - t0)
        t0 = pc()
        r3 = pipe.anomaly.process(frame)
        acc["anomaly detector (ML)"].append(pc() - t0)
        t0 = pc()
        r4 = pipe.integrity.process()
        acc["integrity detector"].append(pc() - t0)
        t0 = pc()
        pipe.fusion.fuse(t=tick.t, wall_time=time.time(), results=[r1, r2, r3, r4],
                         integrity_status=pipe.integrity.status, telemetry=pipe._telemetry_dict())
        acc["fusion + telemetry dict"].append(pc() - t0)
        ex.clear_window_counts()


def bench(work: dict, ml: bool, repeat: int) -> dict:
    model = str(mg.MODEL_PATH) if ml else None
    names = ("parse (per datagram)", "extractor.update (per msg)", "extract (per decision)",
             "protocol detector", "physics detector", "anomaly detector (ML)", "integrity detector",
             "fusion + telemetry dict", "process_tick (decision ticks)", "process_tick (all ticks)")
    acc: dict[str, list[float]] = {k: [] for k in names}
    parser = MavlinkFrameParser()
    for _ in range(repeat):
        for t, data in work["datagrams"]:
            t0 = pc()
            parser.parse(data, t)
            acc["parse (per datagram)"].append(pc() - t0)
    streams = work["streams"]
    for _ in range(repeat):
        for cfg, ticks in streams:
            timed_run(IDSPipeline(cfg, model_path=model), ticks, acc)
    for _ in range(repeat):
        for cfg, ticks in streams:
            pipe = IDSPipeline(cfg, model_path=model)
            for tick in ticks:
                t0 = pc()
                a = pipe.process_tick(tick)
                dt = pc() - t0
                acc["process_tick (all ticks)"].append(dt)
                if a is not None:
                    acc["process_tick (decision ticks)"].append(dt)
    res = {k: stats_us(v) for k, v in acc.items() if v}
    import psutil
    gc.collect()
    proc = psutil.Process()
    rss0 = proc.memory_info().rss
    tracemalloc.start()
    base = tracemalloc.get_traced_memory()[0]
    peak_rss = rss0
    for cfg, ticks in streams:
        pipe = IDSPipeline(cfg, model_path=model)
        for tick in ticks:
            pipe.process_tick(tick)
        peak_rss = max(peak_rss, proc.memory_info().rss)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    res["_memory"] = {"tracemalloc_peak_kib": (peak - base) / 1024.0, "rss_mib_after": peak_rss / 2**20,
                      "rss_mib_before": rss0 / 2**20}
    res["_throughput_ticks_per_s"] = 1.0 / statistics.fmean(acc["process_tick (all ticks)"])
    return res


def profile(work: dict, ml: bool, top: int) -> None:
    model = str(mg.MODEL_PATH) if ml else None
    pipes = [(IDSPipeline(cfg, model_path=model), ticks) for cfg, ticks in work["streams"]]
    parser = MavlinkFrameParser()
    prof = cProfile.Profile()
    prof.enable()
    for pipe, ticks in pipes:
        for tick in ticks:
            pipe.process_tick(tick)
    for t, d in work["datagrams"]:
        parser.parse(d, t)
    prof.disable()
    pstats.Stats(prof).sort_stats("tottime").print_stats(top)


def table(res: dict) -> str:
    rows = ["| operation | n | p50 us | p95 us | mean us | max us |", "|---|---:|---:|---:|---:|---:|"]
    for k, v in res.items():
        if not k.startswith("_"):
            rows.append(f"| {k} | {v['n']} | {v['p50']:.1f} | {v['p95']:.1f} | {v['mean']:.1f} | {v['max']:.1f} |")
    m = res["_memory"]
    rows.append(f"\npeak heap {m['tracemalloc_peak_kib']:.0f} KiB (tracemalloc), RSS {m['rss_mib_after']:.1f} MiB; "
                f"{res['_throughput_ticks_per_s']:.0f} ticks/s")
    return "\n".join(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=None, help="write JSON results here")
    ap.add_argument("--repeat", type=int, default=3)
    ap.add_argument("--profile", action="store_true", help="also print cProfile top functions")
    ap.add_argument("--top", type=int, default=25)
    ap.add_argument("--only", choices=("ml", "no_ml"), default=None)
    a = ap.parse_args()
    work = build_workload()
    out: dict = {"python": sys.version.split()[0], "numpy": np.__version__, "repeat": a.repeat}
    for key, ml in (("no_ml", False), ("ml", True)):
        if (a.only and a.only != key) or (ml and not mg.MODEL_PATH.exists()):
            continue
        out[key] = bench(work, ml, a.repeat)
        print(f"\n== ML {'on' if ml else 'off'} ==\n{table(out[key])}")
        if a.profile:
            profile(work, ml, a.top)
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(json.dumps(out, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
