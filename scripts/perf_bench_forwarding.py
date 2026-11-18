"""Reproducible micro-benchmark of the inline FORWARDING path (host numbers, NOT a Raspberry Pi).

    python scripts/perf_bench_forwarding.py --out artifacts/perf/forwarding_before.json
    python scripts/perf_bench_forwarding.py --profile        # cProfile top functions of a mixed run

Workload: deterministic mixed telemetry (HEARTBEAT, GLOBAL_POSITION_INT incl. zero-trimmed payloads, ATTITUDE,
VFR_HUD, GPS_RAW_INT, SYS_STATUS) downlink and GCS heartbeats / trusted commands uplink, built once with the
corpus helpers of ``scripts/make_golden_forwarding.py`` and excluded from the timings. Per operation: p50 / p95 /
mean / max in microseconds, one ``perf_counter_ns`` pair around every call (its own overhead, roughly 0.1-0.2 us,
is included), plus ``bulk_mean_us`` = total time of a tight loop / calls, which carries no per-call timer cost.
Memory: peak Python heap (tracemalloc) while forwarding the whole workload through a bridge.
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
from collections.abc import Callable
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO / "src"))

import make_golden_forwarding as mgf  # noqa: E402
from aegisflight.hal.inline_ips import InlineIpsBridge  # noqa: E402
from aegisflight.mitigation.inline_policy import InlinePolicy  # noqa: E402
from aegisflight.mitigation.sanitizer import FrameSanitizer  # noqa: E402
from aegisflight.proxy.hooks import FrameContext  # noqa: E402
from aegisflight.proxy.transport import split_frames  # noqa: E402
from aegisflight.sources.mavlink_serial import MavlinkStreamFramer, _crc_x25  # noqa: E402


def workload(n_rounds: int = 400) -> dict:
    g = mgf.Gen()
    down, up = [], []
    for i in range(n_rounds):
        down += [g.heartbeat(1, True), g.gpi(1, rel=30 + i * 0.01, vx=4.0, hdg=0 if i % 2 else 9000), g.attitude(1, 0.01 * i),
                 g.vfr(1), g.gps_raw(1), g.sys_status(1), g.attitude(1), g.attitude(1)]
        if i % 4 == 0:
            up.append(g.heartbeat(255, compid=190))
        if i % 40 == 0:
            up.append(g.command_long(255, 22, float(i)))
    return {"down": down, "up": up, "stream": b"".join(down)}


def stats_us(samples_ns: list[int], bulk_ns: float | None = None, n: int = 0) -> dict:
    s = sorted(samples_ns)

    def q(p: float) -> float:
        return s[min(len(s) - 1, int(p * len(s)))] / 1000.0

    out = {"n": len(s), "p50_us": round(q(0.5), 3), "p95_us": round(q(0.95), 3),
           "mean_us": round(statistics.fmean(s) / 1000.0, 3), "max_us": round(s[-1] / 1000.0, 3)}
    if bulk_ns is not None and n:
        out["bulk_mean_us"] = round(bulk_ns / n / 1000.0, 3)
    return out


def timed(fn: Callable, args_list: list, repeat: int = 5) -> dict:
    """Per-call times over ``repeat`` passes of ``args_list`` + a bulk loop."""
    samples: list[int] = []
    pc = time.perf_counter_ns
    gc.collect()
    gc.disable()
    try:
        for _ in range(repeat):
            for a in args_list:
                t0 = pc()
                fn(*a)
                samples.append(pc() - t0)
        t0 = pc()
        for _ in range(repeat):
            for a in args_list:
                fn(*a)
        bulk = pc() - t0
    finally:
        gc.enable()
    return stats_us(samples, bulk, repeat * len(args_list))


def mk_ctx(raw: bytes, direction: str) -> FrameContext:
    fr = split_frames(raw)[0][0]
    return FrameContext(direction=direction, raw=fr.raw, recv_ns=5_000_000_000, sysid=fr.sysid,  # type: ignore[arg-type]
                        compid=fr.compid, seq=fr.seq, msgid=fr.msgid, signed=fr.signed)


def new_bridge(posture: str) -> tuple[InlineIpsBridge, mgf.Link, mgf.Link, mgf.Clk]:
    clk = mgf.Clk(1000.0)
    b, fc, gcs = mgf.make_bridge(mgf.Scn("bench"), posture, clk)
    return b, fc, gcs, clk


def run_all(quick: bool = False) -> dict:
    w = workload(100 if quick else 400)
    res: dict = {"frames_down": len(w["down"]), "frames_up": len(w["up"]), "stream_bytes": len(w["stream"])}
    rep = 2 if quick else 5
    with mgf.deterministic():
        body = w["down"][1][1:-2]
        res["crc_x25_30B"] = timed(_crc_x25, [(body, 0xFFFF)], 2000 if quick else 20000)
        res["crc_x25_263B"] = timed(_crc_x25, [(bytes(263), 0xFFFF)], 500 if quick else 4000)

        # serial stream framer over realistic read sizes (the transport reads up to 4096 B)
        data = w["stream"]
        for size in (64, 256, 4096):
            chunks = [data[i:i + size] for i in range(0, len(data), size)]
            t = []
            gc.collect()
            for _ in range(rep):
                fr = MavlinkStreamFramer()
                t0 = time.perf_counter_ns()
                for c in chunks:
                    fr.feed(c)
                t.append(time.perf_counter_ns() - t0)
            best = min(t)
            res[f"framer_feed_read{size}"] = {
                "bytes_per_s": int(len(data) / (best / 1e9)), "MB_per_s": round(len(data) / (best / 1e9) / 1e6, 3),
                "us_per_frame": round(best / len(w["down"]) / 1000.0, 3)}
        fr = MavlinkStreamFramer()
        chunks = [data[i:i + 256] for i in range(0, len(data), 256)]
        res["framer_feed_call_256B"] = timed(fr.feed, [(c,) for c in chunks], 1)
        fr = MavlinkStreamFramer()
        res["framer_feed_1frame"] = timed(fr.feed, [(f,) for f in w["down"]], 1)

        res["split_frames_1frame"] = timed(split_frames, [(f,) for f in w["down"]], rep)
        trio = [b"".join(w["down"][i:i + 3]) for i in range(0, len(w["down"]) - 3, 3)]
        res["split_frames_3frames"] = timed(split_frames, [(c,) for c in trio], rep)

        dctx = [(mk_ctx(f, "down"),) for f in w["down"]]
        uctx = [(mk_ctx(f, "up"),) for f in w["up"]]
        for posture in ("passive", "active-ips"):
            pol = InlinePolicy(FrameSanitizer(), clock=mgf.Clk(1000.0))
            pol.set_enforce(posture == "active-ips")
            res[f"policy_down_{posture}"] = timed(pol.down, dctx, rep)
            res[f"policy_up_{posture}"] = timed(pol.up, uctx, rep)
        fr0 = split_frames(w["down"][1])[0][0]
        res["frame_context_create"] = timed(
            lambda: FrameContext(direction="down", raw=fr0.raw, recv_ns=1, sysid=fr0.sysid, compid=fr0.compid,
                                 seq=fr0.seq, msgid=fr0.msgid, signed=False), [()] * 1000, 20)

        for posture in ("passive", "active-ips"):
            b, fc, gcs, clk = new_bridge(posture)

            def handle(stamp, d, direction, b=b, gcs=gcs, fc=fc):
                b._handle(stamp, d, direction)
                if len(gcs.sent) > 4096:
                    gcs.sent.clear()
                if len(fc.sent) > 4096:
                    fc.sent.clear()
                if len(b.tap._q) > 4096:
                    b.tap.poll()
            res[f"bridge_handle_down_{posture}"] = timed(
                handle, [(1_000_000_000 + i, f, "down") for i, f in enumerate(w["down"])], rep)
            res[f"bridge_handle_up_{posture}"] = timed(
                handle, [(1_000_000_000 + i, f, "up") for i, f in enumerate(w["up"])], rep)

        b, fc, gcs, clk = new_bridge("passive")
        mg = b.mgmt

        def emit():
            clk.t += 10.0
            mg._text("AEGIS: test alert", 4, 2, "alert")
            gcs.sent.clear()
        res["mgmt_text_emit"] = timed(emit, [()] * 200, 1 if quick else 5)

        def status():
            clk.t += 10.0
            mg._send_status()
            gcs.sent.clear()
        res["mgmt_status_emit"] = timed(status, [()] * 200, 1 if quick else 5)

        mem = {}
        for posture in ("passive", "active-ips"):
            b, fc, gcs, clk = new_bridge(posture)
            gc.collect()
            tracemalloc.start()
            base = tracemalloc.get_traced_memory()[0]
            for i, f in enumerate(w["down"]):
                b._handle(1_000_000_000 + i, f, "down")
                gcs.sent.clear()
                b.tap.poll()
            for i, f in enumerate(w["up"]):
                b._handle(1_000_000_000 + i, f, "up")
                fc.sent.clear()
                b.tap.poll()
            cur, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            mem[f"bridge_{posture}"] = {"peak_bytes_over_baseline": peak - base, "retained_bytes": cur - base}
        fr = MavlinkStreamFramer()
        gc.collect()
        tracemalloc.start()
        base = tracemalloc.get_traced_memory()[0]
        for i in range(0, len(data), 4096):
            fr.feed(data[i:i + 4096])
        cur, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        mem["framer_4096B_reads"] = {"peak_bytes_over_baseline": peak - base, "retained_bytes": cur - base}
        res["memory"] = mem
    return res


def profile() -> None:
    w = workload(150)
    with mgf.deterministic():
        b, fc, gcs, clk = new_bridge("active-ips")
        fr = MavlinkStreamFramer()
        pr = cProfile.Profile()
        pr.enable()
        for _ in range(3):
            for i in range(0, len(w["stream"]), 256):
                for frame in fr.feed(w["stream"][i:i + 256]):
                    b._handle(1_000_000_000, frame, "down")
                gcs.sent.clear()
                b.tap.poll()
            for f in w["up"]:
                b._handle(1_000_000_000, f, "up")
                fc.sent.clear()
                b.tap.poll()
        pr.disable()
    pstats.Stats(pr).sort_stats("cumulative").print_stats(22)
    pstats.Stats(pr).sort_stats("tottime").print_stats(14)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--profile", action="store_true")
    ap.add_argument("--quick", action="store_true")
    a = ap.parse_args()
    if a.profile:
        profile()
        return 0
    res = run_all(a.quick)
    for k, v in res.items():
        print(k, v)
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(json.dumps(res, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
