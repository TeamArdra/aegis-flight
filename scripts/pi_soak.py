#!/usr/bin/env python3
"""Soak test of the inline bridge over real Linux serial devices (pseudo-terminal pairs), no hardware needed.

    python scripts/pi_soak.py --seconds 60 --rate-mult 5 --mode active-ips

Topology (all on one machine, POSIX only):

    FC emulator --pty A--> [SerialMavlinkTransport] InlineIpsBridge [SerialMavlinkTransport] --pty B--> GCS emulator

The two emulators run in a CHILD process so the CPU and memory reported for the parent are the bridge's alone.
The downlink is the deterministic synthetic stream of ``scripts/make_golden.py`` (``benign``), replayed in real time
at ``--rate-mult`` x its native ~27 frames/s (x5 is about an ArduCopter telemetry link, ~140 frames/s); the GCS side
sends a 1 Hz heartbeat and, every 10 s, a harmless DO_SET_MODE from the trusted sysid 255. Reports frames sent vs
received on each side (loss), the bridge's own CPU % of one core, peak RSS and per-frame latency, ML off.
This measures the software path on the host it runs on; it is not a flight or radio test.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import pty
import sys
import threading
import time
import tty
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "scripts"))


def _emulators(master_a: int, master_b: int, seconds: float, mult: float, q) -> None:
    from pymavlink.dialects.v20 import common as mav2

    import make_golden as mg
    from aegisflight.proxy.transport import split_frames

    frames = mg.gen_stream("benign", 5, 70.0)
    stop = threading.Event()
    counts = {"fc_sent": 0, "gcs_rx": 0, "gcs_sent": 0, "fc_rx": 0}

    def fc_writer() -> None:
        t0 = time.monotonic()
        i, n, span = 0, len(frames), frames[-1][0] + 0.1
        while not stop.is_set():
            lap, (t, raw) = divmod(i, n)[0], frames[i % n]
            due = t0 + ((lap * span) + t) / mult
            delay = due - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            os.write(master_a, raw)
            counts["fc_sent"] += 1
            i += 1

    def reader(fd: int, key: str) -> None:
        while not stop.is_set():
            try:
                data = os.read(fd, 65536)
            except OSError:
                return
            # frames the bridge itself adds toward the GCS (alerts, status, cross-end summary) come from comp 191/192
            counts[key] += sum(1 for fr in split_frames(data, 4096)[0] if fr.compid not in (191, 192))

    def gcs_writer() -> None:
        enc = mav2.MAVLink(None, srcSystem=255, srcComponent=190)
        t0, k = time.monotonic(), 0
        while not stop.is_set():
            time.sleep(max(0.0, t0 + k - time.monotonic()))
            # pymavlink's pack() does not advance the 8-bit sequence counter (send() does): advance it like a real GCS
            hb = enc.heartbeat_encode(6, 8, 0, 0, 4).pack(enc)
            enc.seq = (enc.seq + 1) % 256
            os.write(master_b, bytes(hb))
            counts["gcs_sent"] += 1
            if k % 10 == 5:
                cmd = enc.command_long_encode(1, 1, 176, 0, 1, 5, 0, 0, 0, 0, 0).pack(enc)
                enc.seq = (enc.seq + 1) % 256
                os.write(master_b, bytes(cmd))
                counts["gcs_sent"] += 1
            k += 1

    threads = [threading.Thread(target=f, daemon=True) for f in (fc_writer, gcs_writer)]
    threads += [threading.Thread(target=reader, args=(master_b, "gcs_rx"), daemon=True),
                threading.Thread(target=reader, args=(master_a, "fc_rx"), daemon=True)]
    for th in threads:
        th.start()
    time.sleep(seconds)
    stop.set()
    time.sleep(1.0)  # let the last frames drain
    q.put(counts)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=60.0)
    ap.add_argument("--rate-mult", type=float, default=5.0)
    ap.add_argument("--mode", choices=["passive", "advisory", "active-ips"], default="active-ips")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    import psutil

    from aegisflight.hal.inline_ips import InlineIpsBridge
    from aegisflight.sources.mavlink_serial import SerialMavlinkTransport

    master_a, slave_a = pty.openpty()
    master_b, slave_b = pty.openpty()
    for fd in (slave_a, slave_b):
        tty.setraw(fd)
    fc = SerialMavlinkTransport(os.ttyname(slave_a), baudrate=115200, accept_unverified_ids=True)
    gcs = SerialMavlinkTransport(os.ttyname(slave_b), baudrate=115200, accept_unverified_ids=True)
    ctx = mp.get_context("fork")
    q = ctx.Queue()
    child = ctx.Process(target=_emulators, args=(master_a, master_b, a.seconds, a.rate_mult, q))
    fc.start()
    gcs.start()
    bridge = InlineIpsBridge(fc, gcs, mode=a.mode)
    bridge.start()
    proc = psutil.Process()
    cpu0, wall0 = sum(proc.cpu_times()[:2]), time.monotonic()
    child.start()
    peak_rss = proc.memory_info().rss
    while time.monotonic() - wall0 < a.seconds + 1.0:
        time.sleep(1.0)
        peak_rss = max(peak_rss, proc.memory_info().rss)
    cpu1, wall1 = sum(proc.cpu_times()[:2]), time.monotonic()
    counts = q.get(timeout=30)
    child.join(timeout=10)
    st = bridge.status()
    bridge.close()
    down_loss = counts["fc_sent"] - counts["gcs_rx"]
    up_loss = counts["gcs_sent"] - counts["fc_rx"]
    res = {
        "mode": a.mode, "seconds": round(wall1 - wall0, 1), "rate_mult": a.rate_mult,
        "downlink_frames_per_s": round(counts["fc_sent"] / a.seconds, 1),
        "downlink": {"sent": counts["fc_sent"], "received_at_gcs": counts["gcs_rx"], "lost": down_loss},
        "uplink": {"sent": counts["gcs_sent"], "received_at_fc": counts["fc_rx"], "lost": up_loss},
        "bridge_cpu_percent_of_one_core": round(100.0 * (cpu1 - cpu0) / (wall1 - wall0), 1),
        "bridge_peak_rss_mib": round(peak_rss / 2**20, 1),
        "frame_latency_us": st["latency_us"],
        "analyser": {k: st["analyser"][k] for k in ("decisions", "alerts", "errors")},
        "policy": {k: v for k, v in st["policy"].items() if k.startswith(("dropped", "suspect", "contested", "resyncs", "hook"))},
        "bridge_dropped": {"down": st["frames"]["dropped_down"], "up": st["frames"]["dropped_up"]},
        "tap_overflow": st["frames"]["tap_overflow"], "send_failures": st["frames"]["send_failures"],
    }
    print(json.dumps(res, indent=2))
    if a.out:
        Path(a.out).write_text(json.dumps(res, indent=2), encoding="utf-8")
    return 0 if down_loss <= 1 and up_loss <= 1 else 1


if __name__ == "__main__":
    raise SystemExit(main())
