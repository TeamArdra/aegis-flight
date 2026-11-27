"""Real-flight campaign: benign controls + injected attack variants, each through the real InlineIpsBridge in 3 postures.

    python scripts/realworld/rw_campaign.py --tlogs <dir with ALFA telemetry> --out <dir> [--flights 12] [--workers 12]

Evidence tier REPLAY. Benign baselines are real ALFA flights (some contain real physical faults: those are not cyber
attacks; see the FP split in the summary). Attacks are INJECTED into the recordings and labelled as such.
"""
from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rw_lib as r  # noqa: E402

MODES = ("passive", "advisory", "active-ips")


def variants() -> list[r.Attack]:
    v: list[r.Attack] = []
    A = r.Attack
    for m in (10, 25, 50, 100, 500, 2000):
        v.append(A("gps_offset", {"m": m}))
    for rate in (0.5, 1, 2, 5, 10, 20):
        for brg in (45, 225):
            v.append(A("gps_drift", {"rate": rate, "bearing": brg}))
    v += [A("gps_freeze"), A("gps_jam")]
    for m in (-20, 5, 10, 20, 40, 80):
        v.append(A("alt_bias", {"m": m}))
    for ms in (3, 8, 15, 30):
        v.append(A("speed_mismatch", {"ms": ms}))
    for to in (5, 50):
        v.append(A("battery_jump", {"to": to}))
    v.append(A("frozen_attitude"))
    for sid in (2, 77, 200):
        v.append(A("rogue_sysid", {"sysid": sid}))
    for x in (3, 5, 10, 30):
        v.append(A("rate_spike", {"x": x}))
    v.append(A("seq_scramble"))
    for p in (0.1, 0.3, 0.6, 0.9):
        v.append(A("packet_loss", {"p": p}))
    for dur in (3, 10, 30):
        v.append(A("blackout", {}, dur=dur))
    for s in (0.5, 1.5, 5.0):
        v.append(A("latency", {"s": s}))
    for bits in (1, 4, 16):
        v.append(A("corrupt", {"bits": bits}))
    for kind in ("disarm", "force_arm", "do_set_mode", "set_mode_msg", "param_set", "rc_override", "waypoint",
                 "takeoff", "land", "rtl", "reboot"):
        for rate in (0.5, 2, 10):
            v.append(A(f"cmd_{kind}", {"rate": rate, "sysid": 66}))
    v.append(A("cmd_disarm", {"rate": 2, "sysid": 7}))
    v.append(A("cmd_do_set_mode", {"rate": 2, "sysid": 200}))
    for rate in (1, 5):
        v.append(A("gcs_replay", {"rate": rate}))
    # timing variants of a few
    for k, p in (("gps_offset", {"m": 100}), ("alt_bias", {"m": 40}), ("cmd_disarm", {"rate": 2, "sysid": 66})):
        v.append(A(k, p, start=60, dur=15))
        v.append(A(k, p, start=10, dur=10))
    return v


def one(task: tuple) -> dict:
    path, atk_spec, seg_s = task
    full = r.read_tlog(path, max_s=400.0)
    tm = r.motion_start(full)
    rec: dict = {"flight": path, "t_move": tm, "runs": {}}
    if tm is None and atk_spec is not None:
        rec.update(attack="SKIPPED(no motion)", kind="skipped", window=None, runs={})
        return rec
    skip = max(0.0, (tm if tm is not None else 25.0) - 30.0)   # attack defaults start 30 s in = when the vehicle starts moving
    frames = r.read_tlog(path, max_s=seg_s, skip_s=skip)
    rec.update(frames=len(frames), dur=frames[-1][0] if frames else 0, skip=skip)
    if atk_spec is None:
        inj, win, name, kind = set(), None, "BENIGN", "benign"
        f = frames
    else:
        atk = r.Attack(**atk_spec)
        f, inj = r.inject(frames, atk)
        win, name, kind = atk.window, atk.name, atk.kind
        changed = sum(1 for a, b in zip(sorted(frames, key=lambda x: x[0]), f, strict=False) if a[1] != b[1]) if len(f) == len(frames) else abs(len(f) - len(frames))
        rec["injection_effect_frames"] = changed + len(inj)
    rec.update(attack=name, kind=kind, window=win)
    for mode in MODES:
        t0 = time.time()
        try:
            x = r.run_bridge(f, mode, inj)
        except Exception as e:  # noqa: BLE001
            rec["runs"][mode] = {"error": repr(e)}
            continue
        d = x.__dict__.copy()
        d["secs"] = round(time.time() - t0, 2)
        rec["runs"][mode] = d
    return rec


def _scan(path: str):
    return path, r.motion_start(r.read_tlog(path, max_s=400.0))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tlogs", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--flights", type=int, default=12, help="flights the attack variants run on (benign runs use all)")
    ap.add_argument("--seg", type=float, default=120.0)
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--max-variants", type=int, default=0)
    ap.add_argument("--benign-only", action="store_true")
    a = ap.parse_args()
    logs = sorted(Path(a.tlogs).rglob("*.tlog"))
    with mp.Pool(a.workers) as pool:
        moving = [p for p, tm in pool.map(_scan, [str(x) for x in logs]) if tm is not None]
    step = max(1, len(moving) // a.flights)
    atk_flights = [Path(x) for x in moving[::step][:a.flights]]
    print(f"{len(moving)} of {len(logs)} flights have sustained motion; attacks run on {len(atk_flights)} of them", flush=True)
    vs = variants()
    if a.max_variants:
        vs = vs[:a.max_variants]
    tasks = [(str(p), None, a.seg) for p in logs]
    if not a.benign_only:
        tasks += [(str(p), v.__dict__ | {}, a.seg) for p in atk_flights for v in vs]
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    print(f"{len(logs)} flights benign; {len(atk_flights)} x {len(vs)} attack variants; {len(tasks)} tasks x 3 modes", flush=True)
    t0 = time.time()
    n = 0
    with mp.Pool(a.workers) as pool, (out / "results.jsonl").open("w") as fh:
        for rec in pool.imap_unordered(one, tasks, chunksize=2):
            fh.write(json.dumps(rec) + "\n")
            n += 1
            if n % 100 == 0:
                print(f"{n}/{len(tasks)} {time.time() - t0:.0f}s", flush=True)
    print(f"done {n} tasks in {time.time() - t0:.0f}s", flush=True)


if __name__ == "__main__":
    main()
