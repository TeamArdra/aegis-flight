"""Build the hardware-in-the-loop scenario set: one representative injected scenario per attack kind + real benign flights.

Each scenario is a pickle {frames:[(t,raw,dir)], window, inj_up:[raw], name} of a 40 s segment of a REAL ALFA flight
(starting 15 s before sustained motion; attack at 12 s for 15 s). Replayed at 1x over the real radio by rw_hw_run.py.
"""
from __future__ import annotations

import argparse
import pickle
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rw_lib as r  # noqa: E402

SEG = 40.0
A = r.Attack


def specs() -> list[r.Attack]:
    st, du = 12.0, 15.0
    out = [
        A("gps_offset", {"m": 100}, st, du), A("gps_drift", {"rate": 2, "bearing": 45}, st, du), A("gps_freeze", {}, st, du),
        A("gps_jam", {}, st, du), A("alt_bias", {"m": 40}, st, du), A("speed_mismatch", {"ms": 15}, st, du),
        A("battery_jump", {"to": 5}, st, du), A("frozen_attitude", {}, st, du), A("rogue_sysid", {"sysid": 77}, st, du),
        A("rate_spike", {"x": 10}, st, du), A("seq_scramble", {}, st, du), A("packet_loss", {"p": 0.3}, st, du),
        A("blackout", {}, st, 8.0), A("latency", {"s": 1.5}, st, du), A("corrupt", {"bits": 4}, st, du),
        A("gcs_replay", {"rate": 2}, st, du),
    ]
    for k in ("disarm", "force_arm", "do_set_mode", "set_mode_msg", "param_set", "rc_override", "waypoint", "takeoff", "land",
              "rtl", "reboot"):
        out.append(A(f"cmd_{k}", {"rate": 2, "sysid": 66}, st, du))
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tlogs", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--benign-flights", type=int, default=2)
    a = ap.parse_args()
    logs = sorted(Path(a.tlogs).rglob("*.tlog"))
    moving = []
    for p in logs:
        full = r.read_tlog(p, max_s=400.0)
        tm = r.motion_start(full)
        if tm is not None:
            moving.append((p, tm))
    # choose flights that raise no alert in a replay of the exact segment (a clean baseline), else the first ones
    clean = []
    for p, tm in moving:
        fr = r.read_tlog(p, max_s=SEG, skip_s=max(0.0, tm - 15.0))
        res = r.run_bridge(fr, "passive")
        if not res.alerts:
            clean.append((p, tm))
    base = (clean or moving)[0]
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    n = 0
    p, tm = base
    frames = r.read_tlog(p, max_s=SEG, skip_s=max(0.0, tm - 15.0))
    for atk in specs():
        f, inj = r.inject(frames, atk)
        name = f"{n:02d}_{atk.kind}"
        pickle.dump({"name": name, "attack": atk.name, "kind": atk.kind, "window": atk.window, "frames": f, "inj_up": sorted(inj),
                     "flight": str(p)}, open(out / f"{name}.pkl", "wb"))
        n += 1
    for q, tq in (clean[:a.benign_flights] if len(clean) >= a.benign_flights else moving[:a.benign_flights]):
        fr = r.read_tlog(q, max_s=SEG, skip_s=max(0.0, tq - 15.0))
        name = f"{n:02d}_benign"
        pickle.dump({"name": name, "attack": "BENIGN", "kind": "benign", "window": None, "frames": fr, "inj_up": [], "flight": str(q)},
                    open(out / f"{name}.pkl", "wb"))
        n += 1
    print(f"{n} scenarios in {out}; base flight {base[0]} (t_move {base[1]:.0f}s); {len(clean)} clean moving flights")


if __name__ == "__main__":
    main()
