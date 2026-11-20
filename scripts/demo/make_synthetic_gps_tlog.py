"""Deterministic SIMULATED GPS demo fixture: a repo-framed tlog that was never measured on any vehicle.

    .venv/Scripts/python.exe scripts/demo/make_synthetic_gps_tlog.py generate --out demo/fixtures
    .venv/Scripts/python.exe scripts/demo/make_synthetic_gps_tlog.py evaluate --out <dir> [--config-dir <dir>]

ENVIRONMENT: synthetic (hand-written trajectory, replayed). Every coordinate here is computed by this script
from a fixed origin; nothing came from a GPS receiver, a Pixhawk or a flight log. The file name carries the label
so that ``aegis serve --source replay`` shows it in the dashboard's source bar next to the REPLAY badge. Do not
send these frames to any vehicle: this script only writes a local file and has no transmit path.

The phases are the team's own and the attacks are separable by construction (no sensor model, no wind, a
constant-speed straight track), so a detection here shows only that the pipeline and the dashboard work end to
end. It is not spoofing-detection evidence. The sidecar ``*.groundtruth.json`` is read by the ``evaluate`` scoring
only; detectors see the MAVLink frames and nothing else.

Frames are MAVLink 2 in the same ``>Q`` (unix microseconds) + frame layout that
``scripts/hardware/run_serial_ids.py --tlog`` writes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from pymavlink.dialects.v20 import ardupilotmega as apm

FIXTURE_NAME = "SIMULATED_GPS_not_measured_v1.tlog"
LABEL = "SIMULATED GPS - never measured on any vehicle or receiver"
SEED = 20261103  # fixed: the position jitter below, and therefore the bytes, are reproducible
T0_UNIX_S = 1_790_000_000.0  # fixed synthetic start time; it is not the time of any real event
TICK_HZ = 10
LAT0, LON0 = 12.9, 77.5  # synthetic origin
M_PER_DEG = 111_320.0
SPEED_MS = 10.0  # true track: east at 10 m/s
JITTER_M = 0.3  # 1-sigma reported-position jitter
EKF_SOLUTION = (apm.EKF_ATTITUDE | apm.EKF_VELOCITY_HORIZ | apm.EKF_VELOCITY_VERT | apm.EKF_POS_HORIZ_REL
                | apm.EKF_POS_HORIZ_ABS | apm.EKF_POS_VERT_ABS | apm.EKF_PRED_POS_HORIZ_REL
                | apm.EKF_PRED_POS_HORIZ_ABS)


@dataclass(frozen=True)
class Phase:
    name: str
    start_s: float
    end_s: float
    description: str
    expected: str


PHASES: tuple[Phase, ...] = (
    Phase("NOMINAL", 0.0, 30.0, "reported track = true track; 3D fix, 10 satellites, healthy estimator",
          "no threat decision"),
    Phase("SLOW_DRIFT", 30.0, 50.0, "reported position drifts north at 1 m/s; velocity stays truthful",
          "no alert: below the documented ~4 m/s floor with ML off (known limitation)"),
    Phase("FAST_DRIFT", 50.0, 70.0, "the drift accelerates to 6 m/s; velocity stays truthful",
          "GPS_SPOOFING from the position-residual rule"),
    Phase("SUDDEN_JUMP", 70.0, 85.0, "reported position jumps a further 200 m east, then holds that offset",
          "GPS_SPOOFING at the jump; the held offset is forgotten within the residual window (known limitation)"),
    Phase("GNSS_LOSS", 85.0, 105.0, "offset removed (return jump); GPS_RAW_INT reports fix_type 1, 3 satellites",
          "GPS_SPOOFING at the return jump, then DOS 'GNSS fix lost'"),
    Phase("RECOVERY", 105.0, 140.0, "3D fix, 10 satellites, reported track = true track",
          "alerts stop and the threat clears"),
)
DURATION_S = PHASES[-1].end_s


def phase_at(t: float) -> Phase:
    for p in PHASES:
        if p.start_s <= t < p.end_s:
            return p
    return PHASES[-1]


def _spoof_offset(t: float) -> tuple[float, float]:
    """(north, east) m added to the true position at time ``t``."""
    if t < 30.0:
        return 0.0, 0.0
    if t < 50.0:
        return (t - 30.0) * 1.0, 0.0
    if t < 70.0:
        return 20.0 + (t - 50.0) * 6.0, 0.0
    if t < 85.0:
        return 140.0, 200.0
    return 0.0, 0.0


def _frames(mav: apm.MAVLink, k: int, t: float, rng: random.Random) -> Iterator[bytes]:
    """One 10 Hz tick. HEARTBEAT/SYS_STATUS 1 Hz, GPS_RAW_INT/EKF_STATUS_REPORT 2 Hz, position 5 Hz,
    ATTITUDE/VFR_HUD 10 Hz: the shape of the bench stream at a lower total rate."""
    boot_ms = int(round(t * 1000))
    yaw = math.pi / 2  # east
    north_off, east_off = _spoof_offset(t)
    lost = phase_at(t).name == "GNSS_LOSS"
    fix, sats = (1, 3) if lost else (3, 10)
    north = north_off + rng.gauss(0.0, JITTER_M)
    east = SPEED_MS * t + east_off + rng.gauss(0.0, JITTER_M)
    lat = int(round((LAT0 + north / M_PER_DEG) * 1e7))
    lon = int(round((LON0 + east / (M_PER_DEG * math.cos(math.radians(LAT0)))) * 1e7))
    if k % TICK_HZ == 0:
        yield mav.heartbeat_encode(apm.MAV_TYPE_QUADROTOR, apm.MAV_AUTOPILOT_ARDUPILOTMEGA,
                                   apm.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED | apm.MAV_MODE_FLAG_SAFETY_ARMED,
                                   3, apm.MAV_STATE_ACTIVE).pack(mav)
        gps = apm.MAV_SYS_STATUS_SENSOR_GPS
        yield mav.sys_status_encode(gps, gps, gps, 300, 16000, 500, 90, 0, 0, 0, 0, 0, 0).pack(mav)
    if k % (TICK_HZ // 2) == 0:
        yield mav.gps_raw_int_encode(int(t * 1e6), fix, lat, lon, 960000, 100 if not lost else 9999, 100,
                                     int(SPEED_MS * 100), 9000, sats).pack(mav)
        yield mav.ekf_status_report_encode(EKF_SOLUTION, 0.01, 0.01, 0.01, 0.01, 0.0, 0.0).pack(mav)
    if k % 2 == 0:
        yield mav.global_position_int_encode(boot_ms, lat, lon, 960000, 60000, 0, int(SPEED_MS * 100), 0,
                                             9000).pack(mav)
    yield mav.attitude_encode(boot_ms, 0.0, 0.0, yaw, 0.0, 0.0, 0.0).pack(mav)
    yield mav.vfr_hud_encode(SPEED_MS, SPEED_MS, 90, 50, 960.0, 0.0).pack(mav)


def build_tlog_bytes() -> bytes:
    """The whole fixture. Same inputs, same bytes: no clock, no global RNG."""
    rng = random.Random(SEED)
    mav = apm.MAVLink(None, srcSystem=1, srcComponent=1)
    out = bytearray()
    for k in range(int(round(DURATION_S * TICK_HZ))):
        t = k / TICK_HZ
        for offset, frame in enumerate(_frames(mav, k, t, rng)):
            # frames of one tick are spaced 1 ms apart, inside the tick
            out += struct.pack(">Q", int(round((T0_UNIX_S + t + offset * 0.001) * 1e6))) + frame
    return bytes(out)


def groundtruth() -> dict:
    return {
        "label": LABEL,
        "environment": "synthetic fixture, replayed",
        "seed": SEED, "tick_hz": TICK_HZ, "t0_unix_s": T0_UNIX_S, "duration_s": DURATION_S,
        "origin": {"lat": LAT0, "lon": LON0, "note": "synthetic"},
        "true_track": f"east at {SPEED_MS} m/s, straight, constant altitude",
        "phases": [vars(p) for p in PHASES],
    }


def generate(out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / FIXTURE_NAME
    data = build_tlog_bytes()
    path.write_bytes(data)
    truth = groundtruth() | {"tlog_sha256": hashlib.sha256(data).hexdigest(), "tlog_bytes": len(data)}
    path.with_suffix(".groundtruth.json").write_text(json.dumps(truth, indent=2) + "\n", encoding="utf-8")
    return path


def read_frames(data: bytes) -> list[tuple[float, bytes]]:
    """Split the fixture into (unix seconds, frame). MAVLink 2, unsigned: this fixture carries nothing else."""
    frames: list[tuple[float, bytes]] = []
    i = 0
    while i < len(data):
        ts = struct.unpack(">Q", data[i:i + 8])[0] / 1e6
        n = 12 + data[i + 9]
        frames.append((ts, data[i + 8:i + 8 + n]))
        i += 8 + n
    return frames


def evaluate(out_dir: Path | None, config_dir: str | None = None, tlog: Path | None = None) -> dict:
    """Run the real pipeline (ML off, no firmware verifier: what ``aegis serve --source replay`` builds) and score
    each decision against the phase table. The phase table is read after the decision, never by a detector."""
    from aegisflight.config import load_config
    from aegisflight.pipeline import IDSPipeline
    from aegisflight.sources.mavlink_live import frame_ticks

    data = tlog.read_bytes() if tlog is not None else build_tlog_bytes()
    frames = read_frames(data)
    cfg = load_config(config_dir) if config_dir else load_config()
    pipe = IDSPipeline(cfg, model_path=None, firmware_dir=None)
    rows: list[dict] = []
    per_phase: dict[str, dict] = {
        p.name: {"decisions": 0, "threat": 0, "alerts": 0, "alert_types": {}, "first_alert_s": None,
                 "first_threat_s": None} for p in PHASES}
    timeline: list[dict] = []
    for tick in frame_ticks(frames, sample_rate_hz=TICK_HZ):
        a = pipe.process_tick(tick)
        if a is None:
            continue
        s = per_phase[phase_at(a.t).name]
        s["decisions"] += 1
        s["threat"] += int(bool(a.threat))
        frame = pipe.last_frame
        timeline.append({"t": round(a.t, 3), "score": round(a.threat_score, 4), "threat": bool(a.threat),
                         "alert": bool(a.is_alert), "type": a.attack_type.value,
                         "pos_residual_m": round(frame.pos_residual_m, 2) if frame is not None else None,
                         "gps_fix_type": frame.snapshot.gps_fix_type if frame is not None else None})
        if a.threat and s["first_threat_s"] is None:
            s["first_threat_s"] = round(a.t, 3)
        if a.is_alert:
            s["alerts"] += 1
            kind = a.attack_type.value
            s["alert_types"][kind] = s["alert_types"].get(kind, 0) + 1
            if s["first_alert_s"] is None:
                s["first_alert_s"] = round(a.t, 3)
            rows.append({"t": round(a.t, 3), "phase": phase_at(a.t).name, "type": kind,
                         "score": round(a.threat_score, 4), "evidence": a.evidence})
    result = {
        "label": LABEL,
        "environment": "SIM (synthetic fixture through the real pipeline); claim class: none",
        "tlog_sha256": hashlib.sha256(data).hexdigest(), "frames": len(frames),
        "config_dir": config_dir or "configs (Stage-1 default)", "ml_enabled": False,
        "per_phase": per_phase, "alerts": rows, "timeline": timeline,
    }
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "evaluation.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate", help="write the fixture and its ground-truth sidecar")
    g.add_argument("--out", type=Path, required=True)
    e = sub.add_parser("evaluate", help="run the pipeline on the fixture and score it per phase")
    e.add_argument("--out", type=Path, required=True)
    e.add_argument("--config-dir", default=None)
    e.add_argument("--tlog", type=Path, default=None, help="default: rebuild the fixture in memory")
    args = ap.parse_args(argv)
    if args.cmd == "generate":
        path = generate(args.out)
        print(f"wrote {path} ({path.stat().st_size} bytes)  SIMULATED GPS, not measured")
        return 0
    result = evaluate(args.out, args.config_dir, args.tlog)
    for name, s in result["per_phase"].items():
        print(f"{name:12s} decisions={s['decisions']:4d} threat={s['threat']:4d} alerts={s['alerts']:3d} "
              f"{s['alert_types']} first_alert={s['first_alert_s']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
