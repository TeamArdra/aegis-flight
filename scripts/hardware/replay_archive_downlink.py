#!/usr/bin/env python
"""Replay the downlink frames of an ``aegis onboard`` run archive through the detector pipeline.

Offline and read-only (SIM / SITL evidence tooling, no transmit path): it reads
``frames_down*.jsonl`` from a run directory written by ``BridgeRunArchive``, feeds the forwarded frames to
``IDSPipeline`` under a profile and prints every alert decision plus the benign position-residual
distribution. Used to check whether an alert seen in a live run is reproducible from the archive.

    python scripts/hardware/replay_archive_downlink.py <run dir> --profile configs/universal_flight \
        --frames frames_down.2.jsonl --until 3160 --exclude 596-665 --exclude 1496-1565

``--exclude A-B`` removes a window (seconds from the first frame, e.g. a scripted attack burst) from the
benign statistics. Frames are replayed in archive order with their recorded receive times.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from aegisflight.config import load_config  # noqa: E402
from aegisflight.pipeline import IDSPipeline  # noqa: E402
from aegisflight.sources.mavlink_live import frame_ticks  # noqa: E402


def _load_frames(path: Path, until_s: float) -> list[tuple[float, bytes]]:
    frames: list[tuple[float, bytes]] = []
    t0: float | None = None
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            row = json.loads(line)
            if row.get("verdict") != "forwarded":
                continue
            t = row["t_ns"] / 1e9
            t0 = t if t0 is None else t0
            if t - t0 > until_s:
                break
            frames.append((t, bytes.fromhex(row["raw"])))
    return frames


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run_dir", type=Path)
    ap.add_argument("--profile", default="configs/universal_flight")
    ap.add_argument("--frames", default="frames_down.jsonl", help="archive file inside the run dir")
    ap.add_argument("--until", type=float, default=1e9, help="stop after this many seconds of capture")
    ap.add_argument("--exclude", action="append", default=[], metavar="A-B")
    ap.add_argument("--sample-rate-hz", type=float, default=10.0)
    args = ap.parse_args()

    windows = [tuple(float(x) for x in w.split("-", 1)) for w in args.exclude]
    cfg = load_config(ROOT / args.profile if not Path(args.profile).is_absolute() else Path(args.profile))
    cfg.detector.setdefault("protocol", {})["auto_rate_baseline"] = True
    frames = _load_frames(args.run_dir / args.frames, args.until)
    if not frames:
        print("no forwarded frames found", file=sys.stderr)
        return 2
    pipe = IDSPipeline(cfg, model_path=None)
    rows: list[tuple[float, float, bool, str]] = []
    for tick in frame_ticks(iter(frames), sample_rate_hz=args.sample_rate_hz):
        asmt = pipe.process_tick(tick)
        if asmt is None or pipe.last_frame is None:
            continue
        rows.append((asmt.t, pipe.last_frame.pos_residual_m, bool(asmt.is_alert), asmt.attack_type.value))

    def excluded(t: float) -> bool:
        return any(a <= t <= b for a, b in windows)

    benign = [r for r in rows if r[0] > 30.0 and not excluded(r[0])]
    resid = sorted(r[1] for r in benign)
    n = len(resid)
    print(f"frames={len(frames)} decisions={len(rows)} benign_decisions={n}")
    if n:
        print(
            f"benign pos_residual_m: p50={resid[n // 2]:.2f} p99={resid[int(n * 0.99)]:.2f} "
            f"p99.9={resid[int(n * 0.999)]:.2f} max={resid[-1]:.2f}"
        )
    alerts = [r for r in benign if r[2]]
    print(f"benign alert decisions: {len(alerts)}")
    for t, res, _, kind in alerts[:50]:
        print(f"  t={t:8.1f}s {kind} pos_residual_m={res:.1f}")
    return 0 if not alerts else 1


if __name__ == "__main__":
    raise SystemExit(main())
