"""Deterministic driver shared by the dashboard payload guard test and scripts/perf_bench_backend.py.

Drives ``LiveEngine._process`` tick by tick (no wall-clock pacing) on a SIM source and on a REPLAY of a SYNTHETIC
tlog, capturing every ``update`` message exactly as ``ws.send_json`` would serialise it. Only fields that depend on
the wall clock are masked (``run_id``, ``threat.latency_ms``, mitigation action timestamps that use time.time()).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import struct
import tempfile
from pathlib import Path

from pymavlink.dialects.v20 import common as mav

from aegisflight.backend.engine import LiveEngine
from aegisflight.backend.sources import SourceSpec, iter_tlog_frames
from aegisflight.sources.mavlink_live import frame_ticks

T0_UNIX = 1_792_000_000.0


def canonical(msg: dict) -> str:
    """Same separators / ensure_ascii as starlette's WebSocket.send_json."""
    return json.dumps(msg, separators=(",", ":"), ensure_ascii=False, sort_keys=False)


def synth_tlog(path: Path, seconds: float = 40.0) -> Path:
    """SYNTHETIC moving 10 Hz link (made up here): position drifts, fix drops for a stretch, one GCS command."""
    m = mav.MAVLink(None, srcSystem=1, srcComponent=1)
    out = []
    for k in range(int(seconds * 10)):
        t = k / 10
        msgs = []
        if k % 10 == 0:
            msgs.append(m.heartbeat_encode(2, 3, 81, 0, 4, 3))
            msgs.append(m.sys_status_encode(0, 0, 0, 500, 16000 - k, -1, 90 - k // 100, 0, 0, 0, 0, 0, 0))
        fix = 1 if 200 <= k < 260 else 3
        if k % 5 == 0:
            msgs.append(m.gps_raw_int_encode(int(t * 1e6), fix, 129_000_000 + k * 40, 775_000_000 + k * 25,
                                             900_000 + (k % 7) * 100, 100, 100, 500, 0, 10 if fix == 3 else 3))
        if k % 2 == 0:
            msgs.append(m.global_position_int_encode(int(t * 1000), 129_000_000 + k * 40, 775_000_000 + k * 25,
                                                     900_000 + (k % 7) * 100, 50_000 + k * 10, 400, 100, 0, 0))
            msgs.append(m.vfr_hud_encode(12.0 + (k % 5) * 0.1, 12.0, 28 + k // 50, 0, 900.0 + k * 0.01, 0.2))
        msgs.append(m.attitude_encode(int(t * 1000), 0.01 * (k % 9), -0.02 * (k % 5), 0.5 + k * 0.001, 0.0, 0.0, 0.0))
        for msg in msgs:
            m.seq = (m.seq + 1) & 0xFF
            out.append((t, bytes(msg.pack(m))))
    path.write_bytes(b"".join(struct.pack(">Q", int(round((T0_UNIX + t) * 1e6))) + f for t, f in out))
    return path


def mask(msg: dict) -> dict:
    """Copy with the wall-clock-dependent leaves neutralised (identity of everything else is preserved)."""
    d = json.loads(canonical(msg))
    d["run_id"] = "RUN"
    thr = d.get("threat")
    if thr is not None:
        thr["latency_ms"] = 0
    mit = d.get("mitigation")
    if mit is not None:
        _mask_times(mit)
    return d


def _mask_times(o) -> None:
    """Mitigation action history stamps use time.time() for UNSIGNED_ACK only; mask any 'wall' timestamps."""
    if isinstance(o, dict):
        for k, v in o.items():
            if k == "wall_t":
                o[k] = 0
            else:
                _mask_times(v)
    elif isinstance(o, list):
        for v in o:
            _mask_times(v)


async def _drive(eng: LiveEngine, ticks, attack_at: dict[int, tuple] | None = None) -> list[dict]:
    q = eng.subscribe()
    out: list[dict] = []
    for i, tick in enumerate(ticks):
        if attack_at and i in attack_at:
            args = attack_at[i]
            if args[0] == "attack":
                eng.set_attack(*args[1:])
            elif args[0] == "mode":
                eng.set_defense_mode(args[1])
        if eng.is_sim:
            eng._apply_pending_attack()
        await eng._process(tick)
        while not q.empty():
            out.append(q.get_nowait())
    eng.unsubscribe(q)
    return out


def run_sim(db: str, n: int = 700) -> list[dict]:
    eng = LiveEngine(spec=SourceSpec(kind="sim"), db_path=db)
    ticks = (next(eng._gen) for _ in range(n))
    plan = {50: ("attack", "gps_spoofing"), 300: ("mode", "active-ips"), 500: ("attack", None)}
    try:
        return asyncio.run(_drive(eng, ticks, plan))
    finally:
        eng.store.close() if hasattr(eng.store, "close") else None


def run_replay(db: str, tlog: Path) -> list[dict]:
    eng = LiveEngine(spec=SourceSpec(kind="replay", tlog=str(tlog), speed=0), db_path=db)
    ticks = frame_ticks(iter_tlog_frames(tlog), sample_rate_hz=1.0 / eng.dt)
    try:
        return asyncio.run(_drive(eng, ticks))
    finally:
        eng.store.close() if hasattr(eng.store, "close") else None


def digest(updates: list[dict]) -> str:
    h = hashlib.sha256()
    for u in updates:
        h.update(canonical(mask(u)).encode())
        h.update(b"\n")
    return h.hexdigest()


def collect() -> dict[str, list[dict]]:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
        dd = Path(d)
        tlog = synth_tlog(dd / "synthetic.tlog")
        return {"sim": run_sim(str(dd / "a.sqlite")), "replay": run_replay(str(dd / "b.sqlite"), tlog)}
