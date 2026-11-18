"""One combined pilot session over the real radio, as the trusted GCS (sysid 255): writes ``p3_flight.json``.

    python scripts/radio_test/flight_session.py --out artifacts/radio_test [--stages params,mission] [--hold-after]

Stages (canonical order, ``--stages`` picks a subset, default all):
  link_up      wait for HEARTBEAT, set up telemetry streams, probe round-trip latency (PARAM_REQUEST_READ)
  params       full PARAM_REQUEST_LIST download: count == param_count, no duplicate or missing index
  mission      upload a home slot + 6 waypoints (MISSION_COUNT / MISSION_ITEM_INT handshake), download, compare
  arm_takeoff  GUIDED, arm, takeoff, altitude check (skips arming when the vehicle is already airborne)
  modes        ALT_HOLD, LOITER, GUIDED, each verified through HEARTBEAT
  auto_mission AUTO, fly the mission (or its first ``--auto-items`` items)
  land         LAND until disarmed
Resume: ``--skip-takeoff`` drops arm_takeoff/auto_mission/land (stay on the ground); ``--hold-after`` skips land and leaves
the vehicle flying in LOITER so an attack scenario can run.  To resume on a flying vehicle use ``--stages modes,land``.
Every COMMAND_LONG is recorded in a ledger (sent, acknowledged, timing); a legitimate command that is NAKed or never
acknowledged fails the check "zero legitimate commands dropped/NAK-or-timeout".  Hub: TCP 127.0.0.1:5801 by default.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import statistics
import sys
import time
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

os.environ.setdefault("MAVLINK20", "1")
from pymavlink import mavutil  # noqa: E402

try:
    from .results import PhaseResult
except ImportError:  # run as a plain script
    from results import PhaseResult  # type: ignore[no-redef]  # noqa: I001

PHASE = "p3_flight"
STAGES = ("link_up", "params", "mission", "arm_takeoff", "modes", "auto_mission", "land")
FLIGHT_STAGES = frozenset({"arm_takeoff", "auto_mission", "land"})
MODES = {"STABILIZE": 0, "ALT_HOLD": 2, "AUTO": 3, "GUIDED": 4, "LOITER": 5, "RTL": 6, "LAND": 9}
MODE_NAMES = {v: k for k, v in MODES.items()}
CMD_DO_SET_MODE, CMD_NAV_TAKEOFF, CMD_ARM_DISARM = 176, 22, 400
MSG_SET_MODE = 11
RESULT_ACCEPTED, RESULT_IN_PROGRESS = 0, 5
VEHICLE_COMPID = 1
BRIDGE_COMPIDS = (191, 192)
PING_PARAM = "SYSID_THISMAV"
PING_MIN_RATIO = 0.8
SR1_PARAMS = (("SR1_POSITION", 5), ("SR1_EXTRA1", 5), ("SR1_EXTRA2", 5), ("SR1_RAW_SENS", 2),
              ("SR1_EXT_STAT", 2), ("SR1_EXTRA3", 2))
_FRAME_CANON = {0: 0, 5: 0, 3: 3, 6: 3, 10: 10, 11: 10}  # GLOBAL / RELATIVE_ALT / TERRAIN, plain and _INT variants


# --------------------------------------------------------------------------- #
# Pure logic (no I/O)
# --------------------------------------------------------------------------- #
def select_stages(spec: str | None, skip_takeoff: bool = False, hold_after: bool = False) -> list[str]:
    """Stages to run, in canonical order. ``spec`` is ``all``/empty or a comma list; unknown names raise ValueError."""
    names = [s.strip() for s in (spec or "all").split(",") if s.strip()]
    if not names or "all" in names:
        chosen = set(STAGES)
    else:
        unknown = [n for n in names if n not in STAGES]
        if unknown:
            raise ValueError(f"unknown stage(s) {unknown}; choose from {list(STAGES)}")
        chosen = set(names)
    if skip_takeoff:
        chosen -= FLIGHT_STAGES
    if hold_after:
        chosen.discard("land")
    return [s for s in STAGES if s in chosen]


def latency_stats(values: Sequence[float]) -> dict[str, float | int | None]:
    """Count, min, mean, median, p95 and max of a list of seconds (None fields when empty)."""
    if not values:
        return {"n": 0, "min": None, "mean": None, "median": None, "p95": None, "max": None}
    v = sorted(values)
    p95 = v[min(len(v) - 1, math.ceil(0.95 * len(v)) - 1)]
    return {"n": len(v), "min": v[0], "mean": statistics.fmean(v), "median": statistics.median(v), "p95": p95,
            "max": v[-1]}


def _param_id(msg: Any) -> str:
    pid = msg.param_id
    return pid.decode("ascii", "replace").rstrip("\x00") if isinstance(pid, bytes | bytearray) else str(pid).rstrip("\x00")


@dataclass
class ParamCheck:
    expected: int | None
    received: int
    unique: int
    duplicates: list[int] = field(default_factory=list)
    missing: list[int] = field(default_factory=list)
    out_of_range: list[int] = field(default_factory=list)
    duplicate_names: list[str] = field(default_factory=list)
    count_mismatch: bool = False

    @property
    def complete(self) -> bool:
        return (self.expected is not None and self.unique == self.expected and not self.duplicates
                and not self.missing and not self.out_of_range and not self.duplicate_names
                and not self.count_mismatch)

    def summary(self, cap: int = 20) -> dict[str, Any]:
        return {"expected": self.expected, "received": self.received, "unique": self.unique,
                "duplicates": self.duplicates[:cap], "n_duplicates": len(self.duplicates),
                "missing": self.missing[:cap], "n_missing": len(self.missing),
                "out_of_range": self.out_of_range[:cap], "duplicate_names": self.duplicate_names[:cap],
                "count_mismatch": self.count_mismatch, "complete": self.complete}


def check_params(msgs: Iterable[Any]) -> ParamCheck:
    """Completeness of a PARAM_VALUE stream: every index 0..param_count-1 exactly once, one consistent param_count."""
    rows = [(int(m.param_index), int(m.param_count), _param_id(m)) for m in msgs]
    if not rows:
        return ParamCheck(None, 0, 0)
    counts = Counter(c for _, c, _ in rows)
    expected = counts.most_common(1)[0][0]
    idx_count = Counter(i for i, _, _ in rows)
    names: dict[str, set[int]] = {}
    for i, _, n in rows:
        names.setdefault(n, set()).add(i)
    valid = {i for i in idx_count if 0 <= i < expected}
    return ParamCheck(
        expected=expected, received=len(rows), unique=len(valid),
        duplicates=sorted(i for i, c in idx_count.items() if c > 1),
        missing=[i for i in range(expected) if i not in idx_count],
        out_of_range=sorted(i for i in idx_count if not 0 <= i < expected),
        duplicate_names=sorted(n for n, ix in names.items() if len(ix) > 1),
        count_mismatch=len(counts) > 1)


@dataclass(frozen=True)
class MissionItem:
    seq: int
    frame: int
    command: int
    autocontinue: int
    p1: float
    p2: float
    p3: float
    p4: float
    x: int
    y: int
    z: float

    @classmethod
    def from_msg(cls, m: Any) -> MissionItem:
        """From MISSION_ITEM_INT, or MISSION_ITEM (float degrees converted to 1e7 integers)."""
        x, y = m.x, m.y
        if m.get_type() == "MISSION_ITEM":
            x, y = round(x * 1e7), round(y * 1e7)
        return cls(int(m.seq), int(m.frame), int(m.command), int(m.autocontinue), float(m.param1), float(m.param2),
                   float(m.param3), float(m.param4), int(x), int(y), float(m.z))

    def params(self) -> tuple[float, ...]:
        return self.p1, self.p2, self.p3, self.p4, self.z


def build_mission(home_lat: float, home_lon: float, n_waypoints: int = 6, alt_m: float = 10.0,
                  radius_deg: float = 0.0003) -> list[MissionItem]:
    """Item 0 = home slot (the autopilot owns it), then ``n_waypoints`` NAV_WAYPOINTs on a ring (about 30 m radius)."""
    lat0, lon0 = round(home_lat * 1e7), round(home_lon * 1e7)
    items = [MissionItem(0, 0, 16, 1, 0.0, 0.0, 0.0, 0.0, lat0, lon0, 0.0)]
    for i in range(n_waypoints):
        a = 2 * math.pi * i / max(1, n_waypoints)
        items.append(MissionItem(i + 1, 3, 16, 1, 0.0, 0.0, 0.0, 0.0, lat0 + round(radius_deg * math.cos(a) * 1e7),
                                 lon0 + round(radius_deg * math.sin(a) * 1e7), float(alt_m)))
    return items


def compare_missions(sent: Sequence[MissionItem], got: Sequence[MissionItem], skip_home: bool = True,
                     tol: float = 1e-4) -> list[str]:
    """Differences (empty = identical). Frames are compared modulo the _INT variant; with ``skip_home`` the seq-0 content
    is not compared because ArduPilot reports the real home there."""
    diffs: list[str] = []
    if len(sent) != len(got):
        diffs.append(f"count sent={len(sent)} got={len(got)}")
    for a, b in zip(sent, got, strict=False):
        if a.seq != b.seq:
            diffs.append(f"seq sent={a.seq} got={b.seq}")
            continue
        if skip_home and a.seq == 0:
            continue
        for name in ("command", "autocontinue", "x", "y"):
            if getattr(a, name) != getattr(b, name):
                diffs.append(f"item {a.seq} {name} sent={getattr(a, name)} got={getattr(b, name)}")
        if _FRAME_CANON.get(a.frame, a.frame) != _FRAME_CANON.get(b.frame, b.frame):
            diffs.append(f"item {a.seq} frame sent={a.frame} got={b.frame}")
        for name, va, vb in zip(("p1", "p2", "p3", "p4", "z"), a.params(), b.params(), strict=True):
            if not math.isclose(va, vb, rel_tol=tol, abs_tol=tol):
                diffs.append(f"item {a.seq} {name} sent={va} got={vb}")
    return diffs


@dataclass
class CommandRecord:
    label: str
    command: int
    first_sent_t: float
    sent_t: float
    attempts: int = 1
    result: int | None = None
    ack_t: float | None = None
    in_progress: bool = False
    timed_out: bool = False
    history: list[int] = field(default_factory=list)  # earlier final results (retried NAKs)

    @property
    def done(self) -> bool:
        return self.result is not None

    @property
    def status(self) -> str:
        if self.result is not None:
            return "ok" if self.result == RESULT_ACCEPTED else "nak"
        return "timeout" if self.timed_out else "pending"

    @property
    def latency_s(self) -> float | None:
        return None if self.ack_t is None else self.ack_t - self.sent_t

    def to_dict(self) -> dict[str, Any]:
        return {"label": self.label, "command": self.command, "status": self.status, "result": self.result,
                "attempts": self.attempts, "history": self.history, "in_progress_seen": self.in_progress,
                "latency_s": self.latency_s}


class CommandLedger:
    """Every command sent and whether it was acknowledged. Times are caller-supplied seconds (monotonic)."""

    def __init__(self) -> None:
        self.records: list[CommandRecord] = []

    def sent(self, label: str, command: int, now: float) -> CommandRecord:
        rec = CommandRecord(label, command, now, now)
        self.records.append(rec)
        return rec

    def resend(self, rec: CommandRecord, now: float) -> None:
        if rec.result is not None:
            rec.history.append(rec.result)
        rec.attempts += 1
        rec.sent_t = now
        rec.result = rec.ack_t = None
        rec.in_progress = rec.timed_out = False

    def expire(self, rec: CommandRecord) -> None:
        if rec.result is None:
            rec.timed_out = True

    def on_ack(self, command: int, result: int, now: float) -> CommandRecord | None:
        """Match a COMMAND_ACK to the oldest unanswered record of that command (IN_PROGRESS keeps it open)."""
        for rec in self.records:
            if rec.command == command and rec.result is None:
                if result == RESULT_IN_PROGRESS:
                    rec.in_progress = True
                else:
                    rec.result, rec.ack_t = result, now
                return rec
        return None

    def summary(self) -> dict[str, Any]:
        by: Counter[str] = Counter(r.status for r in self.records)
        dropped = [r for r in self.records if r.status != "ok"]
        lat = [r.latency_s for r in self.records if r.status == "ok" and r.latency_s is not None]
        return {"sent": len(self.records), "ok": by["ok"], "nak": by["nak"],
                "timeout": by["timeout"] + by["pending"], "dropped": len(dropped),
                "retried": sum(1 for r in self.records if r.attempts > 1),
                "failed": [f"{r.label}:{r.status}" + (f"({r.result})" if r.result is not None else "") for r in dropped],
                "ack_latency_s": latency_stats(lat)}


# --------------------------------------------------------------------------- #
# Session
# --------------------------------------------------------------------------- #
@dataclass
class Config:
    stages: list[str] = field(default_factory=lambda: list(STAGES))
    hold_after: bool = False
    takeoff_alt: float = 10.0
    alt_tolerance: float = 1.0
    link_timeout: float = 30.0
    ping_count: int = 10
    streams: bool = True
    sr1_params: bool = True
    arming_check_off: bool = False
    param_timeout: float = 240.0
    param_idle: float = 8.0
    n_waypoints: int = 6
    home_lat: float = 12.9716
    home_lon: float = 77.5946
    mission_timeout: float = 4.0
    mission_retries: int = 3
    ack_timeout: float = 5.0
    retries: int = 1
    mode_timeout: float = 6.0
    mode_dwell: float = 3.0
    mode_via_message: bool = False
    gps_wait: float = 90.0
    settle: float = 15.0
    arm_retries: int = 3
    climb_timeout: float = 60.0
    auto_items: int = 3
    auto_timeout: float = 150.0
    land_timeout: float = 150.0


def log(*a: Any) -> None:
    print(time.strftime("%H:%M:%S"), *a, flush=True)


class Session:
    """The pilot. ``m`` is a pymavlink connection (or a fake with the same ``recv_match`` / ``mav`` surface)."""

    def __init__(self, m: Any, cfg: Config, res: PhaseResult, say: Callable[..., None] = log) -> None:
        self.m, self.cfg, self.res, self.say = m, cfg, res, say
        self.ledger = CommandLedger()
        self.tsys: int | None = None
        self.state: dict[str, Any] = {"alt": 0.0, "armed": False, "mode": None, "fix": 0, "max_alt": 0.0}
        self.reached: set[int] = set()
        self.type_counts: Counter[str] = Counter()
        self.mode_events: list[dict[str, Any]] = []
        self.statustexts: list[str] = []
        self.mission_sent: list[MissionItem] = []
        self.mission_len: int | None = None
        self.t_start = time.monotonic()
        self._last_hb = 0.0
        self.stage_s: dict[str, float] = {}

    # -- plumbing -------------------------------------------------------------------- #
    def _heartbeat(self) -> None:
        now = time.monotonic()
        if now - self._last_hb >= 1.0:
            self._last_hb = now
            self.m.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_GCS, mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0)

    def observe(self, msg: Any) -> None:
        t = msg.get_type()
        self.type_counts[t] += 1
        s = self.state
        if t == "HEARTBEAT":
            if (msg.autopilot != mavutil.mavlink.MAV_AUTOPILOT_INVALID and msg.type != mavutil.mavlink.MAV_TYPE_GCS
                    and msg.get_srcComponent() == VEHICLE_COMPID):
                if self.tsys is None:
                    self.tsys = msg.get_srcSystem()
                if msg.get_srcSystem() == self.tsys:
                    s["armed"] = bool(msg.base_mode & mavutil.mavlink.MAV_MODE_FLAG_SAFETY_ARMED)
                    s["mode"] = msg.custom_mode
        elif t == "GLOBAL_POSITION_INT":
            s["alt"] = msg.relative_alt / 1000.0
            s["max_alt"] = max(s["max_alt"], s["alt"])
        elif t == "GPS_RAW_INT":
            s["fix"] = msg.fix_type
        elif t == "COMMAND_ACK":
            if msg.get_srcComponent() not in BRIDGE_COMPIDS:
                self.ledger.on_ack(msg.command, msg.result, time.monotonic())
        elif t == "MISSION_ITEM_REACHED":
            self.reached.add(int(msg.seq))
        elif t == "STATUSTEXT":
            self.statustexts.append(str(msg.text))
            del self.statustexts[:-30]

    def recv(self, timeout: float) -> Any:
        self._heartbeat()
        msg = self.m.recv_match(blocking=True, timeout=timeout)
        if msg is not None and msg.get_type() != "BAD_DATA":
            self.observe(msg)
            return msg
        return None

    def wait_for(self, pred: Callable[[Any], bool], timeout: float) -> Any:
        end = time.monotonic() + timeout
        while True:
            remaining = end - time.monotonic()
            if remaining <= 0:
                return None
            msg = self.recv(min(0.5, remaining))
            if msg is not None and pred(msg):
                return msg

    def wait_until(self, cond: Callable[[], bool], timeout: float) -> bool:
        end = time.monotonic() + timeout
        while True:
            if cond():
                return True
            remaining = end - time.monotonic()
            if remaining <= 0:
                return False
            self.recv(min(0.5, remaining))

    def pump(self, seconds: float) -> None:
        self.wait_for(lambda _m: False, seconds)

    @property
    def target(self) -> tuple[int, int]:
        if self.tsys is None:
            raise RuntimeError("no vehicle heartbeat yet")
        return self.tsys, VEHICLE_COMPID

    def wait_heartbeat(self, timeout: float) -> bool:
        return self.wait_until(lambda: self.tsys is not None, timeout)

    # -- commands -------------------------------------------------------------------- #
    def send_command(self, label: str, command: int, params: Sequence[float], retries: int | None = None,
                     retry_on_nak: bool = False, timeout: float | None = None) -> CommandRecord:
        """COMMAND_LONG with ledger accounting; a timeout is retried, a NAK only when ``retry_on_nak``."""
        retries = self.cfg.retries if retries is None else retries
        timeout = self.cfg.ack_timeout if timeout is None else timeout
        ts, tc = self.target
        rec = self.ledger.sent(label, command, time.monotonic())
        for attempt in range(retries + 1):
            if attempt:
                if rec.done:
                    self.pump(3.0)
                self.ledger.resend(rec, time.monotonic())
            self.m.mav.command_long_send(ts, tc, command, 0, *params)
            self.wait_until(lambda: rec.done, timeout)
            if not rec.done and rec.in_progress:
                self.wait_until(lambda: rec.done, timeout)
            if rec.status == "ok" or (rec.done and not retry_on_nak):
                break
            if not rec.done:
                self.ledger.expire(rec)
        self.say(f"cmd {label}: {rec.status} result={rec.result} attempts={rec.attempts}")
        return rec

    def set_mode(self, name: str) -> dict[str, Any]:
        """Change mode (DO_SET_MODE with ACK, or the SET_MODE message) and verify it through HEARTBEAT."""
        mode = MODES[name]
        t0 = time.monotonic()
        ts, _tc = self.target
        if self.cfg.mode_via_message:
            rec = self.ledger.sent(f"SET_MODE {name}", MSG_SET_MODE, t0)
            self.m.mav.set_mode_send(ts, mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, mode)
            ok = self.wait_until(lambda: self.state["mode"] == mode, self.cfg.mode_timeout)
            if ok:
                self.ledger.on_ack(MSG_SET_MODE, RESULT_ACCEPTED, time.monotonic())
            else:
                self.ledger.expire(rec)
        else:
            rec = self.send_command(f"DO_SET_MODE {name}", CMD_DO_SET_MODE,
                                    (float(mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED), float(mode), 0, 0, 0, 0, 0))
            ok = self.wait_until(lambda: self.state["mode"] == mode, self.cfg.mode_timeout)
        ev = {"mode": name, "acked": rec.status == "ok", "verified": ok, "seconds": round(time.monotonic() - t0, 2)}
        self.mode_events.append(ev)
        self.say(f"mode {name}: acked={ev['acked']} verified={ok} ({ev['seconds']} s)")
        return ev

    # -- stages ---------------------------------------------------------------------- #
    def stage_link_up(self) -> None:
        t0 = time.monotonic()
        up = self.wait_heartbeat(self.cfg.link_timeout)
        self.res.check("link up (HEARTBEAT)", up, round(time.monotonic() - t0, 2), self.cfg.link_timeout,
                       f"vehicle sysid {self.tsys}" if up else "no vehicle heartbeat")
        if not up:
            return
        ts, tc = self.target
        if self.cfg.streams:
            self.m.mav.request_data_stream_send(ts, tc, mavutil.mavlink.MAV_DATA_STREAM_ALL, 5, 1)
        if self.cfg.sr1_params:
            for name, val in SR1_PARAMS:
                self.m.mav.param_set_send(ts, tc, name.encode(), float(val), mavutil.mavlink.MAV_PARAM_TYPE_REAL32)
                self.pump(0.2)
        if self.cfg.arming_check_off:
            self.m.mav.param_set_send(ts, tc, b"ARMING_CHECK", 0.0, mavutil.mavlink.MAV_PARAM_TYPE_REAL32)
            self.pump(0.2)
        lat: list[float] = []
        for _ in range(self.cfg.ping_count):
            t = time.monotonic()
            self.m.mav.param_request_read_send(ts, tc, PING_PARAM.encode(), -1)
            if self.wait_for(lambda mm: mm.get_type() == "PARAM_VALUE" and _param_id(mm) == PING_PARAM, 5.0):
                lat.append(time.monotonic() - t)
            self.pump(0.3)
        stats = latency_stats(lat)
        self.res.metrics["link_latency_s"] = stats
        self.res.metrics["link_latency_probes"] = {"sent": self.cfg.ping_count, "answered": len(lat)}
        need = math.ceil(PING_MIN_RATIO * self.cfg.ping_count)
        self.res.check("link latency probes answered", len(lat) >= need, len(lat), need,
                       f"PARAM_REQUEST_READ {PING_PARAM}; median {stats['median']}")

    def stage_params(self) -> None:
        ts, tc = self.target
        t0 = time.monotonic()
        self.m.mav.param_request_list_send(ts, tc)
        msgs: list[Any] = []
        seen: set[int] = set()
        t_first = t_done = None
        last = t0
        expected = None
        while True:
            now = time.monotonic()
            if now - t0 > self.cfg.param_timeout or (now - last > self.cfg.param_idle):
                break
            msg = self.recv(0.5)
            if msg is None or msg.get_type() != "PARAM_VALUE":
                continue
            now = time.monotonic()
            last = now
            t_first = t_first if t_first is not None else now - t0
            msgs.append(msg)
            expected = int(msg.param_count)
            if msg.param_index not in seen:
                seen.add(int(msg.param_index))
                t_done = now - t0
            if expected and len(seen) >= expected:
                break
        chk = check_params(msgs)
        secs = round(t_done if t_done is not None else time.monotonic() - t0, 2)
        self.res.metrics.update({"param_download_s": secs, "param_first_s": t_first,
                                 "params_per_s": round(chk.unique / secs, 1) if secs else None,
                                 "params": chk.summary()})
        self.res.check("params complete", chk.complete, f"{chk.unique}/{chk.expected}", chk.expected,
                       f"{secs} s; {len(chk.missing)} missing, {len(chk.duplicates)} duplicate indexes")

    def _mission_request(self, msg: Any) -> bool:
        return msg.get_type() in ("MISSION_REQUEST_INT", "MISSION_REQUEST", "MISSION_ACK")

    def upload_mission(self, items: Sequence[MissionItem]) -> tuple[bool, str]:
        ts, tc = self.target
        n = len(items)
        count_sends = 1
        self.m.mav.mission_count_send(ts, tc, n, 0)
        got_request = False
        while True:
            msg = self.wait_for(self._mission_request, self.cfg.mission_timeout)
            if msg is None:
                if got_request or count_sends > self.cfg.mission_retries:
                    return False, "timeout waiting for MISSION_REQUEST/ACK" + (" after items" if got_request else "")
                count_sends += 1
                self.m.mav.mission_count_send(ts, tc, n, 0)
                continue
            got_request = True
            if msg.get_type() == "MISSION_ACK":
                return (msg.type == 0), f"MISSION_ACK type {msg.type}"
            if not 0 <= msg.seq < n:
                return False, f"request for seq {msg.seq} out of range"
            it = items[msg.seq]
            self.m.mav.mission_item_int_send(ts, tc, it.seq, it.frame, it.command, 1 if it.seq == 1 else 0,
                                             it.autocontinue, it.p1, it.p2, it.p3, it.p4, it.x, it.y, it.z, 0)

    def download_mission(self) -> tuple[list[MissionItem] | None, str]:
        ts, tc = self.target
        count = None
        for _ in range(self.cfg.mission_retries + 1):
            self.m.mav.mission_request_list_send(ts, tc, 0)
            msg = self.wait_for(lambda mm: mm.get_type() == "MISSION_COUNT", self.cfg.mission_timeout)
            if msg is not None:
                count = int(msg.count)
                break
        if count is None:
            return None, "no MISSION_COUNT"
        items: list[MissionItem] = []
        for seq in range(count):
            item = None
            for _ in range(self.cfg.mission_retries + 1):
                self.m.mav.mission_request_int_send(ts, tc, seq, 0)
                item = self.wait_for(lambda mm, s=seq: mm.get_type() in ("MISSION_ITEM_INT", "MISSION_ITEM")
                                     and mm.seq == s, self.cfg.mission_timeout)
                if item is not None:
                    break
            if item is None:
                return None, f"item {seq} not received"
            items.append(MissionItem.from_msg(item))
        self.m.mav.mission_ack_send(ts, tc, 0, 0)
        return items, "ok"

    def stage_mission(self) -> None:
        items = build_mission(self.cfg.home_lat, self.cfg.home_lon, self.cfg.n_waypoints, self.cfg.takeoff_alt)
        t0 = time.monotonic()
        ok, detail = self.upload_mission(items)
        up_s = round(time.monotonic() - t0, 2)
        got = None
        diffs = [f"upload failed: {detail}"]
        t1 = time.monotonic()
        if ok:
            self.mission_sent, self.mission_len = list(items), len(items)
            got, detail = self.download_mission()
            diffs = [f"download failed: {detail}"] if got is None else compare_missions(items, got)
        down_s = round(time.monotonic() - t1, 2)
        self.res.metrics.update({"mission_items": len(items), "mission_upload_s": up_s, "mission_download_s": down_s,
                                 "mission_diffs": diffs[:20]})
        self.res.check("mission round-trip identical", got is not None and not diffs, len(diffs), 0,
                       f"{len(items)} items (home slot + {self.cfg.n_waypoints} waypoints); up {up_s} s, down {down_s} s"
                       + (f"; first diff: {diffs[0]}" if diffs else ""))

    def stage_arm_takeoff(self) -> None:
        c, s = self.cfg, self.state
        target = c.takeoff_alt
        t0 = time.monotonic()
        if s["armed"] and s["alt"] >= target - c.alt_tolerance:
            self.say("already airborne; skipping arm/takeoff")
            self.res.metrics["takeoff"] = {"already_airborne": True, "alt": s["alt"]}
        else:
            if not self.wait_until(lambda: s["fix"] >= 3, c.gps_wait):
                self.say("no 3D fix seen; continuing anyway")
            self.pump(c.settle)
            self.set_mode("GUIDED")
            if not s["armed"]:
                self.send_command("arm", CMD_ARM_DISARM, (1, 0, 0, 0, 0, 0, 0), retries=c.arm_retries, retry_on_nak=True)
                self.wait_until(lambda: s["armed"], 8.0)
            self.send_command("takeoff", CMD_NAV_TAKEOFF, (0, 0, 0, 0, 0, 0, target))
            self.wait_until(lambda: s["alt"] >= target - c.alt_tolerance, c.climb_timeout)
            self.res.metrics["takeoff"] = {"already_airborne": False, "armed": s["armed"],
                                           "seconds_to_alt": round(time.monotonic() - t0, 1), "alt": s["alt"]}
        self.res.metrics["max_alt_m"] = s["max_alt"]
        self.res.check("altitude reached", s["armed"] and s["alt"] >= target - c.alt_tolerance, round(s["alt"], 2),
                       target - c.alt_tolerance, f"target {target} m, max seen {round(s['max_alt'], 2)} m, armed={s['armed']}")

    def stage_modes(self) -> None:
        events = []
        for name in ("ALT_HOLD", "LOITER", "GUIDED"):
            events.append(self.set_mode(name))
            self.pump(self.cfg.mode_dwell)
        good = sum(1 for e in events if e["verified"] and e["acked"])
        self.res.check("mode changes verified", good == len(events), f"{good}/{len(events)}", len(events),
                       ", ".join(f"{e['mode']}:{'ok' if e['verified'] else 'FAIL'}" for e in events))

    def stage_auto_mission(self) -> None:
        c, s = self.cfg, self.state
        if not s["armed"]:
            self.res.check("auto mission flown", False, 0, None, "vehicle not armed; cannot fly AUTO")
            return
        total = (self.mission_len or c.n_waypoints + 1) - 1
        want = min(total, c.auto_items) if c.auto_items > 0 else total
        self.reached.clear()
        ev = self.set_mode("AUTO")
        ts, tc = self.target
        self.m.mav.mission_set_current_send(ts, tc, 1)
        t0 = time.monotonic()
        self.wait_until(lambda: len(self.reached - {0}) >= want, c.auto_timeout)
        done = sorted(self.reached - {0})
        self.res.metrics["auto_mission"] = {"wanted": want, "reached": done,
                                            "seconds": round(time.monotonic() - t0, 1), "mode_change": ev}
        self.res.check("auto mission flown", ev["verified"] and len(done) >= want, len(done), want,
                       f"reached items {done}; mode AUTO verified={ev['verified']}")

    def stage_land(self) -> None:
        s = self.state
        if not s["armed"]:
            self.res.check("landed", True, s["alt"], None, "vehicle already disarmed")
            return
        self.set_mode("LAND")
        ok = self.wait_until(lambda: not s["armed"], self.cfg.land_timeout)
        self.res.check("landed", ok, round(s["alt"], 2), None, "disarmed after LAND" if ok else "still armed at timeout")

    def hold(self) -> None:
        """--hold-after: leave the vehicle flying in LOITER."""
        s = self.state
        if not s["armed"]:
            self.say("hold-after: vehicle not armed, nothing to hold")
            return
        ev = self.set_mode("LOITER") if s["mode"] != MODES["LOITER"] else {"verified": True}
        self.res.metrics["hold_after"] = {"mode": MODE_NAMES.get(s["mode"], s["mode"]), "alt": s["alt"]}
        self.res.check("holding in LOITER", bool(ev["verified"]), round(s["alt"], 2), None, "vehicle left flying")

    # -- driver ---------------------------------------------------------------------- #
    def run(self) -> None:
        stages = self.cfg.stages
        if "link_up" not in stages and not self.wait_heartbeat(self.cfg.link_timeout):
            self.res.check("link up (HEARTBEAT)", False, None, self.cfg.link_timeout, "no vehicle heartbeat")
            return
        for name in stages:
            t0 = time.monotonic()
            self.say(f"== stage {name}")
            try:
                if name != "link_up" and self.tsys is None:
                    raise RuntimeError("no vehicle heartbeat; stage skipped")
                getattr(self, f"stage_{name}")()
            except Exception as exc:  # noqa: BLE001 - one broken stage must not lose the other results
                self.res.check(f"stage {name} completed", False, None, None, f"{type(exc).__name__}: {exc}")
                self.say(f"stage {name} failed: {exc!r}")
            self.stage_s[name] = round(time.monotonic() - t0, 1)
        if self.cfg.hold_after and self.tsys is not None:
            self.hold()

    def finish(self) -> None:
        summ = self.ledger.summary()
        note = f"{summ['ok']}/{summ['sent']} acknowledged, {summ['retried']} retried"
        if summ["failed"]:
            note += "; failed: " + ", ".join(summ["failed"])
        self.res.check("zero legitimate commands dropped/NAK-or-timeout", summ["dropped"] == 0, summ["dropped"], 0, note)
        elapsed = time.monotonic() - self.t_start
        self.res.metrics.update({
            "stages": list(self.cfg.stages), "stage_seconds": self.stage_s, "commands": summ,
            "command_log": [r.to_dict() for r in self.ledger.records], "mode_events": self.mode_events,
            "rx_msgs_per_s": round(sum(self.type_counts.values()) / elapsed, 1) if elapsed > 0 else None,
            "rx_types": dict(self.type_counts.most_common(15)), "statustext_tail": self.statustexts[-10:],
            "session_s": round(elapsed, 1)})


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5801)
    p.add_argument("--out", default="artifacts/radio_test")
    p.add_argument("--stages", default="all", help=f"comma list of {','.join(STAGES)} (default all)")
    p.add_argument("--skip-takeoff", action="store_true", help="stay on the ground: drop arm_takeoff, auto_mission, land")
    p.add_argument("--hold-after", action="store_true", help="skip land; leave the vehicle flying in LOITER")
    p.add_argument("--takeoff-alt", type=float, default=10.0)
    p.add_argument("--auto-items", type=int, default=3, help="mission items to fly in AUTO (0 = all)")
    p.add_argument("--retries", type=int, default=1, help="resends of an unacknowledged command")
    p.add_argument("--mode-via-message", action="store_true", help="use the SET_MODE message instead of DO_SET_MODE")
    p.add_argument("--no-streams", action="store_true", help="do not request data streams / SR1 rates")
    p.add_argument("--arming-check-off", action="store_true", help="set ARMING_CHECK=0 first (SITL)")
    p.add_argument("--home-lat", type=float, default=12.9716)
    p.add_argument("--home-lon", type=float, default=77.5946)
    p.add_argument("--ping-count", type=int, default=10)
    p.add_argument("--param-timeout", type=float, default=240.0)
    p.add_argument("--ack-timeout", type=float, default=5.0)
    p.add_argument("--link-timeout", type=float, default=30.0)
    return p.parse_args(argv)


def config_from_args(a: argparse.Namespace) -> Config:
    return Config(stages=select_stages(a.stages, a.skip_takeoff, a.hold_after), hold_after=a.hold_after,
                  takeoff_alt=a.takeoff_alt, auto_items=a.auto_items, retries=a.retries,
                  mode_via_message=a.mode_via_message, streams=not a.no_streams, sr1_params=not a.no_streams,
                  arming_check_off=a.arming_check_off, home_lat=a.home_lat, home_lon=a.home_lon,
                  ping_count=a.ping_count, param_timeout=a.param_timeout, ack_timeout=a.ack_timeout,
                  link_timeout=a.link_timeout)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        cfg = config_from_args(args)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    res = PhaseResult(PHASE, args.out)
    m = mavutil.mavlink_connection(f"tcp:{args.host}:{args.port}", source_system=255, source_component=190)
    sess = Session(m, cfg, res)
    try:
        sess.run()
    except KeyboardInterrupt:
        res.check("session completed", False, None, None, "interrupted")
    finally:
        sess.finish()
        (res.out / "p3_commands.json").write_text(
            json.dumps({"commands": [r.to_dict() for r in sess.ledger.records],
                                      "modes": sess.mode_events}, indent=2), encoding="utf-8")
        res.artifact("p3_commands.json")
        path = res.save()
        m.close()
    for c in res.checks:
        log("PASS" if c["passed"] else "FAIL", c["name"], c["value"], c["note"])
    log("wrote", path)
    return 0 if all(c["passed"] for c in res.checks) else 1


if __name__ == "__main__":
    sys.exit(main())
