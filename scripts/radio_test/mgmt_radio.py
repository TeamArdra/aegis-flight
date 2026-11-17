"""Drive and measure the in-band management channel over the real radio: writes ``p7_mgmt.json``.

    python scripts/radio_test/mgmt_radio.py --out artifacts/radio_test --seconds 30 [--mgmt-key-file KEY]

1. Baseline window (``--seconds``): no commands; counts bridge management bytes/s (components 191/192, the cross-end
   summary MEMORY_VECT 0xAE15 kept apart because it is outside the budget) and pilot telemetry bytes/s.
2. Command window (at least ``--seconds``): signed commands ADVISORY, ACTIVE_IPS, STATUS, then bad cases (replayed frame,
   unsigned, wrong key, lowering without the two-step), recording every COMMAND_ACK; the same counters run throughout.
Compared: management bytes against the 150 B/s budget (worst case ``burst + rate x T``) and telemetry bytes/s with vs
without management traffic.  Valid commands are paced (the bridge allows 1/s); the three bad frames stay under the
5-bad-signature alarm (bad frames never lock out valid commands).  Test key ``bytes(range(1, 33))`` unless ``--mgmt-key-file``.  ``--lower-to`` completes the
two-step lowering at the end (default: leave the posture raised).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

os.environ.setdefault("MAVLINK20", "1")
from pymavlink import mavutil  # noqa: E402
from pymavlink.dialects.v20 import common as mav2  # noqa: E402

from aegisflight.detectors.crossend import MARKER_ADDRESS, load_signing_key  # noqa: E402
from aegisflight.hal.mgmt_channel import (  # noqa: E402
    CMD_MGMT,
    DENY_TEXT,
    MGMT_COMPID,
    OP_SET_POSTURE,
    OP_STATUS_NOW,
    POSTURES,
    build_command_frame,
    decode_mgmt_frame,
)
from aegisflight.mavlink.signing import MavlinkSignatureVerifier  # noqa: E402

try:
    from .results import PhaseResult
except ImportError:  # run as a plain script
    from results import PhaseResult  # type: ignore[no-redef]  # noqa: I001

PHASE = "p7_mgmt"
MGMT_KEY = bytes(range(1, 33))
BUDGET_BPS = 150.0
BURST_BYTES = 300.0
CROSSEND_EXTRA_BPS = 211.0  # documented worst case of management + cross-end summary together
BRIDGE_COMPIDS = (191, 192)
RESULT_NAMES = {0: "ACCEPTED", 2: "DENIED", 3: "UNSUPPORTED", 4: "FAILED", 5: "IN_PROGRESS"}
EXPECT_RESULT = {"accepted": 0, "denied": 2, "in_progress": 5}


# --------------------------------------------------------------------------- #
# Pure logic (no I/O)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class FrameSample:
    t: float
    nbytes: int
    kind: str  # mgmt | crossend | telemetry


def classify_downlink(compid: int, msg_type: str, address: int | None = None) -> str:
    """``mgmt`` (budgeted), ``crossend`` (summary, not budgeted) or ``telemetry`` (everything else)."""
    if compid in BRIDGE_COMPIDS:
        return "crossend" if msg_type == "MEMORY_VECT" and address == MARKER_ADDRESS else "mgmt"
    return "telemetry"


def rate_summary(samples: Iterable[FrameSample], t0: float, t1: float) -> dict[str, Any]:
    """Per-kind bytes, frames, average and peak 1 s bytes/s, and the per-second series over ``[t0, t1)``."""
    window = max(t1 - t0, 1e-9)
    n_bins = max(1, int(window + 0.999999))
    bins: dict[str, list[int]] = defaultdict(lambda: [0] * n_bins)
    frames: dict[str, int] = defaultdict(int)
    for s in samples:
        if t0 <= s.t < t1:
            bins[s.kind][min(n_bins - 1, int(s.t - t0))] += s.nbytes
            frames[s.kind] += 1
    out: dict[str, Any] = {"window_s": round(window, 2), "kinds": {}}
    for kind in sorted({"mgmt", "crossend", "telemetry"} | set(bins)):
        series = bins.get(kind, [0] * n_bins)
        total = sum(series)
        out["kinds"][kind] = {"bytes": total, "frames": frames.get(kind, 0), "avg_bps": round(total / window, 1),
                              "peak_1s": max(series), "series": series}
    return out


def budget_verdict(total_bytes: float, window_s: float, rate: float = BUDGET_BPS,
                   burst: float = BURST_BYTES) -> dict[str, Any]:
    """Bytes against the worst-case bound ``burst + rate x window`` (the token bucket's guarantee) and the plain rate."""
    bound = burst + rate * window_s
    avg = total_bytes / window_s if window_s > 0 else 0.0
    return {"avg_bps": round(avg, 1), "bytes": total_bytes, "bound_bytes": round(bound, 1), "rate_bps": rate,
            "within_bound": total_bytes <= bound, "within_rate": avg <= rate}


def telemetry_comparison(without_bps: float, with_bps: float, tolerance: float = 0.15) -> dict[str, Any]:
    """Telemetry bytes/s with management traffic vs without; ok when it did not drop by more than ``tolerance``."""
    ratio = with_bps / without_bps if without_bps > 0 else None
    return {"without_bps": round(without_bps, 1), "with_bps": round(with_bps, 1),
            "delta_bps": round(with_bps - without_bps, 1), "ratio": None if ratio is None else round(ratio, 3),
            "tolerance": tolerance, "ok": ratio is not None and ratio >= 1.0 - tolerance}


def describe_ack(ack: dict[str, Any]) -> str:
    """``DENIED(rate limited (1 command/s))`` / ``IN_PROGRESS(token 123)`` / ``ACCEPTED``."""
    res = RESULT_NAMES.get(ack["result"], str(ack["result"]))
    rp2 = ack.get("result_param2", 0)
    if ack["result"] == 2:
        return f"{res}({DENY_TEXT.get(rp2, rp2)})"
    if ack["result"] == 5:
        return f"{res}(token {rp2})"
    return res


def ack_matches(expect: str, acks: Sequence[dict[str, Any]]) -> bool:
    """``none`` = no ACK at all; otherwise at least one ACK with that result (accepted / denied / in_progress)."""
    if expect == "none":
        return len(acks) == 0
    return any(a["result"] == EXPECT_RESULT[expect] for a in acks)


def build_unsigned_command(op: int, posture: int = 0, vehicle_sysid: int = 1) -> bytes:
    """A well-formed MAV_CMD_USER_1 frame without a signature."""
    enc = mav2.MAVLink(None, srcSystem=255, srcComponent=190)
    msg = enc.command_long_encode(vehicle_sysid, MGMT_COMPID, CMD_MGMT, 0, float(op), float(posture), 0.0, 0.0, 0.0,
                                  0.0, 0.0)
    return bytes(msg.pack(enc))


# --------------------------------------------------------------------------- #
# Link monitor
# --------------------------------------------------------------------------- #
class Monitor:
    """Reads the downlink, meters bytes by kind, and keeps decoded management ACKs / status reports."""

    def __init__(self, conn: Any, key: bytes) -> None:
        self.conn = conn
        self.verifier = MavlinkSignatureVerifier(key)
        self.samples: list[FrameSample] = []
        self.acks: list[dict[str, Any]] = []
        self.statuses: list[dict[str, Any]] = []
        self.texts: list[dict[str, Any]] = []
        self.vehicle_sysid: int | None = None
        self.bad_bytes = 0
        self._last_hb = 0.0

    def ingest(self, msg: Any, now: float) -> None:
        mtype = msg.get_type()
        if mtype == "BAD_DATA":
            self.bad_bytes += len(getattr(msg, "data", b""))
            return
        raw = bytes(msg.get_msgbuf())
        comp = msg.get_srcComponent()
        addr = getattr(msg, "address", None) if mtype == "MEMORY_VECT" else None
        kind = classify_downlink(comp, mtype, addr)
        self.samples.append(FrameSample(now, len(raw), kind))
        if mtype == "HEARTBEAT" and self.vehicle_sysid is None and comp == 1 \
                and msg.autopilot != mavutil.mavlink.MAV_AUTOPILOT_INVALID and msg.type != mavutil.mavlink.MAV_TYPE_GCS:
            self.vehicle_sysid = msg.get_srcSystem()
        if kind == "telemetry":
            return
        d = decode_mgmt_frame(raw)
        if d is None:
            return
        if d["kind"] == "ack":
            res = self.verifier.verify_frame(raw)
            self.acks.append({**d, "t": now, "verified": bool(res.valid and res.signed)})
        elif d["kind"] == "status":
            self.statuses.append({"t": now, "report": d["report"], "signed": d["signed"]})
        else:
            self.texts.append({"t": now, "text": d["text"], "severity": d["severity"]})

    def poll(self, timeout: float = 0.2) -> None:
        now = time.monotonic()
        if now - self._last_hb >= 1.0:
            self._last_hb = now
            self.conn.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_GCS, mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0)
        msg = self.conn.recv_match(blocking=True, timeout=timeout)
        if msg is not None:
            self.ingest(msg, time.monotonic())

    def run_until(self, deadline: float, done: Any = None) -> bool:
        """Poll until ``deadline`` (monotonic) or ``done()`` is true; returns whether ``done`` fired."""
        while time.monotonic() < deadline:
            if done is not None and done():
                return True
            self.poll(min(0.2, max(0.01, deadline - time.monotonic())))
        return bool(done is not None and done())

    def latest_posture(self, since: float) -> str | None:
        for s in reversed(self.statuses):
            if s["t"] >= since:
                return s["report"].posture
        return None


# --------------------------------------------------------------------------- #
# Session
# --------------------------------------------------------------------------- #
def log(*a: Any) -> None:
    print(time.strftime("%H:%M:%S"), *a, flush=True)


class Driver:
    def __init__(self, mon: Monitor, key: bytes, wrong_key: bytes, res: PhaseResult, gap: float = 1.4,
                 ack_timeout: float = 4.0, quiet_wait: float = 3.0, allow_unsigned: bool = True) -> None:
        self.mon, self.key, self.wrong, self.res = mon, key, wrong_key, res
        self.gap, self.ack_timeout, self.quiet_wait, self.allow_unsigned = gap, ack_timeout, quiet_wait, allow_unsigned
        self.cases: list[dict[str, Any]] = []
        self._last_valid = 0.0
        self.bad_frames = 0

    @property
    def vehicle(self) -> int:
        return self.mon.vehicle_sysid or 1

    def pace(self) -> None:
        self.mon.run_until(self._last_valid + self.gap)

    def case(self, name: str, frames: Sequence[bytes], expect: str, valid: bool = True) -> dict[str, Any]:
        """Send raw frames, collect the management ACKs that come back, and score them against ``expect``."""
        if valid:
            self.pace()
        t0 = time.monotonic()
        n0 = len(self.mon.acks)
        for fr in frames:
            self.mon.conn.write(fr)
        if valid:
            self._last_valid = t0
        else:
            self.bad_frames += len(frames)
        wait = self.quiet_wait if expect == "none" else self.ack_timeout
        self.mon.run_until(t0 + wait, (lambda: False) if expect == "none" else (lambda: len(self.mon.acks) > n0))
        if expect != "none":
            self.mon.run_until(time.monotonic() + 0.3)  # catch a duplicate or late extra ACK
        acks = [a for a in self.mon.acks[n0:] if a["t"] >= t0]
        c = {"name": name, "expect": expect, "ok": ack_matches(expect, acks), "sent_t": t0,
             "acks": [{"result": a["result"], "text": describe_ack(a), "result_param2": a["result_param2"],
                       "verified": a["verified"], "latency_s": round(a["t"] - t0, 3)} for a in acks]}
        self.cases.append(c)
        log(f"case {name}: expect={expect} got={[x['text'] for x in c['acks']] or 'no ack'} ok={c['ok']}")
        return c

    def posture_cmd(self, name: str, posture: int, expect: str, token: int = 0) -> tuple[dict[str, Any], bytes]:
        fr = build_command_frame(self.key, OP_SET_POSTURE, posture, self.allow_unsigned, token,
                                 vehicle_sysid=self.vehicle)
        return self.case(name, [fr], expect), fr

    def status_cmd(self, name: str) -> tuple[dict[str, Any], bytes, str | None]:
        fr = build_command_frame(self.key, OP_STATUS_NOW, vehicle_sysid=self.vehicle)
        c = self.case(name, [fr], "accepted")
        t = c["sent_t"]
        self.mon.run_until(time.monotonic() + 5.0, lambda: self.mon.latest_posture(t) is not None)
        return c, fr, self.mon.latest_posture(t)

    def sequence(self, lower_to: str = "none") -> dict[str, Any]:
        """ADVISORY, ACTIVE_IPS, STATUS, replay, unsigned, wrong key, lowering without the two-step."""
        out: dict[str, Any] = {}
        c0, _fr, start = self.status_cmd("status (initial)")
        out["start_posture"] = start
        names = [p.value for p in POSTURES]
        cur = names.index(start) if start in names else 0
        if cur <= 1:
            self.posture_cmd("raise ADVISORY", 1, "accepted")
        else:
            log("bridge already ACTIVE_IPS: ADVISORY step skipped")
            self.cases.append({"name": "raise ADVISORY", "skipped": "already active-ips", "ok": True, "acks": []})
        self.posture_cmd("raise ACTIVE_IPS", 2, "accepted")
        _c, status_frame, posture = self.status_cmd("status request")
        out["posture_after_raise"] = posture
        self.case("replayed command", [status_frame], "none", valid=False)
        self.case("unsigned command", [build_unsigned_command(OP_STATUS_NOW, vehicle_sysid=self.vehicle)], "none",
                  valid=False)
        self.case("wrong-key command", [build_command_frame(self.wrong, OP_STATUS_NOW, vehicle_sysid=self.vehicle)],
                  "none", valid=False)
        low, _fr = self.posture_cmd("lower to PASSIVE without confirm", 0, "in_progress")
        token_ack = next((a for a in low["acks"] if a["result"] == 5), None)
        _c, _fr, posture = self.status_cmd("status after one-step lowering")
        out["posture_after_one_step_lower"] = posture
        out["lowering_needs_two_step"] = bool(token_ack) and posture == "active-ips"
        if lower_to != "none" and lower_to in names:
            code = names.index(lower_to)
            first, _fr = self.posture_cmd(f"lower to {lower_to} (step 1)", code, "in_progress")
            tok = next((a["result_param2"] for a in first["acks"] if a["result"] == 5), 0)
            self.posture_cmd(f"lower to {lower_to} (step 2 with token)", code, "accepted", token=int(tok))
            _c, _fr, posture = self.status_cmd("status after two-step lowering")
            out["posture_after_two_step"] = posture
        return out


def load_key(path: str | None) -> bytes:
    return load_signing_key(path) if path else MGMT_KEY


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5801)
    p.add_argument("--out", default="artifacts/radio_test")
    p.add_argument("--seconds", type=float, default=30.0, help="length of each measuring window")
    p.add_argument("--mgmt-key-file", default=None, help="32 raw bytes or 64 hex (default: the test key)")
    p.add_argument("--no-commands", action="store_true", help="passive byte counting only (no baseline comparison)")
    p.add_argument("--no-allow-unsigned", action="store_true", help="do not set allow_unsigned on the ACTIVE_IPS raise")
    p.add_argument("--lower-to", choices=("none", "advisory", "passive"), default="none")
    p.add_argument("--cmd-gap", type=float, default=1.4, help="seconds between valid commands (bridge limit 1/s)")
    p.add_argument("--ack-timeout", type=float, default=4.0)
    p.add_argument("--quiet-wait", type=float, default=3.0, help="how long to listen after a frame that must get no ACK")
    p.add_argument("--budget-bps", type=float, default=BUDGET_BPS)
    p.add_argument("--burst-bytes", type=float, default=BURST_BYTES)
    p.add_argument("--telemetry-tolerance", type=float, default=0.15)
    p.add_argument("--link-timeout", type=float, default=30.0)
    return p.parse_args(argv)


def evaluate(res: PhaseResult, mon: Monitor, drv: Driver | None, base: dict[str, Any] | None, act: dict[str, Any],
             args: argparse.Namespace, seq: dict[str, Any]) -> None:
    """Turn the measurements into checks and metrics."""
    window = act["window_s"]
    mg = act["kinds"]["mgmt"]
    verdict = budget_verdict(mg["bytes"], window, args.budget_bps, args.burst_bytes)
    res.metrics["mgmt_budget_active_window"] = verdict
    res.metrics["mgmt_plus_crossend_active_bps"] = round(
        (mg["bytes"] + act["kinds"]["crossend"]["bytes"]) / window, 1)
    res.metrics["crossend_documented_worst_bps"] = CROSSEND_EXTRA_BPS
    res.check("mgmt bytes/s within 150 B/s budget", verdict["within_bound"], verdict["avg_bps"], args.budget_bps,
              f"{mg['bytes']} B in {window} s vs bound {verdict['bound_bytes']} B (burst + rate x T); peak 1 s {mg['peak_1s']} B;"
              f" cross-end excluded ({act['kinds']['crossend']['bytes']} B)")
    if base is not None:
        bm = base["kinds"]["mgmt"]
        res.metrics["mgmt_baseline_bps"] = bm["avg_bps"]
        cmp_ = telemetry_comparison(base["kinds"]["telemetry"]["avg_bps"], act["kinds"]["telemetry"]["avg_bps"],
                                    args.telemetry_tolerance)
        res.metrics["telemetry_comparison"] = cmp_
        res.check("pilot telemetry unaffected by management traffic", cmp_["ok"], cmp_["ratio"],
                  1.0 - args.telemetry_tolerance,
                  f"{cmp_['without_bps']} B/s without vs {cmp_['with_bps']} B/s with (different windows; flight state may differ)")
    if drv is None:
        return
    for c in drv.cases:
        if c.get("skipped"):
            continue
        res.check(f"mgmt: {c['name']}", c["ok"], [x["text"] for x in c["acks"]] or "no ack", c["expect"])
    acks = [a for c in drv.cases for a in c["acks"]]
    res.check("mgmt ACK signatures verify with management key", bool(acks) and all(a["verified"] for a in acks),
              f"{sum(a['verified'] for a in acks)}/{len(acks)}", len(acks))
    res.check("posture ACTIVE_IPS confirmed by status report", seq.get("posture_after_raise") == "active-ips",
              seq.get("posture_after_raise"), "active-ips")
    res.check("lowering without the two-step does not lower", bool(seq.get("lowering_needs_two_step")),
              seq.get("posture_after_one_step_lower"), "active-ips")
    res.metrics["sequence"] = seq
    res.metrics["cases"] = drv.cases
    res.metrics["bad_frames_sent"] = drv.bad_frames
    res.metrics["status_reports_seen"] = len(mon.statuses)
    res.metrics["text_tail"] = [t["text"] for t in mon.texts[-10:]]


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    key, wrong = load_key(args.mgmt_key_file), bytes(range(101, 133))
    res = PhaseResult(PHASE, args.out)
    conn = mavutil.mavlink_connection(f"tcp:{args.host}:{args.port}", source_system=255, source_component=190)
    mon = Monitor(conn, key)
    drv = None if args.no_commands else Driver(mon, key, wrong, res, args.cmd_gap, args.ack_timeout, args.quiet_wait,
                                               not args.no_allow_unsigned)
    base = act = None
    seq: dict[str, Any] = {}
    try:
        up = mon.run_until(time.monotonic() + args.link_timeout, lambda: mon.vehicle_sysid is not None)
        res.check("link up (HEARTBEAT)", up, mon.vehicle_sysid, None)
        if up:
            if drv is not None:
                t0 = time.monotonic()
                mon.run_until(t0 + args.seconds)
                base = rate_summary(mon.samples, t0, time.monotonic())
                log("baseline", {k: v["avg_bps"] for k, v in base["kinds"].items()})
            t1 = time.monotonic()
            if drv is not None:
                seq = drv.sequence(args.lower_to)
            mon.run_until(t1 + args.seconds)
            act = rate_summary(mon.samples, t1, time.monotonic())
            log("active" if drv is not None else "passive", {k: v["avg_bps"] for k, v in act["kinds"].items()})
            evaluate(res, mon, drv, base, act, args, seq)
            res.metrics["windows"] = {"baseline": base, "active": act}
    except KeyboardInterrupt:
        res.check("session completed", False, None, None, "interrupted")
    finally:
        series = res.out / "p7_mgmt_series.json"
        series.write_text(json.dumps({"baseline": base, "active": act, "bad_bytes": mon.bad_bytes}, indent=1),
                          encoding="utf-8")
        res.artifact(series.name)
        path = res.save()
        conn.close()
    for c in res.checks:
        log("PASS" if c["passed"] else "FAIL", c["name"], c["value"])
    log("wrote", path)
    return 0 if res.checks and all(c["passed"] for c in res.checks) else 1


if __name__ == "__main__":
    sys.exit(main())
