"""Low-rate legitimate trusted-sysid traffic, to prove the inline IPS bridge never false-blocks the pilot.

Connects to the ground hub's GCS port (read/write) as a trusted sysid (default 255) and, once per
``--period-s`` (default 5 s), sends four kinds of legit probe and records whether each got its round
trip within ``--timeout-s``:

  heartbeat              -- success: the vehicle's own heartbeat keeps arriving (link stays alive)
  request_data_stream    -- success: a telemetry stream frame (GLOBAL_POSITION_INT et al.) follows
  set_mode_current       -- harmless DO_SET_MODE to the vehicle's OWN current mode; success: COMMAND_ACK
  param_request_read     -- success: a matching PARAM_VALUE comes back

Writes ``legit.json`` via ``PhaseResult``: zero rounds with a missing round trip proves the bridge, in
whatever posture it is running, never blocks its own pilot.

    python legit_probe.py --hub 127.0.0.1:5801 --seconds 30 --out radio_test_out
    python legit_probe.py --hub 127.0.0.1:5801 --seconds 30 --key-file sign.key --out radio_test_out

Exit codes: 0 all checks passed (zero false blocks), 1 a check failed, 2 the hub is unreachable.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from pymavlink.dialects.v20 import common as mav2

sys.path.insert(0, str(Path(__file__).resolve().parent))
from com_probe import Frame, FrameScanner  # noqa: E402
from results import PhaseResult  # noqa: E402

from aegisflight.mavlink.signing import sign_mavlink2_frame  # noqa: E402

TRUSTED_SYSID = 255
VEHICLE_SYSID = 1
COMPID = 190
LINK_ID = 0

HEARTBEAT_ID = 0
COMMAND_ACK_ID = 77
PARAM_VALUE_ID = 22
STREAM_IDS = frozenset({1, 30, 33, 74})  # SYS_STATUS, ATTITUDE, GLOBAL_POSITION_INT, VFR_HUD

MAV_CMD_DO_SET_MODE = 176
MAV_DATA_STREAM_ALL = 0
MAV_RESULT_ACCEPTED = 0
PROBE_PARAM = "SYSID_THISMAV"  # present on every ArduPilot build, harmless to read
PROBE_KINDS = ("heartbeat", "request_data_stream", "set_mode_current", "param_request_read")


def load_signing_key(path: str | Path) -> bytes:
    """32 raw bytes, or 64 hex characters, as accepted by ``aegis ips-bridge --signing-key-file``."""
    raw = Path(path).read_bytes().strip()
    if len(raw) == 64:
        with contextlib.suppress(ValueError):
            return bytes.fromhex(raw.decode("ascii"))
    if len(raw) == 32:
        return raw
    raise ValueError(f"{path}: expected 32 raw bytes or 64 hex characters, got {len(raw)}")


@dataclass
class ProbeRound:
    kind: str
    sent_t: float
    ok: bool = False
    detail: str = ""


@dataclass
class Session:
    """Owns the trusted-sysid socket; a reader thread tracks vehicle state for the round-trip checks."""

    sock: socket.socket
    key: bytes | None
    _mav: mav2.MAVLink = field(init=False)
    _scanner: FrameScanner = field(default_factory=FrameScanner, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    _stop: threading.Event = field(default_factory=threading.Event, init=False)
    vehicle_mode: int | None = field(default=None, init=False)
    last_heartbeat_t: float = field(default=0.0, init=False)
    last_stream_t: float = field(default=0.0, init=False)
    last_ack: tuple[int, int, float] | None = field(default=None, init=False)  # (command, result, t)
    last_param: tuple[str, float] | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        self._mav = mav2.MAVLink(None, srcSystem=TRUSTED_SYSID, srcComponent=COMPID)
        self._thread = threading.Thread(target=self._run, daemon=True, name="legit-probe-reader")

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        with contextlib.suppress(OSError):
            self.sock.close()
        self._thread.join(timeout=2)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                data = self.sock.recv(4096)
            except OSError:
                return
            if not data:
                return
            now = time.time()
            for fr in self._scanner.feed(data):
                self._on_frame(now, fr)

    def _on_frame(self, now: float, fr: Frame) -> None:
        if fr.sysid != VEHICLE_SYSID:
            return
        with self._lock:
            if fr.msgid == HEARTBEAT_ID and len(fr.payload) >= 5:
                self.vehicle_mode = struct.unpack_from("<I", fr.payload, 0)[0]
                self.last_heartbeat_t = now
            elif fr.msgid in STREAM_IDS:
                self.last_stream_t = now
            elif fr.msgid == COMMAND_ACK_ID and len(fr.payload) >= 3:
                command, result = struct.unpack_from("<HB", fr.payload, 0)
                self.last_ack = (command, result, now)
            elif fr.msgid == PARAM_VALUE_ID and len(fr.payload) >= 16:
                param_id = fr.payload[:16].split(b"\0", 1)[0].decode("ascii", "replace")
                self.last_param = (param_id, now)

    def _send(self, raw: bytes, *, needs_sign: bool = False) -> None:
        if needs_sign and self.key is not None:
            raw = sign_mavlink2_frame(raw, self.key, link_id=LINK_ID)
        self.sock.sendall(raw)

    def _raw(self, msg: mav2.MAVLink_message) -> bytes:
        raw = bytes(msg.pack(self._mav))
        self._mav.seq = (self._mav.seq + 1) % 256
        return raw

    def send_heartbeat(self) -> None:
        self._send(self._raw(self._mav.heartbeat_encode(mav2.MAV_TYPE_GCS, mav2.MAV_AUTOPILOT_INVALID, 0, 0, 0)))

    def send_request_data_stream(self) -> None:
        self._send(self._raw(self._mav.request_data_stream_encode(VEHICLE_SYSID, 1, MAV_DATA_STREAM_ALL, 2, 1)))

    def send_set_mode_current(self) -> bool:
        """Harmless DO_SET_MODE to the vehicle's own last-known mode; False if that mode isn't known yet."""
        with self._lock:
            mode = self.vehicle_mode
        if mode is None:
            return False
        raw = self._raw(self._mav.command_long_encode(VEHICLE_SYSID, 1, MAV_CMD_DO_SET_MODE, 0, 1, mode, 0, 0, 0, 0, 0))
        self._send(raw, needs_sign=True)
        return True

    def send_param_request_read(self, param_id: str = PROBE_PARAM) -> None:
        raw = self._raw(self._mav.param_request_read_encode(VEHICLE_SYSID, 1, param_id.encode(), -1))
        self._send(raw, needs_sign=True)


def run_cycle(sess: Session, timeout_s: float) -> list[ProbeRound]:
    rounds: list[ProbeRound] = []

    t = time.time()
    sess.send_heartbeat()
    deadline = time.time() + timeout_s
    while time.time() < deadline and sess.last_heartbeat_t < t:
        time.sleep(0.1)
    rounds.append(ProbeRound("heartbeat", t, sess.last_heartbeat_t >= t,
                             "vehicle heartbeat seen" if sess.last_heartbeat_t >= t else "no vehicle heartbeat"))

    t = time.time()
    sess.send_request_data_stream()
    deadline = time.time() + timeout_s
    while time.time() < deadline and sess.last_stream_t < t:
        time.sleep(0.1)
    rounds.append(ProbeRound("request_data_stream", t, sess.last_stream_t >= t,
                             "stream frame seen" if sess.last_stream_t >= t else "no stream frame followed"))

    t = time.time()
    if sess.send_set_mode_current():
        deadline = time.time() + timeout_s
        while time.time() < deadline and not (sess.last_ack and sess.last_ack[2] >= t):
            time.sleep(0.1)
        acked = bool(sess.last_ack and sess.last_ack[2] >= t)
        ok = acked and sess.last_ack[0] == MAV_CMD_DO_SET_MODE and sess.last_ack[1] == MAV_RESULT_ACCEPTED
        rounds.append(ProbeRound("set_mode_current", t, ok, f"ack {sess.last_ack}" if acked else "no COMMAND_ACK"))
    else:
        rounds.append(ProbeRound("set_mode_current", t, False, "vehicle mode not yet known, skipped"))

    t = time.time()
    sess.send_param_request_read()
    deadline = time.time() + timeout_s
    while time.time() < deadline and not (sess.last_param and sess.last_param[1] >= t):
        time.sleep(0.1)
    got = bool(sess.last_param and sess.last_param[1] >= t)
    rounds.append(ProbeRound("param_request_read", t, got,
                             f"PARAM_VALUE {sess.last_param[0]!r}" if got else "no PARAM_VALUE"))
    return rounds


def run(a: argparse.Namespace) -> int:
    res = PhaseResult("legit", a.out)
    res.metrics = {"hub": f"{a.hub_host}:{a.hub_port}", "trusted_sysid": TRUSTED_SYSID, "period_s": a.period_s,
                   "seconds": a.seconds, "timeout_s": a.timeout_s}
    try:
        key = load_signing_key(a.key_file) if a.key_file else None
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        res.check("key file valid", False, note=str(exc))
        res.save()
        return 2
    try:
        sock = socket.create_connection((a.hub_host, a.hub_port), timeout=5)
    except OSError as exc:
        print(f"ERROR: cannot reach hub GCS port {a.hub_host}:{a.hub_port}: {exc}", file=sys.stderr)
        res.check("hub reachable", False, note=str(exc))
        res.save()
        return 2
    res.check("hub reachable", True)

    sess = Session(sock, key)
    sess.start()
    all_rounds: list[ProbeRound] = []
    end = time.time() + a.seconds
    try:
        while time.time() < end:
            cycle_t0 = time.time()
            all_rounds.extend(run_cycle(sess, a.timeout_s))
            remaining = a.period_s - (time.time() - cycle_t0)
            if remaining > 0:
                time.sleep(remaining)
    finally:
        sess.stop()

    by_kind: dict[str, list[ProbeRound]] = {k: [] for k in PROBE_KINDS}
    for r in all_rounds:
        by_kind[r.kind].append(r)
    for kind in PROBE_KINDS:
        rs = by_kind[kind]
        ok = sum(1 for r in rs if r.ok)
        res.check(f"{kind} round trips", ok == len(rs) and len(rs) > 0, value=f"{ok}/{len(rs)}", threshold="all",
                  note="; ".join(r.detail for r in rs if not r.ok)[:200])
    res.check("zero false blocks over the run", all(r.ok for r in all_rounds) and bool(all_rounds),
              value=sum(1 for r in all_rounds if not r.ok), threshold=0)
    res.metrics["rounds"] = [{"kind": r.kind, "sent_t": r.sent_t, "ok": r.ok, "detail": r.detail} for r in all_rounds]

    raw_path = Path(a.out) / "legit_raw.json"
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_text(json.dumps(res.metrics["rounds"], indent=2), encoding="utf-8")
    res.artifact(raw_path.name)

    path = res.save()
    print(f"wrote {path}")
    return 0 if all(c["passed"] for c in res.checks) else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--hub", default="127.0.0.1:5801", help="ground hub GCS host:port (read/write)")
    ap.add_argument("--seconds", type=float, default=30.0, help="total run time")
    ap.add_argument("--period-s", type=float, default=5.0, help="seconds between probe cycles")
    ap.add_argument("--timeout-s", type=float, default=2.0, help="max wait for a round trip within one cycle")
    ap.add_argument("--key-file", default=None, help="sign set_mode_current / param_request_read with this key")
    ap.add_argument("--out", default="radio_test_out")
    a = ap.parse_args(argv)
    host, _, port_s = a.hub.rpartition(":")
    if not port_s.isdigit():
        ap.error(f"--hub must be host:port, got {a.hub!r}")
    a.hub_host, a.hub_port = host or "127.0.0.1", int(port_s)
    return run(a)


if __name__ == "__main__":
    sys.exit(main())
