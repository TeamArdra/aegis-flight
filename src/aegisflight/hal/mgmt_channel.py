"""In-band management channel over the telemetry radio (both ends: the bridge and the ground station).

The only link between the drone and the ground is the telemetry radio, so the bridge reports to the ground
station and takes a few signed controls on that same link, using only standard MAVLink 2 messages:

* alerts / IPS actions  -> STATUSTEXT (msgid 253, text starts with ``AEGIS:``, <= 50 bytes)   bridge -> ground
* compact status        -> MEMORY_VECT (msgid 249, own marker, 32-byte versioned payload + CRC8) bridge -> ground
* controls              -> COMMAND_LONG, ``MAV_CMD_USER_1`` (31010) to component 191            ground -> bridge
* answers               -> COMMAND_ACK (msgid 77)                                                bridge -> ground

All of it is sent from sysid 1 / compid 191 to the GCS side ONLY. It is never sent to the flight controller,
never fed to the tap/detectors, and the uplink control frames are consumed by the bridge (never forwarded).
Everything is subject to ONE byte budget (:class:`ByteBudget`), see ``docs/MGMT_CHANNEL.md``.

Honest limits: it is a status + alert + posture channel. It cannot start/stop processes, change configuration,
provision or rotate keys, or read logs. On real hardware it has only been exercised on the bench (Raspberry Pi 3B+ and Pi 5
companions, the MicoAir LR900 radio pair, a disarmed Pixhawk 6X with the propellers removed; docs/RADIO_TEST_RESULTS.md,
unverified session records). No real vehicle has flown with it: the airborne runs in that file use ArduCopter SITL. The uplink
MAV_CMD_USER_1 COMMAND_LONGs to component 191 (MAV_COMP_ID_ONBOARD_COMPUTER) are consumed, for any target system, whether or
not they are signed or a management key is set.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import struct
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pymavlink.dialects.v20 import common as mav2

from ..core.enums import AttackType, Severity
from ..mavlink.signing import MAVLINK_EPOCH_UNIX_S, MavlinkSignatureVerifier
from ..mitigation.types import DefenseMode, MitigationState

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
MSGID_COMMAND_LONG = 76
MSGID_COMMAND_ACK = 77
MSGID_MEMORY_VECT = 249
MSGID_STATUSTEXT = 253

MGMT_COMPID = 191
MGMT_SYSID = 1
CMD_MGMT = 31010  # MAV_CMD_USER_1

#: marker of the compact status MEMORY_VECT (the cross-end summary uses 0xAE15 / 1 / 0)
STATUS_ADDRESS = 0xAE57
STATUS_VER = 1
STATUS_TYPE = 1
STATUS_PAYLOAD_VERSION = 1

#: signature link ids: flight-key frames use 0 (as the cross-end summary), management-key frames use 2 (ACKs)
LINK_FLIGHT = 0
LINK_MGMT_ACK = 2
LINK_MGMT_CMD = 1

OP_SET_POSTURE = 1
OP_ACK_ALARMS = 2
OP_STATUS_NOW = 3
OP_NAMES = {OP_SET_POSTURE: "posture", OP_ACK_ALARMS: "ack_alarms", OP_STATUS_NOW: "status"}

POSTURES = (DefenseMode.PASSIVE, DefenseMode.ADVISORY, DefenseMode.ACTIVE_IPS)
POSTURE_CODE = {m.value: i for i, m in enumerate(POSTURES)}

# COMMAND_ACK results
R_ACCEPTED, R_DENIED, R_UNSUPPORTED, R_FAILED, R_IN_PROGRESS = 0, 2, 3, 4, 5
# reason codes carried in COMMAND_ACK.result_param2 of a DENIED answer
D_CONTROL_DISABLED, D_LOCKED_OUT, D_RATE_LIMITED, D_SIGNING_REQUIRED, D_POSTURE_LOCKED, D_BAD_PARAM = 1, 2, 3, 4, 5, 6
D_STATE_UNWRITABLE = 7  # the replay state could not be written, so the command is not executed (fail closed)
DENY_TEXT = {D_CONTROL_DISABLED: "control disabled (no management key)", D_LOCKED_OUT: "control locked out",
             D_RATE_LIMITED: "rate limited (1 command/s)", D_SIGNING_REQUIRED: "flight signing key required",
             D_POSTURE_LOCKED: "posture locked (local override file)", D_BAD_PARAM: "bad parameter",
             D_STATE_UNWRITABLE: "replay_state_unwritable"}
CONFIRM_TTL_S = 10.0
# >= LOCKOUT_BAD unauthenticated frames in LOCKOUT_WINDOW_S raise one "bad signatures" alarm per LOCKOUT_S. They never
# lock out a validly signed command (D_LOCKED_OUT is kept as a reserved wire code): otherwise anyone with a radio could
# keep remote control locked with a few unsigned frames a minute, exactly while an attack is in progress.
LOCKOUT_BAD = 5
LOCKOUT_WINDOW_S = 60.0
LOCKOUT_S = 60.0
# a validly signed command whose signing timestamp is older than this (vs the bridge's wall clock) is a replay of a
# recording; only applied while the bridge clock looks set (after MIN_SANE_WALL_S), so an unset Pi clock never rejects
MAX_CMD_AGE_S = 300.0
MIN_SANE_WALL_S = 1_735_689_600.0  # 2025-01-01
MIN_CMD_INTERVAL_S = 1.0

# priorities (lower = more important)
P_ACK, P_CRITICAL, P_EVENT, P_STATUS = 0, 1, 2, 3
_RESERVE = {P_ACK: 0.0, P_CRITICAL: 0.0, P_EVENT: 0.25, P_STATUS: 0.5}  # fraction of the bucket that must stay

SEVERITY_TO_MAV = {"CRITICAL": 2, "HIGH": 3, "SUSPICIOUS": 4, "WATCH": 5}
_SEV_ORDER = [s.value for s in (Severity.NORMAL, Severity.WATCH, Severity.SUSPICIOUS, Severity.HIGH, Severity.CRITICAL)]
_ATTACK_ORDER = [a.value for a in AttackType]
_STATE_ORDER = [s.value for s in MitigationState]
TEXT_MAX = 50

FLAG_BITS = ("signing", "analyser_ok", "fc_link", "gcs_link", "contested", "unsigned_ack", "control_enabled")


def _clip(text: str) -> str:
    b = text.encode("utf-8", "replace")[:TEXT_MAX]
    return b.decode("utf-8", "ignore")


# --------------------------------------------------------------------------- #
# Text formats
# --------------------------------------------------------------------------- #
def format_alert(attack_type: str, severity: str, sysid: int | None = None) -> str:
    """``AEGIS: COMMAND_INJECTION HIGH sys66`` (<= 50 bytes)."""
    sev = {"SUSPICIOUS": "SUSP"}.get(severity, severity)
    tail = f" sys{sysid}" if sysid else ""
    return _clip(f"AEGIS: {attack_type} {sev}{tail}")


def format_action(tag: str, detail: str = "") -> str | None:
    """Short text for one controller action (``None`` = not announced here)."""
    import re

    t = tag.upper()
    if t == "MODE_CHANGE":
        return None  # the posture announcement covers it
    m = re.search(r"[Ss]ys(?:tem)?\s?ID\s+(\d+)", detail)
    sysid = m.group(1) if m else ""
    if t == "QUARANTINE":
        return _clip(f"AEGIS: quarantine sys{sysid}" if sysid else "AEGIS: quarantine sender")
    m = re.search(r"\b(ALT_HOLD|LOITER|RTL|LAND|STABILIZE|GUIDED|AUTO|BRAKE)\b", detail)
    if t in ("GPS_ALT_HOLD", "SAFE_HOLD_CMD", "RESTORE_MODE", "MANUAL_SAFE_HOLD"):
        mode = m.group(1) if m else "ALT_HOLD"
        why = "GPS fault" if t == "GPS_ALT_HOLD" else "restore" if t == "RESTORE_MODE" else "safe hold"
        return _clip(f"AEGIS: set {mode} ({why})")
    return _clip(f"AEGIS: {t.lower()}")


def format_posture(mode: str) -> str:
    return _clip(f"AEGIS: posture {mode.upper().replace('-', '_')}")


# --------------------------------------------------------------------------- #
# Byte budget, alert gate
# --------------------------------------------------------------------------- #
class ByteBudget:
    """ONE token bucket over all management traffic, with priorities.

    ``rate`` bytes/s refill, bucket ``capacity`` (default ``max(2*rate, 200)``). A frame of priority P is sent only
    if the bucket still holds ``reserve(P) * capacity`` after paying for it: ACKs and CRITICAL alerts may drain the
    bucket, other events must leave 25 % and status 50 %, so a flood of events cannot starve an ACK and status
    goes last. Hard bound: bytes sent in any window of T seconds <= ``capacity + rate * T``.
    """

    def __init__(self, rate: float = 150.0, capacity: float | None = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.rate = max(0.0, float(rate))
        self.capacity = float(capacity) if capacity is not None else max(2.0 * self.rate, 200.0)
        self._clock = clock
        self.tokens = self.capacity
        self._t = clock()
        self.sent_bytes = 0
        self.denied = 0

    def allow(self, nbytes: int, prio: int) -> bool:
        now = self._clock()
        self.tokens = min(self.capacity, self.tokens + max(0.0, now - self._t) * self.rate)
        self._t = now
        if self.rate <= 0 or self.tokens - nbytes < _RESERVE.get(prio, 0.5) * self.capacity:
            self.denied += 1
            return False
        self.tokens -= nbytes
        self.sent_bytes += nbytes
        return True


class AlertGate:
    """Dedupe + rate limit for event messages: one per key per ``min_interval_s``, a global token bucket
    (``burst`` messages, ``refill_per_s``), and escalation bypass (a higher severity for the same key goes at once).
    A condition that keeps repeating is announced less and less often (the gap doubles up to ``backoff_max_s``), so a
    persistent alert (a tampered firmware file, a sustained flood) does not scroll the pilot's GCS every few seconds."""

    def __init__(self, min_interval_s: float = 2.0, burst: int = 5, refill_per_s: float = 1.0,
                 clock: Callable[[], float] = time.monotonic, backoff_max_s: float = 30.0) -> None:
        self.backoff_max_s = max(float(min_interval_s), float(backoff_max_s))
        self.min_interval_s = float(min_interval_s)
        self.burst = float(burst)
        self.refill = float(refill_per_s)
        self._clock = clock
        self._tokens = self.burst
        self._t = clock()
        self._last: dict[str, tuple[float, int, int]] = {}
        self.suppressed = 0

    def allow(self, key: str, rank: int = 0, force: bool = False) -> bool:
        now = self._clock()
        self._tokens = min(self.burst, self._tokens + max(0.0, now - self._t) * self.refill)
        self._t = now
        last = self._last.get(key)
        escalated = last is not None and rank > last[1]
        fresh = last is None or escalated or now - last[0] > 2.0 * self.backoff_max_s      # a new episode
        repeats = 0 if fresh else last[2]
        if not (force or escalated):
            gap = min(self.min_interval_s * (2 ** repeats), self.backoff_max_s)
            if last is not None and now - last[0] < gap:
                self.suppressed += 1
                return False
            if self._tokens < 1.0:
                self.suppressed += 1
                return False
            self._tokens -= 1.0
            repeats = 0 if fresh else min(repeats + 1, 16)
        self._last[key] = (now, rank, repeats)
        if len(self._last) > 256:
            for k in sorted(self._last, key=lambda x: self._last[x][0])[:128]:
                del self._last[k]
        return True


# --------------------------------------------------------------------------- #
# Status vector
# --------------------------------------------------------------------------- #
def crc8(data: bytes, poly: int = 0x07, init: int = 0) -> int:
    crc = init
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc


_STATUS_BODY = struct.Struct("<BBBBHIHHHHBBHB")  # 23 bytes; zero padding up to byte 31; byte 31 = CRC8
_NEVER = 0xFFFF


def _sat(v: int, hi: int) -> int:
    return max(0, min(int(v), hi))


@dataclass
class StatusReport:
    posture: str = "passive"
    topology: str | None = None
    state: str | None = None
    flags: dict[str, bool] = field(default_factory=lambda: dict.fromkeys(FLAG_BITS, False))
    forwarded: int = 0
    dropped_up: int = 0
    alerts: int = 0
    counter_frames: int = 0
    hook_errors: int = 0
    last_alert_class: str | None = None
    last_alert_severity: str | None = None
    since_action_s: int | None = None
    seq: int = 0


def pack_status(r: StatusReport) -> list[int]:
    """The 32 signed bytes for ``MEMORY_VECT.value`` (payload version 1, CRC8 in the last byte)."""
    flags = sum(1 << i for i, k in enumerate(FLAG_BITS) if r.flags.get(k))
    topo = {"A": 1, "A+B": 2}.get(r.topology or "", 0)
    state = _STATE_ORDER.index(r.state) if r.state in _STATE_ORDER else 255
    cls = _ATTACK_ORDER.index(r.last_alert_class) if r.last_alert_class in _ATTACK_ORDER else 0
    sev = _SEV_ORDER.index(r.last_alert_severity) if r.last_alert_severity in _SEV_ORDER else 0
    since = _NEVER if r.since_action_s is None else _sat(r.since_action_s, _NEVER - 1)
    body = _STATUS_BODY.pack(STATUS_PAYLOAD_VERSION, POSTURE_CODE.get(r.posture, 0), topo, state, flags,
                             _sat(r.forwarded, 0xFFFFFFFF), _sat(r.dropped_up, 0xFFFF), _sat(r.alerts, 0xFFFF),
                             _sat(r.counter_frames, 0xFFFF), _sat(r.hook_errors, 0xFFFF), cls, sev, since,
                             r.seq & 0xFF)
    raw = body.ljust(31, b"\x00")
    raw += bytes([crc8(raw)])
    return [b - 256 if b > 127 else b for b in raw]


def unpack_status(value: list[int] | tuple[int, ...]) -> StatusReport | None:
    """Decode a status vector; ``None`` for a wrong size, bad CRC8 or unknown payload version."""
    if len(value) != 32:
        return None
    raw = bytes(int(v) & 0xFF for v in value)
    if crc8(raw[:31]) != raw[31]:
        return None
    ver, pcode, topo, state, flags, fwd, dup, alerts, cf, herr, cls, sev, since, seq = _STATUS_BODY.unpack(raw[:23])
    if ver != STATUS_PAYLOAD_VERSION or pcode >= len(POSTURES):
        return None
    return StatusReport(
        posture=POSTURES[pcode].value, topology={1: "A", 2: "A+B"}.get(topo), state=_STATE_ORDER[state] if state < len(_STATE_ORDER) else None,
        flags={k: bool(flags >> i & 1) for i, k in enumerate(FLAG_BITS)}, forwarded=fwd, dropped_up=dup, alerts=alerts,
        counter_frames=cf, hook_errors=herr,
        last_alert_class=_ATTACK_ORDER[cls] if 0 < cls < len(_ATTACK_ORDER) else None,
        last_alert_severity=_SEV_ORDER[sev] if 0 < sev < len(_SEV_ORDER) else None,
        since_action_s=None if since == _NEVER else since, seq=seq)


def is_status_marker(address: Any, ver: Any, typ: Any) -> bool:
    return address == STATUS_ADDRESS and ver == STATUS_VER and typ == STATUS_TYPE


# --------------------------------------------------------------------------- #
# Frame building / parsing (shared by both ends)
# --------------------------------------------------------------------------- #
class FrameSender:
    """Encoder for the bridge's sysid 1 / compid 191 stream. ONE instance is shared by the cross-end summary and the
    management channel, so the sequence numbers of that (sysid, compid) stream stay contiguous (a gap would look like
    packet loss to the ground IDS) and the flight-key signature timestamps stay strictly increasing. The sequence
    number is committed only for a frame that was actually sent."""

    def __init__(self, flight_key: bytes | None = None, sysid: int = MGMT_SYSID, compid: int = MGMT_COMPID) -> None:
        self.enc = mav2.MAVLink(None, srcSystem=sysid, srcComponent=compid)
        self.enc.robust_parsing = True
        self.signer = MavlinkSignatureVerifier(flight_key) if flight_key is not None else None
        self.seq = 0
        self.lock = threading.RLock()

    def build(self, factory: Callable[[Any], Any], signer: MavlinkSignatureVerifier | None = None,
              link_id: int = LINK_FLIGHT, sign: bool = True) -> bytes:
        self.enc.seq = self.seq
        raw = bytes(factory(self.enc).pack(self.enc))
        s = signer if signer is not None else (self.signer if sign else None)
        return s.sign_frame(raw, link_id=link_id) if s is not None else raw

    def commit(self) -> None:
        self.seq = (self.seq + 1) % 256


def build_command_frame(key: bytes, op: int, posture: int = 0, allow_unsigned: bool = False, token: int = 0,
                        vehicle_sysid: int = 1, src_sysid: int = 255, src_compid: int = 190,
                        signer: MavlinkSignatureVerifier | None = None, link_id: int = LINK_MGMT_CMD) -> bytes:
    """Ground side: a signed COMMAND_LONG(MAV_CMD_USER_1) addressed to the bridge (compid 191)."""
    enc = mav2.MAVLink(None, srcSystem=src_sysid, srcComponent=src_compid)
    enc.robust_parsing = True
    msg = enc.command_long_encode(vehicle_sysid, MGMT_COMPID, CMD_MGMT, 0, float(op), float(posture),
                                  1.0 if allow_unsigned else 0.0, float(token), 0.0, 0.0, 0.0)
    return (signer or MavlinkSignatureVerifier(key)).sign_frame(bytes(msg.pack(enc)), link_id=link_id)


def _payload(raw: bytes, size: int) -> bytes:
    return raw[10:10 + raw[1]].ljust(size, b"\x00")  # MAVLink 2 trims trailing zero bytes


def parse_command(raw: bytes) -> dict[str, Any] | None:
    """Fields of a COMMAND_LONG frame (v2), or ``None``."""
    if len(raw) < 12 or raw[0] != 0xFD or (raw[7] | raw[8] << 8 | raw[9] << 16) != MSGID_COMMAND_LONG:
        return None
    p = _payload(raw, 33)
    f = struct.unpack("<7fHBBB", p[:33])
    return {"params": f[:7], "command": f[7], "target_system": f[8], "target_component": f[9],
            "src_sysid": raw[5], "src_compid": raw[6]}


def is_mgmt_command(raw: bytes) -> dict[str, Any] | None:
    c = parse_command(raw)
    return c if c is not None and c["command"] == CMD_MGMT and c["target_component"] == MGMT_COMPID else None


def decode_mgmt_frame(raw: bytes) -> dict[str, Any] | None:
    """Ground side: decode a bridge frame (sysid 1 comp 191/192): STATUSTEXT starting with ``AEGIS:``, a status
    MEMORY_VECT or a COMMAND_ACK for the management command. ``None`` for anything else."""
    if len(raw) < 12 or raw[0] != 0xFD:
        return None
    msgid = raw[7] | raw[8] << 8 | raw[9] << 16
    base = {"sysid": raw[5], "compid": raw[6], "signed": bool(raw[2] & 1)}
    try:
        if msgid == MSGID_STATUSTEXT:
            p = _payload(raw, 54)
            text = p[1:51].split(b"\x00", 1)[0].decode("ascii", "replace")
            return {**base, "kind": "text", "severity": p[0], "text": text} if text.startswith("AEGIS:") else None
        if msgid == MSGID_MEMORY_VECT:
            p = _payload(raw, 36)
            addr, ver, typ = struct.unpack("<HBB", p[:4])
            if not is_status_marker(addr, ver, typ):
                return None
            rep = unpack_status(list(struct.unpack("<32b", p[4:36])))
            return {**base, "kind": "status", "report": rep} if rep is not None else None
        if msgid == MSGID_COMMAND_ACK:
            p = _payload(raw, 10)
            command, result, progress, rp2, ts, tc = struct.unpack("<HBBiBB", p[:10])
            return ({**base, "kind": "ack", "result": result, "progress": progress, "result_param2": rp2,
                     "target_system": ts, "target_component": tc} if command == CMD_MGMT else None)
    except (struct.error, IndexError):
        return None
    return None


# --------------------------------------------------------------------------- #
# Hash-chained audit log
# --------------------------------------------------------------------------- #
GENESIS = "0" * 64
_SECRET_KEYS = ("key", "secret", "token")


class AuditLog:
    """Append-only JSONL, each line carries the sha256 of the previous line (``prev``). Never holds keys or
    confirm tokens: those field names are dropped before writing."""

    def __init__(self, path: str | None) -> None:
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self._prev = GENESIS
        self._n = 0
        self.errors = 0
        if self.path is not None and self.path.exists():
            ok, n, _detail = verify_audit_log(self.path)
            lines = self.path.read_bytes().splitlines()
            if lines:
                self._prev = hashlib.sha256(lines[-1]).hexdigest()
                self._n = len(lines)
            if not ok:  # keep appending; the break stays visible to verify_audit_log
                self.errors += 1

    def append(self, event: str, **data: Any) -> None:
        if self.path is None:
            return
        data = {k: v for k, v in data.items() if not any(s in k.lower() for s in _SECRET_KEYS)}
        with self._lock:
            entry = {"n": self._n, "t": round(time.time(), 3), "event": event, **data, "prev": self._prev}
            line = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
            try:
                with open(self.path, "ab") as fh:
                    fh.write(line + b"\n")
            except OSError:
                self.errors += 1
                return
            self._prev = hashlib.sha256(line).hexdigest()
            self._n += 1


def verify_audit_log(path: str | Path) -> tuple[bool, int, str]:
    """(ok, entries, detail). Detects an edited, removed, reordered or inserted line (not a truncated tail)."""
    prev = GENESIS
    n = 0
    for i, line in enumerate(Path(path).read_bytes().splitlines()):
        try:
            entry = json.loads(line)
        except ValueError:
            return False, n, f"line {i + 1}: not JSON"
        if entry.get("prev") != prev or entry.get("n") != i:
            return False, n, f"line {i + 1}: chain broken"
        prev = hashlib.sha256(line).hexdigest()
        n += 1
    return True, n, "ok"


# --------------------------------------------------------------------------- #
# Bridge-side channel
# --------------------------------------------------------------------------- #
class MgmtHost:
    """What the channel needs from the bridge (implemented by ``InlineIpsBridge``)."""

    def mgmt_snapshot(self) -> dict[str, Any]: ...  # pragma: no cover

    def mgmt_set_posture(self, mode: str, allow_unsigned: bool) -> None: ...  # pragma: no cover

    def mgmt_ack_alarms(self) -> None: ...  # pragma: no cover


class MgmtChannel:
    def __init__(
        self,
        send: Callable[[bytes], bool],
        sender: FrameSender,
        host: Any,
        *,
        alerts_enabled: bool = True,
        alert_min_interval_s: float = 2.0,
        status_interval_s: float = 2.0,
        max_bytes_per_s: float = 150.0,
        mgmt_key: bytes | None = None,
        flight_signing: bool = False,
        vehicle_sysid: int = 1,
        state_path: str | None = None,
        audit_path: str | None = None,
        lock_posture_file: str | None = None,
        max_cmd_age_s: float | None = MAX_CMD_AGE_S,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        if mgmt_key is not None and not state_path:
            # without persisted anti-replay state a restart accepts a recorded management command again (the CLI's
            # --mgmt-state check is not enough: scripts construct the bridge / channel directly)
            raise ValueError("a management key needs a replay-state path (state_path / mgmt_state_path / --mgmt-state)")
        self._send, self.sender, self.host = send, sender, host
        self.alerts_enabled = bool(alerts_enabled)
        self.status_interval_s = float(status_interval_s)
        self.mgmt_key = mgmt_key
        self.flight_signing = bool(flight_signing)
        self.vehicle_sysid = int(vehicle_sysid)
        self.lock_posture_file = lock_posture_file
        self._clock = clock
        self.budget = ByteBudget(max_bytes_per_s, clock=clock)
        self.gate = AlertGate(alert_min_interval_s, clock=clock)
        self.audit = AuditLog(audit_path)
        self._ack_signer = MavlinkSignatureVerifier(mgmt_key) if mgmt_key is not None else None
        self._verifier = MavlinkSignatureVerifier(mgmt_key) if mgmt_key is not None else None
        self._state_path = Path(state_path) if state_path else None
        self.max_cmd_age_s = max_cmd_age_s if max_cmd_age_s and max_cmd_age_s > 0 else None
        self._wall = wall_clock
        self._ts_floor = 0  # newest signing timestamp ever executed, on ANY stream (persisted)
        self.state_write_failures = 0  # not in stats(): the forwarding golden guard hashes it
        self._load_state()
        if self._verifier is not None:
            try:  # probe: an unwritable state path fails here, not at the first command
                self._write_state()
            except OSError as exc:
                raise self._state_error(f"cannot be written ({type(exc).__name__})") from None
        self._queue: deque[tuple[int, str, Callable[[], bytes], float]] = deque(maxlen=8)
        self._drops: dict[str, int] = {}
        self._observed: dict[str, int] = {}
        self._drop_window_t = clock()
        self._status_next = clock() + self.status_interval_s
        self._status_now = False
        self._status_seq = 0
        self._bad_sig: deque[float] = deque()
        self._lock_until = -1e9
        self._last_cmd_t = -1e9
        self._pending_confirm: tuple[int, str, float] | None = None
        self._audit_bad_t = -1e9
        self._t0 = clock()
        self._last_action_t: float | None = None
        self.last_alert_class: str | None = None
        self.last_alert_severity: str | None = None
        # counters
        self.sent = {"alert": 0, "action": 0, "status": 0, "ack": 0, "other": 0}
        self.bytes_sent = 0
        self.send_failures = 0
        self.queue_dropped = 0
        self.commands_consumed = 0
        self.cmd_accepted = 0
        self.cmd_denied = 0
        self.cmd_ignored = 0
        self.bad_signatures = 0
        self.lockouts = 0  # number of "bad signatures" alarms (the name is kept for the status / stats schema)
        self.replays_rejected = 0  # not in stats(): the forwarding golden guard hashes it

    # -- state ----------------------------------------------------------------- #

    def _state_error(self, problem: str) -> ValueError:
        """Fixed-text refusal naming the path (never the file's contents)."""
        window = (f"recorded commands newer than max_cmd_age_s ({self.max_cmd_age_s:g} s), or any recording while the "
                  "bridge clock is unset," if self.max_cmd_age_s is not None else "every recorded command")
        return ValueError(f"management replay state {self._state_path} {problem}; refusing to start. Deleting the file "
                          f"starts fresh but reopens the replay window: {window} would execute again")

    def _load_state(self) -> None:
        """Fail closed: a missing file is a first run; anything else that cannot be read and fully understood is refused."""
        if self._state_path is None or self._verifier is None:
            return
        try:
            text = self._state_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return
        except (OSError, UnicodeDecodeError) as exc:  # a directory, no permission, binary garbage
            raise self._state_error(f"cannot be read ({type(exc).__name__})") from None
        try:
            data = json.loads(text)
            if not isinstance(data, dict) or not isinstance(data.get("streams", {}), dict):
                raise TypeError
            streams: dict[tuple[int, int, int], int] = {}
            for k, ts in data.get("streams", {}).items():
                link, sysid, compid = (int(x) for x in k.split(","))
                if type(ts) is not int or ts < 0:
                    raise TypeError
                streams[(link, sysid, compid)] = ts
            floor = data.get("floor", max(streams.values(), default=0))
            if type(floor) is not int or floor < 0:
                raise TypeError
        except (ValueError, TypeError, AttributeError):
            raise self._state_error("is corrupt or not a replay-state file") from None
        self._verifier._last_timestamps.update(streams)
        self._ts_floor = floor

    def _write_state(self) -> None:
        """Atomically write the replay state; raises OSError."""
        assert self._state_path is not None and self._verifier is not None
        data = {"streams": {f"{a},{b},{c}": ts for (a, b, c), ts in self._verifier._last_timestamps.items()},
                "floor": self._ts_floor}
        tmp = self._state_path.with_name(self._state_path.name + ".tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        os.replace(tmp, self._state_path)

    def _persist(self) -> bool:
        """True when the replay state is on disk (or there is none to keep). False = the write failed."""
        if self._state_path is None or self._verifier is None:
            return True
        try:
            self._write_state()
        except OSError:
            self.state_write_failures += 1
            return False
        return True

    @property
    def locked_out(self) -> bool:
        return False  # unauthenticated frames never lock out authenticated control (see LOCKOUT_BAD)

    @property
    def control_enabled(self) -> bool:
        return self.mgmt_key is not None and not self.locked_out

    # -- emission ----------------------------------------------------------------- #

    def _emit(self, prio: int, kind: str, build: Callable[[], bytes]) -> bool:
        """Build, check the budget, send. Priority <= CRITICAL that does not fit is queued (max 8, 10 s)."""
        with self.sender.lock:
            frame = build()
            if not self.budget.allow(len(frame), prio):
                if prio <= P_CRITICAL:
                    if len(self._queue) == self._queue.maxlen:
                        self.queue_dropped += 1
                    self._queue.append((prio, kind, build, self._clock()))
                return False
            if self._send(frame):
                self.sender.commit()
                self.sent[kind] = self.sent.get(kind, 0) + 1
                self.bytes_sent += len(frame)
                return True
            self.send_failures += 1
            return False

    def _text(self, text: str, mav_severity: int, prio: int, kind: str = "alert") -> bool:
        raw = _clip(text).encode("utf-8")
        return self._emit(prio, kind, lambda: self.sender.build(lambda e: e.statustext_encode(mav_severity, raw)))

    def alert(self, attack_type: str, severity: str, sysid: int | None = None) -> bool:
        """One IDS alert -> STATUSTEXT (GCS side only), deduped and rate limited."""
        self.last_alert_class, self.last_alert_severity = attack_type, severity
        if not self.alerts_enabled:
            return False
        rank = _SEV_ORDER.index(severity) if severity in _SEV_ORDER else 0
        if not self.gate.allow(f"alert:{attack_type}", rank):
            return False
        mav = SEVERITY_TO_MAV.get(severity, 5)
        return self._text(format_alert(attack_type, severity, sysid), mav, P_CRITICAL if severity == "CRITICAL" else P_EVENT)

    def action(self, tag: str, detail: str = "") -> bool:
        """One IPS action -> STATUSTEXT. The time of the action is always recorded for the status vector."""
        self._last_action_t = self._clock()
        text = format_action(tag, detail)
        if text is None or not self.alerts_enabled or not self.gate.allow(f"act:{text}"):
            return False
        return self._text(text, 5, P_EVENT, "action")

    def posture_changed(self, mode: str, origin: str = "local") -> bool:
        self.audit.append("posture_change", mode=mode, origin=origin)
        self._last_action_t = self._clock()
        self._status_now = self.status_interval_s > 0
        return self._text(format_posture(mode), 5, P_EVENT, "action") if self.gate.allow(f"posture:{mode}", force=True) else False

    def note_drop(self, label: str) -> None:
        """A hostile frame was dropped; counted here and announced once per second per label (``x3``)."""
        self._drops[label] = self._drops.get(label, 0) + 1

    def note_observed(self, label: str, verdict: str) -> None:
        """A control frame failed the signature check but was NOT blocked (IDS / advisory posture); announced like a drop."""
        key = f"{verdict.replace('_', '-')} {label}"
        self._observed[key] = self._observed.get(key, 0) + 1

    def _flush_drops(self, now: float) -> None:
        if now - self._drop_window_t < 1.0:
            return
        self._drop_window_t = now
        drops, self._drops = self._drops, {}
        for label, n in sorted(drops.items(), key=lambda kv: -kv[1]):
            self._last_action_t = now
            if not self.alerts_enabled or not self.gate.allow(f"drop:{label}", force=True):
                continue
            self._text(f"AEGIS: blocked {label} x{n}", 4, P_EVENT, "action")
        observed, self._observed = self._observed, {}
        for key, n in sorted(observed.items(), key=lambda kv: -kv[1]):
            self._last_action_t = now
            if not self.alerts_enabled or not self.gate.allow(f"obs:{key}", force=True):
                continue
            self._text(f"AEGIS: {key} x{n}", 4, P_EVENT, "action")

    # -- status --------------------------------------------------------------------- #

    def status_report(self) -> StatusReport:
        s = self.host.mgmt_snapshot()
        since = None if self._last_action_t is None else int(max(0.0, self._clock() - self._last_action_t))
        flags = dict(s.get("flags", {}))
        flags["control_enabled"] = self.control_enabled
        self._status_seq = (self._status_seq + 1) % 256
        return StatusReport(posture=s["posture"], topology=s.get("topology"), state=s.get("state"), flags=flags,
                            forwarded=s.get("forwarded", 0), dropped_up=s.get("dropped_up", 0), alerts=s.get("alerts", 0),
                            counter_frames=s.get("counter_frames", 0), hook_errors=s.get("hook_errors", 0),
                            last_alert_class=self.last_alert_class, last_alert_severity=self.last_alert_severity,
                            since_action_s=since, seq=self._status_seq)

    def _send_status(self, prio: int = P_STATUS) -> bool:
        value = pack_status(self.status_report())
        return self._emit(prio, "status", lambda: self.sender.build(
            lambda e: e.memory_vect_encode(STATUS_ADDRESS, STATUS_VER, STATUS_TYPE, value)))

    def service(self) -> None:
        """Called from the forwarding loop: drain queued high-priority frames, flush drop counts, send status."""
        now = self._clock()
        self._flush_drops(now)
        while self._queue:
            prio, kind, build, t_in = self._queue[0]
            if now - t_in > 10.0:
                self._queue.popleft()
                continue
            with self.sender.lock:
                frame = build()
                if not self.budget.allow(len(frame), prio):
                    break
                self._queue.popleft()
                if self._send(frame):
                    self.sender.commit()
                    self.sent[kind] = self.sent.get(kind, 0) + 1
                    self.bytes_sent += len(frame)
                else:
                    self.send_failures += 1
        if self._status_now:
            self._status_now = False
            self._send_status(P_ACK)
            self._status_next = now + self.status_interval_s
        elif self.status_interval_s > 0 and now >= self._status_next:
            self._status_next = now + self.status_interval_s
            self._send_status()

    # -- uplink control --------------------------------------------------------------- #

    def _ack(self, req: dict[str, Any], result: int, rp2: int = 0, progress: int = 0, signed: bool = True) -> None:
        signer = self._ack_signer if signed else None
        sysid, compid = req["src_sysid"], req["src_compid"]
        self._emit(P_ACK, "ack", lambda: self.sender.build(
            lambda e: e.command_ack_encode(CMD_MGMT, result, progress, rp2, sysid, compid),
            signer=signer, link_id=LINK_MGMT_ACK, sign=False))

    def _deny(self, req: dict[str, Any], reason: int, ev: dict[str, Any], announce: bool = True) -> None:
        self.cmd_denied += 1
        self.audit.append("command", result="denied", reason=DENY_TEXT[reason], **ev)
        self._ack(req, R_DENIED, reason)
        if announce:
            self._text(f"AEGIS: cmd denied: {DENY_TEXT[reason]}", 4, P_EVENT, "other")

    def handle_command(self, raw: bytes, req: dict[str, Any]) -> None:
        """Process one consumed MAV_CMD_USER_1 frame. Never raises."""
        try:
            self._handle_command(raw, req)
        except Exception as exc:  # noqa: BLE001 - a bad command must never stop forwarding
            self.audit.append("command", result="error", reason=type(exc).__name__)

    def _handle_command(self, raw: bytes, req: dict[str, Any]) -> None:
        now = self._clock()
        self.commands_consumed += 1
        if req["target_system"] not in (self.vehicle_sysid, 0):
            self.cmd_ignored += 1
            return
        ev = {"src": f"{req['src_sysid']}/{req['src_compid']}"}
        if self._verifier is None:
            self._deny_disabled(req, now, ev)
            return
        res = self._verifier.verify_frame(raw)
        if not res.valid or not res.signed:
            self._note_bad_signature(now, res.reason if res.signed or not res.valid else "unsigned", ev)
            return
        if not self._fresh(res.timestamp_10us, ev):
            return
        self._ts_floor = res.timestamp_10us  # advanced in memory even if the write below fails: no replay in this run
        if not self._persist():  # the replay window is closed on disk BEFORE anything is executed, or nothing is
            self._deny(req, D_STATE_UNWRITABLE, ev)
            return
        if now - self._last_cmd_t < MIN_CMD_INTERVAL_S:
            self._deny(req, D_RATE_LIMITED, ev, announce=False)
            return
        self._last_cmd_t = now
        p1, p2, p3, p4 = req["params"][:4]
        op, post, allow_unsigned, token = int(p1), int(p2), int(p3) == 1, int(p4)
        ev = {**ev, "op": OP_NAMES.get(op, str(op))}
        if op == OP_STATUS_NOW:
            self.audit.append("command", result="accepted", **ev)
            self.cmd_accepted += 1
            self._ack(req, R_ACCEPTED)
            self._status_now = True
        elif op == OP_ACK_ALARMS:
            self.host.mgmt_ack_alarms()
            self.audit.append("command", result="accepted", **ev)
            self.cmd_accepted += 1
            self._ack(req, R_ACCEPTED)
        elif op == OP_SET_POSTURE:
            self._set_posture(req, post, allow_unsigned, token, now, ev)
        else:
            self.cmd_denied += 1
            self.audit.append("command", result="unsupported", **ev)
            self._ack(req, R_UNSUPPORTED)

    def _deny_disabled(self, req: dict[str, Any], now: float, ev: dict[str, Any]) -> None:
        self.cmd_denied += 1
        if now - self._last_cmd_t >= MIN_CMD_INTERVAL_S:  # unsigned answer, at most 1/s
            self._last_cmd_t = now
            self.audit.append("command", result="denied", reason=DENY_TEXT[D_CONTROL_DISABLED], **ev)
            self._ack(req, R_DENIED, D_CONTROL_DISABLED, signed=False)

    def _fresh(self, ts_10us: int, ev: dict[str, Any]) -> bool:
        """A validly signed frame is still a replay if it is not newer than the newest command ever executed (on any
        stream: a recording replayed under another link id / sysid) or, with a set wall clock, older than
        ``max_cmd_age_s``. Replays get no ACK and are audited; they do not count toward the bad-signature alarm."""
        why = None
        if ts_10us <= self._ts_floor:
            why = "replay_older_than_last_command"
        elif self.max_cmd_age_s is not None:
            wall = self._wall()
            if wall >= MIN_SANE_WALL_S and ts_10us / 100_000 + MAVLINK_EPOCH_UNIX_S < wall - self.max_cmd_age_s:
                why = "replay_stale_timestamp"
        if why is None:
            return True
        self.replays_rejected += 1
        self.cmd_ignored += 1
        self.audit.append("command", result="ignored", reason=why, **ev)
        return False

    def _note_bad_signature(self, now: float, reason: str, ev: dict[str, Any]) -> None:
        self.bad_signatures += 1
        self.cmd_ignored += 1
        if now - self._audit_bad_t >= 1.0:
            self._audit_bad_t = now
            self.audit.append("command", result="ignored", reason=f"bad_signature:{reason}", total_bad=self.bad_signatures, **ev)
        self._bad_sig.append(now)
        while self._bad_sig and now - self._bad_sig[0] > LOCKOUT_WINDOW_S:
            self._bad_sig.popleft()
        if len(self._bad_sig) >= LOCKOUT_BAD and now >= self._lock_until:
            self._lock_until = now + LOCKOUT_S
            self._bad_sig.clear()
            self.lockouts += 1
            self.audit.append("lockout", seconds=LOCKOUT_S, total_bad=self.bad_signatures)
            self._text(f"AEGIS: mgmt bad signatures x{LOCKOUT_BAD}+ (ignored)", 3, P_CRITICAL, "other")

    def _lock_file_present(self) -> bool:
        return bool(self.lock_posture_file) and os.path.exists(self.lock_posture_file)

    def _set_posture(self, req: dict[str, Any], code: int, allow_unsigned: bool, token: int, now: float,
                     ev: dict[str, Any]) -> None:
        if not 0 <= code < len(POSTURES):
            self._deny(req, D_BAD_PARAM, ev)
            return
        target = POSTURES[code]
        cur = DefenseMode(self.host.mgmt_snapshot()["posture"])
        ev = {**ev, "from": cur.value, "to": target.value}
        if target == cur:
            self.cmd_accepted += 1
            self.audit.append("command", result="accepted", note="no change", **ev)
            self._ack(req, R_ACCEPTED, code)
            return
        if POSTURES.index(target) > POSTURES.index(cur):  # raising
            if target == DefenseMode.ACTIVE_IPS and not self.flight_signing and not allow_unsigned:
                self._deny(req, D_SIGNING_REQUIRED, ev)
                return
        else:  # lowering
            if self._lock_file_present():
                self._deny(req, D_POSTURE_LOCKED, ev)
                return
            if cur == DefenseMode.ACTIVE_IPS:
                pend = self._pending_confirm
                if not (pend and token and pend[0] == token and pend[1] == target.value and now <= pend[2]):
                    tok = secrets.randbelow(0xFFFFFF - 1) + 1
                    self._pending_confirm = (tok, target.value, now + CONFIRM_TTL_S)
                    self.audit.append("command", result="confirm_required", **ev)
                    self._ack(req, R_IN_PROGRESS, tok, progress=int(CONFIRM_TTL_S))
                    return
                self._pending_confirm = None
        try:
            self.host.mgmt_set_posture(target.value, allow_unsigned)
        except Exception as exc:  # noqa: BLE001
            self.audit.append("command", result="failed", reason=type(exc).__name__, **ev)
            self._ack(req, R_FAILED)
            return
        self.cmd_accepted += 1
        self.audit.append("command", result="accepted", **ev)
        self._ack(req, R_ACCEPTED, code)

    def stats(self) -> dict[str, Any]:
        return {"sent": dict(self.sent), "bytes_sent": self.bytes_sent, "budget_denied": self.budget.denied,
                "suppressed": self.gate.suppressed, "send_failures": self.send_failures,
                "queue_dropped": self.queue_dropped, "commands_consumed": self.commands_consumed,
                "accepted": self.cmd_accepted, "denied": self.cmd_denied, "ignored": self.cmd_ignored,
                "bad_signatures": self.bad_signatures, "lockouts": self.lockouts,
                "control_enabled": self.control_enabled, "locked_out": self.locked_out,
                "budget_bytes_per_s": self.budget.rate}


_COPTER_MODES = {0: "STABILIZE", 2: "ALT_HOLD", 3: "AUTO", 4: "GUIDED", 5: "LOITER", 6: "RTL", 9: "LAND", 16: "POSHOLD"}


def _target_mode(raw: bytes, msgid: int, cmd: dict[str, Any] | None) -> str | None:
    """ArduCopter mode name a dropped DO_SET_MODE / SET_MODE asked for (so 'blocked DO_SET_MODE(LAND)' says what the
    forger wanted, not only the message type); ``None`` for anything else or an unknown mode number."""
    if cmd is not None and cmd["command"] == 176:  # MAV_CMD_DO_SET_MODE: param2 = custom mode
        return _COPTER_MODES.get(int(cmd["params"][1]))
    if msgid == 11 and len(raw) >= 10:  # SET_MODE: custom_mode u32 first in the payload
        return _COPTER_MODES.get(int.from_bytes(_payload(raw, 6)[:4], "little"))
    return None


def drop_label(raw: bytes, sysid: int, msgid: int, direction: str) -> str:
    """Short label of a dropped frame: the MAV_CMD name for a COMMAND_LONG/INT, else the message name."""
    name = None
    c = parse_command(raw) if msgid == MSGID_COMMAND_LONG else None
    if c is not None:
        entry = mav2.enums.get("MAV_CMD", {}).get(c["command"])
        name = entry.name.replace("MAV_CMD_", "").replace("NAV_", "").replace("COMPONENT_", "") if entry else f"CMD{c['command']}"
    else:
        cls = mav2.mavlink_map.get(msgid)
        name = getattr(cls, "msgname", None) or f"MSG{msgid}"
    mode = _target_mode(raw, msgid, c)
    if mode:
        name = f"{name}({mode})"
    prefix = "down " if direction == "down" else ""
    return f"{prefix}{name} sys{sysid}"
