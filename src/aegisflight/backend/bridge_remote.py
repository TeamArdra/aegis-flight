"""Ground side of the in-band management channel (``hal/mgmt_channel.py``).

``BridgeRemote`` reads the RAW frames of the live radio stream (a tap on the transport's ``poll``, so it never
depends on the IDS tick pipeline), decodes the bridge's alert / action STATUSTEXTs (``AEGIS:``), the compact status
MEMORY_VECT and COMMAND_ACKs (sysid 1, compid 191 / 192), and builds + signs the control command. It exposes
``bridge_remote`` for ``GET /api/status`` and every WebSocket update.

Authenticity: with the flight key configured (``aegis serve --signing-key-file``) status / text frames must verify
with it; without one they are unauthenticated (anyone on the radio can forge them: ``authenticated`` is false).
A COMMAND_ACK is accepted only if it verifies with the management key, so a forged ACK cannot fake ``accepted``.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable
from typing import Any

from ..hal.mgmt_channel import (
    DENY_TEXT,
    LINK_MGMT_ACK,
    OP_ACK_ALARMS,
    OP_SET_POSTURE,
    OP_STATUS_NOW,
    POSTURE_CODE,
    R_ACCEPTED,
    R_DENIED,
    R_FAILED,
    R_IN_PROGRESS,
    R_UNSUPPORTED,
    StatusReport,
    build_command_frame,
    decode_mgmt_frame,
)
from ..mavlink.signing import MavlinkSignatureVerifier
from ..proxy.transport import split_frames

PRESENT_S = 10.0
CMD_TIMEOUT_S = 5.0
CONFIRM_TTL_S = 10.0
RECENT = 20
_OP_LABEL = {OP_SET_POSTURE: "posture", OP_ACK_ALARMS: "ack_alarms", OP_STATUS_NOW: "status"}


class BridgeRemote:
    def __init__(self, flight_key: bytes | None = None, mgmt_key: bytes | None = None,
                 clock: Callable[[], float] = time.time, vehicle_sysid: int = 1) -> None:
        self.flight_key, self.mgmt_key = flight_key, mgmt_key
        self._clock = clock
        self.vehicle_sysid = vehicle_sysid
        self._lock = threading.Lock()
        self._flight_ver = MavlinkSignatureVerifier(flight_key) if flight_key is not None else None
        self._ack_ver = MavlinkSignatureVerifier(mgmt_key) if mgmt_key is not None else None
        self._signer = MavlinkSignatureVerifier(mgmt_key) if mgmt_key is not None else None
        self._last_seen: float | None = None
        self._report: StatusReport | None = None
        self._recent: deque[dict[str, Any]] = deque(maxlen=RECENT)
        self._last_alert: str | None = None
        self._last_action: str | None = None
        self._cmd: dict[str, Any] | None = None
        self._token: tuple[int, str, float] | None = None  # (token, mode, expiry) from an IN_PROGRESS answer
        self.rejected = 0

    # -- ingest ------------------------------------------------------------------------ #

    def feed_batch(self, batch: list[tuple[int, bytes]]) -> None:
        for _stamp, data in batch:
            self.feed(data)

    def feed(self, data: bytes) -> None:
        try:
            frames, _bad = split_frames(data)
        except Exception:  # noqa: BLE001 - a tap must never break the live feed
            return
        for fr in frames:
            if fr.sysid != self.vehicle_sysid or fr.compid not in (191, 192) or fr.msgid not in (77, 249, 253):
                continue
            try:
                self._frame(fr.raw)
            except Exception:  # noqa: BLE001
                continue

    def _frame(self, raw: bytes) -> None:
        d = decode_mgmt_frame(raw)
        if d is None:
            return
        now = self._clock()
        with self._lock:
            if d["kind"] == "ack":
                self._ack(raw, d, now)
                return
            if self._flight_ver is not None:
                res = self._flight_ver.verify_frame(raw)
                if not (res.valid and res.signed):
                    self.rejected += 1
                    return
            self._last_seen = now
            if d["kind"] == "status":
                self._report = d["report"]
            else:
                text = d["text"]
                self._recent.append({"t": round(now, 2), "text": text})
                low = text.lower()
                if low.startswith(("aegis: blocked", "aegis: set ", "aegis: quarantine", "aegis: posture", "aegis: cmd")):
                    self._last_action = text
                elif "locked" not in low:
                    self._last_alert = text

    def _ack(self, raw: bytes, d: dict[str, Any], now: float) -> None:
        cmd = self._cmd
        if self._ack_ver is None or cmd is None or cmd["result"] not in ("pending", "confirm_required"):
            return
        res = self._ack_ver.verify_frame(raw)
        if not (res.valid and res.signed and res.link_id == LINK_MGMT_ACK):
            self.rejected += 1
            return
        self._last_seen = now
        r, rp2 = d["result"], d["result_param2"]
        if r == R_ACCEPTED:
            cmd.update(result="accepted", detail="executed" if cmd["op"] != "posture" else f"posture {cmd.get('mode')}")
        elif r == R_IN_PROGRESS:
            self._token = (int(rp2), cmd.get("mode", ""), now + CONFIRM_TTL_S)
            cmd.update(result="confirm_required", detail="confirm within 10 s to lower from active-ips")
        elif r == R_DENIED:
            cmd.update(result="denied", detail=DENY_TEXT.get(int(rp2), "denied"))
        elif r == R_UNSUPPORTED:
            cmd.update(result="failed", detail="unsupported operation")
        elif r == R_FAILED:
            cmd.update(result="failed", detail="bridge failed to execute")
        cmd["t_done"] = now

    # -- control ----------------------------------------------------------------------- #

    def bridge_signing(self) -> bool | None:
        """Whether the bridge reports a flight signing key (None = no status seen yet)."""
        with self._lock:
            return None if self._report is None else bool(self._report.flags.get("signing"))

    def build_command(self, op: int, mode: str | None = None, allow_unsigned: bool = False,
                      confirm: bool = False) -> bytes:
        """Build + sign one control frame and register it as the pending command."""
        if self._signer is None or self.mgmt_key is None:
            raise RuntimeError("no management key")
        now = self._clock()
        with self._lock:
            token = 0
            if confirm and self._token is not None and mode == self._token[1] and now <= self._token[2]:
                token = self._token[0]
            self._cmd = {"op": _OP_LABEL.get(op, str(op)), "mode": mode, "result": "pending",
                         "detail": "sent, waiting for the bridge", "t": now}
            frame = build_command_frame(self.mgmt_key, op, POSTURE_CODE.get(mode or "", 0), allow_unsigned, token,
                                        vehicle_sysid=self.vehicle_sysid, signer=self._signer)
        return frame

    def mark_failed(self, detail: str) -> None:
        with self._lock:
            if self._cmd is not None:
                self._cmd.update(result="failed", detail=detail, t_done=self._clock())

    # -- view -------------------------------------------------------------------------- #

    def snapshot(self, control_available: bool = False) -> dict[str, Any]:
        now = self._clock()
        with self._lock:
            age = None if self._last_seen is None else round(max(0.0, now - self._last_seen), 1)
            r = self._report
            cmd = None
            if self._cmd is not None:
                c = self._cmd
                result = c["result"]
                if result == "pending" and now - c["t"] > CMD_TIMEOUT_S:
                    result = "timeout"
                if result == "confirm_required" and self._token is not None and now > self._token[2]:
                    result = "timeout"
                cmd = {"op": c["op"], "result": result, "detail": c["detail"] if result == c["result"] else "no answer",
                       "age_s": round(max(0.0, now - c.get("t_done", c["t"])), 1)}
            return {
                "present": age is not None and age <= PRESENT_S, "age_s": age,
                "posture": r.posture if r else None, "topology": r.topology if r else None,
                "state": r.state if r else None,
                "flags": {k: bool(r.flags.get(k)) if r else False for k in
                          ("signing", "analyser_ok", "fc_link", "gcs_link", "contested", "unsigned_ack", "control_enabled")},
                "counters": {k: (getattr(r, k) if r else 0) for k in
                             ("forwarded", "dropped_up", "alerts", "counter_frames", "hook_errors")},
                "last_alert": self._last_alert or (
                    f"{r.last_alert_class} {r.last_alert_severity}" if r and r.last_alert_class else None),
                "last_action": self._last_action,
                "last_command": cmd, "control_available": bool(control_available and self.mgmt_key is not None),
                "recent": list(self._recent), "authenticated": self.flight_key is not None,
            }
