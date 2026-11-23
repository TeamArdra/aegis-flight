"""Pre-allocated MAVLink v2 counter-command packet builder."""

from __future__ import annotations

import contextlib
import json
import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import ClassVar

from pymavlink.dialects.v20 import common as mav2

from ..mavlink.codec import (
    COPTER_MAV_TYPES,
    COPTER_MODES,
    FIXED_WING_MAV_TYPE,
    PLANE_MODES,
    PX4_MAIN_MODES,
    ROVER_MAV_TYPES,
    ROVER_MODES,
    VTOL_MAV_TYPES,
    safe_gps_denied_mode,
)
from ..mavlink.signing import MavlinkSignatureVerifier, x25_crc  # noqa: F401 - x25_crc re-exported

MAV_CMD_DO_AUX_FUNCTION = getattr(mav2, "MAV_CMD_DO_AUX_FUNCTION", 218)


class MavlinkActuator:
    """Encodes corrective MAVLink v2 commands with zero allocation churn.

    Only ArduCopter (autopilot 3 with a multicopter/heli ``mav_type``) is enabled for DO_SET_MODE actuation: the
    bridge has been verified on ArduCopter SITL only. The PX4/Plane/Rover/VTOL mapping tables are kept, but
    ``ALLOW_NON_COPTER_DIALECTS`` is False, so every other (or unknown) dialect is refused and audit-logged until a
    maintainer-approved hardware qualification enables it. The dialect starts UNKNOWN: until a vehicle HEARTBEAT
    has been observed (``set_vehicle_dialect``) no DO_SET_MODE is encoded (fail-closed).
    """

    # Frozen safety interlock: flipping this is a maintainer decision (see docs/HARDWARE_FLIGHT_READINESS.md).
    ALLOW_NON_COPTER_DIALECTS: ClassVar[bool] = False

    def __init__(
        self,
        sysid: int = 1,
        compid: int = 191,
        secret_key: bytes | None = None,
        link_id: int = 0,
        on_action: Callable[[str, str, str], None] | None = None,
        *,
        autopilot_id: int | None = None,
        mav_type: int | None = None,
        ts_state_path: str | Path | None = None,
    ) -> None:
        self.sysid = sysid
        self.compid = compid
        self.link_id = link_id
        self._encoder = mav2.MAVLink(None, srcSystem=sysid, srcComponent=compid)
        self._encoder.robust_parsing = True
        self._seq = 0
        self._signer = MavlinkSignatureVerifier(secret_key) if secret_key is not None else None
        self._ts_source: Callable[[], int | None] | None = None
        self._last_ts = 0
        self._last_ts_persist_mono = 0.0
        self._ts_dirty = False
        self._ts_state_path = Path(ts_state_path) if ts_state_path else None
        self.autopilot_id: int | None = autopilot_id
        self.mav_type: int | None = mav_type
        self.on_action = on_action
        self._refused_dialects: set[tuple[int | None, int | None, str]] = set()
        self._load_ts_state()

    def _load_ts_state(self) -> None:
        if self._ts_state_path is None:
            return
        with contextlib.suppress(OSError, ValueError, TypeError):
            raw = json.loads(self._ts_state_path.read_text(encoding="utf-8"))
            self._last_ts = max(self._last_ts, int(raw.get("last_ts_10us", 0)))

    def flush_state(self) -> None:
        """Persist monotonic actuator signing timestamp floor cleanly to disk."""
        if self._ts_state_path is None or not self._ts_dirty:
            return
        with contextlib.suppress(OSError):
            self._ts_state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._ts_state_path.with_suffix(self._ts_state_path.suffix + ".tmp")
            tmp.write_text(json.dumps({"last_ts_10us": int(self._last_ts)}), encoding="utf-8")
            with contextlib.suppress(OSError):
                os.chmod(tmp, 0o600)
            os.replace(tmp, self._ts_state_path)
            self._ts_dirty = False
            self._last_ts_persist_mono = time.monotonic()

    def set_vehicle_dialect(self, autopilot_id: int | None, mav_type: int | None) -> None:
        """Bind mode-mapping dialect dynamically from live vehicle HEARTBEAT."""
        self.autopilot_id = autopilot_id
        self.mav_type = mav_type

    def safe_hold_mode_name(self) -> str | None:
        """Return safe GPS-denied mode for the observed vehicle dialect, or None if unknown or not enabled."""
        if not self._dialect_enabled():
            self._audit_refusal("safe_hold")
            return None
        return safe_gps_denied_mode(self.autopilot_id, self.mav_type)

    def _dialect_enabled(self) -> bool:
        """True only for a positively identified ArduCopter, unless non-Copter actuation is explicitly enabled."""
        if self.ALLOW_NON_COPTER_DIALECTS:
            return True
        return self.autopilot_id == 3 and self.mav_type in COPTER_MAV_TYPES

    def _audit_refusal(self, what: str) -> None:
        """Audit-log (once per dialect and request kind) that a mode command was refused for this dialect."""
        key = (self.autopilot_id, self.mav_type, what)
        if key in self._refused_dialects:
            return
        self._refused_dialects.add(key)
        no_hb = " [no vehicle HEARTBEAT has fixed the dialect yet: fail-closed]" if self.autopilot_id is None else ""
        self._emit_action(
            "refuse_set_mode",
            what,
            f"DO_SET_MODE refused: autopilot={self.autopilot_id} mav_type={self.mav_type} is not an enabled "
            f"ArduCopter dialect (non-Copter actuation is disabled){no_hb}",
        )

    def _emit_action(self, action: str, target: str, detail: str) -> None:
        if self.on_action is not None:
            self.on_action(action, target, detail)

    def _next_seq(self) -> int:
        seq = self._seq
        self._seq = (self._seq + 1) % 256
        self._encoder.seq = seq
        return seq

    def set_timestamp_source(self, source: Callable[[], int | None] | None) -> None:
        """Take signing timestamps from observed signed traffic (10 us units) instead of the wall clock.

        MAVLink signing timestamps must not be older than what the receiver has already seen. A companion computer
        without RTC or internet has an arbitrary clock (hours or years behind), so frames stamped from it are
        rejected by the flight controller; stamping just above the newest valid timestamp seen on the link is not.
        """
        self._ts_source = source

    def _finalize(self, raw: bytes) -> bytes:
        if self._signer is None:
            return raw
        ts = self._ts_source() if self._ts_source is not None else None
        if ts is not None:
            ts = max(ts, self._last_ts + 1)
        elif self._last_ts > 0:
            wall_ts = getattr(self._signer, "next_timestamp", lambda: 0)()
            ts = max(int(wall_ts), self._last_ts + 1)
        signed = self._signer.sign_frame(raw, link_id=self.link_id, timestamp_10us=ts)
        if len(signed) >= 14 and (signed[2] & 0x01):
            emitted_ts = int.from_bytes(signed[-12:-6], "little")
            if emitted_ts > self._last_ts:
                self._last_ts = emitted_ts
                self._ts_dirty = True
                if self._ts_state_path is not None and (time.monotonic() - self._last_ts_persist_mono) >= 1.0:
                    self.flush_state()
        return signed

    def _resolve_mode_params(self, custom_mode_name: str | None) -> tuple[float, float, float] | None:
        if not custom_mode_name:
            return None
        if not self._dialect_enabled():
            self._audit_refusal(str(custom_mode_name).upper())
            return None
        name = str(custom_mode_name).upper()
        ap, mt = self.autopilot_id, self.mav_type
        if ap == 12:  # PX4
            pair = PX4_MAIN_MODES.get(name)
            if pair is None:
                return None
            return (float(mav2.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED), float(pair[0]), float(pair[1]))
        if ap not in (None, 3):  # unrecognized autopilot stack -> fail-closed
            return None
        if mt == FIXED_WING_MAV_TYPE or mt in VTOL_MAV_TYPES:
            mid = PLANE_MODES.get(name)
        elif mt in ROVER_MAV_TYPES:
            mid = ROVER_MODES.get(name)
        elif ap == 3 or (ap is None and mt is None):
            mid = COPTER_MODES.get(name)
        else:
            mid = None
        if mid is None:
            return None
        return (float(mav2.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED), float(mid), 0.0)

    def knows_mode(self, custom_mode_name: str | None) -> bool:
        """True only when ``custom_mode_name`` maps cleanly for the observed autopilot/frame dialect."""
        return self._resolve_mode_params(custom_mode_name) is not None

    def encode_set_mode(self, custom_mode_name: str, target_sysid: int = 1) -> bytes:
        """Encode MAV_CMD_DO_SET_MODE (176) to restore trusted flight mode.

        Raises ValueError for a mode or autopilot dialect it cannot map cleanly.
        """
        resolved = self._resolve_mode_params(custom_mode_name)
        if resolved is None:
            raise ValueError(
                f"unknown mode {custom_mode_name!r} for autopilot={self.autopilot_id} mav_type={self.mav_type}; refusing to guess"
            )
        p1, p2, p3 = resolved
        self._next_seq()
        msg = self._encoder.command_long_encode(
            target_sysid,
            1,  # target_component (autopilot)
            mav2.MAV_CMD_DO_SET_MODE,
            0,  # confirmation
            p1,
            p2,
            p3,
            0.0,
            0.0,
            0.0,
            0.0,
        )
        raw = self._finalize(bytes(msg.pack(self._encoder)))
        self._emit_action("encode_set_mode", f"sysid={target_sysid}", f"mode={custom_mode_name.upper()}")
        return raw

    def encode_ekf_source_switch(self, source_set: int = 2, target_sysid: int = 1) -> bytes:
        """Encode MAV_CMD_DO_AUX_FUNCTION (218) with Aux 90 (EKF Pos Source Switch).

        source_set: 1 = Primary GPS, 2 = Secondary GPS / Dead-Reckoning / OptFlow.
        """
        self._next_seq()
        msg = self._encoder.command_long_encode(
            target_sysid,
            1,
            MAV_CMD_DO_AUX_FUNCTION,
            0,
            90.0,  # Aux function 90: EKF Pos Source
            float(source_set),
            0.0,
            0.0,
            0.0,
            0.0,
            0.0,
        )
        raw = self._finalize(bytes(msg.pack(self._encoder)))
        self._emit_action("encode_ekf_source_switch", f"sysid={target_sysid}", f"source_set={source_set}")
        return raw

    def encode_prearm_disarm(self, force: bool = False, target_sysid: int = 1) -> bytes:
        """Encode MAV_CMD_COMPONENT_ARM_DISARM (400). ``force`` adds ArduPilot's force-disarm code (21196),
        which bypasses the autopilot's own checks; it is off by default and the controller never sets it."""
        self._next_seq()
        force_magic = 21196.0 if force else 0.0
        msg = self._encoder.command_long_encode(
            target_sysid,
            1,
            mav2.MAV_CMD_COMPONENT_ARM_DISARM,
            0,
            0.0,  # disarm
            force_magic,  # force disarm magic number in ArduPilot
            0.0,
            0.0,
            0.0,
            0.0,
            0.0,
        )
        raw = self._finalize(bytes(msg.pack(self._encoder)))
        self._emit_action("encode_prearm_disarm", f"sysid={target_sysid}", f"force={force}")
        return raw

    def encode_param_set(
        self,
        param_id: str,
        param_value: float,
        target_sysid: int = 1,
    ) -> bytes:
        """Encode PARAM_SET (23) to revert unauthorized parameter tampering."""
        self._next_seq()
        msg = self._encoder.param_set_encode(
            target_sysid,
            1,
            param_id.encode("ascii")[:16].ljust(16, b"\x00"),
            float(param_value),
            mav2.MAV_PARAM_TYPE_REAL32,
        )
        raw = self._finalize(bytes(msg.pack(self._encoder)))
        self._emit_action("encode_param_set", f"sysid={target_sysid}", f"{param_id}={param_value}")
        return raw

    def encode_statustext(self, text: str, severity: int = 2) -> bytes:
        """Encode STATUSTEXT (253) message for GCS / HUD display."""
        self._next_seq()
        raw_text = text.encode("utf-8")[:50]
        msg = self._encoder.statustext_encode(severity, raw_text)
        return self._finalize(bytes(msg.pack(self._encoder)))
