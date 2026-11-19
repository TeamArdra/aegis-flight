"""Airborne Semantic Firewall for control-aware parameter & geofence attacks (W1).

Defends against syntactically valid MAVLink ``PARAM_SET`` (msgid 23) and geofence
``MISSION_CLEAR_ALL`` / ``MISSION_COUNT`` / ``MISSION_ITEM_INT`` (``mission_type=1``)
injections while the vehicle is armed, as well as unexpected safety-parameter drift
observed on downlink ``PARAM_VALUE`` (msgid 22) readbacks in side-tap setups.
"""

from __future__ import annotations

import math
import struct
from collections.abc import Iterable
from dataclasses import dataclass

from ..core.geo import haversine_m

_MSG_PARAM_SET = 23
_MSG_MISSION_COUNT = 44
_MSG_MISSION_CLEAR_ALL = 45
_MSG_MISSION_ITEM_INT = 73

MAV_MISSION_TYPE_FENCE = 1
MAV_CMD_NAV_FENCE_CIRCLE_INCLUSION = 5003

DEFAULT_PROTECTED_PARAM_PREFIXES: tuple[str, ...] = (
    # Geofence
    "FENCE_",
    "GF_",
    # Failsafes & arming checks
    "FS_",
    "ARMING_CHECK",
    "BRD_SAFETY",
    "SYSID_",
    "COM_DLL_ACT",
    "COM_RC_LOSS_T",
    "COM_LOW_BAT_ACT",
    "COM_ARM_CHK",
    "CBRK_",
    "BATT_FS_",
    # Estimator / GPS glitch gates
    "EK3_SRC1_",
    "EK3_GPS_",
    "EK2_GPS_",
    "EKF2_GPS_",
    "EKF2_HGT_REF",
    "EKF2_AID_MASK",
    "GPS_TYPE",
    "GPS1_TYPE",
    "GPS_AUTO_SWITCH",
    # Flight control stability loops
    "ATC_RAT_",
    "ATC_ANG_",
    "MC_ROLLRATE_",
    "MC_PITCHRATE_",
    "MC_YAWRATE_",
    "FW_RR_",
    "FW_PR_",
    "MOT_THST_",
)


@dataclass(frozen=True)
class ParamWriteEvent:
    recv_time: float
    sysid: int
    compid: int
    param_id: str
    param_value: float
    param_type: int
    source_kind: str = "param_set"  # "param_set" | "param_value"


@dataclass(frozen=True)
class FenceChangeEvent:
    recv_time: float
    sysid: int
    compid: int
    action: str  # "clear_fence" | "upload_fence" | "fence_item"
    mission_type: int
    count: int | None = None
    command: int | None = None
    radius_m: float | None = None
    lat_deg: float | None = None
    lon_deg: float | None = None


@dataclass(frozen=True)
class SemanticVerdict:
    blocked: bool
    reason: str
    category: str  # "param_tamper" | "geofence_hijack" | "ok"
    severity_score: float


def _payload(raw: bytes) -> bytes | None:
    if not raw:
        return None
    if raw[0] == 0xFD and len(raw) >= 12:
        return raw[10 : 10 + raw[1]] + bytes(48)
    if raw[0] == 0xFE and len(raw) >= 8:
        return raw[6 : 6 + raw[1]] + bytes(48)
    return None


def extract_param_set_raw(raw: bytes) -> tuple[str, float, int] | None:
    """Parse ``(param_id, param_value, param_type)`` from a raw ``PARAM_SET`` frame."""
    p = _payload(raw)
    if p is None:
        return None
    try:
        param_value, _target_sys, _target_comp, raw_id, param_type = struct.unpack_from("<fBB16sB", p, 0)
    except struct.error:
        return None
    param_id = raw_id.split(b"\x00", 1)[0].decode("ascii", errors="ignore").strip()
    return param_id, float(param_value), int(param_type)


def extract_mission_fence_raw(raw: bytes, msgid: int) -> tuple[str, int, int | None, int | None, float | None, float | None, float | None] | None:
    """Parse geofence mission operations from raw MAVLink frames.

    Returns ``(action, mission_type, count, command, radius_m, lat_deg, lon_deg)`` or None.
    """
    p = _payload(raw)
    if p is None:
        return None
    try:
        if msgid == _MSG_MISSION_CLEAR_ALL:
            # <BBB: target_system, target_component, mission_type
            _, _, mtype = struct.unpack_from("<BBB", p, 0)
            return ("clear_fence", int(mtype), None, None, None, None, None)
        if msgid == _MSG_MISSION_COUNT:
            # <HBBB: count, target_system, target_component, mission_type
            cnt, _, _, mtype = struct.unpack_from("<HBBB", p, 0)
            return ("upload_fence", int(mtype), int(cnt), None, None, None, None)
        if msgid == _MSG_MISSION_ITEM_INT:
            # MISSION_ITEM_INT wire layout (size-sorted):
            # param1..4 (4f = 16B), x (i = 4B @ 16), y (i = 4B @ 20), z (f = 4B @ 24),
            # seq (H @ 28), command (H @ 30), target_sys (B @ 32), target_comp (B @ 33),
            # frame (B @ 34), current (B @ 35), autocontinue (B @ 36), mission_type (B @ 37)
            p1, _, _, _, x_i, y_i, _z, _seq, cmd, _ts, _tc, _fr, _cur, _ac, mtype = struct.unpack_from(
                "<ffffiifHHBBBBBB", p, 0
            )
            return (
                "fence_item",
                int(mtype),
                None,
                int(cmd),
                float(p1),
                x_i / 1e7,
                y_i / 1e7,
            )
    except struct.error:
        return None
    return None


class SemanticFirewall:
    """Stateful semantic invariant evaluator for MAVLink parameters and geofences."""

    def __init__(
        self,
        *,
        enabled: bool = True,
        protected_prefixes: Iterable[str] = DEFAULT_PROTECTED_PARAM_PREFIXES,
        deny_always_params: Iterable[str] = (),
        block_when_arm_unknown: bool = False,
    ) -> None:
        self.enabled = bool(enabled)
        self.protected_prefixes = tuple(str(p).upper() for p in protected_prefixes if str(p).strip())
        self.deny_always = frozenset(str(p).upper() for p in deny_always_params if str(p).strip())
        self.block_when_arm_unknown = bool(block_when_arm_unknown)
        self._param_baselines: dict[str, float] = {}

    def is_protected_param(self, param_id: str) -> bool:
        up = param_id.strip().upper()
        if not up:
            return False
        if up in self.deny_always:
            return True
        return any(up.startswith(pref) for pref in self.protected_prefixes)

    def evaluate_param_write(self, ev: ParamWriteEvent, *, armed: bool | None) -> SemanticVerdict:
        if not self.enabled:
            return SemanticVerdict(False, "disabled", "ok", 0.0)
        up = ev.param_id.strip().upper()
        if ev.source_kind == "param_value":
            if self.is_protected_param(up) and math.isfinite(ev.param_value):
                prev = self._param_baselines.get(up)
                if prev is None or armed is False:
                    self._param_baselines[up] = ev.param_value
                elif armed is True and abs(ev.param_value - prev) > 1e-6:
                    self._param_baselines[up] = ev.param_value
                    return SemanticVerdict(
                        blocked=False,
                        reason=f"airborne_param_changed:{up}:{prev:g}->{ev.param_value:g}",
                        category="param_tamper",
                        severity_score=0.90,
                    )
            return SemanticVerdict(False, "ok", "ok", 0.0)

        # Uplink PARAM_SET
        if not self.is_protected_param(up):
            return SemanticVerdict(False, "ok", "ok", 0.0)
        if up in self.deny_always:
            return SemanticVerdict(True, f"denied_safety_param:{up}", "param_tamper", 0.95)
        if armed is True:
            return SemanticVerdict(True, f"airborne_safety_param:{up}", "param_tamper", 0.95)
        if armed is None and self.block_when_arm_unknown:
            return SemanticVerdict(True, f"arm_unknown_safety_param:{up}", "param_tamper", 0.80)
        return SemanticVerdict(False, "ok", "ok", 0.0)

    def evaluate_fence_change(
        self,
        ev: FenceChangeEvent,
        *,
        armed: bool | None,
        home_lat_lon: tuple[float, float] | None = None,
    ) -> SemanticVerdict:
        if not self.enabled or ev.mission_type != MAV_MISSION_TYPE_FENCE:
            return SemanticVerdict(False, "ok", "ok", 0.0)
        if ev.action == "clear_fence" and (armed is True or (armed is None and self.block_when_arm_unknown)):
            return SemanticVerdict(True, "airborne_fence_clear", "geofence_hijack", 0.95)
        if ev.action == "upload_fence" and (armed is True or (armed is None and self.block_when_arm_unknown)):
            return SemanticVerdict(True, "airborne_fence_overwrite", "geofence_hijack", 0.90)
        if (ev.action == "fence_item" and ev.command == MAV_CMD_NAV_FENCE_CIRCLE_INCLUSION
                and home_lat_lon is not None and ev.lat_deg is not None and ev.lon_deg is not None
                and ev.radius_m is not None and ev.radius_m > 0.0):
            dist_m = haversine_m(home_lat_lon[0], home_lat_lon[1], ev.lat_deg, ev.lon_deg)
            if dist_m > ev.radius_m:
                return SemanticVerdict(
                    True,
                    f"fence_excludes_home:dist={dist_m:.0f}m>r={ev.radius_m:.0f}m",
                    "geofence_hijack",
                    0.92,
                )
        return SemanticVerdict(False, "ok", "ok", 0.0)

    def reset(self) -> None:
        self._param_baselines.clear()
