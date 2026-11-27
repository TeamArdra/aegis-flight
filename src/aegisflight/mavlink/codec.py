"""MAVLink v2 encoding / decoding.

Uses the real ``pymavlink`` common dialect so the wire format the IDS ingests is
genuine MAVLink 2 — the same bytes an ArduPilot/PX4 vehicle would emit. The
encoder turns clean :class:`FlightState` ground truth into the six telemetry
message types configured for the vehicle, adding **sensor noise** at this
boundary (position/velocity/attitude/baro jitter, a per-session baro bias). The
decoder turns raw frames back into transport-neutral
:class:`~aegisflight.core.types.MessageEnvelope` objects.

Sequence numbers are managed per-source here because ``msg.pack()`` in this
pymavlink build does not auto-increment ``mav.seq``. Per-source counters let
attacks impersonate rogue system IDs with their own (anomalous) sequence
streams.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
from pymavlink.dialects.v20 import common as mav

from ..core.geo import offset_latlon
from ..core.types import FlightState, MessageEnvelope

# ArduCopter custom_mode <-> name mapping (complete ArduCopter COPTER_MODE table).
COPTER_MODES: dict[str, int] = {
    "STABILIZE": 0,
    "ACRO": 1,
    "ALT_HOLD": 2,
    "AUTO": 3,
    "GUIDED": 4,
    "LOITER": 5,
    "RTL": 6,
    "CIRCLE": 7,
    "LAND": 9,
    "DRIFT": 11,
    "SPORT": 13,
    "FLIP": 14,
    "AUTOTUNE": 15,
    "POSHOLD": 16,
    "BRAKE": 17,
    "THROW": 18,
    "AVOID_ADSB": 19,
    "GUIDED_NOGPS": 20,
    "SMART_RTL": 21,
    "FLOWHOLD": 22,
    "FOLLOW": 23,
    "ZIGZAG": 24,
    "SYSTEMID": 25,
    "AUTOROTATE": 26,
    "AUTO_RTL": 27,
    "TURTLE": 28,
    "TAKEOFF": 4,  # takeoff is flown in GUIDED on ArduCopter
}
MODE_NAMES: dict[int, str] = {v: k for k, v in COPTER_MODES.items() if k != "TAKEOFF"}

PLANE_MODES: dict[str, int] = {
    "MANUAL": 0,
    "CIRCLE": 1,
    "STABILIZE": 2,
    "TRAINING": 3,
    "ACRO": 4,
    "FBWA": 5,
    "FBWB": 6,
    "CRUISE": 7,
    "AUTOTUNE": 8,
    "AUTO": 10,
    "RTL": 11,
    "LOITER": 12,
    "TAKEOFF": 13,
    "GUIDED": 15,
    "QSTABILIZE": 17,
    "QHOVER": 18,
    "QLOITER": 19,
    "QLAND": 20,
    "QRTL": 21,
}
PLANE_MODE_NAMES: dict[int, str] = {v: k for k, v in PLANE_MODES.items()}

ROVER_MODES: dict[str, int] = {
    "MANUAL": 0,
    "ACRO": 1,
    "STEERING": 3,
    "HOLD": 4,
    "LOITER": 5,
    "AUTO": 10,
    "RTL": 11,
    "SMART_RTL": 12,
    "GUIDED": 15,
}
ROVER_MODE_NAMES: dict[int, str] = {v: k for k, v in ROVER_MODES.items()}

PX4_MAIN_MODES: dict[str, tuple[int, int]] = {
    "MANUAL": (1, 0),
    "ALTCTL": (2, 0),
    "POSCTL": (3, 0),
    "AUTO_READY": (4, 1),
    "AUTO_TAKEOFF": (4, 2),
    "AUTO_LOITER": (4, 3),
    "AUTO_MISSION": (4, 4),
    "AUTO_RTL": (4, 5),
    "AUTO_LAND": (4, 6),
    "ACRO": (5, 0),
    "OFFBOARD": (6, 0),
    "STABILIZED": (7, 0),
    "RATTITUDE": (8, 0),
}
_PX4_MODE_NAMES: dict[tuple[int, int], str] = {v: k for k, v in PX4_MAIN_MODES.items()}

COPTER_MAV_TYPES = frozenset({2, 3, 4, 13, 14, 15, 29})
VTOL_MAV_TYPES = frozenset({19, 20, 21, 22, 23, 24, 25})
ROVER_MAV_TYPES = frozenset({10, 11})
FIXED_WING_MAV_TYPE = 1
MAV_AUTOPILOT_INVALID = 8
# MAV_TYPE values for ground stations, companions, gimbals, cameras, sensors, and other non-vehicle peripherals.
NON_VEHICLE_MAV_TYPES = frozenset({
    5,   # MAV_TYPE_ANTENNA_TRACKER
    6,   # MAV_TYPE_GCS
    18,  # MAV_TYPE_ONBOARD_CONTROLLER
    26,  # MAV_TYPE_GIMBAL
    27,  # MAV_TYPE_ADSB
    30,  # MAV_TYPE_CAMERA
    31,  # MAV_TYPE_CHARGING_STATION
    32,  # MAV_TYPE_FLARM
    33,  # MAV_TYPE_SERVO
    34,  # MAV_TYPE_ODID
    36,  # MAV_TYPE_BATTERY
    37,  # MAV_TYPE_PARACHUTE
    38,  # MAV_TYPE_LOG
    39,  # MAV_TYPE_OSD
    40,  # MAV_TYPE_IMU
    41,  # MAV_TYPE_GPS
    42,  # MAV_TYPE_WINCH
    44,  # MAV_TYPE_ILLUMINATOR
    48,  # MAV_TYPE_GRIPPER
})


def decode_flight_mode(autopilot: int | None, mav_type: int | None, custom_mode: int) -> str:
    """Decode ``HEARTBEAT.custom_mode`` according to autopilot stack and frame type."""
    if autopilot == MAV_AUTOPILOT_INVALID or mav_type in NON_VEHICLE_MAV_TYPES:
        return "UNKNOWN"
    if autopilot == 12:  # MAV_AUTOPILOT_PX4
        main_m = (custom_mode >> 16) & 0xFF
        sub_m = (custom_mode >> 24) & 0xFF
        if (main_m, sub_m) in _PX4_MODE_NAMES:
            return _PX4_MODE_NAMES[(main_m, sub_m)]
        if (main_m, 0) in _PX4_MODE_NAMES:
            return _PX4_MODE_NAMES[(main_m, 0)]
        return f"PX4_{main_m}_{sub_m}"
    if autopilot == 3:  # MAV_AUTOPILOT_ARDUPILOTMEGA
        if mav_type == FIXED_WING_MAV_TYPE or (mav_type in VTOL_MAV_TYPES):
            return PLANE_MODE_NAMES.get(custom_mode, f"PLANE_{custom_mode}")
        if mav_type in ROVER_MAV_TYPES:
            return ROVER_MODE_NAMES.get(custom_mode, f"ROVER_{custom_mode}")
        return MODE_NAMES.get(custom_mode, "UNKNOWN")
    return MODE_NAMES.get(custom_mode, "UNKNOWN")


def safe_gps_denied_mode(autopilot: int | None, mav_type: int | None) -> str | None:
    """Return the safe non-GPS fallback mode for ``(autopilot, mav_type)``, or None if unknown."""
    if autopilot == 12:
        return "ALTCTL"
    if autopilot == 3:
        if mav_type == FIXED_WING_MAV_TYPE:
            return "FBWA"
        if mav_type in VTOL_MAV_TYPES:
            return "QHOVER"
        if mav_type in ROVER_MAV_TYPES:
            return "HOLD"
        if mav_type is None or mav_type in COPTER_MAV_TYPES:
            return "ALT_HOLD"
    return None


@dataclass
class RawPacket:
    """A single MAVLink frame on the simulated wire, with a send timestamp."""

    send_time: float
    data: bytes


class MavlinkEncoder:
    """Encodes ``FlightState`` into noisy, genuine MAVLink v2 frames."""

    def __init__(
        self,
        message_rates: dict[str, int],
        noise: dict[str, float],
        seed: int = 42,
        sysid: int = 1,
        compid: int = 1,
    ) -> None:
        self.rates = message_rates
        self.noise = noise
        self.sysid = sysid
        self.compid = compid
        # Separate RNG stream from the simulator so noise never shifts kinematics.
        self.rng = np.random.default_rng(seed + 1_000)
        self.mav = mav.MAVLink(file=None, srcSystem=sysid, srcComponent=compid)
        self.mav.robust_parsing = True
        self.seq_by_src: dict[tuple[int, int], int] = {}
        # A small constant barometric bias per session (sensor characteristic).
        self.baro_bias = float(self.rng.normal(0.0, 0.4))

    # -- low-level helpers -------------------------------------------------- #

    def _pack(self, msg: Any, sysid: int, compid: int) -> bytes:
        seq = self.seq_by_src.get((sysid, compid), 0)
        self.mav.srcSystem = sysid
        self.mav.srcComponent = compid
        self.mav.seq = seq
        buf = msg.pack(self.mav)
        self.seq_by_src[(sysid, compid)] = (seq + 1) % 256
        return bytes(buf)

    def _n(self, sigma: float) -> float:
        return float(self.rng.normal(0.0, sigma)) if sigma > 0 else 0.0

    def due(self, tick: int, msgname: str) -> bool:
        return tick % max(1, self.rates.get(msgname, 1)) == 0

    # -- message builders --------------------------------------------------- #

    def _heartbeat(self, s: FlightState) -> Any:
        base_mode = mav.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED
        if s.armed:
            base_mode |= mav.MAV_MODE_FLAG_SAFETY_ARMED
        custom = COPTER_MODES.get(s.flight_mode, 0)
        state = mav.MAV_STATE_ACTIVE if s.armed else mav.MAV_STATE_STANDBY
        return self.mav.heartbeat_encode(
            mav.MAV_TYPE_QUADROTOR, mav.MAV_AUTOPILOT_ARDUPILOTMEGA, base_mode, custom, state
        )

    def _global_position_int(self, s: FlightState) -> Any:
        np_ = self.noise.get("gps_pos_m", 0.0)
        lat, lon = offset_latlon(s.lat, s.lon, self._n(np_), self._n(np_))
        alt = (s.alt_msl + self._n(self.noise.get("gps_alt_m", 0.0))) * 1000.0
        rel = (s.rel_alt + self._n(self.noise.get("gps_alt_m", 0.0))) * 1000.0
        vn = self.noise.get("vel_ms", 0.0)
        return self.mav.global_position_int_encode(
            int(s.t * 1000) & 0xFFFFFFFF,
            int(lat * 1e7),
            int(lon * 1e7),
            int(alt),
            int(rel),
            int((s.vx + self._n(vn)) * 100),
            int((s.vy + self._n(vn)) * 100),
            int((s.vz + self._n(vn)) * 100),
            int(s.heading * 100) % 36000,
        )

    def _attitude(self, s: FlightState) -> Any:
        an = self.noise.get("attitude_rad", 0.0)
        return self.mav.attitude_encode(
            int(s.t * 1000) & 0xFFFFFFFF,
            s.roll + self._n(an),
            s.pitch + self._n(an),
            s.yaw + self._n(an),
            s.rollspeed + self._n(an),
            s.pitchspeed + self._n(an),
            s.yawspeed + self._n(an),
        )

    def _vfr_hud(self, s: FlightState) -> Any:
        vn = self.noise.get("vel_ms", 0.0)
        gs = max(0.0, s.groundspeed + self._n(vn))
        return self.mav.vfr_hud_encode(
            float(gs + self._n(vn)),  # airspeed ~ groundspeed in still air
            float(gs),
            int(s.heading) % 360,
            int(max(0, min(100, s.throttle))),
            # VFR_HUD.alt is the baro/EKF-fused altitude -> independent of the
            # GPS altitude in GLOBAL_POSITION_INT/GPS_RAW_INT. This gives the
            # physics detector two altitude channels to cross-check.
            float(s.baro_alt + self.baro_bias + self._n(self.noise.get("baro_m", 0.0))),
            float(s.vertical_speed + self._n(vn)),
        )

    def _sys_status(self, s: FlightState) -> Any:
        sensors = (
            mav.MAV_SYS_STATUS_SENSOR_3D_GYRO
            | mav.MAV_SYS_STATUS_SENSOR_3D_ACCEL
            | mav.MAV_SYS_STATUS_SENSOR_3D_MAG
            | mav.MAV_SYS_STATUS_SENSOR_GPS
            | mav.MAV_SYS_STATUS_SENSOR_ABSOLUTE_PRESSURE
        )
        v_mv = int(max(0.0, s.battery_voltage) * 1000)
        return self.mav.sys_status_encode(
            sensors, sensors, sensors,
            int(250 + self._n(20)),          # load (0.1%)
            v_mv,                            # voltage_battery (mV)
            -1,                              # current_battery (unknown)
            int(max(0, min(100, s.battery_remaining))),
            0, 0, 0, 0, 0, 0,                # comm drop/errors, errors_count1..4
        )

    def _gps_raw_int(self, s: FlightState) -> Any:
        np_ = self.noise.get("gps_pos_m", 0.0)
        lat, lon = offset_latlon(s.lat, s.lon, self._n(np_), self._n(np_))
        hdop = max(0.4, s.hdop + self._n(self.noise.get("hdop", 0.0)))
        return self.mav.gps_raw_int_encode(
            int(s.t * 1e6) & 0xFFFFFFFFFFFFFFFF,
            int(s.gps_fix_type),
            int(lat * 1e7),
            int(lon * 1e7),
            int((s.alt_msl + self._n(self.noise.get("gps_alt_m", 0.0))) * 1000),
            int(hdop * 100),
            int(hdop * 130),                 # epv ~ 1.3 * eph
            int(max(0.0, s.groundspeed) * 100),
            int(s.heading * 100) % 36000,
            int(s.satellites),
        )

    _BUILDERS = {
        "HEARTBEAT": _heartbeat,
        "GLOBAL_POSITION_INT": _global_position_int,
        "ATTITUDE": _attitude,
        "VFR_HUD": _vfr_hud,
        "SYS_STATUS": _sys_status,
        "GPS_RAW_INT": _gps_raw_int,
    }

    # -- public API --------------------------------------------------------- #

    def encode_tick(self, state: FlightState, tick: int) -> list[RawPacket]:
        """Return the MAVLink frames due at this simulator tick (with noise)."""
        out: list[RawPacket] = []
        for name, builder in self._BUILDERS.items():
            if self.due(tick, name):
                msg = builder(self, state)
                out.append(RawPacket(state.t, self._pack(msg, self.sysid, self.compid)))
        return out

    def encode_as(
        self,
        state: FlightState,
        sysid: int,
        compid: int,
        names: tuple[str, ...],
        send_time: float | None = None,
    ) -> list[RawPacket]:
        """Encode telemetry messages *as* a given (possibly rogue) source.

        Used by the MAVLink-anomaly attack to impersonate the vehicle from a
        rogue system id, complete with its own sequence stream.
        """
        st = send_time if send_time is not None else state.t
        out: list[RawPacket] = []
        for name in names:
            msg = self._BUILDERS[name](self, state)
            out.append(RawPacket(st, self._pack(msg, sysid, compid)))
        return out

    def encode_command_long(
        self,
        send_time: float,
        command: str | int,
        *,
        sysid: int,
        compid: int,
        target_system: int = 1,
        target_component: int = 1,
        params: tuple[float, ...] = (),
    ) -> RawPacket:
        """Encode a COMMAND_LONG (used by the command-injection attack)."""
        cmd_id = command if isinstance(command, int) else int(getattr(mav, command))
        p = list(params) + [0.0] * (7 - len(params))
        msg = self.mav.command_long_encode(
            target_system, target_component, cmd_id, 0, *p[:7]
        )
        return RawPacket(send_time, self._pack(msg, sysid, compid))


class MavlinkDecoder:
    """Decodes raw MAVLink v2 frames into ``MessageEnvelope`` objects."""

    def __init__(self) -> None:
        self.mav = mav.MAVLink(file=None)
        self.mav.robust_parsing = True

    def decode(self, data: bytes, recv_time: float) -> list[MessageEnvelope]:
        envelopes: list[MessageEnvelope] = []
        msgs = self.mav.parse_buffer(data) or []
        for msg in msgs:
            if msg.get_type() == "BAD_DATA":
                continue
            fields = msg.to_dict()
            fields.pop("mavpackettype", None)
            envelopes.append(
                MessageEnvelope(
                    recv_time=recv_time,
                    sysid=msg.get_srcSystem(),
                    compid=msg.get_srcComponent(),
                    msgid=msg.get_msgId(),
                    msgname=msg.get_type(),
                    seq=msg.get_seq(),
                    signed=bool(msg.get_signed()),
                    byte_len=len(data),
                    fields=fields,
                )
            )
        return envelopes


def command_name_from_id(cmd_id: int) -> str:
    """Best-effort reverse lookup of a MAV_CMD_* name from its numeric id."""
    for name in dir(mav):
        if name.startswith("MAV_CMD_") and getattr(mav, name) == cmd_id:
            return name
    return f"CMD_{cmd_id}"
