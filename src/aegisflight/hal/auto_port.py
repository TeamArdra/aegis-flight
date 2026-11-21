"""Strictly receive-only serial port & baud-rate auto-discovery (W6 / W7).

Probes candidate serial ports across standard MAVLink baud rates with **zero bytes
transmitted** (never calls ``.write()`` on any probed port) using
``MavlinkStreamFramer`` + ``MavlinkDecoder`` to classify flight controllers vs
GCS/SiK telemetry radios and passively capture ``AUTOPILOT_VERSION`` frames.
"""

from __future__ import annotations

import contextlib
import time
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from ..mavlink.codec import MavlinkDecoder
from ..sources.mavlink_serial import MavlinkStreamFramer
from .discovery import KNOWN_FC_VIDS, KNOWN_RADIO_VIDS, HardwareDiscovery, PortInfo

DEFAULT_BAUD_CANDIDATES: tuple[int, ...] = (921600, 57600, 115200, 500000, 230400)
_MAV_TYPE_GCS = 6


@dataclass(frozen=True)
class DiscoveredMavlinkPort:
    """One passively identified MAVLink serial endpoint (zero bytes transmitted)."""

    device: str
    resolved_device: str
    baudrate: int
    role: str  # "fc" | "gcs_radio" | "unknown"
    sysids: tuple[int, ...]
    autopilot_id: int | None
    vehicle_type: int | None
    frames_valid: int
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def resolve_stable_by_id(device: str) -> str:
    """Return ``/dev/serial/by-id/...`` symlink targeting ``device`` when present on Linux."""
    by_id = Path("/dev/serial/by-id")
    if not by_id.is_dir():
        return device
    try:
        target = os_realpath(device)
        for entry in sorted(by_id.iterdir()):
            if os_realpath(str(entry)) == target:
                return str(entry)
    except OSError:
        pass
    return device


def os_realpath(path: str) -> str:
    return str(Path(path).resolve())


def _baud_order_for_port(info: PortInfo, candidates: tuple[int, ...]) -> list[int]:
    if info.is_flight_controller or (info.vid in KNOWN_FC_VIDS):
        preferred = [921600, 115200, 57600, 500000, 230400]
    elif info.is_telemetry_radio or (info.vid in KNOWN_RADIO_VIDS):
        preferred = [57600, 115200, 230400, 921600, 500000]
    else:
        preferred = list(candidates)
    out = [b for b in preferred if b in candidates]
    for b in candidates:
        if b not in out:
            out.append(b)
    return out


def _open_passive_serial(device: str, baudrate: int, timeout_s: float = 0.05) -> Any:
    import serial  # type: ignore[import-untyped]

    # pyserial 3.5 defaults its DTR and RTS state to True and applies it inside open() whenever dsrdtr / rtscts are False
    # (serialposix.py open(): `if not self._dsrdtr: self._update_dtr_state()`; serialwin32.py: DTR_CONTROL_ENABLE). So
    # `Serial(device, dsrdtr=False, rtscts=False)` still drives both lines high. Build the port unopened and set the
    # intended line state first. On Linux the kernel may still raise DTR/RTS for an instant while the tty opens.
    ser = serial.Serial()
    ser.port = device
    ser.baudrate = baudrate
    ser.timeout = timeout_s
    ser.write_timeout = 0.05
    ser.rtscts = False
    ser.xonxoff = False
    ser.dsrdtr = False
    ser.dtr = False
    ser.rts = False
    ser.open()
    return ser


def probe_serial_port_passive(
    info: PortInfo,
    *,
    baud_candidates: tuple[int, ...] = DEFAULT_BAUD_CANDIDATES,
    probe_window_s: float = 1.2,
    serial_opener: Callable[[str, int, float], Any] | None = None,
) -> DiscoveredMavlinkPort | None:
    """Listen strictly receive-only on ``info.device`` across ``baud_candidates``."""
    opener = serial_opener or _open_passive_serial
    order = _baud_order_for_port(info, baud_candidates)
    for baud in order:
        framer = MavlinkStreamFramer(accept_unverified_ids=True)
        decoder = MavlinkDecoder()
        sysids: set[int] = set()
        fc_seen = False
        gcs_seen = False
        radio_seen = False
        autopilot_id: int | None = None
        vehicle_type: int | None = None
        frames_valid = 0
        try:
            ser = opener(info.device, baud, 0.05)
        except Exception:  # noqa: BLE001
            continue
        try:
            deadline = time.monotonic() + max(0.1, probe_window_s)
            while time.monotonic() < deadline:
                chunk = ser.read(4096)
                if not chunk:
                    time.sleep(0.01)
                    continue
                frames = framer.feed(bytes(chunk))
                for raw in frames:
                    for env in decoder.decode(raw, time.monotonic()):
                        frames_valid += 1
                        sysids.add(env.sysid)
                        if env.msgname == "HEARTBEAT":
                            m_type = int(env.fields.get("type", 0))
                            ap = int(env.fields.get("autopilot", 0))
                            if m_type == _MAV_TYPE_GCS:
                                gcs_seen = True
                            else:
                                fc_seen = True
                                autopilot_id = ap
                                vehicle_type = m_type
                        elif env.msgname in ("GLOBAL_POSITION_INT", "ATTITUDE", "GPS_RAW_INT", "VFR_HUD"):
                            fc_seen = True
                        elif env.msgname == "RADIO_STATUS":
                            radio_seen = True
                if frames_valid >= 2 and (fc_seen or gcs_seen or radio_seen):
                    break
        except Exception:  # noqa: BLE001
            frames_valid = 0
        finally:
            with contextlib.suppress(Exception):
                ser.close()

        if frames_valid >= 2:
            if fc_seen and not gcs_seen:
                role = "fc"
            elif gcs_seen or radio_seen or info.is_telemetry_radio:
                role = "gcs_radio"
            elif info.is_flight_controller:
                role = "fc"
            else:
                role = "unknown"
            return DiscoveredMavlinkPort(
                device=info.device,
                resolved_device=resolve_stable_by_id(info.device),
                baudrate=baud,
                role=role,
                sysids=tuple(sorted(sysids)),
                autopilot_id=autopilot_id,
                vehicle_type=vehicle_type,
                frames_valid=frames_valid,
                description=info.description,
            )
    return None


def discover_mavlink_ports(
    *,
    ports: Iterable[PortInfo] | None = None,
    baud_candidates: tuple[int, ...] = DEFAULT_BAUD_CANDIDATES,
    probe_window_s: float = 1.2,
    serial_opener: Callable[[str, int, float], Any] | None = None,
) -> list[DiscoveredMavlinkPort]:
    """Scan local serial ports strictly receive-only and return identified MAVLink links."""
    cand_ports = list(ports) if ports is not None else HardwareDiscovery.scan_serial_ports()
    seen_real: set[str] = set()
    results: list[DiscoveredMavlinkPort] = []
    for p in cand_ports:
        real = os_realpath(p.device) if Path(p.device).exists() else p.device
        if real in seen_real:
            continue
        seen_real.add(real)
        found = probe_serial_port_passive(
            p,
            baud_candidates=baud_candidates,
            probe_window_s=probe_window_s,
            serial_opener=serial_opener,
        )
        if found is not None:
            results.append(found)
    return results


def capture_autopilot_version_passive(
    port: str,
    *,
    baudrate: int = 921600,
    timeout_s: float = 10.0,
    serial_opener: Callable[[str, int, float], Any] | None = None,
) -> dict[str, Any] | None:
    """Passively wait (0 B TX) on ``port`` for ``AUTOPILOT_VERSION`` (msgid 148).

    Returns a normalized dict suitable for ``configs/firmware_allowlist.yaml``, or None
    on timeout.
    """
    opener = serial_opener or _open_passive_serial
    framer = MavlinkStreamFramer(accept_unverified_ids=True)
    decoder = MavlinkDecoder()
    ser = opener(port, baudrate, 0.05)
    try:
        deadline = time.monotonic() + max(0.5, timeout_s)
        while time.monotonic() < deadline:
            chunk = ser.read(4096)
            if not chunk:
                time.sleep(0.01)
                continue
            for raw in framer.feed(bytes(chunk)):
                for env in decoder.decode(raw, time.monotonic()):
                    if env.msgname == "AUTOPILOT_VERSION":
                        f = env.fields
                        raw_custom = f.get("flight_custom_version", ())
                        if isinstance(raw_custom, (list, tuple)):
                            hex_custom = bytes(int(b) & 0xFF for b in raw_custom).hex()
                        elif isinstance(raw_custom, (bytes, bytearray)):
                            hex_custom = bytes(raw_custom).hex()
                        else:
                            hex_custom = str(raw_custom)
                        return {
                            "sysid": int(env.sysid),
                            "compid": int(env.compid),
                            "flight_sw_version": int(f.get("flight_sw_version", 0)),
                            "flight_custom_version_hex": hex_custom,
                            "board_version": int(f.get("board_version", 0)),
                            "vendor_id": int(f.get("vendor_id", 0)),
                            "product_id": int(f.get("product_id", 0)),
                            "uid": int(f.get("uid", 0)),
                        }
    finally:
        with contextlib.suppress(Exception):
            ser.close()
    return None
