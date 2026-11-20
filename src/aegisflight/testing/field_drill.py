"""Pre-flight shadow field drill harness (W10, strictly 0 B FC TX).

Drives AegisFlight's inline firewall, detectors, and signing checks against an
in-memory virtual transport pair so operators can verify active protection logic on
the bench or before takeoff with zero bytes sent to any hardware flight controller.
"""

from __future__ import annotations

import os
import time
from typing import Any

from pymavlink.dialects.v20 import ardupilotmega as apm

from ..config import load_config
from ..core.types import MessageEnvelope
from ..hal.inline_ips import FrameContext, InlineIpsBridge
from ..mavlink.signing import sign_mavlink2_frame
from ..pipeline import IDSPipeline
from ..sources.stream import TelemetryTick

DRILL_SCENARIOS = (
    "signed_spoof_rejection",
    "gps_spoof_escalation",
    "semantic_param_fence_block",
    "clock_skew_sdr_spoof",
)


class _ShadowTransport:
    """In-memory sink transport that never touches a physical serial device."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.port: str | None = None
        self.connected = True
        self.sent_frames: list[bytes] = []

    def recv(self) -> list[tuple[int, bytes]]:
        return []

    def send(self, frame: bytes) -> bool:
        self.sent_frames.append(frame)
        return True

    def close(self) -> None:
        self.connected = False


def _pack(msg: Any, sysid: int, compid: int, seq: int = 1) -> bytes:
    m = apm.MAVLink(file=None, srcSystem=sysid, srcComponent=compid)
    m.seq = seq
    return bytes(msg.pack(m))


def _drill_signed_spoof_rejection() -> dict[str, Any]:
    t0 = time.perf_counter()
    fc = _ShadowTransport("shadow-fc")
    gcs = _ShadowTransport("shadow-gcs")
    key = os.urandom(32)
    bridge = InlineIpsBridge(fc, gcs, mode="active-ips", secret_key=key)
    try:
        hb = _pack(apm.MAVLink_heartbeat_message(2, 3, 0x81 | 0x80, 5, 4, 3), 1, 1, seq=1)
        bridge.policy.down(FrameContext("down", hb, 1_000_000_000, 1, 1, 1, 0, False))

        # Forged unsigned COMMAND_LONG (disarm) from sysid 255
        disarm_raw = _pack(
            apm.MAVLink_command_long_message(1, 1, apm.MAV_CMD_COMPONENT_ARM_DISARM, 0, 0, 0, 0, 0, 0, 0, 0),
            255, 190, seq=2,
        )
        out_unsigned = bridge.policy.up(FrameContext("up", disarm_raw, 2_000_000_000, 255, 190, 2, 76, False))

        # Signed with wrong key
        bad_signed = sign_mavlink2_frame(disarm_raw, os.urandom(32), link_id=0)
        out_bad = bridge.policy.up(FrameContext("up", bad_signed, 2_100_000_000, 255, 190, 3, 76, True))

        # Properly signed forced-disarm / guided command passes
        mode_raw = _pack(apm.MAVLink_set_mode_message(1, 1, 4), 255, 190, seq=4)
        good_signed = sign_mavlink2_frame(mode_raw, key, link_id=0)
        out_good = bridge.policy.up(FrameContext("up", good_signed, 2_200_000_000, 255, 190, 4, 11, True))

        ok = (len(out_unsigned) == 0) and (len(out_bad) == 0) and (len(out_good) == 1)
        return {
            "name": "signed_spoof_rejection",
            "ok": ok,
            "zero_real_fc_tx": True,
            "unsigned_dropped": len(out_unsigned) == 0,
            "bad_mac_dropped": len(out_bad) == 0,
            "valid_signed_forwarded": len(out_good) == 1,
            "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 2),
        }
    finally:
        bridge.close()


def _drill_semantic_param_fence_block() -> dict[str, Any]:
    t0 = time.perf_counter()
    fc = _ShadowTransport("shadow-fc")
    gcs = _ShadowTransport("shadow-gcs")
    bridge = InlineIpsBridge(fc, gcs, mode="active-ips", unsigned_acknowledged=True)
    try:
        hb = _pack(apm.MAVLink_heartbeat_message(2, 3, 0x81 | 0x80, 5, 4, 3), 1, 1, seq=1)
        bridge.policy.down(FrameContext("down", hb, 1_000_000_000, 1, 1, 1, 0, False))

        pset = _pack(apm.MAVLink_param_set_message(1, 1, b"FS_THR_ENABLE", 0.0, apm.MAV_PARAM_TYPE_REAL32), 255, 190, seq=2)
        out_pset = bridge.policy.up(FrameContext("up", pset, 1_500_000_000, 255, 190, 2, 23, False))

        fclear = _pack(apm.MAVLink_mission_clear_all_message(1, 1, 1), 255, 190, seq=3)
        out_fclear = bridge.policy.up(FrameContext("up", fclear, 1_600_000_000, 255, 190, 3, 45, False))

        sem = bridge.policy.semantic_stats()
        ok = (len(out_pset) == 0) and (len(out_fclear) == 0) and sem["dropped_param"] >= 1 and sem["dropped_fence"] >= 1
        return {
            "name": "semantic_param_fence_block",
            "ok": ok,
            "zero_real_fc_tx": True,
            "semantic_stats": sem,
            "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 2),
        }
    finally:
        bridge.close()


def _drill_gps_spoof_escalation() -> dict[str, Any]:
    t0 = time.perf_counter()
    cfg = load_config("configs/universal_flight")
    pipe = IDSPipeline(cfg, model_path=None)
    lat = 19.1334
    lon = 72.9133
    alerts: list[str] = []
    for k in range(30):
        t = k * 0.2
        if k >= 10:
            # Spoofed sudden offset jump (+0.001 deg ~ 111 m while vx=vy=0)
            lat_k = lat + 0.0012
        else:
            lat_k = lat
        msgs = [
            MessageEnvelope(t, 1, 1, 0, "HEARTBEAT", k % 256, False, 17, {"type": 2, "autopilot": 3, "base_mode": 0x81 | 0x80, "custom_mode": 5}),
            MessageEnvelope(t, 1, 1, 24, "GPS_RAW_INT", (k + 1) % 256, False, 40, {"fix_type": 3, "satellites_visible": 11, "eph": 90}),
            MessageEnvelope(t, 1, 1, 33, "GLOBAL_POSITION_INT", (k + 2) % 256, False, 36, {
                "lat": int(lat_k * 1e7), "lon": int(lon * 1e7), "alt": 50_000, "relative_alt": 40_000, "vx": 0, "vy": 0, "vz": 0, "hdg": 0,
            }),
            MessageEnvelope(t, 1, 1, 30, "ATTITUDE", (k + 3) % 256, False, 36, {"roll": 0.0, "pitch": 0.0, "yaw": 0.0, "rollspeed": 0.0, "pitchspeed": 0.0, "yawspeed": 0.0}),
        ]
        res = pipe.process_tick(TelemetryTick(tick=k, t=t, messages=msgs))
        if res is not None and res.is_alert:
            alerts.append(res.attack_type.value)
    return {
        "name": "gps_spoof_escalation",
        "ok": "GPS_SPOOFING" in alerts,
        "zero_real_fc_tx": True,
        "alert_types": sorted(set(alerts)),
        "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 2),
    }


def _drill_clock_skew_sdr_spoof() -> dict[str, Any]:
    t0 = time.perf_counter()
    cfg = load_config("configs/universal_flight")
    pipe = IDSPipeline(cfg, model_path=None)
    alerts: list[str] = []
    base_unix = 1_760_000_000_000_000  # valid Unix usec
    for k in range(16):
        t = k * 0.2
        unix_usec = base_unix + int(t * 1e6)
        if k >= 8:
            unix_usec -= 45_000_000  # 45 s backward SDR replay/spoof step
        msgs = [
            MessageEnvelope(t, 1, 1, 0, "HEARTBEAT", k % 256, False, 17, {"type": 2, "autopilot": 3, "base_mode": 0x81 | 0x80, "custom_mode": 5}),
            MessageEnvelope(t, 1, 1, 2, "SYSTEM_TIME", (k + 1) % 256, False, 20, {"time_unix_usec": unix_usec, "time_boot_ms": int(t * 1000)}),
        ]
        res = pipe.process_tick(TelemetryTick(tick=k, t=t, messages=msgs))
        if res is not None and res.is_alert:
            alerts.append(res.attack_type.value)
    return {
        "name": "clock_skew_sdr_spoof",
        "ok": "GPS_SPOOFING" in alerts,
        "zero_real_fc_tx": True,
        "alert_types": sorted(set(alerts)),
        "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 2),
    }


_RUNNERS = {
    "signed_spoof_rejection": _drill_signed_spoof_rejection,
    "gps_spoof_escalation": _drill_gps_spoof_escalation,
    "semantic_param_fence_block": _drill_semantic_param_fence_block,
    "clock_skew_sdr_spoof": _drill_clock_skew_sdr_spoof,
}


def run_field_drill(scenario: str = "all") -> dict[str, Any]:
    """Run one or all zero-TX shadow verification drills and return summary dict."""
    if scenario == "all":
        names = list(DRILL_SCENARIOS)
    elif scenario in _RUNNERS:
        names = [scenario]
    else:
        raise ValueError(f"unknown drill scenario {scenario!r}; choices: all, {', '.join(DRILL_SCENARIOS)}")

    results = [_RUNNERS[name]() for name in names]
    passed = sum(1 for r in results if r["ok"])
    return {
        "ok": passed == len(results),
        "zero_real_fc_tx": True,
        "passed": passed,
        "total": len(results),
        "scenarios": results,
    }
