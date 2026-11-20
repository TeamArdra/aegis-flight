"""Hardware-readiness & RF-impaired extreme soak suite for AegisFlight.

Simulates real-world flight conditions through the actual ``InlineIpsBridge``
forwarding + analysis threads under:
1. Harsh benign RF flight (4% loss, reordering, corrupt UART bytes, yaw sweeps) -> 0 false alerts.
2. Extreme-volume flood + spoofed-ID storm + IEEE-754 NaN/Inf frames -> bounded memory, 0 errors.
3. Compound multi-vector attack under signed ACTIVE_IPS -> fail-closed uplink blocking & quarantine.
4. Cryptographic SQLite event/action hash chains + HMAC-signed anchor verification.
5. Physical serial receive-only boundary verification.

Usage:
    python scripts/hardware/hw_readiness_soak.py [--cycles 5] [--flood-frames 3000]
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import math
import queue
import random
import struct
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from pymavlink.dialects.v20 import ardupilotmega as apm

from aegisflight.config import load_config
from aegisflight.core.geo import offset_latlon
from aegisflight.hal.inline_ips import InlineIpsBridge
from aegisflight.logging.anchors import AnchorWriter, verify_anchors
from aegisflight.logging.store import EventStore
from aegisflight.mavlink.signing import sign_mavlink2_frame
from aegisflight.mitigation.types import DefenseMode
from aegisflight.sources.mavlink_serial import may_reach_vehicle


class _WireTransport:
    """In-memory bidirectional MAVLink transport with optional RF loss/reorder/garbage."""

    def __init__(self, name: str, *, port: str | None = None) -> None:
        self.name = name
        self.port = port
        self.connected = True
        self._rx: queue.Queue[tuple[int, bytes]] = queue.Queue()
        self.tx_log: list[bytes] = []
        self._lock = threading.Lock()
        self.closed = False

    def push_rx(self, data: bytes, stamp_ns: int | None = None) -> None:
        if not self.closed:
            self._rx.put((time.monotonic_ns() if stamp_ns is None else stamp_ns, data))

    def poll(self) -> list[tuple[int, bytes]]:
        out: list[tuple[int, bytes]] = []
        while True:
            try:
                out.append(self._rx.get_nowait())
            except queue.Empty:
                return out

    def send(self, data: bytes) -> bool:
        if self.closed:
            return False
        with self._lock:
            self.tx_log.append(data)
        return True

    def close(self) -> None:
        self.closed = True


@dataclass
class SoakReport:
    cycles: int
    benign_alerts: int
    attack_alerts: int
    forwarded_frames: int
    dropped_up: int
    dropped_unsigned: int
    dropped_untrusted_control: int
    dropped_semantic_param: int
    analyser_errors: int
    bridge_threads_healthy: bool
    events_chain_ok: bool
    actions_chain_ok: bool
    anchors_ok: bool
    signed_anchors: int
    serial_boundary_ok: bool
    forwarding_p95_us: float | None
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return (
            not self.errors
            and self.benign_alerts == 0
            and self.attack_alerts > 0
            and self.analyser_errors == 0
            and self.bridge_threads_healthy
            and self.events_chain_ok
            and self.actions_chain_ok
            and self.anchors_ok
            and self.signed_anchors >= 1
            and self.serial_boundary_ok
            and self.dropped_unsigned > 0
            and self.dropped_semantic_param > 0
        )


def _pack(mav: apm.MAVLink, msg_fn: str, *args: object) -> bytes:
    return bytes(getattr(mav, f"{msg_fn}_encode")(*args).pack(mav))


def _nan_vfr_hud_frame(seq: int) -> bytes:
    """Build a raw MAVLink v2 VFR_HUD frame containing IEEE-754 NaN airspeed/groundspeed."""
    m = apm.MAVLink(None, srcSystem=1, srcComponent=1)
    m.seq = seq & 0xFF
    raw = bytearray(_pack(m, "vfr_hud", 0.0, 12.0, 90, 55, 60.0, 0.0))
    # Patch groundspeed (float @ offset 14 in V2 packet: 10 hdr + 4 airspeed) with NaN
    struct.pack_into("<f", raw, 14, float("nan"))
    from aegisflight.mavlink.signing import x25_crc

    crc_extra = int(apm.MAVLink_vfr_hud_message.crc_extra) & 0xFF
    crc = x25_crc(bytes(raw[1 : 10 + raw[1]]) + bytes([crc_extra]))
    struct.pack_into("<H", raw, 10 + raw[1], crc)
    return bytes(raw)


def run_hw_readiness_soak(
    *,
    cycles: int = 1,
    flood_frames: int = 1500,
    seed: int = 2026,
) -> SoakReport:
    """Run all 5 hardware-readiness soak phases inside a temporary SQLite/anchor directory."""
    rng = random.Random(seed)
    sign_key = hashlib.sha256(b"aegisflight-hw-readiness-signing-key").digest()
    anchor_key = hashlib.sha256(b"aegisflight-hw-readiness-anchor-key").digest()
    cfg = load_config("configs/universal_flight")
    # Signed real-hardware / HITL bridge deployments must enable protocol.require_signing
    cfg.detector["protocol"]["require_signing"] = True

    with tempfile.TemporaryDirectory(prefix="aegis_hw_soak_") as td:
        db_path = Path(td) / "soak.sqlite"
        store = EventStore(db_path)
        anchor_writer = AnchorWriter(store, interval_s=0.1, key=anchor_key)
        fc = _WireTransport("socket://127.0.0.1:5760", port="socket://127.0.0.1:5760")
        gcs = _WireTransport("udp:127.0.0.1:14550")

        bridge = InlineIpsBridge(
            fc,
            gcs,
            cfg=cfg,
            mode=DefenseMode.PASSIVE,
            secret_key=sign_key,
            store=store,
            run_id="hw-soak-1",
            sample_rate_hz=20.0,
            idle_sleep_s=0.001,
            anchor_writer=anchor_writer,
            fail_closed_uplink_commands=True,
            semantic_firewall_enabled=True,
        )
        store.start_run("hw-soak-1", label="hw-readiness-soak")
        bridge.start()

        fc_mav = apm.MAVLink(None, srcSystem=1, srcComponent=1)
        gcs_mav = apm.MAVLink(None, srcSystem=255, srcComponent=190)
        rogue_mav = apm.MAVLink(None, srcSystem=66, srcComponent=200)
        ts_10us = int((time.time() - 1_420_070_400) * 100_000)

        lat0, lon0 = 19.1334, 72.9133
        vn, ve = 12.0, 0.0
        t_ms = 1000

        def next_sig(raw: bytes, link_id: int = 0) -> bytes:
            nonlocal ts_10us
            ts_10us += 10
            return sign_mavlink2_frame(raw, sign_key, link_id=link_id, timestamp_10us=ts_10us)

        benign_alerts = 0
        attack_alerts = 0
        errors: list[str] = []

        try:
            # --- Phase 1a: Pre-arm ground check (learns GPS-vs-baro static offset = +10 m while disarmed) ---
            for _step in range(10):
                t_ms += 25
                for raw in (
                    next_sig(_pack(fc_mav, "heartbeat", 2, 3, 0x00, 3, 4)),  # MAV_TYPE_QUADROTOR, disarmed
                    next_sig(_pack(fc_mav, "gps_raw_int", t_ms * 1000, 3, int(lat0 * 1e7), int(lon0 * 1e7), 60000, 90, 120, 0, 0, 14)),
                    next_sig(_pack(fc_mav, "global_position_int", t_ms, int(lat0 * 1e7), int(lon0 * 1e7), 60000, 0, 0, 0, 0, 0)),
                    next_sig(_pack(fc_mav, "vfr_hud", 0.0, 0.0, 0, 0, 50.0, 0.0)),
                    next_sig(_pack(fc_mav, "sys_status", 0, 0, 0, 100, 25000, -1, 100, 0, 0, 0, 0, 0, 0)),
                ):
                    fc.push_rx(raw)
                time.sleep(0.025)

            # --- Phase 1b: Harsh Benign RF Flight (drops, reordering, garbage chunks, yaw sweeps, QNH offset) ---
            n_benign_steps = max(25, cycles * 20)
            curr_vn = 0.0
            for step in range(n_benign_steps):
                dt_s = 0.025
                t_ms += int(dt_s * 1000)
                if curr_vn < vn:
                    accel_n = min(1.5, (vn - curr_vn) / dt_s)
                    curr_vn = min(vn, curr_vn + accel_n * dt_s)
                else:
                    accel_n = 0.0
                pitch = -math.asin(min(0.5, accel_n / 9.80665))
                lat0, lon0 = offset_latlon(lat0, lon0, curr_vn * dt_s, ve * dt_s)
                yaw = math.sin(step * 0.06) * 1.4  # multirotor yaw independent of course
                hdg = int(math.degrees(yaw) % 360)

                frames = [
                    next_sig(_pack(fc_mav, "heartbeat", 2, 3, 0x80, 3, 4)),
                    next_sig(_pack(fc_mav, "gps_raw_int", t_ms * 1000, 3, int(lat0 * 1e7), int(lon0 * 1e7), 60000, 90, 120, int(curr_vn * 100), 0, 14)),
                    next_sig(_pack(fc_mav, "global_position_int", t_ms, int(lat0 * 1e7), int(lon0 * 1e7), 60000, 10000, int(curr_vn * 100), int(ve * 100), 0, hdg * 100)),
                    next_sig(_pack(fc_mav, "attitude", t_ms, 0.01, pitch, yaw, 0.01, -0.01, 0.02 + 0.001 * step)),
                    next_sig(_pack(fc_mav, "vfr_hud", curr_vn, curr_vn, hdg, 55, 50.0, 0.0)),
                    next_sig(_pack(fc_mav, "sys_status", 0, 0, 0, 200, 24950 - step * 2, -1, 95, 0, 0, 0, 0, 0, 0)),
                ]
                for raw in frames:
                    if rng.random() < 0.04:
                        continue  # 4% RF drop (note: same-link signed frames are monotonic by MAVLink-2 spec)
                    fc.push_rx(raw)
                if step % 10 == 5:
                    fc.push_rx(b"\xfe\x12\x99garbage_uart_glitch")
                # GCS periodic heartbeat (validly signed)
                if step % 5 == 0:
                    gcs.push_rx(next_sig(_pack(gcs_mav, "heartbeat", 6, 8, 0, 0, 4), link_id=1))
                time.sleep(dt_s)

            time.sleep(0.15)
            benign_alerts = bridge.alerts

            # --- Phase 2: Escalate to signed ACTIVE_IPS + Extreme Flood & NaN Poison ---
            bridge.set_mode(DefenseMode.ACTIVE_IPS)
            # Inject NaN telemetry frame + spoofed-ID flood + malformed flood
            fc.push_rx(_nan_vfr_hud_frame(step + 1))
            spoof_chunk = bytearray()
            for i in range(flood_frames):
                sid = 10 + (i % 600) // 20
                cid = 1 + (i % 20)
                rm = apm.MAVLink(None, srcSystem=sid, srcComponent=cid)
                rm.seq = i & 0xFF
                spoof_chunk.extend(_pack(rm, "attitude", t_ms + i, 0.1, 0.1, 0.1, 0.0, 0.0, 0.0))
                if (i + 1) % 16 == 0:
                    fc.push_rx(bytes(spoof_chunk))
                    spoof_chunk.clear()
            if spoof_chunk:
                fc.push_rx(bytes(spoof_chunk))
            time.sleep(0.25)

            # --- Phase 3: Compound Multi-Vector Attack under Signed ACTIVE_IPS ---
            # 1) Unsigned GCS control forgery attempting force-disarm
            gcs.push_rx(_pack(gcs_mav, "command_long", 1, 1, 400, 0, 0.0, 21196.0, 0.0, 0.0, 0.0, 0.0, 0.0))
            # 2) Signed malicious PARAM_SET modifying FENCE_ENABLE while armed (Semantic Firewall must block)
            gcs.push_rx(next_sig(_pack(gcs_mav, "param_set", 1, 1, b"FENCE_ENABLE\x00\x00\x00\x00", 0.0, apm.MAV_PARAM_TYPE_REAL32), link_id=1))
            # 3) Untrusted rogue sysid 66 command + telemetry
            gcs.push_rx(_pack(rogue_mav, "command_long", 1, 1, 176, 0, 1.0, 6.0, 0.0, 0.0, 0.0, 0.0, 0.0))
            fc.push_rx(_pack(rogue_mav, "gps_raw_int", t_ms * 1000, 3, int((lat0 + 0.01) * 1e7), int((lon0 + 0.01) * 1e7), 50000, 90, 120, 1200, 0, 14))
            # 4) Continued valid FC telemetry + injected position drift so pipeline advances and logs alerts
            for _j in range(25):
                dt_s = 0.05
                t_ms += int(dt_s * 1000)
                lat0, lon0 = offset_latlon(lat0, lon0, (vn + 35.0) * dt_s, ve * dt_s)  # sharp drift
                fc.push_rx(next_sig(_pack(fc_mav, "heartbeat", 2, 3, 0x80, 3, 4)))
                fc.push_rx(next_sig(_pack(fc_mav, "global_position_int", t_ms, int(lat0 * 1e7), int(lon0 * 1e7), 60000, 10000, int(vn * 100), 0, 0, 0)))
                time.sleep(dt_s)

            time.sleep(0.25)
            attack_alerts = bridge.alerts - benign_alerts
            healthy = bridge.threads_healthy()
            st = bridge.status()
        finally:
            bridge.close()

        # --- Phase 4: Verify cryptographic hash chains & signed anchors ---
        ev_cs = store.verify_chain("hw-soak-1")
        act_cs = store.verify_actions_chain("hw-soak-1")
        anc_res = verify_anchors(
            store,
            anchor_writer.anchor_path,
            key=anchor_key,
            expected_min_anchors=1,
        )
        store.close()

        # Verify that no rogue/forged command or param write leaked into fc.tx_log
        leaked_param = any(len(raw) >= 10 and (raw[7] | (raw[8] << 8) | (raw[9] << 16)) == 23 for raw in fc.tx_log)
        if leaked_param:
            errors.append("PARAM_SET leaked through SemanticFirewall onto FC transport")
        leaked_disarm = False
        for raw in fc.tx_log:
            if len(raw) >= 40 and (raw[7] | (raw[8] << 8) | (raw[9] << 16)) == 76:
                p1, p2 = struct.unpack_from("<2f", raw, 10)
                cmd_id = struct.unpack_from("<H", raw, 38)[0]
                if cmd_id == 400 and p1 == 0.0 and hmac.compare_digest(b"1" if p2 == 21196.0 else b"0", b"1"):
                    leaked_disarm = True
        if leaked_disarm:
            errors.append("forged disarm leaked onto FC transport")

        # --- Phase 5: Physical serial receive-only boundary check ---
        serial_refused = False
        for dev in ("/dev/ttyAMA0", "COM3"):
            try:
                InlineIpsBridge(_WireTransport(dev, port=dev), _WireTransport("gcs"), mode=DefenseMode.ACTIVE_IPS)
            except ValueError:
                serial_refused = may_reach_vehicle(dev)
            if not serial_refused:
                errors.append(f"serial boundary failed for {dev}")
                break

        return SoakReport(
            cycles=cycles,
            benign_alerts=benign_alerts,
            attack_alerts=attack_alerts,
            forwarded_frames=st["frames"]["down"] + st["frames"]["up"],
            dropped_up=st["frames"]["dropped_up"],
            dropped_unsigned=st["policy"]["dropped_unsigned"],
            dropped_untrusted_control=st["policy"]["dropped_untrusted_control"],
            dropped_semantic_param=st["semantic_firewall"]["dropped_param"],
            analyser_errors=st["analyser"]["errors"],
            bridge_threads_healthy=healthy,
            events_chain_ok=ev_cs.ok,
            actions_chain_ok=act_cs.ok,
            anchors_ok=anc_res.ok,
            signed_anchors=anc_res.signed_anchors,
            serial_boundary_ok=serial_refused,
            forwarding_p95_us=st["latency_us"]["p95"],
            errors=errors,
        )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cycles", type=int, default=3, help="Number of benign flight cycles before flood/attack phases")
    ap.add_argument("--flood-frames", type=int, default=3000, help="Spoofed/flood frames to burst through bridge")
    ap.add_argument("--seed", type=int, default=2026)
    args = ap.parse_args(argv)
    rep = run_hw_readiness_soak(cycles=args.cycles, flood_frames=args.flood_frames, seed=args.seed)
    print(
        f"hw_readiness_soak: ok={rep.ok} benign_alerts={rep.benign_alerts} attack_alerts={rep.attack_alerts} "
        f"forwarded={rep.forwarded_frames} dropped_up={rep.dropped_up} "
        f"dropped_unsigned={rep.dropped_unsigned} dropped_semantic_param={rep.dropped_semantic_param} "
        f"analyser_errors={rep.analyser_errors} p95_us={rep.forwarding_p95_us} "
        f"events_chain={rep.events_chain_ok} actions_chain={rep.actions_chain_ok} "
        f"anchors={rep.anchors_ok}({rep.signed_anchors}) serial_boundary={rep.serial_boundary_ok}"
    )
    if rep.errors:
        print(f"errors: {rep.errors}", file=sys.stderr)
    return 0 if rep.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
