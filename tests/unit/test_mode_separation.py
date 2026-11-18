"""Strict 3-mode separation tests across InlineIpsBridge and LiveEngine (#58)."""

from __future__ import annotations

import warnings
from pathlib import Path

from pymavlink.dialects.v20 import common as mav2

from aegisflight.backend.engine import LiveEngine
from aegisflight.backend.sources import SourceSpec
from aegisflight.core.enums import AttackType, IntegrityStatus, Severity
from aegisflight.core.types import TelemetrySnapshot, ThreatAssessment
from aegisflight.features.extractor import FeatureFrame
from aegisflight.hal.inline_ips import InlineIpsBridge
from aegisflight.hal.mgmt_channel import OP_STATUS_NOW, build_command_frame
from aegisflight.mavlink.signing import MavlinkSignatureVerifier
from aegisflight.proxy.transport import split_frames
from aegisflight.sources.stream import TelemetryTick

KEY_M = bytes(range(32))
KEY_F = bytes(range(100, 132))


class _FakeLink:
    connected = True

    def __init__(self, port: str | None = None) -> None:
        if port is not None:
            self.port = port
        self.inbox: list[tuple[int, bytes]] = []
        self.sent: list[bytes] = []

    def feed(self, *frames: bytes, stamp: int = 1_000_000_000) -> None:
        self.inbox.extend((stamp, f) for f in frames)

    def poll(self):
        out, self.inbox = self.inbox, []
        return out

    def send(self, data: bytes) -> bool:
        self.sent.append(bytes(data))
        return True

    def close(self) -> None:
        pass


def _cmd_long(sysid: int, command: int, p1: float = 0.0, comp: int = 190) -> bytes:
    m = mav2.MAVLink(None, srcSystem=sysid, srcComponent=comp)
    return bytes(m.command_long_encode(1, 1, command, 0, p1, 0, 0, 0, 0, 0, 0).pack(m))


def _hb(sysid: int = 1) -> bytes:
    m = mav2.MAVLink(None, srcSystem=sysid, srcComponent=1)
    return bytes(m.heartbeat_encode(2, 3, 0x80, 4, 4).pack(m))


def _gpi(sysid: int = 1) -> bytes:
    m = mav2.MAVLink(None, srcSystem=sysid, srcComponent=1)
    return bytes(m.global_position_int_encode(0, 129716000, 775946000, 920000, 30000, 0, 0, 0, 0).pack(m))


def test_passive_default_bridge_is_strict_zero_tx_and_byte_transparent(tmp_path: Path) -> None:
    """Default PASSIVE InlineIpsBridge transmits 0 bytes on both fc and gcs and never consumes compid 191."""
    fc, gcs = _FakeLink(), _FakeLink()
    bridge = InlineIpsBridge(
        fc,
        gcs,
        mode="passive",
        secret_key=KEY_F,
        mgmt_key=KEY_M,
        mgmt_state_path=str(tmp_path / "mgmt_state.json"),
        crossend_interval_s=1.0,
        mgmt_status_interval_s=1.0,
    )
    assert bridge.status()["mgmt_active"] is False

    # Feed vehicle telemetry, hostile uplink command, AND compid-191 management frame
    down = [_hb(1), _gpi(1)]
    mgmt_cmd = build_command_frame(KEY_M, OP_STATUS_NOW, signer=MavlinkSignatureVerifier(KEY_M))
    hostile = _cmd_long(66, 21)
    fc.feed(*down)
    gcs.feed(hostile, mgmt_cmd)
    bridge.pump_once()

    # Exact byte-for-byte forwarding on both links, 0 consumed, 0 dropped, 0 mgmt/crossend TX
    assert gcs.sent == down
    assert fc.sent == [hostile, mgmt_cmd]
    assert bridge.dropped_up == 0 and bridge.dropped_down == 0

    # Clear capture lists and drive an alert assessment via analyse_tick -> still 0 bytes TX!
    fc.sent.clear()
    gcs.sent.clear()
    bridge._last_gpi = down[1]
    snap = TelemetrySnapshot(t=10.0, lat=12.97, lon=77.59, alt_msl=920.0, rel_alt=30.0,
                             vx=0.0, vy=0.0, vz=0.0, groundspeed=0.0, roll=0.0, pitch=0.0, yaw=0.0,
                             heading=0.0, flight_mode="AUTO", armed=True, battery_remaining=90.0)
    frame = FeatureFrame(t=10.0, snapshot=snap, gps_seen=True, gps_raw_seen=True, heartbeat_seen=True)
    asmt = ThreatAssessment(
        t=10.0, wall_time=1000.0, threat=True, threat_score=0.9, severity=Severity.CRITICAL,
        attack_type=AttackType.COMMAND_INJECTION, confidence=0.95, secondary_indicators=[],
        evidence=["unauthorized mode change"], detector_scores={"PROTOCOL": 0.9},
        contributing_detectors=["PROTOCOL"], integrity_status=IntegrityStatus.VALID,
        is_alert=True,
    )
    bridge.pipeline.process_tick = lambda _tick: asmt
    bridge.pipeline.last_frame = frame
    bridge.analyse_tick(TelemetryTick(t=10.0, tick=10, messages=[]))

    assert fc.sent == []
    assert gcs.sent == []
    assert bridge.crossend_sent == 0
    assert bridge.counter_frames_sent == 0
    assert bridge.mgmt.bytes_sent == 0


def test_advisory_sends_gcs_statustext_only_with_zero_fc_writes_or_drops() -> None:
    """ADVISORY sends GCS STATUSTEXT/mgmt only; zero drops or writes reach the FC link."""
    fc, gcs = _FakeLink(), _FakeLink()
    bridge = InlineIpsBridge(fc, gcs, mode="advisory", secret_key=KEY_F, mgmt_status_interval_s=0.0)
    assert bridge.status()["mgmt_active"] is True

    hostile = _cmd_long(66, 176, 1, 9)
    gcs.feed(hostile)
    bridge.pump_once()
    assert fc.sent == [hostile]
    assert bridge.dropped_up == 0
    fc.sent.clear()

    snap = TelemetrySnapshot(t=12.0, lat=12.97, lon=77.59, alt_msl=920.0, rel_alt=30.0,
                             vx=0.0, vy=0.0, vz=0.0, groundspeed=0.0, roll=0.0, pitch=0.0, yaw=0.0,
                             heading=0.0, flight_mode="AUTO", armed=True, battery_remaining=90.0)
    frame = FeatureFrame(t=12.0, snapshot=snap, gps_seen=True, gps_raw_seen=True, heartbeat_seen=True)
    asmt = ThreatAssessment(
        t=12.0, wall_time=1002.0, threat=True, threat_score=0.9, severity=Severity.CRITICAL,
        attack_type=AttackType.COMMAND_INJECTION, confidence=0.95, secondary_indicators=[],
        evidence=["unauthorized mode change"], detector_scores={"PROTOCOL": 0.9},
        contributing_detectors=["PROTOCOL"], integrity_status=IntegrityStatus.VALID,
        is_alert=True,
    )
    bridge.pipeline.process_tick = lambda _tick: asmt
    bridge.pipeline.last_frame = frame
    bridge.analyse_tick(TelemetryTick(t=12.0, tick=12, messages=[]))

    # Zero writes to FC, only STATUSTEXT / crossend to GCS (exactly 1 STATUSTEXT per alert, no duplicate)
    assert fc.sent == []
    gcs_msgs = [fr.msgid for raw in gcs.sent for fr in split_frames(raw)[0]]
    assert gcs_msgs.count(253) == 1  # exactly one STATUSTEXT sent to GCS per alert
    assert 76 not in gcs_msgs  # no COMMAND_LONG sent to GCS


def test_passive_opt_in_mgmt_enable_allows_mgmt_while_fc_stays_untouched(tmp_path: Path) -> None:
    fc, gcs = _FakeLink(), _FakeLink()
    bridge = InlineIpsBridge(
        fc,
        gcs,
        mode="passive",
        mgmt_key=KEY_M,
        mgmt_state_path=str(tmp_path / "mgmt_state.json"),
        mgmt_enable=True,
        mgmt_status_interval_s=0.0,
    )
    assert bridge.status()["mgmt_active"] is True
    mgmt_cmd = build_command_frame(KEY_M, OP_STATUS_NOW, signer=MavlinkSignatureVerifier(KEY_M))
    gcs.feed(mgmt_cmd)
    bridge.pump_once()
    assert fc.sent == []  # consumed cleanly when opted in
    assert [fr.msgid for raw in gcs.sent for fr in split_frames(raw)[0]] == [77, 249]  # COMMAND_ACK + MEMORY_VECT status to GCS


def test_live_engine_gcs_notifier_suppressed_in_passive(tmp_path: Path) -> None:
    """Even when --gcs-notify is set, LiveEngine sends 0 GCS notifications while in PASSIVE posture."""
    spec = SourceSpec(kind="sim", gcs_notify=True, gcs_notify_host="127.0.0.1", gcs_notify_port=14559,
                      defense_mode="passive")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        eng = LiveEngine(db_path=str(tmp_path / "eng.sqlite"), model_path="", spec=spec)
    try:
        assert eng.gcs_notifier is not None
        assert eng.gcs_notifier.enabled is False
        sent: list[bytes] = []
        eng.gcs_notifier.transport = type("T", (), {"send": lambda _self, d: sent.append(d) or True})()
        asmt = ThreatAssessment(
            t=5.0, wall_time=1005.0, threat=True, threat_score=0.95, severity=Severity.CRITICAL,
            attack_type=AttackType.GPS_SPOOFING, confidence=0.9, secondary_indicators=[],
            evidence=["spoof"], detector_scores={"PHYSICS": 0.95},
            contributing_detectors=["PHYSICS"], integrity_status=IntegrityStatus.VALID,
            is_alert=True,
        )
        assert eng.gcs_notifier.notify(asmt) is False
        assert sent == []

        # Switching to advisory enables GcsNotifier immediately; switching back to passive disables it
        eng.set_defense_mode("advisory")
        assert eng.gcs_notifier.enabled is True
        assert eng.gcs_notifier.notify(asmt) is True
        assert len(sent) == 1

        eng.set_defense_mode("passive")
        assert eng.gcs_notifier.enabled is False
        assert eng.gcs_notifier.notify(asmt) is False
        assert len(sent) == 1
    finally:
        eng.store.close()
        eng.gcs_notifier.close()
