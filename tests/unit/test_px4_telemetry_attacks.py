"""Regression tests for PX4 telemetry attacks (frozen_attitude, speed_mismatch, firmware_identity)."""

from __future__ import annotations

from aegisflight.config import load_config
from aegisflight.core.enums import AttackType
from aegisflight.core.types import TelemetrySnapshot
from aegisflight.detectors.integrity import IntegrityDetector
from aegisflight.detectors.physics import PhysicsDetector
from aegisflight.features.extractor import FeatureFrame
from aegisflight.integrity.allowlist import FirmwareAllowlist, FirmwareEntry


def _make_frame(**overrides: object) -> FeatureFrame:
    snap = TelemetrySnapshot(t=10.0, armed=True)
    defaults: dict[str, object] = {
        "t": 10.0,
        "snapshot": snap,
        "gps_seen": True,
        "gps_vfr_speed_diff_ms": 0.0,
        "att_repeat": 0,
    }
    defaults.update(overrides)
    return FeatureFrame(**defaults)  # type: ignore[arg-type]


def test_px4_sitl_config_enables_xmsg_checks_for_frozen_attitude() -> None:
    cfg = load_config("configs/px4_sitl")
    det = PhysicsDetector(cfg.detector["physics"])
    assert det.xmsg_checks is True

    # Benign: att_repeat < 8 should not trigger
    benign_res = det.process(_make_frame(att_repeat=2))
    assert benign_res.score == 0.0

    # Attack: att_repeat >= 8 triggers TELEMETRY_MANIPULATION
    attack_res = det.process(_make_frame(att_repeat=8))
    assert AttackType.TELEMETRY_MANIPULATION in attack_res.attack_votes
    assert attack_res.score > 0.0


def test_px4_speed_mismatch_triggers_when_gps_seen() -> None:
    cfg = load_config("configs/px4_sitl")
    det = PhysicsDetector(cfg.detector["physics"])

    # Benign: small diff
    benign_res = det.process(_make_frame(gps_vfr_speed_diff_ms=1.5, gps_seen=True))
    assert benign_res.score == 0.0

    # Missing GPS stream: gated out (coverage, not attack)
    no_gps_res = det.process(_make_frame(gps_vfr_speed_diff_ms=12.0, gps_seen=False))
    assert no_gps_res.score == 0.0

    # Attack: speed mismatch > 5.0 m/s with GPS present
    attack_res = det.process(_make_frame(gps_vfr_speed_diff_ms=8.0, gps_seen=True))
    assert AttackType.TELEMETRY_MANIPULATION in attack_res.attack_votes
    assert attack_res.score > 0.0


def test_px4_firmware_identity_mismatch_triggers_integrity() -> None:
    allowlist = FirmwareAllowlist(
        entries=(
            FirmwareEntry(
                name="px4-good",
                sysid=3,
                compid=1,
                flight_sw_version=0x010E0000,
                flight_custom_version=b"px4-good",
            ),
        )
    )
    det = IntegrityDetector(allowlist=allowlist)
    det.observe_message(
        "AUTOPILOT_VERSION",
        {
            "flight_sw_version": 0xDEADBEEF,
            "flight_custom_version": list(b"rogue-fw"),
        },
        sysid=3,
        compid=1,
    )
    res = det.process(_make_frame())
    assert res.triggered is True
    assert res.score > 0.0
