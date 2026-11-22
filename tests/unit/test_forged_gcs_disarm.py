"""Regression tests for in-flight / force-disarm detection in ProtocolDetector."""

from aegisflight.core.types import AttackType, TelemetrySnapshot
from aegisflight.detectors.protocol import ProtocolDetector
from aegisflight.features.extractor import CommandEvent, FeatureFrame


def _make_frame(
    *,
    armed: bool,
    groundspeed: float,
    rel_alt: float,
    params: tuple[float, ...],
    sysid: int = 255,
    compid: int = 190,
    t: float = 10.0,
) -> FeatureFrame:
    snap = TelemetrySnapshot(
        t=t,
        armed=armed,
        groundspeed=groundspeed,
        rel_alt=rel_alt,
    )
    cmd = CommandEvent(
        recv_time=t,
        sysid=sysid,
        compid=compid,
        command=400,  # MAV_CMD_COMPONENT_ARM_DISARM
        params=params,
    )
    return FeatureFrame(
        t=t,
        snapshot=snap,
        commands_recent=(cmd,),
    )


def test_hovering_force_disarm_from_expected_gcs_triggers_alert() -> None:
    detector = ProtocolDetector({})
    frame = _make_frame(
        armed=True,
        groundspeed=0.0,
        rel_alt=10.0,
        params=(0.0, 21196.0, 0.0, 0.0, 0.0, 0.0, 0.0),
        sysid=255,
        compid=190,
    )
    res = detector.process(frame)
    assert res.attack_votes.get(AttackType.COMMAND_INJECTION, 0.0) >= 0.90
    assert res.score >= 0.90
    assert any("force-disarm" in e for e in res.evidence)


def test_armed_force_disarm_at_zero_alt_triggers_alert() -> None:
    detector = ProtocolDetector({})
    frame = _make_frame(
        armed=True,
        groundspeed=0.0,
        rel_alt=0.0,
        params=(0.0, 21196.0),
        sysid=255,
        compid=190,
    )
    res = detector.process(frame)
    assert res.attack_votes.get(AttackType.COMMAND_INJECTION, 0.0) >= 0.90
    assert res.score >= 0.90


def test_hovering_normal_disarm_triggers_alert() -> None:
    detector = ProtocolDetector({})
    frame = _make_frame(
        armed=True,
        groundspeed=0.0,
        rel_alt=5.0,
        params=(0.0, 0.0),
        sysid=255,
        compid=190,
    )
    res = detector.process(frame)
    assert res.attack_votes.get(AttackType.COMMAND_INJECTION, 0.0) >= 0.90
    assert res.score >= 0.90


def test_ground_normal_disarm_does_not_trigger_alert() -> None:
    detector = ProtocolDetector({})
    frame = _make_frame(
        armed=True,
        groundspeed=0.0,
        rel_alt=0.0,
        params=(0.0, 0.0),
        sysid=255,
        compid=190,
    )
    res = detector.process(frame)
    assert AttackType.COMMAND_INJECTION not in res.attack_votes
