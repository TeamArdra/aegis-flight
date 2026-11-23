"""A genuine GCS emergency stop (force-disarm, param2=21196, sysid 255) alerts but never actuates.

Traces the real chain ``ProtocolDetector -> FusionEngine -> MitigationController(ACTIVE_IPS)`` and the
inline uplink rule. The alert is expected (maintainer decision pending, see ``docs/DETECTION.md``);
the IPS must neither quarantine the GCS, nor emit any counter-frame, nor drop the command.
"""

from __future__ import annotations

from aegisflight.config import load_config
from aegisflight.core.enums import AttackType, DetectorName, IntegrityStatus
from aegisflight.core.types import DetectorResult, TelemetrySnapshot
from aegisflight.detectors.protocol import ProtocolDetector
from aegisflight.features.extractor import CommandEvent, FeatureFrame
from aegisflight.fusion.engine import FusionEngine
from aegisflight.mitigation.controller import MitigationController
from aegisflight.mitigation.inline_policy import FORCE_MAGIC, InlinePolicy
from aegisflight.mitigation.sanitizer import FrameSanitizer
from aegisflight.mitigation.types import DefenseMode

_FORCE = (0.0, 21196.0, 0.0, 0.0, 0.0, 0.0, 0.0)


def _frame(t: float, *, armed: bool | None, mode: str, with_cmd: bool, cmd_t: float = 10.0) -> FeatureFrame:
    snap = TelemetrySnapshot(
        t=t, lat=18.92, lon=72.83, alt_msl=60.0, rel_alt=35.0, vx=0.0, vy=5.0, groundspeed=5.0,
        heading=90.0, flight_mode=mode, armed=armed, battery_remaining=90.0,
    )
    cmds = (CommandEvent(recv_time=cmd_t, sysid=255, compid=190, command=400, params=_FORCE),) if with_cmd else ()
    # D4 (#91, now in #81) fails closed on DO_SET_MODE until a vehicle HEARTBEAT binds the dialect, so the frames
    # carry an observed ArduCopter quad (autopilot 3, MAV_TYPE 2), as in test_safe_hold_dialect_guard.py.
    return FeatureFrame(autopilot_id=3, mav_type=2,
        t=t, snapshot=snap, gps_seen=True, gps_raw_seen=True, heartbeat_seen=True, msg_rate_hz=28.0,
        sources=((1, 1), (255, 190)), n_sources=2, commands_recent=cmds,
    )


def _chain(modes_before: str, mode_at_stop: str, *, armed_at_stop: bool | None = True, lead_ticks: int = 0):
    cfg = load_config().detector
    det = ProtocolDetector(cfg["protocol"])
    fusion = FusionEngine(cfg["fusion"])
    ctrl = MitigationController(mode=DefenseMode.ACTIVE_IPS)
    counters: list[bytes] = []

    def run(frame: FeatureFrame):
        r = det.process(frame)
        empty = [DetectorResult(d, 0.0, False) for d in (DetectorName.PHYSICS, DetectorName.ANOMALY, DetectorName.INTEGRITY)]
        asmt = fusion.fuse(frame.t, frame.t, [r, *empty], IntegrityStatus.VALID)
        act = ctrl.step(frame, asmt)
        counters.extend(act.counter_frames)
        return asmt, act

    for k in range(25):  # benign flight in the trusted mode
        run(_frame(k * 0.2, armed=True, mode=modes_before, with_cmd=False))
    for k in range(lead_ticks):  # clean ticks in the (new) mode before the stop
        run(_frame(5.0 + k * 0.2, armed=True, mode=mode_at_stop, with_cmd=False))
    asmt, act = run(_frame(10.0, armed=armed_at_stop, mode=mode_at_stop, with_cmd=True))
    return asmt, act, counters, ctrl


def test_emergency_stop_alerts_but_emits_no_counter_frame_and_no_quarantine() -> None:
    asmt, act, counters, ctrl = _chain("LOITER", "LOITER")
    assert asmt.threat and asmt.attack_type is AttackType.COMMAND_INJECTION  # alert is the pinned policy
    assert counters == []
    assert act.counter_frames == []
    assert 255 not in ctrl._quarantined_sysids
    assert not act.quarantined_sysids


def test_emergency_stop_after_a_mode_change_emits_no_counter_frame() -> None:
    """The trusted mode follows the pilot's mode change on the next clean tick: no SET_MODE counter."""
    asmt, act, counters, _ = _chain("AUTO", "LAND", lead_ticks=1)
    assert asmt.threat
    assert counters == [], "force-disarm alert produced IPS counter-frame(s)"


def test_emergency_stop_in_the_same_tick_as_a_mode_change_emits_no_counter_frame() -> None:
    """D12 (maintainer decision): the alert is retained, but no restore/counter-command is sent."""
    asmt, act, counters, ctrl = _chain("AUTO", "LAND", lead_ticks=0)
    assert asmt.threat and asmt.attack_type is AttackType.COMMAND_INJECTION
    assert counters == []
    assert act.counter_frames == []
    assert not any(a["tag"] in ("RESTORE_MODE", "SAFE_HOLD_CMD") for a in ctrl.action_history)


def test_forged_non_force_disarm_command_still_triggers_restore_mode() -> None:
    """The playbook is not disabled: a rogue (non-GCS) command with a mode change still restores the mode."""
    cfg = load_config().detector
    det = ProtocolDetector(cfg["protocol"])
    fusion = FusionEngine(cfg["fusion"])
    ctrl = MitigationController(mode=DefenseMode.ACTIVE_IPS)
    counters: list[bytes] = []

    def run(frame: FeatureFrame):
        r = det.process(frame)
        empty = [DetectorResult(d, 0.0, False) for d in (DetectorName.PHYSICS, DetectorName.ANOMALY, DetectorName.INTEGRITY)]
        asmt = fusion.fuse(frame.t, frame.t, [r, *empty], IntegrityStatus.VALID)
        act = ctrl.step(frame, asmt)
        counters.extend(act.counter_frames)
        return asmt, act

    for k in range(25):
        run(_frame(k * 0.2, armed=True, mode="AUTO", with_cmd=False))
    # rogue sysid 66 sends a plain (non-force) mid-air disarm and the mode flips in the same tick
    frame = _frame(10.0, armed=True, mode="LAND", with_cmd=False)
    frame.commands_recent = (CommandEvent(recv_time=10.0, sysid=66, compid=190, command=400, params=(0.0,) * 7),)
    frame.sources = ((1, 1), (66, 190))
    frame.n_sources = 2
    asmt, act = run(frame)
    assert asmt.threat and asmt.attack_type is AttackType.COMMAND_INJECTION
    assert any(a["tag"] == "RESTORE_MODE" for a in ctrl.action_history)
    assert len(counters) == 1


def test_inline_policy_forwards_trusted_gcs_force_disarm_in_flight() -> None:
    pol = InlinePolicy(FrameSanitizer(), trusted_sysids=(255, 254), vehicle_sysids=(1,))
    pol.armed, pol.rel_alt_m, pol.groundspeed_ms = True, 35.0, 5.0
    assert pol.in_flight
    sent = pol._command_rule(_ctx(), True, 400, 0.0, FORCE_MAGIC)
    assert sent == [b"RAW"]
    assert pol.dropped_inflight_disarm == 0


class _Ctx:
    sysid, compid, raw, signed = 255, 190, b"RAW", False


def _ctx() -> _Ctx:
    return _Ctx()
