"""Regression tests for real-flight IPS safety interlocks (#60)."""

from __future__ import annotations

from aegisflight.core.enums import AttackType, IntegrityStatus, Severity
from aegisflight.core.types import TelemetrySnapshot, ThreatAssessment
from aegisflight.features.extractor import CommandEvent, FeatureFrame
from aegisflight.mitigation.controller import MitigationController
from aegisflight.mitigation.types import DefenseMode, MitigationState


def _snap(t: float, *, armed: bool | None = True, mode: str = "AUTO") -> TelemetrySnapshot:
    return TelemetrySnapshot(
        t=t,
        lat=18.92,
        lon=72.83,
        alt_msl=25.0,
        rel_alt=25.0,
        vx=0.0,
        vy=5.0,
        vz=0.0,
        groundspeed=5.0,
        roll=0.0,
        pitch=0.0,
        yaw=0.0,
        heading=90.0,
        flight_mode=mode,
        armed=armed,
        battery_remaining=90.0,
    )


def _gps_frame(t: float, *, armed: bool | None = True, mode: str = "AUTO") -> FeatureFrame:
    return FeatureFrame(
        t=t,
        snapshot=_snap(t, armed=armed, mode=mode),
        gps_seen=True,
        gps_raw_seen=True,
        heartbeat_seen=True,
        msg_rate_hz=10.0,
        pos_residual_m=40.0,
    )


def _cmd_frame(t: float, *, armed: bool | None = True, mode: str = "LAND") -> FeatureFrame:
    return FeatureFrame(
        t=t,
        snapshot=_snap(t, armed=armed, mode=mode),
        gps_seen=True,
        gps_raw_seen=True,
        heartbeat_seen=True,
        msg_rate_hz=10.0,
        commands_recent=[CommandEvent(recv_time=t, sysid=66, compid=190, command=176)],
    )


def _asmt(t: float, attack: AttackType) -> ThreatAssessment:
    return ThreatAssessment(
        t=t,
        wall_time=t,
        threat=attack != AttackType.BENIGN,
        threat_score=0.95 if attack != AttackType.BENIGN else 0.0,
        severity=Severity.CRITICAL if attack != AttackType.BENIGN else Severity.NORMAL,
        attack_type=attack,
        confidence=0.95 if attack != AttackType.BENIGN else 0.0,
        evidence=["synthetic attack"] if attack != AttackType.BENIGN else [],
        detector_scores={"PHYSICS": 0.95} if attack != AttackType.BENIGN else {},
        contributing_detectors=["PHYSICS"] if attack != AttackType.BENIGN else [],
        integrity_status=IntegrityStatus.VALID,
        latency_ms=0.5,
        is_alert=attack != AttackType.BENIGN,
    )


def test_disarmed_sustained_gps_soak_emits_zero_set_mode_counter_commands() -> None:
    """Reproduce the >30 s bench soak while disarmed: 0 SET_MODE counter-commands permitted."""
    ctrl = MitigationController(mode=DefenseMode.ACTIVE_IPS)
    ctrl.golden.update(_snap(0.0, armed=False, mode="AUTO"), _asmt(0.0, AttackType.BENIGN), active_ips=True)

    emitted: list[bytes] = []
    for k in range(1, 220):  # 44 s at 5 Hz -> crosses >30 s SAFE_HOLD threshold
        t = k * 0.2
        act = ctrl.step(_gps_frame(t, armed=False, mode="AUTO"), _asmt(t, AttackType.GPS_SPOOFING))
        emitted.extend(act.counter_frames)

    assert ctrl.state == MitigationState.SAFE_HOLD
    assert ctrl._episode_counter_cmds == 0
    # At most the single GPS STATUSTEXT warning may appear; zero DO_SET_MODE frames
    assert all(b"ALT_HOLD" not in f for f in emitted)
    assert "SET_MODE_ALT_HOLD" not in ctrl._last_cmd_t


def test_disarmed_command_injection_emits_zero_restore_commands() -> None:
    ctrl = MitigationController(mode=DefenseMode.ACTIVE_IPS)
    ctrl.golden.update(_snap(0.0, armed=False, mode="AUTO"), _asmt(0.0, AttackType.BENIGN), active_ips=True)
    for k in range(1, 180):
        t = k * 0.2
        act = ctrl.step(_cmd_frame(t, armed=False, mode="LAND"), _asmt(t, AttackType.COMMAND_INJECTION))
        assert act.counter_frames == []


def test_armed_safe_hold_is_one_shot_not_1hz_hammering() -> None:
    """Once armed SAFE_HOLD fires ALT_HOLD, it must not re-send every 1.0 s during a long episode."""
    ctrl = MitigationController(mode=DefenseMode.ACTIVE_IPS)
    ctrl.golden.update(_snap(0.0, armed=True, mode="AUTO"), _asmt(0.0, AttackType.BENIGN), active_ips=True)

    set_mode_count = 0
    for k in range(1, 260):  # 52 s at 5 Hz -> well past SAFE_HOLD (>30 s)
        t = k * 0.2
        act = ctrl.step(_gps_frame(t, armed=True, mode="AUTO"), _asmt(t, AttackType.GPS_SPOOFING))
        for frame in act.counter_frames:
            if len(frame) > 9 and frame[7:9] == b"\x4c\x00":  # MAVLINK v2 msgid 76 (COMMAND_LONG)
                set_mode_count += 1

    assert ctrl.state == MitigationState.SAFE_HOLD
    assert set_mode_count == 1  # one-shot per episode, never 20+ frames at 1 Hz


def test_per_episode_and_per_minute_counter_command_budget() -> None:
    """Counter-commands stop once the episode or 60 s rate budget is exhausted."""
    ctrl = MitigationController(
        mode=DefenseMode.ACTIVE_IPS,
        command_cooldown_s=0.1,
        max_counter_cmds_per_episode=2,
        max_counter_cmds_per_min=3,
    )
    ctrl.golden.update(_snap(0.0, armed=True, mode="AUTO"), _asmt(0.0, AttackType.BENIGN), active_ips=True)

    sent = []
    for k in range(1, 12):
        t = float(k)
        act = ctrl.step(_cmd_frame(t, armed=True, mode="LAND"), _asmt(t, AttackType.COMMAND_INJECTION))
        sent.extend(act.counter_frames)
    assert len(sent) == 2

    # Recover cleanly -> resets _episode_counter_cmds to 0
    for r in range(ctrl.recovery_clean_ticks):
        t_rec = 20.0 + r * 0.2
        ctrl.step(_cmd_frame(t_rec, armed=True, mode="AUTO"), _asmt(t_rec, AttackType.BENIGN))
    assert ctrl._episode_counter_cmds == 0

    # Trigger 1 more command in a new episode at t=26.0 -> consumes 3rd slot of per-minute cap (limit=3)
    act3 = ctrl.step(_cmd_frame(26.0, armed=True, mode="LAND"), _asmt(26.0, AttackType.COMMAND_INJECTION))
    assert len(act3.counter_frames) == 1
    assert len(ctrl._cmd_budget_window_t) == 3
    # Episode cap (2) is not reached (_episode_counter_cmds == 1), yet max_counter_cmds_per_min=3 blocks another!
    assert ctrl._episode_counter_cmds == 1
    assert ctrl._can_send_command("RESTORE_AUTO", 26.5) is False

