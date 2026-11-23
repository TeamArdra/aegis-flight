"""SAFE_HOLD escalation must never send an ArduCopter-numbered DO_SET_MODE to a vehicle that is not
flying an ArduCopter mode (e.g. PX4), nor to a disarmed / armed-unknown vehicle. SYNTHETIC frames;
nothing opens a port. Regression for the >30 s SAFE_HOLD path in mitigation/controller.py."""

from __future__ import annotations

import pytest

from aegisflight.core.enums import AttackType, IntegrityStatus, Severity
from aegisflight.core.types import TelemetrySnapshot, ThreatAssessment
from aegisflight.features.extractor import FeatureFrame
from aegisflight.mitigation.controller import MitigationController
from aegisflight.mitigation.types import AttackSubMode, DefenseMode


def _frame(t: float, mode: str, armed: bool | None, dialect: tuple[int | None, int | None] = (3, 2)) -> FeatureFrame:
    snap = TelemetrySnapshot(t=t, lat=18.92, lon=72.83, alt_msl=25.0, rel_alt=25.0, vx=0.0, vy=5.0, vz=0.0,
                             groundspeed=5.0, roll=0.0, pitch=0.0, yaw=0.0, heading=90.0, flight_mode=mode,
                             armed=armed, battery_remaining=90.0)
    # The frame carries an observed ArduCopter dialect (autopilot 3, MAV_TYPE_QUADROTOR 2): since D4b the actuator
    # fails closed on DO_SET_MODE until a vehicle heartbeat has bound the dialect. PX4-named modes stay refused.
    return FeatureFrame(autopilot_id=dialect[0], mav_type=dialect[1], t=t, snapshot=snap, gps_seen=True, gps_raw_seen=True, heartbeat_seen=True,
                        msg_rate_hz=10.0, pos_residual_m=0.0, commands_recent=[])


def _asmt(t: float, attack: AttackType) -> ThreatAssessment:
    threat = attack != AttackType.BENIGN
    return ThreatAssessment(t=t, wall_time=t, threat=threat, threat_score=0.9 if threat else 0.0,
                            severity=Severity.CRITICAL if threat else Severity.NORMAL, attack_type=attack,
                            confidence=0.9 if threat else 0.0, evidence=[], detector_scores={},
                            contributing_detectors=[], integrity_status=IntegrityStatus.VALID,
                            latency_ms=1.0, is_alert=threat)


class Rig:
    """Real controller and classifier routing; only the actuator's encoders are recorded."""

    def __init__(self, sub: AttackSubMode, **ctrl_kwargs) -> None:
        self.c = MitigationController(mode=DefenseMode.ACTIVE_IPS, **ctrl_kwargs)
        self.set_modes: list[str] = []
        a = self.c.actuator
        real_encode = a.encode_set_mode

        def record(mode, *args, **kwargs):
            self.set_modes.append(str(mode).upper())
            return real_encode(mode, *args, **kwargs)

        a.encode_set_mode = record
        self.c.classifier.classify = lambda f, s: sub
        self.t = 100.0

    def run(self, secs: float, attack: AttackType, mode: str, armed: bool | None,
            dialect: tuple[int | None, int | None] = (3, 2)) -> None:
        for _ in range(int(round(secs / 0.2))):
            self.c.step(_frame(self.t, mode, armed, dialect), _asmt(self.t, attack))
            self.t = round(self.t + 0.2, 6)


# PX4 flight-mode names as decoded by sources.mavlink_live.decode_px4_mode, plus names that are not
# ArduCopter modes at all: unknown/blank/padded strings must also never unlock the ArduCopter command.
PX4_MODES = ["POSCTL", "ALTCTL", "AUTO/MISSION", "AUTO/LOITER", "OFFBOARD", "STABILIZED", "MANUAL",
             "ACRO", "RATTITUDE", "MAIN_9", "UNKNOWN", "", " RTL", "RTL "]


@pytest.mark.parametrize("attack_mode", PX4_MODES)
def test_px4_command_injection_safe_hold_sends_no_set_mode(attack_mode):
    r = Rig(AttackSubMode.CMD_MODE_FLIP)
    r.run(5, AttackType.BENIGN, "POSCTL" if attack_mode != "POSCTL" else "ALTCTL", True)  # learn trusted mode
    r.run(40, AttackType.COMMAND_INJECTION, attack_mode, True)  # > 30 s sustained, mode differs
    assert "ALT_HOLD" not in r.set_modes, f"ArduCopter ALT_HOLD sent to a PX4 vehicle in {attack_mode}"


@pytest.mark.parametrize("mode", PX4_MODES)
def test_px4_gps_episode_safe_hold_sends_no_set_mode(mode):
    r = Rig(AttackSubMode.DOS_GNSS_JAMMING)
    r.run(5, AttackType.BENIGN, mode, True)
    r.run(40, AttackType.GPS_SPOOFING, mode, True)
    assert r.set_modes == [], f"DO_SET_MODE sent to a PX4 vehicle in {mode}: {r.set_modes}"


@pytest.mark.parametrize("armed", [False, None])
def test_copter_safe_hold_needs_a_known_armed_vehicle(armed):
    r = Rig(AttackSubMode.CMD_MODE_FLIP)
    r.run(5, AttackType.BENIGN, "LOITER", armed)
    r.run(40, AttackType.COMMAND_INJECTION, "RTL", armed)
    assert "ALT_HOLD" not in r.set_modes


@pytest.mark.parametrize("attack_mode", ["RTL", "rtl"])
def test_copter_safe_hold_still_engages_alt_hold_when_armed(attack_mode):
    """The ArduCopter behaviour the SAFE_HOLD escalation was built for is preserved (the actuator
    matches mode names case-insensitively, so a lower-case report behaves the same)."""
    # The per-episode counter-command budget (#60) is lifted here so this test isolates the
    # dialect/armed gate; the budget's own effect is pinned by the next test.
    r = Rig(AttackSubMode.CMD_MODE_FLIP, max_counter_cmds_per_episode=100, max_counter_cmds_per_min=100)
    r.run(5, AttackType.BENIGN, "LOITER", True)
    r.run(40, AttackType.COMMAND_INJECTION, attack_mode, True)
    assert "ALT_HOLD" in r.set_modes


def test_copter_safe_hold_alt_hold_respects_the_counter_command_budget():
    """With the default per-episode budget (#60), the restore commands that precede the >30 s
    escalation use it up, so SAFE_HOLD's ALT_HOLD is refused rather than sent: the bound wins."""
    r = Rig(AttackSubMode.CMD_MODE_FLIP)
    budget = r.c.max_counter_cmds_per_episode
    r.run(5, AttackType.BENIGN, "LOITER", True)
    r.run(40, AttackType.COMMAND_INJECTION, "RTL", True)
    assert len(r.set_modes) <= budget
    assert "ALT_HOLD" not in r.set_modes


# D4: the dialect comes from the vehicle HEARTBEAT, not from the mode name. A PX4 heartbeat (autopilot 12)
# or no bound dialect at all must refuse DO_SET_MODE even when the reported mode names look like ArduCopter's.
@pytest.mark.parametrize("dialect", [(12, 2), (None, None)], ids=["px4_heartbeat", "no_heartbeat"])
@pytest.mark.parametrize("sub,attack", [(AttackSubMode.CMD_MODE_FLIP, AttackType.COMMAND_INJECTION),
                                        (AttackSubMode.DOS_GNSS_JAMMING, AttackType.GPS_SPOOFING)])
def test_non_copter_dialect_sends_no_set_mode_even_with_copter_mode_names(dialect, sub, attack):
    r = Rig(sub, max_counter_cmds_per_episode=100, max_counter_cmds_per_min=100)
    r.run(5, AttackType.BENIGN, "LOITER", True, dialect)
    r.run(40, attack, "RTL", True, dialect)
    assert r.set_modes == [], f"DO_SET_MODE sent with dialect {dialect}: {r.set_modes}"
