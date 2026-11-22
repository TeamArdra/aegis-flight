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


def _frame(t: float, mode: str, armed: bool | None) -> FeatureFrame:
    snap = TelemetrySnapshot(t=t, lat=18.92, lon=72.83, alt_msl=25.0, rel_alt=25.0, vx=0.0, vy=5.0, vz=0.0,
                             groundspeed=5.0, roll=0.0, pitch=0.0, yaw=0.0, heading=90.0, flight_mode=mode,
                             armed=armed, battery_remaining=90.0)
    return FeatureFrame(t=t, snapshot=snap, gps_seen=True, gps_raw_seen=True, heartbeat_seen=True,
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

    def __init__(self, sub: AttackSubMode) -> None:
        self.c = MitigationController(mode=DefenseMode.ACTIVE_IPS)
        self.set_modes: list[str] = []
        a = self.c.actuator
        real_encode = a.encode_set_mode

        def record(mode, *args, **kwargs):
            self.set_modes.append(str(mode).upper())
            return real_encode(mode, *args, **kwargs)

        a.encode_set_mode = record
        self.c.classifier.classify = lambda f, s: sub
        self.t = 100.0

    def run(self, secs: float, attack: AttackType, mode: str, armed: bool | None) -> None:
        for _ in range(int(round(secs / 0.2))):
            self.c.step(_frame(self.t, mode, armed), _asmt(self.t, attack))
            self.t = round(self.t + 0.2, 6)


# PX4 flight-mode names as decoded by sources.mavlink_live.decode_px4_mode.
PX4_MODES = ["POSCTL", "ALTCTL", "AUTO/MISSION", "AUTO/LOITER", "OFFBOARD", "STABILIZED", "MANUAL"]


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


def test_copter_safe_hold_still_engages_alt_hold_when_armed():
    """The ArduCopter behaviour the SAFE_HOLD escalation was built for is preserved."""
    r = Rig(AttackSubMode.CMD_MODE_FLIP)
    r.run(5, AttackType.BENIGN, "LOITER", True)
    r.run(40, AttackType.COMMAND_INJECTION, "RTL", True)
    assert "ALT_HOLD" in r.set_modes
