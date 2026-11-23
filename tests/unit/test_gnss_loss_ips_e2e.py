"""End-to-end behaviour of a GNSS fix-loss threat through the REAL submode classifier and the REAL
MitigationController at the PX4 message rate (~370 msg/s), under ``DefenseMode.ACTIVE_IPS``.

PR #112 (`submode_classifier`: named GNSS evidence wins over the rate test) is accepted for the
CLASSIFICATION only (maintainer decision D10): the sub-mode label and the alert are DOS_GNSS_JAMMING on
a high-rate link, but nothing about what the IPS sends changes. origin/main classed that case DOS_FLOOD,
never ran the GPS response ladder for it, and these tests pin that the DO_SET_MODE emissions stay what
main sent: no new ALT_HOLD on any vehicle. Nothing is mocked except the input frames: the classifier, the controller and the
actuator (real MAVLink-2 encoding) are the shipped code. All inputs are SYNTHETIC; nothing opens a
port. Environment tag: SIM-style unit test, not SITL evidence.
"""

from __future__ import annotations

import struct

import pytest

from aegisflight.core.enums import AttackType, IntegrityStatus, Severity
from aegisflight.core.types import TelemetrySnapshot, ThreatAssessment
from aegisflight.features.extractor import FeatureFrame
from aegisflight.mitigation.controller import MitigationController
from aegisflight.mitigation.types import AttackSubMode, DefenseMode, MitigationState

MSGID_COMMAND_LONG = 76
MSGID_STATUSTEXT = 253
CMD_DO_SET_MODE = 176
COPTER_ALT_HOLD = 2  # ArduCopter custom mode number; PX4 uses a different encoding

GNSS_EVIDENCE = ["GNSS fix lost: fix_type=0, satellites=2 for 5 decisions"]
DT = 0.2  # decision_rate_hz = 5


def _msgid(frame: bytes) -> int:
    return frame[7] | (frame[8] << 8) | (frame[9] << 16)


def _set_mode_custom(frame: bytes) -> int | None:
    """custom mode number if ``frame`` is a COMMAND_LONG DO_SET_MODE, else None."""
    if _msgid(frame) != MSGID_COMMAND_LONG:
        return None
    payload = frame[10:10 + frame[1]] + bytes(33)
    if struct.unpack_from("<H", payload, 28)[0] != CMD_DO_SET_MODE:
        return None
    return int(struct.unpack_from("<7f", payload, 0)[1])


def _frame(t: float, *, mode: str | None, armed: bool | None = True, rate: float = 370.0,
           fix: int | None = 0, sats: int | None = 2) -> FeatureFrame:
    snap = TelemetrySnapshot(t=t, lat=18.92, lon=72.83, alt_msl=25.0, rel_alt=25.0, vx=0.0, vy=5.0, vz=0.0,
                             groundspeed=5.0, roll=0.0, pitch=0.0, yaw=0.0, heading=90.0, flight_mode=mode,
                             armed=armed, battery_remaining=90.0, gps_fix_type=fix, satellites=sats)
    return FeatureFrame(t=t, snapshot=snap, gps_seen=True, gps_raw_seen=True, heartbeat_seen=True,
                        msg_rate_hz=rate)


def _asmt(t: float, attack: AttackType, evidence: list[str]) -> ThreatAssessment:
    threat = attack != AttackType.BENIGN
    return ThreatAssessment(t=t, wall_time=t, threat=threat, threat_score=0.8 if threat else 0.0,
                            severity=Severity.CRITICAL if threat else Severity.NORMAL, attack_type=attack,
                            confidence=0.8 if threat else 0.0, evidence=evidence, detector_scores={},
                            contributing_detectors=[], integrity_status=IntegrityStatus.VALID,
                            latency_ms=1.0, is_alert=threat)


class Run:
    """Drives the real controller; records (t, sub_mode, state, [frames]) per tick."""

    def __init__(self) -> None:
        self.c = MitigationController(mode=DefenseMode.ACTIVE_IPS)  # real classifier + real actuator
        self.t0 = 100.0
        self.i = 0
        self.log: list[tuple[float, AttackSubMode, MitigationState, list[bytes]]] = []

    def tick(self, attack: AttackType, evidence: list[str], **frame_kw) -> None:
        t = round(self.t0 + self.i * DT, 6)
        self.i += 1
        act = self.c.step(_frame(t, **frame_kw), _asmt(t, attack, evidence))
        self.log.append((t, act.sub_mode, act.state, list(act.counter_frames)))

    def run(self, secs: float, attack: AttackType, evidence: list[str], **frame_kw) -> None:
        for _ in range(int(round(secs / DT))):
            self.tick(attack, evidence, **frame_kw)

    def frames(self) -> list[tuple[float, bytes]]:
        return [(t, f) for t, _s, _st, fs in self.log for f in fs]

    def set_modes(self) -> list[tuple[float, int]]:
        return [(t, m) for t, f in self.frames() if (m := _set_mode_custom(f)) is not None]

    def statustexts(self) -> list[float]:
        return [t for t, f in self.frames() if _msgid(f) == MSGID_STATUSTEXT]


def _assert_main_flood_actions(r: Run) -> None:
    """D10 (classification only): above the flood rate the relabelled GNSS-loss tick takes main's DOS_FLOOD
    actions. The rate limiter engages and the GNSS anti-jam downlink rewrite (sanitize_gps) does not."""
    tags = {a["tag"] for a in r.c.action_history}
    assert "RATE_LIMIT" in tags and "ANTI_JAM_DR" not in tags, tags
    assert r.c._sanitize_gps_latched is False
    assert r.c.sanitizer is not None and r.c.sanitizer.sanitize_gps is False


# --- PX4 mode names at ~370 msg/s ---------------------------------------------------------------

PX4_MODES = ["AUTO_LOITER", "POSCTL", "AUTO_MISSION", "AUTO_RTL", "OFFBOARD"]


@pytest.mark.parametrize("px4_mode", PX4_MODES)
def test_px4_gnss_loss_at_370hz_is_classified_gnss_and_sends_no_do_set_mode_within_30s(px4_mode):
    r = Run()
    r.run(25.0, AttackType.DOS, GNSS_EVIDENCE, mode=px4_mode)  # 125 threat ticks: below the 150-tick SAFE_HOLD
    assert {s for _t, s, _st, _f in r.log} == {AttackSubMode.DOS_GNSS_JAMMING}  # #112's classification, kept
    assert r.set_modes() == []  # the ladder never guesses a PX4 mode: knows_mode() is ArduCopter-only
    # D10: classification only. The GPS ladder (and its "GPS unreliable" STATUSTEXT) is not run for a
    # reclassified high-rate tick, exactly as on main, where this was DOS_FLOOD.
    assert r.statustexts() == []
    assert all(st != MitigationState.SAFE_HOLD for _t, _s, st, _f in r.log)
    _assert_main_flood_actions(r)  # D10: main's flood actions, not the GNSS anti-jam downlink rewrite


def test_px4_sustained_gnss_loss_past_30s_reaches_SAFE_HOLD_but_sends_no_do_set_mode():
    """MEASURED BEHAVIOUR on current main (the #140 SAFE_HOLD gate), pinned for the maintainer.

    After > 150 consecutive threat ticks (30 s at 5 Hz) the controller enters SAFE_HOLD. The
    'Safe Hold Escalation' block now sends ``encode_set_mode("ALT_HOLD")`` only when the vehicle
    reports a mode the actuator can encode (``knows_mode(fm)``, ArduCopter names only) and is
    known to be armed. A PX4 vehicle (AUTO_LOITER) therefore gets NO DO_SET_MODE, even after 30 s
    of GNSS loss: the state still escalates to SAFE_HOLD, the pilot is still told, and nothing is
    sent that PX4 would misread as an ArduCopter ALT_HOLD number. Before #140 this test pinned the
    opposite (a DO_SET_MODE carrying custom mode 2).
    """
    r = Run()
    r.run(40.0, AttackType.DOS, GNSS_EVIDENCE, mode="AUTO_LOITER")  # the 40 s fault of the SITL run
    assert r.set_modes() == []  # the gate: knows_mode("AUTO_LOITER") is False
    assert r.log[-1][2] == MitigationState.SAFE_HOLD  # the state machine still escalates
    assert r.statustexts() == []  # D10: no ladder on the reclassified tick, as on main


def test_px4_high_rate_flood_without_gnss_evidence_stays_a_flood_and_sends_no_do_set_mode():
    r = Run()
    r.run(10.0, AttackType.DOS, ["packet flood msg_rate=724Hz"], mode="AUTO_LOITER", rate=724.0)
    assert {s for _t, s, _st, _f in r.log} == {AttackSubMode.DOS_FLOOD}
    assert r.set_modes() == []


# --- ArduCopter at the same high rate ------------------------------------------------------------


@pytest.mark.parametrize("ac_mode", ["LOITER", "ALT_HOLD", "STABILIZE", "GUIDED", "AUTO", "RTL"])
@pytest.mark.parametrize("secs", [10.0, 40.0], ids=["10s", "40s-SAFE_HOLD"])
def test_arducopter_high_rate_gnss_loss_sends_no_alt_hold_that_main_would_not_send(ac_mode, secs):
    """D10 regression. On origin/main a 370 msg/s GNSS-loss threat was DOS_FLOOD and no DO_SET_MODE was
    sent (measured with the real controller, LOITER/ALT_HOLD/STABILIZE/GUIDED/AUTO/RTL, 10 s and 40 s).
    #112 relabels it DOS_GNSS_JAMMING; without the D10 guard that label sent ALT_HOLD (custom mode 2) at
    +3.2 s (GPS ladder) or at +30 s (SAFE_HOLD escalation)."""
    r = Run()
    r.run(secs, AttackType.DOS, GNSS_EVIDENCE, mode=ac_mode)
    assert {s for _t, s, _st, _f in r.log} == {AttackSubMode.DOS_GNSS_JAMMING}  # label kept
    assert r.set_modes() == []  # == what main sent
    _assert_main_flood_actions(r)  # D10: main's flood actions, not the GNSS anti-jam downlink rewrite


def test_arducopter_high_rate_gnss_loss_recovery_restores_the_trusted_mode_like_main():
    """Main's recovery after a high-rate GNSS-loss threat sends one DO_SET_MODE restoring the trusted
    mode (LOITER = custom mode 5); #112 alone replaced it with an ALT_HOLD at +3.2 s and no restore."""
    r = Run()
    r.run(10.0, AttackType.BENIGN, [], mode="LOITER", fix=3, sats=12)  # learn the trusted mode
    r.run(10.0, AttackType.DOS, GNSS_EVIDENCE, mode="LOITER")
    r.run(20.0, AttackType.BENIGN, [], mode="LOITER", fix=3, sats=12)
    assert [m for _t, m in r.set_modes()] == [5]
    assert r.c.state == MitigationState.NOMINAL


def test_arducopter_low_rate_gnss_loss_still_reaches_alt_hold_once_with_bounds():
    """Unchanged by #112 and by D10: at or below the flood rate main already sent this ALT_HOLD."""
    r = Run()
    r.run(10.0, AttackType.DOS, GNSS_EVIDENCE, mode="LOITER", rate=50.0)
    assert {s for _t, s, _st, _f in r.log} == {AttackSubMode.DOS_GNSS_JAMMING}
    sent = r.set_modes()
    assert [m for _t, m in sent] == [COPTER_ALT_HOLD]  # exactly one ALT_HOLD, no other mode
    # bounds: gps_confirm_ticks=2 -> confirmed at tick 2 (t0+0.2); escalate only >= gps_escalate_s (3 s) later
    confirm_t = r.t0 + DT
    assert sent[0][0] >= confirm_t + 3.0 - 1e-6
    assert sent[0][0] <= confirm_t + 3.0 + 2 * DT
    assert len(r.statustexts()) >= 1


@pytest.mark.parametrize(
    "kw",
    [{"mode": "STABILIZE"}, {"mode": "LOITER", "armed": False}, {"mode": "LOITER", "armed": None}],
    ids=["non-position-mode", "disarmed", "armed-unknown"],
)
def test_arducopter_high_rate_gnss_loss_no_alt_hold_outside_its_bounds(kw):
    r = Run()
    r.run(10.0, AttackType.DOS, GNSS_EVIDENCE, **kw)
    assert r.set_modes() == []


# --- benign no-fix ---------------------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["AUTO_LOITER", "LOITER"])
def test_benign_no_fix_at_370hz_actuates_nothing(mode):
    """No fix but the detector says benign (e.g. never-acquired under the 'coverage' policy)."""
    r = Run()
    r.run(30.0, AttackType.BENIGN, [], mode=mode, fix=0, sats=0)
    assert all(fs == [] for _t, _s, _st, fs in r.log)
    assert {s for _t, s, _st, _f in r.log} == {AttackSubMode.NONE}
    assert r.c.state == MitigationState.NOMINAL
