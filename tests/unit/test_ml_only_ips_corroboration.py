"""D13 (maintainer decision, issue #4): ML alone must not make ACTIVE_IPS act; a corroborated assessment still does.

"Require corroboration before ML-only evidence can trigger ACTIVE_IPS. ML alone must not initiate flight-mode
changes." The real ``FusionEngine`` is built from the DEFAULT detector config (``ml_require_corroboration: false``),
so a saturated lone ML score reaches the threat threshold (0.16/0.34 = 0.4706 >= 0.45); the real
``MitigationController`` then must not send a frame or switch the sanitizer on while in ACTIVE_IPS.

Environment tag: SIM (in-process, hand-built detector results). Claim class: IPS policy only.
"""

from __future__ import annotations

import pytest

from aegisflight.config import load_config
from aegisflight.core.enums import AttackType, DetectorName, IntegrityStatus
from aegisflight.core.types import DetectorResult, TelemetrySnapshot
from aegisflight.features.extractor import FeatureFrame
from aegisflight.fusion.engine import FusionEngine
from aegisflight.mitigation.controller import MitigationController
from aegisflight.mitigation.types import DefenseMode

_TICKS = 40


def _frame(t: float) -> FeatureFrame:
    snap = TelemetrySnapshot(t=t, lat=47.0, lon=8.0, alt_msl=500.0, rel_alt=50.0, vx=5.0, vy=0.0, groundspeed=5.0,
                             flight_mode="POSCTL", armed=True, gps_fix_type=3, satellites=10)
    frame = FeatureFrame(t=t, snapshot=snap, n_sources=1, sources={(1, 1): 1})
    frame.autopilot_id, frame.mav_type = 12, 2  # PX4 multirotor
    frame.pos_residual_m = 50.0
    return frame


def _run(mode: DefenseMode, *, corroborated: bool, profile: str | None = None):
    cfg = load_config(profile)
    fusion = FusionEngine(cfg.detector["fusion"])
    ctl = MitigationController(mode=mode)
    votes = {AttackType.GPS_SPOOFING: 1.0}
    frames: list[bytes] = []
    asmts = []
    flags: set[str] = set()
    for i in range(_TICKS):
        t = i * 0.2
        attack = i >= 10
        ml = DetectorResult(detector=DetectorName.ANOMALY, score=1.0 if attack else 0.0, triggered=attack,
                            attack_votes=votes if attack else {})
        phys = DetectorResult(detector=DetectorName.PHYSICS, score=0.6 if (attack and corroborated) else 0.0,
                              triggered=attack and corroborated, attack_votes=votes if (attack and corroborated) else {})
        silent = [DetectorResult(detector=d, score=0.0, triggered=False)
                  for d in (DetectorName.PROTOCOL, DetectorName.INTEGRITY)]
        asmt = fusion.fuse(t, t, [ml, phys, *silent], IntegrityStatus.UNKNOWN)
        act = ctl.step(_frame(t), asmt)
        asmts.append(asmt)
        frames.extend(act.counter_frames)
        s = ctl.sanitizer
        flags |= {k for k, v in (("sanitize_gps", s.sanitize_gps), ("sanitize_alt", s.sanitize_alt),
                                 ("rate_limit", s.rate_limit_active), ("quarantine", bool(s.quarantined_sysids))) if v}
    return asmts, frames, flags, ctl


def test_ml_only_in_active_ips_sends_no_frame_and_no_sanitizer() -> None:
    asmts, frames, flags, ctl = _run(DefenseMode.ACTIVE_IPS, corroborated=False)
    # the fused assessment still alerts (default profile); only the IPS refuses to act on it
    assert any(a.threat for a in asmts[10:]), "precondition: lone ML reaches the threat threshold on the default profile"
    assert frames == []  # no DO_SET_MODE, no STATUSTEXT, nothing to the FC or the GCS
    assert flags == set()  # no downlink rewrite, no rate limit, no quarantine
    assert not any(a["tag"] in ("SANITIZE_GPS", "RESTORE_MODE", "SAFE_HOLD_CMD", "GPS_LADDER") for a in ctl.action_history)


def test_corroborated_evidence_in_active_ips_still_acts() -> None:
    asmts, frames, flags, _ = _run(DefenseMode.ACTIVE_IPS, corroborated=True)
    assert any(a.threat for a in asmts[10:])
    assert frames, "a non-ML detector scoring > 0 must keep the playbook working"
    assert "sanitize_gps" in flags


def test_ml_only_alerting_in_advisory_and_passive_is_unchanged() -> None:
    _, frames, flags, ctl = _run(DefenseMode.ADVISORY, corroborated=False)
    assert frames and flags == set()  # ADVISORY: the HUD STATUSTEXT is still sent for an ML-only alert
    _, frames, flags, ctl = _run(DefenseMode.PASSIVE, corroborated=False)
    assert frames == [] and flags == set()
    assert any(a["tag"] == "DETECTED" for a in ctl.action_history)  # PASSIVE still reports the detection


@pytest.mark.parametrize("profile", [None, "configs/px4_sitl"])
def test_alert_stream_is_not_changed_by_the_controller(profile: str | None) -> None:
    """The controller does not rewrite the assessment it was given (dashboards / logs see the original)."""
    asmts, _, _, _ = _run(DefenseMode.ACTIVE_IPS, corroborated=False, profile=profile)
    base, _, _, _ = _run(DefenseMode.PASSIVE, corroborated=False, profile=profile)
    assert [(a.threat, a.severity) for a in asmts] == [(a.threat, a.severity) for a in base]
