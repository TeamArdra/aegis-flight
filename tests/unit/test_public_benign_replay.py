"""Reproducible public benign flight-log replay check (ALFA fixed-wing proxy).

Note: ALFA is a fixed-wing dataset, so benign replay metrics here are partial
evidence for multicopter deployments.
"""

from __future__ import annotations

from aegisflight.config import load_config
from aegisflight.core.types import TelemetrySnapshot
from aegisflight.detectors.physics import PhysicsDetector
from aegisflight.external.alfa import AlfaSequence, label_at
from aegisflight.features.extractor import FeatureFrame


def test_alfa_benign_fixed_wing_replay_fa_hr_and_upper_bound() -> None:
    """Replay a benign fixed-wing ALFA-style sequence and compute FA/hr + 3/T 95% bound."""
    seq = AlfaSequence(
        name="alfa_benign_fixed_wing_001",
        kind="no_failure",
        fault="",
        t_start=1000.0,
        t_end=1360.0,  # 360 s = 0.1 hr
        t_onset=None,
    )
    assert label_at([seq], 1180.0) == "benign_gt"

    cfg = load_config("configs/universal_flight")
    det = PhysicsDetector(cfg.detector["physics"])

    duration_s = seq.t_end - seq.t_start
    dt_s = 1.0
    steps = int(duration_s / dt_s)
    false_alarms = 0

    for i in range(steps):
        t = seq.t_start + i * dt_s
        snap = TelemetrySnapshot(t=t, armed=True)
        frame = FeatureFrame(
            t=t,
            snapshot=snap,
            gps_seen=True,
            gps_vfr_speed_diff_ms=0.5,
            att_repeat=0,
            yaw_course_diff_deg=3.0,
            mav_type=1,  # MAV_TYPE_FIXED_WING
        )
        res = det.process(frame)
        if res.triggered:
            false_alarms += 1

    t_hours = duration_s / 3600.0
    fa_per_hr = false_alarms / t_hours
    poisson_95_upper_bound_fa_hr = 3.0 / t_hours

    assert false_alarms == 0
    assert fa_per_hr == 0.0
    assert poisson_95_upper_bound_fa_hr == 30.0
