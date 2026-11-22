"""Synthetic sanity check: the universal_flight physics detector stays quiet on constant nominal frames.

This is NOT a replay of a public flight log and is NOT evidence about false-alarm rates on real vehicles. No ALFA
(or any other) data is read: the frames are constants built in this file (GPS/VFR speed difference 0.5 m/s, yaw/course
difference 3 deg, no repeated attitude), fed to ``PhysicsDetector`` only (not the protocol, ML or fusion stages, and
not through the extractor). Real-data benign replay lives in ``scripts/external_validation.py`` and its committed
artifacts under ``artifacts/external/`` (``docs/EXTERNAL_DATA.md``); ALFA is a fixed-wing dataset, so it is partial
evidence for a multicopter in any case.
"""

from __future__ import annotations

from aegisflight.config import load_config
from aegisflight.core.types import TelemetrySnapshot
from aegisflight.detectors.physics import PhysicsDetector
from aegisflight.features.extractor import FeatureFrame


def test_physics_detector_does_not_trigger_on_360_constant_nominal_frames() -> None:
    cfg = load_config("configs/universal_flight")
    det = PhysicsDetector(cfg.detector["physics"])

    triggered = 0
    for i in range(360):  # 1 Hz for 360 s of synthetic time
        t = 1000.0 + float(i)
        frame = FeatureFrame(
            t=t,
            snapshot=TelemetrySnapshot(t=t, armed=True),
            gps_seen=True,
            gps_vfr_speed_diff_ms=0.5,
            att_repeat=0,
            yaw_course_diff_deg=3.0,
            mav_type=1,  # MAV_TYPE_FIXED_WING
        )
        if det.process(frame).triggered:
            triggered += 1

    assert triggered == 0
