"""PROPOSAL evidence: what an ML-ONLY score can make the inline bridge do in ACTIVE_IPS (needs a maintainer decision).

This is a characterisation test, not a statement that the behaviour is right. It drives the real ``AnomalyDetector``
(stub Isolation-Forest bundle, one ML feature at a time far from baseline), the real ``FusionEngine`` (the other three
detectors score 0.0) and the real ``MitigationController`` in ``ACTIVE_IPS``, and records the frames the controller
emits (what ``InlineIpsBridge.analyse_tick`` would write to the flight controller / GCS) and the inline sanitizer flags.

Environment tag: SIM (in-process, stub model). Claim class: command-path / link-level policy only. It says what the
policy WOULD send for a given ML score; it does not show the real model ever scores a benign flight that high (that
is a separate, measured question: the Stage-1 baseline ML-driven false positives, artifacts/benchmarks/summary.md).
Injection point: none (no attack). The "attack" here is a false positive of the ML detector.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import patch

import numpy as np
import pytest

from aegisflight.config import load_config
from aegisflight.core.enums import DetectorName, IntegrityStatus
from aegisflight.core.types import DetectorResult, TelemetrySnapshot
from aegisflight.detectors.anomaly import AnomalyDetector
from aegisflight.features.extractor import ML_FEATURES, FeatureFrame
from aegisflight.fusion.engine import FusionEngine
from aegisflight.hal.inline_ips import InlineIpsBridge
from aegisflight.mitigation.controller import MitigationController
from aegisflight.mitigation.types import DefenseMode
from aegisflight.sources.mavlink_live import MavlinkFrameParser

_TICKS = 170  # 34 s at 5 Hz: covers the GPS ladder (3 s) and the >30 s (150 tick) SAFE_HOLD escalation
_ATTACK_FROM = 10
_MAGNITUDE = {"msg_rate_hz": 100.0}  # every other driver uses 50.0 (msg_rate 100 > 84 selects the flood sub-mode)


class _ConstIso:
    def score_samples(self, x):
        return np.full(len(x), 0.1)


class _IdentityScaler:
    def transform(self, x):
        return x


def _bundle() -> dict:
    # raw = max(iso_z, ||x||): zero for the benign rows, ||x|| (>= 50) for a driven row -> normalised score ~1.0
    return {"model": _ConstIso(), "scaler": _IdentityScaler(), "score_thr": 0.62, "score_scale": 0.05,
            "iso_mean": -0.1, "iso_std": 0.1, "maha_mean": 0.0, "maha_std": 1.0}


def _ml_detector(cfg, tmp_path: Path) -> AnomalyDetector:
    model = tmp_path / "m.joblib"
    model.write_bytes(b"x")
    (tmp_path / "MODELS.sha256").write_text(f"{hashlib.sha256(b'x').hexdigest()}  m.joblib\n", encoding="utf-8")
    with patch("joblib.load", return_value=_bundle()):
        det = AnomalyDetector(cfg.detector["anomaly"], model)
    det.warmup_ticks = 0
    assert det.bundle is not None
    return det


def _drive(profile: str | None, feature: str, tmp_path: Path) -> dict:
    cfg = load_config(profile)
    det = _ml_detector(cfg, tmp_path)
    fusion = FusionEngine(cfg.detector["fusion"])
    ctl = MitigationController(mode=DefenseMode.ACTIVE_IPS)
    parser = MavlinkFrameParser()
    first = None
    frames: list[tuple[str, str]] = []
    sanitizer_flags: set[str] = set()
    for i in range(_TICKS):
        t = i * 0.2
        snap = TelemetrySnapshot(t=t, lat=47.0, lon=8.0, alt_msl=500.0, rel_alt=50.0, vx=5.0, vy=0.0, groundspeed=5.0,
                                 flight_mode="POSCTL", armed=True, gps_fix_type=3, satellites=10)
        frame = FeatureFrame(t=t, snapshot=snap, n_sources=1, sources={(1, 1): 1})
        frame.autopilot_id, frame.mav_type = 12, 2  # PX4 multirotor: the dialect the live evidence is for
        if i >= _ATTACK_FROM:
            setattr(frame, feature, _MAGNITUDE.get(feature, 50.0))
        ml = det.process(frame)
        silent = [DetectorResult(detector=d, score=0.0, triggered=False)
                  for d in (DetectorName.PROTOCOL, DetectorName.PHYSICS, DetectorName.INTEGRITY)]
        asmt = fusion.fuse(t, t, [ml, *silent], IntegrityStatus.UNKNOWN)
        act = ctl.step(frame, asmt)
        if i >= _ATTACK_FROM and first is None:
            first = (asmt.threat, asmt.severity.value, asmt.attack_type.value, act.sub_mode.value)
        s = ctl.sanitizer
        sanitizer_flags |= {k for k, v in (("sanitize_gps", s.sanitize_gps), ("sanitize_alt", s.sanitize_alt),
                                           ("rate_limit", s.rate_limit_active), ("quarantine", bool(s.quarantined_sysids)))
                            if v}
        for raw in act.counter_frames:
            for env in parser.parse(raw, t):
                if env.msgname == "COMMAND_LONG":
                    cmd = f"COMMAND_LONG cmd={int(env.fields['command'])} param2={env.fields['param2']:g}"
                else:
                    cmd = env.msgname
                frames.append((f"{i}", cmd))
    assert first is not None
    return {"first": first, "frames": frames, "sanitizer": sorted(sanitizer_flags)}


def test_ml_only_score_to_active_ips_action_matrix(tmp_path: Path) -> None:
    rows: dict[tuple[str, str], dict] = {}
    for profile, label in ((None, "base"), ("configs/px4_sitl", "px4_sitl")):
        for feature in ML_FEATURES:
            sub = tmp_path / f"{label}_{feature}"
            sub.mkdir()
            rows[(label, feature)] = _drive(profile, feature, sub)

    print("\nprofile | ML driver feature | threat/severity/attack/sub-mode | frames emitted (tick, frame) | sanitizer")
    for (label, feature), r in rows.items():
        print(f"{label} | {feature} | {r['first']} | {r['frames']} | {r['sanitizer']}")

    # --- default CLI config (Stage-1 configs/, ml_require_corroboration: false) ---------------------------------
    # 0.16/0.34 = 0.4706 max-normalised ML weight: a saturated ML score alone reaches SUSPICIOUS (>= 0.45), which is
    # the controller's is_threat floor.
    gps = [("STATUSTEXT"), ("COMMAND_LONG cmd=176 param2=2")]  # DO_SET_MODE, PX4 main mode 2 = ALTCTL
    for feature in ("pos_residual_m", "accel_ms2"):
        r = rows[("base", feature)]
        assert r["first"][:3] == (True, "SUSPICIOUS", "GPS_SPOOFING")
        assert [c for _, c in r["frames"]] == gps  # one GCS STATUSTEXT, then a mode change sent to the FC
        assert r["sanitizer"] == ["sanitize_gps"]  # downlink position rewrite
    for feature in ("gps_vfr_speed_diff_ms", "gps_baro_alt_diff_m", "alt_rate_ms", "yaw_course_diff_deg", "cmd_rate_hz",
                    "interarrival_jitter_ms", "max_seq_gap", "loss_ratio", "msg_rate_hz"):
        assert rows[("base", feature)]["frames"] == []  # nothing is written to the FC or the GCS
    assert rows[("base", "gps_baro_alt_diff_m")]["sanitizer"] == ["sanitize_alt"]
    assert rows[("base", "alt_rate_ms")]["sanitizer"] == ["sanitize_alt"]
    assert rows[("base", "msg_rate_hz")]["sanitizer"] == ["rate_limit"]
    for feature in ("gps_vfr_speed_diff_ms", "yaw_course_diff_deg", "cmd_rate_hz", "interarrival_jitter_ms",
                    "max_seq_gap", "loss_ratio"):
        assert rows[("base", feature)]["sanitizer"] == []  # logged in the action history only
    # ML can never attribute MAVLINK_ANOMALY or FIRMWARE_INTEGRITY (FEATURE_ATTACK_MAP), so those playbooks
    # (quarantine, pre-arm lock, takeover escalation) are unreachable from ML alone
    assert {r["first"][2] for (lab, _), r in rows.items() if lab == "base"} == {
        "DOS", "GPS_SPOOFING", "TELEMETRY_MANIPULATION", "COMMAND_INJECTION"}
    assert all("quarantine" not in r["sanitizer"] for r in rows.values())

    # --- px4_sitl profile (ml_require_corroboration: true): the lone-ML score is capped below the threat threshold ---
    for feature in ML_FEATURES:
        r = rows[("px4_sitl", feature)]
        assert r["first"][0] is False and r["first"][1] == "NORMAL"
        assert r["frames"] == [] and r["sanitizer"] == []


@pytest.mark.parametrize("profile", ["configs/universal_flight", "configs/ardupilot_copter"])
def test_ml_model_is_refused_by_profiles_that_disable_the_ml_detector(profile: str, tmp_path: Path) -> None:
    """``--model`` with a profile that sets ``anomaly.enabled: false`` is refused at start (never silently ignored)."""
    model = tmp_path / "m.joblib"
    model.write_bytes(b"x")
    (tmp_path / "MODELS.sha256").write_text(f"{hashlib.sha256(b'x').hexdigest()}  m.joblib\n", encoding="utf-8")

    class _T:
        def start(self) -> None: ...
        def close(self) -> None: ...
        def recv(self, timeout_s: float = 0.05):
            return None
        def send(self, data: bytes) -> None: ...

    with patch("joblib.load", return_value=_bundle()), pytest.raises(ValueError, match="ML model failed to load"):
        InlineIpsBridge(_T(), _T(), model_path=str(model), config_dir=profile)
