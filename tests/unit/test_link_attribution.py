"""Unit tests for link-level attack attribution and hierarchical grouping (#22)."""

from __future__ import annotations

from aegisflight.config import DEFAULT_DETECTOR
from aegisflight.core.enums import AttackType
from aegisflight.core.types import TelemetrySnapshot
from aegisflight.detectors.protocol import ProtocolDetector
from aegisflight.features.extractor import FeatureFrame
from aegisflight.metrics.scoring import hierarchical_link_summary, link_layer_label


def _frame(**kw) -> FeatureFrame:
    base = {
        "t": 10.0,
        "msg_rate_hz": 20.0,
        "heartbeat_age_s": 0.5,
        "gps_age_s": 0.2,
        "sources": {(1, 1): 10},
        "n_sources": 1,
        "heartbeat_seen": True,
        "gps_seen": True,
    }
    base.update(kw)
    return FeatureFrame(snapshot=TelemetrySnapshot(t=base["t"]), **base)


def test_selective_heartbeat_loss_attributes_to_mavlink_anomaly_when_enabled() -> None:
    det_off = ProtocolDetector({**DEFAULT_DETECTOR["protocol"], "semantic_link_attribution": False})
    det_on = ProtocolDetector({**DEFAULT_DETECTOR["protocol"], "semantic_link_attribution": True})

    # Selective heartbeat starvation while GPS and non-HB telemetry keep flowing at 15 Hz
    f_sel = _frame(heartbeat_age_s=3.5, gps_age_s=0.2, msg_rate_hz=15.0)
    r_off = det_off.process(f_sel)
    r_on = det_on.process(f_sel)
    assert AttackType.DOS in r_off.attack_votes
    assert AttackType.MAVLINK_ANOMALY in r_on.attack_votes
    assert AttackType.DOS not in r_on.attack_votes

    # Full blackout (link quiet + GPS also stale) stays DOS even with semantic attribution enabled
    f_blackout = _frame(heartbeat_age_s=3.5, gps_age_s=3.2, msg_rate_hz=1.0)
    r_blk = det_on.process(f_blackout)
    assert AttackType.DOS in r_blk.attack_votes

    # Heartbeat stops while residual traffic is >= semantic_link_min_rate_hz (5.0 Hz) and GPS fresh -> MAVLINK_ANOMALY;
    # below custom semantic_link_min_rate_hz -> DOS
    f_hb_only_5hz = _frame(heartbeat_age_s=3.5, gps_age_s=0.5, msg_rate_hz=5.5)
    assert AttackType.MAVLINK_ANOMALY in det_on.process(f_hb_only_5hz).attack_votes
    det_custom = ProtocolDetector(
        {**DEFAULT_DETECTOR["protocol"], "semantic_link_attribution": True, "semantic_link_min_rate_hz": 10.0}
    )
    assert AttackType.DOS in det_custom.process(f_hb_only_5hz).attack_votes


def test_hierarchical_link_layer_grouping_and_summary() -> None:
    assert link_layer_label(AttackType.DOS) == "LINK_LAYER_DISRUPTION"
    assert link_layer_label(AttackType.MAVLINK_ANOMALY) == "LINK_LAYER_DISRUPTION"
    assert link_layer_label(AttackType.GPS_SPOOFING) == AttackType.GPS_SPOOFING.value

    summary = hierarchical_link_summary(
        [AttackType.DOS, AttackType.MAVLINK_ANOMALY, AttackType.GPS_SPOOFING],
        [AttackType.MAVLINK_ANOMALY, AttackType.DOS, AttackType.GPS_SPOOFING],
    )
    assert summary["link_layer_support"] == 2
    assert summary["link_layer_matched"] == 2
    assert summary["link_layer_accuracy"] == 1.0
