"""ConstDet is not muted by reorders or gaps (D14 on #125), checked against the REAL extractor.

``FeatureExtractor.clear_window_counts()`` resets ``reorder_count`` to 0 after every decision, so a
frame reports the reorders seen in its own window. Whatever those per-window gap/reorder counts are,
ConstDet must fire in every window that carries a large control-accel residual.
"""

from __future__ import annotations

from dataclasses import replace

from aegisflight.core.types import MessageEnvelope, TelemetrySnapshot
from aegisflight.detectors.physics import PhysicsDetector
from aegisflight.features.extractor import FeatureExtractor, FeatureFrame


def _hb(t: float, seq: int) -> MessageEnvelope:
    return MessageEnvelope(
        recv_time=t, sysid=1, compid=1, msgid=0, msgname="HEARTBEAT", seq=seq, signed=False, byte_len=17,
        fields={"type": 2, "autopilot": 3, "base_mode": 0, "custom_mode": 0, "system_status": 3},
    )


def _window(ex: FeatureExtractor, t0: float, seqs: list[int]) -> FeatureFrame:
    """One decision window from the real extractor, with a large control-accel residual injected."""
    t = t0
    for i, s in enumerate(seqs):
        t = t0 + i * 0.02
        ex.update(_hb(t, s))
    frame = ex.extract(t + 0.02)
    ex.clear_window_counts()
    snap = TelemetrySnapshot(t=frame.t, armed=True, groundspeed=0.0, rel_alt=10.0)
    return replace(frame, snapshot=snap, control_accel_residual_ms2=15.0)


def test_constdet_fires_in_every_window_regardless_of_gap_or_reorder() -> None:
    ex = FeatureExtractor(reorder_window=16)
    det = PhysicsDetector({"control_semantics_enabled": True, "control_accel_residual_ms2": 4.5})
    # Jitter reorders a packet across a window boundary: the window that sees the skip records a gap
    # (and one late packet), the next window delivers the late packet with no gap of its own.
    plan = [
        [10, 11],  # clean: reorder 0, gap 0
        [13, 12, 15],  # skip 12 -> gap 1, late 12 -> reorder 1, skip 14 -> gap 1
        [14, 16],  # late 14 -> reorder 1 (equal to the previous window's count), gap 0
        [18, 17, 19, 21],  # late 17 -> reorder 1, gap 1 (both skips)
        [20, 22],  # late 20 -> reorder 1, gap 0
        [23, 24],  # clean again
    ]
    results = []
    for k, seqs in enumerate(plan):
        f = _window(ex, 1.0 + k, seqs)
        results.append((f.reorder_count, f.max_seq_gap, "control_accel_residual_ms2" in det.process(f).signals))
    # (reorder_count, max_seq_gap, constdet_fired) per window
    assert [(c, g) for c, g, _ in results] == [(0, 0), (1, 1), (1, 0), (1, 1), (1, 0), (0, 0)], results
    assert all(fired for _, _, fired in results), results
