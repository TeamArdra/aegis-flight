"""Unit tests for MAVLink sequence high-water mark + reorder window (issue #14)."""

from __future__ import annotations

import pytest

from aegisflight.config import load_config
from aegisflight.core.types import MessageEnvelope
from aegisflight.features.extractor import ML_FEATURES, FeatureExtractor, FeatureFrame
from aegisflight.pipeline import IDSPipeline


def _hb(t: float, seq: int, sysid: int = 1, compid: int = 1) -> MessageEnvelope:
    return MessageEnvelope(
        recv_time=t,
        sysid=sysid,
        compid=compid,
        msgid=0,
        msgname="HEARTBEAT",
        seq=seq,
        signed=False,
        byte_len=17,
        fields={"type": 2, "autopilot": 3, "base_mode": 0, "custom_mode": 0, "system_status": 3},
    )


def _step(ex: FeatureExtractor, seqs: list[tuple[int, int, int]], t_start: float = 0.0) -> FeatureFrame:
    t = t_start
    for idx, (sysid, compid, seq) in enumerate(seqs):
        t = t_start + idx * 0.02
        ex.update(_hb(t, seq, sysid=sysid, compid=compid))
    frame = ex.extract(t + 0.02)
    ex.clear_window_counts()
    return frame


def test_in_order_sequences_have_zero_gap_and_zero_reorder() -> None:
    ex = FeatureExtractor(reorder_window=16)
    f = _step(ex, [(1, 1, s) for s in range(10)])
    assert f.max_seq_gap == 0
    assert f.reorder_count == 0


def test_single_loss_records_gap_of_one() -> None:
    ex = FeatureExtractor(reorder_window=16)
    f = _step(ex, [(1, 1, 10), (1, 1, 12)])
    assert f.max_seq_gap == 1
    assert f.reorder_count == 0


def test_burst_loss_of_40_exceeds_threshold() -> None:
    ex = FeatureExtractor(reorder_window=16)
    f = _step(ex, [(1, 1, 10), (1, 1, 51)])
    assert f.max_seq_gap >= 39
    assert f.max_seq_gap == 40
    assert f.reorder_count == 0


def test_wraparound_254_to_1_and_late_255() -> None:
    ex = FeatureExtractor(reorder_window=16)
    # 254 -> 255 -> 0 -> 1 normal wraparound
    f1 = _step(ex, [(1, 1, 254), (1, 1, 255), (1, 1, 0), (1, 1, 1)], t_start=0.0)
    assert f1.max_seq_gap == 0
    assert f1.reorder_count == 0

    # Jump to 3 (gap=1), then late 255 arrives (4 steps behind HWM=3, inside R=16), then 4
    f2 = _step(ex, [(1, 1, 3), (1, 1, 255), (1, 1, 4)], t_start=1.0)
    assert f2.max_seq_gap == 1
    assert f2.reorder_count == 1


@pytest.mark.parametrize("back", [1, 2, 16])
def test_backward_step_within_reorder_window_counts_reorder_not_gap(back: int) -> None:
    ex = FeatureExtractor(reorder_window=16)
    hwm = 50
    late = (hwm - back) % 256
    f = _step(ex, [(1, 1, hwm), (1, 1, late)])
    assert f.max_seq_gap == 0
    assert f.reorder_count == 1


def test_backward_step_beyond_reorder_window_records_gap() -> None:
    ex = FeatureExtractor(reorder_window=16)
    # HWM=50, backward step of R+1 = 17 -> seq=33 -> d=(33-50)%256 = 239 < 240 -> gap=238
    f = _step(ex, [(1, 1, 50), (1, 1, 33)])
    assert f.max_seq_gap == 238
    assert f.reorder_count == 0


def test_duplicate_frame_records_neither_gap_nor_reorder() -> None:
    ex = FeatureExtractor(reorder_window=16)
    f = _step(ex, [(1, 1, 20), (1, 1, 20)])
    assert f.max_seq_gap == 0
    assert f.reorder_count == 0


def test_two_interleaved_sources_tracked_independently() -> None:
    ex = FeatureExtractor(reorder_window=16)
    f = _step(
        ex,
        [
            (1, 1, 100),
            (255, 1, 5),
            (1, 1, 102),  # gap=1 on sys 1
            (255, 1, 6),  # normal on sys 255
            (1, 1, 101),  # late packet for sys 1 (d=255)
            (255, 1, 7),  # normal on sys 255
        ],
    )
    assert f.max_seq_gap == 1
    assert f.reorder_count == 1


def test_late_frame_followed_by_in_order_frames_causes_no_second_gap() -> None:
    ex = FeatureExtractor(reorder_window=16)
    f1 = _step(ex, [(1, 1, 10), (1, 1, 12), (1, 1, 11)], t_start=0.0)
    assert f1.max_seq_gap == 1
    assert f1.reorder_count == 1

    # High-water mark remained 12, so 13 -> 14 -> 15 have d=1 and 0 gap
    f2 = _step(ex, [(1, 1, 13), (1, 1, 14), (1, 1, 15)], t_start=1.0)
    assert f2.max_seq_gap == 0
    assert f2.reorder_count == 0


def test_reorder_window_zero_restores_strict_step_semantics() -> None:
    ex = FeatureExtractor(reorder_window=0)
    f = _step(ex, [(1, 1, 10), (1, 1, 9)])
    assert f.max_seq_gap == 254
    assert f.reorder_count == 0


def test_invalid_reorder_window_rejected() -> None:
    with pytest.raises(ValueError):
        FeatureExtractor(reorder_window=-1)
    with pytest.raises(ValueError):
        FeatureExtractor(reorder_window=128)


def test_ml_features_contract_unchanged_and_pipeline_passes_config() -> None:
    assert "reorder_count" not in ML_FEATURES
    assert len(ML_FEATURES) == 11
    cfg = load_config()
    assert cfg.detector["features"]["reorder_window"] == 16
    cfg.detector["features"]["reorder_window"] = 4
    pipe = IDSPipeline(cfg)
    assert pipe.extractor.reorder_window == 4
