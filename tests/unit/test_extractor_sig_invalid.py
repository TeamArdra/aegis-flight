"""P4: FeatureExtractor.note_sig_invalid -- a windowed counter additive to Stage-1 (default 0,
always a no-op unless a live source with a signing key calls it). No SITL, no sockets."""

from __future__ import annotations

from aegisflight.features.extractor import FeatureExtractor


def test_note_sig_invalid_accumulates_into_the_current_window():
    ext = FeatureExtractor()
    ext.note_sig_invalid(2)
    ext.note_sig_invalid(3)
    frame = ext.extract(1.0)
    assert frame.sig_invalid_count == 5


def test_clear_window_counts_resets_sig_invalid():
    ext = FeatureExtractor()
    ext.note_sig_invalid(4)
    ext.clear_window_counts()
    frame = ext.extract(1.0)
    assert frame.sig_invalid_count == 0


def test_default_is_zero_without_any_call():
    ext = FeatureExtractor()
    frame = ext.extract(1.0)
    assert frame.sig_invalid_count == 0


def test_reset_also_clears_sig_invalid():
    ext = FeatureExtractor()
    ext.note_sig_invalid(7)
    ext.reset()
    frame = ext.extract(1.0)
    assert frame.sig_invalid_count == 0


def test_signing_context_accessor_matches_private_window_state():
    from aegisflight.features.extractor import FeatureExtractor

    fx = FeatureExtractor()
    ctx = fx.signing_context
    assert set(ctx) == {"unsigned_events", "sig_invalid_streams", "sig_verified_streams", "source_msgs"}
    assert ctx["sig_invalid_streams"] is None and ctx["sig_verified_streams"] is None  # untracked source
    assert ctx["unsigned_events"] is fx._unsigned_window and ctx["source_msgs"] is fx._source_msgs_window
    fx.note_signing_streams({(1, 1, 0): 2}, {(1, 1, 1)})
    ctx = fx.signing_context
    assert ctx["sig_invalid_streams"] == {(1, 1, 0): 2} and ctx["sig_verified_streams"] == {(1, 1, 1)}
