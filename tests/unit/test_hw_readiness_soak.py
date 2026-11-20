"""Pytest wrapper for the end-to-end RF-impaired & extreme-flood hardware-readiness soak."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.hardware.hw_readiness_soak import run_hw_readiness_soak  # noqa: E402


def test_hw_readiness_soak_passes_all_phases() -> None:
    rep = run_hw_readiness_soak(cycles=1, flood_frames=1200, seed=2026)
    assert rep.ok, f"soak failed: {rep}"
    assert rep.benign_alerts == 0
    assert rep.attack_alerts > 0
    assert rep.analyser_errors == 0
    assert rep.events_chain_ok is True
    assert rep.actions_chain_ok is True
    assert rep.anchors_ok is True
    assert rep.signed_anchors >= 1
    assert rep.serial_boundary_ok is True
