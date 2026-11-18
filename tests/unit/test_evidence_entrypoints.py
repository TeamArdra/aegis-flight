"""Issue #25: every evidence-producing entry point exposes --allow-dirty and refuses a dirty tree before writing."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "sitl"))

import p2_trial_common  # noqa: E402

from aegisflight import run_provenance  # noqa: E402

ENTRY_POINTS = sorted(
    [*(p.relative_to(ROOT).as_posix() for p in (ROOT / "scripts/sitl").glob("run_p*_trial.py")),
     "scripts/sitl/record_flight.py", "scripts/sitl/live_ids.py", "scripts/sitl/replay_benign.py",
     "scripts/sitl/compare_live_offline.py", "scripts/sitl/serial_framer_replay.py", "scripts/sitl/run_campaign.py",
     "scripts/ardupilot/run_ap_sitl_ids.py", "scripts/ardupilot/replay_ap_tlog.py",
     "scripts/ardupilot/measure_replay_cost.py", "scripts/ardupilot/measure_sitl_rtf.py",
     "scripts/hardware/run_serial_ids.py"])


def test_entry_point_list_covers_every_trial_driver() -> None:
    assert len([e for e in ENTRY_POINTS if "/run_p" in e]) >= 8  # drift, injection, replay x2, gcs, drop, delay, gnss, p4


@pytest.mark.parametrize("script", ENTRY_POINTS)
def test_entry_point_exposes_allow_dirty(script: str) -> None:
    r = subprocess.run([sys.executable, str(ROOT / script), "--help"], capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr[-500:]
    assert "--allow-dirty" in r.stdout


def test_trial_driver_parser_refuses_dirty_tree_before_any_output(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(run_provenance, "tree_state",
                        lambda repo=None: {"commit": "c" * 40, "dirty": True, "dirty_paths": ["src/x.py"]})
    ap = p2_trial_common.build_argparser("t", default_seconds=1.0)
    with pytest.raises(run_provenance.DirtyTreeError):
        ap.parse_args(["--seed", "1", "--out", str(tmp_path / "o")])
    ns = ap.parse_args(["--seed", "1", "--out", str(tmp_path / "o"), "--allow-dirty"])
    assert ns.allow_dirty is True and p2_trial_common._RUN["args"] is ns


def test_ardupilot_version_names_the_copter_release(monkeypatch: pytest.MonkeyPatch) -> None:
    """#25 n=1 dry run: the ArduPilot 4.7.1 release commit carries one tag per vehicle and ``git describe --tags``
    recorded ``APMrover2-stable`` in the ArduCopter run's manifest. Only ``Copter-*`` tags, ``--long``, now count."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("run_ap_sitl_ids", ROOT / "scripts/ardupilot/run_ap_sitl_ids.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    seen: list[list[str]] = []

    def fake_run(argv, **kw):
        seen.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, stdout="Copter-4.7.1-0-gdbe7921\n", stderr="")

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    assert mod.ardupilot_describe() == "Copter-4.7.1-0-gdbe7921"
    argv = seen[0]
    assert argv[argv.index("--match") + 1] == "'Copter-*'"  # quoted: wsl -- runs it through a shell
    assert "--long" in argv and "--tags" in argv


def test_trial_driver_started_dirty_then_cleaned_is_not_reproducible(monkeypatch: pytest.MonkeyPatch,
                                                                     tmp_path: Path) -> None:
    """PR #50 review P1: the tree is judged at parse time (run start), not only when the manifest is written."""
    states = iter([{"commit": "a" * 40, "dirty": True, "dirty_paths": ["src/x.py"]}])
    clean = {"commit": "a" * 40, "dirty": False, "dirty_paths": []}
    monkeypatch.setattr(run_provenance, "tree_state", lambda repo=None: next(states, clean))
    monkeypatch.setattr(p2_trial_common, "px4_describe", lambda *a, **k: "v1.15.0")
    import provenance as sitl_prov

    monkeypatch.setattr(sitl_prov, "collect", lambda **kw: {"aegisflight_commit": "a" * 40, "python": "3.11.0"})
    ap = p2_trial_common.build_argparser("t", default_seconds=1.0)
    ap.parse_args(["--seed", "1", "--out", str(tmp_path / "o"), "--allow-dirty", "--model", "none"])
    run = p2_trial_common.provenance_block("d", "/px4", {})["run_provenance"]
    assert run["status"] == "NOT-REPRODUCIBLE" and "dirty at run start" in run["not_reproducible_reason"]
