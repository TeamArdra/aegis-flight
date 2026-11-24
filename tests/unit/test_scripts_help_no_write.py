"""Issue #158: ``--help`` of an evidence/fixture generator prints usage and writes nothing.

``make_validation_table.py --help`` used to ignore the flag, regenerate and overwrite the committed
``artifacts/validation/validation_table.md``. AGENTS.md section 6: committed evidence changes only through a
deliberate, named, re-runnable command, never as a side effect of asking for help.

Each script runs as a subprocess from a throwaway copy of ``scripts/`` (so every ``REPO``-relative or
cwd-relative output path lands inside ``tmp_path``, never in the real repository). Every file the script would
write is pre-seeded with sentinel bytes; afterwards the whole tmp tree must be byte-identical.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

# script -> the tracked files it writes by default (repo-relative). A regression that writes any of them, or
# anything else, changes the tree below.
WRITES: dict[str, tuple[str, ...]] = {
    "scripts/make_validation_table.py": ("artifacts/validation/validation_table.md",),
    "scripts/make_golden.py": ("tests/golden/golden.json",),
    "scripts/make_golden_forwarding.py": ("tests/golden_forwarding/golden.json",),
    "scripts/ardupilot/make_ap_baseline_summary.py": ("artifacts/ardupilot/BASELINE_SUMMARY.json",
                                                      "artifacts/ardupilot/BASELINE_SUMMARY.md"),
    "scripts/sitl/make_p1_summary.py": ("artifacts/sitl/P1_summary.md",),
    "scripts/sitl/calib_derive.py": ("artifacts/sitl/calibration/derivation.json", "configs/px4_sitl/detector.yaml"),
    "scripts/sitl/calib_lofo.py": ("artifacts/sitl/calibration/lofo_rules.json",),
    "scripts/sitl/calib_regression_check.py": ("artifacts/sitl/calibration/stage1_regression.json",),
    "scripts/sitl/calib_report.py": ("artifacts/sitl/calibration/summary.md", "docs/CALIBRATION_PX4.md"),
    "scripts/sitl/calib_rtf_probe.py": ("artifacts/sitl/calibration/rtf_probe.json",),
    "scripts/sitl/calib_shift.py": ("artifacts/sitl/calibration/feature_shift.json",),
    # the demo suites build a backend engine whose default event store is artifacts/aegisflight_live.sqlite
    "scripts/verify_stage2.py": ("artifacts/aegisflight_live.sqlite",),
}


def _snapshot(root: Path) -> dict[str, str]:
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file() and "__pycache__" not in p.parts}


def test_every_known_writer_is_listed() -> None:
    for script in WRITES:
        assert (ROOT / script).is_file(), script


@pytest.mark.parametrize("script", sorted(WRITES))
@pytest.mark.parametrize("flag", ["--help", "-h"])
def test_help_prints_usage_and_writes_nothing(script: str, flag: str, tmp_path: Path) -> None:
    shutil.copytree(ROOT / "scripts", tmp_path / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
    for rel in WRITES[script]:
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"SENTINEL: committed evidence, must not change\n")
    before = _snapshot(tmp_path)

    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    r = subprocess.run([sys.executable, str(tmp_path / script), flag], cwd=tmp_path, env=env,
                       capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120,
                       stdin=subprocess.DEVNULL)

    assert r.returncode == 0, (r.stdout + r.stderr)[-800:]
    assert "usage:" in r.stdout.lower(), r.stdout[-400:]
    assert _snapshot(tmp_path) == before, "--help changed the tree (written, created or deleted files)"
