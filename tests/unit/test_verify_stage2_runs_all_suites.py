"""Issue #191: ``scripts/verify_stage2.py`` must run all 8 demo suites and exit 0.

The script used to stop at suite 5 (``ValueError: unknown mode 'AUTO'``): the actuator fails closed until a vehicle
dialect is bound (#148), and the controller binds it only from ``frame.autopilot_id`` / ``frame.mav_type``. The demo
built neither, so the IDS/IPS replay-guard check could not have passed even without the exception.

The script runs as a subprocess from a scratch cwd (its backend suites write ``artifacts/aegisflight_live.sqlite``
relative to the cwd, so nothing lands in the repository). It is a demo on hand-built inputs, not evidence; this test
only guards that the documented command keeps working against the current ``src/``.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import aegisflight

ROOT = Path(__file__).resolve().parents[2]
SRC = Path(aegisflight.__file__).resolve().parents[1]  # the src/ the test process itself imports


def _run_script(tmp_path: Path) -> subprocess.CompletedProcess[str]:
    shutil.copytree(ROOT / "scripts", tmp_path / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
    env = {k: v for k, v in os.environ.items() if not k.startswith("AEGIS_")}
    env.update(PYTHONPATH=str(SRC), PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8")
    return subprocess.run(
        [sys.executable, str(tmp_path / "scripts" / "verify_stage2.py")],
        cwd=tmp_path, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=300, stdin=subprocess.DEVNULL,
    )


def test_verify_stage2_runs_all_eight_suites_and_exits_zero(tmp_path: Path) -> None:
    r = _run_script(tmp_path)
    out = re.sub(r"\x1b\[[0-9;]*m", "", r.stdout)
    assert r.returncode == 0, (out + r.stderr)[-1500:]
    assert "[FAIL]" not in out, out[-1500:]
    assert "Traceback" not in r.stderr, r.stderr[-1500:]
    assert len(re.findall(r"\[AEGIS STAGE 2 AUDIT\] (?:\d\. |SUITE 8)", out)) == 8, out[-1500:]
    assert "All 8 demo suites passed" in out
    # the checks that depend on the dialect binding really ran (not skipped)
    assert "Unbound actuator refuses DO_SET_MODE" in out
    assert "Dual-Posture Replay Guard verified" in out
