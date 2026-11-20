"""Regression tests for the issue #10 claims guard (scripts/claims_guard.py).

The pattern is exercised through real ``git grep -E`` (POSIX extended regex), the exact engine CI
uses, in a throwaway repository, never through Python's ``re`` alone.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("claims_guard", REPO_ROOT / "scripts" / "claims_guard.py")
cg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cg)

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is required")


def _repo(tmp_path: Path, files: dict[str, str]) -> Path:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text + "\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    return tmp_path


@pytest.mark.parametrize("line", [
    "Target hardware BOM ₹2,900 INR",          # rupee-prefixed
    "cost 2,900 per unit",                      # standalone, after a space
    "2,900 at the start of a line",
    "(2,900)",
    "11.4% CPU",
    "11.4 % CPU",
    "42.8 MB RAM",
    "82.4 km path",
    "mIDS-UAV dataset",
    "<0.08 ms Rust",
    "EKF failsafe blind",
    "score 92/100",
    "729+ tests",
    "endurance 4.8 h",
])
def test_withdrawn_claim_is_detected(tmp_path, line):
    _repo(tmp_path, {"docs/notes.md": line})
    hits = cg.find_claims(cwd=str(tmp_path))
    assert len(hits) == 1 and hits[0].startswith("docs/notes.md:1:"), (line, hits)


@pytest.mark.parametrize("line", [
    "no grace: 9088 / 470 / 42209 / 1133 over 52,900 (FPR 0.0110)",   # docs/stage2_report_draft.md:217
    "12,900 frames",
    "over 112,900 decisions",
    "1,2,900",
    "2900 without a separator",
    "111.4 MB",
])
def test_real_numbers_that_contain_a_withdrawn_one_are_not_flagged(tmp_path, line):
    _repo(tmp_path, {"docs/notes.md": line})
    assert cg.find_claims(cwd=str(tmp_path)) == [], line


@pytest.mark.parametrize("path", ["docs/STAGE2_GAPS_AND_PRIORITIES.md", "docs/SUBMISSION_READINESS_AUDIT.md",
                                  "docs/REDTEAM_AUDIT_STAGE2.md", "docs/GPS_WORKSTREAM_PROGRESS.md"])
def test_allowlisted_audit_documents_are_skipped(tmp_path, path):
    _repo(tmp_path, {path: "Pi Zero 2W 11.4% CPU · ₹2,900 BOM (withdrawn)"})
    assert cg.find_claims(cwd=str(tmp_path)) == []


@pytest.mark.parametrize(("path", "flagged"), [
    ("frontend/src/components/evalPanels.tsx", True),
    ("frontend/src/x.ts", True),
    ("scripts/x.py", True),
    ("docs/stage2_report_draft.md", True),       # not allowlisted: only its real 52,900 passes
    ("artifacts/x/summary.json", False),         # outside the issue's file globs
    ("notes.txt", False),
])
def test_file_globs_match_the_issue(tmp_path, path, flagged):
    _repo(tmp_path, {path: "value: ₹2,900"})
    assert bool(cg.find_claims(cwd=str(tmp_path))) is flagged


def test_the_repository_itself_is_clean():
    if not (REPO_ROOT / ".git").exists():
        pytest.skip("not a git checkout")
    assert cg.find_claims(cwd=str(REPO_ROOT)) == []


def test_ci_runs_this_guard():
    ci = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "python3 scripts/claims_guard.py" in ci
    assert "git grep -nE" not in ci, "the pattern must live only in scripts/claims_guard.py"
