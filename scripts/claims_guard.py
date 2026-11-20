"""Claims guard (issue #10): fail if a withdrawn, unsupported number comes back.

Single source of truth for the pattern and the allowlist: the CI job ``claims-guard`` runs this
script, and ``tests/unit/test_claims_guard.py`` tests the same constants, so the two cannot drift.

    python scripts/claims_guard.py            # exit 0: clean; exit 1: hits printed; exit 2: git error

The pattern is POSIX extended regex (``git grep -E``), as written in issue #10's acceptance
criterion. ``2,900`` must not be the tail of a longer number: ``(^|[^0-9,])2,900`` matches
"₹2,900" and a standalone "2,900" but not "52,900" (a real decision count in the benchmark tables).
"""

from __future__ import annotations

import subprocess
import sys

PATTERN = (
    r"11\.4 ?%|42\.8 MB|(^|[^0-9,])2,900|82\.4 ?km|4\.8 h|mIDS|0\.08 ms"
    r"|EKF failsafe blind|92/100|729\+"
)
FILE_GLOBS = ("*.md", "*.tsx", "*.ts", "*.py")
# Audit documents that discuss the withdrawn claims on purpose (issue #10's list).
ALLOWLIST = (
    "docs/STAGE2_*",
    "docs/SUBMISSION_READINESS_AUDIT.md",
    "docs/REDTEAM_AUDIT_STAGE2.md",
    "docs/GPS_WORKSTREAM_PROGRESS.md",
)


def git_grep_args() -> list[str]:
    return ["git", "grep", "-nE", PATTERN, "--", *FILE_GLOBS, *(f":!{p}" for p in ALLOWLIST)]


def find_claims(cwd: str | None = None) -> list[str]:
    """Return the offending ``path:line:text`` lines (empty list = clean)."""
    r = subprocess.run(git_grep_args(), cwd=cwd, capture_output=True, text=True, encoding="utf-8")
    if r.returncode == 1:        # git grep: no match
        return []
    if r.returncode != 0:
        raise RuntimeError(f"git grep failed ({r.returncode}): {r.stderr.strip()}")
    return r.stdout.splitlines()


def main() -> int:
    try:
        hits = find_claims()
    except (OSError, RuntimeError) as exc:
        print(f"claims-guard: {exc}", file=sys.stderr)
        return 2
    if hits:
        print("\n".join(hits))
        print("claims-guard: unsupported claim found outside the allowlisted audit documents (issue #10)",
              file=sys.stderr)
        return 1
    print("claims-guard: no unsupported claims found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
