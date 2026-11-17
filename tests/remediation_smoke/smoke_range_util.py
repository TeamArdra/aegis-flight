"""Temporary test-only helper for the automation smoke test (issue #44).

Imported only by tests in this directory; removed once the smoke test is recorded.
"""

from __future__ import annotations


def inclusive_range_count(start: int, stop: int) -> int:
    """Return how many integers n satisfy start <= n <= stop."""
    if stop < start:
        raise ValueError("stop must not be less than start")
    return stop - start
