"""Tests for the temporary smoke-test helper (issue #44)."""

from __future__ import annotations

import pytest
from smoke_range_util import inclusive_range_count


def test_reversed_bounds_raise():
    with pytest.raises(ValueError):
        inclusive_range_count(5, 3)
