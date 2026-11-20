# Canonical test summary, 2026-11-03

Generated from pytest JUnit XML. Host: Windows 11, CPython 3.13.15, pytest 9.1.1. Command: `python -m pytest -p no:cacheprovider -q -rfEs --junitxml=<file>`.

## Unmodified `f9945a7`, all three uncommitted user files present

tests 1064, failures 0, errors 0, skipped 3, 181.7 s

| Directory | Passed | Skipped | Failed |
|---|---|---|---|
| `backend/tests` | 5 | 0 | 0 |
| `tests/e2e` | 2 | 0 | 0 |
| `tests/integration` | 95 | 0 | 0 |
| `tests/unit` | 959 | 3 | 0 |

## Working tree: `f9945a7` plus `tests/unit/test_synthetic_gps_demo.py` and the demo scripts; `git diff HEAD -- src configs` is empty

tests 1075, failures 0, errors 0, skipped 3, 177.3 s

| Directory | Passed | Skipped | Failed |
|---|---|---|---|
| `backend/tests` | 5 | 0 | 0 |
| `tests/e2e` | 2 | 0 | 0 |
| `tests/integration` | 95 | 0 | 0 |
| `tests/unit` | 970 | 3 | 0 |

The 3 skips are POSIX PTY tests in `tests/unit/test_mavlink_serial.py` (no PTY pairs on Windows).

Frontend (`npm test`): 31 passed, 0 failed. `npm run build`: ok. `ruff check src tests scripts backend`: all checks passed. `python scripts/verify_stage2.py`: 8 of 8 demo suites (`SIM`, hand-built inputs, not validation evidence). `cargo test --offline` in `rust/aegis_fastpath`: 0 tests exist.
