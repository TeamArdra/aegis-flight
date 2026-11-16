# consolidation_20261031: verification of the consolidated `main`

**Environment: host Windows 11 (`SIM` for the benchmark and the Stage-2 demo suites; `REPLAY` for the replay-based tests;
software only).** Claim class: none. These are regression and reproducibility checks: nothing touched a vehicle, a serial
device, WSL / PX4 or a network beyond loopback, and nothing was transmitted. Python 3.13.15, numpy 2.5.3, pandas 3.0.6,
scikit-learn 1.9.1, fastapi 0.142.2, pytest 9.1.1, ruff 0.16.10, Node 24.21.0; `models/isoforest.joblib` sha256
`3fe74cddf3689e169610ffd783b109b6539cc6c03629bd1e4bb8b1d3842939c4`; `configs/detector.yaml` sha256
`12948921a230df3c5e26090581540d821491f244d34d4fcb2ab9aaf66f7c37be`.

## Trees
- `3e3d88e`: `origin/main` after PR #3, which merged `integration/github-latest-20261029` (itself a merge of
  `sprint/hardware-free-20261029` and PR #2). It is the authoritative integration of every branch; see
  `docs/SUBMISSION_READINESS_AUDIT.md` §12 for the branch audit.
- `537a5ee`: the capture-007 replay parity test, adapted to the rate baseline that `2d455b5` enables on every non-SIM source.
- `eb829e9`: a serial-device vehicle link is receive-only in `run_serial_ids.py`, `aegis serve` and `aegis ips-bridge`.

## Results
| Check | Command | Result | File |
|---|---|---|---|
| Full suite, `3e3d88e` (before the fixes) | `python -m pytest -p no:cacheprovider -q -rs` | **1 failed**: `test_capture_007_backend_replay_matches_offline_replay` (needs the git-ignored capture 007, so it skips on a clean clone); 1044 passed, 3 skipped (counted from the progress output) | `pytest_3e3d88e_before.txt` |
| Full suite, `eb829e9` (host, local captures present) | `python -m pytest -p no:cacheprovider -rfEs` | **1061 passed, 3 skipped, 0 failed**, 1064 collected (`tests/unit` 962, `tests/integration` 95, `tests/e2e` 2, `backend/tests` 5); the 3 skips are POSIX PTY tests | `pytest_summary.txt` |
| Clean clone + fresh venv, `eb829e9` | `clean_install.sh <scratch> <repo> <python3.13>` (`git clone --branch main`, `pip install -e ".[dev]"`) | pip exit 0; **1052 passed, 12 skipped, 0 failed** (9 skips: git-ignored captures / model absent; 3 PTY); ruff clean (0.17.3); floor-pinned dependencies resolved newer than on the host | `clean_install_summary.txt` |
| Lint | `ruff check src tests scripts backend` | All checks passed | -- |
| Frontend | `npm test` · `npm run build` (in `frontend/`) | 31 passed, 0 failed · `tsc --noEmit` + `vite build` ok | -- |
| Stage-2 demo suites | `python scripts/verify_stage2.py` | 8 of 8 suites passed (`SIM`, hand-built inputs; not validation evidence) | `verify_stage2_summary.txt` |
| Stage-1 regression, `3e3d88e` | `aegis benchmark --out <scratch> --no-figures` + `scripts/compare_benchmark_runs.py` | TP / FP / TN / FN **6535 / 4 / 16826 / 65**; **378 of 378** non-timing cells equal to `artifacts/benchmarks/results.csv` | `benchmark_3e3d88e_vs_committed.json` |
| Stage-1 regression, `eb829e9` | same | **6535 / 4 / 16826 / 65**; **378 of 378** cells equal | `benchmark_eb829e9_vs_committed.json`, `benchmark_eb829e9_summary.md` |

**ALFA replay (`REPLAY` of real fixed-wing logs; false-alarm / fault behaviour, not attack detection), `eb829e9`:**
`python scripts/external_validation.py --alfa --workers 4 --out <scratch>` (28 min), outputs copied unmodified to
`alfa_rerun/`. Against the committed `artifacts/external/alfa*/` (generated 2026-09-24, before the Stage-2 code), the
`benign_gt` and `fault` rows (all and airborne) of both decision-level tables are **identical** (production config: 100 %
fused threat rate, all `DOS`; calibrated: as committed). Only the `unlabelled` rows (manual flight, taxi, ground) differ:
production fused 99.93 % vs 99.99 % committed, physics 0.36 % vs 0.77 %; calibrated fused 6.31 % vs 6.34 %, airborne
1.44 % vs 1.34 %. The committed artifacts are therefore stale for the `unlabelled` rows only; they are not overwritten.

Not run here: a PX4 / ArduPilot SITL session (WSL was not used), any hardware session, `aegis train`. Committed figures and `artifacts/benchmarks*` were not regenerated (`--no-figures`, scratch `--out`).
Timing columns (`throughput_msgs_per_s`, `mean_compute_latency_ms`) depend on the machine and are excluded from the comparison.
