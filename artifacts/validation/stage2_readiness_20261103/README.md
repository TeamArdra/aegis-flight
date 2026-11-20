# stage2_readiness_20261103: checks behind the Stage 2 readiness pass

**Software only.** No serial port was opened. Nothing touched a vehicle, WSL, PX4 or a network beyond loopback, and nothing was transmitted.
**Claim class: none.** These are regression, replay and demonstration checks, not attack-detection evidence on a real vehicle.

**Tree.** `main` `f9945a7`, `git diff HEAD -- src configs` empty. Host Windows 11, CPython 3.13.15, numpy 2.5.3, pandas 3.0.6,
scikit-learn 1.9.1, scipy 1.18.1, pymavlink 2.4.50, pyserial 3.5, fastapi 0.142.2, pytest 9.1.1, ruff 0.16.10, Node 24.21.0.
`models/isoforest.joblib` sha256 `3fe74cddf3689e169610ffd783b109b6539cc6c03629bd1e4bb8b1d3842939c4`.
`configs/detector.yaml` sha256 `12948921a230df3c5e26090581540d821491f244d34d4fcb2ab9aaf66f7c37be`.

Local scratch paths in the JSON were replaced by `<scratch>`. No result value was changed. Files are otherwise as generated.
The `replay_*` JSON files carry a `config_dir` field that is unreliable for choosing a profile: trust the folder name here.

| Path | Env | What | Regenerate |
|---|---|---|---|
| `chain_truncation_check.txt` | software | `aegis verify-log` on scratch copies with rows deleted: mid-chain deletion is detected (exit 2); deleting the newest row or all rows is **not** | sqlite3 `DELETE` on a copy, then `aegis verify-log` |
| `test_summary.md`, `pytest_*.xml` | software | Canonical test counts, and the JUnit XML behind them (host name and local paths removed) | `python -m pytest -p no:cacheprovider -q -rfEs --junitxml=<file>` |
| `benchmark_summary.md`, `benchmark_results.csv`, `benchmark_vs_committed.json` | `SIM`, model used | 6535 / 4 / 16826 / 65; 378 of 378 non-timing cells equal | `aegis benchmark --out <scratch> --no-figures`, then `scripts/compare_benchmark_runs.py` |
| `extended_summary.md`, `extended_vs_20261029.md` | `SIM`, model used | Identical sessions to the 2026-10-29 re-run | `scripts/benchmark_extended.py --out <scratch> --workers 4` |
| `gps_drift_sweep/` | `SIM`, 10 seeds per rate | Summaries, ML off and ML on | `scripts/sweep_gps_drift.py --out <dir> --seeds 10 [--model models/isoforest.joblib]` |
| `replay_default/` | `REPLAY` of `BENCH` | Default profile, ML off, on 5 real captures | `scripts/ardupilot/replay_ap_tlog.py data/hardware/raw/<c>.tlog --no-ml --json <out>` |
| `replay_indoor_profile/` | `REPLAY` of `BENCH` | Same, with `--config-dir demo/indoor_bench_profile` | as above |
| `replay_cusum_on/` | `REPLAY` of `BENCH` | Same, with a scratch copy of `configs/` that adds `physics.cusum_enabled: true`. **Not a supported configuration** | as above |
| `synthetic_gps/{default,indoor_profile,cusum_on}/evaluation.json` | synthetic fixture, labelled | Per-phase results | `scripts/demo/make_synthetic_gps_tlog.py evaluate --out <dir> [--config-dir <dir>]` |
| `figures/` | synthetic fixture and `SIM` | Alert timeline, alert evidence, time to first alert | `scripts/demo/make_stage2_report_figures.py --evaluation … --sessions … --out <dir>` |
| `loopback_dryrun/` | `REPLAY` over a loopback virtual port | Dry runs of the runbook's commands on real bytes: `run_serial_ids.py` and `aegis serve --source serial\|replay`. `console.txt` is the summary. **Not a serial device: no baud, driver, UART or DTR/RTS** | `scripts/hardware/virtual_serial_replay.py` plus the runbook commands with `socket://127.0.0.1:<port> --allow-url` |

**The raw captures are local and git-ignored,** so the `REPLAY` rows need `data/hardware/raw/`. No file here contains a position from the bench captures: the
two events files with position fields, for capture 007 (lat = lon = 0) and the synthetic fixture, were left out.

## Main results

| Check | Result |
|---|---|
| Python tests, `f9945a7` | 1061 passed, 3 skipped, 0 failed of 1064 |
| Python tests, working tree with the demo tests | 1072 passed, 3 skipped, 0 failed of 1075 |
| Stage-1 benchmark, model used | 6535 / 4 / 16826 / 65; 378 of 378 cells |
| Extended benchmark | 116 of 116 sessions identical to 2026-10-29 |
| GPS drift sweep, ML off and ML on (`gps_drift_sweep/`) | `sweep_summary.csv` identical to the 2026-10-29 saved results in both states |
| Capture 007, default profile | 295 threat, 15 `DOS` of 300 decisions. **A false alarm: no receiver reported** |
| Capture 007, indoor profile | 0 threat, 0 alerts |
| Capture 009 / 2026-10-28, default profile | 0 threat, 0 alerts of 300 / 450 |
| Capture 008, default profile | 138 threat, 8 alerts (7 `DOS`, 1 `TELEMETRY_MANIPULATION`) of 313 |
| Capture 008, indoor profile | 5 threat, 2 alerts (1 `GPS_SPOOFING` from receiver velocity, 1 `TELEMETRY_MANIPULATION`) |
| CUSUM on, captures 009 / 008 / 2026-10-28 | 8 / 11 / 22 false `GPS_SPOOFING` |
| Fixture through `aegis serve --source replay`, 10x | 12 persisted events (7 `GPS_SPOOFING`, 5 `DOS`), `verify-log` chain OK |
| Loopback `run_serial_ids.py`, 30 s, four streams | exit 0, `bytes_sent` 0, passive check passed, chain OK |
| Loopback `aegis serve --source serial` | environment `REPLAY` (not `BENCH`), physical false, `bytes_sent` 0, attack `POST` answered 409 |

Not run here: any hardware session; any PX4 or ArduPilot SITL session; ALFA and PX4 Flight Review replays (last ALFA re-run: `../consolidation_20261031/`); a clean-clone
install (last: `../consolidation_20261031/`); a benchmark with a retrained model (`aegis train` ran and wrote a file with a different hash, `184648dc…`; the benchmark on it was stopped for low memory, no result). `artifacts/benchmarks*` and `artifacts/figures` were not regenerated.
