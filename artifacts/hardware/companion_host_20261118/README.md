# Paced replay — HOST baseline (issue #30, Part A)

**Evidence class: environment REPLAY on the development host. This is NOT Raspberry Pi / companion-computer
evidence.** It is the host comparison baseline that the issue asks for. Part B (a run on a Pi-class board) has
not been measured yet. Until it is, the target-hardware figure is "not measured on target hardware".

All numbers are in `paced_replay_px4_benign_001.json`, which the tool generated. This README repeats none of them.

## Command

```bash
PYTHONPATH=src .venv/Scripts/python.exe scripts/hardware/paced_replay.py data/sitl/raw/benign_001.tlog \
    --config-dir configs/px4_sitl --model models/isoforest_px4.joblib \
    --factor 1 --factor 3 --ml both --label host \
    --out artifacts/hardware/companion_host_20261118/paced_replay_px4_benign_001.json
```

- Input: the PX4 SITL benign capture `benign_001.tlog`. Its sidecar says environment SITL and attack NONE. The tlog
  itself is git-ignored; its SHA-256 is in the JSON (`input.tlog_sha256`).
- Model: `isoforest_px4.joblib` (git-ignored; SHA-256 in `config.model_sha256`). Config: the `configs/px4_sitl` profile.
- Machine, OS, Python and package versions, commit and dirty flag are in `provenance`. Board model and power
  are recorded as "not recorded" because this is not a board.

## Reading it

- `runs[]`: one entry per factor (1×, 3×) per ML mode (off, on).
- `decision_compute_ms` covers decode, tick bucketing and the pipeline for each decision. The feeder thread
  shares the GIL, so this is consumer wall time, not pure CPU. `pipeline_latency_ms` is `process_tick` alone.
- `decision_lag_ms` and `late_decisions` measure how far behind real time each decision finished. A late
  decision has a lag above one tick period.
- `frames.dropped` counts frames lost to a full queue. `frames.late` counts frames dequeued more than one tick
  period after release. `ticks.emitted` vs `ticks.expected` compares the paced run with a drop-free count.
- `verdicts_identical_to_unpaced` is true when the paced verdict sequence equals an unpaced replay of the same
  frames. This is the determinism check.
- `memory.rss_mb_process_lifetime_peak` is the peak for the whole process. All four runs share one process, so
  later runs carry the peaks of earlier ones. Use `rss_mb_max_sampled` to compare runs.
- Do not compare these figures with the Stage-1 simulator numbers or the ArduPilot unpaced cost
  (`replay_cost_*.json`). The inputs and metrics are different.
