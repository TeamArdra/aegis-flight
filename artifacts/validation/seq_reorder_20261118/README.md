# Validation: MAVLink sequence high-water mark + reorder window (issue #14)

- **Environment tag:** `SIM` (synthetic extended benchmark v2, both ML off `--no-model` and ML on)
- **Claim class:** link-level detection (simulated benign link stress & attack sessions; not hardware/flight)
- **Commands:**
  - `PYTHONPATH=src python scripts/benchmark_extended.py --no-model --out <dir>`
  - `PYTHONPATH=src python scripts/benchmark_extended.py --out <dir>` (with `models/isoforest.joblib`, `sha256: bafad273e5892a154fe2edf4fbc2a21721a29c180e18e7666f97133af73a31f5`, trained via `python scripts/train_models.py --out models/isoforest.joblib`; canonical Stage-1 regression verified at `6535 / 4 / 16826 / 65`)
- **Base commit (before):** `d71b1d4` (`origin/main`)
- **Feature:** `features.reorder_window = 16` (`FeatureFrame.reorder_count`, not in `ML_FEATURES`)

## Summary comparison — ML off (`--no-model`)

| Metric | Before (`d71b1d4`) | After (`fix/14-reorder-window-seq-gap`) |
|---|---:|---:|
| `link_reorder_benign` FP decisions (of 3,450) | 3,328 (96.46 %) | **0 (0.00 %)** |
| `link_reorder_benign` sessions with >= 1 FP | 6 / 6 | **0 / 6** |
| `benign` FP decisions (of 6,900) | 0 (0.00 %) | 0 (0.00 %) |
| `link_fifo_benign` FP decisions (of 3,450) | 1 (0.03 %) | 1 (0.03 %) |
| `mavlink_anomaly:seq_scramble` sessions detected | 4 / 4 (98.45 %) | **4 / 4 (96.67 %, 100 % attr.)** |
| `mavlink_anomaly:rate_spike` sessions detected | 4 / 4 (100.00 %) | **4 / 4 (97.98 %)** |
| `dos:latency` sessions detected | 4 / 4 (96.16 %, 0 % attr.) | 0 / 4 (see ML-on table & note below) |

## Summary comparison — ML on (`models/isoforest.joblib`)

| Metric | Before (`d71b1d4`) | After (`fix/14-reorder-window-seq-gap`) |
|---|---:|---:|
| Canonical Stage-1 baseline (`23,430` decisions) | `6535 / 4 / 16826 / 65` | **`6535 / 4 / 16826 / 65`** |
| `link_reorder_benign` FP decisions (of 3,450) | 3,449 (99.97 %; `MAVLINK_ANOMALY`: 3,328, `DOS`: 121) | **3,369 (97.65 %; `MAVLINK_ANOMALY`: 0, `DOS`: 3,361)** |
| `link_fifo_benign` FP decisions (of 3,450) | 2,114 (61.28 %; `DOS`: 2,104) | 2,114 (61.28 %; `DOS`: 2,104) |
| `mavlink_anomaly:seq_scramble` sessions detected | 4 / 4 (100.00 %, 98.29 % attr.) | **4 / 4 (99.11 %, 97.42 % attr.)** |
| `mavlink_anomaly:rate_spike` sessions detected | 4 / 4 (100.00 %) | **4 / 4 (100.00 %)** |
| `dos:latency` sessions detected | 4 / 4 (99.77 %, **3.61 % attr.**) | **4 / 4 (97.07 %, 96.88 % attr. to `DOS`)** |

### Explanation of `dos:latency`, `rate_spike`, and `link_reorder_benign` deltas

- **`dos:latency` (`src/aegisflight/attacks/scenarios.py:227-232`)**: adds random per-packet jitter (`0.2..1.0 * 400 ms`), causing packets to arrive a few sequence numbers out of order without dropping or flooding. Before this fix, `seq = prev - 1` produced a spurious `max_seq_gap = 254` `MAVLINK_ANOMALY` vote on every reordered tick, causing `dos:latency` to be misattributed to `MAVLINK_ANOMALY` (`0.00 %` attribution accuracy with ML off, `3.61 %` with ML on). With `reorder_window = 16`, in-window reorders no longer raise a spurious `max_seq_gap = 254` `MAVLINK_ANOMALY` vote: under the full ML-on pipeline, `dos:latency` is detected **4/4 sessions (97.07 % recall)** and its attribution accuracy to `DOS` jumps from **3.61 % to 96.88 %** (via `interarrival_jitter_ms` in `AnomalyDetector`), while under `--no-model` (rules only, which has no standalone `interarrival_jitter_ms` rule) it is `0/4`.
- **`mavlink_anomaly:rate_spike` (`src/aegisflight/attacks/scenarios.py:124-125`)**: repeats the *entire tick batch* `[p_0(seq=s), p_1(seq=s+1), p_2(seq=s+2)]` `extra` times (`s, s+1, s+2, s, s+1, s+2, ...`). At each batch boundary `s+2 -> s`, the backward step is `2` (`d = 254`, `backward_dist = 2 <= 16`). Previously, that `s+2 -> s` transition fired `max_seq_gap = 253` on the very first attack tick (`TTD = 0.00 s`); with `reorder_window = 16`, `s+2 -> s` is counted as an in-window reorder (`reorder_count`), and in `--no-model` mode the message-rate rule fires 2 ticks later (`TTD = 0.40 s`, `97.98 %` recall, `4/4` sessions), while with ML on it remains `100.00 %` (`TTD = 0.00 s`, `4/4` sessions).
- **`link_reorder_benign` with ML on**: all `3,328` `MAVLINK_ANOMALY` sequence-gap false positives are eliminated (`3,328 -> 0`). With ML on, `AnomalyDetector` (trained on zero-delay simulated benign flights where `interarrival_jitter_ms ≈ 0`) still flags the `mean_delay_ms = 25.0` jitter as `DOS`, just as it does on FIFO-ordered `link_fifo_benign` (`61.28 %` `DOS`).

## Files in this directory

- `before_summary.md` — full `benchmark_extended.py --no-model` report at `d71b1d4`
- `after_summary.md` — full `benchmark_extended.py --no-model` report on `fix/14-reorder-window-seq-gap`
- `before_ml_summary.md` — full `benchmark_extended.py` (ML on) report at `d71b1d4`
- `after_ml_summary.md` — full `benchmark_extended.py` (ML on) report on `fix/14-reorder-window-seq-gap`
