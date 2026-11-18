# Validation: MAVLink sequence high-water mark + reorder window (issue #14)

- **Environment tag:** `SIM` (synthetic extended benchmark v2, ML off: `--no-model`)
- **Claim class:** link-level detection (simulated benign link stress & attack sessions; not hardware/flight)
- **Command:** `PYTHONPATH=src python scripts/benchmark_extended.py --no-model --out <dir>`
- **Base commit (before):** `d71b1d4` (`origin/main`)
- **Feature:** `features.reorder_window = 16` (`FeatureFrame.reorder_count`, not in `ML_FEATURES`)

## Summary comparison (before vs. after, ML off)

| Metric | Before (`d71b1d4`) | After (`fix/14-reorder-window-seq-gap`) |
|---|---:|---:|
| `link_reorder_benign` FP decisions (of 3,450) | 3,328 (96.46 %) | **0 (0.00 %)** |
| `link_reorder_benign` sessions with >= 1 FP | 6 / 6 | **0 / 6** |
| `benign` FP decisions (of 6,900) | 0 (0.00 %) | 0 (0.00 %) |
| `link_fifo_benign` FP decisions (of 3,450) | 1 (0.03 %) | 1 (0.03 %) |
| `mavlink_anomaly:seq_scramble` sessions detected | 4 / 4 (98.45 %) | **4 / 4 (96.67 %, 100 % attr.)** |
| `dos:latency` sessions detected | 4 / 4 (96.16 %, 0 % attr.) | 0 / 4 (see note) |

### Explanation of `dos:latency` and `rate_spike` delta

- `dos:latency` (`src/aegisflight/attacks/scenarios.py:227-232`) adds random packet jitter (`0.2..1.0 * 400 ms`), causing packets to arrive a few sequence numbers out of order without dropping or flooding. Before this fix, `dos:latency` was flagged solely as a side-effect of the `seq = prev - 1 -> gap = 254` bug (`0.00 %` attribution accuracy, labelled `MAVLINK_ANOMALY` instead of `DOS`). With reorder tolerance enabled, `dos:latency` is no longer spuriously flagged by `max_seq_gap`.
- `mavlink_anomaly:rate_spike` remains **4/4 sessions** (97.98 % recall, median TTD 0.40 s; duplicated packet bursts with repeating sequence numbers within `R = 16` now count as reorders rather than 254-frame gaps while rate rules detect the spike).

## Files in this directory

- `before_summary.md` — full `benchmark_extended.py --no-model` report at `d71b1d4`
- `after_summary.md` — full `benchmark_extended.py --no-model` report on `fix/14-reorder-window-seq-gap`
