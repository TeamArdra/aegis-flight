# Link-stress sweep on the freeze tag (issue #27 item 2)

**Environment:** `SIM` (in-process simulator sessions, benign only). **Claim class:** none. This measures false alarms under packet loss and re-ordering. It says nothing about attack detection or about real radios.
**Code:** tag `stage2-freeze-2026-11-27` = `8e5800381c4abddc970cbf134d1e95e035a3becf`, clean tree (`working_tree_dirty: false`, status `REPRODUCIBLE` in `run_manifest.json`).
**Model:** `models/isoforest.joblib` sha256 `3fe74cddf3689e169610ffd783b109b6539cc6c03629bd1e4bb8b1d3842939c4` (copied from the reference checkout and checked against `models/MODELS.sha256`; not retrained). Python 3.13.15, scikit-learn 1.9.1, numpy 2.5.3, pymavlink 2.4.50 (full list in `run_manifest.json`).
**Config hashes** (from `run_manifest.json`): `configs` `ff7ed01a…7bf4`, `configs/px4_sitl` `eda294f6…242f`, `configs/ardupilot_copter` `7e76b4c9…2e12`.

## Regenerate

```
python scripts/sweep_link_stress.py --out <dir> --workers 6
```

No other flags: the tool's defaults are the #27 grid (loss {0, 1, 2, 5, 10} % x {fifo, reorder} x ML {off, on} x profile {stage1, px4, ardupilot}, 6 sessions per cell, seeds 70000..70005, 120 s sessions, warm-up 5 s). The tool was not changed. The output was written to a scratch directory outside the repository and copied here byte for byte (git normalised CRLF line endings to LF in `run_manifest.json` on commit). `run_manifest.json` records that scratch path in `command_line`.

| File | What |
|---|---|
| `sweep_table.md` | the full 60-row table (the tool's own rendering, with definitions) |
| `cell_summary.csv` | the same rows as CSV (decision FPR, alert events, observed hours, events/hour, dominant evidence and its count, dominant detector, n/a reason) |
| `decisions.csv.gz` | one row per decision (`evidence` = raw strings, `evidence_key` = normalised), so the firing rule is attributable per decision |
| `run_manifest.json` | provenance (`aegisflight.run_manifest/1` plus the sweep's own fields) |

Definitions are in `sweep_table.md`. In short: a *decision* is one 5 Hz fusion decision after the 5 s warm-up; every session is benign, so every `threat` decision is a false positive; *alert event* = a maximal run of consecutive alarm decisions in one session; *events/h* = events per observed hour (observed = scored decisions x 0.2 s); *dominant evidence* = the most frequent normalised evidence string over alarm decisions.

## Determinism

The sweep was run twice on the same tree (second run into a different scratch directory, same command). `decisions.csv.gz` sha256 `87b70831…9f94` and `cell_summary.csv` sha256 `232e9571…ec20b` are identical in both runs. (The tool's gzip is written with a fixed mtime, so identical rows give identical bytes.)

## Result

Of 60 cells, **30 ran** (20 stage1 cells, 10 ardupilot ML-off cells) and **30 are `n/a`** (marked by the tool, reasons below). Each ran cell has 3,450 scored decisions (6 sessions).

**ML off (20 ran cells, 69,000 scored decisions): 4 alarm decisions in total, decision FPR at most 0.0003.** Where an alarm occurred it was one decision with evidence "implausible acceleration # m/s²" (physics detector): stage1 FIFO 5 %, ardupilot FIFO 5 % and 10 %, ardupilot reorder 10 %. Every other ML-off cell has 0 alarm decisions. Loss and re-ordering alone do not trigger the protocol rule on these sessions.

**ML on (10 ran cells, all stage1, 34,500 scored decisions): 27,612 alarm decisions (pooled decision FPR 0.80: FIFO cells 0.62-0.67, reorder cells 0.90-0.99), all attributed to `ml_anomaly`; the dominant evidence in every cell is "ML anomaly score # >= # (driver: interarrival_jitter_ms, z=#)".**

| Cell (stage1, ML on) | decision FPR | alert events/h | dominant evidence (count) |
|---|---:|---:|---|
| FIFO 0 % | 0.6455 | 2389.6 | ML anomaly ... driver interarrival_jitter_ms (1824) |
| FIFO 1 % | 0.6313 | 2493.9 | same (1744) |
| FIFO 2 % | 0.6336 | 2441.7 | same (1678) |
| FIFO 5 % | 0.6186 | 2619.1 | same (1393) |
| FIFO 10 % | 0.6699 | 2655.7 | same (1293) |
| reorder 0 % | 0.9881 | 156.5 | same (3407) |
| reorder 1 % | 0.9855 | 156.5 | same (3398) |
| reorder 2 % | 0.9768 | 250.4 | same (3363) |
| reorder 5 % | 0.9510 | 464.3 | same (3265) |
| reorder 10 % | 0.9032 | 866.1 | same (2930) |

Worst cells: by decision FPR, stage1 reorder 0 % ML on (0.9881); by alert events per hour, stage1 FIFO 10 % ML on (2655.7 /h). Notes for reading the table:

* **The 61 % FIFO figure of the 2026-11-17 probe is the ML-on configuration (here 0.62-0.67 across FIFO loss levels), driven by `interarrival_jitter_ms`.** It is already present at 0 % loss (0.6455), so it is not caused by loss. With ML off the same sessions give 0 alarm decisions at 0 %, 1 %, 2 % and 10 % and 1 of 3,450 at 5 %. (The probe quoted 0.2 % for ML off at 0-5 % loss with n = 1 per cell; this sweep, n = 6 per cell with other seeds, gives 0.00-0.03 %. The two are different session sets and are not directly comparable.)
* **Events per hour is not monotone in the alarm rate.** Under re-ordering ML on, alarms are almost continuous, so consecutive alarm decisions merge into few long events (30 events at 0 % loss, 166 at 10 %); the FIFO cells alarm intermittently and give many short events. Read events/h together with the decision FPR.
* The Stage-1 model is documented not to transfer to real ArduPilot/PX4 traffic (`docs/ARDUPILOT_SITL.md`); these ML-on numbers are simulator sessions with the simulator-trained model, i.e. a measurement of the simulator link model, not of a deployment.

## Cells marked `n/a` by the tool (30)

* **All 20 `px4` cells (ML off and on).** The tool never executes them. `configs/px4_sitl` is calibrated for PX4 SITL traffic (sysid 3, ~378 msg/s), the simulator emits sysid 1 at ~28 msg/s, so "rogue telemetry source" would fire on every decision and the cell would measure the mismatch, not the profile. The tool says to measure this profile on PX4 SITL replays; those are #27 item 4 (held-out evaluation, `heldout/`), not this folder. There is no opt-in flag. **Consequence: the issue's grid for the PX4 calibrated profile has no SIM cells.**
* **10 `ardupilot` ML-on cells.** No ArduPilot-benign ML model exists and the Stage-1 model is documented not to transfer to ArduPilot. The tool accepts `--model-ardupilot` to force a model; that was not used (it would pair the profile with a model it was not built for). The `ardupilot` ML-off cells are a threshold override on simulator traffic, not a model of ArduPilot's link.

## Not included

* Real-radio loss rates from #29: not available (the #29 walk/range captures do not exist yet).
* No tuning, no re-run until a result looked better, no code change.
