# AegisFlight — Benchmarking

**Every number in this repository's docs comes from `scripts/benchmark.py`.**
Nothing is hand-written. Re-run it to reproduce.

## How to run
```bash
aegis train                      # (once) train the anomaly model
aegis benchmark                  # -> artifacts/benchmarks/ + artifacts/figures/
# equivalently:
python scripts/benchmark.py --seeds 1 2 3 4 5 6
python scripts/benchmark.py --no-model --no-figures --out artifacts/benchmarks_ablation_no_ml
                                             # rule+physics+firmware only (ML off)
python scripts/benchmark_extended.py --workers 8   # extended benchmark v2 (see below)
```
Outputs (in `artifacts/`): `benchmarks/results.json` (authoritative),
`benchmarks/results.csv` (per-session), `benchmarks/summary.md`, and six figures
in `figures/`.

## Methodology
- **Grid:** benign + the six attacks × 6 seeds, routes cycled
  (survey_box/out_and_back/perimeter) → 42 sessions, 23,430 **scored** decisions.
- **Scoring cadence:** one label per decision tick (5 Hz). `true_label` from the
  attack's ground-truth window; `pred_label` = fused `attack_type` if `threat`
  else BENIGN.
- **Warmup:** first 5 s of each session excluded (extractor/ML warmup).
- **Post-attack recovery grace:** benign ticks within `grace_s` (5 s) *after* an
  attack window are excluded from FP scoring. This is disclosed, not hidden — a
  GPS spoof leaves a ~3 s elevated position residual after it stops (the position
  snap-back is genuinely anomalous). FPR is reported on this policy **and** the
  benign-only sessions independently confirm it.
- **Train/test isolation (precise wording):** the benchmark's seeds (1–6) drive
  the *sensor-noise* and attack RNGs and are disjoint from the ML training seeds
  (101–124). The baseline's flight *kinematics*, however, use one fixed simulator
  seed (42) with cruise 12 m/s / 60 m, so the 42 sessions contain only **three
  distinct ground-truth trajectories** (one per route) and the pre-attack part of
  every attack session repeats a benign session's flight. "Unseen noise
  realisations", not "unseen flights". The extended benchmark v2 fixes this.

## Metrics (definitions)
- **Binary** (attack = positive): accuracy, precision `TP/(TP+FP)`, recall/TPR
  `TP/(TP+FN)`, FPR `FP/(FP+TN)`, F1.
- **Per-attack:** one-vs-rest precision/recall/F1 (did we name the right class?).
- **Confusion matrix:** 7×7 over `AttackType`.
- **Detection latency (s):** per attack session, time from onset to first
  in-window detection.
- **Compute latency (ms):** wall time of the per-decision detector+fusion work.
- **Throughput (msg/s):** MAVLink messages processed per wall second.
- **Resources:** process CPU% and RSS (psutil).

## Authoritative results (6 seeds × 7 scenarios, 23,430 scored decisions)

| Metric | Value |
|---|---|
| Accuracy | 0.997 |
| Precision | 0.999 |
| Recall (TPR) | 0.990 |
| False-positive rate | **0.0002** (4 FP / 16,830 benign) |
| F1 | 0.995 |
| TP / FP / TN / FN | 6535 / 4 / 16826 / 65 |

| Attack | Precision | Recall | F1 | Detection latency (s) |
|---|---|---|---|---|
| GPS spoofing | 1.000 | 0.954 | 0.977 | 1.37 |
| MAVLink anomaly | 1.000 | 1.000 | 1.000 | 0.00 |
| Command injection | 1.000 | 1.000 | 1.000 | 0.00 |
| Telemetry manipulation | 0.996 | 1.000 | 0.998 | 0.00 |
| DoS | 1.000 | 1.000 | 1.000 | 0.00 |
| Firmware integrity | 1.000 | 0.991 | 0.996 | 0.80 |

| Efficiency | Value |
|---|---|
| Detection latency mean / p95 | 0.361 s / 1.400 s |
| Compute latency mean / p95 | 17.7 ms / 23.6 ms (≪ 200 ms decision budget) |
| Throughput | 388 msg/s (14× real-time) — ML-off figure: see `artifacts/benchmarks_ablation_no_ml/summary.md` |
| Mean distance / flight | 1,146 m |
| Memory (RSS) mean / max | 155 / 158 MB |

Figures: `artifacts/figures/{confusion_matrix,per_attack_recall,fpr,latency,resource_usage,threat_timeline}.png`.

## ML-off ablation (same grid)
`python scripts/benchmark.py --no-model --no-figures --out artifacts/benchmarks_ablation_no_ml`
→ [`artifacts/benchmarks_ablation_no_ml/summary.md`](../artifacts/benchmarks_ablation_no_ml/summary.md).
Compare it with the table above to see what the ML layer contributes: on this grid it
adds GPS-onset and telemetry decisions and is the only source of false positives.
The headline 0.997 is therefore a **fused-IDS** figure, not an ML figure.

## Extended benchmark v2 (does not replace the baseline)
`python scripts/benchmark_extended.py --workers 8` →
[`artifacts/benchmarks_extended/summary.md`](../artifacts/benchmarks_extended/summary.md)
(+ `results.json`, `sessions.csv`, `decisions.csv.gz`). Design (`benchmark/extended.py`):

| Weakness of the baseline | v2 treatment |
|---|---|
| 3 underlying trajectories (fixed kinematics seed 42, 12 m/s, 60 m) | every session: own kinematics seed (30000+), route, speed 8–16 m/s, altitude 35–90 m, noise ×0.7–1.6 — deliberately wider than the ML training ranges |
| one default mode per attack | all 20 implemented modes × 4 sessions, randomised onset 25–55 s, duration 15–30 s |
| 5 s post-attack grace | reported **with and without** grace from the same run |
| duplicated benign decisions (pre-attack segments replay benign flights) | no duplication — each session is a distinct flight |
| firmware = 41 % of positives | metrics also reported **excluding firmware** |
| clean synthetic link timing | benign **link-impairment stress**: 2 % loss + 25 ms mean delay, FIFO (serial radio) and reordering (UDP) variants |
| single attacks only | 4 simultaneous-attack combinations with multi-label ground truth |
| — | two new modes: `dos:gnss_jamming`, `command_injection:gcs_replay` (known gap) |

Nothing is tuned against v2: production thresholds and the committed model are used.
After adding v2 the baseline grid was re-run and reproduced **bit-identically**
(same TP/FP/TN/FN, confusion matrix, per-attack metrics and latencies).

## Link-stress sweep (`scripts/sweep_link_stress.py`, SIM)

Benign sessions only: loss {0, 1, 2, 5, 10} % x {FIFO, reorder} x {ML off, ML on} x {Stage-1, `configs/px4_sitl`,
`configs/ardupilot_copter`} (px4 cells are reported `n/a`, see below), 6 sessions per cell by default (issue #27 item 2; the tool, not a result). The full grid is
one command on a clean, committed tree; `--allow-dirty` stamps the output NOT-REPRODUCIBLE (#25):

```bash
python scripts/sweep_link_stress.py --out artifacts/validation/final_<tag>/link_stress --workers 4
```

Flags select subsets (`--loss`, `--ordering`, `--ml`, `--profiles`, `--sessions`, `--seed`, `--duration-s`). Default `--out`
is a temporary directory. Outputs: `decisions.csv.gz` (per-decision raw evidence, so the firing rule is attributable),
`cell_summary.csv`, `sweep_table.md` (decision FPR, alert events/h, dominant evidence per cell, with the definitions) and
`run_manifest.json`. An *alert event* is a maximal run of consecutive alarm decisions inside one session.

Per profile: Stage-1 ML-on uses `models/isoforest.joblib`. **Every px4 cell is `n/a` and is never executed**: the
`px4_sitl` profile is calibrated for PX4 SITL traffic (sysid 3, ~378 msg/s) and the simulator emits sysid 1 at ~28 msg/s, so
"rogue telemetry source" would fire on every decision and the cell would measure the mismatch, not the profile; measure it
on PX4 SITL replays (#27 items 3-4). ArduPilot ML-off runs on simulator traffic; ArduPilot ML-on is `n/a` (no ArduPilot
model, the Stage-1 model does not transfer) unless `--model-ardupilot` is given. The `n/a` reasons are in `cell_summary.csv`,
`sweep_table.md` and the manifest's `na_cells`. Models are gitignored. A smoke run is not evidence; evidence comes from the
freeze-tag run.

## Stage 2 metrics

`python scripts/make_stage2_metrics.py --tag <date>` reads committed artifacts only and writes
`artifacts/validation/stage2_metrics_<tag>/metrics.{json,md}` (LF, byte-reproducible; a unit test checks that the
committed files equal a fresh run). Every figure names its source file. Every input is named in the script: if one is
absent the script lists every absent path, exits with status 2 and writes nothing; a decision log whose times are off
the engine's tick grid also stops it with status 2 and one line naming the input. *Missing inputs* in the output lists
what the repository lacks by design (uncommitted tlogs, external raw data, per-decision alert flags), which is why
those sources stay decision level instead of being estimated. Definitions (code: `src/aegisflight/metrics/stage2.py`):

- **Alert event**: a decision the fusion engine marks `is_alert` (a threat at SUSPICIOUS or
  above, de-duplicated by the per-type cooldown `fusion.cooldown_s` while an alert is active).
  Where an artifact logs only decisions, it is re-derived with the engine's rule on the engine's raw
  tick time (`k * 0.1 s`), not the rounded logged `t`: at an exact 4.0 s gap the two differ by one ulp.
  Unit tests check the re-derivation against the real engine at that boundary and row by row against
  the ArduPilot logs, which record the engine's own alert flag.
- **False alerts per hour of exposure** (issue #28 asks for "per flight hour"; no source here measures flight
  time): alert events on benign ground truth / exposure, where exposure is the **scored decision time**, the
  scored decisions x 0.2 s, warm-up excluded from both. That is simulated or SITL time, including ground phases
  such as boot, GPS wait and arming where they are scored, not time in the air. BENCH uses the wall time of a
  disarmed bench run. The bound is the exact **one-sided** 95% Poisson (Garwood) upper limit; 0 events in T h
  gives 2.996 / T. Decision-level FPR is reported next to it.
- **Grace**: shown with (5 s) and without. The 5 s after an attack stops is the recovery tail,
  where detector state still reflects the attack; no-grace is the conservative figure.
- **Session detection / session FPR**: proportions over sessions with **two-sided** Wilson 95% intervals.
- **Latency**: from onset to detection, median and p95 by nearest rank with n. The median is the
  lower middle value for even n; with n < 20 the nearest-rank p95 is the maximum and is printed as
  `max X (n=N)`. For drift it is also given from release (the attacker stops). The SIM, SITL ArduPilot and
  SITL PX4 rows use different detection rules; each row states its rule.
- **Per-class precision / recall / F1, macro-F1** from the confusion matrix. A class that is
  never predicted scores precision 0, not NaN. Macro-F1 is reported **two ways, labelled**: attack classes
  only (the class set of `metrics/scoring.py` `Evaluation.macro()`) and including BENIGN. Which one is the
  headline is a definition sign-off item (#28).
- **Accuracy** is reported last, because the benign majority dominates it, and **two ways, labelled**:
  binary (attack = positive, the definition under "Metrics (definitions)" above; equal to `results.json`
  `binary_*.accuracy`) and multiclass (attribution).
- **Claim class**: each row carries its own source's claim class, verbatim, and "not recorded" where the
  source states none. No figure is flight-hour, real-flight or real-world validation.
- **Excluded sources**: a source the docs record as invalid evidence is left out of every row and pool and
  listed under *Excluded sources* with the reason quoted from those docs (e.g. `live_run_001`, contaminated by an
  aliased 255/190 driver and superseded by `live_run_002`).
- **Provenance and pooling**: each source's commit, dirty-tree flag, config, ML state and date are
  copied from its own metadata ("not recorded" where absent). The figures therefore describe the code
  that produced each source, not the current tree: the output is a dated snapshot, and later changes
  (e.g. PR #39, pending) are not reflected. The committed extended benchmark (2026-09-24) is not reproduced
  exactly by the committed 2026-10-29 re-run (`dos:blackout`); `metrics.md` states the gap, computed from the
  committed re-run files only, and the SIM figures are computed from the committed decisions. ArduPilot SITL runs are pooled only within the same recorded ML
  state and commit. The all-runs pool is kept for comparison and carries a warning.

## Interpreting the numbers
- **GPS recall 0.954** is the detection-latency cost: the sliding-window residual
  takes ~1.4 s to cross threshold at onset; the missed decisions are those first
  ticks, not steady-state misses.
- **FPR 0.0002** — four false decisions across ~17k benign, from transient
  turn dynamics; none escalate to sustained alerts. The ML-off ablation has zero
  false positives, i.e. every baseline FP involves the ML detector (a lone ML score
  ≥ 0.956 crosses the fusion threshold on its own). Because every attack session's
  pre-attack segment replays a benign session's flight, the ~17k benign decisions
  are far fewer *independent* observations (v2 removes this duplication).
- **CPU ~99% during the benchmark** reflects running flat-out (unpaced). In
  real-time operation the meaningful figure is the **per-decision latency**
  (17.7 ms mean at 5 Hz ≈ 9 % duty cycle), not benchmark CPU saturation.
- **Compute cost is dominated by ML inference** (Isolation Forest
  `score_samples`); for the ML-off cost see the generated ablation summary.
  **Bug fixed (2026-09):** before this fix `--no-model` / `model_path=None` silently
  loaded `models/isoforest.joblib` whenever it existed, so earlier "ML off" figures
  may not have been ML-off. The ablation above is regenerated with the fix.

## Caveats
- Metrics are on a *simulated* MAVLink link; they characterise the detection
  logic, not real-RF field performance. The external real-flight replays
  (`docs/EXTERNAL_DATA.md`) show that the production thresholds do **not**
  transfer to a real link without per-vehicle calibration.
- The 5 s grace is applied after **every** attack type, not only GPS; v2 reports
  the no-grace numbers so the effect is visible.
- Absolute recall depends on attack magnitudes in `configs/attacks.yaml`; weaker
  attacks lower recall and raise latency (re-run to measure).
