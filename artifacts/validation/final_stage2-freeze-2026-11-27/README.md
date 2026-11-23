# Freeze-tag evidence regeneration (#27)

Code under test: tag `stage2-freeze-2026-11-27` = `8e5800381c4abddc970cbf134d1e95e035a3becf`
(`feat(stage2 4/4): dual-mode operator console & HMAC-secured frontend command flow (#82)`). Every number below comes from
running that code on a clean tree (`working_tree_dirty: false` in every `run_manifest.json`). No source file was changed on
the branch; this folder only adds files.

This folder holds: `benchmarks/` and `heldout/` (this PR, items 1 and 4 of #27 and the determinism criterion) plus
`sweep/` and `replays/` (written on a companion branch and merged in by the lead; see the placeholders at the end).

Claim classes: the benchmark rows are **SIM**, link-level detection of synthetic attacks (extended benchmark: false-alarm and
detection rates over simulated sessions). The held-out rows are **SITL** (PX4 `v1.18.0-rc1-27-gc239c63807`, replayed
tlogs), false-alarm calibration only: **no attack data, no detection claim, no real-vehicle claim**.

## 1. Environment and inputs

| item | value |
|---|---|
| host | Windows 11, 12 logical CPUs, CPython 3.13.15, one machine for every run here |
| packages | aegisflight 0.1.0 (editable, this worktree), scikit-learn 1.9.1, numpy 2.5.3, scipy 1.18.1, joblib 1.6.0, pymavlink 2.4.50, pyyaml 6.0.3, fastapi 0.142.2, pyserial 3.5 |
| `models/isoforest.joblib` | sha256 `3fe74cddf3689e169610ffd783b109b6539cc6c03629bd1e4bb8b1d3842939c4` (matches `models/MODELS.sha256`) |
| `models/isoforest_px4.joblib` | sha256 `df540999dc6b43c3981d6ac6ecb91369b56ce1ba8cfdb894b76b195951260c7c` (matches `models/MODELS.sha256`) |
| model verification | `python scripts/fetch_models.py --verify-only` printed `ok` for both. Both files were copied from the maintainer checkout's `models/` (git-ignored), never trained locally |
| `configs/` sha256 (run_manifest `detector_profile_sha256`) | `ff7ed01ac5cfbf8310aa17ddefd4ed3269b3f99334c7132894a48e40ad2f7bf4` |
| `configs/detector.yaml` | `d5b52e66dff33f4106e275f5b09cbcfe6d635f7c094d2af0b0360d4a34550879` |
| `configs/px4_sitl/detector.yaml` | `34c210812a407520858a54fa1c8588aebcccde01038b2c5b7e7be5aeae5df52b` |
| `configs/px4_sitl/` directory sha256 | `eda294f6928b480688d48cedb613f89c5d748aa2a19ba7442bd1e0561884242f` |
| firmware allowlist sha256 | `63b01f5fe0cbb69e11b7e5a4fd1fe944bbe1756e3dcbe7e0113d63fd104788ad` |
| held-out tlogs | `data/sitl/raw/benign_006..010.tlog` (git-ignored; copied from the maintainer checkout; their sha256 equal the ones recorded in the committed `artifacts/sitl/calibration/evaluation_heldout.json`) |

Provenance (#25): `aegis benchmark`, `benchmark_extended.py` and `calib_evaluate.py` have no manifest option of their own, so each
was run through `benchmarks/tools/run_with_prov.py`, a thin wrapper that calls the repo's `aegisflight.run_provenance`
(`require_clean_tree`, `collect_run_provenance`, `finish_run`, `write_manifest`) around the unchanged command and writes
`<out>/run_manifest.json` (schema `aegisflight.run_manifest/1`: commit, tree-clean flag, model sha256, profile hash, command
line, python and package versions). All manifests here say `status: REPRODUCIBLE`, commit `8e580038...`, `exit_code: 0`.

## 2. Commands (all from the repo root on the tag; `PYTHONPATH=src:scripts`)

```
# Stage-1 regression (SIM)
python benchmarks/tools/run_with_prov.py --manifest-dir <out>/benchmarks/stage1 --model models/isoforest.joblib -- \
  python -m aegisflight.cli benchmark --out <out>/benchmarks/stage1 --no-figures
# Extended benchmark, ML off (SIM)
python .../run_with_prov.py --manifest-dir <out>/benchmarks/extended_ml_off -- \
  python scripts/benchmark_extended.py --no-model --workers 4 --out <out>/benchmarks/extended_ml_off
# Extended benchmark, ML on, shipped model (SIM)
python .../run_with_prov.py --manifest-dir <out>/benchmarks/extended_ml_on --model models/isoforest.joblib -- \
  python scripts/benchmark_extended.py --model models/isoforest.joblib --workers 4 --out <out>/benchmarks/extended_ml_on
# Determinism re-run (identical command, second run; section 5)
python .../run_with_prov.py --manifest-dir <out>/benchmarks/determinism_rerun_ml_on --model models/isoforest.joblib -- \
  python scripts/benchmark_extended.py --model models/isoforest.joblib --workers 4 --out <out>/benchmarks/determinism_rerun_ml_on
# PX4 SITL held-out evaluation, unchanged script, output redirected (section 6)
python .../run_with_prov.py --manifest-dir <out>/heldout --model models/isoforest_px4.joblib --profile configs/px4_sitl -- \
  python <out>/heldout/run_heldout_redirect.py <out>/heldout
```
`<out>` = `artifacts/validation/final_stage2-freeze-2026-11-27`. (`run_manifest.json` `command_line` fields show the absolute
paths the commands were actually launched with; the two helper scripts were launched from a scratch directory and are
committed here under `benchmarks/tools/` and `heldout/`.)

## 3. Stage-1 regression and extended benchmark (SIM)

| artifact | what | headline |
|---|---|---|
| `benchmarks/stage1/summary.md` | `aegis benchmark`, ML on | TP / FP / TN / FN = **6535 / 4 / 16826 / 65**, identical to the baseline (`artifacts/benchmarks/summary.md`) |
| `benchmarks/extended_ml_on/summary.md` | 116 sessions, ML on (3fe74cdd...) | v2 no grace: **9072 / 462 / 42217 / 1149** (FPR 0.0108); v2 5 s grace: 9072 / 39 / 40813 / 1149 (FPR 0.0010) |
| `benchmarks/extended_ml_off/summary.md` | 116 sessions, ML off | v2 no grace: **8025 / 355 / 42324 / 2196** (FPR 0.0083); v2 5 s grace: 8025 / 3 / 40849 / 2196 (FPR 0.0001) |

Benign false-alarm rows (decision level, from the same summaries):

| condition | ML on FP / decisions | ML off FP / decisions |
|---|---|---|
| `benign` (12 sessions) | 4 / 6900 (0.06 %) | 0 / 6900 |
| `link_fifo_benign` (6 sessions, 2 % loss, FIFO) | 2114 / 3450 (61.28 %) | 1 / 3450 (0.03 %) |
| `link_reorder_benign` (6 sessions, 2 % loss, reordering) | 3369 / 3450 (97.65 %) | 0 / 3450 |

The ML-on figures replace the ones that #31 flagged as coming from model `bafad273`: every ML-on number here comes from the
verified shipped model `3fe74cdd...` (also recorded in each `results.json` `config.model_sha256`). The per-configuration link-stress
grid (loss x FIFO/reorder x ML x profile) is the sweep, not this table.

Compute figures (mean 1.08 ms/decision ML on, 1.11 ms ML off, in each `summary.md`) are machine-dependent and not a benchmark
claim.

## 4. 470 vs 463 no-grace false positives: explained, and a third value (462) on the tag

Question (issue #27): why does the committed `artifacts/benchmarks_extended/summary.md` say no-grace FP/TN 470 / 42,209 while re-runs give 463 / 42,216?

**Answer: different code, not non-determinism.** Evidence: `benchmarks/bisect_470_vs_463/` (`bisect_report.md`, per-step
`summary_<commit>.md`, per-session diffs `diff_*.txt`). Each row is a full 116-session, ML-on extended run of that commit in a
read-only scratch worktree (no commits from them), shipped model `3fe74cdd...`, same machine; the comparison is of the
decompressed 69,600-row `decisions.csv`.

| code | decisions md5 | v2 no-grace TP / FP / TN / FN |
|---|---|---|
| committed `artifacts/benchmarks_extended/` | `29a662b74e71` | 9088 / **470** / 42209 / 1133 |
| `41311fa` (commit that generated it), re-run | `29a662b74e71` (**identical, 0 of 69,600 rows differ**) | 9088 / 470 / 42209 / 1133 |
| `444f385` (= `eae85e6^`) | `29a662b74e71` (identical) | 9088 / 470 / 42209 / 1133 |
| `eae85e6` | `db9c672c099f` | 9088 / **463** / 42216 / 1133 |
| `8605cea` | `db9c672c099f` (identical to `eae85e6`) | 9088 / 463 / 42216 / 1133 |
| `3a10573` (#79) | `477a2eb732fe` | 9072 / **462** / 42217 / 1149 |
| `03e4de9` (#80), `63241a1` (#81), `b6d2ab7` (#112) | `477a2eb732fe` (identical to `3a10573`) | 9072 / 462 / 42217 / 1149 |
| **`8e58003` = freeze tag** | `477a2eb732fe` (identical to `3a10573`) | 9072 / **462** / 42217 / 1149 |

How it was run: `benchmarks/tools/bisect.sh` (`SCRATCH=<dir> bash bisect.sh`: one `git worktree add --detach <commit>` per commit under `$SCRATCH/wt/c<commit>`, the shipped model copied in,
`benchmark_extended.py --model models/isoforest.joblib --workers 4`; the second batch `8605cea 03e4de9 63241a1 b6d2ab7` and the `41311fa` retry used `--workers 3`, which section 5 shows does not matter), then
`benchmarks/tools/make_bisect_report.py`. md5 values in this README are of the files as written on Windows (CRLF line endings); git stores the text files with LF, so `md5sum` of the checked-out files can differ on other platforms. The `decisions md5` in the
bisect table is of the decompressed text and is only used to compare runs made on this machine.

1. **470 -> 463 was commit `eae85e6`** (2026-10-10, "skip position-residual and yaw/course checks across a >2 s link gap",
   `features/extractor.py`). It was committed without regenerating the extended artifact, so the committed files describe
   `41311fa`, not later code. Only sessions 76-79 (`dos:blackout`) change (228 rows, in post-attack rows; net -7 FP); benign,
   `link_*` and every other session are bit-identical. The 5 s-grace FP (39) does not change. This confirms the 2026-11-21 finding on #27.
2. **463 -> 462 (and 9088 -> 9072 TP) happened in commit `3a10573`** (#79, `feat(stage2 1/4): detectors, integrity allowlist, ...`; a large commit touching detectors, features and the benchmark reporting code, see the note below).
   It changed 3,992 decision rows across `mavlink_anomaly:rate_spike`, `seq_scramble`, `dos:flood`, `dos:blackout`,
   `dos:latency`, one combo session and the six `link_reorder_benign` sessions (`diff_8605cea__3a10573.txt`). The freeze tag
   is bit-identical to `3a10573` on this benchmark: #80, #81, #112 and #82 do not change a single decision row.
   So **the freeze-tag value is 462 / 42,217, not 463**. Neither 470 nor 463 is the figure for the tag.
3. Side effects of #79 that are visible in this benchmark and that the report should not hide (ML on, 5 s grace, per-mode table):
   `dos:latency` decision recall 99.77 % -> 97.07 %, `mavlink_anomaly:seq_scramble` 100.00 % -> 99.11 %, overall recall
   0.8891 -> 0.8876; in `link_reorder_benign` the false-alarm class mix moved from `MAVLINK_ANOMALY` 3328 / `DOS` 121 to
   `DOS` 3361 / `TELEMETRY_MANIPULATION` 7 / `GPS_SPOOFING` 1, and the FP count from 3449 to 3369 of 3450 (still 97.65 %).
   Not investigated further here (a detector-owner question, not a validation one).
4. The committed compute figures (23.4 ms/decision) are not comparable to a fresh run (1.1 ms): wall time of the old run was
   222.7 s on 8 workers, the tag run 33.4 s on 4 workers; not isolated, not claimed.
5. `artifacts/benchmarks_extended/` was **not** modified (outputs here are in the new folder only). Whether to regenerate it in place is for the lead.

Correction to the #27 comment of 2026-11-21: it states "the extended-benchmark code (`extended.py`, `extended_report.py`,
`scripts/benchmark_extended.py`) has had no commits since `41311fa`". That holds up to `8605cea` (`git diff 41311fa 8605cea -- src/aegisflight/benchmark`
is empty) but not for `3a10573` (#79), which also edits `benchmark/extended.py`, `runner.py`, `harness.py` and `dataset.py`
(`git diff 8605cea 3a10573 --stat -- src/aegisflight/benchmark`). By reading the diff those edits only add reporting fields
(`ml_loaded`/`ml_sha256`, hierarchical attribution columns) and an `allow_unverified_model` pass-through; the same commit also changes detectors, so this bisect
cannot separate a benchmark-code effect from a detector effect inside `3a10573` by a run. The 470 -> 463 step is unaffected (it is `eae85e6`, before any benchmark-code edit).

## 5. Determinism (extended benchmark, ML on, full 116-session run)

| comparison | decisions.csv (69,600 rows) | sessions.csv | results.json minus timing/workers |
|---|---|---|---|
| run A (`extended_ml_on`, 4 workers) vs run B (`determinism_rerun_ml_on`, same command, 4 workers) | **identical**, md5 `477a2eb732fe3b33d06c360175d72b7d`, 0 differing rows | identical, md5 `5c66cacb78eb17962dab782e6a9f2d3f` | identical |
| run A vs a third run with `--workers 1` (scratch; compare file only) | identical, same md5 | identical | identical |

Files: `benchmarks/determinism_compare_A_vs_B.json`, `benchmarks/determinism_compare_A_vs_workers1.json`, produced by
`benchmarks/tools/cmp_runs.py <dirA> <dirB> --json <out>`. The compare script ignores only wall-clock fields
(`wall_time_s`, `workers`, per-session `compute_*`/`wall_s`); `decisions.csv` has no timing column, so it is compared byte for byte.
Result: **run-to-run determinism holds** on this machine for identical inputs, and the result does not depend on the worker count.
Scope: one machine, one Python/numpy/sklearn combination; not a cross-platform claim.

## 6. PX4 SITL calibration held-out evaluation, re-run on the tag (SITL, link-level false-alarm calibration only)

Command: `scripts/sitl/calib_evaluate.py --set heldout`, **unchanged**, run through `heldout/run_heldout_redirect.py`, which only
re-points `calib_common.OUT_DIR` at `heldout/` (and copies the committed `derivation.json` there, because the script hashes it).
Reason: the script's own output directory is the committed `artifacts/sitl/calibration/`, it refuses to run while
`heldout_lock.json` exists there, and `--burned` would overwrite that lock and `evaluation_heldout.json`. Nothing under
`artifacts/sitl/` was touched.

Result (`heldout/evaluation_heldout.json`; 5 flights `benign_006..010`, 2805 decisions, all benign, so every flagged decision is a false alarm):

| cond | description | FA decisions now (tag) | per flight now | FA decisions committed (2026-10-06 run) |
|---|---|---|---|---|
| A | Stage-1 config + Stage-1 model | 2805 / 2805 | 483, 736, 550, 631, 405 | 2805 (same) |
| B | PX4 profile, ML off | **0** / 2805 | 0, 0, 0, 0, 0 | 1 |
| B2 | PX4 profile + Stage-1 model (diagnostic) | **0** / 2805 | 0, 0, 0, 0, 0 | 2710 |
| C | PX4 profile + PX4-benign model | **0** / 2805 | 0, 0, 0, 0, 0 | 1 |

(`heldout/comparison_with_committed.txt` has the full comparison.) **This is not an "unchanged inputs" reproduction, and must not be quoted as one.**
The committed held-out result was produced on 2026-10-06 against a PX4 profile that has since changed:
`configs/px4_sitl/detector.yaml` gained `gnss_never_acquired_policy: coverage` (D3), `xmsg_checks: true`, `heading_yaw_tolerance_deg: 20.0` and
`fusion.ml_require_corroboration: true` (D5, #49) in `3a10573`/`8e58003`; `configs/detector.yaml`, `derivation.json` and the detector code also changed.
The differences in B/B2/C follow from that: with ML corroboration required, a lone ML vote (the 96.6 % `msg_rate_hz` saturation of the Stage-1 model, B2)
no longer becomes an alert, and the single sequence-gap false alarm (`max_seq_gap >= 30` decisions: 1 -> 0) is gone.
Condition A, which uses the Stage-1 defaults, is identical to the committed result (including the per-flight counts), a useful sanity check.
Decision latency in the new file (about 0.4-1.3 ms mean) is not comparable with the committed one (13-14 ms); it is load- and machine-dependent and is not a result.

Because the profile and `derivation.json` were modified after the 2026-10-06 held-out evaluation, these five flights are **no longer a pristine held-out
set for the current profile**: this run is a regression re-run on them. The headline for the report is therefore "0 false-alarm decisions in 2805 on the
five held-out flights under the tag's profile (re-run, not a fresh held-out)", with the committed calibration-set vs held-out statements left as they are.

### Held-out locks (note for #49)
* `artifacts/sitl/calibration/heldout_lock.json` (PX4 calibration, 2026-10-06) is **stale against the tag** and was **not edited**:
  `profile_yaml_sha256` 4f18f3f0... (now `34c21081...`), `stage1_detector_yaml_sha256` bc9a4d26... (now `d5b52e66...`), `derivation_json_sha256` acb39236... (now `f1cd677c...`).
* #49's ArduPilot/PX4 in-flight lock `artifacts/ardupilot/calibration/heldout_lock.json` (2026-11-18, written by `scripts/evaluate_inflight_fa_per_hour.py`) is also stale against the tag
  (ArduPilot profile `c5cfd220...` vs `e9e83719...`, PX4 profile `94a60c9b...` vs `34c21081...`, `configs/detector.yaml` `12948921...` vs `d5b52e66...`, `anomaly.py` `f5d55dc0...` vs `1121cb56...`;
  `fusion/engine.py` unchanged `8f157851...`). This matches the acceptance verdict already posted on #49.
* **Did this run refresh them? No.** `calib_evaluate.py --set heldout` writes its lock only into its (redirected) output directory; `heldout/heldout_lock.json` here is that by-product
  (`held_out_burned: false` only because the redirected directory had no earlier lock) and is a record of this run's frozen inputs, **not** a replacement for the single-use lock.
  The documented refresh path for either lock is `--burned` on the owning script, which rewrites the lock and marks the set burned; that is a maintainer decision (#49 open item) and was not taken.
  `scripts/evaluate_inflight_fa_per_hour.py` was **not run**.

## 7. Problems met while producing this (recorded, not hidden)
* First attempt of the scratch `41311fa` run crashed in a worker with `OSError: [Errno 22] Invalid argument` opening a temp firmware `.bin` (Windows temp-file race while another 4-worker run was active). Re-run on its own succeeded and reproduced the committed artifact exactly.
* First attempt of `determinism_rerun_ml_on` crashed with `MemoryError` in a worker (two 4-worker benchmark jobs plus the bisect were running concurrently). Its output was deleted and the identical command was re-run alone; the committed `determinism_rerun_ml_on` is that second, clean run (`exit_code: 0`). No result was selected or discarded for its value.
* The committed `benchmarks/determinism_compare_A_vs_workers1.json` references a scratch path for run C (not committed; md5 equal to run A as stated).
* `aegis benchmark`, `benchmark_extended.py` and `calib_evaluate.py` have no built-in manifest (#25 gap); the wrapper above is the workaround. Not fixed here (no code changes on this branch).

## 8. Files
```
README.md
benchmarks/stage1/            aegis benchmark output + run_manifest.json
benchmarks/extended_ml_on/    extended benchmark, shipped model (+ run_manifest.json)
benchmarks/extended_ml_off/   extended benchmark, --no-model (+ run_manifest.json)
benchmarks/determinism_rerun_ml_on/, determinism_compare_A_vs_B.json, determinism_compare_A_vs_workers1.json
benchmarks/bisect_470_vs_463/ per-commit summaries, per-session diffs, bisect_report.md
benchmarks/tools/             run_with_prov.py, cmp_runs.py, cmp_sessions.py, bisect.sh, make_bisect_report.py
heldout/                      evaluation_heldout.json, run_manifest.json, heldout_lock.json (by-product), derivation.json (copy), comparison_with_committed.txt, helper scripts
```

## 9. Placeholders for the companion branch (lead fills in)
* `sweep/` : link-stress sweep (loss x FIFO/reorder x ML on/off x Stage-1/PX4/ArduPilot profiles; decision FPR, alert events per hour, dominant evidence string). **Not in this PR.**
* `replays/` : bench captures 005-009 and the 28 Oct run, #29 walk/range captures, the 5 ArduCopter benign tlogs, ALFA, PX4 Flight Review. **Not in this PR.**
* Final `aegis-reviewer` verdict ("supported") : **pending**.
