# Issue #49 acceptance package: in-flight false alerts per hour

**Status: PENDING MAINTAINER DECISION (D1 / D2 / B5).** Audit date 2026-11-27, against `main` `024baab`
(freeze tag `stage2-freeze-2026-11-27` = `8e58003`; `src/` and `configs/` are byte-identical between the two).
Nothing in `src/`, `configs/`, `models/`, `.github/` or `artifacts/` was changed to produce this page. No flights, no SITL
and no PX4 were run. This page changes no number; it re-derives them and lists what is and is not supported.

Environment tag for every figure below: `SITL` (benign streams; the PX4 rows are `SITL (replayed tlog)`).
Claim class: **link-level detection**, used only as a benign false-alarm reference. It is not flight-hour evidence, not a
real-vehicle result and not an estimator or physical-deviation result. Exposure is 0.04 to 0.25 h per row.

## 1. Verdict in one paragraph

The ArduPilot cause and fix are supported: on the recorded benign runs the Stage-1 Isolation Forest alone produced every
post-boot alert event, and re-fusing the same logged scores under `configs/ardupilot_copter` (ML off, plus
`fusion.ml_require_corroboration: true`) gives 0 events with Poisson 95% upper bounds of 12.21 to 42.49 per hour, within the
50/h target. Three things limit what can be claimed: (1) the "after" numbers are **re-fusion of recorded Stage-1 detector
scores, not fresh flights or a fresh replay through the detectors**, so the profile's protocol and physics overrides are not
exercised; (2) the PX4 calibration-set bound is **52.13/h, above the 50/h target**, and its event count is inferred from
decision counts; (3) the held-out lock is stale against current files and the `held_out_burned` flag does not mean what its
name says. The issue can close **without any frozen-code change** once the maintainer records D1/D2/B5 (section 7); it should
not be described as "0 false alerts per hour" in the report.

## 2. Commands re-run for this audit

| Command | Result |
|---|---|
| `python -m pytest tests/unit/test_inflight_fa_per_hour.py tests/unit/test_calib_derive_profile.py` | `9 passed in 1.26s` |
| `python scripts/evaluate_inflight_fa_per_hour.py --out-dir <scratch>/out --ap-calib-dir <scratch>/calib` (both outputs redirected outside the repo; a fresh scratch lock means `--burned` is not needed; `git status` clean afterwards) | Wrote scratch `metrics.json` and `summary.md`. Every number in `metrics.json`, `evaluation_calib.json`, `evaluation_heldout.json` equals the committed copy; `summary.md` is identical except the `held_out_burned` token. Only `generated_utc` and the `frozen_inputs` hashes differ (the current files hash differently from the ones at commit time, section 5) |
| Poisson bound recomputation (section 4) | Every committed `fa_per_hour_poisson95_upper` reproduced to 2 decimals |
| `git show <commit>:<path> | sha256sum` and `sha256sum <path>` for the five locked inputs | Section 5 |
| Full `python -m pytest` and `ruff check src tests scripts backend` | Section 9 |

## 3. Claims checked

| # | Claim | Result | Evidence |
|---|---|---|---|
| C1 | The ArduPilot false-alert cause is ML-only votes with no corroboration | **Confirmed for post-boot alerts** | `summary.md:36` (section 2 of the artifact): 171/171 post-boot and 120/120 airborne alert events had `ml_anomaly` as the only detector at or above 0.5 (attribution `{'ml_anomaly': 171}` and `{'ml_anomaly': 120}`, `summary.md:13-14`). Across all phases it is 171 of 201 events (85%); the other 30 are start-up protocol/physics alerts or ML plus another detector (`summary.md:12`). Cause confirmed on 5 runs, 0.19 h |
| C2 | It is addressed by ML disablement plus `ml_require_corroboration` | **Confirmed as configuration and as re-fused outcome; not as a fresh run** | `configs/ardupilot_copter/detector.yaml:22-25` sets `anomaly.enabled: false` and `fusion.ml_require_corroboration: true`; the gate is `src/aegisflight/fusion/engine.py` (added in `8bdb380`). Each mechanism alone gives 0 events from arm: profile (ML off) in `summary.md:19-25`; Stage-1 ML kept on with only the corroboration gate, 5 runs, 0 from-arm and 0 airborne events, upper 16.68/h and 24.50/h (`summary.md:26`). Both are re-fusion (section 6) |
| C3 | Zero in-flight false alerts in the relevant ArduPilot "after" evidence | **Confirmed by the artifact's definition, with three qualifiers** | Benign, 7 runs, `from_arm_phase` and `airborne_only`: 0 events (`summary.md:19-25`). Qualifiers: (a) 2 of the 7 runs (`ap_benign_final_noml_001/002`) were recorded with ML already off, so they are unchanged by the fix; the fix changed 5 runs. (b) All-phase events remain: 33 events in 0.26628 h, 123.93/h, upper 165.71/h (section 4); these are start-up alerts (boot/await_gps, #15 scope). (c) A pre-onset alert exists in `ap_attack_drift_002` (C9) |
| C4 | PX4 held-out: 0 events, upper 24.32/h | **Confirmed, airborne only** | Airborne: 0 events in 443.4 s, 2.9957/0.123167 h = 24.32/h. All phases the held-out set has 1 event, upper 30.44/h (`summary.md:30`). The 1 event is a "sequence gap" alert outside the airborne window |
| C5 | PX4 calibration: 2 events, 52.13/h (> 50/h) | **Confirmed arithmetic; the event count is inferred** | Both false-alarm decisions are in one flight (`benign_001.tlog`, evidence "sequence gap # > #", `artifacts/sitl/calibration/evaluation_calib.json`). 6.2958/0.120778 h = 52.13/h exceeds the 50/h target by 4.3%. If the two decisions fell inside one 4.0 s cooldown the count would be 1 event and the bound 39.28/h; the evaluation JSON has no decision timestamps, so this cannot be decided from committed files |
| C6 | ArduPilot calibration bound 42.49/h, held-out 31.13/h, pooled 17.97/h | **Confirmed** | Section 4 (airborne; from-arm bounds are 28.68, 21.26, 12.21) |
| C7 | PX4 event counts were inferred from decisions by cooldown grouping | **Partly refuted: not grouped, and two different rules** | `scripts/evaluate_inflight_fa_per_hour.py:214-221`. If a condition has 5 or fewer false-alarm decisions (conditions B, C), events are set equal to the false-alarm **decision count** (labelled "exact", assuming isolated decisions more than 4.0 s apart; not checked, no timestamps). Otherwise (condition A, saturated) events = per flight `max(1, round(false_alarm_decisions * 0.2 / 4.2))`, a duration heuristic, not a count: condition A has 100% of decisions flagged (2760/2760 calib, 2805/2805 held-out). No decision rows are read; the script reads only the committed evaluation JSONs. The ArduPilot rows are different: they count recorded `alert` flags (before) or `FusionEngine.is_alert` events (after), which do include the 4.0 s per-attack-type cooldown (`configs/detector.yaml:143`) |
| C8 | Which "after" results are fresh versus re-fusion | See section 6 | No new live flights were flown for #49: all 14 ArduPilot runs were collected 2026-10-06 to 2026-10-10 (`artifacts/validation/stage2_metrics_2026-11-17/metrics.md:16-25`), before the issue (2026-11-17) and before the approval comment (2026-11-18) |
| C9 | A pre-onset alert in `drift_002` | **Confirmed, benign-timeline alert not included in the benign exposure** | `metrics.json` `drift_attack_regression`, trial `ap_attack_drift_002`, `profile_pre_onset_inflight_alerts: 1` (`summary.md` section 3, last-but-one row; the table shows `1` with no comment). Reproduced: `physics_consistency` = 1.0, type `GPS_SPOOFING`, phase `arm`, t = 10.0 s, onset 61.13 s. It is present in the recorded run as well, so the profile did not cause it. The original `evaluation.json` records 0 pre-onset in-flight alerts because it counts a narrower phase set. Sensitivity (computed here, command in section 4): adding the 6 drift flights' pre-onset from-arm time (0.0806 h, 1451 decisions) to the 7 benign runs gives 1 event in 0.32594 h, 3.07/h, upper 14.55/h; airborne only gives 0 events, upper 15.73/h. Still within 50/h, but "0 from-arm events" does not hold for that pooling |
| C10 | Stale locks and `held_out_burned: false` | **Confirmed** | Section 5 |
| C11 | Maintainer approval before tuning is not documented | **Partly confirmed**: an approval comment exists and precedes the commit by 6 minutes, but it is by the implementer's account and not linked to a maintainer message | Section 7.1 |
| C12 | Reporting disclosures missing | **Confirmed** | Section 8 |

## 4. Recomputed Poisson upper bounds

Method: one-sided 95% upper bound on the rate = `chi2.ppf(0.95, 2(k+1)) / 2 / hours`, with `hours = decisions * 0.2 s / 3600`
(`PERIOD_S = 0.2`, `scripts/evaluate_inflight_fa_per_hour.py:39`). `chi2.ppf(0.95, 2)/2 = 2.9957` (k = 0), `chi2.ppf(0.95, 4)/2 = 4.7439`
(k = 1), `chi2.ppf(0.95, 6)/2 = 6.2958` (k = 2), `chi2.ppf(0.95, 242)/2 = 139.6438` (k = 120). Computed with `scipy.stats.chi2` from
the `alert_events` and exposure seconds in the committed `metrics.json`; all values equal the committed ones.

Airborne window (`takeoff`, `square`, `rtl`), the stricter in-flight figure, is the D1 comparison:

| Stack | Set | Config | Events (k) | Exposure | Arithmetic | Rate /h | 95% upper /h | Source |
|---|---|---|---:|---:|---|---:|---:|---|
| ArduPilot | calibration, 3 runs | `ardupilot_copter` | 0 | 253.8 s = 0.070500 h | 2.9957 / 0.070500 | 0.00 | **42.49** | `artifacts/ardupilot/calibration/evaluation_calib.json` |
| ArduPilot | held-out, 4 runs | `ardupilot_copter` | 0 | 346.4 s = 0.096222 h | 2.9957 / 0.096222 | 0.00 | **31.13** | `.../evaluation_heldout.json` |
| ArduPilot | pooled, 7 runs | `ardupilot_copter` | 0 | 600.2 s = 0.166722 h | 2.9957 / 0.166722 | 0.00 | **17.97** | `artifacts/validation/inflight_fa_per_hour_20261119/metrics.json` (`after_profile_all_7runs`) |
| ArduPilot | 5 ML-on runs, ML forced on + corroboration | `ardupilot_copter` | 0 | 440.2 s = 0.122278 h | 2.9957 / 0.122278 | 0.00 | 24.50 | same, `after_profile_forced_ml_with_corroboration_5runs` |
| ArduPilot | 5 ML-on runs, before | Stage-1, ML on | 120 | 440.2 s = 0.122278 h | 139.6438 / 0.122278 | 981.37 | 1142.02 | same, `before_stage1_ml_on_pooled_5runs` |
| ArduPilot | 2 ML-off runs, before | Stage-1, ML off | 0 | 160.0 s = 0.044444 h | 2.9957 / 0.044444 | 0.00 | 67.40 | same, `before_stage1_ml_off_pooled_2runs` |
| PX4 | calibration, 5 flights (in-sample) | `px4_sitl`, cond B and C | 2 (inferred) | 434.8 s = 0.120778 h | 6.2958 / 0.120778 | 16.56 | **52.13** | `artifacts/sitl/calibration/evaluation_calib.json` |
| PX4 | held-out, 5 flights | `px4_sitl`, cond B and C | 0 | 443.4 s = 0.123167 h | 2.9957 / 0.123167 | 0.00 | **24.32** | `artifacts/sitl/calibration/evaluation_heldout.json` |
| PX4 | calibration, before | Stage-1 + Stage-1 ML (cond A) | 104 (heuristic) | 434.8 s | 122.4038 / 0.120778 | 861.09 | 1013.46 | same as calibration row |
| PX4 | held-out, before | cond A | 105 (heuristic) | 443.4 s | 123.4840 / 0.123167 | 852.50 | 1002.58 | same as held-out row |

No pooled PX4 figure is committed. `docs/CALIBRATION_PX4.md` section 2 says calibration (in-sample) and held-out numbers are never merged, so none is
quoted here.

From-arm and all-phase figures (same method, same sources):

| Stack | Set | Window | k | Exposure h | 95% upper /h |
|---|---|---|---:|---:|---:|
| ArduPilot after | calibration | from arm | 0 | 0.10444 | 28.68 |
| ArduPilot after | held-out | from arm | 0 | 0.14089 | 21.26 |
| ArduPilot after | pooled 7 | from arm | 0 | 0.24533 | 12.21 |
| ArduPilot after | pooled 7 | all phases | 33 | 0.26628 | 165.71 (rate 123.93) |
| ArduPilot after | calibration / held-out | all phases | 14 / 19 | 0.11350 / 0.15278 | 192.83 / 182.48 |
| PX4 after | calibration / held-out | all phases | 2 / 1 | 0.15333 / 0.15583 | 41.06 / 30.44 |

Sensitivity for C5 (computed here): 1 event in 0.120778 h gives 4.7439 / 0.120778 = 39.28/h.

## 5. Held-out lock and `held_out_burned`

Locked inputs in `artifacts/ardupilot/calibration/heldout_lock.json` (also copied into `metrics.json` and both evaluation JSONs)
against `8bdb380` (the commit that created the lock, 2026-11-18T23:59:53Z), the freeze tag `8e58003` and this worktree:

| Input | Lock value | At `8bdb380` | At `8e58003` and `024baab` | Match at tag |
|---|---|---|---|---|
| `configs/ardupilot_copter/detector.yaml` | `c5cfd220...` | `c5cfd220...` | `e9e83719...` | no |
| `configs/px4_sitl/detector.yaml` | `94a60c9b...` | `94a60c9b...` | `34c21081...` | no |
| `configs/detector.yaml` | `12948921...` | `12948921...` | `d5b52e66...` | no |
| `src/aegisflight/detectors/anomaly.py` | `f5d55dc0...` | `f5d55dc0...` | `1121cb56...` | no |
| `src/aegisflight/fusion/engine.py` | `8f157851...` | `8f157851...` | `8f157851...` | yes |

Findings:

1. The lock was **correct when written** (every hash equals the file at `8bdb380`) and is **stale against the tag**. The only
   change to the ArduPilot profile since is the added `gnss_never_acquired_policy: coverage` (D3). The numbers still reproduce
   on the tag (section 2), because the evaluation re-fuses recorded scores through an unchanged `engine.py`; the lock does not
   certify the detectors now on `main`. `anomaly.py` and `physics`/`protocol` code changed after the lock, and those changes
   are not exercised by this evidence at all (section 6).
2. `held_out_burned: false` in `metrics.json`, both evaluation JSONs and `summary.md:6` is set by the script only when `--burned` is
   passed (`scripts/evaluate_inflight_fa_per_hour.py:341-351`); it is not an indicator that the held-out set was or was not
   scored. The held-out set **was** scored (`evaluation_heldout.json`). `tests/unit/test_inflight_fa_per_hour.py:106` asserts
   `False`, and its lock check compares the committed `metrics.json` with the committed lock, so it cannot detect staleness.
3. The lock is written by the same process, about 150 ms before the evaluation (`locked_utc` 23:59:32.83Z, `generated_utc`
   23:59:32.98Z). "Frozen before the run" holds only in that sense. The held-out ML-on runs (`ap_benign_six_003`, `_004`,
   `groups_001`) were also inspected in step 1 and used for the root-cause statement (`summary.md:36` covers all 5 ML-on runs).
   The split was assigned after all runs had been recorded and inspected. This is not a pristine held-out evaluation. The fix
   is a switch (ML off, corroboration on), not a fitted threshold, which limits the leakage risk but does not remove the point.
4. PX4: `artifacts/sitl/calibration/heldout_lock.json` (2026-10-06) also says `held_out_burned: false`; its profile hash
   `4f18f3f0...` differs from both the `#49` lock's PX4 hash (`94a60c9b...`) and the current profile. The PX4 numbers in the
   `#49` table are the 2026-10-06 evaluation of an earlier PX4 profile version. The `#177` re-run on the tag
   (`artifacts/validation/final_stage2-freeze-2026-11-27/heldout/`, 5 flights, 2805 decisions): condition B, B2 and C all 0
   false alarms, A 2805. It re-used already-scored flights and is a regression re-run, not a fresh held-out result. No
   calibration-set re-run on the tag exists: **not run**.
5. The PX4 raw `.tlog` files are git-ignored (`.gitignore:31`, `data/sitl/raw/*.tlog`), so the PX4 rows cannot be regenerated
   from a fresh clone. The ArduPilot rows can (they read committed `decisions.jsonl`).

## 6. Fresh replay versus re-fusion

| Result | How it was produced | Fresh flight? | Fresh replay through detectors? | Notes |
|---|---|---|---|---|
| ArduPilot "before" (ML on 5 runs, ML off 2 runs) | Reads the recorded `alert` flag and `detector_scores` of committed `decisions.jsonl` (live runs, 2026-10-10, Stage-1 default config, `configs_sha256 f9f7de15...`) | No | No | The 4.0 s cooldown was applied at recording time |
| ArduPilot "after" (calibration, held-out, pooled, from-arm, airborne) | `_refuse_under_profile`: loads the profile, builds a `FusionEngine`, feeds the **recorded** four detector scores through it. ML score is zeroed when `anomaly.enabled: false`; the first-heartbeat protocol sentinel at t <= 1.8 s is zeroed inside `startup_grace_s` (`scripts/evaluate_inflight_fa_per_hour.py:104-126`) | No | **No**: protocol, physics and integrity are not re-run | Profile keys `auto_rate_baseline`, `yaw_course_enabled`, `xmsg_checks`, `battery_rise_v`, `startup_grace_s` (beyond the sentinel) have **no effect** on these numbers. What is measured is: ML gating, the corroboration gate, and fusion on Stage-1 scores |
| ArduPilot "forced ML + corroboration" | Same re-fusion with `keep_ml_scores=True` | No | No | The recorded ML scores are the Stage-1 model's |
| ArduPilot drift regression 6/6, delta 0.0 s | Same re-fusion of recorded drift runs | No | No | The drift runs were recorded with `--no-ml` (`manifest.json`), so ML gating cannot change them; delta 0.0 s is by construction. It shows the fusion gate does not suppress the physics-only drift alert, which is useful but weaker than a fresh profile run |
| PX4 conditions A, B, C (calibration and held-out) | Read from committed `evaluation_{calib,heldout}.json`, produced 2026-10-06 by `scripts/sitl/calib_evaluate.py` replaying recorded tlogs through the full pipeline | No | Yes, in 2026-10-06 (profile `4f18f3f0...`, not the current one) | Events inferred from decision counts (C7). Not re-derived by `#49` script |
| `#177` PX4 held-out on the tag | `calib_evaluate.py --set heldout`, output redirected | No | Yes, on `8e58003` | Held-out only; not pristine; B/B2/C = 0 of 2805 |

No new live SITL flight was flown for #49. The issue's step 1 asked to "re-run" the benign ArduPilot SITL (n >= 3) and the PX4
set; the evidence reuses the 2026-10-06/10 recordings instead (stated in the `#49` closure check, not in the artifact header).

## 7. Maintainer decisions required: D1 / D2 / B5

### 7.1 What is documented about approval (D1 and D2)

The approval text on #49 (comment 2026-11-18T23:53:52Z, account `madhavchoudhary2007-netizen`):

- **D1 (in-flight false-alert target):** "0 in-flight false alert events on the benign SITL flights (95% one-sided Poisson upper
  bound <= 50/h over the pooled ~0.06-0.18 h SITL exposure)."
- **D2 (approach):** "Both": update `configs/ardupilot_copter/detector.yaml` with calibrated ArduCopter SITL thresholds and ML gating
  (`anomaly.enabled: false` by default on ArduCopter unless a calibrated vehicle model is provided, plus
  `fusion.ml_require_corroboration: true` on vehicle profiles), evaluate calibration versus frozen held-out sets with
  `heldout_lock.json`, verify drift detection does not regress, and add the per-hour and per-detector attribution tables under
  `artifacts/validation/inflight_fa_per_hour_20261119/` and `scripts/make_stage2_metrics.py`.

Timeline (all UTC; sources: `gh api repos/TeamArdra/aegis-flight/issues/49/comments` and `/events`, `git log`):

| Time | Event | Account |
|---|---|---|
| 2026-11-17 14:21:57 | Issue created; `needs:human-approval` set | implementer |
| 2026-11-18 23:53:52 | D1/D2 "Maintainer approval confirmed" comment | implementer |
| 23:53:54 | `needs:human-approval` removed, `agent-ready` added | implementer |
| 23:53:59 / 23:54:01 / 23:54:02 | claim comment, assignment, `status:in-progress` | implementer |
| 23:59:32 | lock written and evaluation generated (`locked_utc`, `generated_utc`) | script |
| 23:59:53 | commit `8bdb380` (profile, script, `src/` gate, artifacts, tests, docs in one commit) | implementer |
| 2026-11-19 00:02:00 | `status:in-review` | implementer |
| 2026-11-22 10:00:56 | first comment by the maintainer account (`RajTib`): closure check | maintainer |

What is documented: an approval statement with the target and the option exists and is timestamped **before** the commit
(by 6 minutes 1 second). The issue body already named the options. The 2026-11-22 closure check treats it as the approval.

What is not documented:

1. The approval comment, the label change and the work all come from one account within 10 minutes. No maintainer-account
   statement on #49 predates the work, and the comment cites no message, meeting or decision record for the "maintainer"
   source. `AGENTS.md` section 7 requires approval of the approach **before** code for `needs:human-approval` issues.
2. The target is stated as an outcome ("0 events ... <= 50/h"), not as a number derived from a requirement. The 50/h value has
   no cited source.
3. Whether the ML-gating design existed before the comment cannot be shown; the only time anchor is the single commit 6
   minutes later. The profile-only precursors (`xmsg_checks`, `yaw_course_enabled`) were in `main` from `6ef7600`
   (2026-11-18 11:58 UTC, #39), earlier than the approval.
4. `8bdb380` also added `startup_grace_s: 3.0` and `battery_rise_v: 1.05` to the profile. These are threshold-type choices that are
   not mentioned in D1/D2 and whose effect is not measured by the re-fusion evidence (section 6). The profile header still says
   "An engineering profile, not a calibration against real flights."
5. D2 promised additions to `scripts/make_stage2_metrics.py`; the script's last change is 2026-11-18 16:49 +05:30 (#52), i.e. before
   the approval, and it has no `#49` content.

Recommendation on D1/D2: record, on the issue and from the maintainer account, that D1 and D2 are **ratified after the fact**
(not that they were approved before tuning), with the five points above. No code change is needed for that.

### 7.2 B5: the 52.13/h exception and the lock

**Decision B5a: PX4 calibration-set airborne bound 52.13/h versus D1's 50/h.** Options: accept the exception, or reject it.
Recommended (decision sheet row B5): **report it as missing the target**, together with the in-sample status (the PX4 profile was
fitted on those five flights), the 2-decision basis (C5, C7) and the held-out 24.32/h and `#177` 0/2805 results. Do not round it
to "about 50".

**Decision B5b: stale locks and `held_out_burned`.** Options: annotate, or refresh with `--burned`. A refresh rewrites
`heldout_lock.json`, `metrics.json` and both evaluation JSONs and sets the flag to true, which edits committed evidence.
Recommended: **annotate through documentation, not by editing artifacts**: this page (section 5) is the annotation, and the report
text below states it. Artifacts, locks and tests stay as committed.

### 7.3 Can the issue close without a frozen-code change?

Yes. None of the open items needs a change under `src/`, `configs/`, `models/` or any frozen contract (`AGENTS.md` section 4):
they are decisions (D1/D2 ratification, B5a, B5b) and report wording (section 8). Stage-1 regression is `6535 / 4 / 16826 / 65`
(`SIM`, `artifacts/validation/final_stage2-freeze-2026-11-27/benchmarks/stage1/summary.md:14`, cited by the closure checks; not re-run
here). Closing is **not** recommended before the maintainer records the three decisions, and the issue should not be closed on the
wording "0 false alerts per hour".

**Status: PENDING MAINTAINER DECISION.**

## 8. Acceptance criteria of #49

| # | Criterion | Status | Evidence and gap |
|---|---|---|---|
| 1 | Step-1 artifacts committed by a named re-runnable command, each with an environment tag and claim class | **PARTIAL** | Named command, `summary.md` header and `metrics.json` carry `SITL` and link-level; ArduPilot rows re-run to identical values (section 2). Gaps: no new step-1 flights ("re-run" in scope step 1 was not done), `make_stage2_metrics.py` not extended as D2 stated, PX4 rows not regenerable from a clean clone (tlogs ignored), PX4 events inferred |
| 2 | Per-hour table (all phases and in-flight only) with per-detector attribution, before and after | **PASS with caveats** | `summary.md` section 1 has all phases, from-arm, airborne, attribution, before and after (ArduPilot). PX4 attribution is by decision, not event; PX4 "before" has no from-arm split and its event counts are a duration heuristic. "After" is re-fusion (section 6) |
| 3 | Held-out benign set evaluated once, after the profile is frozen; lock file committed | **PARTIAL** | Lock committed and the split matches. Stale against the tag; `held_out_burned` misleading; lock written 150 ms before the evaluation; held-out runs inspected in step 1; split assigned after recording (section 5) |
| 4 | Stage-1 regression unchanged 6535 / 4 / 16826 / 65 | **PASS (cited, not re-run here)** | Closure checks cite the freeze run and the `stage1-regression` dispatch. This audit did not run the benchmark and changes nothing it covers |
| 5 | Drift detection does not regress on the same profile | **PASS, weak** | 6/6 detected, max delta 0.0 s (`metrics.json`). The recorded drift runs were already ML-off and only fusion was re-run, so no regression is possible by construction; one pre-onset `arm`-phase alert in `drift_002` (C9) |
| 6 | Maintainer approves the per-hour target and the fix option before tuning starts | **PARTIAL** | Approval text exists and predates the commit, but is from the implementer account with no cited maintainer source (section 7.1) |
| (D1) | In-flight 95% upper bound <= 50/h, and 0 events | **PARTIAL / FAIL for PX4 calibration** | ArduPilot: max 42.49/h airborne (met). PX4 held-out 24.32/h (met). PX4 calibration airborne 52.13/h and 2 events (not met; in-sample) |

## 9. Methodological caveats (for the report)

1. Exposure is small: ArduPilot 0.1667 h airborne pooled, PX4 about 0.12 h per set. A 0-event result with 0.1667 h can only
   support an upper bound of 17.97/h, and the bound is not a flight-hour rate. Decisions at 5 Hz are autocorrelated; events are
   cooldown-deduplicated only for the ArduPilot rows.
2. Recorded runs only: ArduPilot SITL runs collected 2026-10-06 to 2026-10-10 on one host, one scripted route (`--stream six`
   or `groups`, `--profile flight`); PX4 five-plus-five flights of one scripted route on one host (`docs/CALIBRATION_PX4.md`).
3. The ML-off ArduPilot runs were selected as a comparison after the ML-on runs misbehaved (`docs/VALIDATION_EVIDENCE.md:76`
   already says 0/2,329 is selected-on-data).
4. The PX4 calibration set is in-sample; its 52.13/h is not a held-out figure and the held-out figure is not a fit to it.
5. The "after" ArduPilot figures measure fusion gating on Stage-1 detector scores; they do not validate the profile's protocol and
   physics overrides.
6. Stale locks, `held_out_burned` flag semantics, 6-minute approval-to-commit gap (sections 5 and 7).
7. Link-level detection on `SITL`; nothing here is real-vehicle, real-RF, estimator-compromise or physical-deviation evidence.

### Reporting disclosures missing from the docs

Checked: `docs/stage2_report_draft.md`, `docs/VALIDATION_EVIDENCE.md`, `docs/CALIBRATION_PX4.md`, `docs/ARDUPILOT_SITL.md`, `docs/DETECTION.md`.

- `docs/stage2_report_draft.md` has no `#49` result. Line 282 says the per-hour rate is "Not computed", line 283 "Not established",
  and line 479 says the per-hour figures are "Computed but not yet transcribed". Line 461 (RSK-10) still quotes the decision-level
  `126/2,339` and has no mention of profile gating. Line 97 and 281 quote PX4 "1 false alarm in 2,805 held-out decisions", while the
  tag re-run is 0 of 2805 for the current profile (`#177`).
- `docs/VALIDATION_EVIDENCE.md` has no row for `artifacts/validation/inflight_fa_per_hour_20261119/` or the ArduPilot lock.
- `docs/CALIBRATION_PX4.md` has no per-hour table (the issue's stated gap for PX4 is still open in the docs); `docs/ARDUPILOT_SITL.md:216-218`
  and `docs/DETECTION.md:442-450` quote the favourable from-arm bounds (21.26 and 12.21) only. They omit the airborne bounds
  (31.13, 17.97, 42.49), the 123.93/h all-phase rate, that "after" is re-fusion, the PX4 52.13/h, the lock status, and the
  pre-onset `drift_002` alert.

## 10. Report disclosure text for #31 (draft, not applied)

> **In-flight false-alarm rate on SITL (link-level, benign streams).** On five recorded ArduPilot SITL benign runs the
> Stage-1 Isolation Forest, scored on the SITL link, produced all 171 post-boot alert events (981 per hour airborne; 95%
> one-sided Poisson upper bound 1142 per hour over 0.12 h). Under the ArduCopter profile (ML disabled, any ML vote requiring
> corroboration) the same recorded detector scores re-fused through the fusion engine give 0 airborne alert events across seven
> runs, upper bound 17.97 per hour over 0.167 h (calibration runs 42.49, held-out runs 31.13). These are re-scorings of runs
> recorded in October 2026, not new flights and not a re-run of the protocol and physics detectors; start-up alerts
> remain (123.9 per hour over all phases of those runs, 0.266 h). For PX4 SITL under the PX4 profile the held-out airborne
> bound is 24.32 per hour (0 events, 0.123 h); the calibration-set airborne bound is **52.13 per hour (2 events, 0.121 h,
> in-sample), which is above the 50 per hour target we set**, and its event count is inferred from false-alarm decision counts.
> One pre-onset alert occurs in an ArduPilot position-drift flight (phase `arm`, physics rule). The held-out split was assigned after the
> recordings had been inspected, and its recorded input hashes no longer match the current detector files, so it is a
> regression check, not a pristine held-out test. Environment `SITL`, claim class link-level detection; the exposure supports
> an upper bound, not a flight-hour rate, and no real-vehicle false-alarm rate exists.

Sources: `artifacts/validation/inflight_fa_per_hour_20261119/{metrics.json,summary.md}`, `artifacts/ardupilot/calibration/`,
`artifacts/sitl/calibration/evaluation_{calib,heldout}.json`, `artifacts/validation/final_stage2-freeze-2026-11-27/heldout/`.

## 11. Full-suite gate (run on this branch, 2026-11-27)

- `python -m pytest`: `3127 passed, 80 skipped, 129 warnings in 499.67s (0:08:19)`.
- `ruff check src tests scripts backend`: `All checks passed!`.
- Stage-1 benchmark: not run (this change touches only `docs/`; section 7.3 cites the freeze-tag result).
