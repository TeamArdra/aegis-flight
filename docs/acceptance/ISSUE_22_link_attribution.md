# Issue #22 acceptance package: link-level attack attribution

**Status: PENDING MAINTAINER DECISION (D10 / B6).** This document is evidence for that decision. It does not
accept or close the issue, and nothing in it changes code, configuration or models.

- Environment tag: `SIM` (in-process simulator). Claim class: link-level detection (attribution of already-detected
  link-layer attack decisions). It says nothing about a vehicle, an estimator, a flight, `SITL` or real RF.
- Code verified: `origin/main` `024baab`. `git diff 8e58003 024baab --stat -- src configs models` is empty, so
  `src/`, `configs/` and `models/` equal the freeze tag `stage2-freeze-2026-11-27` (`8e58003`).
- Implementing change: PR #79 squash `3a10573` (content of closed PR #74, branch `feat/22-link-attack-attribution`).
- Maintainer decision on record: D10 on #4, accept semantic loss attribution as an opt-in rule with hierarchical
  reporting (offline approval 2026-11-18, quoted in the #22 comments). This document does not reopen it.

## 1. What the change is

| Part | Where |
|---|---|
| Opt-in rule: selective heartbeat starvation (`heartbeat_age_s > heartbeat_timeout_s`) while GPS is fresh and `msg_rate_hz >= semantic_link_min_rate_hz` (5.0) votes `MAVLINK_ANOMALY` instead of `DOS` | `src/aegisflight/detectors/protocol.py:56-57, 358-366` |
| Default off | `src/aegisflight/config.py:129`, `configs/detector.yaml:69` |
| Hierarchical metric: `{DOS, MAVLINK_ANOMALY}` grouped as `LINK_LAYER_DISRUPTION` | `src/aegisflight/metrics/scoring.py:19-40`; extended benchmark fields `hierarchical_link_layer_*`, `hierarchical_attribution_accuracy` (`src/aegisflight/benchmark/extended.py:203, 233`) |
| Before/after script | `scripts/eval_link_attribution.py` |
| Tests | `tests/unit/test_link_attribution.py` (3 tests) |
| Documentation | `docs/DETECTION.md:478-512` |

## 2. Verification of the claims handed to this audit

| Claim | Verdict | Evidence |
|---|---|---|
| The semantic rule is opt-in and disabled in all profiles | **CONFIRMED** | Only `semantic_link_attribution` writers: `config.py:129` (False), `configs/detector.yaml:69` (false), `demo/indoor_bench_profile/detector.yaml:81` (false), `protocol.py:56` (`.get(..., False)`), and `scripts/eval_link_attribution.py` (sets it for the "after" run, in memory). The three vehicle profiles do not set the key. Loaded with `load_config(...)`, `protocol.semantic_link_attribution` is `False` for the base config and for `configs/px4_sitl`, `configs/ardupilot_copter` and `configs/universal_flight` (command run 2026-11-27, output `False` x4) |
| Grouped / hierarchical reporting exists and is tested | **CONFIRMED** | `metrics/scoring.py:27` `hierarchical_link_summary`; `tests/unit/test_link_attribution.py:55` `test_hierarchical_link_layer_grouping_and_summary`. Caveat: the group `{DOS, MAVLINK_ANOMALY}` measures link-layer versus non-link-layer attribution, not attribution inside the link layer (`DETECTION.md:504-509` says so) |
| The "rules written before evaluation" criterion is NOT satisfied | **CONFIRMED (cannot be satisfied or shown)** | PR #74 (`gh pr view 74 --json commits`): two commits. `c8471c4` (2026-11-18T19:52:47Z) already contains the rule (`protocol.py`, `config.py`, `configs/detector.yaml`), the metric, `scripts/eval_link_attribution.py`, the tests and the docs in one commit; `8905eab` (23:44:15Z) is the review fix. No commit exists in which the rules were committed before the evaluation script. The PR body of #74 contained the rules and the evaluation table together. PR #79 contains no #22 commit of its own (it squashed #74's content); the original order is not visible on `main` |
| Seed 20261119: packet_loss strict 0.0 -> 0.9508 = 58 of 61 detected decisions; only 61 of 493 packet-loss decisions detected; rate_spike and latency strict 0 | **CONFIRMED** | Re-run, section 3. `0.9508 x 61 = 58.0`. `61 / 493 = 12.4%`. rate_spike strict 0.0000 before and after (500 of 508 detected); latency strict 0.0000 (15 of 554 detected) |
| Other seeds gave packet_loss 0.80 and 0.97, with `dos:blackout` falling 12.5 and 11.8 pp | **NOT VERIFIABLE** | These figures and their seeds appear nowhere in `docs/`, `artifacts/`, the Stage2_Handover notes, the #22 thread, or PR #74, #79 and #178. No other seed is documented, so no other seed was run (a seed chosen now would be an undocumented, post-hoc choice). Only `20261119` is evidenced. Do not quote 0.80 / 0.97 / 12.5 pp / 11.8 pp in the report until their command, seed and output exist |
| Binary recall 0.5687 and FPR 0 unchanged across the cited seeds | **CONFIRMED for seed 20261119 only** | 0.5687 -> 0.5687 and 0.0 -> 0.0 (section 3). Other seeds: not run |
| Stage-1 6535 / 4 / 16826 / 65 unchanged | **CONFIRMED (cited, not re-run)** | `artifacts/benchmarks/summary.md:14` and `artifacts/validation/final_stage2-freeze-2026-11-27/benchmarks/stage1/summary.md:14` both read `6535 / 4 / 16826 / 65`; the freeze run was on `8e58003` with a clean tree (`run_manifest.json`). `src/`, `configs/` and `models/` are byte-identical between `8e58003` and `024baab`. The 9-minute benchmark was **not run** here. The rule is off by default, so Stage-1 output cannot depend on it |
| `DETECTION.md` is consistent with the script | **CONFIRMED (already fixed by #178)** | `docs/DETECTION.md:491-501` now quotes `0.0000 -> 0.9508`, `0.7952 -> 0.6676`, 61 of 493 detected, 299 -> 251 of 376 correctly labelled blackout decisions (`0.7952 x 376 = 299.0`, `0.6676 x 376 = 251.0`), recall and FPR. The old figures `0.9531 / 0.7641 / 0.6410` are gone from `docs/`. They are the numbers of PR #74's body, produced by an older detector state (the PR #74 review recorded binary recall `0.785` then); the current head reproduces `0.9508 / 0.7952 / 0.6676`. No doc edit was needed |

## 3. Re-run (2026-11-27, code `024baab`, clean tree)

Commands run from `D:/Ardra/techfest-2026/aegisflight/.claude/worktrees/wt-22` with the project `.venv` interpreter (CPython 3.13.15) and `PYTHONPATH=<worktree>/src`:

```
python -m pytest tests/unit/test_link_attribution.py            -> 3 passed in 1.16s
python scripts/eval_link_attribution.py --help                  -> usage: eval_link_attribution.py [-h] [--seed SEED]  (no output option)
python scripts/eval_link_attribution.py --seed 20261119 > <scratch>/seed20261119.json          (about 26 s)
python scripts/eval_link_attribution.py --seed 20261119 > artifacts/validation/link_attribution_20261119/eval_link_attribution_seed20261119.json
cmp (the two files)                                             -> identical
```

Output (keys `before` / `after_semantic`; `strict_acc` and `hierarchical_acc` are among **detected** decisions only):

| Mode | decisions | detected | strict before | strict after | hierarchical |
|---|---:|---:|---:|---:|---:|
| `mavlink_anomaly:packet_loss` | 493 | 61 | 0.0000 | 0.9508 | 0.9508 |
| `mavlink_anomaly:rate_spike` | 508 | 500 | 0.0000 | 0.0000 | 1.0000 |
| `dos:latency` | 554 | 15 | 0.0000 | 0.0000 | 0.0000 |
| `dos:blackout` | 497 | 376 | 0.7952 | 0.6676 | 0.8005 |
| `dos:flood` (control) | 501 | 500 | 1.0000 | 1.0000 | 1.0000 |

Binary recall (five-mode subset) 0.5687 -> 0.5687; benign FPR 0.0 -> 0.0. 24 sessions, ML off. The committed copy of this output, with provenance, is
`artifacts/validation/link_attribution_20261119/` (JSON sha256 `539be4be...c857ecdb`). That artifact is stdout redirected by the
shell, because the script has no output option and was not changed. It closes the open item "no before/after artifact committed".

Observations that the audit trail needs:
- The hierarchical figure for packet_loss is already `0.9508` **before** the rule. The rule turns that into a strict-label result by moving the vote from `DOS` to `MAVLINK_ANOMALY`; detection itself (61 of 493) does not change.
- Recall and FPR are unchanged by construction as well as by measurement: the flag changes which class a heartbeat-starvation vote goes to, not whether the decision is flagged.
- A separate measurement exists and is **not reconciled** with the above: `artifacts/validation/final_stage2-freeze-2026-11-27/benchmarks/bisect_470_vs_463/` (ML on, extended benchmark, rule off) shows `dos:latency` "Attribution accuracy" `3.61%` at `41311fa` and `96.88%` at `3a10573` (`summary_41311fa.md:27`, `summary_3a10573.md:27`). That is a different configuration (ML on, different grid and seeds) from this script (ML off, latency strict 0.0 on 15 detections), and the cause of the jump was not investigated here. Do not present either as "the" latency attribution figure.

## 4. Criterion-by-criterion table (issue #22 acceptance criteria)

| # | Criterion (from the issue) | Status | Evidence |
|---|---|---|---|
| 1 | The rules are in the PR before the first evaluation commit (check the commit order) | **FAIL** | PR #74 `c8471c4` holds rule, script, metric and tests in a single commit; the rules cannot be shown to predate the evaluation. The rules were also written with knowledge of the simulator's attack definitions (`DETECTION.md:510-512`). Not repairable after the fact |
| 2a | On fresh seeds, attribution accuracy for the three modes is reported before and after | **PARTIAL** | Reported and reproduced (section 3) for one fresh seed. Improves only `packet_loss` (strict 0.0 -> 0.9508, among 61 of 493 detected). `rate_spike` strict stays 0.0 (hierarchical 1.0); `dos:latency` stays 0.0 with 15 of 554 detected. Single seed, 4 sessions per mode. Before/after artifact now committed (this change) |
| 2b | Binary recall and FPR do not degrade by more than 0.5 pp | **PASS** (seed 20261119) | 0.5687 -> 0.5687; 0.0 -> 0.0. Other seeds: not run |
| 3a | Standard gate passes | **PASS** | section 5 |
| 3b | Stage-1 binary counts identical | **PASS** (cited) | `artifacts/benchmarks/summary.md:14`, freeze `benchmarks/stage1/summary.md:14`; benchmark not re-run here, `src/configs/models` unchanged since the freeze |
| 3c | Any Stage-1 per-class changes are listed | **PARTIAL** | No per-class diff is listed anywhere. The rule is off by default, so none is expected for the default path, but "expected" is not "listed". Not run |
| 4 | The change is disclosed in the report (#31) | **FAIL** (open) | `docs/stage2_report_draft.md` does not mention the rule or the hierarchical metric (grep of `semantic_link`, `hierarchical`, `LINK_LAYER`, `packet loss` finds only the attack-mode table at line 202). The disclosure exists only in `DETECTION.md` and `BENCHMARKING.md:208-210`. Draft text for #31 is in section 7 |
| D10 | Alternative: keep the logic, report hierarchical labels plus the confusion matrix | **PASS (code)** | `hierarchical_link_summary` and the extended-benchmark fields, with a test. The per-class confusion matrices already exist (`results.json`, #28) |

Net: 4 PASS (2b, 3a, 3b, D10), 2 PARTIAL (2a, 3c), 2 FAIL (1, 4). The two FAILs are not code defects: criterion 1 is a process criterion that cannot be satisfied retroactively, and criterion 4 is a report edit that this task was told not to make.

## 5. Gate

Run on branch `docs/22-acceptance-package` (docs and one artifact folder only):

```
python -m pytest                              -> 3127 passed, 80 skipped, 129 warnings in 480.64s (0:08:00)   (started before the docs edits of this change)
python -m pytest <5 doc-reading test files>   -> 173 passed, 2 skipped in 80.34s   (re-run after the docs edits: test_claims_guard, test_verify_package, test_stage2_metrics, test_scripts_help_no_write, test_link_attribution)
python scripts/claims_guard.py                -> claims-guard: no unsupported claims found
ruff check src tests scripts backend          -> All checks passed!
```

## 6. Limitations and evaluation disclosures (to be kept next to any quoted figure)

1. **Rules written with knowledge of the simulator's attack definitions.** The packet-loss rule keys on how the simulator's `packet_loss` attack starves heartbeats while other traffic and GPS continue. Its 0.9508 is attribution accuracy against that same simulator, not evidence that the rule generalises to real links. Red/blue separation is by module, not by person.
2. **Strict accuracy is conditional on detection.** `0.9508` is 58 of the 61 decisions that were detected, out of 493 packet-loss attack decisions (12.4% detected). It is not a recall and not an overall attribution rate.
3. **Two of three target modes did not improve.** `rate_spike` strict 0.0 and `dos:latency` strict 0.0 before and after. `rate_spike` versus `dos:flood` is a taxonomy overlap (near-identical feature vectors per `DETECTION.md:481-483`); latency has 15 of 554 decisions detected, so its accuracy is estimated from 15 decisions.
4. **Blackout regression.** With the rule on, `dos:blackout` strict falls 0.7952 -> 0.6676 (299 -> 251 of 376 detected decisions correctly labelled) because heartbeat-stale ticks with residual non-heartbeat traffic at 5 Hz or more are voted `MAVLINK_ANOMALY`. The hierarchical figure (0.8005) is unaffected.
5. **Opt-in and off everywhere.** No shipped profile enables the rule. The Stage-1 benchmark and every committed artifact were produced with it off. The only place it runs enabled is `scripts/eval_link_attribution.py`.
6. **One seed, small samples.** 24 sessions, 4 per mode, ML off, `SIM`. There are no confidence intervals. No second seed is documented; claims about other seeds (0.80 / 0.97, 12.5 / 11.8 pp) are unsupported (section 2).
7. **Unreconciled latency measurement** between this script (strict 0.0) and the freeze bisect (96.88% at `3a10573`, ML on): section 3.
8. **`docs/CONFIGURATION.md` does not list `semantic_link_attribution` or `semantic_link_min_rate_hz`** (grep finds no match); the keys are documented in `DETECTION.md` and `configs/detector.yaml` only. Not changed here.
9. **No independent anti-tuning review was run** in this task (the issue names `aegis-reviewer`); this document has not been reviewed by one.

## 7. Report disclosure text for #31 (draft; the report draft itself is not edited)

> **Link-layer attribution (SIM, link-level detection).** Several simulated link-layer attacks look alike on the link-level features: a rate spike and a flood differ only in magnitude, and added latency overlaps benign jitter. The shipped configuration therefore reports link-layer disruption (denial of service and MAVLink anomaly) as one family alongside the strict per-class confusion matrix. An optional rule (`protocol.semantic_link_attribution`, **off in every profile**) attributes selective heartbeat loss, with GPS and other traffic still arriving, to a MAVLink anomaly rather than a denial of service. On one fresh simulated seed (`20261119`, 24 sessions, ML off; `artifacts/validation/link_attribution_20261119/`) it raised packet-loss strict attribution from 0.0000 to 0.9508, but that figure is among the 61 of 493 packet-loss decisions that were detected at all, and it lowered denial-of-service blackout strict attribution from 0.7952 to 0.6676. Rate-spike and latency strict attribution stayed at 0.0000 (latency: 15 of 554 decisions detected). Binary recall (0.5687 on this subset) and benign false-positive rate (0.0) did not change. The attribution rules were written with knowledge of the simulator's attack definitions and were not committed before the evaluation script, so the result is a design-time check, not independent validation, and it says nothing about real vehicles or real radio links.

## 8. Maintainer decision required: D10 / B6

**Status: PENDING MAINTAINER DECISION.** Nothing here marks #22 accepted.

Options:
- **A. Accept opt-in plus hierarchical reporting as the D10 outcome, close #22 without changing frozen code** (recommended). The criteria recorded above as FAIL (rule-before-evaluation order; report disclosure) and PARTIAL (rate_spike and latency strict, single seed, no per-class Stage-1 listing) are accepted as known limits. Report disclosure (section 7) is added under #31. No change to `src/`, `configs/` or `models/`.
- **B. Keep #22 open** until the report text is merged and a second documented seed is run (a new `--seed` run, with its command and output committed, chosen before looking at results).
- **C. Reject the rule** (remove it): a code change to `protocol.py` and `config.py`, which are on the Stage-1 regression path, needs the full regression and is not recommended for a rule that is already off by default.

Recommendation: **A**. The rule cannot affect any shipped number because it is off; the hierarchical metric is the D10 alternative the issue itself permits; the open items are disclosure, which does not need a code change. Accepting A means accepting the failed and partial criteria listed in section 4 as stated, not that they were met.

Not enabled anywhere by this change: the semantic packet-loss rule. Not done by this change: closing, commenting on, or labelling the issue.
