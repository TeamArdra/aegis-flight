# Stage 2 delivery plan

Authoritative execution plan for the Stage 2 submission. As of 2026-11-23, main `2bae45a`.
Code freeze 27 Nov, submission 2 Dec (tracker #4).

## Scope

The scope is the official template's marked sections, nothing more. The page-level mapping is in
`docs/STAGE2_REQUIREMENT_TRACEABILITY.md`.

| Section | Marks | Deliverable |
|---|---|---|
| §5–§6 | 30 | detection of 6 attack classes; per-class results with intervals; latency; misses explained; alert traceability |
| §7 | 8 | benign false-alarm exposure; tamper-evident logs; alerting cannot interfere with flight; safe failure |
| §8 | 14 | test suite passes on a clean machine; result files reproduce the reported numbers; datasets with checksums; methods disclosed |
| §9 | 8 | resource use on target hardware; tap point; protocol and autopilot support; dashboard; install guide; **demo video**; cost and power |
| §10–§11 | 12 | source archive; dependencies and licences; risk register; AI-tool declaration; signed integrity declaration |

The rubric (p. 25) gives flight evidence full weight and simulation limited weight, and prefers "a smaller IDS with traceable results and
defensible claims". So every task below either produces traceable evidence, corrects a claim, or fixes a verified safety defect.
Nothing else is in scope.

The maintainer's decisions of 2026-11-23 (tracker #4) are binding: D4 to D15.

## A. Must complete before submission

| # | Task | Tracks | Owner | Depends on | State |
|---|---|---|---|---|---|
| A1 | Land the Stage-2 stack: #81, then #82, plus the children that are ready | #14 #15 #19 #20 #22 #24 #49 | maintainer merges; agents keep heads gated | D-decisions on children (A2–A7) | #81 contains #80, #140 and D4. #82 contains #81. All 13 children merge cleanly (verified 2026-11-23). |
| A2 | **D10** #112: keep the GNSS classification; ship no new ALT_HOLD actuation | #112 | fix-up PR into Madhav's branch | – | #164 merged into #112 (`d04c3ce`); #112 CI green; mode commands and flood actions identical to main (15/15) |
| A3 | **D11** #111: reorder window 48 → **24**, labelled "candidate; not validated until a fresh SITL rerun" | #111, #14 | fix-up PR into Madhav's branch | SITL rerun is human-supervised (D3) | #166 merged into #111 (`89c0240`); #111 CI green |
| A4 | **D12** #114: keep the force-disarm alert; suppress the RESTORE/counter-command for that event (turn the strict xfail into a passing test) | #114 | fix-up PR into Madhav's branch | – | #162 merged into #114 (`d6f9e3c`); **#114 CI red**: one D12 guard test lacks a vehicle heartbeat, and D4 (now in #81) fails closed. One-line test fix verified (5/5 pass); it needs a fix-up into #114 |
| A5 | **D13** #115/#141: ML-only evidence needs corroboration before ACTIVE_IPS acts | #115 | fix-up PR into Madhav's branch; #141's matrix updated to the new behaviour | – | #165 merged into #115 (`e0d63b0`); #115 CI green; #141 merges cleanly into #115. **Conflicts with #114 in `controller.py`** once both are in #81 (two new methods at the same place; keep both) |
| A6 | **D14** #125: ship no unconditional ConstDet mute (keep #145's correctness fix) | #125 | fix-up PR into Madhav's branch | – | #163 merged into #125 (`070f294`); #125 CI green |
| A7 | **D15** #126: `pos_residual_min_streak` stays 1 (keep #147's correctness fix) | #126 | fix-up PR into Madhav's branch | – | #168 merged into #126 (`38a86e5`); #126 CI green |
| A8 | **D9** #93: signed-only API auth, with `scripts/verify_stage2.py` switched to signed requests in the same PR; compatibility switch documented | #93 | ours | – | #93 refreshed onto #82, `verify_stage2.py` signed-only, ready for review (CI green) |
| A9 | **D4b/D8** #101: keep only the evidence-tier docs commit (`0ade022`). R13 duplicates #82 `fe08280`. R8 conflicts with #82's resolution `b60517d`, so it is deferred. | #101 | ours | – | #101 docs-only (2 files, no R8/R13; verified), ready; description updated |
| A10 | Model-verification chain: #154 (#144 TOCTOU), then #160 (#155). Both are drafts, green, and await triage. | #144 #155 | maintainer triage; merge #154 then retarget #160 | – | code complete |
| A11 | **Evidence provenance:** SITL manifests record the Stage-1 model's hash for `model_choice=px4` (122 of 122), and `resolve_model` reports `px4` even when it silently fell back to ML off. Fix the writer before the #26 campaign; state an erratum for the committed manifests (no hand edits). | #26 (campaign must produce correct manifests), #31 item 13 | agent: minimal fix in `scripts/sitl/p2_trial_common.py` | before #26 | #167 (writer hashes the loaded model; a missing requested model fails closed; injection trial uses the shared resolver) |
| A12 | Regenerate replays, the link-stress sweep and the benchmarks on the freeze tag | #27 | agent | freeze tag; #14/#15 landed | blocked by freeze |
| A13 | Report: canonical lineage, the 14 corrections, the traceability table, template gaps | #31 #32 | agents draft (report-repo PR #1); humans choose | lineage choice; A12 numbers | prep done: 819 numbers, 655 match, 25 differ, 53 unsourced, 86 need the freeze run |
| A14 | Package tooling and checklists (verifier, SUBMISSION.md, demo checklist) | #34 #33 | ours, #157 (draft, green) | – | code complete |
| A15 | PX4 evidence PR #113: push its two missing local commits | #113 | Madhav | – | blocked on Madhav |

## B. Already satisfied (proof posted)

| Item | Evidence |
|---|---|
| #58 #59 #60 | closed by the maintainer after the acceptance verdicts (tests on main `03e4de9`) |
| D4 dialect gate | #91 merged into #81 (`9a15d08`); 176 dialect/SAFE_HOLD tests; CI green |
| P0 #139 SAFE_HOLD | #140 on main |
| `issue_claim` crash | #153 on main |
| #21, #35, #49 | readiness verdicts posted earlier; their code is in the stack |

## C. Deferred until after submission

| Item | Why it is not needed for Stage 2 |
|---|---|
| #158 / #159 `--help` safety for evidence scripts | a hazard to developers, not to the submission; #157's doc warns about it |
| #101 R8 and R13 | duplicate or conflicting with #82 (A9) |
| #117 PX4 LAND fallback (draft) | new actuation; no decision; not a deliverable |
| #128 RC-takeover test (draft) | depends on #117's branch; test-only |
| #127 Windows `termios` collection | Windows dev only; Linux CI unaffected; Madhav's branch (comment posted) |
| #124 overclaimed test wording | Madhav; not a deliverable |
| Restore paths without an armed check | no approved decision; document as a known limitation |
| `make_golden_forwarding.py` writes without `--write` | developer hazard only |
| #13 repo settings (CODEOWNERS, approvals) | admin settings; CI and the ruleset already gate main |

## D. Human-only

Full procedures are in `STAGE2_FINAL_READINESS.md`.
- #33 demo video;
- #26 final SITL campaign (supervised);
- #29 outdoor receive-only GNSS walk;
- #30 Pi compute run;
- #34 archive assembly and submission;
- #31/#32 lineage choice and human-input sections;
- AI-tool declaration and integrity signature;
- maintainer merges of A1–A10 and A14.

## Execution order (verified 2026-11-23 by an in-memory merge simulation of every PR head, `git merge-tree`)

Into a stack branch: **Create a merge commit**. Into main: **Squash**.

| Step | PR | Into | Verified state | Needs first |
|---|---|---|---|---|
| 1 | #167 SITL manifest fix | main | clean | must land before the #26 campaign |
| 2 | #154 model single read | main | clean | #144 triage |
| 3 | #160 verified script loads | retarget to main after #154 squash, then main | clean | step 2 |
| 4 | #157 package tooling | main | clean | – |
| 5 | #161 these plan files | main | clean | – |
| 6 | #101 evidence-tier docs | #81 branch | clean | – |
| 7 | #111 reorder window 24 | #81 branch | clean | – |
| 8 | #114 D12 | #81 branch | clean merge; **CI red** (the D12 test needs a heartbeat under D4) | the one-line test fix |
| 9 | #141 D13 matrix test | #115 branch | clean | – |
| 10 | #115 D13 | #81 branch | **conflict with #114** in `controller.py` (keep both new methods) | an integration with resolution |
| 11 | #81 | main | clean after steps 1–10 | steps 6–10 |
| 12 | #112 D10 | main | clean after step 11 | – |
| 13 | main into #82 (carries #81) | #82 branch | **conflict** in `docs/HARDWARE_FLIGHT_READINESS.md` (D4 wording vs #82), with or without #101 | an integration with resolution |
| 14 | #93, #116, #118, #123, #124, #125, #126, #127, #129 | #82 branch | each clean on #82's tip | step 13 |
| 15 | #113 PX4 evidence | #82 branch | clean, but its commits `2b9eab3`, `375b2ab` are still not pushed | Madhav |
| 16 | #82 | main | clean once step 13 is resolved | steps 13–15 |

Then the freeze tag on main, the #26 campaign and #27 on the tag, and the report numbers (#31) from those outputs.
