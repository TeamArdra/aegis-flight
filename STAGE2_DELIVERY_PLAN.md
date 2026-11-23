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
| A2 | **D10** #112: keep the GNSS classification; ship no new ALT_HOLD actuation | #112 | fix-up PR into Madhav's branch | – | fix-up #164 into #112 (DO_SET_MODE equals main in 40/40 scenarios; CI green); open question: #112 still swaps the rate limiter for `sanitize_gps` on high-rate links |
| A3 | **D11** #111: reorder window 48 → **24**, labelled "candidate; not validated until a fresh SITL rerun" | #111, #14 | fix-up PR into Madhav's branch | SITL rerun is human-supervised (D3) | fix-up #166 into #111 (window 24, labelled candidate; Stage-1 baseline) |
| A4 | **D12** #114: keep the force-disarm alert; suppress the RESTORE/counter-command for that event (turn the strict xfail into a passing test) | #114 | fix-up PR into Madhav's branch | – | fix-up #162 into #114 (no counter-command while a genuine stop is latched; alert kept; CI green) |
| A5 | **D13** #115/#141: ML-only evidence needs corroboration before ACTIVE_IPS acts | #115 | fix-up PR into Madhav's branch; #141's matrix updated to the new behaviour | – | fix-up #165 into #115 (controller gate, unconditional in ACTIVE_IPS; CI green); #141 re-pins the matrix (draft) |
| A6 | **D14** #125: ship no unconditional ConstDet mute (keep #145's correctness fix) | #125 | fix-up PR into Madhav's branch | – | fix-up #163 into #125 (ConstDet byte-identical to #82; CI green) |
| A7 | **D15** #126: `pos_residual_min_streak` stays 1 (keep #147's correctness fix) | #126 | fix-up PR into Madhav's branch | – | fix-up #168 into #126 (shipped streak 1; Stage-1 baseline) |
| A8 | **D9** #93: signed-only API auth, with `scripts/verify_stage2.py` switched to signed requests in the same PR; compatibility switch documented | #93 | ours | – | #93 refreshed onto #82, `verify_stage2.py` signed-only, ready for review (CI green) |
| A9 | **D4b/D8** #101: keep only the evidence-tier docs commit (`0ade022`). R13 duplicates #82 `fe08280`. R8 conflicts with #82's resolution `b60517d`, so it is deferred. | #101 | ours | – | done: #101 is docs-only, retargeted to #81, ready for review |
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

## Execution order

1. A2–A9: decision implementation. Agent work, all independent, in parallel.
2. A11: the provenance fix, which must land before #26 runs.
3. Maintainer merges A1, A10, A14.
4. Freeze tag, then A12 and #26.
5. A13: report numbers from those outputs.
6. #34 package, then submission.
