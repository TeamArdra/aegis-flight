# Stage 2 branch audit

Date 2026-11-03. Everything below comes from read-only Git commands in this working tree. `git fetch origin` was run once,
with no prune, merge or rebase. Nothing was merged, rebased, pushed or committed, and no branch was checked out.

## 1. State of the repository

| Item | Value |
|---|---|
| Root | `D:/Ardra/techfest-2026/aegisflight` |
| Current branch / upstream | `main` tracks `origin/main`; 0 ahead, 0 behind, both at `f9945a7` |
| Other Git or Claude processes | no `.git/*.lock`; one `claude.exe`, plus node helpers for MCP servers; no other Git process |
| Uncommitted at the start (the user's) | `.gitignore`, the template PDF (the real 407 KB file replaces a 23 KB text file in Git), `docs/stage2_report_draft.md` (team ID, date, signature). **Left untouched** |
| Added by this audit (uncommitted) | see `docs/STAGE2_GAPS_AND_PRIORITIES.md` §5 |
| Stash | `stash@{0}` "GPS work preserved before Stage 2 integration". It adds no file that `main` lacks |
| Extra worktrees | `wt_head` (`90b9aa2`) and `wt_integration` (`c135159`), both in old scratch folders |
| Backups | 13 `backup-20261031/*` tags, ref `refs/backup/wip-20261031`, a bundle in `.git/aegis-backups/20261031/` |
| Commits on `main` | 108 (82 Raj Tibarewala, 22 pozo, 4 Madhav Choudhary) |

## 2. Branch table

| Branch | Local/remote | Latest commit | Author | Ahead/behind `main` | Purpose | Important implementation | Risks |
|---|---|---|---|---|---|---|---|
| `main` | local | `f9945a7` 2026-10-31 | Raj Tibarewala | 0 / 0 | Single source of truth | Everything listed below except `gps-assist` | Carried unsupported dashboard rows (§4) |
| `origin/main` | remote | `f9945a7` | Raj Tibarewala | 0 / 0 | Same | Same | -- |
| `origin/gps-assist/minor-adjustments` | remote only, **new, found today** | `035fb5e` 2026-11-01 "Assisst-1" | icebot90 | 1 ahead / 41 behind (base `e31caf8`) | GPS health display and 255-satellite handling | See §3 | **4 merge conflicts**; overlaps `core/gps_health.py` on `main`; a detector file changes |
| `origin/stage2-autonomous-defense` | remote | `c96a109` 2026-10-26 | Madhav Choudhary | 0 ahead / 42 behind, **ancestor of `main`** | Teammate defense layer | Mitigation controller, HAL, Tauri shell, Rust crate, twin | Fully merged. Do not merge again. Its own docs held the withdrawn claims |
| `origin/integration/github-latest-20261029` | remote | `708f624` 2026-10-29 | pozo | 0 ahead / 5 behind, ancestor | Integration before PR #3 | Inline bridge, signing, topology, recovered docs | Fully merged. It holds `f816f41`, which added the bad rows (§4) |
| `backup/pre-trailer-strip` | local | `10e5b22` 2026-10-24 | Raj Tibarewala | 0 ahead / 46 behind, ancestor | Safety copy | -- | None |
| `backup/main-before-integration-20261027` | local | `90b9aa2` 2026-10-25 | Raj Tibarewala | 64 ahead / 108 behind, **no common ancestor** | Old rewritten-history main | Superseded | Never merge: rewritten history. `git diff --diff-filter=A main <branch>` finds no file that `main` lacks |
| `integration/stage2-defense-candidate` | local, upstream gone, active worktree | `c135159` 2026-10-27 | Raj Tibarewala | 69 ahead / 108 behind, no common ancestor | Earlier integration | Superseded | Same. Same check finds no missing file |
| `safety/iter2-wip-2026-10-26` | local | `c984c0f` 2026-10-26 | Raj Tibarewala | 65 ahead / 108 behind, no common ancestor | Snapshot of GPS iteration 2 | Superseded by `main` | Same. Same check finds no missing file |

Ahead/behind figures are from `git rev-list --left-right --count main...<branch>`. The "no common ancestor" branches are
the old trailer-stripped history, so a merge would double the history. They are safety copies only.

## 3. The new teammate branch: `origin/gps-assist/minor-adjustments`

Read from `git diff main...origin/gps-assist/minor-adjustments`. It was not checked out and its tests were not run here.
Its own document reports 884 passed, 11 skipped, on its old base, and says its frontend build was blocked.

| Change | Assessment |
|---|---|
| `satellites_visible == 255` becomes "unknown" in the extractor, `LinkMonitor` and the protocol GNSS rule | **A correct small fix.** MAVLink defines 255 as unknown. On `main` it is stored as 255 satellites, which can show on the dashboard and feed the `gps_sat_jump` rule. It touches `detectors/` and `features/`, so a Stage-1 re-benchmark is required before accepting it. On `main` a no-fix report with 255 satellites still fires, so the urgency is low |
| `gps.health_ok`, `gps.health_age_s` and an `estimator{}` block in `LinkMonitor` | **Duplicates `main`.** `core/gps_health.py` already gives `horizontal_solution`, `gps_healthy`, `quality_flags`. Different key names; merging keeps two views of one thing |
| `Header.tsx`, `source.ts`, `types/index.ts` health wording | Conflicts with the `gpsNote()` wording on `main` |
| `test_gps_health_reporting.py` (new, 9 tests) | Keep the 255-satellite cases. The rest targets the duplicate keys |
| 0.3 s delay in the fake serial device of `test_run_serial_ids.py` | A cleaner fix for a race that `main` already works around. Optional |
| `docs/gps_integration_verification.md`, `docs/gps_session_changes_and_difficulties.md` | Useful record. It correctly says no new hardware capture was taken |

**Trial merge** (`git merge-tree --write-tree main <branch>`, no working-tree effect): conflicts in `Header.tsx`,
`types/index.ts`, `source.test.ts` and `backend/engine.py`.

**Recommendation: do not merge the branch.** Ask its author to rebase on `main` and keep only the 255-satellite handling
and its tests. Re-run `pytest` and `aegis benchmark --out <scratch> --no-figures` before accepting it.

## 4. The defense branch: previous findings checked against current `main`

| Previous finding | Verdict on `main` | Evidence |
|---|---|---|
| The hardware layer is used only by its own tests | **Partly true.** `hal/discovery.py`, `identify.py`, `profiles.py`, `link_graph.py`, `topology.py`, `inline_bridge.py` have no production caller (only `tests/unit/test_hal.py`, `test_defense_safety.py`). `hal/inline_ips.py`, `status_server.py`, `topology_status.py` **are** wired, through `aegis ips-bridge` and `backend/` | `grep` of `src`, `scripts`, `backend` |
| The frontend does not call Rust but shows a Rust timing | **True, and fixed in the working tree.** The Tauri shell registers `fastpath_*` commands, but `frontend/src` has no `invoke(`. The Python path never calls the crate. The crate has **0 tests** (`cargo test --offline`: 0 passed). The "<0.08 ms Rust" row had no artifact | `frontend/src-tauri/src/main.rs`; `frontend/src/components/evalPanels.tsx` |
| The protected flight path is scripted, not real defense outcomes | **Partly true.** It is not a fixed script: `_step_cyber_physical_twin` is a closed-loop model driven by the controller state. But it runs only `if self.is_sim` and no vehicle exists behind it. The dashboard labels it "IPS Protected (modelled)". It must never be described as a measured outcome | `backend/engine.py:634,717`; `MapPanel.tsx:360` |
| Raspberry Pi numbers have no artifact | **True, and it had come back.** `f816f41` (pozo, 2026-10-28) re-added "Pi Zero 2W 11.4 % CPU, 42.8 MB, ₹2,900", two datasets that do not exist in the repository, "82.4 km", and "catches subtle drift in 0.4 s (EKF failsafe blind)" to the live dashboard after the 2026-10-27 review had removed them. **Removed in the working tree** (uncommitted) by restoring the row set of `1a61231` | `git log -S"11.4% CPU"`; `docs/GPS_WORKSTREAM_PROGRESS.md:232` |
| Recovery-time and parts-cost claims have no evidence | **True; gone from competition docs.** `next_state.md` says "not measured". The cost was only in the rows above. §9 of the report keeps both as not measured | `docs/next_state.md:28` |
| Test counts differ between documents | **True, historically.** Today's canonical count is in `docs/STAGE2_EVIDENCE_INDEX.md` §1. `docs/technical_proposal.md` keeps "44-test suite" as the Stage-1 record | fresh run |
| The defense branch was based on older mainline history | **Resolved.** It is an ancestor of `main` | `git merge-base --is-ancestor` |
| Root `CLAUDE.md` held an unrelated Antigravity install instruction | **Partly true.** The word is not in `CLAUDE.md`, but its "Autonomous JIT Skills" bullet points to `docs/SKILLS_REGISTRY.md`, whose commands are `npx -y agentic-awesome-skills --antigravity …`. Unrelated to the project, and it tells an agent to run third-party code. Recommend removing both from the submitted archive; a team decision, not changed here | `CLAUDE.md`; `docs/SKILLS_REGISTRY.md:26` |
| The branch deleted recovery and methodology docs | **True for the branch, restored on `main`.** All 5 files deleted by `5740040` exist today | `docs/RECOVERY_*.md`, `dataset_strategy.md`, `detection_methodology.md`; `708f624` |
| Heartbeat handling and CUSUM may change the baseline | **They do not.** Fresh benchmark, model used: 6535 / 4 / 16826 / 65, 378 of 378 cells equal. CUSUM is off by default (§5) | `artifacts/validation/stage2_readiness_20261103/` |

## 5. Code defects found during the audit (none changed)

1. **`detectors/physics.py:201-222` has the CUSUM block twice.** It has no effect while CUSUM is off, because `cusum_enabled`
   defaults to false and no config sets it. With it on, the evidence line would appear twice.
2. **`PhysicsDetector.cusum` is never updated.** Only `frame.cusum_drift_m` drives the rule. Its own integrator stays at zero, so
   `self.cusum.triggered` is never true in that class.
3. **Turning CUSUM on is unsafe on real streams.** `REPLAY` with `cusum_enabled: true` on the stationary bench captures gives
   false `GPS_SPOOFING` alerts: 8 on 009, 11 on 008, 22 on the 2026-10-28 capture (0, 0 and 0 `GPS_SPOOFING` with it off). It is
   not gated by the estimator status. **Keep it off, and do not present it as a working detector.** On the SIMULATED GPS fixture
   it does flag the 1 m/s drift, at 33.4 s.
4. **`docs/README.md:41`** calls the bench document "Pixhawk 6X + Raspberry Pi companion bench validation". No Pi was used.
5. **`docs/INLINE_IPS.md`** says "Not tested against a real flight controller, a radio or SITL", while later sections report
   SITL runs. The raw logs of those runs are not in the repository (`C:/afsitl` is absent on this machine), so those tables
   are prose only.

## 6. Integration recommendations

1. Treat `main` as the only base. Nothing on any other branch is required for Stage 2.
2. Keep the safety branches until submission, then delete them only if the team wishes. Remove the two stale worktrees with
   `git worktree remove` once nobody needs them. Not done here.
3. Handle `gps-assist` as in §3.
4. Ask each teammate to rebase on `main` from now on. `f816f41` shows how a merge can silently restore withdrawn claims.
   Before the freeze, re-run the search in `docs/STAGE2_GAPS_AND_PRIORITIES.md` §4.
