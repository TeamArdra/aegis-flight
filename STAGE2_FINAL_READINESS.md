# Stage 2 final readiness

As of 2026-11-23 (main `2bae45a`). Code freeze tag `stage2-freeze-2026-11-27`; submission 2 Dec. The plan is in `STAGE2_DELIVERY_PLAN.md` and the
findings are in `STAGE2_AUDIT.md`.

Status words: **code-complete** (merged or mergeable, tests green); **evidence-complete** (a committed artifact with a regenerating
command, from the freeze tag); **submission-ready** (both of those, plus the report states it correctly).

## 1. Readiness matrix (template sections)

| Section (marks) | Code | Evidence | Report | Blocking items |
|---|---|---|---|---|
| §5–§6 detection (30) | code-complete on the stack; Stage-1 `6535 / 4 / 16826 / 65` reproduced | SIM complete; SITL needs the freeze rerun (#26); replays (#27) | 25 numbers differ and 53 are unsourced (#31) | A1, A11 → #26, #27, #31 |
| §7 false alarms (8) | code-complete; D12/D13/D14/D15 being implemented as fix-ups | no own-flight exposure (LIMITATION); public-log replay only | must state "rate not established" | A4–A7 merges; #29 adds healthy-GNSS ground data, not flight |
| §8 validation (14) | suite green; provenance writer defect being fixed (A11) | the SITL manifests' model hash is wrong (erratum); inline-IPS raw logs not archived | correct item 13 and the BENCH wording (#31) | A11 before #26 |
| §9 compute and integration (8) | dashboard, install guide; D9 being implemented (#93) | **no Pi measurement; no demo video** | blanks stay blank until measured | #30, #33 (human) |
| §10–§11 package (12) | verifier and checklists in #157 | – | licence, risk register, AI declaration, signature | #34 (human), #32 |

## 2. Report consistency

The prep is in report-repo draft PR TeamArdra/aegisflight-report#1. Of the 819 numbers in the 11-06 build:
- 655 match an artifact;
- **25 differ**: pre-#14 extended-benchmark values; "0.956 crosses 0.45" (the crossing score is 0.9563); SITL latency "0.0–3.0 s" (delay is 7.7–12.5 s from onset);
- **53 are unsourced** (test counts, interpreter and Node versions, the missing `requirements-lock.txt`);
- 86 wait for the freeze run.

Claims to correct:
- "ML off on live sources" is false for the PX4 SITL batches;
- "no attack on real hardware" and "bridge SITL only" contradict the BENCH Pixhawk batches in `docs/RADIO_TEST_RESULTS.md`.

## 3. Evidence inventory (tags as required)

| Evidence | Tag | Location | Status |
|---|---|---|---|
| Stage-1 benchmark | SIM | `artifacts/benchmarks/summary.md` | reproduced 2026-11-23 |
| Extended benchmark (post-#14) | SIM | `artifacts/validation/seq_reorder_20261118` | current; the report quotes older values |
| PX4/ArduPilot SITL batches | SITL | `artifacts/sitl/` | from Oct code on dirty trees; model-hash field wrong; **rerun (#26)** |
| Public-log replays (ALFA, PX4) | REPLAY | `artifacts/external/` | regenerate on the freeze tag (#27) |
| Passive bench captures | BENCH | `docs/HARDWARE_BENCH_PIXHAWK6X.md` | receive-only, indoor, GPS unhealthy |
| Radio and real-Pixhawk attack batches 1–3 | BENCH | `docs/RADIO_TEST_RESULTS.md` | prose; raw logs not archived; disclosure is the maintainer's decision |
| HITL, FLIGHT | – | – | **none exists; never claim** |

## 4. Human-only actions

Do them in this order. None of them involves sending attack traffic to real hardware.

| # | Action | Why | Needs | Procedure | Output |
|---|---|---|---|---|---|
| H1 | **Merges**: #91 is done; next #101, then the D-fix-ups as they turn ready, then #81 → #82 and their children, #154 → #160, #157, #93, the A11 fix | stack and decisions into main | maintainer | Create a merge commit for every PR into a stack branch; squash for main | main at the freeze candidate |
| H2 | **Triage**: label #144 and #155 `agent-ready` (or accept #154/#160 as they are) | model-verification chain | maintainer | GitHub labels | – |
| H3 | **Report lineage**: choose the canonical lineage (11-06 build or 11-07 hand edits); decide the capture-counting rule; decide how the BENCH Pixhawk batches are disclosed; choose the PX4 version (D7) | #31 | team | read `prep/LINEAGE_COMPARISON.md` in aegisflight-report#1 | a decision comment on #31 |
| H4 | **Freeze tag** `stage2-freeze-2026-11-27` on main after H1 | everything below must use one commit | maintainer | `git tag -a stage2-freeze-2026-11-27 <sha>`, then `git push origin stage2-freeze-2026-11-27` | the tag |
| H5 | **Supervised SITL campaign** | #26: §5–§8 SITL numbers on the freeze tag | Windows + WSL `Ubuntu-24.04`, PX4 at the recorded describe, about 12 h | issue #26 procedure on the tag with a clean tree; outputs to `artifacts/sitl/final_<tag>/`; afterwards run, from PowerShell, `wsl -d Ubuntu-24.04 --cd /home/astryx/PX4-Autopilot -- git status --porcelain --untracked-files=no` (it must print nothing) | per-scenario summaries with Wilson CIs; every manifest has `working_tree_dirty: false` and the **correct** model hash (needs A11 merged first) |
| H6 | **Outdoor receive-only walk** | #29: the only healthy-GNSS real data; real distance | board on battery, **props removed, disarmed**; radio band legal at the site (865–867 MHz is licence-exempt in India; **915 MHz is not**); site permission; phone GPX logger | #29 protocol: 10 min static, a ≥ 500 m loop, then the range walk; `scripts/hardware/run_serial_ids.py --tlog <file> --out-dir <dir>`, and `bytes_sent` must be 0 | raw tlog and the IDS output dir; analysis runs later on the freeze tag (#27) |
| H7 | **Pi compute run** | #30: §9 resource use on the target | Raspberry Pi-class board, **TX line physically disconnected (photo)**, USB power meter, scale | #30 Part B: a 10-min live `run_serial_ids.py`, ML off then on; `scripts/hardware/paced_replay.py` at 1× and 3×, ML on and off; idle vs running power; mass | JSON outputs plus photos, committed under `artifacts/hardware/` |
| H8 | **Demo video** (3–5 min, a real run) | #33: the only demonstration requirement (template p. 19–20) | screen recorder; the freeze build | `docs/DEMO_VIDEO_CHECKLIST.md` (#157); state the tag and claim class on screen; SIM or SITL only for attacks | the video file plus its sha256 |
| H9 | **Licences and risk register** | §10 | team | check the ALFA licence at its source (CC BY 4.0 vs CC0); describe the Rust/Tauri prototypes or exclude them; update `docs/RISK_REGISTER.md` to the actual kit | edits through PRs |
| H10 | **AI-tool declaration and integrity signature** | §11 | each team member | read the final report; state what was verified; sign | a signed PDF |
| H11 | **Archive and submit** | #34 | maintainer | `git archive` at the tag; add the report, video and evidence; then `python scripts/submission/verify_package.py <dir>` (#157), which must exit 0 | the submitted package |

## 5. Archive checklist (checked by #157's verifier)

- [ ] Source from `git archive` at the freeze tag; no `models/*.joblib` unless D3 says otherwise; no `*.sqlite`, captures, secrets or `.claude/`.
- [ ] Report PDF with every number traceable (aegisflight-report#1 CSV, regenerated at the freeze).
- [ ] Test-suite run on a clean machine at the tag (the JUnit file in the package, 0 failures).
- [ ] Stage-1 `6535 / 4 / 16826 / 65` at the tag.
- [ ] SITL (#26) and REPLAY (#27) outputs at the tag, with their manifests.
- [ ] Demo video and its checksum.
- [ ] `MANIFEST.sha256` / `CHECKSUMS.sha256` verifies.
- [ ] Signed integrity declaration.

## 6. Final release gate

Submit when every line is true:
1. A1–A11 are merged, or explicitly marked as a documented limitation.
2. The freeze tag exists, and CI is green on it.
3. H5 and #27 outputs are committed from the tag; the report's 86 freeze numbers are filled from them; the 25 differing and 53 unsourced
   numbers are corrected or removed.
4. No SIM/SITL/BENCH/HITL/FLIGHT label is wrong (the reviewer checks the traceability CSV).
5. H8 video and H10 signatures exist.
6. `verify_package.py` exits 0 on the final directory.
