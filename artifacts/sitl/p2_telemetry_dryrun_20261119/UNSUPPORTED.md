# UNSUPPORTED: this dry run is not validated evidence

**Status: NOT reproducible, NOT validated evidence.** This directory may not be cited for any detection
claim, false-positive-rate claim, reproducibility claim, or as support for any statement in a report,
README or submission document. It is kept only as a record of an exploratory SITL dry run. The nine
`*.manifest.json` files and the numbers in `summary.md` are unchanged; this file records why they cannot
be trusted. Environment: `SITL`; claim class: none.

## Provenance defects (exact manifest fields)

1. **`full_provenance.status` = `"REPRODUCIBLE"` and `full_provenance.reproducible` = `true` are wrong.**
   Both fields are asserted in all 9 manifests, but the run fails every condition below, and
   `full_provenance.not_reproducible_reason` is `null`. Do not rely on these fields.
2. **PX4 build not identifiable.** `full_provenance.px4_git_describe` = `"bce8453e-dirty"` in all 9
   manifests. `-dirty` means the PX4 tree had uncommitted changes, so the firmware cannot be rebuilt.
3. **Code commit not in the history this work stacks on.** `full_provenance.commit` =
   `b2170eb54ddb7d0193e1f5a67cab791701484072` (with `working_tree_dirty: false`) is not an ancestor of the
   issue #80 branch (`fix/80-ips-onboard-correctness`) or of `main`. The code that produced the run is
   therefore not the code under review.
4. **Run predates the removal of the force-ARM primitive.** In `p2t_rogue_force_disarm_001.manifest.json`
   `pre_arm_sent` = `true` (and `vehicle_armed_observed` = `false`), i.e. the run sent a pre-arm/ARM
   command through the proxy. That primitive was removed in #80 (commit `5b9ed95`), so this behaviour is not
   reproducible with the current tree. The other 8 manifests carry `pre_arm_sent: null`.
5. **Personal absolute path in the command.** `full_provenance.command_line` ends with
   `--out /Users/madhavchoudhary/Developer/wt-24/artifacts/sitl/p2_telemetry_dryrun_20261119/p2t_<scenario>_001`
   in all 9 manifests: a contributor's local machine path. The recorded command cannot be run as written.
6. **Raw evidence not committed.** The directory holds only the 9 manifests and `summary.md`. There are no
   `*.frames.jsonl` (per-frame proxy log) and no decisions/alerts files, so the "Decisions" and "Threats"
   columns (e.g. `rogue_force_disarm`: 10 of 75) cannot be re-derived or audited.
7. **Not a detection experiment.** n = 1 per scenario, seed 1001, 15 s, `--warmup-s 0`, no
   benign-baseline or FPR design. 8 of 9 scenarios reported 0 threats.

## Permitted use

None for claims. Do not quote the frame counts, `Threats` column, "10 of 75", or any rate derived from
them. `scripts/claims_guard.py` fails CI if this directory's path is cited outside this directory.

## What a valid regeneration requires

- A clean PX4 build with `git describe` recorded exactly (no `-dirty` suffix), and the PX4 revision pinned.
- A final, pushed AegisFlight commit that is an ancestor of the reviewed branch, run from a clean tree
  (`working_tree_dirty: false`, empty `dirty_paths`), so `commit` resolves in the repository.
- Committed raw outputs for every trial: `*.frames.jsonl` plus decisions/alerts files, with sha256s
  recorded in the manifest.
- Sanitised `--out` and other paths (repo-relative, no home directories or usernames).
- The exact command in `command_line`, runnable from the repository root, and a manifest whose
  `reproducible` field is derived from those checks rather than hard-coded.
- A scenario design with enough trials (and benign controls) for the claim being made; the scenarios here
  are one trial each.
- Review by someone other than the author of the attack hooks and detectors (same-team authorship is
  disclosed in `docs/ATTACK_PROXY.md` §9).
