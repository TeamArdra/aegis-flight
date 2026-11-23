# Stage-2 submission package: layout, regeneration commands, human checklist, verifier

Issue #34 (assemble and verify the final package), under epic #9 and tracker #4. Issue #34 is `model:human` and
`needs:human-approval`: **people assemble, sign and submit the package.** This page gives them a layout, the commands that
regenerate each evidence item, an explicit list of what only a human can do, and a read-only verifier.

**Status: preparation only.** No package has been assembled, no evidence item below was regenerated for this page, and
this page records no result. Every number in the real package must come from a generated artifact on the freeze tag
(`AGENTS.md` §6). The layout in §1 is a proposal for the maintainers to accept or change; the verifier reads it from one
table (`REQUIRED` in `scripts/submission/verify_package.py`), so changing the layout is a one-place edit.

The demonstration video (#33) has its own checklist: [DEMO_VIDEO_CHECKLIST.md](DEMO_VIDEO_CHECKLIST.md). The older
inventory of what is in Git and what is not is [SUBMISSION_ARCHIVE_MANIFEST.md](SUBMISSION_ARCHIVE_MANIFEST.md) (a 2026-10-29
draft; read its §2 to §4 for the data-handling decisions that are still open).

## 1. Package layout (proposed)

The package is a directory (zip it last). The right-hand column is the verifier's check id.

```
<package>/
  README.md  INSTALL.md  REPRODUCE.md          readme, install, reproduce      (required)
  MANIFEST.sha256                               sha256sum format; #34 calls it CHECKSUMS.sha256, either is accepted
  report/<final name>.pdf                       the final PDF                    (report)
  report/<source>.md                            optional text source; enables the number check (§4)
  video/<file>.mp4 | video/VIDEO_LINK.txt       #33; a link only if the organisers require one   (video)
  models/MODELS.sha256                          SHA-256 of the trained models (D3)               (model-hashes)
  results/validation/junit.xml                  clean-install pytest JUnit, 0 failures           (junit)
  configs/  src/  tests/  scripts/  backend/  frontend/ (source only)  docs/    the freeze-tag tree
  artifacts/sitl/final_<tag>/...                #26 campaign outputs                             (sitl-campaign)
  artifacts/sitl/final_<tag>/**/frames_down.jsonl   inline-bridge raw logs (#26)                 (bridge-raw-logs)
  artifacts/validation/final_<tag>/sweep/      #27 link-stress sweep                            (link-stress)
  artifacts/benchmarks_extended/summary.md      #27 regenerated extended benchmark               (benchmark-extended)
  artifacts/validation/stage2_metrics_<tag>/    #28 metrics (metrics.json, metrics.md)           (stage2-metrics)
  artifacts/hardware/**/*.sha256                SHA-256 manifests of the #29/#30 captures        (capture-hashes)
  artifacts/hardware/companion_*/paced.json     #30 paced-replay output                          (pi-run)
```

Not in the package (the verifier fails on them; `--allow PATTERN` lets a human-approved file through):

| Item | Why | If the team decides otherwise |
|---|---|---|
| `*.joblib` | git-ignored by rule (`AGENTS.md` §6); the models are shipped by SHA-256 under D3 ([MODEL_DISTRIBUTION.md](MODEL_DISTRIBUTION.md)) | #34 also says "the trained models, with SHA-256". If D3 resolves to bundling the files, run the verifier with `--allow 'models/*.joblib'`; the files are then hash-checked against `models/MODELS.sha256` |
| `*.sqlite` | event databases | the bridge run archive writes `events.sqlite` next to `frames_down.jsonl`; leave the database out and keep its SHA-256 in the manifest of the run's notes |
| `*.tlog`, `*.rawbin`, `*.ulg`, `*.pcap` | raw captures; bench captures hold the real position ([SUBMISSION_ARCHIVE_MANIFEST.md](SUBMISSION_ARCHIVE_MANIFEST.md) §2) | ship only their SHA-256 (the capture manifests above), or `--allow` a copy a human has cleared |
| `.claude/`, `.git/`, `.venv/`, `node_modules/`, `frontend/dist/`, caches, symlinks | local or build-only | none |
| secret-looking file names or contents (keys, `.env`, tokens, signing keys) | `AGENTS.md` §5 | none |

## 2. Regenerate each evidence item

Run on the freeze tag `stage2-freeze-2026-11-27` (when it exists) with a clean tree. Only commands that exist in this
repository are listed; the file that defines each is cited. `<scratch>` is a directory **outside** the repository.
Environment tag and claim class are what the result may be called, nothing more (`AGENTS.md` §6).

| # | Item | Env / claim class | Command (repo root) | Defined in |
|---|---|---|---|---|
| a | Install, models | - | `pip install -e ".[dev]"` then `python scripts/fetch_models.py` (or `--verify-only` if the files were copied in; `(cd models && sha256sum -c MODELS.sha256)`) | `pyproject.toml`, `scripts/fetch_models.py`, [MODEL_DISTRIBUTION.md](MODEL_DISTRIBUTION.md) |
| b | Python tests + JUnit (#12, #34) | - | `python -m pytest -p no:cacheprovider --junitxml=results/validation/junit.xml` (do not add `-q`: `addopts` has it). Run it in a fresh clone and a fresh venv; `artifacts/validation/consolidation_20261031/clean_install.sh` is the earlier script for that | `pyproject.toml`, [TESTING.md](TESTING.md) |
| c | Lint | - | `ruff check src tests scripts backend` | `AGENTS.md` §2 |
| d | Frontend | - | `npm --prefix frontend ci`, `npm --prefix frontend test`, `npm --prefix frontend run build` | `AGENTS.md` §2 |
| e | Stage-1 regression (#27) | `SIM` | `aegis benchmark --out <scratch> --no-figures`, then read the `TP / FP` row of `<scratch>/summary.md`: it must equal the committed `artifacts/benchmarks/summary.md`. Always pass `--no-figures` and a scratch `--out` | `AGENTS.md` §6, [BENCHMARKING.md](BENCHMARKING.md) |
| f | Extended benchmark (#27) | `SIM` | `python scripts/benchmark_extended.py --workers 8 --out artifacts/benchmarks_extended` (the default `--out`; it **overwrites committed artifacts**: run it on the freeze commit only, as #27 directs, and explain any difference from the committed `summary.md`) | `scripts/benchmark_extended.py`, [BENCHMARKING.md](BENCHMARKING.md) |
| g | Link-stress sweep (#27) | `SIM` | `python scripts/sweep_link_stress.py --out artifacts/validation/final_<tag>/sweep --workers 4` | `scripts/sweep_link_stress.py` (docstring), [BENCHMARKING.md](BENCHMARKING.md) |
| h | Real-data replays (#27) | `REPLAY` | `python scripts/fetch_external_data.py --alfa --px4 <N>` then `python scripts/external_validation.py --px4 --alfa --out <dir>`; bench captures through `aegis serve --source replay --tlog <file> --replay-speed 1.0 --db <scratch>/x.sqlite` | `scripts/fetch_external_data.py`, `scripts/external_validation.py`, [EXTERNAL_DATA.md](EXTERNAL_DATA.md) |
| i | Metrics (#28) | as the inputs | `python scripts/make_stage2_metrics.py --tag <tag>` (reads committed artifacts only; exits 2 and writes nothing if an input is absent) | `scripts/make_stage2_metrics.py`, [BENCHMARKING.md](BENCHMARKING.md) |
| j | Session intervals, latency tables | `SIM` | `python scripts/make_submission_stats.py --sessions artifacts/benchmarks_extended/sessions.csv --out <dir>` | `scripts/make_submission_stats.py` |
| k | Report figures | `SIM` / synthetic, as labelled | `python scripts/demo/make_stage2_report_figures.py --evaluation <evaluation.json> --sessions <sessions.csv> --out <dir>` | `scripts/demo/make_stage2_report_figures.py` |
| l | Validation table | from artifacts | `python scripts/make_validation_table.py`. It takes **no arguments, ignores `--help`, and rewrites `artifacts/validation/validation_table.md`**: run it only when you mean to | `scripts/make_validation_table.py` |
| m | SITL campaign, PX4 + ArduPilot (#26) | `SITL`, link-level detection; command-path effect only where the trial manifest says so | preview: `python scripts/sitl/run_campaign.py --out-root artifacts/sitl/final_<tag> --n 10 --list`; run: the same without `--list` (add `--resume` to continue). Needs WSL + PX4 (+ ArduPilot). Telemetry, firmware and restricted-visibility scenarios are not in the built-in table: pass them with `--scenarios-file` (none is committed yet) or run `python scripts/sitl/run_p2_telemetry_trial.py --scenario <name> --seed <n> --out <dir>` per trial | `scripts/sitl/run_campaign.py` (docstring), `scripts/sitl/run_p2_telemetry_trial.py` (`--help`) |
| n | Inline-bridge raw logs (#26) | `SITL`, loopback only | `bash scripts/sitl/run_bridge_evidence.sh <ardupilot_dir> <run_dir> [seconds]` (Linux/WSL; refuses an existing `<run_dir>`) | `scripts/sitl/run_bridge_evidence.sh` (header), `src/aegisflight/hal/run_archive.py` |
| o | PX4 tree untouched (after any WSL work) | - | from PowerShell: `wsl -d Ubuntu-24.04 --cd /home/astryx/PX4-Autopilot -- git status --porcelain --untracked-files=no` prints nothing | `.claude/CLAUDE.md`, #26 |
| p | Outdoor walk and range capture (#29) | receive-only hardware capture, no detection claim (the team names the tag: `AGENTS.md` §6 lists `SIM`, `REPLAY`, `SITL`, `HITL`, `FIELD`; the hardware docs say `BENCH`) | `python scripts/hardware/run_serial_ids.py --port <COM> --baud <baud> --out-dir <dir> --seconds <s> --no-reconnect --defense-mode passive --tlog data/hardware/raw/<name>.tlog`; then `python scripts/hardware/gnss_tlog_summary.py <tlog> --json <out.json>`; then the capture's SHA-256 (`sha256sum`, or `Get-FileHash -Algorithm SHA256`). `bytes_sent` must be 0 (the run exits 3 otherwise) | `scripts/hardware/run_serial_ids.py` (docstring), [HARDWARE_BENCH_PIXHAWK6X.md](HARDWARE_BENCH_PIXHAWK6X.md) |
| q | Companion-computer compute (#30) | `REPLAY` on the host it runs on; **not a flight or radio test** | `python scripts/hardware/paced_replay.py <tlog> --factor 1 --factor 3 --ml both --label pi --out artifacts/hardware/companion_pi_<date>/paced.json`; inline-bridge soak on POSIX: `python scripts/pi_soak.py --seconds 60 --rate-mult 5 --mode active-ips` | `scripts/hardware/paced_replay.py`, `scripts/pi_soak.py` (docstrings), [PERFORMANCE.md](PERFORMANCE.md) |
| r | Event-log chain | log integrity (unsigned) | `aegis verify-log <db.sqlite>`; with an anchors file `aegis verify-log <db.sqlite> --anchors <db.sqlite.anchors.jsonl>` (anchors are written by `aegis ips-bridge --db`; issue #21 is still open) | `src/aegisflight/cli/main.py`, [EVENT_LOGGING.md](EVENT_LOGGING.md) |
| s | Withdrawn-claim guard | - | `python scripts/claims_guard.py` (exit 0) | `scripts/claims_guard.py` |
| t | Archive from the tag | - | plain git, tracked files only (no `.claude/`, models or databases): `git archive --format=zip --prefix=aegisflight/ -o <scratch>/src.zip stage2-freeze-2026-11-27`. No script in the repository assembles the full package | `git` |
| u | Manifest | - | in the package root: `find . -type f ! -name MANIFEST.sha256 -print0 \| LC_ALL=C sort -z \| xargs -0 sha256sum > MANIFEST.sha256`; check with `sha256sum -c MANIFEST.sha256` | coreutils |

Each regenerated item goes into `REPRODUCE.md` as a section whose heading names the topic and whose body holds the command
that was actually run. #34 requires one for each of: walk test, Pi run, link-stress sweep, restricted-visibility injection,
telemetry SITL, firmware SITL (the verifier checks the headings, §4). If a scenario was descoped (issue #24 item 3,
restricted visibility, was descoped after the #17 no-go: see [demo/EVIDENCE_AND_LIMITATIONS.md](demo/EVIDENCE_AND_LIMITATIONS.md)
§4), its section says "descoped" or "not run" and the report discloses it.

## 3. Human-only checklist

Nothing below can be decided or produced by a script or an agent. Tick each one yourself.

**Before assembly**
- [ ] The freeze tag `stage2-freeze-2026-11-27` exists and the tree is clean (`git status`); the tag is named in the report.
- [ ] Decisions recorded on the tracker (#4): D3 models (release asset + SHA-256, or bundle: sets the `--allow` below), D7 PX4 version, D8 hardware / GCS firmware read, D9 report source location.
- [ ] Organisers' answers received and quoted in the report (upload size and format limits, archive size limit, what "Distance Covered" means). The package fits the limits.
- [ ] `aegis-reviewer` has returned "supported" on the #26 and #28 summary tables before they enter the report (#26, #28 acceptance).

**Evidence only people can produce**
- [ ] Hardware sessions #29 and #30: site and radio-band legality, props off, vehicle disarmed, receive-only, a phone GPX track as the distance reference, the firmware version only if D8 allows a transmitting GCS (#29 preconditions).
- [ ] The raw-capture decision: `*.tlog` hold the real position. Ship only SHA-256 values, or a copy a human has cleared and passed to the verifier with `--allow`.
- [ ] The demonstration video (#33): recorded, labelled, and its file name, length, format, size and SHA-256 recorded on the tracker. See [DEMO_VIDEO_CHECKLIST.md](DEMO_VIDEO_CHECKLIST.md).
- [ ] A clean-install run on a fresh machine or VM (not this laptop's venv): the JUnit XML in `results/validation/` shows 0 failures.

**Report and declarations**
- [ ] Team ID, team-leader signature, submission date, the integrity declaration, and the statement of what the team itself reviewed and ran (the AI-tool verification statement). The verifier cannot see a signature in a PDF.
- [ ] `LICENSE` holder line confirmed ([SUBMISSION_ARCHIVE_MANIFEST.md](SUBMISSION_ARCHIVE_MANIFEST.md) §4).
- [ ] Final PDF read page by page: tables fit the page, every figure is referenced, page numbers are consistent, the Word page-break check is done, the final file name is used.
- [ ] Search the **PDF** for `AWAITING`, `TODO` and `TBD` with the reader's own text search (the verifier scans text sources only).
- [ ] Every number in the report was checked against its artifact by a person; the verifier's number check (§4) is a heuristic, not a proof. No "prevented", "protected" or real-vehicle detection claim (`AGENTS.md` §1).

**Final**
- [ ] `python scripts/submission/verify_package.py <package>` exits 0 and its output is saved with the package notes; `sha256sum -c MANIFEST.sha256` passes.
- [ ] Submitted before 12:00 on Wed 2 Dec 2026 by the team leader.
- [ ] The SHA-256 of each submitted file is posted as a comment on #9 and on the tracker #4.

## 4. Run the verifier

```bash
python scripts/submission/verify_package.py <package_dir>
python scripts/submission/verify_package.py <package_dir> --report report/report.md --strict
```

Standard library only; it reads files under `<package_dir>` and nothing else, never writes, and never touches the network
(a test asserts it imports no network or process module). It prints one `PASS` / `WARN` / `FAIL` line per check with every
finding underneath, and exits 0 only when nothing failed.

| Exit | Meaning |
|---|---|
| 0 | no failure (warnings may remain; `--strict` makes them fail) |
| 1 | at least one failure |
| 2 | `<package_dir>` is not a directory |

| Check | Fails when |
|---|---|
| `required` | an item of the §1 layout is missing (each finding names the issue and the globs looked for) |
| `manifest` | a manifest line is malformed or escapes the package, a listed file is missing, or a SHA-256 differs; unlisted files are WARN; `models/MODELS.sha256` must be well formed and any model file present must match |
| `forbidden` | a forbidden file, directory or symlink (§1), or file content that looks like a key or token (the text is never printed) |
| `placeholders` | `AWAITING`, `TODO` or `TBD` in README\*, INSTALL\*, REPRODUCE\*, top-level text files, `report/`, `configs/` (`--scan-extra GLOB` adds more) |
| `junit` | a `results/validation/*.xml` that is not JUnit, declares a DTD, has no tests, or has any failure or error |
| `reproduce` | `REPRODUCE.md` has no heading for one of the six topics, or that section has neither a code block nor a "not run" / "descoped" statement |
| `numbers` | see below |

**Number check (heuristic, documented in the script's docstring).** It runs on text reports (`report/**/*.md`,
`REPORT.md`, or `--report`). In each paragraph or table row it finds `artifacts/...` paths and result numbers (percentages,
decimals, `a/b` fractions, integers of four digits or more; section, figure and table numbers, versions, dates, URLs and
issue numbers are ignored; integers below 1,000 are ignored as too ambiguous). A cited path that is not in the package is
a FAIL. A result number must appear verbatim in a cited text artifact (a directory means every text file under it), or, for
a percentage, as a ratio that rounds to it. Otherwise it is a FAIL, listed, never corrected. A number in a paragraph that
cites no artifact is a WARN (it may legitimately come from elsewhere). `--allow-numbers FILE` records numbers a human
accepted. If there is no text report, the check says `SKIPPED` as a WARN: a PDF-only package is **not** number-checked, and
a PASS elsewhere does not cover it.

What it cannot do: read a PDF or a signature, judge whether a command in `REPRODUCE.md` is right, or confirm that a number
means what the sentence says. Tests: `python -m pytest tests/unit/test_verify_package.py`.
