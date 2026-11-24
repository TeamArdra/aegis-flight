# Demonstration video: capture checklist (issue #33)

Issue #33 is `model:human` and `needs:human-approval`: **people record the video.** This page is the tick list for the
recording day: what to capture, in what order, which commands to run on screen, which environment tag and claim class to
state, and what must not be said. **Nothing here has been recorded, run for this page, or measured**; every "expect" is a
code behaviour or a committed artifact named next to it. Read the real values off the screen on the day.

Where the detail lives (this page does not replace them):
- [demo/DEMO_SCRIPT.md](demo/DEMO_SCRIPT.md): the narration, timings and the chronological shot list (S0 to S18).
- [demo/PRE_RECORDING_CHECKLIST.md](demo/PRE_RECORDING_CHECKLIST.md): freeze-build, bench-safety, SITL and screen set-up.
- [demo/EVIDENCE_AND_LIMITATIONS.md](demo/EVIDENCE_AND_LIMITATIONS.md): where `bytes_sent = 0` comes from, the evidence files, the limits to read aloud.
- [STAGE2_DEMO_RUNBOOK.md](STAGE2_DEMO_RUNBOOK.md): the older 12-minute runbook the script was adapted from.

Rules that bind the video (`AGENTS.md` §1, §5, §6): every result on screen carries an **environment tag** (`SIM`, `REPLAY`,
`SITL`, `HITL`, `FIELD`) and a **claim class** (link-level detection, command-path effect, estimator compromise, physical
deviation, real-world validation); a `SITL` link-level result is called exactly that; real-attack detection on real vehicles
is not claimed; attack tooling targets the local SITL link only; a serial vehicle link is receive-only.

## 0. Acceptance criteria from #33 (tick at the end)

- [ ] Recorded on the **freeze build** (tag `stage2-freeze-2026-11-27`, tree clean), after #23 merged. The commit hash is on the title and end cards.
- [ ] A **real run**, not slides, 3 to 5 minutes. Waiting time in the two SITL trials is cut, and each cut is marked on screen.
- [ ] An evidence label (environment tag + claim class) is visible on screen in every segment, and the dashboard header badge and footer are visible in every dashboard shot.
- [ ] File name, length, format, size and SHA-256 are recorded on the tracker (#4 / #9); the size is within the organisers' limit (ask them if still unknown).
- [ ] The script and shot list are committed with the evidence (they are `docs/demo/DEMO_SCRIPT.md` and this page; update both if the commands changed on the freeze build).

Known gap against #33's wording: the issue asks for the source bar to show "0 bytes sent". On the current tree the dashboard
does **not** display the transmit counter (its source bar shows link state and frame count; the defense panel's "0 BYTES SENT"
is a fixed label for the passive posture: `frontend/src/components/DefensePanel.tsx`). Read the measured counter from
`/api/status` in a terminal (step 1) and do not say the dashboard shows it, unless the freeze build really does.

## 1. Before recording (freeze build, one time)

Full list: [demo/PRE_RECORDING_CHECKLIST.md](demo/PRE_RECORDING_CHECKLIST.md). The ones that bite:

- [ ] `git status` clean; `git rev-parse HEAD` written down. Run every command below with `--help` on this build first: the CLI has changed between recent commits.
- [ ] `python -m pytest -p no:cacheprovider` and `ruff check src tests scripts backend` run; write down the pass/skip counts you actually got for the end card (do not copy a number from a document).
- [ ] `npm --prefix frontend ci`, then `npm --prefix frontend run build` (the server serves `frontend/dist`).
- [ ] Trained models present (git-ignored): `python scripts/fetch_models.py --verify-only`. `run_p2_trial.py` needs `models/isoforest_px4.joblib`.
- [ ] A scratch folder **outside the repository**; every `--db` and `--out` below points into it and does not already exist (the trial scripts refuse to overwrite). Nothing is written into `artifacts/`.
- [ ] Bench board: **disarmed, propellers off, restrained, no ground station connected on any port**, nobody touching the transmitter. Port found with `Get-PnpDevice -Class Ports -PresentOnly`; never open an SLCAN port, never sweep baud rates, never reconfigure the radio.
- [ ] PX4 SITL: record the version with `wsl -d Ubuntu-24.04 --cd /home/astryx/PX4-Autopilot -- git describe --tags --always` (it goes on the title card). Always name the distro.
- [ ] Terminals carry their tag in the prompt (`[BENCH]`, `[SITL]`, `[SIM db]`); resolution at least 1920x1080; no coordinates, tokens, `.claude/` or private paths on screen; do not open any `.tlog`.

## 2. Capture order

Each row: do it in this order, put the title card with the tag and claim class on screen first, then run the command. PowerShell,
repository root, `<scratch>` outside the repo, `<COM>` the bench port.

| Step | Time | Tag / claim class to show | Command run on screen | What to point at | Expect (not yet observed) |
|---|---|---|---|---|---|
| 0 | 0:00-0:20 | legend card | none | commit, PX4 `git describe`, legend: BENCH = physical autopilot on a desk, disarmed, receive-only; SITL = PX4 software on this laptop; SIM = in-process simulator; "No flight. No attack on real hardware." | |
| 1 | 0:20-1:20 | `BENCH`, receive-only ingestion, **no detection claim** | `.venv\Scripts\aegis.exe serve --source serial --serial-port <COM> --baud 115200 --no-reconnect --port 8000 --db <scratch>\bench_demo.sqlite` (start it before the take) then in a terminal `(Invoke-RestMethod http://127.0.0.1:8000/api/status).link.transport \| Select-Object bytes_sent, write_errors, frames_received` | header badge `BENCH`; source label "Physical bench (live serial)"; link "Live"; posture `PASSIVE`; armed `NO`; the terminal counters | `bytes_sent` 0, `write_errors` 0, `frames_received` > 0 and rising (`src/aegisflight/backend/sources.py`). Do not pass `--defense-mode`, `--gcs-notify`, `--mgmt-key-file`. Do not click ACTIVE IPS, Safe Hold or any attack button |
| 2 | 1:20-2:20 | `SITL`, **link-level detection** (PX4 never receives a modified frame) | off camera: `wsl -d Ubuntu-24.04 -- bash <repo>/scripts/sitl/start_px4_sitl.sh stop`, then `start`, wait about 30 s, `status`. On camera: `.venv\Scripts\python.exe scripts\sitl\run_p2_trial.py --seed 1001 --trial-index 0 --seconds 90 --out <scratch>\sitl_drift_demo`; then `Get-Content <scratch>\sitl_drift_demo.ids_decisions.jsonl \| ConvertFrom-Json \| Where-Object threat \| Select-Object -First 3 t, type, score, evidence \| Format-List` | the command line, the final JSON (`frames_modified`, `ids_threat_decisions`), an alert and its **evidence strings**; mark the cut | read what this run prints. If it does not detect, say so. Committed reference runs fired at or after the drift window closed (`artifacts/sitl/closure/final_drift_summary.md`): if yours does, say "it fired when the position jumped back" |
| 3 | 2:20-3:10 | `SITL`, **command-path effect and link-level detection, scored separately** | fresh SITL boot as above, then `.venv\Scripts\python.exe scripts\sitl\run_p2_injection_trial.py --seed 2001 --trial-index 0 --seconds 100 --out <scratch>\sitl_inject_demo`; then `Get-Content <scratch>\sitl_inject_demo.manifest.json \| ConvertFrom-Json \| Select-Object environment, claim_class, frames_injected \| Format-List` and the `COMMAND_INJECTION` decision lines | manifest `environment` and `claim_class`; the acknowledgement result; the alert and its evidence | PX4 on the ground, disarmed: an accepted acknowledgement is acceptance, not a state change. The monitor saw the command only because the harness mirrors the uplink to it. A forger copying the real ground station's identity was not detected in the committed tests (`artifacts/sitl/P2_gcs_impersonation_summary.md`) |
| 4 | 3:10-4:00 | log integrity, **unsigned**; no detection claim | `.venv\Scripts\aegis.exe verify-log <scratch>\bench_demo.sqlite`; then `.venv\Scripts\aegis.exe simulate --attack gps_spoofing --db <scratch>\sim_demo.sqlite`, `verify-log` on it, copy it, edit one stored alert in the **copy** (the one-liner in `demo/DEMO_SCRIPT.md` segment 4), `verify-log` the copy | `chain: OK`; then `chain: BROKEN ... event id=...` and exit code 2 | If the bench database has 0 events, say so and continue on the `SIM` database. Anchors (`aegis verify-log <db> --anchors <file>`): show only if a run that wrote anchors exists on the freeze build and verifies (they are written by `aegis ips-bridge --db`; #21 is open); otherwise say the chain is not externally anchored |
| 5 | 4:00-4:40 | limits, read as written | none | text card + voice (§3) | end card: commit, PX4 version, the pytest counts you obtained |

Restricted-visibility injection (#18 / #24 item 3) was descoped after the #17 no-go: do not show or mention it as done; the
forged-command scenario in step 3 is the substitute #33 allows. If the freeze build changes that, update this table first.

## 3. Say, and never say

Say aloud, near the start of each segment, the tag and claim class from the table, and in the closing card (adapt to what the
screen showed):

> "Nothing in this video flew. The bench board was disarmed with its propellers off and was only listened to; the transmit
> counter is a software counter, not a wire measurement. The attacks ran on a software-in-the-loop link on this laptop. We
> have not attacked a real vehicle or a radio link, and the bench run is not a hardware validation of detection. Known gaps:
> a replayed or forged command carrying the real ground station's identity is not detected without message signing; slow GPS
> drift is missed; status messages are not authenticated; the log is not externally anchored."

Never claim:
- detection of an attack on a real vehicle, real RF, or "GPS spoofing of the vehicle" (the drift is a modified link seen by the monitor, `SITL`, link-level only);
- that the bench segment detects anything (it shows receive-only ingestion);
- "prevented", "protected the drone", "stayed airborne", or any defense figure: the prevention layer is not shown and ACTIVE IPS is not clicked;
- a false-alarm rate per hour, a companion-computer result, or any number that is not on screen from this recording or in a committed artifact you can name;
- that the dashboard shows the transmit counter (see §0).

The tag word on screen for the desk-top board is the dashboard's `BENCH` badge. `AGENTS.md` §6 lists `SIM`, `REPLAY`,
`SITL`, `HITL`, `FIELD` and has no `BENCH`: the hardware docs use it for a receive-only desk-top capture, so say what it
means (legend card) and do not substitute `HITL` or `FIELD`.

## 4. If something fails

Say what failed on camera; do not retry a serial port in a loop; never reuse or delete an earlier `--out`. A stale or wrong
badge: stop and restart, never narrate over it. A SITL trial that reports the PX4 heartbeat timeout: restart SITL (stop, start,
wait 30 s) and use a new `--out`. A bench fallback must be labelled `REPLAY` (loopback virtual port,
`scripts/hardware/virtual_serial_replay.py`, details in `demo/DEMO_SCRIPT.md`) and said aloud; it is never narrated as live.

## 5. After recording

- [ ] Video saved outside Git. Record file name, length, format, size and `Get-FileHash -Algorithm SHA256 <file>` on the tracker.
- [ ] PX4 tree untouched: `wsl -d Ubuntu-24.04 --cd /home/astryx/PX4-Autopilot -- git status --porcelain --untracked-files=no` prints nothing (run from PowerShell).
- [ ] Text evidence saved with the commit and PX4 version: the `/api/status` counters, both `verify-log` outputs (OK and BROKEN), the trial manifests. The trial folders hold positions in `frames.jsonl`: keep them out of the repository unless the evidence owner decides otherwise.
- [ ] `video/<file>` (or `video/VIDEO_LINK.txt` if the organisers require a link) goes into the package ([SUBMISSION.md](SUBMISSION.md) §1) and its SHA-256 into `MANIFEST.sha256`.
