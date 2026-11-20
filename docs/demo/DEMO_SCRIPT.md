# Stage-2 demonstration video: script and shot list (issue #33)

**Status: preparation only. Nothing in this folder has been recorded.** No video, screenshot, log or number in
this folder comes from the recording; every "expected" value below is either a code behaviour (cited by
file:line) or a previous committed artifact (cited by path). Read the real values off the screen on the day.

Companion files:
- `PRE_RECORDING_CHECKLIST.md`: environment, safety and freeze-build checks, run before pressing record.
- `EVIDENCE_AND_LIMITATIONS.md`: what to capture, where `bytes_sent` comes from, what must be said on camera.

Adapted from the off-main `docs/STAGE2_DEMO_RUNBOOK.md` (commit `2d74496`, not on `main`) and the on-main
`docs/DEMO_SCRIPT_SOFTWARE_ONLY.md`. Where those differ from `main`, this file follows `main`: the
`demo/indoor_bench_profile/`, `demo/fixtures/` and `scripts/demo/` paths they use do not exist on `main` and are
not used here.

Run every command from the repository root in **PowerShell** on the freeze build. `<scratch>` is a folder
outside the repository (for example `$env:TEMP\aegis_demo`). `<COM>` is the bench serial port, found without
opening it (checklist §3).

## Target length and structure

Target 4:40, hard limit 5:00. Each segment starts with a title card naming the **environment tag** and the
**claim class** (see `EVIDENCE_AND_LIMITATIONS.md` §3). Waiting time in the two SITL trials is cut, and each cut is
marked on screen ("cut: N s of waiting removed"). Nothing else is edited.

| # | Time | Segment | Environment tag | Claim class |
|---|---|---|---|---|
| 0 | 0:00-0:20 | Title and legend | - | - |
| 1 | 0:20-1:20 | Receive-only live bench stream, `bytes_sent = 0` | `BENCH` | receive-only ingestion (no detection claim) |
| 2 | 1:20-2:20 | GPS drift injected on the local SITL link | `SITL` | link-level detection |
| 3 | 2:20-3:10 | Forged command injected on the local SITL link | `SITL` | command-path effect + link-level detection, scored separately |
| 4 | 3:10-4:00 | Verification and logging: `aegis verify-log`, tamper detected | `BENCH` db + `SIM` db | log integrity (unsigned) |
| 5 | 4:00-4:40 | Limits and safety boundaries, read as written | - | - |

## Segment 0: title and legend (0:00-0:20)

On screen (static card):
- "AegisFlight: passive MAVLink intrusion detection. Stage-2 demonstration."
- Commit: the output of `git rev-parse --short HEAD` on the freeze build (checklist §1).
- PX4 SITL version: the output of the `git describe` command in checklist §4.
- Legend: `BENCH` = physical autopilot on a desk, disarmed, receive-only. `SITL` = PX4 software-in-the-loop on this
  laptop. `SIM` = in-process simulator. "No flight. No attack on real hardware."

Narration:
> "This is AegisFlight, a passive intrusion detection system for MAVLink drones. Every segment is labelled with
> where it ran. Nothing in this video flew, and no attack touched real hardware."

## Segment 1: BENCH, receive-only live stream (0:20-1:20)

Before the segment: the Pixhawk is powered, disarmed, propellers off, and no ground station is connected
(checklist §2). The server is already running (start it off camera, it takes a few seconds):

```powershell
.venv\Scripts\aegis.exe serve --source serial --serial-port <COM> --baud 115200 --no-reconnect --port 8000 --db <scratch>\bench_demo.sqlite
```

Flags verified on `main` (`aegis serve --help`; `src/aegisflight/cli/main.py:436-470`). `--defense-mode` is left at
its default, `passive` (`main.py:459`). Do not pass `--gcs-notify`, `--mgmt-key-file` or `--defense-mode`.
`active-ips` on a serial device is refused at start-up (`src/aegisflight/backend/sources.py:72-74`).

Shots, in order:
1. Browser at `http://127.0.0.1:8000`. Point at the header badge **BENCH** and the source label
   "Physical bench (live serial)" (`backend/sources.py:107-114`, `:129-131`).
2. Link indicator "Live" with a rising frame count; defense posture **PASSIVE**.
3. Vehicle telemetry shows armed **NO**.
4. Switch to the terminal (prompt labelled `[BENCH]`, checklist §6) and read the transmit counter from the
   running server:

```powershell
(Invoke-RestMethod http://127.0.0.1:8000/api/status).link.transport | Select-Object bytes_sent, write_errors, frames_received
```

Expected: `bytes_sent 0`, `write_errors 0`, `frames_received` > 0 and rising if run twice. Where this value comes
from: `EVIDENCE_AND_LIMITATIONS.md` §1.

Narration:
> "This is a real Pixhawk on the bench: disarmed, propellers off, not flying. We only listen. The transmit
> counter on the serial port reads zero bytes sent and zero write errors. That is a software counter in our
> transport, not a measurement on the wire. The badge on screen says BENCH."

Do **not** click ACTIVE IPS, Safe Hold, any override, or any attack button. On this source attack injection is
refused with HTTP 409 (`src/aegisflight/backend/app.py:122-128`, `:239-244`).

The panel text "0 BYTES SENT (Strict Passive IDS)" in the defense panel is a fixed label shown whenever the
posture is passive (`frontend/src/components/DefensePanel.tsx:338-349`). It is not the counter. Point at the
terminal output for the number, not at that label.

End of segment: stop the server with Ctrl-C (its database is used in segment 4).

## Segment 2: SITL, GPS drift on the local link (1:20-2:20)

Before the segment, off camera: a fresh PX4 SITL boot (PX4's UDP link locks to its first sender, see
`docs/STAGE2_RUNBOOK.md` §1).

```powershell
wsl -d Ubuntu-24.04 -- bash /mnt/d/Ardra/techfest-2026/aegisflight/scripts/sitl/start_px4_sitl.sh stop
wsl -d Ubuntu-24.04 -- bash /mnt/d/Ardra/techfest-2026/aegisflight/scripts/sitl/start_px4_sitl.sh start
wsl -d Ubuntu-24.04 -- bash /mnt/d/Ardra/techfest-2026/aegisflight/scripts/sitl/start_px4_sitl.sh status
```

Wait about 30 s after `start`. On camera, in the `[SITL]` terminal:

```powershell
.venv\Scripts\python.exe scripts\sitl\run_p2_trial.py --seed 1001 --trial-index 0 --seconds 90 --out <scratch>\sitl_drift_demo
```

Flags verified (`run_p2_trial.py --help`; `scripts/sitl/run_p2_trial.py:78-88`). Defaults: `--px4-port 18572`, the
WSL IP is discovered, the relay's client side binds loopback port `18672`, profile `configs/px4_sitl`, model
`models/isoforest_px4.joblib`. The script refuses a dirty tree and refuses to overwrite an existing `--out`
(`run_p2_trial.py:100-106`).

What the attack is: the relay on this laptop rewrites `GLOBAL_POSITION_INT` on the **downlink** only (PX4 to the
IDS). PX4 never receives a modified frame. Parameters are fixed by the seed (`src/aegisflight/proxy/attacks_live.py:78-105`):
for `--seed 1001 --trial-index 0` the committed reference run drew onset 44.5 s, duration 15.39 s, 3.502 m/s
(`artifacts/sitl/closure/final_drift_summary.md`, row `p2_final_trial_001`).

Cut the wait (mark it). When the script exits it prints a JSON summary with `frames_modified` and
`ids_threat_decisions`. Then show the alert with its evidence strings:

```powershell
Get-Content <scratch>\sitl_drift_demo.ids_decisions.jsonl | ConvertFrom-Json | Where-Object threat | Select-Object -First 3 t, type, score, evidence | Format-List
```

Reference only (not this run): the committed trial `p2_final_trial_001` fired `GPS_SPOOFING` 0.9 s after the
drift window closed (`artifacts/sitl/closure/final_drift_summary.md`). An example evidence line from a committed
trial: "position residual 29.1 m > 12 m (reported track diverges from velocity)"
(`artifacts/sitl/p2_trial_001.ids_decisions.jsonl`). Read what this run prints; if it does not detect, say so.

Narration:
> "PX4 is running in software on this laptop. A relay we wrote shifts the reported position on the link to the
> monitor. PX4 itself is untouched: this is detection of a modified link, not GPS spoofing of the vehicle. Here
> is the alert and the evidence the detector gives."

If the decision fired after the drift window ended (as in every committed trial), say: "it fired when the
position jumped back, not during the slow drift."

## Segment 3: SITL, forged command on the local link (2:20-3:10)

This replaces the restricted-visibility scenario: issue #24 item 3 was descoped on 18 Nov (#17 no-go) and is
**not shown**. Before the segment, off camera: a fresh SITL boot (same three commands as segment 2). On camera:

```powershell
.venv\Scripts\python.exe scripts\sitl\run_p2_injection_trial.py --seed 2001 --trial-index 0 --seconds 100 --out <scratch>\sitl_inject_demo
```

Flags verified (`run_p2_injection_trial.py --help`; `scripts/sitl/run_p2_injection_trial.py:95-103`). The relay
injects a rogue `COMMAND_LONG` force-disarm (sysid 66) **up** towards PX4 SITL and mirrors uplink frames to the
IDS tap. The vehicle is disarmed on the ground (no flight driver is started), so an ACCEPTED acknowledgement is
acceptance only, not a state change.

Cut the wait (mark it). Then show the manifest's separate answers and the alert:

```powershell
Get-Content <scratch>\sitl_inject_demo.manifest.json | ConvertFrom-Json | Select-Object environment, claim_class, frames_injected | Format-List
Get-Content <scratch>\sitl_inject_demo.ids_decisions.jsonl | ConvertFrom-Json | Where-Object { $_.type -eq "COMMAND_INJECTION" } | Select-Object -First 2 t, type, score, evidence | Format-List
```

Reference only (not this run): `p2i_final_trial_001` was acked `MAV_RESULT_ACCEPTED` and the IDS produced
command-injection evidence (`artifacts/sitl/closure/final_injection_summary.md`).

Narration:
> "Now an attacker on the same local link sends a forged disarm command to the simulated autopilot. PX4 accepts
> it: that is the command-path effect. Separately, the monitor flags a command from an unexpected source. Two
> limits: our monitor saw the command only because this test harness mirrors the uplink to it, and the same
> harness clients also trigger the unexpected-source rule. A forger who copies the real ground station's identity
> was not detected in our tests: only MAVLink signing closes that."

The last sentence is backed by `artifacts/sitl/P2_gcs_impersonation_summary.md` (0/10 detected) and
`artifacts/sitl/P4_signing_summary.md` (signing rejected the forgery in 10/10 SITL trials).

## Segment 4: verification and logging (3:10-4:00)

On camera, in a terminal labelled `[BENCH db]`:

```powershell
.venv\Scripts\aegis.exe verify-log <scratch>\bench_demo.sqlite
```

Output format (`src/aegisflight/cli/main.py:397-404`): `events: N  chain: OK  ...`, exit 0. Read N aloud. If N is 0,
say "no alerts were raised on the bench, so there is nothing to tamper with here", and continue on the SIM log.

Then switch the label to `[SIM db]` and make a small log with alerts, verify it, tamper a **copy**, verify again:

```powershell
.venv\Scripts\aegis.exe simulate --attack gps_spoofing --db <scratch>\sim_demo.sqlite
.venv\Scripts\aegis.exe verify-log <scratch>\sim_demo.sqlite
Copy-Item <scratch>\sim_demo.sqlite <scratch>\sim_demo_tampered.sqlite
.venv\Scripts\python.exe -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('UPDATE events SET threat_score=0.01 WHERE id=(SELECT MIN(id) FROM events)'); c.commit()" <scratch>\sim_demo_tampered.sqlite
.venv\Scripts\aegis.exe verify-log <scratch>\sim_demo_tampered.sqlite
```

Expected behaviour (rehearsed on `main` at `389fc02` with a scratch database, not recorded): the first
`verify-log` reports `chain: OK`; after editing the first stored alert's score, `verify-log` reports
`chain: BROKEN  run gps_spoofing-42: chain broken at event id=1` and exits 2.

Narration:
> "Every alert is written to a hash-chained log. Changing one stored alert breaks the chain, and the tool says
> where. The chain is not signed and not anchored outside this machine: deleting the newest alerts or a whole run
> is not detected, and someone in control of this computer could rewrite all of it."

**Anchors are not shown.** External anchoring (#21) is not implemented on `main`: see
`EVIDENCE_AND_LIMITATIONS.md` §4.

## Segment 5: limits and safety boundaries (4:00-4:40), read as written

> "What you saw: receive-only ingestion from a real autopilot on a desk, two attacks injected on a
> software-in-the-loop link on this laptop, and a tamper-evident alert log. What we have not done: we have not
> flown, we have not attacked a real vehicle or a radio link, and the bench run is not a hardware validation of
> detection. Known gaps: a replayed or forged command carrying the real ground station's identity is not
> detected without message signing; slow GPS drift is missed; status messages are not authenticated; and the log
> is not externally anchored."

End card: commit hash, PX4 `git describe`, the `pytest` counts actually obtained (checklist §1), "No flight. No
attack on real hardware."

## Chronological shot list

| Shot | Segment | Screen | Must be visible | Duration |
|---|---|---|---|---|
| S0 | 0 | Title card | commit, PX4 `git describe`, environment legend | 20 s |
| S1 | 1 | Title card | "BENCH: receive-only. Disarmed, propellers off." | 3 s |
| S2 | 1 | Dashboard, full window | header badge `BENCH`, source "Physical bench (live serial)", link "Live", posture `PASSIVE` | 20 s |
| S3 | 1 | Dashboard, telemetry panel | armed `NO`, frame count rising | 10 s |
| S4 | 1 | Terminal `[BENCH]` | `bytes_sent 0`, `write_errors 0`, `frames_received` > 0 | 15 s |
| S5 | 1 | Terminal | Ctrl-C on the server | 5 s |
| S6 | 2 | Title card | "SITL: link-level detection. PX4 untouched." | 3 s |
| S7 | 2 | Terminal `[SITL]` | `run_p2_trial.py` command line and its first output | 10 s |
| S8 | 2 | Cut card | "cut: N s of waiting removed" | 2 s |
| S9 | 2 | Terminal `[SITL]` | final JSON (`frames_modified`, `ids_threat_decisions`) | 15 s |
| S10 | 2 | Terminal `[SITL]` | decision lines: `type`, `score`, `evidence` | 25 s |
| S11 | 3 | Title card | "SITL: forged command. Command-path effect and detection, scored separately." | 3 s |
| S12 | 3 | Terminal `[SITL]` | `run_p2_injection_trial.py` command line | 7 s |
| S13 | 3 | Cut card | "cut: N s of waiting removed" | 2 s |
| S14 | 3 | Terminal `[SITL]` | manifest `environment`, `claim_class`, `frames_injected`; decision lines | 35 s |
| S15 | 4 | Terminal `[BENCH db]` | `verify-log` on the bench database: `events: N  chain: OK` | 10 s |
| S16 | 4 | Terminal `[SIM db]` | `simulate`, `verify-log` OK, tamper one-liner, `verify-log` BROKEN, exit 2 | 40 s |
| S17 | 5 | Text card + voice | limits text as written | 35 s |
| S18 | 5 | End card | commit, PX4 version, pytest counts, "No flight. No attack on real hardware." | 5 s |

## If something fails on the day

- Do not retry a serial port in a loop, sweep baud rates, or reconfigure the radio. Say what failed.
- Bench fallback (labelled **REPLAY** by the badge, never narrated as live): replay the 28 Oct capture through the
  same serial path over a loopback virtual port (both bind 127.0.0.1):
  ```powershell
  .venv\Scripts\python.exe scripts\hardware\virtual_serial_replay.py data\hardware\raw\gps_hw_verify_20261029.tlog --port 18760
  .venv\Scripts\aegis.exe serve --source serial --serial-port socket://127.0.0.1:18760 --allow-url --no-reconnect --port 8000 --db <scratch>\bench_fallback.sqlite
  ```
  Rehearsed on `main` at `389fc02` (no hardware): badge `REPLAY`, posture `passive`, `bytes_sent 0`. The tlog is
  local and git-ignored and holds the bench position: never open it on screen.
- A SITL trial that prints `ERROR: PX4 never answered the relay's heartbeat within 15s`: restart SITL (stop, start,
  wait 30 s) and use a new `--out`. Never reuse or delete an earlier `--out`.
- Wrong or stale environment label on screen: stop and restart. Never narrate over a wrong label.
