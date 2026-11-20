# Stage 2 demo runbook

For recording the required video ("screen recording of a real run", template p. 19-20) or running it live. Run from the repository root
in PowerShell. Background and expected results are in `docs/STAGE2_GPS_DEGRADED_DEMO_PLAN.md`.

**Status.** All commands below except those marked **HARDWARE** were run on 2026-11-03 (Segment 6 through its API calls: posture changes and both attacks answered OK; no artifact was saved for it). The HARDWARE commands were dry-run over a loopback
virtual port on real captured bytes (`artifacts/validation/stage2_readiness_20261103/loopback_dryrun/`) and **have not been run on the board
on this tree**.

## 0. Before the session

```powershell
.venv\Scripts\python.exe -m pytest -p no:cacheprovider -q        # say the counts you actually get
.venv\Scripts\ruff.exe check src tests scripts backend
npm --prefix frontend test
npm --prefix frontend run build                                  # the server serves frontend/dist: rebuild after any UI change
.venv\Scripts\python.exe scripts\demo\make_synthetic_gps_tlog.py generate --out demo\fixtures
git rev-parse HEAD                                               # read it onto the end card
```

- Close Mission Planner and QGroundControl: a serial port has one owner, and a connected ground station transmits to the board. Do not connect one for this demo without an explicit decision.
- Use a fresh `--db` for every server. The default database is local evidence.
- Pick an unused folder number `<n>`: the runner refuses to overwrite a run.
- Close file explorers and anything showing a path or a coordinate.

## 1. Hardware checklist (operator, by eye)

Record the answers before opening any port. Do not infer them from the software.

- [ ] Date and UTC time; who is present.
- [ ] Board label: Pixhawk 6X. Vehicle disarmed. **Propellers off.** Restrained.
- [ ] How it is powered.
- [ ] GNSS module physically attached? To which port? (look)
- [ ] Antenna position: indoors, how far from a window.
- [ ] Telemetry radio on TELEM1 and laptop-side radio on USB? Or USB only?
- [ ] No ground station connected on any port. If one was connected since power-up, write that down: its stream request stays in RAM.
- [ ] Firmware version: write "not determined" unless it was already recorded. Reading it needs a ground station, which transmits.

## 2. Find the port, without opening it

```powershell
Get-PnpDevice -Class Ports -PresentOnly | Format-Table Status,FriendlyName,InstanceId -AutoSize
```

| Name | Use |
|---|---|
| Silicon Labs CP210x (or similar radio bridge) | **Preferred.** `--baud 115200` was right on this radio earlier. Frames > 0 and 0 CRC rejects re-confirm it |
| ArduPilot MAVLink (`VID_1209&PID_5740`) | USB. Baud is ignored. Expect heartbeat only on a fresh boot |
| ArduPilot SLCAN | **Never open** |

If the device is absent or ambiguous, **stop**. Do not sweep baud rates. Do not reconfigure the radio.

## 3. Receive-only capture with evidence (**HARDWARE**, about 2 min)

```powershell
.venv\Scripts\python.exe scripts\hardware\run_serial_ids.py --port <COM> --baud 115200 --out-dir artifacts\hardware\stage2_demo_<n> --seconds 120 --no-reconnect --defense-mode passive --tlog data\hardware\raw\stage2_demo_<n>.tlog
.venv\Scripts\aegis.exe verify-log artifacts\hardware\stage2_demo_<n>\events.sqlite
.venv\Scripts\python.exe scripts\hardware\gnss_tlog_summary.py data\hardware\raw\stage2_demo_<n>.tlog --json artifacts\hardware\gnss_summary_stage2_demo_<n>.json
Get-FileHash -Algorithm SHA256 data\hardware\raw\stage2_demo_<n>.tlog
```

**Expected.** Exit 0. Console prints `passive_check` passed, `hash_chain` ok, `telemetry_coverage`, `navigation_health`.
`summary.json`: `transport.bytes_sent` 0, `write_errors` 0, frames > 0, `crc_rejects` 0 (a few garbage bytes at port open are normal).

Expected messages on the radio: HEARTBEAT, SYS_STATUS, GPS_RAW_INT, GLOBAL_POSITION_INT, ATTITUDE, VFR_HUD, EKF_STATUS_REPORT.
On USB after a fresh boot: HEARTBEAT and TIMESYNC only. Alerts as in the plan's §2.2 table.

**Outputs.** `artifacts\hardware\stage2_demo_<n>\` (`summary.json`, `health.jsonl`, `alerts.jsonl`, and git-ignored `events.sqlite`);
`data\hardware\raw\stage2_demo_<n>.tlog` (git-ignored, holds the real position).

## 4. Stop conditions (**HARDWARE**, any of these ends the session)

- Exit 3, or `bytes_sent` or `write_errors` above 0: a transmit was attempted. Keep all files.
- Exit 4, `hash_chain.ok` false, or `verify-log` not OK. Keep all files.
- Exit 2, port cannot be opened: close the other program. Do not retry in a loop.
- 0 frames, or CRC rejects or garbage still growing after the first seconds: baud or wiring. Do not sweep.
- The USB device disappears, or `disconnects` > 0.
- **The board arms, changes mode or behaves unexpectedly: unplug the laptop-side radio or USB.** Do not interpret LEDs or tones.

Unexpected source id: record it; do not conclude an attack. A radio injecting `RADIO_STATUS` (often sysid 51) would raise a rogue-source
`MAVLINK_ANOMALY`.

## 5. Demonstration order

Timing assumes about 12 minutes. **Say the environment tag aloud before each segment.**

### Segment 1: architecture and threat model (1 min, slide)
Use Figure 3 and Figure 4 from `docs/figures/`.
> "AegisFlight is a passive intrusion detection system. It reads MAVLink telemetry, extracts features, runs protocol, physics, learned and
> firmware-integrity detectors, fuses them into one explained alert, and writes it to a hash-chained log. We have not flown it."

### Segment 2: real Pixhawk telemetry (**HARDWARE**, `BENCH`, 2 min)
Stop any server first. **Choose the profile from the plan's §2.3.** Recommended:
```powershell
.venv\Scripts\aegis.exe serve --source serial --serial-port <COM> --baud 115200 --no-reconnect --port 8000 --db artifacts\hardware\stage2_demo_<n>_serve.sqlite --config-dir demo\indoor_bench_profile
```
Or without `--config-dir` for the default profile. Open http://127.0.0.1:8000.

Point at, in this order:
| Where | Expected |
|---|---|
| Header badge | `BENCH` |
| Defense posture | `PASSIVE` |
| Source bar | "Physical bench (live serial) · `<COM>` @ 115200", link "live", frame count rising |
| GPS line | what the receiver says, e.g. "NO_FIX · 0 sats · usable fix no" |
| Health note (if `EKF_STATUS_REPORT` arrives) | "no horizontal position solution", "GPS sensor unhealthy" |
| Flight track | "NO POSITION FIX" if lat/lon are zero; otherwise wander only |
| Vehicle telemetry | attitude, battery, armed **NO** |
| `POST /api/simulation/attack` | HTTP 409, read-only source (verified on the loopback dry run) |

> "This is the real board on a bench, disarmed, propellers off, indoors. We only listen: the transmit counter is zero. That is a software
> counter, not a wire measurement. The system reports what the vehicle says about itself. A missing fix on its own is not evidence of an attack."

**Read the screen before saying the last sentence, and adjust it.** Under the default profile a no-fix shows `SUSPICIOUS / DOS`: say so. If a `GPS_SPOOFING` alert appears as the fix degrades (it did on capture 008, on a stationary board), say that it is receiver noise on this bench and that the rule cannot tell.

**Do not click ACTIVE IPS, Safe Hold or any control.**

If you use the indoor profile, say:
> "For this segment the rule that scores a missing fix as denial is turned off, because indoors a missing fix can be normal. **That means real GNSS loss
> or jamming would not be flagged in this run.** In the default configuration, a link with no fix raises a DOS alert whose text says no fix was ever acquired. This
> recording shows that, from a run where the board reported no receiver at all. It is a false alarm, and the report lists it as a known limitation."

Show `demo/screenshots/dashboard_REPLAY_capture007_nofix_default_profile.png` for that sentence.

### Segment 3: missing-data handling (`BENCH`, 1 min)
- Point at the monitor still running on attitude, battery and heartbeat while position is unavailable.
- Pull nothing. Do not power-cycle on camera unless you planned to.
- Stop the server with Ctrl-C, then run `.venv\Scripts\aegis.exe verify-log artifacts\hardware\stage2_demo_<n>_serve.sqlite`.

### Segment 4: SIMULATED GPS (`REPLAY` badge, synthetic, 3 min)
```powershell
.venv\Scripts\aegis.exe serve --source replay --tlog demo\fixtures\SIMULATED_GPS_not_measured_v1.tlog --replay-speed 1.0 --port 8001 --db <scratch>\demo_synth.sqlite
```
Open http://127.0.0.1:8001. **Point at the file name in the source bar first.**
> "We now leave the hardware. The file on screen is called SIMULATED GPS, not measured. We wrote it. No receiver produced these coordinates,
> and nothing here goes to any vehicle."

| Clock | Say | Expected on screen |
|---|---|---|
| 0:00-0:30 | Nominal | `NORMAL`, score 0 |
| 0:30-0:50 | "1 m/s drift. **Watch: nothing fires.** Below about 4 m/s, with ML off, this is a known miss." | `NORMAL` |
| 0:50-1:10 | "6 m/s drift." | `SUSPICIOUS / GPS SPOOFING`, score 0.55, first alert near 0:52; "position residual … > 12 m" |
| 1:10-1:25 | "A 200 m jump." | score near 1.0, `CRITICAL`; drops within ~3 s because a held offset looks consistent: **say this is a limit** |
| 1:25-1:45 | "Fix lost." | return-jump `GPS SPOOFING`, then `DOS`, "GNSS fix lost" |
| 1:45-2:20 | "Recovery." | back to `NORMAL`; alerts stop |

Speed it up with `--replay-speed 2` if needed; the content is unchanged.

### Segment 5: alert, persistence, forensics (1 min)
- Open one alert in Incident History. Read its evidence line, score, detector, time.
- Click **Verify SHA-256 Chain**. Then:
```powershell
.venv\Scripts\aegis.exe verify-log <scratch>\demo_synth.sqlite
```
Expected: `events: 12  chain: OK  1 run chain(s) intact` after the full run.
> "Editing a stored alert, or deleting one from the middle, breaks the chain. Deleting the newest alerts, or a whole run, is not detected, and it is not signed: someone
> controlling this machine could rewrite all of it. Defense actions are kept in memory for the forensic export; only alerts are in the chain."

### Segment 6: defense policy, modelled (`SIM`, 2 min)
```powershell
.venv\Scripts\aegis.exe serve --port 8002 --db <scratch>\demo_sim.sqlite
```
Open http://127.0.0.1:8002. Badge `SIM`. **GPS Spoofing → Gradual Drift → 6.0 m/s → Inject** in `PASSIVE`: alert, 0 bytes. Switch to `ADVISORY`, then
`ACTIVE IPS` (SIM source: no dialog needed; nothing leaves the process).
> "This protected track is a model inside the simulator. **No vehicle exists behind it and no prevention figure has been measured.** On a
> serial link, the software refuses this posture. We ran an inline bridge against simulated ArduCopter on loopback only, a few runs per
> scenario."

Optional limitation:
```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8002/api/simulation/attack -ContentType application/json -Body '{"attack":"command_injection","mode":"gcs_replay"}'
```
Expected: no alert. > "Without message signing this cannot be told apart from the real operator."

**Not shown live:** the inline bridge on SITL. It needs an ArduCopter SITL build in `C:/afsitl`, which is absent on this machine, and has not
been re-run on this tree.

### Segment 7: companion computer status (30 s)
> "A teammate is integrating the Raspberry Pi. We have **no measurements from it** in this report. The planned link is a receive-only UART
> with the transmit line left unconnected."
Update this sentence only from measurements that exist. See `docs/STAGE2_GAPS_AND_PRIORITIES.md` §3.

### Segment 8: limits and next stage (30 s, read as written)
> "We have shown detectors on a simulator and on software-in-the-loop link attacks, and receive-only ingestion on a physical autopilot on the
> bench. We have not flown it, have not attacked a real vehicle, have not measured it on a companion computer, and cannot yet state a
> false-alarm rate per hour. Known gaps: replay of legitimate commands without signing, slow GPS drift, and forged status messages. The next
> step is a receive-only flight with a healthy estimator, then resource measurement on the companion computer."

## 6. Backup if the hardware fails

Do not retry a failed port in a loop. Say what failed, then replay a real capture, which is **labelled REPLAY by the badge**:
```powershell
.venv\Scripts\aegis.exe serve --source replay --tlog data\hardware\raw\gps_hw_verify_20261029.tlog --replay-speed 1.0 --port 8000 --db <scratch>\demo_replay.sqlite
```
Expected: `REPLAY`, "Replaying", "3D_FIX · 7 sats · usable fix yes", "no horizontal position solution", "GPS sensor unhealthy", 0 alerts.
> "This is a recording of the real board from 28 October, not a live link."

No-fix variant: `data\hardware\raw\telemetry_radio_007.tlog`. These captures are local and git-ignored: copy them first if presenting from
another machine.

## 7. Recovery

| Symptom | Action |
|---|---|
| `PermissionError(13)` / exit 2 | Another program holds the port. Close it. Run once more |
| Device vanished mid-run | Stop. Replug. New `<n>`. Say so |
| Dashboard "Backend offline" | The server stopped; check its console |
| Blank page or old UI | `npm --prefix frontend run build`, reload |
| Port 8000 busy | Use another `--port` |
| `--out-dir already holds a previous run` | New `<n>`. Never delete a run |
| Replay ended before you were ready | Ctrl-C, re-run the same command with a new `--db` |
| Dashboard shows a stale tag | Check the source bar. Never narrate over a wrong label; restart |

## 8. Evidence to capture

| When | What | Where |
|---|---|---|
| Segment 0 | Commit hash, test counts | End card |
| §3 | `summary.json`, `alerts.jsonl`, `health.jsonl`, GNSS summary, tlog hash | `artifacts\hardware\stage2_demo_<n>\` |
| Segment 2 | Screenshot with the `BENCH` badge and GPS line | `demo\screenshots\dashboard_BENCH_stage2_<n>.png` |
| Segment 4 | Screenshots at about 1:00 and 1:35 | existing files can be used |
| Segment 5 | `verify-log` output | video and a text file |
| End | Video file, name and SHA-256 | `docs/SUBMISSION_ARCHIVE_MANIFEST.md` |

Then add a row for the new capture to `docs/VALIDATION_EVIDENCE.md` §1e and replace the placeholders in the report (§8.2, §9).

**Capture checklist:** resolution at least 1920×1080; badge and footer visible in every dashboard shot; no coordinates, private paths,
`.claude/` or tokens on screen. Do not say "prevented", "protected the drone" or "stayed airborne" without the word "modelled".
