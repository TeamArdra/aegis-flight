# Real Pixhawk 6X on a Raspberry Pi 5: how to reproduce the bench runs

This is the reproduction guide for the real flight-controller runs recorded in `docs/RADIO_TEST_RESULTS.md`, section "Real Pixhawk 6X on a Pi 5, 2026-10-31". It covers the rig, the safety rules, the scripts and their order, how the Pixhawk was snapshotted, restored and signed, and the lessons from the runs. The plan the runs were judged against is `docs/RADIO_TEST.md`.

**Every run here is a bench run.** The vehicle is disarmed with the propellers removed. Nothing in this guide flies it. The scripts are in `scripts/ardupilot/real_pixhawk/` (see its `README.md`).

## 1. Rig

| Item | What was used |
|---|---|
| Flight controller | Pixhawk 6X running ArduCopter 4.7.1 (firmware version word 67503103) (quadcopter) |
| State for every run | Disarmed, STABILIZE, propellers removed. Bench battery about 15.1 V (4S class). GPS receiver connected, 3D fix with 5 to 7 satellites on the bench |
| Flight-controller link | USB, from the Pixhawk to the Pi 5. Device `/dev/ttyACM0` on the Pi. The same board and cable read normally on the laptop (COM4) |
| Companion | Raspberry Pi 5, Raspberry Pi OS Lite (Debian 13), Python 3.13. Power from a supply that meets the Pi 5's rating |
| Radio pair | MicoAir LR900 pair at 115,200 baud. Air unit on the Pi (`/dev/ttyUSB0`; use the `/dev/serial/by-id/...` path). Ground unit on the laptop (COM3). Settings: `docs/RADIO_TEST.md`, section 3, item 10 |
| Laptop | Windows, a Python venv with the repo installed, `pymavlink` and `pyserial` |
| Keys | None for the unsigned runs. For the signed run, one throwaway 32-byte key, kept outside the repo; the Pi copy was deleted afterwards |

```
Pixhawk 6X --USB--> Raspberry Pi 5 --USB--> LR900 air unit  ~~900 MHz~~  LR900 ground unit --USB--> laptop (COM3)
```

Use a Pi 5, not a Pi 3B+. On 2026-10-30/31 the 3B+ dropped off the network in 3 of 3 attempts when the Pixhawk's USB port was opened, with the radio attached and without it. The same Pixhawk read normally on the laptop. The cause on the 3B+ was not established. The Pi 5 did not drop off.

Only one CP210x adapter may be plugged into the Pi at a time. Both radios report identical USB IDs, so the by-id path is only unique while one is attached.

## 2. Safety rules

1. **Disarmed, propellers removed, bench only.** Nothing in these scripts arms, takes off or sends a motor command. Keep the propellers off for every run.
2. **The scripts refuse an armed vehicle.** `px_attack.py` and `px_signed_attack.py` abort when the vehicle reports armed. `px_common.connect()` exits on an armed vehicle, so `px_snapshot.py`, `px_restore.py` and `px_signing.py` stop. `px_restore_mode.py` refuses too. `px_legit.py` is documented as never arming or flying.
3. **Know what each script changes on the Pixhawk, and how to undo it.**
   * Flight modes: several scripts change the mode (ALT_HOLD, LOITER, GUIDED, LAND, RTL and others). Put the vehicle back to STABILIZE with `px_restore_mode.py` on the Pi, with the bridge stopped.
   * `px_legit.py` writes one scratch parameter, `SCR_USER1` (0 to 1 to 0, then restored). It uploads and clears a two-item mission only if the vehicle has no mission. The bench vehicle had a 5-item mission, which was read only.
   * Signing (`SETUP_SIGNING`) and the parameter and mission restore change the Pixhawk's configuration beyond this. Hidden parameters (`SCR_USER1..6`) are not covered by the snapshot (section 5.6).
4. **Stop the bridge before any script that opens the Pixhawk's USB port directly** (`px_listen.py`, `px_decode.py`, `px_gpslog.py`, `px_snapshot.py`, `px_restore.py`, `px_restore_mode.py`, `px_signing.py`). Only one program can own the port.
5. **Bench radio only.** Both radios on the bench, no other MAVLink system in range, POWER MAX only on the bench, and the band rules for 890 to 915 MHz observed (`docs/RADIO_TEST.md`, section 8). The attack scripts transmit forged MAVLink on the radio frequency.
6. **Power.** Run `vcgencmd get_throttled` on the Pi before each run and record it. `0x0` is the clean reading.
7. **Secrets.** Keys and key files stay outside the repo. Never paste key material into run notes.
8. **Active-ips changes a real vehicle's mode when the GPS alarms are false.** With the GPS false-alarm issue unfixed (section 8), a bridge in active-ips sent 457 counter-commands to a disarmed vehicle during a 1,500 s soak and held it in ALT_HOLD. After any active-ips run, check the mode and restore it (`px_restore_mode.py`).

## 3. Software

**Pi.** A Python 3.13 venv (the rig uses `~/aegis_test/venv`). The bridge needs these at import time: `pymavlink`, `pyserial`, `numpy`, `pyyaml`, `psutil`, `joblib` and `scikit-learn` (with `scipy` and `threadpoolctl`). `pyserial` is the optional `serial` extra in `pyproject.toml`. `aegis ips-bridge --help` runs without the heavy packages, because arguments are parsed first. The bridge itself does not.

`scripts/radio_test/laptop_ctl.py deploy` copies `src/`, `configs/` and `scripts/radio_test/` to the Pi. It does not copy `scripts/ardupilot/`. Copy `scripts/ardupilot/real_pixhawk/` to the Pi by hand for the scripts that run there (`px_restore_mode.py`, `px_snapshot.py`, `px_restore.py`, `px_signing.py`).

**Laptop.** The repo installed in the venv, with the serial extra: `pip install -e ".[dev,serial]"`. The radio scripts use `pymavlink` and `pyserial`.

**Clock.** Set both machines' clocks correctly before any signing run (lesson 11).

**Bridge, passive.** Run on the Pi. `--fc-baud` is ignored by the USB link.

```
aegis ips-bridge \
  --fc-port /dev/ttyACM0 --fc-baud 115200 \
  --gcs-port /dev/serial/by-id/usb-Silicon_Labs_CP2102_USB_to_UART_Bridge_Controller_0001-if00-port0 --gcs-baud 115200 \
  --defense-mode passive --status-port 8765 \
  --config-dir configs/ardupilot_copter \
  --db ~/aegis_runs/<label>/bridge.sqlite --audit-log ~/aegis_runs/<label>/audit.jsonl
```

* Status: `curl -s http://127.0.0.1:8765/status` on the Pi.
* Active-ips on the unsigned link: change `--defense-mode` to `active-ips` and add `--allow-unsigned`. Without it the CLI refuses, because an unsigned link cannot stop a counter-tracking forger.
* Active-ips with signing (the run in section 5.5): add `--signing-key-file KEYFILE --signing-state FILE`, and do not add `--allow-unsigned`.
* Management channel: add `--mgmt-key-file` and `--mgmt-state` (keys on the Pi, outside the repo).
* Firmware check: `aegis fw-manifest DIR` writes `DIR/manifest.json`, then add `--firmware-dir DIR --firmware-recheck-s 5`.
* `--config-dir configs/ardupilot_copter` is the ArduCopter profile that `docs/RADIO_TEST.md` requires. The session record does not restate the profile for each run.

## 4. Order of the runs

Each step notes whether the radio hub must run. The scripts that open the radio port directly need the hub stopped.

| Step | Where | Command | What it does | Changes the Pixhawk? |
|---|---|---|---|---|
| 1 | Pi or laptop | `px_listen.py PORT SECS`; `px_decode.py PORT SECS OUTFILE` | Counts or decodes what a port carries. `px_decode.py` uses the full ArduPilot dialect and accounts for every byte | No |
| 2 | Pi, bridge stopped | `px_snapshot.py PORT OUTDIR` | Reads every listed parameter, the mission, the firmware version and the mode | No (read only) |
| 3 | Pi | bridge `passive` (section 3), 60 s | Forwarding with no actuation | No |
| 4 | laptop, radio port, hub stopped | `px_gcs.py PORT SECS` | Benign ground station on the radio: 1 Hz heartbeat and a low-rate stream request | Stream rates stay on the Pixhawk until it reboots |
| 5 | laptop, hub running | `radio_hub.py --port COM3 --baud 115200 --capture-dir DIR`, then `px_legit.py 127.0.0.1:5801` | The 14-step legitimate-traffic suite | Mode changes; `SCR_USER1` 0 to 1 to 0; mission upload only on an empty vehicle |
| 6 | laptop, hub running | `px_params.py` | Full parameter download with per-index re-requests (hub port 5801 is set in the script) | No |
| 7 | laptop, radio port, hub stopped | `px_attack.py PORT LABEL` | Unsigned attack sequence: forged LAND, RTL spoofing sysid 255, LOITER and force-disarm from sysid 77, replay of ALT_HOLD, flood. Aborts if armed. Writes `px_attack_LABEL.json` next to the script | Mode changes, restored between events |
| 8 | laptop, radio port, hub stopped | `px_track_forger.py PORT LABEL` | Counter-tracking forger: RTL from sysid 255 with the pilot's next sequence number, twice | Mode change if accepted |
| 9 | laptop, hub running; bridge in active-ips with `--signing-key-file` and no `--allow-unsigned` | `px_signed_attack.py KEYFILE [HOST:PORT]` | Signed-link attack sequence: a legitimately signed set-mode, then unsigned forgeries, a wrong-key signed LAND, a replay and an unsigned flood. The vehicle's mode is the witness. Never arms | Mode changes, restored after each event |
| 10 | laptop, hub running | `scripts/radio_test/mgmt_radio.py --mgmt-key-file KEYFILE` | Management channel: signed posture commands, bad frames, byte budget | Bridge posture only |
| 11 | Pi and laptop | bridge with `--firmware-dir`; `px_fwwatch.py SECS` (hub observer port 5802) | Firmware-tamper check: change one `*.bin` in the bridge's directory and watch the AEGIS texts | No. The check does not read the flight controller's firmware |
| 12 | Pi or laptop | `px_gpslog.py PORT SECS OUT RATE_HZ`, then `gps_replay.py LOG` run from the repo root | GPS capture, and replay through the repo's extractor and physics detector | Stream rates |
| 13 | laptop, hub running; bridge in active-ips | `px_soak.py SECS OUT.json`, with `pi_monitor.py` on the Pi | Long benign soak: 1 Hz heartbeat, stream requests every 5 minutes. The 2026-10-31 run was 1,500 s | Mode changes by the bridge (section 2, rule 8) |
| 14 | Pi, bridge stopped | `px_restore_mode.py /dev/ttyACM0` | Back to STABILIZE if disarmed | Mode only |

`px_attack.py`, `px_track_forger.py` and `px_signed_attack.py` write or print their results; `px_attack.py` and `px_track_forger.py` write their output next to the script, in `scripts/ardupilot/real_pixhawk/`. Move the JSON into the run directory before committing anything.

## 5. Snapshot, restore and signing

### 5.1 Snapshot, before any change

On the Pi, with the bridge stopped: `px_snapshot.py PORT OUTDIR`, with `--key KEYFILE` if the vehicle is already signed. It writes `params.json`, `params.param` (loadable in Mission Planner), `mission.json`, `mission.waypoints` and `manifest.json` into `OUTDIR`. Keep `OUTDIR` outside the repo.

Take the snapshot before the first change. On 2026-10-31 this was not done (section 5.6).

### 5.2 Compare, without changing anything

`px_restore.py PORT SNAPSHOT_DIR` prints the parameters that differ, are missing or are new, whether the mission matches the snapshot, and the snapshot's flight mode. The volatile counters (`STAT_BOOTCNT`, `STAT_FLTCNT`, `STAT_FLTTIME`, `STAT_RESET`, `STAT_RUNTIME`) are left out of the comparison. **The comparison covers only the parameters the vehicle lists.** Hidden parameters are not compared.

### 5.3 Put it back

`px_restore.py PORT SNAPSHOT_DIR --apply` writes the differing listed parameters, uploads the snapshot's mission and sets the snapshot's flight mode. It refuses an armed vehicle. Its RESTORED message is based on the listed parameters only.

### 5.4 Verify

Run 5.2 again. Expect no differences in the listed parameters or the mission. Then run `px_restore_mode.py` if the mode is not STABILIZE. For any hidden parameter the test changed, restore it by name and read it back.

### 5.5 Signing: what was run

Run on 2026-10-31 over USB. The bridge was the enforcement point. Enforcement at the flight controller was not tested.

1. Snapshot the vehicle (5.1) with the bridge stopped.
2. Enable signing: `px_signing.py PORT on KEYFILE`. The key file holds 64 hex characters. The vehicle must be unsigned before this step. The script sends `SETUP_SIGNING` and then checks an unsigned parameter read and a signed one.
3. Run the bridge in active-ips with `--signing-key-file KEYFILE --signing-state FILE`, without `--allow-unsigned`. Run `px_signed_attack.py KEYFILE` (step 9 in section 4). The key is used by the pilot side only.
4. Disable signing: `px_signing.py PORT off KEYFILE` (sends a zero key, signed with the key in force), then `px_signing.py PORT check` (an unsigned read must work).
5. Restore: `px_restore.py PORT SNAPSHOT_DIR --apply --key KEYFILE --disable-signing`, then run 5.2 to verify.

`px_signing.py` stamps its signing timestamps from the local clock. Run it on a machine with the correct time.

**Result (2026-10-31).**

* A `SETUP_SIGNING` key was sent over USB. Unsigned requests on the USB link stayed answered afterwards. This fits ArduPilot exempting the USB link from signing, but it is an inference. Whether the key was stored cannot be read back.
* The zero key was sent twice to switch signing off. Afterwards unsigned and signed requests were both answered, and the snapshot diff was empty. The test key was deleted from the Pi; a copy stays on the laptop, outside the repo.
* A tool defect was found and fixed: with a key set, pymavlink silently drops the vehicle's unsigned replies, so the first "signed read: no answer" was an artifact. `px_signing.py` now accepts unsigned replies.
* `px_signed_attack.py`, bridge in active-ips with the key and without `--allow-unsigned`: the legitimately signed set-mode ALT_HOLD passed (the vehicle changed mode), and the restore commands passed. 0 of 7 forged or replayed events reached the vehicle: unsigned forged LAND (sysid 77), unsigned RTL spoofing sysid 255, wrong-key signed LAND spoofing sysid 255, unsigned forged LOITER, replay of the captured signed ALT_HOLD, unsigned force-disarm, and a 5 s unsigned heartbeat flood. Bridge counters for the run: `signed_ok` 9, `dropped_unsigned` 4, `dropped_bad_signature` 1, `dropped_replay` 1, `dropped_dynamic` 449 (flood after quarantine of sysid 77); 134 alerts, 0 errors. Each blocked event was announced at the ground.

**Limits.** One run and one key. The wrong-key and replay cases are one frame each. No signed-timestamp skew test was run. The flight controller's own signature checking was not exercised: enforcement at the flight controller needs a UART or telemetry port wired to the Pi, which was not done. Stale and future timestamps and the signing gate exit code were not run.

### 5.6 Snapshot and restore: result and limits

**Restore is shown for one listed parameter only. Reversibility of the whole vehicle state is not proven.**

* **No snapshot existed before the tests started.** The baseline was taken on 2026-10-31 at 02:36, after most of the tests. The baseline lists 1,098 parameters, a 5-item mission and STABILIZE. A copy is kept on the laptop, outside the repo.
* A dry-run comparison with the baseline showed 0 changes. A listed parameter (`NTF_BUZZ_VOLUME`, 100 to 50) was changed for the test, the dry run showed it, `--apply` restored it, the tool printed RESTORED, and a direct read gave 100.
* **Hidden parameters are not covered.** `SCR_USER1..6` answer by name but are not in the 1,098-parameter list. In a first attempt, `SCR_USER2` was set to 7 and `SCR_USER3` to 3. The restore tool still printed RESTORED. Both were put back to 0 by hand and read back.
* **Changes made before the baseline, or not covered by it, from the record:**
  * `SCR_USER1` written from 0 to 1 and back to 0 by `px_legit.py`, which restored it.
  * `SCR_USER2` and `SCR_USER3` changed by the first restore attempt, then put back to 0 by hand.
  * Flight-mode changes, each put back to STABILIZE.
  * The bridge's ALT_HOLD counter-command during the soak. The mode was restored by hand.
  * A signing key written and then zeroed (signing off). The snapshot diff was empty afterwards.
  * No other parameter or mission change is recorded.

The reversal steps in 5.1 to 5.4 are the planned procedure and were used in this way, but they do not prove that the vehicle was returned to its original state. Hidden parameters need a restore by name and a read-back.

## 6. Lessons

1. **pymavlink's `msg.pack(mav)` does not advance the sequence counter; `mav.send()` does.** Hand-built frames built with `pack()` all carry sequence 0. The bridge then, correctly, reads them as replays and as "two senders on one sysid". Advance the counter yourself, one per sender. The first attack runs of 2026-10-31 were invalid for this reason, and the "pilot lock-out" finding made from them is withdrawn.
2. **Never `pkill -f` a pattern that the same SSH command contains.** It matches the shell that launched it. Stop and start processes in separate calls, or use pid files.
3. **The LR900 ground unit adds about 50 B/s of `0x00` idle fill.** MAVLink parsers skip it. Stream rates persist on the flight controller until it reboots. In the soak the stream rates stayed at about 4 Hz from an earlier capture. The first read of an idle port returns a backlog (about 117 frames in one run), so a rate measured over the first 25 s is too high.
4. **Over the radio, a full parameter download loses about a quarter of its frames.** Re-request the missing indexes, as `px_params.py` does.
5. **A ground station must request the EKF status stream (EXTRA3).** Without it the GPS rules run without estimator context. In the replay, 24 % of ticks at 1 Hz were false evidence from the receiver's own wander, against 0 with the stream present.
6. **The Pi 3B+ dropped off the network 3 of 3 times when the Pixhawk's USB port was opened; the Pi 5 did not.** Power the Pi from a supply that meets its rating.
7. **The bridge refuses `active-ips` on an unsigned link unless `--allow-unsigned` is given.** The refusal is deliberate: an unsigned link cannot stop a counter-tracking forger.
8. **Everything changed on the Pixhawk must be reversible.** Snapshot first, restore and verify after. On 2026-10-31 the snapshot came after most of the tests, so the record cannot show the pre-test state (section 5.6).
9. **Know which scripts need the hub.** `px_attack.py`, `px_track_forger.py`, `px_gcs.py`, `px_listen.py`, `px_decode.py` and `px_gpslog.py` open the serial port themselves, so `radio_hub` must be stopped. `px_legit.py`, `px_params.py`, `px_soak.py`, `px_fwwatch.py`, `px_signed_attack.py` and `mgmt_radio.py` use the hub on TCP (5801 or 5802), so it must be running. Mixing these up gives a "port busy" error or no traffic.
10. **`px_track_forger.py` has a docstring copied from `px_attack.py`.** It says `px_attack.py` and describes the whole sequence. The script runs only the counter-tracking RTL events. Read the file before running it.
11. **Signing timestamps come from the clock.** A signing-enabled flight controller rejects counter-commands stamped from a clock that is far behind. The bridge's counter-commands were rejected when the Pi 3B+ clock was 3 h 9 min behind (`docs/RADIO_TEST_RESULTS.md`, the cic and cid runs). `px_signing.py` also stamps from the local clock.
12. **A headline alert can hide a more important one for tens of seconds.** In the firmware check the integrity evidence appeared about 6 s after the tamper, but the headline stayed `DOS` (from the GPS alert storm) until about 59 s.
13. **`px_legit.py` uploads a mission only when the vehicle has none.** With the bench vehicle's 5-item mission, that step was skipped and the mission was read only.
14. **A snapshot covers only what the vehicle lists.** Parameters that answer by name but are not in the list (`SCR_USER1..6`) are not in the snapshot, and the restore's RESTORED message does not cover them. A test that touches one must restore it by name and read it back.
15. **With a signing key set, pymavlink drops the vehicle's unsigned replies.** A read that gets no answer can be an artifact. Check with an unsigned read before concluding that a request was rejected.
16. **With the GPS false-alarm issue unfixed, active-ips acts on a real vehicle, even a disarmed one.** The 1,500 s soak sent 457 counter-commands and held the vehicle in ALT_HOLD (section 2, rule 8).
17. **Over USB the bridge is the only observable signing enforcement point.** Enforcement at the flight controller needs a UART or telemetry port wired to the Pi.

## 7. Not run

On the real Pixhawk:

* enforcement of signing at the flight controller (needs a UART or telemetry port wired to the Pi);
* stale and future signing timestamps, the signing gate exit code, more than one key, and more than one wrong-key or replay frame;
* radio unplug and replug, and a hard Pi power cut (phase 8);
* the ground-radio unplug and the range test;
* the trusted forced disarm, the pilot override during a GPS fault, and a GPS fault injected through SITL;
* any flight;
* a restore check that covers hidden parameters.

The soak was 1,500 s (25 minutes), below the 30 to 60 minutes that phase 9 asks for.

## 8. GPS on the bench: known open issue

The stationary bench receiver wanders by about ±20 m. Without the EKF status stream, the GPS rules raise `GPS_SPOOFING` false alerts from that wander. The fix is not done; the user decided to skip it for now. In the 1,500 s active-ips soak the bridge acted on these alerts: 207 alerts, 457 counter-commands, and the disarmed vehicle held in ALT_HOLD. The analysis, the measured capture and the candidate fixes (a time-bounded residual window, lower confidence without estimator context, a per-receiver noise floor) are in `docs/RADIO_TEST_RESULTS.md`.

## 9. Where the results are

* Results and the judgement against the plan: `docs/RADIO_TEST_RESULTS.md`, section "Real Pixhawk 6X on a Pi 5, 2026-10-31".
* The plan: `docs/RADIO_TEST.md`, sections 4 and 11.
* The bridge and its postures, the signed and unsigned tables and the soak: `docs/INLINE_IPS.md`, sections "Pi deployment notes (Pi 5, bench, 2026-10-31)" and "Signing enforcement point and the Pi 5 bench soak (2026-10-31)".

## 10. Cross-message checks

The cross-message consistency rules (battery `SYS_STATUS` against `BATTERY_STATUS`, a repeated `ATTITUDE`, and `VFR_HUD` heading against `ATTITUDE` yaw) are described in `docs/DETECTION.md`, section "Cross-message consistency (2026-10-31, additive, `physics.xmsg_checks`)". They are off by default and on in `configs/ardupilot_copter/detector.yaml`. Unit tests: `tests/unit/test_xmsg_checks.py`.

What the bench data show, and what they do not:

* In the bench Pixhawk 6X capture (802 `ATTITUDE` messages over 200 s), every message was distinct from its predecessor (802 of 802). The attitude-repeat rule raised no false alarm in that capture.
* The battery and heading tolerances (1.5 V and 10 degrees) are engineering defaults and are not calibrated. Calibration needs real-flight `BATTERY_STATUS` and `VFR_HUD` data, which has not been captured.
* The session record does not say whether the 2026-10-31 bridge runs had these rules enabled. Do not read those runs as a test of the rules.
