# Real-radio test results log

> **Real-radio runs exist (2026-10-30, MicoAir LR900 pair).** The phase rows below are filled from the session summary; the
> phase JSON files were not reviewed. The notes say where the plan's written criteria are not met. The Bench log below holds the first measured bench observations.
> The real-radio session of the same day is described at the end of this file.
> New runs are added to the phase tables below as measured rows. Do not enter an expected, estimated or simulated number. Each row is one measured run
> of the procedure in `docs/RADIO_TEST.md`, copied from that run's `<phase>.json` / `report.md`. A failed or aborted run gets a row
> too, marked FAIL or ABORTED with the reason. A phase that was not run stays empty.

## Bench log, 2026-10-30 (measured)

Measured on the bench on 2026-10-30. These are observations of the rig, not results of the phases in `docs/RADIO_TEST.md`.
No phase was run to completion, and nothing below is a pass.

**Laptop**

* Silicon Labs CP210x USB driver 11.6.0.420, signed. Device on COM3, status OK.

**Raspberry Pi**

* Kernel 6.18.50. `cp210x` kernel module loaded.
* Radio at `/dev/ttyUSB0`. By-id alias: `/dev/serial/by-id/usb-Silicon_Labs_CP2102_USB_to_UART_Bridge_Controller_0001-if00-port0`.
* User `ardra` is in group `dialout`.
* Python 3.13.5. Venv `~/aegis_test/venv` with pyserial 3.5.

**Pi power**

* `vcgencmd get_throttled` = `0x50005`. Under-voltage and throttling are active now (bits 0 and 2), and both have occurred
  since boot (bits 16 and 18).
* The kernel log shows repeated `Undervoltage detected`.
* Consequence: Pi timing and CPU figures taken on this supply are worst-case and not valid for the plan until the supply is
  fixed (5 V, 2.5 A or more, short thick cable).

**First link attempt**

* Pi: `pi_relay.py --mode echo`. Laptop: `link_baseline.py` on COM3. Both at 57,600 baud, then both at 115,200 baud.
* Warm-up: 0 of 10 echoes at each baud.
* Pi relay counters: 0 bytes received from the radio.
* Result: no data crossed the air link in this attempt.
* Laptop SiK command-mode query (`+++`, then `ATI`) on COM3 at 57,600, 115,200, 38,400, 9,600, 19,200 and 230,400 baud:
  no `OK` reply at any baud.

**Interpretation (hypotheses, not conclusions)**

These have not been tested. Each would explain the symptoms above.

1. The radio may not be a SiK-type, AT-command-capable unit.
2. The radio may be using a UART baud that was not tried.
3. The air side may be unpowered.
4. The two radios may not be paired: different net id or air rate.

**Not yet checked (as of the update below):** the radio model from the labels; the net id, air rate and serial speed of each
unit read with the vendor tool; the USB latency timer on the Pi. The LEDs were checked in the update below.

## Bench log update, 2026-10-30 (measured, second session)

Measured on the bench on 2026-10-30, after the first session above. These are measured observations, not phase results.
The real-radio session of the same day is at the end of this file.

**Rig change**

* The Pi is reached over a direct Ethernet cable, at `ardra.local` = 169.254.225.172 (link-local). No Wi-Fi is used for the Pi.
* The laptop-to-Pi reverse SSH tunnels (`ssh -R 5762` and `ssh -R 5800`) run over that cable.
* The Pi clock is about 2.5 h behind (no time sync). Harmless for these runs; it matters for signing timestamps
  (`docs/RADIO_TEST.md`, section 3, item 7).

**Pi-in-the-loop run, ACTIVE_IPS, before the fix**

Setup: Pi bridge; SITL and the hub on the laptop; SSH tunnels; no radio in the path. This is a software check of the bridge
over the cable, not a radio result.

* 23,273 downlink frames; 4,262 dropped (18 %, counter `dropped_dynamic`).
* Cause: the rate-baseline learner read a step from about 1 to about 135 msg/s (GCS connected after the bridge started) as a
  flood. 8 false DoS alerts for about 30 s. The flood gatekeeper also shed the vehicle's own telemetry.
* 20 forged uplink commands from sysid 66 were dropped. The vehicle stayed airborne at 30 m.
* Latency p50 0.43 ms, p95 0.87 ms. The Pi was under-voltage and throttled at the time.

**Same run after the fix**

Fix: commit `e1ceb76`, followed by a learner-extension change. The commit hash of the second change was not given to the
documentation worker.

* 23,321 downlink frames forwarded; 0 dropped.
* 20 forged uplink commands dropped. The vehicle stayed at 30 m.
* 3 alerts in total, all real: command injection from sysid 66 (2) and a sequence gap of 246 from the attack. 0 false rate
  alerts. Analyser errors 0.
* Latency p50 0.246 ms, p95 0.418 ms. No throttling was active during the run. `get_throttled` = `0x50000` (history only).

**Passive run before the fix:** 23,077 frames forwarded, 0 dropped, p50 0.43 ms.

**The fix**

* (a) The vehicle's own sysid is never rate-shed by the QoS gatekeeper (`InlinePolicy.down`).
* (b) The ProtocolDetector rate learner adopts a stable final plateau after a step, and extends the learning window once when
  the rate is still moving at the end. A rate above the hard limit is still rejected.
* The forwarding golden test is split into `flood_rate_limit` (rogue source, 420 frames shed) and
  `flood_vehicle_telemetry` (0 frames shed). This is software regression evidence, not a radio result.

**Radios (measured 2026-10-30)**

* Both radios are 900 MHz.
* USB descriptors are identical: generic CP2102, VID:PID `10c4:ea60`, serial `0001`, 100 mA. The model and firmware cannot
  be read from USB.
* LEDs: laptop radio steady green (linked). Pi radio steady, with occasional brief blinking. No red LED on either.
* The Pi radio dropped off the USB bus twice. The first drop came right after a logged under-voltage dip, so the supply is
  marginal.
* Serial side: no AT or `+++` reply from either radio at 1,200 to 230,400 baud, with N, E and O parity and 1 and 2 stop bits.
* The laptop radio emits a constant stream of filler bytes: 0x00 at 115,200 baud, and 0xFC when read at 38,400 baud. The Pi
  radio's output is idle junk.
* One transfer worked: a known 32-byte pattern sent Pi to laptop at 115,200 baud arrived intact. At 57,600 baud it was
  garbled. Laptop to Pi never arrived.

**Hypotheses (not tested)**

1. The UART baud of the radios is 115,200.
2. One UART direction on each unit may be dead.
3. The units may not be standard SiK firmware.

**Superseded by the real-radio session below.** The radios are MicoAir LR900 units, not SiK, so the AT probes could never
answer. The one-way and junk data was a configuration mismatch between the two units, fixed on 2026-10-30. The hypotheses above
are not the cause.

## How to fill a row

* **Date**: local date and time of the run (ISO format).
* **Config**: the rig for that run in short form, for example `57600 baud, Pi passive, SITL GUIDED, unsigned` or
  `115200, active-ips, signed, mgmt on`. Include the baud, posture, signing on/off, `--signing-max-age-s`, and anything unusual
  (a different radio placement, a changed air rate).
* **Commit**: `git rev-parse --short HEAD` of the repo that was run on the laptop and on the Pi (the same commit on both; if they
  differed, say so in Notes). Add `+dirty` if there were uncommitted changes.
* **Key numbers**: the figures that decide the phase (the checks' `value` fields), with units.
* **Result**: PASS, FAIL or ABORTED, as written by the tool's `passed` flag, not changed by hand.
* **Notes**: Pi `vcgencmd get_throttled` before and after, Wi-Fi RTT, anything that may bias the figures, link to the run
  directory name. Never paste keys, tokens or passwords.

## Rig record (fill once per campaign)

| Item | Value |
|---|---|
| Campaign date | 2026-10-30 |
| Commit (laptop / Pi) | Pi bridge code e8d08d3 (per coordinator); laptop commit not recorded |
| Radio serial baud (from phase 0) | 115,200 on both units; phase 0 result not in the summary |
| Radio settings (LR900: BAUDRATE, USB_BAUD, CHAN_MODE, RATE, ADDR, CHANNEL, POWER, MODE) | ground FHSS_GROUND, air FHSS_AIR; both BAUDRATE 115200, USB_BAUD 115200, RATE HIGH (2.1 KB/s), ADDR 1000, CHANNEL 0, POWER MAX, MODE DUPLEX; 900 MHz |
| Pi Python / aegis version | Python 3.13 (venv); bridge code e8d08d3 (per coordinator) |
| Pi `get_throttled` at start | not recorded for rad2; 0x50005 in the first session, 0x50000 later |
| Laptop IP / Pi IP / Wi-Fi RTT | Pi at `ardra.local` = 169.254.225.172 over the Ethernet cable; RTT not recorded |
| USB latency timer on the Pi (set to 1 ms? file present?) | not recorded |
| Run directory | not recorded (run label rad2) |

## Phase 0: preflight and probe

| Date | Config | Commit | Best baud / frames / B/s | Result | Notes |
|---|---|---|---|---|---|
| | | | | | |

## Phase 1: link baseline without the bridge

| Date | Config (echo / pass) | Commit | Throughput B/s, frame loss %, RTT p50 / p95 ms, largest heartbeat gap s | Result | Notes |
|---|---|---|---|---|---|
| 2026-10-30 | echo on the Pi (`pi_relay.py --mode echo`); `link_baseline.py` on the laptop at 115,200 baud | not recorded | 0 % loss at 2, 5, 10, 20 and 40 frames/s; RTT p50 59-61 ms, p95 about 70 ms, max 71 ms; saturation at 60 frames/s: 30.5 % loss, rx 1,084 B/s, p99 187 ms; 80 frames/s: 37.9 % loss, RTT p50 1.4 s | meets the stated check on the measured items; phase JSON not reviewed | Warm-up 10/10 echoes. Clean throughput about 1.0-1.05 KB/s each way. The 1 % check at the lowest rate is met. Step (b), the 5-minute relay-vs-hub comparison, is not in the summary. |

## Phase 2: bridge passive forwarding

| Date | Config | Commit | Frames down / up, dropped, hook_errors, extra RTT vs phase 1 p95, bridge CPU %, RSS MiB | Result | Notes |
|---|---|---|---|---|---|
| 2026-10-30 | rad2: ACTIVE_IPS (`--allow-unsigned`), not passive | not recorded | 9,792 frames at the ground vs 9,801 sent (9 in flight); 0 send failures; 0 tap overflow; latency p50 0.30 ms, p95 0.76 ms; uplink 567 of 567 reached the bridge | NOT PASS as written (coordinator label: PASS); phase JSON not reviewed | The plan requires passive mode. No passive run over the radio is in the summary, so this row does not meet the phase 2 criterion as written. |

## Phase 3: normal pilot operation

| Date | Config (advisory / active-ips) | Commit | Commands sent / acked, legitimate dropped, alerts (class, count), ACK latency p50 / p95 ms | Result | Notes |
|---|---|---|---|---|---|
| 2026-10-30 | rad2: ACTIVE_IPS only | not recorded | 14 benign mode probes acknowledged; vehicle armed, took off to 30 m, held GUIDED; no heartbeat gap over 3 s | NOT PASS as written (coordinator label: PASS); phase JSON not reviewed | The plan requires advisory and active-ips, at least 30 probes per posture, repeated 3 times. 14 probes in one posture: not met as written. |

## Phase 4: detection

| Date | Config | Commit | Per attack: alerted (y/n), time to STATUSTEXT at the laptop s | Result | Notes |
|---|---|---|---|---|---|
| 2026-10-30 | rad2: ACTIVE_IPS (the plan specifies advisory) | not recorded | Forged LAND (sysid 66) at +40 s and +160 s: COMMAND_INJECTION and MAVLINK_ANOMALY alerts raised; flood 30 frames/s for 10 s: quarantined, 297 frames dropped; `AEGIS: blocked HEARTBEAT sys66 xN` and `AEGIS: quarantine sys66` reached the ground over the radio | NOT PASS as written (coordinator label: PASS); phase JSON not reviewed | The plan requires advisory, where forged frames reach the FC. Not run in advisory. The 5 s alert-latency check is not in the summary. |

## Phase 5: prevention in ACTIVE_IPS

| Date | Config | Commit | Hostile frames sent / dropped / reaching FC, forced disarm passed, GPS ladder: confirm to ALT_HOLD s, override honoured, legitimate dropped | Result | Notes |
|---|---|---|---|---|---|
| 2026-10-30 | rad2: ACTIVE_IPS | not recorded | Forged LAND dropped at the bridge; vehicle stayed GUIDED at 30 m (vehicle_went_to_land 0); flood quarantined, 297 frames dropped; 14 benign probes acknowledged | NOT PASS as written (coordinator label: PASS); phase JSON not reviewed | Not run over the radio: trusted forced disarm, GPS ladder, pilot override during a GPS warning. |
| 2026-10-30 | rgps1: ACTIVE_IPS; 120 s hover at 30 m, then SIM_GPS1_GLTCH_X = 0.001 (about 111 m) written to SITL at t = 140.0 s of the watcher log | not recorded | GPS_SPOOFING HIGH at +0.8 s; `AEGIS: GPS unreliable - do not trust position` at +1.0 s; `AEGIS: set ALT_HOLD (GPS fault)` and ALT_HOLD (2) at +4.0 s (loopback runs: +3.7 to +3.9 s); CRITICAL, position residual 30.1 m, later; `AEGIS: gps_recovered` at +22.8 s; no AUTO, RTL or LOITER sent by the bridge | NOT PASS as written (partly met); phase JSON not reviewed | The confirmation time is not in the summary, so the plan's 'about 3 s after confirmation' check cannot be evaluated. The GUIDED at +19 s was the pilot's own 20 s benign probe, not sent by the bridge; it was accepted while the GPS fault was active. The vehicle descended and disarmed in ALT_HOLD with no pilot throttle, as documented. All texts reached the ground over the radio. Not run over the radio: the sudden-glitch pilot-override variant, the 1 m/s drift (known miss), jamming. |

## Phase 6: MAVLink-2 signing

| Date | Config (max-age s) | Commit | Signed ok / acked, dropped_unsigned, dropped_bad_signature, dropped_replay, stale dropped, future frame outcome, gate exit code | Result | Notes |
|---|---|---|---|---|---|
| 2026-10-30 | rsg1: ACTIVE_IPS, signing key on the Pi; max-age not recorded | not recorded | signed_ok 10; dropped_unsigned 40 (10 each from unsigned sysid 66 and sysid 255, in MAVLink 2 and v1); dropped_bad_signature 10 (wrong key); dropped_replay 3 (byte-identical replay of a captured signed SET_MODE); stale dropped not run; future frame not run; gate exit code not run | NOT PASS as written (partly met); phase JSON not reviewed | Vehicle mode GUIDED (4) after every stage; hook errors 0. Downlink 4,929 of 4,929 forwarded, 0 dropped, 0 send failures; uplink 71 of 71 reached the bridge; downlink 1,396 B/s average at the ground hub; latency p50 0.29 ms, p95 0.63 ms. GCS: 26 action texts, 0 detector alerts. The drop counts match the Ethernet-tunnel run; signed_ok (10 here, 16 there) and the downlink totals differ, and the summary does not explain this. Acknowledged signed pilot commands: count not in the summary. |

## Phase 7: management channel over the radio

| Date | Config | Commit | Alert latency s, status age s, posture ACK latency s, mgmt B/s nominal / flood (peak 1 s), cross-end B/s, bad-frame ACKs (expect 0) | Result | Notes |
|---|---|---|---|---|---|
| | | | | | |

## Phase 8: failure and recovery

| Date | Failure case | Commit | Outage s (last ACK to first ACK after), manual steps needed, replay after restart dropped (y/n), CRC-invalid frames | Result | Notes |
|---|---|---|---|---|---|
| 2026-10-30 | unp1: Pi air-radio USB cable unplugged about 15 s after takeoff and replugged 16 s later (same port, same /dev/ttyUSB0 and by-id path); 330 s hover at 30 m; active-ips with `--allow-unsigned`; no attacks | not recorded | Outage 16.0 s at the pilot (one heartbeat gap). Manual steps: the physical unplug and replug only. The bridge process stayed up and its serial transport reconnected on its own, with no restart. Downlink resumed at about 28 frames/s; the bridge's forwarded_down counter kept increasing from the first poll after the replug. 414 frames could not be written during the outage (send_failures 414; dropped, not queued). CRC-invalid count: not recorded | NOT PASS as written (one of five cases; recovery met for this case); phase JSON not reviewed | 15 of 16 benign mode probes acknowledged (the missing one fell in the outage). Vehicle GUIDED at 30 m (vehicle_went_to_land 0). State NOMINAL, 0 alerts, 0 analyser errors, 0 tap overflow. Not run: laptop (ground) radio unplug, repeated or longer air-radio unplugs, unplug during an attack, Pi power loss and reboot with auto-start. |
| | Laptop radio replug | | | | |
| 2026-10-30 | rlong1: bridge killed with kill -9 at about +280 s and restarted by hand 25 s later | not recorded | Telemetry gap at the pilot 27.6 s (25 s dead plus about 2.6 s for the new process to start and the stream to resume). Manual steps: the bridge restart only. After the restart: 24,701 downlink forwarded, 0 dropped, 0 send failures, 0 tap overflow, 0 analyser errors. CRC-invalid count, replay after restart: not recorded (the run was unsigned) | NOT PASS as written (one of five cases run); phase JSON not reviewed | Topology A+B, state NOMINAL after the restart. Vehicle stayed GUIDED at 30 m; no manual intervention on the radios. Not run: radio unplug and replug (each radio), SITL drop and restart, Pi reboot, signed restart replay. Outage recorded as the plan requires. |
| | SITL drop and restart | | | | |
| 2026-10-30 | rbt1: `sudo reboot` on the Pi about 85 s after takeoff (soft reboot). The bridge was started at boot by `scripts/radio_test/pi_autostart.sh` from a user crontab entry (a variant: the plan says start it by hand) | not recorded | Pilot heartbeat gap 71.5 s (telemetry outage; the air radio is on the Pi). FC and GCS links both connected at about +70 s (see the timeline in the run section). Manual steps after the reboot command: none. Downlink since the new process started: 9,812 forwarded, 0 dropped, 17 send failures, 0 tap overflow, 0 analyser errors, state NOMINAL. Benign mode probes 19 of 23 acknowledged (the 4 missing fell in the outage). CRC-invalid count: not recorded | NOT PASS as written (auto-start variant run; by-hand start not run); phase JSON not reviewed | Two heartbeat gaps of 3.0 and 3.1 s at +384.8 s and +480.9 s of the flight, unexplained and not investigated. Four start-up DOS CRITICAL alerts (the bridge booted before the FC link was up) were held from the GCS by the quiet window and logged. Vehicle GUIDED at 30 m (vehicle_went_to_land 0). Soft reboot only. |

## Phase 9: soak

| Date | Config | Commit | Duration min, legitimate dropped, hook_errors, RSS start / end MiB, CPU %, loss first / last 10 min, new throttle bits | Result | Notes |
|---|---|---|---|---|---|
| 2026-10-30 | rlong1: active-ips with `--allow-unsigned`, 1,200 s flight at 30 m GUIDED over the radio; run length 20 min (plan: 30 to 60) | not recorded | Duration 20 min. Benign mode probes: 59 of 59 acknowledged (legitimate drops not reported separately). hook_errors: not in summary. RSS 58.9 to 64.9 MiB, slope 0.063 MiB/min, no growth flag. CPU mean 26 % / peak 43 % of one core. SoC 53 C mean, 54 C peak. Loss and latency, first vs last 10 min: not in summary. New throttle bits: not determined (under-voltage and throttling had occurred earlier since boot; the summary does not say whether they occurred in this run) | NOT PASS as written (partly met); phase JSON not reviewed | Bridge killed and restarted by hand (see phase 8). 6 monitor samples lost during the kill. Forged LAND from sysid 66 at +600 s and +900 s dropped (4 untrusted drops; COMMAND_INJECTION SUSPICIOUS x2); vehicle stayed GUIDED at 30 m. Not run: a 30 to 60 minute soak. |

## Combined flight session (phases 3-6)

| Date | Config | Commit | Stages run, per-stage result, anything left unreliable by an earlier stage | Result | Notes |
|---|---|---|---|---|---|
| | | | | | |

## Findings and what was not shown

Fill after the runs: bugs found (with the fix commit and regression test), documented limits that were confirmed or contradicted,
and the list of phases not run or failed. Keep claims to what the rows above show.

| Finding | Phase | Evidence (run directory, file) | Status |
|---|---|---|---|
| LR900 configuration mismatch (CHAN_MODE AUTO at 57,600 baud on one unit, FHSS_AIR at 115,200 on the other) caused one-way and junk data | 1 | Real-radio session section below; `RADIO_TEST.md` section 3, item 10 | Fixed 2026-10-30: both units configured and verified by READ |
| ArduCopter 4.7.1 has no SRn_* parameters; SR1_* writes changed nothing | 1-3 | rad1: 453 downlink frames, no position data, no takeoff | Use REQUEST_DATA_STREAM at low rates (or MAVn_*); see `RADIO_TEST.md` section 5 |
| Rate-learner false positive and gatekeeper shedding the vehicle's telemetry (Pi-in-the-loop, ACTIVE_IPS, 18 % of downlink dropped) | 2-5 | Pi 3B+ in-the-loop section | Fixed (commit e1ceb76 and the learner-extension change). Rerun in ACTIVE_IPS: 0 downlink dropped |
| Soak harness: attacker socket not drained, so only 1 of 5 forged LAND attempts reached the bridge | 5 | Pi 3B+ in-the-loop section, item 5 | Harness fixed after the run; the soak's LAND count is one attempt, not five |
| Phases 2 to 6 not met as written: passive and advisory postures not run over the radio; 14 probes against 30 per posture; signing stale, future and gate checks not run; GPS pilot-override and drift not run | 2-6 | Real-radio session section below | Open: run the plan's postures, probe counts and remaining checks |
| GPS glitch detected over the radio; ALT_HOLD at +4.0 s; no AUTO, RTL or LOITER sent by the bridge (rgps1) | 5 | rgps1, real-radio session section | Measured. The confirmation time is not in the summary, so the 3 s-after-confirmation check is not evaluated |
\1| Pi soft reboot with cron auto-start (rbt1): bridge back with FC and GCS links about 70 s after the reboot command; 71.5 s pilot gap | 8 | rbt1, real-radio Pi reboot section | Measured for the auto-start variant only. The plan's by-hand start, a hard power cut and the systemd unit are not tested |

## Pi 3B+ in-the-loop results (2026-10-30, SITL over Ethernet tunnels, no radio hop)

Measured on 2026-10-30. **No radio is in the path, so none of these rows fills a phase table above.** They are software
results of the bridge on the Pi 3B+, for the behaviour the real-radio phases will depend on. The real-radio status is at the end of this file.

**Rig.** ArduCopter SITL and the hub on the laptop. `aegis ips-bridge` on the Pi 3B+ (Python 3.13, ML off). The Pi is reached
over a direct Ethernet cable through `ssh -R` tunnels. GCS-side clients run on the laptop.

**Pi power, applies to every figure below.** The under-voltage and soft-temperature-limit flags were set during the soak
(SoC temperature mean 58.9 C, peak 60.1 C). CPU and latency figures are therefore worst-case.

**Code.** The forwarding fixes are commit `e1ceb76` and the learner-extension change after it. The new behaviour listed in
item 8 is commit `e8d08d3`.

### 1. Forwarding, passive and ACTIVE_IPS

* Passive: 23,077 frames forwarded, 0 dropped, p50 0.43 ms.
* ACTIVE_IPS after the rate-learner and gatekeeper fixes: 23,321 of 23,321 downlink frames forwarded. 20 forged uplink
  frames dropped. 3 alerts, all real. 0 false rate alerts. p50 0.25 ms, p95 0.42 ms.
* The pre-fix ACTIVE_IPS run is in the bench log update above (18 % of downlink dropped).

### 2. Signing (active-ips)

* `signed_ok` 16. Dropped: `dropped_unsigned` 40, wrong key 10, replay 3.
* Vehicle mode unchanged. 0 valid commands dropped. 24,102 of 24,102 downlink frames forwarded. p50 0.27 ms.
* The forged and unsigned drops are announced to the GCS as `AEGIS: blocked ... xN` STATUSTEXT, one per second per label.
  They are not detector alerts.

### 3. Fault tests (active-ips, vehicle flying at 30 m)

* Bridge hard-killed (`kill -9`) and restarted by hand: telemetry outage 13.0 s (11 s dead, about 2 s start-up).
* Tunnel cut for 10 s, then restored, with no manual restart: one telemetry gap of 11.8 s. The bridge reconnected by itself.
  30,401 of 30,412 downlink frames forwarded afterwards: 11 lost during the outage, 12 send failures. State NOMINAL,
  topology A+B.
* The vehicle stayed GUIDED at 30 m throughout both faults.
* These are not phase 8 results (phase 8 needs the radio). They show the bridge's own recovery behaviour.

### 4. GPS (active-ips)

* Control flight: GUIDED throughout. Only the start-up ground alerts appeared.
* 111 m glitch: detected at +0.5 s. ALT_HOLD at +3.7 s.
* Glitch with a pilot LOITER override: LOITER at +1.2 s. The ladder stood down.
* Scripted drift of about 1 m/s: NOT detected. Known limit, unchanged.

### 5. Soak, 1,800 s, active-ips

* Forged LAND every 5 minutes. **Harness bug:** only the first of the 5 attempts reached the bridge, because the attacker
  socket was not drained and the hub dropped it. This was fixed after the run. The forged-LAND result in this soak is one
  attempt, not five.
* 259,172 messages. 1,878 heartbeats. No gap over 1.5 s.
* 257,213 of 257,213 downlink frames forwarded. 0 send failures, 0 tap overflow, 0 hook errors, 0 analyser errors.
* Latency p50 0.243 ms, p95 0.412 ms.
* RSS 65 MiB, flat (slope 0.003 MiB/min).
* CPU mean 55.7 %, peak 60 % of one core (throttled Pi). The earlier unthrottled passive run was 28 %.
* Vehicle GUIDED at 30 m. 58 of 59 benign mode probes acknowledged.

### 6. Attack set (active-ips, bridge on the Pi, firmware directory with manifest)

| Attack | Result |
|---|---|
| Flood, 400 msg/s from rogue sysid 66, 10 s | Detected within about 2 s (MAVLINK_ANOMALY, then DOS CRITICAL). Sysid 66 quarantined. 3,962 uplink frames dropped. Downlink 34,395 of 34,395 forwarded. GCS saw `AEGIS: quarantine sys66` and `blocked HEARTBEAT sys66 xN`. |
| Man-in-the-middle altitude bias, +40 m | TELEMETRY_MANIPULATION CRITICAL (GPS/baro mismatch 40 m). sanitize_alt rewrote 98 frames. |
| Battery step, +3 V | NOT detected. Documented limit. |
| Frozen attitude while hovering | NOT detected. The yaw-vs-course check needs speed above 2 m/s. Documented limit. |
| Firmware tamper (one byte flipped in `autopilot.bin`) | FIRMWARE_INTEGRITY INVALID within about 5 s. Escalated to `CRITICAL FIRMWARE TAMPER IN FLIGHT -> PILOT TAKEOVER REQUIRED`. |

### 7. Management channel on the Pi

Setup: bridge started passive. Management key, lock file and audit log on the Pi.

* Posture: raise to advisory, then to active-ips, accepted (0.26 s). Lowering needs confirmation. A lowering against the lock
  file was denied.
* Wrong-key and replayed commands got no ack.
* The rate limit denied a command (result 2). The lockout was announced. A valid command sent during the lock was denied, and
  was accepted again after the 60 s lockout.
* Alert latency 0.2 s. Blocked-frame announcement 1.0 s.
* Management bytes down: average 38 B/s over the run. Maximum 210 B in one second. The 18 s burst averaged 129 B/s.
* No management frames reached the FC (user-1 commands: 0).
* Audit chain verified: 20 entries.
* Killing the ground dashboard left the bridge enforcing active-ips.

### 8. New behaviour from this session (code commit `e8d08d3`)

* `ips-bridge --firmware-dir DIR --firmware-recheck-s N` (default 30). `aegis fw-manifest DIR` hashes the `*.bin` files into
  `manifest.json`. The manifest is unsigned: an attacker who can rewrite both the binaries and the manifest defeats the
  check. Without `--firmware-dir` the verdict stays UNKNOWN.
* A 20 s start-up quiet window on the ground side while unarmed. During it, GPS_SPOOFING and DOS alerts, and the
  rate_limit, sanitize_gps, anti_jam_dr and gps_recovered actions, are still detected and logged but not announced to the GCS.
* AlertGate back-off for persistent alerts: the announcement gap doubles (4, 8, 16 s), then stays at 30 s maximum. Escalation
  is announced at once. A quiet 60 s resets the back-off.
* The vehicle's own telemetry is never rate-shed.
* The rate-baseline learner adopts a stable plateau after a stream-request step, and extends its window once.

### 9. Still NOT done

* Real-radio status is updated in the real-radio session section at the end of this file (2026-10-30, LR900 pair).
* `attacks.py` and `legit_probe.py` are unfinished, per the coordinator. `legit_probe.py` is not in the repository.

## Real-radio session, 2026-10-30 (MicoAir LR900 pair)

Measured on 2026-10-30. These figures come from the session summary supplied by the coordinator. The phase JSON files and the
run directories were not part of this documentation pass.

### Radio identification

* MicoAir LR900: module type `900M LORA TELEMETRY RADIO`, firmware 1.1.4, hardware 1.1, USB id CP2102.
* These are **not SiK radios**. They have no AT command set, so `+++` and `ATI` never answered. That is why every earlier AT
  probe got no reply.
* Configuration tool: MicoAssistant v0.9.23 (Windows; `MicoAssistant_EN.zip`, 26.07 MB, from micoair.com/downloads). It
  connected to the radio's COM port at 115,200 baud. Radio page: READ, WRITE, RESET. After WRITE the tool reports
  `WRITE RADIO SETUP SUCCESS, REBOOT TO TAKE EFFECT`. Unplug the USB cable, reconnect and READ to verify.
* Vendor: a steady green LED means link up.

### Root cause of the earlier one-way and junk data

The two units were configured differently. The laptop unit had CHAN_MODE AUTO and BAUDRATE / USB_BAUD 57,600. The Pi unit had
FHSS_AIR and 115,200 / 115,200.

### Configuration in use (verified by READ after a power-cycle)

| Setting | Ground (laptop, COM3) | Air (Pi, /dev/ttyUSB0) |
|---|---|---|
| MODE | DUPLEX | DUPLEX |
| POWER | MAX | MAX |
| ADDR | 1000 | 1000 |
| BAUDRATE | 115200 | 115200 |
| CHAN_MODE | FHSS_GROUND | FHSS_AIR |
| RATE | HIGH (2.1 KB/s) | HIGH (2.1 KB/s) |
| CHANNEL | 0 | 0 |
| USB_BAUD | 115200 | 115200 |

Vendor roles: FHSS_GROUND for the PC-side radio, FHSS_AIR for the flight-controller-side radio. Regulatory note: POWER MAX is used
on the bench. 890-915 MHz is not licence-free in every country; check local rules and lower POWER for bench work.

### Link baseline over the pair at 115,200 baud

Laptop `link_baseline.py`, Pi `pi_relay.py --mode echo`, 26-byte PING frames.

| Offered load | Loss | Round trip | Notes |
|---|---|---|---|
| 2, 5, 10, 20, 40 frames/s | 0 % | p50 59-61 ms, p95 about 70 ms, max 71 ms | Up to 1,040 B/s each way at 40 frames/s. Warm-up 10/10 echoes. |
| 60 frames/s (1,560 B/s offered) | 30.5 % | p99 187 ms | Saturated. Received 1,084 B/s. |
| 80 frames/s | 37.9 % | p50 1.4 s | Queueing. |

Clean throughput with these settings is about 1.0-1.05 KB/s each way. SITL's default telemetry of about 5 KB/s would swamp the
link. Stream rates must be requested low with REQUEST_DATA_STREAM.

### rad1: first session, SR1 parameters only

* 453 downlink frames forwarded. No position data. The vehicle did not take off.
* Forged LAND was still blocked and the flood still quarantined.
* Correction (2026-10-30, coordinator): ArduCopter 4.7.1 has no SRn_* parameters; they were removed. The SR1_* writes in this
  session changed nothing, which is the cause of the no-position-data result. Stream rates must be requested with
  REQUEST_DATA_STREAM, or set with the MAVn_* parameters.

### rad2: flight over the radio, bridge in ACTIVE_IPS

Setup: SITL ArduCopter on the laptop; the bridge on the Pi in `active-ips` with `--allow-unsigned`; the ground radio on COM3
behind `radio_hub.py`; the Pi air radio on `/dev/ttyUSB0` at 115,200 baud. Streams requested: POSITION 2 Hz, EXTRA1 2 Hz,
EXTRA2 1 Hz, EXTENDED_STATUS 1 Hz, EXTRA3 1 Hz, all others 0.

* Flight: 240 s. The pilot over the radio armed, took off to 30 m and held GUIDED. 14 benign mode probes acknowledged. No
  heartbeat gap over 3 s.
* Downlink: average 1,051 B/s; 379,796 B; 9,792 frames at the ground end. The bridge's status snapshot showed 9,801 frames sent
  (9,277 vehicle, 205 management, 319 cross-end). That is effectively lossless: 9 frames were in flight.
* Uplink: 567 of 567 frames from the ground clients reached the bridge.
* 0 send failures, 0 tap overflow, 0 analyser errors. Bridge latency p50 0.30 ms, p95 0.76 ms.
* Forged LAND (sysid 66) at +40 s and +160 s: dropped at the bridge. The vehicle stayed GUIDED at 30 m (`vehicle_went_to_land` 0).
  Alerts COMMAND_INJECTION and MAVLINK_ANOMALY were raised.
* Flood, 30 frames/s for 10 s from sysid 66: quarantined, 297 frames dropped. `AEGIS: blocked HEARTBEAT sys66 xN` and
  `AEGIS: quarantine sys66` reached the ground over the radio.
* Management traffic: 9,688 B over 361 s (about 27 B/s), with 1 budget denial.
* Pi: CPU mean 26 %, peak 44 % of one core. SoC 55 C mean. RSS 64 MiB, flat. Under-voltage flags occurred (the supply is still
  marginal).
* Ground hub: about 15,200 "bad segments" on the downlink, from non-MAVLink filler bytes between frames from the radio. The hub
  resyncs and treats them as harmless.

### rsg1: signing over the radio (phase 6)

Setup: ACTIVE_IPS on the Pi with the signing key on the Pi. Signed pilot over the radio. The attacker used the same hub.

* `signed_ok` 10.
* Dropped: `dropped_unsigned` 40 (10 each from unsigned sysid 66 and sysid 255, in MAVLink 2 and MAVLink 1). `dropped_bad_signature`
  10 (wrong key). `dropped_replay` 3 (byte-identical replay of a captured signed SET_MODE).
* The vehicle mode stayed GUIDED (4) after every stage. Hook errors 0.
* Downlink: 4,929 of 4,929 frames forwarded, 0 dropped, 0 send failures. About 1,396 B/s average at the ground hub.
* Uplink: 71 of 71 frames from the ground reached the bridge.
* Bridge latency p50 0.29 ms, p95 0.63 ms.
* The GCS received 26 action texts and 0 detector alerts. The drops are announced as `AEGIS: blocked ... xN`.
* The drop counts match the Ethernet-tunnel run (40, 10 and 3). `signed_ok` (10 here, 16 in the tunnel run) and the downlink
  totals (4,929 here, 24,102 there) differ. The summary does not explain this.
* Not tested over the radio: stale and future timestamps; the ACTIVE_IPS signing gate exit code; signing with delayed or
  jittered frames beyond the radio's own one-way delay (about 30 ms). The count of acknowledged signed pilot commands is not in
  the summary.

### rgps1: GPS glitch over the radio (phase 5, GPS row)

Setup: ACTIVE_IPS. 120 s hover at 30 m. At t = 140.0 s of the watcher log, `SIM_GPS1_GLTCH_X` = 0.001 was written to SITL (a
glitch of about 111 m). The times below are measured from the glitch.

* GPS_SPOOFING HIGH detected at +0.8 s.
* `AEGIS: GPS unreliable - do not trust position` at +1.0 s.
* `AEGIS: set ALT_HOLD (GPS fault)` at +4.0 s, with the mode ALT_HOLD (2) at +4.0 s. Loopback runs: +3.7 to +3.9 s.
* No AUTO, RTL or LOITER sent by the bridge.
* CRITICAL (position residual 30.1 m) later.
* `AEGIS: gps_recovered` at +22.8 s.
* The return to GUIDED at +19 s was the pilot's own 20 s benign DO_SET_MODE probe, not sent by the bridge. It was accepted
  while the GPS fault was active.
* The vehicle then descended and disarmed in ALT_HOLD with no pilot throttle, as documented in `docs/INLINE_IPS.md`.
* All texts reached the ground over the radio.
* Not run over the radio: the sudden-glitch pilot-override variant, the 1 m/s drift (a known miss) and GPS jamming. The
  confirmation time is not in the summary, so the plan's "about 3 s after confirmation" check cannot be evaluated.

### Phase status against the plan's written criteria (conservative)

The judgement is made against the plan's criteria in `RADIO_TEST.md`, not the coordinator's labels. The same judgement is in
`RADIO_TEST.md` section 11.

| Phase | Over the radio | Judgement |
|---|---|---|
| 0 | not reported | Not reported |
| 1 | no bridge | Meets the stated check on measured items |
| 2 | ACTIVE_IPS only | NOT PASS as written: passive not run |
| 3 | ACTIVE_IPS only | NOT PASS: advisory not run; 14 of 30 probes per posture |
| 4 | ACTIVE_IPS only | NOT PASS: advisory not run |
| 5 | ACTIVE_IPS | PARTLY: forged LAND, flood, GPS glitch measured |
| 6 | ACTIVE_IPS, signing key on the Pi | PARTLY: unsigned, wrong-key and replay measured |
| 7 | ACTIVE_IPS, budget only | PARTLY: budget measured; ground commands not run |
| 8 | ACTIVE_IPS, three cases (bridge kill and manual restart, rlong1; air-radio unplug, unp1; Pi soft reboot with cron auto-start, rbt1) | NOT PASS as written; three of five cases run (the Pi reboot in an auto-start variant); recovery needed no manual step beyond the listed ones |
| 9 | ACTIVE_IPS, 20 min (rlong1) | NOT PASS as written; partly met (20 min, not 30 to 60) |

**Not yet run over the radio:** the passive and advisory postures; management-channel control from the ground; firmware tamper over the radio; ground-radio (laptop) unplug; repeated or longer air-radio unplugs, and unplug during an attack; hard power loss of the Pi (SD-card behaviour), and the Pi reboot with the bridge not auto-started (the plan's by-hand variant); a systemd-managed bridge start (the unit is not installed or tested); SITL drop and restart over the radio; the laptop-side ground-radio replug; the signed-restart replay; the 30 to 60 minute soak (the longest real-radio run was 20 minutes); range; the signing stale and future timestamp checks and the signing gate; the GPS pilot-override variant, the 1 m/s drift and jamming.

### Scripts

* New bench scripts: `scripts/ardupilot/inline_demo/pi/` (its `README.md` lists them). `run_radio_pi.sh` is the real-radio
  runner: the laptop COM3 hub at 115,200 baud, an `ssh -R 5762` tunnel and an `ssh -L 8090` status forward, and the Pi bridge
  started through `scripts/radio_test/pi_bridge.sh`.
* `run_radio_pi.sh` first runs `~/aegis_test/wifi_stop.sh` and `~/aegis_test/stop_relay.sh` on the Pi. Neither script is in
  this repository, and neither was reviewed in this documentation pass.

## Real-radio long run rlong1, 2026-10-30 (LR900 pair, 20 min)

Measured on 2026-10-30. The figures come from the session summary supplied by the coordinator.

**Setup.** Real LR900 pair at 115,200 baud. The ground radio is on the laptop (COM3, behind `radio_hub.py`); the air radio is on
the Pi. SITL runs on the laptop. The bridge runs on the Pi in `active-ips` with `--allow-unsigned`. Low stream rates were
requested with REQUEST_DATA_STREAM. The flight was 1,200 s at 30 m, GUIDED.

**Scope limits, stated plainly.**

* The run is 20 minutes. Phase 9 asks for 30 to 60 minutes.
* The bridge restart was manual, with no supervisor or auto-start. It was not a radio unplug.
* Not run in this session: radio unplug and replug of either radio (this needs a person); the passive and advisory postures over
  the radio; management-channel control from the ground over the radio; firmware tamper over the radio; range.

**Pilot and vehicle.** The pilot over the radio received 1,271 heartbeats and 89,870 messages. All 59 benign mode probes were
acknowledged. The vehicle never left GUIDED at 30 m (`vehicle_went_to_land` 0).

**Forged LAND.** Forged LAND from sysid 66 at +600 s and +900 s: both dropped. 4 untrusted drops. Alerts: COMMAND_INJECTION
SUSPICIOUS x2.

**Bridge kill and restart (phase 8 case).** The bridge was killed with `kill -9` at about +280 s and restarted by hand 25 s
later.

* One telemetry gap at the pilot of 27.6 s: 25 s of dead time plus about 2.6 s for the new process to start and the radio
  stream to resume.
* Nothing else changed on the vehicle. No manual intervention on the radios.
* After the restart (counters of the new process): 24,701 downlink frames forwarded, 0 dropped, 0 send failures, 0 tap overflow,
  0 analyser errors. Latency p50 0.30 ms, p95 0.61 ms. Topology A+B. State NOMINAL.
* The downlink count before the kill is not in the summary, so no whole-run loss figure is given.

**Pi monitor over the run.** CPU mean 26 %, peak 43 % of one core. SoC temperature 53 C mean, 54 C peak. RSS 58.9 to 64.9 MiB, slope
0.063 MiB/min (the flag threshold is 1.0; no growth flag). 6 monitor samples were lost during the bridge kill. Under-voltage and
throttling flags had occurred earlier since boot; the summary does not say whether they occurred during this run.

**Judgement against the plan (conservative).**

* Phase 8: **NOT PASS as written; one of five failure cases run.** Met on this case: the outage was measured and recorded,
  recovery needed only the named-process restart, and the vehicle held GUIDED at 30 m. Not run: radio unplug and replug, SITL
  drop and restart, Pi reboot, and the signed-restart replay. The CRC-invalid count is not in the summary.
* Phase 9: **NOT PASS as written; partly met.** Met: bridge RSS flat (slope 0.063 MiB/min, no growth flag); 59 of 59 benign probes
  acknowledged; forged LAND dropped. Not met: the run is 20 minutes, not 30 to 60. Not shown in the summary: the new-throttle-bit
  check, hook_errors for the run, and loss and latency for the first versus last 10 minutes.

## Real-radio air-radio unplug unp1, 2026-10-30 (LR900 pair)

Measured on 2026-10-30. The figures come from the session summary supplied by the coordinator.

**Setup.** Real LR900 pair at 115,200 baud. SITL on the laptop. The bridge on the Pi in `active-ips` with `--allow-unsigned`.
330 s hover at 30 m, GUIDED. No attacks.

**Event.** The user physically unplugged the Pi's air-radio USB cable at about +15 s after takeoff. The Pi kernel log shows
`cp210x converter disconnected`. The cable was replugged 16 s later, into the same USB port, so `/dev/ttyUSB0` and the by-id
path were unchanged.

**Result.**

* The bridge process stayed up. Its serial transport reconnected on its own, with no restart and no manual action on either radio.
* The pilot at the ground saw exactly one heartbeat gap of 16.0 s, which is the outage length.
* Downlink resumed at about 28 frames/s. The bridge's `forwarded_down` counter kept increasing from the first poll after the replug.
* 414 frames could not be written during the outage. They were counted as `send_failures` (414) and dropped, not queued. The
  counter stopped growing after the replug.
* 15 of 16 benign mode probes were acknowledged. The missing one fell in the outage.
* The vehicle stayed GUIDED at 30 m (`vehicle_went_to_land` 0).
* Bridge state NOMINAL, 0 alerts, 0 analyser errors, 0 tap overflow.

**Scope limits, stated plainly.**

* Not run: ground-radio (laptop) unplug; hard power loss of the Pi (a soft reboot was run later, rbt1); unplug during an attack; repeated
  unplugs; longer outages.
* A systemd unit exists in the repository (`scripts/radio_test/aegis-bridge.service`) but was not installed or tested. Bridge auto-start after a Pi reboot was tested only with a user crontab entry (rbt1).

**Judgement against the plan (conservative).** Phase 8 is NOT PASS as written: one of the five listed failure cases in this
run was the Pi radio replug. For that case the recovery requirement is met: the link recovered without a manual step other
than the listed replug. The outage was recorded. The CRC-invalid count is not in the summary.

## Real-radio Pi soft reboot rbt1, 2026-10-30 (LR900 pair, 480 s hover)

Measured on 2026-10-30. The figures come from the session summary supplied by the coordinator.

**Setup.** Real LR900 pair at 115,200 baud: the ground radio on the laptop (COM3, behind `radio_hub.py`) and the air radio on
the Pi. SITL on the laptop. The bridge on the Pi in `active-ips` with `--allow-unsigned`. 480 s hover at 30 m. No attacks.

The bridge was started at boot by `scripts/radio_test/pi_autostart.sh`, which was launched from a user crontab entry
(`@reboot sleep 10; ~/aegis_test/pi_autostart.sh`), because the bench Pi has no passwordless sudo. The cron entry was removed
after the test. The systemd unit `scripts/radio_test/aegis-bridge.service` is provided for production but was **not installed
or tested**. The laptop kept an `ssh -R` tunnel to the Pi alive with a reconnect loop, standing in for a wired flight-controller
link.

**Event.** A person ran `sudo reboot` on the Pi about 85 s after takeoff. Nobody logged in or touched anything after the reboot
command.

**Timeline (laptop clock; the origin is as given by the coordinator, +0 s = Pi unreachable).**

* About +0 s: Pi unreachable.
* About +50 s: ssh reachable again.
* About +70 s: bridge process running, the radio device present, and both the FC link and the GCS link connected.

**Result.**

* The pilot saw one heartbeat gap of 71.5 s. This is the telemetry outage, because the air radio is on the Pi. Telemetry then
  resumed.
* The vehicle stayed GUIDED at 30 m throughout (`vehicle_went_to_land` 0). At the end it was armed at 30.0 m.
* 19 of 23 benign mode probes were acknowledged. The 4 missing probes fell in the outage.
* Two further heartbeat gaps of 3.0 s and 3.1 s, at +384.8 s and +480.9 s of the flight. They are unexplained and were not
  investigated. The Pi had under-voltage and throttle flags earlier since boot; `get_throttled` read `0x50000` after the reboot.
* The new bridge process, counters since boot: 9,812 downlink frames forwarded, 0 dropped, 17 send failures, 0 tap overflow,
  0 analyser errors, state NOMINAL, posture active-ips.
* Start-up alerts: the event log has 4 `DOS CRITICAL heartbeat stale (never received since monitoring began)` alerts in the
  first 15 s. The bridge booted before the FC link was up. They were held back from the GCS by the 20 s start-up quiet window,
  while the vehicle is not known to be armed. They are logged.

**Posture after a reboot (verified by code reading, not by this run).** The bridge's posture comes from `MODE` in
`autostart.env` (`pi_autostart.sh` defaults to `active-ips`). A reboot therefore restores that configured posture, not a
posture raised or lowered over the management channel. The management state file (`--mgmt-state`) stores only anti-replay
stream timestamps (`src/aegisflight/hal/mgmt_channel.py`, `_persist`), and the posture is set from `--defense-mode` at start
(`src/aegisflight/hal/inline_ips.py`). A lock file (`--lock-posture-file`) is a file-exists check, so if it is on disk at boot
it still blocks remote posture changes. This was not exercised in rbt1: its posture came from `autostart.env`.

**Limits, stated plainly.**

* Soft reboot only (`sudo reboot`). Not a hard power cut. SD-card behaviour was not tested.
* One run.
* The FC link was a tunnel, not a UART. A real UART or USB FC link also needs its device to be present at boot; that was not
  tested here.
* No signing key and no management key in this run.
* No supervisor restarted the bridge on a crash. The systemd unit sets `Restart=on-failure`, but it is untested.
* The cron entry is a bench workaround, not a production start method.

**Judgement against the plan (conservative).** Phase 8, Pi reboot case: **run, but as an auto-start variant**. The plan's step 5
says to reboot with the bridge not auto-started and then start it by hand. The by-hand variant was not run. For the variant
that ran, recovery needed no manual step after the reboot command. Phase 8 overall is **NOT PASS as written; three of five
listed cases run** (air-radio unplug, bridge kill with manual restart, Pi reboot with auto-start). The laptop-radio replug and
the SITL drop have not been run. The CRC-invalid count is not in the summary. The two 3 s gaps are unexplained.
Phase 9 is not affected by this run.
