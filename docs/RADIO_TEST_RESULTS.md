# Real-radio test results log

> **Real-radio runs exist (2026-10-30, MicoAir LR900 pair).** The phase rows below are filled from the session summary; the
> phase JSON files were not reviewed. The notes say where the plan's written criteria are not met. The Bench log below holds the first measured bench observations.
> The real-radio session of the same day is described at the end of this file. Real Pixhawk 6X runs on a Raspberry Pi 5
> (bench, disarmed, 2026-10-30/31) are at the end of this file, in the section "Real Pixhawk 6X on a Pi 5, 2026-10-31".
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

* The Pi is reached over a direct Ethernet cable, at `ardra.local` = <pi-link-local-ip> (link-local). No Wi-Fi is used for the Pi.
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
| Laptop IP / Pi IP / Wi-Fi RTT | Pi at `ardra.local` = <pi-link-local-ip> over the Ethernet cable; RTT not recorded |
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
| 2026-10-30 | cpc: randomised signed campaign, seed 7, PASSIVE (IDS); 11 events; signed link, SITL enforcing signing | not recorded | 81 AEGIS texts over the radio, every one of the 11 events announced. Forged commands and flood: detector alerts plus 'unsigned' texts; wrong-key 3 'bad-signature'; replay 1 'replay'; fw_tamper 7 FIRMWARE_INTEGRITY; gps_glitch 9 GPS_SPOOFING; alt_bias 3; 76 forged telemetry frames reported as 'AEGIS: unsigned down' (forged_down_observed 76). Signing observed: unsigned 9, bad_signature 3, replay 1 | NOT PASS as written; phase JSON not reviewed | Dropped 0 frames up and 0 down; 0 counter-frames: nothing changed on the vehicle path. batt_jump and freeze were detected by the signing rule, not by the battery or attitude detectors. Per-event latency (5 s criterion) not in the summary. Limit: the FC rejected the forged commands itself, so the vehicle was not saved by the bridge. |
| 2026-10-30 | cac: the same campaign (seed 7), ADVISORY; figures as given for passive and advisory together | not recorded | 91 AEGIS texts over the radio, every one of the 11 events announced. Detection classes as for cpc. Forged telemetry: 76 frames reported as unsigned | NOT PASS as written; phase JSON not reviewed | Dropped 0 up and 0 down; 0 counter-frames. The plan's check that no AEGIS frame reaches the FC is not reported. The summary gives no separate advisory breakdown. |
| 2026-10-30 | cic: the same campaign (seed 7), ACTIVE_IPS | not recorded | 112 AEGIS texts over the radio, every one of the 11 events announced ('AEGIS: blocked ...', 'quarantine sys66', 'GPS unreliable - do not trust position', 'set ALT_HOLD (GPS fault)'). Uplink dropped 250; forged telemetry dropped 76 | NOT PASS as written; phase JSON not reviewed | Detection and blocking in one run; the per-event 'detected' column is announcement-based. The watcher text logs were incomplete, so the texts come from the hub capture. The campaign's findings and limits are in the campaign section below. |

## Phase 5: prevention in ACTIVE_IPS

| Date | Config | Commit | Hostile frames sent / dropped / reaching FC, forced disarm passed, GPS ladder: confirm to ALT_HOLD s, override honoured, legitimate dropped | Result | Notes |
|---|---|---|---|---|---|
| 2026-10-30 | rad2: ACTIVE_IPS | not recorded | Forged LAND dropped at the bridge; vehicle stayed GUIDED at 30 m (vehicle_went_to_land 0); flood quarantined, 297 frames dropped; 14 benign probes acknowledged | NOT PASS as written (coordinator label: PASS); phase JSON not reviewed | Not run over the radio: trusted forced disarm, GPS ladder, pilot override during a GPS warning. |
| 2026-10-30 | rgps1: ACTIVE_IPS; 120 s hover at 30 m, then SIM_GPS1_GLTCH_X = 0.001 (about 111 m) written to SITL at t = 140.0 s of the watcher log | not recorded | GPS_SPOOFING HIGH at +0.8 s; `AEGIS: GPS unreliable - do not trust position` at +1.0 s; `AEGIS: set ALT_HOLD (GPS fault)` and ALT_HOLD (2) at +4.0 s (loopback runs: +3.7 to +3.9 s); CRITICAL, position residual 30.1 m, later; `AEGIS: gps_recovered` at +22.8 s; no AUTO, RTL or LOITER sent by the bridge | NOT PASS as written (partly met); phase JSON not reviewed | The confirmation time is not in the summary, so the plan's 'about 3 s after confirmation' check cannot be evaluated. The GUIDED at +19 s was the pilot's own 20 s benign probe, not sent by the bridge; it was accepted while the GPS fault was active. The vehicle descended and disarmed in ALT_HOLD with no pilot throttle, as documented. All texts reached the ground over the radio. Not run over the radio: the sudden-glitch pilot-override variant, the 1 m/s drift (known miss), jamming. |
| 2026-10-30 | cic: campaign, seed 7, ACTIVE_IPS, 11 events, 2400 s bridge budget, legitimate signed pilot flying and probing throughout | not recorded | Uplink dropped 250: forced disarm 3, wrong-key 3, replay 1, forged LAND 3, forged RTL plus flood 237-240. Downlink dropped 76, exactly the forged telemetry frames (forged_down_dropped 76); no genuine telemetry dropped. Counter-frames 6 (GPS ladder warning and ALT_HOLD for the glitch, and the sanitize actions). Pilot altitude stayed at the true 20 m during alt_bias. Vehicle armed in GUIDED at about 20 m throughout; no heartbeat gap over 3 s | NOT PASS as written (partly met); phase JSON not reviewed | The ALT_HOLD counter-command was rejected by the FC because the bridge's counter-command timestamps came from a clock 3 h 9 min behind; fixed (see the finding in the campaign section and row cid). The vehicle path is not a test of the bridge alone, because the FC also rejects forgeries (signing on). Not run as a separate case: trusted forced disarm, pilot-override variant, 1 m/s drift, jamming. |
| 2026-10-30 | cid: campaign re-run after the timestamp fix, seed 7, ACTIVE_IPS, signed link | not recorded | GPS glitch at t = 469.7 s: ALT_HOLD (mode 2) at t = 474.0 s (+4.3 s). Vehicle descended to the ground in ALT_HOLD (no pilot throttle, as documented). Pilot's periodic GUIDED probe back to mode 4 at +12 s. Uplink dropped 250; downlink dropped 77 (the 76 forged frames plus one more, not explained in the summary); 0 heartbeat gaps over 3 s; 0 analyser errors | NOT PASS as written (partly met; the GPS ladder now acts on the vehicle); phase JSON not reviewed | The plan's 'about 3 s after confirmation, accept 5 s' check cannot be evaluated: the confirmation time is not in the summary. Not run as separate cases: pilot override, trusted forced disarm, the 1 m/s drift, jamming. |

## Phase 6: MAVLink-2 signing

| Date | Config (max-age s) | Commit | Signed ok / acked, dropped_unsigned, dropped_bad_signature, dropped_replay, stale dropped, future frame outcome, gate exit code | Result | Notes |
|---|---|---|---|---|---|
| 2026-10-30 | rsg1: ACTIVE_IPS, signing key on the Pi; max-age not recorded | not recorded | signed_ok 10; dropped_unsigned 40 (10 each from unsigned sysid 66 and sysid 255, in MAVLink 2 and v1); dropped_bad_signature 10 (wrong key); dropped_replay 3 (byte-identical replay of a captured signed SET_MODE); stale dropped not run; future frame not run; gate exit code not run | NOT PASS as written (partly met); phase JSON not reviewed | Vehicle mode GUIDED (4) after every stage; hook errors 0. Downlink 4,929 of 4,929 forwarded, 0 dropped, 0 send failures; uplink 71 of 71 reached the bridge; downlink 1,396 B/s average at the ground hub; latency p50 0.29 ms, p95 0.63 ms. GCS: 26 action texts, 0 detector alerts. The drop counts match the Ethernet-tunnel run; signed_ok (10 here, 16 there) and the downlink totals differ, and the summary does not explain this. Acknowledged signed pilot commands: count not in the summary. |
| 2026-10-30 | cic: campaign, seed 7, ACTIVE_IPS; the FC also enforces signing (sign_setup) | not recorded | Uplink: wrong-key 3 dropped, replay 1 dropped, unsigned forgeries dropped (forced disarm 3, forged LAND 3, forged RTL and flood 237-240). Vehicle mode unchanged. Stale, future, gate and acknowledged-signed-command counts not in the summary | NOT PASS as written (partly met); phase JSON not reviewed | The signing rule also judges a source that has been seen signing 20 valid frames: an unsigned or badly signed frame from it is blocked (ACTIVE_IPS) or reported (IDS and advisory). Sources that never sign are not judged. Not run: stale and future timestamps, the signing gate, delay or jitter beyond the radio's one-way delay. |

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
| Bridge counter-commands stamped from a Pi clock 3 h 9 min behind were rejected by a signing-enabled FC (ALT_HOLD never applied in cic) | 5, 6 | cic; cid; direct SITL test | Fixed in code (stamping above the newest valid signed timestamp seen). cid: ALT_HOLD +4.3 s after the glitch. Cause and fix in the campaign section |

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
* `attacks.py` and `legit_probe.py` are unfinished, per the coordinator. `legit_probe.py` is in the repository (`scripts/radio_test/legit_probe.py`, committed in `95399be`) but has never been run; the real-Pixhawk legitimate-traffic suite used `scripts/ardupilot/real_pixhawk/px_legit.py`.

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

**Not yet run over the radio:** plain passive and advisory postures (pilot operation and forwarding; only the attack campaign ran in them); management-channel control from the ground; firmware tamper over the radio; ground-radio (laptop) unplug; repeated or longer air-radio unplugs, and unplug during an attack; hard power loss of the Pi (SD-card behaviour), and the Pi reboot with the bridge not auto-started (the plan's by-hand variant); a systemd-managed bridge start (the unit is not installed or tested); SITL drop and restart over the radio; the laptop-side ground-radio replug; the signed-restart replay; the 30 to 60 minute soak (the longest real-radio run was 20 minutes); range; the signing stale and future timestamp checks and the signing gate; the GPS pilot-override variant, the 1 m/s drift and jamming.

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

## Randomised signed campaign over the real radio, 2026-10-30 (seed 7; passive, advisory, active-ips)

Measured on 2026-10-30. The figures come from the session summary supplied by the coordinator. The campaign JSON files, status
files and hub captures were not part of this documentation pass.

**Setup.**

* Real LR900 pair at 115,200 baud. ArduCopter SITL on the laptop, with MAVLink-2 signing provisioned into the SITL. The flight
  controller itself therefore rejects unsigned, wrong-key and replayed commands.
* The bridge on the Pi with the signing key, a signing state file, and a real firmware directory with a trusted manifest
  (`--firmware-dir`, recheck every 5 s).
* A man-in-the-middle proxy (`inject_proxy.py`) on the flight-controller link, for telemetry forgeries.
* GPS fault by SITL parameter. Flood from sysid 66.
* One run per posture, with the same seed (7), so the event order and timing are identical. Run labels: `cpc` (passive),
  `cac` (advisory), `cic` (active-ips). Earlier runs `cpa` and `cpb` found the gaps listed below; they are not used for results.
* 11 events, shuffled by the seed. Three adjacent pairs overlap: alt_bias and forged_land 3 s apart; forged_rtl and flood 7 s
  apart; forged_force_disarm and fw_tamper 8 s apart. The events: forged_force_disarm (magic 21196, sysid 66), fw_tamper,
  wrong_key_land, freeze, batt_jump (+3 V), replay_loiter (a captured signed DO_SET_MODE LOITER), alt_bias (+40 m), forged_land,
  gps_glitch (`SIM_GPS1_GLTCH_X` 0.001, about 111 m, cleared after 25 s), forged_rtl_spoof255 (unsigned frames claiming sysid
  255) and flood (30 frames/s for 8 s).
* The legitimate signed pilot kept flying and probing throughout: 23 probes, 25 acknowledgements counted.

**Common result, all three postures.** The vehicle stayed armed in GUIDED at about 20 m throughout. No operator recovery was
needed. No heartbeat gap over 3 s. 0 analyser errors. All 11 events produced an `AEGIS:` STATUSTEXT at the ground over the radio.
The texts were recovered from the hub downlink capture: 81 (passive), 91 (advisory), 112 (active-ips).

**Per posture.**

* *Passive (IDS) and advisory, as reported together.* The bridge dropped 0 frames up and 0 down, and sent 0 counter-frames, so
  nothing changed on the vehicle path. Detections: forged commands and the flood by detector alerts plus `unsigned` texts;
  wrong-key 3 `bad-signature`; replay 1 `replay`; fw_tamper 7 FIRMWARE_INTEGRITY alerts; gps_glitch 9 GPS_SPOOFING alerts;
  alt_bias 3 alerts. The 76 forged telemetry frames (31 GLOBAL_POSITION_INT, 30 ATTITUDE, 15 SYS_STATUS) were reported as
  `forged_down_observed` 76 and `AEGIS: unsigned down ... xN`. Signing observed totals: unsigned 9, bad_signature 3, replay 1.
  batt_jump and freeze were detected by the signing rule, not by the battery or attitude detectors.
* *Active-ips.* Uplink dropped 250: forced disarm 3, wrong-key 3, replay 1, forged LAND 3, forged RTL plus flood 237-240.
  Downlink dropped 76, exactly the 76 forged telemetry frames (`forged_down_dropped` 76). No genuine telemetry was dropped.
  Counter-frames 6: the GPS ladder warning and ALT_HOLD for the glitch, plus the sanitize actions. Announcements: `AEGIS: blocked ...`,
  `quarantine sys66`, `GPS unreliable - do not trust position`, `set ALT_HOLD (GPS fault)`. The pilot's altitude stayed at the
  true 20 m during alt_bias. In passive and advisory the pilot saw 60 m (the forged value) in the first forged_land window.

**Finding: the ALT_HOLD counter-command was rejected by the flight controller in cic; cause found, fixed, and re-run as cid (2026-10-30).**

* In cic (signed link, ACTIVE_IPS), the GPS ladder's ALT_HOLD counter-command was announced and sent (counter_frames +4 during the
  glitch), but the vehicle mode never changed: it stayed GUIDED, at 20.2 m. On the unsigned link the same ladder gave ALT_HOLD at
  +4.0 s.
* Cause: MAVLink signing timestamps are wall-clock based. The bridge's signed counter-commands were stamped from the Pi's clock. The
  Pi has no time sync and was 11,369 s (3 h 9 min) behind the laptop. A signing-enabled flight controller rejects stale timestamps,
  so it rejected them.
* Signing itself was not at fault. A direct test against the signing-enabled SITL showed that the FC accepts the bridge's signed
  commands (sysid 1 / compid 191, link_id 0 and 3) when the timestamp is current: ALT_HOLD and STABILIZE both took effect.
* Fix (code): counter-commands are stamped just above the newest valid signed timestamp the bridge has seen on the link
  (`policy.next_signing_timestamp`, `MavlinkActuator.set_timestamp_source`). The clock is used only before any signed traffic has been
  seen. Timestamps are strictly increasing. A unit test covers a link 11 days ahead of the machine clock. The commit hash of this fix
  was not given.
* Re-run cid (same seed 7, ACTIVE_IPS, real radio, signed): the glitch at t = 469.7 s gave ALT_HOLD (mode 2) at t = 474.0 s (+4.3 s).
  The vehicle descended to the ground (altitude -0.1 m; ALT_HOLD with no pilot throttle, as documented). The pilot's own periodic
  GUIDED probe returned the vehicle to mode 4 at +12 s. The campaign's operator recovery re-armed and took off again in 46 s.
  Everything else matched cic: 250 uplink drops; 77 downlink frames dropped (the 76 forged telemetry frames plus one more; the summary
  does not say what the extra one is); 0 heartbeat gaps over 3 s; 0 analyser errors.
* Real-world consequence, stated plainly: a companion computer without an RTC or internet access (an arbitrary clock) would have had
  all its signed bridge commands rejected by a signing-enabled flight controller. Its `--signing-max-age-s` replay window, if set,
  also compares frame timestamps with the local clock and would misjudge. On such a machine keep `--signing-max-age-s` unset, or fix
  the clock. Not tested.

**Findings from this campaign (fixed in code; commit 93d5572 and the following feature commit, whose hash was not given).**

1. With the key configured but enforcement off, a wrong-key forgery and a replayed signed command were invisible to the IDS
   (passive run cpa: 0 alerts). The IDS and advisory postures now judge control-frame signatures and report them
   (`status.signing_observed`, `AEGIS: unsigned | bad-signature | replay ...`).
2. All genuine vehicle telemetry is signed on a signed link: 15,816 frames. The only unsigned frames claiming to be the vehicle
   were the 76 forged ones, yet the bridge forwarded them; battery step and frozen attitude had never been alerted before.
   Now a source that has been seen signing 20 valid frames and then sends an unsigned or badly signed frame is a forgery:
   blocked in ACTIVE_IPS, reported in IDS and advisory. This costs about 3.4 us per frame on the laptop. Sources that never sign
   are never judged. Replayed-timestamp verdicts are ignored on the downlink.

**Limits, stated plainly.**

* (g) The clock fix was tested in one re-run (cid) and a unit test. It has not been run on a second seed.
* (a) Because the SITL has signing enabled, the flight controller rejects the forged commands itself. In no posture did the
  vehicle's mode change. These runs show detection, announcement and blocking at the bridge. They do not show the vehicle being
  saved by the bridge; the earlier unsigned-link runs showed a forged LAND landing the vehicle in passive. A randomised campaign
  on an unsigned link was **not** run.
* (b) One seed (7) and one run per posture, with 11 events. No statistical claim is made.
* (c) A smart attacker holding the key is out of scope. A forger who guesses the 'signed' flag but not the key is caught by
  verification. An attacker replaying a captured genuine signed downlink frame is not judged, because replay verdicts are ignored
  on the downlink.
* (d) The slow 1 m/s GPS drift was not part of the campaign. It is still a known miss.
* (e) The per-event 'detected' column is announcement-based. The watcher text logs were incomplete, so announcements were
  recovered from the hub downlink capture.
* (f) The Pi's under-voltage and throttle flags were present during the campaign.

**Judgement against the plan (conservative).** Phase 4 (detection): **NOT PASS as written.** Advisory is now measured over the
radio, and every event was announced. The per-event latency against the 5 s criterion and the check that no AEGIS frame reaches
the FC are not in the summary. Phase 5 (prevention): **NOT PASS as written; partly met.** The GPS ladder now acts on the vehicle (cid, +4.3 s). Phase 6 (signing): **NOT PASS as
written; partly met.** Phase 2 (passive forwarding): still **NOT PASS as written**; the campaign's passive run dropped 0 frames
each way, but it was an attack run, not a plain forwarding run, and hook_errors and latency for it are not in the summary.

## Real Pixhawk 6X on a Pi 5, 2026-10-31

Measured on 2026-10-30 and 2026-10-31 on the bench. The flight controller was a real Pixhawk 6X running ArduCopter, **disarmed, with the propellers removed**. No run in this section flew the vehicle. The Pixhawk was connected to the companion by USB (CDC), not by a UART. These are bench checks of the bridge against a real flight controller and the LR900 radio pair. They are not added to the phase tables above, which hold rows from the procedure in `docs/RADIO_TEST.md`. The judgement against the plan is at the end of this section. Where the session record gives no figure, it is written as "not recorded", and the plan's check counts as not met.

The procedure for repeating these runs is in `docs/REAL_PIXHAWK_TEST.md`.

### Rig

| Item | Value |
|---|---|
| Flight controller | Pixhawk 6X, ArduCopter (USB descriptor "ArduPilot Pixhawk6X"), quadcopter. Bench: DISARMED, STABILIZE, propellers removed, battery about 15.1 V (4S class), 3D GPS fix with 5 to 7 satellites in the 2026-10-30/31 sessions; no fix in the 2026-11-02 campaign batches 1 to 3 (see their subsections). Firmware: ArduCopter 4.7.1, version word 67503103 (2026-10-31 snapshot) |
| Flight-controller link | USB, `/dev/ttyACM0` on the Pi 5. The same board read normally on the laptop (COM4). MAVLink 1 heartbeats until a MAVLink 2 ground station talks; unsigned throughout |
| Companion | Raspberry Pi 5, Raspberry Pi OS Lite (Debian 13), Python 3.13. `vcgencmd get_throttled` = `0x0` throughout, SoC 43 to 51 C |
| Radio | MicoAir LR900 pair at 115,200 baud, with the settings in "Configuration in use" above. Air unit on the Pi (`/dev/ttyUSB0`), ground unit on the laptop (COM3) |
| Bridge | `aegis ips-bridge` in passive, advisory and active-ips. Active-ips ran with `--allow-unsigned` |
| Mission on the vehicle | 5 items. Read only, never changed |
| Commit | Not recorded per run. Repository HEAD when this section was written: `5f86820` (docs) |

**Why a Pi 5.** The first companion was a Raspberry Pi 3B+ (reflashed by the user). Opening the Pixhawk's serial port (`/dev/ttyACM0`) made the 3B+ drop off the network in 3 of 3 attempts, with the radio attached and without it. An earlier boot also showed under-voltage (`throttled=0x50000`). The same Pixhawk and cable read normally on the laptop. The Pi 5 did not drop off, and every real-Pixhawk run below used it.

### Benign runs (bridge on the Pi 5, radio to the laptop)

| Run | Measured | Result |
|---|---|---|
| Pixhawk alone, read only, 30 s | 1,054 bytes. Only heartbeats (about 1.2 frames/s including TIMESYNC) until a ground station requests streams. Every byte accounted for with the full ArduPilot dialect | Read-only check |
| Passive, 60 s | 0 alerts, 0 errors, 0 dropped frames. Latency p50 about 12 us. The first run counted 143 frames in 25 s, because about 117 were a backlog waiting on the idle port. Steady rate about 1.1 frames/s | 0 drops, 0 alerts |
| Passive, ground side through the radio, 45 s | 45 heartbeats, 22 bridge status frames and 4 time-sync frames, all as expected | As expected |
| Advisory, benign ground traffic | 578 frames forwarded down, 55 up. 0 dropped, 0 alerts. Latency p50 15 us | 0 drops, 0 alerts |

**Limits, stated plainly.** The passive run was 60 s and the ground run 45 s. Neither is the 10-minute run that phase 2 asks for. The pilot did not arm, take off or fly in any of these runs.

### Attack sequence on the unsigned link (`px_attack.py`)

Propellers off, vehicle disarmed. The script aborts if the vehicle reports armed. It sends the attack events through the radio port directly, so `radio_hub` must not hold that port.

**Test defect, finding withdrawn.** The first runs of this sequence were invalid. The test script never advanced the MAVLink sequence counter (pymavlink's `pack()` does not advance it; `send()` does), so every frame carried sequence 0. The bridge then, correctly, dropped the pilot's identical restore commands as replays and reported "two senders using sysid 255". That was a test defect, not a bridge fault, and the "pilot lock-out" finding made from those runs is withdrawn. The active-ips results below come from the corrected script, in which each sender keeps its own counter. The advisory column comes from the first runs, which were invalid; it is kept only as unconfirmed.

| Event (unsigned link) | Advisory (reports only) | Active-ips with `--allow-unsigned` (corrected run) |
|---|---|---|
| LAND from unknown sysid 77 | Accepted by the firmware. `COMMAND_INJECTION` CRITICAL for sysid 77 announced | Blocked. Vehicle mode unchanged. Sender 77 quarantined |
| RTL spoofing sysid 255, own counter | Accepted by the firmware | Passed while the vehicle was on the ground, counted as `suspect_provenance`. In flight the provenance rule drops it. This cannot be tested on a disarmed bench vehicle; it is covered by unit tests |
| DO_SET_MODE LOITER from sysid 77 | Accepted by the firmware | Blocked |
| Force-disarm (magic 21196) from sysid 77 | Accepted by the firmware | Blocked |
| Replay of a captured ALT_HOLD | Accepted by the firmware | Blocked (`dropped_replay_unsigned` 1) |
| Flood from sysid 77 | `MAVLINK_ANOMALY` and `DOS` announced | 443 flood frames dropped (`dropped_dynamic`) |
| Counter-tracking forger on sysid 255 (uses the pilot's next sequence number) | Not in the session record | Passed in two runs. "Two senders using sysid 255" announced about 1 s later. The pilot recovered normally |

* Pilot recovery commands always passed in active-ips.
* In advisory, other events were not announced separately. Alert back-off may have suppressed repeats; this is not verified.
* The advisory column comes from the invalid first runs. Treat it as unconfirmed until it is re-run with the corrected script.
* After each run the Pixhawk was put back to STABILIZE, disarmed.

**Limits, stated plainly.** Only the rows above were run. The counter-tracking forger passing is the documented limit of an unsigned link. The on-ground RTL pass is a bench limit: the in-flight rule was not exercised. Signing was run once over USB with the bridge as the enforcement point (see the signing section); nothing here shows flight-controller-side signing.

### Legitimate-traffic suite through active-ips over the radio (`px_legit.py`)

13 of 14 steps passed: heartbeat; 1 Hz stream request (answered); parameter reads; parameter write, readback and restore on a scratch parameter (`SCR_USER1`, 0 to 1 to 0); AUTOPILOT_VERSION request; pilot mode changes to ALT_HOLD and back to STABILIZE; RC override neutral, then released; mission download (count 5); final state disarmed.

Bridge counters for the suite: 0 dropped in each direction, 3,836 frames forwarded down and 73 up, no policy drops.

The 14th step, a full parameter download of 1,098 parameters in one pass, did not complete: about 856 of 1,098 arrived in 60 s. About a quarter of the frames were lost in the radio; the bridge dropped nothing. With per-index re-requests, as a real ground station does, the download completed: 1,099 received for 1,098 parameters in about 165 s. The session record does not explain the extra one.

### Management channel over the radio (`scripts/radio_test/mgmt_radio.py`)

Bridge in passive with a management key. All cases passed:

* signed status, ADVISORY and ACTIVE_IPS commands accepted;
* replayed, unsigned and wrong-key frames got no ACK;
* lowering without the two-step stayed in progress; the two-step lowering was accepted;
* ACK signatures verified 9 of 9;
* management traffic 81.8 B/s against the 150 B/s budget;
* pilot telemetry ratio 1.009, so the management traffic did not reduce it.

The flight controller was the real Pixhawk 6X on the Pi 5, over the radio. The flood-window bytes, alert latency, status age and ACK latency for this run are not recorded.

### Firmware tamper over the radio on the real Pixhawk (`--firmware-dir`, recheck 5 s, advisory)

The check re-hashes the `*.bin` files in the bridge's firmware directory. The tamper happened at about t+25 s. The alert evidence contained "SHA-256 mismatch" about 6 s later. But the headline alert type stayed `DOS` for about 28 s, because the real-GPS alert storm outranked it. `FIRMWARE_INTEGRITY` (SUSPICIOUS) then appeared as its own alert at about t+59 s and repeated every 4 s.

**Finding.** The integrity signal was in the evidence about 6 s after the tamper, but it was not the headline for about 28 s, and its own alert came about 34 s after the tamper. This is open. It is not a plan check as written.

### GPS on the bench: known open issue (not fixed)

On the stationary bench, `GPS_SPOOFING` alerts (SUSPICIOUS, HIGH and CRITICAL) appeared repeatedly, about 11 in 85 s in one run, and "GPS unreliable" came within 5 s of the streams starting. No attack was running. The user decided to skip fixing this for now. The 1,500 s active-ips soak showed the cost: the bridge acted on these alerts (see the soak result).

Measured capture (200 s, 4 Hz, no attacks, `px_gpslog.py`):

* raw GPS position wanders by about ±20 m (standard deviation 8 to 10 m; north range -10 to +22 m, east range -22 to +27 m);
* EKF velocity is about 0 m/s, but the GPS-reported speed averages about 1 m/s;
* 5 to 7 satellites;
* EKF flags show constant-position mode (no horizontal position solution) while disarmed.

Replay through the repo's `FeatureExtractor` and `PhysicsDetector` (`gps_replay.py`):

| Stream set | 1 Hz | 4 Hz |
|---|---|---|
| `EKF_STATUS_REPORT` present (a normal ground station requests it) | 0 false evidence ticks | 8 of 802 (1 %), from the raw-versus-EKF velocity rule |
| `EKF_STATUS_REPORT` absent (the test streams 2, 6 and 10 only) | 24 % of ticks | 0.5 % of ticks |

Cause: the residual window is counted in fixes (15). At 1 Hz it spans 15 s, so a wandering receiver looks like drift. The estimator gate only works once `EKF_STATUS_REPORT` is received. These are the receiver's own errors on a bench, not a spoofing attack.

Candidate fixes, none done: a time-bounded residual window; treating missing estimator context as lower confidence; a per-receiver noise floor.

### Pi 5 soak, 1,500 s (25 min), active-ips: result

The bridge ran in active-ips with a benign 1 Hz ground station, with the real Pixhawk on the Pi 5 and the radio pair. The Pixhawk streamed at about 4 Hz because stream rates had persisted from an earlier capture (`docs/REAL_PIXHAWK_TEST.md`, lesson 3). The vehicle was disarmed throughout and never armed.

| Measure | Result |
|---|---|
| Duration | 1,500 s (25 min) |
| Frames reaching the ground | 79,135 |
| Heartbeat gaps over 3 s | none |
| Bridge forwarded, down / up | 81,368 / 1,503 |
| Bridge dropped, down / up | 0 / 0 |
| Send failures / errors | 0 / 0 |
| Handling time p50 / p95 / max | 15.6 us / 58.5 us / 5.0 ms |
| Bridge process CPU, max (Pi 5) | 5.1 % |
| Bridge RSS (Pi 5) | max about 68 MB, flat |
| SoC temperature, max | 49.9 C |
| Throttle flags | 0x0 in all 51 samples |
| Alerts raised by the bridge | 207 (including GPS_SPOOFING, DOS, TELEMETRY_MANIPULATION and sanitize_gps actions) |
| Counter-commands sent to the vehicle | 457 |
| Bridge state at the end | SAFE_HOLD |
| Vehicle mode | ALT_HOLD (mode 2) at the start and for the whole run |

**What this shows, conservatively.** Forwarding and handling were clean: no drop, no send failure, no heartbeat gap over 3 s, flat memory and no throttling. Hook errors are not in the session record.

**What it also shows.** The bridge's autonomous GPS response, triggered by the unfixed false GPS alarms (section "GPS on the bench" above), sent 457 counter-commands. The Pixhawk stayed in ALT_HOLD for the run. The vehicle was disarmed, so nothing flew. The record attributes the mode change to the bridge's GPS response. The vehicle was already in ALT_HOLD at the start, so the time of the first change is not recorded. The mode was restored to STABILIZE by hand afterwards. The counter-frames were caused by alerts, but the alerts were false, so the phase 3 expectation of no actuation from false alerts is not met in this run.

**Limits, stated plainly.** One run of 25 minutes, against the 30 to 60 minutes that phase 9 asks for. Hook errors are not in the record. The figures are the bridge's own counters as given in the session summary; the raw files were not reviewed. The soak did not test a pilot override or a real GPS fault.

### Signing on the real Pixhawk: one run over USB, bridge as the enforcement point

Run on 2026-10-31. **Enforcement at the flight controller was not tested.** Over USB, the bridge is the only point where a signed-link decision can be observed. The table below records what the bridge did, judged by the vehicle as a witness.

1. **Key sent over USB (a).** A `SETUP_SIGNING` key was sent to the Pixhawk over USB. Unsigned requests on the USB link stayed answered afterwards. This fits ArduPilot exempting the USB link from signing, but that is an inference. Enforcement was not observed or tested at the flight controller, and whether the key was stored cannot be read back.
2. **Signing switched off (b).** The zero key was sent twice to switch signing off. Afterwards unsigned and signed requests were both answered, and the snapshot diff was empty. The test key was deleted from the Pi. A copy stays on the laptop, outside the repo.
3. **Tool defect, found and fixed (c).** With a key set, pymavlink silently dropped the vehicle's unsigned replies. The first "signed read: no answer" was therefore an artifact, not a rejection. `px_signing.py` now accepts unsigned replies.
4. **Enforcement at the bridge (d).** `px_signed_attack.py`, with the bridge in active-ips, `--signing-key-file` set and `--allow-unsigned` not given. The key was held by the pilot only. The Pixhawk was the witness: a forged command that changed its mode had got past the bridge.

| Event | Vehicle mode changed? | Bridge counter |
|---|---|---|
| Legitimately signed set-mode ALT_HOLD (must pass) | yes, passed | `signed_ok` 9 for the whole run |
| Unsigned forged LAND, sysid 77 | no | `dropped_unsigned` |
| Unsigned RTL spoofing sysid 255 | no | `dropped_unsigned` |
| Wrong-key signed LAND spoofing sysid 255 | no | `dropped_bad_signature` 1 |
| Unsigned forged LOITER, sysid 77 | no | `dropped_unsigned` |
| Replay of the captured signed ALT_HOLD | no | `dropped_replay` 1 |
| Unsigned force-disarm, sysid 77 | no | `dropped_unsigned` |
| Unsigned heartbeat flood, sysid 77, 5 s | no | `dropped_dynamic` (449 for the run, after quarantine of sysid 77) |

Whole run: `dropped_unsigned` 4, `dropped_bad_signature` 1, `dropped_replay` 1, `dropped_dynamic` 449. 134 alerts, 0 errors. Every blocked event was announced at the ground: `AEGIS: blocked` texts for LAND, RETURN_TO_LAUNCH, DO_SET_MODE and ARM_DISARM, and 61 texts for HEARTBEAT.

For contrast, on the unsigned link (active-ips with `--allow-unsigned`), the unsigned RTL spoofing sysid 255 passed while the vehicle was on the ground. On the signed link it was dropped.

**Limits, stated plainly.** One run and one key. The wrong-key and replay cases are one frame each. No signed-timestamp skew test was run. The flight controller's own signature checking was not exercised, and the USB-exemption statement is an inference. Signing enforcement at the flight controller needs a UART or telemetry port wired to the Pi, which was not done. So this result does not show that the vehicle would refuse a forged frame that got past the bridge.

### Snapshot and restore on the real Pixhawk: restore shown for listed parameters only

**There was no snapshot before the tests started.** The baseline was taken on 2026-10-31 at 02:36, after most of the tests in this section. It therefore does not show the vehicle's state from before those tests. Every change made earlier is listed below, as far as the record shows.

Baseline: ArduCopter 4.7.1 (firmware version word 67503103), 1,098 listed parameters, a 5-item mission, STABILIZE. A copy is kept on the laptop, outside the repo.

| Check | Result |
|---|---|
| Dry-run comparison with the baseline | 0 parameters changed |
| Restore of a listed parameter (`NTF_BUZZ_VOLUME`, 100 to 50, then restored) | the dry run showed the change; `--apply` restored it; the tool printed RESTORED; a direct read gave 100 |
| Hidden parameters `SCR_USER1..6` (they answer by name but are not in the 1,098 list) | not covered by the snapshot or by the restore |
| First attempt to prove restore with hidden parameters | `SCR_USER2` was set to 7 and `SCR_USER3` to 3; the tool printed RESTORED anyway; both were put back to 0 by hand and read back |

Changes to the vehicle, from the record:

* `SCR_USER1` written from 0 to 1 and back to 0 by `px_legit.py`, which restored it.
* `SCR_USER2` and `SCR_USER3` changed by the first restore attempt, then put back to 0 by hand.
* Flight-mode changes, each put back to STABILIZE.
* The bridge's ALT_HOLD counter-command during the soak. The mode was restored by hand.
* A signing key written and then zeroed (signing off). The snapshot diff was empty afterwards.
* No other parameter or mission change is recorded.

**Judgement.** Restore is shown for one listed parameter, read back directly. Reversibility of the whole vehicle state is **not proven**. The restore tool's RESTORED message checks only the listed parameters, so it is not evidence for hidden ones. With no pre-test baseline, the record cannot show that the vehicle was returned to its original state.

### Randomised attack campaign on the real Pixhawk: batch 1 of 6 (`px1_passive_unsigned`, 2026-11-02)

**This is batch 1 of 6. More results are coming. It is not a campaign result, and it does not change the judgement above.** One run cannot support a campaign-level conclusion. Batches 2 and 3 are recorded in the subsections after this one. Batches 4 to 6 are not recorded in this document yet.

Measured on 2026-11-02 on the bench. The figures were checked against the run's output files, listed below, which were read for this pass.

**Setup and command.**

* Real Pixhawk 6X running ArduCopter 4.7.1, disarmed, propellers removed, STABILIZE at the start. USB to the Pi 5. The bridge reads the Pixhawk through `px_fc_proxy.py`, which rewrites real telemetry on its way to the bridge (altitude, battery, attitude and heading). The bridge-to-Pixhawk direction is not changed. LR900 radio pair to the laptop.
* Posture `passive`, link `unsigned`, seed 11. The bridge ran with the firmware directory and manifest (recheck every 5 s).
* No GPS fix during this run: fix type 1, 0 satellites. This is a bench condition, not a detector result. The earlier sessions had 5 to 7 satellites.
* Command, run on the laptop with the radio hub running:

```
PI_KEY=<ssh-key-path> PI_HOST=<pi-user>@<pi-ip> COM=COM3 \
  bash scripts/ardupilot/real_pixhawk/run_px_campaign.sh px1_passive_unsigned passive unsigned 11
```

* The driver never arms and sends no takeoff or motor command. It stops if the vehicle reports armed. The run completed with the vehicle disarmed (`RESULT: final mode STABILIZE armed False`).
* Output files, outside the repo: `C:/afsitl/px_campaign_px1_passive_unsigned.json` (driver record: schedule, mode before and after each event, mode log, ground announcement texts); `C:/afsitl/px_events_px1_passive_unsigned.txt` (the bridge's event log, 88 rows, and the bridge's end-of-run status as its last line); `C:/afsitl/run_px1.log` (console log). On the Pi: `~/aegis_runs/px_px1_passive_unsigned/` (`bridge.sqlite`, `bridge.log`, `proxy.log`).

**Schedule.** Ten event slots, shuffled by the seed. The planned schedule (the `schedule` list in the driver record, identical in all three batches) puts two slots 4 to 8 s after the one before them and the others 25 to 35 s after: forged_rtl_spoof255 41.3 s, alt_bias 45.6, forged_land 71.5, forged_force_disarm 78.8, flood 104.7, replay 137.8, spoof255_land 169.8, fw_tamper 195.2, freeze 230.0, batt_jump 264.6. Planned times are not when the events fired. The table uses the actual start times, the `t_start` field of each event record: forged_rtl_spoof255 47.7 s, alt_bias 52.9, forged_land 78.0, forged_force_disarm 85.3, flood 111.1, replay 144.4, spoof255_land 176.3, fw_tamper 201.7, freeze 236.5, batt_jump 270.7. In this batch the actual starts ran 6.1 to 7.3 s after the planned ones. The cause is the driver's time base: `t0` is set before `capture_replay()`, which pumps the link for about 6 s, and the schedule is measured from a later point (`tstart`). Batches 2 and 3 show the same offset.

The replay frame was captured at the start of the run. The driver sent a set-mode ALT_HOLD through the pilot's own connection, saved the exact bytes written to the wire, and returned the vehicle to STABILIZE. The replay event sent those bytes again.

**Results by event.** Vehicle mode is from the driver's heartbeat log. Bridge times are seconds after the event's start, from the bridge's event log.

| Event | Start (s) | Vehicle mode, before to after | Bridge event log (s after start) | Notes |
|---|---|---|---|---|
| forged_rtl_spoof255 (unsigned, claims sysid 255) | 47.7 | STABILIZE to RTL | DOS SUSPICIOUS (+1.1); MAVLINK_ANOMALY CRITICAL (+2.7). No COMMAND_INJECTION row | Passive: nothing blocked |
| alt_bias (+40 m altitude) | 52.9 | RTL to RTL (no change) | TELEMETRY_MANIPULATION HIGH (+3.1), then CRITICAL (+7.3) | "GPS/baro altitude mismatch 40.0 m > 8 m" |
| forged_land (sysid 66) | 78.0 | RTL to LAND | COMMAND_INJECTION HIGH (+2.8) | Announced on the ground as COMMAND_INJECTION HIGH sys66 |
| forged_force_disarm (sysid 66) | 85.3 | LAND to LAND | COMMAND_INJECTION HIGH (+2.3) | The vehicle was disarmed throughout, so the effect of the force-disarm cannot be read from this run |
| flood | 111.1 | LAND to LAND | MAVLINK_ANOMALY HIGH (+2.7) | 356 frames written (run log) |
| replay (the ALT_HOLD captured at the start) | 144.4 | LAND to ALT_HOLD | MAVLINK_ANOMALY CRITICAL (+2.6); DOS SUSPICIOUS (+3.6) | Mode changed at 149.0 s |
| spoof255_land (unsigned, claims sysid 255) | 176.3 | ALT_HOLD to LAND | MAVLINK_ANOMALY CRITICAL (+2.9) | Mode changed at 181.0 s |
| fw_tamper (one `*.bin` in the bridge's firmware directory on the Pi, then restored) | 201.7 | LAND to LAND | DOS SUSPICIOUS and CRITICAL only (4 rows). No FIRMWARE_INTEGRITY row | Not announced. Window 15 s |
| freeze (ATTITUDE repeats the first frame it saw) | 236.5 | LAND to LAND | DOS SUSPICIOUS only (2 rows). No attitude-repeat row | Not announced. Window 10 s. The record says the proxy's rewrite counter confirms it ran |
| batt_jump (+3 V) | 270.7 | LAND to LAND | TELEMETRY_MANIPULATION HIGH (+3.3), "battery voltage rose 3.00 V (implausible)" | Announced |

**What this batch shows, stated conservatively.**

* Passive forwards everything, so nothing was blocked. Four events changed the real vehicle's flight mode: the forged RTL, the forged LAND, the replayed ALT_HOLD and the spoofed LAND. In passive posture this is the expected result. It is not a prevention result. The replay changing the mode on the real vehicle is a measurement from a run with the corrected sequence counter. The earlier advisory runs that suggested the same thing were invalid (`docs/REAL_PIXHAWK_TEST.md`, lesson 1).
* Altitude and battery telemetry manipulation were detected on real, rewritten data: alt_bias gave TELEMETRY_MANIPULATION HIGH and then CRITICAL, and batt_jump gave TELEMETRY_MANIPULATION HIGH. The record links these to the cross-message checks and the altitude and barometer rule (`docs/DETECTION.md`). This is the first recorded detection of these two cases on genuine vehicle data passed through the live injection point.
* Timing of those detections. The bridge's event log shows the first TELEMETRY_MANIPULATION row 3.1 s after the alt_bias start and 3.3 s after the batt_jump start. The ground announcement texts show the first one at 4.6 s and 4.9 s. The lead's summary gave 5 to 9 s. Neither source matches that range, and the record does not explain the difference. The figures above are the artifacts' figures.
* Freeze and firmware tamper were not announced, although both were applied. The firmware file was changed and then restored, and the record says it was verified byte-identical afterwards. Their windows (15 s and 10 s, from `px_campaign.py`) contained only DOS rows from the GNSS condition. No FIRMWARE_INTEGRITY row and no attitude-repeat row appear in the 88 rows. The record says the GNSS verdict was the top verdict on every tick of those windows, and that the fusion engine reports one top verdict per decision tick. That is the lead's reading of the record; it was not re-checked in code in this pass. This is a masking effect under a sustained GNSS condition. It is separate from the bench GPS position-wander false alarm. Neither is fixed (user decision on the GPS issue; this finding is not fixed either).
* The forged force-disarm and the flood were announced. The forged RTL was not announced as a command injection.
* A later DOS HIGH row cites "battery collapse 3.00 V/s", 17.3 s after the batt_jump start (`C:/afsitl/px_events_px1_passive_unsigned.txt`, row 80). It was not listed in the first write-up of this batch. It is a second rule reacting to the same injected step.

**Restore and vehicle state.**

* At the end of the run the vehicle was STABILIZE and disarmed (driver record). The four mode changes were: STABILIZE to RTL at 52.4 s, RTL to LAND at 84.8 s, LAND to ALT_HOLD at 149.0 s, and ALT_HOLD to LAND at 181.0 s. The mode log also shows a change to STABILIZE at 311.0 s, the end of the run.
* A dry-run comparison with the 2026-10-31 baseline (`px_restore.py`) showed 0 changed listed parameters and an unchanged mission, according to the lead's record. That check does not cover hidden parameters (section 5.6). No event in this run writes a parameter.

**Limits of batch 1, stated plainly.**

* One run: one posture (passive), one link (unsigned), one seed (11). No statistical claim is made.
* Passive only. Nothing was blocked, so this run says nothing about prevention.
* **Per-event bridge counters are missing from this run.** Every status read the driver made from the laptop failed with "connection refused" (`WinError 10061`): the per-event readings and the final read in the driver record are all errors. The bridge's status server binds 127.0.0.1 by default (`--status-host`, `src/aegisflight/cli/main.py`), and the driver reads the Pi's LAN address. The end-of-run status came from the Pi over SSH and is the last line of the events file. The record cannot show the bridge's counters at each event. This batch has no counter values at all, so none of them should be read as zero. The defect was found after this run and fixed before batch 3 (batch 2 ran with it too; see batch 2 below).
* No GPS fix (0 satellites), so the GNSS verdict in this run is specific to the indoor bench condition.
* The bridge's state was SAFE_HOLD at the end of the run, and "AEGIS: safe_hold" texts recur through a passive run. The record does not explain this, and it was not investigated in this pass. The vehicle's mode changes above all came from the forged commands.
* The bridge's end-of-run status reports 1,633 analyser decisions (lead's record). The event log holds 88 rows, 72 of them DOS SUSPICIOUS. The record does not say how the two counts relate.
* The ground received 45 announcement texts, 13 of them "safe_hold". Announcements are rate-limited by `AlertGate` (`src/aegisflight/hal/mgmt_channel.py`), so the 88 logged rows were not all announced.
* Driver cosmetic defect: the first status line prints `mode None armed False`, before any heartbeat has updated the driver's state. The recorded mode values are correct everywhere else. This does not affect the results. Fixed before batch 3.
* The driver's mode log starts with `ALT_HOLD` at 0.1 s and returns to `STABILIZE` at 3.1 s. This is intentional test setup, not an anomaly. Before any attack event, `capture_replay()` in `px_campaign.py` sends one legitimate ALT_HOLD (its exact bytes are kept for the replay event), waits 3 s, sends STABILIZE to return to the starting mode, and waits 3 s. Batches 2 and 3 show the same entries.

**Judgement.** None is made from this batch. The judgement table above stands.

### Randomised attack campaign on the real Pixhawk: batch 2 of 6 (`px2_advisory_unsigned`, 2026-11-02)

**This is batch 2 of 6. More results are coming (batches 4 to 6). It is not a campaign result, and it does not change the judgement above.** It repeats batch 1's seed and schedule with the advisory posture. It reproduces batch 1's findings. That is consistency, not an independent finding.

Measured on 2026-11-02 on the bench. The figures were checked against the run's output files `C:/afsitl/px_campaign_px2_advisory_unsigned.json` and `C:/afsitl/px_events_px2_advisory_unsigned.txt`, which were read for this pass. The bridge times in the table are the event-log times minus the driver's start time, on the same time base as the event start times.

**Setup and command.**

* The same rig as batch 1: Pixhawk 6X on ArduCopter 4.7.1, disarmed, propellers removed, USB to the Pi 5, telemetry rewritten by `px_fc_proxy.py` on its way to the bridge, LR900 pair to the laptop.
* Posture `advisory`, link `unsigned`, seed 11. Advisory forwards every frame and sends alerts. It does not block and does not send counter-commands.
* No GPS fix during the run (fix type 1, 0 satellites), as in batch 1.
* Command, in the same form as batch 1: `bash scripts/ardupilot/real_pixhawk/run_px_campaign.sh px2_advisory_unsigned advisory unsigned 11`, with the same `PI_KEY`, `PI_HOST` and `COM` settings as batch 1.
* Output files as for batch 1, with this label. The bridge's end-of-run status is the last line of the events file.

**Schedule.** The same ten slots and seed as batch 1. Actual start times in the driver record: forged_rtl_spoof255 47.6 s, alt_bias 52.6, forged_land 80.6, forged_force_disarm 85.5, flood 111.0, replay 144.4, spoof255_land 175.9, fw_tamper 201.8, freeze 236.1, batt_jump 270.7. Batch 1's starts differed by up to 2.6 s (forged_land 78.0 in batch 1). Against the planned schedule, batch 2's starts ran 6.1 to 7.0 s late, except forged_land, which ran 9.1 s late (80.6 s against a planned 71.5 s). The record does not explain that extra delay; the driver is a single loop, and its blocking calls may hold back the next event (not traced).

**Results by event.** Vehicle mode is from the driver's record, with the mode-log time in brackets. Bridge rows are from the bridge's event log, in seconds after the event start.

| Event | Start (s) | Vehicle mode, before to after | Bridge event log (s after start) | Notes |
|---|---|---|---|---|
| forged_rtl_spoof255 (unsigned, claims sysid 255) | 47.6 | STABILIZE to RTL (52.1 s) | MAVLINK_ANOMALY CRITICAL (+2.5). No COMMAND_INJECTION row | Advisory: nothing blocked |
| alt_bias (+40 m altitude) | 52.6 | RTL to RTL | TELEMETRY_MANIPULATION HIGH (+3.3), then CRITICAL (+7.5, +11.5, +15.5) | "GPS/baro altitude mismatch 40.0 m > 8 m" |
| forged_land (sysid 66) | 80.6 | RTL to LAND (84.9 s) | COMMAND_INJECTION HIGH (+2.3) | Announced |
| forged_force_disarm (sysid 66) | 85.5 | LAND to LAND | COMMAND_INJECTION HIGH (+3.0) | The vehicle was disarmed throughout, so the effect of the force-disarm cannot be read from this run |
| flood | 111.0 | LAND to LAND | MAVLINK_ANOMALY HIGH (+2.7, +6.7) | |
| replay (the ALT_HOLD captured at the start) | 144.4 | LAND to ALT_HOLD (149.0 s) | MAVLINK_ANOMALY CRITICAL (+2.5) | Mode changed, as in batch 1 |
| spoof255_land (unsigned, claims sysid 255) | 175.9 | ALT_HOLD to LAND (180.5 s) | MAVLINK_ANOMALY CRITICAL (+2.6) | |
| fw_tamper (one `*.bin` in the bridge's firmware directory, then restored) | 201.8 | LAND to LAND | None. Only DOS rows in the window | Not announced |
| freeze (ATTITUDE repeats the first frame it saw) | 236.1 | LAND to LAND | None. Only DOS rows in the window | Not announced |
| batt_jump (+3 V) | 270.7 | LAND to LAND | TELEMETRY_MANIPULATION HIGH (+3.2), "battery voltage rose 3.00 V (implausible)". A DOS HIGH row cites "battery collapse 3.00 V/s" at +17.2 s | Announced |

**What this batch shows, stated conservatively.**

* The mode changes match batch 1: four changes, at 52.1, 84.9, 149.0 and 180.5 s here, against 52.4, 84.8, 149.0 and 181.0 s in batch 1. Advisory forwards everything, so nothing was blocked. The bridge's end-of-run status shows 624 up-frames seen and forwarded, 0 dropped, 3,652 down-frames forwarded, and `counter_frames_sent` 0.
* The bridge's end-of-run summary reads "[AEGIS ADV] HOLD RECOMMENDED (>30s): Continuous attack vector detected". Advisory only recommends. No counter-command was sent.
* Detection matches batch 1. Altitude and battery steps gave TELEMETRY_MANIPULATION. Forged LAND and force-disarm gave COMMAND_INJECTION HIGH. The RTL spoof, the flood, the replay and the LAND spoof gave MAVLINK_ANOMALY. Freeze and firmware tamper were not announced. Their windows contain only DOS rows, which fits the same masking effect as batch 1. That reading is the lead's; this pass checked the rows, not the fusion code.
* The 89 decision rows are 77 DOS-class (72 DOS SUSPICIOUS, 4 DOS CRITICAL, 1 DOS HIGH) and 12 others. The lead's summary gave 76, which leaves out the DOS HIGH row.
* The ground received 56 announcement texts, 13 of them `safe_hold`.

**Restore and vehicle state.**

* Driver record: final mode STABILIZE, disarmed. The mode log returns to STABILIZE at 310.9 s.
* Lead's record, after the run: 0 listed parameters changed, mission identical, firmware byte-identical. Not re-run in this pass.

**Limits of batch 2, stated plainly.**

* One run, one seed, the same schedule as batch 1. Not an independent sample.
* **No per-event bridge counters.** Every status read the driver made from the laptop was refused (`WinError 10061`), as in batch 1. The defect was found after batch 1 and fixed before batch 3, so batch 2 ran with it. The table has no counter values, and none should be read as zero. The bridge's end-of-run status (over SSH) shows `policy.rewritten` 0. The proxy's alt_bias rewrite count for this run is not in the record, so the two cannot be compared.
* No GPS fix (0 satellites).
* The mode log starts with ALT_HOLD at 0.1 s and returns to STABILIZE at 3.2 s. This is the replay capture at the start of the run (intentional, see batch 1). Batch 1 shows the same at 3.1 s.
* Ground texts arrive about 1.5 to 2 s after the matching bridge rows in this run (for example COMMAND_INJECTION HIGH: text at 84.9 s, bridge row at 82.9 s). The table uses the bridge rows. The record does not explain the gap.

**Judgement.** None is made from this batch. The judgement table above stands.

### Randomised attack campaign on the real Pixhawk: batch 3 of 6 (`px3_active-ips_unsigned`, 2026-11-02)

**This is batch 3 of 6. More results are coming (batches 4 to 6). It is not a campaign result, and it does not change the judgement above.** It is the first batch with per-event bridge counters. Its schedule is the same as batches 1 and 2.

Measured on 2026-11-02 on the bench. The figures were checked against `C:/afsitl/px_campaign_px3_active-ips_unsigned.json` and `C:/afsitl/px_events_px3_active-ips_unsigned.txt`, which were read for this pass.

**Setup and command.**

* The same rig. Posture `active-ips`, link `unsigned`, seed 11. The orchestrator adds `--allow-unsigned` for active-ips on an unsigned link. The bridge refuses active-ips on an unsigned link without that flag (lesson 7).
* No GPS fix (fix type 1, 0 satellites) for the whole run.
* Command: `bash scripts/ardupilot/real_pixhawk/run_px_campaign.sh px3_active-ips_unsigned active-ips unsigned 11`, with the same `PI_KEY`, `PI_HOST` and `COM` settings as batch 1.

**Schedule.** The same ten slots and seed as batches 1 and 2. Actual start times (`t_start`): forged_rtl_spoof255 47.6 s, alt_bias 51.7, forged_land 77.6, forged_force_disarm 85.3, flood 110.9, replay 143.9, spoof255_land 175.8, fw_tamper 201.4, freeze 236.5, batt_jump 270.8. The planned schedule (forged_rtl at 41.3 s) ran 6.0 to 6.5 s earlier than these, the same time-base offset as batch 1 (see batch 1). The table uses the actual starts.

**Results by event: vehicle and bridge.** Vehicle mode is from the driver's record. Bridge rows are in seconds after the event start.

| Event | Start (s) | Vehicle mode, before to after | Bridge event log (s after start) | Bridge response (ground announcements) |
|---|---|---|---|---|
| forged_rtl_spoof255 (unsigned, claims sysid 255, own counter) | 47.6 | STABILIZE to RTL (48.5 s) | MAVLINK_ANOMALY CRITICAL (+0.7) | "blocked RETURN_TO_LAUNCH sys255 x2" at 49.2 s. Three identical copies sent; the counts imply one passed (see limits) |
| alt_bias (+40 m altitude) | 51.7 | RTL to RTL | TELEMETRY_MANIPULATION HIGH (+1.2), then CRITICAL (+5.2, +9.2) | "sanitize_alt" at 53.1, 55.0 and 60.6 s. `policy.rewritten` 0 to 11 in this window |
| forged_land (sysid 66) | 77.6 | RTL to RTL | COMMAND_INJECTION HIGH (+1.7) | "quarantine sys66", "blocked LAND sys66 x3". Mode unchanged |
| forged_force_disarm (sysid 66) | 85.3 | RTL to RTL | COMMAND_INJECTION HIGH (+1.0) | "blocked ARM_DISARM sys66 x3". Mode unchanged |
| flood (sysid 66 heartbeats) | 110.9 | RTL to RTL | MAVLINK_ANOMALY HIGH (+0.6, +4.6) | sys66 heartbeats blocked. 360 frames dropped as dynamic (quarantine) |
| replay (the ALT_HOLD captured at the start) | 143.9 | RTL to RTL | MAVLINK_ANOMALY CRITICAL (+0.8) | "blocked DO_SET_MODE(ALT_HOLD) sys255 x2". Two copies sent, both dropped (one as unsigned replay, one as burst repeat). Mode unchanged |
| spoof255_land (unsigned, claims sysid 255) | 175.8 | RTL to LAND (176.8 s) | MAVLINK_ANOMALY CRITICAL (+1.1) | "blocked LAND sys255 x2" at 177.3 s. Three identical copies sent; the counts imply one passed (see limits) |
| fw_tamper | 201.4 | LAND to LAND | None. Only DOS rows in the window | Not announced |
| freeze | 236.5 | LAND to LAND | None. Only DOS rows in the window | Not announced |
| batt_jump (+3 V) | 270.8 | LAND to LAND | TELEMETRY_MANIPULATION HIGH (+1.1), "battery voltage rose 3.12 V (implausible)". A DOS CRITICAL row cites "battery collapse 3.00 V/s" at +14.9 s | "batt_filter" at 272.2 s |

**Per-event bridge counters (first batch with them).** The driver read the bridge status over SSH. `dropped_up` is the total of frames the bridge dropped from the GCS side, read at the event's start and at its end. The windows overlap (see limits).

| Event | `dropped_up` at start | `dropped_up` at end | Change | Category at end |
|---|---|---|---|---|
| forged_rtl_spoof255 | 0 | 2 | +2 | `dropped_burst` 2 |
| alt_bias | 2 | 2 | 0 | `rewritten` 0 to 11 |
| forged_land | 2 | 8 | +6 | `dropped_untrusted_control` 6 |
| forged_force_disarm | 5 | 8 | +3 | overlaps the forged_land window |
| flood | 8 | 368 | +360 | `dropped_dynamic` 360 |
| replay | 368 | 370 | +2 | `dropped_replay_unsigned` 1, `dropped_burst` 1 more |
| spoof255_land | 370 | 372 | +2 | `dropped_burst` 2 more |
| fw_tamper, freeze, batt_jump | 372 | 372 | 0 | none |

Bridge status at the end of the run (driver's last read, over SSH): 672 up-frames seen, 300 forwarded, 372 dropped (55 %). Down-frames 3,606 seen and forwarded, 0 dropped. `policy.rewritten` 11, `counter_frames_sent` 1, `suspect_provenance` 8, `provenance_known_sources` 2. The category totals are 6 untrusted-control, 5 burst, 360 dynamic and 1 unsigned replay, which add to the 372 dropped.

**What this batch shows, stated conservatively.**

* **Blocked, mode unchanged:** forged LAND, forced disarm, the flood and the replay. The bridge's texts say LAND and ARM_DISARM from sysid 66 were blocked (three copies each). The six untrusted-control drops match those six copies together, and the per-event windows overlap (see limits). sysid 66 was quarantined. The replay was sent twice and both copies were dropped (one unsigned replay, one burst repeat). Batches 1 and 2 (passive and advisory) let the replay change the mode. Here it did not.
* **Partly blocked, mode changed:** the forged RTL and the spoofed LAND, both claiming sysid 255 with the driver's own counter, each sent three identical copies. Each window shows two dropped, so the counts imply that one copy passed and changed the mode (STABILIZE to RTL, RTL to LAND). The record does not show which copy passed, so this is inferred, not observed. The code gives the mechanism. sysid 255 is in the bridge's default trusted sysids (255 and 254), so the static trust rule does not drop it, and on the ground the provenance rule marks a repeated-identity sender as suspect rather than dropping it (the drop applies in flight or when armed). The two repeats are dropped by the burst rule, which drops a byte-identical sensitive command repeated within 0.05 s. So the 'x2' comes from repeat suppression, not from a finding that sysid 255 is hostile. This is the same unsigned-link limit as earlier in this document.
* **Detected, not blockable:** the altitude step gave TELEMETRY_MANIPULATION HIGH and then CRITICAL, and the battery step gave TELEMETRY_MANIPULATION HIGH. Downlink is not blocked by design in any posture, except for sanitizer-style field edits.
* **Sustained GNSS condition:** 77 of the 88 decision rows are DOS-class (72 DOS SUSPICIOUS, 5 DOS CRITICAL; counted again from the events file this pass), all citing "GNSS fix never acquired". Freeze and firmware tamper were not announced, as in batches 1 and 2. The windows contain only DOS rows. The record's reading is the same masking effect.
* **Escalation:** the bridge ended in SAFE_HOLD. Its summary reads "[AEGIS DEF] ESCALATED: LONG-DURATION ATTACK (>30s) -> SAFE HOLD LOITER ENGAGED", and it sent one counter-command. The record attributes this to the sustained GNSS condition (more than 30 s), not to a scripted event. The driver's mode log has no LOITER change, and the record does not explain why. Not investigated, and no cause is proposed here.
* Two event-driven mode changes, against four in batches 1 and 2. Both were the sysid-255 spoofs, each of which had two of its three copies dropped (see the limits below).

**Restore and vehicle state.**

* Driver record: final mode STABILIZE, disarmed. The mode log returns to STABILIZE at 310.7 s. As in batches 1 and 2, the log starts with ALT_HOLD at 0.1 s and returns to STABILIZE at 3.1 s. This is the replay capture at the start of the run, intentional (see batch 1).
* Lead's record, after the run: 0 listed parameters changed, mission identical, firmware byte-identical. Not re-run in this pass.

**Limits of batch 3, stated plainly.**

* One run, one seed, one link (unsigned, with `--allow-unsigned`). Same seed and schedule as batches 1 and 2, so not independent of them.
* **Copy counts and what passed.** The driver code sends three identical copies for the forged LAND, force-disarm, RTL and spoofed LAND events, and two for the replay (`start_event` in `scripts/ardupilot/real_pixhawk/px_campaign.py`). The campaign record does not store the copies per event, nor which copy passed. The bridge's 'x2' texts and the two burst drops in each sysid-255 window match three sent minus one passed. So one copy passed in each case. That is inferred from the counts and the code, not observed.
* **`policy.rewritten` 11 has two possible sources.** The record links it to the proxy's alt_bias rewrite (11 frames). The bridge also logged `sanitize_alt` actions in the same window, so the counter may include bridge-side rewrites. The record does not separate them.
* `dropped_burst` (5 frames in total: 2 in the RTL window, 1 in the replay window, 2 in the spoof255 window) counts a byte-identical sensitive command repeated within `cadence_s` (0.05 s by default). The rule is in `src/aegisflight/mitigation/inline_policy.py` (`_command_rule`). It suppresses repeats; it does not check the sender, and a repeat sent more than 0.05 s after the previous identical one is not dropped by this rule.
* The per-event windows overlap. The forged LAND window runs to 90.1 s and the force-disarm starts at 85.3 s, so 3 frames are counted in both. The per-event changes add to 375, and the bridge's own total is 372. Use the total.
* The lead's summary gives 88 % of 88 decisions as DOS-class. The file gives 77 of 88 (87.5 %). This subsection uses the file's count.
* No GPS fix.
* The ground texts (74 in total, 13 `safe_hold`) agree with the bridge rows to within about 0.1 s for the events checked (for example forged LAND: text at 79.4 s, bridge row at 79.3 s).

**Judgement.** None is made from this batch. The judgement table above stands. The blocked events agree with the phase 5 entry already recorded. The two sysid-255 spoofs each had one copy pass, inferred from the counts (see the limits above). That is the known unsigned-link limit for sysid-255 spoofs on the ground. The escalation under a sustained GNSS condition is a further case of the phase 3 concern. The judgements are not changed.

### Randomised attack campaign on the real Pixhawk: batches 4 to 6 of 6 (signed link, 2026-11-02)

The same seed 11 and the same ten event slots as batches 1 to 3, on the signed link: the bridge runs with `--signing-key-file`, the pilot signs, and the attacker, spoofed and wrong-key senders do not sign or use the wrong key (the spoofed LAND of the unsigned link becomes a wrong-key signed LAND). Labels `px4_passive_signed`, `px5_advisory_signed`, `px6_active-ips_signed`. The vehicle was disarmed with the propellers removed, and active-ips reached it through `px_fc_proxy.py` as a `socket://` link. After each run the Pixhawk matched its baseline snapshot: 0 parameters changed, mission identical, firmware byte-identical. Figures come from the session record (`C:/afsitl` run files and the docs brief), not from a fresh pass over the raw files.

**Environment change.** The Pixhawk's GPS acquired a fix between batch 3 and batch 4. Batches 1 to 3 had 72 to 76 "GNSS fix never acquired" decisions out of 88 to 89; batches 4 to 6 had none. This is a change in the bench's sky view, not a code or posture effect. With the persistent condition gone, only 6 decisions were logged per run (against about 88), the final state was NOMINAL (not SAFE_HOLD as in batches 1 to 3), and `FIRMWARE_INTEGRITY SUSPICIOUS` appeared in 4 of 6 decisions in all three runs: the first time it appeared in this campaign. That fits the batch 1 explanation that the persistent GNSS verdict had hidden it. It is an observation, not an isolated test.

| Run | Posture | Mode changes of the real vehicle | Signing outcome |
|---|---|---|---|
| batch 4 | passive | RTL at about 48 s, LAND at about 79 s, ALT_HOLD from the replay at about 145 s, LAND from the wrong-key frame at about 178 s | `signing_observed`: unsigned 9, bad-signature 3, replay 2; `dropped_*` all 0 (passive reports and drops nothing) |
| batch 5 | advisory | the same sequence within about 1 s | the same counters as batch 4 |
| batch 6 | active-ips | **none** after the legitimate set-up (ALT_HOLD at 0.1 s, STABILIZE at 3.1 s) | `policy.dropped_unsigned` 9, `dropped_bad_signature` 3, `dropped_replay` 2, `dropped_dynamic` 354, `signed_ok` 3; `signing_observed` all 0 |

* Batch 6 dropped 368 of 670 uplink frames (55%). Every forged, spoofed, replayed and wrong-key command was dropped, including all 3 copies of the sysid-255 RTL that one copy of reached the vehicle in batch 3. On the signed link an unknown or wrong signature is rejected by verification before the provenance logic; on the unsigned link detection rests on sender identity and burst state.
* Batches 4 and 5 are the same result: advisory forwards everything like passive and only adds explicit GCS alert text. The ground texts named the signing verdict.
* Batch 6 sent 17 counter-frames (1 for the flood, 16 during the firmware-tamper event) and a new ground alert kind "prearm_lock" 3 times. Neither is explained.
* The attitude-freeze event was never detected in any of the six runs. With the masking explanation gone in batches 4 to 6, the likelier cause is duration and rate: `attitude_repeat_n` is 8 in `configs/ardupilot_copter/detector.yaml`, so 8 consecutive identical frames at the requested 1 Hz need about 8 of the freeze's 10 s. Open question for a longer freeze.

**Open finding of batch 6, since explained.** The altitude bias, battery jump and attitude freeze were injected (the proxy log shows 34 altered frames; the altitude shifted by +40 m) and raised **no** `TELEMETRY_MANIPULATION` alert and no bridge-side rewrite record, where the same forgery in batch 3 (unsigned) was detected. A focused probe (`px_altbias_probe.py`, one variable changed, GPS held constant) reproduced it: unsigned detected the +40 m bias in 0.2 s, signed detected nothing. Cause: with a key set, the analyser's frame parser dropped every unsigned `GLOBAL_POSITION_INT`, `SYS_STATUS` and `ATTITUDE` from the vehicle (PX4's unsigned-id list does not contain them), so only the heartbeat reached the detectors. Fixed in the parser and the bridge by letting unsigned frames from the vehicle's own sysid through; a frame that claims a signature is still verified and unsigned frames from other sysids are still dropped. The fix is unit-tested and has not been re-run on the bench. Details: `docs/REAL_PIXHAWK_TEST.md`, section 11.

**Campaign summary.** Passive and advisory block nothing on either link type. Signed active-ips blocked every forged uplink command (0 of 10 events changed the mode); unsigned active-ips blocked most but let 1 of 3 repeated sysid-255 copies through. Firmware-tamper and attitude-freeze visibility depended on the GPS state. Limits: one seed, one run per cell, a stationary disarmed vehicle, a proxied link.

### Not run

On the real Pixhawk: radio unplug and replug (phase 8), a hard Pi power cut, the ground-radio unplug, the range test, the trusted forced disarm, the pilot override during a GPS fault, a GPS fault injected through SITL, signing enforcement at the flight controller (needs a UART or telemetry port wired to the Pi), stale and future signing timestamps, the signing gate exit code, more than one key or more than one wrong-key or replay frame, and a restore check that covers hidden parameters. The GPS fix above is not done. The randomised campaign's batches 4 to 6 are not recorded in this document yet.

### Findings

| Finding | Where it came from | Status |
|---|---|---|
| The attack script never advanced the MAVLink sequence counter, so every frame had sequence 0 and the bridge correctly read them as replays and "two senders" | First runs of the attack sequence | Test defect, fixed in the script. The bridge was not at fault. The "pilot lock-out" finding is withdrawn |
| A full parameter download over the radio loses about a quarter of the frames | `px_legit.py` step 14 | Re-request missing indexes (as `px_params.py` does) |
| A counter-tracking forger on sysid 255 passes on an unsigned link | Attack sequence, active-ips | Known limit. On the signed link (one run) the forged frames were blocked |
| A forged RTL with its own counter passes while the vehicle is on the ground | Attack sequence, unsigned link | Provenance rule only applies in flight. Cannot be tested on a disarmed bench vehicle; unit tests cover it. Blocked on the signed link (one run) |
| The firmware-integrity alert was hidden behind the GPS-storm `DOS` headline for about 28 s | Firmware tamper over the radio | Open |
| `GPS_SPOOFING` false alerts on a stationary bench | GPS capture and replay | Known open issue. Not fixed (user decision). In the 1,500 s soak it moved the vehicle's mode |
| The Pi 3B+ dropped off the network when the Pixhawk's USB port was opened (3 of 3) | Pi 3B+ attempts | Moved to a Pi 5, which did not drop off. The Pi 3B+ cause is not established |
| The LR900 ground unit emits about 50 B/s of `0x00` idle fill | 15 s capture with the bridge stopped: 757 zero bytes | Harmless to MAVLink parsers, which skip zeros |
| Hidden scripting parameters `SCR_USER1..6` are not in the parameter list, so the snapshot and restore do not cover them | Snapshot and restore on the Pixhawk | Open. The restore tool's RESTORED message covers listed parameters only |
| No snapshot existed before the test series | Snapshot timing | Open. The baseline is from 02:36 on 2026-10-31, after most tests |
| The bridge in active-ips sent 457 counter-commands on false GPS alerts and held a disarmed vehicle in ALT_HOLD (1,500 s soak) | Pi 5 soak | Open. A concrete cost of active-ips on this bench |
| pymavlink drops unsigned replies when a key is set, so a read with no answer can be an artifact | Signing checks | Fixed in `px_signing.py` |
| A signing key sent over USB showed no observable effect at the flight controller | Signing over USB | Open. Flight-controller-side enforcement needs a UART or telemetry port wired to the Pi |
| A persistent `DOS` alert ("GNSS fix never acquired") was the top verdict on every tick of the freeze and firmware-tamper windows, so neither event reached the event log | Campaign batch 1 (`px1_passive_unsigned`), passive; the same in batches 2 and 3 (see their subsections) | Open. Not fixed. Separate from the GPS position-wander false alarm |
| The laptop's status reads from the Pi were refused for every event, so the run record has no per-event bridge counters | Campaign batches 1 and 2 driver output | Fixed before batch 3: the driver reads the Pi's status over SSH (the bridge still binds loopback). Batches 1 and 2 have no counters; batch 3 has them |
| In active-ips the bridge announced `blocked RETURN_TO_LAUNCH sys255 x2` and `blocked LAND sys255 x2` for the two sysid-255 spoofs, and the vehicle changed mode in both cases | Campaign batch 3 (`px3_active-ips_unsigned`), unsigned | Explained by the copy count and the burst rule: three identical copies per event, two dropped as repeats, so one passed (inferred from the counts, not observed; which copy passed is not recorded) |
| The bridge ended in SAFE_HOLD with the summary `ESCALATED: LONG-DURATION ATTACK (>30s) -> SAFE HOLD LOITER ENGAGED` and one counter-command, under a sustained GNSS condition. The driver's mode log has no LOITER change | Campaign batch 3 | Open. Not investigated. Actuation on a non-attack condition, relevant to the phase 3 rule |
| The per-event drop windows overlap (forged LAND and force-disarm share about 5 s), so the per-event changes add to 375 while the bridge total is 372 | Campaign batch 3 driver record | Open. Driver measurement note. Use the bridge's total |
| `dropped_burst` (5 frames in batch 3) counts a byte-identical repeat within 0.05 s | Campaign batch 3 counters, checked in `inline_policy.py` | Explained. Repeat suppression only; it does not check the sender |
| The driver's mode log shows ALT_HOLD at 0.1 s and STABILIZE at about 3 s at the start of every batch | Campaign batches 1, 2 and 3 | Explained: the replay capture (`capture_replay()`), intentional test setup |
| The planned schedule runs 6 to 7 s before the actual event starts (batch 2 forged_land 9.1 s) | Campaign batches 1 to 3, driver record | Explained for the offset: `t0` is set before the replay capture (about 6 s). Use `t_start`. The extra delay on batch 2 forged_land is not traced |

### Judgement against the plan (conservative)

The judgement is made against the plan's written criteria in `RADIO_TEST.md`, not against any label in the session record.

| Phase | Real Pixhawk on the Pi 5 | Judgement |
|---|---|---|
| 0 preflight | Not run with the Pixhawk | Not run |
| 1 baseline | Not run with the Pixhawk. The earlier judgement stands | No change |
| 2 passive forwarding | Passive 60 s with the Pixhawk (0 drops), and 45 s of ground traffic through the radio. No 10-minute run, no latency comparison with phase 1 | **NOT PASS as written (partly met)** |
| 3 pilot operation | Benign advisory and active-ips traffic, 0 legitimate drops, 13 of 14 suite steps. No arm, takeoff or flight. Fewer than 30 probes per posture. The 1,500 s active-ips soak sent 457 counter-commands from false GPS alerts, so no actuation from false alerts is not met | **NOT PASS as written** |
| 4 detection | Forged LAND and the flood announced in advisory (first, invalid runs; unconfirmed); force-disarm, LOITER and replay not announced separately in those first runs. The valid campaign batches 1 to 3 announced force-disarm (COMMAND_INJECTION HIGH) and replay (MAVLINK_ANOMALY CRITICAL). Per-attack latency not recorded in the summary | **NOT PASS as written** |
| 5 prevention | Active-ips on the unsigned link (`--allow-unsigned`) blocked forged LAND, force-disarm, LOITER, flood and replay with the mode unchanged, and pilot commands passed. A forged RTL with its own counter passed on the ground. A counter-tracking forger passed (known limit). In the signed run (one key, over USB), 0 of 7 forged or replayed events reached the vehicle; that run is judged under phase 6. GPS ladder, trusted forced disarm and pilot override not run on the real Pixhawk | **NOT PASS as written (partly met)** |
| 6 signing | Signed run over USB, bridge as the enforcement point: a legitimately signed set-mode passed; unsigned (4), wrong-key (1) and replayed (1) frames were dropped at the bridge with the mode unchanged. Not tested: enforcement at the flight controller; stale and future timestamps; the signing gate exit code; the count of acknowledged signed pilot commands (not recorded) | **NOT PASS as written (partly met)** |
| 7 management channel | Posture commands, bad-frame rejection and ACK signatures measured over the radio. Nominal management traffic 81.8 B/s against 150 B/s. Flood-window bytes, alert latency, status age and ACK latency not recorded | **PARTLY** |
| 8 failure and recovery | Not run on the real Pixhawk | **NOT RUN** |
| 9 soak | 1,500 s (25 min) active-ips soak completed: 0 dropped either way, 0 send failures, 0 errors, no heartbeat gap over 3 s, RSS flat, no throttle flags. Not in the record: hook errors. The bridge raised 207 alerts and sent 457 counter-commands from false GPS alerts, changing the vehicle's mode. Duration below the 30 to 60 min the plan asks for | **NOT PASS as written (partly met)** |

### Limits, stated plainly

* Bench only, disarmed, propellers removed. No flight. So there is no in-flight provenance test, no GPS ladder on a flying vehicle, and nothing about vibration or power in flight.
* The flight controller was on USB (CDC), not a UART at TELEM speed. Flight-controller-side signing enforcement was therefore not tested.
* One Pixhawk 6X and one LR900 pair, a few metres apart. The "about 2 KB/s" in the session notes matches the vendor's RATE HIGH setting (2.1 KB/s); it is not a measurement. The measured clean throughput at 115,200 baud is about 1.0 to 1.05 KB/s each way (the link baseline above).
* The figures come from the session record supplied to this documentation pass, not from the raw run files, which were not reviewed.
* The advisory column of the attack table comes from the invalid first runs.
* The soak is 25 minutes, below the 30 to 60 minutes of phase 9.
* The restore proof covers listed parameters only, and there was no pre-test baseline.
* One signed run, one key.
* The campaign is six runs at seed 11 (passive, advisory and active-ips on the unsigned link, then the same on the signed link), one run per cell, so the cell comparisons are single observations, not rates. See their subsections.
* The commit for each run is not recorded.

### Git history notes

These hashes come from `git log`, not from the session record. The earlier sections said they were not given.

* The timestamp fix for signed counter-commands is `e099e04` ("the bridge's signed counter-commands carry timestamps from observed signed traffic, not its wall clock").
* The change that makes the IDS and advisory postures report signing failures is `93d5572`.
* `608e379` ("rate learner gives a late step one more window") appears to be the learner-extension change named earlier. The session record does not confirm this.
