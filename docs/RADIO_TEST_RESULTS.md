# Real-radio test results log

> **No phase has passed on the real radio.** The Bench log below (2026-10-30) holds the first measured bench observations.
> They are not phase results.
> The phase tables below are empty templates. Do not enter an expected, estimated or simulated number. Each row is one measured run
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
Real-radio phases 1 to 9 are **not yet run**.

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

**Next step:** read the radio model from the unit labels. Real-radio phases 1 to 9 are therefore NOT yet run.

## How to fill a row

* **Date**: local date and time of the run (ISO format).
* **Config**: the rig for that run in short form, for example `57600 baud, Pi passive, SITL GUIDED, unsigned` or
  `115200, active-ips, signed, mgmt on`. Include the baud, posture, signing on/off, `--signing-max-age-s`, and anything unusual
  (a different radio placement, a changed SiK air rate).
* **Commit**: `git rev-parse --short HEAD` of the repo that was run on the laptop and on the Pi (the same commit on both; if they
  differed, say so in Notes). Add `+dirty` if there were uncommitted changes.
* **Key numbers**: the figures that decide the phase (the checks' `value` fields), with units.
* **Result**: PASS, FAIL or ABORTED, as written by the tool's `passed` flag, not changed by hand.
* **Notes**: Pi `vcgencmd get_throttled` before and after, Wi-Fi RTT, anything that may bias the figures, link to the run
  directory name. Never paste keys, tokens or passwords.

## Rig record (fill once per campaign)

| Item | Value |
|---|---|
| Campaign date | |
| Commit (laptop / Pi) | |
| Radio serial baud (from phase 0) | |
| SiK settings (serial speed, air speed, net id, TX power, band) | |
| Pi Python / aegis version | |
| Pi `get_throttled` at start | |
| Laptop IP / Pi IP / Wi-Fi RTT | |
| USB latency timer on the Pi (set to 1 ms? file present?) | |
| Run directory | |

## Phase 0: preflight and probe

| Date | Config | Commit | Best baud / frames / B/s | Result | Notes |
|---|---|---|---|---|---|
| | | | | | |

## Phase 1: link baseline without the bridge

| Date | Config (echo / pass) | Commit | Throughput B/s, frame loss %, RTT p50 / p95 ms, largest heartbeat gap s | Result | Notes |
|---|---|---|---|---|---|
| | | | | | |

## Phase 2: bridge passive forwarding

| Date | Config | Commit | Frames down / up, dropped, hook_errors, extra RTT vs phase 1 p95, bridge CPU %, RSS MiB | Result | Notes |
|---|---|---|---|---|---|
| | | | | | |

## Phase 3: normal pilot operation

| Date | Config (advisory / active-ips) | Commit | Commands sent / acked, legitimate dropped, alerts (class, count), ACK latency p50 / p95 ms | Result | Notes |
|---|---|---|---|---|---|
| | | | | | |

## Phase 4: detection

| Date | Config | Commit | Per attack: alerted (y/n), time to STATUSTEXT at the laptop s | Result | Notes |
|---|---|---|---|---|---|
| | | | | | |

## Phase 5: prevention in ACTIVE_IPS

| Date | Config | Commit | Hostile frames sent / dropped / reaching FC, forced disarm passed, GPS ladder: confirm to ALT_HOLD s, override honoured, legitimate dropped | Result | Notes |
|---|---|---|---|---|---|
| | | | | | |

## Phase 6: MAVLink-2 signing

| Date | Config (max-age s) | Commit | Signed ok / acked, dropped_unsigned, dropped_bad_signature, dropped_replay, stale dropped, future frame outcome, gate exit code | Result | Notes |
|---|---|---|---|---|---|
| | | | | | |

## Phase 7: management channel over the radio

| Date | Config | Commit | Alert latency s, status age s, posture ACK latency s, mgmt B/s nominal / flood (peak 1 s), cross-end B/s, bad-frame ACKs (expect 0) | Result | Notes |
|---|---|---|---|---|---|
| | | | | | |

## Phase 8: failure and recovery

| Date | Failure case | Commit | Outage s (last ACK to first ACK after), manual steps needed, replay after restart dropped (y/n), CRC-invalid frames | Result | Notes |
|---|---|---|---|---|---|
| | Pi radio replug | | | | |
| | Laptop radio replug | | | | |
| | Bridge kill and restart | | | | |
| | SITL drop and restart | | | | |
| | Pi reboot | | | | |

## Phase 9: soak

| Date | Config | Commit | Duration min, legitimate dropped, hook_errors, RSS start / end MiB, CPU %, loss first / last 10 min, new throttle bits | Result | Notes |
|---|---|---|---|---|---|
| | | | | | |

## Combined flight session (phases 3-6)

| Date | Config | Commit | Stages run, per-stage result, anything left unreliable by an earlier stage | Result | Notes |
|---|---|---|---|---|---|
| | | | | | |

## Findings and what was not shown

Fill after the runs: bugs found (with the fix commit and regression test), documented limits that were confirmed or contradicted,
and the list of phases not run or failed. Keep claims to what the rows above show.

| Finding | Phase | Evidence (run directory, file) | Status |
|---|---|---|---|
| | | | |

## Pi 3B+ in-the-loop results (2026-10-30, SITL over Ethernet tunnels, no radio hop)

Measured on 2026-10-30. **No radio is in the path, so none of these rows fills a phase table above.** They are software
results of the bridge on the Pi 3B+, for the behaviour the real-radio phases will depend on. Real-radio phases 1 to 9 are
still NOT run.

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

* No real-radio phase has been run. The radios have not carried data both ways (see the bench log above).
* `attacks.py` and `legit_probe.py` are unfinished, per the coordinator. `legit_probe.py` is not in the repository.
