# Real-radio test of the inline IPS bridge

> **Status (2026-10-30):** tooling written. The unit tests `tests/unit/test_radio_*.py` exist but were not re-run in this
> documentation pass. Real-radio phases 1-9: **not yet run**. The radio link is not yet usable: in the first attempt 0
> echoes came back, and in a later transfer one 32-byte pattern arrived intact (Pi to laptop, 115,200 baud) but the other
> direction never arrived. A Pi-in-the-loop run (no radio) on 2026-10-30 exposed a rate-learner false positive in
> ACTIVE_IPS, fixed afterwards. Measured facts and the bench log are in `docs/RADIO_TEST_RESULTS.md`.

This is the test plan, rig description and tool reference for running `aegis ips-bridge` on a Raspberry Pi 3B+ between a
pair of real telemetry radios (SiK-type firmware assumed, not yet confirmed) and an ArduCopter SITL on a laptop. Results are logged separately in
`docs/RADIO_TEST_RESULTS.md`. **At the time of writing no run of this plan has been recorded; nothing in this file is a
measurement.** Numbers in the "pass" lines are acceptance thresholds chosen for this plan, not observed values.

Related: `docs/INLINE_IPS.md` (bridge, postures, signing), `docs/MGMT_CHANNEL.md` (in-band alerts and control),
`docs/MINIMAL_BUILD.md` (target wiring), `docs/PERFORMANCE.md` (Raspberry Pi 3B+ measurements on pseudo-terminals),
`scripts/ardupilot/inline_demo/README.md` (the earlier loopback SITL demo).

## 1. Purpose and scope

Everything the bridge has been shown to do so far was shown on loopback sockets (SITL) or Linux pseudo-terminals
(Pi soak). Neither has baud-rate pacing, radio latency, air-link loss, USB-serial buffering or a second machine's clock.
This test puts a real radio link and a real Pi in the path and repeats the existing checks (forwarding fidelity, normal
pilot operation, detection, prevention, signing, the management channel, failure recovery, soak) over it.

**What a pass would show**

* the bridge forwards, filters and reports correctly over a real 57,600 or 115,200 baud radio link and a USB-serial
  adapter, on the Pi 3B+ it was benchmarked on;
* the added latency and loss of the bridge, measured against a dumb byte relay over the same radios;
* the management channel fits and works over the real byte budget;
* the bridge and its link recover from the replug / restart cases in phase 8 as described there.

**What it does NOT prove**

| Not covered | Why |
|---|---|
| A real flight-controller UART | The FC side is a TCP socket to ArduCopter SITL (`socket://127.0.0.1:5762` on the Pi, carried by an SSH reverse tunnel to the laptop; needs `--allow-url`), not a UART at 921,600 baud on a Pixhawk TELEM port. |
| Real GPS RF (spoofing, jamming, receiver behaviour) | GPS faults are injected through SITL parameters (`SIM_GPS1_GLTCH_X` etc., see `docs/INLINE_IPS.md`), and the SITL EKF reacts to them itself. |
| Range, antenna, interference, link budget | The two radios sit on one bench, probably within a few metres. Air-link loss measured here is bench loss. |
| Flight dynamics, vibration, power behaviour in flight | SITL physics only. |
| Real GCS software behaviour (QGroundControl, Mission Planner) | The "GCS" is a Python pilot (pymavlink) on the laptop. Real GCS programs behave differently on restart, heartbeat and signing. |
| A Pi Zero 2 W or any other computer | Only the Pi 3B+. |
| Hardware bypass or bridge failure safety in flight | There is none in this repo (`docs/MINIMAL_BUILD.md`). Phase 8 measures the outage, it does not remove it. |

ArduCopter SITL on the laptop stands in for the flight controller. The SITL is a faithful ArduCopter code base but the
transport it sits behind is a TCP socket, so the FC link in this rig never loses bytes or adds serial latency. It can stall and add delay instead: the Ethernet cable, and TCP inside the SSH tunnel (section 2).

## 2. Rig

```
 LAPTOP (Windows 10, Wi-Fi 10.36.150.220, Ethernet to Pi)                      RASPBERRY PI 3B+ (Ethernet, ardra.local 169.254.225.172, user ardra)
 +-------------------------------------------------------+                    +-------------------------------------------+
 | ArduCopter SITL                                       |                    |  aegis ips-bridge                         |
 |   SERIAL0  tcp 5760  (holder / signing setup)         |                    |    --gcs-port /dev/serial/by-id/          |
 |   SERIAL1  tcp 5762  <-----------------------------------SSH tunnel ---------+   usb-Silicon_Labs_CP2102_USB_to_UART_  |
 |                                                       |                    |   Bridge_Controller_0001-if00-port0       |
 | radio_hub.py  (owns COM3)                             |                    |    --fc-port socket://127.0.0.1:5762       |
 |   5801 GCS clients (pilot, attacks)                   |                    |    --allow-url                            |
 |   5802 read-only observers (aegis serve, monitors)    |                    |                                           |
 |   5803 stats / control                                |                    +----------------------+--------------------+
 |        |                                              |                                           | USB (CP210x, /dev/ttyUSB*)
 |      COM3 (CP210x 10c4:ea60, driver 11.6.0.420)       |                                           |
 +--------+----------------------------------------------+                              +------------+-----------+
          | USB                                                                         |  radio B (Pi side)       |
 +--------+-----------+            900 MHz air link (bench, a few metres)               +--------------------------+
 |  radio A           |<~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>   (same pair)
 |  (laptop side)     |
 +--------------------+
```

The two radios are the pair. Which physical unit is on which side does not matter. Both radios are 900 MHz (measured 2026-10-30).

**Data path, uplink (pilot to FC):** pilot script -> `radio_hub` (5801) -> COM3 -> radio A ~~air~~ radio B -> Pi serial
port -> `aegis ips-bridge` (policy, tap) -> SSH reverse tunnel over the Ethernet cable to SITL 5762.
**Downlink:** SITL 5762 -> SSH tunnel over the Ethernet cable -> bridge (policy, tap, management frames added) -> Pi serial -> radio B ~~air~~ radio A
-> COM3 -> `radio_hub` -> 5801 / 5802 clients.

The FC link (Pi `127.0.0.1:5762`, the SSH reverse tunnel, then the Ethernet cable to the laptop) stands in for the FC UART. It adds jitter, occasional stalls, SSH encryption and TCP-in-TCP delay that a UART
would not. Record the laptop-to-Pi RTT (`ping ardra.local`, over the cable) in the run notes; if it is high or erratic, that contaminates the latency numbers.

### Known facts about this rig

| Item | Value |
|---|---|
| Laptop Wi-Fi IP | 10.36.150.220 (re-check with `ipconfig` on the day; DHCP can change it) |
| Pi | Raspberry Pi 3B+ Rev 1.3, reached over a direct Ethernet cable at `ardra.local` = 169.254.225.172 (link-local; measured 2026-10-30). The earlier Wi-Fi address 10.36.150.82 is no longer used by this plan. SSH user `ardra`, Debian aarch64, kernel 6.18.50 |
| Pi serial driver | `cp210x` kernel module, loaded (measured 2026-10-30); user `ardra` is in group `dialout` (measured) |
| Radios | Two 900 MHz radios (measured 2026-10-30). USB descriptors are identical generic CP2102 (`10c4:ea60`, serial `0001`, 100 mA), so the model and firmware cannot be read from USB; read them from the unit labels. No AT or `+++` reply from either at 1,200-230,400 baud. Not confirmed to be SiK-type firmware (see `RADIO_TEST_RESULTS.md`, Bench log update) |
| Pi radio device | `/dev/serial/by-id/usb-Silicon_Labs_CP2102_USB_to_UART_Bridge_Controller_0001-if00-port0` (kernel node `/dev/ttyUSB0`, measured 2026-10-30) |
| Laptop radio device | `COM3`, Silicon Labs CP210x driver 11.6.0.420, signed, device status OK (measured 2026-10-30) |
| Radio serial baud | 57,600 or 115,200: **to be confirmed by `com_probe.py` (phase 0)**. Not confirmed. 2026-10-30: no echo at either baud in the first attempt; one 32-byte transfer arrived intact Pi to laptop at 115,200 and garbled at 57,600; 115,200 is a hypothesis only. |
| Bridge software on the Pi | Python 3.13.5 and a venv at `~/aegis_test/venv` with pyserial 3.5 (measured 2026-10-30; other packages in the venv not recorded). `pi_bridge_run.sh` uses `PYTHON=python3` unless set: use `PYTHON=$HOME/aegis_test/venv/bin/python`, and confirm the bridge imports from that venv before phase 0. |

Both radios report identical USB descriptors (measured 2026-10-30: generic CP2102, `10c4:ea60`, serial `0001`), so the by-id path of the Pi radio is only unique while one such
adapter is plugged into the Pi. Do not plug a second CP2102 into the Pi.

### How the topology auto-detect labels this rig

`status()` / `GET /status` carries `topology.kind`. A bridge with an FC-side and a GCS-side transport is reported as
`A+B`. The `connected` flags are taken from the two transports and are `null` if a transport does not report one;
`can_block_frames` needs `active-ips` with both links up, `can_send_counter_commands` needs `active-ips` with the FC link
up (`docs/INLINE_IPS.md`, "Detected topology"). On this rig expect `A+B`. Whether the `socket://` FC transport reports a
`connected` flag was not checked for this plan: record what `GET /status` shows (it is read in phase 2) and treat a `null`
as "transport does not report", not as a fault.

## 3. Prerequisites and one-time setup

Do these once, before phase 0. None of them is done by the test tools.

1. **Software.** Repo checked out on the laptop (branch `work/mgmt-channel-and-perf`), a Python venv with the project
   installed, `pyserial` and `pymavlink`. The same repo (or a copy of `src/` and `scripts/radio_test/`) on the Pi with the
   bridge dependencies only. ArduCopter SITL binary and its profile files as in `scripts/ardupilot/inline_demo/README.md`
   (Windows paths there are hard-coded to `C:/afsitl`). Nothing here downloads a binary for you.
2. **Close every program that may own COM3**: Mission Planner, QGroundControl, MAVProxy, any serial monitor, a previous
   `radio_hub`. Windows allows one owner per COM port; the symptom is "Access is denied" (see section 7).
3. **No firewall change.** This plan does not modify the Windows firewall. The Pi reaches SITL through an SSH reverse
   tunnel that the user starts on the laptop and keeps running for the whole campaign, over the direct Ethernet cable to the Pi (2026-10-30). It uses the same key as item 4 and
   runs no remote command (`-N`):

   ```
   ssh -i $env:ARDRA_KEY -N -R 5762:127.0.0.1:5762 ardra@ardra.local
   ```

   A second tunnel on port 5800 (`ssh -R 5800`) was also used on 2026-10-30; this plan does not define its role.

   With `-R` the Pi's sshd listens on `127.0.0.1:5762` only (default `GatewayPorts no`), so the bridge is given
   `--fc-port socket://127.0.0.1:5762 --allow-url`. SITL must be listening on the laptop's port 5762 first (section 7).
   Check the Pi end with `nc -vz 127.0.0.1 5762`. A dropped tunnel looks like a link failure to the bridge; restart the
   tunnel and then the bridge. Do not open 5760 or 5801-5803 to the network: they stay on the laptop.
4. **SSH access to the Pi** with a key file. Point the tools at it with the environment variable `ARDRA_KEY`
   (`$env:ARDRA_KEY = "<path to your private key>"`). Never write key material, passphrases or passwords in this repo, in
   run directories or in the report. Verify with `ssh -i $env:ARDRA_KEY ardra@ardra.local true`.
5. **USB-serial latency timer on the Pi.** A USB-serial adapter can hold received bytes for a timer period before handing
   them to the host, which adds latency to every frame. Where the driver exposes `/sys/bus/usb-serial/devices/<tty>/latency_timer`
   it should be 1 ms. `pi_bridge_run.sh start` tries to write 1 to it (no sudo) and records the outcome in
   `<run_dir>/latency_timer.txt`; if the node is missing or not writable it prints the one-time fix (as root:
   `echo 1 > <node>`, or a udev rule for `SUBSYSTEM=="usb-serial", DRIVER=="cp210x"`). Whether the in-kernel `cp210x` driver
   on this Pi exposes the file was not checked: record what the script prints, and expect the baseline (phase 1) to include
   whatever the adapter adds. The setting does not survive a replug, and the script re-applies it only at `start`.
6. **Throttling baseline and power.** On the Pi run `vcgencmd get_throttled` before the first run and record it. On
   2026-10-30 it read `0x50005`: under-voltage and throttling were active at that moment (low-nibble bits 0 and 2) and had
   occurred since boot (bits 16 and 18). The kernel log showed repeated `Undervoltage detected`. Until the supply is fixed,
   Pi timing and CPU figures are worst-case and must be labelled so. Use a 5 V, 2.5 A or larger supply and a short, thick
   cable; the radio on the Pi's USB port draws from the same 5 V. Later on 2026-10-30 the Pi read `0x50000` (history only) during the Pi-in-the-loop run. Do not record a timing figure from a run whose
   current-state bits (low nibble) are set.
7. **Clocks.** The Pi has no real-time clock, and on 2026-10-30 it was about 2.5 h behind the laptop with no time sync. Sync both machines (NTP, over the cable or Wi-Fi) before phase 6. Signing timestamps and
   `--signing-max-age-s` depend on the bridge clock being right.
8. **Key files for phases 6 and 7.** Generate throwaway 32-byte keys on the bench (flight key and a separate management
   key), keep them outside the repo, copy the Pi's copies with `scp`, `chmod 600`. Do not reuse any real key.
9. **Output directory.** Choose a run directory outside the repo or one that is git-ignored (default `radio_test_out`).
   Nothing in this test is pushed to GitHub.

## 4. Test plan

One run directory per campaign (see section 6). Each phase writes `<phase>.json` there and exits non-zero on failure
where its tool supports it. Phases are cumulative: do not start phase N+1 while phase N fails without understanding why.
Times are the planned duration of the measurement, excluding setup. All thresholds are proposed; if a tool uses a
different number, the tool's `check()` threshold in the phase JSON is the one that was applied and the report shows it.

Common state for all phases: SITL running, `radio_hub` on COM3, bridge on the Pi unless the phase says otherwise. The
bridge is started on the Pi with `pi_bridge_run.sh` (section 5) or by hand:

```
aegis ips-bridge \
  --gcs-port /dev/serial/by-id/usb-Silicon_Labs_CP2102_USB_to_UART_Bridge_Controller_0001-if00-port0 --gcs-baud 57600 \
  --fc-port socket://127.0.0.1:5762 --allow-url \
  --defense-mode passive --status-port 8765 --allow-unsigned \
  --db ~/radio_test/ips.sqlite --audit-log ~/radio_test/audit.jsonl
```

(`--gcs-baud` is the value phase 0 found. `--fc-baud` is ignored for a socket. `--allow-unsigned` is needed only for
`active-ips` without a flight key: phases 3-5 and 7, not phase 6.)

### Phase 0: preflight and probe

* **Goal:** prove the radio link carries valid MAVLink, find its baud, and prove nothing else owns the port.
* **Steps:** start SITL with a client on SERIAL0 (SITL needs one before it opens SERIAL1, `docs/INLINE_IPS.md`) and make
  sure it streams telemetry to the radio side. With the Pi side running a plain relay in `pass` mode to SITL 5762
  (`pi_relay.py --mode pass --other socket://127.0.0.1:5762`, through the SSH tunnel), run the probe on the laptop. The probe never writes to the port.
* **Tool:** `com_probe.py --port COM3 --bauds 57600,115200,38400,9600 --seconds 6` (and `pi_relay.py` on the Pi).
* **Pass:** port opens; at least 3 CRC-valid MAVLink frames at some baud (default `--min-frames 3`); the best baud is
  recorded in `p0_probe.json` (`best_baud`) and used for every later phase on both sides. Also record `vcgencmd
  get_throttled`, laptop-to-Pi RTT over the cable, and the radio settings read separately (for example with the vendor's
  configuration tool: serial speed, air speed, net id, TX power). Expected time: 5 minutes.
* **Fail means:** exit 2, port busy: another process owns COM3. Exit 1, no frames at any baud: radios not linked, wrong
  net id, Pi side silent, or the SITL is not streaming; see section 7. A pass at a baud other than the one assumed means
  the Pi side must be started with the same baud.

### Phase 1: link baseline without the bridge

* **Goal:** measure what the radio pair alone does (loss, round-trip time, saturation), so the bridge's effect can be isolated later.
* **Steps:** `radio_hub` must NOT be running (both it and `link_baseline.py` open COM3). (a) On the Pi run
  `pi_relay.py --mode echo`; on the laptop run `link_baseline.py`, which sends numbered MAVLink-2 PING frames (26 bytes) at 5, 10,
  20 and 40 frames/s for 15 s each (offered load about 130 to 1,040 B/s) and matches the echoes. (b) Then run
  `pi_relay.py --mode pass --other socket://127.0.0.1:5762` on the Pi and `radio_hub.py` on the laptop with SITL streaming, for 5
  minutes, and compare the hub's downlink frame count with the relay's `frames_from_other` (approximate: the relay counts by
  length byte without a CRC check) and the hub's `downlink.bad_segments`.
* **Tool:** `link_baseline.py` (laptop, step a), `pi_relay.py` (Pi), `radio_hub.py` (laptop, step b).
* **Pass (as coded in `link_baseline.py`):** port opens; the echo path is alive in the 2 s warm-up; loss at the lowest rate (5 fps)
  at most 1 %; a p50 RTT is recorded. Recorded, with no pass limit: RTT p50/p95/p99/max per rate, loss per rate, the saturation point
  (first rate with more than 5 % loss, or a p95 RTT above 3 times that of the lowest rate) and `max_clean_fps`. Step (b) is recorded:
  a link that loses more than a few percent of frames makes every later result unreliable (this threshold is a plan guideline, not
  coded). Also compare the load against the serial ceiling: 57,600 baud 8N1 is about 5.7 kB/s each way. Expected time: 15 minutes.
* **Fail means:** exit 1, loss above 1 % even at 5 fps, or no echo (exit 1, "echo path alive" fails: relay not running, wrong baud). This is a
  radio, power, placement, air-rate or USB problem and not a bridge problem; fix it before going on. Exit 2: port busy.

### Phase 2: bridge, passive forwarding

* **Goal:** the bridge in `passive` forwards both directions byte-identically over the real link, with latency and loss
  compared against phase 1.
* **Steps:** stop the relay, start the bridge in `passive`, run the pilot idle (heartbeat only) and then a normal
  telemetry session for 10 minutes. Read `GET /status` on the Pi (`curl http://127.0.0.1:8765/status` over SSH): frames,
  `latency_us`, `policy`, `topology`, `last_error`. Note whether the management and cross-end frames (sysid 1 / compid
  191) appear on the laptop side (they are added by the bridge in every posture).
* **Tool:** `pi_bridge_run.sh` (Pi), `radio_hub.py` + `legit_probe.py` (laptop), `pi_monitor.py` (Pi health, throttling,
  CPU), `link_baseline.py` for the same loss/RTT measure.
* **Pass:** bridge `dropped` = 0 in both directions and `hook_errors` = 0; frames forwarded down at the laptop match
  frames the bridge reports forwarded within the loss measured in phase 1; extra RTT of the bridge versus phase 1 `pass`
  mode below 50 ms at p95 (proposed; the bridge's own measured forwarding time is hundreds of microseconds on this Pi,
  `docs/PERFORMANCE.md`, so a larger number would point at the tunnel, the cable or USB); `GET /status` readable;
  bridge CPU on the Pi recorded. Expected time: 15 minutes.
* **Fail means:** drops in `passive` are a bug (passive never drops). Extra latency without drops points at the tunnel or the cable
  or the USB-serial timer (section 3, item 5) before it points at the bridge.

### Phase 3: normal pilot operation (ADVISORY and ACTIVE_IPS)

* **Goal:** a legitimate pilot can do ordinary operations through the bridge with no legitimate command dropped and no
  actuation caused by false alerts.
* **Steps:** with the bridge in `advisory`, then `active-ips` (`--allow-unsigned` for this unsigned phase), the pilot
  script as sysid 255 arms, takes off in GUIDED to the profile's altitude, flies a short leg, changes modes
  (GUIDED to LOITER to GUIDED), sends parameter reads, then lands. Repeat each posture at least 3 times. The
  `configs/ardupilot_copter` detector profile must be used (rate-baseline and heading-rule differences are documented in
  `docs/INLINE_IPS.md`).
* **Tool:** `legit_probe.py` for individual command round trips; `flight_session.py` for the flight (this is the first
  part of the combined session note below, which lists what it does not cover).
* **Pass:** every legitimate command is acknowledged (100 % of N, N >= 30 per posture); 0 legitimate frames in the bridge's
  `dropped_*` counters; vehicle ends in the expected modes; counter-frames sent to the FC = 0 unless an alert named in the
  notes caused them. Alert count and classes are recorded, not required to be zero: loopback SITL showed a known heading
  versus course false alarm in GUIDED and rate alarms before the profile was applied (`docs/INLINE_IPS.md`). Command
  ACK latency (median, p95) is recorded for every command type. Expected time: 20 minutes.
* **Fail means:** a dropped legitimate command in `active-ips` is a false positive that would lock a pilot out: record the
  counter that fired (`dropped_untrusted_control`, `dropped_provenance`, `dropped_replay_unsigned`, burst) and stop. A
  failing ACK with 0 drops points at the radio. Downlink drops in `active-ips` are a failure too: on 2026-10-30, before the fix, the Pi-in-the-loop run shed 18 % of downlink telemetry (rate learner; see `RADIO_TEST_RESULTS.md`, Bench log update).

### Phase 4: detection

* **Goal:** each attack is detected and reported to the ground over the radio while the bridge is in `advisory` (so the
  forged frames are expected to reach the FC; the test shows detection, not prevention).
* **Steps:** bridge in `advisory`, aircraft airborne in GUIDED. From a second client on the hub (sysid 66 unless stated),
  send in turn: forged LAND (`DO_SET_MODE` and `SET_MODE`), forged DISARM, forged mode change, forged RTL, a message
  flood, a byte-identical replay of a captured genuine command, and a GPS fault injected in SITL. Wait for recovery
  between attacks. For each, read the `AEGIS:` STATUSTEXT at the GCS side and `GET /status` on the Pi.
* **Tool:** `attacks.py` (the attack catalogue) with `flight_session.py` for the airborne baseline; observers on 5802.
* **Pass:** per attack, the bridge raises an alert and an `AEGIS:` STATUSTEXT arrives at the laptop within 5 s of the first
  forged frame (proposed; `docs/MGMT_CHANNEL.md` records 0.1-0.8 s on loopback); no `AEGIS:` frame reaches the FC (checked
  by the FC-side tap of the tool or by the bridge counters); the replay of an unsigned pilot command is detected or
  explained by `docs/INLINE_IPS.md` (an attack that uses the real GCS sysid on an unsigned link is
  indistinguishable from the pilot, so "not detected" is the documented result there and is recorded as such). Expected
  time: 30 minutes.
* **Fail means:** an alert that is generated at the bridge (visible in `/status`) but absent at the laptop is a radio or
  management-budget problem (phase 7); an attack not alerted at all is a detection gap, recorded as a result, not hidden.

### Phase 5: prevention in ACTIVE_IPS

* **Goal:** `active-ips` drops hostile frames before the FC, never the pilot's, and the GPS ladder acts as documented.
* **Steps:** bridge in `active-ips` (`--allow-unsigned`), aircraft airborne in GUIDED. Repeat the phase 4 attacks. Then
  (a) a trusted forced disarm (magic 21196) from sysid 255, (b) a GPS fault via SITL parameter with the aircraft armed in
  a position-dependent mode, (c) a pilot `DO_SET_MODE` after the GPS warning, (d) a pilot command during an attack.
* **Tool:** `attacks.py`, `flight_session.py`, `legit_probe.py`; FC-side verification from SITL mode, bridge counters
  and the optional counting tap.
* **Pass:** forged LAND/DISARM/mode/RTL: vehicle mode unchanged and 0 hostile frames at the FC (bridge `dropped_up`
  grows by the number sent, minus frames lost by the radio before reaching the bridge); flood: critical traffic still
  flows and the pilot's commands are acknowledged; trusted forced disarm reaches the FC and disarms; GPS ladder: a
  warning `AEGIS: GPS unreliable - do not trust position` reaches the laptop and one `ALT_HOLD` is sent about 3 s after
  confirmation (loopback: 3.0 s, `docs/INLINE_IPS.md`; accept <= 5 s from confirmation here because of radio latency),
  with no AUTO/RTL/LOITER/GUIDED/POSHOLD/LAND sent by the controller; pilot `DO_SET_MODE LOITER` after the warning
  cancels the ladder (no `ALT_HOLD`); 0 legitimate commands dropped. A counter-tracking attacker is expected to get
  through on an unsigned link (documented limit); do not count that as a failure of this phase. Expected time: 45 minutes.
* **Fail means:** a hostile frame reaching the FC, or a pilot command dropped, is a bug or rule gap: save the
  bridge's `/status`, the hub capture and the SITL log and stop. ALT_HOLD late or missing needs the GPS-fault timeline
  (detection time from the alert log).

### Phase 6: MAVLink-2 signing over real latency

* **Goal:** with a flight key, forged, unsigned, wrongly keyed, replayed and stale frames are dropped, legitimately signed
  frames pass, and the `active-ips` signing gate holds, over real radio latency and reordering-free serial.
* **Steps:** provision the key into SITL with `SETUP_SIGNING` over SERIAL0 (`scripts/ardupilot/inline_demo/sign_setup.py`
  does this; restart SITL on the same `eeprom.bin`), copy the key to the Pi, start the bridge with `--signing-key-file`,
  `--signing-state`, optionally `--signing-max-age-s 30`, and without `--allow-unsigned`. Check the gate first: starting
  `active-ips` without a key and without `--allow-unsigned` must exit 2. Then: signed pilot flight; unsigned forged
  command; command signed with a wrong key; byte-identical replay of a captured signed command; a signed command whose
  timestamp is older than `--signing-max-age-s`; a signed command with a timestamp in the future.
* **Tool:** `attacks.py` (signing cases) and `flight_session.py` / `legit_probe.py` (signed pilot).
* **Pass:** signed pilot commands all acknowledged and `signed_ok` grows by that count; unsigned, wrong-key and replayed
  frames dropped (`dropped_unsigned`, `dropped_bad_signature`, `dropped_replay`) with the mode unchanged; stale frames
  dropped when `--signing-max-age-s` is set; start of `active-ips` without a key exits 2 with the documented message.
  Expected time: 30 minutes.
* **Fail means / caution on "future":** `InlinePolicy` rejects frames older than `max_age_s`; at the commit this plan
  was written for, reading `src/aegisflight/mitigation/inline_policy.py` shows **no upper bound on a signed timestamp**,
  so a frame signed with the real key and a timestamp far in the future would be accepted and would ratchet that stream's
  last timestamp forward, after which genuine frames are rejected as replays until the clock catches up. A "future frame
  dropped" check is therefore **not expected to pass** unless a bound has been added since; treat the outcome as a
  finding to record, and do not run this case against a state file you cannot reset. Needs a correct clock on the Pi
  (section 3, item 7): clock error shows up as stale drops of genuine frames.

### Phase 7: management channel over the radio

* **Goal:** the in-band channel works over a real radio inside its byte budget, without hurting flight telemetry.
* **Steps:** bridge with a flight key (or `--allow-unsigned`), a separate management key (`--mgmt-key-file`),
  `--mgmt-state`, `--audit-log`. Ground side: `aegis serve --source serial` on the hub's observer port, or the tool's own
  decoder. Check: (1) alerts arrive as `AEGIS:` STATUSTEXT, (2) the 32-byte status vector arrives about every 2 s with
  fields matching the bridge's `/status`, (3) signed posture commands (passive to advisory to active-ips with
  `allow_unsigned`, and the two-step lowering) are acknowledged, (4) wrong-key, unsigned and replayed command frames get no
  ACK, (5) bytes/s of the management stream, nominal and during an alert flood.
* **Tool:** `mgmt_radio.py`, which splits management and telemetry bytes itself. `radio_hub.py` stats port 5803 gives totals per direction only; it does not split management traffic.
* **Pass:** alert STATUSTEXT seen at the laptop within 5 s; status age at the ground <= 5 s in steady state; posture
  commands ACKed within 2 s of sending (proposed, radio included); bad frames get no ACK; management bytes/s measured at
  the radio side <= 150 B/s averaged over the flood window plus the 300 B initial bucket (the design bound is
  300 + 150 x T bytes in any T seconds, `docs/MGMT_CHANNEL.md`); the cross-end summary is outside this budget (about 35-37 B/s
  unsigned, up to 61 B/s signed) and is reported separately; flight telemetry loss in the flood window no worse than the
  phase 2 loss by more than 1 percentage point. Expected time: 30 minutes.
* **Fail means:** over-budget traffic is a bridge bug. Alerts at the bridge and not at the laptop point at link loss or
  the radio's own buffering. No ACK to a valid command: check clock, management key, rate limit (1 command per second)
  and lockout (5 bad frames in 60 s lock control for 60 s).

### Phase 8: failure and recovery

* **Goal:** measure what happens, and how long the link is out, in the failures an installed bridge will see.
* **Steps (each one measured with the aircraft on the ground or hovering in SITL, pilot heartbeat running):**
  1. unplug and replug the radio on the Pi; 2. unplug and replug the radio on the laptop (restart `radio_hub` if it does not
  re-open COM3 by itself); 3. kill the bridge process (`kill -9`) and restart it, with and without `--signing-state`;
  4. drop SITL (stop and restart ArduCopter) while the bridge runs; 5. reboot the Pi (`sudo reboot`) with the bridge not
  auto-started, then start it by hand. The Pi is **never** shut down by a tool: power-off is the user's own
  `sudo shutdown -h now`.
* **Tool:** manual actions timed by `pi_monitor.py` (logs device presence, process state, throttling) and `legit_probe.py`
  (a steady command/ACK stream, so the gap in acknowledged commands is the outage). `laptop_ctl.py` for the laptop-side
  restarts.
* **Pass:** recorded, not pass/fail on absolute time, except: after each failure the link recovers without a manual step
  other than the ones listed above (replug, restart of the named process), and, after recovery, `legit_probe` commands
  are acknowledged again; after a bridge restart with `--signing-state`, a replay of a pre-restart signed command is still
  dropped; no forwarded frame is corrupted (CRC-invalid count stays 0). Outage durations are written into the results
  log. Expected time: 45 minutes.
* **Fail means:** a replug that never recovers is the "replug not recovering" case in section 7 and the result is recorded
  (a bridge that needs a restart after a USB replug is a real operational limit). A dead bridge forwards nothing: this is the
  no-bypass limit of `docs/MINIMAL_BUILD.md`, not a surprise.

### Phase 9: soak

* **Goal:** the bridge and link run for 30 to 60 minutes with a realistic load without drift in loss, latency, memory or
  Pi health.
* **Steps:** bridge in `active-ips` with a flight key and the management channel on; a flight session in a loop (hover and
  rectangle in GUIDED) with 1 Hz heartbeat and a harmless command every 10 s; `pi_monitor.py` sampling every 5 s.
* **Tool:** `flight_session.py` (or `legit_probe.py`), `pi_monitor.py`, `radio_hub.py` stats; `report.py` afterwards.
* **Pass:** 0 legitimate commands dropped; 0 `hook_errors`; `vcgencmd get_throttled` shows no new under-voltage or throttling
  bit during the run (a pre-existing history bit is noted but is not new); bridge RSS not growing over the run beyond what
  the first 5 minutes explain (record start and end; the Pi soak on pseudo-terminals measured 61-62 MiB); loss and
  command-ACK latency in the last 10 minutes not worse than the first 10 by more than the noise visible in phase 2; bridge
  CPU recorded (previous Pi figure: 25-40 % of one core with pseudo-terminals, `docs/PERFORMANCE.md`). Expected time: 30 to
  60 minutes plus setup.
* **Fail means:** growth in RSS or latency over the run is a leak or queue problem; a throttling bit is a power problem and
  makes the run unusable for the CPU numbers.

### Combined flight session: not available as one run

`flight_session.py` runs only the pilot-side stages (`link_up`, `params`, `mission`, `arm_takeoff`, `modes`, `auto_mission`,
`land`; section 5). It does not inject attacks, does not switch the bridge posture and does not restart the bridge into the
signed configuration. Posture changes over the management channel are made by `mgmt_radio.py` (phase 7). The attack steps
of phases 4 to 6 need `attacks.py`, which is not in the repository yet. So no single flight covers phases 3 to 6 as an
earlier version of this plan described. Run each phase separately and record each one separately.

## 5. Tool reference

All tools live in `scripts/radio_test/` (a package; `results.py` is the shared schema). They import `results` as a top-level
module, so run them from that directory or with it on `PYTHONPATH` (`com_probe.py` does `from results import PhaseResult`).
Phase tools write `<out>/<phase>.json`; exit codes are 0 pass, non-zero fail unless stated. Entries marked **interface as
designed, verify against file** were not yet present in the repository on 2026-10-30. Only `legit_probe.py` is still absent; its entry keeps the marker. `attacks.py` appeared that day and was checked. The other entries were checked against their files on 2026-10-30: arguments, defaults, exit codes and outputs.

### `results.py` (verified against file)

Shared result format. `PhaseResult(phase, out_dir)` creates the directory; `.check(name, passed, value, threshold, note)`
appends a check and returns whether it passed; `.artifact(filename)` lists an extra file; `.metrics` is a free dict; `.save()`
writes `<out_dir>/<phase>.json`. The phase passes only if it has at least one check and all checks passed.

### `com_probe.py` (verified against file)

Listen-only probe: finds the baud at which a port carries valid MAVLink. Never writes to the port. Opens each baud for
`--seconds`, counts CRC-valid v1 and v2 frames (signed v2 included; only message ids known to pymavlink's ardupilotmega
dialect count), writes `p0_probe.json`.

| Argument | Default | Meaning |
|---|---|---|
| `--port` | `COM3` | serial port |
| `--bauds` | `57600,115200,38400,9600` | candidates, tried in order |
| `--seconds` | 6 | listen time per baud |
| `--min-frames` | 3 | frames needed to pass |
| `--out` | `radio_test_out` | run directory |

```
python com_probe.py --port COM3 --bauds 57600,115200 --seconds 8 --out radio_test_out/2026-xx-xx
```

Exit 0: valid MAVLink found. 1: nothing valid at any baud, or a port that is missing or fails to open for a reason other than busy. 2: port busy (another program owns it; the probe stops at the first busy
baud). Output: a table per baud (bytes, B/s, frames, valid-byte percentage, message names, sysids) and the JSON with
`metrics.best_baud` and `metrics.results[]`. Checks: `port opened`, `valid mavlink at some baud`.

### `pi_relay.py` (verified against file)

Runs on the Pi; stdlib and pyserial only. A dumb byte relay used for the baseline with no IDS.

| Argument | Default | Meaning |
|---|---|---|
| `--radio` | `/dev/ttyUSB0` | radio serial device (use the by-id path) |
| `--baud` | 57600 | radio baud |
| `--mode` | required | `echo` writes every received byte back; `pass` copies both ways between the radio and `--other` |
| `--other` | | serial path or `socket://host:port` (required for `pass`) |
| `--other-baud` | same as `--baud` | baud of `--other` if serial |
| `--stats-file` | `relay_stats.json` | counters, rewritten every 5 s and at exit |

```
python3 pi_relay.py --radio /dev/serial/by-id/usb-Silicon_Labs_CP2102_USB_to_UART_Bridge_Controller_0001-if00-port0 \
    --baud 57600 --mode pass --other socket://127.0.0.1:5762 --stats-file relay_stats.json
```

Stats keys: `mode`, `uptime_s`, `bytes_radio_rx`, `bytes_radio_tx`, `bytes_other_rx`, `bytes_other_tx`, `frames_from_radio`,
`frames_from_other`, `radio_bad_bytes`, `other_bad_bytes`, `updated`. Frame counts come from the length byte with no CRC check,
so they are approximate on a noisy link. Exit 0 on SIGINT/SIGTERM, 1 if a port fails mid-run, 2 if a port cannot be opened. `--mode pass` without `--other` is a usage error (exit 2).

### `radio_hub.py` (verified against file)

Laptop-side hub; a drop-in for `scripts/ardupilot/inline_demo/hub.py` whose bridge side is the serial port instead of a TCP
connection. It owns the serial port (so nothing else may), and fans it out:

```
radio (serial) <--> hub --5801--> GCS clients (read/write: pilot script, attacker script)
                        --5802--> observers (read-only copy of the downlink; their bytes are discarded)
                        --5803--> stats (one JSON line per connection, then the hub closes it)
```

It survives the radio being unplugged and replugged (0.5 s retry, TCP clients stay connected; uplink arriving while the port is down
is dropped and counted), never lets a slow TCP client block the serial reader (bounded per-client queue, drop-oldest), writes the
uplink to the serial port in 64-byte chunks with a 10 ms pause (a ceiling a little above 6 kB/s, so the hub does not outrun a
57,600 baud radio by much), captures the raw bytes of each direction with a timestamp per read, and binds to 127.0.0.1 unless
`--host` says otherwise.

| Argument | Default | Meaning |
|---|---|---|
| `--port` | required | ground radio serial port, for example `COM3` |
| `--baud` | 57600 | radio baud (the value phase 0 found) |
| `--capture-dir` | required | directory for `downlink.cap` and `uplink.cap` |
| `--host` | `127.0.0.1` | bind address |
| `--gcs-port` / `--obs-port` / `--stats-port` | 5801 / 5802 / 5803 | listeners |
| `--write-chunk`, `--write-pause` | 64, 0.01 | serial write chunk (bytes) and pause (s) |
| `--client-queue` | 512 | queued chunks per TCP client before drop-oldest |

```
python scripts/radio_test/radio_hub.py --port COM3 --baud 57600 --capture-dir radio_test_out/<run>/hub
```

Stats JSON (port 5803; for example read it with a one-shot TCP client): `uptime_s`, `port`, `baud`, `serial_connected`,
`serial_reconnects`, `last_error`, `downlink` and `uplink` blocks (`bytes`, `frames`, `bad_segments`; uplink also
`dropped_serial_down` and `dropped_queue_full`), `serial_write_queue`, `clients_accepted`, `clients[]` (id, kind, addr, rx/tx bytes,
dropped chunks, queue depth). Frame counts are by header with a CRC-checked split (`split_frames`), not by message type: the
hub does **not** separate the management stream (sysid 1 / compid 191) from flight telemetry. Capture format:
`<f8 time><u4 length><data>` records (`read_capture` in the module reads them back). Ctrl+C stops it. The stats port here is a
one-shot JSON line; it is not the read/write dashboard port of `hub_mgmt.py`. Unit tests: `tests/unit/test_radio_hub.py`.

### `link_baseline.py` (verified against file)

Laptop side of the dumb-link baseline (phase 1a). Needs `pi_relay.py --mode echo` on the Pi. Opens the port itself (so
`radio_hub` must be stopped), sends numbered MAVLink-2 PING frames (26 bytes: sequence and send time in the payload, non-zero
target so zero-truncation never changes the length) at each offered rate and matches the echoes by sequence.

| Argument | Default | Meaning |
|---|---|---|
| `--port` | `COM3` | serial port, or `loop://` for a hardware-free dry run |
| `--baud` | 57600 | |
| `--rates` | `5,10,20,40` | offered load in PING frames/s |
| `--seconds-per-rate` | 15 | |
| `--drain` | 2.0 | seconds to wait for stragglers after each rate |
| `--loss-limit` | 1.0 | max loss % at the lowest rate (the check) |
| `--sat-loss` | 5.0 | loss % that marks saturation |
| `--out` | `radio_test_out` | run directory |

```
python scripts/radio_test/link_baseline.py --port COM3 --baud 57600 --rates 5,10,20,40 --out radio_test_out/<run>
```

Outputs: `p1_baseline.json` (checks `port opened`, `echo path alive`, `loss <= 1% at lowest rate`, `rtt p50 recorded`; metrics
`per_rate` {sent, received, dups, loss_pct, rtt_p50/p95/p99/max_ms, offered/tx/rx B/s, late_sends, stray_bytes}, `saturation_fps`,
`max_clean_fps`, `frame_bytes`) and `p1_baseline_raw.csv` (one row per ping; written only when the echo path is alive). Exit 0 all checks passed, 1 a check failed, 2 port busy
or missing. A 26-byte frame at 40 fps is about 1 kB/s each way, so the default rates probe latency and loss, not the 5.7 kB/s ceiling;
add higher `--rates` (for example 100,200) to look for saturation.

### `attacks.py` (appeared in the repository on 2026-10-30; checked against the file)

Injects one hostile scenario per run through the hub's GCS port (read/write) as an untrusted sysid (default 77), alongside a
continuous trusted-sysid heartbeat and command stream (default sysid 255). It watches the hub's observer port (read-only,
5802 by default) for the vehicle's HEARTBEAT `custom_mode` and armed bit, and for `AEGIS:` STATUSTEXT alerts.

Scenarios: `forged_land`, `forged_disarm`, `forged_mode`, `forged_rtl`, `flood`, `replay`, `unsigned_when_signed`, `wrong_key`,
`signed_replay`, `stale_timestamp`, `future_timestamp`, `gps_glitch` (a `PARAM_SET` of a SITL parameter, default
`SIM_GPS1_GLTCH_X`, from the untrusted sysid). The three timestamp cases (`signed_replay`, `stale_timestamp`,
`future_timestamp`) impersonate the trusted sysid, because a fresh identity always passes the monotonicity check. They model
a holder of the signing key or a GCS with a wrong clock, not a man in the middle. `future_timestamp` is an expected gap: the
verifier has no upper bound on a signed timestamp, so the hostile effect is expected to show even under `--expect active`.

Each run writes `<out>/<scenario>.json` (a `PhaseResult`, named after the scenario, not `p4_`-`p6_`) and
`<out>/<scenario>.manifest.json`: the hostile frames injected per drop-reason class, what `active` should block, and what was
seen. Compare the manifest with the bridge's `policy` counters in `/status`. Bench use only (section 8).

| Argument | Default | Meaning |
|---|---|---|
| `--hub` | `127.0.0.1:5801` | hub GCS host:port |
| `--obs-port` | GCS port + 1 (5802) | hub observer port |
| `--scenario` | required | one of the twelve names above |
| `--out` | `radio_test_out` | run directory |
| `--key-file` | unset | 32-byte or 64-hex signing key, the same key the bridge uses |
| `--wrong-key-file` | unset | a different key, for `wrong_key` |
| `--manifest` | `<out>/<scenario>.manifest.json` | manifest path |
| `--expect` | `active` | `active`: the effect should be blocked. `passive`: the effect should be allowed and alerted |
| `--untrusted-sysid` / `--trusted-sysid` | 77 / 255 | sysids |
| `--iterations` | 5 | repeats of the hostile frame(s) |
| `--settle-s` | 6.0 | seconds to wait for an effect after injection |
| `--gps-param` / `--gps-value` | `SIM_GPS1_GLTCH_X` / 0.001 | `gps_glitch` parameter and value |

Checks: `key files valid`, `hub reachable`, `scenario preconditions met`, `hostile effect did not reach vehicle` (blocked
for `active`, allowed for `passive`), `alert raised` (passive only), and `legit trusted traffic still passed` (a GUIDED
command sent after the attack gets through). Exit 0 when all checks pass; 1 when a check fails; 2 when the hub is unreachable
or a precondition (usually a key file) is not met.

### `legit_probe.py` **(not in the repository on 2026-10-30; interface as designed, unverified)**

Steady legitimate pilot traffic: a 1 Hz heartbeat and a harmless command (for example `DO_SET_MODE(GUIDED)` as sysid 255)
at a fixed interval, recording the acknowledgement and its latency per command. Used in phases 3, 5, 8 and 9 to count
legitimate commands dropped, and to turn the gap in acknowledged commands into an outage time.

### `flight_session.py` (verified against file)

Pilot-side flight as the trusted GCS (sysid 255, component 190) through the hub's GCS port. Stages in canonical order:
`link_up` (HEARTBEAT, stream requests, PARAM_REQUEST_READ round trips), `params` (full parameter list: count and no duplicate
or missing index), `mission` (upload and download a home slot plus 6 waypoints, then compare), `arm_takeoff` (GUIDED, arm,
takeoff, altitude check), `modes` (ALT_HOLD, LOITER, GUIDED, each verified by HEARTBEAT), `auto_mission` (AUTO, the first
`--auto-items` items), `land` (LAND until disarmed).

It writes one `p3_flight.json` with these checks: link up, latency probes answered, params complete, mission round-trip
identical, altitude reached, mode changes verified, auto mission flown, landed (or holding in LOITER), and zero legitimate
commands dropped or NAK/timeout. It also writes `p3_commands.json` (every COMMAND_LONG with its acknowledgement and timing,
and the mode events). It does not attack, change posture or restart the bridge.

| Argument | Default | Meaning |
|---|---|---|
| `--host` / `--port` | `127.0.0.1` / 5801 | hub GCS port |
| `--out` | `artifacts/radio_test` | run directory (pass the campaign's run directory) |
| `--stages` | `all` | comma list of the stage names above; an unknown name exits 2 |
| `--skip-takeoff` | off | drop `arm_takeoff`, `auto_mission` and `land` |
| `--hold-after` | off | skip `land`; leave the vehicle flying in LOITER |
| `--takeoff-alt` | 10.0 | metres |
| `--auto-items` | 3 | mission items flown in AUTO (0 = all) |
| `--retries` | 1 | resends of an unacknowledged command |
| `--mode-via-message` | off | use SET_MODE instead of DO_SET_MODE |
| `--no-streams` | off | do not request data streams or SR1 rates |
| `--arming-check-off` | off | set ARMING_CHECK=0 first (SITL) |
| `--home-lat` / `--home-lon` | 12.9716 / 77.5946 | SITL home position |
| `--ping-count` | 10 | latency probes |
| `--param-timeout` / `--ack-timeout` / `--link-timeout` | 240 / 5 / 30 s | timeouts |

Exit 0 when every check passed; 1 otherwise, including an interrupted session; 2 for a bad `--stages` value.

### `mgmt_radio.py` (verified against file)

Ground side of the management channel for phase 7, through the hub's GCS port (sysid 255). It imports the `aegisflight`
package, so run it in the laptop venv with the repo installed. It writes `p7_mgmt.json` and `p7_mgmt_series.json` (per-window
byte series and the bad-byte count).

It measures two windows of `--seconds` each. The first has no commands: management bytes/s (components 191 and 192) and pilot
telemetry bytes/s. The second has signed posture commands (raise to ADVISORY, raise to ACTIVE_IPS, lowering attempts) and bad
cases (replayed, unsigned and wrong-key frames). Valid commands are paced by `--cmd-gap` because the bridge allows one per second.

Checks it makes: link up; management bytes/s within the budget (150 B/s plus a 300 B burst, the design bound in
`docs/MGMT_CHANNEL.md`); pilot telemetry not reduced by management traffic beyond `--telemetry-tolerance`; each command case
gives the expected ACK or none; management ACK signatures verify; posture ACTIVE_IPS is confirmed by a decoded status report;
a lowering without the two-step does not lower. Cross-end summary bytes are reported, not checked.

Not checked by this tool: alert STATUSTEXT latency (only the last 10 AEGIS texts are kept, in `text_tail`), status age, and
the bridge's `/status` HTTP API. Take those phase-7 numbers from the logs or the bridge status by hand.

| Argument | Default | Meaning |
|---|---|---|
| `--host` / `--port` | `127.0.0.1` / 5801 | hub GCS port |
| `--out` | `artifacts/radio_test` | run directory |
| `--seconds` | 30 | length of each measuring window |
| `--mgmt-key-file` | the repo's test key `bytes(range(1, 33))` | 32 raw bytes or 64 hex. The default key is public (it is in the repo); a bench run must use its own key (section 3, item 8) |
| `--no-commands` | off | passive byte counting only: no commands, no baseline comparison |
| `--no-allow-unsigned` | off | do not set `allow_unsigned` on the ACTIVE_IPS raise |
| `--lower-to` | `none` | `advisory` or `passive`: complete the two-step lowering at the end |
| `--cmd-gap` | 1.4 s | gap between valid commands |
| `--ack-timeout` / `--quiet-wait` | 4 / 3 s | ACK wait; listening time after a frame that must get no ACK |
| `--budget-bps` / `--burst-bytes` | 150 / 300 | management budget |
| `--telemetry-tolerance` | 0.15 | allowed telemetry reduction (fraction) |
| `--link-timeout` | 30 s | wait for HEARTBEAT |

Exit 0 only when there is at least one check and all checks pass; 1 otherwise, including after an interrupt.

### `pi_monitor.py` (verified against file)

Runs on the Pi next to the bridge (stdlib only; `psutil` if installed, `/proc` otherwise). Every `--interval` seconds it appends one
JSON line to `--out`: CPU % of one core, RSS in MiB, SoC temperature, `vcgencmd get_throttled` (raw and decoded flags), load average
and the bridge's own `/status` counters. At SIGTERM/Ctrl-C it writes `<out stem>_summary.json`: peaks and means, throttling seen
now / since boot, counter deltas and counter resets (a bridge restart shows up as a reset), peak latency, and an RSS-growth flag.
It does not write a `PhaseResult` file; `report.py` or the operator uses the summary.

| Argument | Default | Meaning |
|---|---|---|
| `--out` | `pi_monitor.jsonl` | sample file (appended) |
| `--summary` | `<out stem>_summary.json` | |
| `--interval` | 2.0 | seconds between samples |
| `--pid` | auto | bridge pid; default is the oldest process whose command line matches `--pattern` (`aegis.*ips-bridge`) |
| `--pattern` | `aegis.*ips-bridge` | regex matched against the bridge's command line (used when `--pid` is not given) |
| `--status-url` | off | for example `http://127.0.0.1:8765` |
| `--seconds` | until SIGTERM | |
| `--warmup` | 30 | seconds ignored at the start of the RSS slope |
| `--rss-slope-limit` | 1.0 | MiB/min above which growth is flagged |
| `--summarize-only FILE` | | rebuild the summary of an existing sample file |

```
python3 pi_monitor.py --out run/pi_monitor.jsonl --status-url http://127.0.0.1:8765 --interval 5
python3 pi_monitor.py --summarize-only run/pi_monitor.jsonl
```

If the bridge dies the samples keep going with `pid: null`, so the gap is visible in the series (phase 8). The tool exits 0
on a normal stop and with `--summarize-only`. `report.py` reads only the top level of its run directory, so after
`laptop_ctl.py pull-logs` copy the `pi_monitor*_summary.json` files to the run directory itself, or the Pi health section
of the report stays empty.

### `pi_bridge_run.sh` (verified against file)

Starts, stops and inspects `aegis ips-bridge` on the Pi, with the radio as the GCS side and the laptop's SITL as the FC side.
No sudo. Configuration is by environment variable; the command is `start`, `stop`, `kill` or `status`.

```
LAPTOP_IP=127.0.0.1 MODE=advisory BAUD=57600 ./pi_bridge_run.sh start   # the SSH tunnel's Pi end (section 3, item 3)
./pi_bridge_run.sh status
./pi_bridge_run.sh kill      # SIGKILL the bridge only (phase 8); the monitor keeps running and records the loss
./pi_bridge_run.sh stop      # SIGTERM (KeyboardInterrupt in the bridge), SIGKILL after 10 s, then stops the monitor
```

| Variable | Default | Meaning |
|---|---|---|
| `LAPTOP_IP` | required for `start` | host of the FC TCP port as the Pi sees it: `127.0.0.1` through the SSH tunnel |
| `FC_PORT_NUM` | 5762 | SITL TCP port used as the FC link |
| `BAUD` | 57600 | radio baud (`--gcs-baud`) |
| `MODE` | `passive` | `passive`, `advisory` or `active-ips` |
| `GCS_PORT` | the by-id CP2102 path above | radio device |
| `STATUS_PORT` | 8765 | bridge status API on 127.0.0.1 |
| `SIGNING_KEY_FILE`, `MGMT_KEY_FILE` | unset | key files on the Pi (readable); never in the repo |
| `ALLOW_UNSIGNED` | 0 | must be 1 for `active-ips` without `SIGNING_KEY_FILE`, else the script refuses |
| `RUN_ROOT` | `~/aegis_runs` | each `start` makes `$RUN_ROOT/<timestamp>-<mode>/` and links `$RUN_ROOT/current` |
| `REPO` | `~/aegis_test` | repo copy on the Pi (`laptop_ctl.py deploy` puts it there) |
| `PYTHON` | `python3` | interpreter for the bridge and the monitor. Use `$HOME/aegis_test/venv/bin/python` (venv measured 2026-10-30, section 2) |
| `MONITOR` | 1 | also start `pi_monitor.py` against the bridge pid |
| `EXTRA_ARGS` | unset | extra `ips-bridge` flags, word-split |

It always passes `--allow-url --status-port --status-interval 5` and per-run `--signing-state`, `--mgmt-state`, `--audit-log` files in the
run directory (so a new `start` begins with new state files: a restart in phase 8 that must keep the old signing state has to
reuse the old files through `EXTRA_ARGS`; see the note in phase 8). The run directory holds `bridge.log`, `run_info.txt` (arguments,
`vcgencmd get_throttled`, no key contents), `latency_timer.txt`, `pi_monitor.jsonl` and its log. `start` waits 3 s and fails (exit 1,
log tail printed) if the bridge exited; exit 2 for bad usage or a missing radio device or repo. Key paths are recorded as yes/no only. Pid files `bridge.pid` and `monitor.pid` in `RUN_ROOT` are checked against `/proc`
before any signal is sent. `status` and `kill` exit 1 when no bridge is running; `stop` exits 0.

### `laptop_ctl.py` (verified against file)

Laptop-side helper that drives the Pi over `ssh`/`scp` (BatchMode, so it never prompts; key from `ARDRA_KEY` or `--key`;
host and user default to 10.36.150.82 and `ardra`, overridable with `ARDRA_HOST`/`ARDRA_USER` or `--host`/`--user`). 10.36.150.82 is the old Wi-Fi address: for the wired link use `ardra.local` (`--host ardra.local` or `ARDRA_HOST=ardra.local`). It runs
`pi_bridge_run.sh` on the Pi; it does not start or stop `radio_hub` and does not touch the firewall.

| Subcommand | Effect |
|---|---|
| `deploy` | tar of `src/`, `configs/` and `scripts/radio_test/` (no caches, no `.pyc`; `.sh` made executable) streamed over ssh into `~/aegis_test` on the Pi. Nothing else from the repo is copied (so `scripts/ardupilot/` and `scripts/pi_soak.py` are not on the Pi) |
| `start` / `restart` | `pi_bridge_run.sh start` with `--mode`, `--baud`, `--laptop-ip` (or env `LAPTOP_IP`), `--signing-key-file` and `--mgmt-key-file` (paths ON THE PI), `--allow-unsigned`, `--status-port`, `--fc-port-num`. `restart` runs `stop` first |
| `stop` | graceful stop of bridge and monitor |
| `status` | bridge pid, status counters, throttling, temperature |
| `kill-bridge` | SIGKILL the bridge only (phase 8); the monitor keeps recording |
| `pull-logs --out DIR` | `scp -r` of the Pi's `~/aegis_runs/` into `DIR/aegis_runs` |
| `reboot-pi` | prints the `sudo -n reboot` command and exits 2; runs it only with `--yes-reboot`. The user approves; there is no shutdown subcommand |

```
set ARDRA_KEY=C:\keys\ardra_key        (PowerShell: $env:ARDRA_KEY = "C:\keys\ardra_key")
python scripts/radio_test/laptop_ctl.py deploy
python scripts/radio_test/laptop_ctl.py start --mode advisory --baud 57600 --laptop-ip 127.0.0.1
python scripts/radio_test/laptop_ctl.py status
python scripts/radio_test/laptop_ctl.py pull-logs --out radio_test_out/<run>/pi
```

Exit 0 ok, 1 the remote command failed (with a one-line hint for the usual ssh errors), 2 usage or local error (missing key,
missing `--laptop-ip`). `sudo -n reboot` needs passwordless sudo for `ardra` on the Pi, which was not checked; if it is absent the
reboot fails and the user reboots by hand.

### `report.py` (verified against file)

    python scripts/radio_test/report.py RUN_DIR [--out report.md] [--expect p1_baseline,p3_flight] [--docs-section]

Reads the top-level `*.json` files of `RUN_DIR`: every `PhaseResult` (a file with `phase` and `checks`) and every
`pi_monitor*_summary.json`. Unreadable files are listed under "Read problems" and are not fatal. It writes `RUN_DIR/report.md`
(or `--out`) with a verdict (PASS, FAIL or NO DATA), failed checks, a phase table, passed checks with value and threshold, Pi
health facts and warnings from the monitor summaries, and an appendix with each phase's raw metrics and artifacts. The header
has the run directory name and the generation time; it does not record a commit. `--expect` names phases that must be present;
an absent one shows as NOT RUN and fails the verdict. `--docs-section` also writes `RUN_DIR/docs_section.md` and prints it.

Exit 0 only when at least one phase is present, every phase passed and every `--expect` name is present; 1 otherwise; 2 when
`RUN_DIR` is not a directory.

### Unit tests: `tests/unit/test_radio_*.py`

Per-tool tests with fake ports. They do not touch hardware. Run `pytest tests/unit -k radio`.

## 6. Run directory and result schema

One directory per campaign, named by the operator (suggested `radio_test_out/<YYYYMMDD-HHMM>-<commit>`):

```
radio_test_out/<run>/
  p0_probe.json  p1_baseline.json  p3_flight.json  p7_mgmt.json      PhaseResult files the tools write (see the note below)
  report.md                                                                          assembled by report.py
  <artifacts>                                                                        raw logs, captures, pi_monitor series
```

`PhaseResult` JSON (from `scripts/radio_test/results.py`):

```
{ "phase": "p2_passive", "started": <epoch s>, "ended": <epoch s>, "passed": bool,
  "checks": [ {"name": str, "passed": bool, "value": any, "threshold": any, "note": str}, ... ],
  "metrics": { ... free-form per tool ... },
  "artifacts": [ "raw.log", ... ] }
```

`passed` is true only if there is at least one check and every check passed, so an empty phase file reads as a fail.
`value` and `threshold` are whatever the tool passes in (numbers, strings, dicts); non-JSON values are written with `str()`.
Re-running a phase overwrites its JSON: copy the run directory first if you need the earlier result.

`attacks.py` writes `PhaseResult` files named after the scenario (for example `forged_land.json`), not `p4_` to `p6_` names, so map them to phases by hand. No tool yet writes a `PhaseResult` for phases 2, 8 or 9, and `legit_probe.py` is not in the
repository. Phase 2 and phase 9 figures come from the `pi_monitor` summary and the bridge's `/status`. `p3_commands.json`,
`p7_mgmt_series.json` and `p1_baseline_raw.csv` are artifacts, not phase results; `report.py` skips them.

`report.py` (section 5) assembles `report.md` from these files: a verdict line, a phase table, failed checks, passed checks
with value and threshold, Pi health from the monitor summaries, and each phase's raw metrics and artifacts. It does not record
the commit, so add the commit hash and rig configuration by hand. The headline numbers then go by hand into
`docs/RADIO_TEST_RESULTS.md` together with the commit and rig configuration of that run.

## 7. Troubleshooting

| Symptom | Likely cause | What to do |
|---|---|---|
| `com_probe` exit 2, "Access is denied" on COM3 | another program owns the port (Mission Planner, QGC, MAVProxy, a serial monitor, an earlier `radio_hub`) | close it; find it with Task Manager or `Get-Process`; unplug/replug the radio if a process died holding it |
| `com_probe` exit 1, no frames at any baud | radios not linked (net id, one unit off, antenna), Pi side not running or silent, SITL not streaming (SITL needs a client on SERIAL0 and a GCS request before it streams extra) | check the radio LEDs, run `pi_relay --mode echo` and see if bytes return, check SITL, then try other bauds |
| Frames at a baud other than expected | radio serial speed was configured differently | use the baud found for the bridge `--gcs-baud` and for `radio_hub` |
| Garbage (valid% far below 100) at the right baud | marginal link, wrong parity/stop bits, USB-serial buffer overrun, air rate lower than the serial speed | read the radio settings; reduce serial speed; check cable and power |
| Pi bridge cannot reach SITL (`last_error`, connection refused/timeout) | SSH reverse tunnel not running or dropped; SITL not running; SITL not listening on 5762 yet (needs SERIAL0 client first) | on the Pi `nc -vz 127.0.0.1 5762`; restart the `ssh -R` tunnel (section 3, item 3); check SITL on the laptop |
| Link jitter spoils latency numbers | Wi-Fi congestion or power-save (if Wi-Fi is used); SSH tunnel stalls | `ping` both ways during the run and note the path; the Pi is on the Ethernet cable since 2026-10-30 |
| Replug does not recover | the process kept a stale handle on the vanished device, or the device came back with a different `/dev/ttyUSB*` name | use the by-id path (it is stable); restart the process; record it as a result for phase 8 |
| Pi `vcgencmd get_throttled` not `0x0`, or new bits during the run | power supply or cable too weak, USB load | change the supply/cable; a run with new throttling bits is not usable for CPU or latency figures |
| High frame loss at 57,600 baud | serial ceiling about 5.7 kB/s each way: ArduCopter telemetry after stream requests, plus the bridge's cross-end summary (about 61 B/s signed) and management traffic (up to 150 B/s), can fill it; the air rate may also be below the serial rate | lower the SITL stream rates, or use 115,200 on both radios and both ends, and compare with phase 1 |
| Signed commands rejected as replay or stale | clocks differ (the Pi has no RTC); `--signing-state` holds a timestamp ahead of the sender's clock | sync NTP on both; reset the state file on the bench only; see the "future" note in phase 6 |
| Valid management command gets no ACK | no management key, command rate limit (1 per second), 60 s lockout after 5 bad frames, replayed state | check `--mgmt-key-file`, wait 60 s, check the audit log |
| No echo, no AT or `+++` reply, filler bytes on the serial line (seen 2026-10-30, see `RADIO_TEST_RESULTS.md`, Bench log and update) | not confirmed. Measured: no AT reply at 1,200-230,400 baud (N/E/O, 1-2 stop bits); the laptop radio streams filler bytes; one 32-byte transfer intact Pi to laptop at 115,200 only. Hypotheses only: UART baud 115,200; one UART direction dead on a unit; units not standard SiK firmware | not yet tested. Read the model from the unit labels, then the vendor tool; then repeat phase 0 at 115,200 |
| Pi radio drops off the USB bus | Pi under-voltage resets the bus (2026-10-30: the first drop came right after a logged under-voltage dip) | check `dmesg` for `Undervoltage detected` and `vcgencmd get_throttled` (`0x50000` = occurred earlier; `0x50005` = happening now); fix the supply (5 V, 2.5 A or more, short thick cable) before any timing run |
| Bridge sheds its own telemetry, or false DoS alerts after a GCS connects in `active-ips` (fixed 2026-10-30) | the rate learner read a step in message rate (about 1 to 135 msg/s) as a flood; the flood gatekeeper also shed the vehicle's own sysid | check `dropped_dynamic` and the analyser alert count in `/status`; a run with downlink drops is failed, not a radio result. Fix: commit `e1ceb76` and the learner-extension change after it |
| `pkill -f` run over ssh kills the ssh shell itself (seen on the Pi, 2026-10-30) | a pattern that also appears in the ssh command line matches the shell that launched it | start and stop processes with pid files and kill by pid, as `pi_bridge_run.sh` does; never `pkill -f` a pattern that the same ssh command contains |
| SITL does not open 5762 | SITL waits for a client on SERIAL0 first | start the holder client on 5760 |
| Pi `vcgencmd get_throttled` shows `0x50005` | under-voltage and throttling happening now (low nibble = now; `0x50000` = history only) | do not run timing phases until it reads `0x0` or history only; see section 3, item 6 |

## 8. Safety and scope

* **Everything stays local.** Nothing from this campaign is pushed to GitHub or any remote; run directories, captures,
  keys and logs stay on the two machines.
* **Hostile traffic is bench-only,** on the user's own radio pair and own SITL, in an isolated bench setting. The attack
  tools transmit forged MAVLink on the radio frequency: run them only with both radios on the bench and no other
  MAVLink system in range, observe the radio regulations of the band the units use, and do not point them at anything that
  is not this rig.
* **The Pi is not shut down or rebooted by any tool.** Power-off is the user's own `sudo shutdown -h now` on the Pi (a reboot in
  phase 8 is likewise the user's action: `laptop_ctl.py reboot-pi` only prints the command unless `--yes-reboot` is given).
* **System changes need approval.** The plan does not change the firewall (section 3, item 3). Radio settings, and driver or package installs, are done
  by the user (or only after the user says yes), not silently by a tool.
* **No secrets in the repo.** Keys (flight, management, SSH) live outside the repo. Docs, run directories and reports never
  contain key material, tokens or passwords.
* **No hardware bypass.** If the bridge or the Pi dies the radio link is cut (`docs/MINIMAL_BUILD.md`); phase 8 measures this
  outage and does not fix it. Do not treat a passed phase 8 as flight readiness.

## 9. Known limitations and what a pass would and would not let us claim

* The FC link is a TCP socket to SITL, carried over the Ethernet cable inside an SSH reverse tunnel, not a UART. Latency and jitter on that hop are not those of a real FC.
* Pi power: the supply was under-voltage on 2026-10-30 (`docs/RADIO_TEST_RESULTS.md`), so Pi figures taken from that supply are worst-case. The Pi radio also dropped off the USB bus twice that day.
* Pi-in-the-loop runs (bridge on the Pi, SITL and hub on the laptop, no radio) are software checks of the bridge over the cable, not radio results. They are logged in `docs/RADIO_TEST_RESULTS.md`.
* One radio pair (both 900 MHz; model not yet read from the labels), a few metres apart: loss and latency are bench figures, not a link budget.
* One pilot and one attacker tool (pymavlink scripts), not real ground-station software. The attacker script reads the hub's observer port, not a capture file; a real attacker would need a sniffer.
* Counter-tracking attacks on an unsigned link are expected to get through (`docs/INLINE_IPS.md`); signing is the only
  defence, and signing has still not been run against a real autopilot's own implementation beyond SITL's.
* The "future timestamp" case probably exposes a missing upper bound (phase 6). A pass of that check is not expected.
* ML is off in the Pi measurements; this plan does not change that.
* Single campaigns: a run proves what happened in that run. Repeat counts are part of each result row.

A full pass would let us say: *on this bench, with a Raspberry Pi 3B+, the inline IPS bridge forwarded traffic between a radio
pair and ArduCopter SITL, with the stated added latency and loss, dropped the listed forged frames before the simulated
FC and did not drop the pilot's, reported over the radio inside its byte budget, and recovered from the listed failures.*

It would **not** let us say that the system is flight-ready, that it works with a real FC or real GCS software, that it detects
or survives a real GPS attack, that the radio range or reliability is adequate, or that it protects against an attacker who can
track the real GCS on an unsigned link. Any phase that is skipped or fails must be reported as such.

## 10. Pi-in-the-loop results (2026-10-30, no radio) and new bridge behaviour

**Summary.** On 2026-10-30 the bridge ran on the Pi 3B+ with SITL and the hub on the laptop, over `ssh -R` tunnels on a direct
Ethernet cable, and no radio in the path. Measured results, with the full detail and figures in `RADIO_TEST_RESULTS.md`
(section "Pi 3B+ in-the-loop results"): forwarding with 0 dropped frames in passive and ACTIVE_IPS, signing, a bridge kill
(13.0 s telemetry outage with a manual restart), a tunnel cut (one 11.8 s gap, the bridge reconnected without a restart), the
GPS ladder, a 1,800 s soak, the attack set and the management channel. Known limits seen: a battery step and a frozen attitude
at hover were not detected, and a scripted GPS drift of about 1 m/s was not detected. The Pi was throttled during the soak, so its CPU
and latency figures are worst-case. These are not phase results: phases 1 to 9 still need the radio.

**CLI and behaviour notes that affect this plan:**

* `aegis ips-bridge --firmware-dir DIR --firmware-recheck-s N` (default 30) re-hashes the `*.bin` files every N seconds. A
  mismatch raises a firmware-integrity alert. Without `--firmware-dir` the verdict is UNKNOWN (not checked).
* `aegis fw-manifest DIR` writes `DIR/manifest.json` with the hashes of the `*.bin` files in DIR. The manifest is unsigned: a
  rewriter of both the binaries and the manifest defeats it.
* `pi_bridge_run.sh` has no dedicated variable for these flags. Pass them with `EXTRA_ARGS` (for example
  `EXTRA_ARGS="--firmware-dir $HOME/aegis_fw"`).
* Ground-side start-up quiet window: 20 s while unarmed. GPS_SPOOFING and DOS alerts, and the rate_limit, sanitize_gps,
  anti_jam_dr and gps_recovered actions, are still detected and logged but not announced to the GCS. A phase run that reads only the GCS side
  must allow for this window.
* Persistent alerts are announced with a back-off (AlertGate): the gap doubles 4, 8, 16 s, then stays at 30 s. Escalation is
  announced at once. A quiet 60 s resets it. A phase count of announced alerts is therefore not a count of detections.
* Forged or unsigned frames are announced to the GCS as `AEGIS: blocked ... xN` STATUSTEXT, one per second per label. They are
  not detector alerts.
* The vehicle's own telemetry is never rate-shed. The rate-baseline learner adopts a stable plateau after a stream-request
  step and extends its window once.
* The soak's forged-LAND schedule was affected by a harness bug (the attacker socket was not drained). Only the first of five
  attempts reached the bridge. Count attempts that reached the bridge, not attempts sent.
