# Inline IPS bridge (Topology B)

`aegis ips-bridge` puts AegisFlight in the wire between a flight controller and its GCS link, so that hostile
frames can be dropped *before* the autopilot sees them. Before this, the IPS could only send a corrective command
after the fact (`FrameSanitizer` and `InlineBridge` were not wired to anything).

```
FC <-- serial -->  [ aegis ips-bridge ]  <-- serial -->  GCS radio
                    forwarder: frame -> InlinePolicy -> other side
                    tap:       copy of every ORIGINAL frame -> IDS pipeline -> MitigationController
                    controller state -> policy (quarantine / rewrite / QoS); counter-frames -> FC
```

```bash
aegis ips-bridge --fc-port /dev/ttyAMA0 --fc-baud 921600 --gcs-port /dev/ttyUSB0 --gcs-baud 57600 \
                 --defense-mode passive --db artifacts/ips.sqlite
```

**Receive-only boundary (2026-10-31):** a serial-device FC port (`/dev/tty*`, `COMx`, a PTY or com0com pair) may be a
physical flight controller, so `active-ips` is refused on it: the CLI exits 2, `InlineIpsBridge(...)`/`set_mode` raise
`ValueError`, and `POST /posture` answers 409 `receive_only_link`. `active-ips` runs only with a `socket://` FC port
(ArduCopter / PX4 SITL, `--allow-url`), which is where every `active-ips` result below was produced. In `passive` /
`advisory` the bridge still relays the operator's own uplink to the FC byte-identically, as a radio would. The
real-Pixhawk bench runs of `active-ips` (`docs/REAL_PIXHAWK_TEST.md`) reached the Pixhawk through `px_fc_proxy.py` as a
`socket://` link: they are bench evidence on a proxied link, not a statement about a flight configuration.
A proposal for enforcement on a real vehicle link that keeps the postures receive-only (`--vehicle-uplink-filter`: drops forged uplink
control only, never changes the downlink, never sends a counter-command, fixed for the run) is in `docs/VEHICLE_UPLINK_FILTER.md`. It is
off by default and not agreed with the team.

Code: `src/aegisflight/mitigation/inline_policy.py` (rules), `src/aegisflight/hal/inline_ips.py` (bridge),
`mitigation/sanitizer.py` (downlink rewrite). Tests: `tests/unit/test_inline_ips.py` (synthetic frames, fake
transports, and one run over real transports on loopback sockets).

## Postures
| Posture | Behaviour |
|---|---|
| `passive` (default) / `advisory` | every other frame is forwarded byte-identically in both directions and NOTHING of the bridge's own is ever sent to the flight controller. The link is not transparent on the GCS side: by default (`--gcs-alerts on`, `--mgmt-status-interval 2`, `--crossend-interval 1`) the bridge sends the cross-end summary and the in-band management traffic (STATUSTEXT alerts/actions, status MEMORY_VECT, COMMAND_ACKs, see `docs/MGMT_CHANNEL.md`) to the GCS side, and it withholds every uplink COMMAND_LONG `MAV_CMD_USER_1` (31010) addressed to component 191, signed or not and whether or not a management key is configured. `advisory` differs from `passive` only in posture label: there is no separate advisory STATUSTEXT path |
| `active-ips` | static uplink rules + controller-driven downlink rules + counter-frames to the FC |

The operator chooses the posture (`--defense-mode`, or `InlineIpsBridge.set_mode`); leaving `active-ips` clears all enforcement.

## What `active-ips` does to the wire
**Static uplink rules (no detector needed):**
- control traffic (`SET_MODE`, sensitive `COMMAND_LONG`/`COMMAND_INT`, mission and parameter writes, position-target,
  attitude-target, RC override) from a sysid that is not a trusted ground station is dropped;
- a plain disarm in flight is dropped (the autopilot refuses it anyway); a *forced* disarm (magic 21196) is dropped
  unless it comes from a trusted ground station, so the pilot's emergency kill is never blocked;
- a byte-identical sensitive command repeated within 50 ms is dropped (burst of one frame).

**Dynamic downlink rules (from the mitigation controller):** quarantine of a rogue sysid (never the vehicle or a trusted
GCS), QoS shedding in a flood, GPS / altitude rewrite with a valid CRC. They apply only while the analyser keeps them
fresh (3 s); a stalled analyser means transparent forwarding, not a stale rewrite. Signed frames are never modified.

**Counter-frames** (EKF source switch, mode restore, SAFE_HOLD ALT_HOLD) go to the flight controller only; the GPS-ladder STATUSTEXT warning goes to the GCS side only (found in SITL: sent to the FC it never reached the pilot).

## Per attack class
| Class | Inline effect |
|---|---|
| Command injection from a rogue sysid (mode flip, rogue command, disarm burst, RC/mission/param writes) | dropped before the FC |
| Rogue sysid telemetry / MAVLink anomaly | dropped after the controller quarantines the sysid |
| Flood / rate spike | non-critical messages shed, critical rate capped |
| GPS spoofing / altitude bias on the downlink | GPS / altitude corrected in transit; EKF switch sent to the FC |
| Telemetry manipulation (speed, battery) | detected; no inline correction exists |
| Firmware tamper | detected; pre-arm lock only when known disarmed |
| `gcs_replay` / any attack using the real GCS sysid | stopped only with `--signing-key-file`; on an unsigned link it is indistinguishable from the pilot |

## MAVLink-2 signing (closes `gcs_replay` and sysid spoofing)
```bash
aegis ips-bridge ... --defense-mode active-ips --signing-key-file gcs.key --signing-state /var/lib/aegis/sig.json
```
`gcs.key` is the same 32-byte key the GCS and the flight controller use (raw bytes or 64 hex characters; keep it out of the repo).
With a key, in `active-ips`:
- every control message and sensitive command on the uplink must carry a valid signature with a strictly increasing
  timestamp per (link, sysid, compid) stream. A forged sysid fails the MAC, a replayed frame fails the timestamp, an unsigned
  frame is dropped. A valid signature, not the sysid, is what makes a sender trusted;
- `--signing-state` keeps the last timestamp per stream across restarts, so a restart does not reopen a replay window;
- `--signing-max-age-s N` also rejects signed frames older than N s on the bridge clock (stops a captured frame that was
  held back and released later). Use it only if the companion's clock is correct (no RTC means a wrong clock);
- `--signing-permissive` is for rollout only: unsigned control frames from a trusted sysid pass, forged or replayed signed
  frames still do not;
- the bridge's own counter-frames are signed with the same key, and the IDS side verifies signatures too (`sig_invalid`).

Downlink (vehicle -> GCS) on a signed link, in every posture:
- the vehicle's own telemetry may be unsigned (ArduPilot over USB, FC-side signing off), so the analyser accepts unsigned
  frames from the vehicle sysids. That exemption ends for a (sysid, compid) once it has sent 20 validly signed frames: an
  unsigned frame claiming that source is then a forgery. It is reported (`signing_observed.forged_down_*`, an `AEGIS:`
  STATUSTEXT), never ingested by the detectors, and in `active-ips` dropped before the GCS;
- if that source sends no valid signed frame for 10 s (signing turned off on the FC, a reboot into an unsigned setup) it
  no longer counts as signing: its telemetry flows and reaches the detectors again, instead of a self-inflicted blackout,
  and the lapse is announced (`AEGIS: signing-lapsed ...`, `policy.signing_lapsed`). The cost: a man in the middle who
  suppresses all of the vehicle's signed frames for 10 s can then inject unsigned telemetry. The lapse is visible to the
  pilot when it happens. Tests: `tests/unit/test_signed_downlink_telemetry.py`.
- **Availability trade-off (maintainer decision, fail-closed kept; review X1).** Suspicious downlink traffic can cause
  the vehicle's legitimate telemetry to be dropped: an unsigned frame claiming a source that signs, or a replayed genuine
  signed recording that makes an unsigned vehicle look like a signing one (see `docs/THREAT_MODEL.md`), leads the
  analyser to drop that source's unsigned telemetry, and `active-ips` drops it before the GCS, until the 10 s lapse.
  The security boundary is deliberately not relaxed to avoid this.

Boot quiet: for the first 20 s after the bridge starts, and only while the vehicle is not armed, GPS_SPOOFING and DOS alerts
(any severity) and their RATE_LIMIT / SANITIZE_GPS / ANTI_JAM_DR / GPS_RECOVERED actions are detected, logged and acted on
but not announced to the GCS: a GPS that has not converged raises CRITICAL GPS_SPOOFING at power-on on the bench, and a
burst of parameter traffic looks like a flood. Every other alert class is always announced, and arming ends the window at
once. The cost: real GPS spoofing or a flood that starts within 20 s of bridge start while disarmed is announced late (it
is still logged and acted on). After an in-flight bridge restart the window also applies until the first heartbeat shows
the vehicle armed (at most 20 s).
**Maintainer decision (review X4): the 20 s boot-quiet window is retained.** During it the pilot is not warned of GPS
spoofing or a flood, and full detection coverage is not guaranteed for the first 20 s after the bridge starts (while
disarmed). Do not rely on AegisFlight warnings in that window.

Not covered: signing must be enabled on the GCS and the flight controller (`SETUP_SIGNING`; PX4 and ArduPilot accept the
first key from whoever sends it first, so provision on a trusted link). Signed downlink telemetry cannot be rewritten
(GPS correction does not apply to it). Rules are only checked for control traffic, not for every frame. The verifier matches
pymavlink's signer (tested), but has not been run against a real autopilot's signing implementation.

## Fix made while building this
`FrameSanitizer` skipped any `GLOBAL_POSITION_INT` shorter than 40 bytes. MAVLink 2 trims trailing zero bytes (`vz`,
`hdg` are often 0), so such frames were never corrected. It now restores the full 28-byte payload, patches the fields and
recomputes the CRC; if nothing needs changing it forwards the original bytes.

## What is and is not established
- Tested: the rules on synthetic MAVLink 2 frames, forwarding fidelity (PASSIVE/ADVISORY byte-identical; benign traffic
  never dropped in ACTIVE), and a run over real `SerialMavlinkTransport` instances on loopback sockets.
- Host micro-benchmark (this PC, no real I/O, 15,000 frames through the policy): p50 ~3 us, p95 ~4 us per frame.
  That is policy cost only. Serial latency, the analyser's decision time (17.7 ms mean with ML on) and anything on a
  companion computer are **not measured**.
- **Tested against ArduCopter SITL, over a real LR900 radio pair (2026-10-30), and against a real Pixhawk 6X on a bench with a Pi 5 (2026-10-31; disarmed, propellers removed, USB link).** Not flown. Any first flight should be restrained. See `docs/REAL_PIXHAWK_TEST.md`.
- **No hardware bypass.** Both ports end in this process; if the companion loses power or the process dies the link is
  cut. A relay or splitter that connects FC and radio directly when the companion is down is required for flight.
- Without a signing key, trust is by sysid and an attacker who claims sysid 255 passes; use signing and set
  `--trusted-sysid` to the ground stations you actually use.
- The vehicle's mode restore only works for ArduCopter mode names; PX4 modes are never guessed.

## GPS response ladder

In `active-ips`, a GPS spoofing or GNSS jamming episode is handled in software only, per episode, on decision ticks:

1. Confirm after 2 consecutive threat ticks; send a STATUSTEXT warning.
2. Without a declared secondary source (default): if the fault persists 3 s after confirmation and the vehicle is armed in a position-dependent mode (AUTO, GUIDED, LOITER, RTL, POSHOLD, ... or unknown), send one `ALT_HOLD`. The controller never sends AUTO/RTL/LOITER/GUIDED/POSHOLD/LAND during an episode.
3. With `--ekf-secondary` (operator declares a configured non-GPS EKF source set): send the EKF source switch at confirmation; if the fault persists 4 s later, fall back to `ALT_HOLD`. Sensor messages never enable this automatically.
4. A pilot mode command (DO_SET_MODE, RTL, LAND) from a trusted sysid after confirmation cancels the ladder for the episode.
5. Recovery needs the clean-tick count and a position residual below 6 m. The EKF primary is restored only if we switched; the trusted flight mode is not restored (the pilot resumes). Command-injection episodes still restore the trusted mode.

PASSIVE and ADVISORY never send control frames. `bridge.status()["analyser"]["ekf_secondary"]` shows the declared capability.

## Cross-end check

Detects telemetry altered AFTER the bridge (radio link, GCS-side injection) while the drone flies normally.
Once per `--crossend-interval` seconds (default 1.0, `0` = off) the bridge sends the GCS side one MAVLink 2
`MEMORY_VECT` (sysid 1, compid 191, fixed marker) holding the exact integer fields (`time_boot_ms, lat, lon, alt,
relative_alt, vx, vy`) of the last `GLOBAL_POSITION_INT` it forwarded (after any rewrite). It is built on the
analyser thread, never in the per-frame hook, and goes to the GCS transport only (not the FC, not the tap).
With `--signing-key-file` the frame is signed and carries a truncated HMAC tag in the payload.

A GCS-side `aegis serve --source serial|udp [--signing-key-file K]` runs `CrossEndMonitor`
(`detectors/crossend.py`), merged into the PROTOCOL detector. A summary whose `time_boot_ms` matches a received
frame must match every field exactly; a difference scores 0.9 (`TELEMETRY_MANIPULATION`). Summaries that stop for
more than 5 s, or a bad/absent authentication when a key is set, give 0.3 (`MAVLINK_ANOMALY`) evidence. Without any
summary seen the monitor is inert.

Limits: sampled at 1 Hz, so a forged frame with a different `time_boot_ms` is never compared; without a key the
summary itself can be forged; it works only if the GCS-side IDS sees the bridge summary on the same link.
Not measured on hardware.

## Detected topology

The dashboard does not offer a topology selector. `status()` (and `GET /status`) carries a `topology` object of kind
`A+B`: the FC and GCS link `connected` flags come from the two transports (`null` if a transport does not report
one). `uplink_visible` is true once frames were seen from the GCS side or the GCS link is connected;
`can_block_frames` needs `active-ips` with both links up; `can_send_counter_commands` needs `active-ips` with the FC
link up. A single-port `aegis serve` sidecar is reported as kind `A` (cannot block frames). See `docs/API.md`.

## In-band management channel (radio)

On a drone whose only link to the ground is the telemetry radio, the bridge also reports and takes signed controls over that
radio with standard MAVLink 2 messages: every IDS alert and IPS action as a short `AEGIS:` STATUSTEXT, a 32-byte status
MEMORY_VECT every 2 s, and signed `MAV_CMD_USER_1` posture commands answered by COMMAND_ACK, all under one byte budget
(150 B/s default). Flags: `--gcs-alerts`, `--alert-min-interval`, `--mgmt-status-interval`, `--mgmt-max-bytes-per-s`,
`--mgmt-key-file`, `--mgmt-state`, `--lock-posture-file`, `--audit-log`. `status()` carries a `mgmt` counters block. Full
description: `docs/MGMT_CHANNEL.md`; wiring and limits: `docs/MINIMAL_BUILD.md`.

## Status endpoint

`aegis ips-bridge --status-port N` (default off) starts a read-only HTTP server on `127.0.0.1:N` (loopback only).
`GET /status` returns the same JSON as the periodic status line (`mode`, `state`, `frames`, `latency_us`, `policy`,
`analyser`, `last_error`) plus `"crossend": {"sent": n}`. Only GET is served (other methods: 405); there are no write
endpoints. CORS echoes the `Origin` only for the dashboard's allowed origins (localhost dev ports, Tauri).

## SITL evidence (ArduCopter SITL, loopback; environment tag `SITL`)
One scenario, one run per posture, on this PC (`scripts/ardupilot/inline_demo/`, profile `configs/ardupilot_copter/`): The profile enables `protocol.auto_rate_baseline` and sets `physics.yaw_course_enabled: false` (this disables the frozen-attitude telemetry check for that profile; see docs/DETECTION.md).
a simulated ArduCopter took off to 30 m and flew a rectangle in GUIDED, with the bridge between the flight controller
and a loopback "radio" hub; a rogue sysid 66 then sent a forged LAND (`DO_SET_MODE` and `SET_MODE`), two bursts.

| | `passive` | `active-ips` |
|---|---|---|
| vehicle after the attack | switched to LAND (mode 9) and descended to 0 m | stayed in GUIDED at 30 m (44 of 44 samples) |
| hostile frames reaching the FC | all | 0 (20 dropped as untrusted control) |
| legitimate GCS frames forwarded | 35 of 35 | 15 of 15 |
| downlink frames forwarded / dropped | 23,473 / 0 | 23,793 / 0 |
| per-frame forwarding time (p50 / p95 / max, socket sends included) | 15.6 / 48 / 2,170 us | 16.4 / 49 / 1,213 us |
| attack detected | yes, `COMMAND_INJECTION` from sys66 | yes |
| cross-end check at the GCS-side IDS | 164 matched, 0 mismatches | 164 matched, 0 mismatches |
| hash-chain log | intact | intact |

What this does not show: a real flight controller, radio or companion computer; signed traffic (all frames unsigned);
an attacker using the real GCS sysid; more than one run per posture. Findings from the run:
- The Stage-1 thresholds raised about 50 false `DOS` alarms (message rate) on this link in `passive`; the profile above
  removed them. Rate alarms must not drive actuation without a per-link profile.
- The multirotor heading-vs-course rule raised 4 false `TELEMETRY_MANIPULATION` alarms in GUIDED (documented limit).
- In `active-ips`, 4 redundant set-mode counter-frames (back to GUIDED) were sent after the blocked attack.
- SITL needs a client on SERIAL0 before it opens SERIAL1, and streams nothing extra on other ports until a GCS asks.

## Unsigned-link provenance (no signing key)

When no `signing_key` is configured, a sysid is only a claim: anyone on the radio link can forge sysid 255 or replay a
captured genuine frame. `InlinePolicy` therefore adds a best-effort, software-only check (`provenance=True`,
`provenance_window=16`; active only with enforcement on and no key; with a key the signature rules decide and this
tracker is bypassed).

- **Sequence tracker.** Every uplink frame updates a per-(sysid, compid) `SeqProvenance`. After 3 frames the 8-bit
  counter is "known". A frame is consistent if `(seq - last) mod 256` is 1..16 (tolerates radio loss); a duplicate or a
  jump/behind is inconsistent. Inconsistent frames never move `last_seq`, so a forger cannot drag the real counter.
- **Decision.** A sensitive command or control message from a trusted sysid with a known but inconsistent counter is
  dropped while armed or in flight (`dropped_provenance`); on the ground it passes and is counted
  (`suspect_provenance`). An unknown counter passes. Existing rules (untrusted sysid, in-flight plain disarm, burst)
  are unchanged.
- **Resync.** Three consecutive inconsistent frames that follow each other (+1..16) replace the learned counter
  (`resyncs`), e.g. a GCS restart, but only when the learned counter has seen no consistent frame for 2 s
  (`SeqProvenance.quiet_s`). A live genuine stream therefore keeps the counter: a forger that sends its own
  consecutive sequence next to the pilot cannot take it over (found in SITL, see below). Worst-case lockout of a genuine
  pilot after a restart: its first 2 frames, and at least 2 s after its previous frame; the same applies after more than
  16 consecutive lost frames.
- **Replay.** A byte-identical (sysid, compid, seq, payload) repeat of an already forwarded sensitive frame within 5
  minutes (bounded to 512 entries) is dropped (`dropped_replay_unsigned`) once that source's counter is known. Re-sending
  the same command with a new seq is not a replay.
- **Counters** in `stats()`: `provenance_known_sources`, `dropped_provenance`, `suspect_provenance`,
  `dropped_replay_unsigned`, `resyncs`.

**Limits.** This does not stop an attacker who can see the link and tracks the real counter, nor a forger whose frames
happen to fall in the +1..16 window. Only MAVLink-2 signing closes those.

## SITL evidence: signing and unsigned smart attacker

Same rig as above (ArduCopter SITL, loopback hub, `configs/ardupilot_copter`-style profile, GUIDED flight at 30 m;
scripts in `scripts/ardupilot/inline_demo/`: `run_signing.sh`, `run_unsigned.sh`). Two runs per active scenario, one
passive run each. Single runs, one simulated autopilot, loopback only: no radio, no real GCS software.

**Scenario A, MAVLink-2 signing** (random 32-byte key provisioned with `SETUP_SIGNING` over SERIAL0, SITL restarted,
`ips-bridge --signing-key-file --signing-state`, pilot and GCS-side `aegis serve` with the same key). Per active run
(two runs, identical counters):

| check | result |
|---|---|
| signed pilot: GUIDED, arm, takeoff 30 m, leg, signed LOITER then GUIDED | all succeeded; `signed_ok` 16 |
| unsigned forged LAND, sysid 66 and sysid 255, MAVLink 2 and MAVLink 1 (10 frames each) | 40 `dropped_unsigned`; mode stayed GUIDED |
| LAND signed with a wrong key (sysid 255, 10 frames) | 10 `dropped_bad_signature`; GUIDED |
| byte-identical replay (3x) of a captured signed SET_MODE(LOITER) | 3 `dropped_replay`; GUIDED, no second LOITER |
| uplink frames | 70 in, 17 forwarded, 53 dropped (= 40 + 10 + 3); no pilot command failed |
| downlink | 24,386 and 24,524 frames forwarded, 0 dropped |
| GCS-side cross-end check | 168 and 169 matched, 0 mismatches |
| IDS inside the bridge | 4 `TELEMETRY_MANIPULATION` (the known heading/course false alarm in GUIDED) and no alerts for the dropped attack frames, which never reach the tap; 4 counter-frames sent |
| `passive`, same key | all 70 uplink frames forwarded; the flight controller itself rejected every unsigned, wrong-key and replayed frame (mode stayed GUIDED); the IDS reported the same 4 heading/course alerts and nothing about the attacks; cross-end 165 matched, 0 mismatches |

Not shown: the FC rejecting these in passive is inferred from its mode, not read from its log; the replay is dropped by
the bridge and would also be refused by the FC's own timestamp check, so "FC does not act twice" is not isolated from
the bridge; no wrong-sysid-with-valid-signature case; no key rotation or clock skew.

**Scenario B, smart attacker on an unsigned link** (no key anywhere; sysid 255 / compid 190 forged; the pilot sends a
1 Hz heartbeat and a benign DO_SET_MODE(GUIDED) every 5 s as probe of lock-out). `passive` is the control.

| attack | `passive` (run 1) | `active-ips` (2 runs after the fix) |
|---|---|---|
| (1) forged LAND, own counter, 10 frames | vehicle went to LAND | 10 `dropped_provenance`, no LAND (before the fix: 5 dropped, 2 `resyncs`, LAND reached the FC) |
| (2) replay of the pilot's captured SET_MODE(LOITER), 3x | vehicle went to LOITER | 3 dropped (counted as `dropped_provenance`: the replayed seq is behind the counter; `dropped_replay_unsigned` stayed 0); no LOITER |
| (3) counter-tracking forged LAND (next expected seq, 10 attempts) | vehicle went to LAND | PASSED: LAND reached the FC in both runs (1 and 2 frames `dropped_provenance` in that stage) |
| (4) pilot restarts its counter at 0 | first LOITER command accepted | first command dropped, second accepted 3.4 s and 3.5 s after the restart (1 `resync`); GUIDED restored |
| `dropped_untrusted_control` / `suspect_provenance` / `dropped_replay_unsigned` | 0 / 0 / 0 | 0 / 0 / 0 |
| totals over the run | 214 of 214 uplink frames forwarded | `dropped_provenance` 15 and 16, `resyncs` 1; 206 and 204 forwarded |

Legitimate frames dropped: 1 per run at the pilot restart (the lock-out above); in the second active run one benign
probe (BEAT 11) got no acknowledgement during the tracking stage, which may have been a duplicate-seq collision with the
attacker; the drops in the tracking stage were not attributed to sender. All other probes were acknowledged.

What this shows: with a key, every forged, wrongly-keyed and replayed uplink frame in these runs was dropped and the
pilot kept working. Without a key the software check stops a naive forger and naive replay, and does nothing against an
attacker that can read the real pilot's counter (3); that remains the case until signing is on. What it does not show:
a real radio, a real GCS (QGroundControl and others behave differently on restart and heartbeat), other attackers'
timing, or more than the stated number of runs.

**Bug found and fixed.** The unsigned resync rule let a forger take over the counter: 3 consecutive own-counter frames
next to the live pilot replaced the learned counter (first run: LAND reached the FC after 5 drops, and the pilot's
own frames were then treated as inconsistent). `SeqProvenance` now resyncs only after the learned counter has been quiet
for 2 s. Regression tests: `test_forger_consecutive_counter_next_to_live_pilot_cannot_take_over` and
`test_seq_provenance_quiet_period_gates_resync` in `tests/unit/test_inline_provenance.py`. No bug was found in the
signing path.

## SITL evidence: wrap-around replay and contested source

Unsigned link, `active-ips`, ArduCopter SITL on loopback through `scripts/ardupilot/inline_demo/` (`run_wrap.sh`,
`run_contested.sh`, `fly_wrap.py`, `attack_wrap.py`, `watch_alarm.py`; the pilot is a pymavlink script as sysid 255).

**Replay memory.** The byte-identical replay set is now count-bounded (`replay_memory`, default the last 4096 forwarded
sensitive/control frames, `--replay-memory`), with no time limit and no need for the source counter to be known. An exact
(sysid, compid, seq, payload) forwarded once is never forwarded again. Cost: a GCS that legitimately sends the same
control frame with the same seq after exactly 256 frames (rare) is dropped once.

**Wrap-around replay (1 run).** The pilot sent a genuine DO_SET_MODE(GUIDED) at seq 104 (hub capture), went back to
LOITER, sent 247 filler heartbeats at about 20/s (15 s) until its counter was at 101, then the attacker replayed the
captured bytes (seq 104 is inside the +1..16 window, so the provenance check alone would accept it). Result:
`dropped_replay_unsigned` +1, `dropped_provenance` 0, vehicle stayed in LOITER (5); the pilot's next legitimate
DO_SET_MODE(GUIDED) (new seq) was forwarded and acked (ack 0, mode 4). Whole run: 374 uplink frames, 1 dropped.

**Counter-tracking attacker (1 run per mode, 10 forged DO_SET_MODE(LAND) each, sent with the pilot's next seq).**
- `alert`: every attempt produced a same-seq/different-payload event (`contested_events` 10), one rate-limited alarm
  (`contested_alarms` 1); the STATUSTEXT (severity 4) was seen at the GCS side and the console printed an ALARM line.
  The attack was NOT stopped: 1 forged frame dropped by provenance, 9 forwarded, vehicle went to LAND (9); the pilot's
  next beat restored GUIDED.
- `drop-sensitive`: same detection and alarm. `dropped_contested` 12: the vehicle still entered LAND (the first forged
  frame passes before a duplicate proves two senders), then forged frames and the pilot's own DO_SET_MODE beats (3 of 3,
  ack None) were dropped, so the real pilot could NOT take the vehicle out of LAND while the source was contested
  (60 s hold, refreshed by each event). The RC radio remains the override.
- So the detector only detects the counter-tracking attacker once the race yields a duplicate; it does not stop its
  first frames, and `drop-sensitive` can lock out the real GCS. A forced disarm (magic 21196) is never dropped. Only
  signing removes the problem; `ips-bridge` prints a warning when `active-ips` runs without `--signing-key-file`.
  The alarm text stays below the 50-byte STATUSTEXT limit.

**What this does not show:** single runs, a simulated autopilot, loopback with no radio latency or loss, a pymavlink
pilot rather than real GCS software, and an attacker script that reads the capture file directly (a real one needs a
radio sniffer).

## SITL finding: late-connecting GCS and the rate baseline (ArduCopter SITL, loopback)
A ground-side monitor started before the GCS asked for its telemetry streams learned a ~5 msg/s baseline, then raised 55 false
`DOS` rate-spike alarms over one flight at 140 msg/s. Two defects: the baseline never switched on for live sources (the key had
an explicit `false` default, so "set if missing" did nothing; unset now means auto: on for live, off for SIM), and a one-shot
baseline cannot follow a link whose rate steps up later (a stable 30 s plateau below the configured hard flood limit is now
adopted, at most twice per session; the hard limit is never relaxed). Same flight after the fix, ground-side IDS: 1 alert
(a heading rule one) and 0 `DOS`. One run; the bridge side was unaffected.

## SITL evidence: sidecar recovery and GPS spoofing response

ArduCopter SITL on loopback, `configs/ardupilot_copter`, flight in GUIDED at 30 m. Scripts: `scripts/ardupilot/inline_demo/sidecar_recovery.py`
(Topology A) and `gps_response.py` (bridge). SERIAL1 streams come from `MAV2_*` persistent parameters loaded with
`--defaults` (`scripts/ardupilot/sitl_defaults_monitor_port.parm`); setting them at run time over MAVLink did not produce streams. Single runs, simulated
autopilot and GPS, loopback, no real hardware.

**Test 1, Topology A** (pure sidecar `aegis serve --source serial` on SERIAL1, no bridge; pilot direct on SERIAL0, silent after takeoff;
attacker on SERIAL2 sends `DO_SET_MODE(LAND)` once):

| Run | Result |
|---|---|
| passive, attacker sysid 66 / 255 | LAND within 0.3 s, descended to 0 m in about 35 s, stayed in LAND; no injection alert |
| active-ips, attacker sysid 66 / 255 | identical: LAND, never back to GUIDED; sidecar `counter_frames_sent` 0 |

The sidecar never recovered the vehicle (no LAND to GUIDED time exists). Cause, from the code and the logs: the IDS raises
`COMMAND_INJECTION` only from command frames it sees, and SERIAL1 carries only the vehicle's own output, so the attacker's frame on SERIAL2 (and the
pilot's on SERIAL0) is invisible to the sidecar. The only trace is the HEARTBEAT mode change, which is indistinguishable from a legitimate
pilot change made on another port, so `golden.trusted_mode` simply follows it (it read `LAND`) and there is nothing to restore. This is a design
limit of a sidecar that does not see the command path, not a bug; recovery in Topology A needs the sidecar on the command path (the bridge) or a
second source of command provenance. Incidental: a start-up `dos:gnss_jamming` alert (no fix yet, on the ground) occurs in every run.

**Test 2, GPS response** (bridge `active-ips`; fault written to `SIM_GPS1_GLTCH_X`, degrees of latitude offset, 0.001 deg = about 111 m; other relevant SITL
parameters: `SIM_GPS1_GLTCH_Y/Z`, `SIM_GPS1_GLTV_*`, `SIM_GPS1_DRFTALT` (altitude only), `SIM_GPS1_JAM`, `SIM_GPS1_NOISE`; no horizontal drift parameter, so drift is a scripted ramp of GLTCH_X):

| Run | Detection (bridge) | GCS warning | Mode timeline | Ladder |
|---|---|---|---|---|
| benign, no fault | no alert in flight (3 alerts on the ground before takeoff, fix acquisition) | none | GUIDED throughout | nothing sent in flight |
| glitch ~111 m, passive | GPS_SPOOFING HIGH at +0.7 s (EKF innovation ratio 29.6), CRITICAL at +12.7 s (position residual 30 m) | none | stays GUIDED | nothing sent (0 counter-frames) |
| glitch ~111 m, active-ips (3 runs; warning seen in the one run after the fix) | same events | `AEGIS: GPS unreliable - do not trust position` at +0.9 s | GUIDED to ALT_HOLD (2) at +3.9 s (3.0 s after confirmation); descended to the ground | 1 warning + 1 ALT_HOLD; no AUTO/RTL/LOITER/GUIDED/POSHOLD |
| glitch + pilot `DO_SET_MODE LOITER` after the warning | same | at +0.8 s | LOITER at +1.1 s, stays LOITER | ladder stood down: warning only, no ALT_HOLD |
| scripted drift ~5 m/s, active-ips | EKF innovation ratio 1.3 at +0.7 s, residual 35 m at +12.7 s | at +0.9 s | ALT_HOLD at +3.9 s | warning + ALT_HOLD |
| scripted drift ~1 m/s, active-ips | no alert at all (run before the fix below) | none | GUIDED for 110 s | none: a miss |

What this shows: the ladder confirmed and acted as designed (warning, one ALT_HOLD 3 s later, no forbidden mode, pilot override honoured), with no false
actuation in the benign flight. What it does not show: the detection evidence here is the SITL EKF's own innovation ratio (the SITL estimator reacts to the glitch, also
switching lanes and printing `GPS Glitch or Compass error`), so this is not independent proof of a position-residual detector; a 1 m/s drift went unnoticed;
ALT_HOLD with no pilot throttle makes SITL descend to the ground (the ladder only stops position-dependent flight; a pilot must take over). The pilot-override test uses `DO_SET_MODE` in
`COMMAND_LONG`; a plain `SET_MODE` message (msgid 11) is not recorded as a command by the feature extractor, so it would not cancel the ladder (not changed).

Bug found and fixed: the ladder's STATUSTEXT warning was sent to the flight controller only and never reached the GCS (first glitch runs: no `AEGIS` text on the GCS side). The bridge now sends STATUSTEXT
counter-frames to the GCS transport (`hal/inline_ips.py`, regression test `test_statustext_counter_frame_goes_to_the_gcs_and_commands_go_to_the_fc`). Logs and sqlite files stay outside the repo (`C:/afsitl`).

## Signing gate and remote posture control

Signing is the only defence against a counter-tracking forger, so `active-ips` on a real link without a key is an
explicit choice:

- `aegis ips-bridge --defense-mode active-ips` without `--signing-key-file` exits 2 unless `--allow-unsigned` is given
  (a one-line notice is then printed).
- `--control-token-file PATH` enables `POST /posture` on the status API (the file holds the token; it is never printed).
  Body `{"mode": "passive"|"advisory"|"active-ips", "allow_unsigned": bool}`, auth `Authorization: Bearer <token>` or
  `X-Aegis-Token`. Errors: 403 `control_disabled`, 401 bad/missing token, 400 bad body, 409 `signing_required` (active-ips,
  no key, `allow_unsigned` not `true`), 409 `receive_only_link` (active-ips with a serial-device FC port; no
  acknowledgement unlocks it), 200 `{"ok": true, "status": ...}`. Browser calls are CORS-limited to the dashboard origins.
- `--status-host HOST` (default `127.0.0.1`); a non-loopback host needs `--control-token-file` and prints a warning that the
  status API is reachable from the network.
- `GET /status` also returns `signing: {configured, unsigned_acknowledged}` and `control: {enabled}`.

Real-radio tests: see [docs/RADIO_TEST.md](RADIO_TEST.md) and [docs/RADIO_TEST_RESULTS.md](RADIO_TEST_RESULTS.md). None of the radio phases passes as written yet. Signing was run once on the real Pixhawk over USB, with the bridge as the enforcement point (see the last section).

## Raspberry Pi 3B+ verification

Measured on 2026-10-30 on a Pi 3B+ (Python 3.13, ML off), with SITL and the hub on the laptop, over `ssh -R` tunnels on a
direct Ethernet cable. No radio in the path. The Pi was under-voltage and soft-temperature-limited during the soak, so CPU and
latency are worst-case. Details: `docs/RADIO_TEST_RESULTS.md`, section "Pi 3B+ in-the-loop results".

| Test | Measured result |
|---|---|
| Passive forwarding | 23,077 frames forwarded, 0 dropped, p50 0.43 ms |
| ACTIVE_IPS forwarding | 23,321 of 23,321 downlink forwarded; 20 forged uplink dropped; 0 false rate alerts; p50 0.25 ms, p95 0.42 ms |
| Signing (active-ips) | signed_ok 16; dropped: unsigned 40, wrong key 10, replay 3; 0 valid commands dropped |
| Bridge `kill -9`, manual restart | telemetry outage 13.0 s (11 s dead, about 2 s start-up) |
| Tunnel cut 10 s | one 11.8 s gap; the bridge reconnected without a restart |
| GPS glitch, 111 m | detected +0.5 s; ALT_HOLD at +3.7 s; pilot LOITER override honoured |
| GPS drift, about 1 m/s | NOT detected (known limit) |
| Soak, 1,800 s | 0 send failures, 0 hook errors, 0 analyser errors; RSS 65 MiB flat; CPU mean 55.7 % (throttled Pi) |
| Flood, 400 msg/s, rogue sysid 66 | detected within about 2 s; sysid quarantined; 3,962 uplink dropped; downlink 34,395 of 34,395 forwarded |
| Altitude bias +40 m (man in the middle) | TELEMETRY_MANIPULATION CRITICAL; 98 frames sanitised |
| Battery step, +3 V | NOT detected (known limit) |
| Frozen attitude at hover | NOT detected (needs speed above 2 m/s; known limit) |
| One firmware byte flipped | FIRMWARE_INTEGRITY INVALID within about 5 s; pilot takeover required |
| Real radio, signing (rsg1) | 10 signed accepted; 40 unsigned, 10 wrong key, 3 replay dropped; mode GUIDED; 4,929 of 4,929 downlink forwarded |
| Real radio, GPS glitch (rgps1) | GPS_SPOOFING HIGH +0.8 s; ALT_HOLD +4.0 s; no AUTO, RTL or LOITER; gps_recovered +22.8 s |
| Real radio, bridge kill and manual restart (rlong1) | 27.6 s telemetry gap (25 s dead); 24,701 downlink forwarded after restart, 0 dropped; state NOMINAL |
| Real radio, GPS ladder on a signed link after the clock fix (cid) | ALT_HOLD +4.3 s after the glitch (was rejected in cic: the bridge's counter-command timestamps came from a Pi clock 3 h 9 min behind); descent in ALT_HOLD with no pilot throttle, as documented; 0 heartbeat gaps over 3 s |

These are software results on a Pi with no radio. They do not replace the real-radio phases in `docs/RADIO_TEST.md`, which
are only partly run. Real-radio note (2026-10-30, MicoAir LR900 pair, ACTIVE_IPS): rad2 (`--allow-unsigned`) gave 9,792 of 9,801 frames sent by the bridge at the ground (9 in flight), 567 of 567 uplink frames to the bridge, and forged LAND and a flood from sysid 66 stopped at the bridge. rsg1 (signing key on the Pi) gave 40 unsigned, 10 wrong-key and 3 replayed frames dropped with the mode unchanged. rgps1 gave a GPS glitch detected at +0.8 s with ALT_HOLD at +4.0 s and no forbidden mode. rlong1 (20 min, ACTIVE_IPS): bridge killed with `kill -9` and restarted by hand gave a 27.6 s telemetry gap; 24,701 downlink forwarded after the restart with 0 dropped; RSS slope 0.063 MiB/min; forged LAND from sysid 66 dropped twice. Not run over the radio: plain passive and advisory postures (the randomised signed campaign ran them with attacks), ground-side management commands, firmware tamper, ground-radio unplug, longer air-radio unplugs (one 16 s air-radio unplug was run, unp1), the 30 to 60 minute soak (20 minutes was run), range, and the stale and future signing timestamps. Details: `docs/RADIO_TEST_RESULTS.md`, real-radio session section.

## Pi deployment notes (Pi 5, bench, 2026-10-31)

Measured on the bench with a real Pixhawk 6X (USB), disarmed, propellers removed, over a MicoAir LR900 pair. Not flown. The procedure is in `docs/REAL_PIXHAWK_TEST.md`. The figures and the judgement against the plan are in `docs/RADIO_TEST_RESULTS.md`, section "Real Pixhawk 6X on a Pi 5, 2026-10-31".

**What changed for a Pi deployment**

* **Hardware.** Raspberry Pi 5 with Raspberry Pi OS Lite (Debian 13) and Python 3.13. The flight controller is on USB (`/dev/ttyACM0`); `--fc-baud` is ignored by USB CDC. The radio is on USB: use the `/dev/serial/by-id/...` path, because two radios of this kind report identical USB IDs. A Raspberry Pi 3B+ dropped off the network when the Pixhawk's USB port was opened (3 of 3), so it was replaced for these runs.
* **Packages the bridge imports at start-up.** `aegis ips-bridge --help` works without them, because the arguments are parsed before the heavy imports. The bridge itself needs `pymavlink`, `pyserial`, `numpy`, `pyyaml`, `psutil`, `joblib` and `scikit-learn` (with `scipy` and `threadpoolctl`). `pyserial` is the optional `serial` extra in `pyproject.toml`. The core dependencies in `pyproject.toml` are a larger set; they also list pandas, pydantic, fastapi and uvicorn.
* **Unsigned link, active-ips.** The CLI refuses `active-ips` without a signing key unless `--allow-unsigned` is given. The refusal says that an unsigned link cannot stop a counter-tracking forger. The bench runs used `--allow-unsigned` for this reason. Passive and advisory do not need it.
* **Power.** Use a supply that meets the Pi 5's rating, and check `vcgencmd get_throttled` before any timing run. `0x0` is the clean reading. The Pi 3B+ supply showed under-voltage on one boot.
* **Clock.** Signing timestamps come from the wall clock. A signing-enabled flight controller rejects counter-commands stamped from a clock that is far behind. On the bench the Pi clock was 3 h 9 min behind and the counter-commands were rejected; the bridge now stamps them from observed signed traffic (commit `e099e04`, per `git log`). Sync the Pi clock before signing. `--signing-max-age-s` also compares frame timestamps with the local clock, so leave it unset on a Pi without a correct clock.
* **Start-up.** On the Pi 3B+ bench a user crontab `@reboot` entry started the bridge (phase 8, rbt1). The systemd unit `scripts/radio_test/aegis-bridge.service` is provided but was not installed or tested on any Pi.
* **Firmware check.** `--firmware-dir` with `--firmware-recheck-s` was run over the radio. The check re-hashes the `*.bin` files in that directory; it does not read the flight controller's own firmware. Its alert headline was late (see `docs/RADIO_TEST_RESULTS.md`).

**Unsigned-link limits, as measured on the bench**

* Blocked in active-ips: forged LAND, force-disarm and LOITER from an unknown sysid; a flood from that sysid (the sender was quarantined); a replayed frame.
* Not blocked: a counter-tracking forger that uses the pilot's sysid and next sequence number passed in two runs. A forged RTL that used its own counter also passed while the vehicle was on the ground; the in-flight provenance rule cannot be exercised on a disarmed vehicle.
* Only signing stops the counter-tracking forger. Signing was run once on the real Pixhawk over USB (see the last section); the flight controller's own enforcement was not tested.

**GPS on the bench.** The stationary receiver's own wander produced `GPS_SPOOFING` false alerts. This is a known open issue and is not fixed (`docs/RADIO_TEST_RESULTS.md`).

**Status.** The 1,500 s (25 min) Pi 5 soak completed; its result, and its cost (false GPS alerts moved the vehicle's mode), are in the last section.

## Signing enforcement point and the Pi 5 bench soak (2026-10-31)

**Signing on the real Pixhawk over USB (one run).** Over USB, the bridge is the enforcement point that can be observed. The flight
controller's own signature checking was **not tested**: it needs a UART or telemetry port wired to the Pi. A test key was sent to the
Pixhawk and later switched off, and whether it was stored cannot be read back. Unsigned requests on the USB link kept being answered.
That fits ArduPilot exempting the USB link from signing, but it is an inference and is not verified.

| Event | Unsigned link: active-ips with `--allow-unsigned` | Signed link: active-ips with `--signing-key-file`, no `--allow-unsigned` |
|---|---|---|
| Legitimately signed pilot command (set-mode ALT_HOLD) | not applicable | passed; the vehicle changed mode |
| Forged LAND from sysid 77 | blocked; sender quarantined | blocked (`dropped_unsigned`) |
| RTL spoofing sysid 255 | passed while the vehicle was on the ground (`suspect_provenance`) | blocked (unsigned; `dropped_unsigned`) |
| Wrong-key signed LAND spoofing sysid 255 | not run on this link | blocked (`dropped_bad_signature` 1) |
| LOITER from sysid 77 | blocked | blocked (`dropped_unsigned`) |
| Replay of a captured ALT_HOLD | blocked (`dropped_replay_unsigned` 1) | blocked (`dropped_replay` 1) |
| Force-disarm from sysid 77 | blocked | blocked (`dropped_unsigned`) |
| Flood from an unknown sysid | 443 frames dropped (`dropped_dynamic`) | 5 s flood after quarantine: `dropped_dynamic` 449 for the run |
| Counter-tracking forger (uses the pilot's next sequence number) | passed in two runs | not in the record |

On the signed link, 0 of 7 forged or replayed events reached the vehicle. The run had 134 alerts and 0 errors, and every blocked event
was announced at the ground (`AEGIS: blocked` texts). **Limits, stated plainly:** one run and one key; the wrong-key and replay
cases are one frame each; no signed-timestamp skew test; the flight controller's own enforcement not tested. So this run does not show
that the vehicle would refuse a forged frame that got past the bridge.

**Pi 5 soak, 1,500 s, active-ips (2026-10-31).** Forwarding was clean: 81,368 frames down and 1,503 up forwarded, 0 dropped either way,
0 send failures, 0 errors, handling p50 15.6 us, p95 58.5 us, max 5.0 ms, no heartbeat gap over 3 s, RSS about 68 MB and flat, and no
throttle flags. **The cost:** the bridge raised 207 alerts from the unfixed GPS false-alarm issue and sent 457 counter-commands through
its autonomous GPS response. The disarmed vehicle was held in ALT_HOLD for the run and was restored to STABILIZE by hand. Until the GPS
false-alarm issue is fixed, active-ips should not be treated as safe on a flying vehicle. Details: `docs/RADIO_TEST_RESULTS.md`, section
"Real Pixhawk 6X on a Pi 5, 2026-10-31".

## Evidence runs: `--run-dir` (raw-log archive)

`aegis ips-bridge --run-dir <dir>` makes the run auditable and replayable. It refuses a dirty tree (or, with
`--allow-dirty`, stamps the directory `NOT-REPRODUCIBLE`), refuses a directory that already holds a run, and writes:

| File | Content |
|---|---|
| `frames_down.jsonl`, `frames_up.jsonl` | FC to GCS and GCS to FC: every **original** received frame (hex) with `verdict` `forwarded` / `dropped` / `rewritten` (and `out` for a rewrite); the verdict is the policy decision, and `send_failed: N` is added when N output frames were refused by the far link (e.g. its port is down) |
| `decisions.jsonl` | one row per analyser decision: threat flag, type, score, evidence, controller mode/state |
| `actions.jsonl` | counter-frames to the FC; STATUSTEXT alarms, cross-end summaries and the management stream (alerts, status, ACKs, `kind: mgmt`) to the GCS; each change of the controller action summary; every sent-frame row carries `sent: true/false` |
| `events.sqlite` | the hash-chained alert log (unless `--db` points elsewhere) |
| `run_manifest.json` | `aegisflight.run_manifest/1` (see `docs/VALIDATION_EVIDENCE.md` §6) plus a `bridge` block: ports, posture, signing on/off, final `status()`, archive row counts |

The forwarding path only appends rows to an in-memory queue and a writer thread does the file I/O, so archiving does not
delay a frame; if the queue overflows the rows are dropped and counted (`bridge.archive.dropped_rows`,
`complete: false`), never silently. Environment tag and claim class are those of the run's wire (SITL loopback);
the archive adds no claim.
