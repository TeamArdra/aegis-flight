# In-band management channel (telemetry radio)

On a cheap drone (flight controller + GPS + telemetry radio + a small companion computer) the radio is the ONLY link
to the ground. `aegis ips-bridge` therefore reports to the ground station, and takes a few signed controls, over
that same radio using only standard MAVLink 2 messages (no dialect change). Code: `src/aegisflight/hal/mgmt_channel.py`
(both ends), wired in `hal/inline_ips.py`; ground side `backend/bridge_remote.py`. Tests: `tests/unit/test_mgmt_channel.py`
(synthetic frames and in-memory links; the later runs over the real LR900 radio pair and on a Pi are in `docs/RADIO_TEST_RESULTS.md`).

All bridge frames are sent from **sysid 1 / compid 191** to the **GCS side only**: never to the flight controller,
never to the bridge's tap/detectors, in every posture (passive / advisory / active-ips). The channel is **on by default**
(`--gcs-alerts on`, status every 2 s), so even in `passive` the bridge transmits on the GCS side and is not a byte-transparent
link there; and every uplink COMMAND_LONG `MAV_CMD_USER_1` addressed to component 191 is consumed by the bridge (never
forwarded to the flight controller), signed or not, with or without a management key. Component 191 is the standard
`MAV_COMP_ID_ONBOARD_COMPUTER`, so such a command meant for a real companion computer behind the bridge would not reach it. The ground IDS already treats
sysid 1 as the vehicle (the cross-end summary uses the same sender); a test runs the ground pipeline over a stream with
these frames and expects no alert and no sequence gap (the cross-end summary and this channel share ONE sequence
counter and signer for the 1/191 stream).

## Messages

| Direction | Message | Content |
|---|---|---|
| bridge -> ground | STATUSTEXT (253) | `AEGIS: COMMAND_INJECTION HIGH sys66` (alert), `AEGIS: blocked DO_SET_MODE(LAND) sys66 x3` (the drop label is the MAV_CMD or message name; a forged mode change also names the requested ArduCopter mode), `AEGIS: set ALT_HOLD (GPS fault)`, `AEGIS: quarantine sys42`, `AEGIS: posture ACTIVE_IPS`, `AEGIS: cmd denied: ...`, `AEGIS: mgmt bad signatures x5+ (ignored)`. <= 50 bytes. Severity: CRITICAL 2, HIGH 3, SUSPICIOUS 4, WATCH 5 (actions 5, drops 4) |
| bridge -> ground | MEMORY_VECT (249) | status, marker address `0xAE57` / ver 1 / type 1 (the cross-end summary is `0xAE15` / 1 / 0), 32-byte payload below |
| ground -> bridge | COMMAND_LONG (76) | `MAV_CMD_USER_1` (31010), target_system = vehicle sysid, target_component = 191 |
| bridge -> ground | COMMAND_ACK (77) | answer to the command |

Status payload (v1, little endian, byte 31 = CRC8 poly 0x07 over bytes 0-30): `0` version, `1` posture (0 passive, 1 advisory,
2 active-ips), `2` topology (0 unknown, 1 A, 2 A+B), `3` controller state (index of NOMINAL, AUTO_MITIGATING, SAFE_HOLD,
GCS_TAKEOVER), `4-5` flags (bit0 signing configured, 1 analyser healthy, 2 FC link up, 3 GCS link up, 4 contested source,
5 unsigned acknowledged, 6 control enabled), `6-9` forwarded u32, `10-11` dropped_up, `12-13` alerts, `14-15` counter_frames,
`16-17` hook_errors (u16, all saturating), `18` last alert class (AttackType index, 0 none), `19` its severity (0 none ... 4
CRITICAL), `20-21` seconds since the last action (0xFFFF never), `22` status sequence, `23-30` reserved zeros. A frame with a
wrong size, bad CRC8, unknown version or another marker is ignored by the decoder.

Command: `param1` op (1 set posture, 2 acknowledge alarms / clear the contested marker, 3 request status now), `param2` posture
(0 passive, 1 advisory, 2 active-ips), `param3` allow_unsigned (1 = operator explicitly acknowledged the unsigned-link risk),
`param4` confirm token. ACK: `ACCEPTED`; `DENIED` (reason in `result_param2`: 1 control disabled, 2 locked out, 3 rate limited,
4 flight signing required, 5 posture locked, 6 bad parameter); `UNSUPPORTED` (unknown op); `FAILED`; `IN_PROGRESS` (confirm
required: `result_param2` = token, `progress` = 10 s).

## Byte budget

ONE token bucket over ALL management traffic (`--mgmt-max-bytes-per-s`, default 150 B/s, bucket = max(2 x rate, 200) bytes).
Priority: COMMAND_ACKs and CRITICAL alerts may drain the bucket (a CRITICAL or ACK that does not fit is queued, max 8, 10 s);
other alerts/actions must leave 25 % of the bucket, status leaves 50 %, so status goes last and a flood cannot starve an ACK.

Frame sizes (MAVLink 2, trailing zero bytes trimmed): STATUSTEXT 21-63 B (typical 48), MEMORY_VECT status 48 B, COMMAND_ACK 22 B;
add 13 B for the signature (flight key on alerts/status, management key on ACKs).

* **Worst case**: bytes sent in any window of T seconds <= 300 + 150 x T, so **150 B/s sustained** (2.6 % of the ~5760 B/s of
  a 57,600 baud 8N1 radio), plus the 300 B initial burst. Asserted in `test_worst_case_bytes_per_second_is_bounded_by_the_budget`.
* **Nominal** (idle, signed): one 61 B status per 2 s = ~30 B/s. Alerts are further limited per attack type
  (`--alert-min-interval`, default 2 s, escalation to a higher severity bypasses), by a global message bucket (5 burst,
  1/s) and drops are aggregated per second and label (counts, not one message per frame).
* The cross-end summary (`--crossend-interval`, default 1 Hz, 61 B signed) is NOT inside this budget: with it the bridge adds at
  most ~211 B/s (3.7 % of 57,600 baud) in the worst case. Radio-side firmware overhead (FEC, MAVLink forwarding by the FC) is not modelled.

Options (`aegis ips-bridge`): `--gcs-alerts on|off` (alert/action STATUSTEXTs; status, ACKs, posture and lockout notices stay),
`--alert-min-interval S`, `--mgmt-status-interval S` (default 2.0, 0 = off; the existing `--status-interval` still only paces
the local JSON status line), `--mgmt-max-bytes-per-s N`, `--mgmt-key-file`, `--mgmt-state`, `--lock-posture-file`, `--audit-log`.

## Control authentication and rules

* The command frame MUST carry a valid MAVLink 2 signature made with a **separate management key** (`--mgmt-key-file`, 32 raw
  bytes or 64 hex; independent of the flight key, because the flight controller never sees these frames). No management key =
  control disabled: every command is answered DENIED (unsigned) and nothing executes.
* Strictly increasing signature timestamp per stream, AND newer than the last command executed on any stream; both are persisted in
  `--mgmt-state` BEFORE a command runs, so a restart does not reopen a replay window. `ips-bridge` refuses `--mgmt-key-file`
  without `--mgmt-state`. A command signed more than `--mgmt-max-age-s` (default 300 s) before the bridge's wall clock is ignored
  as a replayed recording; this check is skipped while the bridge clock is unset (before 2025), so an unset Pi clock never
  rejects. (Keep the ground clock sane: a ground station whose clock is behind the persisted state is rejected as a replay.)
* At most 1 command per second (others DENIED). Unauthenticated frames (wrong key, unsigned, truncated, replayed) get no ACK and
  NEVER lock out a validly signed command: 5 of them in 60 s raise one `AEGIS: mgmt bad signatures` alarm per 60 s (counted as
  `lockouts`, audited). An earlier version locked control for 60 s instead; that let anyone with a radio keep the pilot's control
  locked with 5 unsigned frames a minute (review finding M7), so it was removed.
* Boot quiet (see `docs/INLINE_IPS.md`): GPS_SPOOFING / DOS announcements (any severity) are held for the first 20 s while
  disarmed; every other class is always announced, and arming ends the window.
* Raising to `active-ips` needs the flight signing key configured on the bridge OR `param3 == 1` (same gate as the HTTP API).
* Lowering from `active-ips` is two-step: the first valid command answers IN_PROGRESS with a token, the same command with that
  token (param4) within 10 s executes (a wrong, expired or other-posture token just returns a new token). advisory -> passive is one step.
* `--lock-posture-file PATH`: while the file exists remote commands can only RAISE the posture (local physical override).
* Consumed, never forwarded: the bridge drops these frames before the tap and the policy (they are the only uplink frames it
  withholds in passive/advisory) and never sends them to the FC.
* **Audit log** (`--audit-log`, JSONL): every accepted / denied / ignored command, lockout and posture change; each line carries the
  sha256 of the previous line, so an edited, removed or inserted line breaks the chain (`verify_audit_log`; a cut tail is not
  detectable). Never contains keys or confirm tokens.

## Ground side

`aegis serve --source serial|udp [--signing-key-file F] [--mgmt-key-file M]` taps the raw radio stream, decodes sysid 1 / compid
191-192 frames and exposes `bridge_remote` in `GET /api/status` and every WebSocket update, and `POST /api/bridge/posture`
(see `docs/API.md`). Without `--signing-key-file` the displayed alerts/status are UNAUTHENTICATED (anyone on the radio can forge
them; `bridge_remote.authenticated` is false). ACKs are believed only when they verify with the management key.

## What it cannot do

No process control (start/stop/restart the bridge), no configuration changes, no key provisioning or rotation, no change of
signing enforcement, no log retrieval, no firmware or parameter access. Keys and configuration are provisioned at the bench.
If the bridge process dies the channel is gone too (see `docs/MINIMAL_BUILD.md`). A jammed or cut radio silences it. The
STATUSTEXT/MEMORY_VECT frames of an UNSIGNED link can be forged or suppressed by whoever can transmit on the radio; with a flight
key the ground rejects unsigned or invalid ones.

## Component 191: identity and collision check

The bridge speaks as sysid 1 / compid 191 (`MAV_COMP_ID_ONBOARD_COMPUTER`, `MGMT_COMPID` in `hal/mgmt_channel.py`) and consumes
every `MAV_CMD_USER_1` COMMAND_LONG addressed to component 191, in every posture, signed or not. Checked on 2026-11-18:

- In this repository nothing else uses component 191. `gcs_compids: [190, 191, 200]` in `configs/detector.yaml` /
  `config.py` lists 191, but no code reads that key; `backend/bridge_remote.py` and the radio tools filter 191/192 as the
  bridge's own stream. There is no actual collision in the shipped code or SITL setups.
- Deployment constraint (not enforced in code): do not run another onboard component at compid 191 that uses
  `MAV_CMD_USER_1` (for example a MAVROS / mavlink-router / companion app configured with that id) behind the bridge; its
  commands would be consumed by the bridge and never reach it.

## SITL evidence

Harness (`scripts/ardupilot/inline_demo/`): `run_mgmt.sh <label> on|off`, `mgmt_drive.py` (driver), `hub_mgmt.py` (loopback hub with
a per-second byte meter that separates the management stream, sysid 1 / compid 191, from flight telemetry, and a read/write port
5803 for the ground dashboard), `fc_tap.py` (a counting tap on the bridge-to-FC link). ArduCopter SITL, UNSIGNED flight link
(`--allow-unsigned`), separate management key, ground `aegis serve --source serial` on the hub. The `on` run was done 4 times
(1 early run was discarded: my driver sent two commands within 1 s and hit the rate limit); the table is the last 3 (v2-v4),
which agree unless a range is given. One `off` reference run (`--mgmt-status-interval 0 --gcs-alerts off`, no keys).

| Test | Result (single SITL run each, repeated as noted) |
|---|---|
| (a) forged LAND (DO_SET_MODE + SET_MODE to mode 9) from sysid 66, active-ips | ground `bridge_remote.recent` showed `AEGIS: COMMAND_INJECTION SUSP sys66` after 0.1-0.2 s and `blocked DO_SET_MODE(LAND) sys66 xN` after 0.7-0.8 s; status age 1.1-1.4 s; posture, counters (`dropped_up`, `alerts`) and flags matched the bridge's own `/status` |
| (b) same attack in `passive` | alert arrived; the forged frames reached the FC as designed for passive; `fc_tap` saw 0 frames from 1/191, 0 MAV_CMD_USER_1, 0 `AEGIS` STATUSTEXT, 0 MEMORY_VECT sent to the FC in that window |
| (c) control from the ground | passive -> advisory -> active-ips (`allow_unsigned`) accepted (0.2-0.3 s to the ACK); active-ips -> passive: first call `confirm_required`, second with confirm accepted; lowering with the lock file present: denied "posture locked"; wrong-key frames x3: no ACK; a byte-identical replay of a valid command: no ACK; 3 valid commands within 150 ms: 1 accepted, 2 DENIED rate-limited; 5 wrong-key frames: `AEGIS: mgmt control LOCKED` announced, a valid command during the lock DENIED (locked); after 60 s a valid command was accepted again (this run used the earlier lock-out behaviour, since removed; see above) |
| (d) audit log | hash chain verified, 20 entries (4 posture changes, 7 accepted, 4 denied, 1 confirm-required, 3 ignored bad-signature lines, 1 lockout; bad-signature lines are audited at most 1/s, the total is a counter) |
| (e) bytes/s at the hub (management stream only) | nominal 24 B/s (one unsigned 48 B status per 2 s; signed it is 61 B per 2 s); 15 s forged-command flood at 20 Hz x2: 133.5-133.6 B/s averaged over the 18 s window (2403-2405 B; peak 1 s 204-247 B, which is the 300 B initial bucket); whole run 41 B/s. The worst-case bound 300 + 150 T B held. The cross-end summary (not in the budget) added a separate 35-37 B/s |
| (f) flight telemetry unaffected | forced forged flood: forwarded_down 2461 vs 2464, dropped_up 590 vs 590 (on vs off); other downlink 4786 vs 4764 B/s nominal, 4793 vs 4777 B/s in the flood; the pilot's 28 (on) / 10 (off) mode commands were all ACKed; the ground IDS stored 0 events in on and off runs (management frames in all postures, a ground restart included), no sequence-gap alarm |
| (g) management link lost (ground `aegis serve` killed ~15 s) | bridge stayed in active-ips and kept blocking (dropped_up 606 -> 622 during the outage); management frames kept being sent (no listener); after the dashboard restart the alert arrived again (status age 0.9 s), posture still active-ips |

Bugs found and fixed here: an announced drop of a forged mode change said only `blocked DO_SET_MODE` (the examples in this doc said
`blocked LAND`, which only a real MAV_CMD_NAV_LAND produces); the label now names the requested mode (`hal/mgmt_channel.py`,
regression test `test_dropped_mode_change_label_names_the_requested_mode`).

Design limits seen: two operator commands within 1 s: the second is DENIED (rate limited), the dashboard does not queue them; in
these runs a replayed or wrong-key frame counted toward a 5-frame lock-out, so whoever could transmit on the radio could lock the
ground out of control for 60 s. That lock-out has since been removed (review finding M7, see the control rules above):
unauthenticated frames now raise at most one `AEGIS: mgmt bad signatures` alarm per 60 s and never block a validly signed command,
and the 1-per-second rate limit is applied only after the signature check (unit tests
`test_five_bad_signatures_raise_an_alarm_but_never_lock_out_a_valid_command`,
`test_an_unsigned_flood_does_not_stop_the_pilots_signed_command`; not re-run in SITL); with `--gcs-alerts off` one `posture`
notice is still sent; the active-ips
counter-frames to the FC (COMMAND_LONG from 1/191) are the IPS's own mitigation, not management traffic, and their number differs
between runs.

What this does and does not show: single runs on a simulated autopilot (ArduCopter SITL), a loopback TCP hub (no radio, no
latency, loss, jamming or 57,600 baud limit: the bytes/s are counted bytes, not airtime), one pilot script and one attacker script
instead of real ground-station software, an unsigned flight link (the signed-alert path with `--signing-key-file` was not run
here), one machine and clock. It does not show behaviour under packet loss, real companion-computer load, long soak runs, or
authentication strength beyond the cases listed. Later (2026-10-31): the management channel was also run over the real LR900 pair, with a real Pixhawk 6X on a Raspberry Pi 5 (disarmed): posture commands, bad-frame cases and ACK signatures passed, and nominal management traffic was 81.8 B/s against the 150 B/s budget. The flood-window bytes, alert latency, status age and ACK latency for that run are not recorded (`docs/RADIO_TEST_RESULTS.md`).
