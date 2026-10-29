# In-band management channel (telemetry radio)

On a cheap drone (flight controller + GPS + telemetry radio + a small companion computer) the radio is the ONLY link
to the ground. `aegis ips-bridge` therefore reports to the ground station, and takes a few signed controls, over
that same radio using only standard MAVLink 2 messages (no dialect change). Code: `src/aegisflight/hal/mgmt_channel.py`
(both ends), wired in `hal/inline_ips.py`; ground side `backend/bridge_remote.py`. Tests: `tests/unit/test_mgmt_channel.py`
(synthetic frames, in-memory links; nothing measured on a radio or a companion computer).

All bridge frames are sent from **sysid 1 / compid 191** to the **GCS side only**: never to the flight controller,
never to the bridge's tap/detectors, in every posture (passive / advisory / active-ips). The ground IDS already treats
sysid 1 as the vehicle (the cross-end summary uses the same sender); a test runs the ground pipeline over a stream with
these frames and expects no alert and no sequence gap (the cross-end summary and this channel share ONE sequence
counter and signer for the 1/191 stream).

## Messages

| Direction | Message | Content |
|---|---|---|
| bridge -> ground | STATUSTEXT (253) | `AEGIS: COMMAND_INJECTION HIGH sys66` (alert), `AEGIS: blocked LAND sys66 x3`, `AEGIS: set ALT_HOLD (GPS fault)`, `AEGIS: quarantine sys42`, `AEGIS: posture ACTIVE_IPS`, `AEGIS: cmd denied: ...`, `AEGIS: mgmt control LOCKED 60s (bad signatures)`. <= 50 bytes. Severity: CRITICAL 2, HIGH 3, SUSPICIOUS 4, WATCH 5 (actions 5, drops 4) |
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
* Strictly increasing signature timestamp per stream; the last timestamps are persisted in `--mgmt-state` BEFORE a command runs, so
  a restart does not reopen a replay window. (Keep the ground clock sane: a ground station whose clock is behind the persisted
  state is rejected as a replay.)
* At most 1 command per second (others DENIED). 5 bad-signature (wrong key, unsigned, truncated, replayed) frames in 60 s lock
  control for 60 s; this is counted, announced (`AEGIS: mgmt control LOCKED`) and audited. Bad-signature frames get no ACK.
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
