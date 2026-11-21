# AegisFlight — Backend API

FastAPI app in `src/aegisflight/backend/app.py`, driven by the real-time
`LiveEngine` (`backend/engine.py`) over **one telemetry source chosen at startup**
(`backend/sources.py`). Start with `aegis serve` (default: the simulator on
`127.0.0.1:8000`). If `frontend/dist` exists it is served at `/`.

Every payload carries `environment` (`SIM` / `REPLAY` / `SITL` / `BENCH`) and
`sim` (true only for `SIM`), so a client can never present simulated or replayed
activity as live physical telemetry.

## Telemetry source (startup-only)

| `aegis serve --source …` | Reads | `environment` |
|---|---|---|
| `sim` (default) | in-process simulator (genuine MAVLink encode/decode); Stage-1 behaviour, ML on | `SIM` |
| `replay --tlog F [--replay-speed X]` | a repo-framed tlog (`>Q` unix µs + one frame), paced at X × capture time; finite | `REPLAY` |
| `serial --serial-port COM7 [--baud 115200] [--no-reconnect]` | `SerialMavlinkTransport` → `LiveMavlinkSource(origin="start")`, receive-only — the construction `scripts/hardware/run_serial_ids.py` uses | `BENCH` |
| `serial --serial-port socket://127.0.0.1:N --allow-url` | a loopback virtual port (tests, `scripts/hardware/virtual_serial_replay.py`) | `REPLAY` (never `BENCH`) |
| `udp --udp-port N` | `UdpMavlinkTransport` bound to `127.0.0.1:N`, passive (no GCS heartbeat) | `SITL` |

- The environment is **derived** from the source, never user-settable. `BENCH`
  means "an OS serial device was configured": it does not prove a physical
  board, and frame origin is not authenticated on an unsigned link. `SITL` is the
  operator's stated setup: the UDP sender is not verified.
- Common flags: `--config-dir D` (detector profile; default Stage-1 `configs/`),
  `--db PATH` (event store; default `artifacts/aegisflight_live.sqlite`).
- ML is simulation-only (the Stage-1 model does not transfer to real stacks); a
  non-SIM source has no firmware verifier (integrity `UNKNOWN`).
- `--no-reconnect` (serial): a port that cannot be opened is a source **error**
  (no ticks, so no "heartbeat never received" alerts for a port that never
  opened). Default: retried every 1 s, shown as `disconnected`, ticks continue
  and the detectors judge the silent link as they do in the runner.
- `aegis serve` exits 2 **before any server starts** on an invalid source (serial
  without a port, `socket://` without `--allow-url`, replay without an existing
  tlog, udp without a port) and on `--reload` or a non-loopback `--host` with any
  non-SIM source. It never falls back to SIM.
- The CLI hands the source to the app as `AEGIS_*` variables (`AEGIS_SOURCE`,
  `AEGIS_SERIAL_PORT`, `AEGIS_BAUD`, `AEGIS_ALLOW_URL`, `AEGIS_TLOG`,
  `AEGIS_REPLAY_SPEED`, `AEGIS_UDP_PORT`, `AEGIS_CONFIG_DIR`, `AEGIS_ML`,
  `AEGIS_RECONNECT`, `AEGIS_DB`, `AEGIS_SERVE_HOST`) and always sets all of them,
  so a stale shell variable cannot change the source. Running
  `uvicorn aegisflight.backend.app:app` directly reads the same variables (unset = SIM).
- **No endpoint can open, select or switch a source.** Nothing on a non-SIM path
  transmits: `transport.send` is never called (`link.transport.bytes_sent` stays 0).

## Link state — `link` (in `/api/status` and every WebSocket update)

Application-level health computed from the ticks. Display only: it is never fed
to the detectors. Ages are on the source's tick clock, so a dead live link (which
keeps ticking) shows growing ages instead of frozen "fresh" values.

| `state` | Meaning |
|---|---|
| `simulated` | SIM source |
| `waiting` | source open, no MAVLink frame received yet |
| `live` | last frame ≤ `stale_after_s` ago (`protocol.heartbeat_timeout_s`, 3.0 s) |
| `stale` | frames stopped on an open link: last frame > `stale_after_s` ago |
| `disconnected` | the transport reports `connected: false` (unplugged / unopenable port; `transport.open_failures` counts the retries) |
| `ended` | a finite source (replay) finished |
| `error` | the source failed; `link.error` = `"<ExcType>: <message>"` (home directory shown as `~`) |

Non-SIM precedence: `error > ended > disconnected > waiting > stale > live`.
Other fields: `frames`, `last_frame_age_s`, `stale_after_s`,
`messages{NAME: {count, age_s}}`, `transport` (the transport's own counters —
`connected, disconnects, reconnects, open_failures, crc_rejects, garbage_bytes,
frames_received, bytes_received, bytes_sent, write_errors, last_error_history,
bad_frames`; `null` for replay), `gps` (`fix_type, fix_name, satellites` (`null` = unknown: MAVLink `satellites_visible` 255),
valid_fix, gps_raw_age_s, position_age_s, position_zero`: the last raw report;
`valid_fix` applies the GNSS rule's thresholds to each report, whereas the rule
itself votes only after `gnss_loss_ticks` consecutive bad decisions), `error`.

## Exposure
Same-origin only. There is no CORS middleware (the Vite dev server proxies
`/api`, `/health` and `/ws`). `TrustedHostMiddleware` accepts only local Host
headers (`localhost`, `127.0.0.1`, `::1`, plus the operator's own `--host` for
SIM); a foreign Host gets HTTP 400. The WebSocket refuses (close code 1008) any
browser `Origin` that is not local, including `Origin: null`; a request without
an `Origin` (non-browser client) is allowed.

## REST

### `GET /health`
→ `{"status":"ok","version":"0.1.0","sim":false,"environment":"REPLAY"}`

### `GET /api/status`
Example (REPLAY of the BENCH capture 007 at its end; scratch run, 2026-10-20):
```json
{"running":true,"sim":false,"environment":"REPLAY",
 "source":{"kind":"replay","environment":"REPLAY","physical":false,
           "label":"Replay (recorded / virtual link)",
           "detail":{"tlog":"telemetry_radio_007.tlog","speed":1.0},
           "ml":false,"config_dir":"configs (Stage-1 default)"},
 "link":{"state":"ended","frames":1620,"last_frame_age_s":0.0,"stale_after_s":3.0,
         "messages":{"HEARTBEAT":{"count":60,"age_s":0.6}, "…":"…"},
         "transport":null,"error":null,
         "gps":{"fix_type":0,"fix_name":"NO_GPS","satellites":0,"valid_fix":false,
                "gps_raw_age_s":0.2,"position_age_s":0.2,"position_zero":true}},
 "sim_time_s":59.8,"uptime_s":102.3,"active_attack":null,"ml_available":false,
 "threat":true,"severity":"SUSPICIOUS","attack_type":"DOS","threat_score":0.6176,
 "integrity_status":"UNKNOWN","distance_m":0.0,"run_id":"replay-20261020-222114-1"}
```
`threat/severity/attack_type/threat_score` reflect the **last decision**. Before
the first decision `integrity_status` is `VALID` for SIM and `UNKNOWN` otherwise.
`sim_time_s` is the source's tick clock (replay / monitor time for non-SIM).

`checks` (in `/api/status` and every WebSocket update): `null` for SIM, else
`{"mission":{"known","xtrack_m","wp_seq"},"crossend":{"active","matched","mismatches","last_summary_age_s"},
"receiver":{"ekf_vel_var","ekf_pos_var","sat_jump","snr_spread"}}`, taken from the last feature frame and the
cross-end monitor; unavailable values are `null`. For non-SIM sources `telemetry` is exactly what the pipeline
received (no simulated twin) and every tick is broadcast.

### `GET /api/topology` (read-only)

The operator does not choose a topology; it is detected from how the software is connected. `POST /api/topology` was
removed (404/405). The same `topology_info` object is in `GET /api/status` and every WebSocket `update`; the bridge
status server (`GET /status`) carries it as `topology`. Legacy keys `topology` (`a`, `a+b`, `sim`, `replay`) and
`reasons` remain on this route.

```
"topology_info": {"kind": "A" | "A+B" | "SIM" | "REPLAY" | "UNKNOWN", "label": str,
  "source": "detected" | "modelled" | "none", "posture": "passive" | "advisory" | "active-ips",
  "links": {"fc": {"connected": bool|null, "name": str|null}, "gcs": {"connected": bool|null, "name": str|null}},
  "uplink_visible": bool|null, "can_block_frames": bool, "can_send_counter_commands": bool, "reasons": [str]}
```

- `A`: sidecar on one port (serial/UDP source). Sees only what the flight controller sends there; `uplink_visible`
  is true only once a ground-station frame (sysid in `expected_gcs_sysids`) or a COMMAND/SET_MODE was seen;
  never blocks frames; counter-commands only in `active-ips`.
- `A+B`: inline bridge. `can_block_frames` needs `active-ips` and both links connected; counter-commands need
  `active-ips` and the FC link.
- `SIM` is a modelled inline twin; `REPLAY` has no wiring. `reasons` state only what was observed.

### `GET /api/metrics`
```json
{"messages_processed":1620,"decisions":300,"alerts":15,"throughput_msgs_per_s":26.7,
 "decision_compute_ms":0.298,"last_latency_ms":0.298,"time_to_detect_s":null,
 "distance_m":0.0,"event_log":{"count":15,"chain_ok":true},"ml_available":false,
 "environment":"REPLAY"}
```
`alerts` = persisted alerts of the current run (= `event_log.count`);
`event_log.chain_ok` re-verifies the run's hash chain.

### `GET /api/events?limit=50`
The **current run's** alerts, newest first, read back from the event store
(`EventStore.get_events(run_id=…)`) — not an in-memory copy. `limit` must be
1–1000 (HTTP 422 otherwise). → `{"events":[…],"run_id":"…","source":{…},"count":N}`,
`count` = the run's total. Each event is the stored row plus the run's
`environment`:
```json
{"id":15,"run_id":"replay-20261020-222114-1","t":57.0,"wall_time":1792515132.507076,
 "attack_type":"DOS","severity":"SUSPICIOUS","threat_score":0.6176,"confidence":0.6176,
 "integrity_status":"UNKNOWN","latency_ms":0.4116,
 "evidence":["GNSS fix never acquired: fix_type=0, satellites=0 for 285 decisions (no valid fix since monitoring began)"],
 "detector_scores":{"protocol_rule":0.7,"physics_consistency":0.0,"ml_anomaly":0.0,"firmware_integrity":0.0},
 "contributing_detectors":["protocol_rule"],"telemetry":{"…":"…"},
 "prev_hash":"123ab164…8620","hash":"4edf65f7…8a35","environment":"REPLAY"}
```
`id` is the event-store row id. A run's source identity is recorded in the
store's `runs` table — `label` `<environment>-<kind>` (`live-demo` for SIM) and
`meta` = the source spec (a tlog by file name + sha256, never a local directory;
the USB identity of a physical port from the OS device list). The event schema
and hash canonicalisation are unchanged. Verify a run offline with
`aegis verify-log <db>`.

### `GET /api/config`
The configuration in use (a `--config-dir` profile, if any): `attacks`
(choices), `decision_rate_hz`, `sample_rate_hz`,
`fusion.{threat_threshold,weights,severity_bands}`, `home`.

### Simulation control (POST) — SIM only
| Route | Body | Effect |
|---|---|---|
| `/api/simulation/start` | — | start the live loop |
| `/api/simulation/stop` | — | pause the loop |
| `/api/simulation/reset` | — | stop loop → restore clean baseline → start a fresh run |
| `/api/simulation/attack` | `{"attack":"gps_spoofing"}` or `{"attack":"none"}` | inject / clear an attack at runtime |

Unknown attack → `400 {"ok":false,"error":…,"choices":[…]}`. With any non-SIM
source every route returns **409**
`{"ok":false,"environment":"BENCH","error":"… is simulation-only; the source is BENCH (read-only)"}`:
a real or replayed source cannot be started, stopped, reset (that would erase
detector memory) or attacked from the API.

**Reset semantics (SIM).** Reset returns the simulated vehicle to a known-good
baseline: it clears the active attack, **reflashes the simulated firmware fixture
to known-good bytes** (a tampered image is discarded, never re-trusted — see
`FirmwareVerifier.restore_fixture`), clears every extractor / detector / fusion
runtime state, and starts a **new run id** (its own hash chain). Historical audit
records from earlier runs are preserved. These endpoints are `async` so the
loop restart runs on the event loop.

Example:
```bash
curl -X POST localhost:8000/api/simulation/attack \
     -H 'Content-Type: application/json' -d '{"attack":"dos"}'
```

## WebSocket — `GET /ws/telemetry`
One JSON message per tick (~10 Hz):
```json
{"type":"update","sim":true,"environment":"SIM","source":{…},"link":{…},
 "run_id":"live-20261020-…","t":42.5,
 "telemetry":{"lat":19.13,"lon":72.91,"rel_alt":60.0,"groundspeed":12.0,
              "heading":135,"battery_voltage":23.2,"battery_remaining":67,
              "satellites":14,"flight_mode":"AUTO","armed":true},
 "attack_active":"gps_spoofing","distance_m":1234.5,
 "threat":{ /* present only on decision ticks (5 Hz) */
   "threat":true,"threat_score":0.76,"severity":"HIGH",
   "attack_type":"GPS_SPOOFING","confidence":0.76,"evidence":[…],
   "detector_scores":{…},"contributing_detectors":[…],
   "integrity_status":"VALID","latency_ms":0.4,"is_alert":true}}
```
A new subscriber first receives the latest update. When a finite source ends or
a source fails, one final update carries the `ended` / `error` link state (also
when no tick ever arrived). The dashboard's `useLiveData` hook consumes this
(auto-reconnect). Slow clients have frames dropped (bounded per-subscriber
queue), never blocking the engine. Client messages are never read.

## Lifecycle and threading
The engine starts with the app (FastAPI lifespan). On shutdown it stops the
loop and the source thread, closes the transport (port released) and closes the
event store. A non-SIM source runs in a background thread (`LiveFeed`); its
ticks reach the event loop through an unbounded FIFO (none dropped or reordered:
the decision cadence is tick-count based) and go through the same
`IDSPipeline.process_tick` as the benchmark and `run_serial_ids.py`. Event-store
reads (`/api/events`, `/api/metrics`) run on the event-loop thread, the same
thread that appends the alerts.

## Status
- All endpoints above are implemented. Tested with SIM, REPLAY tlogs and
  loopback virtual serial ports (`tests/integration/test_app_live_source.py`,
  `tests/unit/test_cli_serve.py`, `backend/tests/test_api.py`). The serial
  source has **not yet been run against the physical board through the
  dashboard** — the pending gate is `docs/HARDWARE_BENCH_PIXHAWK6X.md` §6.10.
- SIM data is a simulation. A BENCH source is receive-only bench telemetry, not
  flight data, and its alerts describe that link (see `docs/DETECTION.md`).

## Remote bridge (`bridge_remote`, `POST /api/bridge/posture`)

`GET /api/status` and every WebSocket update carry `bridge_remote`, decoded from the in-band management frames of the live
radio stream (sysid 1, compid 191/192; `docs/MGMT_CHANNEL.md`):
`{"present", "age_s", "posture", "topology", "state", "flags": {"signing", "analyser_ok", "fc_link", "gcs_link", "contested",
"unsigned_ack", "control_enabled"}, "counters": {"forwarded", "dropped_up", "alerts", "counter_frames", "hook_errors"},
"last_alert", "last_action", "last_command": {"op", "result": "accepted|denied|confirm_required|timeout|failed|pending",
"detail", "age_s"} | null, "control_available", "recent": [{"t", "text"}] (last 20), "authenticated"}`. `present` is false (and the
rest empty) for SIM, replay, or when nothing was heard for 10 s. `authenticated` is true only with `--signing-key-file`.

`aegis serve --mgmt-key-file PATH` (32-byte key, separate from the flight key) enables control: `control_available` is true only
with that key AND a live transport the bridge may write to: UDP or a `socket://` URL. A serial OS device
(`COM7`, `/dev/ttyACM0`, a PTY) is receive-only (`may_reach_vehicle()`): it may be the flight controller itself, so
`control_available` is false there and the route returns 403. `POST /api/bridge/posture` body `{"mode": "passive|advisory|active-ips",
"allow_unsigned"?: bool, "confirm"?: bool}` builds and signs the command, sends it on the live transport and returns
`{"ok": true, "pending": true}`; the bridge's COMMAND_ACK updates `last_command`. Errors: `400` bad body, `403
control_unavailable` (no management key, or replay/SIM/no transport), `409 signing_required` (same wording as
`/api/defense/mode`; when the BRIDGE reports no signing key and `allow_unsigned` is not true), `502 send_failed`. Lowering from
`active-ips` is two-step: the first call yields `last_command.result == "confirm_required"`, repeat with `"confirm": true`
within 10 s. The usual origin / `AEGIS_API_TOKEN` checks apply.

**Per-posture wire guarantees (`#58`):**
- **`passive` (default):** Strict zero-TX on both `fc` and `gcs` links (`0` bytes sent, `0` frames consumed or dropped). On the bridge, the in-band management channel (`compid 191/192`), `crossend`, and `STATUSTEXT` advisories are silent unless `--mgmt-enable` is explicitly passed (so remote promotion out of `passive` via `POST /api/bridge/posture` requires the bridge to be started with `--mgmt-enable`). On `aegis serve`, `--gcs-notify` (`GcsNotifier` UDP `STATUSTEXT`) is suppressed while `defense_mode == "passive"` and resumes automatically when promoted to `advisory` or `active-ips`.
- **`advisory`:** Zero bytes transmitted and zero policy drops on the `fc` link; `STATUSTEXT` alerts and management telemetry are emitted on the `gcs` side only (without duplicate `STATUSTEXT` frames per alert).
- **`active-ips`:** Refused on any physical/OS serial device (`may_reach_vehicle()`); requires `--signing-key-file` (or explicit `--allow-unsigned`) and only drops frames or sends corrective commands when explicitly in `active-ips`.

## Signing gate (`/api/defense/mode`)

`GET /api/status` and every WebSocket update carry `signing: {"configured": bool}` (true when `aegis serve` got
`--signing-key-file`; counter-frames are then signed) and `unsigned_acknowledged`. `POST /api/defense/mode` accepts an
optional boolean `allow_unsigned`. For a non-SIM source, `active-ips` without a key and without `allow_unsigned: true`
returns `409 {"ok": false, "error": "signing_required", "message": ..., "signing": {"configured": false}}`. SIM, `passive`
and `advisory` are never gated. The bridge's own `POST /posture` is documented in `docs/INLINE_IPS.md`.

## End-to-End Request Signing, Replay Protection & Bench Setup Gate (W9–W13)

- **Security Headers & Signed Control Requests:** All responses carry CSP (`default-src 'self'`),
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and `Cache-Control: no-store` on `/api/*`.
  When `AEGIS_API_TOKEN` is configured, control requests are authenticated by a canonical HMAC-SHA256 signature
  (`X-Aegis-Key-Id`, `X-Aegis-Nonce`, `X-Aegis-Timestamp`, `X-Aegis-Signature`); the raw token is not sent when the
  browser can sign. Each nonce is single-use inside a bounded `60 s` replay cache (recorded only after the signature
  verifies) with per-client authentication lockout (`429 Retry-After`). `AEGIS_REQUIRE_SIGNED_API` defaults to ON when a
  token is set; `AEGIS_REQUIRE_SIGNED_API=0` is the compatibility switch that re-allows legacy token-only clients
  (`X-Aegis-Token` / `Bearer`). Signing needs Web Crypto (https or localhost); without it the console sends the token
  header to loopback origins only and refuses other origins. `VITE_AEGIS_API_TOKEN` is dev-server only: production builds
  fail if it is set. **Limits:** over plain HTTP the signature stops replay and tampering but not eavesdropping on the
  request itself, and nothing here protects the response; use loopback or TLS for anything beyond a bench.
- **Forensic Export & Field Drills:**
  - `GET /api/forensic/report?format=json|html` returns hash-chain-verified event/action/anchor reports.
  - `POST /api/drill/run` executes zero-TX shadow verification drills (`DRILL_SCENARIOS`).
- **Loopback + Disarmed Bench Setup Gate:** `/api/setup/discover-ports` (0 B TX), `/api/setup/preflight`, `/api/setup/generate-config`, and `/api/setup/enroll-firmware` require both a local loopback peer AND a disarmed vehicle (`409 vehicle_armed` in flight).

## Endpoint authentication matrix

Authentication classes: **none** (no credential; the Host header is still restricted to local names), **token**
(`_require_control_auth`: Origin allow-list, lockout, then a valid credential when `AEGIS_API_TOKEN` is set; with no token
configured the route is open), **bench gate** (token **plus** loopback TCP peer **plus** disarmed vehicle). "Console" columns
show what the React console sends when a token is configured: **T+S** = raw `X-Aegis-Token` plus timestamp/nonce/HMAC (if
Web Crypto exists), **S** = key-id/timestamp/nonce/HMAC only (no raw token), **-** = nothing.

| Method | Path | Auth | Console on #82 | Console with #90 | Console with #93 |
|---|---|---|---|---|---|
| GET | `/health` | none | - | - | - |
| GET | `/api/status` | none | - | - | - |
| GET | `/api/metrics` | none | - | - | - |
| GET | `/api/events` | none | - | - | - |
| GET | `/api/events/forensic` | none | - | - | - |
| GET | `/api/config` | none | - | - | - |
| GET | `/api/forensic/report` | none (reads the whole report; see note 1) | - | - | - |
| GET | `/api/topology` | none | - | - | - |
| WS | `/ws/telemetry` | none (browser Origin must be local) | - | - | - |
| GET | `/` and static files | none | - | - | - |
| POST | `/api/simulation/start` | token | T+S | T+S | S |
| POST | `/api/simulation/stop` | token | T+S | T+S | S |
| POST | `/api/simulation/reset` | token | T+S | T+S | S |
| POST | `/api/simulation/attack` | token (+ SIM only) | T+S | T+S | S |
| POST | `/api/defense/mode` | token | T+S | T+S | S |
| POST | `/api/defense/override` | token | T+S | T+S | S |
| POST | `/api/bridge/posture` | token | T+S | T+S | S |
| POST | `/api/drill/run` | token | T+S | T+S | S |
| GET | `/api/setup/discover-ports` | bench gate | **- (401 when a token is set)** | T+S | S |
| POST | `/api/setup/preflight` | bench gate | T+S | T+S | S |
| POST | `/api/setup/generate-config` | bench gate | T+S | T+S | S |
| POST | `/api/setup/enroll-firmware` | bench gate | T+S | T+S | S |

Without Web Crypto (plain `http://` on a non-loopback host): #82 and #90 send the raw token header only; #93 refuses to send
anything to a non-loopback origin and, on loopback, sends the raw token header, which the default (signed-required) backend
rejects with 401 unless `AEGIS_REQUIRE_SIGNED_API=0`. `http://localhost` and `http://127.0.0.1` are secure contexts, so this
path is rare in practice.

Notes: (1) every unauthenticated GET is readable by any process that can reach the port; keep `aegis serve` on loopback (the
default). (2) The signature covers method, path (not the query string), timestamp, nonce and body, not the `Origin` or `Host`
headers. (3) The replay cache is in memory: a backend restart empties it, and it keeps at most 4096 nonces, so a flood of
valid requests can evict old ones inside the 60 s window. Replay protection is best-effort on a bench link, not a guarantee.

### Non-browser clients

| Client | What it calls | Credential it sends | Current backend | #93 default | #93 with `AEGIS_REQUIRE_SIGNED_API=0` |
|---|---|---|---|---|---|
| `scripts/verify_stage2.py` (suite 7, in-process `TestClient`) | `POST /api/defense/mode` | before the signing fix: raw `X-Aegis-Token`; after: key-id, timestamp, nonce, HMAC and token (`aegisflight.backend.client_auth.signed_headers`) | works / works | **before: 401, after: works** | works / works |
| `scripts/ardupilot/inline_demo/mgmt_drive.py` | `GET /api/status`, `/api/events`; `POST /api/bridge/posture` on the GCS (`:8104`) | before: none (the GCS is started without a token); after: signed when `AEGIS_API_TOKEN` is exported | works (no token set) | works (no token set) | works |
| `mgmt_drive.py` posts to the bridge (`:8090/posture`) | the Pi bridge status server, **not** this backend | raw `X-Aegis-Token` (bridge's own token) | unchanged | unchanged | unchanged |
| `tests/unit/test_mitigation.py`, `tests/unit/test_mgmt_channel.py` | `POST /api/defense/mode`, `/api/bridge/posture` | raw `X-Aegis-Token` | works | 401 unless the test sets the compat switch (it does on #93) | works |
| `tests/unit/test_backend_command_security.py` | control routes | raw token + signature, and signed-only on #93 | works | works | works |
| `curl` examples in `docs/API.md`, `docs/DEMO_SCRIPT_SOFTWARE_ONLY.md` | `POST /api/simulation/attack` | none (valid only when no token is configured) | works without a token | works without a token | works without a token |
| `deploy/bench/docker-compose.yml` | none (runs `field-drill` and the soak in-process) | sets `AEGIS_API_TOKEN` but makes no HTTP calls | n/a | n/a | n/a |
| Any third-party `curl`/script sending `X-Aegis-Token` or `Bearer` only | control routes | raw token | works | **401** | works |
