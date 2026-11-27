# AegisFlight — Frontend

A single-page **Vite + React + TypeScript** dashboard (`frontend/`), no UI or
charting libraries — inline SVG + CSS, so it builds small and self-contained
(~155 kB JS gzip 50 kB). Builds to `frontend/dist`, which the FastAPI backend
serves at `/`.

## Structure
```
frontend/src/
├── main.tsx                 React root
├── App.tsx                  layout: 3-column grid + metrics bar + footer
├── index.css                dark "security-ops" theme (CSS variables)
├── types/index.ts           TS mirrors of backend payloads
├── services/api.ts          REST client + wsUrl()
├── hooks/useLiveData.ts     WebSocket stream + REST polling → state
└── components/
    ├── Header.tsx           title, SIMULATION badge, connection, sim clock, ML
    ├── panels.tsx           ThreatPanel, DetectorPanel, EvidencePanel, TelemetryPanel
    ├── MapPanel.tsx         SVG position track + threat-score sparkline
    ├── AlertsPanel.tsx      event history list
    └── ControlPanel.tsx     start/stop/reset + attack-injection buttons
```

## Data flow
`useLiveData` opens `ws://<host>/ws/telemetry` (auto-reconnect) and updates:
- `telemetry` and `attackActive` every tick (10 Hz),
- `threat`, a `scoreHistory` sparkline buffer, and a `track` buffer on decision
  ticks (5 Hz).
It also polls `/api/events` and `/api/metrics` every 2 s for the event history
and the bottom metrics bar. `ControlPanel` POSTs to `/api/simulation/*`.

## What's backend-derived vs UI-only
- **Backend-derived (live):** all telemetry values, threat state/score/severity,
  attack class, confidence, evidence, detector scores, latency, integrity status,
  alerts, metrics.
- **UI-only:** the self-scaling of the position track (converts lat/lon to a
  local metric frame for display), colour/severity styling, sparkline buffering.
No mock/demo data — every number comes from the backend.

## Components (props → data)
| Component | Props | Source |
|---|---|---|
| `Header` | connected, simTime, mlAvailable | WS + metrics |
| `ThreatPanel` | threat | WS `threat` |
| `DetectorPanel` | threat.detector_scores | WS |
| `EvidencePanel` | threat.evidence | WS |
| `TelemetryPanel` | telemetry | WS |
| `MapPanel` | track, scoreHistory, threat | WS-derived buffers |
| `AlertsPanel` | alerts | `/api/events` |
| `ControlPanel` | activeAttack | posts to `/api/simulation/attack` |

## Dev vs build
- **Build:** `npm run build` (`tsc --noEmit && vite build`) → `dist/`.
- **Dev:** `npm run dev` on :5173; `vite.config.ts` proxies `/api`, `/health`,
  `/ws` to the backend on :8000 (no CORS friction).
- `wsUrl()` derives ws/wss from `location`, so the same code works in dev
  (proxied) and when served by FastAPI (same-origin).
- `aegis serve` serves the untracked local `frontend/dist`; rebuild it after any UI change.
- Each build writes `build-info.json` (schema 2: UI source hash, commit, dirty flag, build time and a sha256
  manifest of every emitted file; served at `/build-info.json`).
  `node frontend/scripts/provenance.mjs --check frontend/dist` fails (non-zero exit, message on stderr) when the
  directory or `build-info.json` is missing or malformed, the bundle was built from a different UI source than the
  current checkout, any emitted file is missing, extra or modified after the build (including a bundle with no
  `index.html` or JS), or a file contains banned overclaim wording. The commit and dirty flag are informational:
  the source hash is the contract. A pass is an **integrity check only** (which UI source this bundle came from); it is
  not evidence of detection performance and the UI/backend never present it as such.
- After pulling a change to `frontend/`, rebuild the untracked local bundle and verify it:
  `npm --prefix frontend ci && npm --prefix frontend run build && node frontend/scripts/provenance.mjs --check frontend/dist`.
  A `dist` built before schema 2 (or before #183) fails the check until rebuilt.
- The Integration and Validation Evidence panels are static reference copy (`src/lib/evalCopy.ts`, shown in demo mode
  only). The dashboard displays no campaign or trial results; every figure in the Validation panel is quoted from a
  committed artifact with its environment tag and claim class, and `tests/evalCopy.test.ts` pins each figure to
  that artifact.

## Simulation labelling
The header shows a persistent **● Simulation** badge and the footer states all
data/attacks are local simulations — simulated attacks must never look like a
real UAV under attack.

## Running against a live link / the desktop app

Start the backend on the CLI default port with the source you want (see `aegis serve --help`), e.g. `aegis serve --port 8000 ...`, then:

- **Browser dev server** (`npm run dev`, :5173) proxies `/api`, `/health`, `/ws` to `VITE_BACKEND_PORT` (default 8000).
- **Backend URL** resolution, first match wins: `window.__AEGIS_BACKEND__`, localStorage `aegis_backend_url`, build-time `VITE_BACKEND_URL`, inside the Tauri desktop app `http://127.0.0.1:8000`, otherwise same-origin. Set or clear it from the header **Settings** button (http/https URLs only; the page reloads to reconnect). The WebSocket scheme follows the URL scheme.
- **Inline IPS bridge**: enter the bridge status URL (e.g. `http://127.0.0.1:<port>`; localStorage `aegis_bridge_url`) in Settings. The dashboard polls `<url>/status` every 2 s and shows an "Inline IPS bridge" panel (hidden when unset, "unreachable" on error).
- For REPLAY/SITL/BENCH sources the flight track shows only the as-received positions (no protected/ghost overlay), ignores invalid fixes (null, NaN, out of range, 0/0, receiver reports no fix) and shows "NO POSITION FIX" until a valid one arrives. The origin is the first valid fix of the run. A "Checks" panel shows mission cross-track, cross-end matches/mismatches and receiver EKF/satellite health.

## Active IPS confirmation and bridge posture control
- Switching to ACTIVE IPS on a non-SIM source (Defense panel or Inline IPS bridge panel) opens `ActiveIpsDialog`. It explains that the monitor sends counter-commands (the bridge also drops hostile frames) and shows `Signing: configured` or `Signing: NOT configured`. Unsigned links also show the risk text and require "I understand — proceed unsigned", which sends `allow_unsigned: true`. A 409 `signing_required` answer is shown in the dialog. SIM and switches back to passive/advisory never show it.
- The Defense area shows a Signing indicator for non-SIM sources (from `signing` in `/api/status` and WS updates).
- The bridge panel shows posture and remote-control state. With control enabled and a token set it offers the three posture buttons (`POST <bridge>/posture`, `Authorization: Bearer`). Otherwise it explains: start the bridge with `--control-token-file`, then enter the token in Settings. 401/403/network errors are displayed.
- Settings has an optional "Bridge control token" (localStorage `aegis_bridge_token`, masked). It is only ever sent in the Authorization header, never in a URL or log.
- Pure logic lives in `src/lib/posture.ts` (tests: `tests/posture.test.ts`).

## In-band bridge status and posture control (over the radio)
- On a cheap drone the telemetry radio is the only link, so the bridge reports in-band and the backend exposes it as `bridge_remote` in `/api/status` and every WS update. The Inline IPS bridge panel prefers it; otherwise it uses the optional HTTP bridge URL poll; otherwise it shows "Bridge not reporting".
- The panel shows posture, topology, state, flags (signing, analyser, FC/GCS link, contested, unsigned acknowledged), counters, "last status N s ago" (STALE above 10 s, LOST above 30 s), last alert/action, the recent AEGIS feed (newest first, max 20) and the last command result (pending / accepted / denied + detail / confirmation required / timeout).
- When `control_available`, the posture buttons call `POST /api/bridge/posture` (the result arrives later in `last_command`; buttons are disabled while pending). Raising to ACTIVE IPS uses `ActiveIpsDialog` (signing from `flags.signing`; a 409 is shown in the dialog). Lowering from active-ips: when `last_command.result` becomes `confirm_required`, a 10 s countdown with Confirm (re-sends with `confirm: true`) and Cancel is shown. Otherwise the panel explains to start `aegis serve` with `--mgmt-key-file`.
- Pure logic: `src/lib/bridgeRemote.ts` (tests: `tests/bridgeRemote.test.ts`); UI: `src/components/BridgeInband.tsx`.
