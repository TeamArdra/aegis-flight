"""FastAPI backend for the AegisFlight dashboard.

Exposes REST status endpoints and a WebSocket that streams live telemetry +
threat assessments from the :class:`LiveEngine`. If a built frontend exists at
``frontend/dist`` it is served at ``/`` so ``aegis serve`` hosts the whole app;
otherwise ``/`` returns a small JSON banner.

The telemetry source is chosen at startup (``aegis serve --source``, read here
from ``AEGIS_*`` variables); no endpoint can open or switch it. Every payload
carries ``environment`` (SIM / REPLAY / SITL / BENCH) and ``sim`` (true only for
SIM), so the dashboard can never present simulated or replayed activity as a
real airframe. The control and attack endpoints are simulation-only (HTTP 409
otherwise): a real or replayed source is read-only.

Exposure: same-origin only. There is no CORS middleware (the built frontend is
served from this origin and the Vite dev server proxies ``/api``, ``/health`` and
``/ws``), the Host header must be local (DNS-rebinding guard), and the WebSocket
refuses a browser Origin that is not local -- live bench telemetry (possibly a
real position) must not be readable by an arbitrary web page.
"""

from __future__ import annotations

import contextlib
import hmac
import json
import math
import os
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .. import __version__
from ..attacks import ATTACK_REGISTRY
from .engine import LiveEngine
from .security import (
    GLOBAL_RATE_LIMITER,
    SecurityHeadersMiddleware,
    _client_ip,
    is_loopback_client,
    read_bounded_body,
    verify_signed_headers,
)
from .sources import spec_from_env

engine: LiveEngine | None = None

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "tauri.localhost"}

_ALLOWED_CORS_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:8008",
    "http://127.0.0.1:8008",
    "tauri://localhost",
    "http://tauri.localhost",
    "https://tauri.localhost",
]


def _local_hosts() -> set[str]:
    # AEGIS_SERVE_HOST is the operator's own --host (non-loopback only for SIM); an unset one adds nothing
    # (adding None would match the hostname-less ``Origin: null``)
    extra = os.environ.get("AEGIS_SERVE_HOST")
    return _LOCAL_HOSTS | ({extra} if extra else set())


_ATTACK_MODE_RE = re.compile(r"[a-z0-9_]{1,40}")
_MAX_DRIFT_RATE_MS = 100.0


def _allowed_hosts() -> list[str]:
    # "testserver" is Starlette's TestClient host
    return sorted(_local_hosts() | {"[::1]", "testserver"})


def _origin_allowed(origin: str, request: Request) -> bool:
    """A browser Origin may drive the control plane only if it is an allow-listed dev/dashboard origin, or
    the exact same origin (scheme + host + port) as this server on a local host. Comparing the hostname
    alone would let a page served by any other localhost port fire the body-less POSTs."""
    if origin in _ALLOWED_CORS_ORIGINS:
        return True
    parsed = urlparse(origin)
    return (parsed.hostname in _local_hosts() and parsed.scheme == request.url.scheme
            and parsed.netloc == request.headers.get("host", ""))


def _require_control_auth(request: Request, *, body: bytes = b"") -> JSONResponse | None:
    """Validate Origin, rate-limit, X-Aegis-Token/Bearer, and optional HMAC+nonce signature."""
    origin = request.headers.get("origin")
    if origin is not None and not _origin_allowed(origin, request):
        return JSONResponse(
            status_code=403,
            content={"ok": False, "error": "forbidden cross-origin control-plane request"},
        )

    ip = _client_ip(request)
    if (retry_after := GLOBAL_RATE_LIMITER.check_allowed(ip)) is not None:
        return JSONResponse(
            status_code=429,
            headers={"Retry-After": str(retry_after)},
            content={"ok": False, "error": "rate_limited: too many invalid authentication attempts"},
        )

    expected_token = os.environ.get("AEGIS_API_TOKEN", "").strip()
    if expected_token:
        provided = request.headers.get("x-aegis-token", "").strip()
        if not provided:
            auth_hdr = request.headers.get("authorization", "").strip()
            if auth_hdr.lower().startswith("bearer "):
                provided = auth_hdr[7:].strip()
        if not provided or not hmac.compare_digest(provided.encode("utf-8"), expected_token.encode("utf-8")):
            retry = GLOBAL_RATE_LIMITER.record_failure(ip)
            headers = {"Retry-After": str(retry)} if retry else {}
            return JSONResponse(
                status_code=401 if not retry else 429,
                headers=headers,
                content={"ok": False, "error": "unauthorized: valid X-Aegis-Token or Bearer token required"},
            )
        if (sig_err := verify_signed_headers(request, token=expected_token, body=body)) is not None:
            return sig_err
        GLOBAL_RATE_LIMITER.clear(ip)
    return None


def _audit_control_action(action: str, target: str, detail: str = "") -> None:
    """Best-effort append of mutating UI/API command into EventStore hash-chained actions table."""
    eng = get_engine()
    if getattr(eng, "store", None) is None or getattr(eng.store, "read_only", False):
        return
    with contextlib.suppress(Exception):
        t_val = float(eng.pipeline.last_frame.t) if getattr(eng.pipeline, "last_frame", None) else 0.0
        eng.store.log_action(eng._run_id, t_val, "web_api", action, target, detail)


def _require_bench_setup_gate(request: Request, *, body: bytes = b"") -> JSONResponse | None:
    """Strict gate for Bench/Setup routes: auth + loopback peer + vehicle must not be armed."""
    if (auth_err := _require_control_auth(request, body=body)) is not None:
        return auth_err
    if not is_loopback_client(request):
        return JSONResponse(
            status_code=403,
            content={"ok": False, "error": "setup_loopback_only",
                     "message": "Bench setup endpoints accept loopback requests only."},
        )
    eng = get_engine()
    if bool(getattr(eng.pipeline.extractor.snapshot, "armed", False)):
        return JSONResponse(
            status_code=409,
            content={"ok": False, "error": "vehicle_armed",
                     "message": "Bench setup tools are locked while the vehicle is armed."},
        )
    return None


def get_engine() -> LiveEngine:
    """The single engine; a pre-set ``engine`` (tests) wins, else it is built from ``AEGIS_*``."""
    global engine
    if engine is None:
        engine = LiveEngine(spec=spec_from_env(), db_path=os.environ.get("AEGIS_DB") or None)
    return engine


def _sim_only(action: str) -> JSONResponse | None:
    eng = get_engine()
    if eng.is_sim:
        return None
    return JSONResponse(status_code=409, content={
        "ok": False, "environment": eng.spec.environment,
        "error": f"{action} is simulation-only; the source is {eng.spec.environment} (read-only)"})


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    await get_engine().start()  # auto-start the configured source
    yield
    if engine is not None:
        await engine.close()  # loop and source stopped, port released, event store closed


app = FastAPI(title="AegisFlight IDS", version=__version__, lifespan=lifespan)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=_allowed_hosts())
app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=[
        "Content-Type",
        "X-Aegis-Token",
        "X-Aegis-Nonce",
        "X-Aegis-Timestamp",
        "X-Aegis-Signature",
        "Authorization",
    ],
)


# --------------------------------------------------------------------------- #
# REST API
# --------------------------------------------------------------------------- #
@app.get("/health")
def health() -> dict:
    eng = get_engine()
    return {"status": "ok", "version": __version__, "sim": eng.is_sim, "environment": eng.spec.environment}


@app.get("/api/status")
def status() -> dict:
    return get_engine().status()


# metrics / events are async on purpose: every EventStore read then runs on the event-loop thread, the same
# thread that appends the alerts (no SQLite connection is shared across threads).
@app.get("/api/metrics")
async def metrics() -> dict:
    return get_engine().metrics()


@app.get("/api/events")
async def events(limit: int = Query(50, ge=1, le=1000)) -> dict:
    """The CURRENT run's persisted alerts, newest first, read back from the event store (hash-chain fields
    included); ``count`` is the run's total. Bounded ``limit``: SQLite treats a negative LIMIT as unlimited."""
    eng = get_engine()
    return {"events": eng.recent_alerts(limit), "run_id": eng._run_id, "source": eng.spec.describe(),
            "count": eng.store.count_events(eng._run_id)}


@app.get("/api/events/forensic")
async def events_forensic(limit: int = Query(200, ge=1, le=1000)) -> dict:
    """Return cryptographically verified SHA-256 hash-chain status + forensic alert & mitigation bundle."""
    return get_engine().forensic_bundle(limit=limit)


@app.get("/api/config")
def config() -> dict:
    cfg = get_engine().cfg  # the configuration actually in use (a --config-dir profile, if any)
    det = cfg.detector
    return {
        "attacks": sorted(ATTACK_REGISTRY.keys()),
        "decision_rate_hz": det.get("decision_rate_hz"),
        "sample_rate_hz": cfg.simulation.get("sample_rate_hz"),
        "fusion": {
            "threat_threshold": det["fusion"]["threat_threshold"],
            "weights": det["fusion"]["weights"],
            "severity_bands": det["fusion"]["severity_bands"],
        },
        "home": cfg.simulation.get("home"),
    }


@app.post("/api/simulation/start", response_model=None)
async def sim_start(request: Request) -> dict | JSONResponse:
    if (auth_err := _require_control_auth(request)) is not None:
        return auth_err
    if (refused := _sim_only("start")) is not None:
        return refused
    await get_engine().start()
    return {"ok": True, "running": True}


@app.post("/api/simulation/stop", response_model=None)
async def sim_stop(request: Request) -> dict | JSONResponse:
    if (auth_err := _require_control_auth(request)) is not None:
        return auth_err
    if (refused := _sim_only("stop")) is not None:
        return refused
    await get_engine().stop()
    return {"ok": True, "running": False}


@app.post("/api/simulation/reset", response_model=None)
async def sim_reset(request: Request) -> dict | JSONResponse:
    if (auth_err := _require_control_auth(request)) is not None:
        return auth_err
    # Refused for a live source: pipeline.reset() would erase detector memory (docs/THREAT_MODEL.md).
    if (refused := _sim_only("reset")) is not None:
        return refused
    # Stop the running loop, restore a clean baseline, then start a fresh loop.
    # Async (not sync) so start()'s create_task runs on the event loop.
    eng = get_engine()
    await eng.stop()
    eng.reset()
    await eng.start()
    return {"ok": True, "reset": True}


@app.post("/api/simulation/attack", response_model=None)
async def sim_attack(request: Request) -> JSONResponse:
    try:
        raw = await read_bounded_body(request)
    except ValueError as exc:
        return JSONResponse(status_code=413, content={"ok": False, "error": str(exc)})
    if (auth_err := _require_control_auth(request, body=raw)) is not None:
        return auth_err
    if (refused := _sim_only("attack injection")) is not None:
        return refused
    try:
        payload = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return JSONResponse(status_code=400, content={"ok": False, "error": "invalid JSON body"})
    if not isinstance(payload, dict):
        return JSONResponse(status_code=400, content={"ok": False, "error": "JSON object required"})
    name = (payload or {}).get("attack")
    mode = (payload or {}).get("mode")
    drift_rate_ms = (payload or {}).get("drift_rate_ms")
    # validated here: a bad value would otherwise raise inside the engine loop and stop the simulation
    if mode is not None and not (isinstance(mode, str) and _ATTACK_MODE_RE.fullmatch(mode)):
        return JSONResponse(status_code=400, content={"ok": False, "error": "mode must be a short identifier"})
    if drift_rate_ms is not None:
        if isinstance(drift_rate_ms, bool) or not isinstance(drift_rate_ms, int | float)                 or not math.isfinite(drift_rate_ms) or not 0.0 < drift_rate_ms <= _MAX_DRIFT_RATE_MS:
            return JSONResponse(status_code=400, content={
                "ok": False, "error": f"drift_rate_ms must be a number in (0, {_MAX_DRIFT_RATE_MS:g}]"})
    if name and name not in ATTACK_REGISTRY and name not in ("none", "benign"):
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": f"unknown attack '{name}'",
                     "choices": sorted(ATTACK_REGISTRY.keys())},
        )
    get_engine().set_attack(name, mode=mode, drift_rate_ms=drift_rate_ms)
    return JSONResponse(content={"ok": True, "attack": name or "cleared", "mode": mode})


@app.post("/api/defense/mode", response_model=None)
async def set_defense_mode(request: Request) -> JSONResponse:
    try:
        raw = await read_bounded_body(request)
    except ValueError as exc:
        return JSONResponse(status_code=413, content={"ok": False, "error": str(exc)})
    if (auth_err := _require_control_auth(request, body=raw)) is not None:
        return auth_err
    try:
        payload = json.loads(raw) if raw else {}
    except (ValueError, UnicodeDecodeError):
        return JSONResponse(status_code=400, content={"ok": False, "error": "invalid JSON body"})
    mode = (payload or {}).get("mode") if isinstance(payload, dict) else None
    if mode not in ("passive", "advisory", "active-ips"):
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": f"unknown defense mode '{mode}'",
                     "choices": ["passive", "advisory", "active-ips"]},
        )
    allow_unsigned = (payload or {}).get("allow_unsigned")
    if allow_unsigned is not None and not isinstance(allow_unsigned, bool):
        return JSONResponse(status_code=400, content={"ok": False, "error": "allow_unsigned must be a boolean"})
    eng = get_engine()
    if (gated := eng.signing_gate(mode, allow_unsigned is True)) is not None:
        return JSONResponse(status_code=409, content=gated)
    res = eng.set_defense_mode(mode, allow_unsigned=allow_unsigned is True)
    _audit_control_action("defense_mode", str(mode), f"allow_unsigned={allow_unsigned is True}")
    return JSONResponse(content={"ok": True, **res})


@app.post("/api/bridge/posture", response_model=None)
async def bridge_posture(request: Request) -> JSONResponse:
    """Ask the remote ips-bridge (over the telemetry radio, in-band) to change its posture. Signed with the
    management key; the answer arrives as a COMMAND_ACK and shows in ``bridge_remote.last_command``."""
    try:
        raw = await read_bounded_body(request)
    except ValueError as exc:
        return JSONResponse(status_code=413, content={"ok": False, "error": str(exc)})
    if (auth_err := _require_control_auth(request, body=raw)) is not None:
        return auth_err
    try:
        body = json.loads(raw) if raw else {}
    except (ValueError, UnicodeDecodeError):
        return JSONResponse(status_code=400, content={"ok": False, "error": "invalid JSON body"})
    if not isinstance(body, dict):
        body = {}
    mode = body.get("mode")
    if mode not in ("passive", "advisory", "active-ips"):
        return JSONResponse(status_code=400, content={"ok": False, "error": f"unknown mode '{mode}'",
                                                      "choices": ["passive", "advisory", "active-ips"]})
    for k in ("allow_unsigned", "confirm"):
        if body.get(k) is not None and not isinstance(body.get(k), bool):
            return JSONResponse(status_code=400, content={"ok": False, "error": f"{k} must be a boolean"})
    eng = get_engine()
    if not eng.control_writable() or eng.bridge_remote.mgmt_key is None:
        return JSONResponse(status_code=403, content={
            "ok": False, "error": "control_unavailable",
            "message": "needs a live UDP / socket:// source and --mgmt-key-file; replay, simulation and serial devices "
                       "(receive-only) never send"})
    allow_unsigned = body.get("allow_unsigned") is True
    if mode == "active-ips" and not allow_unsigned and eng.bridge_remote.bridge_signing() is False:
        return JSONResponse(status_code=409, content={
            "ok": False, "error": "signing_required",
            "message": "Unsigned links cannot stop a counter-tracking forger; provision a key and start with "
                       "--signing-key-file, or acknowledge the risk to proceed unsigned."})
    res = eng.send_bridge_posture(mode, allow_unsigned=allow_unsigned, confirm=body.get("confirm") is True)
    _audit_control_action("bridge_posture", str(mode), f"ok={res.get('ok')} confirm={body.get('confirm') is True}")
    return JSONResponse(status_code=200 if res.get("ok") else 502, content=res)


@app.post("/api/defense/override", response_model=None)
async def defense_override(request: Request) -> JSONResponse:
    try:
        raw = await read_bounded_body(request)
    except ValueError as exc:
        return JSONResponse(status_code=413, content={"ok": False, "error": str(exc)})
    if (auth_err := _require_control_auth(request, body=raw)) is not None:
        return auth_err
    try:
        payload = json.loads(raw) if raw else {}
    except (ValueError, UnicodeDecodeError):
        return JSONResponse(status_code=400, content={"ok": False, "error": "invalid JSON body"})
    action = (payload or {}).get("action") if isinstance(payload, dict) else None
    if action not in ("safe_hold", "reset_quarantine", "ack_takeover"):
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": f"unknown override action '{action}'",
                     "choices": ["safe_hold", "reset_quarantine", "ack_takeover"]},
        )
    res = get_engine().defense_override(action)
    _audit_control_action("defense_override", str(action), "executed")
    return JSONResponse(content={"ok": True, "action": action, "mitigation": res})


@app.get("/api/forensic/report", response_model=None)
async def forensic_report(
    format: str = Query("json", pattern="^(json|html)$"),
    limit: int = Query(500, ge=1, le=2000),
) -> JSONResponse | HTMLResponse:
    """Return a cryptographically verified post-flight forensic report (JSON or HTML)."""
    from ..reporting.forensic_report import build_forensic_report, render_forensic_html

    eng = get_engine()
    db_str = str(getattr(eng, "db_path", ":memory:"))
    if db_str != ":memory:" and Path(db_str).is_file():
        rep = build_forensic_report(db_str, run_id=eng._run_id, limit=limit)
    else:
        bundle = eng.forensic_bundle(limit=limit)
        ev_c = bundle.get("chain") or {}
        act_c = bundle.get("actions_chain") or {"ok": True, "length": 0, "detail": "in-memory"}
        rep = {
            "schema": "aegisflight.forensic_report/1",
            "db_path": db_str,
            "run_id": eng._run_id,
            "verified": bool(ev_c.get("ok", True) and act_c.get("ok", True)),
            "events_chain": ev_c,
            "actions_chain": act_c,
            "anchors": bundle.get("anchors"),
            "runs": [],
            "summary": {
                "total_events_included": len(bundle.get("events", [])),
                "total_actions_included": len(bundle.get("actions", [])),
                "by_attack_type": {},
                "by_severity": {},
                "by_action_type": {},
            },
            "events": bundle.get("events", []),
            "actions": bundle.get("actions", []),
        }
    if format == "html":
        return HTMLResponse(content=render_forensic_html(rep))
    return JSONResponse(content=rep)


@app.post("/api/drill/run", response_model=None)
async def run_shadow_drill(request: Request) -> JSONResponse:
    """Run non-destructive zero-TX shadow verification drills (W10)."""
    from ..testing.field_drill import run_field_drill

    try:
        raw = await read_bounded_body(request)
    except ValueError as exc:
        return JSONResponse(status_code=413, content={"ok": False, "error": str(exc)})
    if (auth_err := _require_control_auth(request, body=raw)) is not None:
        return auth_err
    try:
        payload = json.loads(raw) if raw else {}
    except (ValueError, UnicodeDecodeError):
        return JSONResponse(status_code=400, content={"ok": False, "error": "invalid JSON body"})
    scenario = (payload or {}).get("scenario", "all") if isinstance(payload, dict) else "all"
    try:
        res = run_field_drill(str(scenario))
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"ok": False, "error": str(exc)})
    _audit_control_action("shadow_drill", str(scenario), f"passed={res['passed']}/{res['total']}")
    return JSONResponse(content=res)


@app.get("/api/setup/discover-ports", response_model=None)
def setup_discover_ports(request: Request) -> JSONResponse:
    """Zero-TX passive serial port + baud discovery (loopback + disarmed bench gate)."""
    from dataclasses import asdict

    from ..hal.auto_port import discover_mavlink_ports

    if (gate_err := _require_bench_setup_gate(request)) is not None:
        return gate_err
    ports = [asdict(p) for p in discover_mavlink_ports(probe_window_s=0.6)]
    return JSONResponse(content={"ok": True, "zero_tx": True, "ports": ports})


@app.post("/api/setup/preflight", response_model=None)
async def setup_preflight(request: Request) -> JSONResponse:
    """Validate proposed onboard companion configuration with 0 B FC TX."""
    import tempfile

    import yaml

    from ..onboard import load_onboard_config, run_preflight

    try:
        raw = await read_bounded_body(request)
    except ValueError as exc:
        return JSONResponse(status_code=413, content={"ok": False, "error": str(exc)})
    if (gate_err := _require_bench_setup_gate(request, body=raw)) is not None:
        return gate_err
    try:
        payload = json.loads(raw) if raw else {}
    except (ValueError, UnicodeDecodeError):
        return JSONResponse(status_code=400, content={"ok": False, "error": "invalid JSON body"})
    if not isinstance(payload, dict):
        return JSONResponse(status_code=400, content={"ok": False, "error": "body must be JSON object"})
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as fh:
        yaml.safe_dump(payload, fh)
        tmp_path = fh.name
    try:
        cfg = load_onboard_config(tmp_path)
        rep = run_preflight(cfg)
    except (OSError, ValueError) as exc:
        return JSONResponse(status_code=400, content={"ok": False, "error": str(exc)})
    finally:
        with contextlib.suppress(OSError):
            Path(tmp_path).unlink()
    return JSONResponse(content=rep)


@app.post("/api/setup/generate-config", response_model=None)
async def setup_generate_config(request: Request) -> JSONResponse:
    """Validate and return hardened YAML configuration for the companion computer."""
    import yaml

    from ..onboard import OnboardConfig, _validate_onboard

    try:
        raw = await read_bounded_body(request)
    except ValueError as exc:
        return JSONResponse(status_code=413, content={"ok": False, "error": str(exc)})
    if (gate_err := _require_bench_setup_gate(request, body=raw)) is not None:
        return gate_err
    try:
        payload = json.loads(raw) if raw else {}
    except (ValueError, UnicodeDecodeError):
        return JSONResponse(status_code=400, content={"ok": False, "error": "invalid JSON body"})
    if not isinstance(payload, dict):
        return JSONResponse(status_code=400, content={"ok": False, "error": "body must be JSON object"})
    allowed_keys = {
        "topology", "fc_port", "fc_baud", "fc_rtscts", "gcs_port", "gcs_baud", "gcs_rtscts",
        "allow_url", "defense_mode", "config_dir", "fail_closed_uplink_commands",
        "semantic_firewall_enabled", "anchors_enabled", "allow_unsigned",
    }
    clean: dict[str, object] = {k: v for k, v in payload.items() if k in allowed_keys}
    try:
        cfg = OnboardConfig(**{k: v for k, v in clean.items() if v is not None})  # type: ignore[arg-type]
        _validate_onboard(cfg)
    except (TypeError, ValueError) as exc:
        return JSONResponse(status_code=400, content={"ok": False, "error": str(exc)})
    # the generated file always states its topology: load_onboard_config refuses a file without one
    clean = {"topology": cfg.topology, **clean}
    return JSONResponse(content={"ok": True, "yaml": yaml.safe_dump(clean, sort_keys=False)})


@app.post("/api/setup/enroll-firmware", response_model=None)
async def setup_enroll_firmware(request: Request) -> JSONResponse:
    """Passively capture AUTOPILOT_VERSION (0 B TX) on a local serial port for allowlist enrollment."""
    from ..hal.auto_port import capture_autopilot_version_passive

    try:
        raw = await read_bounded_body(request)
    except ValueError as exc:
        return JSONResponse(status_code=413, content={"ok": False, "error": str(exc)})
    if (gate_err := _require_bench_setup_gate(request, body=raw)) is not None:
        return gate_err
    try:
        payload = json.loads(raw) if raw else {}
    except (ValueError, UnicodeDecodeError):
        return JSONResponse(status_code=400, content={"ok": False, "error": "invalid JSON body"})
    port = str((payload or {}).get("port", "")).strip()
    baud = int((payload or {}).get("baudrate", 921600))
    timeout_s = min(15.0, max(0.5, float((payload or {}).get("timeout_s", 5.0))))
    if not port:
        return JSONResponse(status_code=400, content={"ok": False, "error": "port is required"})
    try:
        entry = capture_autopilot_version_passive(port, baudrate=baud, timeout_s=timeout_s)
    except (OSError, ValueError) as exc:
        return JSONResponse(status_code=400, content={"ok": False, "error": str(exc)})
    if entry is None:
        return JSONResponse(
            status_code=504,
            content={"ok": False, "error": f"timed out waiting for AUTOPILOT_VERSION on {port}@{baud}"},
        )
    return JSONResponse(content={"ok": True, "zero_tx": True, "entry": entry})


@app.get("/api/topology")
def get_topology() -> dict:
    """Read-only detected topology; legacy ``topology`` / ``reasons`` keys kept for compatibility."""
    from ..hal.topology_status import legacy_name
    info = get_engine().topology_info()
    return {"ok": True, **info, "topology": legacy_name(info), "reasons": info["reasons"], "topology_info": info}


# --------------------------------------------------------------------------- #
# WebSocket — live telemetry + threat stream
# --------------------------------------------------------------------------- #
_WS_TEXT_CACHE: list = [None, None]  # [last message object, its JSON text]: N clients share one serialisation


def _ws_text(msg: object) -> str:
    """Exactly what ``WebSocket.send_json`` would send, computed once per broadcast message object.

    ``_broadcast`` puts the same dict into every subscriber queue and the engine never mutates it afterwards,
    so the text is identical for every client (the cache holds the object itself, so its id cannot be reused).
    """
    c = _WS_TEXT_CACHE
    if c[0] is msg:
        return c[1]
    text = json.dumps(msg, separators=(",", ":"), ensure_ascii=False)
    c[0], c[1] = msg, text
    return text


@app.websocket("/ws/telemetry")
async def ws_telemetry(ws: WebSocket) -> None:
    # CORS does not apply to WebSockets: refuse a browser Origin that is not this machine. No Origin
    # (non-browser clients, TestClient) is allowed. Client messages are never read.
    origin = ws.headers.get("origin")
    if origin is not None and urlparse(origin).hostname not in _local_hosts():  # "null" -> hostname None
        await ws.close(code=1008)
        return
    await ws.accept()
    eng = get_engine()
    q = eng.subscribe()
    try:
        while True:
            msg = await q.get()
            await ws.send_text(_ws_text(msg))
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001 - client vanished mid-send
        pass
    finally:
        eng.unsubscribe(q)
        with contextlib.suppress(Exception):
            await ws.close()


# --------------------------------------------------------------------------- #
# Static frontend (if built)
# --------------------------------------------------------------------------- #
_DIST = Path(__file__).resolve().parents[3] / "frontend" / "dist"
if _DIST.exists():
    app.mount("/", StaticFiles(directory=str(_DIST), html=True), name="frontend")
else:
    @app.get("/")
    def root() -> dict:
        eng = get_engine()
        return {
            "name": "AegisFlight IDS",
            "version": __version__,
            "sim": eng.is_sim,
            "environment": eng.spec.environment,
            "note": "frontend not built; run `npm --prefix frontend install && "
                    "npm --prefix frontend run build`, or use the dev server",
            "endpoints": ["/health", "/api/status", "/api/metrics", "/api/events",
                          "/api/config", "/ws/telemetry"],
        }
