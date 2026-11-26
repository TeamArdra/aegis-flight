"""Unified onboard companion runtime supervisor (#59).

Consolidates ``ips-bridge``, :class:`BridgeStatusServer`, hash-chained SQLite /
archive logging with bounded disk rotation, optional local dashboard process
supervision, and signal-safe ``SIGTERM`` shutdown under a single YAML config and
``aegis onboard --config <path>`` entry point.
"""

from __future__ import annotations

import contextlib
import inspect
import ipaddress
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

import yaml

from .hal.auto_port import (
    capture_autopilot_version_passive,
    discover_mavlink_ports,
    probe_serial_port_passive,
)
from .hal.hw_watchdog import HardwareWatchdog
from .hal.inline_ips import InlineIpsBridge
from .hal.run_archive import FILES as ARCHIVE_FILES
from .hal.run_archive import BridgeRunArchive
from .hal.side_tap import SideTapRunner
from .hal.status_server import BridgeStatusServer
from .hal.watchdog import SystemdNotifier
from .integrity.allowlist import (
    ALLOWLIST_KEY_ENV,
    AllowlistError,
    FirmwareAllowlist,
    compute_allowlist_hmac,
    default_allowlist_path,
    load_firmware_allowlist,
)
from .logging import EventStore
from .logging.anchors import AnchorWriter
from .logging.rotation import prune_rotated_files
from .run_provenance import DirtyTreeError, begin_run, finish_run, write_manifest
from .sources.mavlink_serial import SerialMavlinkTransport, may_reach_vehicle

DEFAULT_RUN_ROOT = "onboard_runs"


@dataclass
class RetentionConfig:
    max_db_bytes: int = 50 * 1024 * 1024
    max_jsonl_bytes: int = 50 * 1024 * 1024
    max_rotations: int = 5
    max_total_disk_bytes: int = 500 * 1024 * 1024
    check_interval_s: float = 5.0


@dataclass
class DashboardConfig:
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 8000


@dataclass
class OnboardConfig:
    topology: str = "side-tap"
    fc_port: str = "/dev/ttyAMA0"
    fc_baud: int | str = 921600
    fc_rtscts: bool = False
    gcs_port: str = "/dev/ttyUSB0"
    gcs_baud: int | str = 57600
    gcs_rtscts: bool = False
    allow_url: bool = False
    defense_mode: str = "passive"
    fail_closed_uplink_commands: bool = True
    semantic_firewall_enabled: bool = True
    config_dir: str | None = None
    run_root: str = DEFAULT_RUN_ROOT
    archive_enabled: bool = True
    allow_dirty: bool = True
    db_name: str = "events.sqlite"
    anchors_enabled: bool = True
    anchor_interval_s: float = 30.0
    signing_key_file: str | None = None
    signing_state: str | None = None
    signing_permissive: bool = False
    signing_max_age_s: float | None = None
    allow_unsigned: bool = False
    mgmt_enable: bool = False
    mgmt_key_file: str | None = None
    mgmt_state: str | None = None
    mgmt_max_age_s: float = 300.0
    lock_posture_file: str | None = None
    audit_log: str | None = None
    gcs_alerts: bool | None = None
    mgmt_status_interval_s: float = 2.0
    crossend_interval_s: float = 1.0
    vehicle_uplink_filter: bool = False
    filter_override_file: str | None = None
    filter_lockout_failopen_s: float | None = None
    firmware_dir: str | None = None
    firmware_allowlist: str | None = None
    firmware_recheck_s: float = 30.0
    ekf_secondary: bool = False
    contested_policy: str = "alert"
    replay_memory: int = 4096
    status_host: str = "127.0.0.1"
    status_port: int = 8090
    status_interval_s: float = 5.0
    control_token_file: str | None = None
    retention: RetentionConfig = field(default_factory=RetentionConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _clean_opt_str(val: Any) -> str | None:
    if val is None:
        return None
    s = str(val).strip()
    return s or None


_TRUE_STRINGS = frozenset({"true", "yes", "1", "on"})
_FALSE_STRINGS = frozenset({"false", "no", "0", "off"})
_KNOWN_TOP_KEYS = frozenset(f.name for f in fields(OnboardConfig))
_KNOWN_RETENTION_KEYS = frozenset(f.name for f in fields(RetentionConfig))
_KNOWN_DASHBOARD_KEYS = frozenset(f.name for f in fields(DashboardConfig))


def _parse_bool(val: Any, key: str) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        s = val.strip().lower()
        if s in _TRUE_STRINGS:
            return True
        if s in _FALSE_STRINGS:
            return False
    raise ValueError(f"invalid boolean for {key!r}: {val!r} (expected true/false)")


def _parse_baud(val: Any, default: int) -> int | str:
    if val is None:
        return default
    if isinstance(val, str) and val.strip().lower() == "auto":
        return "auto"
    return int(val)


def load_onboard_config(path: str | Path | None = None) -> OnboardConfig:
    """Load an :class:`OnboardConfig` from YAML (or return safe defaults if ``path`` is None)."""
    if path is None:
        return OnboardConfig()
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"onboard config {path} must be a YAML mapping")

    unknown_top = sorted(str(k) for k in raw if k not in _KNOWN_TOP_KEYS)
    if unknown_top:
        raise ValueError(
            f"unknown onboard config key(s) in {path}: {', '.join(unknown_top)}"
        )

    ret_raw = raw.get("retention") or {}
    if not isinstance(ret_raw, dict):
        raise ValueError("retention must be a YAML mapping")
    unknown_ret = sorted(str(k) for k in ret_raw if k not in _KNOWN_RETENTION_KEYS)
    if unknown_ret:
        raise ValueError(
            f"unknown retention config key(s) in {path}: {', '.join(unknown_ret)}"
        )
    ret = RetentionConfig(
        max_db_bytes=int(ret_raw.get("max_db_bytes", 50 * 1024 * 1024)),
        max_jsonl_bytes=int(ret_raw.get("max_jsonl_bytes", 50 * 1024 * 1024)),
        max_rotations=int(ret_raw.get("max_rotations", 5)),
        max_total_disk_bytes=int(ret_raw.get("max_total_disk_bytes", 500 * 1024 * 1024)),
        check_interval_s=float(ret_raw.get("check_interval_s", 5.0)),
    )

    dash_raw = raw.get("dashboard") or {}
    if not isinstance(dash_raw, dict):
        raise ValueError("dashboard must be a YAML mapping")
    unknown_dash = sorted(str(k) for k in dash_raw if k not in _KNOWN_DASHBOARD_KEYS)
    if unknown_dash:
        raise ValueError(
            f"unknown dashboard config key(s) in {path}: {', '.join(unknown_dash)}"
        )
    dash = DashboardConfig(
        enabled=_parse_bool(dash_raw.get("enabled", False), "dashboard.enabled"),
        host=str(dash_raw.get("host", "127.0.0.1")),
        port=int(dash_raw.get("port", 8000)),
    )

    gcs_alerts_raw = raw.get("gcs_alerts")
    gcs_alerts = None if gcs_alerts_raw is None else _parse_bool(gcs_alerts_raw, "gcs_alerts")

    return OnboardConfig(
        topology=str(raw.get("topology", "side-tap")).strip().lower() or "side-tap",
        fc_port=str(raw.get("fc_port", "/dev/ttyAMA0")),
        fc_baud=_parse_baud(raw.get("fc_baud"), 921600),
        fc_rtscts=_parse_bool(raw.get("fc_rtscts", False), "fc_rtscts"),
        gcs_port=str(raw.get("gcs_port", "/dev/ttyUSB0")),
        gcs_baud=_parse_baud(raw.get("gcs_baud"), 57600),
        gcs_rtscts=_parse_bool(raw.get("gcs_rtscts", False), "gcs_rtscts"),
        allow_url=_parse_bool(raw.get("allow_url", False), "allow_url"),
        defense_mode=str(raw.get("defense_mode", "passive")),
        fail_closed_uplink_commands=_parse_bool(
            raw.get("fail_closed_uplink_commands", True), "fail_closed_uplink_commands"
        ),
        semantic_firewall_enabled=_parse_bool(
            raw.get("semantic_firewall_enabled", True), "semantic_firewall_enabled"
        ),
        config_dir=_clean_opt_str(raw.get("config_dir")),
        run_root=str(raw.get("run_root", DEFAULT_RUN_ROOT)),
        archive_enabled=_parse_bool(raw.get("archive_enabled", True), "archive_enabled"),
        allow_dirty=_parse_bool(raw.get("allow_dirty", True), "allow_dirty"),
        db_name=str(raw.get("db_name", "events.sqlite")),
        anchors_enabled=_parse_bool(raw.get("anchors_enabled", True), "anchors_enabled"),
        anchor_interval_s=float(raw.get("anchor_interval_s", 30.0)),
        signing_key_file=_clean_opt_str(raw.get("signing_key_file")),
        signing_state=_clean_opt_str(raw.get("signing_state")),
        signing_permissive=_parse_bool(raw.get("signing_permissive", False), "signing_permissive"),
        signing_max_age_s=(
            None if raw.get("signing_max_age_s") is None else float(raw["signing_max_age_s"])
        ),
        allow_unsigned=_parse_bool(raw.get("allow_unsigned", False), "allow_unsigned"),
        mgmt_enable=_parse_bool(raw.get("mgmt_enable", False), "mgmt_enable"),
        mgmt_key_file=_clean_opt_str(raw.get("mgmt_key_file")),
        mgmt_state=_clean_opt_str(raw.get("mgmt_state")),
        mgmt_max_age_s=float(raw.get("mgmt_max_age_s", 300.0)),
        lock_posture_file=_clean_opt_str(raw.get("lock_posture_file")),
        audit_log=_clean_opt_str(raw.get("audit_log")),
        gcs_alerts=gcs_alerts,
        mgmt_status_interval_s=float(raw.get("mgmt_status_interval_s", 2.0)),
        crossend_interval_s=float(raw.get("crossend_interval_s", 1.0)),
        vehicle_uplink_filter=_parse_bool(
            raw.get("vehicle_uplink_filter", False), "vehicle_uplink_filter"
        ),
        filter_override_file=_clean_opt_str(raw.get("filter_override_file")),
        filter_lockout_failopen_s=(
            None
            if raw.get("filter_lockout_failopen_s") is None
            else float(raw["filter_lockout_failopen_s"])
        ),
        firmware_dir=_clean_opt_str(raw.get("firmware_dir")),
        firmware_allowlist=_clean_opt_str(raw.get("firmware_allowlist")),
        firmware_recheck_s=float(raw.get("firmware_recheck_s", 30.0)),
        ekf_secondary=_parse_bool(raw.get("ekf_secondary", False), "ekf_secondary"),
        contested_policy=str(raw.get("contested_policy", "alert")),
        replay_memory=int(raw.get("replay_memory", 4096)),
        status_host=str(raw.get("status_host", "127.0.0.1")),
        status_port=int(raw.get("status_port", 8090)),
        status_interval_s=float(raw.get("status_interval_s", 5.0)),
        control_token_file=_clean_opt_str(raw.get("control_token_file")),
        retention=ret,
        dashboard=dash,
    )


def _load_optional_allowlist(cfg: OnboardConfig) -> FirmwareAllowlist | None:
    path = Path(cfg.firmware_allowlist) if cfg.firmware_allowlist else default_allowlist_path(cfg.config_dir)
    if path is None:
        return None
    return load_firmware_allowlist(path)


def _resolve_ports_and_bauds(cfg: OnboardConfig) -> tuple[str, int, str | None, int | None]:
    """Resolve explicit or ``auto`` ports/bauds using strictly 0 B TX passive discovery."""
    fc_port = cfg.fc_port.strip()
    gcs_port = (cfg.gcs_port or "").strip()
    fc_baud_raw = cfg.fc_baud
    gcs_baud_raw = cfg.gcs_baud

    need_scan = (
        fc_port.lower() == "auto"
        or (cfg.topology == "inline" and gcs_port.lower() == "auto")
    )
    discovered = discover_mavlink_ports() if need_scan else []

    if fc_port.lower() == "auto":
        fc_cands = [d for d in discovered if d.role == "fc"] or discovered
        if not fc_cands:
            raise ValueError("auto fc_port discovery found no active MAVLink serial device (0 B TX probe)")
        fc_chosen = max(fc_cands, key=lambda d: d.frames_valid)
        fc_port = fc_chosen.device
        fc_baud = fc_chosen.baudrate if str(fc_baud_raw).lower() == "auto" else int(fc_baud_raw)
    elif str(fc_baud_raw).lower() == "auto":
        found = probe_serial_port_passive(fc_port)
        if found is None:
            raise ValueError(f"auto fc_baud detection failed on {fc_port}: no MAVLink telemetry seen")
        fc_baud = found.baudrate
    else:
        fc_baud = int(fc_baud_raw)

    if cfg.topology == "side-tap":
        return fc_port, fc_baud, None, None

    if gcs_port.lower() == "auto":
        gcs_cands = [d for d in discovered if d.device != fc_port and d.role == "gcs_radio"] or [
            d for d in discovered if d.device != fc_port
        ]
        if not gcs_cands:
            raise ValueError("auto gcs_port discovery found no distinct secondary MAVLink port")
        gcs_chosen = max(gcs_cands, key=lambda d: d.frames_valid)
        gcs_port = gcs_chosen.device
        gcs_baud = gcs_chosen.baudrate if str(gcs_baud_raw).lower() == "auto" else int(gcs_baud_raw)
    elif str(gcs_baud_raw).lower() == "auto":
        found = probe_serial_port_passive(gcs_port)
        if found is None:
            raise ValueError(f"auto gcs_baud detection failed on {gcs_port}: no MAVLink frames seen")
        gcs_baud = found.baudrate
    else:
        gcs_baud = int(gcs_baud_raw)

    return fc_port, fc_baud, gcs_port, gcs_baud


def _validate_onboard(
    cfg: OnboardConfig,
    *,
    resolved_fc_port: str | None = None,
    resolved_gcs_port: str | None = None,
) -> tuple[bytes | None, bytes | None, str | None, FirmwareAllowlist | None]:
    if cfg.topology not in ("inline", "side-tap"):
        raise ValueError(f"invalid topology {cfg.topology!r}; expected 'inline' or 'side-tap'")
    if cfg.defense_mode not in ("passive", "advisory", "active-ips"):
        raise ValueError(f"invalid defense_mode {cfg.defense_mode!r}")
    if cfg.topology == "side-tap" and cfg.defense_mode != "passive":
        raise ValueError("side-tap topology is strictly receive-only and requires defense_mode='passive'")

    fc_p = resolved_fc_port or cfg.fc_port
    gcs_p = resolved_gcs_port if resolved_gcs_port is not None else cfg.gcs_port
    if cfg.topology == "inline" and fc_p == gcs_p and fc_p.lower() != "auto":
        raise ValueError("fc_port and gcs_port must differ")
    if cfg.defense_mode == "active-ips" and may_reach_vehicle(fc_p):
        raise ValueError(
            f"refusing defense_mode='active-ips' on fc_port {fc_p}: serial links are receive-only"
        )
    if cfg.vehicle_uplink_filter and cfg.defense_mode == "active-ips":
        raise ValueError("vehicle_uplink_filter cannot be combined with active-ips")
    if cfg.dashboard.enabled and not _is_loopback(cfg.dashboard.host):
        raise ValueError(f"refusing non-loopback dashboard host {cfg.dashboard.host!r}")

    from .detectors.crossend import load_signing_key  # noqa: PLC0415

    key = load_signing_key(cfg.signing_key_file) if cfg.signing_key_file else None
    mgmt_key = load_signing_key(cfg.mgmt_key_file) if cfg.mgmt_key_file else None
    if mgmt_key is not None and not cfg.mgmt_state:
        raise ValueError("mgmt_key_file requires mgmt_state for persisted anti-replay state")
    if cfg.vehicle_uplink_filter and key is None:
        raise ValueError("vehicle_uplink_filter requires signing_key_file")
    if cfg.defense_mode == "active-ips" and key is None and not cfg.allow_unsigned:
        raise ValueError("active-ips requires signing_key_file or allow_unsigned=true")

    allowlist = _load_optional_allowlist(cfg)

    token = None
    if cfg.control_token_file:
        token = Path(cfg.control_token_file).read_text(encoding="utf-8").strip()
        if not token:
            raise ValueError("control_token_file is empty")
    if not _is_loopback(cfg.status_host) and token is None:
        raise ValueError(f"non-loopback status_host {cfg.status_host!r} requires control_token_file")
    return key, mgmt_key, token, allowlist


def _allocate_run_dir(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("onboard-%Y%m%d-%H%M%S")
    cand = root / f"{stamp}-{os.getpid()}"
    idx = 0
    while cand.exists():
        idx += 1
        cand = root / f"{stamp}-{os.getpid()}-{idx}"
    return cand


def _start_dashboard_child(cfg: OnboardConfig) -> subprocess.Popen[bytes] | None:
    if not cfg.dashboard.enabled or cfg.status_port <= 0:
        return None
    env = os.environ.copy()
    env["AEGIS_SOURCE"] = "bridge"
    env["AEGIS_BRIDGE_URL"] = f"http://127.0.0.1:{cfg.status_port}"
    env["AEGIS_DEFENSE_MODE"] = cfg.defense_mode
    return subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "aegisflight.backend.app:app",
            "--host",
            cfg.dashboard.host,
            "--port",
            str(cfg.dashboard.port),
        ],
        env=env,
    )


def _open_serial_transport(
    port: str, baud: int, *, allow_url: bool, rtscts: bool
) -> SerialMavlinkTransport:
    kwargs: dict[str, Any] = {"baudrate": baud, "allow_url": allow_url, "accept_unverified_ids": True}
    if rtscts:
        kwargs["rtscts"] = True
    return SerialMavlinkTransport(port, **kwargs)


def run_preflight(cfg: OnboardConfig) -> dict[str, Any]:
    """Run non-destructive zero-TX onboard preflight diagnostics."""
    checks: list[dict[str, Any]] = []
    ok = True

    def record(name: str, passed: bool, detail: str) -> None:
        nonlocal ok
        if not passed:
            ok = False
        checks.append({"name": name, "ok": passed, "detail": detail})

    fc_p, fc_b = cfg.fc_port, cfg.fc_baud
    gcs_p: str | None = cfg.gcs_port
    gcs_b: int | str | None = cfg.gcs_baud
    try:
        if cfg.fc_port.strip().lower() == "auto" or str(cfg.fc_baud).lower() == "auto" or (
            cfg.topology == "inline"
            and (cfg.gcs_port.strip().lower() == "auto" or str(cfg.gcs_baud).lower() == "auto")
        ):
            fc_p, fc_b, gcs_p, gcs_b = _resolve_ports_and_bauds(cfg)
            record("ports_discovery", True, f"fc={fc_p}@{fc_b}, gcs={gcs_p}@{gcs_b}")
        else:
            record("ports_discovery", True, f"explicit fc={fc_p}@{fc_b}, gcs={gcs_p}@{gcs_b}")
    except Exception as exc:  # noqa: BLE001
        record("ports_discovery", False, str(exc))

    try:
        key, mgmt_key, _token, allowlist = _validate_onboard(
            cfg, resolved_fc_port=str(fc_p), resolved_gcs_port=None if gcs_p is None else str(gcs_p)
        )
        record(
            "config_and_boundaries",
            True,
            f"topology={cfg.topology}, mode={cfg.defense_mode}, signing={'on' if key else 'off'}, "
            f"mgmt_key={'on' if mgmt_key else 'off'}, allowlist={getattr(allowlist, 'sha256', 'none')}",
        )
    except Exception as exc:  # noqa: BLE001
        record("config_and_boundaries", False, str(exc))

    try:
        run_root = Path(cfg.run_root)
        run_root.mkdir(parents=True, exist_ok=True)
        probe = run_root / f".preflight-{os.getpid()}.tmp"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        record("run_root_writable", True, str(run_root))
    except Exception as exc:  # noqa: BLE001
        record("run_root_writable", False, str(exc))

    return {
        "ok": ok,
        "topology": cfg.topology,
        "defense_mode": cfg.defense_mode,
        "fc_port": str(fc_p),
        "fc_baud": fc_b,
        "gcs_port": None if gcs_p is None else str(gcs_p),
        "gcs_baud": gcs_b,
        "checks": checks,
    }


def run_enroll_firmware(
    cfg: OnboardConfig,
    *,
    out_path: str | Path,
    vehicle_name: str = "companion-fc",
    timeout_s: float = 10.0,
) -> int:
    """Passively listen for ``AUTOPILOT_VERSION`` (0 B TX) and pin it into a firmware allowlist YAML."""
    try:
        fc_p, fc_b, _, _ = _resolve_ports_and_bauds(cfg)
    except ValueError as exc:
        print(f"aegis onboard --enroll-firmware: {exc}", file=sys.stderr)
        return 2
    entry = capture_autopilot_version_passive(fc_p, baudrate=int(fc_b), timeout_s=timeout_s)
    if entry is None:
        print(
            f"aegis onboard --enroll-firmware: timed out waiting for AUTOPILOT_VERSION on {fc_p}@{fc_b}",
            file=sys.stderr,
        )
        return 2

    out = Path(out_path)
    doc: dict[str, Any] = {"schema": "aegisflight.firmware_allowlist/1", "vehicles": []}
    if out.is_file():
        try:
            load_firmware_allowlist(out)
        except (AllowlistError, OSError) as exc:
            print(
                f"aegis onboard --enroll-firmware: refusing to modify existing allowlist {out}: {exc}",
                file=sys.stderr,
            )
            return 2
        existing = yaml.safe_load(out.read_text(encoding="utf-8")) or {}
        if isinstance(existing, dict) and isinstance(existing.get("vehicles"), list):
            doc["vehicles"] = [v for v in existing["vehicles"] if isinstance(v, dict)]

    pinned = {
        "name": vehicle_name,
        "sysid": entry["sysid"],
        "compid": entry["compid"],
        "flight_sw_version": entry["flight_sw_version"],
        "flight_custom_version": entry["flight_custom_version_hex"],
        "board_version": entry["board_version"],
        "vendor_id": entry["vendor_id"],
        "product_id": entry["product_id"],
        "uid": entry["uid"],
    }
    doc["vehicles"] = [v for v in doc["vehicles"] if v.get("name") != vehicle_name] + [pinned]
    doc.pop("hmac_sha256", None)
    key_env = os.environ.get(ALLOWLIST_KEY_ENV)
    if key_env:
        doc["hmac_sha256"] = compute_allowlist_hmac(doc, key_env)
    out.parent.mkdir(parents=True, exist_ok=True)
    rendered = yaml.safe_dump(doc, sort_keys=False)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{out.name}.", suffix=".tmp", dir=str(out.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(rendered)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, out)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise
    print(f"aegis onboard --enroll-firmware: pinned {vehicle_name!r} -> {out} (signed={bool(key_env)})", flush=True)
    return 0


def run_onboard(
    cfg: OnboardConfig,
    *,
    seconds: float | None = None,
    stop_event: threading.Event | None = None,
) -> int:
    """Run the unified onboard companion service until ``SIGTERM``/``SIGINT`` or ``seconds``."""
    notifier = SystemdNotifier()
    try:
        # Opt-in watchdog env config is validated with the other onboard config so an
        # invalid value fails closed (rc 2, clean message) instead of a raw traceback.
        hw_watchdog = HardwareWatchdog.from_env(
            health_check=lambda: bridge.threads_healthy() if hasattr(bridge, "threads_healthy") else True
        )
        fc_port, fc_baud, gcs_port, gcs_baud = _resolve_ports_and_bauds(cfg)
        key, mgmt_key, token, allowlist = _validate_onboard(
            cfg, resolved_fc_port=fc_port, resolved_gcs_port=gcs_port
        )
        fc = _open_serial_transport(fc_port, fc_baud, allow_url=cfg.allow_url, rtscts=cfg.fc_rtscts)
        gcs: SerialMavlinkTransport | None = None
        if cfg.topology == "inline":
            assert gcs_port is not None and gcs_baud is not None
            gcs = _open_serial_transport(gcs_port, gcs_baud, allow_url=cfg.allow_url, rtscts=cfg.gcs_rtscts)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        print(f"aegis onboard: {exc}", file=sys.stderr)
        return 2

    run_root = Path(cfg.run_root)
    run_dir: Path | None = None
    archive: BridgeRunArchive | None = None
    run_prov: dict[str, Any] | None = None
    if cfg.archive_enabled:
        run_dir = _allocate_run_dir(run_root)
        try:
            run_prov = begin_run(allow_dirty=cfg.allow_dirty, profile_dir=cfg.config_dir)
        except DirtyTreeError:
            fc.close()
            if gcs is not None:
                gcs.close()
            return 2
        archive = BridgeRunArchive(
            run_dir,
            max_file_bytes=cfg.retention.max_jsonl_bytes,
            max_rotations=cfg.retention.max_rotations,
            max_total_bytes=cfg.retention.max_total_disk_bytes,
        )
        db_path = run_dir / cfg.db_name
    else:
        run_root.mkdir(parents=True, exist_ok=True)
        db_path = run_root / cfg.db_name

    store = EventStore(db_path)
    run_id = time.strftime("onboard-%Y%m%d-%H%M%S")
    store.start_run(run_id, label="onboard")
    anchor_writer = (
        AnchorWriter(
            store,
            anchor_path=db_path.with_suffix(".anchors.jsonl"),
            interval_s=cfg.anchor_interval_s,
            key=key,
        )
        if cfg.anchors_enabled
        else None
    )

    try:
        if cfg.topology == "side-tap":
            bridge: InlineIpsBridge | SideTapRunner = SideTapRunner(
                fc,
                config_dir=cfg.config_dir,
                store=store,
                run_id=run_id,
                secret_key=key,
                firmware_dir=cfg.firmware_dir,
                firmware_allowlist=allowlist,
                firmware_recheck_s=cfg.firmware_recheck_s,
                anchor_writer=anchor_writer,
                archive=archive,
                on_alarm=lambda m: print(f"aegis onboard: ALARM {m}", flush=True),
            )
        else:
            assert gcs is not None
            bridge_kwargs: dict[str, Any] = {
                "config_dir": cfg.config_dir,
                "mode": cfg.defense_mode,
                "store": store,
                "run_id": run_id,
                "secret_key": key,
                "allow_unsigned_from_trusted": cfg.signing_permissive,
                "signing_max_age_s": cfg.signing_max_age_s,
                "signing_state_path": cfg.signing_state,
                "ekf_secondary": cfg.ekf_secondary,
                "firmware_dir": cfg.firmware_dir,
                "firmware_recheck_s": cfg.firmware_recheck_s,
                "contested_policy": cfg.contested_policy,
                "replay_memory": cfg.replay_memory,
                "mgmt_key": mgmt_key,
                "mgmt_state_path": cfg.mgmt_state,
                "mgmt_max_cmd_age_s": cfg.mgmt_max_age_s,
                "lock_posture_file": cfg.lock_posture_file,
                "audit_log_path": cfg.audit_log,
                "unsigned_acknowledged": (
                    cfg.allow_unsigned and key is None and cfg.defense_mode == "active-ips"
                ),
                "vehicle_filter": cfg.vehicle_uplink_filter,
                "filter_override_file": cfg.filter_override_file,
                "filter_lockout_failopen_s": cfg.filter_lockout_failopen_s,
                "on_alarm": lambda m: print(f"aegis onboard: ALARM {m}", flush=True),
                "archive": archive,
            }
            bridge_params = inspect.signature(InlineIpsBridge.__init__).parameters
            if "mgmt_enable" in bridge_params:
                bridge_kwargs["mgmt_enable"] = cfg.mgmt_enable
                bridge_kwargs["gcs_alerts"] = cfg.gcs_alerts
                bridge_kwargs["mgmt_status_interval_s"] = cfg.mgmt_status_interval_s
                bridge_kwargs["crossend_interval_s"] = cfg.crossend_interval_s
            elif cfg.defense_mode == "passive" and not cfg.mgmt_enable:
                bridge_kwargs["gcs_alerts"] = False
                bridge_kwargs["mgmt_status_interval_s"] = 0.0
                bridge_kwargs["crossend_interval_s"] = 0.0
            else:
                bridge_kwargs["gcs_alerts"] = True if cfg.gcs_alerts is None else cfg.gcs_alerts
                bridge_kwargs["mgmt_status_interval_s"] = cfg.mgmt_status_interval_s
                bridge_kwargs["crossend_interval_s"] = cfg.crossend_interval_s
            if "firmware_allowlist" in bridge_params:
                bridge_kwargs["firmware_allowlist"] = allowlist
            if "anchor_writer" in bridge_params:
                bridge_kwargs["anchor_writer"] = anchor_writer
            if "fail_closed_uplink_commands" in bridge_params:
                bridge_kwargs["fail_closed_uplink_commands"] = cfg.fail_closed_uplink_commands
            if "semantic_firewall_enabled" in bridge_params:
                bridge_kwargs["semantic_firewall_enabled"] = cfg.semantic_firewall_enabled
            bridge = InlineIpsBridge(fc, gcs, **bridge_kwargs)
    except ValueError as exc:
        print(f"aegis onboard: {exc}", file=sys.stderr)
        store.close()
        if archive is not None:
            archive.close()
        fc.close()
        if gcs is not None:
            gcs.close()
        return 2

    ev = stop_event or threading.Event()
    old_sigint = old_sigterm = None
    on_main_thread = threading.current_thread() is threading.main_thread()

    def _on_signal(_signum: int, _frame: Any) -> None:
        ev.set()

    if on_main_thread:
        old_sigint = signal.getsignal(signal.SIGINT)
        old_sigterm = signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGINT, _on_signal)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, _on_signal)

    fc.start()
    if gcs is not None:
        gcs.start()
    bridge.start()
    status_srv: BridgeStatusServer | None = None
    dash_proc: subprocess.Popen[bytes] | None = None
    rc = 0

    try:
        if cfg.status_port > 0:
            status_srv = BridgeStatusServer(
                bridge,
                cfg.status_port,
                host=cfg.status_host,
                control_token=token,
                signing_configured=key is not None,
                allow_unsigned=cfg.allow_unsigned and cfg.defense_mode == "active-ips",
            ).start()
        dash_proc = _start_dashboard_child(cfg)
        notifier.ready(f"AegisFlight {cfg.topology} posture={cfg.defense_mode}")
        hw_watchdog.start()
        link_desc = f"{fc_port} (side-tap RX-only)" if cfg.topology == "side-tap" else f"{fc_port} <-> {gcs_port}"
        print(
            f"aegis onboard: {link_desc}, posture {cfg.defense_mode}, "
            f"status=http://{cfg.status_host}:{cfg.status_port}",
            flush=True,
        )

        deadline = None if seconds is None else time.monotonic() + max(0.0, seconds)
        check_step = max(0.2, min(cfg.retention.check_interval_s, 3.0))
        while not ev.is_set():
            wait_s = check_step
            if deadline is not None:
                rem = deadline - time.monotonic()
                if rem <= 0:
                    break
                wait_s = min(wait_s, rem)
            if ev.wait(wait_s):
                break
            threads_ok = bridge.threads_healthy() if hasattr(bridge, "threads_healthy") else True
            if not threads_ok:
                print("aegis onboard: worker thread died unexpectedly; failing fast for supervisor restart", file=sys.stderr)
                rc = 1
                break
            notifier.watchdog()
            try:
                bridge.rotate_store(
                    max_bytes=cfg.retention.max_db_bytes,
                    max_rotations=cfg.retention.max_rotations,
                    run_id_prefix="onboard",
                )
            except Exception as exc:  # noqa: BLE001 - a rotation fault must never stop the IDS (bridge already logs it)
                print(f"aegis onboard: store rotation failed: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
            if cfg.retention.max_total_disk_bytes > 0:
                active = set(ARCHIVE_FILES) | {cfg.db_name, "run_manifest.json", db_path.with_suffix(".anchors.jsonl").name}
                pruned_names: list[str] = []
                deleted = prune_rotated_files(
                    db_path.parent,
                    max_total_bytes=cfg.retention.max_total_disk_bytes,
                    active_names=active,
                    deleted_paths=pruned_names,
                )
                if archive is not None and deleted > 0:
                    archive.record_pruned(deleted)
                if deleted > 0:
                    with bridge._store_lock, contextlib.suppress(Exception):
                        if bridge.store is not None:
                            bridge.store.log_action(
                                bridge.run_id,
                                time.time(),
                                "retention",
                                "PRUNE_ROTATED",
                                str(db_path.parent),
                                f"Pruned {deleted} rotated segment(s): {', '.join(pruned_names)}",
                            )
    finally:
        hw_watchdog.stop()
        notifier.stopping()
        if dash_proc is not None and dash_proc.poll() is None:
            dash_proc.terminate()
            try:
                dash_proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                dash_proc.kill()
        if status_srv is not None:
            status_srv.close()
        bridge.close()
        with bridge._store_lock, contextlib.suppress(Exception):
            if bridge.store is not None:
                bridge.store.close()
        if archive is not None and run_prov is not None and run_dir is not None:
            try:
                archive_stats = archive.close()
            except Exception as exc:  # noqa: BLE001
                archive_stats = {"complete": False, "writer_error": f"{type(exc).__name__}: {exc}"}
            run_prov["bridge"] = {
                "topology": cfg.topology,
                "fc_port": fc_port,
                "gcs_port": gcs_port,
                "defense_mode": cfg.defense_mode,
                "signing": key is not None,
                "final_status": bridge.status(),
                "archive": archive_stats,
            }
            write_manifest(run_dir, finish_run(run_prov))
            print(f"aegis onboard: shutdown clean, archive={run_dir}", flush=True)
        if on_main_thread:
            if old_sigint is not None:
                signal.signal(signal.SIGINT, old_sigint)
            if old_sigterm is not None and hasattr(signal, "SIGTERM"):
                signal.signal(signal.SIGTERM, old_sigterm)

    return rc
