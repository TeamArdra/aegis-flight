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
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .hal.inline_ips import InlineIpsBridge
from .hal.run_archive import FILES as ARCHIVE_FILES
from .hal.run_archive import BridgeRunArchive
from .hal.status_server import BridgeStatusServer
from .logging import EventStore
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
    fc_port: str = "/dev/ttyAMA0"
    fc_baud: int = 921600
    gcs_port: str = "/dev/ttyUSB0"
    gcs_baud: int = 57600
    allow_url: bool = False
    defense_mode: str = "passive"
    config_dir: str | None = None
    run_root: str = DEFAULT_RUN_ROOT
    archive_enabled: bool = True
    allow_dirty: bool = True
    db_name: str = "events.sqlite"
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


def load_onboard_config(path: str | Path | None = None) -> OnboardConfig:
    """Load an :class:`OnboardConfig` from YAML (or return safe defaults if ``path`` is None)."""
    if path is None:
        return OnboardConfig()
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"onboard config {path} must be a YAML mapping")

    ret_raw = raw.get("retention") or {}
    if not isinstance(ret_raw, dict):
        raise ValueError("retention must be a YAML mapping")
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
    dash = DashboardConfig(
        enabled=bool(dash_raw.get("enabled", False)),
        host=str(dash_raw.get("host", "127.0.0.1")),
        port=int(dash_raw.get("port", 8000)),
    )

    gcs_alerts_raw = raw.get("gcs_alerts")
    gcs_alerts = None if gcs_alerts_raw is None else bool(gcs_alerts_raw)

    return OnboardConfig(
        fc_port=str(raw.get("fc_port", "/dev/ttyAMA0")),
        fc_baud=int(raw.get("fc_baud", 921600)),
        gcs_port=str(raw.get("gcs_port", "/dev/ttyUSB0")),
        gcs_baud=int(raw.get("gcs_baud", 57600)),
        allow_url=bool(raw.get("allow_url", False)),
        defense_mode=str(raw.get("defense_mode", "passive")),
        config_dir=_clean_opt_str(raw.get("config_dir")),
        run_root=str(raw.get("run_root", DEFAULT_RUN_ROOT)),
        archive_enabled=bool(raw.get("archive_enabled", True)),
        allow_dirty=bool(raw.get("allow_dirty", True)),
        db_name=str(raw.get("db_name", "events.sqlite")),
        signing_key_file=_clean_opt_str(raw.get("signing_key_file")),
        signing_state=_clean_opt_str(raw.get("signing_state")),
        signing_permissive=bool(raw.get("signing_permissive", False)),
        signing_max_age_s=(
            None if raw.get("signing_max_age_s") is None else float(raw["signing_max_age_s"])
        ),
        allow_unsigned=bool(raw.get("allow_unsigned", False)),
        mgmt_enable=bool(raw.get("mgmt_enable", False)),
        mgmt_key_file=_clean_opt_str(raw.get("mgmt_key_file")),
        mgmt_state=_clean_opt_str(raw.get("mgmt_state")),
        mgmt_max_age_s=float(raw.get("mgmt_max_age_s", 300.0)),
        lock_posture_file=_clean_opt_str(raw.get("lock_posture_file")),
        audit_log=_clean_opt_str(raw.get("audit_log")),
        gcs_alerts=gcs_alerts,
        mgmt_status_interval_s=float(raw.get("mgmt_status_interval_s", 2.0)),
        crossend_interval_s=float(raw.get("crossend_interval_s", 1.0)),
        vehicle_uplink_filter=bool(raw.get("vehicle_uplink_filter", False)),
        filter_override_file=_clean_opt_str(raw.get("filter_override_file")),
        filter_lockout_failopen_s=(
            None
            if raw.get("filter_lockout_failopen_s") is None
            else float(raw["filter_lockout_failopen_s"])
        ),
        firmware_dir=_clean_opt_str(raw.get("firmware_dir")),
        firmware_recheck_s=float(raw.get("firmware_recheck_s", 30.0)),
        ekf_secondary=bool(raw.get("ekf_secondary", False)),
        contested_policy=str(raw.get("contested_policy", "alert")),
        replay_memory=int(raw.get("replay_memory", 4096)),
        status_host=str(raw.get("status_host", "127.0.0.1")),
        status_port=int(raw.get("status_port", 8090)),
        status_interval_s=float(raw.get("status_interval_s", 5.0)),
        control_token_file=_clean_opt_str(raw.get("control_token_file")),
        retention=ret,
        dashboard=dash,
    )


def _validate_onboard(cfg: OnboardConfig) -> tuple[bytes | None, bytes | None, str | None]:
    if cfg.defense_mode not in ("passive", "advisory", "active-ips"):
        raise ValueError(f"invalid defense_mode {cfg.defense_mode!r}")
    if cfg.fc_port == cfg.gcs_port:
        raise ValueError("fc_port and gcs_port must differ")
    if cfg.defense_mode == "active-ips" and may_reach_vehicle(cfg.fc_port):
        raise ValueError(
            f"refusing defense_mode='active-ips' on fc_port {cfg.fc_port}: serial links are receive-only"
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

    token = None
    if cfg.control_token_file:
        token = Path(cfg.control_token_file).read_text(encoding="utf-8").strip()
        if not token:
            raise ValueError("control_token_file is empty")
    if not _is_loopback(cfg.status_host) and token is None:
        raise ValueError(f"non-loopback status_host {cfg.status_host!r} requires control_token_file")
    return key, mgmt_key, token


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


def run_onboard(
    cfg: OnboardConfig,
    *,
    seconds: float | None = None,
    stop_event: threading.Event | None = None,
) -> int:
    """Run the unified onboard companion service until ``SIGTERM``/``SIGINT`` or ``seconds``."""
    try:
        key, mgmt_key, token = _validate_onboard(cfg)
        fc = SerialMavlinkTransport(
            cfg.fc_port, baudrate=cfg.fc_baud, allow_url=cfg.allow_url, accept_unverified_ids=True
        )
        gcs = SerialMavlinkTransport(
            cfg.gcs_port, baudrate=cfg.gcs_baud, allow_url=cfg.allow_url, accept_unverified_ids=True
        )
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

    try:
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
        bridge = InlineIpsBridge(fc, gcs, **bridge_kwargs)
    except ValueError as exc:
        print(f"aegis onboard: {exc}", file=sys.stderr)
        store.close()
        if archive is not None:
            archive.close()
        fc.close()
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
    gcs.start()
    bridge.start()
    status_srv: BridgeStatusServer | None = None
    dash_proc: subprocess.Popen[bytes] | None = None

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
        print(
            f"aegis onboard: {cfg.fc_port} <-> {cfg.gcs_port}, posture {cfg.defense_mode}, "
            f"status=http://{cfg.status_host}:{cfg.status_port}",
            flush=True,
        )

        deadline = None if seconds is None else time.monotonic() + max(0.0, seconds)
        check_step = max(0.2, min(cfg.retention.check_interval_s, 5.0))
        while not ev.is_set():
            wait_s = check_step
            if deadline is not None:
                rem = deadline - time.monotonic()
                if rem <= 0:
                    break
                wait_s = min(wait_s, rem)
            if ev.wait(wait_s):
                break
            bridge.rotate_store(
                max_bytes=cfg.retention.max_db_bytes,
                max_rotations=cfg.retention.max_rotations,
                run_id_prefix="onboard",
            )
            if cfg.retention.max_total_disk_bytes > 0:
                active = set(ARCHIVE_FILES) | {cfg.db_name, "run_manifest.json"}
                prune_rotated_files(
                    db_path.parent,
                    max_total_bytes=cfg.retention.max_total_disk_bytes,
                    active_names=active,
                )
    finally:
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
                "fc_port": cfg.fc_port,
                "gcs_port": cfg.gcs_port,
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

    return 0
