"""Unit tests for systemd watchdog, SQLite WAL + rotation checkpointing, and onboard preflight (W7, W8)."""

from __future__ import annotations

import socket
from pathlib import Path

from aegisflight.core.enums import AttackType, Severity
from aegisflight.core.types import ThreatAssessment
from aegisflight.hal.watchdog import SystemdNotifier
from aegisflight.logging.rotation import rotate_sqlite_store
from aegisflight.logging.store import EventStore
from aegisflight.onboard import OnboardConfig, run_preflight


def test_systemd_notifier_sends_datagrams_over_unix_socket(monkeypatch) -> None:
    import os

    sock_path = Path(f"/tmp/aegis-notify-{os.getpid()}.sock")
    sock_path.unlink(missing_ok=True)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    srv.bind(str(sock_path))
    srv.settimeout(1.0)
    monkeypatch.setenv("NOTIFY_SOCKET", str(sock_path))
    try:
        notifier = SystemdNotifier()
        assert notifier.enabled is True
        assert notifier.ready("booted") is True
        assert notifier.watchdog() is True
        assert notifier.stopping() is True

        msgs = [srv.recv(512).decode("utf-8") for _ in range(3)]
        assert msgs[0] == "READY=1\nSTATUS=booted"
        assert msgs[1] == "WATCHDOG=1"
        assert msgs[2] == "STOPPING=1"
    finally:
        srv.close()
        sock_path.unlink(missing_ok=True)


def test_sqlite_wal_enabled_and_cleanly_checkpointed_on_rotation(tmp_path: Path) -> None:
    db_path = tmp_path / "events.sqlite"
    store = EventStore(db_path)
    mode = store.conn.execute("PRAGMA journal_mode;").fetchone()[0]
    assert str(mode).lower() == "wal"
    store.start_run("wal-run")
    for k in range(25):
        store.log_event(
            ThreatAssessment(
                t=float(k), wall_time=float(k), threat=True, threat_score=0.8,
                severity=Severity.HIGH, attack_type=AttackType.GPS_SPOOFING, confidence=0.8,
                evidence=[f"e{k}" * 20],
            ),
            "wal-run",
        )
    fresh, rotated = rotate_sqlite_store(store, max_bytes=1024, max_rotations=3, run_id="wal-run-2")
    assert rotated is True
    assert fresh.verify_chain("wal-run-2").ok
    fresh.close()


def test_onboard_preflight_validates_receive_only_and_boundaries(tmp_path: Path) -> None:
    cfg_ok = OnboardConfig(
        topology="side-tap",
        fc_port="/dev/ttyAMA0",
        defense_mode="passive",
        run_root=str(tmp_path / "runs"),
    )
    rep_ok = run_preflight(cfg_ok)
    assert rep_ok["ok"] is True

    # Side-tap + active-ips must fail validation safely in preflight
    cfg_bad = OnboardConfig(
        topology="side-tap",
        fc_port="/dev/ttyAMA0",
        defense_mode="active-ips",
        run_root=str(tmp_path / "runs2"),
    )
    rep_bad = run_preflight(cfg_bad)
    assert rep_bad["ok"] is False
