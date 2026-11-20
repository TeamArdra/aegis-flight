"""Unit and signal-shutdown tests for unified onboard companion runtime (#59)."""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
import yaml

from aegisflight.core.enums import AttackType, Severity
from aegisflight.core.types import ThreatAssessment
from aegisflight.hal.run_archive import BridgeRunArchive
from aegisflight.logging import EventStore
from aegisflight.logging.rotation import (
    prune_rotated_files,
    rotate_file_series,
    rotate_sqlite_store,
)
from aegisflight.onboard import OnboardConfig, _validate_onboard, load_onboard_config

REPO_ROOT = Path(__file__).resolve().parents[2]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_default_config_is_safe_passive_and_blocks_active_on_serial() -> None:
    cfg = load_onboard_config(REPO_ROOT / "configs" / "onboard_default.yaml")
    assert cfg.defense_mode == "passive"
    assert cfg.mgmt_enable is False
    assert cfg.allow_url is False
    assert cfg.fc_port == "/dev/ttyAMA0"
    assert cfg.retention.max_db_bytes > 0
    assert cfg.retention.max_total_disk_bytes > 0

    bad = OnboardConfig(fc_port="/dev/ttyAMA0", gcs_port="/dev/ttyUSB0", defense_mode="active-ips")
    with pytest.raises(ValueError, match="receive-only"):
        _validate_onboard(bad)


def test_scripts_and_systemd_unit_have_safe_parameterized_defaults() -> None:
    unit = (REPO_ROOT / "deploy" / "aegis-onboard.service").read_text(encoding="utf-8")
    assert "KillSignal=SIGTERM" in unit
    assert "Restart=on-failure" in unit
    assert "/home/ardra" not in unit

    autostart = (REPO_ROOT / "scripts" / "radio_test" / "pi_autostart.sh").read_text(encoding="utf-8")
    assert "${MODE:-passive}" in autostart
    assert "active-ips" not in autostart

    bridge_sh = (REPO_ROOT / "scripts" / "radio_test" / "pi_bridge.sh").read_text(encoding="utf-8")
    assert "${2:-passive}" in bridge_sh
    assert "/home/ardra" not in bridge_sh


def test_sqlite_rotation_preserves_independent_verifiable_hash_chains(tmp_path: Path) -> None:
    db_path = tmp_path / "events.sqlite"
    store = EventStore(db_path)
    store.start_run("run-1", label="onboard")
    for i in range(40):
        store.log_event(
            ThreatAssessment(
                t=float(i),
                wall_time=1000.0 + i,
                threat=True,
                threat_score=0.9,
                severity=Severity.HIGH,
                attack_type=AttackType.DOS,
                confidence=0.9,
                evidence=[f"ev-{i}"],
                detector_scores={"protocol_rule": 0.9},
                contributing_detectors=[],
                is_alert=True,
            ),
            "run-1",
        )
    cur_size = db_path.stat().st_size
    assert cur_size > 0

    fresh, rotated = rotate_sqlite_store(
        store, max_bytes=1, max_rotations=3, run_id="run-2", label="onboard"
    )
    assert rotated is True
    rotated_db = tmp_path / "events.1.sqlite"
    assert rotated_db.exists() and db_path.exists()

    fresh.log_event(
        ThreatAssessment(
            t=1.0,
            wall_time=2000.0,
            threat=True,
            threat_score=0.8,
            severity=Severity.HIGH,
            attack_type=AttackType.DOS,
            confidence=0.8,
            evidence=["fresh"],
            detector_scores={"protocol_rule": 0.8},
            contributing_detectors=[],
            is_alert=True,
        ),
        "run-2",
    )
    fresh.close()

    arch_check = EventStore(rotated_db)
    assert arch_check.verify_chain().ok is True
    assert arch_check.count_events() == 40
    prev_head = arch_check.conn.execute("SELECT hash FROM events ORDER BY id DESC LIMIT 1").fetchone()["hash"]
    arch_check.close()

    cur_check = EventStore(db_path)
    assert cur_check.verify_chain().ok is True
    assert cur_check.verify_actions_chain().ok is True
    assert cur_check.count_events() == 1
    meta_json = json.loads(cur_check.list_runs()[0]["meta"])
    assert meta_json["prev_segment"]["last_event_hash"] == prev_head
    assert meta_json["prev_segment"]["event_count"] == 40
    act_rows = cur_check.conn.execute("SELECT action, detail FROM actions WHERE action='ROTATION_LINK'").fetchall()
    assert len(act_rows) == 1
    assert json.loads(act_rows[0]["detail"])["last_event_hash"] == prev_head
    cur_check.close()


def test_archive_rotation_and_disk_cap_enforcement(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    arch = BridgeRunArchive(
        run_dir,
        flush_interval_s=0.05,
        max_file_bytes=400,
        max_rotations=3,
        max_total_bytes=4096,
    )
    for i in range(40):
        arch.action(i * 1000, "alarm", "gcs", b"1234567890" * 4, idx=i)
        time.sleep(0.01)
    stats = arch.close()
    assert stats["rotations"]["actions.jsonl"] >= 1
    assert (run_dir / "actions.1.jsonl").exists()
    if stats["rotated_out_files"] > 0 or stats["pruned_files"] > 0:
        assert stats["complete"] is False

    # Create extra large rotated segments and verify prune_rotated_files caps disk without touching active files
    for idx in (2, 3, 4):
        p = run_dir / f"actions.{idx}.jsonl"
        p.write_bytes(b"x" * 2048)
    deleted = prune_rotated_files(
        run_dir,
        max_total_bytes=3500,
        active_names={"actions.jsonl", "decisions.jsonl", "frames_down.jsonl", "frames_up.jsonl"},
    )
    assert deleted >= 1
    assert (run_dir / "actions.jsonl").exists()

    # Direct rotate_file_series check
    f = tmp_path / "sample.jsonl"
    f.write_bytes(b"a" * 500)
    assert rotate_file_series(f, max_bytes=100, max_rotations=2) is True
    assert (tmp_path / "sample.1.jsonl").exists()


def test_archive_marks_complete_false_when_segments_rotated_out_and_missing_joblib_warns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from aegisflight.detectors.anomaly import AnomalyDetector

    run_dir = tmp_path / "run_incomplete"
    arch = BridgeRunArchive(
        run_dir,
        flush_interval_s=0.02,
        max_file_bytes=80,
        max_rotations=1,
        max_total_bytes=0,
    )
    for i in range(25):
        arch.action(i * 1000, "alarm", "gcs", b"abcdef0123456789", idx=i)
        time.sleep(0.01)
    st = arch.close()
    assert st["rotated_out_files"] >= 1
    assert st["discarded_bytes"] > 0
    assert st["complete"] is False

    # Missing joblib when a model file exists -> explicit RuntimeWarning + load_error recorded
    fake_model = tmp_path / "fake.joblib"
    fake_model.write_bytes(b"placeholder")
    monkeypatch.setitem(sys.modules, "joblib", None)
    with pytest.warns(RuntimeWarning, match="AnomalyDetector disabled"):
        det = AnomalyDetector({}, model_path=fake_model)
    assert det.available is False
    assert det.load_error is not None and "ImportError" in det.load_error


@pytest.mark.skipif(not hasattr(signal, "SIGTERM"), reason="SIGTERM requires POSIX")
def test_sigterm_shuts_down_onboard_cleanly_with_valid_sqlite_and_manifest(tmp_path: Path) -> None:
    fc_port = _free_port()
    gcs_port = _free_port()
    status_port = _free_port()
    run_root = tmp_path / "runs"
    cfg_path = tmp_path / "onboard.yaml"
    cfg_path.write_text(
        yaml.safe_dump(
            {
                "fc_port": f"socket://127.0.0.1:{fc_port}",
                "gcs_port": f"socket://127.0.0.1:{gcs_port}",
                "allow_url": True,
                "defense_mode": "passive",
                "run_root": str(run_root),
                "archive_enabled": True,
                "allow_dirty": True,
                "status_host": "127.0.0.1",
                "status_port": status_port,
                "retention": {
                    "max_db_bytes": 1024 * 1024,
                    "max_jsonl_bytes": 1024 * 1024,
                    "max_rotations": 3,
                    "max_total_disk_bytes": 10 * 1024 * 1024,
                    "check_interval_s": 0.25,
                },
            }
        ),
        encoding="utf-8",
    )

    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT / "src") + (f":{env['PYTHONPATH']}" if env.get("PYTHONPATH") else "")
    proc = subprocess.Popen(
        [sys.executable, "-m", "aegisflight.cli.main", "onboard", "--config", str(cfg_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    try:
        # Wait briefly until run dir & manifest/sqlite creation starts
        deadline = time.monotonic() + 8.0
        run_dirs: list[Path] = []
        while time.monotonic() < deadline:
            if run_root.exists():
                run_dirs = [p for p in run_root.iterdir() if p.is_dir()]
                if run_dirs and (run_dirs[0] / "events.sqlite").exists():
                    break
            time.sleep(0.1)
        assert run_dirs, proc.stderr.read()

        time.sleep(0.4)
        proc.send_signal(signal.SIGTERM)
        rc = proc.wait(timeout=10.0)
        assert rc == 0, (proc.stdout.read(), proc.stderr.read())
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=3.0)

    rdir = run_dirs[0]
    manifest = json.loads((rdir / "run_manifest.json").read_text(encoding="utf-8"))
    assert manifest["bridge"]["defense_mode"] == "passive"
    assert manifest["bridge"]["archive"]["complete"] is True
    store = EventStore(rdir / "events.sqlite")
    try:
        assert store.verify_chain().ok is True
    finally:
        store.close()
