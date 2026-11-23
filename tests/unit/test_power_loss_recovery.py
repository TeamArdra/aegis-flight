"""SIGKILL mid-write recovery for SQLite WAL + AnchorWriter (SIM; process-kill, not real power cut)."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from aegisflight.logging import ANCHOR_KEY_ENV, AnchorWriter, EventStore, verify_anchors

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="SIGKILL semantics are POSIX")

WRITER = textwrap.dedent(
    """
    import sys, time
    from pathlib import Path
    from tests.unit.test_anchors_and_actions_chain import _assessment
    from aegisflight.logging import AnchorWriter, EventStore
    db = Path(sys.argv[1])
    store = EventStore(db)
    store.start_run("kill-run", label="sim")
    aw = AnchorWriter(store, interval_s=0.2)
    print("READY", flush=True)
    i = 0
    while True:
        i += 1
        store.log_event(_assessment(float(i), 0.7), "kill-run")
        if i % 20 == 0:
            aw.write_now("kill-run", force=True)
    """
)


@pytest.mark.parametrize("delay_s", [0.15, 0.4, 0.8])
def test_sigkill_mid_write_recovers_or_detects(tmp_path: Path, delay_s: float) -> None:
    root = Path(__file__).resolve().parents[2]
    db = tmp_path / "events.sqlite"
    env = dict(os.environ, **{ANCHOR_KEY_ENV: "power-loss-key"})
    env["PYTHONPATH"] = f"{root / 'src'}{os.pathsep}{root}"
    proc = subprocess.Popen([sys.executable, "-c", WRITER, str(db)], stdout=subprocess.PIPE, env=env, cwd=root, text=True)
    try:
        assert proc.stdout is not None and proc.stdout.readline().strip() == "READY"
        time.sleep(delay_s)
        proc.send_signal(signal.SIGKILL)
        proc.wait(timeout=5)
    finally:
        if proc.poll() is None:
            proc.kill()

    # Restart: reopen (WAL replay), nothing may be corrupt.
    os.environ[ANCHOR_KEY_ENV] = "power-loss-key"
    try:
        store = EventStore(db)
        assert store.conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert store.verify_chain().ok is True
        assert store.verify_actions_chain().ok is True
        n = store.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        assert n > 0
        anchors = db.with_suffix(".anchors.jsonl")
        aw = AnchorWriter(store)  # must resume the chain from a possibly torn last line
        anchors = aw.anchor_path
        if anchors.is_file():
            av = verify_anchors(store, anchors)
            # Either clean, or the only complaint is a torn final anchor line (detected, not silent).
            assert av.ok or all("invalid JSON" in e for e in av.errors), av.errors
        # Store remains writable and chained after recovery.
        from tests.unit.test_anchors_and_actions_chain import _assessment

        store.log_event(_assessment(1e6), "kill-run")
        assert store.verify_chain().ok is True
        store.close()
    finally:
        os.environ.pop(ANCHOR_KEY_ENV, None)


def test_torn_final_anchor_line_is_detected_not_silent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from tests.unit.test_anchors_and_actions_chain import _seed_store

    monkeypatch.setenv(ANCHOR_KEY_ENV, "k")
    store = _seed_store(tmp_path / "e.sqlite", "r", n=3)
    aw = AnchorWriter(store)
    aw.write_now("r", force=True)
    store.log_event(__import__("tests.unit.test_anchors_and_actions_chain", fromlist=["x"])._assessment(99.0), "r")
    aw.write_now("r", force=True)
    raw = aw.anchor_path.read_bytes()
    aw.anchor_path.write_bytes(raw[: len(raw) - 40])  # tear mid final line
    av = verify_anchors(store, aw.anchor_path)
    assert av.ok is False and any("invalid JSON" in e for e in av.errors)
    AnchorWriter(store)  # restart must not crash on the torn tail
    store.close()
