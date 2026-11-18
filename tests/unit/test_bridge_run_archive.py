"""Issue #25: an inline-bridge run archives both directions' raw frames, decisions, actions and a manifest."""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest
from test_inline_ips import (  # noqa: E402 - sibling test module
    FakeLink,
    command_long,
    gpi,
    heartbeat,
)

from aegisflight import run_provenance
from aegisflight.hal.inline_ips import InlineIpsBridge
from aegisflight.hal.run_archive import BridgeRunArchive
from aegisflight.mitigation.inline_policy import MAV_CMD_DO_SET_MODE


def _rows(p: Path) -> list[dict]:
    return [json.loads(x) for x in p.read_text().splitlines() if x]


def test_archive_records_both_directions_raw_with_verdicts(tmp_path):
    fc, gcs = FakeLink(), FakeLink()
    arch = BridgeRunArchive(tmp_path / "run")
    b = InlineIpsBridge(fc, gcs, mode="active-ips", crossend_interval_s=0, archive=arch)
    down = [heartbeat(), gpi()]
    pilot = command_long(255, MAV_CMD_DO_SET_MODE, 1, 4)
    hostile = command_long(66, MAV_CMD_DO_SET_MODE, 1, 9)
    fc.feed(*down)
    gcs.feed(pilot, hostile)
    b.pump_once()
    b.close()
    d = tmp_path / "run"
    fd, fu = _rows(d / "frames_down.jsonl"), _rows(d / "frames_up.jsonl")
    assert [bytes.fromhex(r["raw"]) for r in fd] == down and {r["verdict"] for r in fd} == {"forwarded"}
    assert [bytes.fromhex(r["raw"]) for r in fu] == [pilot, hostile]  # ORIGINAL bytes, even the one that was dropped
    assert [r["verdict"] for r in fu] == ["forwarded", "dropped"] and fu[1]["raw"] == hostile.hex()
    assert all(isinstance(r["t_ns"], int) for r in fd + fu)
    for n in ("decisions.jsonl", "actions.jsonl"):
        assert (d / n).exists()
    assert arch.stats()["rows"]["frames_down.jsonl"] == 2 and arch.stats()["complete"] is True


def test_archive_records_decisions_and_actions(tmp_path):
    arch = BridgeRunArchive(tmp_path / "run")
    fc, gcs = FakeLink(), FakeLink()
    b = InlineIpsBridge(fc, gcs, mode="passive", crossend_interval_s=0, archive=arch)

    class A:  # minimal assessment
        t = 1.5
        threat = True
        is_alert = True
        threat_score = 0.91234
        evidence = ["e1"]

        class attack_type:  # noqa: N801
            value = "GPS_SPOOFING"

    arch.decision(5, A, "passive", "NORMAL", "none")
    arch.summary_changed(5, "none", "passive", "NORMAL")
    arch.summary_changed(6, "none", "passive", "NORMAL")  # unchanged -> not repeated
    arch.action(7, "counter_frame", "fc", b"\xfd\x01")
    b.close()
    dec = _rows(tmp_path / "run" / "decisions.jsonl")
    assert dec == [{"t_ns": 5, "t": 1.5, "threat": True, "alert": True, "type": "GPS_SPOOFING", "score": 0.9123,
                    "evidence": ["e1"], "mode": "passive", "state": "NORMAL", "summary": "none"}]
    act = _rows(tmp_path / "run" / "actions.jsonl")
    assert [a["kind"] for a in act] == ["summary", "counter_frame"] and act[1]["raw"] == "fd01" and act[1]["to"] == "fc"


def test_archive_overflow_is_counted_not_silent(tmp_path):
    arch = BridgeRunArchive(tmp_path / "r", max_queue=2, flush_interval_s=60)
    for i in range(5):
        arch.frame("down", i, b"\xfd", [b"\xfd"])
    st = arch.close()
    assert st["dropped_rows"] == 3 and st["rows"]["frames_down.jsonl"] == 2 and st["complete"] is False


def test_archive_refuses_a_previous_run_dir(tmp_path):
    BridgeRunArchive(tmp_path / "r").close()
    with pytest.raises(FileExistsError):
        BridgeRunArchive(tmp_path / "r")


cli = importlib.import_module("aegisflight.cli.main")
_BASE = ["ips-bridge", "--fc-port", "socket://127.0.0.1:1", "--gcs-port", "socket://127.0.0.1:2", "--allow-url",
         "--seconds", "0.3", "--status-interval", "0.1"]


def test_cli_run_dir_writes_manifest_and_logs(tmp_path, monkeypatch):
    monkeypatch.setattr(run_provenance, "tree_state", lambda repo=None: {"commit": "c" * 40, "dirty": False, "dirty_paths": []})
    rd = tmp_path / "run"
    assert cli.main([*_BASE, "--run-dir", str(rd)]) == 0
    m = json.loads((rd / "run_manifest.json").read_text())
    assert m["schema"] == "aegisflight.run_manifest/1" and m["status"] == "REPRODUCIBLE" and m["ended_utc"]
    assert m["ml_enabled"] is False and m["model_path"] == "none"
    assert m["bridge"]["archive"]["complete"] is True and m["bridge"]["defense_mode"] == "passive"
    for n in ("frames_down.jsonl", "frames_up.jsonl", "decisions.jsonl", "actions.jsonl", "events.sqlite"):
        assert (rd / n).exists()
    assert not (rd / "NOT-REPRODUCIBLE").exists()


def test_cli_run_dir_refuses_dirty_then_stamps(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(run_provenance, "tree_state",
                        lambda repo=None: {"commit": "c" * 40, "dirty": True, "dirty_paths": ["src/x.py"]})
    assert cli.main([*_BASE, "--run-dir", str(tmp_path / "a")]) == 2
    assert "--allow-dirty" in capsys.readouterr().err and not (tmp_path / "a" / "run_manifest.json").exists()
    assert cli.main([*_BASE, "--run-dir", str(tmp_path / "b"), "--allow-dirty"]) == 0
    assert (tmp_path / "b" / "NOT-REPRODUCIBLE").is_file()
    assert json.loads((tmp_path / "b" / "run_manifest.json").read_text())["status"] == "NOT-REPRODUCIBLE"


def test_archive_records_the_management_stream_sent_to_the_gcs(tmp_path):
    """Management alerts / status / ACKs (PR #39) leave the bridge for the GCS too: an evidence run must archive every
    one of them, byte-identical to what was sent, or the run's record of bridge output is silently incomplete."""
    fc, gcs = FakeLink(), FakeLink()
    arch = BridgeRunArchive(tmp_path / "run")
    b = InlineIpsBridge(fc, gcs, mode="passive", crossend_interval_s=0, archive=arch)
    b.mgmt.action("FILTER_TEST", "")
    b.close()
    mgmt = [a for a in _rows(tmp_path / "run" / "actions.jsonl") if a["kind"] == "mgmt"]
    assert mgmt and all(a["to"] == "gcs" for a in mgmt)
    assert [bytes.fromhex(a["raw"]) for a in mgmt] == gcs.sent


def test_without_an_archive_the_management_stream_goes_straight_to_the_gcs():
    fc, gcs = FakeLink(), FakeLink()
    b = InlineIpsBridge(fc, gcs, mode="passive", crossend_interval_s=0)
    b.mgmt.action("FILTER_TEST", "")
    b.close()
    assert gcs.sent  # unchanged behaviour when no evidence run is configured
