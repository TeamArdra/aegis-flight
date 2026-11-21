"""Unit & integration tests for external chain anchoring and the actions chain (#21)."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import warnings
from pathlib import Path

import pytest
from tests.unit.test_inline_ips import FakeLink, command_long

from aegisflight.cli.main import main as aegis_main
from aegisflight.core.enums import AttackType, IntegrityStatus, Severity
from aegisflight.core.types import ThreatAssessment
from aegisflight.hal.inline_ips import InlineIpsBridge
from aegisflight.logging import (
    ANCHOR_KEY_ENV,
    AnchorWriter,
    EventStore,
    default_anchors_path,
    verify_anchors,
)
from aegisflight.mitigation.actuator import MavlinkActuator

FIXTURE_SQL = Path(__file__).resolve().parents[1] / "fixtures" / "legacy_f9945a7.sql"


def _assessment(t: float, score: float = 0.8) -> ThreatAssessment:
    return ThreatAssessment(
        t=t,
        wall_time=1_700_000_000.0 + t,
        threat=True,
        threat_score=score,
        severity=Severity.HIGH,
        attack_type=AttackType.GPS_SPOOFING,
        confidence=0.9,
        secondary_indicators=[],
        evidence=[f"pos mismatch t={t}"],
        detector_scores={"PHYSICS": score},
        contributing_detectors=["PHYSICS"],
        integrity_status=IntegrityStatus.VALID,
        telemetry={"lat": 12.9, "lon": 77.5},
        latency_ms=0.5,
        is_alert=True,
    )


def _seed_store(db_path: Path, run_id: str = "run-1", n: int = 4) -> EventStore:
    store = EventStore(db_path)
    store.start_run(run_id, label="sim")
    for i in range(n):
        store.log_event(_assessment(float(i + 1), 0.7 + 0.02 * i), run_id)
    return store


def test_anchor_detects_tail_truncation_and_deleted_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db = tmp_path / "events.sqlite"
    store = _seed_store(db, "run-a", n=4)
    store.start_run("run-b", label="sim")
    store.log_event(_assessment(10.0), "run-b")

    monkeypatch.setenv(ANCHOR_KEY_ENV, "anchor-secret-key")
    aw = AnchorWriter(store)
    rec_a = aw.write_now("run-a", force=True)
    aw.write_now("run-b", force=True)
    assert rec_a is not None and rec_a["signed"] is True

    # Healthy database + anchors -> OK
    av_ok = verify_anchors(store, aw.anchor_path)
    assert av_ok.ok is True and av_ok.signed_anchors == 2

    # 1. Delete last k rows of run-a (tail truncation) -> detected!
    store.conn.execute("DELETE FROM events WHERE run_id='run-a' AND t >= 3.0")
    store.conn.commit()
    av_trunc = verify_anchors(store, aw.anchor_path)
    assert av_trunc.ok is False
    assert any("truncated" in err for err in av_trunc.errors), av_trunc.errors

    # 2. Delete all rows of run-b (whole run deleted) -> detected!
    store.conn.execute("DELETE FROM events WHERE run_id='run-b'")
    store.conn.commit()
    av_del = verify_anchors(store, aw.anchor_path)
    assert av_del.ok is False
    assert any("run-b" in err and "missing from database" in err for err in av_del.errors), av_del.errors
    store.close()


def test_anchor_detects_edit_row_and_anchor_hmac_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "events.sqlite"
    store = _seed_store(db, "run-1", n=3)
    monkeypatch.setenv(ANCHOR_KEY_ENV, "anchor-key-42")
    aw = AnchorWriter(store)
    aw.write_now("run-1", force=True)
    store.close()

    # Valid CLI verify-log with --anchors
    assert aegis_main(["verify-log", str(db), "--anchors", str(aw.anchor_path)]) == 0
    out = capsys.readouterr().out
    assert "events: 3  chain: OK" in out and "status: OK" in out

    # Tamper anchor head_hash -> HMAC failure
    lines = aw.anchor_path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[-1])
    rec["row_count"] = 1
    tampered_path = tmp_path / "tampered.anchors.jsonl"
    tampered_path.write_text(json.dumps(rec) + "\n", encoding="utf-8")
    assert aegis_main(["verify-log", str(db), "--anchors", str(tampered_path)]) == 2
    capsys.readouterr()

    # Strip hmac_sha256 + set signed=False and lower row_count/last_id/head_hash -> rejected when key set (R1)
    stripped_rec = json.loads(lines[-1])
    stripped_rec.pop("hmac_sha256", None)
    stripped_rec["signed"] = False
    stripped_rec["row_count"] = 1
    stripped_rec["last_id"] = 1
    stripped_path = tmp_path / "stripped.anchors.jsonl"
    stripped_path.write_text(json.dumps(stripped_rec) + "\n", encoding="utf-8")
    assert aegis_main(["verify-log", str(db), "--anchors", str(stripped_path)]) == 2
    capsys.readouterr()

    # Missing AEGIS_ANCHOR_KEY for signed anchor -> fails verification
    monkeypatch.delenv(ANCHOR_KEY_ENV, raising=False)
    assert aegis_main(["verify-log", str(db), "--anchors", str(aw.anchor_path)]) == 2
    capsys.readouterr()

    # Edit an event row -> verify_chain detects it as before
    s2 = EventStore(db)
    s2.conn.execute("UPDATE events SET threat_score = 0.1 WHERE id = 1")
    s2.conn.commit()
    assert s2.verify_chain("run-1").ok is False
    s2.close()


def test_anchor_unsigned_warns_when_key_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv(ANCHOR_KEY_ENV, raising=False)
    db = tmp_path / "unsigned.sqlite"
    store = _seed_store(db, "run-u", n=2)
    aw = AnchorWriter(store)
    with warnings.catch_warnings(record=True) as rec:
        warnings.simplefilter("always")
        anchor = aw.write_now("run-u", force=True)
    assert anchor is not None and anchor["signed"] is False
    assert any("unsigned event-log anchor" in str(w.message) for w in rec)
    snap = aw.snapshot()
    assert snap is not None and snap["head_hash"] == anchor["head_hash"] and snap["signed"] is False
    store.close()

    assert default_anchors_path(db) == aw.anchor_path
    assert aegis_main(["verify-log", str(db), "--anchors", str(aw.anchor_path)]) == 0
    captured = capsys.readouterr()
    assert "unsigned anchor" in captured.err.lower()
    assert "unsigned: 1" in captured.out


def test_legacy_f9945a7_database_verifies_byte_identically_without_mutation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "legacy_f9945a7.sqlite"
    conn = sqlite3.connect(str(db))
    conn.executescript(FIXTURE_SQL.read_text(encoding="utf-8"))
    conn.close()
    before_sha = hashlib.sha256(db.read_bytes()).hexdigest()

    assert aegis_main(["verify-log", str(db)]) == 0
    out = capsys.readouterr().out.strip()
    assert out == "events: 2  chain: OK  1 run chain(s) intact"
    after_sha = hashlib.sha256(db.read_bytes()).hexdigest()
    assert after_sha == before_sha


def test_actions_chain_logs_bridge_drops_and_actuator_commands(tmp_path: Path) -> None:
    db = tmp_path / "bridge_actions.sqlite"
    store = EventStore(db)
    store.start_run("ips-run-1", label="ips-bridge")

    fc, gcs = FakeLink(), FakeLink()
    bridge = InlineIpsBridge(fc, gcs, mode="active-ips", store=store, run_id="ips-run-1")
    rogue_cmd = command_long(66, 176, 1, 4)  # untrusted sysid=66 -> InlinePolicy drops in active-ips
    gcs.feed(rogue_cmd)
    bridge.pump_once()
    assert bridge.dropped_up == 1

    act_events: list[tuple[str, str, str]] = []
    actuator = MavlinkActuator(
        on_action=lambda action, target, detail: (
            act_events.append((action, target, detail)),
            store.log_action("ips-run-1", 12.5, "actuator", action, target, detail),
        )
    )
    actuator.encode_set_mode("AUTO")
    assert len(act_events) == 1

    rows = store.get_actions("ips-run-1")
    assert len(rows) == 2
    assert any(r["actor"] == "inline_ips" and r["action"] == "drop_frame" for r in rows)
    assert any(r["actor"] == "actuator" and r["action"] == "encode_set_mode" for r in rows)

    cs = store.verify_actions_chain("ips-run-1")
    assert cs.ok is True and cs.length == 2

    # Tampering an action breaks the actions chain
    store.conn.execute("UPDATE actions SET detail='forged' WHERE id=1")
    store.conn.commit()
    assert store.verify_actions_chain("ips-run-1").ok is False
    store.close()


def test_anchor_chain_detects_middle_deletion_head_deletion_reordering_gaps_and_truncation(tmp_path: Path) -> None:
    """P1 anchor continuity (#21 / D6): signed anchor chain detects deletion, reordering, gaps, and truncation."""
    db = tmp_path / "chain_events.sqlite"
    store = EventStore(db)
    store.start_run("run-chain", label="sim")
    key = b"anchor-chain-test-key-32-bytes!!"
    aw = AnchorWriter(store, interval_s=0.2, key=key)

    for i in range(4):
        store.log_event(_assessment(float(i)), "run-chain")
        rec = aw.write_now("run-chain", force=True)
        assert rec is not None and rec["seq"] == i

    lines = aw.anchor_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 4
    assert verify_anchors(store, aw.anchor_path, key=key, expected_min_anchors=4).ok is True

    # 1. Middle deletion (drop seq=1) -> detected via seq discontinuity & prev_anchor_hash mismatch
    mid = tmp_path / "mid_deleted.anchors.jsonl"
    mid.write_text("\n".join([lines[0], lines[2], lines[3]]) + "\n", encoding="utf-8")
    v_mid = verify_anchors(store, mid, key=key)
    assert v_mid.ok is False
    assert any("sequence discontinuity" in e or "prev_anchor_hash" in e for e in v_mid.errors)

    # 2. Head deletion (drop seq=0) -> detected
    head = tmp_path / "head_deleted.anchors.jsonl"
    head.write_text("\n".join(lines[1:]) + "\n", encoding="utf-8")
    v_head = verify_anchors(store, head, key=key)
    assert v_head.ok is False
    assert any("sequence discontinuity" in e for e in v_head.errors)

    # 3. Reordering (swap seq=1 and seq=2) -> detected
    reord = tmp_path / "reordered.anchors.jsonl"
    reord.write_text("\n".join([lines[0], lines[2], lines[1], lines[3]]) + "\n", encoding="utf-8")
    v_reord = verify_anchors(store, reord, key=key)
    assert v_reord.ok is False

    # 4. Tail truncation (drop seq=3) -> detected when expected_min_anchors=4
    tail = tmp_path / "tail_trunc.anchors.jsonl"
    tail.write_text("\n".join(lines[:3]) + "\n", encoding="utf-8")
    v_tail = verify_anchors(store, tail, key=key, expected_min_anchors=4)
    assert v_tail.ok is False
    assert any("anchor log truncated" in e for e in v_tail.errors)

    # 5. Modified record -> detected via anchor_hash + HMAC
    mod = tmp_path / "modified.anchors.jsonl"
    r1 = json.loads(lines[1])
    r1["row_count"] = 999
    mod.write_text("\n".join([lines[0], json.dumps(r1), lines[2], lines[3]]) + "\n", encoding="utf-8")
    v_mod = verify_anchors(store, mod, key=key)
    assert v_mod.ok is False
    store.close()


@pytest.mark.parametrize("tail", ['{"seq": 1, "anchor_ha', "not json at all", "[1, 2, 3]", '{"no_seq": true}'])
def test_anchor_writer_never_forks_a_chain_with_a_corrupt_tail(tmp_path: Path, caplog: pytest.LogCaptureFixture,
                                                                tail: str) -> None:
    """R5: a corrupt last anchor line must not restart at seq=0/GENESIS in the same file."""
    db = tmp_path / "events.sqlite"
    store = _seed_store(db, "run-a", n=3)
    aw = AnchorWriter(store)
    assert aw.write_now("run-a", force=True) is not None
    path = aw.anchor_path
    with path.open("a", encoding="utf-8") as fh:
        fh.write(tail + "\n")
    before = path.read_bytes()

    with caplog.at_level("ERROR", logger="aegisflight.logging.anchors"):
        aw2 = AnchorWriter(store)
    assert any("corrupt tail" in r.getMessage() for r in caplog.records)
    assert aw2.anchor_path != path and "resumed-after-corrupt" in aw2.anchor_path.name
    rec = aw2.write_now("run-a", force=True)
    assert rec is not None
    assert path.read_bytes() == before  # damaged file untouched: no second genesis appended
    assert aw2.anchor_path.is_file()


def test_anchor_writer_still_resumes_a_healthy_chain(tmp_path: Path) -> None:
    db = tmp_path / "events.sqlite"
    store = _seed_store(db, "run-a", n=3)
    aw = AnchorWriter(store)
    first = aw.write_now("run-a", force=True)
    aw2 = AnchorWriter(store)
    assert aw2.anchor_path == aw.anchor_path
    second = aw2.write_now("run-a", force=True)
    assert second["seq"] == first["seq"] + 1 and second["prev_anchor_hash"] == first["anchor_hash"]


def test_verify_log_reports_and_verifies_the_diverted_anchor_file(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """R1: after a corrupt-tail diversion, verify-log must not look only at the damaged original."""
    db = tmp_path / "events.sqlite"
    store = _seed_store(db, "run-a", n=3)
    aw = AnchorWriter(store)
    aw.write_now("run-a", force=True)
    with aw.anchor_path.open("a", encoding="utf-8") as fh:
        fh.write('{"seq": 1, "anchor_ha\n')
    aw2 = AnchorWriter(store)
    assert aw2.diverted_from == aw.anchor_path
    aw2.write_now("run-a", force=True)
    store.close()

    from aegisflight.logging import find_diverted_anchor_files

    assert find_diverted_anchor_files(aw.anchor_path) == [aw2.anchor_path]
    rc = aegis_main(["verify-log", str(db), "--anchors", str(aw.anchor_path)])
    cap = capsys.readouterr()
    assert rc == 2  # the damaged original still fails verification
    assert aw2.anchor_path.name in cap.err and "corrupt tail" in cap.err
    assert f"diverted anchors {aw2.anchor_path.name}: 1" in cap.out and "status: OK" in cap.out.splitlines()[-1]
