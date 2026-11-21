"""Exact-behaviour tests for the tamper-evident event store.

Pins the stored precision of every hashed field, the exact `ChainStatus` of every verifier outcome (which the CLI, the
dashboard and the offline forensic tools print), the SQLite pragmas and the read-only boundary.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from pathlib import Path

import pytest

from aegisflight.core.enums import AttackType, IntegrityStatus, Severity
from aegisflight.core.types import ThreatAssessment
from aegisflight.logging.store import GENESIS_HASH, ChainStatus, EventStore


def assessment(t: float = 1.0, **kw) -> ThreatAssessment:
    base = {
        "t": t, "wall_time": 1.5, "threat": True, "threat_score": 0.7, "severity": Severity.HIGH,
        "attack_type": AttackType.GPS_SPOOFING, "confidence": 0.8, "evidence": ["e"],
        "detector_scores": {"physics_consistency": 0.9}, "contributing_detectors": ["physics_consistency"],
        "integrity_status": IntegrityStatus.VALID, "latency_ms": 0.4, "telemetry": {"k": 1}, "is_alert": True,
    }
    base.update(kw)
    return ThreatAssessment(**base)


def sha(prev: str, payload: dict) -> str:
    return hashlib.sha256((prev + json.dumps(payload, sort_keys=True, separators=(",", ":"))).encode("utf-8")).hexdigest()


# -- pragmas, defaults, connection -----------------------------------------------------------------------------------------

def test_default_path_and_pragmas_for_a_file_database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    st = EventStore()
    assert (tmp_path / "aegisflight.sqlite").exists() and st.db_path == "aegisflight.sqlite"
    assert st.conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert st.conn.execute("PRAGMA synchronous").fetchone()[0] == 1  # NORMAL
    assert st.conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
    st.close()


def test_in_memory_database_skips_the_file_pragmas() -> None:
    st = EventStore(":memory:")
    assert st.conn.execute("PRAGMA journal_mode").fetchone()[0] == "memory"
    st.start_run("r")
    st.close()


def test_the_connection_may_be_used_from_another_thread(tmp_path: Path) -> None:
    st = EventStore(tmp_path / "t.sqlite")
    st.start_run("r")
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            st.log_event(assessment(), "r")
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    th = threading.Thread(target=worker)
    th.start()
    th.join()
    assert errors == [] and st.count_events("r") == 1
    st.close()


def test_read_only_store_reads_but_cannot_write_and_never_creates_a_file(tmp_path: Path) -> None:
    missing = tmp_path / "absent.sqlite"
    with pytest.raises(sqlite3.OperationalError):
        EventStore(missing, read_only=True)
    assert not missing.exists()
    db = tmp_path / "ro.sqlite"
    rw = EventStore(db)
    rw.start_run("r")
    rw.log_event(assessment(), "r")
    rw.close()
    ro = EventStore(db, read_only=True)
    assert ro.read_only is True and ro.count_events() == 1
    with pytest.raises(sqlite3.OperationalError, match="^attempt to write to a read-only EventStore$"):
        ro.log_action("r", 1.0, "a", "b", "c")
    with pytest.raises(sqlite3.OperationalError):
        ro.conn.execute("DELETE FROM events")
    ro.close()


def test_a_path_with_special_characters_opens_read_only(tmp_path: Path) -> None:
    db = tmp_path / "weird name #1.sqlite"
    EventStore(db).close()
    ro = EventStore(db, read_only=True)
    assert ro.count_events() == 0
    ro.close()


# -- runs ------------------------------------------------------------------------------------------------------------------

def test_start_run_defaults_and_replacement() -> None:
    st = EventStore(":memory:")
    st.start_run("a")
    st.start_run("b", label="lbl", meta={"k": [1, 2]})
    runs = {r["run_id"]: r for r in st.list_runs()}
    assert runs["a"]["label"] == "" and runs["a"]["meta"] == "{}"
    assert runs["b"]["label"] == "lbl" and json.loads(runs["b"]["meta"]) == {"k": [1, 2]}
    st.start_run("b", label="again")
    assert [r["label"] for r in st.list_runs() if r["run_id"] == "b"] == ["again"]
    assert [r["run_id"] for r in st.list_runs()] == ["b", "a"] or [r["run_id"] for r in st.list_runs()] == ["a", "b"]
    st.close()


# -- events ----------------------------------------------------------------------------------------------------------------

def test_logged_event_rounds_every_field_and_chains_from_genesis() -> None:
    st = EventStore(":memory:")
    st.start_run("r")
    a = assessment(t=1.23456, threat_score=0.123456, confidence=0.654321, latency_ms=0.123456,
                   detector_scores={"a": 0.123456, "b": 1.0})
    row = st.log_event(a, "r")
    expect_payload = {
        "run_id": "r", "t": 1.235, "wall_time": 1.5, "attack_type": a.attack_type.value, "severity": a.severity.value,
        "threat_score": 0.1235, "confidence": 0.6543, "integrity_status": a.integrity_status.value,
        "latency_ms": 0.1235, "evidence": ["e"], "detector_scores": {"a": 0.1235, "b": 1.0},
        "contributing_detectors": ["physics_consistency"], "telemetry": {"k": 1},
    }
    assert row["hash"] == sha(GENESIS_HASH, expect_payload)
    assert set(row) == {"id", "hash", *expect_payload}
    assert row["id"] == 1 and {k: row[k] for k in expect_payload} == expect_payload
    second = st.log_event(assessment(t=2.0), "r")
    stored = st.get_events("r")
    assert [e["id"] for e in stored] == [2, 1] and stored[0]["prev_hash"] == row["hash"] == stored[1]["hash"]
    assert second["id"] == 2 and stored[1]["prev_hash"] == GENESIS_HASH
    st.close()


def test_runs_are_independent_chains() -> None:
    st = EventStore(":memory:")
    for run in ("r1", "r2"):
        st.start_run(run)
        st.log_event(assessment(), run)
    rows = {e["run_id"]: e for e in st.get_events()}
    assert rows["r1"]["prev_hash"] == rows["r2"]["prev_hash"] == GENESIS_HASH
    st.close()


def test_get_events_filters_limits_and_counts() -> None:
    st = EventStore(":memory:")
    for run, n in (("a", 3), ("b", 2)):
        st.start_run(run)
        for i in range(n):
            st.log_event(assessment(t=float(i)), run)
    assert st.count_events() == 5 and st.count_events("a") == 3 and st.count_events("zzz") == 0
    assert len(st.get_events()) == 5 and len(st.get_events("a")) == 3 and len(st.get_events(limit=2)) == 2
    assert [e["id"] for e in st.get_events(since_id=3)] == [5, 4]
    assert [e["id"] for e in st.get_events("b", since_id=3)] == [5, 4]
    event = st.get_events("a", limit=1)[0]
    assert event["evidence"] == ["e"] and event["detector_scores"] == {"physics_consistency": 0.9}
    assert event["contributing_detectors"] == ["physics_consistency"] and event["telemetry"] == {"k": 1}
    assert st.get_events("none") == []
    st.close()


# -- verify_chain ----------------------------------------------------------------------------------------------------------

def make_events(st: EventStore, run: str, n: int) -> None:
    st.start_run(run)
    for i in range(n):
        st.log_event(assessment(t=float(i)), run)


def test_verify_chain_statuses_are_exact() -> None:
    st = EventStore(":memory:")
    assert st.verify_chain() == ChainStatus(ok=True, length=0, detail="0 run chain(s) intact")
    assert st.verify_chain("none") == ChainStatus(ok=True, length=0, broken_at=None, detail="chain intact")
    make_events(st, "a", 3)
    make_events(st, "b", 2)
    assert st.verify_chain("a") == ChainStatus(ok=True, length=3, broken_at=None, detail="chain intact")
    assert st.verify_chain() == ChainStatus(ok=True, length=5, broken_at=None, detail="2 run chain(s) intact")
    st.conn.execute("UPDATE events SET threat_score=0.01 WHERE run_id='a' AND t=1.0")
    st.conn.commit()
    bad = st.verify_chain("a")
    ids = [r[0] for r in st.conn.execute("SELECT id FROM events WHERE run_id='a' ORDER BY id")]
    assert bad == ChainStatus(ok=False, length=3, broken_at=1, detail=f"chain broken at event id={ids[1]}")
    whole = st.verify_chain()
    assert whole == ChainStatus(ok=False, length=3, broken_at=1, detail=f"run a: chain broken at event id={ids[1]}")
    st.close()


def test_verify_chain_reports_the_first_broken_run_with_the_running_total() -> None:
    st = EventStore(":memory:")
    make_events(st, "a", 2)
    make_events(st, "b", 3)
    st.conn.execute("UPDATE events SET hash='00' WHERE run_id='b' AND t=2.0")
    st.conn.commit()
    got = st.verify_chain()
    assert got.ok is False and got.length == 5 and got.broken_at == 2 and got.detail.startswith("run b: chain broken")
    st.close()


def test_a_broken_prev_hash_link_alone_is_detected() -> None:
    st = EventStore(":memory:")
    make_events(st, "a", 3)
    st.conn.execute("UPDATE events SET prev_hash='x' WHERE run_id='a' AND t=2.0")
    st.conn.commit()
    got = st.verify_chain("a")
    assert got.ok is False and got.broken_at == 2
    st.close()


@pytest.mark.parametrize("column", ["evidence", "detector_scores", "contributing_detectors", "telemetry"])
def test_malformed_stored_json_is_a_broken_chain_for_every_json_column(column: str) -> None:
    st = EventStore(":memory:")
    make_events(st, "a", 3)
    st.conn.execute(f"UPDATE events SET {column}='{{oops' WHERE run_id='a' AND t=1.0")
    st.conn.commit()
    rid = st.conn.execute("SELECT id FROM events WHERE run_id='a' AND t=1.0").fetchone()[0]
    assert st.verify_chain("a") == ChainStatus(
        ok=False, length=3, broken_at=1, detail=f"chain broken at event id={rid}: stored payload is not valid JSON")
    st.close()


@pytest.mark.parametrize("column", ["t", "wall_time", "attack_type", "severity", "threat_score", "confidence",
                                    "integrity_status", "latency_ms"])
def test_tampering_any_hashed_scalar_column_breaks_the_chain(column: str) -> None:
    st = EventStore(":memory:")
    make_events(st, "a", 2)
    value = "'zzz'" if column in ("attack_type", "severity", "integrity_status") else "123.456"
    st.conn.execute(f"UPDATE events SET {column}={value} WHERE run_id='a' AND t=0.0" if column != "t"
                    else "UPDATE events SET t=123.456 WHERE run_id='a' AND t=0.0")
    st.conn.commit()
    assert st.verify_chain("a").ok is False
    st.close()


# -- actions chain ---------------------------------------------------------------------------------------------------------

def test_action_log_row_hash_and_defaults() -> None:
    st = EventStore(":memory:")
    row = st.log_action("r", 1.234567, "bridge", "DROP", "tgt")
    payload = {"run_id": "r", "t": 1.2346, "actor": "bridge", "action": "DROP", "target": "tgt", "detail": ""}
    assert row["hash"] == sha(GENESIS_HASH, payload) and row["prev_hash"] == GENESIS_HASH and row["id"] == 1
    assert set(row) == {"id", "prev_hash", "hash", *payload}
    again = st.log_action("r", 2.0, "bridge", "DROP", "tgt", "d")
    assert again["prev_hash"] == row["hash"]
    other = st.log_action("r2", 2.0, "bridge", "DROP", "tgt")
    assert other["prev_hash"] == GENESIS_HASH
    st.close()


def test_get_actions_default_limit_is_one_hundred_and_orders_newest_first() -> None:
    st = EventStore(":memory:")
    for i in range(120):
        st.log_action("r", float(i), "a", "x", str(i))
    assert len(st.get_actions()) == 100 and len(st.get_actions("r")) == 100
    assert [a["target"] for a in st.get_actions(limit=3)] == ["119", "118", "117"]
    assert [a["target"] for a in st.get_actions("r", limit=2)] == ["119", "118"]
    assert st.get_actions("nope") == []
    st.close()


def test_verify_actions_statuses_are_exact() -> None:
    st = EventStore(":memory:")
    assert st.verify_actions_chain() == ChainStatus(ok=True, length=0, broken_at=None, detail="0 action chain(s) intact")
    assert st.verify_actions_chain("none") == ChainStatus(ok=True, length=0, broken_at=None, detail="action chain intact")
    for run, n in (("a", 3), ("b", 2)):
        for i in range(n):
            st.log_action(run, float(i), "bridge", "ACT", f"t{i}", "d")
    assert st.verify_actions_chain("a") == ChainStatus(ok=True, length=3, broken_at=None, detail="action chain intact")
    assert st.verify_actions_chain() == ChainStatus(ok=True, length=5, broken_at=None, detail="2 action chain(s) intact")
    st.conn.execute("UPDATE actions SET detail='forged' WHERE run_id='a' AND target='t1'")
    st.conn.commit()
    rid = st.conn.execute("SELECT id FROM actions WHERE run_id='a' AND target='t1'").fetchone()[0]
    assert st.verify_actions_chain("a") == ChainStatus(
        ok=False, length=3, broken_at=1, detail=f"action chain broken at action id={rid}")
    assert st.verify_actions_chain() == ChainStatus(
        ok=False, length=3, broken_at=1, detail=f"run a: action chain broken at action id={rid}")
    st.close()


def test_a_store_without_an_actions_table_verifies_vacuously() -> None:
    st = EventStore(":memory:")
    st.conn.execute("DROP TABLE actions")
    assert st.verify_actions_chain() == ChainStatus(ok=True, length=0, broken_at=None, detail="no actions table")
    assert st.get_actions() == []
    st.close()


@pytest.mark.parametrize("column", ["t", "actor", "action", "target", "detail", "prev_hash", "hash"])
def test_tampering_any_action_column_breaks_the_actions_chain(column: str) -> None:
    st = EventStore(":memory:")
    for i in range(2):
        st.log_action("r", float(i), "bridge", "ACT", f"t{i}", "d")
    value = "123.5" if column == "t" else "'zzz'"
    st.conn.execute(f"UPDATE actions SET {column}={value} WHERE target='t0'")
    st.conn.commit()
    assert st.verify_actions_chain("r").ok is False
    st.close()


def test_a_read_only_store_may_also_be_read_from_another_thread(tmp_path: Path) -> None:
    db = tmp_path / "ro_thread.sqlite"
    rw = EventStore(db)
    rw.start_run("r")
    rw.log_event(assessment(), "r")
    rw.close()
    ro = EventStore(db, read_only=True)
    seen: list[int] = []
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            seen.append(ro.count_events())
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    th = threading.Thread(target=worker)
    th.start()
    th.join()
    assert errors == [] and seen == [1]
    ro.close()


def test_get_events_default_limit_is_exactly_one_hundred() -> None:
    st = EventStore(":memory:")
    st.start_run("r")
    for i in range(101):
        st.log_event(assessment(t=float(i)), "r")
    assert len(st.get_events()) == 100 and len(st.get_events("r")) == 100
    assert st.get_events()[0]["id"] == 101
    st.close()
