"""Tests for the paced replay tool (``scripts/hardware/paced_replay.py``, issue #30 Part A).

Synthetic tlogs only: pacing accuracy (within 5%), drop/late accounting, determinism against the unpaced
reference, and loud failure (exit 2) on missing or malformed input.
"""

from __future__ import annotations

import json
import struct
import sys
import threading
import time
from pathlib import Path

import pytest
from pymavlink.dialects.v20 import common as mav

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "hardware"))

import paced_replay as pr  # noqa: E402

from aegisflight.config import load_config  # noqa: E402
from aegisflight.pipeline import IDSPipeline  # noqa: E402

T0_US = 1_700_000_000_000_000


def _synthetic_frames(seconds: float, hz: float) -> list[tuple[int, bytes]]:
    """(stamp_us, frame) at ``hz`` frames/s: HEARTBEAT, ATTITUDE, GLOBAL_POSITION_INT in rotation."""
    m = mav.MAVLink(None, srcSystem=1, srcComponent=1)
    out: list[tuple[int, bytes]] = []
    n = int(round(seconds * hz))
    for i in range(n + 1):
        m.seq = i & 0xFF
        boot_ms = int(i * 1000 / hz)
        kind = i % 3
        if kind == 0:
            msg = m.heartbeat_encode(2, 3, 81, 0, 4, 3)
        elif kind == 1:
            msg = m.attitude_encode(boot_ms, 0.01, 0.02, 0.03, 0.0, 0.0, 0.0)
        else:
            msg = m.global_position_int_encode(boot_ms, 473977418, 85455940, 488000, 10000, 0, 0, 0, 0)
        out.append((T0_US + round(i * 1e6 / hz), bytes(msg.pack(m))))
    return out


def write_tlog(path: Path, seconds: float = 1.0, hz: float = 60.0) -> Path:
    path.write_bytes(b"".join(struct.pack(">Q", ts) + fb for ts, fb in _synthetic_frames(seconds, hz)))
    return path


@pytest.fixture
def cfg():
    return load_config(None)


def _pipe(cfg):
    return IDSPipeline(cfg, model_path=None, firmware_dir=None)


# --------------------------------------------------------------------------- #
# reader
# --------------------------------------------------------------------------- #


def test_read_tlog_round_trips_every_frame(tmp_path):
    p = write_tlog(tmp_path / "a.tlog", 1.0, 30.0)
    frames = pr.read_tlog(p)
    assert len(frames) == 31
    assert frames[0][0] == pytest.approx(T0_US / 1e6)
    assert frames[-1][0] - frames[0][0] == pytest.approx(1.0, abs=1e-6)


@pytest.mark.parametrize("mutate, msg", [
    (lambda b: b"", "no frames"),
    (lambda b: b[:-3], "truncated"),
    (lambda b: b + b"\x00\x01", "truncated record"),
    (lambda b: b[:8] + b"\x55" + b[9:], "bad MAVLink magic"),
    (lambda b: b"hello, this is not a tlog at all", "bad MAVLink magic"),
])
def test_read_tlog_rejects_malformed_input(tmp_path, mutate, msg):
    good = write_tlog(tmp_path / "g.tlog", 0.5, 20.0).read_bytes()
    bad = tmp_path / "bad.tlog"
    bad.write_bytes(mutate(good))
    with pytest.raises(pr.InputError, match=msg):
        pr.read_tlog(bad)


def test_read_tlog_missing_file(tmp_path):
    with pytest.raises(pr.InputError, match="not found"):
        pr.read_tlog(tmp_path / "nope.tlog")


def test_schedule_clamps_backwards_stamps():
    frames = [(10.0, b""), (10.5, b""), (10.2, b""), (11.0, b"")]
    rel, back = pr.schedule(frames)
    assert rel == [0.0, 0.5, 0.5, 1.0]
    assert back == 1


def test_dist_percentiles():
    d = pr.dist([float(x) for x in range(1, 101)])
    assert (d["n"], d["p50"], d["p95"], d["p99"], d["max"]) == (100, 51.0, 95.0, 99.0, 100.0)
    assert pr.dist([])["p50"] is None


# --------------------------------------------------------------------------- #
# pacing, accounting, determinism (real IDSPipeline)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("factor, seconds", [(1.0, 1.0), (3.0, 1.5)])
def test_pacing_accuracy_within_5_percent(tmp_path, cfg, factor, seconds):
    frames = pr.read_tlog(write_tlog(tmp_path / "p.tlog", seconds, 60.0))
    r = pr.paced_run(frames, _pipe(cfg), factor=factor, rate_hz=10.0)
    assert r["pacing"]["achieved_speed"] == pytest.approx(factor, rel=0.05)
    assert abs(r["pacing"]["error_pct"]) <= 5.0
    # the whole run also takes span / factor of wall time (+ the start lead and end drain)
    assert r["wall_s"] == pytest.approx(seconds / factor, rel=0.05, abs=0.1)
    assert r["frames"]["dropped"] == 0
    assert r["frames"]["consumed"] == r["frames"]["total"] == len(frames)
    assert r["ticks"]["emitted"] == r["ticks"]["expected"]
    assert r["decisions"] > 0
    for k in ("p50", "p95", "p99", "max"):
        assert r["decision_compute_ms"][k] is not None and r["decision_compute_ms"][k] >= 0


def test_paced_verdicts_equal_unpaced_reference(tmp_path, cfg):
    frames = pr.read_tlog(write_tlog(tmp_path / "d.tlog", 1.5, 60.0))
    ref = pr.unpaced(frames, _pipe(cfg), 10.0)
    assert pr.unpaced(frames, _pipe(cfg), 10.0)["digest"] == ref["digest"]  # deterministic input -> same digest
    r = pr.paced_run(frames, _pipe(cfg), factor=3.0, rate_hz=10.0)
    assert r["digest"] == ref["digest"]
    assert r["decisions"] == ref["decisions"]


class _SlowPipe:
    """Stands in for a too-slow target: every tick costs ``cost_s`` of consumer time."""

    def __init__(self, inner, cost_s: float) -> None:
        self.inner, self.cost_s = inner, cost_s

    def process_tick(self, tick):
        time.sleep(self.cost_s)
        return self.inner.process_tick(tick)


def test_slow_consumer_drops_and_late_frames_are_counted(tmp_path, cfg):
    frames = pr.read_tlog(write_tlog(tmp_path / "s.tlog", 1.0, 200.0))
    # 10 ticks/s of data at 2x = 20 ticks/s offered; 120 ms per tick can serve ~8/s -> backlog, overflow
    r = pr.paced_run(frames, _SlowPipe(_pipe(cfg), 0.12), factor=2.0, rate_hz=10.0, queue_frames=16)
    f = r["frames"]
    assert f["dropped"] > 0
    assert f["released"] == f["total"] == len(frames)
    assert f["consumed"] + f["dropped"] == f["total"]  # every frame is either processed or counted as lost
    assert f["late"] > 0
    assert f["max_queue_depth"] <= 16
    assert r["late_decisions"] > 0
    assert r["decision_lag_ms"]["max"] > r["tick_period_wall_ms"]


def test_fast_consumer_has_no_drops_with_a_tiny_queue(tmp_path, cfg):
    frames = pr.read_tlog(write_tlog(tmp_path / "f.tlog", 0.6, 60.0))
    r = pr.paced_run(frames, _pipe(cfg), factor=1.0, rate_hz=10.0, queue_frames=4)
    assert r["frames"]["dropped"] == 0
    assert r["ticks"]["emitted"] == r["ticks"]["expected"]


class _FailingProc:
    """A psutil.Process stand-in whose RSS probe (called only by the feeder thread) raises."""

    def cpu_times(self):
        return (0.0, 0.0, 0.0, 0.0)

    def memory_info(self):
        raise PermissionError("rss probe denied")


def test_feeder_failure_fails_loudly_instead_of_hanging(tmp_path, cfg):
    frames = pr.read_tlog(write_tlog(tmp_path / "x.tlog", 0.6, 60.0))
    outcome: dict = {}

    def run() -> None:
        try:
            outcome["result"] = pr.paced_run(frames, _pipe(cfg), factor=1.0, rate_hz=10.0, proc=_FailingProc())
        except BaseException as exc:  # noqa: BLE001
            outcome["error"] = exc

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout=15)
    assert not t.is_alive(), "paced_run hung after the feeder thread failed"
    assert "result" not in outcome  # no complete-looking result for a failed feed
    err = outcome["error"]
    assert isinstance(err, RuntimeError) and "feeder failed" in str(err)
    assert isinstance(err.__cause__, PermissionError)


def test_paced_run_rejects_bad_arguments(cfg):
    with pytest.raises(ValueError):
        pr.paced_run([(0.0, b""), (1.0, b"")], _pipe(cfg), factor=0, rate_hz=10.0)
    with pytest.raises(ValueError):
        pr.paced_run([(0.0, b""), (1.0, b"")], _pipe(cfg), factor=1, rate_hz=10.0, queue_frames=0)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def test_cli_writes_labelled_host_json(tmp_path, capsys):
    tlog = write_tlog(tmp_path / "c.tlog", 0.6, 60.0)
    out = tmp_path / "out" / "paced.json"
    rc = pr.main([str(tlog), "--factor", "2", "--factor", "4", "--ml", "off", "--out", str(out)])
    assert rc == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["schema"] == pr.SCHEMA
    ev = doc["evidence"]
    assert ev["environment"] == "REPLAY" and ev["measured_on"] == "host" and ev["target_hardware"] is False
    assert "NOT Raspberry Pi" in ev["claim"]
    assert ev["input_capture_environment"] == pr.NOT_RECORDED  # no sidecar JSON
    assert [r["factor"] for r in doc["runs"]] == [2.0, 4.0]
    assert all(r["ml_enabled"] is False and r["verdicts_identical_to_unpaced"] for r in doc["runs"])
    prov = doc["provenance"]
    assert prov["python"] and prov["board_model"] == pr.NOT_RECORDED
    assert isinstance(prov["working_tree_dirty"], bool) or prov["working_tree_dirty"] == pr.NOT_RECORDED
    assert doc["input"]["tlog_name"] == "c.tlog" and len(doc["input"]["tlog_sha256"]) == 64
    assert json.loads(capsys.readouterr().out)["runs"][0]["dropped"] == 0
    # a measurement is never overwritten
    assert pr.main([str(tlog), "--factor", "4", "--ml", "off", "--out", str(out)]) == 2


def test_cli_reads_capture_environment_from_sidecar(tmp_path):
    tlog = write_tlog(tmp_path / "side.tlog", 0.4, 30.0)
    (tmp_path / "side.json").write_text(json.dumps({"environment": "SITL"}), encoding="utf-8")
    a = pr._parse([str(tlog), "--factor", "4", "--ml", "off", "--no-reference"])
    doc = pr.run(a)
    assert doc["evidence"]["input_capture_environment"] == "SITL"
    assert "unpaced_reference" not in doc["runs"][0]


@pytest.mark.parametrize("args", [
    ["{missing}"],
    ["{garbage}"],
    ["{empty}"],
    ["{single}"],
    ["{good}", "--factor", "0"],
    ["{good}", "--factor", "-1"],
    ["{good}", "--queue-frames", "0"],
    ["{good}", "--max-capture-s", "0"],
    ["{good}", "--ml", "on", "--model", "{missing_model}"],
    ["{good}", "--config-dir", "{missing_dir}"],
])
def test_cli_missing_or_malformed_input_exits_2(tmp_path, capsys, args):
    paths = {
        "missing": tmp_path / "missing.tlog",
        "garbage": tmp_path / "garbage.tlog",
        "empty": tmp_path / "empty.tlog",
        "single": tmp_path / "single.tlog",
        "good": write_tlog(tmp_path / "good.tlog", 0.3, 30.0),
        "missing_model": tmp_path / "no_model.joblib",
        "missing_dir": tmp_path / "no_configs",
    }
    paths["garbage"].write_bytes(b"\x00" * 64)
    paths["empty"].write_bytes(b"")
    ts, fb = _synthetic_frames(0.1, 10.0)[0]
    paths["single"].write_bytes(struct.pack(">Q", ts) + fb)
    argv = [x.format(**{k: str(v) for k, v in paths.items()}) for x in args]
    assert pr.main(argv) == 2
    assert "paced_replay:" in capsys.readouterr().err


def test_cli_bad_factor_type_is_an_argparse_error(tmp_path):
    with pytest.raises(SystemExit) as exc:
        pr.main([str(write_tlog(tmp_path / "x.tlog", 0.2, 20.0)), "--factor", "fast"])
    assert exc.value.code == 2
