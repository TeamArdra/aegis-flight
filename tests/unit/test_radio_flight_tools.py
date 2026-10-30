"""Radio test tools (scripts/radio_test/flight_session.py, mgmt_radio.py): pure logic and a fake vehicle link.

Canned pymavlink messages only; nothing here opens a socket, a serial port or SITL.
"""

from __future__ import annotations

import os
import sys
import time
from collections import deque
from pathlib import Path
from types import SimpleNamespace
from typing import Any

os.environ.setdefault("MAVLINK20", "1")
import pytest  # noqa: E402
from pymavlink import mavutil  # noqa: E402
from pymavlink.dialects.v20 import common as mav2  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.radio_test import flight_session as fs  # noqa: E402
from scripts.radio_test import mgmt_radio as mr  # noqa: E402
from scripts.radio_test.results import PhaseResult  # noqa: E402

from aegisflight.detectors.crossend import MARKER_ADDRESS  # noqa: E402
from aegisflight.hal.mgmt_channel import (  # noqa: E402
    CMD_MGMT,
    OP_STATUS_NOW,
    STATUS_ADDRESS,
    STATUS_TYPE,
    STATUS_VER,
    StatusReport,
    build_command_frame,
    pack_status,
)
from aegisflight.mavlink.signing import MavlinkSignatureVerifier  # noqa: E402

KEY = bytes(range(1, 33))


def canned(factory: Any, src: tuple[int, int] = (1, 1), key: bytes | None = None, link_id: int = 0) -> Any:
    """Encode a message from ``src`` (optionally signed) and parse it back, as it would arrive on the link."""
    enc = mav2.MAVLink(None, srcSystem=src[0], srcComponent=src[1])
    raw = bytes(factory(enc).pack(enc))
    if key is not None:
        raw = MavlinkSignatureVerifier(key).sign_frame(raw, link_id=link_id)
    parser = mav2.MAVLink(None)
    parser.robust_parsing = True
    out = [m for m in (parser.parse_char(bytes([b])) for b in raw) if m is not None]
    assert len(out) == 1
    return out[0]


def param_value(idx: int, count: int, name: str | None = None) -> Any:
    return canned(lambda e: e.param_value_encode((name or f"P{idx}").encode(), 1.0, 9, count, idx))


# --------------------------------------------------------------------------- #
# flight_session: pure logic
# --------------------------------------------------------------------------- #
def test_check_params_complete():
    chk = fs.check_params([param_value(i, 5) for i in (3, 0, 1, 4, 2)])
    assert chk.complete and chk.unique == 5 and chk.expected == 5 and chk.missing == []


def test_check_params_missing_duplicate_and_mismatch():
    chk = fs.check_params([param_value(0, 4), param_value(1, 4), param_value(1, 4), param_value(3, 4)])
    assert not chk.complete
    assert chk.missing == [2] and chk.duplicates == [1] and chk.unique == 3 and chk.received == 4
    mixed = fs.check_params([param_value(0, 2), param_value(1, 3)])
    assert mixed.count_mismatch and not mixed.complete


def test_check_params_empty_and_duplicate_names():
    assert not fs.check_params([]).complete
    chk = fs.check_params([param_value(0, 2, "A"), param_value(1, 2, "A")])
    assert chk.duplicate_names == ["A"] and not chk.complete


def test_build_mission_shape():
    items = fs.build_mission(12.9716, 77.5946, 6, 10.0)
    assert len(items) == 7 and [i.seq for i in items] == list(range(7))
    assert all(i.command == 16 and i.z == 10.0 for i in items[1:])
    assert items[0].x == round(12.9716 * 1e7)


def test_compare_missions_identical_and_home_ignored():
    sent = fs.build_mission(12.9716, 77.5946)
    got = [fs.MissionItem(**{**i.__dict__, "frame": 6 if i.seq else 0}) for i in sent]  # _INT frame variant
    got[0] = fs.MissionItem(0, 0, 16, 1, 0, 0, 0, 0, 1, 2, 920.0)  # the real home replaces the placeholder
    assert fs.compare_missions(sent, got) == []
    assert fs.compare_missions(sent, got, skip_home=False)


def test_compare_missions_detects_differences():
    sent = fs.build_mission(12.9716, 77.5946)
    bad = list(sent)
    bad[2] = fs.MissionItem(**{**sent[2].__dict__, "x": sent[2].x + 1})
    bad[4] = fs.MissionItem(**{**sent[4].__dict__, "z": 11.0})
    diffs = fs.compare_missions(sent, bad)
    assert any("item 2 x" in d for d in diffs) and any("item 4 z" in d for d in diffs)
    assert any("count" in d for d in fs.compare_missions(sent, sent[:-1]))


def test_mission_item_from_msg_converts_float_degrees():
    msg = canned(lambda e: e.mission_item_encode(1, 1, 2, 3, 16, 0, 1, 0, 0, 0, 0, 12.5, 77.25, 10.0))
    item = fs.MissionItem.from_msg(msg)
    assert (item.x, item.y, item.seq, item.z) == (125000000, 772500000, 2, 10.0)


def test_ledger_ack_nak_timeout_accounting():
    led = fs.CommandLedger()
    a = led.sent("arm", 400, 10.0)
    b = led.sent("takeoff", 22, 11.0)
    c = led.sent("mode", 176, 12.0)
    assert led.on_ack(400, 0, 10.4) is a
    assert led.on_ack(22, 4, 11.2) is b
    led.expire(c)
    assert (a.status, b.status, c.status) == ("ok", "nak", "timeout")
    s = led.summary()
    assert (s["sent"], s["ok"], s["nak"], s["timeout"], s["dropped"]) == (3, 1, 1, 1, 2)
    assert s["failed"] == ["takeoff:nak(4)", "mode:timeout"]
    assert s["ack_latency_s"]["n"] == 1 and s["ack_latency_s"]["max"] == pytest.approx(0.4)


def test_ledger_in_progress_retry_and_unknown_ack():
    led = fs.CommandLedger()
    a = led.sent("arm", 400, 0.0)
    assert led.on_ack(400, 5, 0.5) is a and a.status == "pending" and a.in_progress
    assert led.on_ack(999, 0, 0.6) is None
    led.on_ack(400, 4, 1.0)
    led.resend(a, 5.0)
    assert a.attempts == 2 and a.history == [4] and a.status == "pending"
    led.on_ack(400, 0, 5.3)
    s = led.summary()
    assert s["ok"] == 1 and s["retried"] == 1 and s["dropped"] == 0
    assert s["ack_latency_s"]["median"] == pytest.approx(0.3)


def test_ledger_ack_via_canned_command_ack():
    led = fs.CommandLedger()
    led.sent("takeoff", 22, 0.0)
    msg = canned(lambda e: e.command_ack_encode(22, 0, 0, 0, 255, 190))
    led.on_ack(msg.command, msg.result, 0.2)
    assert led.summary()["ok"] == 1


def test_select_stages():
    assert fs.select_stages("all") == list(fs.STAGES)
    assert fs.select_stages("land,params") == ["params", "land"]
    assert "arm_takeoff" not in fs.select_stages(None, skip_takeoff=True)
    assert fs.select_stages("all", hold_after=True)[-1] == "auto_mission"
    with pytest.raises(ValueError):
        fs.select_stages("params,bogus")


def test_latency_stats():
    s = fs.latency_stats([0.1, 0.2, 0.3, 0.4, 1.0])
    assert s["n"] == 5 and s["median"] == 0.3 and s["max"] == 1.0 and s["p95"] == 1.0
    assert fs.latency_stats([])["n"] == 0


# --------------------------------------------------------------------------- #
# flight_session: Session against a fake vehicle
# --------------------------------------------------------------------------- #
class FakeMav:
    def __init__(self, link: FakeLink) -> None:
        self.link = link

    def heartbeat_send(self, *a: Any) -> None:
        pass

    def request_data_stream_send(self, *a: Any) -> None:
        pass

    def param_set_send(self, *a: Any) -> None:
        pass

    def command_long_send(self, ts: int, tc: int, command: int, conf: int, *params: float) -> None:
        self.link.commands.append(command)
        if command in self.link.ignore:
            return
        result = self.link.nak.get(command, 0)
        self.link.push(canned(lambda e: e.command_ack_encode(command, result, 0, 0, 255, 190)))
        if command == 176:
            self.link.push(self.link.heartbeat(int(params[1])))

    def param_request_read_send(self, ts: int, tc: int, pid: bytes, idx: int) -> None:
        self.link.push(param_value(0, 1, pid.decode()))

    def param_request_list_send(self, ts: int, tc: int) -> None:
        n = self.link.n_params
        for i in range(n):
            if i == self.link.lose_param:
                continue
            self.link.push(param_value(i, n))

    def mission_count_send(self, ts: int, tc: int, count: int, mtype: int = 0) -> None:
        self.link.uploading = {}
        self.link.upload_count = count
        self.link.push(canned(lambda e: e.mission_request_int_encode(255, 190, 0, 0)))

    def mission_item_int_send(self, ts: int, tc: int, seq: int, frame: int, command: int, current: int, auto: int,
                              p1: float, p2: float, p3: float, p4: float, x: int, y: int, z: float, mtype: int = 0) -> None:
        self.link.uploading[seq] = (seq, 6 if seq else 0, command, auto, p1, p2, p3, p4, x, y, z)
        if seq + 1 < self.link.upload_count:
            self.link.push(canned(lambda e: e.mission_request_int_encode(255, 190, seq + 1, 0)))
        else:
            self.link.stored = [self.link.uploading[i] for i in range(self.link.upload_count)]
            self.link.push(canned(lambda e: e.mission_ack_encode(255, 190, 0, 0)))

    def mission_request_list_send(self, ts: int, tc: int, mtype: int = 0) -> None:
        n = len(self.link.stored)
        self.link.push(canned(lambda e: e.mission_count_encode(255, 190, n, 0)))

    def mission_request_int_send(self, ts: int, tc: int, seq: int, mtype: int = 0) -> None:
        r = self.link.stored[seq]
        self.link.push(canned(lambda e: e.mission_item_int_encode(255, 190, r[0], r[1], r[2], 0, r[3], r[4], r[5], r[6],
                                                                  r[7], r[8], r[9], r[10], 0)))

    def mission_ack_send(self, *a: Any) -> None:
        pass


class FakeLink:
    def __init__(self) -> None:
        self.inbox: deque[Any] = deque()
        self.commands: list[int] = []
        self.ignore: set[int] = set()
        self.nak: dict[int, int] = {}
        self.n_params = 6
        self.lose_param: int | None = None
        self.stored: list[tuple] = []
        self.uploading: dict[int, tuple] = {}
        self.upload_count = 0
        self.mav = FakeMav(self)
        self.push(self.heartbeat(0))

    def heartbeat(self, mode: int, armed: bool = False) -> Any:
        base = 1 | (128 if armed else 0)
        return canned(lambda e: e.heartbeat_encode(2, 3, base, mode, 4, 3))

    def push(self, msg: Any) -> None:
        self.inbox.append(msg)

    def recv_match(self, blocking: bool = True, timeout: float = 0.1, **_k: Any) -> Any:
        if self.inbox:
            return self.inbox.popleft()
        time.sleep(min(timeout, 0.005))
        return None

    def close(self) -> None:
        pass


def make_session(tmp_path: Path, link: FakeLink, **cfg: Any) -> fs.Session:
    base = {"ack_timeout": 0.3, "mission_timeout": 0.3, "param_idle": 0.4, "param_timeout": 3.0, "ping_count": 3,
            "link_timeout": 2.0, "mode_timeout": 0.5, "retries": 1}
    sess = fs.Session(link, fs.Config(**{**base, **cfg}), PhaseResult("p3_test", tmp_path), say=lambda *a: None)
    assert sess.wait_heartbeat(2.0)
    return sess


def check_named(sess: fs.Session, name: str) -> dict:
    return next(c for c in sess.res.checks if c["name"] == name)


def test_session_mission_round_trip_and_params(tmp_path):
    link = FakeLink()
    sess = make_session(tmp_path, link)
    sess.stage_params()
    sess.stage_mission()
    assert check_named(sess, "params complete")["passed"]
    assert check_named(sess, "mission round-trip identical")["passed"]
    assert sess.res.metrics["param_download_s"] >= 0


def test_session_reports_missing_param_and_mission_difference(tmp_path):
    link = FakeLink()
    link.lose_param = 2
    sess = make_session(tmp_path, link)
    sess.stage_params()
    chk = check_named(sess, "params complete")
    assert not chk["passed"] and chk["value"] == "5/6"
    assert sess.res.metrics["params"]["missing"] == [2]


def test_session_drop_and_nak_fail_the_command_check(tmp_path):
    link = FakeLink()
    link.ignore.add(22)
    link.nak[400] = 4
    sess = make_session(tmp_path, link, retries=1)
    ok = sess.send_command("good", 176, (1, 4, 0, 0, 0, 0, 0))
    nak = sess.send_command("arm", 400, (1, 0, 0, 0, 0, 0, 0))
    lost = sess.send_command("takeoff", 22, (0, 0, 0, 0, 0, 0, 10))
    assert (ok.status, nak.status, lost.status) == ("ok", "nak", "timeout")
    assert link.commands.count(22) == 2 and link.commands.count(400) == 1  # timeouts are retried, a NAK is not
    sess.finish()
    c = check_named(sess, "zero legitimate commands dropped/NAK-or-timeout")
    assert not c["passed"] and c["value"] == 2


def test_session_set_mode_verified_through_heartbeat(tmp_path):
    link = FakeLink()
    sess = make_session(tmp_path, link)
    ev = sess.set_mode("LOITER")
    assert ev["acked"] and ev["verified"]
    link.ignore.add(176)
    assert not sess.set_mode("GUIDED")["verified"]


# --------------------------------------------------------------------------- #
# mgmt_radio: pure logic
# --------------------------------------------------------------------------- #
def test_classify_downlink():
    assert mr.classify_downlink(1, "ATTITUDE") == "telemetry"
    assert mr.classify_downlink(191, "STATUSTEXT") == "mgmt"
    assert mr.classify_downlink(192, "COMMAND_ACK") == "mgmt"
    assert mr.classify_downlink(191, "MEMORY_VECT", STATUS_ADDRESS) == "mgmt"
    assert mr.classify_downlink(191, "MEMORY_VECT", MARKER_ADDRESS) == "crossend"


def test_rate_summary_bins_window_and_peak():
    s = [mr.FrameSample(0.1, 60, "mgmt"), mr.FrameSample(0.9, 40, "mgmt"), mr.FrameSample(2.5, 200, "mgmt"),
         mr.FrameSample(1.0, 1000, "telemetry"), mr.FrameSample(99.0, 5, "mgmt"), mr.FrameSample(0.5, 61, "crossend")]
    out = mr.rate_summary(s, 0.0, 4.0)
    m = out["kinds"]["mgmt"]
    assert m["bytes"] == 300 and m["frames"] == 3 and m["avg_bps"] == 75.0 and m["peak_1s"] == 200
    assert m["series"] == [100, 0, 200, 0]
    assert out["kinds"]["telemetry"]["avg_bps"] == 250.0 and out["kinds"]["crossend"]["bytes"] == 61


def test_budget_verdict_bound_and_rate():
    v = mr.budget_verdict(1500, 10)
    assert v["avg_bps"] == 150.0 and v["within_rate"] and v["within_bound"] and v["bound_bytes"] == 1800
    v = mr.budget_verdict(1700, 10)  # over the rate, still inside burst + rate x T
    assert not v["within_rate"] and v["within_bound"]
    assert not mr.budget_verdict(1900, 10)["within_bound"]


def test_telemetry_comparison():
    assert mr.telemetry_comparison(1000, 950)["ok"]
    assert not mr.telemetry_comparison(1000, 700)["ok"]
    assert not mr.telemetry_comparison(0, 500)["ok"]


def test_ack_accounting_helpers():
    ok = {"result": 0, "result_param2": 0}
    inp = {"result": 5, "result_param2": 4242}
    den = {"result": 2, "result_param2": 3}
    assert mr.ack_matches("accepted", [ok]) and not mr.ack_matches("accepted", [den])
    assert mr.ack_matches("in_progress", [inp]) and mr.ack_matches("denied", [den])
    assert mr.ack_matches("none", []) and not mr.ack_matches("none", [ok])
    assert mr.describe_ack(inp) == "IN_PROGRESS(token 4242)"
    assert mr.describe_ack(den).startswith("DENIED(rate limited")


def test_unsigned_command_is_a_valid_unsigned_frame():
    raw = mr.build_unsigned_command(OP_STATUS_NOW)
    assert raw[0] == 0xFD and raw[2] & 1 == 0
    signed = build_command_frame(KEY, OP_STATUS_NOW)
    assert len(signed) == len(raw) + 13


# --------------------------------------------------------------------------- #
# mgmt_radio: Monitor on canned frames
# --------------------------------------------------------------------------- #
def test_monitor_meters_bytes_and_decodes_management_frames():
    mon = mr.Monitor(SimpleNamespace(), KEY)
    ack = canned(lambda e: e.command_ack_encode(CMD_MGMT, 0, 0, 0, 255, 190), (1, 191), key=KEY, link_id=2)
    forged = canned(lambda e: e.command_ack_encode(CMD_MGMT, 0, 0, 0, 255, 190), (1, 191),
                    key=bytes(range(50, 82)), link_id=2)
    report = pack_status(StatusReport(posture="active-ips"))
    status = canned(lambda e: e.memory_vect_encode(STATUS_ADDRESS, STATUS_VER, STATUS_TYPE, report), (1, 191))
    summary = canned(lambda e: e.memory_vect_encode(MARKER_ADDRESS, 1, 0, [0] * 32), (1, 191))
    text = canned(lambda e: e.statustext_encode(4, b"AEGIS: posture ACTIVE_IPS"), (1, 191))
    telem = canned(lambda e: e.attitude_encode(0, 0, 0, 0, 0, 0, 0), (1, 1))
    for i, m in enumerate((ack, forged, status, summary, text, telem)):
        mon.ingest(m, 1.0 + i * 0.1)
    kinds = [s.kind for s in mon.samples]
    assert kinds == ["mgmt", "mgmt", "mgmt", "crossend", "mgmt", "telemetry"]
    assert mon.samples[0].nbytes == len(ack.get_msgbuf()) == 22 + 13  # signature bytes are counted
    assert [a["verified"] for a in mon.acks] == [True, False]
    assert mon.acks[0]["result"] == 0
    assert mon.latest_posture(since=0.0) == "active-ips" and mon.latest_posture(since=9.0) is None
    assert mon.texts[0]["text"] == "AEGIS: posture ACTIVE_IPS"
    summ = mr.rate_summary(mon.samples, 1.0, 2.0)
    assert summ["kinds"]["mgmt"]["frames"] == 4 and summ["kinds"]["telemetry"]["frames"] == 1


def test_monitor_learns_vehicle_sysid_from_heartbeat_only():
    mon = mr.Monitor(SimpleNamespace(), KEY)
    mon.ingest(canned(lambda e: e.heartbeat_encode(mavutil.mavlink.MAV_TYPE_GCS, 8, 0, 0, 4, 3), (255, 190)), 1.0)
    assert mon.vehicle_sysid is None
    mon.ingest(canned(lambda e: e.heartbeat_encode(2, 3, 0, 0, 4, 3), (7, 1)), 2.0)
    assert mon.vehicle_sysid == 7
