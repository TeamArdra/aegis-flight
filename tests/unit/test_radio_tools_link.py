"""Offline tests for the real-radio link tools (``scripts/radio_test``): parsing, statistics, relay. No hardware."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest
import serial
from pymavlink.dialects.v10 import common as mav1
from pymavlink.dialects.v20 import common as mav2

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "radio_test"))

import com_probe  # noqa: E402
import link_baseline as lb  # noqa: E402
import pi_relay  # noqa: E402


class FakePort:
    """In-memory serial port: ``inbox`` is what a read returns; ``on_write`` may reply (echo, drop, ...)."""

    def __init__(self, inbox: bytes = b"", on_write=None) -> None:
        self.inbox = bytearray(inbox)
        self.written = bytearray()
        self.on_write = on_write
        self.closed = False

    @property
    def in_waiting(self) -> int:
        return len(self.inbox)

    def read(self, n: int = 1) -> bytes:
        if not self.inbox:
            time.sleep(0.002)
            return b""
        out = bytes(self.inbox[:n])
        del self.inbox[:n]
        return out

    def write(self, data: bytes) -> int:
        self.written.extend(data)
        if self.on_write:
            self.on_write(self, data)
        return len(data)

    def reset_input_buffer(self) -> None:
        self.inbox.clear()

    def close(self) -> None:
        self.closed = True


def echo(port: FakePort, data: bytes) -> None:
    port.inbox.extend(data)


def echo_every_other(port: FakePort, data: bytes) -> None:
    port.count = getattr(port, "count", 0) + 1
    if port.count % 2:
        port.inbox.extend(data)


def heartbeat_v2(sysid: int = 1) -> bytes:
    m = mav2.MAVLink(None, srcSystem=sysid, srcComponent=1)
    return bytes(mav2.MAVLink_heartbeat_message(2, 3, 81, 0, 4, 3).pack(m))


def heartbeat_v1(sysid: int = 7) -> bytes:
    m = mav1.MAVLink(None, srcSystem=sysid, srcComponent=1)
    return bytes(mav1.MAVLink_heartbeat_message(2, 3, 81, 0, 4, 3).pack(m))


def signed_ping() -> bytes:
    m = mav2.MAVLink(None, srcSystem=1, srcComponent=1)
    m.signing.secret_key = b"k" * 32
    m.signing.sign_outgoing = True
    m.signing.timestamp = 1
    return bytes(mav2.MAVLink_ping_message(1, 2, 1, 1).pack(m))


# ---- frame scanner -------------------------------------------------------------------------------------------------


def test_scanner_v1_v2_and_signed():
    sc = com_probe.FrameScanner()
    signed = signed_ping()
    assert len(signed) == 26 + 13
    frames = sc.feed(heartbeat_v2(1) + heartbeat_v1(7) + signed)
    assert [(f.msgid, f.sysid) for f in frames] == [(0, 1), (0, 7), (4, 1)]
    assert sc.garbage_bytes == 0


def test_scanner_chunked_and_garbage():
    stream = b"\x00\x11" + heartbeat_v2() + b"\xfd\xff\xfe" + heartbeat_v1() + heartbeat_v2() * 12
    sc = com_probe.FrameScanner()
    out = []
    for i in range(0, len(stream), 3):
        out += sc.feed(stream[i : i + 3])
    assert len(out) == 14  # a bogus long header stalls the scan, then it resyncs without losing frames
    assert sc.garbage_bytes > 0


def test_scanner_rejects_bad_crc_and_unknown_id():
    bad = bytearray(heartbeat_v2())
    bad[-1] ^= 0xFF
    sc = com_probe.FrameScanner()
    assert sc.feed(bytes(bad)) == []
    unknown = bytearray(heartbeat_v2())
    unknown[7:10] = (0xFF, 0xFF, 0x0F)
    assert com_probe.FrameScanner().feed(bytes(unknown)) == []
    assert len(sc.feed(heartbeat_v2())) == 1  # recovers after garbage


# ---- ping codec and statistics -------------------------------------------------------------------------------------


def test_ping_codec_fixed_length_roundtrip():
    codec = lb.PingCodec()
    for seq in (0, 1, 255, 70000):
        raw = codec.encode(seq, 123456789 + seq)
        assert len(raw) == lb.FRAME_LEN == 26
        (fr,) = com_probe.FrameScanner().feed(raw)
        assert fr.msgid == lb.PING_ID
        assert lb.PingCodec.decode(fr.payload) == (123456789 + seq, seq)
    assert lb.PingCodec.decode(b"\x01") == (1, 0)


def test_percentile():
    assert lb.percentile([], 50) is None
    assert lb.percentile([5.0], 99) == 5.0
    vals = [float(v) for v in range(1, 101)]
    assert lb.percentile(vals, 50) == pytest.approx(50.5)
    assert lb.percentile(vals, 100) == 100.0
    assert lb.percentile(vals[::-1], 95) == pytest.approx(95.05)


def _samples(rate: float, rtts: list[float | None]) -> list[lb.Sample]:
    return [lb.Sample(i, rate, i / rate, r) for i, r in enumerate(rtts)]


def test_summarize_rate_loss_and_throughput():
    row = lb.summarize_rate(10, _samples(10, [100.0, 200.0, None, 300.0]), 26, send_span_s=0.4)
    assert (row.sent, row.received) == (4, 3)
    assert row.loss_pct == pytest.approx(25.0)
    assert row.rtt_p50_ms == 200.0 and row.rtt_max_ms == 300.0
    assert row.rx_Bps == pytest.approx(3 * 26 / 0.4)
    empty = lb.summarize_rate(10, _samples(10, [None, None]), 26, 0.2)
    assert empty.loss_pct == 100.0 and empty.rtt_p50_ms is None


def test_find_saturation():
    def row(rate, loss, p95):
        return lb.RateResult(rate, 100, 100, 0, loss, p95, p95, p95, p95, 0, 0, 0, 0, 0)

    clean = [row(5, 0, 100), row(10, 0.5, 120), row(20, 1, 200)]
    assert lb.find_saturation(clean) is None
    assert lb.find_saturation([*clean, row(40, 12, 300)]) == 40
    assert lb.find_saturation([row(5, 0, 100), row(10, 0, 400), row(20, 0, 900)]) == 10  # latency blow-up
    assert lb.find_saturation([row(40, 9, 1), row(5, 0, 1)]) == 40  # order-independent


# ---- baseline run over fake / loopback ports -----------------------------------------------------------------------


def test_run_baseline_loopback_clean():
    ser = serial.serial_for_url("loop://", timeout=0.05)
    alive, rows, samples, err = lb.run_baseline(ser, [20, 40], 0.4, drain_s=0.3, warmup_s=0.4, log=lambda *_: None)
    ser.close()
    assert alive and not err
    assert [r.rate_fps for r in rows] == [20, 40]
    assert all(r.loss_pct == 0 and r.dups == 0 and r.rtt_p50_ms is not None for r in rows)
    assert all(r.rtt_p50_ms < 200 for r in rows)
    assert len(samples) == sum(r.sent for r in rows)


def test_run_baseline_lossy_link():
    port = FakePort(on_write=echo_every_other)
    alive, rows, _, _ = lb.run_baseline(port, [20], 0.6, drain_s=0.2, warmup_s=0.6, log=lambda *_: None)
    assert alive
    assert 40 <= rows[0].loss_pct <= 60


def test_run_baseline_dead_echo_path():
    alive, rows, samples, _ = lb.run_baseline(FakePort(), [20], 0.2, drain_s=0.1, warmup_s=0.4, log=lambda *_: None)
    assert not alive and rows == [] and samples == []


def test_run_baseline_counts_duplicates_and_noise():
    def dup_echo(port: FakePort, data: bytes) -> None:
        port.inbox.extend(b"\x00\x01" + data + data)

    port = FakePort(on_write=dup_echo)
    alive, rows, _, _ = lb.run_baseline(port, [20], 0.4, drain_s=0.2, warmup_s=0.4, log=lambda *_: None)
    assert alive and rows[0].loss_pct == 0
    assert rows[0].dups >= rows[0].sent - 1 and rows[0].stray_bytes > 0


def test_baseline_main_dry_run_writes_results(tmp_path):
    rc = lb.main(["--port", "loop://", "--rates", "20,40", "--seconds-per-rate", "0.4", "--drain", "0.3",
                  "--out", str(tmp_path)])
    assert rc == 0
    doc = json.loads((tmp_path / "p1_baseline.json").read_text())
    assert doc["phase"] == "p1_baseline" and doc["passed"]
    assert set(doc["metrics"]["per_rate"]) == {"20", "40"}
    assert {c["name"] for c in doc["checks"]} >= {"loss <= 1% at lowest rate", "rtt p50 recorded"}
    lines = (tmp_path / "p1_baseline_raw.csv").read_text().splitlines()
    assert lines[0] == "rate_fps,seq,sent_s,rtt_ms,dups" and len(lines) > 10
    assert "p1_baseline_raw.csv" in doc["artifacts"]


def test_baseline_main_port_missing(tmp_path):
    rc = lb.main(["--port", "/dev/does-not-exist-af", "--out", str(tmp_path)])
    assert rc == 2
    assert json.loads((tmp_path / "p1_baseline.json").read_text())["passed"] is False


# ---- com_probe -----------------------------------------------------------------------------------------------------


def _probe_opener(good_baud: int, written: list[bytes]):
    def opener(port: str, baud: int, timeout: float = 0.1) -> FakePort:
        stream = heartbeat_v2(1) * 20 if baud == good_baud else b"\x8f\x01\xfd\x33\xaa" * 40
        return FakePort(stream, on_write=lambda _p, d: written.append(d))

    return opener


def test_probe_picks_best_baud_and_never_writes(tmp_path):
    written: list[bytes] = []
    rc = com_probe.run("COM3", [57600, 115200, 9600], 0.05, str(tmp_path), opener=_probe_opener(115200, written))
    assert rc == 0 and written == []
    doc = json.loads((tmp_path / "p0_probe.json").read_text())
    assert doc["passed"] and doc["metrics"]["best_baud"] == 115200
    by_baud = {r["baud"]: r for r in doc["metrics"]["results"]}
    assert by_baud[115200]["frames"] == 20 and by_baud[115200]["msg_ids"] == [0] and by_baud[115200]["sysids"] == [1]
    assert by_baud[57600]["frames"] == 0


def test_probe_no_valid_mavlink(tmp_path):
    rc = com_probe.run("COM3", [57600], 0.05, str(tmp_path), opener=_probe_opener(0, []))
    assert rc == 1
    doc = json.loads((tmp_path / "p0_probe.json").read_text())
    assert not doc["passed"] and doc["metrics"]["best_baud"] is None


def test_probe_port_busy_exits_nonzero(tmp_path, capsys):
    def busy(*_a, **_k):
        raise serial.SerialException("could not open port 'COM3': PermissionError(13, 'Access is denied.', None, 5)")

    rc = com_probe.run("COM3", [57600, 115200], 0.05, str(tmp_path), opener=busy)
    assert rc == 2
    assert "busy" in capsys.readouterr().err
    doc = json.loads((tmp_path / "p0_probe.json").read_text())
    assert [c["passed"] for c in doc["checks"]] == [False, False]


# ---- pi_relay ------------------------------------------------------------------------------------------------------


def test_frame_counter_chunked():
    hb = heartbeat_v2() + heartbeat_v1() + signed_ping()
    fc = pi_relay.FrameCounter()
    for i in range(0, len(hb) + 5, 4):
        fc.feed(hb[i : i + 4])
    assert fc.frames == 3 and fc.bad_bytes == 0
    fc.feed(b"\x00\x00")
    assert fc.bad_bytes == 2


def test_relay_echo_returns_every_byte():
    radio = FakePort(heartbeat_v2() * 3)
    relay = pi_relay.Relay(radio)
    while relay.pump_once():
        pass
    assert bytes(radio.written) == heartbeat_v2() * 3
    s = relay.stats("echo")
    assert s["bytes_radio_rx"] == s["bytes_radio_tx"] == len(heartbeat_v2()) * 3
    assert s["frames_from_radio"] == 3


def test_relay_pass_both_directions():
    radio, other = FakePort(heartbeat_v2()), FakePort(heartbeat_v1() * 2)
    relay = pi_relay.Relay(radio, other)
    while relay.pump_once():
        pass
    assert bytes(other.written) == heartbeat_v2()
    assert bytes(radio.written) == heartbeat_v1() * 2
    s = relay.stats("pass")
    assert (s["frames_from_radio"], s["frames_from_other"]) == (1, 2)
    assert s["bytes_other_tx"] == len(heartbeat_v2()) and s["bytes_radio_tx"] == 2 * len(heartbeat_v1())


def test_relay_serve_writes_stats_file(tmp_path):
    stats = tmp_path / "stats.json"
    radio = FakePort(heartbeat_v2())
    relay = pi_relay.Relay(radio)
    t0 = time.monotonic()
    pi_relay.serve(relay, "echo", str(stats), interval=0.05, stop=lambda: time.monotonic() - t0 > 0.15)
    doc = json.loads(stats.read_text())
    assert doc["mode"] == "echo" and doc["frames_from_radio"] == 1 and doc["bytes_radio_tx"] == len(heartbeat_v2())
