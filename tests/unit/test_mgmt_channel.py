"""In-band management channel (hal/mgmt_channel.py + backend/bridge_remote.py): SYNTHETIC frames, in-memory links.

Nothing here opens a socket, a serial port or SITL, and nothing is measured on a radio or a companion computer.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from pymavlink.dialects.v20 import common as mav2

from aegisflight.backend.bridge_remote import BridgeRemote
from aegisflight.detectors.crossend import MARKER_ADDRESS, MARKER_TYPE, MARKER_VER, pack_summary
from aegisflight.hal.inline_ips import InlineIpsBridge
from aegisflight.hal.mgmt_channel import (
    CMD_MGMT,
    OP_ACK_ALARMS,
    OP_SET_POSTURE,
    OP_STATUS_NOW,
    P_ACK,
    P_EVENT,
    P_STATUS,
    STATUS_ADDRESS,
    STATUS_TYPE,
    STATUS_VER,
    AlertGate,
    AuditLog,
    ByteBudget,
    StatusReport,
    build_command_frame,
    crc8,
    decode_mgmt_frame,
    format_action,
    format_alert,
    pack_status,
    unpack_status,
    verify_audit_log,
)
from aegisflight.mavlink.signing import MavlinkSignatureVerifier
from aegisflight.proxy.transport import split_frames

KEY_M = bytes(range(32))          # management key
KEY_F = bytes(range(100, 132))    # flight key
WRONG = bytes(range(50, 82))


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


class Link:
    connected = True

    def __init__(self) -> None:
        self.inbox: list[tuple[int, bytes]] = []
        self.sent: list[bytes] = []

    def feed(self, *frames: bytes) -> None:
        self.inbox.extend((1_000_000_000, f) for f in frames)

    def poll(self):
        out, self.inbox = self.inbox, []
        return out

    def send(self, data: bytes) -> bool:
        self.sent.append(bytes(data))
        return True

    def close(self) -> None:
        pass


def _enc(sysid: int, comp: int = 1) -> mav2.MAVLink:
    m = mav2.MAVLink(None, srcSystem=sysid, srcComponent=comp)
    m.robust_parsing = True
    return m


def cmd_long(sysid: int, command: int, p1: float = 0, comp: int = 190) -> bytes:
    m = _enc(sysid, comp)
    return bytes(m.command_long_encode(1, 1, command, 0, p1, 0, 0, 0, 0, 0, 0).pack(m))


def heartbeat() -> bytes:
    m = _enc(1, 1)
    return bytes(m.heartbeat_encode(2, 3, 0x80, 4, 4).pack(m))


def gpi(tbm: int = 1000) -> bytes:
    m = _enc(1, 1)
    return bytes(m.global_position_int_encode(tbm, 190000000, 729000000, 40000, 30000, 0, 0, 0, 0).pack(m))


def decode_all(frames: list[bytes]) -> list[dict]:
    out = []
    for f in frames:
        for fr in split_frames(f)[0]:
            d = decode_mgmt_frame(fr.raw)
            if d is not None:
                out.append(d)
    return out


def texts(link: Link) -> list[str]:
    return [d["text"] for d in decode_all(link.sent) if d["kind"] == "text"]


def acks(link: Link, key: bytes | None = KEY_M) -> list[dict]:
    ver = MavlinkSignatureVerifier(key) if key else None
    out = []
    for f in link.sent:
        for fr in split_frames(f)[0]:
            d = decode_mgmt_frame(fr.raw)
            if d and d["kind"] == "ack":
                if ver is not None:
                    assert ver.verify_frame(fr.raw).valid, "ACK must be signed with the management key"
                out.append(d)
    return out


def make_bridge(tmp_path=None, mode="passive", **kw):
    clock = Clock()
    fc, gcs = Link(), Link()
    kw.setdefault("mgmt_status_interval_s", 0.0)
    kw.setdefault("mgmt_clock", clock)
    if tmp_path is not None:
        kw.setdefault("audit_log_path", str(tmp_path / "audit.jsonl"))
        kw.setdefault("mgmt_state_path", str(tmp_path / "state.json"))
    return InlineIpsBridge(fc, gcs, mode=mode, **kw), fc, gcs, clock


class Ground:
    """Signs commands like the dashboard backend does (one signer = strictly increasing timestamps)."""

    def __init__(self, key: bytes = KEY_M) -> None:
        self.key = key
        self.signer = MavlinkSignatureVerifier(key)

    def frame(self, op: int, posture: int = 0, allow: bool = False, token: int = 0) -> bytes:
        return build_command_frame(self.key, op, posture, allow, token, signer=self.signer)


def run_cmd(b, fc, gcs, clock, g: Ground, *a, dt: float = 1.5, **kw) -> dict | None:
    clock.t += dt
    n0 = len(acks(gcs, None))
    gcs.feed(g.frame(*a, **kw))
    b.pump_once()
    got = acks(gcs, None)
    return got[-1] if len(got) > n0 else None


# --------------------------------------------------------------------------- #
# status vector
# --------------------------------------------------------------------------- #
def full_report() -> StatusReport:
    return StatusReport(posture="active-ips", topology="A+B", state="SAFE_HOLD",
                        flags={"signing": True, "analyser_ok": False, "fc_link": True, "gcs_link": False,
                               "contested": True, "unsigned_ack": True, "control_enabled": True},
                        forwarded=123456, dropped_up=77, alerts=9, counter_frames=5, hook_errors=2,
                        last_alert_class="COMMAND_INJECTION", last_alert_severity="HIGH", since_action_s=42, seq=200)


def test_status_round_trips_every_field_and_is_32_bytes():
    r = full_report()
    v = pack_status(r)
    assert len(v) == 32 and all(-128 <= x <= 127 for x in v)
    assert unpack_status(v) == r


@pytest.mark.parametrize("posture", ["passive", "advisory", "active-ips"])
@pytest.mark.parametrize("topo", [None, "A", "A+B"])
def test_status_round_trips_postures_and_topologies(posture, topo):
    r = StatusReport(posture=posture, topology=topo, state="NOMINAL", since_action_s=None)
    assert unpack_status(pack_status(r)) == r


def test_status_flags_each_bit_independent():
    for k in ("signing", "analyser_ok", "fc_link", "gcs_link", "contested", "unsigned_ack", "control_enabled"):
        r = StatusReport(flags={**StatusReport().flags, k: True})
        out = unpack_status(pack_status(r))
        assert [n for n, on in out.flags.items() if on] == [k]


def test_status_counters_saturate():
    r = StatusReport(forwarded=2**40, dropped_up=10**9, alerts=70000, counter_frames=65536, hook_errors=99999,
                     since_action_s=10**6)
    out = unpack_status(pack_status(r))
    assert (out.forwarded, out.dropped_up, out.alerts, out.counter_frames, out.hook_errors) == (
        0xFFFFFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF)
    assert out.since_action_s == 0xFFFE


def test_status_rejects_corrupt_wrong_size_and_version():
    v = pack_status(full_report())
    for i in range(31):
        bad = list(v)
        bad[i] ^= 0x10
        assert unpack_status(bad) is None, i
    assert unpack_status(v[:31]) is None
    raw = bytearray(b & 0xFF for b in v)
    raw[0] = 9  # unknown payload version with a VALID crc
    raw[31] = crc8(bytes(raw[:31]))
    assert unpack_status([b - 256 if b > 127 else b for b in raw]) is None


def test_status_frame_decodes_and_other_markers_are_rejected():
    sender = _enc(1, 191)
    good = bytes(sender.memory_vect_encode(STATUS_ADDRESS, STATUS_VER, STATUS_TYPE, pack_status(full_report())).pack(sender))
    assert decode_mgmt_frame(good)["report"] == full_report()
    cross = bytes(sender.memory_vect_encode(MARKER_ADDRESS, MARKER_VER, MARKER_TYPE,
                                            pack_summary((1, 2, 3, 4, 5, 6, 7))).pack(sender))
    assert decode_mgmt_frame(cross) is None  # the cross-end summary marker is distinct
    other = bytes(sender.memory_vect_encode(0x1234, 1, 1, pack_status(full_report())).pack(sender))
    assert decode_mgmt_frame(other) is None
    assert (STATUS_ADDRESS, STATUS_VER, STATUS_TYPE) != (MARKER_ADDRESS, MARKER_VER, MARKER_TYPE)


# --------------------------------------------------------------------------- #
# text, budget, dedupe
# --------------------------------------------------------------------------- #
def test_alert_and_action_texts_are_short_and_prefixed():
    assert format_alert("COMMAND_INJECTION", "HIGH", 66) == "AEGIS: COMMAND_INJECTION HIGH sys66"
    assert len(format_alert("TELEMETRY_MANIPULATION", "SUSPICIOUS", 255).encode()) <= 50
    assert format_action("QUARANTINE", "Quarantined rogue sender SysID 42 (x)") == "AEGIS: quarantine sys42"
    assert format_action("GPS_ALT_HOLD", "GPS fault -> ALT_HOLD so ...") == "AEGIS: set ALT_HOLD (GPS fault)"
    assert format_action("MODE_CHANGE", "x") is None
    assert len(format_action("SOMETHING_ELSE", "y" * 200).encode()) <= 50


def test_alert_severity_mapping_and_gcs_only_in_every_posture():
    for mode in ("passive", "advisory", "active-ips"):
        b, fc, gcs, clock = make_bridge(mode=mode, secret_key=KEY_F)
        for i, (sev, want) in enumerate((("CRITICAL", 2), ("HIGH", 3), ("SUSPICIOUS", 4), ("WATCH", 5))):
            clock.t += 10
            assert b.mgmt.alert("DOS" if i == 0 else "GPS_SPOOFING" if i == 1 else "MAVLINK_ANOMALY" if i == 2
                                else "TELEMETRY_MANIPULATION", sev, 66)
            fr = split_frames(gcs.sent[-1])[0][0]
            assert fr.msgid == 253 and fr.sysid == 1 and fr.compid == 191 and fr.signed
            assert decode_mgmt_frame(fr.raw)["severity"] == want
        assert fc.sent == []  # never the flight controller
        assert len(texts(gcs)) == 4


def test_gcs_alerts_off_sends_no_alert_or_action_text():
    b, fc, gcs, clock = make_bridge(gcs_alerts=False)
    assert not b.mgmt.alert("DOS", "CRITICAL", None)
    assert not b.mgmt.action("QUARANTINE", "SysID 3")
    assert gcs.sent == []


def test_dedupe_per_type_and_escalation_bypass():
    clock = Clock()
    g = AlertGate(min_interval_s=2.0, burst=100, clock=clock)
    assert g.allow("DOS", 3)
    assert not g.allow("DOS", 3)              # same type, same severity inside the interval
    assert not g.allow("DOS", 2)              # lower severity
    assert g.allow("DOS", 4)                  # escalation: at once
    assert g.allow("GPS", 3)                  # another type is independent
    clock.t += 2.1
    assert g.allow("DOS", 4)                  # interval passed


def test_global_bucket_limits_a_storm_of_different_types():
    clock = Clock()
    g = AlertGate(min_interval_s=2.0, burst=5, refill_per_s=1.0, clock=clock)
    ok = sum(g.allow(f"T{i}", 1) for i in range(50))
    assert ok == 5


def test_budget_priorities_ack_first_status_last():
    clock = Clock()
    b = ByteBudget(150.0, clock=clock)
    n = 0
    while b.allow(60, P_EVENT):
        n += 1
    assert n >= 1
    assert not b.allow(60, P_STATUS)          # status is starved first
    assert not b.allow(60, P_EVENT)           # events keep a reserve
    assert b.allow(35, P_ACK)                 # an ACK still goes


def test_worst_case_bytes_per_second_is_bounded_by_the_budget():
    """Flood every kind of message for 60 s: total bytes <= capacity + rate * T (150 B/s sustained)."""
    b, fc, gcs, clock = make_bridge(secret_key=KEY_F, mgmt_key=KEY_M, mgmt_status_interval_s=0.2,
                                    alert_min_interval_s=0.0)
    b.mgmt.gate.burst = b.mgmt.gate._tokens = 1e9  # take the per-message gate out: the BYTE budget must hold alone
    b.mgmt.gate.refill = 1e9
    g = Ground()
    T = 60
    for _ in range(T * 20):
        clock.t += 0.05
        for i, t in enumerate(("DOS", "GPS_SPOOFING", "COMMAND_INJECTION", "MAVLINK_ANOMALY")):
            b.mgmt.alert(t, "CRITICAL" if i == 0 else "HIGH", 66)
            b.mgmt.action(f"ACT{i}{int(clock.t * 20)}", "x")
            b.mgmt.note_drop(f"LAND sys{i}")
        gcs.feed()
        b.mgmt.service()
        if int(clock.t * 20) % 20 == 0:
            gcs.feed(g.frame(OP_STATUS_NOW))
            b.pump_once()
    cap = b.mgmt.budget.capacity
    assert b.mgmt.bytes_sent == sum(len(f) for f in gcs.sent)
    assert b.mgmt.bytes_sent <= cap + b.mgmt.budget.rate * T
    assert b.mgmt.bytes_sent / T <= 150 * 1.05 + cap / T
    assert b.mgmt.budget.denied > 0


def test_normal_operation_stays_far_below_the_budget():
    b, fc, gcs, clock = make_bridge(secret_key=KEY_F, mgmt_key=KEY_M, mgmt_status_interval_s=2.0)
    for _ in range(600):  # 60 s of idle status
        clock.t += 0.1
        b.pump_once()
    per_s = sum(len(f) for f in gcs.sent) / 60
    assert 20 <= per_s <= 40  # one 61-byte signed status every 2 s


# --------------------------------------------------------------------------- #
# bridge wiring
# --------------------------------------------------------------------------- #
def _stub_assessment(b, attack="COMMAND_INJECTION", sev="HIGH", rogue=(66,)):
    from aegisflight.core.enums import AttackType, Severity

    asmt = SimpleNamespace(is_alert=True, attack_type=AttackType(attack), severity=Severity(sev))
    b.pipeline = SimpleNamespace(process_tick=lambda tick: asmt, last_frame=object())
    b.controller = SimpleNamespace(
        mode=b.controller.mode, state=b.controller.state, set_mode=b.controller.set_mode, action_history=[],
        step=lambda frame, a: SimpleNamespace(summary="s", counter_frames=[], params=SimpleNamespace(rogue_sysids=rogue)),
        sanitizer=b.controller.sanitizer, ekf_secondary_available=False)


@pytest.mark.parametrize("mode", ["passive", "advisory", "active-ips"])
def test_ids_alert_becomes_statustext_to_gcs_only(mode):
    b, fc, gcs, clock = make_bridge(mode=mode, secret_key=KEY_F)
    _stub_assessment(b)
    b.analyse_tick(object())
    assert texts(gcs) == ["AEGIS: COMMAND_INJECTION HIGH sys66"]
    assert fc.sent == []


def test_controller_actions_are_announced_once_each():
    b, fc, gcs, clock = make_bridge(mode="active-ips", secret_key=KEY_F)
    b.controller.action_history.append({"t": 1.0, "tag": "QUARANTINE", "detail": "Quarantined rogue sender SysID 42"})
    b.controller.action_history.append({"t": 2.0, "tag": "GPS_ALT_HOLD", "detail": "GPS fault -> ALT_HOLD"})
    b._announce_actions()
    b._announce_actions()
    assert texts(gcs) == ["AEGIS: quarantine sys42", "AEGIS: set ALT_HOLD (GPS fault)"]
    assert fc.sent == []


def test_posture_change_is_announced_and_hostile_drops_are_aggregated():
    b, fc, gcs, clock = make_bridge(secret_key=KEY_F)
    b.set_mode("active-ips")
    assert "AEGIS: posture ACTIVE_IPS" in texts(gcs)
    land = cmd_long(66, 21)  # NAV_LAND from an untrusted sysid on a keyed link: unsigned -> dropped
    for _ in range(3):
        fc.feed()
        gcs.feed(land)
        b.pump_once()
    assert [fr for f in fc.sent for fr in split_frames(f)[0] if fr.msgid == 76] == []
    clock.t += 1.2
    b.pump_once()
    drops = [t for t in texts(gcs) if t.startswith("AEGIS: blocked")]
    assert drops == ["AEGIS: blocked LAND sys66 x3"]


def test_status_vector_flows_with_counters_and_flags():
    b, fc, gcs, clock = make_bridge(secret_key=KEY_F, mgmt_key=KEY_M, mgmt_status_interval_s=2.0)
    fc.feed(heartbeat(), gpi())
    b.pump_once()
    clock.t += 2.1
    b.pump_once()
    st = [d["report"] for d in decode_all(gcs.sent) if d["kind"] == "status"]
    assert len(st) == 1
    r = st[0]
    assert r.posture == "passive" and r.topology == "A+B" and r.state == "NOMINAL"
    assert r.flags["signing"] and r.flags["control_enabled"] and r.flags["fc_link"] and r.flags["analyser_ok"]
    assert r.forwarded == 2 and r.since_action_s is None


def test_mgmt_frames_are_never_tapped_and_share_one_sequence_stream():
    b, fc, gcs, clock = make_bridge(secret_key=KEY_F, mgmt_key=KEY_M, mgmt_status_interval_s=0.5)
    g = Ground()
    fc.feed(gpi())
    b.pump_once()
    b.tap.poll()
    clock.t += 1
    gcs.feed(g.frame(OP_STATUS_NOW))
    b.pump_once()
    b.mgmt.alert("DOS", "CRITICAL", 5)
    b.emit_crossend()
    b.mgmt.service()
    assert b.tap.poll() == []  # nothing the management channel did reached the detectors
    seqs = [fr.seq for f in gcs.sent for fr in split_frames(f)[0] if fr.compid == 191]
    assert len(seqs) >= 3 and seqs == [(seqs[0] + i) % 256 for i in range(len(seqs))]


# --------------------------------------------------------------------------- #
# command authentication matrix
# --------------------------------------------------------------------------- #
def test_command_consumed_never_forwarded_or_tapped_even_without_key():
    b, fc, gcs, clock = make_bridge()  # no mgmt key
    g = Ground()
    gcs.feed(g.frame(OP_SET_POSTURE, 2), cmd_long(255, 400))
    b.pump_once()
    fcframes = [fr for f in fc.sent for fr in split_frames(f)[0]]
    assert [fr.msgid for fr in fcframes] == [76]  # only the unrelated COMMAND_LONG; the mgmt command is consumed
    raw_tap = [fr for _s, d in b.tap.poll() for fr in split_frames(d)[0]]
    assert len(raw_tap) == 1  # the ordinary command only
    assert b.controller.mode.value == "passive"


def test_no_key_control_disabled_denied_unsigned_ack():
    b, fc, gcs, clock = make_bridge()
    a = run_cmd(b, fc, gcs, clock, Ground(), OP_SET_POSTURE, 2, True)
    assert a["result"] == 2 and a["result_param2"] == 1
    assert not split_frames(gcs.sent[-1])[0][0].signed
    assert b.controller.mode.value == "passive"


def test_wrong_key_unsigned_and_replay_are_ignored_and_never_execute(tmp_path):
    b, fc, gcs, clock = make_bridge(tmp_path, mgmt_key=KEY_M)
    n0 = len(gcs.sent)
    assert run_cmd(b, fc, gcs, clock, Ground(WRONG), OP_SET_POSTURE, 2, True) is None
    unsigned = bytes(_enc(255, 190).command_long_encode(1, 191, CMD_MGMT, 0, 1, 2, 1, 0, 0, 0, 0).pack(_enc(255, 190)))
    gcs.feed(unsigned)
    b.pump_once()
    assert b.controller.mode.value == "passive" and len(gcs.sent) == n0
    g = Ground()
    frame = g.frame(OP_STATUS_NOW)
    clock.t += 2
    gcs.feed(frame)
    b.pump_once()
    assert acks(gcs, KEY_M)[-1]["result"] == 0
    clock.t += 2
    gcs.feed(frame)  # exact replay
    b.pump_once()
    assert len(acks(gcs, KEY_M)) == 1 and b.mgmt.bad_signatures == 3


def test_valid_raise_to_active_needs_flight_key_or_ack():
    b, fc, gcs, clock = make_bridge(mgmt_key=KEY_M)  # no flight key
    g = Ground()
    a = run_cmd(b, fc, gcs, clock, g, OP_SET_POSTURE, 2, False)
    assert a["result"] == 2 and a["result_param2"] == 4 and b.controller.mode.value == "passive"
    a = run_cmd(b, fc, gcs, clock, g, OP_SET_POSTURE, 2, True)
    assert a["result"] == 0 and b.controller.mode.value == "active-ips" and b.unsigned_acknowledged
    assert fc.sent == []
    b2, _fc2, gcs2, clock2 = make_bridge(mgmt_key=KEY_M, secret_key=KEY_F)
    a = run_cmd(b2, _fc2, gcs2, clock2, Ground(), OP_SET_POSTURE, 2, False)
    assert a["result"] == 0 and b2.controller.mode.value == "active-ips"


def test_rate_limit_one_command_per_second():
    b, fc, gcs, clock = make_bridge(mgmt_key=KEY_M)
    g = Ground()
    assert run_cmd(b, fc, gcs, clock, g, OP_SET_POSTURE, 1)["result"] == 0
    a = run_cmd(b, fc, gcs, clock, g, OP_SET_POSTURE, 0, dt=0.2)
    assert a["result"] == 2 and a["result_param2"] == 3 and b.controller.mode.value == "advisory"
    assert run_cmd(b, fc, gcs, clock, g, OP_SET_POSTURE, 0, dt=1.1)["result"] == 0


def test_five_bad_signatures_lock_control_for_60s_and_announce():
    b, fc, gcs, clock = make_bridge(mgmt_key=KEY_M)
    bad = Ground(WRONG)
    for _ in range(5):
        run_cmd(b, fc, gcs, clock, bad, OP_STATUS_NOW, dt=1.0)
    assert b.mgmt.lockouts == 1 and b.mgmt.locked_out
    assert any("LOCKED" in t for t in texts(gcs))
    a = run_cmd(b, fc, gcs, clock, Ground(), OP_SET_POSTURE, 1, dt=2)
    assert a["result"] == 2 and a["result_param2"] == 2 and b.controller.mode.value == "passive"
    assert unpack_status(pack_status(b.mgmt.status_report())).flags["control_enabled"] is False
    clock.t += 61
    assert run_cmd(b, fc, gcs, clock, Ground(), OP_SET_POSTURE, 1, dt=0)["result"] == 0


def test_lowering_from_active_is_two_step_with_a_10s_token():
    b, fc, gcs, clock = make_bridge(mgmt_key=KEY_M, secret_key=KEY_F, mode="active-ips")
    g = Ground()
    a = run_cmd(b, fc, gcs, clock, g, OP_SET_POSTURE, 0)
    assert a["result"] == 5 and b.controller.mode.value == "active-ips"
    tok = a["result_param2"]
    assert tok > 0
    a = run_cmd(b, fc, gcs, clock, g, OP_SET_POSTURE, 0, token=tok + 1)   # wrong token: a NEW token, no change
    assert a["result"] == 5 and b.controller.mode.value == "active-ips"
    tok2 = a["result_param2"]
    a = run_cmd(b, fc, gcs, clock, g, OP_SET_POSTURE, 0, token=tok2, dt=11)  # expired
    assert a["result"] == 5 and b.controller.mode.value == "active-ips"
    tok3 = a["result_param2"]
    a = run_cmd(b, fc, gcs, clock, g, OP_SET_POSTURE, 1, token=tok3)          # token is bound to the target posture
    assert a["result"] == 5
    a = run_cmd(b, fc, gcs, clock, g, OP_SET_POSTURE, 0, token=a["result_param2"] - 0)
    assert a["result"] in (0, 5)
    # the straight path
    b, fc, gcs, clock = make_bridge(mgmt_key=KEY_M, secret_key=KEY_F, mode="active-ips")
    g = Ground()
    tok = run_cmd(b, fc, gcs, clock, g, OP_SET_POSTURE, 1)["result_param2"]
    a = run_cmd(b, fc, gcs, clock, g, OP_SET_POSTURE, 1, token=tok, dt=5)
    assert a["result"] == 0 and b.controller.mode.value == "advisory"
    # advisory -> passive is a single step
    assert run_cmd(b, fc, gcs, clock, g, OP_SET_POSTURE, 0)["result"] == 0 and b.controller.mode.value == "passive"


def test_lock_file_allows_only_raising(tmp_path):
    lock = tmp_path / "lock"
    b, fc, gcs, clock = make_bridge(tmp_path, mgmt_key=KEY_M, secret_key=KEY_F, mode="advisory", lock_posture_file=str(lock))
    g = Ground()
    lock.write_text("x")
    a = run_cmd(b, fc, gcs, clock, g, OP_SET_POSTURE, 0)
    assert a["result"] == 2 and a["result_param2"] == 5 and b.controller.mode.value == "advisory"
    assert run_cmd(b, fc, gcs, clock, g, OP_SET_POSTURE, 2)["result"] == 0  # raising still works
    lock.unlink()
    a = run_cmd(b, fc, gcs, clock, g, OP_SET_POSTURE, 0)
    assert a["result"] == 5  # now allowed (two-step from active-ips)


def test_other_ops_and_unsupported_and_bad_params():
    b, fc, gcs, clock = make_bridge(mgmt_key=KEY_M)
    g = Ground()
    assert run_cmd(b, fc, gcs, clock, g, 99)["result"] == 3          # UNSUPPORTED (no config / key / process ops)
    assert run_cmd(b, fc, gcs, clock, g, OP_SET_POSTURE, 7)["result"] == 2  # bad posture
    assert run_cmd(b, fc, gcs, clock, g, OP_ACK_ALARMS)["result"] == 0
    assert run_cmd(b, fc, gcs, clock, g, OP_SET_POSTURE, 0)["result"] == 0   # same posture: no-op accepted


def test_wrong_target_system_is_ignored():
    b, fc, gcs, clock = make_bridge(mgmt_key=KEY_M)
    g = Ground()
    frame = build_command_frame(KEY_M, OP_STATUS_NOW, vehicle_sysid=9, signer=g.signer)
    gcs.feed(frame)
    b.pump_once()
    assert acks(gcs, None) == [] and [fr.msgid for f in fc.sent for fr in split_frames(f)[0]] == []


def test_state_file_survives_restart_no_replay_window(tmp_path):
    b, fc, gcs, clock = make_bridge(tmp_path, mgmt_key=KEY_M)
    g = Ground()
    old = g.frame(OP_STATUS_NOW)
    clock.t += 2
    gcs.feed(old)
    b.pump_once()
    assert acks(gcs, None)[-1]["result"] == 0
    b2, fc2, gcs2, clock2 = make_bridge(tmp_path, mgmt_key=KEY_M)   # restart, same state file
    clock2.t += 2
    gcs2.feed(old)
    b2.pump_once()
    assert acks(gcs2, None) == [] and b2.mgmt.bad_signatures == 1
    clock2.t += 2
    gcs2.feed(g.frame(OP_STATUS_NOW))
    b2.pump_once()
    assert acks(gcs2, None)[-1]["result"] == 0


# --------------------------------------------------------------------------- #
# audit log
# --------------------------------------------------------------------------- #
def test_audit_chain_verifies_detects_tampering_and_has_no_keys(tmp_path):
    b, fc, gcs, clock = make_bridge(tmp_path, mgmt_key=KEY_M, secret_key=KEY_F, mode="active-ips")
    g = Ground()
    run_cmd(b, fc, gcs, clock, g, OP_STATUS_NOW)
    tok = run_cmd(b, fc, gcs, clock, g, OP_SET_POSTURE, 0)["result_param2"]
    run_cmd(b, fc, gcs, clock, g, OP_SET_POSTURE, 0, token=tok)
    run_cmd(b, fc, gcs, clock, Ground(WRONG), OP_STATUS_NOW)
    path = tmp_path / "audit.jsonl"
    ok, n, _ = verify_audit_log(path)
    assert ok and n >= 5
    text = path.read_text()
    assert KEY_M.hex() not in text and KEY_F.hex() not in text and str(tok) not in text.replace('"t":', "")
    events = [json.loads(line) for line in text.splitlines()]
    assert {e["event"] for e in events} >= {"command", "posture_change"}
    # continue the chain after a restart
    AuditLog(str(path)).append("x")
    assert verify_audit_log(path)[0]
    lines = path.read_text().splitlines()
    assert "accepted" in lines[0]
    lines[0] = lines[0].replace("accepted", "denied")
    path.write_text("\n".join(lines) + "\n")
    assert not verify_audit_log(path)[0]
    lines = path.read_text().splitlines()
    path.write_text("\n".join([lines[0]] + lines[2:]) + "\n")  # a line removed
    assert not verify_audit_log(path)[0]


# --------------------------------------------------------------------------- #
# ground side + full loop
# --------------------------------------------------------------------------- #
def relay(bridge_gcs: Link, remote: BridgeRemote, upto: int = 0) -> None:
    """The radio: bytes the bridge sent to the GCS side arrive at the ground decoder."""
    for f in bridge_gcs.sent[upto:]:
        remote.feed(f)


def test_full_loop_bridge_to_ground_reproduces_bridge_remote(tmp_path):
    t = Clock()
    remote = BridgeRemote(flight_key=KEY_F, mgmt_key=KEY_M, clock=t)
    assert remote.snapshot()["present"] is False and remote.snapshot()["age_s"] is None
    b, fc, gcs, clock = make_bridge(tmp_path, mgmt_key=KEY_M, secret_key=KEY_F, mgmt_status_interval_s=1.0)
    fc.feed(heartbeat(), gpi())
    b.pump_once()
    clock.t += 1.1
    b.pump_once()
    _stub_assessment(b)
    b.analyse_tick(object())
    b.controller.action_history.append({"t": 1.0, "tag": "QUARANTINE", "detail": "SysID 66"})
    b._announce_actions()
    clock.t += 1.1
    b.pump_once()
    relay(gcs, remote)
    snap = remote.snapshot(control_available=True)
    assert snap["present"] and snap["posture"] == "passive" and snap["topology"] == "A+B" and snap["state"] == "NOMINAL"
    assert snap["flags"] == {"signing": True, "analyser_ok": True, "fc_link": True, "gcs_link": True, "contested": False,
                             "unsigned_ack": False, "control_enabled": True}
    assert snap["counters"]["alerts"] == 1 and snap["counters"]["forwarded"] == 2
    assert snap["last_alert"] == "AEGIS: COMMAND_INJECTION HIGH sys66"
    assert snap["last_action"] == "AEGIS: quarantine sys66"
    assert [r["text"] for r in snap["recent"]] == ["AEGIS: COMMAND_INJECTION HIGH sys66", "AEGIS: quarantine sys66"]
    assert snap["control_available"] and snap["last_command"] is None and snap["authenticated"]


def test_ground_rejects_unsigned_text_when_flight_key_configured_and_caps_recent():
    remote = BridgeRemote(flight_key=KEY_F, mgmt_key=KEY_M)
    unsigned = bytes(_enc(1, 191).statustext_encode(3, b"AEGIS: DOS HIGH").pack(_enc(1, 191)))
    remote.feed(unsigned)
    assert remote.snapshot()["recent"] == []
    keyless = BridgeRemote()
    keyless.feed(unsigned)
    assert keyless.snapshot()["recent"][0]["text"] == "AEGIS: DOS HIGH" and keyless.snapshot()["authenticated"] is False
    for i in range(30):
        keyless.feed(bytes(_enc(1, 191).statustext_encode(5, f"AEGIS: n{i}".encode()).pack(_enc(1, 191))))
    assert len(keyless.snapshot()["recent"]) == 20
    # a non-AEGIS STATUSTEXT from the vehicle is not ours
    keyless2 = BridgeRemote()
    keyless2.feed(bytes(_enc(1, 191).statustext_encode(5, b"PreArm: x").pack(_enc(1, 191))))
    assert keyless2.snapshot()["present"] is False


def test_ground_post_to_bridge_execute_ack_last_command_accepted(tmp_path):
    t = Clock()
    remote = BridgeRemote(flight_key=KEY_F, mgmt_key=KEY_M, clock=t)
    b, fc, gcs, clock = make_bridge(tmp_path, mgmt_key=KEY_M, secret_key=KEY_F, mode="advisory")
    frame = remote.build_command(OP_SET_POSTURE, "active-ips")
    assert remote.snapshot()["last_command"]["result"] == "pending"
    clock.t += 1.5
    gcs.feed(frame)
    b.pump_once()
    relay(gcs, remote)
    lc = remote.snapshot()["last_command"]
    assert lc["result"] == "accepted" and lc["op"] == "posture"
    assert b.controller.mode.value == "active-ips"
    # lowering: IN_PROGRESS -> confirm_required -> confirm with the remembered token
    n = len(gcs.sent)
    t.t += 2
    clock.t += 2
    gcs.feed(remote.build_command(OP_SET_POSTURE, "passive"))
    b.pump_once()
    relay(gcs, remote, n)
    assert remote.snapshot()["last_command"]["result"] == "confirm_required"
    n = len(gcs.sent)
    t.t += 2
    clock.t += 2
    gcs.feed(remote.build_command(OP_SET_POSTURE, "passive", confirm=True))
    b.pump_once()
    relay(gcs, remote, n)
    assert remote.snapshot()["last_command"]["result"] == "accepted"
    assert b.controller.mode.value == "passive"
    # an unanswered command times out; a forged ACK (wrong key) is not believed
    t.t += 2
    remote.build_command(OP_SET_POSTURE, "advisory")
    forged = MavlinkSignatureVerifier(WRONG).sign_frame(
        bytes(_enc(1, 191).command_ack_encode(CMD_MGMT, 0, 0, 0, 255, 190).pack(_enc(1, 191))), link_id=2)
    remote.feed(forged)
    assert remote.snapshot()["last_command"]["result"] == "pending"
    t.t += 6
    assert remote.snapshot()["last_command"]["result"] == "timeout"


def test_ground_ack_denied_reason_text():
    t = Clock()
    remote = BridgeRemote(mgmt_key=KEY_M, clock=t)
    b, fc, gcs, clock = make_bridge(mgmt_key=KEY_M)
    clock.t += 1.5
    gcs.feed(remote.build_command(OP_SET_POSTURE, "active-ips"))
    b.pump_once()
    relay(gcs, remote)
    lc = remote.snapshot()["last_command"]
    assert lc["result"] == "denied" and "signing" in lc["detail"]


# --------------------------------------------------------------------------- #
# HTTP API
# --------------------------------------------------------------------------- #
@pytest.fixture()
def api(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from aegisflight.backend import app as appmod
    from aegisflight.backend.engine import LiveEngine
    from aegisflight.backend.sources import SourceSpec

    keyf = tmp_path / "mgmt.key"
    keyf.write_bytes(KEY_M)
    monkeypatch.delenv("AEGIS_API_TOKEN", raising=False)

    def make(kind="udp", mgmt=True, writable=True):
        spec = SourceSpec(kind=kind, udp_port=14999 if kind == "udp" else None,
                          mgmt_key_file=str(keyf) if mgmt else None)
        eng = LiveEngine(spec=spec, db_path=str(tmp_path / "e.sqlite"))
        link = Link()
        if writable:
            eng.feed = SimpleNamespace(transport=link, ended=False, error=None, source=None,
                                      transport_stats=lambda: {"connected": True})
        appmod.engine = eng
        return TestClient(appmod.app), eng, link

    yield make
    if appmod.engine is not None:
        appmod.engine.store.close()
    appmod.engine = None


def test_api_status_carries_bridge_remote_and_post_errors(api):
    c, eng, link = api()
    st = c.get("/api/status").json()["bridge_remote"]
    assert st["present"] is False and st["control_available"] is True and st["recent"] == []
    assert c.post("/api/bridge/posture", json={"mode": "bogus"}).status_code == 400
    assert c.post("/api/bridge/posture", json={"mode": "passive", "confirm": "yes"}).status_code == 400
    r = c.post("/api/bridge/posture", json={"mode": "advisory"})
    assert r.status_code == 200 and r.json() == {"ok": True, "pending": True}
    frames = [fr for f in link.sent for fr in split_frames(f)[0]]
    assert len(frames) == 1 and frames[0].msgid == 76 and frames[0].signed
    assert c.get("/api/status").json()["bridge_remote"]["last_command"]["result"] == "pending"


def test_api_control_unavailable_without_key_or_live_transport(api):
    c, _eng, link = api(mgmt=False)
    assert c.get("/api/status").json()["bridge_remote"]["control_available"] is False
    r = c.post("/api/bridge/posture", json={"mode": "advisory"})
    assert r.status_code == 403 and r.json()["error"] == "control_unavailable" and link.sent == []
    c, _eng, _ = api(kind="sim", mgmt=True, writable=False)
    assert c.post("/api/bridge/posture", json={"mode": "advisory"}).status_code == 403
    assert c.get("/api/status").json()["bridge_remote"]["control_available"] is False


def test_api_signing_required_when_bridge_reports_unsigned(api):
    c, eng, link = api()
    b, fc, gcs, clock = make_bridge(mgmt_key=KEY_M, mgmt_status_interval_s=1.0)  # no flight key
    clock.t += 1.1
    b.pump_once()
    relay(gcs, eng.bridge_remote)
    assert eng.bridge_remote.bridge_signing() is False
    r = c.post("/api/bridge/posture", json={"mode": "active-ips"})
    assert r.status_code == 409 and r.json()["error"] == "signing_required" and link.sent == []
    assert c.post("/api/bridge/posture", json={"mode": "active-ips", "allow_unsigned": True}).status_code == 200
    assert len(link.sent) == 1


def test_api_origin_and_token_checks_still_apply(api, monkeypatch):
    c, _eng, link = api()
    assert c.post("/api/bridge/posture", json={"mode": "advisory"},
                  headers={"origin": "http://evil.example"}).status_code == 403
    monkeypatch.setenv("AEGIS_API_TOKEN", "s3cret")
    assert c.post("/api/bridge/posture", json={"mode": "advisory"}).status_code == 401
    assert c.post("/api/bridge/posture", json={"mode": "advisory"},
                  headers={"x-aegis-token": "s3cret"}).status_code == 200
    assert len(link.sent) == 1


def test_api_post_to_bridge_to_ack_end_to_end(api):
    c, eng, link = api()
    b, fc, gcs, clock = make_bridge(mgmt_key=KEY_M, secret_key=KEY_F, mode="advisory")
    assert c.post("/api/bridge/posture", json={"mode": "active-ips"}).status_code == 200
    clock.t += 1.5
    gcs.feed(link.sent[-1])
    b.pump_once()
    relay(gcs, eng.bridge_remote)
    lc = c.get("/api/status").json()["bridge_remote"]["last_command"]
    assert lc["result"] == "accepted" and b.controller.mode.value == "active-ips"


# --------------------------------------------------------------------------- #
# the ground IDS must not flag the management traffic
# --------------------------------------------------------------------------- #
def test_ground_ids_does_not_flag_bridge_management_frames():
    from aegisflight.config import load_config
    from aegisflight.pipeline import IDSPipeline
    from aegisflight.sources.mavlink_live import frame_ticks

    b, fc, gcs, clock = make_bridge(secret_key=KEY_F, mgmt_key=KEY_M, mgmt_status_interval_s=0.5)
    stream: list[tuple[float, bytes]] = []
    t = 1.0e9
    for i in range(80):
        fc.feed(heartbeat(), gpi(1000 + i * 100))
        clock.t += 0.25
        t += 0.25
        b.pump_once()
        if i == 10:
            b.mgmt.alert("DOS", "CRITICAL", None)
            b.mgmt.action("QUARANTINE", "SysID 3")
        for f in list(fc.sent) + list(gcs.sent):
            stream.append((t, f))
        fc.sent.clear()
        gcs.sent.clear()
    assert any(d["kind"] == "status" for _t, f in stream for d in decode_all([f]))
    cfg = load_config()
    cfg.detector["protocol"]["auto_rate_baseline"] = True
    pipe = IDSPipeline(cfg, model_path=None, firmware_dir=None)
    alerts = []
    for tick in frame_ticks(iter(stream), sample_rate_hz=10.0):
        a = pipe.process_tick(tick)
        if a is not None and a.is_alert:
            alerts.append(a)
    assert alerts == []
    assert pipe.last_frame is not None and pipe.last_frame.max_seq_gap == 0


def test_dropped_mode_change_label_names_the_requested_mode():
    """Found in SITL: a forged DO_SET_MODE(LAND) was announced only as 'blocked DO_SET_MODE'."""
    from aegisflight.hal.mgmt_channel import drop_label

    m = _enc(66, 190)
    do_set_mode = bytes(m.command_long_encode(1, 1, 176, 0, 1, 9, 0, 0, 0, 0, 0).pack(m))
    set_mode = bytes(m.set_mode_encode(1, 1, 9).pack(m))
    unknown = bytes(m.command_long_encode(1, 1, 176, 0, 1, 77, 0, 0, 0, 0, 0).pack(m))
    assert drop_label(do_set_mode, 66, 76, "up") == "DO_SET_MODE(LAND) sys66"
    assert drop_label(set_mode, 66, 11, "up") == "SET_MODE(LAND) sys66"
    assert drop_label(unknown, 66, 76, "up") == "DO_SET_MODE sys66"
    assert len(format_action("QUARANTINE", "")) <= 50 and len("AEGIS: blocked DO_SET_MODE(STABILIZE) sys255 x99") <= 50


# --------------------------------------------------------------------------- #
# ground start-up quiet window
# --------------------------------------------------------------------------- #
def _tick_with(b, clock, attack: str, severity: str = "CRITICAL", armed: bool | None = None) -> None:
    """Drive analyse_tick with a canned assessment (the detectors themselves are covered elsewhere)."""
    b._clock_ns = lambda: int(clock.t * 1e9)
    b.policy.armed = armed
    assessment = SimpleNamespace(attack_type=SimpleNamespace(value=attack), severity=SimpleNamespace(value=severity), is_alert=True)
    b.pipeline = SimpleNamespace(process_tick=lambda tick: assessment, last_frame=object())
    b.controller = SimpleNamespace(step=lambda frame, a: SimpleNamespace(summary="x", params=None, counter_frames=[]),
                                   mode=b.controller.mode, action_history=[])
    b.analyse_tick(object())


def test_ground_startup_gps_and_flood_alerts_wait_for_the_quiet_window_to_pass():
    b, fc, gcs, clock = make_bridge()
    _tick_with(b, clock, "GPS_SPOOFING")                       # fix acquisition on the ground, a second after power-on
    assert not any("GPS_SPOOFING" in t for t in texts(gcs))
    assert b.alerts == 1                                        # still counted (and logged); only the GCS text is held back
    clock.t += 30.0
    _tick_with(b, clock, "GPS_SPOOFING")                       # still there 30 s later: now the pilot is told
    assert any("GPS_SPOOFING" in t for t in texts(gcs))


def test_quiet_window_never_applies_once_armed_or_to_other_alert_classes():
    b, fc, gcs, clock = make_bridge()
    _tick_with(b, clock, "GPS_SPOOFING", armed=True)
    assert any("GPS_SPOOFING" in t for t in texts(gcs))
    b2, fc2, gcs2, clock2 = make_bridge()
    _tick_with(b2, clock2, "COMMAND_INJECTION", severity="HIGH")
    assert any("COMMAND_INJECTION" in t for t in texts(gcs2))


def test_alert_gate_backs_off_for_a_persistent_condition_and_resets_on_escalation():
    t = [0.0]
    g = AlertGate(min_interval_s=4.0, burst=100, refill_per_s=100.0, clock=lambda: t[0], backoff_max_s=30.0)
    sent = []
    for i in range(400):                      # the same alert offered every second for 400 s
        t[0] = float(i)
        if g.allow("alert:FIRMWARE_INTEGRITY", 1):
            sent.append(i)
    gaps = [b - a for a, b in zip(sent, sent[1:], strict=False)]
    assert gaps[:4] == [4, 8, 16, 30] and set(gaps[4:]) == {30}          # 4, 8, 16, then every 30 s at most
    assert len(sent) < 20                                                  # ~13 instead of 100 at a fixed 4 s
    t[0] += 1.0
    assert g.allow("alert:FIRMWARE_INTEGRITY", 3)                          # a higher severity goes out at once
    t[0] += 61.0                                                           # quiet for a long time: a new episode, short gap again
    assert g.allow("alert:FIRMWARE_INTEGRITY", 3)
    t[0] += 4.0
    assert g.allow("alert:FIRMWARE_INTEGRITY", 3)


def test_boot_quiet_holds_only_start_up_noise_not_real_actions():
    b, fc, gcs, clock = make_bridge()
    b._clock_ns = lambda: int(clock.t * 1e9)
    b.policy.armed = None
    b.controller.action_history.extend([{"t": 1.0, "tag": "RATE_LIMIT", "detail": "x"},
                                        {"t": 1.1, "tag": "QUARANTINE", "detail": "Quarantined anomalous sender SysID 42"}])
    b._announce_actions()
    assert texts(gcs) == ["AEGIS: quarantine sys42"]


# --------------------------------------------------------------------------- #
# report-only signature verdicts (IDS / advisory)
# --------------------------------------------------------------------------- #
def _forged_cmd(sysid: int) -> bytes:
    enc = mav2.MAVLink(None, srcSystem=sysid, srcComponent=190)
    return bytes(enc.command_long_encode(1, 1, 176, 0, 1, 9, 0, 0, 0, 0, 0).pack(enc))      # DO_SET_MODE(LAND)


@pytest.mark.parametrize("mode", ["passive", "advisory"])
def test_ids_and_advisory_report_signing_failures_but_forward_everything(mode):
    b, fc, gcs, clock = make_bridge(mode=mode, secret_key=KEY_F)
    good, bad = MavlinkSignatureVerifier(KEY_F), MavlinkSignatureVerifier(WRONG)
    unsigned = _forged_cmd(66)
    wrong_key = bad.sign_frame(_forged_cmd(255), link_id=1)
    valid = good.sign_frame(_forged_cmd(255), link_id=1)
    gcs.feed(unsigned, wrong_key, valid, valid)                      # the last one is a byte-identical replay
    b.pump_once()
    clock.t += 2.0
    b.pump_once()
    assert fc.sent == [unsigned, wrong_key, valid, valid]            # nothing dropped, nothing rewritten: the bridge only reports
    st = b.status()
    assert st["signing_observed"] == {"unsigned": 1, "bad_signature": 1, "replay": 1}
    assert st["frames"]["dropped_up"] == 0
    tx = texts(gcs)
    assert any(t.startswith("AEGIS: unsigned") and "sys66" in t for t in tx), tx
    assert any(t.startswith("AEGIS: bad-signature") for t in tx), tx
    assert any(t.startswith("AEGIS: replay") for t in tx), tx
    assert not any("blocked" in t for t in tx)


def test_active_ips_still_blocks_and_does_not_double_report():
    b, fc, gcs, clock = make_bridge(mode="active-ips", secret_key=KEY_F)
    gcs.feed(_forged_cmd(66))
    b.pump_once()
    assert fc.sent == [] and b.status()["signing_observed"] == {"unsigned": 0, "bad_signature": 0, "replay": 0}
