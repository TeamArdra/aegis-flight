"""Property-based fuzzing of the code that parses or judges hostile input (SIM, no hardware).

Every property runs at least 500 generated examples (``EXAMPLES``). MAVLink, serial and file content is hostile by
design (AGENTS.md section 5), so these tests assert that

* no parser, sanitizer, extractor or detector raises on hostile bytes or NaN / Inf / out-of-range telemetry,
* detector scores and fused threat scores stay finite and inside [0, 1],
* ``SemanticFirewall`` and ``InlinePolicy`` never forward a command they are specified to block, whatever the bytes
  or header fields are, and never fall into their fail-open ``except`` path (``hook_errors`` stays 0),
* ``may_reach_vehicle`` keeps its exact contract, so a serial device is never treated as a safe link,
* the event hash chain is intact for any sequence of events and breaks for any single-field tamper.

Hypothesis' example database is disabled so a run leaves nothing in the working tree.
"""

from __future__ import annotations

import dataclasses
import json
import math
import struct
from types import SimpleNamespace

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pymavlink.dialects.v20 import ardupilotmega as apm
from pymavlink.dialects.v20 import common as mav2

from aegisflight.config import load_config
from aegisflight.core.enums import AttackType, Severity
from aegisflight.core.types import MessageEnvelope, ThreatAssessment
from aegisflight.features.extractor import FeatureFrame
from aegisflight.hal.inline_ips import InlineIpsBridge
from aegisflight.logging.store import EventStore
from aegisflight.mitigation.inline_policy import (
    CONTROL_MSGIDS,
    SENSITIVE_COMMANDS,
    InlinePolicy,
)
from aegisflight.mitigation.sanitizer import FrameSanitizer
from aegisflight.mitigation.semantic_firewall import (
    DEFAULT_PROTECTED_PARAM_PREFIXES,
    FenceChangeEvent,
    ParamWriteEvent,
    SemanticFirewall,
    extract_mission_fence_raw,
    extract_param_set_raw,
)
from aegisflight.pipeline import IDSPipeline
from aegisflight.proxy.hooks import FrameContext
from aegisflight.proxy.transport import split_frames
from aegisflight.sources.mavlink_live import LiveStats, MavlinkFrameParser
from aegisflight.sources.mavlink_serial import ALLOWED_URL_SCHEMES, _check_port, may_reach_vehicle
from aegisflight.sources.stream import TelemetryTick

EXAMPLES = 500
FUZZ = settings(
    max_examples=EXAMPLES,
    deadline=None,
    database=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large, HealthCheck.filter_too_much],
)

# --------------------------------------------------------------------------- #
# strategies
# --------------------------------------------------------------------------- #

hostile_floats = st.one_of(
    st.floats(allow_nan=True, allow_infinity=True, width=64),
    st.sampled_from([0.0, -0.0, 1e308, -1e308, 5e-324, 3.4e38, -3.4e38, math.nan, math.inf, -math.inf]),
)
hostile_ints = st.one_of(
    st.integers(-(2**40), 2**40),
    st.sampled_from([0, -1, 2**31 - 1, -(2**31), 2**32 - 1, 2**16 - 1, 255, 256]),
)
hostile_numbers = st.one_of(hostile_floats, hostile_ints)

_V2_HEADER = struct.Struct("<BBBBBBBBBB")


def v2_frame(msgid: int, payload: bytes, *, sysid: int, compid: int, seq: int, signature: bytes | None) -> bytes:
    """A hand-built MAVLink 2 frame (CRC bytes random: the policy layer never checks them)."""
    incompat = 1 if signature is not None else 0
    head = _V2_HEADER.pack(0xFD, len(payload), incompat, 0, seq, sysid, compid, msgid & 0xFF, (msgid >> 8) & 0xFF, (msgid >> 16) & 0xFF)
    return head + payload + b"\xaa\xbb" + (signature or b"")


@st.composite
def v2_frames(draw, msgids=None, signed: bool | None = None) -> bytes:
    msgid = draw(st.sampled_from(sorted(msgids)) if msgids is not None else st.integers(0, 2**24 - 1))
    payload = draw(st.binary(min_size=0, max_size=255))
    is_signed = draw(st.booleans()) if signed is None else signed
    sig = draw(st.binary(min_size=13, max_size=13)) if is_signed else None
    return v2_frame(msgid, payload, sysid=draw(st.integers(0, 255)), compid=draw(st.integers(0, 255)),
                    seq=draw(st.integers(0, 255)), signature=sig)


def ctx_of(raw: bytes, direction: str = "up", recv_ns: int = 1_000_000_000) -> FrameContext | None:
    frames, _bad = split_frames(raw)
    if not frames:
        return None
    fr = frames[0]
    return FrameContext(direction=direction, raw=fr.raw, recv_ns=recv_ns, sysid=fr.sysid, compid=fr.compid,  # type: ignore[arg-type]
                        seq=fr.seq, msgid=fr.msgid, signed=fr.signed)


def command_long(sysid: int, command: int, params: tuple[float, ...], signature: bytes | None = None) -> bytes:
    m = mav2.MAVLink(None, srcSystem=sysid, srcComponent=190)
    m.robust_parsing = True
    raw = bytes(m.command_long_encode(1, 1, command, 0, *params).pack(m))
    if signature is None:
        return raw
    raw = bytearray(raw)
    raw[2] |= 1  # incompat flag: signed
    return bytes(raw) + signature


KEY = bytes(range(32))


class Clock:
    t = 100.0

    def __call__(self) -> float:
        return self.t


def armed_policy(*, signing: bool, trusted: tuple[int, ...] = (255,)) -> InlinePolicy:
    pol = InlinePolicy(FrameSanitizer(), trusted_sysids=trusted, vehicle_sysids=(1,), signing_key=KEY if signing else None,
                       provenance=False, clock=Clock(), semantic_firewall_enabled=True)
    pol.set_enforce(True)
    m = apm.MAVLink(None, srcSystem=1, srcComponent=1)
    hb = bytes(apm.MAVLink_heartbeat_message(2, 3, 0x81 | 0x80, 5, 4, 3).pack(m))
    c = ctx_of(hb, "down")
    assert c is not None
    pol.down(c)
    assert pol.armed is True
    return pol


# --------------------------------------------------------------------------- #
# receive-only serial boundary
# --------------------------------------------------------------------------- #


@FUZZ
@given(st.text())
def test_may_reach_vehicle_treats_every_non_url_string_as_a_vehicle(port: str) -> None:
    assert may_reach_vehicle(port) is (bool(port) and "://" not in port)


@FUZZ
@given(st.one_of(st.none(), st.integers(), st.floats(), st.binary(), st.lists(st.text())))
def test_may_reach_vehicle_is_false_for_non_string_ports(port: object) -> None:
    assert may_reach_vehicle(port) is False


@FUZZ
@given(st.text(min_size=1, max_size=40).filter(lambda s: "://" not in s and "\x00" not in s))
def test_active_ips_is_refused_on_every_serial_device_name(port: str) -> None:
    bridge = SimpleNamespace(fc=SimpleNamespace(port=port))
    with pytest.raises(ValueError, match="receive-only"):
        InlineIpsBridge._refuse_active_on_device(bridge, "active-ips")  # type: ignore[arg-type]


@FUZZ
@given(st.text(max_size=12).filter(lambda s: s.lower() not in ALLOWED_URL_SCHEMES), st.text(max_size=30), st.booleans())
def test_pyserial_urls_outside_the_allowlist_never_open(scheme: str, rest: str, allow_url: bool) -> None:
    port = f"{scheme}://{rest}"
    with pytest.raises(ValueError):
        _check_port(port, allow_url)


@FUZZ
@given(st.text(max_size=20))
def test_embedded_nul_or_empty_port_is_rejected(name: str) -> None:
    with pytest.raises(ValueError):
        _check_port(name + "\x00", True)
    with pytest.raises(ValueError):
        _check_port("", True)


# --------------------------------------------------------------------------- #
# frame decoding and sanitizing
# --------------------------------------------------------------------------- #


@FUZZ
@given(st.binary(max_size=600), st.floats(0.0, 1e6))
def test_frame_parser_never_raises_on_random_bytes(data: bytes, t: float) -> None:
    out = MavlinkFrameParser(LiveStats()).parse(data, t)
    assert isinstance(out, list) and all(isinstance(m, MessageEnvelope) for m in out)


@FUZZ
@given(st.lists(v2_frames(), min_size=1, max_size=6), st.binary(max_size=40))
def test_frame_parser_never_raises_on_hostile_v2_frames(frames: list[bytes], tail: bytes) -> None:
    out = MavlinkFrameParser(LiveStats(), secret_key=KEY).parse(b"".join(frames) + tail, 1.0)
    assert isinstance(out, list)


@FUZZ
@given(st.binary(max_size=800), st.integers(1, 64))
def test_split_frames_never_raises_and_only_returns_whole_frames(data: bytes, limit: int) -> None:
    frames, bad = split_frames(data, limit)
    assert bad >= 0 and len(frames) <= limit
    for fr in frames:
        assert fr.raw[0] in (0xFD, 0xFE) and len(fr.raw) >= 8 and fr.raw in data


@FUZZ
@given(
    raw=st.one_of(st.binary(max_size=120), v2_frames()),
    direction=st.sampled_from(["up", "down"]),
    sysid=st.integers(-5, 300),
    msgid=st.one_of(st.just(33), st.integers(-5, 2**25)),
    signed=st.booleans(),
    recv_ns=st.integers(-5, 2**62),
    active=st.booleans(),
    quarantined=st.sets(st.integers(0, 255), max_size=4),
    gps=st.booleans(),
    alt=st.booleans(),
    lat_off=hostile_floats,
    alt_bias=hostile_floats,
    rate_limit=st.booleans(),
)
def test_frame_sanitizer_never_raises_and_returns_bytes(raw, direction, sysid, msgid, signed, recv_ns, active, quarantined,
                                                        gps, alt, lat_off, alt_bias, rate_limit) -> None:
    san = FrameSanitizer()
    san.configure(active=active, quarantined_sysids=quarantined, sanitize_gps=gps, sanitize_alt=alt,
                  lat_offset_deg=lat_off, lon_offset_deg=lat_off, alt_bias_m=alt_bias, rate_limit_active=rate_limit)
    ctx = FrameContext(direction=direction, raw=raw, recv_ns=recv_ns, sysid=sysid, compid=1, seq=0, msgid=msgid, signed=signed)  # type: ignore[arg-type]
    out = san(ctx)
    assert isinstance(out, list) and all(isinstance(b, bytes) for b in out) and len(out) <= 1
    if active and sysid in quarantined:
        assert out == []  # a quarantined sender is dropped in both directions
    if not active:
        assert out == [raw]


@FUZZ
@given(
    lat=st.integers(-(2**31), 2**31 - 1), lon=st.integers(-(2**31), 2**31 - 1), alt=st.integers(-(2**31), 2**31 - 1),
    rel=st.integers(-(2**31), 2**31 - 1), vx=st.integers(-(2**15), 2**15 - 1),
    lat_off=st.floats(-90, 90), lon_off=st.floats(-180, 180), bias=st.floats(-1e4, 1e4),
)
def test_rewritten_position_frames_are_still_valid_mavlink(lat, lon, alt, rel, vx, lat_off, lon_off, bias) -> None:
    enc = mav2.MAVLink(None, srcSystem=1, srcComponent=1)
    raw = bytes(mav2.MAVLink_global_position_int_message(1000, lat, lon, alt, rel, vx, 0, 0, 0).pack(enc))
    san = FrameSanitizer()
    san.configure(active=True, sanitize_gps=True, sanitize_alt=True, lat_offset_deg=lat_off, lon_offset_deg=lon_off, alt_bias_m=bias)
    out = san.sanitize_frame(raw, "down", 1, 1, 33)
    assert out is not None
    if out != raw:  # a rewritten frame must still pass the CRC check of a strict decoder
        dec = mav2.MAVLink(None)
        dec.robust_parsing = False
        msg = dec.parse_buffer(out)
        assert msg and msg[0].get_type() == "GLOBAL_POSITION_INT"


# --------------------------------------------------------------------------- #
# extractor, detectors, fusion on NaN / Inf / out-of-range telemetry
# --------------------------------------------------------------------------- #

# field name -> "f" (pymavlink float: NaN / Inf / huge allowed) or "i" (integer field: out-of-range integers only; the
# wire decoder cannot produce NaN or a float for these)
_FIELDS = {
    "HEARTBEAT": {"type": "i", "autopilot": "i", "base_mode": "i", "custom_mode": "i", "system_status": "i"},
    "GLOBAL_POSITION_INT": dict.fromkeys(("lat", "lon", "alt", "relative_alt", "vx", "vy", "vz", "hdg"), "i"),
    "GPS_RAW_INT": dict.fromkeys(("fix_type", "satellites_visible", "lat", "lon", "alt", "eph", "epv", "vel", "cog"), "i"),
    "ATTITUDE": dict.fromkeys(("roll", "pitch", "yaw", "rollspeed", "pitchspeed", "yawspeed"), "f"),
    "VFR_HUD": {"airspeed": "f", "groundspeed": "f", "heading": "i", "throttle": "i", "alt": "f", "climb": "f"},
    "SYS_STATUS": dict.fromkeys(("voltage_battery", "current_battery", "battery_remaining", "drop_rate_comm"), "i"),
    "EKF_STATUS_REPORT": {"flags": "i", "velocity_variance": "f", "pos_horiz_variance": "f", "pos_vert_variance": "f", "compass_variance": "f"},
    "COMMAND_LONG": {"command": "i", "param1": "f", "param2": "f", "target_system": "i", "target_component": "i"},
    "SYSTEM_TIME": {"time_unix_usec": "i", "time_boot_ms": "i"},
    "BATTERY_STATUS": {"current_battery": "i", "battery_remaining": "i", "temperature": "i"},
    "OPTICAL_FLOW": {"flow_comp_m_x": "f", "flow_comp_m_y": "f", "quality": "i", "ground_distance": "f"},
    "STATUSTEXT": {"severity": "i"},
}
_IDS = {name: i for i, name in enumerate(_FIELDS)}


@st.composite
def envelopes(draw, t: float) -> MessageEnvelope:
    name = draw(st.sampled_from(sorted(_FIELDS)))
    fields = {f: draw(hostile_floats if kind == "f" else hostile_ints) for f, kind in _FIELDS[name].items()}
    if name == "BATTERY_STATUS":
        fields["voltages"] = draw(st.lists(hostile_ints, max_size=10))
    if name == "STATUSTEXT":
        fields["text"] = draw(st.text(max_size=60))
    return MessageEnvelope(t, draw(st.integers(0, 255)), draw(st.integers(0, 255)), _IDS[name] + 100, name,
                           draw(st.integers(0, 255)), draw(st.booleans()), draw(st.integers(0, 300)), fields)


def _finite01(x: float) -> bool:
    return isinstance(x, int | float) and math.isfinite(x) and -1e-9 <= x <= 1.0 + 1e-9


@FUZZ
@given(st.data(), st.sampled_from(["", "configs/universal_flight", "configs/ardupilot_copter", "configs/px4_sitl"]))
def test_pipeline_survives_hostile_telemetry_with_bounded_scores(data, profile: str) -> None:
    pipe = IDSPipeline(load_config(profile or None), model_path=None)
    n_ticks = data.draw(st.integers(2, 10))
    for k in range(n_ticks):
        t = k * 0.1 + data.draw(st.floats(-0.05, 0.05))
        msgs = [data.draw(envelopes(t)) for _ in range(data.draw(st.integers(0, 6)))]
        res = pipe.process_tick(TelemetryTick(tick=k, t=t, messages=msgs, sig_invalid=data.draw(st.integers(0, 5))))
        if res is not None:
            assert _finite01(res.threat_score) and _finite01(res.confidence)
            assert all(_finite01(v) for v in res.detector_scores.values()), res.detector_scores
            assert isinstance(res.is_alert, bool)


_FRAME_FLOATS = [f.name for f in dataclasses.fields(FeatureFrame) if f.name not in ("t", "snapshot") and f.type in ("float", "float | None")]


@FUZZ
@given(st.data())
def test_detectors_bound_their_scores_on_a_poisoned_feature_frame(data) -> None:
    pipe = IDSPipeline(load_config("configs/universal_flight"), model_path=None)
    for k in range(6):
        pipe.process_tick(TelemetryTick(tick=k, t=k * 0.1, messages=[
            MessageEnvelope(k * 0.1, 1, 1, 33, "GLOBAL_POSITION_INT", k, False, 36,
                            {"lat": 191334000, "lon": 729133000, "alt": 50_000, "relative_alt": 40_000, "vx": 100, "vy": 0, "vz": 0, "hdg": 0})]))
    base = pipe.last_frame
    assert base is not None
    names = data.draw(st.lists(st.sampled_from(_FRAME_FLOATS), min_size=1, max_size=8, unique=True))
    poisoned = dataclasses.replace(base, **{n: data.draw(hostile_floats) for n in names})
    for det in (pipe.protocol, pipe.physics, pipe.anomaly, pipe.integrity):
        r = det.process(poisoned)
        assert _finite01(r.score), (type(det).__name__, names, r.score)
        assert isinstance(r.triggered, bool)


# --------------------------------------------------------------------------- #
# semantic firewall
# --------------------------------------------------------------------------- #


def _variants(name: str, data) -> str:
    out = "".join(c.upper() if data.draw(st.booleans()) else c.lower() for c in name)
    return " " * data.draw(st.integers(0, 3)) + out + " " * data.draw(st.integers(0, 3))


@FUZZ
@given(st.data(), st.sampled_from(DEFAULT_PROTECTED_PARAM_PREFIXES), st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789", max_size=8),
       hostile_floats, st.integers(0, 255))
def test_armed_protected_param_write_is_always_blocked(data, prefix: str, suffix: str, value: float, ptype: int) -> None:
    fw = SemanticFirewall(enabled=True)
    name = _variants(prefix + suffix, data)
    v = fw.evaluate_param_write(ParamWriteEvent(1.0, 255, 190, name, value, ptype), armed=True)
    assert v.blocked is True and v.category == "param_tamper"


@FUZZ
@given(st.text(max_size=20), hostile_floats, st.sampled_from([True, False, None]), st.booleans(), st.sampled_from(["param_set", "param_value"]))
def test_param_evaluation_never_raises(name: str, value: float, armed, block_unknown: bool, kind: str) -> None:
    fw = SemanticFirewall(enabled=True, block_when_arm_unknown=block_unknown)
    v = fw.evaluate_param_write(ParamWriteEvent(0.0, 1, 1, name, value, 9, kind), armed=armed)
    assert isinstance(v.blocked, bool) and math.isfinite(v.severity_score)


@FUZZ
@given(st.sampled_from(["clear_fence", "upload_fence", "fence_item", "other"]), st.integers(-5, 300),
       st.one_of(st.none(), hostile_ints), st.one_of(st.none(), hostile_floats), st.one_of(st.none(), hostile_floats),
       st.one_of(st.none(), hostile_floats), st.sampled_from([True, False, None]),
       st.one_of(st.none(), st.tuples(hostile_floats, hostile_floats)))
def test_fence_evaluation_never_raises_and_always_blocks_armed_clear(action, mtype, cmd, radius, lat, lon, armed, home) -> None:
    fw = SemanticFirewall(enabled=True)
    ev = FenceChangeEvent(0.0, 255, 190, action, mtype, 1, cmd, radius, lat, lon)
    try:
        v = fw.evaluate_fence_change(ev, armed=armed, home_lat_lon=home)
    except (ValueError, OverflowError, TypeError) as exc:  # pragma: no cover - a failure here is a finding
        pytest.fail(f"fence evaluation raised {type(exc).__name__}: {exc}")
    assert isinstance(v.blocked, bool)
    if mtype == 1 and action in ("clear_fence", "upload_fence") and armed is True:
        assert v.blocked is True


@FUZZ
@given(st.binary(max_size=300), st.integers(0, 2**24 - 1))
def test_semantic_extractors_never_raise_on_hostile_bytes(raw: bytes, msgid: int) -> None:
    assert extract_param_set_raw(raw) is None or isinstance(extract_param_set_raw(raw), tuple)
    out = extract_mission_fence_raw(raw, msgid)
    assert out is None or isinstance(out, tuple)


# --------------------------------------------------------------------------- #
# inline policy: nothing blocked reaches the vehicle, and the fail-open path stays unused
# --------------------------------------------------------------------------- #


@FUZZ
@given(v2_frames(msgids=CONTROL_MSGIDS, signed=False))
def test_signed_policy_never_forwards_unsigned_control_frames(raw: bytes) -> None:
    pol = armed_policy(signing=True)
    ctx = ctx_of(raw)
    assert ctx is not None
    assert pol.up(ctx) == []
    assert pol.hook_errors == 0


@FUZZ
@given(v2_frames(msgids=CONTROL_MSGIDS, signed=True))
def test_signed_policy_never_forwards_control_frames_with_a_forged_signature(raw: bytes) -> None:
    pol = armed_policy(signing=True)
    ctx = ctx_of(raw)
    assert ctx is not None
    assert pol.up(ctx) == []  # random 13 signature bytes never verify
    assert pol.hook_errors == 0


f32_floats = st.floats(allow_nan=True, allow_infinity=True, width=32)  # what a MAVLink float field can carry


@FUZZ
@given(st.sampled_from(sorted(SENSITIVE_COMMANDS)), st.tuples(*[f32_floats] * 7), st.integers(0, 255), st.one_of(st.none(), st.binary(min_size=13, max_size=13)))
def test_signed_policy_never_forwards_sensitive_commands_without_a_valid_signature(command, params, sysid, sig) -> None:
    pol = armed_policy(signing=True)
    ctx = ctx_of(command_long(sysid, command, params, sig))
    assert ctx is not None
    assert pol.up(ctx) == []
    assert pol.hook_errors == 0


@FUZZ
@given(v2_frames(msgids=CONTROL_MSGIDS), st.integers(0, 255).filter(lambda s: s != 255))
def test_unsigned_policy_never_forwards_control_frames_from_untrusted_sysids(raw: bytes, sysid: int) -> None:
    pol = armed_policy(signing=False)
    frames, _ = split_frames(raw)
    assert frames
    fr = frames[0]
    ctx = FrameContext("up", fr.raw, 1_000_000_000, sysid, fr.compid, fr.seq, fr.msgid, fr.signed)
    assert pol.up(ctx) == []
    assert pol.hook_errors == 0


@FUZZ
@given(st.data(), st.sampled_from(DEFAULT_PROTECTED_PARAM_PREFIXES), st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789", max_size=8), f32_floats)
def test_armed_policy_drops_protected_param_writes_even_from_the_trusted_sysid(data, prefix, suffix, value) -> None:
    pol = armed_policy(signing=False)
    name = _variants(prefix + suffix, data).strip()[:16]
    m = apm.MAVLink(None, srcSystem=255, srcComponent=190)
    raw = bytes(apm.MAVLink_param_set_message(1, 1, name.encode("ascii", "ignore"), value, 9).pack(m))
    ctx = ctx_of(raw)
    assert ctx is not None
    assert pol.up(ctx) == []
    assert pol.semantic_stats()["dropped_param"] >= 1 and pol.hook_errors == 0


@FUZZ
@given(st.one_of(st.binary(max_size=300), v2_frames()), st.sampled_from(["up", "down"]), st.integers(-5, 300), st.integers(-5, 2**25),
       st.booleans(), st.booleans(), st.booleans())
def test_policy_never_falls_into_the_fail_open_path_on_arbitrary_input(raw, direction, sysid, msgid, signed, signing, enforce) -> None:
    pol = armed_policy(signing=signing)
    pol.set_enforce(enforce)
    ctx = FrameContext(direction, raw, 1_000_000_000, sysid, 1, 0, msgid, signed)  # type: ignore[arg-type]
    out = pol.up(ctx) if direction == "up" else pol.down(ctx)
    assert isinstance(out, list) and all(isinstance(b, bytes) for b in out)
    assert pol.hook_errors == 0


# --------------------------------------------------------------------------- #
# forensic hash chain
# --------------------------------------------------------------------------- #


@st.composite
def assessments(draw) -> ThreatAssessment:
    return ThreatAssessment(
        t=draw(st.floats(0, 1e6)), wall_time=draw(st.floats(1e9, 2e9)), threat=draw(st.booleans()),
        threat_score=draw(st.floats(0, 1)), severity=draw(st.sampled_from(list(Severity))),
        attack_type=draw(st.sampled_from(list(AttackType))), confidence=draw(st.floats(0, 1)),
        evidence=draw(st.lists(st.text(max_size=30), max_size=3)),
        detector_scores={"protocol_rule": draw(st.floats(0, 1))}, contributing_detectors=["protocol_rule"],
        telemetry={"lat": draw(st.floats(-90, 90)), "text": draw(st.text(max_size=20))}, is_alert=True)


@FUZZ
@given(st.lists(assessments(), min_size=1, max_size=8))
def test_hash_chain_verifies_for_any_event_sequence(events: list[ThreatAssessment]) -> None:
    store = EventStore(":memory:")
    store.start_run("r1")
    for ev in events:
        store.log_event(ev, "r1")
    cs = store.verify_chain("r1")
    assert cs.ok and cs.length == len(events)
    store.close()


_TAMPER = {
    "t": lambda v: (v or 0.0) + 1.0, "threat_score": lambda v: (v or 0.0) + 0.5, "confidence": lambda v: (v or 0.0) + 0.5,
    "attack_type": lambda v: v + "x", "severity": lambda v: v + "x", "evidence": lambda v: json.dumps(["forged"]) + str(v),
    "telemetry": lambda v: v[:-1] + ', "forged": 1}', "prev_hash": lambda v: "0" * 64 if v != "0" * 64 else "1" * 64,
    "hash": lambda v: "f" * 64 if v != "f" * 64 else "e" * 64, "wall_time": lambda v: (v or 0.0) + 1.0,
    "integrity_status": lambda v: v + "x", "latency_ms": lambda v: (v or 0.0) + 1.0,
}


@FUZZ
@given(st.lists(assessments(), min_size=2, max_size=8), st.data())
def test_hash_chain_detects_any_single_field_tamper_or_row_deletion(events, data) -> None:
    store = EventStore(":memory:")
    store.start_run("r1")
    for ev in events:
        store.log_event(ev, "r1")
    rows = store.conn.execute("SELECT * FROM events WHERE run_id='r1' ORDER BY id").fetchall()
    victim = data.draw(st.integers(0, len(rows) - 1))
    if data.draw(st.booleans()) and victim < len(rows) - 1:  # deleting a row that has a successor breaks the link
        store.conn.execute("DELETE FROM events WHERE id=?", (rows[victim]["id"],))
    else:
        col = data.draw(st.sampled_from(sorted(_TAMPER)))
        store.conn.execute(f"UPDATE events SET {col}=? WHERE id=?", (_TAMPER[col](rows[victim][col]), rows[victim]["id"]))
    store.conn.commit()
    assert store.verify_chain("r1").ok is False
    store.close()
