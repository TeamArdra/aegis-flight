"""Property-based / fuzz tests of the inline bridge and the frame splitter (SYNTHETIC input, in-memory links).

Invariants fuzzed:
  * the splitter and the bridge never raise on arbitrary bytes, in any posture;
  * PASSIVE / ADVISORY never write anything to the FC except whole, byte-identical forwarded uplink frames, never drop and never
    send a counter-frame, whatever the input;
  * valid frames pass through PASSIVE / ADVISORY byte-identically in order, in both directions;
  * on a serial FC port no sequence of posture changes reaches an IPS write without the explicit hardware opt-in.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pymavlink.dialects.v20 import common as mav2

from aegisflight.hal.inline_ips import InlineIpsBridge
from aegisflight.proxy.transport import split_frames

sys.path.insert(0, str(Path(__file__).parent))
import test_vehicle_uplink_filter as helpers  # noqa: E402

SET = settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])


def _enc(sysid: int, comp: int = 1) -> mav2.MAVLink:
    m = mav2.MAVLink(None, srcSystem=sysid, srcComponent=comp)
    m.robust_parsing = True
    return m


@st.composite
def valid_frame(draw):
    sysid = draw(st.integers(1, 255))
    m = _enc(sysid, draw(st.integers(0, 255)))
    kind = draw(st.sampled_from(["hb", "att", "gpi", "cmd", "param", "rc", "text"]))
    if kind == "hb":
        msg = m.heartbeat_encode(draw(st.integers(0, 20)), draw(st.integers(0, 20)), draw(st.integers(0, 255)), draw(st.integers(0, 2**31)), 4, 3)
    elif kind == "att":
        msg = m.attitude_encode(draw(st.integers(0, 2**31)), *[draw(st.one_of(st.floats(-4, 4), st.just(float('nan')), st.just(float('inf')))) for _ in range(6)])
    elif kind == "gpi":
        msg = m.global_position_int_encode(draw(st.integers(0, 2**31)), draw(st.integers(-900000000, 900000000)),
                                           draw(st.integers(-1800000000, 1800000000)), draw(st.integers(-10**6, 10**6)),
                                           draw(st.integers(-10**6, 10**6)), 0, 0, 0, 0)
    elif kind == "cmd":
        msg = m.command_long_encode(1, 1, draw(st.sampled_from([400, 176, 20, 21, 22, 246, 511, 31010])), 0,
                                    *[draw(st.floats(-1e6, 1e6)) for _ in range(7)])
    elif kind == "param":
        msg = m.param_set_encode(1, 1, draw(st.binary(min_size=1, max_size=16)), draw(st.floats(-1e6, 1e6)), 9)
    elif kind == "rc":
        msg = m.rc_channels_override_encode(1, 1, *[draw(st.integers(0, 2200)) for _ in range(8)])
    else:
        msg = m.statustext_encode(draw(st.integers(0, 7)), draw(st.binary(min_size=0, max_size=50)))
    return bytes(msg.pack(m))


def _mut(raw: bytes, data) -> bytes:
    op = data.draw(st.sampled_from(["flip", "trunc", "dup", "pad", "none"]))
    b = bytearray(raw)
    if op == "flip" and b:
        for _ in range(data.draw(st.integers(1, 4))):
            b[data.draw(st.integers(0, len(b) - 1))] ^= 1 << data.draw(st.integers(0, 7))
    elif op == "trunc" and len(b) > 1:
        b = b[:data.draw(st.integers(1, len(b) - 1))]
    elif op == "dup":
        b = b + b
    elif op == "pad":
        b = bytes(data.draw(st.binary(max_size=8))) + b
    return bytes(b)


def _bridge(mode: str, serial_fc: bool = True):
    fc = helpers.SerialLink() if serial_fc else helpers.FakeLink()
    gcs = helpers.FakeLink()
    return InlineIpsBridge(fc, gcs, mode=mode), fc, gcs


@SET
@given(st.binary(max_size=2000))
def test_splitter_never_raises_and_lengths_are_consistent(data):
    frames, bad = split_frames(data)
    assert bad >= 0
    for f in frames:
        assert f.raw in data
        assert f.raw[0] in (0xFD, 0xFE)


@pytest.mark.parametrize("mode", ["passive", "advisory", "active-ips"])
@SET
@given(st.lists(st.binary(max_size=300), max_size=12), st.lists(st.binary(max_size=300), max_size=12))
def test_bridge_never_raises_on_arbitrary_bytes(mode, down, up):
    if mode == "active-ips":
        fc, gcs = helpers.FakeLink(), helpers.FakeLink()  # socket-like FC: IPS permitted
        b = InlineIpsBridge(fc, gcs, mode=mode)
    else:
        b, fc, gcs = _bridge(mode)
    fc.feed(*down)
    gcs.feed(*up)
    b.pump_once()
    assert b.policy.hook_errors == 0


@pytest.mark.parametrize("mode", ["passive", "advisory"])
@SET
@given(st.data())
def test_ids_postures_forward_valid_frames_identically_and_never_write_beyond_forwarding(mode, data):
    down = data.draw(st.lists(valid_frame(), max_size=15))
    up = data.draw(st.lists(valid_frame(), max_size=15))
    b, fc, gcs = _bridge(mode)
    fc.feed(*down)
    gcs.feed(*up)
    b.pump_once()
    # the bridge may drop only the management control frames (compid 191 COMMAND_LONG USER_1) from the uplink; none generated here
    assert gcs.sent == down
    assert fc.sent == up
    assert b.dropped_up == 0 and b.dropped_down == 0 and b.counter_frames_sent == 0


@pytest.mark.parametrize("mode", ["passive", "advisory"])
@SET
@given(st.data())
def test_ids_postures_never_write_to_fc_anything_but_whole_forwarded_frames_even_when_input_is_mutated(mode, data):
    raws = data.draw(st.lists(valid_frame(), min_size=1, max_size=12))
    mutated = [_mut(r, data) for r in raws]
    b, fc, gcs = _bridge(mode)
    gcs.feed(*mutated)
    fc.feed(*[_mut(r, data) for r in raws])
    b.pump_once()
    assert b.counter_frames_sent == 0
    for sent in fc.sent:
        frames, bad = split_frames(sent)
        assert bad == 0 and len(frames) >= 1                   # only whole frames reach the FC
    assert sum(len(split_frames(s)[0]) for s in fc.sent) <= sum(len(split_frames(m)[0]) for m in mutated)


@SET
@given(st.lists(st.sampled_from(["passive", "advisory", "active-ips"]), min_size=1, max_size=12))
def test_posture_sequences_cannot_open_the_ips_gate_on_a_serial_fc_without_the_opt_in(seq):
    b, fc, gcs = _bridge("advisory")
    for m in seq:
        try:
            b.set_mode(m)
        except ValueError:
            assert m == "active-ips"
        assert b._ips_may_write_fc() is False
        assert b.controller.mode.value != "active-ips"


@SET
@given(st.lists(st.sampled_from(["passive", "advisory", "active-ips"]), min_size=1, max_size=12))
def test_with_the_opt_in_only_active_ips_opens_the_gate(seq):
    fc, gcs = helpers.SerialLink(), helpers.FakeLink()
    b = InlineIpsBridge(fc, gcs, mode="advisory", secret_key=helpers.KEY, allow_active_on_hardware=True)
    for m in seq:
        b.set_mode(m)
        assert b._ips_may_write_fc() is (m == "active-ips")
