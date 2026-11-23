"""Acceptance: Active IPS blocking, armed-state lock and the local safe-hold override."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pymavlink.dialects.v20 import common as mav2
from pytest_bdd import given, parsers, scenarios, then, when

from aegisflight.hal.inline_ips import InlineIpsBridge
from aegisflight.mitigation.inline_policy import InlinePolicy
from aegisflight.mitigation.sanitizer import FrameSanitizer
from aegisflight.proxy.hooks import FrameContext
from aegisflight.proxy.transport import split_frames

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "unit"))
import test_vehicle_uplink_filter as helpers  # noqa: E402

scenarios("features/active_ips.feature")


@pytest.fixture
def ctx() -> dict:
    return {}


def _ctx_of(raw: bytes, direction: str = "up", recv_ns: int = 1_000_000_000) -> FrameContext:
    fr = split_frames(raw)[0][0]
    return FrameContext(direction, fr.raw, recv_ns, fr.sysid, fr.compid, fr.seq, fr.msgid, fr.signed)  # type: ignore[arg-type]


def _frame(fn, *args, sysid: int = 255) -> bytes:
    m = mav2.MAVLink(None, srcSystem=sysid, srcComponent=190)
    return bytes(fn(*args).pack(m))


def _policy(ctx: dict, semantic: bool) -> None:
    pol = InlinePolicy(FrameSanitizer(), trusted_sysids=(255,), vehicle_sysids=(1,), semantic_firewall_enabled=semantic)
    pol.set_enforce(True)
    ctx["policy"] = pol


@given("an Active IPS policy that trusts only the real ground station")
def trusted_only(ctx: dict) -> None:
    _policy(ctx, semantic=False)


@given("an Active IPS policy with the semantic firewall enabled")
def with_semantic(ctx: dict) -> None:
    _policy(ctx, semantic=True)


def _heartbeat(ctx: dict, armed: bool) -> None:
    base = 0x01 | (0x80 if armed else 0)
    m = mav2.MAVLink(None, srcSystem=1, srcComponent=1)
    raw = bytes(mav2.MAVLink_heartbeat_message(2, 3, base, 0, 4, 3).pack(m))
    ctx["policy"].down(_ctx_of(raw, "down"))
    assert ctx["policy"].armed is armed


@given("the vehicle reports that it is armed")
def armed(ctx: dict) -> None:
    _heartbeat(ctx, True)


@given("the vehicle reports that it is disarmed")
def disarmed(ctx: dict) -> None:
    _heartbeat(ctx, False)


@when("an untrusted source sends a mode change")
def untrusted(ctx: dict) -> None:
    ctx["out"] = ctx["policy"].up(_ctx_of(helpers.cmd(66)))


@when(parsers.parse('the ground station writes the protected parameter "{name}"'))
def write_param(ctx: dict, name: str) -> None:
    raw = _frame(mav2.MAVLink_param_set_message, 1, 1, name.encode(), 1.0, 9)
    ctx["raw"] = raw
    ctx["out"] = ctx["policy"].up(_ctx_of(raw, recv_ns=2_000_000_000))


@when("the ground station clears the geofence")
def clear_fence(ctx: dict) -> None:
    ctx["out"] = ctx["policy"].up(_ctx_of(_frame(mav2.MAVLink_mission_clear_all_message, 1, 1, 1), recv_ns=2_000_000_000))


@then("the frame is dropped")
def dropped(ctx: dict) -> None:
    assert ctx["out"] == []


@then("the frame is forwarded")
def forwarded(ctx: dict) -> None:
    assert ctx["out"] == [ctx["raw"]]


@then("the drop is counted as untrusted control")
def counted(ctx: dict) -> None:
    assert ctx["policy"].dropped_untrusted_control == 1


@then("the semantic firewall counts one dropped parameter write")
def semantic_count(ctx: dict) -> None:
    assert ctx["policy"].semantic_stats()["dropped_param"] == 1


@given("a signing-aware vehicle filter that has engaged")
def engaged_filter(ctx: dict, tmp_path: Path) -> None:
    flag = tmp_path / "filter_off"
    fc, gcs = helpers.SerialLink(), helpers.FakeLink()
    bridge = InlineIpsBridge(fc, gcs, mode="passive", secret_key=helpers.KEY, vehicle_filter=True,
                             filter_override_file=str(flag))
    bridge._override_interval_s = 0.0
    helpers.engage(bridge, gcs)
    ctx.update(flag=flag, fc=fc, gcs=gcs, bridge=bridge, forged=helpers.cmd(66))


@when("the operator creates the local override file")
def create_flag(ctx: dict) -> None:
    ctx["flag"].write_text("off", encoding="ascii")


@given("the operator created the local override file and then removed it")
def create_and_remove(ctx: dict) -> None:
    ctx["flag"].write_text("off", encoding="ascii")
    ctx["gcs"].feed(ctx["forged"])
    ctx["bridge"].pump_once()
    ctx["flag"].unlink()


@when("a forged command arrives")
def forged_arrives(ctx: dict) -> None:
    ctx["fc"].sent.clear()
    ctx["gcs"].feed(ctx["forged"])
    ctx["bridge"].pump_once()


@then("the forged command is forwarded")
def forged_forwarded(ctx: dict) -> None:
    assert ctx["fc"].sent == [ctx["forged"]]


@then(parsers.parse('the filter state is "{state}"'))
def filter_state(ctx: dict, state: str) -> None:
    assert ctx["bridge"].policy.filter_state == state
