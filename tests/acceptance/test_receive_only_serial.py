"""Acceptance: a serial vehicle link is receive-only (docs/SERIAL_TRANSPORT.md)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from aegisflight.hal.inline_ips import InlineIpsBridge
from aegisflight.sources.mavlink_serial import _check_port, may_reach_vehicle

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "unit"))
import test_vehicle_uplink_filter as helpers  # noqa: E402  (reuse the synthetic frames and fake links)

scenarios("features/receive_only_serial.feature")


@pytest.fixture
def ctx() -> dict:
    return {}


@when(parsers.parse('the bridge classifies the port "{port}"'))
def classify(ctx: dict, port: str) -> None:
    ctx["result"] = may_reach_vehicle(port)


@when("the bridge classifies an empty port name")
def classify_empty(ctx: dict) -> None:
    ctx["result"] = may_reach_vehicle("")


@when("the bridge classifies a transport that has no port")
def classify_none(ctx: dict) -> None:
    ctx["result"] = may_reach_vehicle(None)


@then("the port may reach a vehicle")
def may_reach(ctx: dict) -> None:
    assert ctx["result"] is True


@then("the port may not reach a vehicle")
def may_not_reach(ctx: dict) -> None:
    assert ctx["result"] is False


@given(parsers.parse('a passive inline bridge whose vehicle link is the serial device "{port}"'))
def serial_bridge(ctx: dict, port: str) -> None:
    fc, gcs = helpers.SerialLink(), helpers.FakeLink()
    fc.port = port
    ctx.update(fc=fc, gcs=gcs, bridge=InlineIpsBridge(fc, gcs, mode="passive", secret_key=helpers.KEY))


@when(parsers.parse('an Active IPS bridge is built on the serial device "{port}"'))
def build_active(ctx: dict, port: str) -> None:
    fc = helpers.SerialLink()
    fc.port = port
    try:
        InlineIpsBridge(fc, helpers.FakeLink(), mode="active-ips", secret_key=helpers.KEY)
        ctx["error"] = None
    except ValueError as exc:
        ctx["error"] = exc


@then("building the bridge is refused")
def build_refused(ctx: dict) -> None:
    assert ctx["error"] is not None and "receive-only" in str(ctx["error"])


@when("the vehicle streams telemetry and the ground station stays silent")
def telemetry_only(ctx: dict) -> None:
    for _ in range(5):
        ctx["fc"].feed(helpers.heartbeat(), helpers.gpi())
        ctx["bridge"].pump_once()
    assert ctx["gcs"].sent  # the telemetry did reach the ground station


@then("nothing is written to the vehicle link")
def nothing_sent(ctx: dict) -> None:
    assert ctx["fc"].sent == []


@when(parsers.parse('a serial source is opened on "{url}" without allow_url'))
def open_url(ctx: dict, url: str) -> None:
    try:
        _check_port(url, allow_url=False)
        ctx["error"] = None
    except ValueError as exc:
        ctx["error"] = exc


@then("opening is refused")
def refused(ctx: dict) -> None:
    assert ctx["error"] is not None
