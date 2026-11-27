"""IPS on a physical serial FC is an explicit, keyed, construction-time opt-in; the IDS postures never write to the FC."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from aegisflight.hal.inline_ips import InlineIpsBridge

sys.path.insert(0, str(Path(__file__).parent))
import test_vehicle_uplink_filter as helpers  # noqa: E402  (synthetic frames and fake links)


def _serial_fc(port: str = "/dev/ttyAMA0"):
    fc = helpers.SerialLink()
    fc.port = port
    return fc


def test_active_ips_on_serial_is_refused_by_default():
    with pytest.raises(ValueError, match="receive-only"):
        InlineIpsBridge(_serial_fc(), helpers.FakeLink(), mode="active-ips", secret_key=helpers.KEY)


def test_active_ips_on_serial_needs_the_explicit_opt_in_and_a_key():
    with pytest.raises(ValueError, match="signing key"):
        InlineIpsBridge(_serial_fc(), helpers.FakeLink(), mode="active-ips", allow_active_on_hardware=True)
    br = InlineIpsBridge(_serial_fc(), helpers.FakeLink(), mode="active-ips", secret_key=helpers.KEY,
                         allow_active_on_hardware=True)
    assert br._ips_may_write_fc() is True


@pytest.mark.parametrize("mode", ["passive", "advisory"])
def test_ids_postures_never_pass_the_ips_write_gate_even_with_the_opt_in(mode):
    br = InlineIpsBridge(_serial_fc(), helpers.FakeLink(), mode=mode, secret_key=helpers.KEY,
                         allow_active_on_hardware=True)
    assert br._ips_may_write_fc() is False


def test_posture_cannot_be_raised_to_ips_at_run_time_without_the_opt_in():
    br = InlineIpsBridge(_serial_fc(), helpers.FakeLink(), mode="advisory", secret_key=helpers.KEY)
    with pytest.raises(ValueError, match="receive-only"):
        br.set_mode("active-ips")
    assert br.controller.mode.value == "advisory"
    assert br._ips_may_write_fc() is False


def test_opted_in_bridge_can_drop_back_to_ids_and_the_gate_closes():
    br = InlineIpsBridge(_serial_fc(), helpers.FakeLink(), mode="active-ips", secret_key=helpers.KEY,
                         allow_active_on_hardware=True)
    br.set_mode("advisory")
    assert br._ips_may_write_fc() is False
