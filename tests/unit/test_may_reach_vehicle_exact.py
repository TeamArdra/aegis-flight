"""Exact truth table for the receive-only boundary predicate ``may_reach_vehicle``.

True means "this port string may be wired to a physical flight controller", so AegisFlight must never transmit on
it. Only a non-empty string without a pyserial URL scheme qualifies; everything else (URL links, empty values,
non-strings) must come back exactly ``False`` (a bool, never a truthy/None surrogate).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aegisflight.sources.mavlink_serial import may_reach_vehicle


@pytest.mark.parametrize(
    "port",
    ["COM7", "com3", "/dev/ttyACM0", "/dev/tty.usbmodem14101", "/dev/pts/4", "\\\\.\\COM12", "COM7:", "a:/b", "x:", "//"],
)
def test_every_os_serial_device_name_may_reach_the_vehicle(port: str) -> None:
    assert may_reach_vehicle(port) is True


@pytest.mark.parametrize(
    "port",
    [
        "socket://127.0.0.1:5760", "spy:///dev/ttyACM0", "loop://", "rfc2217://host:2217", "a://", "://", "COM7://x",
        "/dev/ttyACM0://", "x://y://z", "hwgrep://0403", "SOCKET://127.0.0.1:1", " ://",
    ],
)
def test_url_style_ports_never_count_as_a_vehicle_device(port: str) -> None:
    assert may_reach_vehicle(port) is False


@pytest.mark.parametrize("port", ["", None, 0, 1, 5760, b"COM7", b"socket://x", b"", 7.5, True, False, [], ["COM7"],
                                  ("COM7",), {}, {"port": "COM7"}, object(), Path("/dev/ttyACM0"), bytearray(b"COM7")])
def test_empty_and_non_string_values_are_not_a_vehicle_device(port: object) -> None:
    assert may_reach_vehicle(port) is False


def test_a_str_subclass_is_still_a_string() -> None:
    class Name(str):
        pass

    assert may_reach_vehicle(Name("COM7")) is True
    assert may_reach_vehicle(Name("socket://h:1")) is False
    assert may_reach_vehicle(Name("")) is False
