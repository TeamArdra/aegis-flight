"""The passive serial probe must not assert DTR/RTS when it opens a port. A fake pyserial stands in; nothing opens a port.

It extends the receive-only guarantees in tests/unit/test_side_tap_and_auto_port.py, which use ``serial_opener`` fakes
and therefore never exercise ``_open_passive_serial`` itself.
"""

from __future__ import annotations

import serial

from aegisflight.hal import auto_port


class _FakeSerial:
    """Records the line state at the moment ``open()`` is called (pyserial applies DTR/RTS inside open())."""

    instances: list[_FakeSerial] = []

    def __init__(self, *args: object, **kwargs: object) -> None:
        # pyserial's own defaults: both lines asserted unless the caller changes them before open()
        self.dtr = True
        self.rts = True
        self.rtscts = False
        self.dsrdtr = False
        self.is_open = False
        self.state_at_open: tuple[bool, bool] | None = None
        _FakeSerial.instances.append(self)
        if args or kwargs.get("port"):  # the old call style opened the port inside the constructor
            self.open()

    def open(self) -> None:
        self.state_at_open = (self.dtr, self.rts)
        self.is_open = True


def test_passive_open_does_not_assert_dtr_or_rts(monkeypatch) -> None:
    _FakeSerial.instances.clear()
    monkeypatch.setattr(serial, "Serial", _FakeSerial)

    ser = auto_port._open_passive_serial("/dev/ttyACM0", 115200)

    assert ser.is_open
    assert ser.state_at_open == (False, False)  # DTR and RTS low when the port was opened
    assert (ser.rtscts, ser.dsrdtr) == (False, False)
    assert ser.port == "/dev/ttyACM0" and ser.baudrate == 115200
    assert len(_FakeSerial.instances) == 1


def test_fake_reproduces_the_old_constructor_behaviour(monkeypatch) -> None:
    """Control: constructing with the port (the previous code) opens with pyserial's default DTR/RTS = True."""
    _FakeSerial.instances.clear()
    monkeypatch.setattr(serial, "Serial", _FakeSerial)
    old = serial.Serial("/dev/ttyACM0", baudrate=115200, rtscts=False, xonxoff=False, dsrdtr=False)
    assert old.state_at_open == (True, True)
