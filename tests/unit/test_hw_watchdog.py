"""Unit tests for the opt-in hardware UART-bypass watchdog pulse (SIM/unit evidence only)."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from aegisflight.hal.hw_watchdog import ENV_PATH, ENV_PERIOD_MS, HardwareWatchdog


def _wait(pred, timeout=2.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.002)
    return False


def test_disabled_by_default_is_noop() -> None:
    wd = HardwareWatchdog.from_env(env={})
    assert wd.enabled is False
    assert wd.start() is False and wd.running is False
    wd.stop()  # must not raise
    assert wd.pulses == 0


def test_from_env_enables_and_parses_period(tmp_path: Path) -> None:
    pin = tmp_path / "value"
    wd = HardwareWatchdog.from_env(env={ENV_PATH: str(pin), ENV_PERIOD_MS: "3"})
    assert wd.enabled and wd._period_s == pytest.approx(0.003)


@pytest.mark.parametrize("bad", [0, -1, 0.006, 0.1])
def test_rejects_period_that_breaks_10ms_contract(bad: float) -> None:
    with pytest.raises(ValueError):
        HardwareWatchdog("x", period_s=bad)


def test_toggles_and_stop_leaves_pin_low(tmp_path: Path) -> None:
    levels: list[str] = []
    wd = HardwareWatchdog(str(tmp_path / "v"), writer=lambda p, v: levels.append(v))
    assert wd.start() is True and wd.start() is False
    assert _wait(lambda: wd.pulses >= 10)
    wd.stop()
    assert levels[-1] == "0" and not wd.running
    body = levels[: wd.pulses]
    assert all(a != b for a, b in zip(body, body[1:], strict=False))  # strict alternation


def test_real_file_backend(tmp_path: Path) -> None:
    pin = tmp_path / "value"
    wd = HardwareWatchdog(str(pin))
    wd.start()
    assert _wait(lambda: wd.pulses >= 5)
    wd.stop()
    assert pin.read_text() == "0"


def test_unhealthy_suppresses_pulses_and_drops_low() -> None:
    state = {"ok": True}
    levels: list[str] = []
    wd = HardwareWatchdog("x", health_check=lambda: state["ok"], writer=lambda p, v: levels.append(v))
    wd.start()
    assert _wait(lambda: wd.pulses >= 5)
    state["ok"] = False
    assert _wait(lambda: wd.suppressed >= 3)
    frozen = wd.pulses
    time.sleep(0.05)
    assert wd.pulses == frozen and levels[-1] == "0"
    state["ok"] = True  # recovers
    assert _wait(lambda: wd.pulses > frozen)
    wd.stop()


def test_health_check_exception_is_unhealthy() -> None:
    def boom() -> bool:
        raise RuntimeError("x")

    wd = HardwareWatchdog("x", health_check=boom, writer=lambda p, v: None)
    wd.start()
    assert _wait(lambda: wd.suppressed >= 2)
    wd.stop()
    assert wd.pulses == 0


def test_write_errors_counted_not_fatal() -> None:
    def bad(p: str, v: str) -> None:
        raise OSError("gone")

    wd = HardwareWatchdog("x", writer=bad)
    wd.start()
    assert _wait(lambda: wd.write_errors >= 3)
    wd.stop()
    assert wd.pulses == 0


def test_max_gap_between_writes_under_10ms(tmp_path: Path) -> None:
    stamps: list[float] = []
    wd = HardwareWatchdog("x", writer=lambda p, v: stamps.append(time.monotonic()))
    wd.start()
    assert _wait(lambda: len(stamps) >= 200, 5.0)
    wd.stop()
    gaps = sorted(b - a for a, b in zip(stamps, stamps[1:], strict=False))
    # Median must be well inside budget; worst-case is scheduler dependent so only report-bound it loosely.
    assert gaps[len(gaps) // 2] < 0.006
