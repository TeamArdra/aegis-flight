"""Opt-in hardware watchdog pulse for a normally-closed (NC) UART bypass relay.

Wiring concept (props-off bench, not yet validated on hardware): a relay that is
*de-energised* routes the FC<->GCS UART straight through (transparent bypass).
The companion keeps the relay energised only while it toggles a pin at a steady
rate; an external retriggerable monostable / RC detector converts "no edge for
> ``timeout``" into relay release. If AegisFlight is killed, hangs or loses
power, the pulses stop and the link falls back to pass-through.

This module only produces the pulse. It is disabled by default, needs no extra
dependencies, and writes to any path (a Linux sysfs GPIO ``value`` file, a
``/dev/gpiomem``-style shim, or a regular file in tests).

SIM/unit-test evidence only: the < 10 ms release time is a property of the
external detector plus ``period_s``; software guarantees a pulse at least every
``period_s`` while healthy and a de-asserted (low) pin on clean stop.
"""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable
from typing import Any

ENV_PATH = "AEGIS_HW_WATCHDOG_PATH"
ENV_PERIOD_MS = "AEGIS_HW_WATCHDOG_PERIOD_MS"
DEFAULT_PERIOD_S = 0.004  # 4 ms toggle => detector with 8-9 ms hold meets < 10 ms
MAX_PERIOD_S = 0.005  # refuse periods that cannot honour the < 10 ms contract


class HardwareWatchdog:
    """Toggle ``path`` between ``1`` and ``0`` every ``period_s`` seconds.

    ``health_check`` (optional) is evaluated before each pulse; a falsy result
    or exception suppresses the pulse so the relay drops to bypass.
    """

    def __init__(
        self,
        path: str | None = None,
        *,
        period_s: float = DEFAULT_PERIOD_S,
        health_check: Callable[[], bool] | None = None,
        writer: Callable[[str, str], None] | None = None,
    ) -> None:
        if not path:
            path = None
        if not 0 < period_s <= MAX_PERIOD_S:
            raise ValueError(f"period_s must be in (0, {MAX_PERIOD_S}] to meet the <10 ms release contract")
        self._path = path
        self._period_s = float(period_s)
        self._health_check = health_check
        self._writer = writer or self._default_write
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._level = 0
        self.pulses = 0
        self.suppressed = 0
        self.write_errors = 0

    @classmethod
    def from_env(cls, health_check: Callable[[], bool] | None = None, env: dict[str, str] | None = None) -> HardwareWatchdog:
        """Disabled unless ``AEGIS_HW_WATCHDOG_PATH`` is set."""
        e = os.environ if env is None else env
        path = (e.get(ENV_PATH) or "").strip() or None
        kwargs: dict[str, Any] = {}
        raw = (e.get(ENV_PERIOD_MS) or "").strip()
        if raw:
            kwargs["period_s"] = float(raw) / 1000.0
        return cls(path, health_check=health_check, **kwargs)

    @property
    def enabled(self) -> bool:
        return self._path is not None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @staticmethod
    def _default_write(path: str, value: str) -> None:
        with open(path, "w", encoding="ascii") as fh:
            fh.write(value)

    def _set(self, level: int) -> bool:
        assert self._path is not None
        try:
            self._writer(self._path, str(level))
            self._level = level
            return True
        except OSError:
            self.write_errors += 1
            return False

    def _healthy(self) -> bool:
        if self._health_check is None:
            return True
        try:
            return bool(self._health_check())
        except Exception:  # noqa: BLE001 - unhealthy by definition
            return False

    def _loop(self) -> None:
        next_t = time.monotonic()
        while not self._stop.is_set():
            if self._healthy():
                if self._set(1 - self._level):
                    self.pulses += 1
            else:
                self.suppressed += 1
                self._set(0)
            next_t += self._period_s
            delay = next_t - time.monotonic()
            if delay > 0:
                self._stop.wait(delay)
            else:
                next_t = time.monotonic()

    def start(self) -> bool:
        """Start pulsing. Returns False (no-op) when disabled or already running."""
        if not self.enabled or self.running:
            return False
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="hw-watchdog", daemon=True)
        self._thread.start()
        return True

    def stop(self) -> None:
        """Stop pulsing and leave the pin low (relay released -> bypass)."""
        self._stop.set()
        t = self._thread
        if t is not None:
            t.join(timeout=1.0)
        self._thread = None
        if self.enabled:
            self._set(0)
