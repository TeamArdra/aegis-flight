"""Minimal pure-Python ``sd_notify`` systemd watchdog client.

Zero external dependencies (uses stdlib ``AF_UNIX`` datagram sockets). Safely
becomes a no-op when ``NOTIFY_SOCKET`` is unset (e.g. interactive runs, macOS,
or unit tests without a socket). Supports Linux abstract sockets (``@...``).
"""

from __future__ import annotations

import os
import socket


class SystemdNotifier:
    """Send lifecycle and watchdog datagrams to systemd's ``NOTIFY_SOCKET``."""

    def __init__(self, socket_path: str | None = None) -> None:
        raw = socket_path if socket_path is not None else os.environ.get("NOTIFY_SOCKET")
        self._socket_path: str | None = (raw.strip() or None) if isinstance(raw, str) else None

    @property
    def enabled(self) -> bool:
        return self._socket_path is not None

    def _target_address(self) -> bytes | str | None:
        if not self._socket_path:
            return None
        if self._socket_path.startswith("@"):
            return b"\x00" + self._socket_path[1:].encode("utf-8")
        return self._socket_path

    def notify(self, state: str) -> bool:
        """Send one ``sd_notify`` payload string (e.g. ``'WATCHDOG=1'``)."""
        addr = self._target_address()
        if addr is None:
            return False
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
                sock.settimeout(0.5)
                sock.sendto(state.encode("utf-8"), addr)
            return True
        except OSError:
            return False

    def ready(self, status: str | None = None) -> bool:
        msg = "READY=1" if not status else f"READY=1\nSTATUS={status}"
        return self.notify(msg)

    def watchdog(self, status: str | None = None) -> bool:
        msg = "WATCHDOG=1" if not status else f"WATCHDOG=1\nSTATUS={status}"
        return self.notify(msg)

    def status(self, text: str) -> bool:
        return self.notify(f"STATUS={text}")

    def stopping(self, status: str | None = None) -> bool:
        msg = "STOPPING=1" if not status else f"STOPPING=1\nSTATUS={status}"
        return self.notify(msg)
