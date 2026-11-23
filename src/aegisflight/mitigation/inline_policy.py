"""Inline enforcement policy for a bump-in-the-wire IPS (Topology B).

``InlinePolicy`` supplies the two ``FrameHook`` callables (uplink GCS -> FC, downlink FC -> GCS) that an
inline bridge runs on every frame. It has two layers:

* **Static rules** (uplink, need no detector): when enforcement is on, hostile control traffic is dropped
  before the autopilot sees it, whatever the IDS has concluded so far:

  - a control message (``SET_MODE``, ``COMMAND_LONG``/``COMMAND_INT`` with a sensitive command, mission /
    parameter writes, position-target and RC-override messages) from a sysid that is not a trusted
    ground station is dropped;
  - a *non-forced* disarm in flight is dropped for everyone (the autopilot refuses it anyway); a forced
    disarm (magic 21196) is dropped unless it comes from a trusted ground station, so the pilot's
    emergency kill is never blocked;
  - a byte-identical sensitive command repeated within ``cadence_s`` is dropped (burst / replay of one frame).

  The pilot is never blocked: every frame from a trusted sysid passes (except the burst rule and the
  non-forced in-flight disarm, which the autopilot would not honour either).

* **Dynamic rules** (downlink, driven by the mitigation controller's ``FrameSanitizer``): quarantine of a
  rogue sysid, QoS shedding in a flood, GPS / altitude rewrite. They apply only while the controller keeps
  them fresh (``touch`` within ``dynamic_ttl_s``); a stalled analyser therefore degrades to transparent
  forwarding, never to a stale rewrite. Signed frames are never modified (a rewrite would break the MAC).

**MAVLink-2 signing (optional, ``signing_key``).** On an unsigned link a sysid is only a claim, so an attacker who
uses the real GCS sysid (255) is indistinguishable from the pilot (``gcs_replay``). With a 32-byte key the policy
instead requires every control message and sensitive command on the uplink to carry a valid signature with a strictly
increasing timestamp per (link, sysid, compid) stream: a forged sysid fails the MAC, a replayed frame fails the
timestamp, and an unsigned frame is dropped (``allow_unsigned_from_trusted`` softens only that last case, for a
rollout). A valid signature, not the sysid, is then what makes a sender trusted. Timestamp state can be persisted
(``state_path``) so a restart does not reopen a replay window; ``max_age_s`` additionally rejects frames older than
that on the bridge's clock (leave it off if the companion has no real-time clock). A signed frame cannot be altered
by a rewrite, and a frame the attacker merely *delays* keeps a valid signature until ``max_age_s`` lapses.

**Unsigned-link provenance (no key, ``provenance=True``).** Each (sysid, compid) uplink source gets a ``SeqProvenance``
sequence-counter tracker. A sensitive command / control message from a trusted sysid whose counter is known but
inconsistent is dropped while armed or in flight and only counted on the ground; a byte-identical repeat of a
forwarded sensitive frame is dropped as a replay (count-bounded memory of the last ``replay_memory`` frames, no time
limit, so a frame replayed after the 8-bit counter wraps is still caught). Two transmitters under one (sysid, compid)
(same seq, different payload within 2 s) mark the source ``contested`` for ``contested_hold_s``: an operator alarm is
queued (``take_alarms``) and, with ``contested_policy='drop-sensitive'``, sensitive/control frames from it are dropped
in flight (a forced disarm never). Best effort only: signing is the real fix (see docs/INLINE_IPS.md).
Any exception in a rule forwards the original frame (fail-open).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import struct
import threading
import time
import zlib
from collections import deque
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from ..mavlink.signing import MAVLINK_EPOCH_UNIX_S, MavlinkSignatureVerifier
from ..proxy.hooks import FrameContext
from .sanitizer import FrameSanitizer
from .semantic_firewall import (
    FenceChangeEvent,
    ParamWriteEvent,
    SemanticFirewall,
    extract_mission_fence_raw,
    extract_param_set_raw,
)

_MSG_HEARTBEAT = 0
_MSG_SET_MODE = 11
_MSG_PARAM_SET = 23
_MSG_GLOBAL_POSITION_INT = 33
_MSG_MISSION_ITEM = 39
_MSG_MISSION_COUNT = 44
_MSG_MISSION_CLEAR_ALL = 45
_MSG_RC_CHANNELS_OVERRIDE = 70
_MSG_MISSION_ITEM_INT = 73
_MSG_COMMAND_INT = 75
_MSG_COMMAND_LONG = 76
_MSG_SET_POSITION_TARGET_LOCAL_NED = 84
_MSG_SET_POSITION_TARGET_GLOBAL_INT = 86
_MSG_SET_ATTITUDE_TARGET = 82

#: control messages that only a trusted ground station may send to the vehicle
CONTROL_MSGIDS = frozenset({
    _MSG_SET_MODE, _MSG_PARAM_SET, _MSG_MISSION_ITEM, _MSG_MISSION_COUNT, _MSG_MISSION_CLEAR_ALL,
    _MSG_RC_CHANNELS_OVERRIDE, _MSG_MISSION_ITEM_INT, _MSG_SET_POSITION_TARGET_LOCAL_NED,
    _MSG_SET_POSITION_TARGET_GLOBAL_INT, _MSG_SET_ATTITUDE_TARGET,
})
_COMMAND_MSGIDS = frozenset({_MSG_COMMAND_LONG, _MSG_COMMAND_INT})

MAV_CMD_NAV_RETURN_TO_LAUNCH = 20
MAV_CMD_NAV_LAND = 21
MAV_CMD_NAV_TAKEOFF = 22
MAV_CMD_DO_SET_MODE = 176
MAV_CMD_DO_PARAMETER = 180
MAV_CMD_DO_FLIGHTTERMINATION = 185
MAV_CMD_DO_REPOSITION = 192
MAV_CMD_MISSION_START = 300
MAV_CMD_COMPONENT_ARM_DISARM = 400
MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN = 246
FORCE_MAGIC = 21196.0

#: commands a non-trusted sysid may not send, and the commands covered by the burst rule
SENSITIVE_COMMANDS = frozenset({
    MAV_CMD_NAV_RETURN_TO_LAUNCH, MAV_CMD_NAV_LAND, MAV_CMD_NAV_TAKEOFF, MAV_CMD_DO_SET_MODE,
    MAV_CMD_DO_PARAMETER, MAV_CMD_DO_FLIGHTTERMINATION, MAV_CMD_DO_REPOSITION, MAV_CMD_MISSION_START,
    MAV_CMD_COMPONENT_ARM_DISARM, MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN,
})

_V2, _V1 = 0xFD, 0xFE


def _payload(raw: bytes, signed_len: int = 0) -> bytes | None:
    """Payload of one unsigned-or-signed frame, zero-padded (MAVLink 2 trims trailing zeros)."""
    if not raw:
        return None
    if raw[0] == _V2 and len(raw) >= 12:
        return raw[10:10 + raw[1]] + bytes(40)
    if raw[0] == _V1 and len(raw) >= 8:
        return raw[6:6 + raw[1]] + bytes(40)
    return None


_ZEROS40 = bytes(40)


def _payload_crc32(raw: bytes) -> int:
    """``zlib.crc32(_payload(raw) or raw)`` without building the zero-padded copy (CRC-32 chains over the padding)."""
    if raw:
        if raw[0] == _V2 and len(raw) >= 12:
            return zlib.crc32(_ZEROS40, zlib.crc32(raw[10:10 + raw[1]]))
        if raw[0] == _V1 and len(raw) >= 8:
            return zlib.crc32(_ZEROS40, zlib.crc32(raw[6:6 + raw[1]]))
    return zlib.crc32(raw)


def _command(raw: bytes, msgid: int) -> tuple[int, float, float] | None:
    """``(command, param1, param2)`` of a COMMAND_LONG / COMMAND_INT frame."""
    p = _payload(raw)
    if p is None:
        return None
    if msgid == _MSG_COMMAND_LONG:
        p1, p2 = struct.unpack_from("<2f", p, 0)
        return struct.unpack_from("<H", p, 28)[0], p1, p2
    if msgid == _MSG_COMMAND_INT:
        p1, p2 = struct.unpack_from("<2f", p, 0)
        return struct.unpack_from("<H", p, 28)[0], p1, p2
    return None


class SeqProvenance:
    """Learn one source's 8-bit MAVLink sequence counter and judge later frames against it.

    Known after 3 consecutive consistent frames. A frame is consistent if ``(seq - last) mod 256`` is in
    ``1..window``. Inconsistent frames never move ``last`` (a forger must not drag the real counter); 3
    consecutive inconsistent frames that follow each other consistently replace the counter (``resyncs``), but only
    once the learned counter has been quiet for ``quiet_s`` seconds: a live genuine stream keeps the counter, so a
    forger that sends its own consecutive sequence next to it cannot take it over (SITL finding; a restarted GCS has
    no live old stream). ``now`` is the caller's monotonic clock; ``None`` disables the quiet check.
    """

    __slots__ = ("last", "count", "bad", "window", "resyncs", "quiet_s", "last_t")

    def __init__(self, window: int = 16, quiet_s: float = 2.0) -> None:
        self.last = -1
        self.count = 0
        self.bad: list[int] = []
        self.window = window
        self.resyncs = 0
        self.quiet_s = quiet_s
        self.last_t = 0.0

    @property
    def known(self) -> bool:
        return self.count >= 3

    def observe(self, seq: int, now: float | None = None) -> str:
        """``unknown`` | ``consistent`` | ``inconsistent`` (the third frame of a resync run is consistent)."""
        t = 0.0 if now is None else now
        if not self.known:
            ok = self.count > 0 and 1 <= (seq - self.last) % 256 <= self.window
            self.count = self.count + 1 if ok else 1
            self.last = seq
            self.last_t = t
            return "unknown"
        if 1 <= (seq - self.last) % 256 <= self.window:
            self.last = seq
            self.last_t = t
            self.bad.clear()
            return "consistent"
        if self.bad and 1 <= (seq - self.bad[-1]) % 256 <= self.window:
            self.bad.append(seq)
            del self.bad[:-3]
        else:
            self.bad = [seq]
        if len(self.bad) >= 3 and (now is None or t - self.last_t >= self.quiet_s):
            self.last = seq
            self.last_t = t
            self.bad.clear()
            self.resyncs += 1
            return "consistent"
        return "inconsistent"


class InlinePolicy:
    """Thread-safe uplink/downlink filter for an inline bridge. See the module docstring."""

    def __init__(
        self,
        sanitizer: FrameSanitizer | None = None,
        *,
        trusted_sysids: Iterable[int] = (255, 254),
        vehicle_sysids: Iterable[int] = (1,),
        cadence_s: float = 0.05,
        dynamic_ttl_s: float = 3.0,
        in_flight_alt_m: float = 2.0,
        in_flight_speed_ms: float = 1.0,
        signing_key: bytes | None = None,
        allow_unsigned_from_trusted: bool = False,
        max_age_s: float | None = None,
        state_path: str | os.PathLike[str] | None = None,
        clock: Callable[[], float] = time.monotonic,
        provenance: bool = True,
        provenance_window: int = 16,
        replay_memory: int = 4096,
        contested_policy: str = "alert",
        contested_hold_s: float = 60.0,
        contested_alarm_interval_s: float = 10.0,
        semantic_firewall: SemanticFirewall | None = None,
        semantic_firewall_enabled: bool = True,
    ) -> None:
        if contested_policy not in ("alert", "drop-sensitive"):
            raise ValueError("contested_policy must be 'alert' or 'drop-sensitive'")
        self.sanitizer = sanitizer or FrameSanitizer()
        self.trusted_sysids = frozenset(int(s) for s in trusted_sysids)
        self.vehicle_sysids = frozenset(int(s) for s in vehicle_sysids)
        self.cadence_s = float(cadence_s)
        self.dynamic_ttl_s = float(dynamic_ttl_s)
        self.in_flight_alt_m = float(in_flight_alt_m)
        self.in_flight_speed_ms = float(in_flight_speed_ms)
        self._clock = clock
        self._lock = threading.Lock()
        self.enforce = False                # static uplink rules + dynamic rewrites; off = byte-identical forwarding
        # receive-only-compatible filtering (InlineIpsBridge vehicle_filter): with enforce on, ONLY the uplink rules run;
        # the downlink is forwarded untouched (no forged-frame drop, no rewrite) and no dynamic rule applies
        self.uplink_filter_only = False
        # safeguards of that filter (docs/VEHICLE_UPLINK_FILTER.md, section 5): it starts in 'learning' (forwarding everything, only
        # reporting) and engages on the first validly signed frame from a ground station, which proves the key; 'override' is the
        # operator's local off switch; 'failopen' is the optional lock-out watchdog. 'off' = the filter was not requested.
        self.filter_state = "off"
        self.filter_override = False
        self.lockout_failopen_s: float | None = None
        self._last_valid_t: float | None = None
        self._engaged_t: float | None = None
        self._lockout_drops = 0
        self.filter_events: list[tuple[str, str]] = []
        self._last_touch: float | None = None
        # vehicle state learnt from the frames the policy itself forwards (no detector involved)
        self.armed: bool | None = None
        self.rel_alt_m: float | None = None
        self.groundspeed_ms: float | None = None
        self._last_cmd: dict[tuple[int, int, int], tuple[float, bytes]] = {}
        # MAVLink-2 signing of the uplink (None = trust by sysid)
        self._verifier = MavlinkSignatureVerifier(signing_key) if signing_key is not None else None
        self.allow_unsigned_from_trusted = bool(allow_unsigned_from_trusted)
        self.max_age_s = max_age_s
        self._state_path = Path(state_path) if state_path else None
        self._state_dirty = False
        self._last_persist = 0.0
        if self._verifier is not None and self._state_path is not None:
            self._load_state()
        self.signed_ok = 0
        self.dropped_unsigned = 0
        self.dropped_bad_signature = 0
        self.dropped_replay = 0
        # unsigned-link provenance (sequence-counter tracker + byte-identical replay set)
        self.provenance = bool(provenance)
        self.provenance_window = int(provenance_window)
        self._seq: dict[tuple[int, int], SeqProvenance] = {}
        self._seen: dict[bytes, float] = {}
        self.dropped_provenance = 0
        self.suspect_provenance = 0
        self.dropped_replay_unsigned = 0
        self.resyncs = 0
        self.replay_memory = max(1, int(replay_memory))
        # dual-transmitter detection ("contested" source)
        self.contested_policy = contested_policy
        self.contested_hold_s = float(contested_hold_s)
        self.contested_alarm_interval_s = float(contested_alarm_interval_s)
        self.contested_events = 0
        self.dropped_contested = 0
        self.contested_alarms = 0
        self._recent: dict[tuple[int, int], deque[tuple[float, int, int]]] = {}
        self._contested_until: dict[tuple[int, int], float] = {}
        self._alarm_last: dict[tuple[int, int], float] = {}
        self._alarms: list[int] = []
        # counters
        self.dropped_untrusted_control = 0
        self.dropped_inflight_disarm = 0
        self.dropped_burst = 0
        self.dropped_dynamic = 0
        # report-only signature verdicts (posture below ACTIVE_IPS): counted and announced, never dropped
        self.observed_unsigned = 0
        self.observed_bad_signature = 0
        self.observed_replay = 0
        self._observed_pending: list[tuple[str, bytes, int, int]] = []
        self.max_signed_ts = 0  # newest valid signing timestamp seen in either direction (10 us units)
        self.dropped_forged_down = 0
        self.observed_forged_down = 0
        self._down_signed: dict[tuple[int, int], int] = {}  # (sysid, compid) -> valid signed frames seen
        self._down_signed_t: dict[tuple[int, int], int] = {}  # (sysid, compid) -> recv_ns of the last valid signed frame
        self.signing_lapsed = 0  # sources that stopped signing (not in stats(): the forwarding guard hashes it)
        self.rewritten = 0
        self.hook_errors = 0
        # Semantic firewall (#W1): counters intentionally kept out of stats() so forwarding golden digests stay exact
        self.semantic_firewall = semantic_firewall or SemanticFirewall(enabled=semantic_firewall_enabled)
        self.dropped_semantic_param = 0
        self.dropped_semantic_fence = 0
        self.last_semantic_reason: str | None = None
        self._home_lat_lon: tuple[float, float] | None = None

    def semantic_stats(self) -> dict[str, Any]:
        return {
            "enabled": bool(self.semantic_firewall.enabled),
            "dropped_param": self.dropped_semantic_param,
            "dropped_fence": self.dropped_semantic_fence,
            "last_reason": self.last_semantic_reason,
        }

    # -- control ------------------------------------------------------------- #

    def set_enforce(self, enforce: bool) -> None:
        with self._lock:
            self.enforce = bool(enforce)
            if not enforce:
                self._last_cmd.clear()
                self._seq.clear()
                self._seen.clear()
                self._recent.clear()
                self._contested_until.clear()
                self._alarms.clear()

    def set_uplink_filter_only(self, flag: bool) -> None:
        with self._lock:
            if bool(flag) == self.uplink_filter_only:
                return  # unchanged: a posture change between the reporting postures must not make the filter re-learn the key
            self.uplink_filter_only = bool(flag)
            self.filter_state = "learning" if flag else "off"
            self._lockout_drops = 0

    def _set_filter_state(self, state: str, detail: str = "") -> None:
        if state == self.filter_state:
            return
        self.filter_state = state
        now = self._clock()
        self._engaged_t = now if state == "engaged" else None
        self._lockout_drops = 0
        if len(self.filter_events) < 16:
            self.filter_events.append((state, detail))

    def take_filter_events(self) -> list[tuple[str, str]]:
        out, self.filter_events = self.filter_events, []
        return out

    def _filter_gate(self, ctx: FrameContext) -> bool:
        """Vehicle uplink filter safeguards. True = forward this frame untouched (the filter is not acting on it)."""
        if self.filter_override:
            self._set_filter_state("override", "local override file present: forwarding everything, reporting only")
        elif self.filter_state == "override":
            self._set_filter_state("learning", "override cleared: waiting for a validly signed ground-station frame")
        v = self._verifier
        if v is None:
            return True
        gcs_signed = ctx.signed and ctx.sysid not in self.vehicle_sysids
        if self.filter_state == "engaged":
            if self.lockout_failopen_s is not None and gcs_signed and not self._is_control(ctx):
                if self._check_signature(ctx, observe=True) == "ok":
                    self._note_valid()
            return False
        if gcs_signed and self.filter_state in ("learning", "failopen") and self._check_signature(ctx, observe=True) == "ok":
            self._note_valid()
            self._set_filter_state("engaged", "a validly signed ground-station frame proves the key: filtering uplink control")
            return True
        self._observe_signature(ctx)
        return True

    def _is_control(self, ctx: FrameContext) -> bool:
        cmd = _command(ctx.raw, ctx.msgid) if ctx.msgid in _COMMAND_MSGIDS else None
        return ctx.msgid in CONTROL_MSGIDS or (cmd is not None and cmd[0] in SENSITIVE_COMMANDS)

    def _note_valid(self) -> None:
        self._last_valid_t = self._clock()
        self._lockout_drops = 0

    def _note_lockout_drop(self, ctx: FrameContext, verdict: str) -> None:
        """Optional watchdog. Pilot lock-out looks like this: control frames from a TRUSTED ground-station sysid keep failing the
        signature check while no validly signed ground-station frame has been seen for lockout_failopen_s. It cannot tell that from an
        attacker who spoofs the pilot's sysid while the real GCS is silent, which is why it is off by default."""
        if self.lockout_failopen_s is None or ctx.sysid not in self.trusted_sysids or verdict not in ("unsigned", "bad_signature"):
            return
        self._lockout_drops += 1
        since = self._last_valid_t if self._last_valid_t is not None else self._engaged_t
        if self._lockout_drops >= 3 and since is not None and self._clock() - since >= self.lockout_failopen_s:
            self._set_filter_state("failopen", f"pilot lock-out suspected: no valid signed ground-station frame for "
                                  f"{self.lockout_failopen_s:.0f} s while control frames from a trusted sysid were dropped; "
                                  "forwarding everything until a signed frame is seen")

    def take_alarms(self) -> list[int]:
        """Sysids with a new contested alarm to raise (rate-limited per source); the bridge sends the STATUSTEXT."""
        if not self._alarms:
            return []
        with self._lock:
            out, self._alarms = self._alarms, []
        return out

    def is_contested(self, sysid: int, compid: int | None = None) -> bool:
        now = self._clock()
        return any(k[0] == sysid and (compid is None or k[1] == compid) and now < u
                   for k, u in self._contested_until.items())

    def touch(self) -> None:
        """The analyser calls this after every controller step; it keeps the dynamic rules fresh."""
        self._last_touch = self._clock()

    @property
    def dynamic_fresh(self) -> bool:
        t = self._last_touch
        return t is not None and (self._clock() - t) <= self.dynamic_ttl_s

    @property
    def protected_sysids(self) -> frozenset[int]:
        """Never quarantined: the vehicle and the trusted ground stations."""
        return self.trusted_sysids | self.vehicle_sysids

    @property
    def in_flight(self) -> bool:
        if not self.armed:
            return False
        return bool((self.rel_alt_m or 0.0) > self.in_flight_alt_m
                    or (self.groundspeed_ms or 0.0) > self.in_flight_speed_ms)

    def stats(self) -> dict[str, int | bool | None]:
        return {"signing": self._verifier is not None, "signed_ok": self.signed_ok,
                "dropped_unsigned": self.dropped_unsigned, "dropped_bad_signature": self.dropped_bad_signature,
                "dropped_replay": self.dropped_replay, "enforce": self.enforce, "dynamic_fresh": self.dynamic_fresh, "armed": self.armed,
                "in_flight": self.in_flight, "dropped_untrusted_control": self.dropped_untrusted_control,
                "dropped_inflight_disarm": self.dropped_inflight_disarm, "dropped_burst": self.dropped_burst,
                "dropped_dynamic": self.dropped_dynamic, "rewritten": self.rewritten,
                "hook_errors": self.hook_errors,
                "provenance_known_sources": sum(1 for t in self._seq.values() if t.known),
                "dropped_provenance": self.dropped_provenance, "suspect_provenance": self.suspect_provenance,
                "dropped_replay_unsigned": self.dropped_replay_unsigned, "resyncs": self.resyncs,
                "replay_memory": self.replay_memory, "contested_policy": self.contested_policy,
                "contested_events": self.contested_events,
                "contested_sources": sum(1 for u in list(self._contested_until.values()) if self._clock() < u),
                "contested_alarms": self.contested_alarms, "dropped_contested": self.dropped_contested}

    # -- hooks --------------------------------------------------------------- #

    SIGNED_SOURCE_MIN = 20  # valid signed frames before a source counts as "signs its frames"
    SIGNING_LAPSE_NS = 10_000_000_000  # no valid signed frame for this long: the source no longer counts as signing

    def _down_forged(self, ctx: FrameContext) -> str | None:
        """Signed link: a source that has been signing its frames and now sends an unsigned (or badly signed) one is a forgery.

        The vehicle's own telemetry is signed on a signed link, so an attacker without the key (a man in the middle on the
        flight-controller link, a rogue component) cannot produce frames that pass. A source is only judged after it was seen
        signing, so links or components that never sign are left alone. Replayed-timestamp verdicts are ignored (reordering).
        """
        v = self._verifier
        assert v is not None
        src = (ctx.sysid, ctx.compid)
        n = self._down_signed.get(src, 0)
        if n >= self.SIGNED_SOURCE_MIN and ctx.recv_ns - self._down_signed_t.get(src, ctx.recv_ns) > self.SIGNING_LAPSE_NS:
            # the source stopped signing (FC signing turned off, a reboot into an unsigned setup): dropping all of its
            # telemetry from now on would black the vehicle out for the pilot, so it is judged afresh -- and said loudly
            n = 0
            del self._down_signed[src]
            self.signing_lapsed += 1
            if len(self._observed_pending) < 64:
                self._observed_pending.append(("signing_lapsed", ctx.raw, ctx.sysid, ctx.msgid))
        if not ctx.signed:
            return "unsigned" if n >= self.SIGNED_SOURCE_MIN else None
        res = v.verify_frame(ctx.raw)
        if res.valid:
            self.max_signed_ts = max(self.max_signed_ts, res.timestamp_10us)
            self._down_signed_t[src] = ctx.recv_ns
            if n < self.SIGNED_SOURCE_MIN + 5:
                if len(self._down_signed) >= 256 and src not in self._down_signed:
                    evict = next(iter(self._down_signed))
                    self._down_signed.pop(evict)
                    self._down_signed_t.pop(evict, None)
                self._down_signed[src] = n + 1
            return None
        if n >= self.SIGNED_SOURCE_MIN and res.signed and not res.replayed:
            return "bad_signature"
        return None

    def down(self, ctx: FrameContext) -> list[bytes]:
        """FC -> GCS."""
        try:
            if self._verifier is not None:
                forged = self._down_forged(ctx)
                if forged:
                    if self.enforce and not self.uplink_filter_only:
                        self.dropped_forged_down += 1
                        return []  # never reaches the GCS and never feeds the learned vehicle state
                    self.observed_forged_down += 1
                    if len(self._observed_pending) < 64:
                        self._observed_pending.append((forged, ctx.raw, ctx.sysid, ctx.msgid))
            self._learn_state(ctx)
            if not self.enforce or self.uplink_filter_only or not self.dynamic_fresh or not self.sanitizer.active:
                return [ctx.raw]
            san = self.sanitizer
            if ctx.sysid in self.protected_sysids:
                # the vehicle's own telemetry may be rewritten (GPS / altitude) but a protected sysid is never
                # quarantined and never shed by the flood gatekeeper: dropping the flight controller's telemetry
                # on a false or soft rate alarm would blind the pilot. Pass bypass_quarantine_and_qos=True to avoid
                # mutating shared sanitizer attributes across threads.
                out = san(ctx, bypass_quarantine_and_qos=True)
            else:
                out = san(ctx)
            if not out:
                self.dropped_dynamic += 1
            elif out != [ctx.raw]:
                self.rewritten += 1
            return out
        except Exception:  # noqa: BLE001 - fail open
            self.hook_errors += 1
            return [ctx.raw]

    def up(self, ctx: FrameContext) -> list[bytes]:
        """GCS -> FC."""
        try:
            if self.uplink_filter_only and self._filter_gate(ctx):
                return [ctx.raw]
            if not self.enforce:
                if self._verifier is not None:
                    self._observe_signature(ctx)
                return [ctx.raw]
            trusted = ctx.sysid in self.trusted_sysids
            msgid = ctx.msgid
            cmd = _command(ctx.raw, msgid) if msgid in _COMMAND_MSGIDS else None
            needs_auth = msgid in CONTROL_MSGIDS or (cmd is not None and cmd[0] in SENSITIVE_COMMANDS)
            if needs_auth and self._verifier is not None:
                verdict = self._check_signature(ctx)
                if verdict == "ok":
                    trusted = True  # a valid signature, not the sysid, makes the sender trusted
                    if self.uplink_filter_only:
                        self._note_valid()
                elif verdict == "unsigned" and trusted and self.allow_unsigned_from_trusted:
                    pass  # rollout mode: an unsigned frame from a trusted sysid still passes
                else:
                    if self.uplink_filter_only:
                        self._note_lockout_drop(ctx, verdict)
                        if self.filter_state == "failopen":
                            return [ctx.raw]
                    return []
            track = self.provenance and self._verifier is None
            verdict = self._observe_seq(ctx) if track else "unknown"
            if track:
                self._observe_dual(ctx)
                if (needs_auth and self.contested_policy == "drop-sensitive" and self.in_flight
                        and self.is_contested(ctx.sysid, ctx.compid)
                        and not (cmd is not None and cmd[0] == MAV_CMD_COMPONENT_ARM_DISARM
                                 and cmd[1] == 0.0 and cmd[2] == FORCE_MAGIC)):
                    self.dropped_contested += 1
                    return []
            if msgid in CONTROL_MSGIDS and not trusted:
                self.dropped_untrusted_control += 1
                return []
            if self.semantic_firewall.enabled and not self.uplink_filter_only:
                if msgid == _MSG_PARAM_SET:
                    parsed_ps = extract_param_set_raw(ctx.raw)
                    if parsed_ps is not None:
                        pid, pval, ptype = parsed_ps
                        verdict = self.semantic_firewall.evaluate_param_write(
                            ParamWriteEvent(
                                recv_time=ctx.recv_ns / 1e9,
                                sysid=ctx.sysid,
                                compid=ctx.compid,
                                param_id=pid,
                                param_value=pval,
                                param_type=ptype,
                                source_kind="param_set",
                            ),
                            armed=self.armed,
                        )
                        if verdict.blocked:
                            self.dropped_semantic_param += 1
                            self.last_semantic_reason = verdict.reason
                            return []
                elif msgid in (_MSG_MISSION_CLEAR_ALL, _MSG_MISSION_COUNT, _MSG_MISSION_ITEM_INT):
                    parsed_fc = extract_mission_fence_raw(ctx.raw, msgid)
                    if parsed_fc is not None:
                        action, mtype, cnt, fcmd, rad, flat, flon = parsed_fc
                        verdict = self.semantic_firewall.evaluate_fence_change(
                            FenceChangeEvent(
                                recv_time=ctx.recv_ns / 1e9,
                                sysid=ctx.sysid,
                                compid=ctx.compid,
                                action=action,
                                mission_type=mtype,
                                count=cnt,
                                command=fcmd,
                                radius_m=rad,
                                lat_deg=flat,
                                lon_deg=flon,
                            ),
                            armed=self.armed,
                            home_lat_lon=self._home_lat_lon,
                        )
                        if verdict.blocked:
                            self.dropped_semantic_fence += 1
                            self.last_semantic_reason = verdict.reason
                            return []
            if needs_auth and track:
                if verdict == "inconsistent" and trusted:
                    if self.armed or self.in_flight:
                        self.dropped_provenance += 1
                        return []
                    self.suspect_provenance += 1
                return self._replay_filter(ctx, self._after_provenance(ctx, trusted, cmd))
            if cmd is not None and cmd[0] in SENSITIVE_COMMANDS:
                return self._command_rule(ctx, trusted, *cmd)
            if self.dynamic_fresh and self.sanitizer.active and not trusted and not self.uplink_filter_only:
                # quarantined / flooding sender on the uplink (the sanitizer drops both directions)
                if ctx.sysid in self.sanitizer.quarantined_sysids and ctx.sysid not in self.protected_sysids:
                    self.dropped_dynamic += 1
                    return []
            return [ctx.raw]
        except Exception:  # noqa: BLE001 - fail open
            self.hook_errors += 1
            return [ctx.raw]

    # -- internals ----------------------------------------------------------- #

    def _observe_seq(self, ctx: FrameContext) -> str:
        key = (ctx.sysid, ctx.compid)
        with self._lock:
            t = self._seq.get(key)
            if t is None:
                if len(self._seq) >= 256:
                    self._seq.pop(next(iter(self._seq)))
                t = self._seq[key] = SeqProvenance(self.provenance_window)
            before = t.resyncs
            verdict = t.observe(ctx.seq, self._clock())
            self.resyncs += t.resyncs - before
        return verdict

    def _observe_dual(self, ctx: FrameContext) -> None:
        """Same (sysid, compid) and same seq but a different payload within 2 s: two transmitters share the identity."""
        key = (ctx.sysid, ctx.compid)
        h = _payload_crc32(ctx.raw)
        seq = ctx.seq
        now = self._clock()
        with self._lock:
            ring = self._recent.get(key)
            if ring is None:
                if len(self._recent) >= 256:
                    self._recent.pop(next(iter(self._recent)))
                ring = self._recent[key] = deque(maxlen=32)
            hit = False
            for t, s, ph in ring:
                if s == seq and ph != h and now - t <= 2.0:
                    hit = True
                    break
            ring.append((now, seq, h))
            if not hit:
                return
            was = now < self._contested_until.get(key, 0.0)
            self._contested_until[key] = now + self.contested_hold_s
            self.contested_events += 1
            if not was or now - self._alarm_last.get(key, -1e18) >= self.contested_alarm_interval_s:
                self._alarm_last[key] = now
                self.contested_alarms += 1
                self._alarms.append(ctx.sysid)

    def _after_provenance(self, ctx: FrameContext, trusted: bool, cmd: tuple[int, float, float] | None) -> list[bytes]:
        if cmd is not None and cmd[0] in SENSITIVE_COMMANDS:
            return self._command_rule(ctx, trusted, *cmd)
        return [ctx.raw]

    def _replay_filter(self, ctx: FrameContext, out: list[bytes]) -> list[bytes]:
        """Drop a byte-identical repeat (same sysid, compid, seq, payload) of a frame already forwarded."""
        if not out:
            return out
        h = hashlib.blake2b(
            bytes((ctx.sysid, ctx.compid, ctx.seq & 0xFF)) + (_payload(ctx.raw) or ctx.raw), digest_size=16).digest()
        now = self._clock()
        with self._lock:
            t = self._seen.get(h)
            # count-bounded, no time limit: a frame replayed after the 8-bit counter wrapped is still caught. Known or
            # not, an exact (sysid, compid, seq, payload) already forwarded is never forwarded twice.
            if t is not None:
                self.dropped_replay_unsigned += 1
                return []
            self._seen[h] = now
            while len(self._seen) > self.replay_memory:
                self._seen.pop(next(iter(self._seen)))
        return out

    def _check_signature(self, ctx: FrameContext, observe: bool = False) -> str:
        """``ok`` | ``unsigned`` | ``bad_signature`` | ``replay`` (each counted: as a drop, or as an observation when ``observe``)."""
        v = self._verifier
        assert v is not None
        res = v.verify_frame(ctx.raw)
        if res.valid:
            if self.max_age_s is not None:
                now_10us = (time.time() - MAVLINK_EPOCH_UNIX_S) * 100_000
                if res.timestamp_10us < now_10us - self.max_age_s * 100_000:
                    if observe:
                        self.observed_replay += 1
                    else:
                        self.dropped_replay += 1
                    return "replay"
            self.signed_ok += 1
            self.max_signed_ts = max(self.max_signed_ts, res.timestamp_10us)
            self._state_dirty = True
            self._maybe_persist()
            return "ok"
        if not res.signed:
            if observe:
                self.observed_unsigned += 1
            else:
                self.dropped_unsigned += 1
            return "unsigned"
        if res.replayed:
            if observe:
                self.observed_replay += 1
            else:
                self.dropped_replay += 1
            return "replay"
        if observe:
            self.observed_bad_signature += 1
        else:
            self.dropped_bad_signature += 1
        return "bad_signature"

    def _observe_signature(self, ctx: FrameContext) -> None:
        """IDS / advisory postures: judge the signature of control frames exactly as ACTIVE_IPS would, but only report."""
        msgid = ctx.msgid
        cmd = _command(ctx.raw, msgid) if msgid in _COMMAND_MSGIDS else None
        if not (msgid in CONTROL_MSGIDS or (cmd is not None and cmd[0] in SENSITIVE_COMMANDS)):
            return
        verdict = self._check_signature(ctx, observe=True)
        if verdict == "ok" or (verdict == "unsigned" and ctx.sysid in self.trusted_sysids and self.allow_unsigned_from_trusted):
            return
        if len(self._observed_pending) < 64:
            self._observed_pending.append((verdict, ctx.raw, ctx.sysid, msgid))

    def next_signing_timestamp(self) -> int | None:
        """A timestamp just above the newest valid signed frame seen on the link, or None before any was seen."""
        return self.max_signed_ts + 1 if self.max_signed_ts else None

    def observed_stats(self) -> dict[str, int]:
        """Report-only signature verdicts (IDS / advisory postures); kept apart from stats() so the forwarding guard is untouched."""
        return {"unsigned": self.observed_unsigned, "bad_signature": self.observed_bad_signature, "replay": self.observed_replay,
                "forged_down_observed": self.observed_forged_down, "forged_down_dropped": self.dropped_forged_down}

    def take_observed(self) -> list[tuple[str, bytes, int, int]]:
        """Pending report-only verdicts (``verdict, raw, sysid, msgid``), cleared on read. Forwarding thread only."""
        out, self._observed_pending = self._observed_pending, []
        return out

    # -- signing state persistence ------------------------------------------- #

    def _load_state(self) -> None:
        assert self._verifier is not None and self._state_path is not None
        with contextlib.suppress(OSError, ValueError, KeyError, TypeError, AttributeError):
            data = json.loads(self._state_path.read_text(encoding="utf-8"))
            for k, ts in data.get("streams", {}).items():
                link, sysid, compid = (int(x) for x in k.split(":"))
                self._verifier._last_timestamps[(link, sysid, compid)] = int(ts)

    def _maybe_persist(self, force: bool = False) -> None:
        if self._state_path is None or self._verifier is None or not self._state_dirty:
            return
        now = time.monotonic()
        if not force and now - self._last_persist < 1.0:
            return
        self._last_persist = now
        self._state_dirty = False
        with contextlib.suppress(OSError):
            tmp = self._state_path.with_suffix(self._state_path.suffix + ".tmp")
            streams = {f"{k[0]}:{k[1]}:{k[2]}": v for k, v in self._verifier._last_timestamps.items()}
            tmp.write_text(json.dumps({"streams": streams}), encoding="utf-8")
            os.replace(tmp, self._state_path)

    def flush(self) -> None:
        """Write the signing timestamp state now (called on shutdown)."""
        self._maybe_persist(force=True)

    def _command_rule(self, ctx: FrameContext, trusted: bool, command: int, p1: float, p2: float) -> list[bytes]:
        if not trusted:
            self.dropped_untrusted_control += 1
            return []
        if command == MAV_CMD_COMPONENT_ARM_DISARM and p1 == 0.0 and self.in_flight and p2 != FORCE_MAGIC:
            # a plain disarm in flight is refused by the autopilot anyway; a forced one is the pilot's kill switch
            self.dropped_inflight_disarm += 1
            return []
        key = (ctx.sysid, ctx.compid, command)
        body = ctx.raw[10:-2] if ctx.raw[0] == _V2 and not ctx.signed else ctx.raw
        now = self._clock()
        with self._lock:
            prev = self._last_cmd.get(key)
            self._last_cmd[key] = (now, body)
            if len(self._last_cmd) > 256:
                self._last_cmd.pop(next(iter(self._last_cmd)))
        if prev is not None and (now - prev[0]) < self.cadence_s and prev[1] == body:
            self.dropped_burst += 1
            return []
        return [ctx.raw]

    def _learn_state(self, ctx: FrameContext) -> None:
        if ctx.sysid not in self.vehicle_sysids:
            return
        if ctx.msgid == _MSG_HEARTBEAT:
            p = _payload(ctx.raw)
            # Ignore GCS (type=6) and non-autopilot peripheral/companion heartbeats (autopilot=8)
            if p is not None and len(ctx.raw) >= 12 and p[4] != 6 and p[5] != 8:
                self.armed = bool(p[6] & 0x80)  # base_mode SAFETY_ARMED
        elif ctx.msgid == _MSG_GLOBAL_POSITION_INT:
            p = _payload(ctx.raw)
            if p is not None:
                _, lat_i, lon_i, _, rel_alt, vx, vy, _, _ = struct.unpack_from("<IiiiihhhH", p, 0)
                if self._home_lat_lon is None and (lat_i != 0 or lon_i != 0):
                    self._home_lat_lon = (lat_i / 1e7, lon_i / 1e7)
                self.rel_alt_m = rel_alt / 1000.0
                self.groundspeed_ms = ((vx / 100.0) ** 2 + (vy / 100.0) ** 2) ** 0.5
