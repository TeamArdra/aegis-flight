"""Byte-exact equivalence corpus + fixture generator for the inline FORWARDING path.

    python scripts/make_golden_forwarding.py            # (re)write tests/golden_forwarding/golden.json
    python scripts/make_golden_forwarding.py --check    # recompute and compare, exit 1 on a difference

The fixture is generated from the code BEFORE the forwarding-path optimisation and must never be
regenerated to make a failing test pass: a difference means the forwarding behaviour changed. Everything is
deterministic: fixed seeds, injected clocks (policy, bridge and management channel), ``time.time`` and
``secrets.randbelow`` patched while the corpus is built and run.

What is recorded per (scenario, posture): the exact bytes sent to the FC and to the GCS (count + sha256 of the
concatenation + an order-sensitive digest over both), the management frames among them, the tap contents,
every bridge / policy / sanitizer / management counter. Separate layers record ``split_frames`` outputs, the
serial stream framer (frames + all counters, several read splits and configurations) and the CRC helpers.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import random
import secrets
import struct
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from pymavlink.dialects.v10 import common as mav1  # noqa: E402
from pymavlink.dialects.v20 import common as mav2  # noqa: E402

from aegisflight.hal.inline_ips import InlineIpsBridge  # noqa: E402
from aegisflight.hal.mgmt_channel import (  # noqa: E402
    OP_ACK_ALARMS,
    OP_SET_POSTURE,
    OP_STATUS_NOW,
    build_command_frame,
)
from aegisflight.mavlink.signing import MavlinkSignatureVerifier, sign_mavlink2_frame  # noqa: E402
from aegisflight.mitigation.actuator import x25_crc  # noqa: E402
from aegisflight.proxy.transport import split_frames  # noqa: E402
from aegisflight.sources.mavlink_serial import MavlinkStreamFramer, _crc_x25  # noqa: E402

GOLDEN_PATH = REPO / "tests" / "golden_forwarding" / "golden.json"
POSTURES = ("passive", "advisory", "active-ips")
KEY = bytes(range(1, 33))          # flight signing key
WRONG_KEY = bytes(range(101, 133))
MGMT_KEY = bytes(range(201, 233))  # management control key
T0 = 1000.0                         # injected clock origin (seconds)
EPOCH = 1_420_070_400
FAKE_WALL = 1_800_000_000.0         # patched time.time()
TS0 = int((FAKE_WALL - EPOCH) * 100_000)  # signature timestamp of "now"


@contextlib.contextmanager
def deterministic() -> Iterator[None]:
    """Fixed wall clock and token source for everything that is not injected."""
    with mock.patch.object(time, "time", lambda: FAKE_WALL), \
            mock.patch.object(secrets, "randbelow", lambda n: 12345 % max(1, n)):
        yield


# --------------------------------------------------------------------------- #
# frame generation (pymavlink, fixed values)
# --------------------------------------------------------------------------- #


class Gen:
    """pymavlink encoders per (sysid, compid) with their own sequence counters."""

    def __init__(self, v1: bool = False) -> None:
        self._m: dict[tuple[int, int], Any] = {}
        self._dialect = mav1 if v1 else mav2

    def enc(self, sysid: int, compid: int = 1) -> Any:
        key = (sysid, compid)
        if key not in self._m:
            m = self._dialect.MAVLink(None, srcSystem=sysid, srcComponent=compid)
            m.robust_parsing = True
            self._m[key] = m
        return self._m[key]

    def pack(self, sysid: int, compid: int, build: str, *args: Any, seq: int | None = None) -> bytes:
        m = self.enc(sysid, compid)
        if seq is not None:
            m.seq = seq
        return bytes(getattr(m, build)(*args).pack(m))

    # telemetry
    def heartbeat(self, sysid: int = 1, armed: bool = False, compid: int = 1, seq: int | None = None) -> bytes:
        return self.pack(sysid, compid, "heartbeat_encode", 2, 3, 0x80 if armed else 0, 4, 4, seq=seq)

    def gpi(self, sysid: int = 1, lat: float = 19.0, lon: float = 72.9, rel: float = 30.0, vx: float = 5.0,
            vz: int = 0, hdg: int = 0, seq: int | None = None) -> bytes:
        return self.pack(sysid, 1, "global_position_int_encode", 1000, int(lat * 1e7), int(lon * 1e7),
                         int((rel + 10) * 1000), int(rel * 1000), int(vx * 100), 0, vz, hdg, seq=seq)

    def attitude(self, sysid: int = 1, yaw: float = 0.5) -> bytes:
        return self.pack(sysid, 1, "attitude_encode", 2000, 0.01, -0.02, yaw, 0.0, 0.0, 0.0)

    def vfr(self, sysid: int = 1) -> bytes:
        return self.pack(sysid, 1, "vfr_hud_encode", 5.0, 5.2, 90, 50, 40.0, 0.1)

    def gps_raw(self, sysid: int = 1) -> bytes:
        return self.pack(sysid, 1, "gps_raw_int_encode", 3_000_000, 3, 190000000, 729000000, 40000, 120, 150, 500, 9000, 11)

    def sys_status(self, sysid: int = 1) -> bytes:
        return self.pack(sysid, 1, "sys_status_encode", 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 400, 12400, 800, 77, 0, 0, 0, 0, 0, 0)

    # uplink
    def command_long(self, sysid: int, command: int, p1: float = 0.0, p2: float = 0.0, comp: int = 190,
                     seq: int | None = None) -> bytes:
        return self.pack(sysid, comp, "command_long_encode", 1, 1, command, 0, p1, p2, 0, 0, 0, 0, 0, seq=seq)

    def command_int(self, sysid: int, command: int, comp: int = 190) -> bytes:
        return self.pack(sysid, comp, "command_int_encode", 1, 1, 6, command, 0, 0, 0, 0, 0, 0, 100, 200, 30.0)

    def set_mode(self, sysid: int, mode: int = 4, seq: int | None = None) -> bytes:
        return self.pack(sysid, 190, "set_mode_encode", 1, 1, mode, seq=seq)

    def rc_override(self, sysid: int) -> bytes:
        return self.pack(sysid, 190, "rc_channels_override_encode", 1, 1, 1500, 1500, 1500, 1500, 0, 0, 0, 0)

    def param_set(self, sysid: int) -> bytes:
        return self.pack(sysid, 190, "param_set_encode", 1, 1, b"WPNAV_SPEED", 500.0, 9)

    def mission_count(self, sysid: int) -> bytes:
        return self.pack(sysid, 190, "mission_count_encode", 1, 1, 3)

    def mission_clear(self, sysid: int) -> bytes:
        return self.pack(sysid, 190, "mission_clear_all_encode", 1, 1)

    def pos_target(self, sysid: int) -> bytes:
        return self.pack(sysid, 190, "set_position_target_local_ned_encode", 0, 1, 1, 1, 0xFF8, 1.0, 2.0, -3.0,
                         0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)

    def param_request(self, sysid: int) -> bytes:
        return self.pack(sysid, 190, "param_request_list_encode", 1, 1)


def signed(raw: bytes, key: bytes = KEY, ts: int = TS0, link: int = 0) -> bytes:
    return sign_mavlink2_frame(raw, key, link_id=link, timestamp_10us=ts)


def ref_crc(data: bytes, crc: int = 0xFFFF) -> int:
    """Independent bit-level X.25 (not one of the repo's implementations)."""
    for b in data:
        for i in range(8):
            bit = (crc ^ (b >> i)) & 1
            crc >>= 1
            if bit:
                crc ^= 0x8408
    return crc


def raw_v2(msgid: int, payload: bytes, sysid: int = 1, compid: int = 1, seq: int = 0, incompat: int = 0,
           extra: int | None = None, bad_crc: bool = False) -> bytes:
    if extra is None:
        extra = mav2.mavlink_map[msgid].crc_extra
    hdr = bytes([len(payload), incompat, 0, seq & 0xFF, sysid, compid, msgid & 0xFF, (msgid >> 8) & 0xFF, msgid >> 16])
    crc = ref_crc(bytes([extra]), ref_crc(hdr + payload))
    if bad_crc:
        crc ^= 0x0101
    return b"\xfd" + hdr + payload + struct.pack("<H", crc)


# --------------------------------------------------------------------------- #
# bridge scenarios
# --------------------------------------------------------------------------- #


class Scn:
    """A timeline of steps. ``kw`` are InlineIpsBridge keyword arguments."""

    def __init__(self, name: str, **kw: Any) -> None:
        self.name = name
        self.kw = kw
        self.steps: list[tuple[str, float, Any]] = []
        self.t = T0 + 1.0

    def adv(self, dt: float) -> Scn:
        self.t += dt
        return self

    def add(self, kind: str, payload: Any = None, dt: float = 0.0) -> Scn:
        self.t += dt
        self.steps.append((kind, self.t, payload))
        return self

    def down(self, data: bytes, dt: float = 0.05) -> Scn:
        return self.add("down", data, dt)

    def up(self, data: bytes, dt: float = 0.05) -> Scn:
        return self.add("up", data, dt)

    def cfg(self, **kw: Any) -> Scn:
        return self.add("cfg", kw)


def _telemetry_round(g: Gen, s: Scn, i: int, armed: bool = False, rel: float = 10.0) -> None:
    s.down(g.heartbeat(1, armed))
    s.down(g.gpi(1, rel=rel + i * 0.1, vx=3.0, hdg=0 if i % 2 else 9000))      # hdg=0 -> trimmed payload
    s.down(g.attitude(1, 0.1 * i))
    s.down(g.vfr(1) + g.gps_raw(1) + g.sys_status(1), dt=0.02)                  # several frames in one chunk


def sc_telemetry() -> Scn:
    g, s = Gen(), Scn("telemetry_normal")
    for i in range(30):
        _telemetry_round(g, s, i)
        if i % 5 == 0:
            s.up(g.heartbeat(255, compid=190))
            s.up(g.param_request(255))
    s.down(g.gpi(1, vz=0, hdg=0, vx=0.0))                                        # all-zero tail: heavily trimmed
    return s


def sc_trusted_cmds(armed: bool, name: str) -> Scn:
    g, s = Gen(), Scn(name)
    s.down(g.heartbeat(1, armed)).down(g.gpi(1, rel=40.0 if armed else 0.0, vx=6.0 if armed else 0.0))
    for sysid in (255, 254):
        s.up(g.command_long(sysid, 400, 1.0)).up(g.command_long(sysid, 22, 0.0, 0.0))
        s.up(g.command_long(sysid, 20)).up(g.command_long(sysid, 176, 1.0, 4.0))
        s.up(g.set_mode(sysid)).up(g.mission_count(sysid)).up(g.param_set(sysid))
        s.up(g.command_long(sysid, 521, 0.0)).up(g.command_int(sysid, 192))
        s.up(g.command_long(sysid, 400, 0.0))                                    # plain disarm
        s.up(g.command_long(sysid, 400, 0.0, 21196.0))                           # forced disarm
        s.up(g.rc_override(sysid)).up(g.pos_target(sysid)).up(g.mission_clear(sysid))
    return s


def sc_rogue(armed: bool, name: str) -> Scn:
    g, s = Gen(), Scn(name)
    s.down(g.heartbeat(1, armed)).down(g.gpi(1, rel=40.0 if armed else 0.0, vx=6.0 if armed else 0.0))
    s.up(g.heartbeat(255, compid=190))
    for sysid in (7, 99, 1):
        s.up(g.set_mode(sysid)).up(g.command_long(sysid, 176, 1.0, 9.0)).up(g.command_long(sysid, 21))
        s.up(g.command_long(sysid, 400, 0.0)).up(g.command_long(sysid, 400, 0.0, 21196.0))
        s.up(g.command_long(sysid, 400, 1.0)).up(g.command_long(sysid, 521)).up(g.command_int(sysid, 20))
        s.up(g.rc_override(sysid)).up(g.param_set(sysid)).up(g.mission_count(sysid)).up(g.mission_clear(sysid))
        s.up(g.pos_target(sysid)).up(g.command_long(sysid, 185, 1.0))
    s.up(g.command_long(255, 400, 0.0, 21196.0)).up(g.command_long(255, 400, 0.0))
    return s


def sc_burst() -> Scn:
    g, s = Gen(), Scn("burst_and_replay")
    s.down(g.heartbeat(1, True)).down(g.gpi(1, rel=1.0, vx=0.0))
    base = g.command_long(255, 22, 0.0, 0.0, seq=10)
    for _ in range(5):
        s.up(base, dt=0.004)                         # byte-identical burst inside cadence
    s.up(g.command_long(255, 20), dt=0.3)
    s.up(base, dt=0.3)                               # byte-identical replay later
    s.up(g.command_long(255, 22, 0.0, 0.0, seq=11), dt=0.1).up(g.command_long(255, 22, 0.0, 0.0, seq=12), dt=0.01)
    for i in range(300):                             # counter wrap: 8-bit counter goes round again
        s.up(g.command_long(255, 22, float(i % 5), 0.0, seq=(13 + i) & 0xFF), dt=0.06)
    s.up(g.command_long(255, 22, 0.0, 0.0, seq=10), dt=0.1)   # same bytes as `base` after the wrap
    s.up(base, dt=0.1)
    return s


def sc_wrap_small_memory() -> Scn:
    g, s = Gen(), Scn("replay_memory_eviction", replay_memory=8)
    s.down(g.heartbeat(1, False))
    cmds = [g.command_long(255, 22, float(i), 0.0, seq=i) for i in range(20)]
    for c in cmds:
        s.up(c, dt=0.1)
    for c in cmds[:3] + cmds[-3:] + cmds[10:14]:
        s.up(c, dt=0.1)
    return s


def sc_forgery() -> Scn:
    g, s = Gen(), Scn("counter_forgery_restart")
    s.down(g.heartbeat(1, True)).down(g.gpi(1, rel=30.0, vx=5.0))
    real = Gen()
    forger = Gen()
    for _i in range(10):                                  # real GCS learns the counter
        s.up(real.heartbeat(255, compid=190))
    s.up(real.command_long(255, 20), dt=0.1)             # consistent sensitive
    for i in range(6):                                   # forger with own counter next to the live stream
        s.up(forger.command_long(255, 176, 1.0, 5.0 + i, seq=100 + i), dt=0.1)
        s.up(real.heartbeat(255, compid=190), dt=0.1)
    s.up(forger.command_long(255, 21, seq=60), dt=0.1)   # inconsistent while armed
    s.up(real.command_long(255, 21), dt=0.1)             # genuine continues
    s.adv(5.0)                                           # GCS restart: counter restarts, quiet > 2 s
    restart = Gen()
    for _i in range(8):
        s.up(restart.heartbeat(255, compid=190), dt=0.1)
    s.up(restart.command_long(255, 20), dt=0.1)
    s.down(g.heartbeat(1, False)).down(g.gpi(1, rel=0.0, vx=0.0))   # disarmed: only suspect counts
    s.up(forger.command_long(255, 21, seq=200), dt=0.1)
    s.up(forger.command_long(255, 22, seq=201), dt=0.1)
    return s


def sc_dual(policy: str) -> Scn:
    g, s = Gen(), Scn(f"dual_transmitter_{policy}", contested_policy=policy)
    s.down(g.heartbeat(1, True)).down(g.gpi(1, rel=30.0, vx=5.0))
    a, b = Gen(), Gen()
    for _i in range(6):
        s.up(a.heartbeat(255, compid=190), dt=0.05)
    s.up(a.command_long(255, 400, 1.0, 0.0, seq=6), dt=0.05)
    s.up(b.command_long(255, 400, 1.0, 1.0, seq=6), dt=0.05)             # same seq, other payload: contested
    s.up(a.command_long(255, 20, seq=7), dt=0.05).up(a.command_long(255, 400, 0.0, 21196.0, seq=8), dt=0.05)
    s.up(a.set_mode(255, seq=9), dt=0.05)
    s.add("ack_alarms", None, 0.2)
    s.up(a.command_long(255, 21, seq=10), dt=0.05)
    s.adv(15.0)
    s.up(a.heartbeat(255, compid=190, seq=11)).up(b.heartbeat(255, compid=190, seq=11))
    s.up(a.heartbeat(255, compid=190, seq=12)).up(b.set_mode(255, seq=12))
    s.adv(70.0)
    s.up(a.command_long(255, 21, seq=13))
    return s


def sc_mav1() -> Scn:
    g, s = Gen(v1=True), Scn("mavlink1_frames")
    s.down(g.heartbeat(1, True)).down(g.gpi(1, rel=20.0, vx=4.0))
    s.down(g.attitude(1)).down(g.vfr(1))
    s.up(g.command_long(255, 400, 0.0)).up(g.command_long(7, 21)).up(g.set_mode(7)).up(g.set_mode(255))
    s.up(g.command_long(255, 22)).up(g.command_long(255, 22))
    s.up(g.heartbeat(255, compid=190))
    g2 = Gen()
    s.down(g.gpi(1, rel=21.0) + g2.heartbeat(1, True) + g.vfr(1), dt=0.01)   # mixed v1/v2 chunk
    return s


def sc_garbage() -> Scn:
    g, s = Gen(), Scn("garbage_truncated_oversized")
    rng = random.Random(4242)
    s.down(g.heartbeat(1, True)).down(g.gpi(1, rel=20.0, vx=3.0))
    good = [g.attitude(1), g.vfr(1), g.gps_raw(1), g.sys_status(1), g.gpi(1, rel=22.0)]
    s.down(bytes(rng.randrange(256) for _ in range(40)))                      # garbage only
    s.down(b"\x00\x01\x02" + good[0] + b"\xaa\xbb" + good[1])                  # garbage between frames
    s.down(good[2][:-5])                                                       # truncated tail
    s.down(good[2] + good[3][:7])                                              # whole frame + truncated
    s.down(b"\xfd\x05\x02\x00\x00\x01\x01\x00\x00\x00" + b"\x00" * 30 + good[0])   # unknown incompat flags
    s.down(b"\xfd" * 8 + good[1])
    s.down(b"\xfe" + b"\xff" * 5)                                              # oversized v1 length, truncated
    s.down(b"\xfd\xff\x00\x00\x00\x01\x01\x00\x00\x00" + b"\x00" * 100)        # oversized v2, truncated
    s.down(b"")
    s.down(b"".join(good) * 15)                                                # > 64 frames in one datagram
    s.up(b"\xfd\x00")                                                          # header incomplete
    s.up(bytes(rng.randrange(256) for _ in range(30)) + g.command_long(255, 400, 0.0))
    s.up(g.command_long(7, 21)[:-3])
    s.up(g.heartbeat(255, compid=190) * 3 + b"\xfe\x00")
    return s


def sc_sanitizer() -> Scn:
    g, s = Gen(), Scn("sanitizer_quarantine_qos_gps")
    s.down(g.heartbeat(1, True))
    s.cfg(active=True, quarantined_sysids={7}, sanitize_gps=True, sanitize_alt=True, lat_offset_deg=0.0005,
          lon_offset_deg=-0.0003, alt_bias_m=12.5)
    sg = Gen()
    for i in range(6):
        s.down(g.gpi(1, rel=30.0 + i, vx=2.0, hdg=0 if i % 2 else 100))           # rewritten (some trimmed)
        s.down(g.gpi(1, lat=0.0, lon=0.0, rel=0.0, vx=0.0))                        # near zero
    s.down(g.heartbeat(7, True) + g.gpi(7, rel=5.0))                                # quarantined sysid downlink
    s.down(signed(g.gpi(1, rel=33.0)))                                              # signed: never rewritten
    s.down(Gen(v1=True).gpi(1, rel=33.0))                                           # v1: never rewritten
    s.up(g.command_long(7, 21)).up(g.heartbeat(7, compid=190)).up(g.set_mode(255))  # quarantine uplink
    s.up(g.heartbeat(8, compid=190)).up(sg.command_long(255, 22))
    s.cfg(active=True, quarantined_sysids={1, 255}, sanitize_gps=False)             # protected sysids not quarantined
    s.down(g.gpi(1, rel=30.0)).up(g.heartbeat(255, compid=190)).up(g.heartbeat(9, compid=190))
    s.cfg(active=True, sanitize_alt=True, alt_bias_m=-4.0, rate_limit_active=True)
    for _i in range(10):
        s.down(g.attitude(1) + g.vfr(1) + g.gps_raw(1) + g.heartbeat(1, True) + g.gpi(1, rel=30.0), dt=0.01)
    s.cfg(active=True, rate_limit_active=True, sanitize_gps=True, lat_offset_deg=1e-7, lon_offset_deg=1e-7)
    for _i in range(3):
        s.down(g.gpi(1, rel=1.0, hdg=1), dt=0.4)
    s.adv(10.0)                                                                      # stale: dynamic rules lapse
    s.down(g.gpi(1, rel=30.0)).up(g.heartbeat(9, compid=190))
    s.cfg(active=False)
    s.down(g.gpi(1, rel=30.0))
    return s


def sc_flood(src: int = 9, name: str = "flood_rate_limit") -> Scn:
    """QoS shedding under a flood: frames from a non-protected source are shed, the vehicle's own are not."""
    g, s = Gen(), Scn(name)
    s.down(g.heartbeat(1, True))
    s.cfg(active=True, rate_limit_active=True)
    crit = [g.heartbeat(1, True), g.attitude(src), g.gpi(src, rel=20.0), g.command_long(255, 521)]
    other = [g.vfr(src), g.gps_raw(src), g.sys_status(src)]
    for _sec in range(3):
        for i in range(140):
            s.down(crit[i % 4] + other[i % 3], dt=0.007)
    return s


def sc_signed(key: bytes | None, variant: str, **kw: Any) -> Scn:
    g, s = Gen(), Scn(f"signed_{variant}", secret_key=key, **kw)
    s.down(g.heartbeat(1, True)).down(g.gpi(1, rel=30.0, vx=5.0))
    ts = TS0
    s.up(signed(g.command_long(255, 22), ts=ts + 100))                              # valid
    s.up(signed(g.command_long(255, 20), ts=ts + 200))                              # valid
    s.up(signed(g.command_long(255, 21), key=WRONG_KEY, ts=ts + 300))               # wrong key
    s.up(signed(g.command_long(255, 21), ts=ts + 150))                              # older ts: replayed
    s.up(g.command_long(255, 22))                                                   # unsigned trusted
    s.up(g.command_long(7, 22))                                                     # unsigned rogue
    s.up(signed(g.set_mode(255), ts=ts + 400))
    s.up(signed(g.set_mode(7), ts=ts + 500, link=1))                                # signed by key, rogue sysid
    s.up(signed(g.heartbeat(255, compid=190), ts=ts + 600))
    s.up(g.heartbeat(255, compid=190))
    s.up(signed(g.rc_override(255), ts=ts + 700) + g.heartbeat(255, compid=190))
    old = signed(g.command_long(255, 22, 1.0), ts=TS0 - 100 * 100_000)              # 100 s old: max_age
    s.up(old)
    s.up(signed(g.command_long(255, 400, 0.0, 21196.0), ts=ts + 800))
    s.up(signed(g.command_long(255, 400, 0.0), ts=ts + 900))
    s.down(signed(g.gpi(1, rel=30.0), ts=ts + 1000))
    return s


def sc_mgmt() -> Scn:
    g, s = Gen(), Scn("mgmt_alerts_actions_status", mgmt_key=MGMT_KEY, secret_key=KEY, mgmt_status_interval_s=2.0)
    s.down(g.heartbeat(1, False)).down(g.gpi(1, rel=0.0, vx=0.0))
    s.add("alert", ("GPS_SPOOFING", "CRITICAL", None))
    s.add("alert", ("GPS_SPOOFING", "CRITICAL", None), 0.1)                           # suppressed (dedupe)
    s.add("alert", ("COMMAND_INJECTION", "HIGH", 7), 0.5)
    s.add("alert", ("DOS_FLOOD", "SUSPICIOUS", 9), 0.5)
    s.add("action", ("quarantine", "sysid 7"), 0.2)
    s.add("action", ("gps_sanitize", ""), 0.2)
    for _i in range(30):
        s.down(g.heartbeat(1, False), dt=0.3)
    s.up(g.command_long(7, 21)).up(g.set_mode(7))
    ctl = MavlinkSignatureVerifier(MGMT_KEY)
    cg = Gen()
    s.adv(3.0)
    s.up(build_command_frame(MGMT_KEY, OP_STATUS_NOW, signer=ctl))
    s.up(build_command_frame(MGMT_KEY, OP_SET_POSTURE, posture=2, signer=ctl), dt=1.5)
    s.up(build_command_frame(MGMT_KEY, OP_ACK_ALARMS, signer=ctl), dt=0.3)           # rate limited
    s.up(build_command_frame(MGMT_KEY, OP_SET_POSTURE, posture=0, signer=ctl), dt=1.5)  # confirm token required
    s.up(build_command_frame(MGMT_KEY, OP_SET_POSTURE, posture=0, token=12345, signer=ctl), dt=1.5)
    s.up(build_command_frame(MGMT_KEY, OP_SET_POSTURE, posture=1, signer=ctl), dt=1.5)
    s.up(build_command_frame(MGMT_KEY, OP_SET_POSTURE, posture=9, signer=ctl), dt=1.5)  # bad param
    s.up(build_command_frame(MGMT_KEY, 77, signer=ctl), dt=1.5)                       # unsupported op
    s.up(build_command_frame(MGMT_KEY, OP_STATUS_NOW, vehicle_sysid=9, signer=ctl), dt=1.5)  # other system
    s.up(build_command_frame(WRONG_KEY, OP_STATUS_NOW), dt=1.5)                       # bad signature
    for _ in range(6):
        s.up(build_command_frame(WRONG_KEY, OP_SET_POSTURE, posture=2), dt=0.2)        # lockout
    s.up(build_command_frame(MGMT_KEY, OP_STATUS_NOW, signer=ctl), dt=1.0)            # locked out
    s.up(cg.pack(255, 190, "command_long_encode", 1, 191, 31010, 0, 3.0, 0, 0, 0, 0, 0, 0), dt=0.5)  # unsigned mgmt cmd
    s.adv(100.0)
    s.up(build_command_frame(MGMT_KEY, OP_SET_POSTURE, posture=2, signer=ctl))
    s.add("mode", ("advisory", "local"), 2.0)
    s.add("mode", ("active-ips", "local"), 0.5)
    s.up(g.command_long(7, 21), dt=0.3).up(g.set_mode(7), dt=0.0)
    s.adv(5.0)
    s.add("pump", None)
    return s


def sc_mgmt_nokey() -> Scn:
    g, s = Gen(), Scn("mgmt_no_key_unsigned", gcs_alerts=True)
    s.down(g.heartbeat(1, False))
    s.add("alert", ("DOS_FLOOD", "WATCH", None))
    s.up(build_command_frame(MGMT_KEY, OP_SET_POSTURE, posture=2), dt=1.0)           # control disabled: unsigned deny
    s.up(build_command_frame(MGMT_KEY, OP_SET_POSTURE, posture=2), dt=0.2)
    s.up(build_command_frame(MGMT_KEY, OP_STATUS_NOW), dt=2.0)
    s.add("mode", ("active-ips", "local"), 1.0)
    for _i in range(10):
        s.up(g.command_long(7, 21)).up(g.rc_override(7), dt=0.1)
    s.adv(3.0).add("pump")
    s.add("alert", ("A", "HIGH", None), 1.0)
    return s


def sc_crossend() -> Scn:
    g, s = Gen(), Scn("crossend_summary", crossend_interval_s=1.0)
    s.down(g.heartbeat(1, True))
    for i in range(6):
        s.down(g.gpi(1, rel=10.0 + i, vx=1.0), dt=0.4)
        s.add("crossend")
    s.cfg(active=True, sanitize_gps=True, lat_offset_deg=0.001, lon_offset_deg=0.001)
    s.down(g.gpi(1, rel=40.0), dt=1.5)
    s.add("crossend")
    return s


def sc_send_failures() -> Scn:
    g, s = Gen(), Scn("link_send_failures", fc_fail_every=3, gcs_fail_every=4)
    s.down(g.heartbeat(1, True)).down(g.gpi(1, rel=5.0))
    for i in range(12):
        s.down(g.attitude(1)).up(g.command_long(255, 22, float(i)), dt=0.1).up(g.heartbeat(255, compid=190))
        s.up(g.command_long(7, 21))
    s.add("alert", ("A", "CRITICAL", None))
    return s


def sc_fuzz(seed: int) -> Scn:
    rng = random.Random(seed)
    g, s = Gen(), Scn(f"fuzz_{seed}")
    sysids = [1, 255, 254, 7, 99, 255, 255, 1]
    gens = [lambda sy: g.heartbeat(sy, rng.random() < 0.5), lambda sy: g.gpi(sy, rel=rng.uniform(0, 60),
            vx=rng.uniform(0, 8), hdg=rng.choice([0, 100])), lambda sy: g.attitude(sy), lambda sy: g.vfr(sy),
            lambda sy: g.command_long(sy, rng.choice([400, 22, 20, 21, 176, 521, 180, 246, 192, 300]),
                                      rng.choice([0.0, 1.0]), rng.choice([0.0, 21196.0, 4.0])),
            lambda sy: g.set_mode(sy), lambda sy: g.rc_override(sy), lambda sy: g.param_set(sy),
            lambda sy: g.mission_count(sy), lambda sy: g.gps_raw(sy), lambda sy: g.sys_status(sy),
            lambda sy: signed(g.command_long(sy, 22), ts=TS0 + rng.randrange(1000))]
    for i in range(500):
        n = rng.choice([1, 1, 1, 2, 3])
        chunk = b"".join(rng.choice(gens)(rng.choice(sysids)) for _ in range(n))
        if rng.random() < 0.05:
            chunk = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 9))) + chunk
        if rng.random() < 0.05:
            chunk = chunk[:rng.randrange(1, len(chunk) + 1)]
        if rng.random() < 0.15:
            s.up(chunk, dt=rng.choice([0.0, 0.01, 0.3]))
        else:
            s.down(chunk, dt=rng.choice([0.0, 0.01, 0.3]))
        if i % 70 == 0:
            s.cfg(active=rng.random() < 0.8, quarantined_sysids={rng.choice([7, 99])}, sanitize_gps=rng.random() < 0.5,
                  sanitize_alt=rng.random() < 0.5, lat_offset_deg=rng.choice([0.0, 0.0004]),
                  lon_offset_deg=rng.choice([0.0, -0.0002]), alt_bias_m=rng.choice([0.0, 3.5]),
                  rate_limit_active=rng.random() < 0.3)
        if i % 160 == 99:
            s.adv(rng.choice([1.0, 5.0]))
    return s


def all_scenarios() -> list[Scn]:
    return [
        sc_telemetry(), sc_trusted_cmds(False, "trusted_cmds_ground"), sc_trusted_cmds(True, "trusted_cmds_inflight"),
        sc_rogue(False, "rogue_ground"), sc_rogue(True, "rogue_inflight"), sc_burst(), sc_wrap_small_memory(),
        sc_forgery(), sc_dual("alert"), sc_dual("drop-sensitive"), sc_mav1(), sc_garbage(), sc_sanitizer(),
        sc_flood(), sc_flood(1, "flood_vehicle_telemetry"), sc_signed(KEY, "with_key"), sc_signed(None, "no_key"),
        sc_signed(KEY, "unsigned_from_trusted_ok", allow_unsigned_from_trusted=True),
        sc_signed(KEY, "max_age", signing_max_age_s=10.0), sc_mgmt(), sc_mgmt_nokey(), sc_crossend(),
        sc_send_failures(), sc_fuzz(1), sc_fuzz(2), sc_fuzz(3),
    ]


class Clk:
    def __init__(self, t: float) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


class Link:
    """In-memory transport: ``poll`` returns what was queued, ``send`` records (and may fail every n-th call)."""

    def __init__(self, fail_every: int = 0) -> None:
        self.queue: list[tuple[int, bytes]] = []
        self.sent: list[bytes] = []
        self.calls = 0
        self.fail_every = fail_every

    def poll(self) -> list[tuple[int, bytes]]:
        out, self.queue = self.queue, []
        return out

    def send(self, data: bytes) -> bool:
        self.calls += 1
        if self.fail_every and self.calls % self.fail_every == 0:
            return False
        self.sent.append(bytes(data))
        return True

    def close(self) -> None:
        return None


def _sha(frames: list[bytes]) -> str:
    h = hashlib.sha256()
    for f in frames:
        h.update(f)
    return h.hexdigest()


def make_bridge(scn: Scn, posture: str, clk: Clk) -> tuple[InlineIpsBridge, Link, Link]:
    kw = dict(scn.kw)
    fc = Link(kw.pop("fc_fail_every", 0))
    gcs = Link(kw.pop("gcs_fail_every", 0))
    bridge = InlineIpsBridge(fc, gcs, mode=posture, clock_ns=lambda: int(clk.t * 1e9), mgmt_clock=clk, **kw)
    bridge.policy._clock = clk  # the bridge does not take a policy clock
    return bridge, fc, gcs


def apply_step(bridge: InlineIpsBridge, fc: Link, gcs: Link, clk: Clk, kind: str, t: float, payload: Any) -> None:
    clk.t = t
    stamp = int(t * 1e9)
    if kind == "up":
        gcs.queue.append((stamp, payload))
        bridge.pump_once()
    elif kind == "down":
        fc.queue.append((stamp, payload))
        bridge.pump_once()
    elif kind == "cfg":
        bridge.controller.sanitizer.configure(**payload)
        bridge.policy.touch()
    elif kind == "touch":
        bridge.policy.touch()
    elif kind == "alert":
        bridge.mgmt.alert(*payload)
    elif kind == "action":
        bridge.mgmt.action(*payload)
    elif kind == "mode":
        bridge.set_mode(*payload)
    elif kind == "ack_alarms":
        bridge.mgmt_ack_alarms()
    elif kind == "crossend":
        bridge.emit_crossend()
    elif kind == "pump":
        bridge.pump_once()
    else:
        raise ValueError(kind)


def run_bridge(scn: Scn, posture: str) -> dict[str, Any]:
    clk = Clk(T0)
    bridge, fc, gcs = make_bridge(scn, posture, clk)
    for kind, t, payload in scn.steps:
        apply_step(bridge, fc, gcs, clk, kind, t, payload)
    return record(bridge, fc, gcs)


def record(bridge: InlineIpsBridge, fc: Link, gcs: Link) -> dict[str, Any]:
    order = hashlib.sha256()
    for tag, link in ((b"F", fc), (b"G", gcs)):
        for f in link.sent:
            order.update(tag + len(f).to_bytes(2, "little") + f)
    mgmt = [f for f in gcs.sent if len(f) > 6 and f[0] == 0xFD and f[5] == 1 and f[6] in (191, 192)]
    tap = bridge.tap.poll()
    th = hashlib.sha256()
    for stamp, data in tap:
        th.update(stamp.to_bytes(8, "little") + data)
    pol = bridge.policy
    san = bridge.controller.sanitizer
    return {
        "to_fc": {"n": len(fc.sent), "sha": _sha(fc.sent)},
        "to_gcs": {"n": len(gcs.sent), "sha": _sha(gcs.sent)},
        "mgmt_frames": {"n": len(mgmt), "sha": _sha(mgmt)},
        "order": order.hexdigest(),
        "tap": {"n": len(tap), "sha": th.hexdigest()},
        "lat_samples": len(bridge._lat_us),
        "bridge": {k: getattr(bridge, k) for k in (
            "frames_down", "frames_up", "forwarded_down", "forwarded_up", "dropped_down", "dropped_up",
            "send_failures", "counter_frames_sent", "alarms_sent", "crossend_sent", "unsigned_acknowledged")},
        "policy": dict(pol.stats()),
        "policy_state": {"seen": len(pol._seen), "seq_sources": len(pol._seq), "last_cmd": len(pol._last_cmd),
                         "armed": pol.armed, "rel_alt": pol.rel_alt_m, "gs": pol.groundspeed_ms,
                         "enforce": pol.enforce, "hook_errors": pol.hook_errors,
                         "seq_state": sorted((k, t.last, t.count, t.resyncs, list(t.bad)) for k, t in pol._seq.items())},
        "sanitizer": {"dropped": san.frames_dropped, "sanitized": san.frames_sanitized, "active": san.active},
        "mgmt": bridge.mgmt.stats(),
        "mgmt_snapshot": bridge.mgmt_snapshot(),
        "mode_end": bridge.controller.mode.value,
    }


def _digest(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=repr).encode()).hexdigest()


def summarise(rec: dict[str, Any]) -> dict[str, Any]:
    return {"to_fc": rec["to_fc"]["n"], "to_gcs": rec["to_gcs"]["n"], "mgmt": rec["mgmt_frames"]["n"],
            "tap": rec["tap"]["n"], "up_sha": rec["to_fc"]["sha"][:16], "down_sha": rec["to_gcs"]["sha"][:16],
            "dropped_up": rec["bridge"]["dropped_up"], "dropped_down": rec["bridge"]["dropped_down"],
            "hook_errors": rec["policy_state"]["hook_errors"]}


# --------------------------------------------------------------------------- #
# split_frames layer
# --------------------------------------------------------------------------- #


def corpus_chunks() -> list[bytes]:
    """Every data chunk of every scenario (both directions), in order."""
    out = []
    for scn in all_scenarios():
        out.extend(p for k, _t, p in scn.steps if k in ("up", "down"))
    return out


def split_record() -> dict[str, Any]:
    chunks = corpus_chunks()
    variants = {}
    for max_frames in (64, 3, 1):
        h = hashlib.sha256()
        n_frames = n_bad = 0
        for chunk in chunks:
            frames, bad = split_frames(chunk, max_frames)
            n_bad += bad
            n_frames += len(frames)
            h.update(repr(([(f.raw, f.sysid, f.compid, f.seq, f.msgid, f.signed) for f in frames], bad)).encode())
        variants[str(max_frames)] = {"frames": n_frames, "bad": n_bad, "sha": h.hexdigest()}
    return variants


# --------------------------------------------------------------------------- #
# stream framer layer
# --------------------------------------------------------------------------- #


def framer_streams() -> dict[str, bytes]:
    g = Gen()
    rng = random.Random(777)
    base = []
    for i in range(40):
        base += [g.heartbeat(1, i % 2 == 0), g.gpi(1, rel=i, hdg=0 if i % 3 else 500), g.attitude(1), g.vfr(1),
                 g.gps_raw(1), g.sys_status(1), g.command_long(255, 400, 1.0)]
    clean = b"".join(base)
    garbage = bytearray()
    for f in base:
        garbage += bytes(rng.randrange(256) for _ in range(rng.choice([0, 0, 1, 5, 40]))) + f
    corrupt = []
    for i, f in enumerate(base):
        if i % 7 == 3:
            b = bytearray(f)
            b[rng.randrange(1, len(b))] ^= 1 << rng.randrange(8)
            f = bytes(b)
        corrupt.append(f)
    unknown = [raw_v2(60000, bytes(range(10)), extra=33), raw_v2(60000, bytes(range(12)), extra=33, bad_crc=True),
               raw_v2(60001, b"\x01\x02", extra=5), raw_v2(0, bytes(9), bad_crc=False)]
    signed_frames = [signed(f, ts=TS0 + i) for i, f in enumerate(base[:14])]
    v1 = Gen(v1=True)
    v1frames = [v1.heartbeat(1, True), v1.gpi(1, rel=3.0), v1.attitude(1), v1.command_long(255, 400, 1.0)]
    magic_in_payload = raw_v2(0, bytes([0xFD, 9, 0, 0, 0, 0xFD, 0xFE, 1, 4]))
    dense = b"\x00\xfd\x00\x02" * 120
    big = raw_v2(253, bytes(51)) + raw_v2(253, b"\x04" + b"x" * 49 + b"\x00\x00")
    trunc_then_good = base[1][:9] + b"".join(base[2:8])
    return {
        "clean": clean, "garbage": bytes(garbage), "corrupt_crc": b"".join(corrupt),
        "unknown_ids": b"".join(unknown + base[:5] + unknown), "signed": b"".join(signed_frames),
        "mavlink1": b"".join(v1frames * 5), "mixed": b"".join(base[:20] + v1frames + signed_frames[:5] + unknown),
        "magic_in_payload": magic_in_payload * 6 + b"".join(base[:6]),
        "dense_false_magic": dense + b"".join(base[:10]), "oversize_len": big * 4,
        "truncated_then_good": trunc_then_good * 5,
        "random_noise": bytes(rng.randrange(256) for _ in range(4000)) + b"".join(base[:30]),
        "bad_incompat": b"\xfd\x05\x04\x00\x00\x01\x01\x00\x00\x00" * 6 + b"".join(base[:8]),
    }


def _splits(data: bytes, mode: str) -> list[bytes]:
    if mode == "whole":
        return [data]
    if mode == "byte":
        return [data[i:i + 1] for i in range(len(data))]
    rng = random.Random(len(data) * 31 + len(mode))
    n = int(mode.split(":")[1])
    out, i = [], 0
    while i < len(data):
        k = rng.randrange(1, n + 1)
        out.append(data[i:i + k])
        i += k
    return out


FRAMER_COUNTERS = ("bytes_in", "frames_out", "garbage_bytes", "resync_events", "header_rejects", "crc_rejects",
                   "unverifiable_rejects", "unverified_accepted", "crc_bytes_checked", "partial_timeouts",
                   "unverifiable_id_overflow", "pending_bytes")


def run_framer(data: bytes, mode: str, cfg: str) -> dict[str, Any]:
    kw: dict[str, Any] = {}
    if cfg == "accept_unverified":
        kw["accept_unverified_ids"] = True
    elif cfg == "extra_crc":
        kw["extra_crc"] = {60000: 33, 60001: 5}
    fr = MavlinkStreamFramer(**kw)
    out: list[bytes] = []
    marks = []
    for i, chunk in enumerate(_splits(data, mode)):
        got = fr.feed(chunk)
        out.extend(got)
        marks.append(len(got))
        if cfg == "flush" and i % 5 == 4:
            out.extend(fr.flush_stale())
    out.extend(fr.flush_stale())
    out.extend(fr.flush_stale())
    return {"frames": len(out), "sha": _sha(out), "per_feed": hashlib.sha256(bytes(m & 0xFF for m in marks)).hexdigest(),
            "counters": {k: getattr(fr, k) for k in FRAMER_COUNTERS},
            "unverifiable_ids": sorted(fr.unverifiable_ids.items())}


def framer_records() -> dict[str, Any]:
    out = {}
    for name, data in framer_streams().items():
        for mode in ("whole", "byte", "rand:7", "rand:40", "rand:300"):
            for cfg in ("default", "accept_unverified", "extra_crc", "flush"):
                out[f"{name}|{mode}|{cfg}"] = run_framer(data, mode, cfg)
    return out


def crc_record() -> dict[str, Any]:
    rng = random.Random(99)
    h = hashlib.sha256()
    n = 0
    for ln in (0, 1, 2, 7, 33, 100, 263, 300):
        for _ in range(8):
            data = bytes(rng.randrange(256) for _ in range(ln))
            init = rng.choice([0xFFFF, 0, 0x1234, rng.randrange(65536)])
            vals = (x25_crc(data, init), _crc_x25(data, init), ref_crc(data, init))
            assert len(set(vals)) == 1, (ln, vals)
            h.update(repr(vals).encode())
            n += 1
    return {"n": n, "sha": h.hexdigest()}


# --------------------------------------------------------------------------- #
# whole fixture
# --------------------------------------------------------------------------- #


def compute() -> dict[str, Any]:
    with deterministic():
        bridge = {}
        for scn in all_scenarios():
            for posture in POSTURES:
                rec = run_bridge(scn, posture)
                bridge[f"{scn.name}|{posture}"] = {"digest": _digest(rec), "summary": summarise(rec)}
        framer = {k: {"digest": _digest(v), "frames": v["frames"]} for k, v in framer_records().items()}
        return {"version": 1, "bridge": bridge, "split_frames": split_record(), "framer": framer, "crc": crc_record()}


def main() -> int:
    check = "--check" in sys.argv
    data = compute()
    if check:
        gold = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
        ok = gold == data
        print("forwarding golden:", "MATCH" if ok else "DIFFERENT")
        return 0 if ok else 1
    GOLDEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    GOLDEN_PATH.write_text(json.dumps(data, indent=1, sort_keys=True), encoding="utf-8")
    print(f"wrote {GOLDEN_PATH} ({len(data['bridge'])} bridge cases, {len(data['framer'])} framer cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
