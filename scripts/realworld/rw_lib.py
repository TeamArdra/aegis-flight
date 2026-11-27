"""Real-flight replay harness: real tlog frames + frame-level attack injectors + a driver for the REAL InlineIpsBridge.

Evidence tier: REPLAY (offline, in-process fake links). Benign baselines are real recorded flights; attacks are INJECTED
into those recordings at MAVLink frame level and are labelled as injected, not real-world attacks. Nothing here touches RF,
a real vehicle, or a network.
"""
from __future__ import annotations

import random
import struct
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from pymavlink.dialects.v10 import ardupilotmega as mav1  # noqa: E402
from pymavlink.dialects.v20 import ardupilotmega as mav  # noqa: E402

from aegisflight.hal.inline_ips import InlineIpsBridge  # noqa: E402
from aegisflight.proxy.transport import split_frames  # noqa: E402
from aegisflight.sources.mavlink_live import frame_ticks  # noqa: E402

GCS_SYSIDS = {255, 254, 250, 190}
Frame = tuple[float, bytes, str]  # (t_s, raw, "down"|"up")


# ----------------------------------------------------------------------------- reading real logs
def read_tlog(path: str | Path, max_s: float | None = None, skip_s: float = 0.0) -> list[Frame]:
    """Raw .tlog -> [(t_s_from_first_frame, raw_frame, dir)]. 8-byte big-endian us timestamp precedes each frame."""
    data = Path(path).read_bytes()
    i, n, out, t0 = 0, len(data), [], None
    prev_t = None
    while i + 9 < n:
        ts = struct.unpack(">Q", data[i:i + 8])[0] / 1e6
        magic = data[i + 8]
        if magic == 0xFD:
            ln = 12 + data[i + 9] + (13 if data[i + 10] & 1 else 0)
        elif magic == 0xFE:
            ln = 8 + data[i + 9]
        else:
            i += 1
            continue
        if i + 8 + ln > n:
            break
        raw = data[i + 8:i + 8 + ln]
        i += 8 + ln
        if prev_t is not None and (ts < prev_t - 1.0 or ts - prev_t > 30.0):
            break  # clock jump: stop at the first continuous segment
        prev_t = ts
        if t0 is None:
            t0 = ts
        t = ts - t0
        if t < skip_s:
            continue
        if max_s is not None and t > skip_s + max_s:
            break
        sysid = raw[5] if raw[0] == 0xFD else raw[3]
        out.append((t - skip_s, raw, "up" if sysid in GCS_SYSIDS else "down"))
    return out


def motion_start(frames: list[Frame], min_speed_ms: float = 5.0, hold_s: float = 3.0) -> float | None:
    """First time the vehicle's ground speed (GLOBAL_POSITION_INT vx,vy in cm/s) stays above ``min_speed_ms`` for ``hold_s``."""
    t_hi = None
    for t, raw, d in frames:
        if d != "down" or _msgid(raw) != GPI:
            continue
        m = _decode(raw)
        if m is None:
            continue
        sp = (m.vx ** 2 + m.vy ** 2) ** 0.5 / 100.0
        if sp >= min_speed_ms:
            if t_hi is None:
                t_hi = t
            if t - t_hi >= hold_s:
                return t_hi
        else:
            t_hi = None
    return None


def _decode(raw: bytes):
    m = (mav1 if raw[0] == 0xFE else mav).MAVLink(None)
    m.robust_parsing = True
    try:
        return m.decode(bytearray(raw))
    except Exception:  # noqa: BLE001
        return None


def _repack(msg, raw: bytes, **changes) -> bytes:
    """Re-encode ``msg`` with changed fields, keeping sysid/compid/seq and the wire version of ``raw``."""
    v1 = raw[0] == 0xFE
    sysid, comp, seq = (raw[3], raw[4], raw[2]) if v1 else (raw[5], raw[6], raw[4])
    enc = (mav1 if v1 else mav).MAVLink(None, srcSystem=sysid, srcComponent=comp)
    enc.seq = seq
    for k, v in changes.items():
        setattr(msg, k, v)
    return bytes(msg.pack(enc))


def _msgid(raw: bytes) -> int:
    return raw[7] | raw[8] << 8 | raw[9] << 16 if raw[0] == 0xFD else raw[5]


def _src(raw: bytes) -> int:
    return raw[5] if raw[0] == 0xFD else raw[3]


GPI, GPS_RAW, VFR, ATT, HB, SYS = 33, 24, 74, 30, 0, 1


# ----------------------------------------------------------------------------- attack injectors
@dataclass
class Attack:
    kind: str
    params: dict = field(default_factory=dict)
    start: float = 30.0
    dur: float = 30.0
    seed: int = 0

    @property
    def name(self) -> str:
        p = "_".join(f"{k}{v}" for k, v in self.params.items())
        return f"{self.kind}[{p}]@{self.start:g}+{self.dur:g}"

    @property
    def window(self) -> tuple[float, float]:
        return self.start, self.start + self.dur


def _m_enc(sysid: int, comp: int = 190) -> mav.MAVLink:
    e = mav.MAVLink(None, srcSystem=sysid, srcComponent=comp)
    return e


def _cmd_frame(enc, kind: str, seq: int, p: dict) -> bytes:
    enc.seq = seq
    tgt = (1, 1)
    if kind == "disarm":
        m = mav.MAVLink_command_long_message(*tgt, 400, 0, 0, 21196, 0, 0, 0, 0, 0)
    elif kind == "force_arm":
        m = mav.MAVLink_command_long_message(*tgt, 400, 0, 1, 2989, 0, 0, 0, 0, 0)
    elif kind == "do_set_mode":
        m = mav.MAVLink_command_long_message(*tgt, 176, 0, 1, p.get("mode", 9), 0, 0, 0, 0, 0)
    elif kind == "set_mode_msg":
        m = mav.MAVLink_set_mode_message(1, 1, p.get("mode", 9))
    elif kind == "param_set":
        m = mav.MAVLink_param_set_message(*tgt, b"FENCE_ENABLE", 0.0, 9)
    elif kind == "rc_override":
        m = mav.MAVLink_rc_channels_override_message(*tgt, 1000, 1000, 1000, 1000, 0, 0, 0, 0)
    elif kind == "waypoint":
        m = mav.MAVLink_mission_item_int_message(*tgt, 0, 3, 16, 2, 1, 0, 0, 0, 0, int(19.0e7), int(73.0e7), 100.0, 0)
    elif kind == "takeoff":
        m = mav.MAVLink_command_long_message(*tgt, 22, 0, 0, 0, 0, 0, 0, 0, 50)
    elif kind == "land":
        m = mav.MAVLink_command_long_message(*tgt, 21, 0, 0, 0, 0, 0, 0, 0, 0)
    elif kind == "rtl":
        m = mav.MAVLink_command_long_message(*tgt, 20, 0, 0, 0, 0, 0, 0, 0, 0)
    elif kind == "reboot":
        m = mav.MAVLink_command_long_message(*tgt, 246, 0, 1, 0, 0, 0, 0, 0, 0)
    else:
        raise ValueError(kind)
    return bytes(m.pack(enc))


def inject(frames: list[Frame], atk: Attack) -> tuple[list[Frame], set[bytes]]:
    """Return (attacked frame list sorted by time, set of raw bytes of injected malicious UPLINK frames)."""
    rng = random.Random(atk.seed)
    t0, t1 = atk.window
    p = atk.params
    out: list[Frame] = []
    inj_up: set[bytes] = set()
    k = atk.kind
    frozen: dict[int, object] = {}

    def in_w(t: float) -> bool:
        return t0 <= t < t1

    # ---- uplink injections (added frames only)
    if k.startswith("cmd_"):
        kind = k[4:]
        rate = p.get("rate", 2.0)
        sysid = p.get("sysid", 66)
        enc = _m_enc(sysid)
        t, seq = t0, rng.randrange(256)
        while t < t1:
            raw = _cmd_frame(enc, kind, seq % 256, p)
            out.append((t, raw, "up"))
            inj_up.add(raw)
            seq += 1
            t += 1.0 / rate
        out.extend(frames)
        out.sort(key=lambda f: f[0])
        return out, inj_up
    if k == "gcs_replay":  # replay of a legitimate-looking GCS command with the trusted sysid, unsigned
        enc = _m_enc(255)
        raw0 = _cmd_frame(enc, p.get("cmd", "do_set_mode"), 7, {"mode": 4})
        t = t0
        while t < t1:
            out.append((t, raw0, "up"))
            inj_up.add(raw0)
            t += 1.0 / p.get("rate", 2.0)
        out.extend(frames)
        out.sort(key=lambda f: f[0])
        return out, inj_up

    seq_off = 0
    for (t, raw, d) in frames:
        mid = _msgid(raw)
        if d == "up" or not in_w(t):
            if k == "seq_scramble" and d == "down" and t >= t1 and seq_off:
                pass  # scramble only inside window
            out.append((t, raw, d))
            continue
        # ---- downlink perturbations inside the window
        if k == "gps_drift" and mid in (GPI, GPS_RAW):
            msg = _decode(raw)
            if msg is not None:
                dm = p.get("rate", 2.0) * (t - t0)
                import math
                brg = math.radians(p.get("bearing", 45))
                dlat = int(dm * math.cos(brg) / 0.0111)          # 1e-7 deg ~ 1.11 cm
                dlon = int(dm * math.sin(brg) / 0.0111)
                raw = _repack(msg, raw, lat=msg.lat + dlat, lon=msg.lon + dlon)
        elif k == "gps_offset" and mid in (GPI, GPS_RAW):
            msg = _decode(raw)
            if msg is not None:
                d_ = int(p.get("m", 100) / 0.0111)
                raw = _repack(msg, raw, lat=msg.lat + d_, lon=msg.lon)
        elif k == "gps_freeze" and mid in (GPI, GPS_RAW):
            msg = _decode(raw)
            if msg is not None:
                fz = frozen.setdefault(mid, (msg.lat, msg.lon))
                raw = _repack(msg, raw, lat=fz[0], lon=fz[1])
        elif k == "gps_jam" and mid == GPS_RAW:
            msg = _decode(raw)
            if msg is not None:
                raw = _repack(msg, raw, fix_type=0, satellites_visible=0)
        elif k == "gps_jam" and mid == GPI:
            msg = _decode(raw)
            if msg is not None:
                fz = frozen.setdefault(mid, (msg.lat, msg.lon, msg.alt))
                raw = _repack(msg, raw, lat=fz[0], lon=fz[1], vx=0, vy=0)
        elif k == "alt_bias" and mid == GPI:
            msg = _decode(raw)
            if msg is not None:
                b = int(p.get("m", 30) * 1000)
                raw = _repack(msg, raw, alt=msg.alt + b, relative_alt=msg.relative_alt + b)
        elif k == "speed_mismatch" and mid == VFR:
            msg = _decode(raw)
            if msg is not None:
                raw = _repack(msg, raw, groundspeed=msg.groundspeed + p.get("ms", 15.0))
        elif k == "battery_jump" and mid == SYS:
            msg = _decode(raw)
            if msg is not None:
                raw = _repack(msg, raw, battery_remaining=max(0, min(100, p.get("to", 5))), voltage_battery=msg.voltage_battery // 2)
        elif k == "frozen_attitude" and mid == ATT:
            msg = _decode(raw)
            if msg is not None:
                fz = frozen.setdefault(mid, msg.yaw)
                raw = _repack(msg, raw, yaw=fz)
        elif k == "rogue_sysid" and mid in (ATT, GPI, HB):
            msg = _decode(raw)
            if msg is not None:
                rs = p.get("sysid", 77)
                e = (mav1 if raw[0] == 0xFE else mav).MAVLink(None, srcSystem=rs, srcComponent=1)
                e.seq = rng.randrange(256)
                fake = bytes(msg.pack(e))
                out.append((t + 0.001, fake, "down"))
        elif k == "rate_spike":
            for j in range(int(p.get("x", 8)) - 1):
                out.append((t + 0.0005 * (j + 1), raw, "down"))
        elif k == "seq_scramble":
            v1 = raw[0] == 0xFE
            ra = bytearray(raw)
            if v1:
                ra[2] = rng.randrange(256)
            else:
                ra[4] = rng.randrange(256)
            raw = bytes(ra)  # CRC covers seq: frame becomes CRC-invalid on purpose (a corrupted-link / injection symptom)
        elif k == "packet_loss":
            if rng.random() < p.get("p", 0.3):
                continue
        elif k == "blackout":
            continue
        elif k == "latency":
            t = t + p.get("s", 1.5)
        elif k == "corrupt":
            ra = bytearray(raw)
            for _ in range(p.get("bits", 2)):
                ra[rng.randrange(len(ra))] ^= 1 << rng.randrange(8)
            raw = bytes(ra)
        out.append((t, raw, d))
    out.sort(key=lambda f: f[0])
    return out, inj_up


# ----------------------------------------------------------------------------- driving the real bridge
class Link:
    def __init__(self) -> None:
        self.inbox: list[tuple[int, bytes]] = []
        self.sent: list[bytes] = []

    def poll(self):
        o, self.inbox = self.inbox, []
        return o

    def send(self, data: bytes) -> bool:
        self.sent.append(bytes(data))
        return True

    def close(self) -> None:
        return None


class SerialLink(Link):
    """Behaves like a physical serial FC port (``may_reach_vehicle`` True)."""
    port = "/dev/ttyACM0"


@dataclass
class RunResult:
    mode: str
    alerts: list[tuple[float, str, str]]          # (t_s, attack_type, severity)
    decisions: int
    forwarded_down: int
    forwarded_up: int
    dropped_up: int
    dropped_down: int
    fc_writes_total: int                           # everything written to the FC link
    fc_writes_nonforward: int                      # written to FC that is NOT a forwarded uplink frame (counter-frames)
    counter_frames: int
    down_identical: bool                           # every downlink frame forwarded to the GCS byte-identically, in order
    up_identical: bool
    injected_up_total: int
    injected_up_delivered: int
    benign_up_total: int
    benign_up_dropped: int
    analyser_errors: int
    hook_errors: int
    exception: str | None = None
    counter_detail: list = field(default_factory=list)


def _valid(raw: bytes) -> bool:
    fr, bad = split_frames(raw)
    return bad == 0 and len(fr) == 1 and fr[0].raw == raw


def run_bridge(frames: list[Frame], mode: str, inj_up: set[bytes] | None = None, *, serial_fc: bool = False,
               config_dir: str | None = "configs/universal_flight", allow_hw: bool = False, key: bytes | None = None,
               sample_rate_hz: float = 10.0) -> RunResult:
    inj_up = inj_up or set()
    fc = SerialLink() if serial_fc else Link()
    gcs = Link()
    sim = [0.0]
    b = InlineIpsBridge(fc, gcs, mode=mode, config_dir=config_dir, secret_key=key, allow_active_on_hardware=allow_hw,
                        clock_ns=lambda: int(sim[0] * 1e9), crossend_interval_s=0.0)
    b.policy._clock = lambda: sim[0]
    alerts: list[tuple[float, str, str]] = []
    orig = b.pipeline.process_tick

    def proc(tick):
        a = orig(tick)
        if a is not None and a.is_alert:
            alerts.append((sim[0], a.attack_type.value, a.severity.value))
        return a

    b.pipeline.process_tick = proc
    sent_down: list[bytes] = []
    sent_up: list[bytes] = []
    up_all = {raw for _, raw, d in frames if d == 'up'}
    exc = None

    def feeder() -> Iterable[tuple[float, bytes]]:
        # drive the bridge, then hand the analyser exactly what the real analyser thread reads: the bridge's own tap
        # (original frames of BOTH directions, GCS-side frames wrapped as GcsSideDatagram)
        for t, raw, d in frames:
            sim[0] = t
            stamp = int(t * 1e9)
            if d == "down":
                fc.inbox.append((stamp, raw))
                sent_down.append(raw)
            else:
                gcs.inbox.append((stamp, raw))
                sent_up.append(raw)
            b.pump_once()
            for st_ns, data in b.tap.poll():
                yield (st_ns / 1e9, data)

    try:
        for tick in frame_ticks(feeder(), sample_rate_hz=sample_rate_hz):
            try:
                b.analyse_tick(tick)
            except Exception as e:  # noqa: BLE001
                b.analyser_errors += 1
                exc = repr(e)
    except Exception as e:  # noqa: BLE001
        exc = repr(e)
    # frames the bridge refuses to forward (unframeable) are counted by the transport; here frames are whole
    down_set = set(sent_down)
    fwd_up = [f for f in fc.sent if f in up_all]
    counter = b.counter_frames_sent
    delivered = sum(1 for f in fwd_up if f in inj_up)
    benign_up = [f for f in sent_up if f not in inj_up]
    up_set_delivered = {}
    for f in fwd_up:
        up_set_delivered[f] = up_set_delivered.get(f, 0) + 1
    benign_dropped = 0
    need: dict[bytes, int] = {}
    for f in benign_up:
        need[f] = need.get(f, 0) + 1
    for f, c in need.items():
        benign_dropped += max(0, c - up_set_delivered.get(f, 0))
    def _desc(f: bytes) -> str:
        m = _decode(f)
        if m is None:
            return f"msgid{_msgid(f)}"
        n = m.get_type()
        if n == "COMMAND_LONG":
            return f"COMMAND_LONG cmd={m.command} p1={m.param1:g} p2={m.param2:g}"
        if n == "SET_MODE":
            return f"SET_MODE mode={m.custom_mode}"
        if n == "STATUSTEXT":
            return "STATUSTEXT " + (m.text if isinstance(m.text, str) else bytes(m.text).decode(errors='replace'))[:40]
        return n

    counter_detail = [_desc(f) for f in fc.sent if f not in up_all]
    return RunResult(
        mode=mode, alerts=alerts, decisions=b.decisions, forwarded_down=b.forwarded_down, forwarded_up=b.forwarded_up,
        dropped_up=b.dropped_up, dropped_down=b.dropped_down, fc_writes_total=len(fc.sent),
        fc_writes_nonforward=max(0, len(fc.sent) - b.forwarded_up), counter_frames=counter,
        down_identical=([f for f in gcs.sent if f in down_set and _valid(f)] == [f for f in sent_down if _valid(f)]), up_identical=([f for f in fwd_up if _valid(f)] == [f for f in sent_up if _valid(f)]),
        injected_up_total=sum(1 for f in sent_up if f in inj_up), injected_up_delivered=delivered,
        benign_up_total=len(benign_up), benign_up_dropped=benign_dropped, analyser_errors=b.analyser_errors,
        hook_errors=b.policy.hook_errors, exception=exc, counter_detail=counter_detail)
