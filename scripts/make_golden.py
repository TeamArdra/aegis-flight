"""Bit-exact equivalence guard for the detection pipeline (golden fixture generator).

    python scripts/make_golden.py            # (re)write tests/golden/golden.json from the CURRENT code
    python scripts/make_golden.py --check    # recompute and compare, exit 1 on any difference
    python scripts/make_golden.py --add-portable   # add the rounded layers to the fixture, ONLY if every bit-exact
                                                   # digest still matches here (so they come from the same results)

``env_tag()`` names the platform; the bit-exact layers are compared only in the environments listed in the fixture's
``strict_envs`` (where they were generated or re-verified). Elsewhere the C maths library can differ in the last bit
(measured: Linux x86-64 CI changes the ``frame`` / ``detectors`` digests while ``parse`` / ``stats`` / ``assess`` match),
so the guard compares ``frame_r`` / ``detectors_r``: the same layers with floats rounded to 9 significant digits.

Every case drives ``parse -> FeatureExtractor -> 4 detectors -> fusion -> ThreatAssessment``
(through ``IDSPipeline.process_tick``) and hashes, per decision, THREE canonical serialisations:

* ``assess``    every field of the ThreatAssessment (floats via ``repr``, i.e. to the last bit) except
                ``wall_time`` / ``latency_ms`` which are wall-clock measurements, not results;
* ``frame``     every field of the FeatureFrame (incl. the snapshot, commands, sources);
* ``detectors`` every field of the four DetectorResults (score, evidence, votes, signals).

Live-style cases additionally hash the parsed MessageEnvelopes of each tick and the parser statistics.
The fixture stores one sha256 per (case, layer) plus a few human-readable expected values. Cases:
SIM sessions for every attack class / mode (``benchmark.extended.MODES``), several seeds, benign,
composites and benign link stress, and synthetic pymavlink streams for the live code paths.
Each case runs with ML off, and with ML on when ``models/isoforest.joblib`` exists. Hashes of ML cases
depend on the installed numpy / scikit-learn; regenerate only from a known-good tree.
"""

from __future__ import annotations

import enum
import hashlib
import json
import math
import random
import sys
import tempfile
from collections import defaultdict
from dataclasses import fields, is_dataclass
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from pymavlink.dialects.v10 import common as mav1  # noqa: E402
from pymavlink.dialects.v20 import ardupilotmega as apm  # noqa: E402

from aegisflight.attacks import build_attack  # noqa: E402
from aegisflight.benchmark.extended import MODES, SessionSpec, session_config  # noqa: E402
from aegisflight.config import load_config  # noqa: E402
from aegisflight.detectors.crossend import (  # noqa: E402
    MARKER_ADDRESS,
    CrossEndMonitor,
    pack_summary,
)
from aegisflight.pipeline import IDSPipeline  # noqa: E402
from aegisflight.sources.mavlink_live import LiveStats, frame_ticks  # noqa: E402
from aegisflight.sources.stream import SimulatedTelemetrySource  # noqa: E402

GOLDEN_PATH = REPO / "tests" / "golden" / "golden.json"
MODEL_PATH = REPO / "models" / "isoforest.joblib"
SIM_SEEDS = (3, 11)  # two seeds per mode (ML cases use the first only)
SIM_DURATION_S = 45.0
_SKIP = {"wall_time", "latency_ms"}


# --------------------------------------------------------------------------- #
# canonical serialisation
# --------------------------------------------------------------------------- #


def _rfloat(v: float) -> str:
    """Portable float form: 9 significant digits, |v| < 1e-9 as 0 (absorbs last-bit libm differences)."""
    if v != v or v in (float("inf"), float("-inf")):
        return repr(v)
    return "0" if abs(v) < 1e-9 else f"{v:.9g}"


def ser(x, rnd: bool = False) -> str:
    """Deterministic, type-preserving text form; floats are ``repr`` (exact round-trip), or ``_rfloat`` with ``rnd``."""
    if x is None or isinstance(x, bool | int | str):
        return repr(x)
    if isinstance(x, enum.Enum):
        return f"E<{type(x).__name__}.{x.name}={x.value!r}>"
    if isinstance(x, float):
        return _rfloat(x) if rnd else repr(x)
    if isinstance(x, np.generic):
        v = x.item()
        return f"np<{type(x).__name__}:{_rfloat(v) if rnd and isinstance(v, float) else repr(v)}>"
    if is_dataclass(x) and not isinstance(x, type):
        return (
            type(x).__name__
            + "("
            + ",".join(
                f"{f.name}={ser(getattr(x, f.name), rnd)}" for f in fields(x) if f.name not in _SKIP
            )
            + ")"
        )
    if isinstance(x, dict):
        return "{" + ",".join(f"{ser(k, rnd)}:{ser(v, rnd)}" for k, v in x.items()) + "}"
    if isinstance(x, list):
        return "[" + ",".join(ser(v, rnd) for v in x) + "]"
    if isinstance(x, tuple):
        return "(" + ",".join(ser(v, rnd) for v in x) + ")"
    if isinstance(x, set | frozenset):
        return "{" + ",".join(sorted(ser(v, rnd) for v in x)) + "}"
    if isinstance(x, bytes | bytearray):
        return "b" + bytes(x).hex()
    raise TypeError(f"unserialisable {type(x)}")


class CaseRecorder:
    """Runs a stream of ticks through a pipeline and accumulates per-layer digests."""

    def __init__(self, pipe: IDSPipeline) -> None:
        self.pipe = pipe
        self.h = {
            k: hashlib.sha256()
            for k in ("assess", "frame", "detectors", "parse", "frame_r", "detectors_r")
        }
        self.n = 0
        self.n_frames = 0
        self.threats = 0
        self.alerts = 0
        self.types: set[str] = set()
        self.last: dict = {}
        self._cur: list = []
        for name in ("protocol", "physics", "anomaly", "integrity"):
            det = getattr(pipe, name)
            orig = det.process

            def wrap(*a, _o=orig, **k):
                r = _o(*a, **k)
                self._cur.append(r)
                return r

            det.process = wrap

    def tick(self, tick) -> None:
        self.n_frames += len(tick.messages)
        self.h["parse"].update(ser((tick.t, tick.tick, tick.sig_invalid, tick.messages)).encode())
        self._cur = []
        a = self.pipe.process_tick(tick)
        if a is None:
            return
        self.n += 1
        self.h["assess"].update(ser(a).encode())
        self.h["frame"].update(ser(self.pipe.last_frame).encode())
        self.h["detectors"].update(ser(self._cur).encode())
        self.h["frame_r"].update(ser(self.pipe.last_frame, rnd=True).encode())
        self.h["detectors_r"].update(ser(self._cur, rnd=True).encode())
        self.threats += int(a.threat)
        self.alerts += int(a.is_alert)
        if a.threat:
            self.types.add(a.attack_type.value)
        self.last = {
            "t": a.t,
            "threat_score": repr(a.threat_score),
            "severity": a.severity.value,
            "attack_type": a.attack_type.value,
            "confidence": repr(a.confidence),
        }

    def result(self, extra: str = "") -> dict:
        d = {k: v.hexdigest() for k, v in self.h.items() if k != "parse" or self.n_frames}
        if extra:
            d["stats"] = hashlib.sha256(extra.encode()).hexdigest()
        return {
            "digests": d,
            "n_decisions": self.n,
            "n_messages": self.n_frames,
            "threat_decisions": self.threats,
            "alerts": self.alerts,
            "attack_types": sorted(self.types),
            "last": self.last,
        }


# --------------------------------------------------------------------------- #
# SIM cases
# --------------------------------------------------------------------------- #


def _sim_spec(idx: int, scenario: str, mode: str, seed: int, kind: str, link: dict | None = None):
    r = np.random.default_rng(seed)
    return SessionSpec(
        idx=idx,
        kind=kind,
        scenario=scenario,
        mode=mode,
        seed=seed,
        route=("survey_box", "out_and_back", "perimeter")[seed % 3],
        speed=float(r.uniform(8, 16)),
        alt=float(r.uniform(35, 90)),
        noise_scale=float(r.uniform(0.7, 1.6)),
        onset=14.0 + seed % 5,
        duration=14.0,
        offset2=4.0 if kind == "combo" else 0.0,
        link=link or {},
    )


def sim_cases() -> list[tuple[str, SessionSpec]]:
    out: list[tuple[str, SessionSpec]] = []
    i = 0
    for s in SIM_SEEDS:
        out.append((f"sim/benign/s{s}", _sim_spec(i, "benign", "", s, "benign")))
        i += 1
    for atk, modes in MODES.items():
        for m in modes:
            for s in SIM_SEEDS:
                out.append(
                    (
                        f"sim/{atk}:{m}/s{s}",
                        _sim_spec(i, atk, "" if m == "default" else m, s, "single"),
                    )
                )
                i += 1
    for combo in (
        "gps_spoofing+mavlink_anomaly",
        "gps_spoofing+command_injection",
        "dos+telemetry_manipulation",
        "telemetry_manipulation+firmware_integrity",
    ):
        out.append((f"sim/combo/{combo}", _sim_spec(i, combo, "", 5, "combo")))
        i += 1
    for kind, link in (
        ("link_fifo", {"mean_delay_ms": 25.0, "loss_prob": 0.02, "fifo": True}),
        ("link_reorder", {"mean_delay_ms": 25.0, "loss_prob": 0.02, "fifo": False}),
    ):
        out.append((f"sim/{kind}_benign/s7", _sim_spec(i, "benign", "", 7, kind, link)))
        i += 1
    return out


def run_sim_case(spec: SessionSpec, ml: bool) -> dict:
    cfg = session_config(load_config(), spec)
    cfg.simulation["duration_s"] = SIM_DURATION_S
    fw_dir = tempfile.mkdtemp(prefix="aegis_golden_fw_")
    pipe = IDSPipeline(cfg, model_path=str(MODEL_PATH) if ml else None, firmware_dir=fw_dir)
    rng = np.random.default_rng(spec.seed + 99)
    kw = {"firmware_dir": fw_dir} if "firmware_integrity" in spec.scenario.split("+") else {}
    attack = build_attack(spec.scenario, cfg.attacks, rng, **kw)
    rec = CaseRecorder(pipe)
    for tick in SimulatedTelemetrySource(cfg, attack, seed=spec.seed).stream():
        rec.tick(tick)
    return rec.result()


# --------------------------------------------------------------------------- #
# synthetic live-style streams (pymavlink bytes)
# --------------------------------------------------------------------------- #

_MAVS: dict = {}
LAT0, LON0, M_PER_DEG = 47.0, 8.0, 111194.9
HEALTHY, NOSOL = (
    0x37,
    0x87,
)  # EKF flags: att+vel+pos(abs)+vert / const-pos-mode, no horizontal position
KEY = bytes(range(32))


def pk(sysid: int, comp: int, seq: int, name: str, *args, dialect=apm) -> bytes:
    key = (dialect.__name__, sysid, comp)
    m = _MAVS.get(key)
    if m is None:
        m = _MAVS[key] = dialect.MAVLink(None, srcSystem=sysid, srcComponent=comp)
    m.seq = seq
    return bytes(getattr(m, name + "_encode")(*args).pack(m))


SCENARIOS = (
    "benign",
    "ekf_gate",
    "gps_sig",
    "mission",
    "cmds",
    "seq",
    "flood",
    "crossend",
    "crossend_keyed",
    "mgmt",
    "garbage",
    "signed",
    "spoof_drift",
    "dropout",
)


def gen_stream(scn: str, seed: int = 5, dur: float = 70.0) -> list[tuple[float, bytes]]:
    rnd = random.Random(seed)
    seqs: dict[tuple[int, int], int] = defaultdict(int)
    out: list[tuple[float, bytes]] = []
    kcos = math.cos(math.radians(LAT0))

    def send(t, sysid, comp, name, *args, seq=None, dialect=apm):
        s = seqs[(sysid, comp)] if seq is None else seq
        seqs[(sysid, comp)] = (s + 1) % 256
        out.append((t, pk(sysid, comp, s, name, *args, dialect=dialect)))

    def gpi_args(t, north, east, vx=1000, vy=0):
        return (
            int(t * 1000),
            int((LAT0 + north / M_PER_DEG) * 1e7),
            int((LON0 + east / (M_PER_DEG * kcos)) * 1e7),
            100000 + int(rnd.gauss(0, 200)),
            50000,
            vx,
            vy,
            0,
            0,
        )

    if scn == "mission":
        wps = [
            (LAT0 + 0.0, LON0),
            (LAT0 + 700 / M_PER_DEG, LON0),
            (LAT0 + 700 / M_PER_DEG, LON0 + 700 / (M_PER_DEG * kcos)),
            (LAT0, LON0 + 700 / (M_PER_DEG * kcos)),
        ]
    n = int(dur * 10)
    summaries: list[tuple] = []
    for i in range(n):
        t = round(i * 0.1, 6)
        north = 10.0 * t + rnd.gauss(0, 0.4)
        east = rnd.gauss(0, 0.4)
        vx, vy = 1000 + int(rnd.gauss(0, 15)), int(rnd.gauss(0, 15))
        if scn == "spoof_drift" and 25 <= t < 50:
            east += 0.8 * (t - 25)  # position drifts away from the reported velocity
        if scn == "mission" and t >= 30:
            east += 3.0 * (t - 30)
        nosol = scn == "ekf_gate" and 25 <= t < 45
        if nosol:
            vx, vy = 0, 0  # estimator velocity pinned while the receiver position keeps moving
        flags = NOSOL if nosol else HEALTHY
        gpi_ok = not (scn == "dropout" and 30 <= t < 40)
        hb_ok = not (scn == "dropout" and 50 <= t < 60)
        mode = 3 if scn == "mission" else 5  # ArduCopter AUTO=3, LOITER=5

        send(t, 1, 1, "attitude", int(t * 1000), 0.01 * math.sin(t), -0.02, 0.0, 0.0, 0.0, 0.0)
        if scn == "flood" and 25 <= t < 35:
            for _ in range(12):
                send(t, 1, 1, "attitude", int(t * 1000), 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
        if i % 2 == 0:
            if gpi_ok:
                a = list(gpi_args(t, north, east, vx, vy))
                summaries.append((a[0], a[1], a[2], a[3], a[4], a[5], a[6]))
                if scn.startswith("crossend") and 30 <= t < 36:
                    a[1] += 3000  # altered in transit AFTER the bridge sampled it
                send(t, 1, 1, "global_position_int", *a)
            send(t, 1, 1, "vfr_hud", 10.0, 10.0, 0, 50, 100.0, 0.0)
        if i % 5 == 0:
            sats = 14 if not (scn == "gps_sig" and 25 <= t < 30) else 6
            fix = 3 if not (scn == "gps_sig" and 50 <= t < 55) else 1
            rawvel = 1000 if not (scn == "gps_sig" and 35 <= t < 45) else 0
            if scn == "gps_sig" and 50 <= t < 55:
                sats = 0
            send(
                t,
                1,
                1,
                "gps_raw_int",
                int(t * 1e6),
                fix,
                int((LAT0 + north / M_PER_DEG) * 1e7),
                int(LON0 * 1e7),
                100000,
                90 + i % 7,
                150,
                rawvel,
                0,
                sats,
            )
        if i % 10 == 0:
            if hb_ok:
                send(t, 1, 1, "heartbeat", 2, 3, 0x80 if t > 3 else 0, mode, 4)
            send(
                t,
                1,
                1,
                "sys_status",
                0,
                0,
                0,
                300,
                12400 - int(t * 3),
                5000,
                90 - int(t / 20),
                0,
                0,
                0,
                0,
                0,
                0,
            )
            snr = (
                [40] * 14
                if scn == "gps_sig" and t >= 25
                else [30 + (k * 7) % 13 for k in range(14)]
            ) + [0] * 6
            send(
                t,
                1,
                1,
                "gps_status",
                14,
                [k + 1 for k in range(20)],
                [1] * 20,
                [45] * 20,
                [0] * 20,
                snr,
            )
            var = 1.5 if (scn == "ekf_gate" and t >= 55) else 0.3
            send(t, 1, 1, "ekf_status_report", flags, var, var / 2, 0.2, 0.1, 0.0)
        if i % 10 == 5:
            send(t, 255, 190, "heartbeat", 6, 8, 0, 0, 4)
        if scn == "mission":
            if i == 20:
                send(t, 255, 190, "mission_count", 1, 1, len(wps), 0)
                for k, (la, lo) in enumerate(wps):
                    send(
                        t,
                        255,
                        190,
                        "mission_item_int",
                        1,
                        1,
                        k,
                        6,
                        16,
                        0,
                        1,
                        0,
                        0,
                        0,
                        0,
                        int(la * 1e7),
                        int(lo * 1e7),
                        50.0,
                        0,
                    )
            if i % 10 == 3 and t > 2:
                send(t, 1, 1, "mission_current", 1)
        if scn == "cmds":
            if i == 100:
                send(t, 66, 200, "set_mode", 1, 1, 4)
            if i == 150:
                send(t, 66, 200, "command_long", 1, 1, 400, 0, 1, 0, 0, 0, 0, 0, 0)
            if i == 200:
                send(t, 255, 190, "command_long", 1, 1, 400, 0, 1, 0, 0, 0, 0, 0, 0)
            if i == 250:
                for _ in range(8):
                    send(t, 66, 200, "command_long", 1, 1, 176, 0, 1, 4, 0, 0, 0, 0, 0)
            if i == 300:
                send(t, 255, 190, "set_mode", 1, 1, 6)
            if i == 400:
                send(t, 2, 1, "command_long", 1, 1, 21, 0, 0, 0, 0, 0, 0, 0, 0)
        if scn == "seq" and i % 10 == 0:
            if 20 <= t < 22:
                seqs[(1, 1)] = (seqs[(1, 1)] + 30) % 256  # dropped frames
            if 30 <= t < 31 and out:
                out.append(out[-1])  # duplicate
            if 35 <= t < 36 and len(out) > 3:
                out[-1], out[-2] = out[-2], out[-1]  # reordered
            if 40 <= t < 41:
                seqs[(1, 1)] = rnd.randrange(256)  # scrambled
        if scn in ("crossend", "crossend_keyed") and i % 10 == 2 and t < 50 and summaries:
            key = KEY if scn == "crossend_keyed" else None
            send(t, 1, 191, "memory_vect", MARKER_ADDRESS, 1, 0, pack_summary(summaries[-1], key))
        if scn == "mgmt":
            if i % 10 == 2:
                send(t, 1, 191, "statustext", 6, b"AEGIS: status ok")
            if i % 10 == 4:
                send(t, 1, 192, "heartbeat", 18, 8, 0, 0, 4)
            if i == 300:
                send(t, 255, 190, "command_long", 1, 191, 31010, 0, 1, 0, 0, 0, 0, 0, 0)
                send(t, 1, 191, "command_ack", 31010, 0)
            if 400 <= i < 440 and i % 5 == 0:
                send(t, 1, 192, "statustext", 4, b"AEGIS: alert injected")
        if scn == "garbage" and i % 7 == 0:
            r = i % 28
            if r == 0:
                out.append((t, bytes(rnd.randrange(256) for _ in range(20))))
            elif r == 7:
                out.append((t, pk(2, 5, i % 256, "heartbeat", 1, 12, 0, 0, 4, dialect=mav1)))
            elif r == 14:
                good = pk(1, 1, seqs[(1, 1)], "attitude", 1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
                seqs[(1, 1)] = (seqs[(1, 1)] + 1) % 256
                out.append((t, good + good[:12]))  # truncated tail
                bad = bytearray(good)
                bad[-1] ^= 0xFF
                out.append((t, bytes(bad)))  # bad crc
            else:
                payload = bytes([i % 256, 2, 3])
                out.append(
                    (
                        t,
                        bytes([0xFD, 3, 0, 0, i % 256, 9, 1])
                        + (9999).to_bytes(3, "little")
                        + payload
                        + b"\xaa\xbb",
                    )
                )  # unknown id, header sane
                a = pk(1, 1, seqs[(1, 1)], "attitude", 1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
                b = pk(1, 1, (seqs[(1, 1)] + 1) % 256, "heartbeat", 2, 3, 0x80, 5, 4)
                seqs[(1, 1)] = (seqs[(1, 1)] + 2) % 256
                out.append((t, a + b))  # two frames in one datagram
    if scn == "signed":
        out = _resign(out)
    return out


def _resign(frames: list[tuple[float, bytes]]) -> list[tuple[float, bytes]]:
    """Re-encode the heartbeats of a stream signed (valid, wrong key, unsigned) for the verifying parser."""
    res = []
    m = apm.MAVLink(None, srcSystem=1, srcComponent=1)
    ts = 1_000_000
    for k, (t, data) in enumerate(frames):
        if data[0] == 0xFD and (data[7] | data[8] << 8 | data[9] << 16) == 0:  # HEARTBEAT
            m.seq = data[4]
            m.signing.sign_outgoing = True
            m.signing.link_id = 0
            m.signing.secret_key = KEY if k % 5 else bytes(32)  # every 5th with the wrong key
            ts += 7
            m.signing.timestamp = ts
            res.append((t, bytes(m.heartbeat_encode(2, 3, 0x80, 5, 4).pack(m))))
        else:
            res.append((t, data))
    return res


def run_live_case(scn: str, variant: str, ml: bool) -> dict:
    cfg = (
        load_config(REPO / "configs" / "ardupilot_copter")
        if variant == "profile"
        else load_config()
    )
    if variant == "profile":
        cfg.detector["protocol"]["auto_rate_baseline"] = True
    crossend = None
    if scn.startswith("crossend") or scn == "mgmt":
        crossend = CrossEndMonitor(KEY if scn == "crossend_keyed" else None)
    pipe = IDSPipeline(cfg, model_path=str(MODEL_PATH) if ml else None, crossend=crossend)
    stats = LiveStats()
    rec = CaseRecorder(pipe)
    frames = gen_stream(scn)
    for tick in frame_ticks(frames, 10.0, stats=stats, secret_key=KEY if scn == "signed" else None):
        rec.tick(tick)
    extra = ser(stats.as_dict())
    if crossend is not None:
        extra += ser(crossend.stats()) + ser(crossend.bad_auth) + ser(crossend.mismatches)
    return rec.result(extra)


def live_cases() -> list[tuple[str, str, str]]:
    return [(f"live/{s}/{v}", s, v) for s in SCENARIOS for v in ("profile", "default")]


# --------------------------------------------------------------------------- #
# driver
# --------------------------------------------------------------------------- #


def compute(ml: bool, only: str | None = None) -> dict[str, dict]:
    res: dict[str, dict] = {}
    for name, spec in sim_cases():
        if only and only not in name:
            continue
        if ml and name.endswith(f"/s{SIM_SEEDS[1]}"):
            continue  # ML cases: one seed per mode keeps the runtime down
        res[name] = run_sim_case(spec, ml)
    for name, scn, var in live_cases():
        if only and only not in name:
            continue
        res[name] = run_live_case(scn, var, ml)
    return res


def build_golden() -> dict:
    g = {"format": 1, "numpy": np.__version__, "ml_model_sha256": None, "no_ml": compute(False)}
    if MODEL_PATH.exists():
        g["ml_model_sha256"] = hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()
        g["ml"] = compute(True)
    return g


def env_tag() -> str:
    import platform

    return f"{platform.system()}-{platform.machine().lower()}-py{sys.version_info[0]}.{sys.version_info[1]}"


PORTABLE = ("frame_r", "detectors_r")


def main(argv: list[str]) -> int:
    if "--add-portable" in argv:
        gold = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
        bad = 0
        for key, ml in (("no_ml", False), ("ml", True)):
            if key not in gold or (ml and not MODEL_PATH.exists()):
                continue
            now = compute(ml)
            for name, want in gold[key].items():
                got = now[name]
                exact = {k: v for k, v in got["digests"].items() if k not in PORTABLE}
                same = exact == {
                    k: v for k, v in want["digests"].items() if k not in PORTABLE
                } and all(got[k] == want[k] for k in want if k != "digests")
                if not same:
                    bad += 1
                    print("MISMATCH", key, name)
                    continue
                want["digests"].update({k: got["digests"][k] for k in PORTABLE})
        if bad:
            print("not written: the bit-exact digests do not match in this environment")
            return 1
        envs = set(gold.get("strict_envs", [])) | {env_tag()}
        gold["strict_envs"] = sorted(envs)
        GOLDEN_PATH.write_text(json.dumps(gold, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        print(f"added {PORTABLE} to {GOLDEN_PATH}; strict_envs = {gold['strict_envs']}")
        return 0
    if "--check" in argv:
        gold = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
        bad = 0
        for key, ml in (("no_ml", False), ("ml", True)):
            if key not in gold or (ml and not MODEL_PATH.exists()):
                continue
            now = compute(ml)
            for name, want in gold[key].items():
                if now.get(name) != want:
                    bad += 1
                    print("MISMATCH", key, name)
        print("golden check:", "FAILED" if bad else "ok")
        return 1 if bad else 0
    g = build_golden()
    GOLDEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    GOLDEN_PATH.write_text(json.dumps(g, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    n = sum(len(g[k]) for k in ("no_ml", "ml") if k in g)
    print(f"wrote {GOLDEN_PATH} ({n} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
