"""Software replay of the signed-link detection gap (campaign batch 6), no hardware needed.

Drives the REAL InlineIpsBridge (its threads, tap, signing-aware analyser and detectors) with an unsigned ArduPilot-style downlink
shaped like the bench: HEARTBEAT 1 Hz, SYS_STATUS 1 Hz, GLOBAL_POSITION_INT, GPS_RAW_INT, VFR_HUD and ATTITUDE 2 Hz (the two streams the
campaign requested, plus the barometric altitude the GPS altitude is checked against), a stationary disarmed vehicle with a healthy GPS fix. After WARMUP_S a +40 m altitude bias is applied to
GLOBAL_POSITION_INT, as `px_fc_proxy.py alt_bias 40` does on the real link. Three arms, n runs each, one seed per run:

  unsigned       no signing key
  signed-fixed   signing key, the bridge as it is now (vehicle sysids may be unsigned)
  signed-before  signing key, the analyser built without unsigned_allowed_sysids (the behaviour before the fix)

The vehicle stream is synthetic (shaped by the real bench's message set and rates); the bridge, parser and detectors are the real ones. This
is a software replay, not a bench or field result.

usage: signed_downlink_replay.py ARM N OUT.json     (ARM: unsigned | signed-fixed | signed-before)"""

from __future__ import annotations

import json
import os
import random
import sys
import threading
import time

os.environ.setdefault("MAVLINK20", "1")

from pymavlink.dialects.v20 import common as mv  # noqa: E402

import aegisflight.hal.inline_ips as ips  # noqa: E402
from aegisflight.hal.inline_ips import InlineIpsBridge  # noqa: E402

KEY = bytes(range(32))
WARMUP_S = 10.0
ATTACK_S = 8.0
BIAS_M = 40.0


class _Sink:
    def __init__(self) -> None:
        self.buf = b""

    def write(self, data: bytes) -> None:
        self.buf += bytes(data)

    def take(self) -> bytes:
        out, self.buf = self.buf, b""
        return out


class _Link:
    def __init__(self) -> None:
        self.inbox: list[tuple[int, bytes]] = []
        self.sent: list[bytes] = []
        self.lock = threading.Lock()

    def feed(self, data: bytes) -> None:
        with self.lock:
            self.inbox.append((time.monotonic_ns(), data))

    def poll(self):  # type: ignore[no-untyped-def]
        with self.lock:
            out, self.inbox = self.inbox, []
        return out

    def send(self, data: bytes) -> bool:
        self.sent.append(bytes(data))
        return True

    def close(self) -> None:
        return None


class _Store:
    def __init__(self) -> None:
        self.events: list[tuple[float, str, str]] = []

    def log_event(self, assessment, run_id):  # type: ignore[no-untyped-def]
        self.events.append((time.monotonic(), assessment.attack_type.value, assessment.severity.value))


def _one_run(arm: str, seed: int) -> dict:
    rng = random.Random(seed)
    key = None if arm == "unsigned" else KEY
    if arm == "signed-before":
        real = ips.LiveMavlinkSource

        def old_source(*a, **kw):  # type: ignore[no-untyped-def]
            kw.pop("unsigned_allowed_sysids", None)
            return real(*a, **kw)

        ips.LiveMavlinkSource = old_source  # type: ignore[assignment]
    fc, gcs, store = _Link(), _Link(), _Store()
    bridge = InlineIpsBridge(fc, gcs, mode="passive", secret_key=key, store=store)
    sink = _Sink()
    enc = mv.MAVLink(sink, srcSystem=1, srcComponent=1)
    t_attack: float | None = None
    try:
        bridge.start()
        t0 = time.monotonic()
        step = 0
        while True:
            now = time.monotonic() - t0
            if now >= WARMUP_S + ATTACK_S:
                break
            if t_attack is None and now >= WARMUP_S:
                t_attack = time.monotonic()
            bias = BIAS_M if t_attack is not None else 0.0
            ms = int(now * 1000)
            if step % 2 == 0:  # 2 Hz position streams
                alt = 100_000 + rng.randint(-300, 300)
                enc.global_position_int_send(ms, 190_000_000 + rng.randint(-20, 20), 729_000_000 + rng.randint(-20, 20),
                                             alt + int(bias * 1000), int(bias * 1000) + rng.randint(-150, 150), 0, 0, 0, 0)
                enc.gps_raw_int_send(ms * 1000, 3, 190_000_000, 729_000_000, alt, 90, 120, 0, 0, 10)
                # the barometric altitude (VFR_HUD.alt) is what the GPS altitude is cross-checked against; the bias is applied
                # to the GPS-derived GLOBAL_POSITION_INT only, as the proxy does
                enc.vfr_hud_send(0.0, 0.0, 90, 0, 100.0 + rng.uniform(-0.2, 0.2), 0.0)
                enc.attitude_send(ms, rng.uniform(-0.002, 0.002), rng.uniform(-0.002, 0.002), 1.5708 + rng.uniform(-0.002, 0.002),
                                  0.0, 0.0, 0.0)
            if step % 4 == 0:  # 1 Hz
                enc.heartbeat_send(2, 3, 81, 0, 4)
                enc.sys_status_send(0, 0, 0, 300, 15_100 + rng.randint(-10, 10), -1, 90, 0, 0, 0, 0, 0, 0)
            data = sink.take()
            if data:
                fc.feed(data)
            step += 1
            time.sleep(0.25)
    finally:
        bridge.close()
        if arm == "signed-before":
            ips.LiveMavlinkSource = real  # type: ignore[assignment]
    st = bridge.status()
    pre = [e for e in store.events if t_attack is not None and e[0] < t_attack]
    post = [e for e in store.events if t_attack is not None and e[0] >= t_attack]
    manip = [e for e in post if e[1] == "TELEMETRY_MANIPULATION"]
    return {
        "seed": seed, "decisions": st["analyser"]["decisions"], "alerts_before_attack": len(pre),
        "alert_kinds_after": sorted({e[1] for e in post}),
        "detected": bool(manip), "first_manipulation_s": round(manip[0][0] - t_attack, 2) if manip else None,
        "forwarded_down": st["frames"]["forwarded_down"], "analyser_errors": st["analyser"]["errors"],
    }


def main() -> None:
    arm, n, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    runs = [_one_run(arm, 1000 + i) for i in range(n)]
    det = [r for r in runs if r["detected"]]
    lat = sorted(r["first_manipulation_s"] for r in det)
    res = {"arm": arm, "n": n, "detected": len(det), "false_alerts_before_attack_total": sum(r["alerts_before_attack"] for r in runs),
           "latency_s_median": lat[len(lat) // 2] if lat else None, "latency_s_max": lat[-1] if lat else None, "runs": runs}
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=1)
    print(f"{arm}: detected {len(det)}/{n}, false alerts before the attack {res['false_alerts_before_attack_total']}, "
          f"latency median {res['latency_s_median']} s, max {res['latency_s_max']} s")


if __name__ == "__main__":
    main()
