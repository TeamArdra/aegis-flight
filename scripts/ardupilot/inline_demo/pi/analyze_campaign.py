# ruff: noqa  (bench script: quick one-off driver, not library code)
"""Per-event outcome table for the campaign runs. usage: analyze_campaign.py <label> [<label> ...]   (env REPO for the hub capture reader)"""

import bisect
import json
import os
import re
import sys

KEYS = {
    "forged_land": ("COMMAND_INJECTION", "blocked", "unsigned", "quarantine", "MAVLINK_ANOMALY"),
    "forged_force_disarm": (
        "COMMAND_INJECTION",
        "blocked",
        "unsigned",
        "DISARM",
        "quarantine",
        "MAVLINK_ANOMALY",
    ),
    "forged_rtl_spoof255": (
        "COMMAND_INJECTION",
        "blocked",
        "unsigned",
        "quarantine",
        "MAVLINK_ANOMALY",
    ),
    "wrong_key_land": ("bad-signature", "blocked"),
    "spoof255_land": ("COMMAND_INJECTION", "blocked", "quarantine", "MAVLINK_ANOMALY"),
    "replay_loiter": ("replay", "blocked"),
    "flood": ("DOS", "rate_limit", "quarantine", "MAVLINK_ANOMALY", "blocked HEARTBEAT"),
    "gps_glitch": ("GPS_SPOOFING", "GPS unreliable", "ALT_HOLD", "sanitize_gps"),
    "alt_bias": ("TELEMETRY_MANIPULATION", "sanitize_alt", "unsigned down", "blocked down"),
    "batt_jump": ("TELEMETRY_MANIPULATION", "unsigned down", "blocked down"),
    "freeze": ("TELEMETRY_MANIPULATION", "unsigned down", "blocked down"),
    "fw_tamper": ("FIRMWARE_INTEGRITY", "escalation"),
}
# MAVLink 2 STATUSTEXT (msgid 253 = fd 00 00): fd, len, incompat flags (0 or 1 = signed), compat, seq, sysid, compid, fd 00 00
STATUSTEXT = re.compile(rb"\xfd(.)[\x00\x01]\x00.(.)(.)\xfd\x00\x00", re.S)


def capture_texts(label, c):
    """AEGIS STATUSTEXTs recovered from the radio hub's downlink capture (times: seconds on the campaign clock)."""
    sys.path.insert(0, os.environ.get("REPO", "") + "/scripts/radio_test")
    from radio_hub import read_capture

    buf, offs = b"", []
    for t, d in read_capture(f"C:/afsitl/hubcap_{label}/downlink.cap"):
        offs.append((len(buf), t))
        buf += d
    starts = [o for o, _ in offs]
    out = []
    for m in STATUSTEXT.finditer(buf):
        n = m.group(1)[0]
        payload = buf[m.end() : m.end() + n]
        if len(payload) < 2:
            continue
        text = payload[1:51].split(b"\x00")[0].decode("ascii", "replace")
        if text.startswith("AEGIS"):
            i = bisect.bisect_right(starts, m.start()) - 1
            out.append((round(offs[i][1] - c["t0"], 1), text))
    return out


for label in sys.argv[1:]:
    c = json.load(open(f"C:/afsitl/campaign_{label}.json"))
    tpath = f"C:/afsitl/texts_{label}.json"
    if os.path.exists(tpath):
        texts = json.load(open(tpath))
        off = texts["t0"] - c["t0"]  # watcher clock minus campaign clock
    else:
        texts = {"t0": c["t0"], "texts": capture_texts(label, c), "modes": []}
        off = 0.0
    s = json.load(open(f"C:/afsitl/status_{label}.json"))
    print(
        f"\n=== {label}  posture={c['posture']}  seed={c['seed']}  probes={c['probes']}  hb_gaps={c['heartbeat_gaps_over_3s']}  recoveries={[(r['t'], r['ok'], r['took_s']) for r in c['recoveries']]}"
    )
    print(
        f"    bridge: dropped_up={s['frames']['dropped_up']} dropped_down={s['frames']['dropped_down']} counter_frames={s['analyser']['counter_frames_sent']} "
        f"alerts={s['analyser']['alerts']} errors={s['analyser']['errors']} signing_observed={s.get('signing_observed')} rewritten={s['policy'].get('rewritten')}"
    )
    print(f"    ground-side AEGIS texts recovered: {len(texts['texts'])}")
    for e in c["events"]:
        b = e["before"]
        f = e.get("final") or {}
        t1 = e["t_start"] + 30
        win = [x[1] for x in texts["texts"] if e["t_start"] - 1 <= x[0] + off <= t1]
        hit = sorted({k for k in KEYS[e["event"]] if any(k in w for w in win)})

        def d(k):
            return (f.get(k) or 0) - (b.get(k) or 0)

        print(
            f"  {e['t_start']:6.1f} {e['event']:20s} mode {e['mode_before']}->{e.get('mode_after')} alt {round(e['alt_before'])}->{round(e.get('alt_after', 0))} | "
            f"d_alerts={d('alerts')} d_drop_up={d('dropped_up')} d_counter={d('counter_frames')} d_rewritten={d('rewritten')} | announced: {hit or 'NONE'}"
        )
