"""Summarise a rw_campaign results.jsonl into markdown + a machine-readable json."""
from __future__ import annotations

import collections
import json
import statistics
import sys
from pathlib import Path

MODES = ("passive", "advisory", "active-ips")


def family(kind: str) -> str:
    if kind.startswith("cmd_") or kind == "gcs_replay":
        return "command_injection(uplink)"
    return {"gps_offset": "gps_spoofing", "gps_drift": "gps_spoofing", "gps_freeze": "gps_spoofing", "gps_jam": "gnss_jamming",
            "alt_bias": "telemetry_manipulation", "speed_mismatch": "telemetry_manipulation",
            "battery_jump": "telemetry_manipulation", "frozen_attitude": "telemetry_manipulation",
            "rogue_sysid": "mavlink_anomaly", "seq_scramble": "mavlink_anomaly", "corrupt": "mavlink_anomaly",
            "rate_spike": "dos", "packet_loss": "dos", "blackout": "dos", "latency": "dos"}.get(kind, kind)


def main(path: str, out_md: str) -> None:
    recs = [json.loads(line) for line in open(path)]
    benign = [x for x in recs if x["kind"] == "benign"]
    attacks = [x for x in recs if x["kind"] != "benign"]
    L: list[str] = []
    res: dict = {"benign_flights": len(benign), "attack_runs": len(attacks) * 3}
    errs = [(x["attack"], m, v["error"]) for x in recs for m, v in x["runs"].items() if "error" in v]
    L.append(f"# Real-flight replay campaign summary\n\nTier: REPLAY. {len(benign)} real ALFA flights as benign controls, "
             f"{len(attacks)} injected-attack scenarios x 3 postures = {len(attacks) * 3} attack runs. "
             f"Runtime errors: {len(errs)}.\n")
    # ---- invariants
    viol = collections.Counter()
    viol_examples: dict[str, list] = collections.defaultdict(list)
    for x in recs:
        for m in ("passive", "advisory"):
            v = x["runs"].get(m)
            if not v or "error" in v:
                continue
            for k, bad in (("up_not_identical", not v["up_identical"]), ("down_not_identical", not v["down_identical"]),
                           ("counter_frames", v["counter_frames"] > 0), ("fc_nonforward_writes", v["fc_writes_nonforward"] > 0),
                           ("dropped_frames", v["dropped_up"] + v["dropped_down"] > 0)):
                if bad:
                    viol[f"{m}:{k}"] += 1
                    if len(viol_examples[f"{m}:{k}"]) < 3:
                        viol_examples[f"{m}:{k}"].append(x["attack"] + " " + Path(x["flight"]).parts[-2])
    exc = [(x["attack"], m, v["exception"]) for x in recs for m, v in x["runs"].items() if v.get("exception")]
    ae = sum(v.get("analyser_errors", 0) for x in recs for v in x["runs"].values() if "error" not in v)
    he = sum(v.get("hook_errors", 0) for x in recs for v in x["runs"].values() if "error" not in v)
    L.append("## 1. Mode separation invariants (passive / advisory must never alter, drop, or write to the FC)\n")
    L.append(f"Runs checked per mode: {len(recs)}. Violations: **{sum(viol.values())}**. {dict(viol) or 'none'}. "
             f"Examples: {dict(viol_examples) or 'n/a'}. Analyser errors {ae}, hook errors {he}, harness exceptions {len(exc)}.\n")
    res["invariant_violations"] = dict(viol)
    # ---- benign
    L.append("## 2. Benign real flights (false alarms / false drops)\n")
    L.append("| mode | flights | flights with >=1 alert | total alerts | active-ips false drops (up/down) | counter-frames on benign |\n|---|---|---|---|---|---|")
    for m in MODES:
        runs = [x["runs"][m] for x in benign if m in x["runs"] and "error" not in x["runs"][m]]
        fa = sum(1 for v in runs if v["alerts"])
        L.append(f"| {m} | {len(runs)} | {fa} | {sum(len(v['alerts']) for v in runs)} | "
                 f"{sum(v['dropped_up'] for v in runs)}/{sum(v['dropped_down'] for v in runs)} | {sum(v['counter_frames'] for v in runs)} |")
    flagged = [(Path(x["flight"]).parts[-3] + "/" + Path(x["flight"]).parts[-2], collections.Counter(a[1] for a in x["runs"]["passive"]["alerts"]))
               for x in benign if x["runs"]["passive"]["alerts"]]
    L.append("\nFlights with alerts (passive; may include real physical faults, not only false alarms): "
             + "; ".join(f"{f}: {dict(c)}" for f, c in flagged[:30]) + "\n")
    res["benign_flagged"] = [(f, dict(c)) for f, c in flagged]
    # ---- per family / kind
    L.append("## 3. Injected attacks: detection by family and posture\n")
    L.append("Detected = at least one IDS alert inside [attack start, attack end + 5 s]. FP = alerts outside that window on the same flight.\n")
    fam: dict = collections.defaultdict(lambda: collections.defaultdict(list))
    kinds: dict = collections.defaultdict(lambda: collections.defaultdict(list))
    undetected: dict[str, list] = collections.defaultdict(list)
    for x in attacks:
        t0, t1 = x["window"]
        for m in MODES:
            v = x["runs"].get(m)
            if not v or "error" in v:
                continue
            inw = [a for a in v["alerts"] if t0 <= a[0] <= t1 + 5]
            outw = [a for a in v["alerts"] if not (t0 <= a[0] <= t1 + 5)]
            rec = {"det": bool(inw), "delay": (inw[0][0] - t0) if inw else None, "fp": len(outw),
                   "inj_total": v["injected_up_total"], "inj_deliv": v["injected_up_delivered"],
                   "benign_up_dropped": v["benign_up_dropped"], "benign_up_total": v["benign_up_total"],
                   "ctr": v["counter_frames"]}
            fam[family(x["kind"])][m].append(rec)
            kinds[x["kind"]][m].append(rec)
            if m == "passive" and not inw:
                undetected[x["kind"]].append(x["attack"])

    def row(name, d):
        cells = []
        for m in MODES:
            rs = d[m]
            if not rs:
                cells.append("-")
                continue
            det = sum(1 for q in rs if q["det"])
            dl = [q["delay"] for q in rs if q["delay"] is not None]
            s = f"{det}/{len(rs)} ({100 * det / len(rs):.0f}%)"
            if dl:
                s += f", median delay {statistics.median(dl):.1f}s"
            cells.append(s)
        return f"| {name} | " + " | ".join(cells) + " |"

    L.append("| family | passive | advisory | active-ips |\n|---|---|---|---|")
    for f in sorted(fam):
        L.append(row(f, fam[f]))
    L.append("\n| attack kind | passive | advisory | active-ips |\n|---|---|---|---|")
    for k in sorted(kinds):
        L.append(row(k, kinds[k]))
    res["family"] = {f: {m: [sum(1 for q in fam[f][m] if q["det"]), len(fam[f][m])] for m in MODES} for f in fam}
    # ---- uplink
    L.append("\n## 4. Uplink command injection: injected frames that reached the flight controller\n")
    L.append("| kind | passive delivered | advisory delivered | active-ips delivered | active benign-uplink false drops |\n|---|---|---|---|---|")
    for k in sorted(kinds):
        if not (k.startswith("cmd_") or k == "gcs_replay"):
            continue
        cells = []
        for m in MODES:
            rs = kinds[k][m]
            t = sum(q["inj_total"] for q in rs)
            d = sum(q["inj_deliv"] for q in rs)
            cells.append(f"{d}/{t}")
        bd = sum(q["benign_up_dropped"] for q in kinds[k]["active-ips"])
        L.append(f"| {k} | " + " | ".join(cells) + f" | {bd} |")
    # ---- FP in attack runs
    fps = {m: sum(q["fp"] for f in fam for q in fam[f][m]) for m in MODES}
    L.append(f"\nAlerts outside the attack windows on attacked flights (includes lingering post-attack alerts): {fps}\n")
    # ---- undetected
    L.append("## 5. Variants NOT detected by the IDS (passive)\n")
    for k, v in sorted(undetected.items()):
        L.append(f"- **{k}** ({len(v)}): " + ", ".join(sorted({a.split('@')[0] for a in v})))
    res["undetected"] = {k: sorted({a.split('@')[0] for a in v}) for k, v in undetected.items()}
    Path(out_md).write_text("\n".join(L), encoding="utf-8")
    Path(out_md).with_suffix(".json").write_text(json.dumps(res, indent=1), encoding="utf-8")
    print("\n".join(L))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
