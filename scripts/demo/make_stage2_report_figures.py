"""Report figures from files that already exist; nothing is re-run and no number is typed by hand.

    .venv/Scripts/python.exe scripts/demo/make_stage2_report_figures.py --evaluation <evaluation.json> \
        --sessions artifacts/validation/submission_rerun_20261029/extended_rerun/sessions.csv --out <dir>

Writes three PNGs:

* ``alert_timeline_SIMULATED_GPS.png``: threat score and alerts per decision on the SIMULATED GPS fixture.
* ``alert_evidence_SIMULATED_GPS.png``: the position residual the GPS_SPOOFING alerts cite, against its threshold.
* ``time_to_first_alert_by_class_SIM.png``: one dot per detected SIM session, per attack class.

Every title states the environment. None of these is flight evidence.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

INK = "#0b0b0b"
MUTED = "#52514e"
GRID = "#e4e3df"
SERIES = "#2a78d6"
ALERT = "#eb6834"
SHADE = "#f1f0ec"
CLASSES = ["gps_spoofing", "mavlink_anomaly", "command_injection", "telemetry_manipulation", "dos",
           "firmware_integrity"]
PRETTY = {"gps_spoofing": "GPS spoofing", "mavlink_anomaly": "MAVLink anomalies", "command_injection": "Command injection",
          "telemetry_manipulation": "Telemetry manipulation", "dos": "Denial of service",
          "firmware_integrity": "Firmware integrity"}
PHASES = [("NOMINAL", 0, 30), ("SLOW DRIFT", 30, 50), ("FAST DRIFT", 50, 70), ("JUMP", 70, 85), ("GNSS LOSS", 85, 105),
          ("RECOVERY", 105, 140)]


def _style(ax) -> None:
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(MUTED)
    ax.tick_params(colors=MUTED)


def _phases(ax, top: float) -> None:
    for i, (name, a, b) in enumerate(PHASES):
        if i % 2 == 1:
            ax.axvspan(a, b, color=SHADE, zorder=0)
        ax.text((a + b) / 2, top, name, ha="center", va="bottom", fontsize=8, color=MUTED)


def timeline(rows: list[dict], out: Path) -> None:
    fig, ax = plt.subplots(figsize=(9, 3.4), dpi=160)
    ax.plot([r["t"] for r in rows], [r["score"] for r in rows], color=SERIES, linewidth=1.6, label="Threat score")
    alerts = [r for r in rows if r["alert"]]
    ax.scatter([r["t"] for r in alerts], [r["score"] for r in alerts], s=42, color=ALERT, edgecolor="white", linewidth=1.2,
               zorder=3, label="Alert raised")
    ax.axhline(0.45, color=MUTED, linewidth=0.9, linestyle="--")
    ax.text(0.5, 0.47, "threat threshold 0.45", fontsize=8, color=MUTED)
    _phases(ax, 1.03)
    ax.set_xlim(0, 140)
    ax.set_ylim(0, 1.03)
    ax.set_xlabel("Fixture time (s)", color=MUTED)
    ax.set_ylabel("Threat score", color=MUTED)
    ax.legend(frameon=False, loc="center right", fontsize=8)
    _style(ax)
    fig.suptitle("Alert timeline: SIMULATED GPS fixture, never measured on a vehicle", fontsize=10, color=INK, y=1.02)
    fig.savefig(out, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def evidence(rows: list[dict], threshold: float, out: Path) -> None:
    fig, ax = plt.subplots(figsize=(9, 3.4), dpi=160)
    ax.plot([r["t"] for r in rows], [r["pos_residual_m"] for r in rows], color=SERIES, linewidth=1.6,
            label="Position residual")
    gps = [r for r in rows if r["alert"] and r["type"] == "GPS_SPOOFING"]
    ax.scatter([r["t"] for r in gps], [r["pos_residual_m"] for r in gps], s=42, color=ALERT, edgecolor="white",
               linewidth=1.2, zorder=3, label="GPS_SPOOFING alert")
    ax.axhline(threshold, color=MUTED, linewidth=0.9, linestyle="--")
    ax.text(0.5, threshold + 0.6, f"rule threshold {threshold:g} m", fontsize=8, color=MUTED)
    top = max(r["pos_residual_m"] for r in rows) * 1.08
    _phases(ax, top)
    ax.set_xlim(0, 140)
    ax.set_ylim(0, top)
    ax.set_xlabel("Fixture time (s)", color=MUTED)
    ax.set_ylabel("Residual (m)", color=MUTED)
    ax.legend(frameon=False, loc="center right", fontsize=8, bbox_to_anchor=(1.0, 0.55))
    _style(ax)
    fig.suptitle("Alert evidence: the telemetry value each alert cites (SIMULATED GPS fixture)", fontsize=10, color=INK, y=1.02)
    fig.savefig(out, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def latency(sessions: Path, out: Path) -> None:
    by_class: dict[str, list[float]] = {c: [] for c in CLASSES}
    with sessions.open(encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            key = row["key"].split(":")[0]
            if key in by_class and row["ttd_s"] not in ("", "None"):
                by_class[key].append(float(row["ttd_s"]))
    fig, ax = plt.subplots(figsize=(9, 3.2), dpi=160)
    names = list(reversed(CLASSES))
    for y, name in enumerate(names):
        vals = sorted(by_class[name])
        # same-valued sessions are spread vertically so each one stays visible
        ys = [y + (i - len(vals) / 2) * 0.03 for i in range(len(vals))]
        ax.scatter(vals, ys, s=26, color=SERIES, edgecolor="white", linewidth=0.8, zorder=3)
    ax.set_yticks(range(len(names)), [f"{PRETTY[n]} (n = {len(by_class[n])})" for n in names])
    ax.set_xlim(-0.5, 20)
    ax.set_xlabel("Time to first alert after attack onset (s); decision cadence 0.2 s; undetected sessions not shown", color=MUTED)
    _style(ax)
    ax.grid(axis="x", color=GRID, linewidth=0.8)
    ax.grid(axis="y", visible=False)
    fig.suptitle("Time to first alert per detected session, by class (SIM, extended benchmark)", fontsize=10, color=INK, y=1.0)
    fig.savefig(out, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--evaluation", type=Path, required=True)
    ap.add_argument("--sessions", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--threshold", type=float, default=12.0, help="physics.gps_pos_residual_m of the config evaluated")
    args = ap.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    rows = json.loads(args.evaluation.read_text(encoding="utf-8"))["timeline"]
    timeline(rows, args.out / "alert_timeline_SIMULATED_GPS.png")
    evidence(rows, args.threshold, args.out / "alert_evidence_SIMULATED_GPS.png")
    latency(args.sessions, args.out / "time_to_first_alert_by_class_SIM.png")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
