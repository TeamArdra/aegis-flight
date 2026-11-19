"""Run ONE live SITL proxy trial for telemetry-manipulation, firmware-identity,
or restricted-visibility command-injection scenarios (#24).

Usage:
    python scripts/sitl/run_p2_telemetry_trial.py --scenario altitude_bias --seed 1001 \\
        --out artifacts/sitl/p2t_altitude_bias_001
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from provenance import add_provenance_args, collect_run_provenance, finish_run, require_clean_tree

from aegisflight.config import load_config
from aegisflight.pipeline import IDSPipeline
from aegisflight.proxy import (
    AltitudeBiasAttack,
    BatteryJumpAttack,
    FirmwareIdentityAttack,
    FrameLogWriter,
    FrozenAttitudeAttack,
    SpeedMismatchAttack,
    build_restricted_visibility_hook,
)
from aegisflight.proxy.transport import make_udp_relay
from aegisflight.sources.mavlink_live import LiveMavlinkSource, UdpMavlinkTransport

DOWNLINK_SCENARIOS = {
    "altitude_bias": AltitudeBiasAttack,
    "speed_mismatch": SpeedMismatchAttack,
    "battery_jump": BatteryJumpAttack,
    "frozen_attitude": FrozenAttitudeAttack,
    "firmware_identity": FirmwareIdentityAttack,
}
UPLINK_SCENARIOS = (
    "rogue_force_disarm",
    "gcs_forgery_own_counter",
    "gcs_forgery_track_identity",
    "benign_pilot_control",
)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--scenario", choices=(*DOWNLINK_SCENARIOS, *UPLINK_SCENARIOS), required=True)
    ap.add_argument("--px4-host", default="127.0.0.1")
    ap.add_argument("--px4-port", type=int, default=18572)
    ap.add_argument("--relay-listen-port", type=int, default=18672)
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--trial-index", type=int, default=0)
    ap.add_argument("--seconds", type=float, default=90.0)
    ap.add_argument("--warmup-s", type=float, default=None, help="override hook warmup_s (default: hook built-in)")
    ap.add_argument("--onset-s", type=float, default=None, help="override hook onset_s (default: hook built-in)")
    ap.add_argument("--expected-sysid", type=int, default=None, help="override protocol.expected_sysids for SITL instance")
    ap.add_argument("--profile", default="configs/px4_sitl", help="load_config dir; '' for Stage-1 default")
    ap.add_argument("--px4-git-describe", default=None, help="PX4 git describe string for provenance")
    ap.add_argument("--out", required=True)
    add_provenance_args(ap)
    a = ap.parse_args(argv)

    start_state = require_clean_tree(a.allow_dirty)
    started = datetime.now(UTC).isoformat()
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    for suffix in (".frames.jsonl", ".manifest.json", ".ids_decisions.jsonl"):
        p = out.with_suffix(suffix)
        if p.exists():
            print(f"ERROR: {p} already exists; refusing to overwrite evidence", file=sys.stderr)
            return 2

    frame_log = FrameLogWriter(out.with_suffix(".frames.jsonl"))
    if a.scenario in DOWNLINK_SCENARIOS:
        kw: dict = {"frame_log": frame_log}
        if a.warmup_s is not None:
            kw["warmup_s"] = a.warmup_s
        hook = DOWNLINK_SCENARIOS[a.scenario](**kw)
        if a.onset_s is not None and hasattr(hook, "_onset_s"):
            hook._onset_s = float(a.onset_s)
        relay = make_udp_relay(a.px4_host, a.px4_port, a.relay_listen_port, down_hook=hook)
    else:
        hook = build_restricted_visibility_hook(
            a.scenario,
            seed=a.seed,
            trial_index=a.trial_index,
            warmup_s=0.0 if a.warmup_s is None else a.warmup_s,
            frame_log=frame_log,
        )
        if a.onset_s is not None and hasattr(hook, "params") and hasattr(hook.params, "onset_s"):
            hook.params.onset_s = float(a.onset_s)
        relay = make_udp_relay(
            a.px4_host,
            a.px4_port,
            a.relay_listen_port,
            up_hook=hook,
            down_hook=hook,
            mirror_uplink_to_clients=True,
        )

    relay.start()
    if not relay.wait_upstream_alive(timeout=15.0):
        relay.close()
        frame_log.close()
        print("ERROR: SITL vehicle never answered relay heartbeat within 15s", file=sys.stderr)
        return 2

    ids_transport = UdpMavlinkTransport(connect=("127.0.0.1", relay.downstream.local_address[1]), gcs_heartbeat=True)
    ids_transport.start()
    cfg = load_config(a.profile or None)
    if a.expected_sysid is not None:
        cfg.detector["protocol"]["expected_sysids"] = [int(a.expected_sysid)]
    pipe = IDSPipeline(cfg, model_path=None)
    ids_src = LiveMavlinkSource(ids_transport, sample_rate_hz=10.0, max_ticks=int(a.seconds * 10))
    n_decisions = n_threats = 0
    try:
        with open(out.with_suffix(".ids_decisions.jsonl"), "w", encoding="utf-8") as jf:
            for tick in ids_src.stream():
                asmt = pipe.process_tick(tick)
                if asmt is None:
                    continue
                n_decisions += 1
                n_threats += int(asmt.threat)
                jf.write(
                    json.dumps(
                        {
                            "t": round(asmt.t, 2),
                            "threat": bool(asmt.threat),
                            "type": asmt.attack_type.value,
                            "score": round(asmt.threat_score, 3),
                            "evidence": list(asmt.evidence),
                        }
                    )
                    + "\n"
                )
    finally:
        ids_transport.close()
        relay.close()
        frame_log.close()

    prov = finish_run(
        collect_run_provenance(
            allow_dirty=a.allow_dirty,
            profile_dir=a.profile or None,
            model_path=None,
            px4_git_describe=a.px4_git_describe,
            started_utc=started,
            start_state=start_state,
        )
    )
    out.with_suffix(".manifest.json").write_text(
        json.dumps(
            {
                "scenario": a.scenario,
                "seed": a.seed,
                "trial_index": a.trial_index,
                "frames_seen": hook.frames_seen,
                "frames_modified": getattr(hook, "frames_modified", 0),
                "frames_injected": getattr(hook, "frames_injected", 0),
                "frames_skipped_signed": getattr(hook, "frames_skipped_signed", 0),
                "frames_rewrite_failed": getattr(hook, "frames_rewrite_failed", 0),
                "vehicle_armed_observed": getattr(hook, "vehicle_armed_observed", None),
                "pre_arm_sent": getattr(hook, "pre_arm_sent", None),
                "n_decisions": n_decisions,
                "n_threats": n_threats,
                "full_provenance": prov,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
