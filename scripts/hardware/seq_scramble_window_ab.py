"""SIM, link-level: seq_scramble end to end through IDSPipeline, reorder_window A/B.

    python scripts/hardware/seq_scramble_window_ab.py <profile_dir_window16> <profile_dir_window48> <out.json>

Overrides attacks.mavlink_anomaly.mode to seq_scramble; 20 seeds, ML off, attack and benign sessions.
"""

import json
import sys

from aegisflight.benchmark.runner import run_session
from aegisflight.config import load_config
from aegisflight.metrics import evaluate

prof = {"w16": sys.argv[1], "w48": sys.argv[2]}
out = {}
for name, d in prof.items():
    cfg = load_config(d)
    cfg.attacks["mavlink_anomaly"]["mode"] = "seq_scramble"
    print(name, "reorder_window =", cfg.detector["features"].get("reorder_window", 16), flush=True)
    for scen in ("mavlink_anomaly", "benign"):
        rows = []
        for s in range(1, 21):
            r = run_session(cfg, scen, seed=s, route=None, model_path=None)
            sc = [x for x in r.records if x.scored]
            b = evaluate([x.true_label for x in sc], [x.pred_label for x in sc]).binary
            rows.append(
                {
                    "seed": s,
                    "ttd_s": r.time_to_detect_s,
                    "recall": b.recall,
                    "fpr": b.fpr,
                    "n": len(sc),
                }
            )
        out[f"{name}/{scen}"] = rows
        det = [x for x in rows if x["ttd_s"] is not None]
        print(
            f"  {scen:20s} detected {len(det)}/20; mean ttd "
            f"{(sum(x['ttd_s'] for x in det) / len(det)) if det else float('nan'):.2f}s; "
            f"mean recall {sum(x['recall'] for x in rows) / 20:.3f}; mean FPR {sum(x['fpr'] for x in rows) / 20:.4f}",
            flush=True,
        )
json.dump(out, open(sys.argv[3], "w"), indent=1)
