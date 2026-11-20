"""Evaluate link-level attribution before/after semantic loss + hierarchical link-layer grouping
on fresh simulated seeds (#22)."""

from __future__ import annotations

import argparse
from dataclasses import asdict

from aegisflight.benchmark.extended import MODES, build_grid, session_config
from aegisflight.benchmark.runner import run_session
from aegisflight.config import load_config
from aegisflight.core.enums import AttackType
from aegisflight.metrics.scoring import hierarchical_link_summary

TARGET_MODES = ("mavlink_anomaly:packet_loss", "mavlink_anomaly:rate_spike", "dos:latency")


def evaluate_fresh_seeds(*, master_seed: int = 20261119, seeds_per_mode: int = 4) -> dict:
    specs = [
        s
        for s in build_grid(seeds_per_mode=seeds_per_mode, n_benign=4, combo_seeds=0, n_link=0, master_seed=master_seed)
        if s.kind == "benign" or s.key in TARGET_MODES or s.key in ("dos:flood", "dos:blackout")
    ]
    base_cfg = load_config()
    out: dict = {}
    for label, semantic in (("before", False), ("after_semantic", True)):
        mode_stats: dict[str, dict] = {}
        benign_recs = []
        atk_recs = []
        for s in specs:
            cfg = session_config(base_cfg, s)
            cfg.detector["protocol"]["semantic_link_attribution"] = semantic
            res = run_session(cfg, s.scenario, seed=s.seed, model_path=None, grace_s=5.0)
            for r in res.records:
                if r.t < 5.0 or (s.kind != "benign" and r.in_grace):
                    continue
                if s.kind == "benign":
                    benign_recs.append(r)
                else:
                    atk_recs.append((s.key, r))
                    if r.true_label is not AttackType.BENIGN:
                        st = mode_stats.setdefault(s.key, {"n": 0, "det": 0, "exact": 0, "hier": 0})
                        st["n"] += 1
                        if r.threat:
                            st["det"] += 1
                            if r.pred_label == r.true_label:
                                st["exact"] += 1
                            if hierarchical_link_summary([r.true_label], [r.pred_label])["link_layer_matched"] == 1:
                                st["hier"] += 1
        fp = sum(1 for r in benign_recs if r.threat)
        tp = sum(1 for _, r in atk_recs if r.true_label is not AttackType.BENIGN and r.threat)
        pos = sum(1 for _, r in atk_recs if r.true_label is not AttackType.BENIGN)
        out[label] = {
            "binary_recall": round(tp / pos, 4) if pos else 0.0,
            "benign_fpr": round(fp / len(benign_recs), 4) if benign_recs else 0.0,
            "modes": {
                k: {
                    "n_pos": v["n"],
                    "detected": v["det"],
                    "strict_acc": round(v["exact"] / v["det"], 4) if v["det"] else 0.0,
                    "hierarchical_acc": round(v["hier"] / v["det"], 4) if v["det"] else 0.0,
                }
                for k, v in sorted(mode_stats.items())
            },
        }
    return {
        "master_seed": master_seed,
        "modes_declared": list(MODES),
        "spec_count": len(specs),
        "sample_spec": asdict(specs[0]),
        **out,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seed", type=int, default=20261119)
    args = ap.parse_args()
    import json

    print(json.dumps(evaluate_fresh_seeds(master_seed=args.seed), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
