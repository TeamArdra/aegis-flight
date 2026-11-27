// Static, hand-quoted copy of the reference panels (Integration, Validation Evidence). Kept out of the
// component file so tests/evalCopy.test.ts can check every figure against the committed artifacts/**
// and every line against the overclaim list, without a DOM.

/** Integration panel tagline. It describes the product; it must not claim a safety property no evidence supports. */
export const INTEGRATION_TAGLINE =
  "Modular MAVLink intrusion-detection monitor with an optional inline bridge (verified in ArduCopter SITL only; not flight-validated).";

export type ValTier = "sim" | "expanded" | "sitl" | "replay";

export const TIER_LABEL: Record<ValTier, string> = {
  sim: "Simulated",
  expanded: "Expanded sim",
  sitl: "SITL",
  replay: "Replay",
};

// Every figure is quoted verbatim from the artifact named in the row (environment tag, claim class and
// what the number does NOT show are part of the row). Recall is shown next to accuracy because the
// benign decisions dominate accuracy.
export const VAL_ROWS: Array<{ tier: ValTier; metric: string; value: string }> = [
  {
    tier: "sim",
    metric: "Baseline benchmark (SIM, ML-on · artifacts/benchmarks/summary.md)",
    value: "accuracy 99.7%  ·  recall 99.0%  ·  TP/FP/TN/FN 6535 / 4 / 16826 / 65  ·  23,430 decisions  ·  link-level",
  },
  {
    tier: "expanded",
    metric: "Expanded v2 benchmark (SIM · artifacts/benchmarks_extended/summary.md)",
    value:
      "5 s grace: accuracy 97.7%, recall 88.9%  ·  no grace: accuracy 97.0%, recall 88.9%, FPR 1.1%  ·  link-level",
  },
  {
    tier: "sitl",
    metric: "PX4 SITL held-out benign flights (SITL, ML-off · artifacts/sitl/calibration/evaluation_heldout.json)",
    value:
      "PX4-calibrated profile: 1 / 2,805 false alarms  ·  uncalibrated Stage-1 config: 2,805 / 2,805  ·  false-alarm only (no attacks)",
  },
  {
    tier: "replay",
    metric: "ArduPilot ALFA replay (REPLAY, ML-off · artifacts/external/alfa_calibrated/results.json)",
    value: "Calibrated nominal-rate replay  ·  physical faults only (no cyber attacks)",
  },
];

export const VALIDATION_FOOT =
  "Reproducible results from committed artifacts/**. Benchmark CPU ~99% reflects a saturated measurement loop, " +
  "not steady-state efficiency; no embedded / Jetson figures are claimed. Not real-vehicle detection results.";
