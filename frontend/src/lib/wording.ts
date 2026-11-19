// Pure, evidence-bounded wording for the threat card and the defense panel (frontend/tests/wording.test.ts).
// Rule: say what the vehicle state and the evidence support, nothing more. BENCH and SITL results are not
// flight validation; no counter-action is described as having succeeded.
import type { DefenseMode, Environment, MitigationState, Telemetry } from "../types";

/** Groundspeed below this (m/s) counts as "not moving" for the threat card. */
export const MOVING_GS_MS = 0.5;

/** Quiet (no-threat) line of the threat card, from the reported armed state and groundspeed. */
export function quietThreatText(tele: Pick<Telemetry, "armed" | "groundspeed"> | null | undefined): string {
  const armed = tele?.armed;
  const gs = tele?.groundspeed;
  const known = typeof gs === "number" && !Number.isNaN(gs);
  if (armed === false) {
    return known && gs < MOVING_GS_MS ? "On ground · disarmed · no active threat" : "Disarmed · no active threat";
  }
  if (armed === true) {
    return known && gs >= MOVING_GS_MS ? "No active threat · nominal flight" : "Armed · no active threat";
  }
  return "No active threat";
}

export interface ModeOption { id: DefenseMode; label: string; desc: string }

export const MODE_OPTIONS: ModeOption[] = [
  { id: "passive", label: "PASSIVE", desc: "IDS only · nothing sent to the flight controller" },
  { id: "advisory", label: "ADVISORY", desc: "Alerts to the GCS only · nothing sent to the flight controller" },
  { id: "active-ips", label: "ACTIVE IPS", desc: "Drops hostile frames, may send counter-commands · verified in ArduCopter SITL only" },
];

export interface PostureBanner { cls: string; title: string; desc: string; badge: string }

const pretty = (attack: string | null | undefined): string => (attack || "intrusion").replace(/_/g, " ");

/** Factual posture statement for the banner at the top of the defense panel. */
export function postureBanner(
  mode: DefenseMode,
  attackActive: boolean,
  attackType?: string | null,
  environment?: Environment | null,
): PostureBanner {
  const sim = environment === "SIM";
  if (mode === "active-ips") {
    const scope = sim
      ? "Simulated: the twin models the inline bridge's frame drops and counter-commands; nothing is wired."
      : "Refused on a serial (physical) flight-controller link. The sidecar counter-command path failed in SITL (the vehicle landed).";
    if (attackActive) {
      return {
        cls: "res-resisting",
        title: `ACTIVE IPS: ${pretty(attackType)} detected`,
        desc: `Enforcement rules are engaged; the action timeline lists what was dropped or sent. Not flight-validated. ${scope}`,
        badge: "DETECTED",
      };
    }
    return {
      cls: "res-nominal",
      title: "ACTIVE IPS (verified in ArduCopter SITL only)",
      desc: `The inline bridge drops hostile frames. Not flight-validated. ${scope}`,
      badge: "ACTIVE IPS",
    };
  }
  if (mode === "advisory") {
    if (attackActive) {
      return {
        cls: "res-advisory",
        title: `ADVISORY: ${pretty(attackType)} detected`,
        desc: "Alert raised for the GCS. Nothing is sent to the flight controller; no frame is dropped or changed.",
        badge: "DETECTED",
      };
    }
    return {
      cls: "res-nominal",
      title: "ADVISORY: monitoring, alerts to the GCS only",
      desc: "Nothing is sent to the flight controller; no frame is dropped or changed.",
      badge: "ADVISORY",
    };
  }
  if (attackActive) {
    return {
      cls: "res-passive",
      title: `PASSIVE: ${pretty(attackType)} detected, no counter-action`,
      desc: "Reported only. Nothing is sent to the flight controller. Only ACTIVE IPS drops frames or sends counter-commands.",
      badge: "DETECTED",
    };
  }
  return {
    cls: "res-nominal",
    title: "PASSIVE: monitoring, nothing transmitted to the flight controller",
    desc: "The IDS reports only: no counter-command, no frame drop, no sanitization.",
    badge: "PASSIVE",
  };
}

export interface LadderState { id: MitigationState; label: string; color: string; desc: string }

/** The 4-state escalation ladder; the descriptions say what the state means, not what it achieved. */
export function ladderStates(mode: DefenseMode): LadderState[] {
  if (mode === "passive") {
    return [
      { id: "NOMINAL", label: "NOMINAL", color: "var(--ok)", desc: "No active threat · stream monitored" },
      { id: "AUTO_MITIGATING", label: "INTRUSION DETECTED", color: "var(--warn)", desc: "Anomaly reported · nothing sent to the flight controller" },
      { id: "SAFE_HOLD", label: "SUSTAINED ANOMALY", color: "#f97316", desc: "Anomaly persists >30 s · high-priority IDS alert" },
      { id: "GCS_TAKEOVER", label: "CRITICAL INTEGRITY ALERT", color: "var(--crit)", desc: "Firmware / safety integrity alert · operator attention" },
    ];
  }
  if (mode === "advisory") {
    return [
      { id: "NOMINAL", label: "NOMINAL", color: "var(--ok)", desc: "No active threat · advisory standby" },
      { id: "AUTO_MITIGATING", label: "ADVISORY ALERTING", color: "var(--warn)", desc: "Alert raised for the GCS" },
      { id: "SAFE_HOLD", label: "HOLD RECOMMENDED", color: "#f97316", desc: "Anomaly persists >30 s · pilot may switch to ALT_HOLD" },
      { id: "GCS_TAKEOVER", label: "PILOT TAKEOVER URGENT", color: "var(--crit)", desc: "Critical integrity alert · manual control advised" },
    ];
  }
  return [
    { id: "NOMINAL", label: "NOMINAL", color: "var(--ok)", desc: "No active threat · rules idle" },
    { id: "AUTO_MITIGATING", label: "AUTO MITIGATING", color: "var(--warn)", desc: "Enforcement rules engaged" },
    { id: "SAFE_HOLD", label: "SAFE HOLD", color: "#f97316", desc: "Sustained conflict · ALT_HOLD requested" },
    { id: "GCS_TAKEOVER", label: "GCS TAKEOVER", color: "var(--crit)", desc: "Pilot control required" },
  ];
}

/** Fallback for the summary bar when the backend sends no summary. */
export function summaryFallback(mode: DefenseMode): string {
  if (mode === "passive") return "Passive IDS monitoring";
  if (mode === "advisory") return "Advisory monitoring";
  return "ACTIVE IPS: no action taken";
}

/** Standing limitations shown under the posture banner (sources: docs/INLINE_IPS.md,
 *  docs/VEHICLE_UPLINK_FILTER.md, src/aegisflight/hal/topology_status.py). */
export const DEFENSE_LIMITS: string[] = [
  "Vehicle uplink filter: a separate bridge option, off by default.",
  "Boot quiet: for the first 20 s after the bridge starts, while disarmed, GPS-spoofing and flood alerts are logged but not announced to the GCS.",
  "A sidecar on one port sees only the downlink (what the flight controller sends); it cannot see or block the uplink.",
];

/** Label of the per-decision compute time (it is not attack-onset detection latency). */
export const DECISION_COMPUTE_LABEL = "Decision compute";
