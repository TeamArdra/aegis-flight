// Pure, evidence-bounded wording for the threat card and the defense panel (frontend/tests/wording.test.ts).
// Rule: say what the vehicle state and the evidence support, nothing more. BENCH and SITL results are not
// flight validation; no counter-action is described as having succeeded.
import type { DefenseMode, Environment, MitigationState, Telemetry, Threat } from "../types";

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
  { id: "advisory", label: "ADVISORY", desc: "Alerts only (optional GCS notice) · nothing sent to the flight controller" },
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
        desc: `The controller applies its enforcement rules; the decision log lists what it decided to drop or send, not confirmed transmissions. Not flight-validated. ${scope}`,
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
        desc: "Alert condition detected. Nothing is sent to the flight controller; no frame is dropped or changed.",
        badge: "DETECTED",
      };
    }
    return {
      cls: "res-nominal",
      title: "ADVISORY: monitoring, alerts only",
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

/** The 4-state escalation ladder: the controller's internal state; descriptions say what the state means, not what was executed. */
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
      { id: "AUTO_MITIGATING", label: "ADVISORY ALERTING", color: "var(--warn)", desc: "Alert condition · controller state only, nothing executed" },
      { id: "SAFE_HOLD", label: "HOLD RECOMMENDED", color: "#f97316", desc: "Anomaly persists >30 s · pilot may switch to ALT_HOLD" },
      { id: "GCS_TAKEOVER", label: "PILOT TAKEOVER URGENT", color: "var(--crit)", desc: "Critical integrity alert · manual control advised" },
    ];
  }
  return [
    { id: "NOMINAL", label: "NOMINAL", color: "var(--ok)", desc: "No active threat · rules idle" },
    { id: "AUTO_MITIGATING", label: "AUTO MITIGATING", color: "var(--warn)", desc: "Controller decides to apply enforcement rules (internal state)" },
    { id: "SAFE_HOLD", label: "SAFE HOLD", color: "#f97316", desc: "Sustained conflict · controller requests ALT_HOLD (internal state)" },
    { id: "GCS_TAKEOVER", label: "GCS TAKEOVER", color: "var(--crit)", desc: "Controller calls for pilot control (internal state)" },
  ];
}

/** Fallback for the summary bar when the backend sends no summary. */
export function summaryFallback(mode: DefenseMode): string {
  if (mode === "passive") return "Passive IDS monitoring";
  if (mode === "advisory") return "Advisory monitoring";
  return "ACTIVE IPS: no controller action recorded";
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

/* ------------------------------------------------------------------------------------------------
 * Internal mitigation state vs. actions that actually happened (issue #181).
 * `mitigation.state` is the controller's internal state machine, computed in every mode, including
 * PASSIVE. `counter_frames_sent` counts frames the controller encoded/queued in a tick, not frames
 * transmitted. The API reports no field that confirms transmission on the engine path, so nothing
 * here may say an action was sent, executed or engaged.
 * ---------------------------------------------------------------------------------------------- */

export type MitigationRowId = "threat" | "internal" | "mode" | "transmission";
export interface MitigationRow { id: MitigationRowId; label: string; value: string }

export interface MitigationPresentationInput {
  mode: DefenseMode;
  /** Controller state; null/undefined = no mitigation payload reported. */
  state?: MitigationState | null;
  environment?: Environment | null;
  threat?: Pick<Threat, "threat" | "attack_type" | "severity"> | null;
  /** Frames the controller encoded/queued this tick (not transmitted); null/undefined = not reported. */
  queuedFrames?: number | null;
}

const MODE_LABEL: Record<DefenseMode, string> = { passive: "PASSIVE", advisory: "ADVISORY", "active-ips": "ACTIVE IPS" };

/** What is known about transmission for this mode/environment; never an affirmative "was sent" claim. */
export function transmissionText(
  mode: DefenseMode,
  environment: Environment | null | undefined,
  queuedFrames: number | null | undefined,
  payloadPresent: boolean,
): string {
  if (mode === "passive") return "None: PASSIVE never transmits";
  if (mode === "advisory") {
    return "No counter-command or mode command is sent, and the mitigation controller sends nothing to the flight controller. "
      + "Optional GCS STATUSTEXT alert notifications (a server flag) are not reported by this API.";
  }
  if (!payloadPresent) return "Unknown: no mitigation data reported";
  if (environment === "SIM" || environment === "REPLAY") return "None: no live transport in SIM/REPLAY (modelled only)";
  const n = typeof queuedFrames === "number" && Number.isFinite(queuedFrames) ? queuedFrames : null;
  return n === null
    ? "Not reported by the API (queued frame count not reported)"
    : `Not reported by the API (${n} frame${n === 1 ? "" : "s"} queued by the controller)`;
}

/** The four labelled rows of the defense panel: threat, internal state, configured mode, transmission. */
export function mitigationPresentation(input: MitigationPresentationInput): MitigationRow[] {
  const { mode, state, environment, threat, queuedFrames } = input;
  const detected = Boolean(threat?.threat);
  const sev = detected && threat?.severity ? ` · severity ${threat.severity}` : "";
  return [
    {
      id: "threat",
      label: "Threat assessment",
      value: detected ? `Threat detected: ${pretty(threat?.attack_type)}${sev}` : "No threat detected",
    },
    {
      id: "internal",
      label: "Internal mitigation state (controller)",
      value: state
        ? `${state} · the controller's internal state, not proof of an executed action`
        : "Not reported (no mitigation data)",
    },
    { id: "mode", label: "Configured defense mode", value: MODE_LABEL[mode] },
    {
      id: "transmission",
      label: "Transmission / action",
      value: transmissionText(mode, environment, queuedFrames, Boolean(state)),
    },
  ];
}

/** Title of the escalation-ladder section: it shows the controller's internal state. */
export function internalStateTitle(mode: DefenseMode): string {
  if (mode === "passive") return "IDS ESCALATION STATE (CONTROLLER INTERNAL)";
  if (mode === "advisory") return "ADVISORY ESCALATION STATE (CONTROLLER INTERNAL)";
  return "IPS ESCALATION STATE (CONTROLLER INTERNAL)";
}

export function internalStateCaption(mode: DefenseMode): string {
  const base = "The controller's internal state machine, computed in every mode. It is not proof that any action was executed.";
  if (mode === "passive") return `${base} In PASSIVE nothing is transmitted.`;
  if (mode === "advisory") return `${base} In ADVISORY no counter-command is sent.`;
  return `${base} The API does not confirm transmission.`;
}

/** Label of the summary bar: the summary text is written by the mitigation controller. */
export function controllerSummaryLabel(mode: DefenseMode): string {
  if (mode === "passive") return "IDS CONTROLLER SUMMARY:";
  if (mode === "advisory") return "ADVISORY CONTROLLER SUMMARY:";
  return "IPS CONTROLLER SUMMARY:";
}
export const CONTROLLER_SUMMARY_CAPTION = "Text written by the mitigation controller, not a confirmed action.";

/** Caption under the action timeline. */
export const ACTION_TIMELINE_CAPTION = "Entries are controller decisions, not confirmed transmissions.";

/** Neutral text of the empty action timeline. */
export function emptyTimelineText(mode: DefenseMode): string {
  if (mode === "passive") return "Passive IDS stream active — no intrusions logged yet.";
  if (mode === "advisory") return "Advisory monitoring — no controller entries yet.";
  return "No controller decisions logged yet.";
}

/** Feedback after an operator override when the backend sent no summary. */
export function overrideFallback(action: string): string {
  return `Override ${action} accepted by the controller (not confirmed on a vehicle)`;
}
