// Pure helpers for the in-band (over-the-radio) bridge status, alert feed and posture control (frontend/tests/).
import type { BridgeCommandResult, BridgeRemote, DefenseMode } from "../types";

export const STALE_AFTER_S = 10; // 3x the bridge report interval
export const LOST_AFTER_S = 30;
export const CONFIRM_WINDOW_S = 10;
export const FEED_MAX = 20;

export type BridgeSource = "inband" | "http" | "none";

/** In-band report first, then the optional HTTP bridge URL, else nothing. */
export function selectBridgeSource(remote: BridgeRemote | null | undefined, httpUrl: string | null): BridgeSource {
  if (remote && remote.present) return "inband";
  return httpUrl ? "http" : "none";
}

export type Freshness = "fresh" | "stale" | "lost";
export function freshness(ageS: number | null | undefined): Freshness {
  if (typeof ageS !== "number" || !Number.isFinite(ageS)) return "lost";
  if (ageS > LOST_AFTER_S) return "lost";
  if (ageS > STALE_AFTER_S) return "stale";
  return "fresh";
}

export function fmtAgo(s: number | null | undefined): string {
  if (typeof s !== "number" || !Number.isFinite(s) || s < 0) return "—";
  if (s < 60) return `${Math.round(s)} s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  return `${Math.floor(s / 3600)} h ago`;
}

/** Newest first, at most `max`. Does not mutate the input. */
export function orderFeed(recent: Array<{ t: number; text: string }> | null | undefined, max = FEED_MAX): Array<{ t: number; text: string }> {
  return (recent ?? []).filter((e) => e && typeof e.text === "string" && Number.isFinite(e.t))
    .slice().sort((a, b) => b.t - a.t).slice(0, max);
}

/** Age in seconds of a feed entry; `t` is a unix timestamp (s). Null when it cannot be related to `nowS`. */
export function feedAge(t: number, nowS: number): number | null {
  return t > 1e9 ? Math.max(0, nowS - t) : null;
}

export type CmdTone = "info" | "ok" | "warn" | "crit";
export interface CommandView { kind: BridgeCommandResult | "none"; text: string; tone: CmdTone }

export function commandView(lc: BridgeRemote["last_command"] | null | undefined): CommandView {
  if (!lc) return { kind: "none", text: "No command sent", tone: "info" };
  const d = lc.detail ? ` — ${lc.detail}` : "";
  switch (lc.result) {
    case "pending": return { kind: "pending", text: `${lc.op}: pending (waiting for the bridge over the radio)`, tone: "info" };
    case "accepted": return { kind: "accepted", text: `${lc.op}: accepted${d}`, tone: "ok" };
    case "denied": return { kind: "denied", text: `${lc.op}: denied${d}`, tone: "crit" };
    case "confirm_required": return { kind: "confirm_required", text: `${lc.op}: confirmation required${d}`, tone: "warn" };
    case "timeout": return { kind: "timeout", text: `${lc.op}: timed out, no reply from the bridge${d}`, tone: "crit" };
    default: return { kind: "failed", text: `${lc.op}: failed${d}`, tone: "crit" };
  }
}

export function isPending(sending: boolean, lc: BridgeRemote["last_command"] | null | undefined): boolean {
  return sending || lc?.result === "pending";
}

/** Buttons are usable only when the backend can sign + send commands and none is in flight. */
export function canSend(remote: BridgeRemote | null | undefined, sending: boolean): boolean {
  return !!remote && remote.control_available && !isPending(sending, remote.last_command);
}

export const CONTROL_HINT = "Posture control unavailable: start `aegis serve` with --mgmt-key-file and run the bridge with its management key; control is signed and works over the telemetry radio.";

/** Lowering from active-ips needs a second confirmation from the operator. */
export function isLowering(current: DefenseMode | null, target: DefenseMode): boolean {
  return current === "active-ips" && target !== "active-ips";
}

/** Deadline (client ms) of a confirm_required result first seen at `seenAtMs`, given its age on the backend. */
export function confirmDeadline(lc: BridgeRemote["last_command"] | null | undefined, seenAtMs: number): number | null {
  if (!lc || lc.result !== "confirm_required") return null;
  const age = Number.isFinite(lc.age_s) && lc.age_s > 0 ? lc.age_s : 0;
  return seenAtMs + Math.max(0, CONFIRM_WINDOW_S - age) * 1000;
}
export function confirmRemainingS(deadlineMs: number | null, nowMs: number): number {
  return deadlineMs == null ? 0 : Math.max(0, Math.ceil((deadlineMs - nowMs) / 1000));
}
/** The prompt shows while a target is waiting, the bridge asked for it and the window is still open. */
export function confirmOpen(target: DefenseMode | null, lc: BridgeRemote["last_command"] | null | undefined, deadlineMs: number | null, nowMs: number): boolean {
  return target != null && lc?.result === "confirm_required" && confirmRemainingS(deadlineMs, nowMs) > 0;
}

export function radioPostureBody(mode: DefenseMode, allowUnsigned?: boolean, confirm?: boolean): string {
  const b: Record<string, unknown> = { mode };
  if (allowUnsigned) b.allow_unsigned = true;
  if (confirm) b.confirm = true;
  return JSON.stringify(b);
}

export type RadioPostureResult =
  | { kind: "pending" }
  | { kind: "signing_required"; message: string }
  | { kind: "unavailable"; message: string }
  | { kind: "bad_request"; message: string }
  | { kind: "error"; message: string };

export function parseRadioPostureResponse(httpStatus: number, body: unknown): RadioPostureResult {
  const b = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
  const msg = typeof b.message === "string" ? b.message : "";
  if (httpStatus === 409 && b.error === "signing_required") {
    return { kind: "signing_required", message: msg || "The bridge reports signing off; ACTIVE IPS needs explicit unsigned acknowledgement." };
  }
  if (httpStatus === 403) return { kind: "unavailable", message: CONTROL_HINT };
  if (httpStatus === 400) return { kind: "bad_request", message: msg || "The backend rejected the request (400)." };
  if (httpStatus >= 200 && httpStatus < 300 && b.ok !== false) return { kind: "pending" };
  return { kind: "error", message: msg || `Request failed (HTTP ${httpStatus}).` };
}
