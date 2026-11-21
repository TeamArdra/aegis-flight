// REST + WebSocket endpoints. In the Vite dev server (:5173) requests are
// proxied to the backend on :8000; when served by FastAPI they are same-origin.
import type { DefenseMode, EventsResponse, Metrics, MitigationInfo, Status } from "../types";

import { bridgeAuthHeaders, bridgePostureUrl, parsePostureResponse, postureBody, type PostureResult, type SigningInfo } from "../lib/posture";
import { parseRadioPostureResponse, radioPostureBody, type RadioPostureResult } from "../lib/bridgeRemote";
import { buildSignedAuthHeaders, getSessionBridgeToken, saveSessionBridgeToken } from "../lib/requestAuth";
import { isHttpUrl, normalizeUrl, resolveBackend, resolveWsUrl } from "./backend";

export const BACKEND_KEY = "aegis_backend_url";
export const BRIDGE_KEY = "aegis_bridge_url";
export const BRIDGE_TOKEN_KEY = "aegis_bridge_token";

export interface DiscoveredPort {
  device: string;
  resolved_device?: string;
  baudrate: number;
  sysids: number[];
  autopilot_id: number | null;
  vehicle_type: number | null;
  role: string;
  frames_valid: number;
  description?: string;
}

function lsGet(k: string): string | null {
  try { return window.localStorage?.getItem(k) ?? null; } catch { return null; }
}

/** Base URL for every REST call and the WebSocket ('' = same origin). Resolved per call so settings apply live. */
export function backendBase(): string {
  const metaEnv = (import.meta as unknown as { env?: Record<string, string | undefined> }).env;
  return resolveBackend({
    win: (window as unknown as { __AEGIS_BACKEND__?: string }).__AEGIS_BACKEND__ ?? null,
    stored: lsGet(BACKEND_KEY),
    vite: metaEnv?.VITE_BACKEND_URL ?? null,
    protocol: location.protocol,
    hostname: location.hostname,
  });
}

export function wsUrl(): string {
  return resolveWsUrl(backendBase(), location.protocol, location.host);
}

export function getBridgeToken(): string { return getSessionBridgeToken(); }
export function saveBridgeToken(v: string): void {
  saveSessionBridgeToken(v);
  // Migrate away from persistent localStorage if a legacy token existed
  try { window.localStorage?.removeItem(BRIDGE_TOKEN_KEY); } catch { /* ignore */ }
}

/** POST <bridge>/posture; token goes only in the Authorization header. Never throws. */
export async function setBridgePosture(url: string, token: string, mode: DefenseMode, allowUnsigned?: boolean): Promise<PostureResult> {
  try {
    const r = await fetch(bridgePostureUrl(url), { method: "POST", headers: bridgeAuthHeaders(token), body: postureBody(mode, allowUnsigned) });
    let body: unknown = null;
    try { body = await r.json(); } catch { /* non-JSON body */ }
    return parsePostureResponse(r.status, body);
  } catch {
    return { kind: "error", message: "Bridge unreachable (network error)." };
  }
}

export function getBridgeUrl(): string | null {
  const v = lsGet(BRIDGE_KEY);
  return v && isHttpUrl(v) ? normalizeUrl(v) : null;
}

/** Save (or clear with "") a URL setting; returns an error string for invalid input. */
export function saveUrlSetting(key: string, value: string): string | null {
  const v = value.trim();
  try {
    if (!v) { window.localStorage.removeItem(key); return null; }
    if (!isHttpUrl(v)) return "Must be an http(s):// URL";
    window.localStorage.setItem(key, normalizeUrl(v));
    return null;
  } catch {
    return "Browser storage unavailable";
  }
}
export function getUrlSetting(key: string): string { return lsGet(key) ?? ""; }

async function jget<T>(path: string, opts?: { signed?: boolean }): Promise<T> {
  // Gated GET routes (bench setup) need the same token + signature headers as a POST.
  const headers = opts?.signed ? await buildSignedAuthHeaders("GET", path) : undefined;
  const r = await fetch(backendBase() + path, headers ? { headers } : undefined);
  if (!r.ok) throw new Error(httpErrorMessage(path, r.status));
  return r.json();
}

function httpErrorMessage(path: string, status: number): string {
  if (status === 401) return `${path}: 401 unauthorized - check the API token in Settings`;
  if (status === 429) return `${path}: 429 too many invalid authentication attempts - wait and retry`;
  return `${path}: ${status}`;
}

async function jpost<T>(path: string, body?: unknown): Promise<T> {
  const payload = body !== undefined ? JSON.stringify(body) : "";
  const headers = await buildSignedAuthHeaders("POST", path, payload);
  const r = await fetch(backendBase() + path, {
    method: "POST",
    headers,
    body: payload || undefined,
  });
  let parsed: unknown = null;
  try { parsed = await r.json(); } catch { /* non-JSON body */ }
  if (!r.ok) {
    // Backend rejections ({ok:false,error}) are returned so callers can show the message; anything else
    // (401/429 without a body, framework 422, proxy errors) must not be silently treated as success.
    const rec = parsed as { ok?: unknown; error?: unknown; message?: unknown } | null;
    const hasMsg = !!rec && typeof rec === "object" && rec.ok === false && (rec.error || rec.message);
    if (!hasMsg) throw new Error(httpErrorMessage(path, r.status));
  }
  return parsed as T;
}

export const api = {
  status: () => jget<Status>("/api/status"),
  metrics: () => jget<Metrics>("/api/metrics"),
  // the CURRENT run's persisted alerts (hash-chained event log), newest first
  events: (limit = 50) => jget<EventsResponse>(`/api/events?limit=${limit}`),
  config: () => jget<Record<string, unknown>>("/api/config"),
  start: () => jpost("/api/simulation/start"),
  stop: () => jpost("/api/simulation/stop"),
  reset: () => jpost("/api/simulation/reset"),
  attack: (attack: string | null, mode?: string, drift_rate_ms?: number) =>
    jpost("/api/simulation/attack", { attack, mode, drift_rate_ms }),
  forensic: (limit = 200) => jget<Record<string, unknown>>(`/api/events/forensic?limit=${limit}`),
  forensicReportJson: (limit = 500) => jget<Record<string, unknown>>(`/api/forensic/report?format=json&limit=${limit}`),
  discoverPorts: () => jget<{ ok: boolean; zero_tx?: boolean; error?: string; ports?: DiscoveredPort[] }>("/api/setup/discover-ports", { signed: true }),
  runPreflight: (cfg: Record<string, unknown>) => jpost<Record<string, unknown>>("/api/setup/preflight", cfg),
  generateConfig: (cfg: Record<string, unknown>) => jpost<{ ok: boolean; yaml?: string; error?: string }>("/api/setup/generate-config", cfg),
  enrollFirmware: (port: string, baudrate: number) =>
    jpost<{ ok: boolean; error?: string; entry?: Record<string, unknown> }>("/api/setup/enroll-firmware", { port, baudrate }),
  runDrill: (scenario = "all") => jpost<Record<string, unknown>>("/api/drill/run", { scenario }),
  setDefenseMode: (mode: DefenseMode, allowUnsigned?: boolean) =>
    jpost<{ ok: boolean; mode?: DefenseMode; error?: string; message?: string; signing?: SigningInfo }>(
      "/api/defense/mode", allowUnsigned ? { mode, allow_unsigned: true } : { mode }),
  defenseOverride: (action: "safe_hold" | "reset_quarantine" | "ack_takeover") =>
    jpost<{ ok: boolean; action: string; mitigation: MitigationInfo }>("/api/defense/override", { action }),
};

/** POST /api/bridge/posture: sent over the telemetry radio; the result arrives later in bridge_remote.last_command. Never throws. */
export async function setBridgePostureViaRadio(mode: DefenseMode, allowUnsigned?: boolean, confirm?: boolean): Promise<RadioPostureResult> {
  const payload = radioPostureBody(mode, allowUnsigned, confirm);
  const headers = await buildSignedAuthHeaders("POST", "/api/bridge/posture", payload);
  try {
    const r = await fetch(backendBase() + "/api/bridge/posture", { method: "POST", headers, body: payload });
    let body: unknown = null;
    try { body = await r.json(); } catch { /* non-JSON body */ }
    return parseRadioPostureResponse(r.status, body);
  } catch {
    return { kind: "error", message: "Backend unreachable (network error)." };
  }
}
