// Dual-mode UI state and GCS vs Bench Setup capability separation (W11, W12).
import type { Environment } from "../types";

export type ConsoleMode = "demo" | "flight-ops";
export type FlightOpsTab = "monitor" | "bench-setup" | "forensics";

export interface ModeCapabilities {
  mode: ConsoleMode;
  simInjectAllowed: boolean;
  gcsRadioControlsAllowed: boolean;
  benchSetupAllowed: boolean;
  benchBlockedReason: string | null;
}

export function deriveConsoleMode(
  env: Environment | null | undefined,
  userOverride: ConsoleMode | null,
): ConsoleMode {
  if (env && env !== "SIM") return "flight-ops";
  if (userOverride) return userOverride;
  return "demo";
}

export function isLocalBrowserHost(hostname?: string): boolean {
  const h = (hostname ?? (typeof location !== "undefined" ? location.hostname : "")).toLowerCase();
  return !h || h === "localhost" || h === "127.0.0.1" || h === "::1" || h === "tauri.localhost";
}

export function computeCapabilities(
  env: Environment | null | undefined,
  userOverride: ConsoleMode | null,
  armed: boolean | null | undefined,
  hostname?: string,
): ModeCapabilities {
  const mode = deriveConsoleMode(env, userOverride);
  const simInjectAllowed = env === "SIM" && mode === "demo";
  const local = isLocalBrowserHost(hostname);
  let benchBlockedReason: string | null = null;
  if (!local) {
    benchBlockedReason = "Bench setup requires local loopback access on the companion computer (locked remotely).";
  } else if (armed === true) {
    benchBlockedReason = "Vehicle is ARMED — physical bench setup and firmware enrollment are locked in flight.";
  }

  return {
    mode,
    simInjectAllowed,
    gcsRadioControlsAllowed: true,
    benchSetupAllowed: benchBlockedReason === null,
    benchBlockedReason,
  };
}
