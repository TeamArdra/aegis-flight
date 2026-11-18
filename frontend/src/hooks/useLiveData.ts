import type { SigningInfo } from "../lib/posture";
import { useEffect, useReducer, useRef } from "react";
import { api, wsUrl } from "../services/api";
import { acceptFix, nextOrigin, type LatLon } from "../lib/geo";
import { grow, keepIfEqual } from "../lib/stable";
import type {
  AlertRow, BridgeRemote, DefenseMode, Checks, Environment, LinkStatus, Metrics, MitigationInfo, SourceInfo, Telemetry, Threat, TopologyInfo, Update,
} from "../types";

export interface LiveState {
  connected: boolean; // dashboard <-> backend WebSocket (NOT the vehicle link: see `link`)
  environment: Environment | null; // as reported by the backend; null until it has reported
  source: SourceInfo | null;
  defenseMode: DefenseMode;
  signing: SigningInfo | null;
  mitigation: MitigationInfo | null;
  link: LinkStatus | null;
  runId: string | null;
  checks: Checks | null; // null for SIM
  bridgeRemote: BridgeRemote | null; // in-band bridge report over the radio
  origin: LatLon | null; // first valid fix of the current run (local-frame origin)
  eventsCount: number | null; // persisted alerts of the current run
  updateAgeS: number | null; // seconds since the last WebSocket update (backend freshness)
  t: number;
  telemetry: Telemetry | null;
  sanitizedTelemetry: Telemetry | null;
  threat: Threat | null;
  attackActive: string | null;
  distance: number; // cumulative simulated flight-path length (m), live
  track: Array<[number, number]>; // effective vehicle [lat, lon] (IPS-restored when active-ips)
  trackThreat: boolean[]; // index-aligned with `track`: true where that fix was flown under threat
  rawTrack: Array<[number, number]>; // raw un-sanitized GPS [lat, lon] for the CURRENT attack episode only
  scoreHistory: Array<{ t: number; score: number }>;
  altHistory: Array<{ t: number; rawAlt: number; effAlt: number; diverging: boolean }>;
  topologyInfo: TopologyInfo | null;
  alerts: AlertRow[];
  metrics: Metrics | null;
}

const MAX_TRACK = 400;
const MAX_HISTORY = 240;

interface ReducerState {
  connected: boolean;
  environment: Environment | null;
  source: SourceInfo | null;
  defenseMode: DefenseMode;
  signing: SigningInfo | null;
  topologyInfo: TopologyInfo | null;
  mitigation: MitigationInfo | null;
  link: LinkStatus | null;
  runId: string | null;
  checks: Checks | null;
  bridgeRemote: BridgeRemote | null;
  origin: LatLon | null;
  eventsCount: number | null;
  lastUpdate: number | null;
  now: number;
  t: number;
  telemetry: Telemetry | null;
  sanitizedTelemetry: Telemetry | null;
  threat: Threat | null;
  attackActive: string | null;
  distance: number;
  track: Array<[number, number]>;
  trackThreat: boolean[];
  rawTrack: Array<[number, number]>;
  scoreHistory: Array<{ t: number; score: number }>;
  altHistory: Array<{ t: number; rawAlt: number; effAlt: number; diverging: boolean }>;
  alerts: AlertRow[];
  metrics: Metrics | null;
}

const initialState: ReducerState = {
  connected: false,
  environment: null,
  source: null,
  defenseMode: "passive",
  signing: null,
  topologyInfo: null,
  mitigation: null,
  link: null,
  runId: null,
  checks: null,
  bridgeRemote: null,
  origin: null,
  eventsCount: null,
  lastUpdate: null,
  now: Date.now(),
  t: 0,
  telemetry: null,
  sanitizedTelemetry: null,
  threat: null,
  attackActive: null,
  distance: 0,
  track: [],
  trackThreat: [],
  rawTrack: [],
  scoreHistory: [],
  altHistory: [],
  alerts: [],
  metrics: null,
};

type Action =
  | { type: "WS_OPEN" }
  | { type: "WS_CLOSE" }
  | { type: "UPDATE"; payload: Update; now: number }
  | { type: "POLL"; events: AlertRow[]; count: number; metrics: Metrics; status: any }
  | { type: "TICK"; now: number };

function liveReducer(state: ReducerState, action: Action): ReducerState {
  switch (action.type) {
    case "WS_OPEN":
      return { ...state, connected: true };
    case "WS_CLOSE":
      return { ...state, connected: false };
    case "TICK":
      return { ...state, now: action.now };
    case "POLL": {
      const st = action.status;
      const last = state.lastUpdate;
      return {
        ...state,
        alerts: action.events,
        eventsCount: action.count,
        metrics: action.metrics,
        environment: st?.environment ?? state.environment,
        source: keepIfEqual(state.source, st?.source ?? state.source),
        defenseMode: st?.defense_mode ?? (st?.source?.defense_mode || state.defenseMode),
        signing: keepIfEqual(state.signing, st?.signing ?? state.signing),
        topologyInfo: keepIfEqual(state.topologyInfo, st?.topology_info ?? state.topologyInfo),
        mitigation: keepIfEqual(state.mitigation, st?.mitigation ?? state.mitigation),
        bridgeRemote: keepIfEqual(state.bridgeRemote, st?.bridge_remote ?? state.bridgeRemote),
        link: keepIfEqual(state.link, st?.link && (last == null || Date.now() - last > 1000) ? st.link : state.link),
      };
    }
    case "UPDATE": {
      const msg = action.payload;
      const isNewRun = msg.run_id && msg.run_id !== state.runId;

      const env = msg.environment ?? state.environment;
      const isSim = env == null || env === "SIM";
      const currentMode = msg.defense_mode ?? (msg.source?.defense_mode || state.defenseMode);
      // The protected/IPS overlay exists only in the simulator; live/recorded sources are shown as received.
      const isIps = isSim && currentMode === "active-ips";
      const effTele = isIps && msg.sanitized_telemetry ? msg.sanitized_telemetry : msg.telemetry;
      const gpsValid = msg.link?.gps?.valid_fix ?? null;
      // Only valid fixes enter the track (null/NaN/out of range/(0,0)/receiver says no fix).
      // Per-point "flown under threat" flag, kept index-aligned with `track` so the
      // map highlights only the segment flown during an attack, not the whole history.
      const accepted = acceptFix(effTele?.lat, effTele?.lon, isSim ? null : gpsValid);
      const fix: [number, number] | null = accepted ? [effTele!.lat as number, effTele!.lon as number] : null;
      const underThreat = !!(msg.threat?.threat ?? state.threat?.threat) || !!msg.attack_active;
      const newTrack = grow(state.track, !!isNewRun, MAX_TRACK, fix);
      const newTrackThreat = grow(state.trackThreat, !!isNewRun, MAX_TRACK, accepted ? underThreat : null);
      const org = nextOrigin(
        { origin: state.origin, runId: state.runId }, msg.run_id ?? null,
        effTele?.lat, effTele?.lon, isSim ? null : gpsValid,
      );

      // The raw (pre-sanitization) track only feeds the rejected-GPS ghost overlay (SIM only), so it
      // is scoped to the CURRENT attack episode: switching or clearing the attack starts a
      // fresh ghost.
      const attackChanged = (msg.attack_active ?? null) !== state.attackActive;
      const newRawTrack = grow(
        state.rawTrack, !!isNewRun || attackChanged, MAX_TRACK,
        isSim && acceptFix(msg.telemetry?.lat, msg.telemetry?.lon) ? ([msg.telemetry.lat as number, msg.telemetry.lon as number] as [number, number]) : null,
      );

      const newHistory = grow(state.scoreHistory, !!isNewRun, MAX_HISTORY, msg.threat ? { t: msg.t, score: msg.threat.threat_score } : null);

      // rel_alt is metres above home; the 60 m fallback is a simulator-only baseline.
      const fb = isSim ? 60.0 : null;
      const rawAltV = msg.telemetry?.rel_alt ?? (isSim ? msg.telemetry?.alt_msl : null) ?? fb;
      const effAltV = effTele?.rel_alt ?? (isSim ? effTele?.alt_msl : null) ?? fb;
      const altPoint = typeof rawAltV === "number" && Number.isFinite(rawAltV) && typeof effAltV === "number" && Number.isFinite(effAltV)
        ? { t: msg.t, rawAlt: rawAltV, effAlt: effAltV, diverging: isIps && Math.abs(rawAltV - effAltV) > 1.5 }
        : null;
      const newAltHistory = grow(state.altHistory, !!isNewRun, MAX_HISTORY, altPoint);

      return {
        ...state,
        lastUpdate: action.now,
        environment: msg.environment ?? state.environment,
        source: keepIfEqual(state.source, msg.source ?? state.source),
        defenseMode: msg.defense_mode ?? (msg.source?.defense_mode || state.defenseMode),
        signing: keepIfEqual(state.signing, msg.signing ?? state.signing),
        topologyInfo: keepIfEqual(state.topologyInfo, msg.topology_info ?? state.topologyInfo),
        mitigation: keepIfEqual(state.mitigation, msg.mitigation ?? state.mitigation),
        link: keepIfEqual(state.link, msg.link ?? state.link),
        runId: msg.run_id ?? state.runId,
        checks: keepIfEqual(state.checks, msg.checks ?? null),
        bridgeRemote: keepIfEqual(state.bridgeRemote, msg.bridge_remote ?? state.bridgeRemote),
        origin: org.origin,
        t: msg.t,
        telemetry: keepIfEqual(state.telemetry, msg.telemetry),
        sanitizedTelemetry: keepIfEqual(state.sanitizedTelemetry, msg.sanitized_telemetry ?? msg.telemetry),
        attackActive: msg.attack_active,
        distance: typeof msg.distance_m === "number" ? msg.distance_m : state.distance,
        threat: keepIfEqual(state.threat, msg.threat ?? state.threat),
        track: newTrack,
        trackThreat: newTrackThreat,
        rawTrack: newRawTrack,
        scoreHistory: newHistory,
        altHistory: newAltHistory,
      };
    }
    default:
      return state;
  }
}

export function useLiveData(): LiveState {
  const [state, dispatch] = useReducer(liveReducer, initialState);
  const stateRef = useRef(state);
  stateRef.current = state;

  // WebSocket live telemetry stream (auto-reconnect).
  useEffect(() => {
    let ws: WebSocket | null = null;
    let closed = false;
    let retry: number | undefined;

    const connect = () => {
      ws = new WebSocket(wsUrl());
      ws.onopen = () => dispatch({ type: "WS_OPEN" });
      ws.onclose = () => {
        dispatch({ type: "WS_CLOSE" });
        if (!closed) retry = window.setTimeout(connect, 1500);
      };
      ws.onerror = () => ws?.close();
      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data) as Update;
          if (msg.type === "update") {
            dispatch({ type: "UPDATE", payload: msg, now: Date.now() });
          }
        } catch {
          // ignore corrupted frame
        }
      };
    };
    connect();
    return () => {
      closed = true;
      if (retry) clearTimeout(retry);
      ws?.close();
    };
  }, []);

  // Poll REST for the persisted alerts, metrics and status.
  // Throttles polling during active mitigation (state !== "NOMINAL") to save companion CPU & bandwidth.
  useEffect(() => {
    let alive = true;
    let timerId: number | undefined;

    const poll = async () => {
      try {
        const [ev, m, st] = await Promise.all([api.events(30), api.metrics(), api.status()]);
        if (!alive) return;
        dispatch({
          type: "POLL",
          events: ev.events,
          count: ev.count ?? ev.events.length,
          metrics: m,
          status: st,
        });
      } catch {
        /* backend not ready */
      } finally {
        if (alive) {
          const isMitigating = stateRef.current.mitigation && stateRef.current.mitigation.state !== "NOMINAL";
          const delay = isMitigating ? 5000 : 2000;
          timerId = window.setTimeout(poll, delay);
        }
      }
    };

    poll();
    return () => {
      alive = false;
      if (timerId) clearTimeout(timerId);
    };
  }, []);

  // 1 Hz clock for the "time since the last backend update" freshness indicator.
  useEffect(() => {
    const id = window.setInterval(() => dispatch({ type: "TICK", now: Date.now() }), 1000);
    return () => clearInterval(id);
  }, []);

  const last = state.lastUpdate;
  return {
    connected: state.connected,
    environment: state.environment,
    source: state.source,
    defenseMode: state.defenseMode,
    signing: state.signing,
    mitigation: state.mitigation,
    link: state.link,
    runId: state.runId,
    checks: state.checks,
    bridgeRemote: state.bridgeRemote,
    origin: state.origin,
    eventsCount: state.eventsCount,
    updateAgeS: last == null ? null : Math.max(0, (state.now - last) / 1000),
    t: state.t,
    telemetry: state.telemetry,
    sanitizedTelemetry: state.sanitizedTelemetry,
    threat: state.threat,
    attackActive: state.attackActive,
    distance: state.distance,
    track: state.track,
    trackThreat: state.trackThreat,
    rawTrack: state.rawTrack,
    scoreHistory: state.scoreHistory,
    altHistory: state.altHistory,
    topologyInfo: state.topologyInfo,
    alerts: state.alerts,
    metrics: state.metrics,
  };
}
