// Pure geometry for the flight-track graphic: fix validation, local-frame projection and fitting.
// No React, no DOM — unit tested in frontend/tests/geo.test.ts.
export type LatLon = [number, number];
export type XY = [number, number];

export const M_PER_DEG_LAT = 111_320;

/** A fix is usable only if finite, in range and not the (0,0) "no GPS" placeholder. */
export function isValidFix(lat: unknown, lon: unknown): boolean {
  if (typeof lat !== "number" || typeof lon !== "number") return false;
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) return false;
  if (Math.abs(lat) > 90 || Math.abs(lon) > 180) return false;
  if (lat === 0 && lon === 0) return false;
  return true;
}

/** isValidFix plus the link's own GPS report (`false` = the receiver says there is no valid fix). */
export function acceptFix(lat: unknown, lon: unknown, gpsValidFix?: boolean | null): boolean {
  if (gpsValidFix === false) return false;
  return isValidFix(lat, lon);
}

/** Longitude difference lon - lon0 in degrees, normalised to (-180, 180] (antimeridian safe). */
export function lonDelta(lon: number, lon0: number): number {
  let d = (lon - lon0) % 360;
  if (d > 180) d -= 360;
  else if (d <= -180) d += 360;
  return d;
}

export function metresPerDegLon(latDeg: number): number {
  return M_PER_DEG_LAT * Math.cos((latDeg * Math.PI) / 180);
}

/** Local east/north metres of (lat, lon) relative to origin; north up, cos(origin latitude). */
export function toLocal(origin: LatLon, lat: number, lon: number): XY {
  return [lonDelta(lon, origin[1]) * metresPerDegLon(origin[0]), (lat - origin[0]) * M_PER_DEG_LAT];
}

export function projectTrack(track: LatLon[], origin: LatLon): XY[] {
  return track.map((p) => toLocal(origin, p[0], p[1]));
}

/** Origin bookkeeping: first VALID fix of a run; a new run id re-origins. */
export interface OriginState { origin: LatLon | null; runId: string | null }
export function nextOrigin(prev: OriginState, runId: string | null, lat: unknown, lon: unknown, gpsValid?: boolean | null): OriginState {
  const base: OriginState = runId && runId !== prev.runId ? { origin: null, runId } : { origin: prev.origin, runId: runId ?? prev.runId };
  if (!base.origin && acceptFix(lat, lon, gpsValid)) base.origin = [lat as number, lon as number];
  return base;
}

export interface Extent { minX: number; maxX: number; minY: number; maxY: number; span: number }
export function extentOf(points: XY[], minSpan = 20): Extent {
  let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
  for (const [x, y] of points) {
    if (x < minX) minX = x; if (x > maxX) maxX = x;
    if (y < minY) minY = y; if (y > maxY) maxY = y;
  }
  if (!Number.isFinite(minX)) { minX = maxX = minY = maxY = 0; }
  return { minX, maxX, minY, maxY, span: Math.max(maxX - minX, maxY - minY, minSpan) };
}

export interface Fit { pxPerM: number; sx: (x: number) => number; sy: (y: number) => number }
/** Equal-aspect fit (same px/m on both axes), extent centred in the plot box, north up. */
export function fitExtent(e: Extent, W: number, H: number, pad: number): Fit {
  const pw = W - 2 * pad, ph = H - 2 * pad;
  const pxPerM = Math.min(pw, ph) / e.span;
  const cx = (e.minX + e.maxX) / 2, cy = (e.minY + e.maxY) / 2;
  return {
    pxPerM,
    sx: (x) => pad + pw / 2 + (x - cx) * pxPerM,
    sy: (y) => H - pad - ph / 2 - (y - cy) * pxPerM,
  };
}

/** Round to a clean 1/2/5 x 10^n value (scale bar). */
export function niceScale(x: number): number {
  if (!(x > 0)) return 0;
  const pow = Math.pow(10, Math.floor(Math.log10(x)));
  const f = x / pow;
  return (f >= 5 ? 5 : f >= 2 ? 2 : 1) * pow;
}

/** Memo of the last projection: the track it was computed from, the origin and the projected points. */
export interface ProjCache { track: LatLon[]; origin: LatLon; pts: XY[] }

/**
 * Incremental `projectTrack`: the track is a sliding window (shifted by k, new fixes appended) whose elements keep
 * their identity, so the points already projected for the same origin are reused and only the new tail is
 * projected with the very same `toLocal`. The result is element-for-element identical to `projectTrack(track,
 * origin)`; any mismatch (different origin, a new run, a replaced element) falls back to the full recomputation.
 */
export function projectTrackInc(track: LatLon[], origin: LatLon, prev: ProjCache | null): ProjCache {
  let pts: XY[] | null = null;
  if (prev && track.length > 0 && prev.track.length > 0 && prev.origin[0] === origin[0] && prev.origin[1] === origin[1]) {
    let k = prev.track.indexOf(track[0]);
    if (k >= 0) {
      const overlap = Math.min(track.length, prev.track.length - k);
      let same = true;
      for (let i = 1; i < overlap; i++) {
        if (track[i] !== prev.track[i + k]) { same = false; break; }
      }
      if (same) {
        pts = prev.pts.slice(k, k + overlap);
        for (let i = overlap; i < track.length; i++) pts.push(toLocal(origin, track[i][0], track[i][1]));
      }
    }
  }
  return { track, origin, pts: pts ?? projectTrack(track, origin) };
}
