import assert from "node:assert/strict";
import { test } from "node:test";
import { acceptFix, extentOf, fitExtent, isValidFix, lonDelta, nextOrigin, niceScale, projectTrack, toLocal } from "../src/lib/geo.ts";

const near = (a, b, tol) => assert.ok(Math.abs(a - b) <= tol, `${a} !~ ${b}`);

test("projection scales east by cos(latitude) at 0/19/60/-45", () => {
  for (const lat of [0, 19, 60, -45]) {
    const [x, y] = toLocal([lat, 10], lat, 10.001);
    near(x, 111.32 * Math.cos((lat * Math.PI) / 180), 0.01);
    near(y, 0, 1e-9);
    const [, y2] = toLocal([lat, 10], lat + 0.001, 10);
    near(y2, 111.32, 0.01);
  }
});

test("longitude is normalised across the antimeridian", () => {
  near(lonDelta(-179.999, 179.999), 0.002, 1e-9);
  near(lonDelta(179.999, -179.999), -0.002, 1e-9);
  const [x] = toLocal([0.5, 179.999], 0.5, -179.999);
  assert.ok(x > 0 && x < 300);
});

test("invalid fixes are rejected", () => {
  for (const [a, b] of [[0, 0], [NaN, 1], [1, Infinity], [91, 0], [0, 181], [null, 5], [undefined, undefined]]) {
    assert.equal(isValidFix(a, b), false, `${a},${b}`);
  }
  assert.equal(isValidFix(0, 5), true);
  assert.equal(isValidFix(19.4, -99.1), true);
  assert.equal(acceptFix(19.4, -99.1, false), false);
  assert.equal(acceptFix(19.4, -99.1, null), true);
});

test("origin is the first valid fix and resets on a new run", () => {
  let s = { origin: null, runId: null };
  s = nextOrigin(s, "a", 0, 0);
  assert.equal(s.origin, null);
  s = nextOrigin(s, "a", NaN, 1);
  assert.equal(s.origin, null);
  s = nextOrigin(s, "a", 10, 20);
  assert.deepEqual(s.origin, [10, 20]);
  s = nextOrigin(s, "a", 11, 21);
  assert.deepEqual(s.origin, [10, 20]);
  s = nextOrigin(s, "b", 30, 40);
  assert.deepEqual(s.origin, [30, 40]);
  s = nextOrigin(s, "c", 0, 0);
  assert.equal(s.origin, null);
});

test("fit is equal-aspect, north-up and auto-scaled", () => {
  const pts = projectTrack([[19, -99], [19.001, -99], [19.001, -98.998]], [19, -99]);
  const e = extentOf(pts);
  const fit = fitExtent(e, 680, 410, 34);
  assert.ok(fit.pxPerM > 0);
  assert.ok(fit.sy(pts[1][1]) < fit.sy(pts[0][1])); // north is up
  const dx = fit.sx(pts[2][0]) - fit.sx(pts[1][0]);
  near(dx / fit.pxPerM, pts[2][0] - pts[1][0], 1e-6);
  for (const p of pts) {
    assert.ok(fit.sx(p[0]) >= 34 && fit.sx(p[0]) <= 646 && fit.sy(p[1]) >= 34 && fit.sy(p[1]) <= 376);
  }
  assert.equal(extentOf([[0, 0]]).span, 20);
  assert.equal(niceScale(130), 100);
  assert.equal(niceScale(0), 0);
});

import { projectTrackInc, type LatLon, type ProjCache } from "../src/lib/geo.ts";

function rng(seed) { let s = seed >>> 0; return () => ((s = (Math.imul(s, 1664525) + 1013904223) >>> 0) / 2 ** 32); }

test("incremental projection equals full recomputation exactly for random sliding tracks", () => {
  for (let seed = 1; seed <= 40; seed++) {
    const r = rng(seed);
    const lat0 = (r() - 0.5) * 170, lon0 = (r() - 0.5) * 358;
    const origin: LatLon = [lat0, lon0];
    let track: LatLon[] = [];
    let cache: ProjCache | null = null;
    for (let step = 0; step < 900; step++) {
      // mimic the reducer: copy, trim to the last 399 when full, push a new (possibly antimeridian-crossing) fix
      track = track.length >= 400 ? track.slice(-399) : track.slice();
      if (r() < 0.9) track.push([lat0 + (r() - 0.5) * 0.01, lon0 + (r() - 0.5) * 0.01 + (seed % 5 === 0 ? 180 : 0)]);
      if (step % 137 === 100) track = []; // a new run
      if (step % 211 === 50) track = track.map((p) => [p[0], p[1]] as LatLon); // identity lost -> fallback
      if (track.length === 0) { cache = null; continue; }
      cache = projectTrackInc(track, origin, cache);
      assert.deepStrictEqual(cache.pts, projectTrack(track, origin));
    }
  }
});

test("incremental projection with a different origin recomputes", () => {
  const t: LatLon[] = [[10, 20], [10.001, 20.001]];
  const c1 = projectTrackInc(t, [10, 20], null);
  const c2 = projectTrackInc(t, [10.5, 20.5], c1);
  assert.deepStrictEqual(c2.pts, projectTrack(t, [10.5, 20.5]));
  const c3 = projectTrackInc([t[1]], [10.5, 20.5], c2);
  assert.deepStrictEqual(c3.pts, projectTrack([t[1]], [10.5, 20.5]));
});
