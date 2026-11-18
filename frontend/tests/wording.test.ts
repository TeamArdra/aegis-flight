import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import {
  DECISION_COMPUTE_LABEL,
  DEFENSE_LIMITS,
  MODE_OPTIONS,
  ladderStates,
  postureBanner,
  quietThreatText,
  summaryFallback,
} from "../src/lib/wording.ts";
import type { DefenseMode, Environment, MitigationState } from "../src/types/index.ts";

// Phrases that overstate what the evidence supports (issue #23).
const OVERCLAIM = /NEUTRALI[SZ]|holding flight integrity|armed and ready|protecting flight|golden tracking|loitering/i;

const MODES: DefenseMode[] = ["passive", "advisory", "active-ips"];
const ENVS: Array<Environment | null> = ["SIM", "REPLAY", "SITL", "BENCH", null];
const STATES: MitigationState[] = ["NOMINAL", "AUTO_MITIGATING", "SAFE_HOLD", "GCS_TAKEOVER"];

/* ------------------------------------------------------------ threat card */
test("threat card: on ground and disarmed", () => {
  assert.equal(quietThreatText({ armed: false, groundspeed: 0 }), "On ground · disarmed · no active threat");
  assert.equal(quietThreatText({ armed: false, groundspeed: 0.49 }), "On ground · disarmed · no active threat");
});

test("threat card: armed state unknown", () => {
  assert.equal(quietThreatText(null), "No active threat");
  assert.equal(quietThreatText(undefined), "No active threat");
  assert.equal(quietThreatText({ armed: null, groundspeed: 12 }), "No active threat");
  assert.equal(quietThreatText({ armed: null, groundspeed: 0 }), "No active threat");
});

test("threat card: nominal flight only when armed and moving", () => {
  assert.equal(quietThreatText({ armed: true, groundspeed: 0.5 }), "No active threat · nominal flight");
  assert.equal(quietThreatText({ armed: true, groundspeed: 8 }), "No active threat · nominal flight");
  assert.equal(quietThreatText({ armed: true, groundspeed: 0.2 }), "Armed · no active threat");
  assert.equal(quietThreatText({ armed: true, groundspeed: null }), "Armed · no active threat");
  assert.equal(quietThreatText({ armed: false, groundspeed: 3 }), "Disarmed · no active threat");
  assert.equal(quietThreatText({ armed: false, groundspeed: null }), "Disarmed · no active threat");
  for (const t of [null, { armed: false, groundspeed: 0 }, { armed: null, groundspeed: 9 }, { armed: true, groundspeed: 0 }]) {
    assert.doesNotMatch(quietThreatText(t), /nominal flight/);
  }
});

/* ---------------------------------------------------------- defense panel */
test("defense banner: every mode × attack × environment is factual", () => {
  for (const mode of MODES) {
    for (const attack of [false, true]) {
      for (const env of ENVS) {
        const b = postureBanner(mode, attack, attack ? "gps_spoofing" : null, env);
        const all = `${b.title} ${b.desc} ${b.badge}`;
        assert.doesNotMatch(all, OVERCLAIM, `${mode}/${attack}/${env}: ${all}`);
        assert.ok(b.title && b.desc && b.badge && b.cls);
        if (attack) assert.match(b.title, /gps spoofing detected/);
        if (mode !== "active-ips") assert.match(all, /[Nn]othing (is )?(sent|transmitted) to the flight controller/);
        if (mode === "active-ips") {
          assert.match(all, /Not flight-validated/);
          if (env === "SIM") assert.match(b.desc, /Simulated/);
          else assert.match(b.desc, /sidecar counter-command path failed in SITL/);
        }
      }
    }
  }
});

test("defense banner: the issue's posture statements", () => {
  assert.equal(postureBanner("passive", false).title, "PASSIVE: monitoring, nothing transmitted to the flight controller");
  const ips = postureBanner("active-ips", false, null, "SITL");
  assert.equal(ips.title, "ACTIVE IPS (verified in ArduCopter SITL only)");
  assert.match(ips.desc, /^The inline bridge drops hostile frames\./);
  assert.equal(postureBanner("advisory", false).badge, "ADVISORY");
  assert.equal(postureBanner("passive", true, "dos").badge, "DETECTED");
  assert.equal(postureBanner("active-ips", true).title, "ACTIVE IPS: intrusion detected");
});

test("defense ladder: every mode × state has a factual description", () => {
  for (const mode of MODES) {
    const ladder = ladderStates(mode);
    assert.deepEqual(ladder.map((s) => s.id), STATES);
    for (const s of ladder) assert.doesNotMatch(`${s.label} ${s.desc}`, OVERCLAIM, `${mode}/${s.id}`);
    assert.doesNotMatch(ladder[0].desc, /flight/i); // NOMINAL says nothing about the vehicle flying
  }
  for (const s of ladderStates("passive")) assert.doesNotMatch(s.desc, /requested|engaged/);
});

test("defense mode selector, summary fallback and compute label", () => {
  assert.deepEqual(MODE_OPTIONS.map((m) => m.id), MODES);
  for (const m of MODE_OPTIONS) assert.doesNotMatch(m.desc, OVERCLAIM);
  assert.match(MODE_OPTIONS[2].desc, /verified in ArduCopter SITL only/);
  for (const mode of MODES) assert.doesNotMatch(summaryFallback(mode), /Autonomous/);
  assert.equal(DECISION_COMPUTE_LABEL, "Decision compute");
});

test("defense limits keep the three disclosures", () => {
  const all = DEFENSE_LIMITS.join(" ");
  assert.match(all, /uplink filter.*off by default/i);
  assert.match(all, /20 s after the bridge starts/);
  assert.match(all, /only the downlink/);
});

/* -------------------------------------------------------- source grep gate */
function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

test("frontend/src has no overclaim phrases", () => {
  const src = join(import.meta.dirname, "..", "src");
  const hits = walk(src)
    .filter((f) => /\.(tsx?|css)$/.test(f))
    .filter((f) => /NEUTRALIZED|holding flight integrity|armed and ready/.test(readFileSync(f, "utf8")));
  assert.deepEqual(hits, []);
  const panel = readFileSync(join(src, "components", "DefensePanel.tsx"), "utf8");
  assert.doesNotMatch(panel, /Detection Latency/);
  const panels = readFileSync(join(src, "components", "panels.tsx"), "utf8");
  assert.doesNotMatch(panels, /No active threat — nominal flight/);
});
