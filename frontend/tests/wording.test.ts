import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import {
  ACTION_TIMELINE_CAPTION,
  CONTROLLER_SUMMARY_CAPTION,
  DECISION_COMPUTE_LABEL,
  DEFENSE_LIMITS,
  MODE_OPTIONS,
  controllerSummaryLabel,
  emptyTimelineText,
  internalStateCaption,
  internalStateTitle,
  ladderStates,
  mitigationPresentation,
  overrideFallback,
  postureBanner,
  quietThreatText,
  summaryFallback,
} from "../src/lib/wording.ts";
import type { DefenseMode, Environment, MitigationState } from "../src/types/index.ts";

// Phrases that overstate what the evidence supports (issue #23).
const OVERCLAIM = /NEUTRALI[SZ]|holding flight integrity|armed and ready|protecting flight|golden tracking|loitering|zero-interference|cyber-physical shield/i;

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

/* ----------------------------------- internal state vs executed actions (#181) */
const THREATS = [
  { label: "none", t: { threat: false, attack_type: "none", severity: "none" } },
  { label: "low", t: { threat: true, attack_type: "gps_spoofing", severity: "low" } },
  { label: "high", t: { threat: true, attack_type: "command_injection", severity: "high" } },
];
const QUEUED: Array<number | null | undefined> = [undefined, null, 0, 3];
// Affirmative claims that something was transmitted or acted on.
const ACTED = /\b(sent|transmitted|dispatched|emitted|executed|engaged)\b/i;
const NEGATION = /\b(no|not|nothing|never|none)\b/i;
/** Every sentence mentioning an "acted" verb must be negated: "not transmitted" is fine, "was sent" is not. */
function affirmativeClaims(text: string): string[] {
  return text.split(/(?<=[.;])\s+/).filter((s) => ACTED.test(s) && !NEGATION.test(s));
}

type Rows = ReturnType<typeof mitigationPresentation>;
function allRows(): Array<{ key: string; rows: Rows }> {
  const out: Array<{ key: string; rows: Rows }> = [];
  for (const mode of MODES) for (const state of STATES) for (const th of THREATS) for (const env of ENVS) for (const q of QUEUED) {
    out.push({ key: `${mode}/${state}/${th.label}/${env}/${q}`, rows: mitigationPresentation({ mode, state, environment: env, threat: th.t, queuedFrames: q }) });
  }
  return out;
}
const row = (rows: Rows, id: string) => rows.find((r) => r.id === id)!;

test("mitigation presentation: four labelled rows for every mode x state x threat x environment", () => {
  for (const { key, rows } of allRows()) {
    assert.deepEqual(rows.map((r) => r.id), ["threat", "internal", "mode", "transmission"], key);
    for (const r of rows) {
      assert.ok(r.label && r.value, `${key}/${r.id}`);
      assert.doesNotMatch(`${r.label} ${r.value}`, OVERCLAIM, `${key}/${r.id}`);
    }
  }
});

test("mitigation presentation: threat row reports the assessment only", () => {
  const mk = (t: (typeof THREATS)[number]["t"]) => row(mitigationPresentation({ mode: "passive", state: "NOMINAL", threat: t }), "threat").value;
  assert.equal(mk(THREATS[0].t), "No threat detected");
  assert.match(mk(THREATS[1].t), /gps spoofing.*severity low/);
  assert.match(mk(THREATS[2].t), /command injection.*severity high/);
  assert.equal(row(mitigationPresentation({ mode: "passive", state: "NOMINAL" }), "threat").value, "No threat detected");
});

test("mitigation presentation: internal state is always labelled as the controller's own state", () => {
  for (const { key, rows } of allRows()) {
    const r = row(rows, "internal");
    assert.match(r.label, /[Ii]nternal/, key);
    assert.match(r.label, /[Cc]ontroller/, key);
    assert.match(r.value, /internal state, not proof of an executed action/, key);
  }
  const missing = row(mitigationPresentation({ mode: "passive", state: null }), "internal");
  assert.match(missing.label, /[Ii]nternal/);
  assert.match(missing.value, /Not reported/);
});

test("mitigation presentation: configured mode row", () => {
  assert.equal(row(mitigationPresentation({ mode: "passive", state: "NOMINAL" }), "mode").value, "PASSIVE");
  assert.equal(row(mitigationPresentation({ mode: "advisory", state: "NOMINAL" }), "mode").value, "ADVISORY");
  assert.equal(row(mitigationPresentation({ mode: "active-ips", state: "NOMINAL" }), "mode").value, "ACTIVE IPS");
});

test("mitigation presentation: PASSIVE transmission is none, even in a mitigating state or without a payload", () => {
  const passive = allRows().filter((x) => x.key.startsWith("passive/"));
  assert.ok(passive.length > 0);
  for (const { key, rows } of passive) {
    assert.equal(row(rows, "transmission").value, "None: PASSIVE never transmits", key);
  }
  assert.equal(row(mitigationPresentation({ mode: "passive", state: null }), "transmission").value, "None: PASSIVE never transmits");
});

test("mitigation presentation: ADVISORY sends no counter-command and makes no affirmative transmission claim", () => {
  const advisory = allRows().filter((x) => x.key.startsWith("advisory/"));
  assert.ok(advisory.length > 0);
  for (const { key, rows } of advisory) {
    const v = row(rows, "transmission").value;
    assert.match(v, /No counter-command or mode command is sent/, key);
    assert.match(v, /nothing to the flight controller/, key);
    assert.match(v, /STATUSTEXT alert notifications .* not reported by this API/, key);
    assert.deepEqual(affirmativeClaims(v), [], `${key}: ${v}`);
    assert.doesNotMatch(v, /none at all|alerts? (was|were|have been) (sent|delivered)/i, key);
  }
  assert.match(row(mitigationPresentation({ mode: "advisory", state: null }), "transmission").value, /^No counter-command/);
});

test("mitigation presentation: ACTIVE IPS in SIM/REPLAY is modelled only", () => {
  for (const env of ["SIM", "REPLAY"] as const) {
    for (const q of QUEUED) {
      const v = row(mitigationPresentation({ mode: "active-ips", state: "SAFE_HOLD", environment: env, queuedFrames: q }), "transmission").value;
      assert.equal(v, "None: no live transport in SIM/REPLAY (modelled only)", `${env}/${q}`);
    }
  }
});

test("mitigation presentation: ACTIVE IPS on SITL/BENCH/unknown environment is not reported, even with queued frames", () => {
  for (const env of ["SITL", "BENCH", null] as const) {
    for (const state of STATES) {
      const at = (q: number | null | undefined) => row(mitigationPresentation({ mode: "active-ips", state, environment: env, queuedFrames: q }), "transmission").value;
      const v3 = at(3);
      assert.equal(v3, "Not reported by the API (3 frames queued by the controller)", `${env}/${state}`);
      assert.deepEqual(affirmativeClaims(v3), [], v3);
      assert.equal(at(1), "Not reported by the API (1 frame queued by the controller)");
      assert.equal(at(0), "Not reported by the API (0 frames queued by the controller)");
      for (const q of [undefined, null]) {
        assert.equal(at(q), "Not reported by the API (queued frame count not reported)", `${env}/${state}/${q}`);
      }
    }
  }
});

test("mitigation presentation: ACTIVE IPS without a mitigation payload is unknown", () => {
  for (const env of ENVS) {
    for (const state of [null, undefined]) {
      const v = row(mitigationPresentation({ mode: "active-ips", state, environment: env, queuedFrames: 2 }), "transmission").value;
      assert.match(v, /^Unknown/, `${env}/${state}`);
    }
  }
});

test("internal-state, summary, timeline and override wording never claims an executed action", () => {
  for (const mode of MODES) {
    assert.match(internalStateTitle(mode), /CONTROLLER INTERNAL/);
    assert.match(internalStateCaption(mode), /internal state machine/);
    assert.match(internalStateCaption(mode), /not proof that any action was executed/);
    assert.match(controllerSummaryLabel(mode), /CONTROLLER SUMMARY/);
    const empty = emptyTimelineText(mode);
    assert.doesNotMatch(empty, /armed|dispatched|ready/i, `${mode}: ${empty}`);
    for (const text of [internalStateTitle(mode), internalStateCaption(mode), controllerSummaryLabel(mode), empty]) {
      assert.doesNotMatch(text, OVERCLAIM);
      assert.deepEqual(affirmativeClaims(text), [], text);
    }
  }
  assert.match(CONTROLLER_SUMMARY_CAPTION, /controller, not a confirmed action/);
  assert.match(ACTION_TIMELINE_CAPTION, /controller decisions, not confirmed transmissions/);
  assert.match(overrideFallback("safe_hold"), /accepted by the controller \(not confirmed on a vehicle\)/);
  assert.doesNotMatch(overrideFallback("safe_hold"), /executed/);
});

test("reworded banners and ladder no longer imply executed actions", () => {
  const ipsAttack = postureBanner("active-ips", true, "gps_spoofing", "SITL");
  assert.doesNotMatch(ipsAttack.desc, /lists what was dropped or sent/);
  assert.match(ipsAttack.desc, /not confirmed transmissions/);
  assert.doesNotMatch(postureBanner("advisory", true, "dos").desc, /Alert raised for the GCS/);
  assert.equal(summaryFallback("active-ips"), "ACTIVE IPS: no controller action recorded");
  const adv = ladderStates("advisory")[1].desc;
  assert.doesNotMatch(adv, /raised for the GCS/);
  assert.match(adv, /nothing executed/);
  for (const s of ladderStates("active-ips").slice(1)) assert.match(s.desc, /controller|internal state/);
});

test("DefensePanel renders the four-row block and no longer hard-codes transmission claims", () => {
  const panel = readFileSync(join(import.meta.dirname, "..", "src", "components", "DefensePanel.tsx"), "utf8");
  assert.match(panel, /data-testid="mitigation-presentation"/);
  assert.match(panel, /mitigation-row-\$\{r\.id\}/);
  assert.doesNotMatch(panel, /0 BYTES SENT/);
  assert.doesNotMatch(panel, /STATUSTEXT \(Active\)|Alert Frames Emitted|Last Advisory Sent|\(DROPPED\)|TX\)|dispatched|armed and ready|executed`/);
  assert.doesNotMatch(panel, /speedBias > 0\.5|batteryBias > 0\.1/);
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
