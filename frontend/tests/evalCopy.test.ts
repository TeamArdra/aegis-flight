import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
// @ts-expect-error plain ESM tooling module without type declarations
import { BANNED } from "../scripts/provenance.mjs";
import { INTEGRATION_TAGLINE, VALIDATION_FOOT, VAL_ROWS } from "../src/lib/evalCopy.ts";

// The reference panels quote figures by hand. These tests pin every quoted figure to the committed artifact it names,
// and keep the overclaim wording out of the copy (issue #23; AGENTS.md section 6: env tag + claim class on every number).
const artifacts = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "artifacts");
const have = existsSync(join(artifacts, "benchmarks", "summary.md"));
const read = (p: string) => readFileSync(join(artifacts, p), "utf8");
const row = (tier: string) => VAL_ROWS.find((r) => r.tier === tier)!;

test("overclaim phrases are banned in the bundle check and absent from the panel copy", () => {
  for (const phrase of ["zero-interference", "cyber-physical shield", "armed and ready", "NEUTRALISED", "loitering"]) {
    assert.match(phrase, BANNED, phrase);
  }
  const all = [INTEGRATION_TAGLINE, VALIDATION_FOOT, ...VAL_ROWS.flatMap((r) => [r.metric, r.value])].join("\n");
  assert.doesNotMatch(all, BANNED);
  assert.match(INTEGRATION_TAGLINE, /verified in ArduCopter SITL only/);
  assert.match(INTEGRATION_TAGLINE, /not flight-validated/);
});

test("every validation row names its environment tag, artifact and claim scope", () => {
  assert.deepEqual(VAL_ROWS.map((r) => r.tier), ["sim", "expanded", "sitl", "replay"]);
  for (const r of VAL_ROWS) {
    assert.match(r.metric, /artifacts\/\S+\.(md|json)/, `${r.tier}: artifact path`);
    assert.match(r.metric, /SIM|SITL|REPLAY/, `${r.tier}: environment tag`);
    assert.match(r.value, /link-level|false-alarm only|physical faults only/, `${r.tier}: claim class / scope`);
  }
  assert.match(row("sitl").value, /no attacks/);
  assert.match(row("replay").value, /no cyber attacks/);
  assert.match(VALIDATION_FOOT, /Not real-vehicle detection results/);
});

test("validation figures equal the committed artifacts", { skip: have ? false : "artifacts/ not present in this tree" }, () => {
  // baseline: summary.md table
  const base = read("benchmarks/summary.md");
  const cm = base.match(/TP \/ FP \/ TN \/ FN \| (\d+) \/ (\d+) \/ (\d+) \/ (\d+)/)!;
  assert.deepEqual(cm.slice(1).map(Number), [6535, 4, 16826, 65], "Stage-1 baseline confusion counts");
  assert.ok(row("sim").value.includes(`${cm[1]} / ${cm[2]} / ${cm[3]} / ${cm[4]}`));
  const acc = Number(base.match(/\| Accuracy \| ([\d.]+) \|/)![1]);
  const rec = Number(base.match(/\| Recall \(TPR\) \| ([\d.]+) \|/)![1]);
  assert.ok(row("sim").value.includes(`accuracy ${(acc * 100).toFixed(1)}%`));
  assert.ok(row("sim").value.includes(`recall ${(rec * 100).toFixed(1)}%`));
  assert.ok(row("sim").value.includes(`${Number(base.match(/from (\d+) scored decisions/)![1]).toLocaleString("en-US")} decisions`));

  // expanded v2: results.json (grace 5 s / no grace)
  const ext = JSON.parse(read("benchmarks_extended/results.json"));
  const pct = (x: number) => (x * 100).toFixed(1);
  const g5 = ext.binary_grace5, g0 = ext.binary_grace0;
  const v = row("expanded").value;
  assert.ok(v.includes(`5 s grace: accuracy ${pct(g5.accuracy)}%, recall ${pct(g5.recall)}%`), v);
  assert.ok(v.includes(`no grace: accuracy ${pct(g0.accuracy)}%, recall ${pct(g0.recall)}%, FPR ${pct(g0.fpr)}%`), v);

  // SITL held-out: false alarms, calibrated profile (B) vs uncalibrated Stage-1 config (A)
  const sitl = JSON.parse(read("sitl/calibration/evaluation_heldout.json"));
  assert.equal(sitl.attack_status, "NONE");
  const b = sitl.conditions.B.pooled, a = sitl.conditions.A.pooled;
  const n = (x: number) => x.toLocaleString("en-US");
  assert.ok(row("sitl").value.includes(`${b.false_alarm_decisions} / ${n(b.decisions)} false alarms`), row("sitl").value);
  assert.ok(row("sitl").value.includes(`${n(a.false_alarm_decisions)} / ${n(a.decisions)}`), row("sitl").value);
});
