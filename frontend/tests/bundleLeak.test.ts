import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

// Production-bundle leakage: VITE_* values are public by construction, so the API token must never reach a shipped bundle.
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const viteBin = join(root, "node_modules", "vite", "bin", "vite.js");
const CANARY = "CANARY-aegis-token-9f3b7c1d2e";

function build(outDir: string, extraEnv: Record<string, string>) {
  const env: NodeJS.ProcessEnv = { ...process.env, ...extraEnv };
  if (!("VITE_AEGIS_API_TOKEN" in extraEnv)) delete env.VITE_AEGIS_API_TOKEN;
  return spawnSync(process.execPath, [viteBin, "build", "--outDir", outDir, "--emptyOutDir"], {
    cwd: root, env, encoding: "utf8", timeout: 240_000,
  });
}

function* walk(dir: string): Generator<string> {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* walk(p);
    else yield p;
  }
}

test("a production build with VITE_AEGIS_API_TOKEN set fails and emits no bundle", () => {
  const out = mkdtempSync(join(tmpdir(), "aegis-leak-fail-"));
  try {
    const r = build(out, { VITE_AEGIS_API_TOKEN: CANARY });
    assert.notEqual(r.status, 0, "build must fail when the token variable is set");
    assert.match(`${r.stderr}${r.stdout}`, /VITE_AEGIS_API_TOKEN is dev-server only/);
    assert.ok(!`${r.stderr}${r.stdout}`.includes(CANARY), "the failure message must not echo the secret");
    const emitted = [...walk(out)].filter((f) => f.endsWith(".js"));
    assert.equal(emitted.length, 0, "no JS bundle may be written by a failed build");
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});

test("a normal production build contains neither the variable name nor a canary", () => {
  const out = mkdtempSync(join(tmpdir(), "aegis-leak-ok-"));
  try {
    const r = build(out, {});
    assert.equal(r.status, 0, `build failed:\n${r.stderr}${r.stdout}`);
    const files = [...walk(out)];
    assert.ok(files.some((f) => f.endsWith(".js")), "expected a JS bundle");
    for (const f of files) {
      const text = readFileSync(f, "utf8");
      assert.ok(!text.includes("VITE_AEGIS_API_TOKEN"), `${f} references VITE_AEGIS_API_TOKEN`);
      assert.ok(!text.includes(CANARY), `${f} contains the canary`);
    }
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});
