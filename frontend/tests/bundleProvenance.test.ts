import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
// @ts-expect-error plain ESM tooling module without type declarations
import { BANNED, sourceHash } from "../scripts/provenance.mjs";

// Bundle provenance (issue #180): a built bundle names the UI source it came from and can be verified against current source.
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const viteBin = join(root, "node_modules", "vite", "bin", "vite.js");
const provenance = join(root, "scripts", "provenance.mjs");

function build(outDir: string) {
  const env: NodeJS.ProcessEnv = { ...process.env };
  delete env.VITE_AEGIS_API_TOKEN;
  return spawnSync(process.execPath, [viteBin, "build", "--outDir", outDir, "--emptyOutDir"], {
    cwd: root, env, encoding: "utf8", timeout: 240_000,
  });
}

function check(dir: string) {
  return spawnSync(process.execPath, [provenance, "--check", dir], { encoding: "utf8", timeout: 60_000 });
}

function* walk(dir: string): Generator<string> {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* walk(p);
    else yield p;
  }
}

test("a production build emits verifiable provenance and no banned wording", () => {
  const out = mkdtempSync(join(tmpdir(), "aegis-prov-"));
  const copy = mkdtempSync(join(tmpdir(), "aegis-prov-copy-"));
  try {
    const r = build(out);
    assert.equal(r.status, 0, `build failed:\n${r.stderr}${r.stdout}`);

    // (a) build-info.json is emitted, matches an independently computed hash, and carries no machine-specific paths.
    const infoPath = join(out, "build-info.json");
    assert.ok(existsSync(infoPath), "build-info.json must be emitted");
    const raw = readFileSync(infoPath, "utf8");
    const info = JSON.parse(raw);
    assert.equal(info.schema, 1);
    assert.equal(info.source_hash, sourceHash(root));
    assert.match(info.source_hash, /^[0-9a-f]{64}$/);
    assert.ok(!Number.isNaN(Date.parse(info.built_at)), "built_at must be an ISO timestamp");
    assert.ok(!/[A-Za-z]:\\/.test(raw) && !raw.includes("/Users/") && !raw.includes("/home/") && !raw.includes("\\\\"), `absolute path in build-info.json: ${raw}`);

    // (b) no emitted file contains banned wording.
    for (const f of walk(out)) assert.doesNotMatch(readFileSync(f, "utf8"), BANNED, `${f} contains banned wording`);

    // (c) the checker accepts the fresh bundle.
    const ok = check(out);
    assert.equal(ok.status, 0, `--check failed on a fresh build:\n${ok.stderr}${ok.stdout}`);

    // (d) the checker rejects a wrong hash, banned wording, and a missing build-info.json (on temp copies only).
    cpSync(out, copy, { recursive: true });
    writeFileSync(join(copy, "build-info.json"), JSON.stringify({ ...info, source_hash: "0".repeat(64) }));
    const badHash = check(copy);
    assert.notEqual(badHash.status, 0, "a wrong source_hash must fail --check");
    assert.match(badHash.stderr, /different UI source/);

    writeFileSync(join(copy, "build-info.json"), raw);
    const js = [...walk(copy)].find((f) => f.endsWith(".js"));
    assert.ok(js, "expected a JS bundle");
    writeFileSync(js, `${readFileSync(js, "utf8")}\n/* NEUTRALIZED */\n`);
    const banned = check(copy);
    assert.notEqual(banned.status, 0, "banned wording must fail --check");
    assert.match(banned.stderr, /banned wording/i);

    rmSync(join(copy, "build-info.json"));
    assert.equal(check(copy).status, 2, "a missing build-info.json must exit 2");
  } finally {
    rmSync(out, { recursive: true, force: true });
    rmSync(copy, { recursive: true, force: true });
  }
});

test("build-info.json hashes the frontend tree even when vite is launched from another directory", () => {
  const out = mkdtempSync(join(tmpdir(), "aegis-prov-cwd-"));
  const elsewhere = mkdtempSync(join(tmpdir(), "aegis-prov-elsewhere-"));
  try {
    const env: NodeJS.ProcessEnv = { ...process.env };
    delete env.VITE_AEGIS_API_TOKEN;
    const r = spawnSync(
      process.execPath,
      [viteBin, "build", root, "--config", join(root, "vite.config.ts"), "--outDir", out, "--emptyOutDir"],
      { cwd: elsewhere, env, encoding: "utf8", timeout: 240_000 },
    );
    assert.equal(r.status, 0, `build failed:\n${r.stderr}${r.stdout}`);
    const info = JSON.parse(readFileSync(join(out, "build-info.json"), "utf8"));
    assert.equal(info.source_hash, sourceHash(root), "build-info.json must hash the config file's directory, not the cwd");
    assert.equal(check(out).status, 0, "--check must accept a bundle built from another cwd");
  } finally {
    rmSync(out, { recursive: true, force: true });
    rmSync(elsewhere, { recursive: true, force: true });
  }
});

test("sourceHash changes with UI inputs, ignores line endings and tooling files", () => {
  const tmp = mkdtempSync(join(tmpdir(), "aegis-prov-src-"));
  try {
    mkdirSync(join(tmp, "src"));
    mkdirSync(join(tmp, "public"));
    mkdirSync(join(tmp, "scripts"));
    writeFileSync(join(tmp, "src", "a.ts"), "export const a = 1;\n");
    writeFileSync(join(tmp, "public", "m.json"), "{}\n");
    writeFileSync(join(tmp, "index.html"), "<html></html>\n");
    writeFileSync(join(tmp, "package.json"), "{}\n");
    writeFileSync(join(tmp, "vite.config.ts"), "export default {};\n");
    const base = sourceHash(tmp);

    writeFileSync(join(tmp, "src", "a.ts"), "export const a = 2;\n");
    const changed = sourceHash(tmp);
    assert.notEqual(changed, base, "editing a src file must change the hash");

    writeFileSync(join(tmp, "src", "a.ts"), "export const a = 2;\r\n");
    assert.equal(sourceHash(tmp), changed, "CRLF vs LF must not change the hash");

    writeFileSync(join(tmp, "src", "b.ts"), "export const b = 1;\n");
    assert.notEqual(sourceHash(tmp), changed, "adding a src file must change the hash");

    writeFileSync(join(tmp, "public", "m.json"), '{"x":1}\n');
    const afterPublic = sourceHash(tmp);
    writeFileSync(join(tmp, "index.html"), "<html>x</html>\n");
    assert.notEqual(sourceHash(tmp), afterPublic, "editing index.html must change the hash");

    const stable = sourceHash(tmp);
    writeFileSync(join(tmp, "vite.config.ts"), "export default { changed: true };\n");
    writeFileSync(join(tmp, "scripts", "x.mjs"), "// tooling\n");
    assert.equal(sourceHash(tmp), stable, "tooling files are not UI inputs");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
