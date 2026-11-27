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
    assert.equal(info.schema, 2);
    assert.ok(info.files && Object.keys(info.files).includes("index.html"), "build-info.json must carry an output manifest with index.html");
    assert.ok(!("build-info.json" in info.files), "the manifest does not list build-info.json itself");
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

    // (e) fail closed on a tampered, incomplete or malformed bundle (each case on a fresh copy of the good build).
    const fresh = () => {
      rmSync(copy, { recursive: true, force: true });
      cpSync(out, copy, { recursive: true });
    };
    const mustFail = (label: string, want: RegExp, code?: number) => {
      const r = check(copy);
      assert.notEqual(r.status, 0, `${label} must fail --check`);
      if (code !== undefined) assert.equal(r.status, code, `${label}: exit code`);
      assert.match(r.stderr, want, `${label}: message`);
      assert.doesNotMatch(r.stderr, /TypeError|\n\s+at /, `${label}: must be a clean message, not a stack trace`);
    };
    const jsFile = () => [...walk(copy)].find((f) => f.endsWith(".js"))!;

    rmSync(join(copy, "build-info.json"));
    mustFail("a missing build-info.json", /build-info\.json is missing/, 2);

    const missingDir = check(join(copy, "does-not-exist"));
    assert.equal(missingDir.status, 2, "a missing dist directory must exit 2");
    assert.match(missingDir.stderr, /bundle directory not found/);

    for (const [label, body] of [["null", "null"], ["an array", "[]"], ["an empty object", "{}"], ["truncated JSON", '{"schema":2']] as const) {
      fresh();
      writeFileSync(join(copy, "build-info.json"), body);
      mustFail(`build-info.json that is ${label}`, /not valid JSON|malformed/, 1);
    }
    fresh();
    writeFileSync(join(copy, "build-info.json"), JSON.stringify({ ...info, schema: 1 }));
    mustFail("an old schema (no manifest guarantee)", /unsupported schema/, 1);
    fresh();
    const { built_at: _drop, ...noTime } = info;
    writeFileSync(join(copy, "build-info.json"), JSON.stringify(noTime));
    mustFail("a missing built_at", /built_at/, 1);
    fresh();
    writeFileSync(join(copy, "build-info.json"), JSON.stringify({ ...info, files: undefined }));
    mustFail("a missing output manifest", /files/, 1);

    fresh();
    writeFileSync(jsFile(), `${readFileSync(jsFile(), "utf8")}
/* harmless edit */
`);
    mustFail("a bundle file modified after the build", /modified after build/, 1);
    fresh();
    rmSync(join(copy, "index.html"));
    mustFail("a missing index.html", /missing: index\.html/, 1);
    fresh();
    rmSync(jsFile());
    mustFail("a missing JS bundle", /missing: assets\//, 1);
    fresh();
    writeFileSync(join(copy, "stray.txt"), "left over from an older build");
    mustFail("a file that is not in the manifest", /not in build-info\.json: stray\.txt/, 1);
    fresh();
    for (const f of [...walk(copy)]) if (!f.endsWith("build-info.json")) rmSync(f);
    mustFail("a bundle holding only build-info.json", /missing: index\.html/, 1);
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
