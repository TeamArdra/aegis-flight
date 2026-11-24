// Build provenance for the dashboard bundle (issue #180).
//
// frontend/dist is untracked and served by `aegis serve`, so a stale local build can silently
// ship old UI. This module records which UI source a bundle was built from (build-info.json,
// emitted by vite.config.ts) and can verify a bundle against the current source.
//
//   node frontend/scripts/provenance.mjs                       print the current build info
//   node frontend/scripts/provenance.mjs --check <distDir>     verify a built bundle
//
// Plain ESM, node built-ins only. Nothing machine-specific (paths, user names, env) is recorded.
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

// Must stay in step with OVERCLAIM in frontend/tests/wording.test.ts (phrases that overstate the evidence, issue #23).
export const BANNED = /NEUTRALI[SZ]|holding flight integrity|armed and ready|protecting flight|golden tracking|loitering/i;

// UI source inputs. vite.config.ts and scripts/ are deliberately excluded: the hash identifies the UI source, not the tooling.
export const UI_SOURCE_INPUTS = [
  "src/",
  "index.html",
  "public/",
  "package.json",
  "package-lock.json",
  "tsconfig.json",
];

function* walk(dir) {
  for (const name of readdirSync(dir).sort()) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* walk(p);
    else yield p;
  }
}

function inputFiles(frontendRoot) {
  const files = [];
  for (const entry of UI_SOURCE_INPUTS) {
    const abs = join(frontendRoot, entry);
    if (!existsSync(abs)) continue;
    if (statSync(abs).isDirectory()) files.push(...walk(abs));
    else files.push(abs);
  }
  return files
    .map((abs) => ({ abs, rel: relative(frontendRoot, abs).split(sep).join("/") }))
    .sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0));
}

// sha256 over sorted (posix relative path NUL content NUL), CRLF normalised to LF so Windows and Linux checkouts agree.
export function sourceHash(frontendRoot) {
  const h = createHash("sha256");
  for (const { abs, rel } of inputFiles(frontendRoot)) {
    const text = readFileSync(abs).toString("latin1").replace(/\r\n/g, "\n");
    h.update(rel);
    h.update("\0");
    h.update(Buffer.from(text, "latin1"));
    h.update("\0");
  }
  return h.digest("hex");
}

function git(frontendRoot, args) {
  try {
    const r = spawnSync("git", args, { cwd: frontendRoot, encoding: "utf8", timeout: 15_000 });
    if (r.error || r.status !== 0) return null;
    return r.stdout;
  } catch {
    return null;
  }
}

// {commit, dirty}; both null when git is unavailable or this is not a checkout (the archived submission is built outside git).
export function gitInfo(frontendRoot) {
  const head = git(frontendRoot, ["rev-parse", "HEAD"]);
  if (head === null) return { commit: null, dirty: null };
  const status = git(frontendRoot, ["status", "--porcelain", "--", "."]);
  if (status === null) return { commit: head.trim(), dirty: null };
  const dirty = status.split(/\r?\n/).some((line) => {
    if (!line.trim()) return false;
    // porcelain: "XY path" (renames: "XY old -> new"); paths are repo-root relative, so strip up to "frontend/".
    const paths = line.slice(3).split(" -> ").map((p) => p.replace(/^"|"$/g, ""));
    return paths.some((p) => {
      const rel = p.includes("frontend/") ? p.slice(p.indexOf("frontend/") + "frontend/".length) : p;
      return UI_SOURCE_INPUTS.some((i) => (i.endsWith("/") ? rel.startsWith(i) : rel === i));
    });
  });
  return { commit: head.trim(), dirty };
}

export function buildInfo(frontendRoot) {
  const g = gitInfo(frontendRoot);
  return {
    schema: 1,
    source_hash: sourceHash(frontendRoot),
    source_commit: g.commit,
    source_dirty: g.dirty,
    built_at: new Date().toISOString(),
  };
}

// Exit 0 only when build-info.json matches the current source and no emitted file contains banned wording.
function check(distDir) {
  const infoPath = join(distDir, "build-info.json");
  if (!existsSync(infoPath)) {
    console.error("FAIL: build-info.json is missing from the bundle (not built with this tooling). Rebuild: npm --prefix frontend run build");
    return 2;
  }
  const frontendRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  let info;
  try {
    info = JSON.parse(readFileSync(infoPath, "utf8"));
  } catch (e) {
    console.error(`FAIL: build-info.json is not valid JSON (${e.message})`);
    return 1;
  }
  let failed = false;
  const current = sourceHash(frontendRoot);
  if (info.source_hash === current) {
    console.log(`OK: bundle source hash matches current UI source (${current.slice(0, 12)})`);
  } else {
    failed = true;
    console.error(
      `FAIL: bundle was built from a different UI source (bundle ${String(info.source_hash).slice(0, 12)}, current ${current.slice(0, 12)}). Rebuild: npm --prefix frontend run build`,
    );
  }
  const hits = [];
  let scanned = 0;
  for (const f of walk(distDir)) {
    scanned += 1;
    const m = readFileSync(f, "utf8").match(BANNED);
    if (m) hits.push(`${relative(distDir, f).split(sep).join("/")}: "${m[0]}"`);
  }
  if (hits.length === 0) {
    console.log(`OK: no banned wording in ${scanned} bundle file(s)`);
  } else {
    failed = true;
    console.error(`FAIL: banned wording in bundle:\n  ${hits.join("\n  ")}`);
  }
  if (info.source_dirty) console.log("note: bundle was built from a working tree with uncommitted UI changes");
  console.log(`built from commit ${info.source_commit ?? "unknown"} at ${info.built_at ?? "unknown"}`);
  return failed ? 1 : 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args[0] === "--check") {
    if (!args[1]) {
      console.error("usage: provenance.mjs --check <distDir>");
      process.exit(2);
    }
    process.exit(check(resolve(args[1])));
  } else if (args.length === 0) {
    console.log(JSON.stringify(buildInfo(resolve(dirname(fileURLToPath(import.meta.url)), "..")), null, 2));
  } else {
    console.error("usage: provenance.mjs [--check <distDir>]");
    process.exit(2);
  }
}
