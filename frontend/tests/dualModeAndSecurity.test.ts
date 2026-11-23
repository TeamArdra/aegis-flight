import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { test } from "node:test";
import { computeCapabilities, deriveConsoleMode } from "../src/lib/consoleMode.ts";
import { buildSignedAuthHeaders, computeKeyId, isLoopbackOrigin, generateNonce, getApiToken, saveApiToken, signCanonicalRequest } from "../src/lib/requestAuth.ts";

test("deriveConsoleMode enforces Flight Ops on non-SIM environments", () => {
  assert.equal(deriveConsoleMode("SIM", null), "demo");
  assert.equal(deriveConsoleMode("SIM", "flight-ops"), "flight-ops");
  // Any non-SIM source forces Flight Ops regardless of user override
  assert.equal(deriveConsoleMode("SITL", "demo"), "flight-ops");
  assert.equal(deriveConsoleMode("BENCH", "demo"), "flight-ops");
  assert.equal(deriveConsoleMode("REPLAY", "demo"), "flight-ops");
});

test("computeCapabilities gates simulation injection and armed/remote bench setup", () => {
  const simDemo = computeCapabilities("SIM", null, false, "127.0.0.1");
  assert.equal(simDemo.simInjectAllowed, true);
  assert.equal(simDemo.benchSetupAllowed, true);

  const liveDisarmedLocal = computeCapabilities("BENCH", null, false, "127.0.0.1");
  assert.equal(liveDisarmedLocal.simInjectAllowed, false);
  assert.equal(liveDisarmedLocal.benchSetupAllowed, true);

  const liveArmedLocal = computeCapabilities("BENCH", null, true, "127.0.0.1");
  assert.equal(liveArmedLocal.benchSetupAllowed, false);
  assert.match(liveArmedLocal.benchBlockedReason ?? "", /ARMED/i);

  const remoteDisarmed = computeCapabilities("BENCH", null, false, "192.168.1.50");
  assert.equal(remoteDisarmed.benchSetupAllowed, false);
  assert.match(remoteDisarmed.benchBlockedReason ?? "", /loopback/i);
});

test("signCanonicalRequest matches Node crypto HMAC-SHA256 verification", async () => {
  const token = "companion-hmac-secret-99";
  const body = JSON.stringify({ mode: "advisory" });
  const ts = "1760000000.123";
  const nonce = generateNonce();
  assert.ok(nonce.length >= 16);

  const webCryptoSig = await signCanonicalRequest(token, "POST", "/api/defense/mode", ts, nonce, body);
  const bodyHash = createHmac ? await (async () => {
    const { createHash } = await import("node:crypto");
    return createHash("sha256").update(body).digest("hex");
  })() : "";
  const canonical = `POST\n/api/defense/mode\n${ts}\n${nonce}\n${bodyHash}`;
  const expectedSig = createHmac("sha256", token).update(canonical).digest("hex");
  assert.equal(webCryptoSig, expectedSig);

  saveApiToken(token);
  assert.equal(getApiToken(), token);
  const headers = await buildSignedAuthHeaders("POST", "/api/defense/mode", body);
  assert.equal(headers["X-Aegis-Token"], undefined); // signed-only: the raw token is not sent
  assert.equal(headers["X-Aegis-Key-Id"], (await computeKeyId(token)));
  assert.ok(headers["X-Aegis-Nonce"]);
  assert.ok(headers["X-Aegis-Timestamp"]);
  assert.ok(headers["X-Aegis-Signature"]);
  saveApiToken("");
});

function fakeStorage(init: Record<string, string> = {}) {
  const m = new Map(Object.entries(init));
  return {
    getItem: (k: string) => (m.has(k) ? m.get(k)! : null),
    setItem: (k: string, v: string) => void m.set(k, v),
    removeItem: (k: string) => void m.delete(k),
    has: (k: string) => m.has(k),
  };
}

test("legacy localStorage API token is migrated once into sessionStorage and removed", async () => {
  // fresh module instance so the in-memory token cache is empty
  const mod = await import(`../src/lib/requestAuth.ts?migrate=${Date.now()}`);
  const local = fakeStorage({ aegis_api_token: "  legacy-token  " });
  const session = fakeStorage();
  (globalThis as any).window = { localStorage: local, sessionStorage: session };
  try {
    assert.equal(mod.getApiToken(), "legacy-token");
    assert.equal(local.has("aegis_api_token"), false);
    assert.equal(session.getItem("aegis_api_token_session"), "legacy-token");
    assert.equal(mod.getApiToken(), "legacy-token"); // second read comes from memory/session
  } finally {
    delete (globalThis as any).window;
  }
});

test("session token wins over a legacy key, and the legacy key is not read", async () => {
  const mod = await import(`../src/lib/requestAuth.ts?nomigrate=${Date.now()}`);
  const local = fakeStorage({ aegis_api_token: "old" });
  const session = fakeStorage({ aegis_api_token_session: "new" });
  (globalThis as any).window = { localStorage: local, sessionStorage: session };
  try {
    assert.equal(mod.getApiToken(), "new");
  } finally {
    delete (globalThis as any).window;
  }
});

test("without crypto.subtle: operator warning is raised and only the token header is sent", async () => {
  const mod = await import(`../src/lib/requestAuth.ts?nosubtle=${Date.now()}`);
  mod.saveApiToken("tok-123");
  const desc = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  Object.defineProperty(globalThis, "crypto", { value: { randomUUID: () => "x" }, configurable: true });
  try {
    const st = mod.getSigningStatus();
    assert.equal(st.available, false);
    assert.match(st.warning ?? "", /signing is unavailable/i);
    const h = await mod.buildSignedAuthHeaders("POST", "/api/x", "{}", undefined, "http://127.0.0.1:8000");
    assert.equal(h["X-Aegis-Token"], "tok-123");
    await assert.rejects(() => mod.buildSignedAuthHeaders("POST", "/api/x", "{}", undefined, "http://192.168.1.50:8000"), /non-loopback/);
    assert.equal(h["X-Aegis-Signature"], undefined); // transmission unchanged from before
  } finally {
    if (desc) Object.defineProperty(globalThis, "crypto", desc);
    mod.saveApiToken("");
  }
  // with subtle available and a token: no warning; with no token: no warning
  assert.equal(mod.getSigningStatus().warning, null);
});

test("authenticated GET headers carry token and signature over an empty body", async () => {
  saveApiToken("get-token-1");
  try {
    const h = await buildSignedAuthHeaders("GET", "/api/setup/discover-ports");
    assert.equal(h["X-Aegis-Token"], undefined);
    const expected = await signCanonicalRequest("get-token-1", "GET", "/api/setup/discover-ports", h["X-Aegis-Timestamp"], h["X-Aegis-Nonce"], "");
    assert.equal(h["X-Aegis-Signature"], expected);
  } finally {
    saveApiToken("");
  }
});

test("key id matches the backend derivation and loopback origin detection", async () => {
  const { createHash } = await import("node:crypto");
  const expected = createHash("sha256").update("aegis-key-id:abc").digest("hex").slice(0, 16);
  assert.equal(await computeKeyId("abc"), expected);
  assert.equal(isLoopbackOrigin("http://localhost:5173"), true);
  assert.equal(isLoopbackOrigin("http://127.0.0.1:8000"), true);
  assert.equal(isLoopbackOrigin("http://[::1]:8000"), true);
  assert.equal(isLoopbackOrigin("http://192.168.1.50:8000"), false);
  assert.equal(isLoopbackOrigin("https://gcs.example.com"), false);
});
