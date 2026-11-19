import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { test } from "node:test";
import { computeCapabilities, deriveConsoleMode } from "../src/lib/consoleMode.ts";
import { buildSignedAuthHeaders, generateNonce, getApiToken, saveApiToken, signCanonicalRequest } from "../src/lib/requestAuth.ts";

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
  assert.equal(headers["X-Aegis-Token"], token);
  assert.ok(headers["X-Aegis-Nonce"]);
  assert.ok(headers["X-Aegis-Timestamp"]);
  assert.ok(headers["X-Aegis-Signature"]);
  saveApiToken("");
});
