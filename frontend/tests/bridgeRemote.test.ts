import assert from "node:assert/strict";
import { test } from "node:test";
import {
  canSend, commandView, confirmDeadline, confirmOpen, confirmRemainingS, feedAge, fmtAgo, freshness, isLowering, isPending,
  orderFeed, parseRadioPostureResponse, radioPostureBody, selectBridgeSource, CONTROL_HINT,
} from "../src/lib/bridgeRemote.ts";

const remote = (o: Record<string, unknown> = {}) => ({ present: true, control_available: true, last_command: null, ...o }) as never;
const lc = (result: string, age_s = 0) => ({ op: "posture", result, detail: "d", age_s }) as never;

test("source selection: in-band, then http, then none", () => {
  assert.equal(selectBridgeSource(remote(), "http://x"), "inband");
  assert.equal(selectBridgeSource(remote({ present: false }), "http://x"), "http");
  assert.equal(selectBridgeSource(null, "http://x"), "http");
  assert.equal(selectBridgeSource(null, null), "none");
  assert.equal(selectBridgeSource(remote({ present: false }), null), "none");
});

test("staleness", () => {
  assert.equal(freshness(2), "fresh");
  assert.equal(freshness(10), "fresh");
  assert.equal(freshness(10.5), "stale");
  assert.equal(freshness(31), "lost");
  assert.equal(freshness(null), "lost");
  assert.equal(fmtAgo(4.2), "4 s ago");
  assert.equal(fmtAgo(125), "2 min ago");
  assert.equal(fmtAgo(null), "—");
});

test("feed ordering: newest first, max 20, no mutation", () => {
  const rows = Array.from({ length: 30 }, (_, i) => ({ t: 1700000000 + i, text: `a${i}` }));
  const copy = rows.slice();
  const out = orderFeed(rows);
  assert.equal(out.length, 20);
  assert.equal(out[0].text, "a29");
  assert.equal(out[19].text, "a10");
  assert.deepEqual(rows, copy);
  assert.deepEqual(orderFeed(null), []);
  assert.equal(feedAge(1700000010, 1700000015), 5);
  assert.equal(feedAge(12, 1700000015), null);
});

test("command view states", () => {
  assert.equal(commandView(null).kind, "none");
  assert.equal(commandView(lc("pending")).kind, "pending");
  assert.match(commandView(lc("denied")).text, /denied — d/);
  assert.equal(commandView(lc("accepted")).tone, "ok");
  assert.equal(commandView(lc("confirm_required")).tone, "warn");
  assert.equal(commandView(lc("timeout")).kind, "timeout");
  assert.equal(commandView(lc("failed")).kind, "failed");
});

test("control state machine: pending blocks sending", () => {
  assert.equal(canSend(remote(), false), true);
  assert.equal(canSend(remote(), true), false);
  assert.equal(canSend(remote({ last_command: lc("pending") }), false), false);
  assert.equal(canSend(remote({ last_command: lc("accepted") }), false), true);
  assert.equal(canSend(remote({ control_available: false }), false), false);
  assert.equal(canSend(null, false), false);
  assert.equal(isPending(false, lc("pending")), true);
  assert.equal(isPending(false, null), false);
});

test("lowering from active-ips needs confirmation", () => {
  assert.equal(isLowering("active-ips", "advisory"), true);
  assert.equal(isLowering("active-ips", "passive"), true);
  assert.equal(isLowering("advisory", "passive"), false);
  assert.equal(isLowering("passive", "active-ips"), false);
});

test("confirm countdown and expiry", () => {
  const dl = confirmDeadline(lc("confirm_required", 2), 1000)!;
  assert.equal(dl, 1000 + 8000);
  assert.equal(confirmDeadline(lc("accepted"), 1000), null);
  assert.equal(confirmRemainingS(dl, 1000), 8);
  assert.equal(confirmRemainingS(dl, 5500), 4);
  assert.equal(confirmRemainingS(dl, 9000), 0);
  assert.equal(confirmRemainingS(dl, 20000), 0);
  assert.equal(confirmRemainingS(null, 0), 0);
  assert.equal(confirmDeadline(lc("confirm_required", 0), 0), 10000);
  assert.equal(confirmOpen("advisory", lc("confirm_required"), dl, 5000), true);
  assert.equal(confirmOpen("advisory", lc("confirm_required"), dl, 9000), false); // expired
  assert.equal(confirmOpen(null, lc("confirm_required"), dl, 5000), false); // Cancel cleared the target
  assert.equal(confirmOpen("advisory", lc("pending"), dl, 5000), false); // re-sent
});

test("request body and response mapping", () => {
  assert.deepEqual(JSON.parse(radioPostureBody("advisory")), { mode: "advisory" });
  assert.deepEqual(JSON.parse(radioPostureBody("active-ips", true, true)), { mode: "active-ips", allow_unsigned: true, confirm: true });
  assert.deepEqual(parseRadioPostureResponse(200, { ok: true, pending: true }), { kind: "pending" });
  assert.deepEqual(parseRadioPostureResponse(409, { ok: false, error: "signing_required", message: "m" }), { kind: "signing_required", message: "m" });
  assert.deepEqual(parseRadioPostureResponse(403, { error: "control_unavailable" }), { kind: "unavailable", message: CONTROL_HINT });
  assert.equal(parseRadioPostureResponse(400, { message: "bad" }).kind, "bad_request");
  assert.equal(parseRadioPostureResponse(500, null).kind, "error");
  assert.equal(parseRadioPostureResponse(200, { ok: false }).kind, "error");
});
