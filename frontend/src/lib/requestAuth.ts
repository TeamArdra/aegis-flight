// End-to-end control-plane authentication & canonical HMAC-SHA256 request signing (W13).
// Sensitive tokens stay strictly in memory + sessionStorage (never persisted in localStorage).

const SESSION_API_TOKEN_KEY = "aegis_api_token_session";
const SESSION_BRIDGE_TOKEN_KEY = "aegis_bridge_token_session";
// Pre-W13 builds kept the API token in localStorage under this key; it is migrated once (see getApiToken).
export const LEGACY_API_TOKEN_KEY = "aegis_api_token";

let _memApiToken = "";
let _memBridgeToken = "";

function ssGet(key: string): string {
  try {
    return (typeof window !== "undefined" && window.sessionStorage?.getItem(key)) || "";
  } catch {
    return "";
  }
}

function ssSet(key: string, value: string): void {
  try {
    if (typeof window === "undefined" || !window.sessionStorage) return;
    if (value) window.sessionStorage.setItem(key, value);
    else window.sessionStorage.removeItem(key);
  } catch {
    /* sessionStorage unavailable */
  }
}

/** One-time move of a legacy localStorage API token into sessionStorage; the legacy key is always removed. */
function migrateLegacyApiToken(): string {
  try {
    const ls = typeof window !== "undefined" ? window.localStorage : undefined;
    if (!ls) return "";
    const legacy = (ls.getItem(LEGACY_API_TOKEN_KEY) || "").trim();
    if (!legacy) return "";
    ssSet(SESSION_API_TOKEN_KEY, legacy);
    ls.removeItem(LEGACY_API_TOKEN_KEY);
    return legacy;
  } catch {
    return "";
  }
}

export function getApiToken(): string {
  if (_memApiToken) return _memApiToken;
  const fromSession = ssGet(SESSION_API_TOKEN_KEY);
  if (fromSession) {
    _memApiToken = fromSession;
    return fromSession;
  }
  const migrated = migrateLegacyApiToken();
  if (migrated) {
    _memApiToken = migrated;
    return migrated;
  }
  // Dev server only: the literal `import.meta.env.VITE_*` form below is dead-code-eliminated in production
  // builds, and vite.config.ts additionally refuses to build when the variable is set.
  if ((import.meta as unknown as { env?: { DEV?: boolean } }).env?.DEV) {
    return (import.meta as unknown as { env: Record<string, string | undefined> }).env.VITE_AEGIS_API_TOKEN?.trim() || "";
  }
  return "";
}

export function saveApiToken(token: string): void {
  const clean = token.trim();
  _memApiToken = clean;
  ssSet(SESSION_API_TOKEN_KEY, clean);
}

export function getSessionBridgeToken(): string {
  if (_memBridgeToken) return _memBridgeToken;
  const fromSession = ssGet(SESSION_BRIDGE_TOKEN_KEY);
  if (fromSession) {
    _memBridgeToken = fromSession;
    return fromSession;
  }
  return "";
}

export function saveSessionBridgeToken(token: string): void {
  const clean = token.trim();
  _memBridgeToken = clean;
  ssSet(SESSION_BRIDGE_TOKEN_KEY, clean);
}

export function generateNonce(): string {
  const c = globalThis.crypto;
  if (c && typeof c.randomUUID === "function") {
    return c.randomUUID().replace(/-/g, "");
  }
  if (c && typeof c.getRandomValues === "function") {
    const buf = new Uint8Array(16);
    c.getRandomValues(buf);
    return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
  }
  return `${Date.now().toString(16)}${Math.random().toString(16).slice(2, 14)}`;
}

async function sha256Hex(text: string): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error("Web Crypto subtle API unavailable for request hashing");
  }
  const bytes = new TextEncoder().encode(text);
  const digest = await subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

export async function signCanonicalRequest(
  token: string,
  method: string,
  path: string,
  timestamp: string,
  nonce: string,
  body: string,
): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error("Web Crypto subtle API unavailable for HMAC signing");
  }
  const enc = new TextEncoder();
  const bodyHash = await sha256Hex(body);
  const canonical = `${method.toUpperCase()}\n${path}\n${timestamp}\n${nonce}\n${bodyHash}`;
  const key = await subtle.importKey(
    "raw",
    enc.encode(token),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await subtle.sign("HMAC", key, enc.encode(canonical));
  return Array.from(new Uint8Array(sig), (b) => b.toString(16).padStart(2, "0")).join("");
}

export interface SigningStatus {
  /** Web Crypto (`crypto.subtle`) is available, so requests can be HMAC-signed. */
  available: boolean;
  tokenConfigured: boolean;
  /** Operator-facing warning, or null when nothing needs attention. */
  warning: string | null;
}

/** `crypto.subtle` exists only in secure contexts (https or localhost); over plain http to a LAN host it is absent. */
export function getSigningStatus(): SigningStatus {
  const available = !!globalThis.crypto?.subtle;
  const tokenConfigured = !!getApiToken();
  const warning =
    tokenConfigured && !available
      ? "Request signing is unavailable in this browser context (Web Crypto needs https or localhost). " +
        "Control requests are sent with the API token only, without HMAC/nonce replay protection. " +
        "Open the console over https or http://localhost."
      : null;
  return { available, tokenConfigured, warning };
}

/** True for http(s) origins whose host is loopback; '' / relative means same-origin as the page. */
export function isLoopbackOrigin(origin: string): boolean {
  const o = origin || (typeof location !== "undefined" ? location.origin : "");
  try {
    const h = new URL(o).hostname.replace(/^\[|\]$/g, "").toLowerCase();
    return h === "localhost" || h === "::1" || /^127\./.test(h);
  } catch {
    return false;
  }
}

/** Public identifier of the token (matches backend `key_id`); the token itself is never sent when signing. */
export async function computeKeyId(token: string): Promise<string> {
  return (await sha256Hex(`aegis-key-id:${token}`)).slice(0, 16);
}

/**
 * Signed-only scheme: when Web Crypto is available send ONLY key-id/timestamp/nonce/signature (no raw token).
 * Without Web Crypto the legacy token header is sent to a loopback origin only; for any other origin the
 * request is refused rather than sending the secret in the clear.
 */
export async function buildSignedAuthHeaders(
  method: string,
  path: string,
  body = "",
  tokenOverride?: string,
  origin = "",
): Promise<Record<string, string>> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  const token = (tokenOverride ?? getApiToken()).trim();
  if (!token) return headers;

  if (!globalThis.crypto?.subtle) {
    if (!isLoopbackOrigin(origin)) {
      throw new Error(
        "Refusing to send an unsigned control request to a non-loopback origin: Web Crypto is unavailable " +
          "(open the console over https or http://localhost).",
      );
    }
    headers["X-Aegis-Token"] = token;
    return headers;
  }
  const timestamp = (Date.now() / 1000).toFixed(3);
  const nonce = generateNonce();
  headers["X-Aegis-Key-Id"] = await computeKeyId(token);
  headers["X-Aegis-Timestamp"] = timestamp;
  headers["X-Aegis-Nonce"] = nonce;
  headers["X-Aegis-Signature"] = await signCanonicalRequest(token, method, path, timestamp, nonce, body);
  return headers;
}
