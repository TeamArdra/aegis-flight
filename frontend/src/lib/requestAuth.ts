// End-to-end control-plane authentication & canonical HMAC-SHA256 request signing (W13).
// Sensitive tokens stay strictly in memory + sessionStorage (never persisted in localStorage).

const SESSION_API_TOKEN_KEY = "aegis_api_token_session";
const SESSION_BRIDGE_TOKEN_KEY = "aegis_bridge_token_session";

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

export function getApiToken(): string {
  if (_memApiToken) return _memApiToken;
  const fromSession = ssGet(SESSION_API_TOKEN_KEY);
  if (fromSession) {
    _memApiToken = fromSession;
    return fromSession;
  }
  const metaEnv = (import.meta as unknown as { env?: Record<string, string | undefined> }).env;
  return metaEnv?.VITE_AEGIS_API_TOKEN?.trim() || "";
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

export async function buildSignedAuthHeaders(
  method: string,
  path: string,
  body = "",
  tokenOverride?: string,
): Promise<Record<string, string>> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  const token = (tokenOverride ?? getApiToken()).trim();
  if (!token) return headers;

  headers["X-Aegis-Token"] = token;
  if (globalThis.crypto?.subtle) {
    const timestamp = (Date.now() / 1000).toFixed(3);
    const nonce = generateNonce();
    const signature = await signCanonicalRequest(token, method, path, timestamp, nonce, body);
    headers["X-Aegis-Timestamp"] = timestamp;
    headers["X-Aegis-Nonce"] = nonce;
    headers["X-Aegis-Signature"] = signature;
  }
  return headers;
}
