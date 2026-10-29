// Referential stability for JSON values: when a freshly parsed WebSocket sub-object equals the one already in
// state, keep the old reference so memoised panels skip re-rendering. Pure, no React. Tested in tests/stable.test.ts.

/** Deep equality for parsed-JSON values (null, boolean, number, string, arrays, plain objects). */
export function jsonEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== "object" || typeof b !== "object" || a === null || b === null) {
    return typeof a === "number" && typeof b === "number" && Number.isNaN(a) && Number.isNaN(b);
  }
  const aa = Array.isArray(a);
  if (aa !== Array.isArray(b)) return false;
  if (aa) {
    const x = a as unknown[], y = b as unknown[];
    if (x.length !== y.length) return false;
    for (let i = 0; i < x.length; i++) if (!jsonEqual(x[i], y[i])) return false;
    return true;
  }
  const x = a as Record<string, unknown>, y = b as Record<string, unknown>;
  const kx = Object.keys(x);
  if (kx.length !== Object.keys(y).length) return false;
  for (const k of kx) {
    if (!Object.prototype.hasOwnProperty.call(y, k) || !jsonEqual(x[k], y[k])) return false;
  }
  return true;
}

/** `prev` when it is deeply equal to `next` (same reference, nothing re-renders), else `next`. */
export function keepIfEqual<T>(prev: T, next: T): T {
  return jsonEqual(prev, next) ? prev : next;
}

/**
 * Bounded history append without needless copies. Same result as the former
 * `reset ? [] : prev.length >= cap ? prev.slice(-(cap - 1)) : prev.slice()` followed by an optional push,
 * except that when nothing changes the previous array itself is returned (so memoised consumers skip work).
 * `item === null` means "nothing to append".
 */
export function grow<T>(prev: T[], reset: boolean, cap: number, item: T | null): T[] {
  if (reset) return item === null ? (prev.length === 0 ? prev : []) : [item];
  if (prev.length >= cap) {
    const a = prev.slice(-(cap - 1));
    if (item !== null) a.push(item);
    return a;
  }
  if (item === null) return prev;
  const a = prev.slice();
  a.push(item);
  return a;
}
