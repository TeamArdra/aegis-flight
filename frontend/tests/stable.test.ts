import assert from "node:assert/strict";
import { test } from "node:test";
import { jsonEqual, keepIfEqual } from "../src/lib/stable.ts";

test("jsonEqual: primitives, nesting, key order, arrays", () => {
  assert.equal(jsonEqual({ a: 1, b: [1, { c: null }] }, { b: [1, { c: null }], a: 1 }), true);
  assert.equal(jsonEqual({ a: 1 }, { a: 2 }), false);
  assert.equal(jsonEqual({ a: 1 }, { a: 1, b: undefined }), false);
  assert.equal(jsonEqual([1, 2], [1, 2, 3]), false);
  assert.equal(jsonEqual([], {}), false);
  assert.equal(jsonEqual(null, {}), false);
  assert.equal(jsonEqual(0, -0), true);
  assert.equal(jsonEqual("1", 1), false);
  assert.equal(jsonEqual(NaN, NaN), true);
});

test("keepIfEqual keeps the old reference only for equal values", () => {
  const prev = { x: [1, 2], y: { z: "a" } };
  assert.equal(keepIfEqual(prev, JSON.parse(JSON.stringify(prev))), prev);
  const next = { x: [1, 3], y: { z: "a" } };
  assert.equal(keepIfEqual(prev, next), next);
  assert.equal(keepIfEqual(null as typeof prev | null, next), next);
});

import { grow } from "../src/lib/stable.ts";

test("grow equals the former slice/push logic for random sequences and never mutates its input", () => {
  let s = 7;
  const rnd = () => ((s = (Math.imul(s, 1664525) + 1013904223) >>> 0) / 2 ** 32);
  const cap = 12;
  let cur: number[] = [];
  let ref: number[] = [];
  for (let i = 0; i < 3000; i++) {
    const reset = rnd() < 0.01;
    const item = rnd() < 0.7 ? i : null;
    const before = cur.slice();
    cur = grow(cur, reset, cap, item);
    const next = reset ? [] : ref.length >= cap ? ref.slice(-(cap - 1)) : ref.slice();
    if (item !== null) next.push(item);
    ref = next;
    assert.deepStrictEqual(cur, ref);
    assert.ok(cur.length <= cap);
    if (!reset && item === null && before.length < cap) assert.ok(cur.length === before.length);
  }
  const a = [1, 2, 3];
  assert.equal(grow(a, false, 10, null), a);
  const b = grow(a, false, 10, 4);
  assert.deepStrictEqual(a, [1, 2, 3]);
  assert.deepStrictEqual(b, [1, 2, 3, 4]);
});
