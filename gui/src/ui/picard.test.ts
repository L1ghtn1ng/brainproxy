import { test } from "node:test";
import assert from "node:assert/strict";
import { typed } from "./picard.ts";

const type = (keys: string) => {
  let sofar = "";
  let hits = 0;
  for (const k of keys) {
    const [rest, done] = typed(sofar, k);
    sofar = rest;
    if (done) hits++;
  }
  return hits;
};

test("the word answers once, wherever it is typed", () => {
  assert.equal(type("engage"), 1);
  assert.equal(type("ENGAGE"), 1);
  assert.equal(type("xxengagexx"), 1);
  assert.equal(type("enengage"), 1);
  assert.equal(type("engageengage"), 2);
  assert.equal(type("engag"), 0);
  assert.equal(type("egnage"), 0);
});
