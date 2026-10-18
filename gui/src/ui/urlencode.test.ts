import { test } from "node:test";
import assert from "node:assert/strict";
import { autoEncodeRequest, decode, encodeAll, encodeLoose } from "./urlencode.ts";

test("encodeLoose keeps URL structure and existing escapes", () => {
  assert.equal(encodeLoose("/s?q=a b&x=1"), "/s?q=a%20b&x=1");
  assert.equal(encodeLoose("/s?q=x' OR 1=1--"), "/s?q=x'%20OR%201=1--");
  assert.equal(encodeLoose('/a?b="<c>"#d'), "/a?b=%22%3Cc%3E%22%23d");
  assert.equal(encodeLoose("/a?b=%41%zz%"), "/a?b=%41%25zz%25");
  assert.equal(encodeLoose("/é😀"), "/%C3%A9%F0%9F%98%80");
});

test("encodeAll and decode round-trip a value", () => {
  const v = "a&b=c d/é'()*";
  assert.equal(encodeAll(v), "a%26b%3Dc%20d%2F%C3%A9%27%28%29%2A");
  assert.equal(decode(encodeAll(v)), v);
  assert.equal(decode("a+b%20c", true), "a b c");
  assert.equal(decode("%zz%41"), "%zzA");
});

test("autoEncodeRequest encodes the target and form bodies only", () => {
  const raw = "POST /s?q=a b HTTP/1.1\nHost: h\nContent-Type: application/x-www-form-urlencoded\n\nu=x y&p=<1>";
  const r = autoEncodeRequest(raw);
  assert.equal(r.text, "POST /s?q=a%20b HTTP/1.1\nHost: h\nContent-Type: application/x-www-form-urlencoded\n\nu=x%20y&p=%3C1%3E");
  assert.equal(r.encoded, 4);
  const json = "POST /a HTTP/1.1\nContent-Type: application/json\n\n{\"a\": \"b c\"}";
  assert.deepEqual(autoEncodeRequest(json), { text: json, encoded: 0 });
  assert.equal(autoEncodeRequest("GET /a b").text, "GET /a%20b");
});
