import { test } from "node:test";
import assert from "node:assert/strict";
import { bodyText, isBinary, requireWhole, textBytes, type Body } from "./api.ts";

const gzip = Uint8Array.from([0x1f, 0x8b, 0x08, 0x00, 0x91, 0xff, 0x00, 0x0a]);
const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));

test("a base64 body round-trips to its exact bytes", () => {
  const body: Body = { encoding: "base64", content: b64(gzip) };
  assert.ok(isBinary(body));
  assert.deepEqual(textBytes(bodyText(body), isBinary(body)), gzip);
  // The bug: encoding that text as UTF-8 doubles every byte >= 0x80.
  assert.notDeepEqual(new TextEncoder().encode(bodyText(body)), gzip);
});

test("text bodies are UTF-8; chars above 0xFF typed into binary text go in as UTF-8", () => {
  assert.deepEqual(textBytes("é"), Uint8Array.from([0xc3, 0xa9]));
  assert.ok(!isBinary({ encoding: "utf8", content: "é" }));
  assert.deepEqual(textBytes("\xff€", true), Uint8Array.from([0xff, 0xe2, 0x82, 0xac]));
});

test("a truncated body can't be edited or sent", () => {
  assert.throws(() => requireWhole({ encoding: "utf8", content: "x", length: 3000000, truncated: true }), /3000000 bytes/);
  requireWhole({ encoding: "utf8", content: "x", length: 1, truncated: false });
});
