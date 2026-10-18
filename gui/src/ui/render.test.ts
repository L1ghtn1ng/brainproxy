import { test } from "node:test";
import assert from "node:assert/strict";
import { renderable } from "./render.ts";

const CSP = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; font-src data:">`;

test("HTML gets the lockdown CSP first and loses its own meta tags", () => {
  const r = renderable(`HTTP/1.1 200 OK\nContent-Type: text/html\n\n<META http-equiv=refresh content="0;url=https://x"><meta http-equiv="Content-Security-Policy" content="default-src *"><p>hi</p>`);
  assert.equal(r.kind, "html");
  if (r.kind !== "html") return;
  assert.ok(r.srcdoc.startsWith(CSP));
  assert.ok(r.srcdoc.endsWith("<p>hi</p>"));
  assert.equal(r.srcdoc.match(/<meta/gi)?.length, 2);
});

test("HTML is decoded with the response charset", () => {
  const latin1 = renderable("HTTP/1.1 200 OK\ncontent-type: text/html; charset=iso-8859-1\n\ncaf\xe9");
  assert.ok(latin1.kind === "html" && latin1.srcdoc.endsWith("café"));
  const utf8Bytes = renderable("HTTP/1.1 200 OK\nContent-Type: text/html\n\ncaf\xc3\xa9");
  assert.ok(utf8Bytes.kind === "html" && utf8Bytes.srcdoc.endsWith("café"));
  const text = renderable("HTTP/1.1 200 OK\nContent-Type: text/html\n\ncafé 😀");
  assert.ok(text.kind === "html" && text.srcdoc.endsWith("café 😀"));
});

test("images become data URLs of the body bytes; other types are not rendered", () => {
  const r = renderable("HTTP/1.1 200 OK\nContent-Type: image/png\n\n\x89PNG\xff");
  assert.deepEqual(r, { kind: "image", src: `data:image/png;base64,${btoa("\x89PNG\xff")}` });
  assert.deepEqual(renderable("HTTP/1.1 200 OK\nContent-Type: application/json\n\n{}"), { kind: "none", type: "application/json" });
  assert.deepEqual(renderable("HTTP/1.1 204 No Content\n\n"), { kind: "none", type: "no Content-Type" });
});
