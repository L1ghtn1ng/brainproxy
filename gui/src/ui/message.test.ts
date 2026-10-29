import { test } from "node:test";
import assert from "node:assert/strict";
import { markable, normalizeHead, templateBytes, withBody } from "./message.ts";

const MULTIPART = "POST /up HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=XX\r\n\r\n--XX\r\nContent-Disposition: form-data; name=a\r\n\r\n1\r\n--XX--\r\n";

test("an edit keeps the body's line endings", () => {
  // What a textarea gives back after the header was edited: \n everywhere.
  const edited = MULTIPART.replace(/\r\n/g, "\n").replace("POST /up", "POST /upload");
  assert.equal(withBody(edited, MULTIPART), MULTIPART.replace(/\r\n/g, "\n").split("\n\n")[0].replace("POST /up", "POST /upload") + "\n\n" + MULTIPART.split("\r\n\r\n").slice(1).join("\r\n\r\n"));
  // An edited body gets CRLF back where the original body had it.
  const changed = edited.replace("name=a\n\n1", "name=a\n\n2");
  assert.ok(withBody(changed, MULTIPART).endsWith("--XX\r\nContent-Disposition: form-data; name=a\r\n\r\n2\r\n--XX--\r\n"));
  // A body without CRLF stays as edited.
  assert.equal(withBody("GET / HTTP/1.1\nA: b\n\nx\ny", "GET / HTTP/1.1\r\nA: b\r\n\r\nx\ny"), "GET / HTTP/1.1\nA: b\n\nx\ny");
});

test("only the head is normalized", () => {
  const png = "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n\x89PNG\r\n\x1a\n";
  assert.equal(normalizeHead(png), "HTTP/1.1 200 OK\nContent-Type: image/png\n\n\x89PNG\r\n\x1a\n");
});

test("binary templates send markers as UTF-8 and body bytes as they are", () => {
  const raw = "POST /up?id=§1§ HTTP/1.1\nHost: h\n\n\x00\x01\r\n\xa7\xff";
  assert.deepEqual(
    [...templateBytes(raw, true)],
    [...new TextEncoder().encode("POST /up?id=§1§ HTTP/1.1\nHost: h\n\n"), 0x00, 0x01, 0x0d, 0x0a, 0xa7, 0xff],
  );
  assert.equal(markable(raw, true).split("§").length - 1, 2);
});
