import { test } from "node:test";
import assert from "node:assert/strict";
import { joinMessages, splitMessages, wsOrigin, wsSendArgs } from "./ws.ts";

test("messages are split on lines holding only ---", () => {
  assert.deepEqual(splitMessages('{"a":1}\n---\nline one\nline two\r\n  ---  \n\n---\nlast'), ['{"a":1}', "line one\nline two", "last"]);
  assert.deepEqual(splitMessages(""), []);
  // A --- inside a line is part of the message.
  assert.deepEqual(splitMessages("a --- b"), ["a --- b"]);
  assert.deepEqual(splitMessages(joinMessages(["x", "y\nz"])), ["x", "y\nz"]);
});

test("ws send arguments keep each message whole", () => {
  const args = wsSendArgs({ target: "wss://a.test", messages: ["--not-a-flag", "two words"], wait: 3, until: "ok" });
  assert.deepEqual(args, ["ws", "send", "--target=wss://a.test", "--wait", "3", "--until=ok", "--message=--not-a-flag", "--message=two words", "--max-body=2000000", "-"]);
  assert.ok(!wsSendArgs({ target: "ws://a", messages: [], wait: 1 }).some((a) => a.startsWith("--until")));
});

test("a ws URL's origin is the http origin of its handshake", () => {
  assert.equal(wsOrigin("wss://a.test:8443/chat?x=1"), "https://a.test:8443");
  assert.equal(wsOrigin("ws://a.test/chat"), "http://a.test");
  assert.equal(wsOrigin("not a url"), "");
});
