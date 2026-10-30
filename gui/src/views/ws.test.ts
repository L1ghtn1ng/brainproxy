import { test } from "node:test";
import assert from "node:assert/strict";
import { joinMessages, splitMessages, wsOrigin, wsSendArgs, wsSendInput } from "./ws.ts";

test("messages are split on lines holding only ---", () => {
  assert.deepEqual(splitMessages('{"a":1}\n---\nline one\nline two\r\n  ---  \n\n---\nlast'), ['{"a":1}', "line one\nline two", "last"]);
  assert.deepEqual(splitMessages(""), []);
  // A --- inside a line is part of the message.
  assert.deepEqual(splitMessages("a --- b"), ["a --- b"]);
  assert.deepEqual(splitMessages(joinMessages(["x", "y\nz"])), ["x", "y\nz"]);
});

test("messages go on stdin, never in the arguments", () => {
  const args = wsSendArgs({ target: "wss://a.test", wait: 3, until: "ok" });
  assert.deepEqual(args, ["ws", "send", "--target=wss://a.test", "--wait", "3", "--until=ok", "--input-json", "--max-body=2000000"]);
  assert.ok(!wsSendArgs({ target: "ws://a", wait: 1 }).some((a) => a.startsWith("--until")));
  assert.deepEqual(JSON.parse(wsSendInput("GET / HTTP/1.1\n\n", ["--not-a-flag", "token=secret"])), { handshake: "GET / HTTP/1.1\n\n", messages: ["--not-a-flag", "token=secret"] });
});

test("a ws URL's origin is the http origin of its handshake", () => {
  assert.equal(wsOrigin("wss://a.test:8443/chat?x=1"), "https://a.test:8443");
  assert.equal(wsOrigin("ws://a.test/chat"), "http://a.test");
  assert.equal(wsOrigin("not a url"), "");
});
