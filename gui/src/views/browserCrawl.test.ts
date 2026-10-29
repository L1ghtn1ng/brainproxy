import { test } from "node:test";
import assert from "node:assert/strict";
import { browserFlag, browserProgress, hasChromium, wizardBrowserArgs } from "./browserCrawl.ts";

test("the browser crawl needs a Chromium-based browser", () => {
  assert.equal(hasChromium(null), false);
  assert.equal(hasChromium({ browsers: [] }), false);
  assert.equal(hasChromium({ browsers: [{ id: "firefox", name: "Firefox", kind: "firefox", path: "/usr/bin/firefox" }] }), false);
  assert.equal(hasChromium({ browsers: [{ id: "chromium", name: "Chromium", kind: "chromium", path: "/usr/bin/chromium" }] }), true);
});

test("--browser only when asked for and available", () => {
  assert.deepEqual(browserFlag(true, true), ["--browser"]);
  assert.deepEqual(browserFlag(true, false), []);
  assert.deepEqual(browserFlag(false, true), []);
  assert.deepEqual(wizardBrowserArgs("thorough", true), ["--browser"]);
  assert.deepEqual(wizardBrowserArgs("standard", true), []);
  assert.deepEqual(wizardBrowserArgs("thorough", false), []);
});

test("browser crawl progress", () => {
  assert.equal(browserProgress(null), null);
  assert.equal(browserProgress({ depth: 2, requests: 10, endpoints: 3, queued: 1 }), null);
  assert.equal(
    browserProgress({ mode: "browser", depth: 2, states: 4, clicks: 7, requests: 30, endpoints: 6, queued: 5 }),
    "browser · depth 2 · 4 states · 7 clicks · 30 req · 6 endpoints · 5 queued",
  );
});
