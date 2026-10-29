import { test } from "node:test";
import assert from "node:assert/strict";
import { cellKind, grid, hostOf, liveValue, runArgs, runLabel, type Matrix, type RunForm } from "./access.ts";

const cell = (verdict: string, status: number | null, history_id: number, confidence: string | null = null) => ({ verdict, confidence, status, history_id });

const matrix: Matrix = {
  run_id: 7,
  identities: ["bob", "anonymous", "carol"],
  truncated: false,
  requests: [
    {
      source_id: 1,
      method: "GET",
      url: "http://shop.test/api/me",
      owner: "alice",
      baseline_history_id: 10,
      baseline_status: 200,
      cells: { anonymous: cell("enforced", 401, 11), bob: cell("different", 200, 12), carol: cell("different", 200, 13) },
    },
    {
      source_id: 2,
      method: "GET",
      url: "http://shop.test/api/orders/1",
      owner: "alice",
      baseline_history_id: 20,
      baseline_status: 200,
      cells: { anonymous: cell("enforced", 401, 21), bob: cell("bypass", 200, 22, "high"), carol: cell("error", null, 23) },
    },
    { source_id: 3, method: "GET", url: "http://shop.test/api/orders/9", owner: "alice", baseline_history_id: 30, baseline_status: 404, cells: {}, skipped: "skipped: baseline status 404; nothing to compare against" },
    {
      source_id: 4,
      method: "GET",
      url: "http://shop.test/dashboard",
      owner: "bob",
      baseline_history_id: 40,
      baseline_status: 200,
      // bob is the owner here, so he has no cell.
      cells: { anonymous: cell("public", 200, 41), carol: cell("bypass", 200, 42, "low") },
    },
  ],
};

test("cells get a kind from their verdict and confidence", () => {
  assert.equal(cellKind(cell("bypass", 200, 1, "high")), "bypass-high");
  assert.equal(cellKind(cell("bypass", 200, 1, "medium")), "bypass-medium");
  assert.equal(cellKind(cell("bypass", 200, 1, null)), "bypass-low");
  assert.equal(cellKind(cell("enforced", 403, 1)), "enforced");
  assert.equal(cellKind(cell("weird", 200, 1)), "none");
  assert.equal(cellKind(undefined), "none");
});

test("the matrix becomes rows with a cell per identity, anonymous first", () => {
  const g = grid(matrix);
  assert.deepEqual(g.columns, ["anonymous", "bob", "carol"]);
  assert.equal(g.rows.length, 4);
  const orders = g.rows[1];
  assert.deepEqual(
    orders.cells.map((c) => [c.identity, c.kind, c.text, c.historyId]),
    [
      ["anonymous", "enforced", "enforced 401", 21],
      ["bob", "bypass-high", "bypass 200", 22],
      ["carol", "error", "error", 23],
    ],
  );
  assert.equal(orders.worst, "bypass-high");
  assert.equal(orders.baselineId, 20);
  // The owner's own column says so; a skipped row has no verdicts.
  assert.deepEqual(g.rows[3].cells[1], { identity: "bob", kind: "none", text: "owner", historyId: null });
  assert.equal(g.rows[2].skipped, "skipped: baseline status 404; nothing to compare against");
  assert.equal(g.rows[2].worst, "none");
  assert.equal(g.skipped, 1);
  assert.deepEqual(
    Object.fromEntries(Object.entries(g.counts).filter(([, n]) => n)),
    { "bypass-high": 1, "bypass-low": 1, public: 1, different: 2, enforced: 2, error: 1, none: 1 },
  );
});

test("rows can be filtered by kind and sorted worst first", () => {
  assert.deepEqual(grid(matrix, { only: "bypass-low" }).rows.map((r) => r.url.split("/").pop()), ["dashboard"]);
  assert.deepEqual(grid(matrix, { worstFirst: true }).rows.map((r) => r.url.split("/").pop()), ["1", "dashboard", "me", "9"]);
});

const form: RunForm = { identities: ["bob", "carol"], anonymous: true, owner: "", select: "all", host: "", tag: "", where: "", keepCookies: "", rate: "" };

test("a run's arguments come from the form", () => {
  assert.deepEqual(runArgs(form), ["authz", "run", "--as=bob,carol"]);
  assert.deepEqual(runArgs({ ...form, identities: [], owner: "alice", select: "tag", tag: " api ", keepCookies: "lang, theme", rate: "5" }), [
    "authz",
    "run",
    "--owner=alice",
    "--tag=api",
    "--keep-cookie=lang,theme",
    "--rate=5",
  ]);
  assert.deepEqual(runArgs({ ...form, anonymous: false, select: "host", host: "https://shop.test:8443/x" }), ["authz", "run", "--as=bob,carol", "--no-anonymous", "--where=host = 'shop.test'"]);
  // A quote in the host can't end the SQL string.
  assert.equal(runArgs({ ...form, select: "host", host: "a'b" }).at(-1), "--where=host = 'a''b'");
  assert.deepEqual(runArgs({ ...form, select: "where", where: "path LIKE '/api/%'" }).at(-1), "--where=path LIKE '/api/%'");
  assert.throws(() => runArgs({ ...form, identities: [], anonymous: false }), /at least one identity/);
  assert.throws(() => runArgs({ ...form, select: "host", host: " " }), /host/);
  assert.equal(liveValue(form), "anonymous,bob,carol");
  assert.equal(liveValue({ identities: ["bob"], anonymous: false }), "bob");
});

test("hosts and run labels", () => {
  assert.equal(hostOf("shop.test:8080"), "shop.test");
  assert.equal(hostOf("http://10.0.0.5/x"), "10.0.0.5");
  const run = { run_id: 12, time: "2026-10-29T10:11:12.000Z", state: "running", args: ["proxy", "run", "--authz", "bob"], verdicts: { bypass: 2, enforced: 5 } };
  assert.equal(runLabel(run), "#12 · 2026-10-29 10:11 · live (proxy) · running · 2 bypasses");
  assert.equal(runLabel({ ...run, args: ["authz", "run"], verdicts: { bypass: 1 } }), "#12 · 2026-10-29 10:11 · running · 1 bypass");
});
