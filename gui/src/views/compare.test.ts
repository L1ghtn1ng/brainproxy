import { test } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { compareSql, scanScope } from "./compare.ts";

test("a scan's scope comes from its arguments", () => {
  const s = scanScope({ id: 3, time: "2026-10-22T10:00:00.000Z", finished_time: null, args: ["scan", "active", "http://a.test:8080/x", "b.test:81", "--crawl", "--strength", "medium", "--rules=40018,100002"] }, "2026-10-22T11:00:00.000Z");
  assert.deepEqual(s, {
    start: "2026-10-22T10:00:00.000Z",
    end: "2026-10-22T11:00:00.000Z",
    origins: ["http://a.test:8080", "http://b.test:81"],
    rules: [40018, 100002],
    excludeRules: [],
    portedRules: true,
    checkIds: [],
    crawled: true,
  });
  assert.deepEqual(scanScope({ id: 1, time: "t", finished_time: "u", args: ["scan", "active", "--recorded"] }).origins, null);
  // Requests picked by a filter: no site counts as covered.
  assert.deepEqual(scanScope({ id: 1, time: "t", finished_time: "u", args: ["scan", "active", "--history-id", "5"] }).origins, []);
  const t = scanScope({ id: 1, time: "t", finished_time: "u", args: ["scan", "active", "a.test", "--no-rules", "--checks", "nuclei", "--check-ids=x,y", "--exclude-rules", "40018"] });
  assert.deepEqual([t.portedRules, t.checkIds, t.excludeRules], [false, ["x", "y"], [40018]]);
  // Checks picked by severity or tags: which ran isn't known.
  const args = (...a: string[]) => scanScope({ id: 1, time: "t", finished_time: "u", args: ["scan", "active", "a.test", ...a] }).checkIds;
  assert.deepEqual(args("--checks", "nuclei", "--check-severity", "high"), []);
  assert.deepEqual(args("--checks", "nuclei", "--check-ids", "x", "--check-tags", "cve"), []);
});

test("findings are new, still there, gone, or outside the scan", () => {
  const db = new DatabaseSync(":memory:");
  db.exec(`CREATE TABLE history (id INTEGER PRIMARY KEY, time TEXT);
    CREATE TABLE findings (id INTEGER PRIMARY KEY, time TEXT, source TEXT, rule_id INTEGER, alert_ref TEXT, url TEXT, last_history_id INTEGER);
    INSERT INTO history VALUES (1, '2026-10-21T09:00:00.000Z'), (2, '2026-10-22T10:30:00.000Z');
    INSERT INTO findings VALUES
      (1, '2026-10-22T10:10:00.000Z', 'active', 40018, '40018', 'http://a.test/x', NULL),  -- first seen by the scan
      (2, '2026-10-21T09:00:00.000Z', 'active', 40018, '40018', 'http://a.test/', 2),     -- seen before and again
      (3, '2026-10-21T09:00:00.000Z', 'active', 40018, '40018', 'http://a.test/y?q=1', 1), -- not seen again: gone
      (4, '2026-10-21T09:00:00.000Z', 'active', 40018, '40018', 'http://a.test:8080/', 1), -- another service on the host
      (5, '2026-10-21T09:00:00.000Z', 'active', 10020, '10020', 'http://a.test/', 1),     -- a rule the scan didn't run
      (6, '2026-10-21T09:00:00.000Z', 'passive', 10020, '10020', 'http://a.test/', 1),    -- passive, scan didn't crawl
      (7, '2026-10-22T12:00:00.000Z', 'active', 40018, '40018', 'http://a.test/', NULL),  -- after the scan
      (8, '2026-10-21T09:00:00.000Z', 'active', 0, 'check:cve-1', 'http://a.test/', 1);   -- a Nuclei check`);
  const job = { id: 3, time: "2026-10-22T10:00:00.000Z", finished_time: "2026-10-22T11:00:00.000Z", args: ["scan", "active", "http://a.test/", "--rules=40018"] };
  const seen = (args: string[]) =>
    Object.fromEntries(db.prepare(compareSql(scanScope({ ...job, args }))).all().map((r: any) => [r.id, r.seen]));
  assert.deepEqual(seen(job.args), { 1: "new", 2: "still", 3: "gone", 4: "other", 5: "other", 6: "other", 7: "other", 8: "other" });
  // A crawl with every rule covers passive findings and every active rule on the site, not checks it didn't run.
  assert.deepEqual(seen(["scan", "active", "http://a.test/", "--crawl"]), { 1: "new", 2: "still", 3: "gone", 4: "other", 5: "gone", 6: "gone", 7: "other", 8: "other" });
  // A high-severity-only check scan doesn't make a lower one look fixed.
  assert.equal(seen(["scan", "active", "http://a.test/", "--checks", "nuclei", "--check-severity", "high"])[8], "other");
  // Excluded rules, and ported rules under --no-rules, aren't covered; the checks named are.
  assert.equal(seen(["scan", "active", "http://a.test/", "--exclude-rules=40018"])[3], "other");
  const checksOnly = seen(["scan", "active", "http://a.test/", "--no-rules", "--checks", "nuclei", "--check-ids", "cve-1"]);
  assert.deepEqual([checksOnly[3], checksOnly[5], checksOnly[8]], ["other", "other", "gone"]);
  // A scan of picked requests covers no site.
  assert.equal(seen(["scan", "active", "--history-id", "5"])[3], "other");
  // Quotes in a host can't break out of the query.
  assert.doesNotThrow(() => db.prepare(compareSql({ ...scanScope(job), origins: ["http://a'b"] })).all());
});
