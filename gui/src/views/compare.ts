// Findings against one scan: what it found first, what it found again, and what it no longer
// finds. A finding's last sighting is the time of its `last_history_id` exchange.

export type Seen = "new" | "still" | "gone" | "other";

export interface ScanJob {
  id: number;
  time: string;
  finished_time: string | null;
  args: string[];
}

/**
 * What a scan covered: its time window; sites as origins (null = everything recorded, [] =
 * only requests picked by --where/--history-id, which can't be told apart here); the
 * ported rules it ran (`rules` null = all of them, less `excludeRules`; none with
 * --no-rules); and the declarative checks known to have run: those named with
 * --check-ids. Without them, which checks ran depends on their severity and tags
 * (--check-severity, the default --check-exclude-tags), which findings don't record, so
 * no check finding is taken as covered.
 */
export interface ScanScope {
  start: string;
  end: string;
  origins: string[] | null;
  rules: number[] | null;
  excludeRules: number[];
  portedRules: boolean;
  checkIds: string[];
  crawled: boolean;
}

export function scanScope(job: ScanJob, now = new Date().toISOString()): ScanScope {
  // `scan active <site>... --flags`: the sites come before the first flag, with or without a scheme.
  const origins = new Set<string>();
  const firstFlag = job.args.findIndex((a, i) => i >= 2 && a.startsWith("-"));
  for (const a of job.args.slice(2, firstFlag < 0 ? undefined : firstFlag)) {
    try {
      origins.add(new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(a) ? a : `http://${a}`).origin);
    } catch {
      /* not a URL */
    }
  }
  // Every value of `--name=a,b` or `--name a,b`; null when the flag isn't there.
  const values = (name: string): string[] | null => {
    let out: string[] | null = null;
    job.args.forEach((a, i) => {
      const v = a.startsWith(`${name}=`) ? a.slice(name.length + 1) : a === name ? (job.args[i + 1] ?? "") : null;
      if (v != null) out = [...(out ?? []), ...v.split(",").map((x) => x.trim()).filter(Boolean)];
    });
    return out;
  };
  const numbers = (v: string[] | null) => v?.map(Number).filter((n) => n > 0) ?? null;
  const has = (name: string) => job.args.some((a) => a === name || a.startsWith(`${name}=`));
  const picked = has("--where") || has("--history-id");
  return {
    start: job.time,
    end: job.finished_time ?? now,
    origins: origins.size ? [...origins] : picked ? [] : null,
    rules: numbers(values("--rules")),
    excludeRules: numbers(values("--exclude-rules")) ?? [],
    portedRules: !has("--no-rules"),
    checkIds: has("--checks") && !["--check-severity", "--check-severity-max", "--check-tags"].some(has) ? (values("--check-ids") ?? []) : [],
    crawled: job.args.includes("--crawl"),
  };
}

const q = (s: string) => `'${s.replace(/'/g, "''")}'`;

/**
 * `SELECT id, seen` for every finding. "gone" needs the scan to have covered the finding: its
 * site, and its rule for an active finding. A passive finding (headers, cookies, ...) only
 * counts when the scan crawled, since the attack requests themselves aren't passively scanned.
 */
export function compareSql(s: ScanScope): string {
  const last = "coalesce(h.time, f.time)";
  // The finding's URL starts with a scanned origin and a "/" (so :80 doesn't match :8080).
  const site = !s.origins ? "1" : s.origins.length ? `(${s.origins.map((o) => `substr(f.url, 1, ${o.length + 1}) = ${q(`${o}/`)}`).join(" OR ")})` : "0";
  // Active findings come from a ported rule (by id) or a declarative check (`check:<id>`).
  const isCheck = "substr(f.alert_ref, 1, 6) = 'check:'";
  const excluded = s.excludeRules.length ? ` AND f.rule_id NOT IN (${s.excludeRules.join(", ")})` : "";
  const rule = !s.portedRules ? "0" : `${s.rules ? `f.rule_id IN (${s.rules.join(", ")})` : "1"}${excluded}`;
  const check = s.checkIds.length ? `f.alert_ref IN (${s.checkIds.map((id) => q(`check:${id}`)).join(", ")})` : "0";
  const active = `(${isCheck} AND ${check}) OR (NOT ${isCheck} AND ${rule})`;
  const covered = `${site} AND ((f.source = 'active' AND (${active})) OR (f.source = 'passive' AND ${s.crawled && !s.rules ? 1 : 0}))`;
  return `SELECT f.id, CASE
    WHEN f.time > ${q(s.end)} THEN 'other'
    WHEN f.time >= ${q(s.start)} THEN 'new'
    WHEN ${last} >= ${q(s.start)} THEN 'still'
    WHEN ${covered} THEN 'gone'
    ELSE 'other' END AS seen
  FROM findings f LEFT JOIN history h ON h.id = f.last_history_id`;
}
