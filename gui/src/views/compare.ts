// Findings against one scan: what it found first, what it found again, and what it no longer
// finds. A finding's last sighting is the time of its `last_history_id` exchange.

export type Seen = "new" | "still" | "gone" | "other";

export interface ScanJob {
  id: number;
  time: string;
  finished_time: string | null;
  args: string[];
}

/** What a scan covered: its time window, sites as origins (null = everything recorded), rules (null = all). */
export interface ScanScope {
  start: string;
  end: string;
  origins: string[] | null;
  rules: number[] | null;
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
  let rules: number[] | null = null;
  job.args.forEach((a, i) => {
    const r = a.startsWith("--rules=") ? a.slice(8) : a === "--rules" ? job.args[i + 1] ?? "" : null;
    if (r != null) rules = [...(rules ?? []), ...r.split(",").map(Number).filter((n) => n > 0)];
  });
  return {
    start: job.time,
    end: job.finished_time ?? now,
    origins: origins.size ? [...origins] : null,
    rules,
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
  const site = s.origins ? `(${s.origins.map((o) => `substr(f.url, 1, ${o.length + 1}) = ${q(`${o}/`)}`).join(" OR ")})` : "1";
  const rule = s.rules ? `f.rule_id IN (${s.rules.join(", ")})` : "1";
  const covered = `${site} AND ((f.source = 'active' AND ${rule}) OR (f.source = 'passive' AND ${s.crawled && !s.rules ? 1 : 0}))`;
  return `SELECT f.id, CASE
    WHEN f.time > ${q(s.end)} THEN 'other'
    WHEN f.time >= ${q(s.start)} THEN 'new'
    WHEN ${last} >= ${q(s.start)} THEN 'still'
    WHEN ${covered} THEN 'gone'
    ELSE 'other' END AS seen
  FROM findings f LEFT JOIN history h ON h.id = f.last_history_id`;
}
