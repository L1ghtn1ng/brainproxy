// Access control across users (`authz`): the arguments for a run, and `authz matrix` as a grid
// of requests by identities, each cell coloured by its verdict.

export interface MatrixCell {
  verdict: string;
  confidence: string | null;
  status: number | null;
  history_id: number | null;
}

export interface MatrixRequest {
  source_id: number | null;
  method: string;
  url: string;
  owner: string;
  baseline_history_id: number | null;
  baseline_status: number | null;
  cells: Record<string, MatrixCell>;
  /** Why there is nothing to compare (`skipped: …`, `error: …`). */
  skipped?: string;
}

export interface Matrix {
  run_id: number;
  identities: string[];
  requests: MatrixRequest[];
  truncated: boolean;
}

export interface AuthzRun {
  run_id: number;
  time: string;
  state: string;
  args: string[];
  verdicts: Record<string, number>;
}

export type CellKind = "bypass-high" | "bypass-medium" | "bypass-low" | "public" | "different" | "enforced" | "error" | "none";

/** Most severe first: the order of the legend and of "worst first" sorting. */
export const KINDS: CellKind[] = ["bypass-high", "bypass-medium", "bypass-low", "public", "different", "enforced", "error", "none"];

export const KIND_LABEL: Record<CellKind, string> = {
  "bypass-high": "bypass (high)",
  "bypass-medium": "bypass (medium)",
  "bypass-low": "bypass (low)",
  public: "public",
  different: "different",
  enforced: "enforced",
  error: "error",
  none: "not sent",
};

export function cellKind(c: MatrixCell | undefined): CellKind {
  if (!c) return "none";
  if (c.verdict === "bypass") return c.confidence === "high" ? "bypass-high" : c.confidence === "medium" ? "bypass-medium" : "bypass-low";
  if (c.verdict === "public" || c.verdict === "different" || c.verdict === "enforced" || c.verdict === "error") return c.verdict;
  return "none";
}

export interface GridCell {
  identity: string;
  kind: CellKind;
  /** Short text in the cell. */
  text: string;
  historyId: number | null;
}

export interface GridRow {
  key: string;
  method: string;
  url: string;
  owner: string;
  baselineId: number | null;
  baselineStatus: number | null;
  skipped: string | null;
  cells: GridCell[];
  /** The most severe of its cells (`none` for a skipped row). */
  worst: CellKind;
}

export interface Grid {
  /** Identities as columns: `anonymous` first, then the order the run used. */
  columns: string[];
  rows: GridRow[];
  /** Cells per kind, skipped rows not included. */
  counts: Record<CellKind, number>;
  skipped: number;
}

const rank = (k: CellKind) => KINDS.indexOf(k);

/** The matrix as rows of cells, optionally only rows with a cell of `only` and worst rows first. */
export function grid(m: Matrix, opts: { only?: CellKind | null; worstFirst?: boolean } = {}): Grid {
  const columns = [...m.identities.filter((i) => i === "anonymous"), ...m.identities.filter((i) => i !== "anonymous")];
  const counts = Object.fromEntries(KINDS.map((k) => [k, 0])) as Record<CellKind, number>;
  let skipped = 0;
  let rows: GridRow[] = m.requests.map((r, i) => {
    const cells = columns.map((identity): GridCell => {
      const c = r.cells[identity];
      const kind = cellKind(c);
      const text = !c ? (identity === r.owner ? "owner" : "–") : c.status != null ? `${KIND_LABEL[kind].replace(/ \(.*/, "")} ${c.status}` : KIND_LABEL[kind];
      return { identity, kind, text, historyId: c?.history_id ?? null };
    });
    if (r.skipped) skipped++;
    else for (const c of cells) counts[c.kind]++;
    const worst = r.skipped ? "none" : cells.reduce<CellKind>((w, c) => (rank(c.kind) < rank(w) ? c.kind : w), "none");
    return {
      key: `${i}:${r.source_id ?? ""}:${r.method} ${r.url}`,
      method: r.method,
      url: r.url,
      owner: r.owner,
      baselineId: r.baseline_history_id,
      baselineStatus: r.baseline_status,
      skipped: r.skipped ?? null,
      cells,
      worst,
    };
  });
  if (opts.only) rows = rows.filter((r) => r.cells.some((c) => c.kind === opts.only));
  if (opts.worstFirst) rows = rows.map((r, i) => [r, i] as const).sort((a, b) => rank(a[0].worst) - rank(b[0].worst) || a[1] - b[1]).map(([r]) => r);
  return { columns, rows, counts, skipped };
}

/** What a run picker shows for a run: id, live or not, state and the bypass count. */
export function runLabel(r: AuthzRun): string {
  const live = r.args[0] === "proxy" ? " · live (proxy)" : "";
  const bypasses = r.verdicts.bypass ?? 0;
  const time = r.time.replace("T", " ").slice(0, 16);
  return `#${r.run_id} · ${time}${live} · ${r.state}${bypasses ? ` · ${bypasses} bypass${bypasses === 1 ? "" : "es"}` : ""}`;
}

export type Selection = "all" | "host" | "tag" | "where";

export interface RunForm {
  identities: string[];
  anonymous: boolean;
  /** Empty: worked out per request. */
  owner: string;
  select: Selection;
  host: string;
  tag: string;
  where: string;
  /** Comma-separated cookie names that aren't credentials. */
  keepCookies: string;
  rate: string;
}

const q = (s: string) => `'${s.replace(/'/g, "''")}'`;

/** A host from what was typed: a bare host, host:port, or a URL. */
export function hostOf(text: string): string {
  const t = text.trim();
  if (!t) return "";
  try {
    return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(t) ? t : `http://${t}`).hostname;
  } catch {
    return t;
  }
}

/** Throws with a message to show when the form can't make a run. */
export function runArgs(f: RunForm): string[] {
  if (!f.identities.length && !f.anonymous) throw new Error("Pick at least one identity, or keep the anonymous control on");
  const args = ["authz", "run"];
  if (f.identities.length) args.push(`--as=${f.identities.join(",")}`);
  if (f.owner) args.push(`--owner=${f.owner}`);
  if (!f.anonymous) args.push("--no-anonymous");
  if (f.select === "host") {
    const host = hostOf(f.host);
    if (!host) throw new Error("Enter the site's host");
    args.push(`--where=host = ${q(host)}`);
  } else if (f.select === "tag") {
    if (!f.tag.trim()) throw new Error("Enter a tag");
    args.push(`--tag=${f.tag.trim()}`);
  } else if (f.select === "where") {
    if (!f.where.trim()) throw new Error("Enter a SQL condition on history");
    args.push(`--where=${f.where.trim()}`);
  }
  const cookies = f.keepCookies.split(",").map((c) => c.trim()).filter(Boolean);
  if (cookies.length) args.push(`--keep-cookie=${cookies.join(",")}`);
  if (f.rate.trim()) args.push(`--rate=${f.rate.trim()}`);
  return args;
}

/** `proxy start --authz` value for live testing with the same identities. */
export function liveValue(f: Pick<RunForm, "identities" | "anonymous">): string {
  if (!f.identities.length && !f.anonymous) throw new Error("Pick at least one identity, or keep the anonymous control on");
  return [...(f.anonymous ? ["anonymous"] : []), ...f.identities].join(",");
}
