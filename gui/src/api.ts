// Every engine call is a brainproxy CLI invocation returning its JSON envelope. In the desktop
// app it goes through the Tauri `cli` command; under `npm run dev` in a browser, through the
// Vite dev bridge (/api/cli).

export type Envelope<T = any> =
  | { ok: true; command: string; data: T }
  | { ok: false; command?: string; error: { kind: string; message: string } };

export class CliError extends Error {
  constructor(public kind: string, message: string) {
    super(message);
  }
}

export const inTauri = "__TAURI_INTERNALS__" in window;

let project = "";
export const setProject = (p: string) => (project = p);
export const getProject = () => project;

export async function cli<T = any>(args: string[], stdin?: string): Promise<Envelope<T>> {
  if (inTauri) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<Envelope<T>>("cli", { project, args, stdin: stdin ?? null });
  }
  const res = await fetch("/api/cli", {
    method: "POST",
    headers: { "content-type": "application/json", "x-brainproxy": "1" },
    body: JSON.stringify({ project, args, stdin }),
  });
  return res.json();
}

/** Runs a command and returns its data, throwing CliError when ok is false. */
export async function run<T = any>(args: string[], stdin?: string): Promise<T> {
  const env = await cli<T>(args, stdin);
  if (!env.ok) throw new CliError(env.error.kind, env.error.message);
  return env.data;
}

// --- Shapes of the CLI output the UI uses ---

export interface Body {
  encoding: "utf8" | "base64";
  content: string;
  length?: number;
  truncated?: boolean;
}

export interface HistoryItem {
  id: number;
  time: string;
  source: string;
  method: string;
  url: string;
  status: number | null;
  resp_content_type: string | null;
  resp_body_length: number | null;
  title: string | null;
  duration_ms: number | null;
  error: string | null;
  note: string | null;
  tags: string[];
}

export interface HistoryEntry {
  id: number;
  url: string;
  duration_ms: number | null;
  request: Body;
  response: { status: number; reason: string; headers: string[]; body: Body; http_version?: string } | null;
  entry: HistoryItem;
}

export type Risk = "high" | "medium" | "low" | "info";

export interface FindingGroup {
  alert_ref: string;
  name: string;
  risk: Risk;
  instances: number;
  hits: number;
  hosts: number;
}

export interface FindingItem {
  id: number;
  alert_ref: string;
  name: string;
  risk: Risk;
  confidence: string;
  host: string;
  method: string;
  url: string;
  param: string;
  evidence: string;
  hits: number;
  history_id: number | null;
  state: string;
}

export interface Finding extends FindingItem {
  rule_id: number;
  cwe: number | null;
  wasc: number | null;
  other_info: string;
  attack: string;
  description: string;
  solution?: string;
  refs?: string[];
  tags: string[];
  note: string | null;
  source: string;
}

/** Text of a body: UTF-8 as is, base64 decoded as Latin-1 so every byte stays visible. */
export function bodyText(b: Body | undefined | null): string {
  if (!b) return "";
  if (b.encoding === "utf8") return b.content;
  try {
    return atob(b.content);
  } catch {
    return b.content;
  }
}

/** A raw HTTP response rebuilt from `history show` (status line, headers, body). */
export function rawResponse(e: HistoryEntry): string {
  const r = e.response;
  if (!r) return "";
  return `${r.http_version ?? "HTTP/1.1"} ${r.status} ${r.reason}\r\n${r.headers.join("\r\n")}\r\n\r\n${bodyText(r.body)}`;
}

export function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return "";
  }
}

export function pathOf(url: string): string {
  try {
    const u = new URL(url);
    return u.pathname + u.search;
  } catch {
    return url;
  }
}

/**
 * Adds a scheme to a URL typed without one ("10.0.0.5:8100/x", "app.example.com"):
 * https for port 443/8443 or no port, http for any other explicit port.
 */
export function withScheme(url: string): string {
  const u = url.trim();
  if (!u || /^[a-z][a-z0-9+.-]*:\/\//i.test(u)) return u;
  const port = /^[^/?#]*:(\d+)(?:[/?#]|$)/.exec(u)?.[1];
  return `${!port || port === "443" || port === "8443" ? "https" : "http"}://${u}`;
}
