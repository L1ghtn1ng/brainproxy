// Connection options (`connection *`) and platform auth (`auth add --platform`): the shapes the
// CLI returns and the arguments the Settings forms send. Values go as --flag=value so they may
// start with "-", and positionals after "--".

export interface UpstreamRule {
  host: string;
  proxy?: string;
  username?: string;
  password_env?: string;
}

export interface HostOverride {
  host: string;
  ip: string;
}

export interface ClientCert {
  host: string;
  cert?: string;
  key?: string;
  pkcs12?: string;
  password_env?: string;
}

/** What every `connection` command answers with. */
export interface ConnectionSettings {
  upstream: UpstreamRule[];
  hosts: HostOverride[];
  client_certs: ClientCert[];
  passthrough: string[];
  warnings: string[];
}

export interface UpstreamForm {
  host: string;
  direct: boolean;
  proxy: string;
  username: string;
  passwordEnv: string;
  first: boolean;
}

export const EMPTY_UPSTREAM: UpstreamForm = { host: "*", direct: false, proxy: "", username: "", passwordEnv: "", first: false };

export function upstreamAddArgs(f: UpstreamForm): string[] {
  const args = ["connection", "upstream", "add", `--host=${f.host.trim()}`];
  if (f.direct) args.push("--direct");
  else args.push(`--proxy=${f.proxy.trim()}`);
  if (!f.direct && f.username.trim()) {
    args.push(`--username=${f.username.trim()}`);
    if (f.passwordEnv.trim()) args.push(`--password-env=${f.passwordEnv.trim()}`);
  }
  if (f.first) args.push("--first");
  return args;
}

export interface CertForm {
  host: string;
  kind: "pem" | "pkcs12";
  cert: string;
  key: string;
  pkcs12: string;
  passwordEnv: string;
}

export const EMPTY_CERT: CertForm = { host: "", kind: "pem", cert: "", key: "", pkcs12: "", passwordEnv: "" };

export function certAddArgs(f: CertForm): string[] {
  const args = ["connection", "cert", "add", `--host=${f.host.trim()}`];
  if (f.kind === "pem") args.push(`--cert=${f.cert.trim()}`, `--key=${f.key.trim()}`);
  else {
    args.push(`--pkcs12=${f.pkcs12.trim()}`);
    if (f.passwordEnv.trim()) args.push(`--password-env=${f.passwordEnv.trim()}`);
  }
  return args;
}

export const hostsAddArgs = (host: string, ip: string) => ["connection", "hosts", "add", "--", host.trim(), ip.trim()];

/** Pass-through patterns from a text field: separated by spaces, commas, or lines. */
export const passthroughAddArgs = (text: string) => [
  "connection",
  "passthrough",
  "add",
  "--",
  ...text
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean),
];

export type PlatformScheme = "basic" | "digest" | "ntlm";

/** An auth profile's `platform` section as `auth show` returns it. */
export interface PlatformAuth {
  scheme: PlatformScheme;
  hosts: string[];
  domain?: string;
}

export interface PlatformForm {
  /** Empty: no platform authentication. */
  scheme: "" | PlatformScheme;
  /** Host patterns, one per line (or separated by spaces or commas). */
  hosts: string;
  domain: string;
}

export const platformForm = (p?: PlatformAuth): PlatformForm => ({
  scheme: p?.scheme ?? "",
  hosts: (p?.hosts ?? []).join("\n"),
  domain: p?.domain ?? "",
});

export function platformArgs(f: PlatformForm): string[] {
  if (!f.scheme) return [];
  const args = [`--platform=${f.scheme}`];
  for (const h of f.hosts.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean)) args.push(`--platform-host=${h}`);
  if (f.scheme === "ntlm" && f.domain.trim()) args.push(`--domain=${f.domain.trim()}`);
  return args;
}

export const describePlatform = (p: PlatformAuth) =>
  `${p.scheme.toUpperCase()} for ${p.hosts.join(", ")}${p.domain ? ` (domain ${p.domain})` : ""}`;
