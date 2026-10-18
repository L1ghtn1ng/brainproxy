// Out-of-band listener (our take on a Collaborator client): start/stop the per-project
// listener, issue payloads, and watch the interactions that call back (`oob *`).

import { useEffect, useState } from "react";
import { run } from "../api";
import { useApp } from "../store";
import { DataTable, type Column } from "../ui/DataTable";
import { HttpView } from "../ui/HttpView";
import { Split } from "../ui/Split";
import { usePoll } from "../ui/usePoll";

interface Listener {
  pid: number;
  tcp_listen: string;
  dns_listen: string | null;
  public_ip: string | null;
  endpoint: { domain: string | null; public_host: string; public_port: number; auto_host: boolean };
  payload_example: { host: string; url: string; dns: boolean };
}

interface OobStatus {
  running: boolean;
  listener: Listener | null;
  payloads: number;
  interactions: number;
}

interface Payload {
  token: string;
  host: string;
  url: string;
  dns: boolean;
  examples: Record<string, string>;
  note?: string;
}

interface Interaction {
  id: number;
  time: string;
  protocol: string;
  remote: string;
  token: string | null;
  summary: string;
  raw: string;
  raw_truncated: boolean;
  payload: { source: string; alert_ref: string | null; param: string; note: string | null; history_id: number | null } | null;
}

const COLUMNS: Column<Interaction>[] = [
  { key: "id", label: "#", width: 48, value: (r) => r.id, align: "right" },
  { key: "time", label: "Time", width: 150, value: (r) => r.time, render: (r) => new Date(r.time).toLocaleString() },
  { key: "protocol", label: "Type", width: 56, value: (r) => r.protocol.toUpperCase() },
  { key: "token", label: "Payload", width: 170, value: (r) => r.token ?? "" },
  { key: "remote", label: "Source", width: 150, value: (r) => r.remote },
  { key: "origin", label: "From", width: 110, value: (r) => r.payload?.note || r.payload?.alert_ref || r.payload?.source || "unknown" },
  { key: "summary", label: "Summary", width: 420, value: (r) => r.summary },
];

const copy = (text: string) => navigator.clipboard.writeText(text);

export function OobView({ active }: { active: boolean }) {
  const app = useApp();
  const [status, refreshStatus] = usePoll<OobStatus>(() => run(["oob", "status"]), 2000, active);
  const [opts, setOpts] = useState({ listen: "0.0.0.0:8880", publicHost: "", publicPort: "", domain: "", dnsListen: "", publicIp: "" });
  const [busy, setBusy] = useState(false);
  const [gen, setGen] = useState({ count: "1", note: "", target: "" });
  const [payloads, setPayloads] = useState<Payload[]>([]);
  const [items, setItems] = useState<Interaction[]>([]);
  const [since, setSince] = useState(0);
  const [selected, setSelected] = useState<number | null>(null);

  // Interactions are fetched incrementally with next_since. Polling also turns late
  // callbacks to scan payloads into findings, so it runs whether or not the listener is up.
  const [poll] = usePoll<{ interactions: Interaction[]; next_since: number }>(
    () => run(["oob", "poll", "--since", String(since), "--limit", "500", "--max-raw", "16384"]),
    2000,
    active,
  );
  useEffect(() => {
    if (!poll || poll.next_since <= since) return;
    setItems((old) => [...old, ...poll.interactions.filter((i) => i.id > since)]);
    setSince(poll.next_since);
  }, [poll, since]);

  const start = async () => {
    const o = opts;
    const flag = (f: string, v: string) => (v.trim() ? [f, v.trim()] : []);
    setBusy(true);
    try {
      await run([
        "oob",
        "start",
        ...flag("--listen", o.listen),
        ...flag("--public-host", o.publicHost),
        ...flag("--public-port", o.publicPort),
        ...flag("--domain", o.domain),
        ...flag("--dns-listen", o.dnsListen),
        ...flag("--public-ip", o.publicIp),
      ]);
      refreshStatus();
    } catch (e: any) {
      app.toast(e.message, "error");
    }
    setBusy(false);
  };

  const stop = async () => {
    try {
      await run(["oob", "stop"]);
      refreshStatus();
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };

  const generate = async () => {
    try {
      const args = ["oob", "payload", "--count", gen.count || "1"];
      if (gen.note) args.push("--note", gen.note);
      if (gen.target) args.push("--target", gen.target);
      const d = await run<{ payloads: Payload[] }>(args);
      setPayloads((p) => [...d.payloads.map((x) => ({ ...x, note: gen.note })), ...p]);
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };

  const l = status?.listener;
  const field = (key: keyof typeof opts, label: string, placeholder: string) => (
    <label>
      <span className="label">{label}</span>
      <input className="input" value={opts[key]} placeholder={placeholder} onChange={(e) => setOpts({ ...opts, [key]: e.target.value })} />
    </label>
  );
  const item = items.find((i) => i.id === selected);

  return (
    <div className="col fill">
      <div className="toolbar">
        <span className={`pill ${status?.running ? "live" : ""}`}>
          <span className="dot" />
          {status?.running ? "Listening" : "Listener off"}
        </span>
        {l && (
          <>
            <span className="muted">on {l.tcp_listen}{l.dns_listen ? ` + DNS ${l.dns_listen}` : ""} · targets call</span>
            <span className="mono">{l.endpoint.domain ? `*.${l.endpoint.domain}` : `${l.endpoint.public_host}:${l.endpoint.public_port}`}</span>
            {l.endpoint.auto_host && <span className="chip warn" title="Set a public host if targets reach you through NAT or a tunnel">public host guessed</span>}
            <button className="btn small" onClick={stop}>
              Stop
            </button>
          </>
        )}
        <span className="grow" />
        {status && (
          <span className="muted">
            {status.payloads} payloads · {status.interactions} interactions
          </span>
        )}
      </div>
      <Split id="oob" dir="row" initial={0.36}>
        <div className="detail oob-side">
          {!status?.running ? (
            <>
              <h3>Start the listener</h3>
              <div className="form">
                {field("listen", "Listen (TCP: HTTP, LDAP, TLS)", "0.0.0.0:8880")}
                {field("publicHost", "Public host", "auto: this machine's outbound address")}
                {field("publicPort", "Public port", "listen port")}
                {field("domain", "DNS domain (optional)", "oob.example.com")}
                {field("dnsListen", "DNS listen (needs domain)", "0.0.0.0:53")}
                {field("publicIp", "Public IP for DNS answers", "public host if it is an IP")}
              </div>
              <div className="row gap oob-actions">
                <button className="btn primary" disabled={busy} onClick={start}>
                  {busy ? "Starting…" : "Start listener"}
                </button>
              </div>
              <p className="muted small">
                Payloads use the public host and port, not the listen address. Behind NAT, a VPN, or a tunnel, set them to the
                address the target can reach. With a domain whose NS (or a wildcard A record) points here, payloads become{" "}
                <span className="mono">&lt;token&gt;.&lt;domain&gt;</span> and DNS lookups are caught too.
              </p>
            </>
          ) : (
            <>
              <h3>Generate payloads</h3>
              <div className="form">
                <label>
                  <span className="label">Count</span>
                  <input className="input" type="number" min={1} max={100} value={gen.count} onChange={(e) => setGen({ ...gen, count: e.target.value })} />
                </label>
                <label>
                  <span className="label">Note</span>
                  <input className="input" value={gen.note} placeholder="where it is injected" onChange={(e) => setGen({ ...gen, note: e.target.value })} />
                </label>
                <label>
                  <span className="label">Target (optional)</span>
                  <input className="input" value={gen.target} placeholder="picks the local address routing to it" onChange={(e) => setGen({ ...gen, target: e.target.value })} />
                </label>
              </div>
              <div className="row gap oob-actions">
                <button className="btn primary" onClick={generate}>
                  Generate
                </button>
                {payloads.length > 0 && (
                  <button className="btn" onClick={() => setPayloads([])}>
                    Clear list
                  </button>
                )}
              </div>
              {payloads.map((p) => (
                <div key={p.token} className="oob-payload">
                  <div className="row gap">
                    <span className="mono grow ellipsis">{p.token}</span>
                    {p.note && <span className="muted ellipsis">{p.note}</span>}
                  </div>
                  {[["url", p.url], ["host", p.host], ...Object.entries(p.examples)].map(([k, v]) => (
                    <div key={k} className="oob-line">
                      <span className="label">{k}</span>
                      <span className="mono ellipsis" title={v}>
                        {v}
                      </span>
                      <button className="btn small" onClick={() => copy(v)}>
                        Copy
                      </button>
                    </div>
                  ))}
                </div>
              ))}
            </>
          )}
        </div>
        <Split id="oob-detail" dir="col" initial={0.5}>
          <DataTable
            rows={items}
            columns={COLUMNS}
            rowKey={(r) => r.id}
            selected={selected}
            onSelect={(r) => setSelected(r.id)}
            initialSort={{ key: "id", desc: true }}
            empty={
              <>
                No interactions yet.
                <span className="muted small">
                  Inject a payload; when the target resolves or fetches it, the callback appears here. The listener must be
                  reachable from the target: its public host and port (or DNS domain) have to route to this machine, through
                  any firewall, NAT, or VPN in between.
                </span>
              </>
            }
          />
          {item ? (
            <HttpView
              title={`${item.protocol.toUpperCase()} from ${item.remote}${item.raw_truncated ? " (truncated)" : ""}`}
              value={item.raw}
              extra={item.payload?.history_id != null ? <span className="muted">finding from history #{item.payload.history_id}</span> : undefined}
            />
          ) : (
            <div className="blank">Select an interaction to see the full request.</div>
          )}
        </Split>
      </Split>
    </div>
  );
}
