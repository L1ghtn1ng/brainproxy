import { useCallback, useEffect, useRef, useState } from "react";
import { inTauri, run, setProject } from "./api";
import { AppProvider, autoProxy, useApp, type Tab } from "./store";
import { ProxyView } from "./views/Proxy";
import { RepeaterView } from "./views/Repeater";
import { FindingsView } from "./views/Findings";
import { DecoderView } from "./views/Decoder";
import { OobView } from "./views/Oob";
import { SettingsView } from "./views/Settings";
import { FuzzerView } from "./views/Fuzzer";
import { ComparerView } from "./views/Comparer";
import { DashboardView } from "./views/Dashboard";
import { ENGAGEMENT_CHANGED, TargetView } from "./views/Target";
import { ScannerView } from "./views/Scanner";
import { Logo } from "./ui/Logo";
import { Icon } from "./ui/Icons";
import { SideBrand } from "./ui/Brand";
import { Boundary } from "./ui/Boundary";
import { Menu, useMenu } from "./ui/Menu";
import { Welcome, remember } from "./views/Welcome";
import { usePoll } from "./ui/usePoll";

export function App() {
  const [project, setProj] = useState<string | null>(null);
  const [theme, setTheme] = useState(() => {
    try {
      return localStorage.getItem("theme") ?? "dark";
    } catch {
      return "dark";
    }
  });
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem("theme", theme);
    } catch {
      /* storage unavailable */
    }
  }, [theme]);

  const open = useCallback(async (path: string) => {
    setProject(path);
    await run(["project", "init"]);
    remember(path);
    setProj(path);
  }, []);

  const toggleTheme = () => setTheme((t) => (t === "dark" ? "light" : "dark"));
  if (!project) return <Welcome open={open} />;
  return (
    <AppProvider project={project}>
      <Shell onClose={() => setProj(null)} toggleTheme={toggleTheme} />
    </AppProvider>
  );
}

/** Sidebar: tools grouped by what you're doing. */
const NAV: { group: string; items: { id: Tab; label: string; icon: string }[] }[] = [
  {
    group: "Recon",
    items: [
      { id: "dashboard", label: "Overview", icon: "overview" },
      { id: "target", label: "Site map", icon: "sitemap" },
    ],
  },
  { group: "Capture", items: [{ id: "proxy", label: "Proxy", icon: "proxy" }] },
  {
    group: "Attack",
    items: [
      { id: "repeater", label: "Replay", icon: "replay" },
      { id: "fuzzer", label: "Fuzzer", icon: "fuzzer" },
      { id: "scanner", label: "Scans", icon: "scans" },
    ],
  },
  {
    group: "Results",
    items: [
      { id: "findings", label: "Findings", icon: "findings" },
      { id: "oob", label: "Callbacks", icon: "callbacks" },
    ],
  },
  {
    group: "Tools",
    items: [
      { id: "decoder", label: "Codec", icon: "codec" },
      { id: "comparer", label: "Diff", icon: "diff" },
    ],
  },
];

/** Ports tried in order when the app starts the proxy (another project may hold 8080). */
const PROXY_PORTS = [8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089];

interface ProxyStatus {
  running: boolean;
  proxy: { listen?: string; pid?: number } | null;
  pending_intercepts: number;
  intercept_enabled: boolean;
}

function Shell({ onClose, toggleTheme }: { onClose: () => void; toggleTheme: () => void }) {
  const app = useApp();
  const [scope, setScope] = useState<string[] | null>(null);
  const [status, refreshStatus] = usePoll<ProxyStatus>(() => run(["proxy", "status"]), 2000);

  useEffect(() => {
    const load = () =>
      run(["engagement", "show"])
        .then((d) => setScope(d.engagement?.include ?? []))
        .catch(() => setScope([]));
    load();
    window.addEventListener(ENGAGEMENT_CHANGED, load);
    return () => window.removeEventListener(ENGAGEMENT_CHANGED, load);
  }, []);

  const [browsers, setBrowsers] = useState<{ id: string; name: string; kind: string }[]>([]);
  useEffect(() => {
    run<{ browsers: { id: string; name: string; kind: string }[] }>(["browser", "list"]).then((d) => setBrowsers(d.browsers), () => {});
  }, []);
  const browserMenu = useMenu();

  // Starts the proxy if needed, then a browser in this project's profile.
  const openBrowser = async (id: string) => {
    try {
      if (!status?.running) {
        await run(["proxy", "start"]);
        refreshStatus();
      }
      const d = await run<{ browser: { name: string }; note: string | null }>(["browser", "open", "--browser", id]);
      app.toast(d.note ? `${d.browser.name} opened. ${d.note}` : `${d.browser.name} opened through the proxy. Browse the target; requests appear in Proxy › Traffic.`, "info");
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };

  // The proxy starts with the project (unless turned off in Settings); one the app started
  // stops again when the project closes or the window does, so none are left behind.
  const startedHere = useRef(false);
  useEffect(() => {
    if (!autoProxy()) return;
    let cancelled = false;
    (async () => {
      const s = await run<ProxyStatus>(["proxy", "status"]).catch(() => null);
      if (cancelled || !s || s.running) return;
      for (const port of PROXY_PORTS) {
        try {
          await run(["proxy", "start", "--listen", `127.0.0.1:${port}`]);
          startedHere.current = true;
          refreshStatus();
          return;
        } catch (e: any) {
          if (!/cannot listen/i.test(e.message)) return app.toast(`The proxy didn't start: ${e.message}`, "error");
        }
      }
      app.toast(`The proxy didn't start: ports ${PROXY_PORTS.join(", ")} are all in use. Start it from the Proxy pill.`, "error");
    })();
    return () => {
      cancelled = true;
      if (startedHere.current) {
        startedHere.current = false;
        run(["proxy", "stop"]).catch(() => {});
      }
    };
  }, [app, refreshStatus]);

  useEffect(() => {
    if (!inTauri) return;
    let unlisten: (() => void) | undefined;
    import("@tauri-apps/api/window").then(({ getCurrentWindow }) =>
      getCurrentWindow()
        .onCloseRequested(async () => {
          if (startedHere.current) await run(["proxy", "stop"]).catch(() => {});
        })
        .then((u) => (unlisten = u)),
    );
    return () => unlisten?.();
  }, []);

  const proxyToggle = async () => {
    try {
      if (status?.running) await run(["proxy", "stop"]);
      else await run(["proxy", "start"]);
      refreshStatus();
    } catch (e: any) {
      app.toast(e.message, "error");
    }
  };

  const listen = status?.proxy?.listen ?? "127.0.0.1:8080";
  const [collapsed, setCollapsed] = useState(() => {
    try {
      return localStorage.getItem("sidebar") === "collapsed";
    } catch {
      return false;
    }
  });
  const toggleSidebar = () =>
    setCollapsed((c) => {
      try {
        localStorage.setItem("sidebar", c ? "open" : "collapsed");
      } catch {
        /* storage unavailable */
      }
      return !c;
    });

  const navItem = (t: { id: Tab; label: string; icon: string }) => (
    <button key={t.id} className={`nav-item ${app.tab === t.id ? "on" : ""}`} onClick={() => app.setTab(t.id)} title={collapsed ? t.label : undefined}>
      <Icon name={t.icon} />
      <span className="nav-label">{t.label}</span>
      {t.id === "repeater" && app.repeater.length > 0 && <span className="count">{app.repeater.length}</span>}
    </button>
  );

  return (
    <div className={`app ${collapsed ? "nav-collapsed" : ""}`}>
      <header className="top">
        <div className="top-left">
          <div className="brand" onClick={onClose} title="Switch project">
            <Logo size={22} />
            <span className="brand-name">brainproxy</span>
          </div>
          <span className="project" title={app.project}>
            {app.project.split("/").pop()}
          </span>
          <div className="scope">
            {scope == null ? null : scope.length === 0 ? (
              <span className="chip warn" title="Nothing can be sent until engagement start sets the targets">
                no engagement scope
              </span>
            ) : (
              scope.map((s) => (
                <span key={s} className="chip" title="Engagement scope (write-once)">
                  {s}
                </span>
              ))
            )}
          </div>
        </div>
        <div className="top-right">
          {status?.intercept_enabled && (
            <button className="pill hold" onClick={() => app.setTab("proxy")}>
              Intercept on{status.pending_intercepts ? ` · ${status.pending_intercepts} held` : ""}
            </button>
          )}
          {browsers.length > 0 && (
            <button
              className="pill"
              onClick={(e) => {
                const r = e.currentTarget.getBoundingClientRect();
                browserMenu.open({ clientX: r.left, clientY: r.bottom + 4 }, browsers.map((b) => ({ label: `${b.name}${b.kind === "firefox" ? " (import the CA once)" : ""}`, action: () => openBrowser(b.id) })));
              }}
              title="Open a browser that goes through the proxy, in its own profile for this project"
            >
              <Icon name="globe" size={14} />
              Open browser
            </button>
          )}
          <button className={`pill ${status?.running ? "live" : ""}`} onClick={proxyToggle} title={status?.running ? "Stop the proxy" : "Start the proxy"}>
            <span className="dot" />
            {status?.running ? `Proxy ${listen}` : "Proxy off"}
          </button>
          <button className="icon-btn" onClick={toggleTheme} title="Toggle light/dark">
            <Icon name="theme" />
          </button>
        </div>
      </header>
      <div className="body">
        <aside className="sidebar">
          <nav className="nav-groups">
            {NAV.map((g) => (
              <div key={g.group} className="nav-group">
                <div className="nav-heading">{g.group}</div>
                {g.items.map(navItem)}
              </div>
            ))}
          </nav>
          <div className="nav-foot">
            {navItem({ id: "settings", label: "Settings", icon: "settings" })}
            <button className="nav-item" onClick={onClose} title={collapsed ? "Switch project" : undefined}>
              <Icon name="switch" />
              <span className="nav-label">Switch project</span>
            </button>
            <SideBrand collapsed={collapsed} />
            <button className="nav-item" onClick={toggleSidebar} title={collapsed ? "Expand" : "Collapse"}>
              <Icon name={collapsed ? "expand" : "collapse"} />
              <span className="nav-label">Collapse</span>
            </button>
          </div>
        </aside>
      <main className="view">
        {/* Views stay mounted so their state survives tab switches. */}
        <div hidden={app.tab !== "dashboard"} className="view-slot">
          <Boundary><DashboardView active={app.tab === "dashboard"} /></Boundary>
        </div>
        <div hidden={app.tab !== "target"} className="view-slot">
          <Boundary><TargetView active={app.tab === "target"} /></Boundary>
        </div>
        <div hidden={app.tab !== "proxy"} className="view-slot">
          <Boundary><ProxyView /></Boundary>
        </div>
        <div hidden={app.tab !== "repeater"} className="view-slot">
          <Boundary><RepeaterView /></Boundary>
        </div>
        <div hidden={app.tab !== "fuzzer"} className="view-slot">
          <Boundary><FuzzerView /></Boundary>
        </div>
        <div hidden={app.tab !== "scanner"} className="view-slot">
          <Boundary><ScannerView active={app.tab === "scanner"} /></Boundary>
        </div>
        <div hidden={app.tab !== "findings"} className="view-slot">
          <Boundary><FindingsView active={app.tab === "findings"} /></Boundary>
        </div>
        <div hidden={app.tab !== "oob"} className="view-slot">
          <Boundary><OobView active={app.tab === "oob"} /></Boundary>
        </div>
        <div hidden={app.tab !== "decoder"} className="view-slot">
          <Boundary><DecoderView /></Boundary>
        </div>
        <div hidden={app.tab !== "comparer"} className="view-slot">
          <Boundary><ComparerView /></Boundary>
        </div>
        <div hidden={app.tab !== "settings"} className="view-slot">
          <Boundary><SettingsView /></Boundary>
        </div>
      </main>
      </div>
      <Menu menu={browserMenu.menu} close={browserMenu.close} />
      <div className="toasts">
        {app.toasts.map((t) => (
          <div key={t.id} className={`toast ${t.kind}`}>
            {t.text}
          </div>
        ))}
      </div>
    </div>
  );
}
