//! A Chromium-family browser driven over the Chrome DevTools Protocol.
//!
//! The protocol runs over `--remote-debugging-pipe`: the browser reads commands on fd 3 and
//! writes replies and events on fd 4, each a JSON message ended by a NUL byte. Unlike
//! `--remote-debugging-port` this opens no TCP port that other local users or processes
//! could connect to, and it needs no WebSocket or HTTP client: only this module, serde_json
//! and tokio, so the static musl build is unaffected. Pipes are passed the Unix way
//! (dup2 before exec), so the browser crawl runs on Linux and macOS.
//!
//! The browser gets a fresh temporary profile (removed afterwards), goes only through the
//! proxy it is given, trusts the brainproxy CA by its key, and has the features that phone
//! home switched off. JavaScript dialogs are dismissed and pop-up windows closed as they
//! appear, so a page can never block the crawl waiting for an answer.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::sync::oneshot;

use crate::error::{Error, Result};

/// How long one protocol command may take.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);

#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) struct LaunchOptions<'a> {
    pub path: &'a Path,
    pub headless: bool,
    /// The proxy every request goes through.
    pub proxy: SocketAddr,
    /// base64(SHA-256(SPKI)) of the CA the proxy signs with.
    pub ca_spki: String,
    /// Run without Chromium's sandbox (needed as root, or where user namespaces are off).
    pub no_sandbox: bool,
}

type Reply = std::result::Result<Value, String>;

struct Conn {
    writer: Mutex<Box<dyn std::io::Write + Send>>,
    next: AtomicU64,
    pending: Mutex<HashMap<u64, oneshot::Sender<Reply>>>,
    closed: AtomicBool,
}

#[cfg_attr(not(unix), allow(dead_code))]
impl Conn {
    fn send(&self, id: u64, method: &str, params: Value, session: Option<&str>) -> std::io::Result<()> {
        let mut msg = json!({"id": id, "method": method, "params": params});
        if let Some(s) = session {
            msg["sessionId"] = json!(s);
        }
        let mut bytes = serde_json::to_vec(&msg).unwrap_or_default();
        bytes.push(0);
        let mut w = self.writer.lock().unwrap();
        w.write_all(&bytes)?;
        w.flush()
    }

    /// A command whose reply nobody waits for.
    fn fire(&self, method: &str, params: Value, session: Option<&str>) {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let _ = self.send(id, method, params, session);
    }

    /// Handles one message from the browser.
    fn dispatch(&self, msg: Value) {
        if let Some(id) = msg.get("id").and_then(Value::as_u64) {
            if let Some(tx) = self.pending.lock().unwrap().remove(&id) {
                let reply = match msg.get("error") {
                    Some(e) => Err(e.get("message").and_then(Value::as_str).unwrap_or("CDP error").to_string()),
                    None => Ok(msg.get("result").cloned().unwrap_or(Value::Null)),
                };
                let _ = tx.send(reply);
            }
            return;
        }
        let session = msg.get("sessionId").and_then(Value::as_str);
        let params = &msg["params"];
        match msg.get("method").and_then(Value::as_str) {
            // alert/confirm/prompt/beforeunload: dismissed, so a confirm() before a
            // destructive action answers "no" and nothing waits for a person.
            Some("Page.javascriptDialogOpening") => {
                self.fire("Page.handleJavaScriptDialog", json!({"accept": false}), session);
            }
            // Pop-ups and new tabs opened by the page: closed (their URLs are
            // recorded by the page script and crawled in the main tab).
            Some("Target.targetCreated") => {
                let info = &params["targetInfo"];
                if info["type"] == "page" && info.get("openerId").and_then(Value::as_str).is_some() {
                    if let Some(id) = info["targetId"].as_str() {
                        self.fire("Target.closeTarget", json!({"targetId": id}), None);
                    }
                }
            }
            _ => {}
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        for (_, tx) in self.pending.lock().unwrap().drain() {
            let _ = tx.send(Err("the browser exited".into()));
        }
    }
}

/// A running browser. Dropping it kills the browser and removes its profile.
pub(crate) struct Chrome {
    child: std::process::Child,
    conn: Arc<Conn>,
    profile: PathBuf,
}

impl Chrome {
    #[cfg(not(unix))]
    pub fn launch(_opts: &LaunchOptions) -> Result<Chrome> {
        Err(Error::InvalidInput(
            "the browser crawl runs on Linux and macOS; on Windows, browse the site through the proxy (browser open)"
                .into(),
        ))
    }

    #[cfg(unix)]
    pub fn launch(opts: &LaunchOptions) -> Result<Chrome> {
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;

        let profile = temp_profile()?;
        // Commands go down `to_browser` (the browser's fd 3); replies come up `from_browser` (fd 4).
        let (to_browser_r, to_browser_w) = std::io::pipe()?;
        let (from_browser_r, from_browser_w) = std::io::pipe()?;
        let stderr = std::fs::File::create(profile.join("stderr.log"))?;
        let mut cmd = std::process::Command::new(opts.path);
        cmd.args(args(opts, &profile))
            // Crash reports and caches stay in the temporary profile, not the user's home.
            .env("XDG_CONFIG_HOME", profile.join("config"))
            .env("XDG_CACHE_HOME", profile.join("cache"))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(stderr)
            // Its own process group, so the renderers it starts can be killed with it.
            .process_group(0);
        let (r, w) = (to_browser_r.as_raw_fd(), from_browser_w.as_raw_fd());
        // SAFETY: only async-signal-safe calls (fcntl, dup2, prctl) between fork and exec.
        unsafe {
            cmd.pre_exec(move || {
                // Copies above fd 10 first, so placing them at 3 and 4 can't overwrite each other.
                let r2 = libc::fcntl(r, libc::F_DUPFD_CLOEXEC, 10);
                let w2 = libc::fcntl(w, libc::F_DUPFD_CLOEXEC, 10);
                if r2 < 0 || w2 < 0 || libc::dup2(r2, 3) < 0 || libc::dup2(w2, 4) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // The browser dies with us, even if we are killed.
                #[cfg(target_os = "linux")]
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                Ok(())
            });
        }
        let child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&profile);
                return Err(Error::InvalidInput(format!("can't start {}: {e}", opts.path.display())));
            }
        };
        drop((to_browser_r, from_browser_w));
        let conn = Arc::new(Conn {
            writer: Mutex::new(Box::new(to_browser_w)),
            next: AtomicU64::new(1),
            pending: Mutex::default(),
            closed: AtomicBool::new(false),
        });
        let reader = conn.clone();
        std::thread::spawn(move || {
            use std::io::BufRead;
            let mut input = std::io::BufReader::new(from_browser_r);
            let mut buf = Vec::new();
            loop {
                buf.clear();
                match input.read_until(0, &mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if buf.last() == Some(&0) {
                            buf.pop();
                        }
                        if let Ok(msg) = serde_json::from_slice::<Value>(&buf) {
                            reader.dispatch(msg);
                        }
                    }
                }
            }
            reader.close();
        });
        Ok(Chrome { child, conn, profile })
    }

    /// Whether the browser is still connected.
    pub fn alive(&self) -> bool {
        !self.conn.closed.load(Ordering::SeqCst)
    }

    /// Sends a command and waits for its result.
    pub async fn call(&self, method: &str, params: Value, session: Option<&str>) -> Result<Value> {
        self.call_timeout(method, params, session, CALL_TIMEOUT).await
    }

    pub async fn call_timeout(
        &self,
        method: &str,
        params: Value,
        session: Option<&str>,
        timeout: Duration,
    ) -> Result<Value> {
        if self.conn.closed.load(Ordering::SeqCst) {
            return Err(Error::Protocol(format!("the browser exited{}", self.stderr_hint())));
        }
        let id = self.conn.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.conn.pending.lock().unwrap().insert(id, tx);
        if let Err(e) = self.conn.send(id, method, params, session) {
            self.conn.pending.lock().unwrap().remove(&id);
            return Err(Error::Protocol(format!("the browser exited ({e}){}", self.stderr_hint())));
        }
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(Ok(v))) => Ok(v),
            Ok(Ok(Err(e))) if e == "the browser exited" => Err(Error::Protocol(format!("{e}{}", self.stderr_hint()))),
            Ok(Ok(Err(e))) => Err(Error::Protocol(format!("{method}: {e}"))),
            Ok(Err(_)) => Err(Error::Protocol(format!("the browser exited{}", self.stderr_hint()))),
            Err(_) => {
                self.conn.pending.lock().unwrap().remove(&id);
                Err(Error::Timeout(timeout))
            }
        }
    }

    /// The end of the browser's error output, to explain why it stopped.
    fn stderr_hint(&self) -> String {
        let log = std::fs::read_to_string(self.profile.join("stderr.log")).unwrap_or_default();
        let lines: Vec<&str> = log
            .lines()
            .filter(|l| !l.contains("crashpad") && !l.trim().is_empty())
            .rev()
            .take(3)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        let mut hint = if lines.is_empty() { String::new() } else { format!(": {}", lines.join(" / ")) };
        if log.contains("No usable sandbox") || log.contains("Running as root without --no-sandbox") {
            hint.push_str(
                " (Chromium's sandbox isn't available here: install your distribution's chromium-sandbox \
                 package or enable user namespaces, or set BRAINPROXY_BROWSER_NO_SANDBOX=1 to run without it)",
            );
        }
        hint
    }

    /// Asks the browser to exit, then makes sure it has.
    pub async fn close(self) {
        let _ = self.call_timeout("Browser.close", json!({}), None, Duration::from_secs(3)).await;
        // Drop kills whatever is left.
    }
}

impl Drop for Chrome {
    fn drop(&mut self) {
        #[cfg(unix)]
        // SAFETY: plain kill(2) on the browser's own process group.
        unsafe {
            libc::kill(-(self.child.id() as libc::pid_t), libc::SIGKILL);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.profile);
    }
}

/// A new private directory for the browser profile.
#[cfg_attr(not(unix), allow(dead_code))]
fn temp_profile() -> Result<PathBuf> {
    let mut rnd = [0u8; 8];
    getrandom::fill(&mut rnd).map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
    let dir = std::env::temp_dir().join(format!("brainproxy-browser-{}", hex::encode(rnd)));
    let mut b = std::fs::DirBuilder::new();
    // Not recursive: the temp dir exists, and the profile must be a new folder.
    b.recursive(false);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(&dir)?;
    Ok(dir)
}

/// Whether Chromium's sandbox must be off: it refuses to start as root with it, and
/// `BRAINPROXY_BROWSER_NO_SANDBOX=1` turns it off where user namespaces are unavailable.
pub(crate) fn sandbox_off() -> bool {
    #[cfg(unix)]
    // SAFETY: geteuid has no preconditions.
    let root = unsafe { libc::geteuid() } == 0;
    #[cfg(not(unix))]
    let root = false;
    root || std::env::var("BRAINPROXY_BROWSER_NO_SANDBOX").is_ok_and(|v| !v.is_empty() && v != "0")
}

/// The browser's command line.
#[cfg_attr(not(unix), allow(dead_code))]
fn args(opts: &LaunchOptions, profile: &Path) -> Vec<String> {
    let mut a: Vec<String> = vec![
        format!("--user-data-dir={}", profile.display()),
        "--remote-debugging-pipe".into(),
        format!("--proxy-server=http://{}", opts.proxy),
        // Chromium bypasses the proxy for loopback unless told otherwise.
        "--proxy-bypass-list=<-loopback>".into(),
        // Nothing is looked up directly: names go to the proxy, which checks the scope after DNS.
        format!("--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE {}", opts.proxy.ip()),
        // WebRTC would otherwise send UDP around the proxy.
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp".into(),
        "--webrtc-ip-handling-policy=disable_non_proxied_udp".into(),
        format!("--ignore-certificate-errors-spki-list={}", opts.ca_spki),
        "--window-size=1280,1000".into(),
    ];
    if opts.headless {
        a.push("--headless=new".into());
    }
    if opts.no_sandbox {
        a.push("--no-sandbox".into());
    }
    for flag in [
        // No background traffic of the browser's own (updates, safe browsing, metrics, sync).
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-sync",
        "--disable-domain-reliability",
        "--disable-client-side-phishing-detection",
        "--disable-default-apps",
        "--disable-extensions",
        "--no-pings",
        "--metrics-recording-only",
        "--no-service-autorun",
        "--disable-breakpad",
        "--disable-crash-reporter",
        "--password-store=basic",
        "--use-mock-keychain",
        "--disable-quic",
        "--mute-audio",
        "--disable-dev-shm-usage",
        "--disable-background-timer-throttling",
        "--disable-renderer-backgrounding",
        // HttpsUpgrades: an http:// target must not be tried over https first.
        "--disable-features=OptimizationHints,MediaRouter,DialMediaRouteProvider,Translate,\
         AutofillServerCommunication,CertificateTransparencyComponentUpdater,InterestFeedContentSuggestions,\
         HttpsUpgrades,HttpsFirstBalancedModeAutoEnable,PrivacySandboxSettings4",
    ] {
        a.push(flag.into());
    }
    a.push("about:blank".into());
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_flags_route_everything_through_the_proxy() {
        let opts = LaunchOptions {
            path: Path::new("/usr/bin/chromium"),
            headless: true,
            proxy: "127.0.0.1:41234".parse().unwrap(),
            ca_spki: "abc=".into(),
            no_sandbox: false,
        };
        let a = args(&opts, Path::new("/tmp/p"));
        for want in [
            "--proxy-server=http://127.0.0.1:41234",
            "--proxy-bypass-list=<-loopback>",
            "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1",
            "--ignore-certificate-errors-spki-list=abc=",
            "--remote-debugging-pipe",
            "--headless=new",
            "--user-data-dir=/tmp/p",
        ] {
            assert!(a.iter().any(|x| x == want), "{want} missing from {a:?}");
        }
        assert!(!a.iter().any(|x| x.starts_with("--remote-debugging-port")));
        assert!(!a.iter().any(|x| x == "--no-sandbox"));
        assert!(a.iter().any(|x| x.contains("HttpsUpgrades")));
        assert_eq!(a.last().map(String::as_str), Some("about:blank"));
    }
}
