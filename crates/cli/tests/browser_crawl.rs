//! `crawl --browser` against a local single-page app whose API endpoints only show up
//! when its JavaScript runs: a client-side route reached by clicking an element with a
//! click listener (history.pushState), a hash route with a form, and buttons that call
//! fetch(). The API paths are built at run time, so the plain crawl can't read them from
//! the script. Skipped when no Chromium-based browser is installed.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use serde_json::Value;

const INDEX: &str = r##"<!doctype html><html><head><title>SPA</title></head><body>
<nav><span data-route="/reports">Reports</span> <a href="#/settings">Settings</a> <button id="logout">Log out</button></nav>
<div id="view"></div><script src="/app.js"></script></body></html>"##;

const APP: &str = r#"
const api = (...p) => ['', 'api', ...p].join('/');
function render() {
  const view = document.getElementById('view');
  const route = location.hash.startsWith('#/') ? location.hash.slice(1) : location.pathname;
  if (route === '/reports') {
    view.innerHTML = '<button id="load">Load report</button> <button id="del">Delete report</button>';
    document.getElementById('load').addEventListener('click', () =>
      fetch(api('reports', 'export'), {method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({format: 'csv'})}).then(r => r.json()).then(() =>
          view.insertAdjacentHTML('beforeend', '<p>exported</p>')));
    document.getElementById('del').addEventListener('click', () => fetch(api('reports', '1'), {method: 'DELETE'}));
  } else if (route === '/settings') {
    view.innerHTML = '<form id="f"><input name="nickname"><button>Save</button></form>';
    document.getElementById('f').addEventListener('submit', (e) => {
      e.preventDefault();
      fetch(api('settings') + '?nickname=' + encodeURIComponent(e.target.nickname.value));
    });
  } else {
    view.innerHTML = '<p>Welcome</p>';
  }
}
document.querySelectorAll('[data-route]').forEach((el) => el.addEventListener('click', () => {
  history.pushState({}, '', el.dataset.route);
  render();
}));
document.getElementById('logout').addEventListener('click', () => fetch(api('logout-now'), {method: 'POST'}));
addEventListener('hashchange', render);
addEventListener('popstate', render);
render();
fetch(api('me'));
"#;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_brainproxy"))
}

fn run(args: &[&str], project: &std::path::Path) -> (i32, Value) {
    let out = bin()
        .args(["--format", "json", "--project"])
        .arg(project)
        .args(args)
        // The page is this test's own: Chromium's sandbox may be unavailable in containers and CI.
        .env("BRAINPROXY_BROWSER_NO_SANDBOX", "1")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!("bad JSON ({e}): {}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
    });
    (out.status.code().unwrap(), v)
}

/// The single-page app; returns its port and the request lines it saw.
fn serve_spa() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let log = log.clone();
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 65536];
                let mut len = 0;
                loop {
                    match s.read(&mut buf[len..]) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => len += n,
                    }
                    let text = String::from_utf8_lossy(&buf[..len]).to_string();
                    if let Some(i) = text.find("\r\n\r\n") {
                        let cl = text
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().to_string())
                            })
                            .and_then(|v| v.parse::<usize>().ok())
                            .unwrap_or(0);
                        if len >= i + 4 + cl {
                            break;
                        }
                    }
                }
                let line = String::from_utf8_lossy(&buf[..len]).lines().next().unwrap_or("").to_string();
                log.lock().unwrap().push(line.clone());
                let path = line.split(' ').nth(1).unwrap_or("/");
                let (ct, body) = if path == "/app.js" {
                    ("application/javascript", APP.to_string())
                } else if path.starts_with("/api/") {
                    ("application/json", "{\"ok\":true}".to_string())
                } else if path == "/favicon.ico" {
                    ("image/x-icon", String::new())
                } else {
                    // Every other path is the app (deep links to client-side routes work).
                    ("text/html", INDEX.to_string())
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
    (port, seen)
}

#[test]
fn browser_crawl_finds_api_calls_made_by_javascript() {
    let (code, list) = {
        let dir = std::env::temp_dir().join(format!("bp-test-{}-browser-list", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        run(&["browser", "list"], &dir.join("p.bpdb"))
    };
    assert_eq!(code, 0, "{list}");
    let chromium = list["data"]["browsers"].as_array().into_iter().flatten().any(|b| b["kind"] == "chromium");
    if !chromium {
        eprintln!(
            "SKIPPED browser_crawl_finds_api_calls_made_by_javascript: no Chromium-based browser found \
             (install chromium, Chrome, Edge or Brave to run it)"
        );
        return;
    }

    let dir = std::env::temp_dir().join(format!("bp-test-{}-browser-crawl", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let project = dir.join("p.bpdb");
    let _ = std::fs::remove_file(&project);
    let (code, v) = run(&["engagement", "start", "--target", "127.0.0.1"], &project);
    assert_eq!(code, 0, "{v}");

    let (port, seen) = serve_spa();
    let site = format!("http://127.0.0.1:{port}/");
    let (code, v) = run(&["crawl", &site, "--browser", "--max-pages", "60", "--max-minutes", "3"], &project);
    assert_eq!(code, 0, "{v}");
    let data = &v["data"];
    assert_eq!(data["mode"], "browser", "{v}");

    let lines = seen.lock().unwrap().clone();
    let saw = |l: &str| lines.iter().any(|x| x.starts_with(l));
    // Reached only by running the script, clicking a listener-only element, a button, and a form.
    assert!(saw("GET /api/me "), "{lines:?}");
    assert!(saw("POST /api/reports/export "), "{lines:?}");
    assert!(saw("GET /api/settings?nickname=brainproxy "), "{lines:?}");
    assert!(saw("GET /reports "), "the pushState route is loaded directly too: {lines:?}");
    // Nothing destructive reached the site.
    assert!(!lines.iter().any(|l| l.starts_with("DELETE ") || l.contains("logout")), "{lines:?}");

    let not_clicked: Vec<&str> = data["not_clicked"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
    assert!(not_clicked.iter().any(|l| l.contains("Log out")), "{v}");
    assert!(not_clicked.iter().any(|l| l.contains("Delete report")), "{v}");
    let api: Vec<String> = data["api_calls"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| format!("{} {}", e["method"].as_str().unwrap(), e["path"].as_str().unwrap()))
        .collect();
    for want in ["GET /api/me", "POST /api/reports/export", "GET /api/settings"] {
        assert!(api.iter().any(|a| a == want), "{want} not in {api:?}");
    }
    let export = data["api_calls"].as_array().unwrap().iter().find(|e| e["path"] == "/api/reports/export").unwrap();
    assert_eq!(export["params"], serde_json::json!(["format"]), "JSON body keys are parameters");

    // Recorded in history as crawl-browser, ready for `scan active`.
    let (code, h) = run(&["history", "list", "--source", "crawl-browser", "--limit", "200"], &project);
    assert_eq!(code, 0, "{h}");
    let rows = h["data"]["items"].as_array().cloned().unwrap_or_default();
    let export = format!("{site}api/reports/export");
    assert!(rows.iter().any(|r| r["url"] == export.as_str() && r["method"] == "POST"), "{h}");
}

#[test]
fn browser_crawl_flags_need_browser() {
    let dir = std::env::temp_dir().join(format!("bp-test-{}-browser-flags", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = bin()
        .args(["--format", "json", "--project"])
        .arg(dir.join("p.bpdb"))
        .args(["crawl", "http://127.0.0.1:1/", "--headful"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(text.contains("--browser"), "{text}");
}
