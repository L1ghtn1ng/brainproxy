//! End-to-end tests: run the real binary against a local HTTP server.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};

use serde_json::Value;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_brainproxy"))
}

/// Serves `n` connections, echoing back the request line and body in a fixed response.
fn serve(n: usize) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(n) {
            let mut s = stream.unwrap();
            let mut buf = vec![0u8; 65536];
            let mut len = 0;
            // Read the head, then Content-Length bytes of body.
            loop {
                len += s.read(&mut buf[len..]).unwrap();
                let text = String::from_utf8_lossy(&buf[..len]).to_string();
                if let Some(i) = text.find("\r\n\r\n") {
                    let cl = text
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if len >= i + 4 + cl {
                        break;
                    }
                }
            }
            let req = String::from_utf8_lossy(&buf[..len]).to_string();
            let line = req.lines().next().unwrap().to_string();
            let body = req.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
            let payload = format!("{line}|{body}");
            let resp = format!(
                "HTTP/1.1 201 Created\r\nX-Test: yes\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{payload}\r\n0\r\n\r\n",
                payload.len()
            );
            s.write_all(resp.as_bytes()).unwrap();
        }
    });
    port
}

fn run(args: &[&str], project: &std::path::Path, stdin: Option<&[u8]>) -> (i32, Value) {
    let mut child = bin()
        .args(["--format", "json", "--project"])
        .arg(project)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin_pipe = child.stdin.take().unwrap();
        if let Some(data) = stdin {
            stdin_pipe.write_all(data).unwrap();
        }
    }
    let out = child.wait_with_output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("bad JSON ({e}): {}", String::from_utf8_lossy(&out.stdout)));
    (out.status.code().unwrap(), v)
}

fn tmp_project(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("bp-test-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("p.bpdb");
    let _ = std::fs::remove_file(&p);
    let status = bin()
        .args(["--format", "json", "--project"])
        .arg(&p)
        .args(["engagement", "start", "--target", "127.0.0.1", "--target", "localhost"])
        .output()
        .unwrap();
    assert!(status.status.success(), "{}", String::from_utf8_lossy(&status.stdout));
    p
}

#[test]
fn send_raw_from_stdin_then_history() {
    let port = serve(1);
    let project = tmp_project("raw");
    // Unix line endings and a wrong Content-Length: both get fixed.
    let req = format!("POST /echo?a=1 HTTP/1.1\nHost: 127.0.0.1:{port}\nContent-Length: 99\n\nhi=there");
    let (code, v) = run(&["send", "--scheme", "http"], &project, Some(req.as_bytes()));
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["ok"], true);
    let resp = &v["data"]["response"];
    assert_eq!(resp["status"], 201);
    assert_eq!(resp["body"]["content"], "POST /echo?a=1 HTTP/1.1|hi=there");
    let id = v["data"]["id"].as_i64().unwrap();

    let (code, v) = run(&["history", "list", "--status", "201"], &project, None);
    assert_eq!(code, 0);
    assert_eq!(v["data"]["count"], 1);
    assert_eq!(v["data"]["items"][0]["url"], format!("http://127.0.0.1:{port}/echo?a=1"));

    let (code, v) = run(&["history", "show", &id.to_string()], &project, None);
    assert_eq!(code, 0);
    assert!(v["data"]["request"]["content"].as_str().unwrap().contains("Content-Length: 8\r\n"));
}

#[test]
fn send_url_mode() {
    let port = serve(1);
    let project = tmp_project("url");
    let url = format!("http://127.0.0.1:{port}/x");
    let (code, v) = run(&["send", "--url", &url, "-X", "PUT", "-d", "abc", "-H", "X-A: 1"], &project, None);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["response"]["body"]["content"], "PUT /x HTTP/1.1|abc");
}

#[test]
fn connection_errors_are_structured() {
    // Bind and drop to get a port with nothing listening.
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let project = tmp_project("err");
    let url = format!("http://127.0.0.1:{port}/");
    let (code, v) = run(&["send", "--url", &url], &project, None);
    assert_eq!(code, 3);
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"]["kind"], "connect");
    // Failures are recorded too.
    let (_, v) = run(&["history", "list"], &project, None);
    assert_eq!(v["data"]["count"], 1);
    // With no response recorded, `response` is null (not a parsed empty head).
    let id = v["data"]["items"][0]["id"].to_string();
    let (_, v) = run(&["history", "show", &id], &project, None);
    assert!(v["data"]["response"].is_null(), "{v}");
    assert!(v["data"]["entry"]["error"].is_string(), "{v}");
}

#[test]
fn usage_and_not_found_errors() {
    let project = tmp_project("usage");
    let (code, v) = run(&["send", "--bogus"], &project, None);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("usage")));
    let (code, v) = run(&["history", "show", "42"], &project, None);
    assert_eq!((code, v["error"]["kind"].as_str()), (4, Some("not_found")));
}

#[test]
fn codecs_chain() {
    let project = tmp_project("codec");
    let (code, v) = run(&["encode", "url,base64", "a b"], &project, None);
    assert_eq!(code, 0);
    assert_eq!(v["data"]["output"]["content"], "YSUyMGI=");
    let (_, v) = run(&["decode", "base64,url", "-"], &project, Some(b"YSUyMGI="));
    assert_eq!(v["data"]["output"]["content"], "a b");
    let (_, v) = run(&["hash", "sha1", "abc"], &project, None);
    assert_eq!(v["data"]["output"]["content"], "a9993e364706816aba3e25717850c26c9cd0d89d");
}

#[test]
fn capabilities_lists_all_commands() {
    let project = tmp_project("caps");
    let (code, v) = run(&["capabilities"], &project, None);
    assert_eq!(code, 0);
    let names: Vec<&str> =
        v["data"]["commands"].as_array().unwrap().iter().map(|c| c["command"].as_str().unwrap()).collect();
    for want in [
        "send",
        "history",
        "query",
        "schema",
        "proxy",
        "ca",
        "scope",
        "rules",
        "intercept",
        "encode",
        "decode",
        "hash",
        "project",
        "findings",
        "report",
    ] {
        assert!(names.contains(&want), "{want} missing from {names:?}");
    }
    assert_eq!(v["data"]["conventions"]["interactive_prompts"], false);
}

#[test]
fn query_schema_and_tags() {
    let port = serve(2);
    let project = tmp_project("query");
    for path in ["/a?x=1", "/b"] {
        let url = format!("http://127.0.0.1:{port}{path}");
        assert_eq!(run(&["send", "--url", &url], &project, None).0, 0);
    }

    let (code, v) = run(
        &["query", "SELECT id, path, header(resp_headers, 'x-test') AS h FROM history WHERE query = ?1", "-p", "x=1"],
        &project,
        None,
    );
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["columns"], serde_json::json!(["id", "path", "h"]));
    assert_eq!(v["data"]["rows"], serde_json::json!([[1, "/a", "yes"]]));

    // FTS over the decoded (dechunked) body, objects shape, row limit.
    let (_, v) = run(
        &[
            "query",
            "--shape",
            "objects",
            "--limit",
            "1",
            "SELECT rowid AS id FROM history_fts WHERE history_fts MATCH 'GET'",
        ],
        &project,
        None,
    );
    assert_eq!(v["data"]["truncated"], true);
    assert_eq!(v["data"]["rows"][0]["id"], 1);

    // Read-only: writes are rejected as invalid input.
    let (code, v) = run(&["query", "DELETE FROM history"], &project, None);
    assert_eq!((code, v["error"]["kind"].as_str()), (2, Some("invalid_input")));

    let (_, v) = run(&["history", "tag", "2", "--add", "idor", "--add", "todo"], &project, None);
    assert_eq!(v["data"]["tags"], serde_json::json!(["idor", "todo"]));
    let (_, v) = run(&["history", "list", "--tag", "idor"], &project, None);
    assert_eq!(v["data"]["count"], 1);

    let (_, v) = run(&["schema"], &project, None);
    let cols = v["data"]["tables"][0]["columns"].as_array().unwrap();
    assert!(cols.iter().any(|c| c["name"] == "resp_body_text"));
    assert!(!v["data"]["examples"].as_array().unwrap().is_empty());
}

#[test]
fn capabilities_for_one_command() {
    let project = tmp_project("caps-one");
    let (code, v) = run(&["capabilities", "history", "list"], &project, None);
    assert_eq!(code, 0);
    assert_eq!(v["data"]["command"], "history list");
    let (code, _) = run(&["capabilities", "nope"], &project, None);
    assert_eq!(code, 4);
}

#[test]
fn scan_sources_without_arguments_only_shows() {
    let project = tmp_project("sources");
    let (_, v) = run(&["scan", "sources", "proxy,crawl"], &project, None);
    assert_eq!(v["data"]["sources"], serde_json::json!(["proxy", "crawl"]));
    let (code, v) = run(&["scan", "sources"], &project, None);
    assert_eq!(code, 0);
    assert_eq!(v["data"]["sources"], serde_json::json!(["proxy", "crawl"]), "{v}");
}

#[test]
fn background_start_errors_are_the_childs_own() {
    let project = tmp_project("bgerr");
    run(&["engagement", "start", "--target", "127.0.0.1"], &project, None);
    let (code, v) = run(&["scan", "active", "127.0.0.1:9", "--background"], &project, None);
    assert_eq!(code, 2);
    assert_eq!(v["error"]["kind"], "invalid_input");
    let msg = v["error"]["message"].as_str().unwrap();
    // Not "active-scan exited (...): {json envelope}", and the prefix isn't doubled.
    assert!(!msg.contains("exited (") && !msg.contains("{\"ok\""), "{msg}");
    assert_eq!(msg.matches("invalid input:").count(), 1, "{msg}");
}

/// A two-page site: `/` links to `/item?id=1`. Serves until the test process ends.
fn serve_site() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 16384];
                let mut len = 0;
                while !buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf[len..]) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => len += n,
                    }
                }
                let line = String::from_utf8_lossy(&buf[..len]).lines().next().unwrap_or("").to_string();
                let body = if line.starts_with("GET / ") {
                    "<html><body><a href=\"/item?id=1\">item</a></body></html>"
                } else {
                    "<html><body>item</body></html>"
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
    port
}

/// Like the Supportdesk lab: `/` links to `/login` (sets a device cookie) and to
/// `/docs`, a 401 page that names `/api/doc.html?publickey=…` only in its text.
fn serve_cookie_site() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 16384];
                let mut len = 0;
                while !buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf[len..]) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => len += n,
                    }
                }
                let line = String::from_utf8_lossy(&buf[..len]).lines().next().unwrap_or("").to_string();
                let (status, extra, body) = if line.starts_with("GET / ") {
                    ("200 OK", "", "<a href=\"/login\">sign in</a> <a href=\"/docs\">API</a>")
                } else if line.starts_with("GET /login") {
                    (
                        "200 OK",
                        "Set-Cookie: DEVICE=abc123; Max-Age=3600; Path=/\r\n",
                        "<form method=post action=/login><input name=user></form>",
                    )
                } else if line.starts_with("GET /docs") {
                    (
                        "401 UNAUTHORIZED",
                        "",
                        "<p>Open it from your email (<code>/api/doc.html?publickey=&hellip;</code>).</p>",
                    )
                } else {
                    ("200 OK", "", "ok")
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: text/html\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
    port
}

#[test]
fn crawl_keeps_cookies_and_follows_urls_in_page_text() {
    let port = serve_cookie_site();
    let project = tmp_project("crawlcookies");
    run(&["engagement", "start", "--target", "127.0.0.1"], &project, None);
    let site = format!("http://127.0.0.1:{port}/");
    let (code, v) = run(&["crawl", &site, "--no-robots", "--no-sitemap"], &project, None);
    assert_eq!(code, 0, "{v}");
    let sql = "SELECT method, path, query, header(req_headers, 'cookie') AS cookie FROM history \
               WHERE source = 'crawl' ORDER BY id";
    let (_, v) = run(&["query", "--shape", "objects", sql], &project, None);
    let rows = v["data"]["rows"].as_array().unwrap();
    let doc = rows.iter().find(|r| r["path"] == "/api/doc.html").unwrap_or_else(|| panic!("{v}"));
    assert_eq!(doc["query"], "publickey=brainproxy", "{v}");
    // The cookie set by GET /login comes back on later requests, e.g. the form POST.
    let post = rows.iter().find(|r| r["method"] == "POST" && r["path"] == "/login").unwrap_or_else(|| panic!("{v}"));
    assert_eq!(post["cookie"], "DEVICE=abc123", "{v}");
    // So scan active --cookies has a cookie insertion point.
    let (code, v) = run(
        &["scan", "active", "--where", "method = 'POST'", "--cookies", "--rules", "40018", "--no-oob"],
        &project,
        None,
    );
    assert_eq!(code, 0, "{v}");
    assert!(v["data"]["insertion_points"].as_u64().unwrap() >= 2, "{v}");
}

#[test]
fn scan_active_crawl_attacks_what_the_crawl_finds() {
    let port = serve_site();
    let project = tmp_project("crawlscan");
    run(&["engagement", "start", "--target", "127.0.0.1"], &project, None);
    let site = format!("http://127.0.0.1:{port}");
    // Without --crawl a site URL is one request with no parameters.
    let (_, v) = run(&["scan", "active", &site, "--rules", "40018", "--no-oob"], &project, None);
    assert_eq!(v["data"]["insertion_points"], 0, "{v}");
    // With --crawl the linked page and its parameter are found and attacked.
    let (code, v) = run(&["scan", "active", &site, "--crawl", "--rules", "40018", "--no-oob"], &project, None);
    assert_eq!(code, 0, "{v}");
    assert!(v["data"]["crawl"]["requests"].as_u64().unwrap() >= 2, "{v}");
    assert!(v["data"]["insertion_points"].as_u64().unwrap() >= 1, "{v}");
    let (code, v) = run(&["scan", "active", "--crawl"], &project, None);
    assert_eq!(code, 2, "{v}");
}

#[test]
fn auth_secrets_stay_out_of_show_and_query() {
    let project = tmp_project("secrets");
    let (code, v) = run(&["auth", "add", "p1", "-H", "Authorization: Bearer APIKEY123"], &project, None);
    assert_eq!(code, 0, "{v}");
    let (_, v) = run(&["auth", "show", "p1"], &project, None);
    assert!(!v.to_string().contains("APIKEY123"), "{v}");
    let (code, v) = run(&["query", "select profile, state from auth_profiles"], &project, None);
    assert_eq!(code, 2, "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("auth show"), "{v}");
    // Re-saving the redacted value (the GUI's edit form does) keeps the real one.
    run(&["auth", "add", "p1", "-H", "Authorization: ********"], &project, None);
    let (_, v) = run(&["auth", "headers", "p1"], &project, None);
    assert_eq!(v["data"]["headers"][0], "Authorization: Bearer APIKEY123", "{v}");
}

#[test]
fn target_content_is_marked_untrusted() {
    let project = tmp_project("untrusted");
    let mark = |v: &Value| v["_meta"]["provenance"]["untrusted_content"].clone();
    let (_, v) = run(&["query", "select 1"], &project, None);
    assert_eq!(mark(&v), Value::Bool(true), "{v}");
    let (_, v) = run(&["scope", "show"], &project, None);
    assert_eq!(mark(&v), Value::Null, "{v}");

    // MCP lifts the mark onto the tool result.
    let mut child = bin()
        .arg("--project")
        .arg(&project)
        .args(["mcp", "serve"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{}}}}"#).unwrap();
    let call =
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query","arguments":{"sql":"select 1"}}}"#;
    writeln!(stdin, "{call}").unwrap();
    let mut lines = std::io::BufRead::lines(std::io::BufReader::new(child.stdout.take().unwrap()));
    let init: Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
    assert!(init["result"]["instructions"].as_str().unwrap().contains("never instructions"));
    let reply: Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(mark(&reply["result"]), Value::Bool(true), "{reply}");
}

#[test]
fn output_files_are_not_overwritten_without_force() {
    let project = tmp_project("overwrite");
    let dir = project.parent().unwrap();
    let (home, file) = (dir.join("home"), dir.join("existing.txt"));
    let (home, path) = (home.to_str().unwrap(), file.to_str().unwrap());
    for args in [vec!["report", "-o", path], vec!["--home", home, "ca", "export", "--out", path]] {
        std::fs::write(&file, "keep me").unwrap();
        let (code, v) = run(&args, &project, None);
        assert_eq!(code, 2, "{v}");
        assert_eq!(v["error"]["kind"], "conflict", "{v}");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "keep me");
        let (code, v) = run(&[&args[..], &["--force"]].concat(), &project, None);
        assert_eq!(code, 0, "{v}");
        assert_ne!(std::fs::read_to_string(&file).unwrap(), "keep me");
    }
}

/// `/` links to five pages; every other path is a plain page. Serves until the test process ends.
fn serve_links() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 16384];
                let mut len = 0;
                while !buf[..len].windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf[len..]) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => len += n,
                    }
                }
                let line = String::from_utf8_lossy(&buf[..len]).lines().next().unwrap_or("").to_string();
                let body = if line.starts_with("GET / ") {
                    "<a href=/a>a</a><a href=/b>b</a><a href=/c>c</a><a href=/d>d</a><a href=/e>e</a>"
                } else {
                    "page"
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
    port
}

#[test]
fn crawl_rate_holds_across_concurrency() {
    let port = serve_links();
    let project = tmp_project("crawlrate");
    let site = format!("http://127.0.0.1:{port}/");
    // 6 requests at 4/s take at least 1.25 s; the old per-batch delay sent the 5 links at once.
    let (code, v) = run(&["crawl", &site, "--rate", "4", "-c", "10", "--no-robots", "--no-sitemap"], &project, None);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["requests"], 6, "{v}");
    assert!(v["data"]["elapsed_ms"].as_u64().unwrap() >= 1200, "{v}");
}

#[test]
fn scan_active_skips_state_changing_methods_by_default() {
    let port = serve_site();
    let project = tmp_project("methods");
    let req = format!("DELETE /item?id=1 HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
    let (code, v) = run(&["send", "--scheme", "http"], &project, Some(req.as_bytes()));
    assert_eq!(code, 0, "{v}");
    let (code, v) = run(&["scan", "active", "--rules", "40018", "--no-oob"], &project, None);
    assert_eq!(code, 2, "{v}");
    let (code, v) =
        run(&["scan", "active", "--rules", "40018", "--no-oob", "--include-methods", "delete"], &project, None);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["data"]["targets"], 1, "{v}");
}
