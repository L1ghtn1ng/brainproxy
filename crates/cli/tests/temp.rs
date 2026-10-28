//! The CLI side of temporary engagements, which are a desktop-app feature: the app's shell
//! creates and deletes their folders itself. Here: `project save` and `project stop` (which
//! delete nothing), and the guard that neither the CLI nor `mcp serve` can make or wipe a
//! self-deleting project, so whatever a script or agent starts keeps its project file.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::{json, Value};

/// A private folder and CA home per test, with a project scoped to 127.0.0.1.
struct Env {
    dir: PathBuf,
    project: PathBuf,
}

impl Env {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("bp-temp-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let env = Self { project: dir.join("p.bpdb"), dir };
        env.ok(&env.project, &["engagement", "start", "--target", "127.0.0.1"]);
        env
    }

    fn cmd(&self, project: &Path) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_brainproxy"));
        c.env_remove("BRAINPROXY_PROJECT")
            .args(["--format", "json", "--home"])
            .arg(self.dir.join("home"))
            .arg("--project")
            .arg(project);
        c
    }

    fn run(&self, project: &Path, args: &[&str]) -> (i32, Value) {
        let out = self.cmd(project).args(args).output().unwrap();
        let v = serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|e| panic!("bad JSON ({e}): {}", String::from_utf8_lossy(&out.stdout)));
        (out.status.code().unwrap(), v)
    }

    fn ok(&self, project: &Path, args: &[&str]) -> Value {
        let (code, v) = self.run(project, args);
        assert_eq!(code, 0, "{args:?} -> {v}");
        v["data"].clone()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn save_copies_and_never_overwrites() {
    let env = Env::new("save");
    let saved = env.dir.join("kept/acme.bpdb");
    env.ok(&env.project, &["project", "save", "--output", saved.to_str().unwrap()]);
    let shown = env.ok(&saved, &["engagement", "show"]);
    assert_eq!(shown["engagement"]["include"], json!(["127.0.0.1"]));

    let (code, v) = env.run(&env.project, &["project", "save", "--output", saved.to_str().unwrap()]);
    assert_ne!(code, 0, "{v}");
    assert_eq!(v["error"]["kind"], "conflict");
}

#[test]
fn stop_stops_the_proxy_and_deletes_nothing() {
    let env = Env::new("stop");
    let started = env.ok(&env.project, &["proxy", "start", "--listen", "127.0.0.1:0"]);
    let pid = started["pid"].as_u64().unwrap() as u32;

    // A copy saved meanwhile doesn't take the running proxy for its own.
    let copy = env.dir.join("copy.bpdb");
    env.ok(&env.project, &["project", "save", "--output", copy.to_str().unwrap()]);
    assert_eq!(env.ok(&copy, &["proxy", "status"])["running"], false);
    let (code, _) = env.run(&copy, &["proxy", "stop"]);
    assert_ne!(code, 0);

    let d = env.ok(&env.project, &["project", "stop"]);
    assert_eq!(d["proxy"], pid, "{d}");
    assert_eq!(env.ok(&env.project, &["proxy", "status"])["running"], false);
    #[cfg(unix)]
    assert_ne!(unsafe { libc::kill(pid as i32, 0) }, 0, "proxy {pid} still running");
    assert!(env.project.exists());
    // Nothing running: stopping again is fine.
    env.ok(&env.project, &["project", "stop"]);
}

/// Answers every request after `delay`, so work against it stays busy.
fn slow_server(delay: Duration) -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = stream;
                let mut buf = [0u8; 4096];
                while let Ok(n) = std::io::Read::read(&mut s, &mut buf) {
                    if n == 0 {
                        break;
                    }
                    std::thread::sleep(delay);
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                }
            });
        }
    });
    port
}

#[test]
fn stop_stops_background_fuzzing() {
    let env = Env::new("fuzz");
    let port = slow_server(Duration::from_millis(200));
    let url = format!("http://127.0.0.1:{port}/§x§");
    let started =
        env.ok(&env.project, &["fuzz", "run", "--url", &url, "-p", "range:1-5000", "-c", "2", "--background"]);
    let run = started["run"]["id"].as_i64().unwrap();
    let d = env.ok(&env.project, &["project", "stop"]);
    let work = d["work"].as_array().unwrap();
    assert!(work.iter().any(|w| w["kind"] == "fuzz run" && w["id"] == run), "{d}");
    let state = env.ok(&env.project, &["fuzz", "status", &run.to_string()]);
    assert_eq!(state["run"]["state"], "stopped", "{state}");
    assert!(env.project.exists());
}

#[test]
fn cli_cannot_make_or_wipe_temporary_projects() {
    let env = Env::new("cli");
    for cmd in [&["project", "temp"][..], &["project", "discard"], &["project", "sweep"]] {
        let (code, v) = env.run(&env.project, cmd);
        assert_eq!(code, 2, "{cmd:?} -> {v}");
        assert_eq!(v["error"]["kind"], "usage", "{cmd:?} -> {v}");
    }
    assert!(env.project.exists());
}

#[test]
fn mcp_serve_cannot_make_or_wipe_temporary_projects() {
    let env = Env::new("mcp");
    let out = env.cmd(&env.project).args(["mcp", "serve", "--temp"]).stdin(Stdio::null()).output().unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", String::from_utf8_lossy(&out.stdout));

    let mut child =
        env.cmd(&env.project).args(["mcp", "serve"]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    writeln!(stdin, "{}", json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})).unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    drop(stdin);
    let _ = child.wait();
    let reply: Value = serde_json::from_str(&line).unwrap();
    let names: Vec<&str> =
        reply["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"project_stop"), "{names:?}");
    for name in &names {
        assert!(!["temp", "discard", "sweep", "delete", "wipe"].iter().any(|w| name.contains(w)), "{name}");
    }
    // Copying the project elsewhere is for the person running the server.
    assert!(!names.contains(&"project_save"), "{names:?}");
    assert!(env.project.exists());
}
