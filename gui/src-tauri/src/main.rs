//! Desktop shell for brainproxy. The window runs the React UI in `../src`; every engine call
//! goes through the `brainproxy` CLI with `--format json`, the same way `mcp serve` runs
//! tools, so scope enforcement, output, and errors are exactly the CLI's.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::process::Stdio;

use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// The CLI to run: $BRAINPROXY_BIN, else the bundled sidecar next to this executable,
/// else `brainproxy` on PATH.
fn binary() -> PathBuf {
    if let Some(bin) = std::env::var_os("BRAINPROXY_BIN") {
        return bin.into();
    }
    let name = if cfg!(windows) { "brainproxy.exe" } else { "brainproxy" };
    std::env::current_exe()
        .ok()
        .and_then(|exe| Some(exe.parent()?.join(name)))
        .filter(|p| p.is_file())
        .unwrap_or_else(|| name.into())
}

fn failure(message: String) -> Value {
    json!({"ok": false, "command": "gui", "error": {"kind": "gui", "message": message}})
}

/// Runs `brainproxy --format json --project PROJECT ARGS...` and returns its JSON envelope.
#[tauri::command]
async fn cli(project: String, args: Vec<String>, stdin: Option<String>) -> Value {
    let mut cmd = Command::new(binary());
    cmd.args(["--format", "json", "--project"]).arg(&project).args(&args);
    cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return failure(format!("can't run {}: {e}", binary().display())),
    };
    if let (Some(data), Some(mut pipe)) = (stdin, child.stdin.take()) {
        tokio::spawn(async move {
            let _ = pipe.write_all(data.as_bytes()).await;
        });
    }
    match child.wait_with_output().await {
        Ok(out) => serde_json::from_slice(&out.stdout).unwrap_or_else(|_| {
            let text = String::from_utf8_lossy(if out.stdout.is_empty() { &out.stderr } else { &out.stdout });
            failure(text.trim().to_string())
        }),
        Err(e) => failure(e.to_string()),
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![cli])
        .run(tauri::generate_context!())
        .expect("error while running brainproxy");
}
