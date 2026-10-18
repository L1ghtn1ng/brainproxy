#!/usr/bin/env python3
"""Writes gui/src/licenses.json: the NOTICE text and every third-party package that ships
in brainproxy or the desktop app (Rust crates linked into the CLI and the Tauri app, and the
npm packages bundled into the frontend). Dev-only dependencies are left out.

Run after changing dependencies: python3 scripts/gen-licenses.py"""
import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent.parent


def crates(manifest):
    meta = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--format-version", "1", "--locked", "--manifest-path", str(manifest)]))
    pkgs = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    own = set(meta["workspace_members"])
    seen, todo = set(), list(own)
    while todo:  # walk normal (shipped) dependencies only
        for d in nodes[todo.pop()]["deps"]:
            if any(k["kind"] is None for k in d["dep_kinds"]) and d["pkg"] not in seen:
                seen.add(d["pkg"])
                todo.append(d["pkg"])
    for i in seen - own:
        p = pkgs[i]
        if p["source"] is None:  # path dependency inside this repo (brainproxy-core)
            continue
        yield {"name": p["name"], "version": p["version"], "license": p.get("license") or "see repository",
               "url": p.get("repository") or p.get("homepage") or f"https://crates.io/crates/{p['name']}",
               "kind": "crate"}


def npm():
    lock = json.loads((ROOT / "gui/package-lock.json").read_text())["packages"]
    for path, p in lock.items():
        if path and not p.get("dev"):
            name = path.split("node_modules/")[-1]
            yield {"name": name, "version": p["version"], "license": p.get("license", "see repository"),
                   "url": f"https://www.npmjs.com/package/{name}", "kind": "npm"}


packages = {}
for p in [*crates(ROOT / "Cargo.toml"), *crates(ROOT / "gui/src-tauri/Cargo.toml"), *npm()]:
    packages[(p["kind"], p["name"], p["version"])] = p
out = {
    "notice": (ROOT / "NOTICE").read_text(),
    "packages": sorted(packages.values(), key=lambda p: (p["name"].lower(), p["version"])),
}
(ROOT / "gui/src/licenses.json").write_text(json.dumps(out, indent=1) + "\n")
print(f"{len(out['packages'])} packages")
