import { spawn } from "node:child_process";
import { resolve } from "node:path";
import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

// Dev-only bridge so the UI also runs in a plain browser (`npm run dev`): POST /api/cli runs
// the brainproxy CLI the same way the Tauri `cli` command does. It answers only requests
// to a localhost Host with the X-Brainproxy header, which blocks DNS rebinding and simple
// cross-site posts. Never part of a build.
function cliBridge(): Plugin {
  const bin = process.env.BRAINPROXY_BIN ?? resolve(__dirname, "../target/debug/brainproxy");
  return {
    name: "brainproxy-cli-bridge",
    apply: "serve",
    configureServer(server) {
      server.middlewares.use("/api/cli", (req, res) => {
        const host = (req.headers.host ?? "").replace(/:\d+$/, "");
        if (req.method !== "POST" || req.headers["x-brainproxy"] !== "1" || !["localhost", "127.0.0.1"].includes(host)) {
          res.statusCode = 403;
          res.end();
          return;
        }
        let body = "";
        req.on("data", (c) => (body += c));
        req.on("end", () => {
          const { project, args, stdin } = JSON.parse(body) as { project: string; args: string[]; stdin?: string };
          const child = spawn(bin, ["--format", "json", "--project", project, ...args], {
            stdio: [stdin == null ? "ignore" : "pipe", "pipe", "pipe"],
          });
          if (stdin != null) child.stdin!.end(stdin);
          let out = "";
          let err = "";
          child.stdout!.on("data", (c) => (out += c));
          child.stderr!.on("data", (c) => (err += c));
          child.on("error", (e) => res.end(JSON.stringify({ ok: false, error: { kind: "gui", message: String(e) } })));
          child.on("close", () => {
            res.setHeader("content-type", "application/json");
            res.end(out.trim() || JSON.stringify({ ok: false, error: { kind: "gui", message: err.trim() || "no output" } }));
          });
        });
      });
    },
  };
}

export default defineConfig({
  plugins: [react(), cliBridge()],
  clearScreen: false,
  server: { port: 5173, strictPort: true, host: "127.0.0.1" },
  build: { target: "es2022", outDir: "dist" },
});
