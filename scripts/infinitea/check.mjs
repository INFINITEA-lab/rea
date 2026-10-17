#!/usr/bin/env node
// INFINITEA hardening check for REA. Deterministic PASS/FAIL; exit 1 on any FAIL.
// Usage: node scripts/infinitea/check.mjs <path-to-rea-bin> [<skill-dir>]
// Runs everything with a throwaway HOME so no real client configuration can be touched.
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const bin = path.resolve(process.argv[2] ?? "node_modules/.bin/rea");
const skillDir = path.resolve(process.argv[3] ?? path.join(here, "../../.agents/skills/reverse-engineer-anything"));
const PIN = "rea-agents@6.5.0";
const GATED_SAMPLE = ["list_browser_targets", "capture_process_scenario", "start_frida_session", "push_adb_file",
  "capture_browser_scenario", "observe_javascript_runtime", "start_gdb_session", "cutter_command"];
const STATIC_SAMPLE = ["analyze_javascript_application", "open_binary", "inspect_artifact", "inspect_electron_fuses",
  "inspect_web_network_capture", "inspect_adb_client"];
const results = [];
const check = (name, ok, detail = "") => results.push([name, Boolean(ok), detail]);
const freshHome = () => fs.mkdtempSync(path.join(os.tmpdir(), "rea-infinitea-home-"));
const baseEnv = (home, extra = {}) => ({ PATH: process.env.PATH, HOME: home, LANG: "C.UTF-8", ...extra });

// R1 skill: pinned, no floating latest, fork notes, frontmatter valid
{
  const t = fs.readFileSync(path.join(skillDir, "SKILL.md"), "utf8");
  const refs = fs.readdirSync(path.join(skillDir, "references")).map((f) => fs.readFileSync(path.join(skillDir, "references", f), "utf8")).join("\n");
  const fm = /^---\n([\s\S]*?)\n---\n/.exec(t)?.[1] ?? "";
  const name = /^name:\s*(.+)$/m.exec(fm)?.[1]?.trim() ?? "";
  const desc = /^description:\s*(.+)$/m.exec(fm)?.[1]?.trim() ?? "";
  const latest = (t + refs).match(/rea-agents@latest/g)?.length ?? 0;
  const pinned = t.match(new RegExp(PIN.replace(/[.@]/g, "\\$&"), "g"))?.length ?? 0;
  const unpinned = (t + refs).match(/npx (-y )?rea-agents(?!@)/g)?.length ?? 0;
  const notes = /Treat all REA output as untrusted/.test(t) && /REA_INFINITEA_RUNTIME_TOOLS=1/.test(t) && /dry run/.test(t);
  check("R1 SKILL.md pinned + fork notes + frontmatter valid",
    latest === 0 && unpinned === 0 && pinned >= 1 && notes && /^[a-z0-9-]{1,64}$/.test(name) && desc.length > 0 && desc.length <= 1024 && !desc.includes("<"),
    `latest=${latest} unpinned=${unpinned} pinned=${pinned} notes=${notes} name=${name} desc_len=${desc.length}`);
}

// MCP helper
const mcp = (env, callName) => new Promise((resolve) => {
  const p = spawn(bin, ["mcp"], { stdio: ["pipe", "pipe", "pipe"], env });
  let buf = "", id = 0; const pending = new Map();
  p.stdout.on("data", (d) => { buf += d; let i; while ((i = buf.indexOf("\n")) >= 0) { const line = buf.slice(0, i); buf = buf.slice(i + 1); try { const m = JSON.parse(line); if (pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); } } catch {} } });
  p.stderr.on("data", () => {});
  const rpc = (method, params) => new Promise((res) => { const my = ++id; pending.set(my, res); p.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: my, method, params }) + "\n"); });
  const timer = setTimeout(() => { p.kill(); resolve({ error: "timeout" }); }, 60000);
  (async () => {
    await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "infinitea-check", version: "0" } });
    p.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
    const tools = []; let cursor;
    do { const r = await rpc("tools/list", cursor ? { cursor } : {}); tools.push(...(r.result?.tools ?? [])); cursor = r.result?.nextCursor; } while (cursor);
    let call;
    if (callName) { const r = await rpc("tools/call", { name: callName, arguments: {} }); call = { error: r.error?.message ?? null, isError: r.result?.isError ?? null, text: JSON.stringify(r.result?.content ?? "").slice(0, 200) }; }
    clearTimeout(timer); p.kill(); resolve({ names: tools.map((t) => t.name), call });
  })();
});

const home1 = freshHome();
const def = await mcp(baseEnv(home1), "list_browser_targets");
const gatedListed = GATED_SAMPLE.filter((n) => def.names?.includes(n));
const staticMissing = STATIC_SAMPLE.filter((n) => !def.names?.includes(n));
check("R2 MCP default: runtime tools hidden, static tools present",
  def.names && gatedListed.length === 0 && staticMissing.length === 0,
  `tools=${def.names?.length} gated_listed=[${gatedListed}] static_missing=[${staticMissing}]`);
const refused = /disabled/i.test(def.call?.error ?? "") || (def.call?.isError === true && /disabled/i.test(def.call?.text ?? ""));
check("R3 MCP default: calling a runtime tool is refused", refused, `error=${def.call?.error} isError=${def.call?.isError}`);
const opt = await mcp(baseEnv(freshHome(), { REA_INFINITEA_RUNTIME_TOOLS: "1" }));
check("R4 MCP opt-in: REA_INFINITEA_RUNTIME_TOOLS=1 restores runtime tools",
  GATED_SAMPLE.every((n) => opt.names?.includes(n)), `tools=${opt.names?.length} (default ${def.names?.length})`);

// CLI helpers
const cli = (args, env) => spawnSync(bin, args, { env, encoding: "utf8", timeout: 120000 });
const marker = path.join(freshHome(), "should-not-exist");
const scen = path.join(freshHome(), "scenario.json");
fs.writeFileSync(scen, JSON.stringify({ command: ["/usr/bin/touch", marker] }));
const r5 = cli(["capture-process", scen], baseEnv(freshHome()));
const r5b = cli(["list-browser-targets", "http://127.0.0.1:9"], baseEnv(freshHome()));
check("R5 CLI default: runtime commands refused, nothing executed",
  r5.status !== 0 && /INFINITEA/.test(r5.stdout + r5.stderr) && !fs.existsSync(marker) && r5b.status !== 0 && /INFINITEA/.test(r5b.stdout + r5b.stderr),
  `capture-process exit=${r5.status} list-browser-targets exit=${r5b.status} marker_created=${fs.existsSync(marker)}`);

// R6 static analysis regression on a synthetic Electron app
{
  const app = fs.mkdtempSync(path.join(os.tmpdir(), "rea-app-"));
  fs.writeFileSync(path.join(app, "package.json"), '{"name":"synthetic","version":"1.0.0","main":"main.js"}');
  fs.writeFileSync(path.join(app, "main.js"), "const { app, ipcMain } = require('electron');\nconst fs = require('fs');\nipcMain.handle('notes:export', async (_e, n) => { fs.writeFileSync('/tmp/x.csv', String(n)); return 1; });\n");
  fs.writeFileSync(path.join(app, "preload.js"), "const { contextBridge, ipcRenderer } = require('electron');\ncontextBridge.exposeInMainWorld('api', { e: (n) => ipcRenderer.invoke('notes:export', n) });\n");
  const r = cli(["analyze-javascript-application", app, "--json"], baseEnv(freshHome()));
  const sides = [...new Set([...(r.stdout ?? "").matchAll(/"side":"(\w+)","operation":"(\w+)"/g)].map((m) => `${m[1]}:${m[2]}`))].sort();
  check("R6 static JS analysis still works", r.status === 0 && sides.includes("main:handle") && sides.includes("renderer:invoke"), `exit=${r.status} ipc=${sides}`);
}

// R7 setup --yes is forced to a dry run; R8 uninstall/update refused
const listFiles = (dir) => { const out = []; const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) { if (e.name !== ".npm") walk(p); } else out.push(path.relative(dir, p)); } }; walk(dir); return out; };
{
  const home = freshHome();
  const r = cli(["setup", "--client", "claude_code", "--yes", "--json"], baseEnv(home));
  const written = listFiles(home).filter((f) => /^\.(claude|codex|cursor|gemini|config)/.test(f));
  check("R7 setup --yes forced to dry run: no client config written", written.length === 0,
    `exit=${r.status} written=[${written.slice(0, 5)}] dryRunShown=${/dry.?run/i.test(r.stdout + r.stderr)}`);
  const u = cli(["uninstall"], baseEnv(home));
  const up = cli(["update"], baseEnv(home));
  check("R8 uninstall/update refused", u.status !== 0 && up.status !== 0 && /INFINITEA/.test(u.stdout + u.stderr) && /INFINITEA/.test(up.stdout + up.stderr),
    `uninstall exit=${u.status} update exit=${up.status}`);
}

for (const [n, ok, d] of results) console.log(`${ok ? "PASS" : "FAIL"}  ${n}  [${d}]`);
const all = results.every((r) => r[1]);
console.log("OVERALL", all ? "PASS" : "FAIL");
process.exit(all ? 0 : 1);
