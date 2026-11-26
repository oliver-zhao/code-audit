#!/usr/bin/env node
// Release check: pack the three workspace packages, inspect the tarballs,
// install them into an empty temporary project and run the installed
// commands. Nothing is published and nothing outside the temporary directory
// is written (third-party dependencies are fetched by npm as usual).
//
//   pnpm build && pnpm run pack:verify [-- --keep]
import { execFileSync, spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const keep = process.argv.includes("--keep");
const work = fs.mkdtempSync(path.join(os.tmpdir(), "code-audit-pack-"));
const packs = path.join(work, "packs");
const app = path.join(work, "app");
const project = path.join(work, "project");
for (const dir of [packs, app, project]) fs.mkdirSync(dir);

const failures = [];
const check = (ok, text) => {
  process.stdout.write(`${ok ? "ok  " : "FAIL"} ${text}\n`);
  if (!ok) failures.push(text);
};
const run = (command, args, options = {}) =>
  execFileSync(command, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], ...options });

// A path that must never be in a published tarball.
const FORBIDDEN =
  /(^|\/)(fixtures|test|tests|src|node_modules|\.tools|\.audit|\.tmp-test-[^/]*)\/|\.map$|\.tsbuildinfo$|\.test\.[cm]?[jt]s$/;

const version = JSON.parse(fs.readFileSync(path.join(repoRoot, "package.json"), "utf8")).version;
const tarballs = [];
for (const name of ["core", "mcp", "cli"]) {
  run("pnpm", ["pack", "--pack-destination", packs], { cwd: path.join(repoRoot, "packages", name) });
  const tarball = path.join(packs, `code-audit-${name}-${version}.tgz`);
  tarballs.push(tarball);
  const files = run("tar", ["tzf", tarball]).split("\n").filter(Boolean);
  const size = fs.statSync(tarball).size;
  process.stdout.write(`\n@code-audit/${name}: ${files.length} files, ${(size / 1024).toFixed(1)} kB packed\n`);
  const byTop = new Map();
  for (const file of files) {
    const top = file.split("/").slice(1, 2).join("/");
    byTop.set(top, (byTop.get(top) ?? 0) + 1);
  }
  process.stdout.write(`  ${[...byTop].map(([top, count]) => `${top} (${count})`).join(", ")}\n`);
  const bad = files.filter((file) => FORBIDDEN.test(file.replace(/^package\//, "")));
  check(bad.length === 0, `${name}: no fixtures, tests, sources, maps or tool directories${bad.length ? `: ${bad.slice(0, 5).join(", ")}` : ""}`);
  for (const required of ["package/LICENSE", "package/NOTICE", "package/README.md", "package/package.json"]) {
    check(files.includes(required), `${name}: ships ${required.slice(8)}`);
  }
  const manifest = JSON.parse(run("tar", ["xzf", tarball, "-O", "package/package.json"]));
  check(manifest.version === version, `${name}: version ${manifest.version}`);
  check(!JSON.stringify(manifest.dependencies ?? {}).includes("workspace:"), `${name}: no workspace: dependency ranges`);
  check(manifest.private !== true, `${name}: not private`);
  if (name === "core") {
    check(files.some((file) => file.startsWith("package/assets/rules/sast/")), "core: ships rules");
    check(files.includes("package/assets/skills/code-audit/SKILL.md"), "core: ships the skill");
  }
  check(!fs.existsSync(path.join(repoRoot, "packages", name, "assets")), `${name}: packing left no assets/ copy behind`);
}

process.stdout.write("\nInstalling the tarballs into an empty project (npm)...\n");
// The tarballs are named both as dependencies and as overrides, so npm takes
// @code-audit/* from the local files and never asks the registry for them
// (checked below: the packages are not published).
const spec = Object.fromEntries(
  ["core", "mcp", "cli"].map((name, index) => [`@code-audit/${name}`, `file:${tarballs[index]}`]),
);
fs.writeFileSync(
  path.join(app, "package.json"),
  `${JSON.stringify({ name: "pack-check", private: true, dependencies: spec, overrides: { "@code-audit/core": spec["@code-audit/core"], "@code-audit/mcp": spec["@code-audit/mcp"] } }, null, 2)}\n`,
);
const npm = spawnSync("npm", ["install", "--no-audit", "--no-fund", "--ignore-scripts", "--loglevel", "http"], {
  cwd: app,
  encoding: "utf8",
});
if (npm.status !== 0) {
  process.stdout.write(`${npm.stdout}${npm.stderr}`);
  process.exit(1);
}
const ownRequests = `${npm.stdout}${npm.stderr}`
  .split("\n")
  .filter((line) => /http fetch/.test(line) && /code-audit/i.test(line));
check(ownRequests.length === 0, "npm made no registry request for @code-audit/* packages");
const appReal = fs.realpathSync(app);
const bin = (name) => path.join(app, "node_modules", ".bin", name);
const cli = (args, options = {}) => {
  try {
    return { code: 0, out: run(bin("code-audit"), args, { cwd: project, ...options }) };
  } catch (error) {
    return { code: error.status, out: `${error.stdout ?? ""}${error.stderr ?? ""}` };
  }
};

const help = cli(["--help"]);
check(help.code === 0 && help.out.startsWith(`code-audit ${version}`), "code-audit --help");
check(cli(["--version"]).out.trim() === version, "code-audit --version");

const doctor = cli(["doctor", "--json"]);
const report = JSON.parse(doctor.out);
check(doctor.code === 0 && report.rules.count > 0 && report.rules.error === null, `code-audit doctor: ${report.rules.count} built-in rules from ${path.relative(appReal, report.rules.dir)}`);
check(report.rules.opengrepCount > 0, `code-audit doctor: ${report.rules.opengrepCount} Opengrep rules`);
check(report.rules.dir.startsWith(appReal), "rules are read from the installed package");
check(report.mcp.bundledExists, `bundled MCP command: ${path.relative(appReal, report.mcp.bundled)}`);

fs.writeFileSync(
  path.join(project, "app.py"),
  'import subprocess\nfrom flask import request\n\ndef ping():\n    return subprocess.check_output("ping " + request.args["host"], shell=True)\n',
);
const scan = cli(["scan", ".", "--offline", "--no-external"]);
process.stdout.write(scan.out.split("\n").slice(0, 8).map((line) => `  | ${line}`).join("\n") + "\n");
check(scan.code === 1 && /Findings: 1 /.test(scan.out), "code-audit scan finds the seeded command injection (exit 1)");

const install = cli(["install", "--host", "claude-code", "--absolute"]);
check(install.code === 0 && fs.existsSync(path.join(project, ".claude/skills/code-audit/SKILL.md")), "code-audit install writes the skill from the installed package");
const rescan = cli(["scan", ".", "--offline", "--no-external", "--format", "json"]);
check(rescan.code === 1 && /Findings: 1 /.test(rescan.out), "installed adapter files are recognised (no extra finding)");

// MCP: initialize, then list the tools, over stdio.
const mcpReply = await new Promise((resolve, reject) => {
  const child = spawn(bin("code-audit-mcp"), [], { cwd: project, stdio: ["pipe", "pipe", "pipe"] });
  const timer = setTimeout(() => {
    child.kill();
    reject(new Error("code-audit-mcp did not answer within 15 s"));
  }, 15_000);
  let buffer = "";
  const replies = [];
  child.stdout.on("data", (chunk) => {
    buffer += chunk;
    let index;
    while ((index = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, index).trim();
      buffer = buffer.slice(index + 1);
      if (!line) continue;
      const message = JSON.parse(line);
      replies.push(message);
      if (message.id === 1) {
        child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
        child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} })}\n`);
      }
      if (message.id === 2) {
        clearTimeout(timer);
        child.kill();
        resolve(replies);
      }
    }
  });
  child.on("error", reject);
  child.stdin.write(
    `${JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "pack-check", version: "0" } },
    })}\n`,
  );
});
const init = mcpReply.find((message) => message.id === 1)?.result;
const tools = mcpReply.find((message) => message.id === 2)?.result?.tools ?? [];
process.stdout.write(`  | initialize -> ${JSON.stringify({ protocolVersion: init?.protocolVersion, serverInfo: init?.serverInfo })}\n`);
process.stdout.write(`  | tools/list -> ${tools.map((tool) => tool.name).join(", ")}\n`);
check(init?.serverInfo?.name === "code-audit" && init?.serverInfo?.version === version, "code-audit-mcp answers initialize with its name and version");
check(tools.length === 8, "code-audit-mcp lists 8 tools");

if (keep) process.stdout.write(`\nKept: ${work}\n`);
else fs.rmSync(work, { recursive: true, force: true });
process.stdout.write(failures.length === 0 ? "\nAll pack checks passed.\n" : `\n${failures.length} check(s) failed.\n`);
process.exit(failures.length === 0 ? 0 : 1);
