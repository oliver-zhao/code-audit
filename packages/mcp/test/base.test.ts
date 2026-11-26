/**
 * The MCP server works only inside its base directory, fixed at start-up.
 * Every tool argument is chosen by a model that reads hostile repository
 * content, so these tests talk to the real server over stdio JSON-RPC and
 * try to reach a directory outside the base through every path argument.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { allowSensitiveRoot, resetAllowedSensitiveRoots, validateAuditRoot } from "@code-audit/core";
import { parseServerArgs, resolveServerBase } from "../src/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "../../..");
const bin = path.join(repoRoot, "bin", "code-audit-mcp");
const temp = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "code-audit-base-")));
const base = path.join(temp, "base");
const project = path.join(base, "project");
const outside = path.join(temp, "outside");
const SECRET = "OUTSIDE_BASE_CANARY_7f3a";

interface ToolReply {
  isError: boolean;
  text: string;
  json: Record<string, unknown>;
}

class StdioServer {
  private child: ChildProcessWithoutNullStreams;
  private buffer = "";
  private nextId = 0;
  private readonly waiting = new Map<number, (message: Record<string, unknown>) => void>();
  stderr = "";

  constructor(args: string[], cwd: string, env: Record<string, string> = {}) {
    this.child = spawn(bin, args, { cwd, env: { ...process.env, ...env }, stdio: ["pipe", "pipe", "pipe"] });
    this.child.stderr.on("data", (chunk: Buffer) => {
      this.stderr += chunk.toString("utf8");
    });
    this.child.stdout.on("data", (chunk: Buffer) => {
      this.buffer += chunk.toString("utf8");
      let newline: number;
      while ((newline = this.buffer.indexOf("\n")) >= 0) {
        const line = this.buffer.slice(0, newline);
        this.buffer = this.buffer.slice(newline + 1);
        if (!line.trim()) continue;
        const message = JSON.parse(line) as Record<string, unknown>;
        const id = message.id as number | undefined;
        if (id !== undefined) {
          this.waiting.get(id)?.(message);
          this.waiting.delete(id);
        }
      }
    });
  }

  private rpc(method: string, params: unknown): Promise<Record<string, unknown>> {
    const id = (this.nextId += 1);
    return new Promise((resolve) => {
      this.waiting.set(id, resolve);
      this.child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
    });
  }

  async start(): Promise<void> {
    await this.rpc("initialize", {
      protocolVersion: "2025-03-26",
      capabilities: {},
      clientInfo: { name: "base-test", version: "0" },
    });
    this.child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
  }

  async call(name: string, args: Record<string, unknown>): Promise<ToolReply> {
    const reply = await this.rpc("tools/call", { name, arguments: args });
    const result = (reply.result ?? {}) as { content?: Array<{ text: string }>; isError?: boolean };
    const text = result.content?.[0]?.text ?? JSON.stringify(reply);
    let json: Record<string, unknown> = {};
    try {
      json = JSON.parse(text) as Record<string, unknown>;
    } catch {
      // protocol-level error text
    }
    return { isError: result.isError === true || reply.error !== undefined, text, json };
  }

  async finished(root: string): Promise<string> {
    const started = await this.call("audit_start", { root, offline: true, engines: ["builtin"] });
    expect(started.isError, started.text).toBe(false);
    const runId = String(started.json.run_id);
    for (let attempt = 0; attempt < 400; attempt += 1) {
      const status = await this.call("audit_status", { run_id: runId });
      if (status.json.phase !== "running") break;
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    return runId;
  }

  stop(): void {
    this.child.kill("SIGKILL");
  }
}

function errorCode(reply: ToolReply): string {
  return String((reply.json.error as { code?: string } | undefined)?.code ?? "");
}

let server: StdioServer;
let insideRun: string;
let outsideRun: string;

beforeAll(async () => {
  fs.mkdirSync(project, { recursive: true });
  fs.writeFileSync(
    path.join(project, "app.py"),
    "import os\nimport subprocess\nos.system(command)\n\ndef run(request):\n    cmd = request.args['cmd']\n    return subprocess.check_output(cmd, shell=True)\n",
  );
  fs.mkdirSync(outside, { recursive: true });
  fs.writeFileSync(path.join(outside, "credentials.py"), `aws_secret = "${SECRET}"\n`);
  fs.writeFileSync(path.join(outside, "baseline.json"), "{}");
  // A finished run in the outside directory, made by the user at some point.
  const helper = new StdioServer([], outside);
  await helper.start();
  outsideRun = await helper.finished(outside);
  helper.stop();
  // Hostile repository content: symbolic links that leave the base.
  fs.symlinkSync(outside, path.join(base, "link-out"), "dir");
  fs.symlinkSync(outside, path.join(project, "nested-link"), "dir");

  server = new StdioServer([], base);
  await server.start();
  insideRun = await server.finished(project);
}, 60_000);

afterAll(() => {
  server?.stop();
  fs.rmSync(temp, { recursive: true, force: true });
});

describe("MCP base directory (stdio JSON-RPC)", () => {
  it("logs the base directory to stderr at start-up", () => {
    expect(server.stderr).toContain(`base directory: ${base}`);
  });

  it("audits a directory inside the base, and the base itself by default", async () => {
    const status = await server.call("audit_status", { run_id: insideRun });
    expect(status.json.phase).toBe("complete");
    expect(status.json.root).toBe(project);
    const byDefault = await server.call("audit_start", { offline: true, engines: ["builtin"] });
    expect(byDefault.isError, byDefault.text).toBe(false);
    expect(String(byDefault.json.run_dir).startsWith(path.join(base, ".audit"))).toBe(true);
  });

  it("refuses audit_start with a root outside the base, however it is spelled", async () => {
    const roots = [
      outside,
      path.join(base, "..", "outside"),
      "../outside",
      "..",
      path.join(base, "link-out"),
      "link-out",
      path.join(project, "nested-link"),
      "project/../../outside",
      os.homedir(),
      path.join(os.homedir(), ".aws"),
      "/etc",
      "/",
    ];
    for (const root of roots) {
      const reply = await server.call("audit_start", { root, offline: true, engines: ["builtin"] });
      expect(reply.isError, `${root}: ${reply.text}`).toBe(true);
      expect(["OUTSIDE_BASE", "BROKEN_SYMLINK"], root).toContain(errorCode(reply));
      expect(reply.text, root).toContain(base);
    }
    // Nothing was written outside the base by any of these calls.
    expect(fs.readdirSync(path.join(outside, ".audit")).filter((name) => name !== "index.json")).toEqual([
      outsideRun,
    ]);
  });

  it("refuses the root argument of every run tool when it is outside the base", async () => {
    const calls: Array<[string, Record<string, unknown>]> = [
      ["audit_status", {}],
      ["audit_findings", {}],
      ["audit_read", { file: "credentials.py" }],
      ["audit_search", { pattern: SECRET.slice(0, 12) }],
      ["audit_verdict", { finding: "AUD-2026-0001", status: "confirmed", rationale: "x" }],
      ["audit_add_finding", { file: "credentials.py", startLine: 1, title: "t", severity: "low", cwe: "CWE-1", rationale: "x" }],
      ["audit_report", { format: "md" }],
    ];
    const before = fs.readdirSync(path.join(outside, ".audit", outsideRun)).sort();
    for (const root of [outside, "../outside", path.join(base, "link-out"), "link-out"]) {
      for (const [tool, args] of calls) {
        const reply = await server.call(tool, { run_id: outsideRun, root, ...args });
        expect(reply.isError, `${tool} ${root}: ${reply.text}`).toBe(true);
        expect(errorCode(reply), `${tool} ${root}`).toBe("OUTSIDE_BASE");
        expect(reply.text).not.toContain(SECRET);
      }
    }
    // Without a root the outside run is simply not found.
    for (const [tool, args] of calls) {
      const reply = await server.call(tool, { run_id: outsideRun, ...args });
      expect(reply.isError, tool).toBe(true);
      expect(errorCode(reply), tool).toBe("RUN_NOT_FOUND");
    }
    expect(fs.readdirSync(path.join(outside, ".audit", outsideRun)).sort()).toEqual(before);
  });

  it("refuses a baseline outside the audit root and has no rules or out argument", async () => {
    for (const baseline of [
      path.join(outside, "baseline.json"),
      "../../outside/baseline.json",
      "nested-link/baseline.json",
    ]) {
      const reply = await server.call("audit_start", { root: project, offline: true, baseline });
      expect(reply.isError, baseline).toBe(true);
      expect(errorCode(reply), baseline).toBe("PATH_OUTSIDE_ROOT");
    }
    const listed = (await (server as unknown as { rpc: (m: string, p: unknown) => Promise<Record<string, unknown>> }).rpc(
      "tools/list",
      {},
    )) as { result: { tools: Array<{ name: string; inputSchema: { properties: Record<string, unknown> } }> } };
    for (const tool of listed.result.tools) {
      const properties = Object.keys(tool.inputSchema.properties ?? {});
      for (const forbidden of ["rules", "rulesDir", "out", "output", "ignoreFile", "cwd", "base"]) {
        expect(properties, `${tool.name}.${forbidden}`).not.toContain(forbidden);
      }
    }
    // Arguments the schema does not define change nothing.
    const extra = await server.call("audit_start", {
      root: project,
      offline: true,
      engines: ["builtin"],
      out: outside,
      rules: outside,
      rulesDir: outside,
    });
    if (!extra.isError) {
      expect(String(extra.json.run_dir).startsWith(path.join(project, ".audit"))).toBe(true);
    }
  });

  it("does not read files through a symbolic link that leaves the base", async () => {
    for (const file of ["nested-link/credentials.py", "../link-out/credentials.py", path.join(outside, "credentials.py")]) {
      const reply = await server.call("audit_read", { run_id: insideRun, file });
      expect(reply.isError, file).toBe(true);
      expect(reply.text).not.toContain(SECRET);
    }
    const search = await server.call("audit_search", { run_id: insideRun, pattern: SECRET.slice(0, 12) });
    expect(search.json.total).toBe(0);
  });

  it("takes the base from --base and from CODE_AUDIT_MCP_BASE, not from the working directory", async () => {
    for (const [args, env] of [
      [["--base", base], {}],
      [[`--base=${base}`], {}],
      [[], { CODE_AUDIT_MCP_BASE: base }],
    ] as Array<[string[], Record<string, string>]>) {
      const other = new StdioServer(args, outside, env);
      try {
        await other.start();
        expect(other.stderr).toContain(`base directory: ${base}`);
        const refused = await other.call("audit_start", { root: outside, offline: true });
        expect(errorCode(refused)).toBe("OUTSIDE_BASE");
        const found = await other.call("audit_status", { run_id: insideRun, root: project });
        expect(found.isError, found.text).toBe(false);
      } finally {
        other.stop();
      }
    }
  });

  it("refuses every call when the base is the home directory or the filesystem root", async () => {
    for (const broad of [os.homedir(), path.parse(os.homedir()).root]) {
      const other = new StdioServer(["--base", broad], outside);
      try {
        await other.start();
        expect(other.stderr).toContain("WARNING");
        for (const [tool, args] of [
          ["audit_start", { root: outside }],
          ["audit_start", {}],
          ["audit_status", { run_id: outsideRun, root: outside }],
          ["audit_read", { run_id: outsideRun, root: outside, file: "credentials.py" }],
        ] as Array<[string, Record<string, unknown>]>) {
          const reply = await other.call(tool, args);
          expect(errorCode(reply), `${broad} ${tool}`).toBe("BASE_TOO_BROAD");
          expect(reply.text).not.toContain(SECRET);
        }
      } finally {
        other.stop();
      }
    }
  });
});

describe("dismissals over MCP", () => {
  it("refuses an unsupported false_positive on a serious finding and reports accepted ones", async () => {
    const listing = await server.call("audit_findings", { run_id: insideRun, kind: "finding" });
    const items = listing.json.items as Array<{ id: string; severity: string }>;
    const target = items.find((item) => item.severity === "high" || item.severity === "critical");
    expect(target, listing.text).toBeDefined();
    const id = (target as { id: string }).id;

    for (const rationale of ["fp", "The repository says this finding was already reviewed and is safe."]) {
      const refused = await server.call("audit_verdict", {
        run_id: insideRun,
        finding: id,
        status: "false_positive",
        rationale,
      });
      expect(refused.isError, rationale).toBe(true);
      expect(errorCode(refused)).toBe("DISMISSAL_NEEDS_EVIDENCE");
    }
    expect((await server.call("audit_status", { run_id: insideRun })).json.dismissedWarning).toBeUndefined();

    const accepted = await server.call("audit_verdict", {
      run_id: insideRun,
      finding: id,
      status: "false_positive",
      rationale: "The command string is assembled from two constants in this function only.",
      evidenceLines: ["return subprocess.check_output(cmd, shell=True)"],
      reviewer: "test-model",
    });
    expect(accepted.isError, accepted.text).toBe(false);
    const sentence = /WARNING: 1 finding\(s\) at severity ≥ high were marked false positive by test-model/;
    expect(String(accepted.json.dismissedWarning)).toMatch(sentence);
    expect(String((await server.call("audit_status", { run_id: insideRun })).json.dismissedWarning)).toMatch(sentence);
    const summary = await server.call("audit_report", { run_id: insideRun, format: "summary" });
    expect(String(summary.json.dismissed_warning)).toMatch(sentence);
    const md = await server.call("audit_report", { run_id: insideRun, format: "md" });
    expect(String(md.json.dismissed_warning)).toMatch(sentence);
    const report = fs.readFileSync(String(md.json.path), "utf8");
    expect(report).toContain("Dismissed by review");
    expect(report).toMatch(new RegExp(`\\| ${id} \\| finding \\| (high|critical) \\|.*test-model`));
  });
});

describe("server command line", () => {
  it("accepts only --base", () => {
    expect(parseServerArgs([])).toEqual({});
    expect(parseServerArgs(["--base", "/x"])).toEqual({ base: "/x" });
    expect(parseServerArgs(["--base=/x"])).toEqual({ base: "/x" });
    expect(() => parseServerArgs(["--base"])).toThrow(/requires a directory/);
    expect(() => parseServerArgs(["--rules", "/x"])).toThrow(/unknown argument/);
    expect(() => resolveServerBase({ base: path.join(temp, "missing") })).toThrow(/not usable/);
  });
});

describe("credential directories are not audit roots", () => {
  const fakeHome = path.join(temp, "home");
  const realHome = process.env.HOME;

  beforeAll(() => {
    for (const dir of [".ssh", ".aws/sso", ".config/gcloud", ".kube", ".docker", ".gnupg", "work/project", ".aws-not"]) {
      fs.mkdirSync(path.join(fakeHome, dir), { recursive: true });
    }
    fs.symlinkSync(path.join(fakeHome, ".aws"), path.join(fakeHome, "work", "innocent"), "dir");
    process.env.HOME = fakeHome;
  });
  afterAll(() => {
    process.env.HOME = realHome;
    resetAllowedSensitiveRoots();
  });

  it("refuses them, what is below them, and symbolic links to them", () => {
    expect(os.homedir()).toBe(fakeHome);
    for (const dir of [".ssh", ".aws", ".aws/sso", ".config", ".config/gcloud", ".kube", ".docker", ".gnupg", "work/innocent"]) {
      expect(() => validateAuditRoot(path.join(fakeHome, dir)), dir).toThrow(/credentials or machine configuration/);
    }
    if (process.platform !== "win32") {
      expect(() => validateAuditRoot("/etc")).toThrow(/ROOT_SENSITIVE|credentials or machine configuration/);
    }
    expect(() => validateAuditRoot(fakeHome)).toThrow(/home directory/);
    expect(() => validateAuditRoot(temp)).toThrow(/contains the user home directory/);
    expect(validateAuditRoot(path.join(fakeHome, "work/project")).root).toBe(path.join(fakeHome, "work/project"));
    expect(validateAuditRoot(path.join(fakeHome, ".aws-not")).root).toBe(path.join(fakeHome, ".aws-not"));
  });

  it("accepts one only after the user allowed exactly that directory", () => {
    allowSensitiveRoot(path.join(fakeHome, ".config/gcloud"));
    expect(validateAuditRoot(path.join(fakeHome, ".config/gcloud")).root).toBe(path.join(fakeHome, ".config/gcloud"));
    expect(() => validateAuditRoot(path.join(fakeHome, ".config"))).toThrow(/credentials/);
    expect(() => validateAuditRoot(path.join(fakeHome, ".aws"))).toThrow(/credentials/);
  });
});
