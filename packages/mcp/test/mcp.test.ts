import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createAuditServer } from "../src/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "../../..");
const temp = fs.mkdtempSync(path.join(repoRoot, ".tmp-test-mcp-"));
const project = path.join(temp, "project");
let client: Client;
let runId: string;

async function call(
  name: string,
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const result = (await client.callTool({ name, arguments: args })) as {
    content: Array<{ type: string; text: string }>;
    isError?: boolean;
  };
  const text = result.content[0]?.text ?? "{}";
  expect(result.isError).toBeUndefined();
  return JSON.parse(text) as Record<string, unknown>;
}

async function callError(
  name: string,
  args: Record<string, unknown>,
): Promise<{ code: string; message: string }> {
  const result = (await client.callTool({ name, arguments: args })) as {
    content: Array<{ type: string; text: string }>;
    isError?: boolean;
  };
  expect(result.isError).toBe(true);
  const parsed = JSON.parse(result.content[0]?.text ?? "{}") as {
    error?: { code: string; message: string };
  };
  expect(parsed.error).toBeDefined();
  return parsed.error as { code: string; message: string };
}

/**
 * Make the tests hermetic and the background scan genuinely asynchronous.
 *
 * The server discovers external scanners on PATH. Whatever happens to be
 * installed on the machine running the tests (for example a Homebrew gitleaks
 * on macOS) must not change the outcome, so PATH is replaced by a directory
 * holding a single fake `gitleaks`. The fake takes a moment to finish, which
 * guarantees a window in which the run exists but has no run.json yet - the
 * situation every real external tool creates.
 */
const FAKE_SCAN_DELAY_MS = 400;
const originalPath = process.env.PATH;

function installFakeGitleaks(): void {
  const dir = path.join(temp, "fake-bin");
  fs.mkdirSync(dir, { recursive: true });
  const target = path.join(dir, "gitleaks");
  fs.writeFileSync(
    target,
    [
      `#!${process.execPath}`,
      "const fs = require('fs');",
      "const args = process.argv.slice(2);",
      "if (args[0] === 'version') { process.stdout.write('8.0.0-fake\\n'); process.exit(0); }",
      "const i = args.indexOf('--report-path');",
      `setTimeout(() => { if (i >= 0) fs.writeFileSync(args[i + 1], '[]'); process.exit(0); }, ${FAKE_SCAN_DELAY_MS});`,
      "",
    ].join("\n"),
    "utf8",
  );
  fs.chmodSync(target, 0o755);
  process.env.PATH = dir;
}

async function waitForCompletion(id: string): Promise<Record<string, unknown>> {
  let status: Record<string, unknown> = {};
  for (let attempt = 0; attempt < 200; attempt += 1) {
    status = await call("audit_status", { run_id: id });
    if (status.phase !== "running") break;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return status;
}

beforeAll(async () => {
  installFakeGitleaks();
  fs.cpSync(path.join(repoRoot, "fixtures/vulnerable"), project, {
    recursive: true,
  });
  const server = createAuditServer();
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  client = new Client({ name: "code-audit-test", version: "1.0.0" });
  await client.connect(clientTransport);
});

afterAll(async () => {
  await client.close();
  process.env.PATH = originalPath;
  fs.rmSync(temp, { recursive: true, force: true });
});

describe("MCP server", () => {
  it("exposes exactly the eight audit tools", async () => {
    const tools = await client.listTools();
    expect(tools.tools.map((tool) => tool.name).sort()).toEqual([
      "audit_add_finding",
      "audit_findings",
      "audit_read",
      "audit_report",
      "audit_search",
      "audit_start",
      "audit_status",
      "audit_verdict",
    ]);
    for (const tool of tools.tools) {
      expect(tool.description ?? "").not.toBe("");
    }
    // audit_start can turn off inline code-audit:ignore comments.
    const start = tools.tools.find((tool) => tool.name === "audit_start");
    expect(
      Object.keys((start?.inputSchema as { properties?: object }).properties ?? {}),
    ).toContain("noInlineIgnore");
    // ... and the confidence lowering for test / docs paths and dev dependencies.
    const startProperties = Object.keys(
      (start?.inputSchema as { properties?: object }).properties ?? {},
    );
    expect(startProperties).toContain("includeTests");
    expect(startProperties).toContain("includeDev");
    for (const name of ["audit_read", "audit_search", "audit_findings"]) {
      const description =
        tools.tools.find((tool) => tool.name === name)?.description ?? "";
      expect(description.toLowerCase()).toContain("untrusted");
    }
  });

  it("rejects an audit_start baseline outside the audit root", async () => {
    const outside = path.join(temp, "outside-baseline.json");
    const error = await callError("audit_start", {
      root: project,
      offline: true,
      baseline: outside,
    });
    expect(error.code).toBe("PATH_OUTSIDE_ROOT");

    const traversal = await callError("audit_start", {
      root: project,
      offline: true,
      baseline: "../x",
    });
    expect(traversal.code).toBe("PATH_OUTSIDE_ROOT");
  });

  it("starts a scan in the background and reports completion", async () => {
    const started = await call("audit_start", {
      root: project,
      offline: true,
    });
    expect(typeof started.run_id).toBe("string");
    expect(started.phase).toBe("running");
    runId = String(started.run_id);

    // While the scan is in flight the run must already be visible: status
    // reports "running" (not RUN_NOT_FOUND) and tools that need the finished
    // run say so explicitly.
    const early = await call("audit_status", { run_id: runId });
    expect(early.phase).toBe("running");
    expect(early.runId).toBe(runId);
    const notReady = await callError("audit_findings", { run_id: runId });
    expect(notReady.code).toBe("RUN_NOT_READY");
    expect(notReady.message).toContain("audit_status");
    const notReadyRead = await callError("audit_read", {
      run_id: runId,
      file: "python/app.py",
    });
    expect(notReadyRead.code).toBe("RUN_NOT_READY");

    const status = await waitForCompletion(runId);
    expect(status.phase).toBe("complete");
    expect(status.findings).toBeGreaterThan(0);
    expect(status.hotspots).toBeGreaterThan(0);
  });

  it("paginates findings with a cursor and caps the response size", async () => {
    const first = (await call("audit_findings", {
      run_id: runId,
      kind: "finding",
      limit: 2,
    })) as {
      items: Array<{ id: string; kind: string }>;
      next_cursor: string | null;
      total: number;
    };
    expect(first.items).toHaveLength(2);
    expect(first.items[0]?.kind).toBe("finding");
    expect(first.next_cursor).toBe("2");
    const second = (await call("audit_findings", {
      run_id: runId,
      kind: "finding",
      limit: 2,
      cursor: first.next_cursor,
    })) as { items: Array<{ id: string }> };
    expect(second.items[0]?.id).not.toBe(first.items[0]?.id);

    const raw = (await client.callTool({
      name: "audit_findings",
      arguments: { run_id: runId, kind: "all", limit: 20 },
    })) as { content: Array<{ text: string }> };
    expect(Buffer.byteLength(raw.content[0]?.text ?? "", "utf8")).toBeLessThanOrEqual(
      8000,
    );
  });

  it("reads snippets with delimiters and redacts secrets", async () => {
    const snippet = (await call("audit_read", {
      run_id: runId,
      file: "secrets/secrets.txt",
      startLine: 1,
      endLine: 5,
    })) as { content: string; file: string };
    expect(snippet.content).toContain("<<<UNTRUSTED_REPOSITORY_CONTENT>>>");
    expect(snippet.content).toContain("<<<END_UNTRUSTED_REPOSITORY_CONTENT>>>");
    expect(snippet.content).not.toContain("AKIAFAKEFIXTURE00000");
    expect(snippet.content).not.toContain("Fake-Password-For-Fixture-Only-2026");
  });

  it("rejects path escapes and unknown run ids", async () => {
    const escape = await callError("audit_read", {
      run_id: runId,
      file: "../../etc/passwd",
    });
    expect(["PATH_OUTSIDE_ROOT", "FILE_NOT_IN_INVENTORY", "PATH_JAIL"]).toContain(
      escape.code,
    );
    const missing = await callError("audit_status", {
      run_id: "no-such-run",
    });
    expect(["RUN_NOT_FOUND", "RUN_STORE"]).toContain(missing.code);
  });

  it("requires a rationale for verdicts", async () => {
    const listing = await call("audit_findings", {
      run_id: runId,
      kind: "finding",
      limit: 1,
    });
    const target = (listing.items as Array<{ id: string }>)[0];
    expect(target).toBeDefined();
    const error = await callError("audit_verdict", {
      run_id: runId,
      finding: target?.id,
      status: "confirmed",
      rationale: " ",
    });
    expect(error.code).toBe("RATIONALE_REQUIRED");

    const verdict = (await call("audit_verdict", {
      run_id: runId,
      finding: target?.id,
      status: "likely",
      rationale: "data flow reaches the sink",
    })) as { status: string; reviewed: number };
    expect(verdict.status).toBe("likely");
    expect(verdict.reviewed).toBe(1);
  });

  it("rejects out-of-range add_finding lines and accepts valid ones", async () => {
    const error = await callError("audit_add_finding", {
      run_id: runId,
      file: "python/app.py",
      startLine: 99999,
      title: "bad",
      severity: "high",
      cwe: "CWE-89",
      rationale: "line does not exist",
    });
    expect(error.code).toBe("LINE_OUT_OF_RANGE");

    const added = (await call("audit_add_finding", {
      run_id: runId,
      file: "python/app.py",
      startLine: 14,
      title: "SQL string built with an operator",
      severity: "high",
      cwe: "CWE-200",
      rationale: "The name parameter reaches execute() without binding.",
      source: "mcp test",
    })) as { finding: { id: string; provenance: { engine: string } } };
    expect(added.finding.provenance.engine).toBe("agent");
    expect(added.finding.id).toMatch(/^AUD-\d{4}-\d{4}$/);
  });

  it("renders a report with verdicts merged", async () => {
    const summary = (await call("audit_report", {
      run_id: runId,
      format: "summary",
    })) as { text: string };
    const parsed = JSON.parse(summary.text) as {
      reviewed: number;
      unreviewed: number;
      findings: number;
    };
    expect(parsed.reviewed).toBe(1);
    expect(parsed.unreviewed).toBeGreaterThan(0);

    const markdown = (await call("audit_report", {
      run_id: runId,
      format: "md",
    })) as { text: string; path: string };
    expect(markdown.text).toContain("Source Code Security Audit Report");
    expect(markdown.text).toContain("Review progress");
    expect(fs.existsSync(markdown.path)).toBe(true);
  });

  it("returns the same counting summary from audit_status and audit_report", async () => {
    interface Summary {
      thresholds: { minConfidence: string; failOn: string };
      headline: { total: number; bySeverity: Record<string, number>; byCategory: Record<string, number> };
      lowConfidence: { total: number };
      hotspots: number;
      falsePositives: number;
      exitCode: { counting: number; code: number };
    }
    interface Shape {
      findings: number;
      findingCounts: Record<string, number>;
      lowConfidenceCandidates: number;
      hotspots: number;
      records: { findings: number; hotspots: number };
      summary: Summary;
    }
    const status = (await call("audit_status", { run_id: runId })) as unknown as Shape;
    const report = (await call("audit_report", { run_id: runId, format: "summary" })) as { text: string };
    const parsed = JSON.parse(report.text) as Shape;
    for (const shape of [status, parsed]) {
      expect(shape.summary.thresholds).toMatchObject({ minConfidence: "medium", failOn: "high" });
      // Headline: active findings at confidence >= medium, not every record.
      expect(shape.findings).toBe(shape.summary.headline.total);
      expect(shape.findingCounts).toEqual(shape.summary.headline.bySeverity);
      expect(shape.lowConfidenceCandidates).toBe(shape.summary.lowConfidence.total);
      expect(shape.hotspots).toBe(shape.summary.hotspots);
      const sum = (values: Record<string, number>): number =>
        Object.values(values).reduce((a, b) => a + b, 0);
      expect(sum(shape.summary.headline.bySeverity)).toBe(shape.findings);
      expect(sum(shape.summary.headline.byCategory)).toBe(shape.findings);
      expect(shape.findings + shape.lowConfidenceCandidates + shape.summary.falsePositives).toBeLessThanOrEqual(
        shape.records.findings,
      );
      expect(shape.summary.exitCode.code).toBe(shape.summary.exitCode.counting > 0 ? 1 : 0);
    }
    expect(parsed.summary).toEqual(status.summary);
    expect(status.lowConfidenceCandidates).toBeGreaterThan(0);

    // The numbers are those of findings.json, recomputed with verdicts applied.
    const listed = (await call("audit_findings", {
      run_id: runId,
      kind: "finding",
      minConfidence: "medium",
      limit: 1,
    })) as { total: number };
    expect(status.findings).toBeLessThanOrEqual(listed.total);

    // A false-positive verdict takes a finding out of the headline.
    const page = (await call("audit_findings", {
      run_id: runId,
      kind: "finding",
      minConfidence: "medium",
      status: "candidate",
      limit: 1,
    })) as { items: Array<{ id: string }> };
    const target = page.items[0]?.id;
    expect(target).toBeTruthy();
    await call("audit_verdict", {
      run_id: runId,
      finding: target,
      status: "false_positive",
      rationale: "constant input in a fixture",
    });
    const after = (await call("audit_status", { run_id: runId })) as unknown as Shape;
    expect(after.findings).toBe(status.findings - 1);
    expect(after.summary.falsePositives).toBe(status.summary.falsePositives + 1);
    expect(after.records).toEqual(status.records);
  });

  it("counts a run with the thresholds it was started with, like the report cover", async () => {
    interface Summary {
      thresholds: { minConfidence: string; failOn: string; newOnly: boolean };
      headline: { total: number };
      exitCode: { counting: number; code: number };
    }
    const numbers: Record<string, { headline: number; counting: number }> = {};
    for (const [name, args] of Object.entries({
      defaults: {},
      "low-medium": { minConfidence: "low", failOn: "medium" },
    })) {
      const started = await call("audit_start", {
        root: project,
        offline: true,
        engines: ["builtin"],
        noBaseline: true,
        ...args,
      });
      const id = String(started.run_id);
      const status = (await waitForCompletion(id)) as unknown as {
        phase: string;
        runDir: string;
        findings: number;
        policy: { minConfidence: string; failOn: string };
        summary: Summary;
      };
      expect(status.phase).toBe("complete");
      const report = (await call("audit_report", { run_id: id, format: "summary" })) as { text: string };
      const parsed = JSON.parse(report.text) as { findings: number; summary: Summary };
      const cover = fs.readFileSync(path.join(status.runDir, "report.md"), "utf8");
      const onDisk = JSON.parse(fs.readFileSync(path.join(status.runDir, "findings.json"), "utf8")) as {
        run: { summary: Summary };
      };
      const counting = status.summary.exitCode.counting;
      // audit_status, audit_report, findings.json and the cover agree.
      expect(parsed.summary).toEqual(status.summary);
      expect(onDisk.run.summary).toEqual(status.summary);
      expect(parsed.findings).toBe(status.findings);
      expect(status.findings).toBe(status.summary.headline.total);
      expect(cover).toContain(`**${counting} findings count toward the exit code**`);
      expect(cover).toMatch(new RegExp(`\\| \\*\\*${status.summary.headline.total}\\*\\* \\|$`, "m"));
      expect(status.policy).toMatchObject({
        minConfidence: (args as { minConfidence?: string }).minConfidence ?? "medium",
        failOn: (args as { failOn?: string }).failOn ?? "high",
      });
      numbers[name] = { headline: status.findings, counting };
    }
    expect(numbers["low-medium"]?.headline).toBeGreaterThan(numbers.defaults?.headline ?? Infinity);
    expect(numbers["low-medium"]?.counting).toBeGreaterThan(numbers.defaults?.counting ?? Infinity);
  });
});

/**
 * macOS regression: the OS temp directory (and therefore many real project
 * locations) sits below a symlink. The layout is built by hand so that the
 * test covers the same situation on every OS:
 *
 *   base/real/project          real audit root
 *   base/real/outside          outside the root
 *   base/alias -> base/real    symlinked parent used to address the root
 */
describe("MCP server with a root below a symlinked directory", () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "code-audit-mcp-"));
  const realProject = path.join(base, "real", "project");
  const aliasProject = path.join(base, "alias", "project");
  let linkedRunId: string;

  beforeAll(() => {
    fs.mkdirSync(path.join(base, "real", "outside"), { recursive: true });
    fs.cpSync(path.join(repoRoot, "fixtures/vulnerable"), realProject, {
      recursive: true,
    });
    fs.writeFileSync(
      path.join(base, "real", "outside", "secret.py"),
      "OUTSIDE_THE_AUDIT_ROOT = 1\n",
    );
    fs.writeFileSync(path.join(base, "real", "outside", "baseline.json"), "{}");
    fs.symlinkSync(path.join(base, "real"), path.join(base, "alias"), "dir");
    // Hostile repository content: symlinks that point out of the root.
    fs.symlinkSync(
      path.join(base, "real", "outside"),
      path.join(realProject, "escape-dir"),
      "dir",
    );
    fs.symlinkSync(
      path.join(base, "real", "outside", "secret.py"),
      path.join(realProject, "python", "escape.py"),
      "file",
    );
  });

  afterAll(() => {
    fs.rmSync(base, { recursive: true, force: true });
  });

  it("runs a scan and serves the run through the symlinked path", async () => {
    const started = await call("audit_start", {
      root: aliasProject,
      offline: true,
    });
    linkedRunId = String(started.run_id);
    // The run directory is reported under the canonical real root.
    expect(started.run_dir).toBe(
      path.join(fs.realpathSync.native(realProject), ".audit", linkedRunId),
    );
    const status = await waitForCompletion(linkedRunId);
    expect(status.phase).toBe("complete");
    expect(status.findings).toBeGreaterThan(0);

    const snippet = (await call("audit_read", {
      run_id: linkedRunId,
      file: "python/app.py",
      startLine: 1,
      endLine: 3,
    })) as { file: string; content: string };
    expect(snippet.file).toBe("python/app.py");

    const listing = (await call("audit_findings", {
      run_id: linkedRunId,
      kind: "finding",
      limit: 5,
    })) as { items: Array<{ file: string }> };
    expect(listing.items.length).toBeGreaterThan(0);
    for (const item of listing.items) {
      expect(item.file.startsWith("..")).toBe(false);
      expect(path.isAbsolute(item.file)).toBe(false);
    }
  });

  it("still refuses to read through symlinks that leave the root", async () => {
    for (const file of [
      "escape-dir/secret.py",
      "python/escape.py",
      "../outside/secret.py",
      path.join(base, "alias", "outside", "secret.py"),
      path.join(base, "real", "outside", "secret.py"),
    ]) {
      const error = await callError("audit_read", {
        run_id: linkedRunId,
        file,
      });
      expect(
        ["PATH_OUTSIDE_ROOT", "FILE_NOT_IN_INVENTORY", "PATH_JAIL"],
        file,
      ).toContain(error.code);
      expect(error.message).not.toContain("OUTSIDE_THE_AUDIT_ROOT");
    }
    const search = (await call("audit_search", {
      run_id: linkedRunId,
      pattern: "OUTSIDE_THE_AUDIT_ROOT",
    })) as { total: number };
    expect(search.total).toBe(0);
  });

  it("jails the baseline path against the real root", async () => {
    for (const baseline of [
      "escape-dir/baseline.json",
      "../outside/baseline.json",
      path.join(base, "alias", "outside", "baseline.json"),
      path.join(base, "real", "outside", "baseline.json"),
    ]) {
      const error = await callError("audit_start", {
        root: aliasProject,
        offline: true,
        baseline,
      });
      expect(error.code, baseline).toBe("PATH_OUTSIDE_ROOT");
    }
  });
});

describe("MCP trust boundary", () => {
  const RUN_TOOLS = [
    "audit_status",
    "audit_findings",
    "audit_read",
    "audit_search",
    "audit_verdict",
    "audit_add_finding",
    "audit_report",
  ];

  async function finishedRun(root: string, args: Record<string, unknown> = {}): Promise<{ id: string; runDir: string }> {
    const started = await call("audit_start", {
      root,
      offline: true,
      engines: ["builtin"],
      noBaseline: true,
      ...args,
    });
    const id = String(started.run_id);
    const status = await waitForCompletion(id);
    expect(status.phase).toBe("complete");
    return { id, runDir: String(status.runDir) };
  }

  function makeProject(name: string, files: Record<string, string>): string {
    const root = fs.realpathSync(fs.mkdtempSync(path.join(temp, `${name}-`)));
    for (const [file, content] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
      fs.writeFileSync(path.join(root, file), content);
    }
    return root;
  }

  it("says where run ids are resolved and takes a root on every run tool", async () => {
    const tools = (await client.listTools()).tools;
    for (const name of RUN_TOOLS) {
      const tool = tools.find((item) => item.name === name);
      expect(tool?.description ?? "", name).toContain("<root>/.audit/<run_id>");
      expect(tool?.description ?? "", name).toContain("a root the client named");
      expect(Object.keys((tool?.inputSchema as { properties?: object }).properties ?? {}), name).toContain("root");
    }
    const start = tools.find((item) => item.name === "audit_start");
    const properties = Object.keys((start?.inputSchema as { properties?: object }).properties ?? {});
    for (const option of ["untrusted", "failOnExisting", "noIgnoreFile", "includePlaceholders", "profile", "since", "latestLink"]) {
      expect(properties, option).toContain(option);
    }
  });

  it("passes untrusted through to the scan", async () => {
    const root = makeProject("untrusted", { "app.py": 'import os\nos.system("ls " + input())  # code-audit:ignore *\n' });
    const run = await finishedRun(root, { untrusted: true });
    const record = JSON.parse(fs.readFileSync(path.join(run.runDir, "run.json"), "utf8")) as {
      args: { untrusted?: boolean; noInlineIgnore?: boolean };
    };
    expect(record.args.untrusted).toBe(true);
    expect(record.args.noInlineIgnore).toBe(true);
  });

  it("does not read another project through a planted run, a path or a link", async () => {
    const victim = makeProject("victim", { "notes.txt": "codename BLUEHERON\n", "app.py": "x = 1\n" });
    const genuine = await finishedRun(victim);
    const victimBefore = fs.readdirSync(genuine.runDir).sort();

    const hostile = makeProject("hostile", { "main.py": "y = 2\n" });
    const own = await finishedRun(hostile);
    // The repository now carries a prepared run that names the victim ...
    const planted = path.join(hostile, ".audit", "EVIL");
    fs.renameSync(own.runDir, planted);
    const record = JSON.parse(fs.readFileSync(path.join(planted, "run.json"), "utf8")) as Record<string, unknown>;
    record.runId = "EVIL";
    record.args = { ...(record.args as object), root: victim, resolvedRoot: victim };
    record.rulesDir = path.join(hostile, "rules");
    fs.writeFileSync(path.join(planted, "run.json"), JSON.stringify(record));
    // ... and a link to the victim's genuine run.
    fs.symlinkSync(genuine.runDir, path.join(hostile, ".audit", "LINK"));

    // Not found without a root: the server cwd is not that project.
    expect((await callError("audit_status", { run_id: "EVIL" })).code).toBe("RUN_NOT_FOUND");

    const read = await callError("audit_read", { run_id: "EVIL", root: hostile, file: "notes.txt" });
    expect(read.code).toBe("FILE_NOT_IN_INVENTORY");
    const search = await call("audit_search", { run_id: "EVIL", root: hostile, pattern: "BLUEHERON" });
    expect(search.total).toBe(0);
    expect(search.root).toBe(hostile);
    expect(search.matches).toEqual([]);
    const added = await callError("audit_add_finding", {
      run_id: "EVIL",
      root: hostile,
      file: "notes.txt",
      startLine: 1,
      title: "t",
      severity: "low",
      cwe: "CWE-1",
      rationale: "r",
    });
    expect(added.code).toBe("FILE_NOT_IN_INVENTORY");
    const status = await call("audit_status", { run_id: "EVIL", root: hostile });
    expect(status.runDir).toBe(planted);
    expect(status.root).toBe(hostile);

    // A path is not a run id, wherever it points.
    for (const runId of [genuine.runDir, planted, `../${path.basename(victim)}/.audit/${genuine.id}`, ".audit/EVIL"]) {
      for (const tool of ["audit_status", "audit_findings", "audit_report"]) {
        expect((await callError(tool, { run_id: runId, root: hostile })).code, `${tool} ${runId}`).toBe("RUN_NOT_FOUND");
      }
    }
    // A link in .audit that leaves it is refused, for reads and for writes.
    expect((await callError("audit_findings", { run_id: "LINK", root: hostile })).code).toBe("RUN_DIR_ESCAPE");
    const verdict = await callError("audit_verdict", {
      run_id: "LINK",
      root: hostile,
      finding: "AUD-2026-0001",
      status: "false_positive",
      rationale: "planted",
    });
    expect(verdict.code).toBe("RUN_DIR_ESCAPE");
    expect((await callError("audit_report", { run_id: "LINK", root: hostile, format: "md" })).code).toBe("RUN_DIR_ESCAPE");
    expect(fs.readdirSync(genuine.runDir).sort()).toEqual(victimBefore);
  });

  it("re-renders every derived file after a verdict and an added finding", async () => {
    const root = makeProject("channels", {
      "app.py": 'import os\n\n\ndef run(c):\n    os.system("ls " + c)\n\n\ndef other(c):\n    os.system("rm " + c)\n',
    });
    const run = await finishedRun(root, { latestLink: true });
    const check = async (label: string): Promise<{ headline: { total: number }; falsePositives: number }> => {
      const status = (await call("audit_status", { run_id: run.id })) as unknown as {
        summary: { headline: { total: number }; exitCode: { counting: number }; falsePositives: number };
      };
      for (const dir of [run.runDir, path.join(root, ".audit", "latest")]) {
        const findings = JSON.parse(fs.readFileSync(path.join(dir, "findings.json"), "utf8")) as {
          run: { summary: unknown };
        };
        expect(findings.run.summary, `${label}: ${dir}/findings.json`).toEqual(status.summary);
        const cover = fs.readFileSync(path.join(dir, "report.md"), "utf8");
        expect(cover, `${label}: ${dir}/report.md`).toMatch(
          new RegExp(`\\| \\*\\*Total\\*\\* \\|.*\\| \\*\\*${status.summary.headline.total}\\*\\* \\|`),
        );
        const sarif = JSON.parse(fs.readFileSync(path.join(dir, "results.sarif"), "utf8")) as {
          runs: Array<{ properties: { headline: { total: number }; exitCode: { counting: number } } }>;
        };
        expect(sarif.runs[0]?.properties.headline.total, `${label}: ${dir}/results.sarif`).toBe(
          status.summary.headline.total,
        );
        expect(sarif.runs[0]?.properties.exitCode.counting, `${label}: ${dir}/results.sarif`).toBe(
          status.summary.exitCode.counting,
        );
      }
      const record = JSON.parse(fs.readFileSync(path.join(run.runDir, "run.json"), "utf8")) as { summary: unknown };
      expect(record.summary, `${label}: run.json`).toEqual(status.summary);
      return status.summary;
    };
    const before = await check("after the scan");
    expect(before.headline.total).toBeGreaterThan(0);

    const page = (await call("audit_findings", { run_id: run.id, kind: "finding", limit: 1 })) as {
      items: Array<{ id: string }>;
    };
    const verdict = (await call("audit_verdict", {
      run_id: run.id,
      finding: page.items[0]?.id,
      status: "false_positive",
      rationale: "checked",
    })) as { refreshed: string[] };
    expect(verdict.refreshed.length).toBeGreaterThanOrEqual(7);
    const afterVerdict = await check("after the verdict");
    expect(afterVerdict.headline.total).toBe(before.headline.total - 1);
    expect(afterVerdict.falsePositives).toBe(1);

    await call("audit_add_finding", {
      run_id: run.id,
      file: "app.py",
      startLine: 1,
      title: "Manual finding",
      severity: "critical",
      confidence: "high",
      cwe: "CWE-20",
      rationale: "by hand",
    });
    const afterAdd = await check("after the added finding");
    expect(afterAdd.headline.total).toBe(before.headline.total);
  });
});

describe("MCP stdio entrypoint", () => {
  it("serves the same tools over stdio", async () => {
    const bin = path.join(here, "../dist/bin.js");
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [bin],
      cwd: project,
      stderr: "pipe",
    });
    const stdioClient = new Client({ name: "stdio-test", version: "1.0.0" });
    await stdioClient.connect(transport);
    const tools = await stdioClient.listTools();
    expect(tools.tools).toHaveLength(8);
    await stdioClient.close();
  });
});
