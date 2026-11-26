import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { afterAll, describe, expect, it } from "vitest";
import {
  CLEAN,
  CLI,
  REPO_ROOT,
  VULNERABLE,
  cleanup,
  makeTempDir,
} from "./helpers.js";

const temp = makeTempDir("cli");

afterAll(() => cleanup(temp));

function run(args: string[]) {
  return spawnSync(process.execPath, [CLI, ...args], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    timeout: 60_000,
  });
}

function reportDir(stdout: string): string {
  const match = /^Report directory: (.+)$/m.exec(stdout);
  expect(match).not.toBeNull();
  return match?.[1]?.trim() ?? "";
}

describe("CLI exit codes", () => {
  it("returns 1 when findings reach the fail-on threshold", () => {
    const out = path.join(temp, "vulnerable");
    const result = run([
      "scan",
      VULNERABLE,
      "--offline",
      "--format",
      "md,json,sarif",
      "--out",
      out,
    ]);
    expect(result.status).toBe(1);
    const runDir = reportDir(result.stdout);
    expect(path.dirname(runDir)).toBe(out);
    expect(result.stdout.trimEnd().endsWith(`Report directory: ${runDir}`)).toBe(
      true,
    );
    for (const file of ["report.md", "findings.json", "results.sarif", "run.json", "coverage.json"]) {
      expect(fs.existsSync(path.join(runDir, file))).toBe(true);
    }
  });

  it("returns 0 when nothing reaches the threshold", () => {
    const result = run([
      "scan",
      CLEAN,
      "--offline",
      "--fail-on",
      "high",
      "--out",
      path.join(temp, "clean"),
    ]);
    expect(result.status).toBe(0);
  });

  it("keeps low-confidence hotspots but ignores them for exit codes by default", () => {
    const out = path.join(temp, "clean-confidence");
    const result = run([
      "scan",
      CLEAN,
      "--offline",
      "--format",
      "json",
      "--out",
      out,
    ]);
    expect(result.status).toBe(0);
    const runDir = reportDir(result.stdout);
    const document = JSON.parse(
      fs.readFileSync(path.join(runDir, "findings.json"), "utf8"),
    ) as {
      findings: Array<{ severity: string; confidence: string }>;
      hotspots: Array<{ severity: string; confidence: string; kind: string }>;
    };
    expect(document.findings).toEqual([]);
    expect(document.hotspots.length).toBeGreaterThan(0);
    expect(document.hotspots.some((hotspot) => hotspot.confidence === "low")).toBe(
      true,
    );
    for (const hotspot of document.hotspots) {
      expect(hotspot.kind).toBe("hotspot");
    }

    const strict = run([
      "scan",
      CLEAN,
      "--offline",
      "--format",
      "json",
      "--min-confidence",
      "low",
      "--out",
      path.join(temp, "clean-confidence-low"),
    ]);
    // Hotspots never influence the exit code, even at the lowest threshold.
    expect(strict.status).toBe(0);
  });

  it("returns 2 for a nonexistent target", () => {
    const result = run([
      "scan",
      path.join(temp, "does-not-exist"),
      "--offline",
      "--out",
      path.join(temp, "missing"),
    ]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("code-audit:");
    expect(result.stderr).toContain("audit root does not exist");
  });

  it("returns 2 for invalid options and prints English usage", () => {
    const result = run(["scan", VULNERABLE, "--format", "xml"]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("unknown --format: xml");
    expect(result.stderr).toContain("Usage:");
    expect(result.stderr).not.toContain("用法");
  });
});

describe("doctor", () => {
  it("reports Node, rules and external tool detection as JSON", () => {
    const result = run(["doctor", "--json"]);
    expect(result.status).toBe(0);
    const report = JSON.parse(result.stdout);
    expect(report.node.ok).toBe(true);
    expect(report.rules.count).toBeGreaterThanOrEqual(70);
    expect(report.externalTools.map((tool: { name: string }) => tool.name)).toEqual([
      "opengrep",
      "semgrep",
      "osv-scanner",
      "gitleaks",
    ]);
  });
});

describe("CLI query commands", () => {
  const out = path.join(temp, "query-runs");
  const scan = run([
    "scan",
    VULNERABLE,
    "--offline",
    "--format",
    "md,json,sarif",
    "--out",
    out,
  ]);
  const runDir = reportDir(scan.stdout);
  let findingId = "";
  let hotspotId = "";

  it("reports status as JSON", () => {
    const result = run(["status", runDir, "--json"]);
    expect(result.status).toBe(0);
    const status = JSON.parse(result.stdout) as {
      phase: string;
      findings: number;
      hotspots: number;
    };
    expect(status.phase).toBe("complete");
    expect(status.findings).toBeGreaterThan(0);
    expect(status.hotspots).toBeGreaterThan(0);
  });

  it("lists findings with filters and a cursor", () => {
    const result = run([
      "findings",
      runDir,
      "--kind",
      "finding",
      "--limit",
      "2",
      "--json",
    ]);
    expect(result.status).toBe(0);
    const page = JSON.parse(result.stdout) as {
      items: Array<{ id: string; kind: string }>;
      next_cursor: string | null;
      total: number;
    };
    expect(page.items).toHaveLength(2);
    expect(page.items[0]?.kind).toBe("finding");
    expect(page.next_cursor).toBe("2");
    findingId = page.items[0]?.id ?? "";
    expect(findingId).toMatch(/^AUD-/);

    const hotspots = run(["findings", runDir, "--kind", "hotspot", "--json"]);
    const hotspotPage = JSON.parse(hotspots.stdout) as {
      items: Array<{ id: string; kind: string }>;
    };
    expect(hotspotPage.items[0]?.kind).toBe("hotspot");
    hotspotId = hotspotPage.items[0]?.id ?? "";
    expect(hotspotId).toMatch(/^HOT-/);
  });

  it("reads snippets and searches", () => {
    const read = run([
      "read",
      runDir,
      "python/app.py",
      "--start",
      "1",
      "--end",
      "5",
      "--json",
    ]);
    expect(read.status).toBe(0);
    const snippet = JSON.parse(read.stdout) as { content: string; lines: unknown[] };
    expect(snippet.lines).toHaveLength(5);
    expect(snippet.content).toContain("import");

    const secret = run([
      "read",
      runDir,
      "secrets/secrets.txt",
      "--start",
      "1",
      "--end",
      "4",
      "--json",
    ]);
    const redacted = JSON.parse(secret.stdout) as { content: string };
    expect(redacted.content).not.toContain("AKIAFAKEFIXTURE00000");

    const search = run([
      "search",
      runDir,
      "os\\.system",
      "--regex",
      "--max-results",
      "3",
      "--json",
    ]);
    expect(search.status).toBe(0);
    const matches = JSON.parse(search.stdout) as {
      matches: Array<{ file: string; line: number }>;
    };
    expect(matches.matches.length).toBeGreaterThan(0);
    expect(matches.matches.length).toBeLessThanOrEqual(3);
  });

  it("records verdicts and requires a rationale", () => {
    const missing = run([
      "verdict",
      runDir,
      findingId,
      "--status",
      "confirmed",
    ]);
    expect(missing.status).toBe(2);

    const verdict = run([
      "verdict",
      runDir,
      findingId,
      "--status",
      "likely",
      "--rationale",
      "input reaches the sink",
      "--json",
    ]);
    expect(verdict.status).toBe(0);
    const result = JSON.parse(verdict.stdout) as { status: string; reviewed: number };
    expect(result.status).toBe("likely");
    expect(result.reviewed).toBe(1);
  });

  it("adds and promotes findings with validation", () => {
    const bad = run([
      "add-finding",
      runDir,
      "--file",
      "python/app.py",
      "--start",
      "99999",
      "--title",
      "bad",
      "--severity",
      "high",
      "--cwe",
      "CWE-89",
      "--rationale",
      "line does not exist",
    ]);
    expect(bad.status).toBe(2);

    const added = run([
      "add-finding",
      runDir,
      "--file",
      "python/app.py",
      "--start",
      "14",
      "--title",
      "Operator-controlled SQL string",
      "--severity",
      "high",
      "--cwe",
      "CWE-200",
      "--rationale",
      "The name parameter reaches execute() without binding.",
      "--source",
      "cli test",
      "--json",
    ]);
    expect(added.status).toBe(0);
    const addedResult = JSON.parse(added.stdout) as {
      finding: { provenance: { engine: string }; source: string };
    };
    expect(addedResult.finding.provenance.engine).toBe("agent");
    expect(addedResult.finding.source).toBe("cli test");

    const promoted = run([
      "add-finding",
      runDir,
      "--promote",
      hotspotId,
      "--rationale",
      "confirmed dangerous API with tainted input",
      "--json",
    ]);
    expect(promoted.status).toBe(0);
    const promotedResult = JSON.parse(promoted.stdout) as {
      promoted: boolean;
      finding: { kind: string };
    };
    expect(promotedResult.promoted).toBe(true);
    expect(promotedResult.finding.kind).toBe("finding");
  });

  it("renders summary, Markdown and JSON reports", () => {
    const summary = run(["report", runDir, "--json"]);
    expect(summary.status).toBe(0);
    const parsed = JSON.parse(summary.stdout) as {
      reviewed: number;
      unreviewed: number;
    };
    expect(parsed.reviewed).toBeGreaterThan(0);
    expect(parsed.unreviewed).toBeGreaterThan(0);

    const markdown = run(["report", runDir, "--format", "md"]);
    expect(markdown.status).toBe(0);
    expect(markdown.stdout).toContain("Source Code Security Audit Report");
    expect(markdown.stdout).toContain("Review progress");

    const target = path.join(temp, "report.json");
    const json = run([
      "report",
      runDir,
      "--format",
      "json",
      "--output",
      target,
    ]);
    expect(json.status).toBe(0);
    const document = JSON.parse(fs.readFileSync(target, "utf8")) as {
      findings: unknown[];
      hotspots: unknown[];
    };
    expect(document.findings.length).toBeGreaterThan(0);
    expect(document.hotspots.length).toBeGreaterThan(0);
  });

  it("returns 2 for unknown runs and flags", () => {
    expect(run(["status", "no-such-run"]).status).toBe(2);
    expect(run(["findings", runDir, "--bogus", "x"]).status).toBe(2);
  });
});

describe("CLI install command", () => {
  it("creates project-local OpenCode files and merges JSONC", () => {
    const project = path.join(temp, "install-opencode");
    fs.mkdirSync(project, { recursive: true });
    fs.writeFileSync(
      path.join(project, "opencode.jsonc"),
      '{\n  // keep me\n  "theme": "dark",\n}\n',
      "utf8",
    );

    const dry = run([
      "install",
      "--host",
      "opencode",
      "--project",
      project,
      "--dry-run",
    ]);
    expect(dry.status).toBe(0);
    expect(dry.stdout).toContain("dry run");
    expect(fs.existsSync(path.join(project, ".opencode/skills"))).toBe(false);

    const result = run(["install", "--host", "opencode", "--project", project]);
    expect(result.status).toBe(0);
    const config = JSON.parse(
      fs
        .readFileSync(path.join(project, "opencode.jsonc"), "utf8")
        .replace(/\/\/.*$/gm, "")
        .replace(/,\s*([}\]])/g, "$1"),
    ) as { theme: string; mcp: { servers: Record<string, unknown> } };
    expect(config.theme).toBe("dark");
    expect(config.mcp.servers["code-audit"]).toEqual({
      type: "local",
      command: ["code-audit-mcp"],
    });
    expect(
      fs.existsSync(path.join(project, ".opencode/skills/code-audit/SKILL.md")),
    ).toBe(true);
    expect(
      fs.readdirSync(project).some((name) =>
        name.includes("code-audit-backup"),
      ),
    ).toBe(true);
  });

  it("installs DSH, Claude Code and Codex project files", () => {
    const dsh = path.join(temp, "install-dsh");
    fs.mkdirSync(dsh, { recursive: true });
    expect(run(["install", "--host", "dsh", "--project", dsh]).status).toBe(0);
    const patch = fs.readFileSync(
      path.join(dsh, "dsh/cordis.patch.yml"),
      "utf8",
    );
    expect(patch).toContain("- insert:");
    expect(patch).toContain("name: '@deepseek-ai/dsh-mcp-client'");
    expect(patch).toContain("serverName: code-audit");
    expect(
      fs.existsSync(path.join(dsh, ".dsh/skills/code-audit/SKILL.md")),
    ).toBe(true);

    const claude = path.join(temp, "install-claude");
    fs.mkdirSync(claude, { recursive: true });
    fs.writeFileSync(
      path.join(claude, ".mcp.json"),
      '{"mcpServers":{"existing":{"command":"x","args":[]}}}\n',
      "utf8",
    );
    expect(
      run(["install", "--host", "claude-code", "--project", claude]).status,
    ).toBe(0);
    const claudeConfig = JSON.parse(
      fs.readFileSync(path.join(claude, ".mcp.json"), "utf8"),
    ) as { mcpServers: Record<string, unknown> };
    expect(Object.keys(claudeConfig.mcpServers).sort()).toEqual([
      "code-audit",
      "existing",
    ]);
    expect(
      fs.existsSync(path.join(claude, ".claude-plugin/plugin.json")),
    ).toBe(true);
    expect(fs.existsSync(path.join(claude, "commands/audit.md"))).toBe(true);

    const codex = path.join(temp, "install-codex");
    fs.mkdirSync(codex, { recursive: true });
    fs.writeFileSync(
      path.join(codex, "AGENTS.md"),
      "# Existing agents\n",
      "utf8",
    );
    expect(run(["install", "--host", "codex", "--project", codex]).status).toBe(
      0,
    );
    const toml = fs.readFileSync(
      path.join(codex, ".codex/config.toml"),
      "utf8",
    );
    expect(toml).toContain("[mcp_servers.code-audit]");
    expect(toml).toContain('command = "code-audit-mcp"');
    const agents = fs.readFileSync(path.join(codex, "AGENTS.md"), "utf8");
    expect(agents).toContain("# Existing agents");
    expect(agents).toContain("<!-- code-audit:begin -->");
    expect(
      fs.existsSync(path.join(codex, ".agents/skills/code-audit/SKILL.md")),
    ).toBe(true);
  });

  it("rejects unknown hosts and missing --host", () => {
    expect(run(["install", "--host", "cursor"]).status).toBe(2);
    expect(run(["install"]).status).toBe(2);
  });

  it("skips install-created adapter files during a later scan", () => {
    const project = path.join(temp, "install-skip");
    fs.mkdirSync(project, { recursive: true });
    fs.writeFileSync(
      path.join(project, "opencode.json"),
      '{"theme":"dark"}\n',
      "utf8",
    );
    fs.writeFileSync(path.join(project, "app.py"), "print(1)\n");
    expect(
      run(["install", "--host", "opencode", "--project", project]).status,
    ).toBe(0);

    const scan = run([
      "scan",
      project,
      "--offline",
      "--out",
      path.join(temp, "install-skip-out"),
    ]);
    expect(scan.status).toBe(0);
    const runDir = reportDir(scan.stdout);
    const coverage = JSON.parse(
      fs.readFileSync(path.join(runDir, "coverage.json"), "utf8"),
    ) as {
      scannedFiles: Array<{ path: string }>;
      skipped: Array<{ path: string; reason: string }>;
    };
    const adapterSkipped = coverage.skipped
      .filter((entry) => entry.reason === "code-audit adapter file")
      .map((entry) => entry.path);
    expect(adapterSkipped).toContain(".opencode/skills/code-audit/SKILL.md");
    expect(adapterSkipped).toContain(".opencode/commands/audit.md");
    // A user's own opencode.json predates the install and stays auditable.
    expect(adapterSkipped).not.toContain("opencode.json");
    expect(coverage.scannedFiles.some((file) => file.path === "app.py")).toBe(
      true,
    );
  });
});
