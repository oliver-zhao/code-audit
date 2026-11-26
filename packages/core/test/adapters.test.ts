import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { REPO_ROOT } from "./helpers.js";

function read(relative: string): string {
  return fs.readFileSync(path.join(REPO_ROOT, relative), "utf8");
}

function parseJson(relative: string): Record<string, unknown> {
  return JSON.parse(read(relative)) as Record<string, unknown>;
}

describe("shared skill", () => {
  it("has trigger-oriented frontmatter and the full workflow", () => {
    const skill = read("skills/code-audit/SKILL.md");
    expect(skill.startsWith("---\n")).toBe(true);
    expect(skill).toMatch(/^name: code-audit$/m);
    const description = /^description: (.+)$/m.exec(skill)?.[1] ?? "";
    expect(description).toContain("security audit");
    for (const tool of [
      "audit_start",
      "audit_status",
      "audit_findings",
      "audit_read",
      "audit_search",
      "audit_verdict",
      "audit_add_finding",
      "audit_report",
    ]) {
      expect(skill).toContain(tool);
    }
    expect(skill).toContain("untrusted");
    expect(skill).toContain("code-audit-mcp");
    for (const option of ["engines", "baseline", "noInlineIgnore", "reading list"]) {
      expect(skill).toContain(option);
    }
  });

  it("names tools by their bare names and explains host prefixes once", () => {
    const skill = read("skills/code-audit/SKILL.md");
    const prefixed = skill.match(/\b(?:mcp__code[-_]audit__|code-audit_)audit_\w+/g) ?? [];
    expect(prefixed.sort()).toEqual([
      "code-audit_audit_start",
      "mcp__code-audit__audit_start",
      "mcp__code_audit__audit_start",
    ]);
    expect(skill).toContain("bare name");
  });

  it("is copied into every host adapter", () => {
    const canonical = read("skills/code-audit/SKILL.md");
    for (const relative of [
      "adapters/opencode/skills/code-audit/SKILL.md",
      "adapters/dsh/skills/code-audit/SKILL.md",
      "adapters/claude-code/skills/code-audit/SKILL.md",
      "adapters/codex/.agents/skills/code-audit/SKILL.md",
    ]) {
      expect(read(relative)).toBe(canonical);
    }
  });
});

describe("host adapters", () => {
  it("declares OpenCode and example MCP servers with the verified shape", () => {
    for (const relative of [
      "adapters/opencode/opencode.json",
      "examples/opencode-demo/opencode.json",
    ]) {
      const config = parseJson(relative) as {
        mcp: { servers: Record<string, { type: string; command: string[] }> };
      };
      expect(config.mcp.servers["code-audit"]).toEqual({
        type: "local",
        command: ["code-audit-mcp"],
      });
    }
    expect(read("adapters/opencode/commands/audit.md")).toContain(
      "description:",
    );
  });

  it("declares DSH insert patches for both the adapter and the example", () => {
    for (const relative of [
      "adapters/dsh/cordis.patch.yml",
      "examples/dsh-demo/dsh/cordis.patch.yml",
    ]) {
      const patch = read(relative);
      expect(patch).toContain("- insert:");
      expect(patch).toContain("id: mcp-code-audit");
      expect(patch).toContain("name: '@deepseek-ai/dsh-mcp-client'");
      expect(patch).toContain("serverName: code-audit");
      expect(patch).toContain("command: code-audit-mcp");
    }
    expect(read("examples/dsh-demo/probe.mjs")).toContain("probeServer");
  });

  it("declares a Claude Code plugin, MCP config and command", () => {
    const plugin = parseJson("adapters/claude-code/.claude-plugin/plugin.json");
    expect(plugin.name).toBe("code-audit");
    expect((plugin.author as { name?: string }).name).toBeTruthy();
    // Shape accepted by `claude plugin validate --strict .` (Claude Code 2.1.183).
    const marketplace = parseJson(".claude-plugin/marketplace.json") as {
      name: string;
      owner: { name: string };
      plugins: Array<{ name: string; source: string }>;
    };
    expect(marketplace.owner.name).toBeTruthy();
    expect(marketplace.plugins).toHaveLength(1);
    expect(marketplace.plugins[0]?.name).toBe(plugin.name);
    expect(marketplace.plugins[0]?.source).toBe("./adapters/claude-code");
    const mcp = parseJson("adapters/claude-code/.mcp.json") as {
      mcpServers: Record<string, { command: string }>;
    };
    expect(mcp.mcpServers["code-audit"]?.command).toBe("code-audit-mcp");
    expect(read("adapters/claude-code/commands/audit.md")).toContain(
      "argument-hint:",
    );
  });

  it("documents the installer's safety rules in every adapter README", () => {
    for (const host of ["opencode", "dsh", "claude-code", "codex"]) {
      const readme = read(`adapters/${host}/README.md`);
      expect(readme, host).toContain(`code-audit install --host ${host}`);
      expect(readme, host).toContain("never from a file in the project");
      expect(readme, host).toContain(".code-audit/backups/");
      expect(readme, host).toContain("--dry-run");
      // Backups next to the file were replaced by one backup per file.
      expect(readme, host).not.toContain(".code-audit-backup-");
    }
    expect(read("adapters/dsh/README.md")).toContain("command: 'code-audit-mcp'");
    expect(read("adapters/opencode/README.md")).toContain("--force");
    expect(read("adapters/claude-code/README.md")).toContain("--force");
  });

  it("declares Codex MCP TOML, skills and an AGENTS.md snippet", () => {
    const toml = read("adapters/codex/.codex/config.toml");
    expect(toml).toContain("[mcp_servers.code-audit]");
    expect(toml).toContain('command = "code-audit-mcp"');
    const agents = read("adapters/codex/AGENTS.md");
    expect(agents).toContain("<!-- code-audit:begin -->");
    expect(agents).toContain("<!-- code-audit:end -->");
  });
});
