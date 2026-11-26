import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  ADAPTER_OWNED_FILES,
  RULE_FIELDS,
  TOOL_VERSION,
  defaultOpengrepRulesDir,
  defaultRulesDir,
  loadRules,
  monorepoRootDir,
  scanRules,
  toolRootDir,
  type InventoryFile,
} from "@code-audit/core";
import { MCP_SERVER_VERSION, createAuditServer } from "../src/index.js";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const read = (relative: string): string => fs.readFileSync(path.join(repoRoot, relative), "utf8");
const json = (relative: string): Record<string, unknown> =>
  JSON.parse(read(relative)) as Record<string, unknown>;
const cli = path.join(repoRoot, "packages/cli/dist/index.js");

describe("release consistency", () => {
  it("uses one version everywhere", () => {
    const versions: Record<string, unknown> = {
      "package.json": json("package.json").version,
      "packages/core/package.json": json("packages/core/package.json").version,
      "packages/mcp/package.json": json("packages/mcp/package.json").version,
      "packages/cli/package.json": json("packages/cli/package.json").version,
      "adapters/claude-code/.claude-plugin/plugin.json": json(
        "adapters/claude-code/.claude-plugin/plugin.json",
      ).version,
      ".claude-plugin/marketplace.json": (
        json(".claude-plugin/marketplace.json").metadata as { version?: string }
      ).version,
      TOOL_VERSION,
      MCP_SERVER_VERSION,
      "code-audit --version": execFileSync(process.execPath, [cli, "--version"], {
        encoding: "utf8",
      }).trim(),
    };
    for (const [where, version] of Object.entries(versions)) {
      expect(version, where).toBe(TOOL_VERSION);
    }
    expect(TOOL_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
    expect(read("CHANGELOG.md")).toContain(`## [${TOOL_VERSION}]`);
  });

  it("declares publishable package metadata", () => {
    for (const name of ["core", "mcp", "cli"]) {
      const manifest = json(`packages/${name}/package.json`) as {
        name: string;
        private?: boolean;
        license: string;
        type: string;
        description: string;
        repository: { url: string; directory: string };
        homepage: string;
        bugs: { url: string };
        engines: { node: string };
        files: string[];
        exports: Record<string, unknown>;
        bin?: Record<string, string>;
        dependencies?: Record<string, string>;
      };
      expect(manifest.name).toBe(`@code-audit/${name}`);
      expect(manifest.private).toBeUndefined();
      expect(manifest.license).toBe("Apache-2.0");
      expect(manifest.type).toBe("module");
      expect(manifest.description.length).toBeGreaterThan(20);
      expect(manifest.repository.directory).toBe(`packages/${name}`);
      expect(manifest.homepage).toContain("github.com");
      expect(manifest.bugs.url).toContain("/issues");
      expect(manifest.engines.node).toBe(">=22");
      expect(manifest.files).toContain("dist");
      expect(manifest.files).toContain("!dist/**/*.map");
      expect(manifest.exports).toBeTruthy();
      expect(fs.existsSync(path.join(repoRoot, "packages", name, "README.md"))).toBe(true);
      // Workspace packages depend on each other by workspace range only.
      for (const [dependency, range] of Object.entries(manifest.dependencies ?? {})) {
        if (dependency.startsWith("@code-audit/")) expect(range).toBe("workspace:*");
      }
    }
    const cliManifest = json("packages/cli/package.json") as { bin: Record<string, string> };
    expect(Object.keys(cliManifest.bin).sort()).toEqual(["code-audit", "code-audit-mcp"]);
    expect((json("packages/mcp/package.json") as { bin: Record<string, string> }).bin).toEqual({
      "code-audit-mcp": "dist/bin.js",
    });
    expect((json("packages/core/package.json") as { files: string[] }).files).toContain("assets");
  });

  it("locates rules, skill and adapter files in the checkout, and packs all of them", () => {
    expect(monorepoRootDir()).toBe(repoRoot);
    expect(toolRootDir()).toBe(repoRoot);
    expect(defaultRulesDir()).toBe(path.join(repoRoot, "rules"));
    expect(defaultOpengrepRulesDir()).toBe(path.join(repoRoot, "rules/opengrep"));
    // Everything the installed package reads through toolRootDir() must be in
    // the asset list of scripts/pack-assets.mjs.
    const script = read("scripts/pack-assets.mjs");
    const assets = [...(/CORE_ASSETS = \[([^\]]*)\]/.exec(script)?.[1] ?? "").matchAll(/"([^"]+)"/g)].map(
      (match) => match[1] as string,
    );
    expect(assets).toContain("rules");
    for (const source of new Set(Object.values(ADAPTER_OWNED_FILES))) {
      expect(assets, source).toContain(source);
      expect(fs.existsSync(path.join(repoRoot, source)), source).toBe(true);
    }
    const installer = read("packages/cli/src/install.ts");
    for (const match of installer.matchAll(/repoFile\("([^"]+)"\)/g)) {
      expect(assets, match[1]).toContain(match[1]);
    }
  });
});

describe("documentation matches the code", () => {
  const help = execFileSync(process.execPath, [cli, "--help"], { encoding: "utf8" });

  it("lists every implemented flag and command in --help", () => {
    const index = read("packages/cli/src/index.ts");
    const query = read("packages/cli/src/query.ts");
    const flags = new Set<string>();
    for (const match of index.matchAll(/arg === "(--[a-z-]+)"/g)) flags.add(match[1] as string);
    for (const match of query.matchAll(/parseRunCommand\(\s*args,\s*\[([^\]]*)\]/g)) {
      for (const name of (match[1] ?? "").matchAll(/"([a-z-]+)"/g)) flags.add(`--${name[1]}`);
    }
    for (const name of /COMMON_FLAGS = \[([^\]]*)\]/.exec(query)?.[1]?.matchAll(/"([a-z-]+)"/g) ?? []) {
      flags.add(`--${name[1]}`);
    }
    flags.add("--json");
    expect(flags.size).toBeGreaterThan(40);
    for (const flag of flags) {
      expect(help, flag).toMatch(new RegExp(`${flag}(?![a-z-])`));
    }
    for (const command of [
      "scan",
      "baseline",
      "status",
      "findings",
      "read",
      "search",
      "verdict",
      "add-finding",
      "report",
      "mcp",
      "install",
      "doctor",
    ]) {
      expect(help, command).toContain(`code-audit ${command}`);
    }
    // `--help` after a command prints the usage instead of an error.
    for (const args of [["doctor", "--help"], ["status", "--help"], ["scan", "-h"]]) {
      expect(execFileSync(process.execPath, [cli, ...args], { encoding: "utf8" })).toBe(help);
    }
  });

  it("documents every scan flag in the README", () => {
    const readme = read("README.md");
    const scanBlock = /function parseScanArgs[\s\S]*?\n}\n/.exec(read("packages/cli/src/index.ts"))?.[0] ?? "";
    const flags = [...scanBlock.matchAll(/arg === "(--[a-z-]+)"/g)]
      .map((match) => match[1] as string)
      .filter((flag) => flag !== "--help");
    expect(flags.length).toBeGreaterThan(20);
    for (const flag of flags) expect(readme, flag).toContain(`\`${flag}`);
  });

  it("documents every rule field in docs/rules.md", () => {
    const doc = read("docs/rules.md");
    expect(RULE_FIELDS.length).toBeGreaterThan(20);
    for (const field of RULE_FIELDS) expect(doc, field).toContain(`| \`${field}\` |`);
    const documented = [...doc.matchAll(/^\| `([A-Za-z_]+)` \| /gm)].map((match) => match[1]);
    expect(documented.sort()).toEqual([...RULE_FIELDS].sort());
  });

  it("documents every MCP tool and argument in docs/mcp.md", async () => {
    const server = createAuditServer();
    const client = new Client({ name: "release-test", version: "0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    const { tools } = await client.listTools();
    await client.close();
    const doc = read("docs/mcp.md");
    expect(tools).toHaveLength(8);
    for (const tool of tools) {
      const start = doc.indexOf(`## \`${tool.name}\``);
      expect(start, tool.name).toBeGreaterThan(0);
      const next = doc.indexOf("\n## ", start + 1);
      const section = doc.slice(start, next < 0 ? undefined : next);
      const properties = Object.keys(
        (tool.inputSchema as { properties?: Record<string, unknown> }).properties ?? {},
      );
      for (const property of properties) {
        // run_id and root are documented once, for all tools.
        const where = property === "run_id" || property === "root" ? doc : section;
        expect(where, `${tool.name}.${property}`).toContain(`\`${property}\``);
      }
    }
  });
});

describe("JavaScript exec rules", () => {
  function hits(source: string): string[] {
    const dir = fs.mkdtempSync(path.join(repoRoot, ".tmp-test-jsexec-"));
    try {
      const file = path.join(dir, "a.js");
      fs.writeFileSync(file, source);
      const inventory = [
        { absPath: file, relPath: "a.js", language: "javascript", scannable: true },
      ] as unknown as InventoryFile[];
      return scanRules(inventory, loadRules(defaultRulesDir()))
        .hits.filter((hit) => hit.rule.group === "js-command")
        .map((hit) => `${hit.rule.id}:${hit.line}`);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }

  it("does not take RegExp.prototype.exec or query.exec() for a subprocess", () => {
    expect(
      hits(
        [
          "const m = /^[a-z]+/.exec(line.slice(start, start + 3));",
          "while ((match = PATTERN.exec(text + suffix)) !== null) {}",
          "const rows = await query.exec();",
        ].join("\n"),
      ),
    ).toEqual([]);
  });

  it("still reports child_process exec calls", () => {
    expect(
      hits(
        [
          'exec("ls " + name);',
          'child_process.exec("ls " + name);',
          'require("child_process").exec("ls " + name);',
          "cp.execSync(command);",
          "execSync(command);",
        ].join("\n"),
      ),
    ).toEqual([
      "js-command-injection:1",
      "js-command-injection:2",
      "js-command-injection:3",
      "js-exec-api:4",
      "js-exec-api:5",
    ]);
  });
});
