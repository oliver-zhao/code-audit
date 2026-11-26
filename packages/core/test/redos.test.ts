/**
 * Patterns supplied at run time (a search regex, a glob, the rules of a
 * `--rules` directory) are matched under limits that hold whatever the
 * pattern and the content are. A structural "is this regex safe" check cannot
 * be complete; these tests use patterns that pass it.
 */
import fs from "node:fs";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { compileGlob, globMatches, globToRegExp } from "../src/glob.js";
import { InterruptedError, runInterruptible } from "../src/interrupt.js";
import { inventory } from "../src/inventory.js";
import { loadRules, scanRules } from "../src/rules.js";
import { assertSafeRegex, RunStoreError, searchCode } from "../src/runstore.js";
import { scanProject } from "../src/scan.js";
import { CLI, REPO_ROOT, cleanup, makeTempDir, writeFile } from "./helpers.js";

const temp = makeTempDir("redos");
const project = path.join(temp, "project");
let runId: string;

/** Exponential for the pattern below; one match attempt takes far over a minute. */
const HOSTILE_LINE = `${"a".repeat(60)}!`;
/** Both pass `assertSafeRegex`. */
const HOSTILE_PATTERNS = ["(a|aa)+$", "(a|a?)+$", "^(a|aa|aaa)+$"];

beforeAll(async () => {
  writeFile(project, "app.py", "import os\nos.system(cmd)\nvalue = '(a|aa)+$'\n");
  writeFile(project, "data/hostile.txt", `${HOSTILE_LINE}\n`);
  writeFile(project, "data/long.txt", `${"x".repeat(5000)}NEEDLE${"y".repeat(30_000)}TAIL\n`);
  const result = await scanProject({ root: project, offline: true, engines: ["builtin"], formats: ["json"] });
  runId = result.runId;
});

afterAll(() => cleanup(temp));

describe("runInterruptible", () => {
  it("interrupts a regular expression in the middle of a match", () => {
    const started = performance.now();
    expect(() => runInterruptible(() => /(a|aa)+$/.exec(HOSTILE_LINE), 150)).toThrow(InterruptedError);
    expect(performance.now() - started).toBeLessThan(2000);
    // The process is fine afterwards, results and errors pass through.
    expect(runInterruptible(() => /b/.exec("abc")?.index, 1000)).toBe(1);
    expect(() =>
      runInterruptible(() => {
        throw new RangeError("mine");
      }, 1000),
    ).toThrow(RangeError);
  });
});

describe("search under a hard time limit", () => {
  it("stops a catastrophic regex with SEARCH_TIMEOUT", () => {
    for (const pattern of HOSTILE_PATTERNS) {
      // The structural guard lets it through: it cannot be complete.
      expect(() => assertSafeRegex(pattern), pattern).not.toThrow();
      const started = performance.now();
      let error: unknown;
      try {
        searchCode(runId, { pattern, regex: true, timeoutMs: 300 }, { cwd: project });
      } catch (caught) {
        error = caught;
      }
      const elapsed = performance.now() - started;
      expect(error, pattern).toBeInstanceOf(RunStoreError);
      expect((error as RunStoreError).code, pattern).toBe("SEARCH_TIMEOUT");
      expect((error as RunStoreError).message).toMatch(/time limit of 300 ms/);
      expect(elapsed, pattern).toBeLessThan(2500);
    }
  });

  it("uses a 2 second budget by default", () => {
    const started = performance.now();
    expect(() => searchCode(runId, { pattern: "(a|aa)+$", regex: true }, { cwd: project })).toThrow(
      /time limit of 2000 ms/,
    );
    const elapsed = performance.now() - started;
    expect(elapsed).toBeGreaterThan(1500);
    expect(elapsed).toBeLessThan(4500);
  });

  it("never compiles a literal pattern as a regular expression", () => {
    const literal = searchCode(runId, { pattern: "(a|aa)+$" }, { cwd: project });
    expect(literal.matches.map((match) => `${match.file}:${match.line}:${match.column}`)).toEqual(["app.py:3:10"]);
    // Text that is not a valid regex, and text with every metacharacter.
    expect(searchCode(runId, { pattern: "(((" }, { cwd: project }).total).toBe(0);
    expect(searchCode(runId, { pattern: "os.system(" }, { cwd: project }).total).toBe(1);
    expect(searchCode(runId, { pattern: "os.system" }, { cwd: project }).total).toBe(1);
    expect(searchCode(runId, { pattern: "osXsystem" }, { cwd: project }).total).toBe(0);
  });

  it("matches over-long lines in windows and says so", () => {
    const found = searchCode(runId, { pattern: "NEEDLE", regex: true, glob: "data/long.txt" }, { cwd: project });
    expect(found.matches).toHaveLength(1);
    expect(found.matches[0]?.column).toBe(5001);
    expect(found.notices.join("\n")).toMatch(/longer than 2000 characters/);
    // Beyond the matched part of the line.
    expect(searchCode(runId, { pattern: "TAIL", glob: "data/long.txt" }, { cwd: project }).total).toBe(0);
  });

  it("returns from the CLI within the budget", () => {
    const started = performance.now();
    const result = spawnSync(process.execPath, [CLI, "search", runId, "(a|aa)+$", "--regex"], {
      cwd: project,
      encoding: "utf8",
      timeout: 20_000,
    });
    const elapsed = performance.now() - started;
    expect(result.status).not.toBe(0);
    expect(result.status).not.toBeNull();
    expect(result.stderr).toMatch(/time limit of 2000 ms/);
    expect(elapsed).toBeLessThan(6000);

    const quick = spawnSync(
      process.execPath,
      [CLI, "search", runId, "(a|aa)+$", "--regex", "--timeout-ms", "200"],
      { cwd: project, encoding: "utf8", timeout: 20_000 },
    );
    expect(quick.stderr).toMatch(/time limit of 200 ms/);
    const literal = spawnSync(process.execPath, [CLI, "search", runId, "(a|aa)+$"], {
      cwd: project,
      encoding: "utf8",
    });
    expect(literal.status).toBe(0);
    expect(literal.stdout).toContain("app.py:3:10");
  });

  it("keeps the MCP server responsive during and after a hostile search", async () => {
    const child = spawn(path.join(REPO_ROOT, "bin", "code-audit-mcp"), [], {
      cwd: project,
      stdio: ["pipe", "pipe", "pipe"],
    });
    try {
      let buffer = "";
      const waiting = new Map<number, (message: { result?: { content?: Array<{ text: string }>; isError?: boolean } }) => void>();
      child.stdout.on("data", (chunk: Buffer) => {
        buffer += chunk.toString("utf8");
        let newline: number;
        while ((newline = buffer.indexOf("\n")) >= 0) {
          const line = buffer.slice(0, newline);
          buffer = buffer.slice(newline + 1);
          if (!line.trim()) continue;
          const message = JSON.parse(line) as { id?: number };
          if (message.id !== undefined) {
            waiting.get(message.id)?.(message as never);
            waiting.delete(message.id);
          }
        }
      });
      let nextId = 0;
      const rpc = (method: string, params: unknown) =>
        new Promise<{ result?: { content?: Array<{ text: string }>; isError?: boolean } }>((resolve) => {
          const id = (nextId += 1);
          waiting.set(id, resolve);
          child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
        });
      const callTool = async (name: string, args: Record<string, unknown>) => {
        const started = performance.now();
        const reply = await rpc("tools/call", { name, arguments: args });
        return {
          elapsed: performance.now() - started,
          text: reply.result?.content?.[0]?.text ?? "",
          isError: reply.result?.isError === true,
        };
      };
      await rpc("initialize", {
        protocolVersion: "2025-03-26",
        capabilities: {},
        clientInfo: { name: "redos-test", version: "0" },
      });
      child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);

      // Both requests are sent at once: the status call is answered as soon
      // as the search has been stopped, not 25 seconds (or never) later.
      const [search, status] = await Promise.all([
        callTool("audit_search", { run_id: runId, pattern: "(a|aa)+$", regex: true }),
        callTool("audit_status", { run_id: runId }),
      ]);
      expect(search.isError).toBe(true);
      expect(JSON.parse(search.text).error.code).toBe("SEARCH_TIMEOUT");
      expect(search.elapsed).toBeLessThan(5000);
      expect(status.isError).toBe(false);
      expect(status.elapsed).toBeLessThan(5000);

      const after = await callTool("audit_status", { run_id: runId });
      expect(JSON.parse(after.text).phase).toBe("complete");
      expect(after.elapsed).toBeLessThan(1000);
      // The time limit is not an MCP argument.
      const custom = await callTool("audit_search", {
        run_id: runId,
        pattern: "(a|aa)+$",
        regex: true,
        timeoutMs: 60_000,
        timeout_ms: 60_000,
      });
      expect(custom.elapsed).toBeLessThan(5000);
      expect(custom.text).toMatch(/SEARCH_TIMEOUT|time limit of 2000 ms/);
    } finally {
      child.kill("SIGKILL");
    }
  }, 40_000);
});

describe("globs are matched without backtracking", () => {
  it("answers a glob of double stars against a deep path at once", () => {
    const glob = `${"**/".repeat(40)}x`;
    const deep = `${"a/".repeat(200)}y`;
    const started = performance.now();
    expect(globMatches(glob, deep)).toBe(false);
    expect(globMatches(`${"*a".repeat(40)}b`, "a".repeat(400))).toBe(false);
    expect(globMatches(`${"**a".repeat(40)}b`, `${"a/".repeat(200)}`)).toBe(false);
    expect(performance.now() - started).toBeLessThan(500);
    expect(() => compileGlob("*".repeat(5000))).toThrow(/too long/);
  });

  it("agrees with the reference regular expression", () => {
    const globs = [
      "**", "*", "?", "a/**", "**/x.py", "a/*/b.py", "*.py", "a/?.py", "**/*.ts", "src/**/*.ts", "**/a/**/b",
      "a**b", "a/**/", "**/", "*/*", "a*b*c", "**x", "x**", "a/**/**/b", "?*?", "", "a", "a/", "/a", "**/**",
      "a+b(1).py", "file[1].txt", "*.*", "**/.*", "a/b/**/c/*.d",
    ];
    const paths = [
      "", "a", "b", "x.py", "a/x.py", "a/b/x.py", "a/b/c.py", "a/b/c/d.py", "a/x/b.py", "a/x/y/b.py", "dir/a.py",
      "a//.py", "a/xy.py", "src/a.ts", "src/a/b.ts", "src/.ts", "a/b", "a/c/b", "a/", "/a", "a/a/a/b/b", "ab",
      "axxb", "a/b/c", "abc", "aXbYc", "x", "xx", "a+b(1).py", "file[1].txt", ".hidden", "a/.hidden", "a/b/q/c/e.d",
      "a/b/c/e.d", "/", "//",
    ];
    for (const glob of globs) {
      const reference = globToRegExp(glob);
      const matcher = compileGlob(glob);
      for (const candidate of paths) {
        expect(matcher(candidate), `${JSON.stringify(glob)} vs ${JSON.stringify(candidate)}`).toBe(
          reference.test(candidate),
        );
      }
    }
  });

  it("applies a hostile --glob within the search budget", () => {
    const started = performance.now();
    const result = searchCode(runId, { pattern: "os", glob: `${"**/".repeat(60)}*.py` }, { cwd: project });
    expect(result.total).toBeGreaterThan(0);
    expect(performance.now() - started).toBeLessThan(2000);
  });
});

describe("rule matching is interrupted when a custom rule does not return", () => {
  it("stops the file, warns, and goes on with the next file", () => {
    const rulesDir = path.join(temp, "rules");
    writeFile(
      rulesDir,
      "custom.yml",
      [
        "version: 1",
        "rules:",
        "  - id: custom-exponential",
        "    title: Exponential custom rule",
        "    severity: low",
        "    confidence: low",
        "    cwe: CWE-1",
        "    languages:",
        "      - python",
        "    pattern: (a|aa)+$",
        "    message: m",
        "    remediation: r",
        "  - id: custom-plain",
        "    title: Plain custom rule",
        "    severity: low",
        "    confidence: low",
        "    cwe: CWE-1",
        "    languages:",
        "      - python",
        "    pattern: MARKER_[0-9]+",
        "    message: m",
        "    remediation: r",
        "",
      ].join("\n"),
    );
    const root = path.join(temp, "custom-project");
    writeFile(root, "a_hostile.py", `x = 1\nMARKER_1\ny = "${"a".repeat(60)}!"\nMARKER_2\n`);
    writeFile(root, "b_fine.py", "MARKER_3\n");
    const files = inventory(root).files;
    const started = performance.now();
    const result = scanRules(files, loadRules(rulesDir), { fileBudgetMs: 200 });
    const elapsed = performance.now() - started;
    // 200 ms budget + 1000 ms grace, not the minutes the match would take.
    expect(elapsed).toBeLessThan(4000);
    expect(result.warnings.join("\n")).toMatch(/a_hostile\.py was interrupted after 1200 ms/);
    const hits = result.hits.map((hit) => `${hit.file.relPath}:${hit.line}:${hit.rule.id}`);
    // Found before the interruption, and in the next file.
    expect(hits).toContain("a_hostile.py:2:custom-plain");
    expect(hits).toContain("b_fine.py:1:custom-plain");
  }, 30_000);
});

describe("redaction and credential-file detection stay linear on hostile lines", () => {
  it("handles 20,000-character lines made for the new patterns quickly", async () => {
    const { redactLine } = await import("../src/redact.js");
    const { scanSecrets } = await import("../src/secrets.js");
    const lines: Array<[string, string]> = [
      ["notes.txt", `Cookie: ${"a".repeat(19_000)}`],
      ["notes.txt", `Cookie: ${"a=".repeat(9_000)}`],
      [".netrc", '"'.repeat(19_000)],
      [".netrc", `password ${'" '.repeat(9_000)}`],
      ["a.sh", `sshpass -p '${"x".repeat(19_000)}`],
      ["a.sh", "curl -u '".repeat(2_000)],
      ["a.sh", "mysql ".repeat(3_000)],
      ["a.sh", `htpasswd -b ${"x".repeat(19_000)}`],
      ["a.conf", `${" ".repeat(10_000)}${"pwd x ".repeat(1_500)}`],
      ["a.txt", "password is ".repeat(1_600)],
      [".pgpass", ":".repeat(19_000)],
      [".pgpass", "\\".repeat(19_000)],
    ];
    const started = performance.now();
    for (const [file, line] of lines) redactLine(line, { file });
    expect(performance.now() - started).toBeLessThan(1500);

    // A "kubeconfig" of empty lines, and one of quotes.
    const dir = path.join(temp, "linear");
    writeFile(dir, "kubeconfig", "\n".repeat(60_000));
    writeFile(dir, "config.json", `"auths"${" ".repeat(60_000)}`);
    writeFile(dir, "deploy/admin.conf", `${"\n \t".repeat(20_000)}kind: Config\n`);
    const files = inventory(dir).files;
    const scanStarted = performance.now();
    scanSecrets(files);
    expect(performance.now() - scanStarted).toBeLessThan(1500);
  });
});
