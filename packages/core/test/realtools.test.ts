import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import {
  findExecutable,
  loadOpengrepRules,
  resolveRuleId,
  runGitleaks,
  runOsvScanner,
  runTool,
} from "../src/external/index.js";
import { scanProject } from "../src/scan.js";
import {
  CLEAN,
  REPO_ROOT,
  VULNERABLE,
  cleanup,
  loadExpected,
  makeTempDir,
} from "./helpers.js";

// These tests exercise the real scanners in .tools/bin (or on PATH). They skip
// themselves when a tool is absent so the suite still passes on a machine
// without the real tools. The unit tests use fake executables only.

const temp = makeTempDir("realtools");

afterAll(() => cleanup(temp));

const toolsBin = path.join(REPO_ROOT, ".tools", "bin");
const pathEnv = [toolsBin, process.env.PATH ?? ""].join(path.delimiter);
const opengrep = findExecutable("opengrep", pathEnv);
const osvScanner = findExecutable("osv-scanner", pathEnv);
const gitleaks = findExecutable("gitleaks", pathEnv);
const hasAll = Boolean(opengrep && osvScanner && gitleaks);

interface RawOpengrep {
  results: Array<{
    check_id: string;
    path: string;
    start?: { line?: number };
    extra?: { metadata?: { confidence?: string } };
  }>;
  errors: unknown[];
}

async function runOpengrep(root: string): Promise<RawOpengrep> {
  const result = await runTool(opengrep as string, [
    "scan",
    "--json",
    "--quiet",
    "--disable-version-check",
    "--config",
    path.join(REPO_ROOT, "rules/opengrep"),
    root,
  ], { cwd: root, timeoutMs: 60_000 });
  const document = JSON.parse(result.stdout) as Partial<RawOpengrep>;
  return { results: document.results ?? [], errors: document.errors ?? [] };
}

describe.skipIf(!hasAll)("real external tools", () => {
  it("opengrep reports 0 rule errors, matches every rule on the vulnerable fixture and nothing medium+ on clean", async () => {
    const vulnerable = await runOpengrep(VULNERABLE);
    expect(vulnerable.errors).toEqual([]);
    const knownIds = new Set(
      loadOpengrepRules(path.join(REPO_ROOT, "rules/opengrep")).rules.map(
        (rule) => rule.id,
      ),
    );
    const ids = new Set(
      vulnerable.results.map((entry) => resolveRuleId(entry.check_id, knownIds)),
    );
    const expected = loadExpected().opengrep ?? [];
    expect(expected.length).toBeGreaterThanOrEqual(12);
    for (const hit of expected) {
      expect(ids.has(hit.ruleId)).toBe(true);
    }

    const clean = await runOpengrep(CLEAN);
    expect(clean.errors).toEqual([]);
    const mediumPlus = clean.results.filter((entry) =>
      ["MEDIUM", "HIGH"].includes(
        (entry.extra?.metadata?.confidence ?? "").toUpperCase(),
      ),
    );
    expect(mediumPlus).toEqual([]);
  });

  it("osv-scanner parses real vulnerabilities and lockfile paths", async () => {
    const result = await runOsvScanner({
      root: VULNERABLE,
      toolPath: osvScanner as string,
      version: "2.7.1",
      timeoutMs: 60_000,
    });
    expect(result.ok).toBe(true);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.reportedFiles.length).toBeGreaterThan(0);
    expect(result.warnings).toEqual([]);
  });

  it("gitleaks finds the planted secret and never stores it in clear text", async () => {
    const result = await runGitleaks({
      root: VULNERABLE,
      toolPath: gitleaks as string,
      version: "8.30.1",
      timeoutMs: 60_000,
    });
    expect(result.findings.length).toBeGreaterThan(0);
    for (const finding of result.findings) {
      expect(finding.evidence).not.toContain("BEGIN");
      expect(finding.provenance.engine).toBe("gitleaks");
    }
  });

  it("runs the three engines in parallel and merges cross-engine duplicates", async () => {
    const result = await scanProject({
      root: VULNERABLE,
      out: path.join(temp, "scan-out"),
      offline: false,
      formats: ["json"],
      pathEnv,
    });
    const statuses = new Map(
      result.coverage.engines.map((engine) => [engine.name, engine.status]),
    );
    expect(statuses.get("opengrep")).toBe("ok");
    expect(statuses.get("osv-scanner")).toBe("ok");
    expect(statuses.get("gitleaks")).toBe("ok");

    const merged = result.findings.filter(
      (finding) => (finding.provenance.engines?.length ?? 0) > 1,
    );
    expect(
      merged.some(
        (finding) =>
          finding.provenance.engines?.includes("gitleaks") &&
          finding.provenance.engines?.includes("builtin-secrets"),
      ),
    ).toBe(true);
    expect(
      merged.some(
        (finding) =>
          finding.provenance.engines?.includes("opengrep") &&
          finding.provenance.engines?.includes("builtin-rules"),
      ),
    ).toBe(true);

    // Parallel execution: the wall-clock total is below the sum of the
    // individual external-engine durations.
    const durations = result.coverage.engines
      .map((engine) => engine.durationMs)
      .filter((value): value is number => typeof value === "number");
    const sum = durations.reduce((total, value) => total + value, 0);
    expect(result.durationMs).toBeLessThan(sum);
  }, 60_000);
});