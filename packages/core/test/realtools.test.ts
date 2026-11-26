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
    extra?: {
      message?: string;
      severity?: string;
      metadata?: { confidence?: string; cwe?: string | string[] };
    };
  }>;
  errors: unknown[];
}

const OPENGREP_RULES_DIR = path.join(REPO_ROOT, "rules/opengrep");

async function runOpengrep(root: string): Promise<RawOpengrep> {
  // Same arguments as the adapter (sastArgs in src/external/semgrep.ts).
  const result = await runTool(opengrep as string, [
    "scan",
    "--json",
    "--quiet",
    "--disable-version-check",
    "--config",
    OPENGREP_RULES_DIR,
    root,
  ], { cwd: root, timeoutMs: 60_000 });
  const document = JSON.parse(result.stdout) as Partial<RawOpengrep>;
  return { results: document.results ?? [], errors: document.errors ?? [] };
}

interface Hit {
  file: string;
  line: number;
  ruleId: string;
  confidence: string;
}

/** Normalize raw results to root-relative POSIX paths and bare rule ids. */
function toHits(raw: RawOpengrep, root: string, knownIds: Set<string>): Hit[] {
  return raw.results.map((entry) => ({
    file: path
      .relative(root, path.resolve(root, entry.path))
      .split(path.sep)
      .join("/"),
    line: entry.start?.line ?? 0,
    ruleId: resolveRuleId(entry.check_id, knownIds),
    confidence: (entry.extra?.metadata?.confidence ?? "").toLowerCase(),
  }));
}

const hitKey = (hit: { file: string; line: number; ruleId: string }): string =>
  `${hit.file}:${hit.line}:${hit.ruleId}`;

/** The fixture files that hold the taint seeds (and nothing else). */
const isTaintFixture = (file: string): boolean =>
  /^python\/taint_[a-z0-9_]+\.py$/.test(file);

const TAINT_RULE_IDS = [
  "py-taint-sql",
  "py-taint-command",
  "py-taint-path",
  "py-taint-ssrf",
  "py-taint-template",
  "py-taint-redirect",
  "py-taint-deserialization",
  "py-taint-eval",
];

describe.skipIf(!hasAll)("real external tools", () => {
  it("opengrep reports 0 rule errors, every expected hit on the vulnerable fixture and nothing medium+ on clean", async () => {
    const vulnerable = await runOpengrep(VULNERABLE);
    expect(vulnerable.errors).toEqual([]);
    const ruleSet = loadOpengrepRules(OPENGREP_RULES_DIR);
    expect(ruleSet.errors).toEqual([]);
    const knownIds = new Set(ruleSet.rules.map((rule) => rule.id));
    const hits = toHits(vulnerable, VULNERABLE, knownIds);
    const byKey = new Map(hits.map((hit) => [hitKey(hit), hit]));
    const expected = loadExpected().opengrep ?? [];
    expect(expected.length).toBeGreaterThanOrEqual(12);
    // Every expected entry is matched on file, line, rule id and confidence.
    const missing = expected.filter((hit) => !byKey.has(hitKey(hit)));
    expect(missing).toEqual([]);
    for (const hit of expected) {
      expect(byKey.get(hitKey(hit))?.confidence).toBe(hit.confidence.toLowerCase());
    }
    // Every rule that ships in rules/opengrep has at least one expected hit.
    const expectedIds = new Set(expected.map((hit) => hit.ruleId));
    expect([...knownIds].filter((id) => !expectedIds.has(id))).toEqual([]);

    const clean = await runOpengrep(CLEAN);
    expect(clean.errors).toEqual([]);
    const mediumPlus = clean.results.filter((entry) =>
      ["MEDIUM", "HIGH"].includes(
        (entry.extra?.metadata?.confidence ?? "").toUpperCase(),
      ),
    );
    expect(mediumPlus).toEqual([]);
  }, 120_000);

  it("taint rules report exactly the seeded flows and stay silent on clean", async () => {
    const ruleSet = loadOpengrepRules(OPENGREP_RULES_DIR);
    const knownIds = new Set(ruleSet.rules.map((rule) => rule.id));
    const taintRules = ruleSet.rules.filter((rule) => rule.id.includes("taint"));
    expect(taintRules.map((rule) => rule.id).sort()).toEqual([...TAINT_RULE_IDS].sort());
    for (const rule of taintRules) {
      expect(rule.languages).toEqual(["python"]);
      expect(rule.cwe).toMatch(/^CWE-\d+$/);
    }

    const root = path.join(VULNERABLE, "python");
    const vulnerable = await runOpengrep(root);
    expect(vulnerable.errors).toEqual([]);
    for (const entry of vulnerable.results) {
      if (!entry.check_id.includes("py-taint-")) continue;
      expect(entry.extra?.metadata?.cwe).toMatch(/^CWE-\d+$/);
      expect(["HIGH", "MEDIUM"]).toContain(entry.extra?.metadata?.confidence);
      expect(["ERROR", "WARNING"]).toContain(entry.extra?.severity);
      expect((entry.extra?.message ?? "").length).toBeGreaterThan(40);
    }

    // In the taint seed files the real results and EXPECTED.json agree in
    // both directions: no seeded flow is missed and nothing else is reported.
    const actual = toHits(vulnerable, root, knownIds)
      .map((hit) => ({ ...hit, file: `python/${hit.file}` }))
      .filter((hit) => isTaintFixture(hit.file));
    const expected = (loadExpected().opengrep ?? []).filter((hit) =>
      isTaintFixture(hit.file),
    );
    expect(actual.map(hitKey).sort()).toEqual(expected.map(hitKey).sort());

    // Every taint rule is seeded with at least one flow in each of the three
    // framework files (Flask, Django, FastAPI/Starlette).
    for (const file of ["python/taint_app.py", "python/taint_django.py", "python/taint_fastapi.py"]) {
      const ids = new Set(actual.filter((hit) => hit.file === file).map((hit) => hit.ruleId));
      for (const id of TAINT_RULE_IDS) {
        expect(ids.has(id), `${id} in ${file}`).toBe(true);
      }
    }

    // The clean counterparts read the same request data but are sanitized,
    // parameterized or constant: no taint rule may report anywhere under
    // clean/python, and no rule of any kind in the clean taint files.
    const cleanRoot = path.join(CLEAN, "python");
    const clean = await runOpengrep(cleanRoot);
    expect(clean.errors).toEqual([]);
    const cleanTaint = toHits(clean, cleanRoot, knownIds).filter(
      (hit) => hit.ruleId.includes("taint") || isTaintFixture(`python/${hit.file}`),
    );
    expect(cleanTaint).toEqual([]);
  }, 120_000);

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