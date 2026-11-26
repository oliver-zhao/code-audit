import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import {
  escapeAnnotationMessage,
  escapeAnnotationProperty,
  renderAnnotations,
  renderStepSummaryMarkdown,
  renderWarningAnnotations,
} from "../src/ci.js";
import { createFinding, type Finding } from "../src/finding.js";
import {
  renderHeadlineMarkdown,
  renderMarkdown,
  summarizeFindings,
  type ReportContext,
} from "../src/report.js";
import { CLI, REPO_ROOT, VULNERABLE, cleanup, makeTempDir } from "./helpers.js";

const temp = makeTempDir("ci");

afterAll(() => cleanup(temp));

function finding(overrides: Record<string, unknown> = {}) {
  return createFinding({
    ruleId: "py-command-injection",
    title: "Command injection",
    category: "sast",
    severity: "high",
    file: "python/app.py",
    startLine: 15,
    evidence: 'os.system("ls " + command)',
    remediation: "Use subprocess with a list.",
    provenance: { engine: "builtin-rules" },
    ...overrides,
  });
}

function advisory(pkg: string, id: string, overrides: Record<string, unknown> = {}): Finding {
  return {
    ...createFinding({
      ruleId: `sca-${id.toLowerCase()}`,
      title: `${pkg}@1.0.0: Advisory ${id}`,
      category: "sca",
      severity: "high",
      confidence: "high",
      file: "uv.lock",
      startLine: 40,
      evidence: `${pkg}@1.0.0`,
      remediation: `Upgrade ${pkg}.`,
      provenance: { engine: "osv" },
      package: pkg,
      ecosystem: "PyPI",
      installedVersion: "1.0.0",
      fixedVersion: "1.2.0",
      advisoryId: id,
      dependencyScope: "runtime",
      dependencyPath: "uv direct dependency",
    }),
    ...overrides,
  } as Finding;
}

const GITHUB = { GITHUB_ACTIONS: "true" } as NodeJS.ProcessEnv;

describe("annotation escaping", () => {
  it("escapes percent, carriage return and newline in messages", () => {
    expect(escapeAnnotationMessage("100% done")).toBe("100%25 done");
    expect(escapeAnnotationMessage("a\rb")).toBe("a%0Db");
    expect(escapeAnnotationMessage("a\nb")).toBe("a%0Ab");
  });

  it("additionally escapes colon and comma in properties", () => {
    expect(escapeAnnotationProperty("a:b")).toBe("a%3Ab");
    expect(escapeAnnotationProperty("a,b")).toBe("a%2Cb");
    expect(escapeAnnotationProperty("a:b,c")).toBe("a%3Ab%2Cc");
  });
});

describe("annotations", () => {
  it("emits one ::error line per high finding when GITHUB_ACTIONS=true", () => {
    const lines = renderAnnotations([finding()], {
      env: { GITHUB_ACTIONS: "true" } as NodeJS.ProcessEnv,
    });
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(/^::error file=python\/app\.py,line=15,title=py-command-injection::/);
  });

  it("uses ::warning for medium and below", () => {
    const lines = renderAnnotations([finding({ severity: "medium" })], {
      env: GITHUB,
      failOn: "medium",
    });
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(/^::warning /);
  });

  it("annotates only findings that count toward the exit code", () => {
    const findings = [
      finding({ startLine: 1, evidence: "a" }),
      // Below --fail-on (default high).
      finding({ startLine: 2, evidence: "b", severity: "medium" }),
      // Below --min-confidence (default medium).
      finding({ startLine: 3, evidence: "c", confidence: "low" }),
      // Existing in the baseline.
      { ...finding({ startLine: 4, evidence: "d" }), baselineState: "existing" } as Finding,
      { ...finding({ startLine: 5, evidence: "e" }), baselineState: "new" } as Finding,
      // A hotspot is never annotated.
      finding({ startLine: 6, evidence: "f", kind: "hotspot" }),
    ];
    const line = (lines: string[]): string[] =>
      lines.map((entry) => /line=(\d+)/.exec(entry)?.[1] ?? "");
    expect(line(renderAnnotations(findings, { env: GITHUB }))).toEqual(["1", "4", "5"]);
    expect(line(renderAnnotations(findings, { env: GITHUB, newOnly: true }))).toEqual(["1", "5"]);
    expect(line(renderAnnotations(findings, { env: GITHUB, failOn: "medium" }))).toEqual(["1", "4", "5", "2"]);
    expect(line(renderAnnotations(findings, { env: GITHUB, minConfidence: "low" }))).toEqual(["1", "3", "4", "5"]);
    expect(renderAnnotations(findings, { env: GITHUB, failOn: "critical" })).toEqual([]);
    // The number of annotations is the number the summary gives for the exit code.
    expect(renderAnnotations(findings, { env: GITHUB, newOnly: true })).toHaveLength(
      summarizeFindings(findings, [], { newOnly: true }).exitCode.counting,
    );
  });

  it("emits one annotation per vulnerable package, not per advisory", () => {
    const findings = [
      ...Array.from({ length: 20 }, (_, index) =>
        advisory("virtualenv", `GHSA-v-${String(index).padStart(2, "0")}`, {
          severity: index === 0 ? "critical" : "high",
        }),
      ),
      advisory("jinja2", "GHSA-j-01", { startLine: 80 }),
      // Does not count: medium severity, and a dev advisory lowered to low.
      advisory("flask", "GHSA-f-01", { severity: "medium" }),
      advisory("pytest", "GHSA-p-01", { confidence: "low", dependencyScope: "dev" }),
      finding(),
    ];
    const lines = renderAnnotations(findings, { env: GITHUB });
    expect(lines).toHaveLength(3);
    expect(lines[0]).toBe(
      "::error file=uv.lock,line=40,title=virtualenv@1.0.0::virtualenv 1.0.0 (runtime dependency): 20 advisories, highest severity critical: GHSA-v-00, GHSA-v-01, GHSA-v-02, GHSA-v-03, GHSA-v-04 +15 more. Recommended upgrade: 1.2.0.",
    );
    expect(lines.filter((entry) => entry.includes("title=jinja2@1.0.0"))).toHaveLength(1);
    expect(lines.join("\n")).toContain("1 advisory, highest severity high: GHSA-j-01.");
    expect(lines.join("\n")).not.toContain("flask");
    expect(lines.join("\n")).not.toContain("pytest");
  });

  it("escapes package names and ids taken from a lockfile", () => {
    const lines = renderAnnotations(
      [advisory("evil\n::error::pkg,x:y", "GHSA-e%0A", { file: "a,b:c.lock" })],
      { env: GITHUB },
    );
    expect(lines).toHaveLength(1);
    expect(lines[0]).not.toContain("\n");
    expect(lines[0]).toMatch(/^::error file=a%2Cb%3Ac\.lock,line=40,title=evil%0A%3A%3Aerror%3A%3Apkg%2Cx%3Ay@1\.0\.0::/);
    expect(lines[0]).toContain("GHSA-e%250A");
  });

  it("applies the cap after folding advisories into packages", () => {
    const findings = Array.from({ length: 60 }, (_, pkg) =>
      Array.from({ length: 3 }, (_, index) => advisory(`package-${pkg}`, `GHSA-${pkg}-${index}`)),
    ).flat();
    expect(renderAnnotations(findings, { env: GITHUB })).toHaveLength(50);
    expect(renderAnnotations(findings, { env: GITHUB, cap: 5 })).toHaveLength(5);
    // Highest severity first, so the cap never hides a critical behind highs.
    const mixed = [...findings, advisory("zzz-last", "GHSA-z", { severity: "critical" })];
    expect(renderAnnotations(mixed, { env: GITHUB })[0]).toContain("title=zzz-last@1.0.0");
  });

  it("emits nothing when GITHUB_ACTIONS is not true", () => {
    expect(
      renderAnnotations([finding()], { env: {} as NodeJS.ProcessEnv }),
    ).toHaveLength(0);
  });

  it("caps the number of annotations at 50", () => {
    const many = Array.from({ length: 80 }, (_, i) =>
      finding({ startLine: i + 1, evidence: `line ${i + 1}` }),
    );
    const lines = renderAnnotations(many, {
      env: { GITHUB_ACTIONS: "true" } as NodeJS.ProcessEnv,
    });
    expect(lines).toHaveLength(50);
  });

  it("never puts secret evidence into an annotation", () => {
    const secret = finding({
      ruleId: "secret-aws-access-key",
      title: "Hardcoded AWS access key",
      message: "Possible plaintext credential; evidence is redacted.",
      evidence: "AKIAFAKEFIXTURE00000",
    });
    const lines = renderAnnotations([secret], {
      env: { GITHUB_ACTIONS: "true" } as NodeJS.ProcessEnv,
    });
    expect(lines[0]).not.toContain("AKIAFAKEFIXTURE");
  });

  it("skips suppressed and false-positive findings", () => {
    const lines = renderAnnotations(
      [
        finding({ status: "suppressed", suppression: { source: "inline", reason: "x" } }),
        finding({ status: "false_positive", startLine: 16 }),
      ],
      { env: { GITHUB_ACTIONS: "true" } as NodeJS.ProcessEnv },
    );
    expect(lines).toHaveLength(0);
  });
});

describe("warning annotations", () => {
  it("emits nothing when GITHUB_ACTIONS is not true", () => {
    expect(
      renderWarningAnnotations(["ignore entry #0 expired on 2020-01-01"], {
        env: {} as NodeJS.ProcessEnv,
      }),
    ).toHaveLength(0);
  });

  it("emits escaped ::warning:: lines and is not capped at 50", () => {
    const warnings = Array.from(
      { length: 60 },
      (_, index) => `warning ${index} 100%`,
    );
    const lines = renderWarningAnnotations(warnings, {
      env: { GITHUB_ACTIONS: "true" } as NodeJS.ProcessEnv,
    });
    expect(lines).toHaveLength(60);
    expect(lines[0]).toBe("::warning::warning 0 100%25");
  });
});

describe("step summary", () => {
  const findings = [
    finding({ severity: "critical" }),
    finding({ startLine: 16, evidence: "x" }),
    finding({ startLine: 17, evidence: "y" }),
    finding({ startLine: 18, evidence: "z", confidence: "low" }),
    advisory("jinja2", "GHSA-j-01"),
  ];
  const hotspots = [finding({ kind: "hotspot", startLine: 30, evidence: "h" })];
  const summary = summarizeFindings(findings, hotspots);
  const empty = summarizeFindings([]);

  it("renders counts, baseline and report paths", () => {
    const md = renderStepSummaryMarkdown({
      summary,
      baseline: { new: 1, existing: 2, fixed: 0 },
      reportPaths: ["/run/report.md"],
    });
    expect(md).toContain("code-audit summary");
    expect(md).toContain("New: 1 · Existing: 2 · Fixed: 0");
    expect(md).toContain("/run/report.md");
    expect(md).toContain("**4 findings count toward the exit code**");
    expect(md).toContain("| **Total** | **1** | **3** | **0** | **0** | **0** | **4** |");
    expect(md).toContain("Low-confidence candidates (confidence below medium, not counted above): 1");
    expect(md).toContain("Review hotspots (uses of dangerous APIs, not counted above): 1");
  });

  it("shows the same headline block as the report cover", () => {
    const block = renderHeadlineMarkdown(summary).join("\n");
    const step = renderStepSummaryMarkdown({ summary, reportPaths: [] });
    expect(step).toContain(block);
    const context: ReportContext = {
      runId: "r",
      target: "/repo",
      startedAt: "2026-01-01T00:00:00.000Z",
      finishedAt: "2026-01-01T00:00:01.000Z",
      durationMs: 1,
      toolVersion: "0.1.0",
      nodeVersion: "v24.0.0",
      profile: "standard",
      offline: true,
      lang: "en",
      rules: [],
      findings,
      hotspots,
      coverage: {
        root: "/repo",
        stats: { files: 0, scannedFiles: 0, skippedFiles: 0, loc: 0 },
        languages: {},
        scannedFiles: [],
        skipped: [],
        manifests: [],
        engines: [],
        rulesCount: 0,
        warnings: [],
        suppressed: [],
      },
      warnings: [],
    };
    expect(renderMarkdown(context)).toContain(block);
  });

  it("renders a Warnings section when warnings are present", () => {
    const md = renderStepSummaryMarkdown({
      summary: empty,
      reportPaths: [],
      warnings: ["ignore entry #0 expired on 2020-01-01", "bad file <img src=x>|[a](javascript:1)"],
    });
    expect(md).toContain("### Warnings");
    expect(md).toContain("ignore entry #0 expired on 2020-01-01");
    // Warnings can quote repository file names.
    expect(md).not.toContain("<img");
    expect(md).not.toContain("](javascript:");
  });

  it("is appended, not overwritten, by the CLI", () => {
    // The CLI opens GITHUB_STEP_SUMMARY with appendFileSync; verify the helper
    // output is plain appendable text (no leading truncation markers).
    const md = renderStepSummaryMarkdown({ summary: empty, reportPaths: [] });
    const file = path.join(temp, "summary.md");
    fs.writeFileSync(file, "existing\n", "utf8");
    fs.appendFileSync(file, md, "utf8");
    const content = fs.readFileSync(file, "utf8");
    expect(content.startsWith("existing\n")).toBe(true);
    expect(content).toContain("code-audit summary");
  });
});

describe("CLI summary and exit code", () => {
  function scan(args: string[], env: Record<string, string> = {}) {
    return spawnSync(
      process.execPath,
      [CLI, "scan", VULNERABLE, "--offline", "--no-external", "--no-ignore-file", "--no-baseline", ...args],
      { cwd: REPO_ROOT, encoding: "utf8", timeout: 60_000, env: { ...process.env, ...env } },
    );
  }
  function document(out: string) {
    const runDir = path.join(out, fs.readdirSync(out)[0] as string);
    return {
      runDir,
      json: JSON.parse(fs.readFileSync(path.join(runDir, "findings.json"), "utf8")) as {
        run: { summary: ReturnType<typeof summarizeFindings> };
        findings: Finding[];
        hotspots: Finding[];
      },
    };
  }

  it("prints the numbers of run.summary and explains the exit code", () => {
    const out = path.join(temp, "cli-summary");
    const result = scan(["--out", out]);
    const { runDir, json } = document(out);
    const summary = json.run.summary;
    expect(summary).toEqual(summarizeFindings(json.findings, json.hotspots));
    expect(summary.headline.total).toBeGreaterThan(0);
    expect(summary.lowConfidence.total + summary.headline.total).toBe(
      json.findings.filter((entry) => entry.status !== "suppressed" && entry.status !== "false_positive").length,
    );
    const severity = summary.headline.bySeverity;
    expect(result.stdout).toContain(
      `Findings: ${summary.headline.total} (critical ${severity.critical}, high ${severity.high}, medium ${severity.medium}, low ${severity.low}, info ${severity.info}) at confidence >= medium`,
    );
    expect(result.stdout).toContain(`Low-confidence candidates: ${summary.lowConfidence.total} (not counted above`);
    expect(result.stdout).toContain(`Hotspots: ${summary.hotspots} (not counted above)`);
    expect(result.stdout).toContain(
      `Exit code: 1 - ${summary.exitCode.counting} findings count toward the exit code (severity >= high, confidence >= medium)`,
    );
    expect(result.status).toBe(1);
    // The Markdown cover gives the same verdict and total.
    const md = fs.readFileSync(path.join(runDir, "report.md"), "utf8");
    expect(md).toContain(`**${summary.exitCode.counting} findings count toward the exit code**`);
    expect(md).toContain(renderHeadlineMarkdown(summary).join("\n"));
  });

  it("follows --fail-on and --min-confidence in the printed numbers and the exit code", () => {
    const out = path.join(temp, "cli-summary-strict");
    const result = scan(["--out", out, "--fail-on", "critical", "--min-confidence", "high"]);
    const { json } = document(out);
    const summary = json.run.summary;
    expect(summary.thresholds).toMatchObject({ failOn: "critical", minConfidence: "high" });
    expect(result.status).toBe(summary.exitCode.code);
    expect(result.stdout).toContain(`Exit code: ${summary.exitCode.code} - `);
    expect(result.stdout).toContain("(severity >= critical, confidence >= high)");
    expect(result.stdout).toContain(") at confidence >= high");
    // Raising the threshold moves findings from the headline to the candidates.
    const standard = document(path.join(temp, "cli-summary")).json.run.summary;
    expect(summary.headline.total).toBeLessThan(standard.headline.total);
    expect(summary.headline.total + summary.lowConfidence.total).toBe(
      standard.headline.total + standard.lowConfidence.total,
    );
  });

  it("--ci prints the headline table and annotates exactly the counting findings", () => {
    const out = path.join(temp, "cli-summary-ci");
    const result = scan(["--out", out, "--ci"], { GITHUB_ACTIONS: "true" });
    const { json } = document(out);
    const summary = json.run.summary;
    expect(result.stdout).toContain(renderHeadlineMarkdown(summary).join("\n"));
    const annotations = result.stdout.split("\n").filter((line) => /^::(error|warning) file=/.test(line));
    expect(annotations).toHaveLength(Math.min(50, summary.exitCode.counting));
  });
});
