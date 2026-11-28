/**
 * Counting model and report layout, tested with hand-made findings so the
 * tests do not depend on what a scan of the fixtures happens to produce.
 */
import { describe, expect, it } from "vitest";
import { createFinding, type Finding } from "../src/finding.js";
import {
  REPORT_LABELS,
  countsTowardExitCode,
  groupVulnerablePackages,
  renderFindingsJson,
  renderHeadlineMarkdown,
  renderMarkdown,
  renderSarif,
  renderSummaryText,
  summarizeFindings,
  type ReportContext,
} from "../src/report.js";

let serial = 0;

function code(overrides: Record<string, unknown> = {}): Finding {
  serial += 1;
  return {
    ...createFinding({
      ruleId: "py-command-injection",
      title: "Command injection",
      category: "sast",
      severity: "high",
      confidence: "high",
      file: "src/app.py",
      startLine: serial,
      evidence: `os.system("ls " + command${serial})`,
      message: "Request data reaches a shell command.",
      remediation: "Use subprocess with an argument list.",
      provenance: { engine: "builtin-rules" },
    }),
    id: `AUD-2026-${String(serial).padStart(4, "0")}`,
    ...overrides,
  } as Finding;
}

function advisory(
  pkg: string,
  version: string,
  id: string,
  overrides: Record<string, unknown> = {},
): Finding {
  serial += 1;
  return {
    ...createFinding({
      ruleId: `sca-${id.toLowerCase()}`,
      title: `${pkg}@${version}: Advisory ${id}`,
      category: "sca",
      severity: "high",
      confidence: "high",
      file: "uv.lock",
      startLine: 10,
      evidence: `${pkg}@${version}`,
      message: `Details of ${id}.`,
      remediation: `Upgrade ${pkg}.`,
      provenance: { engine: "osv" },
      package: pkg,
      ecosystem: "PyPI",
      installedVersion: version,
      fixedVersion: `${version.split(".")[0]}.99.0`,
      advisoryId: id,
      dependencyPath: "uv direct dependency",
      dependencyScope: "runtime",
    }),
    id: `AUD-2026-${String(serial).padStart(4, "0")}`,
    ...overrides,
  } as Finding;
}

function hotspot(overrides: Record<string, unknown> = {}): Finding {
  return code({
    ruleId: "py-eval-api",
    title: "eval with a non-literal argument",
    kind: "hotspot",
    confidence: "low",
    ...overrides,
  });
}

function context(
  findings: Finding[],
  hotspots: Finding[] = [],
  overrides: Partial<ReportContext> = {},
): ReportContext {
  return {
    runId: "20260101T000000Z-test",
    target: "/repo",
    startedAt: "2026-01-01T00:00:00.000Z",
    finishedAt: "2026-01-01T00:00:01.000Z",
    durationMs: 1000,
    toolVersion: "0.1.0",
    nodeVersion: "v24.0.0",
    profile: "standard",
    offline: false,
    lang: "en",
    rules: [],
    findings,
    hotspots,
    coverage: {
      root: "/repo",
      stats: { files: 1, scannedFiles: 1, skippedFiles: 0, loc: 10 },
      languages: { python: { files: 1, loc: 10 } },
      scannedFiles: [],
      skipped: [],
      manifests: [],
      engines: [{ name: "builtin-rules", enabled: true, status: "ok" }],
      rulesCount: 0,
      warnings: [],
      suppressed: [],
    },
    warnings: [],
    ...overrides,
  };
}

/** A mixed run: every bucket of the counting model has at least one member. */
function mixed(): { findings: Finding[]; hotspots: Finding[] } {
  const findings = [
    code({ severity: "critical" }),
    code({ severity: "high", confidence: "medium" }),
    code({ severity: "medium" }),
    // Low confidence: a candidate, never in the headline.
    code({ confidence: "low" }),
    // Lowered by path context from high to low: out of the headline, visibly.
    code({
      file: "tests/test_app.py",
      confidence: "low",
      confidenceOriginal: "high",
      adjustments: ["path-context:test"],
      pathContext: "test",
    }),
    // Lowered but still at the threshold: stays in the headline.
    code({
      category: "secrets",
      ruleId: "secret-generic-assignment",
      title: "Hardcoded secret",
      file: "docs/setup.md",
      confidence: "medium",
      confidenceOriginal: "high",
      adjustments: ["path-context:docs"],
      pathContext: "docs",
      evidence: 'password = "************"',
    }),
    code({
      category: "secrets",
      ruleId: "secret-generic-assignment",
      title: "Hardcoded secret",
      confidence: "low",
      confidenceOriginal: "high",
      adjustments: ["placeholder-value"],
      evidence: 'password = "********"',
    }),
    code({ category: "config", ruleId: "dockerfile-no-user", title: "No USER", file: "Dockerfile" }),
    // Not active.
    code({ status: "suppressed", suppression: { source: "inline", reason: "trust me" } }),
    code({ status: "suppressed", suppression: { source: "ignore-file", reason: "legacy", entry: 0 } }),
    code({ status: "false_positive" }),
    // Dependencies: 3 advisories in one runtime package, 2 in a dev package
    // (lowered to medium), 1 unknown scope, 1 dev advisory lowered to low.
    advisory("jinja2", "3.1.2", "GHSA-aaaa-0001", { severity: "critical" }),
    advisory("jinja2", "3.1.2", "GHSA-aaaa-0002"),
    advisory("jinja2", "3.1.2", "GHSA-aaaa-0003", { severity: "medium" }),
    advisory("virtualenv", "20.0.0", "GHSA-bbbb-0001", {
      dependencyScope: "dev",
      dependencyPath: "uv dev dependency",
      confidence: "medium",
      confidenceOriginal: "high",
      adjustments: ["dev-dependency"],
    }),
    advisory("virtualenv", "20.0.0", "GHSA-bbbb-0002", {
      dependencyScope: "dev",
      dependencyPath: "uv dev dependency",
      confidence: "medium",
      confidenceOriginal: "high",
      adjustments: ["dev-dependency"],
    }),
    advisory("requests", "2.0.0", "GHSA-cccc-0001", {
      dependencyScope: "unknown",
      file: "requirements.txt",
      dependencyPath: "requirements direct dependency",
    }),
    advisory("pytest", "7.0.0", "GHSA-dddd-0001", {
      dependencyScope: "optional",
      confidence: "low",
      confidenceOriginal: "high",
      adjustments: ["dev-dependency"],
    }),
  ];
  const hotspots = [
    hotspot(),
    hotspot({ startLine: 900 }),
    hotspot({ status: "suppressed", suppression: { source: "inline", reason: "" } }),
  ];
  return { findings, hotspots };
}

describe("counting model", () => {
  it("counts only active findings at or above --min-confidence in the headline", () => {
    const { findings, hotspots } = mixed();
    const summary = summarizeFindings(findings, hotspots);
    expect(summary.thresholds).toEqual({ minConfidence: "medium", failOn: "high", newOnly: false });
    // 3 code + 1 secret (docs, medium) + 1 config + 6 advisories.
    expect(summary.headline.total).toBe(11);
    expect(summary.headline.byCategory).toEqual({ code: 3, secrets: 1, config: 1, dependencies: 6 });
    expect(summary.headline.bySeverity).toEqual({ critical: 2, high: 7, medium: 2, low: 0, info: 0 });
    expect(summary.headline.matrix.code).toEqual({ critical: 1, high: 1, medium: 1, low: 0, info: 0 });
    // Every breakdown adds up to the headline total.
    const sum = (values: Record<string, number>): number =>
      Object.values(values).reduce((a, b) => a + b, 0);
    expect(sum(summary.headline.bySeverity)).toBe(summary.headline.total);
    expect(sum(summary.headline.byCategory)).toBe(summary.headline.total);
  });

  it("keeps low-confidence candidates, hotspots, suppressed and false positives separate", () => {
    const { findings, hotspots } = mixed();
    const summary = summarizeFindings(findings, hotspots);
    expect(summary.lowConfidence.total).toBe(4);
    expect(summary.lowConfidence.byCategory).toEqual({ code: 2, secrets: 1, config: 0, dependencies: 1 });
    expect(summary.lowConfidence.dependencies).toEqual({ advisories: 1, vulnerablePackages: 1 });
    expect(summary.hotspots).toBe(2);
    expect(summary.suppressed).toEqual({ total: 3, ignoreFile: 1, inline: 2 });
    expect(summary.falsePositives).toBe(1);
  });

  it("reports advisories and distinct vulnerable packages, split by scope", () => {
    const { findings } = mixed();
    const summary = summarizeFindings(findings);
    expect(summary.dependencies.advisories).toBe(6);
    expect(summary.dependencies.vulnerablePackages).toBe(3);
    expect(summary.dependencies.byScope).toEqual({
      runtime: { advisories: 3, vulnerablePackages: 1 },
      devOptional: { advisories: 2, vulnerablePackages: 1 },
      unknown: { advisories: 1, vulnerablePackages: 1 },
    });
  });

  it("counts one package once across lockfiles and PyPI name spellings", () => {
    const summary = summarizeFindings([
      advisory("PyYAML", "5.1", "GHSA-x-1", { file: "requirements.txt", dependencyScope: "unknown" }),
      advisory("pyyaml", "5.1", "GHSA-x-1", { file: "lab/requirements.txt", dependencyScope: "runtime" }),
      advisory("pyyaml", "5.2", "GHSA-x-1", { file: "other/requirements.txt", dependencyScope: "dev" }),
    ]);
    expect(summary.dependencies.advisories).toBe(3);
    expect(summary.dependencies.vulnerablePackages).toBe(2);
    // A package that is runtime in any lockfile is a runtime package.
    expect(summary.dependencies.byScope.runtime.vulnerablePackages).toBe(1);
    expect(summary.dependencies.byScope.devOptional.vulnerablePackages).toBe(1);
    expect(summary.dependencies.byScope.unknown.vulnerablePackages).toBe(0);
  });

  it("shows how many findings had their confidence lowered and why", () => {
    const { findings, hotspots } = mixed();
    const summary = summarizeFindings(findings, hotspots);
    expect(summary.confidenceLowered).toEqual({
      total: 6,
      outOfHeadline: 3,
      pathContext: 2,
      placeholder: 1,
      devDependency: 3,
      optionalDependency: 0,
      other: 0,
    });
    expect(summary.pathContext).toEqual({ test: 1, docs: 1 });
  });

  it("cannot be shrunk silently: findings lowered out of the headline are reported everywhere", () => {
    // A hostile repository puts all its code under tests/.
    const findings = Array.from({ length: 5 }, () =>
      code({
        file: "tests/evil.py",
        severity: "critical",
        confidence: "low",
        confidenceOriginal: "high",
        adjustments: ["path-context:test"],
        pathContext: "test",
      }),
    );
    const summary = summarizeFindings(findings);
    expect(summary.headline.total).toBe(0);
    expect(summary.exitCode).toEqual({ counting: 0, code: 0 });
    expect(summary.lowConfidence.total).toBe(5);
    expect(summary.confidenceLowered).toMatchObject({ total: 5, outOfHeadline: 5, pathContext: 5 });

    const text = renderSummaryText(summary).join("\n");
    expect(text).toContain("Low-confidence candidates: 5");
    expect(text).toContain("Confidence lowered: 5 (path context 5,");
    expect(text).toContain("5 dropped below the threshold");
    const cover = renderHeadlineMarkdown(summary).join("\n");
    expect(cover).toContain("Confidence lowered by the scan on 5 active findings: path context 5");
    expect(cover).toContain("5 of them dropped below the threshold");
    const md = renderMarkdown(context(findings));
    expect(md).toContain("tests/evil.py:");
    expect(md).toContain("(high → low)");
    // With --min-confidence low they are headline findings again.
    expect(summarizeFindings(findings, [], { minConfidence: "low" }).headline.total).toBe(5);
    expect(summarizeFindings(findings, [], { minConfidence: "low" }).exitCode.code).toBe(1);
  });

  it("treats a finding with adjustments but no confidenceOriginal as lowered", () => {
    const summary = summarizeFindings([code({ confidence: "low", adjustments: ["something-new"] })]);
    expect(summary.confidenceLowered).toMatchObject({ total: 1, outOfHeadline: 1, other: 1 });
  });

  it("follows --min-confidence and --fail-on", () => {
    const { findings, hotspots } = mixed();
    const strict = summarizeFindings(findings, hotspots, { minConfidence: "high" });
    // high-confidence only: 2 code + 1 config + 4 advisories (jinja2 x3, requests).
    expect(strict.headline.total).toBe(7);
    expect(strict.lowConfidence.total).toBe(8);
    const loose = summarizeFindings(findings, hotspots, { minConfidence: "low" });
    expect(loose.headline.total).toBe(15);
    expect(loose.lowConfidence.total).toBe(0);
    for (const summary of [strict, loose]) {
      expect(summary.headline.total + summary.lowConfidence.total).toBe(15);
    }
  });

  it("explains the exit code with the same rule the CLI uses", () => {
    const { findings, hotspots } = mixed();
    const options = { failOn: "high", minConfidence: "medium" } as const;
    const summary = summarizeFindings(findings, hotspots, options);
    const counting = findings.filter((finding) => countsTowardExitCode(finding, options));
    // critical + high code, docs secret, config, 2 jinja2, 2 virtualenv, requests.
    expect(counting).toHaveLength(9);
    expect(summary.exitCode).toEqual({ counting: 9, code: 1 });
    expect(renderSummaryText(summary).at(-1)).toBe(
      "Exit code: 1 - 9 findings count toward the exit code (severity >= high, confidence >= medium)",
    );

    expect(summarizeFindings(findings, hotspots, { failOn: "critical" }).exitCode.counting).toBe(2);
    // Suppressed, false-positive and hotspot records never count.
    expect(countsTowardExitCode(code({ status: "suppressed" }))).toBe(false);
    expect(countsTowardExitCode(code({ status: "false_positive" }))).toBe(false);
    expect(countsTowardExitCode(hotspot({ confidence: "high" }))).toBe(false);
    expect(countsTowardExitCode(code({ confidence: "low" }))).toBe(false);
    expect(countsTowardExitCode(code({ severity: "medium" }))).toBe(false);
  });

  it("counts only new findings toward the exit code when a baseline is active", () => {
    const findings = [
      code({ baselineState: "existing" }),
      code({ baselineState: "existing" }),
      code({ baselineState: "new" }),
    ];
    const summary = summarizeFindings(findings, [], { newOnly: true });
    // The headline still shows everything that is there.
    expect(summary.headline.total).toBe(3);
    expect(summary.exitCode).toEqual({ counting: 1, code: 1 });
    expect(renderSummaryText(summary).at(-1)).toBe(
      "Exit code: 1 - 1 finding counts toward the exit code (severity >= high, confidence >= medium, new since the baseline only)",
    );
    expect(summarizeFindings(findings).exitCode.counting).toBe(3);
  });

  it("writes the same summary into findings.json run.summary", () => {
    const { findings, hotspots } = mixed();
    const document = JSON.parse(
      renderFindingsJson({ runId: "r", failOn: "critical", minConfidence: "high" }, findings, hotspots),
    );
    expect(document.run.summary).toEqual(
      summarizeFindings(findings, hotspots, { failOn: "critical", minConfidence: "high" }),
    );
    expect(document.findings).toHaveLength(findings.length);
    // A baseline in the run record means "new only".
    const withBaseline = JSON.parse(
      renderFindingsJson({ runId: "r", baseline: { new: 0 } }, [code({ baselineState: "existing" })]),
    );
    expect(withBaseline.run.summary.thresholds.newOnly).toBe(true);
    expect(withBaseline.run.summary.exitCode.code).toBe(0);
  });
});

describe("headline block", () => {
  it("is identical on the Markdown cover and in the step summary source", () => {
    const { findings, hotspots } = mixed();
    const summary = summarizeFindings(findings, hotspots);
    const block = renderHeadlineMarkdown(summary).join("\n");
    expect(renderMarkdown(context(findings, hotspots))).toContain(block);
    expect(block).toContain("**9 findings count toward the exit code** (severity ≥ high, confidence ≥ medium); a scan with these thresholds exits 1.");
    expect(block).toContain("| Code | 1 | 1 | 1 | 0 | 0 | 3 |");
    expect(block).toContain("| Dependencies (advisories) | 1 | 4 | 1 | 0 | 0 | 6 |");
    expect(block).toContain("| **Total** | **2** | **7** | **2** | **0** | **0** | **11** |");
    expect(block).toContain(
      "Dependency advisories: 6 · vulnerable packages (distinct package@version): 3 — by scope, advisories / packages: runtime 3 / 1 · dev/optional 2 / 1 · unknown scope 1 / 1",
    );
    expect(block).toContain("Low-confidence candidates (confidence below medium, not counted above): 4");
    expect(block).toContain("Review hotspots (uses of dangerous APIs, not counted above): 2");
    expect(block).toContain("3 suppressed (ignore file 1, inline comments 2) · 1 marked false positive");
  });

  it("says so when nothing counts toward the exit code", () => {
    const block = renderHeadlineMarkdown(summarizeFindings([code({ severity: "low" })])).join("\n");
    expect(block).toContain("**No finding counts toward the exit code**");
    expect(block).toContain("exits 0");
  });

  it("has every label in both languages", () => {
    const en = REPORT_LABELS.en as Record<string, string>;
    const zh = REPORT_LABELS.zh as Record<string, string>;
    expect(Object.keys(zh).sort()).toEqual(Object.keys(en).sort());
    const placeholders = (text: string): string[] => (text.match(/\{\w+\}/g) ?? []).sort();
    for (const key of Object.keys(en)) {
      expect(zh[key], key).toBeTruthy();
      expect(placeholders(zh[key] as string), key).toEqual(placeholders(en[key] as string));
    }
    // No English sentence labels leak into the Chinese report.
    const { findings, hotspots } = mixed();
    const md = renderMarkdown(context(findings, hotspots, { lang: "zh" }));
    for (const phrase of ["count toward", "Low-confidence", "Top risks", "Recommended upgrade", "Run details", "advisories", "None."]) {
      expect(md, phrase).not.toContain(phrase);
    }
    expect(md).toContain("9 条发现计入退出码");
  });
});

describe("dependency aggregation", () => {
  it("renders one row per package version per lockfile, runtime first and dev under its own heading", () => {
    const { findings } = mixed();
    const md = renderMarkdown(context(findings));
    const start = md.indexOf("Dependency Vulnerabilities");
    const section = md.slice(start, md.indexOf("\n## ", start));
    const rows = section.split("\n").filter((line) => /^\| (jinja2|virtualenv|requests|pytest) /.test(line));
    expect(rows).toHaveLength(4);
    expect(rows[0]).toBe(
      "| jinja2 | 3.1.2 | runtime | direct | 3 | critical | 3.99.0 | GHSA-aaaa-0001, GHSA-aaaa-0002, GHSA-aaaa-0003 | uv.lock:10 |",
    );
    expect(rows[1]).toMatch(/^\| requests \| 2\.0\.0 \| unknown \| direct \| 1 \| high \|/);
    const devHeading = section.indexOf("### Development and optional dependencies");
    expect(devHeading).toBeGreaterThan(section.indexOf(rows[1] as string));
    expect(section.indexOf("| virtualenv | 20.0.0 | dev |")).toBeGreaterThan(devHeading);
    // The low-confidence dev advisory is still listed, and marked.
    expect(section).toContain("| pytest | 7.0.0 | optional | direct | 1 (all low confidence) | high |");
    // Per-advisory detail only for critical/high advisories of runtime packages.
    expect(section).toContain("<summary>jinja2 3.1.2 — critical/high advisories: 2 — uv.lock</summary>");
    expect(section).toContain("- **CRITICAL** GHSA-aaaa-0001");
    expect(section).not.toContain("- **MEDIUM** GHSA-aaaa-0003");
    expect(section).not.toContain("<summary>virtualenv");
    expect(section).not.toContain("<summary>requests");
    expect(section).toContain("Advisory findings: 7 (distinct advisory ids: 7) · vulnerable package versions: 4 · table rows: 4 · lockfiles: 2.");
  });

  it("shows the first advisory ids and a +N more marker", () => {
    const findings = Array.from({ length: 20 }, (_, index) =>
      advisory("virtualenv", "20.0.0", `GHSA-many-${String(index).padStart(4, "0")}`),
    );
    const md = renderMarkdown(context(findings));
    expect(md).toContain("| 20 | high | 20.99.0 | GHSA-many-0000, GHSA-many-0001, GHSA-many-0002 +17 more |");
    // One table row, not twenty, and the detail block is capped.
    expect(md.split("\n").filter((line) => line.startsWith("| virtualenv ")).length).toBe(1);
    expect(md).toContain("10 more are listed in findings.json.");
    expect(md).not.toContain("GHSA-many-0015");
    expect(groupVulnerablePackages(findings)).toHaveLength(1);
  });

  it("keeps the same package in two lockfiles as two rows", () => {
    const groups = groupVulnerablePackages([
      advisory("flask", "2.0.0", "GHSA-f-1", { file: "a/requirements.txt", dependencyScope: "dev" }),
      advisory("flask", "2.0.0", "GHSA-f-1", { file: "b/requirements.txt" }),
      advisory("flask", "2.0.0", "GHSA-f-2", { file: "b/requirements.txt", severity: "critical" }),
    ]);
    expect(groups.map((group) => [group.file, group.scope, group.advisories.length, group.maxSeverity])).toEqual([
      ["b/requirements.txt", "runtime", 2, "critical"],
      ["a/requirements.txt", "dev", 1, "high"],
    ]);
  });
});

describe("report size and order", () => {
  function large(): { findings: Finding[]; hotspots: Finding[] } {
    const findings: Finding[] = [];
    // 110 code findings across 11 rules, 600 advisories across 40 packages.
    for (let index = 0; index < 110; index += 1) {
      findings.push(
        code({
          ruleId: `rule-${index % 11}`,
          title: `Rule ${index % 11}`,
          file: `src/module${index % 7}.py`,
          confidence: index % 5 === 0 ? "low" : "high",
        }),
      );
    }
    for (let index = 0; index < 600; index += 1) {
      findings.push(
        advisory(`package-${index % 40}`, "1.0.0", `GHSA-big-${String(index).padStart(4, "0")}`, {
          dependencyScope: index % 40 < 10 ? "runtime" : index % 40 < 30 ? "dev" : "unknown",
          severity: index % 3 === 0 ? "critical" : "medium",
        }),
      );
    }
    const hotspots = Array.from({ length: 80 }, (_, index) =>
      hotspot({ ruleId: `hot-${index % 6}`, file: `src/h${index}.py` }),
    );
    return { findings, hotspots };
  }

  it("stays readable with 700 findings", () => {
    const { findings, hotspots } = large();
    expect(findings).toHaveLength(710);
    const md = renderMarkdown(context(findings, hotspots));
    const lines = md.split("\n");
    expect(lines.length).toBeLessThan(700);
    // One table row per package, not per advisory.
    expect(lines.filter((line) => /^\| package-\d+ \|/.test(line))).toHaveLength(40);
    // Hotspots: one row per rule.
    const hotspotStart = md.indexOf("Review hotspots\n");
    const hotspotSection = md.slice(hotspotStart, md.indexOf("\n## ", hotspotStart));
    expect(hotspotSection.split("\n").filter((line) => line.startsWith("| high |"))).toHaveLength(6);
    expect(hotspotSection).toContain("+");
  });

  it("stays within the same budget once every code finding and hotspot is reviewed", () => {
    const trace = [
      { file: "src/a.py", line: 1, role: "source", note: "request data" },
      { file: "src/b.py", line: 2, role: "propagation" },
      { file: "src/c.py", line: 3, role: "propagation" },
      { file: "src/d.py", line: 4, role: "sink", note: "the call" },
    ];
    const states: Array<[string, Record<string, unknown>]> = [
      ["needs_review", { status: "needs_review", review: { status: "needs_review", rationale: "unsure" } }],
      [
        "proof_gap with every field",
        {
          status: "proof_gap",
          review: {
            status: "proof_gap",
            rationale: "could not tell",
            missing: "whether the handler is reachable without the admin role, ".repeat(5),
            trace,
            severityOverride: { severity: "low", reason: "needs an admin session ".repeat(5) },
          },
        },
      ],
      ["confirmed with a trace", { status: "confirmed", review: { status: "confirmed", rationale: "traced", trace } }],
      [
        "disputed",
        {
          status: "needs_review",
          review: {
            status: "needs_review",
            primaryStatus: "confirmed",
            rationale: "traced",
            trace,
            disputed: true,
            disputeOpen: true,
            dissent: { reviewer: "sub", role: "independent", status: "false_positive", at: "x", rationale: "constant ".repeat(30), independence: "subagent" },
          },
        },
      ],
    ];
    // L-n5: every field at its maximum - 20 trace steps with 500-character
    // notes and 200-character paths, 4000-character texts, an open dispute
    // and a proof gap on every record.
    const longTrace = Array.from({ length: 20 }, (_, index) => ({
      file: `${"p".repeat(190)}/f${index}.py`,
      line: index + 1,
      role: index === 0 ? "source" : index === 19 ? "sink" : "propagation",
      note: "n".repeat(500),
    }));
    const dissent = {
      reviewer: "r".repeat(200),
      role: "independent",
      status: "false_positive",
      at: "x",
      rationale: "d".repeat(4000),
      independence: "same-session",
    };
    for (const status of ["proof_gap", "needs_review"]) {
      states.push([
        `every field at its maximum (${status})`,
        {
          status,
          review: {
            status,
            primaryStatus: "proof_gap",
            rationale: "q".repeat(4000),
            missing: "m".repeat(4000),
            trace: longTrace,
            conditions: { auth: "admin", userInteraction: true, note: "c".repeat(2000) },
            evidenceLines: Array.from({ length: 20 }, () => "e".repeat(1000)),
            disputed: true,
            disputeOpen: true,
            dissent,
            history: Array.from({ length: 50 }, () => dissent),
            // A person's decision on a disputed record adds the cover line.
            decidedByPerson: { reviewer: "a".repeat(200), at: "x" },
          },
        },
      ]);
    }
    for (const [label, state] of states) {
      const { findings, hotspots } = large();
      // A confirmed verdict raises a low confidence to high and so moves a
      // low-confidence candidate into the headline (counting behaviour from
      // before F3, more findings rather than more review text): here the
      // low-confidence records get needs_review, the rest the state.
      const reviewed = (list: Finding[]) =>
        list.map(
          (finding) =>
            (finding.confidence === "low" && state.status === "confirmed"
              ? { ...finding, ...states[0]![1] }
              : { ...finding, ...state }) as Finding,
        );
      const md = renderMarkdown(context(reviewed(findings), reviewed(hotspots)));
      const lines = md.split("\n");
      expect(lines.length, label).toBeLessThanOrEqual(699);
      if (label.startsWith("every field")) expect(md, label).toContain("were settled by a person's decision");
      if (label.startsWith("proof_gap")) {
        expect(md).toContain("- **Open proof gaps (790)**");
        expect(md).toContain("… 787 more (see findings.json)");
        expect(md).toContain("… 1 more (see findings.json)");
      }
      if (label === "disputed") expect(md).toContain("- **Disputed verdicts (790)**");
    }
  });

  it("orders the sections: cover, findings, dependencies, candidates, hotspots, suppressed, fixed, coverage", () => {
    const { findings, hotspots } = mixed();
    const md = renderMarkdown(
      context(findings, hotspots, {
        baseline: { path: "b.json", entries: 2, new: 1, existing: 1, fixed: 1 },
        baselineFixed: [
          { fingerprint: "f".repeat(64), ruleId: "old-rule", file: "old.py", severity: "high", title: "Old" } as never,
        ],
      }),
    );
    const headings = md.split("\n").filter((line) => line.startsWith("## "));
    expect(headings).toEqual([
      "## 1. Executive Summary",
      "## 2. Findings: code, secrets and configuration",
      "## 3. Dependency Vulnerabilities",
      "## 4. Low-confidence candidates",
      "## 5. Review hotspots",
      "## 6. Suppressed findings",
      "## 7. Dismissed by review",
      "## 8. Fixed since baseline",
      "## 9. Coverage and Limitations",
      "## 10. Appendix: Rules triggered in this run",
    ]);
    expect(md).toContain("| old-rule | old.py | high | Old |");
    expect(md).toContain("new since the baseline only");
    // The verdict comes before anything else in the summary.
    expect(md.indexOf("count toward the exit code")).toBeLessThan(md.indexOf("| Category |"));
    expect(md.indexOf("### Top risks")).toBeLessThan(md.indexOf("### Run details"));
  });

  it("picks top risks by severity, confidence, production over test/dev, then category", () => {
    const findings = [
      code({ ruleId: "r-medium", title: "Medium thing", severity: "medium" }),
      code({ ruleId: "r-test", title: "In a test", severity: "critical", pathContext: "test", file: "tests/t.py" }),
      code({ ruleId: "r-prod", title: "In production", severity: "critical" }),
      code({ ruleId: "r-prod", title: "In production", severity: "critical" }),
      code({ ruleId: "r-medconf", title: "Medium confidence", severity: "critical", confidence: "medium" }),
      code({ ruleId: "r-secret", title: "A secret", severity: "critical", category: "secrets" }),
      advisory("devtool", "1.0.0", "GHSA-t-1", { severity: "critical", dependencyScope: "dev" }),
      advisory("runtime-lib", "1.0.0", "GHSA-t-2", { severity: "critical" }),
      code({ ruleId: "r-low", title: "Low confidence", severity: "critical", confidence: "low" }),
    ];
    const md = renderMarkdown(context(findings));
    const start = md.indexOf("### Top risks");
    const top = md
      .slice(start, md.indexOf("\n### ", start + 5))
      .split("\n")
      .filter((line) => /^\d+\. /.test(line));
    expect(top.map((line) => line.replace(/^\d+\. /, "").split(" — ").slice(0, 2).join(" — "))).toEqual([
      "**CRITICAL** · high · Secrets — A secret",
      "**CRITICAL** · high · Code — In production",
      "**CRITICAL** · high · Dependency — runtime-lib 1.0.0 (runtime, direct): 1 advisory, upgrade to 1.99.0",
      "**CRITICAL** · high · Code — In a test",
      "**CRITICAL** · high · Dependency — devtool 1.0.0 (dev, direct): 1 advisory, upgrade to 1.99.0",
      "**CRITICAL** · medium · Code — Medium confidence",
      "**MEDIUM** · high · Code — Medium thing",
    ]);
    // One entry per rule, with the other locations counted.
    expect(top[1]).toContain("(+1 more)");
    // Low-confidence candidates are never a top risk.
    expect(top.join("\n")).not.toContain("Low confidence");
  });

  it("lists at most ten top risks", () => {
    const findings = Array.from({ length: 30 }, (_, index) =>
      code({ ruleId: `rule-${index}`, title: `Rule ${index}` }),
    );
    const md = renderMarkdown(context(findings));
    const start = md.indexOf("### Top risks");
    const top = md.slice(start, md.indexOf("\n### ", start + 5));
    expect(top.split("\n").filter((line) => /^\d+\. /.test(line))).toHaveLength(10);
  });

  it("groups findings by rule: detail blocks first, then a table of locations", () => {
    const findings = Array.from({ length: 50 }, (_, index) =>
      code({ file: `src/f${String(index).padStart(2, "0")}.py`, startLine: 5 }),
    );
    const md = renderMarkdown(context(findings));
    expect(md.match(/^### Command injection — `py-command-injection`$/gm)).toHaveLength(1);
    expect(md).toContain("**HIGH** · Code · 50 locations");
    // Full detail (with the evidence block) for the first three.
    expect(md.match(/^~~~text$/gm)).toHaveLength(3);
    expect(md).toContain(`**${findings[0]?.id}** · src/f00.py:5 · Confidence: high · Status: candidate · Engine: builtin-rules`);
    // The rest as table rows, capped, with a pointer to findings.json.
    const rows = md.split("\n").filter((line) => /^\| AUD-2026-\d+ \| src\/f\d+\.py:5 \|/.test(line));
    expect(rows).toHaveLength(40);
    expect(md).toContain("7 more are listed in findings.json.");
  });

  it("tags locations with their path context and shows lowered confidence", () => {
    const { findings, hotspots } = mixed();
    const md = renderMarkdown(
      context(findings, [...hotspots, hotspot({ file: "vendor/lib.py", pathContext: "vendored" })]),
    );
    expect(md).toContain("docs/setup.md:");
    expect(md).toMatch(/docs\/setup\.md:\d+ `docs` · Confidence: high → medium · adjusted: path-context:docs/);
    expect(md).toMatch(/tests\/test\\_app\.py:\d+ `test` \(high → low\)/);
    expect(md).toMatch(/vendor\/lib\.py:\d+ `vendored`/);
    // An unknown context value from the data is reduced to a harmless tag.
    const odd = renderMarkdown(context([code({ pathContext: "<img src=x>|`" })]));
    expect(odd).toContain("`imgsrcx`");
    expect(odd).not.toContain("<img");
  });

  it("lists suppressed findings with source and reason, and never as findings", () => {
    const { findings, hotspots } = mixed();
    const md = renderMarkdown(context(findings, hotspots));
    const start = md.indexOf("Suppressed findings\n");
    const section = md.slice(start, md.indexOf("\n## ", start));
    expect(section.split("\n").filter((line) => line.startsWith("| AUD-"))).toHaveLength(3);
    expect(section).toContain("| inline comment | trust me | — |");
    expect(section).toContain("| ignore-file | legacy | — |");
    expect(section).toContain("| inline comment | no reason given | — |");
    const suppressedIds = findings.filter((finding) => finding.status === "suppressed").map((finding) => finding.id);
    const before = md.slice(0, start);
    for (const id of suppressedIds) expect(before).not.toContain(id);
  });
});

describe("escaping of repository-controlled text", () => {
  const hostile = "<script>alert(1)</script> [x](javascript:alert(1)) | `tick` **bold**";

  it("escapes Markdown and HTML in every field that reaches the report", () => {
    const findings = [
      code({
        ruleId: "agent-<b>rule</b>",
        title: hostile,
        message: hostile,
        remediation: hostile,
        file: "src/<script>alert.md",
        references: [hostile],
        adjustments: [hostile],
        evidence: `${hostile}\n~~~\n<img src=x onerror=alert(1)>`,
      }),
      code({ confidence: "low", title: hostile, ruleId: "low-<i>", file: "a|b<script>.py" }),
      code({
        status: "suppressed",
        file: "s<script>.py",
        suppression: { source: "inline", reason: hostile },
      }),
      advisory("<script>pkg</script>", "1.0<b>", "GHSA-<script>", {
        severity: "critical",
        title: `<script>pkg</script>@1.0<b>: ${hostile}`,
        message: hostile,
        aliases: [hostile, "CVE-<img src=x>"],
        fixedVersion: "2.0<script>",
        file: "req<script>.txt",
      }),
    ];
    const hotspots = [hotspot({ title: hostile, file: "h<script>.py", ruleId: "hot-<u>" })];
    for (const lang of ["en", "zh"] as const) {
      const md = renderMarkdown(
        context(findings, hotspots, {
          lang,
          warnings: [`warning about ${hostile}`],
          baselineFixed: [
            { fingerprint: "f".repeat(64), ruleId: "r<script>", file: "f<script>.py", severity: "high", title: hostile } as never,
          ],
        }),
      );
      expect(md).not.toMatch(/<(script|img|b|i|u)\b/i);
      expect(md).not.toContain("](javascript:");
      // The evidence cannot close its own fence.
      expect(md.match(/^~~~$/gm)?.length).toBe(md.match(/^~~~text$/gm)?.length);
      // Only the report's own HTML elements are present.
      const tags = new Set(md.match(/<\/?[a-zA-Z][^>]*>/g) ?? []);
      for (const tag of tags) expect(["<details>", "</details>", "<summary>", "</summary>"]).toContain(tag);
      expect(md).toContain("&lt;script&gt;");
    }
  });

  it("prints evidence only as it arrives (already redacted) and nowhere else in CI output", () => {
    const secret = code({
      category: "secrets",
      ruleId: "secret-aws-access-key",
      title: "Hardcoded AWS access key",
      message: "Possible plaintext credential detected; evidence is redacted in every report.",
      evidence: "aws_key = AKIA**************00",
    });
    const md = renderMarkdown(context([secret]));
    expect(md).toContain("aws_key = AKIA**************00");
    const text = renderSummaryText(summarizeFindings([secret])).join("\n");
    expect(text).not.toContain("AKIA");
  });
});

// ---------------------------------------------------------------------------
// SARIF 2.1.0 structure, checked by hand against the parts of the schema the
// tool emits: required properties and enumerated values.
// ---------------------------------------------------------------------------

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validateSarif(document: unknown): string[] {
  const errors: string[] = [];
  const fail = (path: string, message: string): void => {
    errors.push(`${path}: ${message}`);
  };
  const LEVELS = ["none", "note", "warning", "error"];
  const SUPPRESSION_KINDS = ["inSource", "external"];
  const SUPPRESSION_STATUS = ["accepted", "underReview", "rejected"];
  const checkMessage = (value: unknown, path: string): void => {
    if (!isObject(value) || (typeof value.text !== "string" && typeof value.id !== "string")) {
      fail(path, "message needs text or id");
    }
  };
  const checkBag = (value: unknown, path: string): void => {
    if (value === undefined) return;
    if (!isObject(value)) return fail(path, "properties must be an object");
    if (value.tags !== undefined) {
      if (!Array.isArray(value.tags) || value.tags.some((tag) => typeof tag !== "string")) {
        fail(`${path}.tags`, "must be an array of strings");
      } else if (new Set(value.tags).size !== value.tags.length) {
        fail(`${path}.tags`, "must be unique");
      }
    }
  };

  if (!isObject(document)) return ["$: not an object"];
  if (document.version !== "2.1.0") fail("$.version", "must be 2.1.0");
  if (typeof document.$schema !== "string") fail("$.$schema", "must be a string");
  if (!Array.isArray(document.runs)) return [...errors, "$.runs: required array"];
  document.runs.forEach((run: unknown, runIndex: number) => {
    const runPath = `$.runs[${runIndex}]`;
    if (!isObject(run)) return fail(runPath, "not an object");
    const driver = isObject(run.tool) ? run.tool.driver : undefined;
    if (!isObject(driver)) return fail(`${runPath}.tool.driver`, "required");
    if (typeof driver.name !== "string" || !driver.name) fail(`${runPath}.tool.driver.name`, "required");
    const rules = Array.isArray(driver.rules) ? driver.rules : [];
    const ruleIds = new Set<string>();
    rules.forEach((rule: unknown, index: number) => {
      const path = `${runPath}.tool.driver.rules[${index}]`;
      if (!isObject(rule)) return fail(path, "not an object");
      if (typeof rule.id !== "string" || !rule.id) fail(`${path}.id`, "required");
      else if (ruleIds.has(rule.id)) fail(`${path}.id`, "duplicate rule id");
      else ruleIds.add(rule.id);
      for (const key of ["shortDescription", "fullDescription", "help"]) {
        const value = rule[key];
        if (value !== undefined && (!isObject(value) || typeof value.text !== "string")) {
          fail(`${path}.${key}`, "needs text");
        }
      }
      const configuration = rule.defaultConfiguration;
      if (configuration !== undefined) {
        if (!isObject(configuration) || !LEVELS.includes(configuration.level as string)) {
          fail(`${path}.defaultConfiguration.level`, "not a SARIF level");
        }
      }
      checkBag(rule.properties, `${path}.properties`);
    });
    if (isObject(run.originalUriBaseIds)) {
      for (const [key, value] of Object.entries(run.originalUriBaseIds)) {
        if (!isObject(value) || (value.uri !== undefined && typeof value.uri !== "string")) {
          fail(`${runPath}.originalUriBaseIds.${key}`, "needs a uri string");
        }
      }
    }
    if (Array.isArray(run.invocations)) {
      run.invocations.forEach((invocation: unknown, index: number) => {
        if (!isObject(invocation) || typeof invocation.executionSuccessful !== "boolean") {
          fail(`${runPath}.invocations[${index}].executionSuccessful`, "required boolean");
        }
      });
    }
    if (!Array.isArray(run.results)) return fail(`${runPath}.results`, "must be an array");
    run.results.forEach((result: unknown, index: number) => {
      const path = `${runPath}.results[${index}]`;
      if (!isObject(result)) return fail(path, "not an object");
      checkMessage(result.message, `${path}.message`);
      if (typeof result.ruleId !== "string") fail(`${path}.ruleId`, "must be a string");
      if (
        typeof result.ruleIndex !== "number" ||
        !Number.isInteger(result.ruleIndex) ||
        result.ruleIndex < -1 ||
        !isObject(rules[result.ruleIndex]) ||
        (rules[result.ruleIndex] as Record<string, unknown>).id !== result.ruleId
      ) {
        fail(`${path}.ruleIndex`, "must point at the rule with this ruleId");
      }
      if (!LEVELS.includes(result.level as string)) fail(`${path}.level`, "not a SARIF level");
      if (
        result.rank !== undefined &&
        (typeof result.rank !== "number" || result.rank < -1 || result.rank > 100)
      ) {
        fail(`${path}.rank`, "must be between -1 and 100");
      }
      if (!Array.isArray(result.locations)) fail(`${path}.locations`, "must be an array");
      else {
        result.locations.forEach((location: unknown, locationIndex: number) => {
          const locationPath = `${path}.locations[${locationIndex}].physicalLocation`;
          const physical = isObject(location) ? location.physicalLocation : undefined;
          if (!isObject(physical)) return fail(locationPath, "required");
          const artifact = physical.artifactLocation;
          if (!isObject(artifact) || typeof artifact.uri !== "string") {
            fail(`${locationPath}.artifactLocation.uri`, "required string");
          } else if (/[\s<>"{}|\\^`]/.test(artifact.uri)) {
            fail(`${locationPath}.artifactLocation.uri`, "not a valid URI reference");
          }
          const region = physical.region;
          if (isObject(region)) {
            for (const key of ["startLine", "endLine"]) {
              const value = region[key];
              if (value !== undefined && (!Number.isInteger(value) || (value as number) < 1)) {
                fail(`${locationPath}.region.${key}`, "must be an integer >= 1");
              }
            }
            if (region.snippet !== undefined && (!isObject(region.snippet) || typeof region.snippet.text !== "string")) {
              fail(`${locationPath}.region.snippet`, "needs text");
            }
          }
        });
      }
      if (result.partialFingerprints !== undefined) {
        if (
          !isObject(result.partialFingerprints) ||
          Object.values(result.partialFingerprints).some((value) => typeof value !== "string")
        ) {
          fail(`${path}.partialFingerprints`, "must map names to strings");
        }
      }
      if (result.suppressions !== undefined) {
        if (!Array.isArray(result.suppressions)) fail(`${path}.suppressions`, "must be an array");
        else {
          result.suppressions.forEach((suppression: unknown, suppressionIndex: number) => {
            const suppressionPath = `${path}.suppressions[${suppressionIndex}]`;
            if (!isObject(suppression)) return fail(suppressionPath, "not an object");
            if (!SUPPRESSION_KINDS.includes(suppression.kind as string)) {
              fail(`${suppressionPath}.kind`, "required: inSource or external");
            }
            if (suppression.status !== undefined && !SUPPRESSION_STATUS.includes(suppression.status as string)) {
              fail(`${suppressionPath}.status`, "not a SARIF suppression status");
            }
            if (suppression.justification !== undefined && typeof suppression.justification !== "string") {
              fail(`${suppressionPath}.justification`, "must be a string");
            }
          });
        }
      }
      checkBag(result.properties, `${path}.properties`);
    });
  });
  return errors;
}

describe("SARIF", () => {
  interface SarifResult {
    ruleId: string;
    level: string;
    suppressions: Array<{ kind: string; status: string; justification: string }>;
    properties: Record<string, unknown>;
    locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }>;
  }
  const { findings, hotspots } = mixed();
  const hostileFile = code({ file: "dir with space/<script>#1.py", severity: "low" });
  const sarif = JSON.parse(renderSarif(context([...findings, hostileFile], hotspots)));
  const results = sarif.runs[0].results as SarifResult[];

  it("passes the structural SARIF 2.1.0 checks", () => {
    expect(validateSarif(sarif)).toEqual([]);
    expect(results).toHaveLength(findings.length + 1 + hotspots.length);
  });

  it("the validator itself rejects broken documents", () => {
    const broken = JSON.parse(JSON.stringify(sarif));
    broken.runs[0].results[0].level = "high";
    broken.runs[0].results[1].suppressions = [{ kind: "inline" }];
    broken.runs[0].results[2].ruleIndex = 9999;
    delete broken.runs[0].results[3].message;
    broken.runs[0].tool.driver.name = "";
    const errors = validateSarif(broken).join("\n");
    expect(errors).toContain("results[0].level");
    expect(errors).toContain("results[1].suppressions[0].kind");
    expect(errors).toContain("results[2].ruleIndex");
    expect(errors).toContain("results[3].message");
    expect(errors).toContain("tool.driver.name");
  });

  it("marks suppressed results with kind and justification, and only those", () => {
    const records = [...findings, hostileFile, ...hotspots];
    // A false_positive verdict is a suppression too (kind external); see
    // dismissed.test.ts. The rest of this test is about ignore entries.
    const dismissed = results.filter((_, index) => records[index]?.status === "false_positive");
    expect(dismissed.length).toBeGreaterThan(0);
    for (const result of dismissed) {
      expect(result.suppressions).toHaveLength(1);
      expect(result.suppressions[0]?.kind).toBe("external");
      expect(result.suppressions[0]?.justification).toMatch(/^Marked false positive by /);
    }
    const suppressed = results.filter(
      (result, index) => result.suppressions.length > 0 && records[index]?.status === "suppressed",
    );
    expect(suppressed).toHaveLength(3);
    records.forEach((record, index) => {
      const result = results[index] as SarifResult;
      if (record.status === "false_positive") return;
      if (record.status !== "suppressed") {
        expect(result.suppressions).toEqual([]);
        return;
      }
      expect(result.suppressions).toEqual([
        {
          kind: record.suppression?.source === "inline" ? "inSource" : "external",
          status: "accepted",
          justification: record.suppression?.reason || "no reason given",
        },
      ]);
    });
    expect(suppressed.map((result) => result.suppressions[0]?.kind).sort()).toEqual([
      "external",
      "inSource",
      "inSource",
    ]);
    expect(suppressed.map((result) => result.suppressions[0]?.justification).sort()).toEqual([
      "legacy",
      "no reason given",
      "trust me",
    ]);
  });

  it("carries confidence, category, path context, dependency scope and adjustments", () => {
    const records = [...findings, hostileFile, ...hotspots];
    records.forEach((record, index) => {
      const properties = (results[index] as SarifResult).properties;
      const extra = record as Record<string, unknown>;
      expect(properties.confidence).toBe(record.confidence);
      expect(properties.category).toBe(record.category);
      expect(properties.pathContext).toBe(extra.pathContext);
      expect(properties.dependencyScope).toBe(record.dependencyScope);
      expect(properties.adjustments).toEqual(extra.adjustments);
      expect(properties.confidenceOriginal).toBe(extra.confidenceOriginal);
    });
    const lowered = results.find((result) => result.properties.pathContext === "test");
    expect(lowered?.properties).toMatchObject({
      confidence: "low",
      confidenceOriginal: "high",
      adjustments: ["path-context:test"],
    });
    expect(results.some((result) => result.properties.dependencyScope === "dev")).toBe(true);
  });

  it("keeps the level mapping: error for critical/high, warning for medium, note below and for hotspots", () => {
    const records = [...findings, hostileFile, ...hotspots];
    records.forEach((record, index) => {
      const expected =
        record.kind === "hotspot"
          ? "note"
          : record.severity === "critical" || record.severity === "high"
            ? "error"
            : record.severity === "medium"
              ? "warning"
              : "note";
      expect((results[index] as SarifResult).level).toBe(expected);
    });
  });

  it("encodes file names into valid URI references", () => {
    const result = results[findings.length] as SarifResult;
    expect(result.locations[0]?.physicalLocation.artifactLocation.uri).toBe(
      "dir%20with%20space/%3Cscript%3E%231.py",
    );
  });
});
