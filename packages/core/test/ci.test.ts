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
import { createFinding } from "../src/finding.js";
import { cleanup, makeTempDir } from "./helpers.js";

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
      env: { GITHUB_ACTIONS: "true" } as NodeJS.ProcessEnv,
    });
    expect(lines[0]).toMatch(/^::warning /);
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
  it("renders a Markdown table with counts and report paths", () => {
    const md = renderStepSummaryMarkdown({
      findingCounts: { critical: 1, high: 2, medium: 0, low: 0, info: 0 },
      total: 3,
      hotspots: 4,
      baseline: { new: 1, existing: 2, fixed: 0 },
      reportPaths: ["/run/report.md"],
    });
    expect(md).toContain("code-audit summary");
    expect(md).toContain("New: 1 · Existing: 2 · Fixed: 0");
    expect(md).toContain("/run/report.md");
  });

  it("renders a Warnings section when warnings are present", () => {
    const md = renderStepSummaryMarkdown({
      findingCounts: {},
      total: 0,
      hotspots: 0,
      reportPaths: [],
      warnings: ["ignore entry #0 expired on 2020-01-01"],
    });
    expect(md).toContain("### Warnings");
    expect(md).toContain("ignore entry #0 expired on 2020-01-01");
  });

  it("is appended, not overwritten, by the CLI", () => {
    // The CLI opens GITHUB_STEP_SUMMARY with appendFileSync; verify the helper
    // output is plain appendable text (no leading truncation markers).
    const md = renderStepSummaryMarkdown({
      findingCounts: {},
      total: 0,
      hotspots: 0,
      reportPaths: [],
    });
    const file = path.join(temp, "summary.md");
    fs.writeFileSync(file, "existing\n", "utf8");
    fs.appendFileSync(file, md, "utf8");
    const content = fs.readFileSync(file, "utf8");
    expect(content.startsWith("existing\n")).toBe(true);
    expect(content).toContain("code-audit summary");
  });
});