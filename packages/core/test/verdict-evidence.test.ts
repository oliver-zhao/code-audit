/**
 * F3: structured verdicts (verdicts.json schemaVersion 2), proof_gap,
 * strict evidence, location checks through the path jail, independent
 * review and the review ledger of the reports.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createFinding, type Finding } from "../src/finding.js";
import { renderMarkdown, renderSarif, triageCoverage, type ReportContext } from "../src/report.js";
import {
  RunStoreError,
  effectiveFindings,
  initRunVerdicts,
  loadRun,
  queryFindings,
  recordVerdict,
  renderRunReport,
  runStatus,
  verdictsDisagree,
  type RecordVerdictInput,
} from "../src/runstore.js";
import { scanProject } from "../src/scan.js";
import { splitLines } from "../src/redact.js";
import { VULNERABLE, cleanup, makeTempDir } from "./helpers.js";

const temp = makeTempDir("verdict-evidence");
const outside = fs.mkdtempSync(path.join(os.tmpdir(), "code-audit-f3-outside-"));
afterAll(() => {
  cleanup(temp);
  fs.rmSync(outside, { recursive: true, force: true });
});

const APP = "python/app.py";
const APP_LINES = splitLines(fs.readFileSync(path.join(VULNERABLE, APP), "utf8")).length;

async function freshRun(name: string) {
  const project = path.join(temp, name);
  fs.cpSync(VULNERABLE, project, { recursive: true });
  const result = await scanProject({ root: project, offline: true, engines: ["builtin"] });
  const options = { cwd: project };
  const run = loadRun(result.runId, options);
  const pick = (severity: string, kind = "finding"): Finding[] =>
    [...run.findings, ...run.hotspots].filter(
      (finding) => finding.severity === severity && finding.kind === kind && finding.status === "candidate",
    );
  const verdict = (finding: Finding | string, input: RecordVerdictInput) =>
    recordVerdict(result.runId, typeof finding === "string" ? finding : finding.id, input, options);
  const refused = (finding: Finding | string, input: RecordVerdictInput): RunStoreError => {
    let caught: unknown;
    try {
      verdict(finding, input);
    } catch (error) {
      caught = error;
    }
    expect(caught, JSON.stringify(input).slice(0, 200)).toBeInstanceOf(RunStoreError);
    return caught as RunStoreError;
  };
  const entries = () => loadRun(result.runId, options).verdictsDocument.entries;
  return { project, runId: result.runId, runDir: result.runDir, options, pick, verdict, refused, entries };
}

type Ctx = Awaited<ReturnType<typeof freshRun>>;

const SOURCE = { file: APP, line: 1, role: "source" as const, note: "request data" };
const SINK = { file: APP, line: 2, role: "sink" as const, note: "dangerous call" };
const CONTROL = { file: APP, line: 3, note: "the value is a constant" };
const SAFE = "The argument is a constant defined in this module and never reaches the request handler.";

describe("verdicts.json schemaVersion 2 reads version 1", () => {
  let ctx: Ctx;
  beforeAll(async () => {
    ctx = await freshRun("compat");
  });

  it("loads a hand-written version 1 file and writes version 2 on the next verdict", () => {
    const [first, second] = ctx.pick("critical") as [Finding, Finding];
    const v1 = {
      schemaVersion: 1,
      runId: ctx.runId,
      entries: [
        {
          fingerprint: first.fingerprint,
          findingId: first.id,
          status: "confirmed",
          rationale: "request data reaches the sink",
          at: "2026-11-01T00:00:00.000Z",
          reviewer: "old-model",
        },
      ],
    };
    fs.writeFileSync(path.join(ctx.runDir, "verdicts.json"), `${JSON.stringify(v1, null, 2)}\n`);
    const run = loadRun(ctx.runId, ctx.options);
    expect(run.verdicts[first.fingerprint]?.status).toBe("confirmed");
    const listed = queryFindings(run, { kind: "finding" }, undefined, 20).items;
    expect(listed.find((item) => item.id === first.id)?.review?.independentlyReviewed).toBe(false);
    // An independent review of a version 1 entry takes it as the primary.
    const result = ctx.verdict(first, { status: "likely", rationale: "agrees", role: "independent", reviewer: "second" });
    expect(result.status).toBe("confirmed");
    expect(result.independentlyReviewed).toBe(true);
    ctx.verdict(second, { status: "needs_review", rationale: "unsure" });
    const written = JSON.parse(fs.readFileSync(path.join(ctx.runDir, "verdicts.json"), "utf8"));
    expect(written.schemaVersion).toBe(2);
    expect(written.entries).toHaveLength(3);
    expect(written.entries[0]).toEqual(v1.entries[0]);
    expect(written.entries[1].reviewers.map((item: { reviewer: string; role: string }) => `${item.role}:${item.reviewer}`)).toEqual([
      "primary:old-model",
      "independent:second",
    ]);
  });

  it("refuses a file with an unknown schema version", () => {
    const file = path.join(ctx.runDir, "verdicts.json");
    const saved = fs.readFileSync(file, "utf8");
    try {
      fs.writeFileSync(file, JSON.stringify({ schemaVersion: 3, runId: ctx.runId, entries: [] }));
      expect(() => loadRun(ctx.runId, ctx.options)).toThrow(/verdicts\.json/);
    } finally {
      fs.writeFileSync(file, saved);
    }
  });
});

describe("structured evidence is checked", () => {
  let ctx: Ctx;
  beforeAll(async () => {
    ctx = await freshRun("evidence");
    fs.writeFileSync(path.join(outside, "secret.py"), "x = 1\ny = 2\n");
    fs.symlinkSync(path.join(outside, "secret.py"), path.join(ctx.project, "python", "escape.py"));
  });

  it("names the malformed field and how to fill it", () => {
    const finding = ctx.pick("medium")[0] as Finding;
    const cases: Array<[Partial<RecordVerdictInput>, RegExp]> = [
      [{ trace: [{ file: APP, line: 1 } as never] }, /trace\[0\]\.role must be "source", "propagation" or "sink"/],
      [{ trace: [{ line: 1, role: "source" } as never] }, /trace\[0\]\.file is missing: give the path relative to the audit root/],
      [{ trace: [{ file: APP, line: 0, role: "sink" }] }, /trace\[0\]\.line is missing or not a line number/],
      [{ trace: Array.from({ length: 21 }, () => SOURCE) }, /at most 20 are accepted/],
      [{ control: { file: APP, line: 1 } as never }, /control\.note is missing/],
      [{ missing: "too short" }, /missing must say in at least 20 characters/],
      [{ cwe: "89" }, /cwe must look like CWE-89/],
      [{ conditions: { auth: "root" } as never }, /conditions\.auth must be "none"/],
      [{ severityOverride: { severity: "huge", reason: "x" } as never }, /severityOverride\.severity must be one of/],
      [{ severityOverride: { severity: "low", reason: " " } }, /severityOverride\.reason is missing/],
    ];
    for (const [extra, message] of cases) {
      const error = ctx.refused(finding, { status: "likely", rationale: "checked", ...extra });
      expect(error.code).toBe("INVALID_EVIDENCE");
      expect(error.message).toMatch(message);
    }
    expect(ctx.entries()).toHaveLength(0);
  });

  it("refuses locations outside the root, outside the file or not in the inventory", () => {
    const finding = ctx.pick("medium")[0] as Finding;
    const cases: Array<[Record<string, unknown>, RegExp]> = [
      [{ ...SOURCE, file: "../outside.py" }, /trace\[0\] \(\.\.\/outside\.py:1\): the path leaves the audit root/],
      [{ ...SOURCE, file: path.join(ctx.project, APP) }, /an absolute path is not accepted/],
      [{ ...SOURCE, file: "/etc/passwd" }, /an absolute path is not accepted/],
      [{ ...SOURCE, file: "python/escape.py" }, /the path leaves the audit root/],
      [{ ...SOURCE, file: "python/missing.py" }, /not a file of the audit inventory/],
      [{ ...SOURCE, file: ".audit/index.json" }, /not a file of the audit inventory/],
      [{ ...SOURCE, file: "python/app.py\u0000.txt" }, /cannot be resolved inside the audit root|not a file of the audit inventory/],
      [{ ...SOURCE, line: APP_LINES + 1 }, new RegExp(`line ${APP_LINES + 1} is beyond the end of python/app\\.py \\(${APP_LINES} lines\\)`)],
    ];
    for (const [step, message] of cases) {
      const error = ctx.refused(finding, { status: "likely", rationale: "checked", trace: [step as never] });
      expect(error.code, String(step.file)).toBe("EVIDENCE_LOCATION_INVALID");
      expect(error.message).toMatch(message);
      expect(error.message).toContain("Check the location with audit_read");
      // The resolved target of a link is never echoed.
      expect(error.message).not.toContain(outside);
    }
    // A bad control is named as such, and every bad item is listed.
    const both = ctx.refused(finding, {
      status: "false_positive",
      rationale: SAFE,
      trace: [{ ...SINK, line: 9999 }],
      control: { ...CONTROL, file: "../../x.py" },
    });
    expect(both.code).toBe("EVIDENCE_LOCATION_INVALID");
    expect(both.message).toMatch(/trace\[0\] .*; control \(\.\.\/\.\.\/x\.py:3\): the path leaves the audit root/);
    expect(ctx.entries()).toHaveLength(0);
  });

  it("stores checked locations relative to the root, with notes redacted", () => {
    const finding = ctx.pick("medium")[0] as Finding;
    const token = ["ghp_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"].join("");
    const result = ctx.verdict(finding, {
      status: "confirmed",
      rationale: "request data reaches the call",
      trace: [{ ...SOURCE, file: `./python/../${APP}`, note: `token ${token}` }, SINK],
      conditions: { auth: "none", userInteraction: false },
      cwe: "cwe-78",
      severityOverride: { severity: "critical", reason: "reachable without login" },
    });
    expect(result.status).toBe("confirmed");
    const stored = ctx.entries().at(-1);
    expect(stored?.trace?.map((step) => `${step.file}:${step.line}:${step.role}`)).toEqual([
      `${APP}:1:source`,
      `${APP}:2:sink`,
    ]);
    expect(stored?.cwe).toBe("CWE-78");
    expect(JSON.stringify(stored)).not.toContain(token);
    // The counted severity does not change with an override.
    const effective = effectiveFindings(loadRun(ctx.runId, ctx.options)).find(
      (item) => item.fingerprint === finding.fingerprint,
    );
    expect(effective?.severity).toBe(finding.severity);
    expect(effective?.review?.severityOverride?.severity).toBe("critical");
  });

  it("counts a control as the evidence a serious dismissal needs", () => {
    const high = ctx.pick("high")[0] as Finding;
    expect(ctx.refused(high, { status: "false_positive", rationale: SAFE }).code).toBe("DISMISSAL_NEEDS_EVIDENCE");
    expect(ctx.verdict(high, { status: "false_positive", rationale: SAFE, control: CONTROL }).status).toBe("false_positive");
    // A control does not make up for a short rationale.
    const other = ctx.pick("high")[1] as Finding;
    expect(ctx.refused(other, { status: "false_positive", rationale: "fp", control: CONTROL }).code).toBe(
      "DISMISSAL_NEEDS_EVIDENCE",
    );
  });

  it("accepts proof_gap without missing when strict evidence is off", () => {
    const finding = ctx.pick("low")[0] ?? (ctx.pick("medium")[1] as Finding);
    expect(ctx.verdict(finding, { status: "proof_gap", rationale: "could not tell" }).status).toBe("proof_gap");
  });
});

describe("strict evidence", () => {
  let ctx: Ctx;
  beforeAll(async () => {
    ctx = await freshRun("strict");
  });

  it("requires a source and a sink, a control, or missing, with an example of the field", () => {
    const finding = ctx.pick("medium")[0] as Finding;
    const strict = { strictEvidence: true };
    let error = ctx.refused(finding, { status: "confirmed", rationale: "yes", ...strict });
    expect(error.code).toBe("EVIDENCE_REQUIRED");
    expect(error.message).toMatch(/no "source" and no "sink" step given\). Example: trace: \[\{"file":/);
    error = ctx.refused(finding, { status: "confirmed", rationale: "yes", trace: [SOURCE], ...strict });
    expect(error.message).toMatch(/no "sink" step given/);
    error = ctx.refused(finding, { status: "false_positive", rationale: SAFE, ...strict });
    expect(error.code).toBe("EVIDENCE_REQUIRED");
    expect(error.message).toMatch(/needs control: .* for example control: \{"file":/);
    error = ctx.refused(finding, { status: "proof_gap", rationale: "unclear", ...strict });
    expect(error.message).toMatch(/needs missing: the fact you could not establish, in at least 20 characters/);
    expect(ctx.entries()).toHaveLength(0);
    // likely and needs_review need nothing more.
    ctx.verdict(finding, { status: "likely", rationale: "probably", ...strict });
    ctx.verdict(finding, { status: "confirmed", rationale: "traced", trace: [SOURCE, SINK], ...strict });
    ctx.verdict(finding, { status: "proof_gap", rationale: "unclear", missing: "whether the handler is reachable without login", ...strict });
    expect(ctx.entries().at(-1)?.status).toBe("proof_gap");
  });

  it("is inherited from the run and cannot be turned off by a call", () => {
    initRunVerdicts(ctx.runDir, ctx.runId, { strictEvidence: true });
    const document = loadRun(ctx.runId, ctx.options).verdictsDocument;
    expect(document.strictEvidence).toBe(true);
    // Earlier entries survive.
    expect(document.entries.length).toBe(3);
    const finding = ctx.pick("medium")[1] as Finding;
    expect(ctx.refused(finding, { status: "confirmed", rationale: "yes" }).code).toBe("EVIDENCE_REQUIRED");
    expect(ctx.refused(finding, { status: "confirmed", rationale: "yes", strictEvidence: false }).code).toBe(
      "EVIDENCE_REQUIRED",
    );
    const result = ctx.verdict(finding, { status: "confirmed", rationale: "traced", trace: [SOURCE, SINK] });
    expect(result.strictEvidence).toBe(true);
    // The setting is kept when verdicts are written.
    expect(JSON.parse(fs.readFileSync(path.join(ctx.runDir, "verdicts.json"), "utf8")).strictEvidence).toBe(true);
  });
});

describe("independent review", () => {
  let ctx: Ctx;
  beforeAll(async () => {
    ctx = await freshRun("independent");
  });

  it("classifies disagreements", () => {
    expect(verdictsDisagree("confirmed", "confirmed")).toBe(false);
    expect(verdictsDisagree("confirmed", "likely")).toBe(false);
    expect(verdictsDisagree("likely", "confirmed")).toBe(false);
    expect(verdictsDisagree("confirmed", "false_positive")).toBe(true);
    expect(verdictsDisagree("false_positive", "likely")).toBe(true);
    expect(verdictsDisagree("proof_gap", "needs_review")).toBe(true);
    expect(verdictsDisagree("needs_review", "proof_gap")).toBe(true);
    expect(verdictsDisagree("proof_gap", "proof_gap")).toBe(false);
    expect(verdictsDisagree("false_positive", "needs_review")).toBe(true);
  });

  it("needs a primary verdict first", () => {
    const finding = ctx.pick("high")[0] as Finding;
    const error = ctx.refused(finding, { status: "confirmed", rationale: "x", role: "independent" });
    expect(error.code).toBe("PRIMARY_VERDICT_REQUIRED");
    expect(error.message).toContain('role "primary"');
    expect(ctx.refused(finding, { status: "confirmed", rationale: "x", role: "boss" as never }).code).toBe(
      "INVALID_VERDICT",
    );
  });

  it("downgrades a disagreement to needs_review and keeps both sides", () => {
    const finding = ctx.pick("high")[0] as Finding;
    ctx.verdict(finding, {
      status: "confirmed",
      rationale: "request data reaches the call",
      reviewer: "primary-model",
      trace: [SOURCE, SINK],
    });
    const result = ctx.verdict(finding, {
      status: "false_positive",
      rationale: `${SAFE} See python/app.py:3.`,
      reviewer: "fresh-subagent",
      role: "independent",
    });
    expect(result.status).toBe("needs_review");
    expect(result.requestedStatus).toBe("false_positive");
    expect(result.role).toBe("independent");
    expect(result.independentlyReviewed).toBe(true);
    expect(result.disagreement).toMatch(/independent reviewer fresh-subagent said false_positive, primary reviewer primary-model said confirmed/);
    const stored = ctx.entries().at(-1);
    expect(stored?.status).toBe("needs_review");
    expect(stored?.rationale).toMatch(/^Reviewers disagree; needs a human decision\. primary \(primary-model\) said confirmed: request data reaches the call \| independent \(fresh-subagent\) said false_positive: /);
    // The primary evidence stays.
    expect(stored?.trace).toHaveLength(2);
    expect(stored?.reviewers?.map((item) => `${item.role}:${item.status}`)).toEqual([
      "primary:confirmed",
      "independent:false_positive",
    ]);
    // A later independent review that agrees does not erase the disagreement.
    const again = ctx.verdict(finding, { status: "confirmed", rationale: "same-session: traced it again", role: "independent" });
    expect(again.status).toBe("needs_review");
    // A new primary verdict starts over.
    const reset = ctx.verdict(finding, { status: "confirmed", rationale: "re-decided by a person", reviewer: "human" });
    expect(reset.status).toBe("confirmed");
    expect(reset.independentlyReviewed).toBe(false);
    expect(ctx.entries().at(-1)?.reviewers).toHaveLength(1);
  });

  it("keeps an agreed status and can never dismiss on its own", () => {
    const [agreeFp, agreeReal, gap] = ctx.pick("high").slice(1) as [Finding, Finding, Finding];
    ctx.verdict(agreeFp, { status: "false_positive", rationale: SAFE, control: CONTROL, reviewer: "a" });
    const fp = ctx.verdict(agreeFp, {
      status: "false_positive",
      rationale: "same-session: devil's advocate found no path; python/app.py:3 holds a constant.",
      role: "independent",
      reviewer: "a",
    });
    expect(fp.status).toBe("false_positive");
    expect(fp.independentlyReviewed).toBe(true);
    expect(fp.disagreement).toBeUndefined();
    ctx.verdict(agreeReal, { status: "likely", rationale: "probably reachable", trace: [SOURCE, SINK] });
    expect(ctx.verdict(agreeReal, { status: "confirmed", rationale: "traced", role: "independent" }).status).toBe("likely");
    ctx.verdict(gap, { status: "proof_gap", rationale: "unclear", missing: "whether the route requires a session cookie" });
    const later = ctx.verdict(gap, { status: "needs_review", rationale: "could not decide", role: "independent" });
    expect(later.status).toBe("needs_review");
    expect(ctx.entries().at(-1)?.missing).toBe("whether the route requires a session cookie");
  });

  it("is reported in the Markdown report, SARIF, findings.json and the summary", () => {
    const md = renderRunReport(ctx.runId, "md", ctx.options).text;
    expect(md).toContain("(independently reviewed)");
    expect(md).toMatch(/\*\*Trace\*\*: python/);
    // A dismissal shows its control in the "Dismissed by review" table.
    expect(md).toContain("control: python/app.py:3");
    const sarif = JSON.parse(renderRunReport(ctx.runId, "sarif", ctx.options).text);
    const reviewed = sarif.runs[0].results.filter((result: { properties: { review?: unknown } }) => result.properties.review);
    expect(reviewed.length).toBeGreaterThan(0);
    expect(reviewed.some((result: { properties: { review: { independentlyReviewed: boolean } } }) => result.properties.review.independentlyReviewed)).toBe(true);
    const json = JSON.parse(renderRunReport(ctx.runId, "json", ctx.options).text);
    expect(json.findings.some((finding: Finding) => finding.review?.independentlyReviewed === true)).toBe(true);
    const status = runStatus(ctx.runId, ctx.options);
    expect(status.triage.independentlyReviewed).toBe(3);
  });
});

describe("proof gaps and the review ledger", () => {
  let ctx: Ctx;
  beforeAll(async () => {
    ctx = await freshRun("ledger");
  });

  it("lists open proof gaps, counts them as open and never suppresses them", () => {
    const finding = ctx.pick("critical")[0] as Finding;
    const missing = "whether <b>admin</b> | export is reachable without the admin role";
    ctx.verdict(finding, { status: "proof_gap", rationale: "could not tell", missing });
    const status = runStatus(ctx.runId, ctx.options);
    expect(status.triage.open).toBe(1);
    expect(status.triage.proofGaps).toEqual([
      { id: finding.id, location: `${finding.file}:${finding.startLine}`, missing },
    ]);
    // Still active: a proof_gap counts like needs_review.
    const before = runStatus(ctx.runId, ctx.options).findings;
    expect(before).toBeGreaterThan(0);
    const md = renderRunReport(ctx.runId, "md", ctx.options).text;
    expect(md).toContain("### Open proof gaps (1)");
    expect(md).toContain(`**${finding.id}** · critical`);
    // Escaped like every other piece of agent-written text.
    expect(md).toContain("&lt;b&gt;admin&lt;/b&gt; \\| export");
    const sarif = JSON.parse(renderRunReport(ctx.runId, "sarif", ctx.options).text);
    const result = sarif.runs[0].results.find((item: { properties: { fingerprint: string } }) => item.properties.fingerprint === finding.fingerprint);
    expect(result.suppressions).toEqual([]);
    expect(result.properties.status).toBe("proof_gap");
    expect(result.properties.review.missing).toContain("admin");
    expect(sarif.runs[0].properties.review.proofGaps).toBe(1);
  });

  it("has a coverage ledger by kind and rule and says the review is incomplete", () => {
    const md = renderRunReport(ctx.runId, "md", ctx.options).text;
    expect(md).toContain("### Review coverage");
    expect(md).toMatch(/> \*\*Review incomplete: \d+ of \d+ finding\(s\) and \d+ of \d+ hotspot\(s\) have no verdict/);
    expect(md).toMatch(/^- Findings: \d+ · with a verdict 1 · not reviewed \d+ — not reviewed, by rule: `/m);
    expect(md).toMatch(/^- Hotspots: \d+ · with a verdict 0 · not reviewed \d+/m);
    expect(md).not.toContain("No reportable issues found.");
    const summary = JSON.parse(renderRunReport(ctx.runId, "summary", ctx.options).text);
    expect(summary.triage.findings.reviewed).toBe(1);
    expect(summary.triage.hotspots.unreviewed).toBe(summary.triage.hotspots.total);
    expect(Object.keys(summary.triage.hotspots.unreviewedByRule).length).toBeGreaterThan(0);
    expect(Object.keys(summary.triage.findings.unreviewedByRule).length).toBeLessThanOrEqual(10);
  });
});

describe("report wording without a verdict", () => {
  let serial = 0;
  function record(overrides: Record<string, unknown> = {}): Finding {
    serial += 1;
    return {
      ...createFinding({
        ruleId: "py-eval-api",
        title: "eval",
        category: "sast",
        severity: "medium",
        confidence: "low",
        kind: "hotspot",
        file: "src/app.py",
        startLine: serial,
        evidence: "eval(x)",
        remediation: "Do not eval.",
        provenance: { engine: "builtin-rules" },
      }),
      id: `HOT-2026-${String(serial).padStart(4, "0")}`,
      ...overrides,
    } as Finding;
  }
  function context(findings: Finding[], hotspots: Finding[]): ReportContext {
    return {
      runId: "20260101T000000Z-test",
      target: "/repo",
      startedAt: "2026-01-01T00:00:00.000Z",
      finishedAt: "2026-01-01T00:00:01.000Z",
      durationMs: 1000,
      toolVersion: "0.4.0",
      nodeVersion: "v24.0.0",
      profile: "standard",
      offline: true,
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
    };
  }

  it("does not say no issues while hotspots are unreviewed", () => {
    const md = renderMarkdown(context([], [record(), record()]));
    expect(md).not.toContain("No reportable issues found.");
    expect(md).toContain("This is not a clean result: 2 finding(s) or hotspot(s) have no verdict yet");
    expect(md).toContain("Review incomplete: 0 of 0 finding(s) and 2 of 2 hotspot(s) have no verdict");
    const zh = renderMarkdown({ ...context([], [record()]), lang: "zh" });
    expect(zh).not.toContain("未发现可报告的问题。");
    expect(zh).toContain("复核未完成");
    expect(zh).toContain("### 复核覆盖");
  });

  it("keeps the plain wording when nothing is left to review", () => {
    const reviewed = record({ status: "false_positive", review: { status: "false_positive", rationale: "constant" } });
    const md = renderMarkdown(context([], [reviewed]));
    expect(md).toContain("No reportable issues found.");
    expect(md).not.toContain("Review incomplete");
    expect(renderMarkdown(context([], []))).not.toContain("### Review coverage");
  });

  it("counts suppressed records outside the ledger", () => {
    const triage = triageCoverage([record({ kind: "finding", status: "suppressed" })], [record()]);
    expect(triage.suppressed).toBe(1);
    expect(triage.findings.total).toBe(0);
    expect(triage.hotspots.byRule).toEqual([{ ruleId: "py-eval-api", total: 1, reviewed: 0, unreviewed: 1 }]);
    const sarif = JSON.parse(renderSarif(context([], [record()])));
    expect(sarif.runs[0].properties.review.hotspotsUnreviewed).toBe(1);
  });
});
