/**
 * F3: structured verdicts (verdicts.json schemaVersion 2), proof_gap,
 * strict evidence, location checks through the path jail, independent
 * review and the review ledger of the reports - including the scenarios of
 * the adversarial review (F3_REVIEW.md: H1, H2, M1, M3, L1, L5-L10).
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createFinding, type Finding } from "../src/finding.js";
import {
  isConfusableLabel,
  neutralizeLinks,
  renderMarkdown,
  renderSarif,
  triageCoverage,
  type ReportContext,
} from "../src/report.js";
import {
  MAX_RUN_FILE_BYTES,
  MAX_VERDICTS_PER_FINDING,
} from "../src/runSchemas.js";
import {
  RunStoreError,
  effectiveFindings,
  initRunVerdicts,
  loadRun,
  queryFindings,
  recordVerdict,
  renderRunReport,
  runStatus,
  textLineCount,
  verdictsDisagree,
  withRunLock,
  type RecordVerdictInput,
} from "../src/runstore.js";
import { scanProject } from "../src/scan.js";
import {
  AGENT_ENVIRONMENT_VARIABLES,
  assertHumanContext,
  confirmHumanDecision,
  readTerminalLine,
  type HumanGateInput,
} from "../src/humanGate.js";

/** Test-only: the registered symbol runstore checks to skip the terminal checks. */
const TEST_HUMAN = { human: true, [Symbol.for("code-audit.test-only.skip-human-gate")]: true } as const;
import { CLI, REPO_ROOT, VULNERABLE, cleanup, makeTempDir, writeFile } from "./helpers.js";

const temp = makeTempDir("verdict-evidence");
const outside = fs.mkdtempSync(path.join(os.tmpdir(), "code-audit-f3-outside-"));
afterAll(() => {
  cleanup(temp);
  fs.rmSync(outside, { recursive: true, force: true });
});

const APP = "python/app.py";
const APP_LINES = textLineCount(fs.readFileSync(path.join(VULNERABLE, APP), "utf8"));

async function runOf(project: string, untrusted = false) {
  const result = await scanProject({ root: project, offline: true, engines: ["builtin"], untrusted });
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
  const current = (finding: Finding) =>
    effectiveFindings(loadRun(result.runId, options)).find((item) => item.fingerprint === finding.fingerprint);
  return { project, runId: result.runId, runDir: result.runDir, options, run, pick, verdict, refused, entries, current };
}

async function freshRun(name: string) {
  const project = path.join(temp, name);
  fs.cpSync(VULNERABLE, project, { recursive: true });
  return runOf(project);
}

type Ctx = Awaited<ReturnType<typeof freshRun>>;

const SOURCE = { file: APP, line: 1, role: "source" as const, note: "request data" };
const SINK = { file: APP, line: 2, role: "sink" as const, note: "dangerous call" };
const CONTROL = { file: APP, line: 3, note: "the value is a constant" };
const SAFE = "The argument is a constant defined in this module and never reaches the request handler.";
const SUB = { role: "independent" as const, independence: "subagent" as const };

describe("verdicts.json schemaVersion 2 reads version 1", () => {
  let ctx: Ctx;
  beforeAll(async () => {
    ctx = await freshRun("compat");
  });

  it("loads a hand-written version 1 file and appends version 2 entries", () => {
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
    // A version 1 entry is the primary decision.
    const result = ctx.verdict(first, { status: "likely", rationale: "agrees", reviewer: "second", ...SUB });
    expect(result.status).toBe("confirmed");
    expect(result.independentlyReviewed).toBe(true);
    ctx.verdict(second, { status: "needs_review", rationale: "unsure" });
    const written = JSON.parse(fs.readFileSync(path.join(ctx.runDir, "verdicts.json"), "utf8"));
    expect(written.schemaVersion).toBe(2);
    expect(written.entries).toHaveLength(3);
    expect(written.entries[0]).toEqual(v1.entries[0]);
    // Each entry is one reviewer's verdict, stored once.
    expect(written.entries[1]).toMatchObject({ role: "independent", independence: "subagent", status: "likely", rationale: "agrees" });
    expect(written.entries[1].reviewers).toBeUndefined();
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
    expect(ctx.refused(finding, { status: "false_positive", rationale: SAFE, control: { file: APP, line: 1 } as never }).message).toMatch(
      /control\.note is missing/,
    );
    expect(ctx.refused(finding, { status: "proof_gap", rationale: "x", missing: "too short" }).message).toMatch(
      /missing must say in at least 20 characters/,
    );
    expect(ctx.entries()).toHaveLength(0);
  });

  it("refuses fields that do not belong to the status (L5)", () => {
    const finding = ctx.pick("medium")[0] as Finding;
    const cases: Array<[RecordVerdictInput, RegExp]> = [
      [{ status: "confirmed", rationale: "x", missing: "whether the handler is reachable at all" }, /missing belongs to proof_gap only/],
      [{ status: "likely", rationale: "x", control: CONTROL }, /control belongs to false_positive only/],
      [{ status: "false_positive", rationale: SAFE, control: CONTROL, severityOverride: { severity: "low", reason: "x" } }, /severityOverride belongs to confirmed and likely only/],
      [{ status: "needs_review", rationale: "x", independence: "subagent" }, /independence belongs to role "independent" only/],
    ];
    for (const [input, message] of cases) {
      const error = ctx.refused(finding, input);
      expect(["INVALID_EVIDENCE", "INVALID_VERDICT"]).toContain(error.code);
      expect(error.message).toMatch(message);
    }
    expect(ctx.entries()).toHaveLength(0);
  });

  it("refuses locations outside the root, outside the file or not scanned by the run", () => {
    const finding = ctx.pick("medium")[0] as Finding;
    // Created after the scan: not part of what the run scanned.
    writeFile(ctx.project, "python/later.py", "x = 1\n");
    writeFile(ctx.project, "python/nl.py", "a = 1\nb = 2\n");
    const cases: Array<[Record<string, unknown>, RegExp]> = [
      [{ ...SOURCE, file: "../outside.py" }, /trace\[0\] \(\.\.\/outside\.py:1\): the path leaves the audit root/],
      [{ ...SOURCE, file: path.join(ctx.project, APP) }, /an absolute path is not accepted/],
      [{ ...SOURCE, file: "/etc/passwd" }, /an absolute path is not accepted/],
      [{ ...SOURCE, file: "python/escape.py" }, /the path leaves the audit root/],
      [{ ...SOURCE, file: "python/missing.py" }, /not a file this run scanned/],
      [{ ...SOURCE, file: "python/later.py" }, /not a file this run scanned/],
      [{ ...SOURCE, file: ".audit/index.json" }, /not a file this run scanned/],
      [{ ...SOURCE, file: "python/app.py\u0000.txt" }, /cannot be resolved inside the audit root|not a file this run scanned/],
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

  it("does not count a trailing line break as a line (L1)", () => {
    expect(textLineCount("")).toBe(0);
    expect(textLineCount("a")).toBe(1);
    expect(textLineCount("a\nb\n")).toBe(2);
    expect(textLineCount("a\r\nb")).toBe(2);
    expect(textLineCount("a\n\n")).toBe(2);
    // The fixture ends in a line break: its last line is accepted, the next is not.
    const finding = ctx.pick("medium")[0] as Finding;
    const text = fs.readFileSync(path.join(ctx.project, APP), "utf8");
    expect(text.endsWith("\n")).toBe(true);
    const lines = text.split("\n").length - 1;
    expect(ctx.refused(finding, { status: "likely", rationale: "x", trace: [{ ...SINK, line: lines + 1 }] }).code).toBe(
      "EVIDENCE_LOCATION_INVALID",
    );
    expect(ctx.verdict(finding, { status: "likely", rationale: "x", trace: [{ ...SINK, line: lines }] }).status).toBe("likely");
  });

  it("stores checked locations relative to the root, with notes, rationale and label redacted (L7)", () => {
    const finding = ctx.pick("medium")[1] as Finding;
    const token = ["ghp_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"].join("");
    const result = ctx.verdict(finding, {
      status: "confirmed",
      rationale: `request data reaches the call; token ${token}`,
      reviewer: `model ${token}`,
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
    expect(fs.readFileSync(path.join(ctx.runDir, "verdicts.json"), "utf8")).not.toContain(token);
    expect(fs.readFileSync(path.join(ctx.runDir, "findings.json"), "utf8")).not.toContain(token);
    expect(renderRunReport(ctx.runId, "md", ctx.options).text).not.toContain(token);
    // The counted severity does not change with an override.
    const effective = ctx.current(finding);
    expect(effective?.severity).toBe(finding.severity);
    expect(effective?.review?.severityOverride?.severity).toBe("critical");
  });

  it("counts a control as the evidence a serious dismissal needs", () => {
    const high = ctx.pick("high")[0] as Finding;
    expect(ctx.refused(high, { status: "false_positive", rationale: SAFE }).code).toBe("DISMISSAL_NEEDS_EVIDENCE");
    expect(ctx.verdict(high, { status: "false_positive", rationale: SAFE, control: CONTROL }).status).toBe("false_positive");
    const other = ctx.pick("high")[1] as Finding;
    expect(ctx.refused(other, { status: "false_positive", rationale: "fp", control: CONTROL }).code).toBe(
      "DISMISSAL_NEEDS_EVIDENCE",
    );
  });

  it("accepts proof_gap without missing when strict evidence is off", () => {
    const finding = ctx.pick("low")[0] ?? (ctx.pick("medium")[2] as Finding);
    expect(ctx.verdict(finding, { status: "proof_gap", rationale: "could not tell" }).status).toBe("proof_gap");
  });
});

describe("evidence of an untrusted run (M3)", () => {
  it("accepts files the run scanned in default-excluded directories, and nothing created later", async () => {
    const project = path.join(temp, "untrusted");
    writeFile(project, "dist/bundle.py", "import os\n\ndef run(cmd):\n    os.system(cmd)\n");
    writeFile(project, "app.py", "x = 1\n");
    const ctx = await runOf(project, true);
    const finding = [...ctx.run.findings, ...ctx.run.hotspots].find((item) => item.file === "dist/bundle.py");
    expect(finding, "the untrusted scan reports dist/bundle.py").toBeDefined();
    const at = { file: "dist/bundle.py", line: (finding as Finding).startLine };
    const result = ctx.verdict(finding as Finding, {
      status: "confirmed",
      rationale: "cmd reaches os.system",
      strictEvidence: true,
      trace: [{ ...at, role: "source" }, { ...at, role: "sink" }],
    });
    expect(result.status).toBe("confirmed");
    writeFile(project, "dist/new.py", "y = 2\n");
    expect(
      ctx.refused(finding as Finding, { status: "likely", rationale: "x", trace: [{ file: "dist/new.py", line: 1, role: "sink" }] }).message,
    ).toMatch(/not a file this run scanned/);
  });
});

describe("strict evidence", () => {
  let ctx: Ctx;
  beforeAll(async () => {
    ctx = await freshRun("strict");
  });

  it("requires a source and a sink, a sink for likely, a control, or missing", () => {
    const finding = ctx.pick("medium")[0] as Finding;
    const strict = { strictEvidence: true };
    let error = ctx.refused(finding, { status: "confirmed", rationale: "yes", ...strict });
    expect(error.code).toBe("EVIDENCE_REQUIRED");
    expect(error.message).toMatch(/no "source" and no "sink" step given\). Example: trace: \[\{"file":/);
    error = ctx.refused(finding, { status: "confirmed", rationale: "yes", trace: [SOURCE], ...strict });
    expect(error.message).toMatch(/no "sink" step given/);
    // L10: likely needs at least the sink it was checked at.
    error = ctx.refused(finding, { status: "likely", rationale: "probably", ...strict });
    expect(error.code).toBe("EVIDENCE_REQUIRED");
    expect(error.message).toMatch(/a likely verdict needs trace with at least one step of role "sink"/);
    error = ctx.refused(finding, { status: "false_positive", rationale: SAFE, ...strict });
    expect(error.message).toMatch(/needs control: .* for example control: \{"file":/);
    error = ctx.refused(finding, { status: "proof_gap", rationale: "unclear", ...strict });
    expect(error.message).toMatch(/needs missing: the fact you could not establish, in at least 20 characters/);
    expect(ctx.entries()).toHaveLength(0);
    ctx.verdict(finding, { status: "likely", rationale: "probably", trace: [SINK], ...strict });
    ctx.verdict(finding, { status: "needs_review", rationale: "unsure", ...strict });
    ctx.verdict(finding, { status: "confirmed", rationale: "traced", trace: [SOURCE, SINK], ...strict });
    ctx.verdict(finding, { status: "proof_gap", rationale: "unclear", missing: "whether the handler is reachable without login", ...strict });
    expect(ctx.entries().at(-1)?.status).toBe("proof_gap");
  });

  it("is inherited from the run and cannot be turned off by a call", () => {
    initRunVerdicts(ctx.runDir, ctx.runId, { strictEvidence: true });
    const document = loadRun(ctx.runId, ctx.options).verdictsDocument;
    expect(document.strictEvidence).toBe(true);
    expect(document.entries.length).toBe(4);
    const finding = ctx.pick("medium")[1] as Finding;
    expect(ctx.refused(finding, { status: "confirmed", rationale: "yes" }).code).toBe("EVIDENCE_REQUIRED");
    expect(ctx.refused(finding, { status: "confirmed", rationale: "yes", strictEvidence: false }).code).toBe(
      "EVIDENCE_REQUIRED",
    );
    const result = ctx.verdict(finding, { status: "confirmed", rationale: "traced", trace: [SOURCE, SINK] });
    expect(result.strictEvidence).toBe(true);
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

  it("needs a primary verdict, its own label and independence (M1)", () => {
    const finding = ctx.pick("high")[0] as Finding;
    let error = ctx.refused(finding, { status: "confirmed", rationale: "x", reviewer: "sub", ...SUB });
    expect(error.code).toBe("PRIMARY_VERDICT_REQUIRED");
    expect(error.message).toContain('role "primary"');
    expect(ctx.refused(finding, { status: "confirmed", rationale: "x", role: "boss" as never }).code).toBe("INVALID_VERDICT");
    ctx.verdict(finding, { status: "false_positive", rationale: SAFE, control: CONTROL, reviewer: "agent-x" });
    // harness t2 case A: the primary reviewer reviewing itself.
    error = ctx.refused(finding, { status: "false_positive", rationale: SAFE, control: CONTROL, reviewer: "agent-x", ...SUB });
    expect(error.code).toBe("INDEPENDENT_SAME_REVIEWER");
    error = ctx.refused(finding, { status: "false_positive", rationale: SAFE, control: CONTROL, ...SUB });
    expect(error.message).toMatch(/an independent verdict needs reviewer/);
    error = ctx.refused(finding, { status: "false_positive", rationale: SAFE, control: CONTROL, reviewer: "sub", role: "independent" });
    expect(error.message).toMatch(/needs independence: "subagent" .* or "same-session"/);
    const ok = ctx.verdict(finding, {
      status: "false_positive",
      rationale: "same-session: devil's advocate found no path; python/app.py:3 holds a constant.",
      reviewer: "devil",
      role: "independent",
      independence: "same-session",
    });
    expect(ok.status).toBe("false_positive");
    expect(ok.independentlyReviewed).toBe(true);
    expect(ctx.current(finding)?.review?.independentReview?.independence).toBe("same-session");
    // A primary verdict by another label would replace a reviewed decision.
    error = ctx.refused(finding, { status: "confirmed", rationale: "x", reviewer: "forgot-role", trace: [SOURCE, SINK] });
    expect(error.code).toBe("PRIMARY_REPLACE_REFUSED");
    expect(error.message).toMatch(/pass role "independent"/);
    expect(error.message).toContain("replace: true");
    const replaced = ctx.verdict(finding, { status: "confirmed", rationale: "re-decided", reviewer: "human", replace: true });
    expect(replaced.status).toBe("confirmed");
    expect(replaced.independentlyReviewed).toBe(false);
    expect(ctx.entries().at(-1)?.replace).toBe(true);
  });

  it("never erases a disagreement (H1, harness t2 case B)", () => {
    const finding = ctx.pick("high")[1] as Finding;
    ctx.verdict(finding, { status: "false_positive", rationale: SAFE, control: CONTROL, reviewer: "p" });
    const dissent = ctx.verdict(finding, {
      status: "confirmed",
      rationale: "the value is user controlled",
      reviewer: "sub",
      trace: [SOURCE, SINK],
      ...SUB,
    });
    expect(dissent.status).toBe("needs_review");
    expect(dissent.disagreement).toMatch(/independent reviewer sub said confirmed while the decision was false_positive/);
    // The same agent re-decides: the dispute stays open.
    const again = ctx.verdict(finding, { status: "false_positive", rationale: SAFE, control: CONTROL, reviewer: "p" });
    expect(again.status).toBe("needs_review");
    expect(again.disputed).toBe(true);
    expect(again.independentlyReviewed).toBe(false);
    // ... and cannot review itself.
    expect(ctx.refused(finding, { status: "false_positive", rationale: SAFE, control: CONTROL, reviewer: "p", ...SUB }).code).toBe(
      "INDEPENDENT_SAME_REVIEWER",
    );
    // The independent evidence never becomes part of the decision (L5).
    expect(ctx.current(finding)?.review?.trace).toBeUndefined();
    expect(ctx.current(finding)?.review?.control?.file).toBe(APP);
    let md = renderRunReport(ctx.runId, "md", ctx.options).text;
    expect(md).toMatch(/- \*\*Disputed verdicts \(\d+\)\*\*: /);
    expect(md).toMatch(new RegExp(`\\*\\*${finding.id}\\*\\* .*Status: needs\\\\_review \\(decision: false\\\\_positive\\), disputed: sub said confirmed \\(subagent\\) — the value is user controlled`));
    expect(md).not.toMatch(new RegExp(`\\| ${finding.id} \\|[^\\n]*independently reviewed`));
    // An agreeing independent with another label resolves it; the dissent stays visible.
    const resolved = ctx.verdict(finding, {
      status: "false_positive",
      rationale: `${SAFE} Checked python/app.py:3 again.`,
      reviewer: "sub-2",
      ...SUB,
    });
    expect(resolved.status).toBe("false_positive");
    expect(resolved.independentlyReviewed).toBe(true);
    expect(resolved.disputed).toBe(true);
    md = renderRunReport(ctx.runId, "md", ctx.options).text;
    expect(md).toMatch(new RegExp(`\\| ${finding.id} \\|[^\\n]*\\(independently reviewed by sub-2: subagent\\)[^\\n]*was disputed: sub said confirmed`));
    const history = ctx.current(finding)?.review?.history ?? [];
    expect(history.map((item) => `${item.role}:${item.reviewer}:${item.status}:${item.superseded}:${item.disagreed}`)).toEqual([
      "primary:p:false_positive:true:false",
      "independent:sub:confirmed:true:true",
      "primary:p:false_positive:false:false",
      "independent:sub-2:false_positive:false:false",
    ]);
  });

  it("keeps an agreed status, and an independent alone never dismisses", () => {
    const [real, gap] = ctx.pick("high").slice(2) as [Finding, Finding];
    ctx.verdict(real, { status: "likely", rationale: "probably reachable", trace: [SOURCE, SINK], reviewer: "p" });
    expect(ctx.verdict(real, { status: "confirmed", rationale: "traced", reviewer: "s", ...SUB }).status).toBe("likely");
    const dismiss = ctx.verdict(real, { status: "false_positive", rationale: `${SAFE} python/app.py:3`, reviewer: "s2", ...SUB });
    expect(dismiss.status).toBe("needs_review");
    expect(ctx.current(real)?.status).toBe("needs_review");
    ctx.verdict(gap, { status: "proof_gap", rationale: "unclear", missing: "whether the route requires a session cookie", reviewer: "p" });
    const later = ctx.verdict(gap, { status: "needs_review", rationale: "could not decide", reviewer: "s", ...SUB });
    expect(later.status).toBe("needs_review");
    expect(ctx.current(gap)?.review?.missing).toBe("whether the route requires a session cookie");
  });

  it("is reported in SARIF, findings.json and the summary", () => {
    const sarif = JSON.parse(renderRunReport(ctx.runId, "sarif", ctx.options).text);
    const reviewed = sarif.runs[0].results.filter((result: { properties: { review?: { independentlyReviewed: boolean } } }) => result.properties.review?.independentlyReviewed);
    expect(reviewed.length).toBeGreaterThan(0);
    expect(sarif.runs[0].properties.review.disputed).toBeGreaterThanOrEqual(2);
    const json = JSON.parse(renderRunReport(ctx.runId, "json", ctx.options).text);
    expect(json.findings.some((finding: Finding) => finding.review?.disputed === true)).toBe(true);
    const status = runStatus(ctx.runId, ctx.options);
    expect(status.triage.disputed).toBeGreaterThanOrEqual(2);
    expect(status.triage.disputesOpen).toBeGreaterThanOrEqual(1);
  });
});

describe("verdict storage stays bounded (H2, harness t4)", () => {
  let ctx: Ctx;
  beforeAll(async () => {
    ctx = await freshRun("storage");
  });

  it("stores each entry once and caps entries per finding", () => {
    const finding = ctx.pick("high")[0] as Finding;
    ctx.verdict(finding, { status: "likely", rationale: "p".repeat(4000), reviewer: "p" });
    const sizes: number[] = [];
    for (let index = 1; index < MAX_VERDICTS_PER_FINDING; index += 1) {
      const result = ctx.verdict(finding, {
        status: "likely",
        rationale: String(index).padEnd(5000, "r"),
        reviewer: `r${index}`,
        ...SUB,
      });
      expect(result.notices.join(" ")).toMatch(/cut to 4000 characters/);
      sizes.push(fs.statSync(path.join(ctx.runDir, "verdicts.json")).size);
    }
    // Linear growth: about one rationale per entry, never a copy of the history.
    const perEntry = (sizes.at(-1)! - sizes[0]!) / (sizes.length - 1);
    expect(perEntry).toBeLessThan(5000);
    expect(sizes.at(-1)!).toBeLessThan(300_000);
    const error = ctx.refused(finding, { status: "likely", rationale: "one more", reviewer: "extra", ...SUB });
    expect(error.code).toBe("VERDICT_LIMIT");
    expect(ctx.entries()).toHaveLength(MAX_VERDICTS_PER_FINDING);
    // The run is still readable by every tool.
    expect(runStatus(ctx.runId, ctx.options).phase).toBe("complete");
    // findings.json carries a short history, not 50 full rationales.
    const findingsJson = fs.statSync(path.join(ctx.runDir, "findings.json")).size;
    expect(findingsJson).toBeLessThan(2_000_000);
  });

  it("refuses a verdict that would make verdicts.json unreadable, and writes nothing", () => {
    const file = path.join(ctx.runDir, "verdicts.json");
    const document = JSON.parse(fs.readFileSync(file, "utf8"));
    const other = ctx.pick("high")[1] as Finding;
    // Fill the file to just under the reader's limit.
    const filler = MAX_RUN_FILE_BYTES - Buffer.byteLength(JSON.stringify(document, null, 2)) - 2000;
    document.entries.push({
      fingerprint: other.fingerprint,
      findingId: other.id,
      status: "needs_review",
      rationale: "x".repeat(filler),
      at: "2026-11-01T00:00:00.000Z",
    });
    fs.writeFileSync(file, `${JSON.stringify(document, null, 2)}\n`);
    const before = fs.statSync(file).size;
    expect(before).toBeLessThan(MAX_RUN_FILE_BYTES);
    const third = ctx.pick("high")[2] as Finding;
    const error = ctx.refused(third, { status: "needs_review", rationale: "y".repeat(3000) });
    expect(error.code).toBe("VERDICT_STORE_FULL");
    expect(fs.statSync(file).size).toBe(before);
  }, 60_000);
});

describe("concurrent writers (L8, harness t8)", () => {
  it("keeps every verdict of two processes writing at the same time", async () => {
    const ctx = await freshRun("concurrent");
    const [a, b] = ctx.pick("critical").concat(ctx.pick("high")) as [Finding, Finding];
    const core = path.join(REPO_ROOT, "packages/core/dist/index.js");
    const script = path.join(temp, "writer.mjs");
    fs.writeFileSync(
      script,
      [
        `const { recordVerdict } = await import(${JSON.stringify(core)});`,
        "const [runId, cwd, finding, tag, count] = process.argv.slice(2);",
        "for (let i = 0; i < Number(count); i++) {",
        "  recordVerdict(runId, finding, { status: 'needs_review', rationale: tag + i }, { cwd });",
        "}",
      ].join("\n"),
    );
    const N = 15;
    const runWriter = (finding: Finding, tag: string) =>
      new Promise<number>((resolve) => {
        const child = spawn(process.execPath, [script, ctx.runId, ctx.project, finding.id, tag, String(N)], {
          stdio: ["ignore", "ignore", "inherit"],
        });
        child.on("exit", (code) => resolve(code ?? 1));
      });
    const codes = await Promise.all([runWriter(a, "A"), runWriter(b, "B")]);
    expect(codes).toEqual([0, 0]);
    const entries = ctx.entries();
    expect(entries.filter((entry) => entry.rationale.startsWith("A"))).toHaveLength(N);
    expect(entries.filter((entry) => entry.rationale.startsWith("B"))).toHaveLength(N);
    expect(fs.existsSync(path.join(ctx.runDir, "verdicts.json.lock"))).toBe(false);
  }, 120_000);
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
    expect(status.findings).toBeGreaterThan(0);
    const md = renderRunReport(ctx.runId, "md", ctx.options).text;
    expect(md).toContain("- **Open proof gaps (1)**");
    expect(md).toContain(`**${finding.id}** critical ${finding.file}:${finding.startLine} — Missing: `);
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
    expect(md).toMatch(/; Hotspots: \d+ · with a verdict 0 · not reviewed \d+/);
    expect(md).not.toContain("No reportable issues found.");
    const summary = JSON.parse(renderRunReport(ctx.runId, "summary", ctx.options).text);
    expect(summary.triage.findings.reviewed).toBe(1);
    expect(summary.triage.hotspots.unreviewed).toBe(summary.triage.hotspots.total);
    expect(Object.keys(summary.triage.findings.unreviewedByRule).length).toBeLessThanOrEqual(10);
  });

  it("neutralises mentions and bare links in reviewer text (L9)", () => {
    const finding = ctx.pick("high")[0] as Finding;
    ctx.verdict(finding, {
      status: "proof_gap",
      rationale: "x",
      reviewer: "@octocat",
      missing: "ask @octocat or see https://evil.example/auto and www.evil.example",
    });
    const md = renderRunReport(ctx.runId, "md", ctx.options).text;
    expect(md).not.toMatch(/@octocat/);
    // Only the reviewer's text: the fixtures' own evidence may quote URLs.
    const reviewerLines = md.split("\n").filter((line) => line.includes("ask @"));
    expect(reviewerLines.length).toBeGreaterThan(0);
    for (const line of reviewerLines) {
      expect(line).not.toMatch(/https:\/\/evil\.example/);
      expect(line).not.toMatch(/www\.evil\.example/);
    }
    expect(md).toContain("https\u200b://evil.example/auto");
    expect(neutralizeLinks("mail me@x.org at http://a.b")).toBe("mail me@\u200bx.org at http\u200b://a.b");
  });
});

describe("report wording", () => {
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
  const reviewed = (overrides: Record<string, unknown> = {}) =>
    record({ status: "needs_review", review: { status: "needs_review", rationale: "unsure" }, ...overrides });

  it("keeps the plain-scan wording when nobody has reviewed anything (L6)", () => {
    const md = renderMarkdown(context([], [record(), record()]));
    expect(md).not.toContain("Review incomplete");
    expect(md).toContain("No reportable issues found.");
    expect(md).toContain("### Review coverage");
  });

  it("does not say no issues once a review has started and records are left", () => {
    const md = renderMarkdown(context([], [reviewed(), record()]));
    expect(md).not.toContain("No reportable issues found.");
    expect(md).toContain("This is not a clean result: 1 finding(s) or hotspot(s) have no verdict yet");
    expect(md).toContain("No vulnerable dependency was found.");
    expect(md).toContain("Review incomplete: 0 of 0 finding(s) and 1 of 2 hotspot(s) have no verdict");
    const zh = renderMarkdown({ ...context([], [reviewed(), record()]), lang: "zh" });
    expect(zh).not.toContain("未发现可报告的问题。");
    expect(zh).toContain("复核未完成");
    expect(zh).toContain("### 复核覆盖");
  });

  it("keeps the plain wording when nothing is left to review", () => {
    const md = renderMarkdown(context([], [record({ status: "false_positive", review: { status: "false_positive", rationale: "constant" } })]));
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

describe("round 2: labels, replacing a decision, human decisions, the lock", () => {
  let ctx: Ctx;
  beforeAll(async () => {
    ctx = await freshRun("round2");
  });
  const human = (finding: Finding, input: RecordVerdictInput) =>
    recordVerdict(ctx.runId, finding.id, input, ctx.options, TEST_HUMAN);

  it("compares reviewer labels normalised and stores them as given (L-n2)", () => {
    const finding = ctx.pick("medium")[0] as Finding;
    ctx.verdict(finding, { status: "likely", rationale: "probably", reviewer: "p" });
    for (const label of ["P", "p​", " p ", "ｐ", "p‮"]) {
      const error = ctx.refused(finding, { status: "likely", rationale: "x", reviewer: label, ...SUB });
      expect(error.code, JSON.stringify(label)).toBe("INDEPENDENT_SAME_REVIEWER");
    }
    // The same label in another spelling is the same primary reviewer: no replace needed.
    expect(ctx.verdict(finding, { status: "confirmed", rationale: "traced", reviewer: "P" }).status).toBe("confirmed");
    expect(ctx.entries().at(-1)?.reviewer).toBe("P");
  });

  it("refuses a primary verdict by another label unless replace is passed (L-n3)", () => {
    const finding = ctx.pick("medium")[1] as Finding;
    ctx.verdict(finding, { status: "false_positive", rationale: SAFE, control: CONTROL, reviewer: "p" });
    for (const reviewer of ["s", undefined]) {
      const error = ctx.refused(finding, { status: "confirmed", rationale: "real", reviewer });
      expect(error.code).toBe("PRIMARY_REPLACE_REFUSED");
      expect(error.message).toContain('pass role "independent"');
    }
    expect(ctx.verdict(finding, { status: "confirmed", rationale: "real", reviewer: "s", replace: true }).status).toBe("confirmed");
    expect(ctx.entries().at(-1)?.replace).toBe(true);
  });

  it("records a person's decision only through the human access, and it settles a dispute (M-n1)", () => {
    const finding = ctx.pick("high")[0] as Finding;
    ctx.verdict(finding, { status: "confirmed", rationale: "reachable", reviewer: "p", trace: [SOURCE, SINK] });
    ctx.verdict(finding, { status: "false_positive", rationale: `${SAFE} python/app.py:3`, reviewer: "sub", ...SUB });
    expect(ctx.current(finding)?.status).toBe("needs_review");
    // Not from an agent: the MCP server never passes the human access.
    const agent = ctx.refused(finding, { status: "false_positive", rationale: SAFE, reviewer: "alice", role: "human", replace: true });
    expect(agent.code).toBe("HUMAN_DECISION_CLI_ONLY");
    // It points at the CLI help without spelling out the command.
    expect(agent.message).toContain("see `code-audit verdict --help`");
    expect(agent.message).not.toContain("--role human");
    const refused = (input: RecordVerdictInput): RunStoreError => {
      try {
        human(finding, input);
      } catch (error) {
        return error as RunStoreError;
      }
      throw new Error("not refused");
    };
    expect(refused({ status: "false_positive", rationale: SAFE, reviewer: "alice", role: "human" }).message).toMatch(/pass --replace/);
    expect(refused({ status: "false_positive", rationale: SAFE, role: "human", replace: true }).message).toMatch(/needs --reviewer/);
    // Evidence as today: a high dismissal needs it from a person too.
    expect(refused({ status: "false_positive", rationale: "fp", reviewer: "alice", role: "human", replace: true }).code).toBe(
      "DISMISSAL_NEEDS_EVIDENCE",
    );
    const decided = human(finding, { status: "false_positive", rationale: SAFE, control: CONTROL, reviewer: "alice", role: "human", replace: true });
    expect(decided.status).toBe("false_positive");
    expect(decided.disagreement).toBeUndefined();
    expect(decided.disputed).toBe(true);
    const review = ctx.current(finding)?.review;
    expect(review?.decidedByPerson?.reviewer).toBe("alice");
    expect(review?.disputeOpen).toBe(false);
    expect(review?.history?.map((item) => item.role)).toEqual(["primary", "independent", "human"]);
    const md = renderRunReport(ctx.runId, "md", ctx.options).text;
    expect(md).toMatch(new RegExp(`\\| ${finding.id} \\|[^\\n]*\\(decided by a person \\(alice\\)\\)[^\\n]*was disputed: sub said false\\\\_positive`));
    // Agents cannot overturn it; only another human decision can.
    expect(ctx.refused(finding, { status: "confirmed", rationale: "x", reviewer: "p", replace: true, trace: [SOURCE, SINK] }).code).toBe(
      "HUMAN_DECISION_STANDS",
    );
    expect(ctx.refused(finding, { status: "confirmed", rationale: "x", reviewer: "sub2", ...SUB }).code).toBe("HUMAN_DECISION_STANDS");
    expect(human(finding, { status: "confirmed", rationale: "re-decided", reviewer: "bob", role: "human", replace: true }).status).toBe(
      "confirmed",
    );
  });

  it("refuses a planted lock at once and takes over a stale one (L-n1)", () => {
    const finding = ctx.pick("low")[0] ?? (ctx.pick("medium")[2] as Finding);
    const lock = path.join(ctx.runDir, "verdicts.json.lock");
    fs.symlinkSync(path.join(outside, "elsewhere"), lock);
    let started = Date.now();
    let error = ctx.refused(finding, { status: "needs_review", rationale: "x" });
    expect(error.code).toBe("RUN_LOCK_INVALID");
    expect(error.message).toContain("a symbolic link");
    expect(error.message).toContain(lock);
    expect(Date.now() - started).toBeLessThan(2000);
    fs.unlinkSync(lock);
    fs.mkdirSync(lock);
    started = Date.now();
    error = ctx.refused(finding, { status: "needs_review", rationale: "x" });
    expect(error.code).toBe("RUN_LOCK_INVALID");
    expect(error.message).toContain("a directory");
    expect(Date.now() - started).toBeLessThan(2000);
    fs.rmdirSync(lock);
    // A lock left by a writer that died three minutes ago.
    fs.writeFileSync(lock, "99999:dead\n");
    const old = new Date(Date.now() - 180_000);
    fs.utimesSync(lock, old, old);
    expect(ctx.verdict(finding, { status: "needs_review", rationale: "after a stale lock" }).status).toBe("needs_review");
    expect(fs.existsSync(lock)).toBe(false);
    expect(fs.readdirSync(ctx.runDir).filter((name) => name.includes(".lock"))).toEqual([]);
  });
});

describe("round 2: the CLI records structured, independent and human verdicts (L4, M-n1)", () => {
  it("supports every F3 option and scan --strict-evidence", () => {
    const project = path.join(temp, "cli");
    fs.cpSync(VULNERABLE, project, { recursive: true });
    const cli = (...args: string[]) =>
      spawnSync(process.execPath, [CLI, ...args], { cwd: project, encoding: "utf8" });
    const scan = cli("scan", ".", "--offline", "--engines", "builtin", "--strict-evidence");
    expect([0, 1]).toContain(scan.status);
    const runId = fs
      .readdirSync(path.join(project, ".audit"))
      .filter((name) => /^\d{8}T\d{6}Z-/.test(name))
      .sort()
      .at(-1) as string;
    const runDir = path.join(project, ".audit", runId);
    expect(JSON.parse(fs.readFileSync(path.join(runDir, "verdicts.json"), "utf8")).strictEvidence).toBe(true);
    const run = loadRun(runId, { cwd: project });
    const [first, second] = run.findings.filter((item) => item.severity === "high" || item.severity === "critical") as [Finding, Finding];
    // Strict: likely without a sink is refused.
    let result = cli("verdict", runId, first.id, "--status", "likely", "--rationale", "x");
    expect(result.status).not.toBe(0);
    expect(result.stderr).toMatch(/a likely verdict needs trace with at least one step of role "sink"/);
    result = cli("verdict", runId, first.id, "--status", "confirmed", "--rationale", "x", "--trace", "python/app.py");
    expect(result.status).not.toBe(0);
    expect(result.stderr).toMatch(/--trace python\/app\.py: expected <file>:<line>:<role>\[:<note>\]/);
    result = cli(
      "verdict", runId, first.id, "--status", "confirmed", "--rationale", "request data reaches the call",
      "--reviewer", "p", "--trace", "python/app.py:1:source:request: data", "--trace", "python/app.py:2:sink", "--cwe", "CWE-78",
    );
    expect(result.status, result.stderr).toBe(0);
    let entry = loadRun(runId, { cwd: project }).verdictsDocument.entries.at(-1);
    expect(entry?.trace).toEqual([
      { file: "python/app.py", line: 1, role: "source", note: "request: data" },
      { file: "python/app.py", line: 2, role: "sink" },
    ]);
    expect(entry?.cwe).toBe("CWE-78");
    result = cli(
      "verdict", runId, first.id, "--status", "false_positive", "--rationale", `${SAFE} python/app.py:3`,
      "--reviewer", "sub", "--role", "independent", "--independence", "subagent", "--control", "python/app.py:3:constant",
    );
    expect(result.status, result.stderr).toBe(0);
    expect(loadRun(runId, { cwd: project }).verdicts[first.fingerprint]?.status).toBe("needs_review");
    // Another agent label is refused without --replace; a person settles it.
    result = cli("verdict", runId, first.id, "--status", "confirmed", "--rationale", "x", "--reviewer", "q", "--trace", "python/app.py:2:source", "--trace", "python/app.py:2:sink");
    expect(result.stderr).toMatch(/would replace it/);
    // L-r3: the CLI message names the CLI flags.
    expect(result.stderr).toContain("call again with --replace");
    expect(result.stderr).toContain("--role independent --independence");
    expect(result.stderr).not.toContain("replace: true");
    // M-r2: not from a pipe, and not from an agent's shell.
    const humanArgs = [
      "verdict", runId, first.id, "--status", "false_positive", "--rationale", SAFE, "--reviewer", "alice",
      "--role", "human", "--replace", "--control", "python/app.py:3:constant",
    ];
    const cleanEnv = Object.fromEntries(
      Object.entries(process.env).filter(([name]) => !AGENT_ENVIRONMENT_VARIABLES.includes(name as never)),
    );
    result = spawnSync(process.execPath, [CLI, ...humanArgs], { cwd: project, encoding: "utf8", env: cleanEnv });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toMatch(/HUMAN_DECISION_REFUSED: --role human needs an interactive terminal/);
    result = spawnSync(process.execPath, [CLI, ...humanArgs], { cwd: project, encoding: "utf8", env: { ...cleanEnv, CLAUDECODE: "1" } });
    expect(result.stderr).toMatch(/HUMAN_DECISION_REFUSED: --role human is refused in a shell run by a coding agent \(CLAUDECODE set\)/);
    expect(loadRun(runId, { cwd: project }).verdicts[first.fingerprint]?.decidedByPerson).toBeUndefined();
    // What the CLI records once the person confirmed at a terminal.
    recordVerdict(
      runId,
      first.id,
      { status: "false_positive", rationale: SAFE, reviewer: "alice", role: "human", replace: true, control: { file: APP, line: 3, note: "constant" } },
      { cwd: project },
      { ...TEST_HUMAN, cli: true },
    );
    const current = loadRun(runId, { cwd: project }).verdicts[first.fingerprint];
    expect(current?.status).toBe("false_positive");
    expect(current?.decidedByPerson?.reviewer).toBe("alice");
    result = cli("verdict", runId, second.id, "--status", "proof_gap", "--rationale", "x", "--missing", "whether the route needs a session cookie");
    expect(result.status, result.stderr).toBe(0);
    entry = loadRun(runId, { cwd: project }).verdictsDocument.entries.at(-1);
    expect(entry?.missing).toBe("whether the route needs a session cookie");
    result = cli("verdict", runId, second.id, "--status", "proof_gap", "--rationale", "x", "--role", "boss");
    expect(result.status).not.toBe(0);
    expect(result.stderr).toMatch(/--role/);
  });
});

describe("round 3: the human gate, the lock race, labels in the report", () => {
  const gate = (overrides: Partial<HumanGateInput>): string | undefined => {
    let prompt = "";
    try {
      confirmHumanDecision({
        finding: "AUD-2026-0003",
        env: {},
        stdinIsTTY: true,
        stdoutIsTTY: true,
        write: (text) => {
          prompt += text;
        },
        readLine: () => "AUD-2026-0003",
        ...overrides,
      });
    } catch (error) {
      return (error as Error).message;
    }
    expect(prompt).toContain("Type AUD-2026-0003 to confirm");
    return undefined;
  };

  it("lets a person at a terminal confirm by typing the finding id, and nobody else (M-r2)", () => {
    expect(gate({})).toBeUndefined();
    expect(gate({ readLine: () => " AUD-2026-0003 " })).toBeUndefined();
    expect(gate({ readLine: () => "yes" })).toMatch(/finding id was not typed back/);
    expect(gate({ readLine: () => undefined })).toMatch(/finding id was not typed back/);
    expect(gate({ stdinIsTTY: false })).toMatch(/needs an interactive terminal/);
    expect(gate({ stdoutIsTTY: false })).toMatch(/needs an interactive terminal/);
    for (const name of AGENT_ENVIRONMENT_VARIABLES) {
      // Set, even empty, is enough; there is no override.
      expect(gate({ env: { [name]: "" } }), name).toMatch(new RegExp(`coding agent \\(${name} set\\)`));
      expect(gate({ env: { [name]: "1", CODE_AUDIT_I_AM_HUMAN: "1" } }), name).toMatch(/coding agent/);
    }
    expect(AGENT_ENVIRONMENT_VARIABLES).toEqual([
      "CLAUDECODE",
      "CLAUDE_CODE_ENTRYPOINT",
      "CODEX_SANDBOX",
      "CODEX_SANDBOX_NETWORK_DISABLED",
      "OPENCODE",
      "OPENCODE_BIN_PATH",
      "AI_AGENT",
      "DSH_AGENT",
    ]);
  });

  it("keeps every verdict when four processes race for a stale lock, 40 rounds (M-r1)", async () => {
    const ctx = await freshRun("stale-race");
    const targets = [...ctx.pick("high"), ...ctx.pick("critical"), ...ctx.pick("medium")].slice(0, 4);
    expect(targets).toHaveLength(4);
    const core = path.join(REPO_ROOT, "packages/core/dist/index.js");
    const script = path.join(temp, "stale-writer.mjs");
    fs.writeFileSync(
      script,
      [
        `const { recordVerdict } = await import(${JSON.stringify(core)});`,
        "const [runId, cwd, finding, tag] = process.argv.slice(2);",
        "recordVerdict(runId, finding, { status: 'needs_review', rationale: tag }, { cwd });",
      ].join("\n"),
    );
    const lock = path.join(ctx.runDir, "verdicts.json.lock");
    const write = (finding: Finding, tag: string) =>
      new Promise<number>((resolve) => {
        const child = spawn(process.execPath, [script, ctx.runId, ctx.project, finding.id, tag], {
          stdio: ["ignore", "ignore", "inherit"],
        });
        child.on("exit", (code) => resolve(code ?? 1));
      });
    const ROUNDS = 40;
    for (let round = 0; round < ROUNDS; round += 1) {
      fs.writeFileSync(lock, "1\n");
      const old = new Date(Date.now() - 10 * 60_000);
      fs.utimesSync(lock, old, old);
      const codes = await Promise.all(targets.map((finding, index) => write(finding, `r${round}w${index}`)));
      expect(codes, `round ${round}`).toEqual([0, 0, 0, 0]);
    }
    const entries = ctx.entries();
    expect(entries).toHaveLength(ROUNDS * 4);
    for (let round = 0; round < ROUNDS; round += 1) {
      for (let index = 0; index < 4; index += 1) {
        expect(entries.filter((entry) => entry.rationale === `r${round}w${index}`), `r${round}w${index}`).toHaveLength(1);
      }
    }
    expect(fs.existsSync(lock)).toBe(false);
    expect(fs.readdirSync(ctx.runDir).filter((name) => name.includes(".lock"))).toEqual([]);
  }, 300_000);

  it("refreshes a held lock so a slow write is not judged stale (L-r4)", () => {
    const dir = fs.mkdtempSync(path.join(temp, "lockdir-"));
    const lock = path.join(dir, "verdicts.json.lock");
    const saved = process.env.CODE_AUDIT_LOCK_REFRESH_MS;
    process.env.CODE_AUDIT_LOCK_REFRESH_MS = "50";
    try {
      withRunLock(dir, () => {
        const old = new Date(Date.now() - 10 * 60_000);
        fs.utimesSync(lock, old, old);
        // Block this thread; the heartbeat runs in a worker thread.
        const until = Date.now() + 1500;
        while (Date.now() < until) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);
        expect(Date.now() - fs.statSync(lock).mtimeMs).toBeLessThan(1000);
      });
    } finally {
      if (saved === undefined) delete process.env.CODE_AUDIT_LOCK_REFRESH_MS;
      else process.env.CODE_AUDIT_LOCK_REFRESH_MS = saved;
    }
    expect(fs.existsSync(lock)).toBe(false);
  });

  it("names the independent reviewer, marks non-ASCII labels and puts a human override on the cover (L-r2, M-r2)", async () => {
    const ctx = await freshRun("labels");
    const [one, two] = ctx.pick("high") as [Finding, Finding];
    ctx.verdict(one, { status: "false_positive", rationale: SAFE, control: CONTROL, reviewer: "p" });
    // A Cyrillic er looks like a Latin p.
    ctx.verdict(one, { status: "false_positive", rationale: `${SAFE} python/app.py:3`, reviewer: "р", ...SUB });
    ctx.verdict(two, { status: "confirmed", rationale: "real", reviewer: "p", trace: [SOURCE, SINK] });
    ctx.verdict(two, { status: "false_positive", rationale: `${SAFE} python/app.py:3`, reviewer: "sub", ...SUB });
    recordVerdict(
      ctx.runId,
      two.id,
      { status: "false_positive", rationale: SAFE, control: CONTROL, reviewer: "alice", role: "human", replace: true },
      ctx.options,
      { ...TEST_HUMAN, cli: true },
    );
    const md = renderRunReport(ctx.runId, "md", ctx.options).text;
    expect(md).toMatch(new RegExp(`\\| ${one.id} \\|[^\\n]*\\(independently reviewed by \\? \\[non-ASCII label\\]: subagent\\)`));
    expect(md).toContain(
      `> **1 dispute(s) between reviewers were settled by a person's decision recorded with the CLI (--role human): ${two.id}.`,
    );
    // L-r3: from MCP the message names replace: true.
    const error = ctx.refused(one, { status: "confirmed", rationale: "x", reviewer: "q", trace: [SOURCE, SINK] });
    expect(error.message).toContain("call again with replace: true");
    expect(error.message).not.toContain("--replace");
  });
});

describe("round 4: takeover mutex, the gate in core, invalid human entries, labels", () => {
  let ctx: Ctx;
  beforeAll(async () => {
    ctx = await freshRun("round4");
  });
  const staleLock = (): string => {
    const lock = path.join(ctx.runDir, "verdicts.json.lock");
    fs.writeFileSync(lock, "1\n");
    const old = new Date(Date.now() - 10 * 60_000);
    fs.utimesSync(lock, old, old);
    return lock;
  };

  it("waits for a takeover left by a crashed writer without spinning, then records (M-f1)", () => {
    const finding = ctx.pick("medium")[0] as Finding;
    const lock = staleLock();
    // A fresh takeover file: what a writer that died during a takeover leaves.
    fs.writeFileSync(`${lock}.takeover`, "9999:dead\n");
    const cpu = process.cpuUsage();
    const started = Date.now();
    expect(ctx.verdict(finding, { status: "needs_review", rationale: "after a crashed takeover" }).status).toBe("needs_review");
    const wall = Date.now() - started;
    const used = process.cpuUsage(cpu);
    expect(wall).toBeLessThan(15_000);
    expect(wall).toBeGreaterThan(3_000);
    // Waiting, not spinning: far less CPU time than wall time.
    expect((used.user + used.system) / 1000).toBeLessThan(wall / 3);
    expect(fs.readdirSync(ctx.runDir).filter((name) => name.includes(".lock"))).toEqual([]);
  }, 30_000);

  it("refuses a takeover path that is a directory or a symbolic link at once (M-f1)", () => {
    const finding = ctx.pick("medium")[1] as Finding;
    for (const plant of ["directory", "symlink"] as const) {
      const lock = staleLock();
      const mutex = `${lock}.takeover`;
      if (plant === "directory") fs.mkdirSync(mutex);
      else fs.symlinkSync(path.join(outside, "nowhere"), mutex);
      const started = Date.now();
      const error = ctx.refused(finding, { status: "needs_review", rationale: "x" });
      expect(error.code, plant).toBe("RUN_LOCK_INVALID");
      expect(error.message).toContain(mutex);
      expect(error.message).toContain(plant === "directory" ? "a directory" : "a symbolic link");
      expect(Date.now() - started).toBeLessThan(2000);
      fs.rmSync(mutex, { recursive: true, force: true });
      fs.rmSync(lock, { force: true });
    }
  });

  it("gates the exported API like the CLI (L-f1)", () => {
    const finding = ctx.pick("high")[0] as Finding;
    let caught: unknown;
    try {
      recordVerdict(
        ctx.runId,
        finding.id,
        { status: "confirmed", rationale: "x", reviewer: "bob", role: "human", replace: true, trace: [SOURCE, SINK] },
        ctx.options,
        { human: true },
      );
    } catch (error) {
      caught = error;
    }
    expect((caught as RunStoreError).code).toBe("HUMAN_DECISION_REFUSED");
    // Under vitest stdin is not a terminal, or an agent variable is set.
    expect((caught as RunStoreError).message).toMatch(/coding agent|interactive terminal/);
    expect(ctx.current(finding)?.review?.decidedByPerson).toBeUndefined();
    const checks = (context: Partial<Parameters<typeof assertHumanContext>[0]>) => {
      try {
        assertHumanContext({ env: {}, stdinIsTTY: true, stdoutIsTTY: true, ...context });
        return "ok";
      } catch (error) {
        return (error as Error).message;
      }
    };
    expect(checks({})).toBe("ok");
    expect(checks({ env: { AI_AGENT: "x" } })).toMatch(/AI_AGENT set/);
    expect(checks({ stdoutIsTTY: false })).toMatch(/interactive terminal/);
  });

  it("ignores hand-written human entries that this tool would not write (L-f1)", () => {
    const [high, other] = ctx.pick("high").slice(1) as [Finding, Finding];
    ctx.verdict(high, { status: "confirmed", rationale: "real", reviewer: "p", trace: [SOURCE, SINK] });
    const file = path.join(ctx.runDir, "verdicts.json");
    const document = JSON.parse(fs.readFileSync(file, "utf8"));
    const forged = (fields: Record<string, unknown>) => ({
      fingerprint: high.fingerprint,
      findingId: high.id,
      status: "false_positive",
      rationale: "hand edit",
      at: "2026-11-28T00:00:00.000Z",
      role: "human",
      ...fields,
    });
    document.entries.push(
      forged({ reviewer: "carol" }),
      forged({ replace: true }),
      forged({ reviewer: "carol", replace: true }),
      { ...forged({ reviewer: "dave", replace: true, rationale: SAFE, control: CONTROL }), fingerprint: other.fingerprint, findingId: other.id },
    );
    fs.writeFileSync(file, `${JSON.stringify(document, null, 2)}\n`);
    const run = loadRun(ctx.runId, ctx.options);
    // The three invalid entries are ignored: the decision stays confirmed.
    expect(run.verdicts[high.fingerprint]?.status).toBe("confirmed");
    expect(run.verdicts[high.fingerprint]?.decidedByPerson).toBeUndefined();
    // A complete one (label, replace, evidence) is read as a human decision.
    expect(run.verdicts[other.fingerprint]?.decidedByPerson?.reviewer).toBe("dave");
    const status = runStatus(ctx.runId, ctx.options);
    const warnings = status.warnings.filter((line: string) => line.startsWith("ignored an invalid human decision entry"));
    expect(warnings).toHaveLength(3);
    expect(warnings.join(" ")).toMatch(/no replace flag/);
    expect(warnings.join(" ")).toMatch(/no reviewer label/);
    expect(warnings.join(" ")).toMatch(/high or critical dismissal without the required evidence/);
    expect(status.notices.join(" ")).toContain("ignored an invalid human decision entry");
    const md = renderRunReport(ctx.runId, "md", ctx.options).text;
    expect(md).toContain(`ignored an invalid human decision entry for ${high.id}`);
    expect(md).not.toContain("decided by a person (carol)");
    // The file keeps every entry: it is append-only.
    expect(JSON.parse(fs.readFileSync(file, "utf8")).entries).toHaveLength(document.entries.length);
  });

  it("shows single-script names as written and marks confusable ones (L-f3)", () => {
    expect(isConfusableLabel("张三")).toBe(false);
    expect(isConfusableLabel("山田 太郎")).toBe(false);
    expect(isConfusableLabel("Иван")).toBe(false);
    expect(isConfusableLabel("Ελένη")).toBe(false);
    expect(isConfusableLabel("р")).toBe(true);
    expect(isConfusableLabel("pаypal")).toBe(true);
    expect(isConfusableLabel("alice")).toBe(false);
    const [one, two] = ctx.pick("critical") as [Finding, Finding];
    ctx.verdict(one, { status: "false_positive", rationale: SAFE, control: CONTROL, reviewer: "p" });
    ctx.verdict(one, { status: "false_positive", rationale: `${SAFE} python/app.py:3`, reviewer: "张三", ...SUB });
    ctx.verdict(two, { status: "false_positive", rationale: SAFE, control: CONTROL, reviewer: "p" });
    ctx.verdict(two, { status: "false_positive", rationale: `${SAFE} python/app.py:3`, reviewer: "pаypal", ...SUB });
    const md = renderRunReport(ctx.runId, "md", ctx.options).text;
    expect(md).toContain("independently reviewed by 张三: subagent");
    expect(md).toContain("independently reviewed by p?ypal [non-ASCII label]: subagent");
  });

  it("reads a typed line from a descriptor without spinning (L-f4)", () => {
    const file = path.join(temp, "typed.txt");
    fs.writeFileSync(file, "AUD-2026-0001\r\nrest\n");
    const fd = fs.openSync(file, "r");
    try {
      expect(readTerminalLine(fd)).toBe("AUD-2026-0001");
    } finally {
      fs.closeSync(fd);
    }
    const empty = path.join(temp, "empty.txt");
    fs.writeFileSync(empty, "");
    const fd2 = fs.openSync(empty, "r");
    try {
      expect(readTerminalLine(fd2)).toBeUndefined();
    } finally {
      fs.closeSync(fd2);
    }
  });
});
