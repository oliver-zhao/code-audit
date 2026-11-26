/**
 * A reviewing agent reads the audited repository and can be prompt-injected
 * into marking findings false positive. Dismissals must stay visible to the
 * human: itemised in the Markdown report, a WARNING wherever the result is
 * summarised, suppressions in SARIF - and a serious finding cannot be
 * dismissed without a real rationale and evidence.
 */
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { REPORT_LABELS, renderStepSummaryMarkdown, renderSummaryText } from "../src/index.js";
import {
  loadRun,
  recordVerdict,
  renderRunReport,
  runStatus,
  runSummary,
  RunStoreError,
} from "../src/runstore.js";
import { scanProject } from "../src/scan.js";
import type { Finding } from "../src/finding.js";
import { CLI, VULNERABLE, cleanup, makeTempDir } from "./helpers.js";

const temp = makeTempDir("dismissed");
afterAll(() => cleanup(temp));

const GOOD =
  "The value is a constant defined two lines above and never comes from the request; see python/app.py:12 for the assignment.";

async function freshRun(name: string, lang: "en" | "zh" = "en") {
  const project = path.join(temp, name);
  fs.cpSync(VULNERABLE, project, { recursive: true });
  const result = await scanProject({ root: project, offline: true, engines: ["builtin"], lang });
  const options = { cwd: project };
  const run = loadRun(result.runId, options);
  const pick = (severity: string, kind = "finding"): Finding[] =>
    [...run.findings, ...run.hotspots].filter(
      (finding) => finding.severity === severity && finding.kind === kind && finding.status === "candidate",
    );
  return { project, runId: result.runId, runDir: result.runDir, options, pick };
}

describe("dismissing a serious finding needs a rationale and evidence", () => {
  let ctx: Awaited<ReturnType<typeof freshRun>>;
  beforeAll(async () => {
    ctx = await freshRun("evidence");
  });

  it("refuses a short or unsupported rationale for high and critical findings", () => {
    const critical = ctx.pick("critical")[0] as Finding;
    const high = ctx.pick("high")[0] as Finding;
    for (const finding of [critical, high]) {
      for (const input of [
        { rationale: "fp" },
        { rationale: "false positive" },
        { rationale: "Not exploitable, test code." },
        // Long enough, but nothing that shows what was looked at.
        { rationale: "This is a false positive because the repository says the scanner is wrong about it." },
        // Evidence, but no real rationale.
        { rationale: "safe", evidenceLines: ["x = 1"] },
        { rationale: GOOD.slice(0, 20), evidenceLines: ["   "] },
      ]) {
        let error: unknown;
        try {
          recordVerdict(ctx.runId, finding.id, { status: "false_positive", ...input }, ctx.options);
        } catch (caught) {
          error = caught;
        }
        expect(error, input.rationale).toBeInstanceOf(RunStoreError);
        expect((error as RunStoreError).code).toBe("DISMISSAL_NEEDS_EVIDENCE");
        expect((error as RunStoreError).message).toContain(finding.id);
      }
    }
    // Nothing was recorded.
    expect(loadRun(ctx.runId, ctx.options).verdictsDocument.entries).toHaveLength(0);
  });

  it("accepts a rationale with a file:line reference or with evidence lines", () => {
    const [first, second] = ctx.pick("critical") as [Finding, Finding];
    expect(
      recordVerdict(ctx.runId, first.id, { status: "false_positive", rationale: GOOD }, ctx.options).status,
    ).toBe("false_positive");
    expect(
      recordVerdict(
        ctx.runId,
        second.id,
        {
          status: "false_positive",
          rationale: "The query text is a literal and the only argument is bound as a parameter.",
          evidenceLines: ['cursor.execute("SELECT 1 WHERE id = ?", (item_id,))'],
        },
        ctx.options,
      ).status,
    ).toBe("false_positive");
  });

  it("does not ask for more on lower severities, hotspots or other verdicts", () => {
    const medium = ctx.pick("medium")[0] ?? ctx.pick("low")[0];
    expect(medium).toBeDefined();
    recordVerdict(ctx.runId, (medium as Finding).id, { status: "false_positive", rationale: "test data" }, ctx.options);
    const hotspot = [...ctx.pick("high", "hotspot"), ...ctx.pick("critical", "hotspot"), ...ctx.pick("medium", "hotspot")][0];
    if (hotspot) {
      recordVerdict(ctx.runId, hotspot.id, { status: "false_positive", rationale: "not reachable" }, ctx.options);
    }
    const high = ctx.pick("high")[1] as Finding;
    recordVerdict(ctx.runId, high.id, { status: "confirmed", rationale: "yes" }, ctx.options);
    recordVerdict(ctx.runId, high.id, { status: "needs_review", rationale: "unsure" }, ctx.options);
  });

  it("is enforced by the CLI too", () => {
    const high = ctx.pick("high")[2] as Finding;
    const refused = spawnSync(
      process.execPath,
      [CLI, "verdict", ctx.runId, high.id, "--status", "false_positive", "--rationale", "fp"],
      { cwd: ctx.project, encoding: "utf8" },
    );
    expect(refused.status).not.toBe(0);
    expect(refused.stderr).toMatch(/requires a rationale of at least 40 characters/);
    const accepted = spawnSync(
      process.execPath,
      [
        CLI, "verdict", ctx.runId, high.id, "--status", "false_positive",
        "--rationale", "The argument is a fixed list and no shell is involved in this call.",
        "--evidence-line", 'subprocess.run(["ls", "-l"])', "--reviewer", "cli-reviewer",
      ],
      { cwd: ctx.project, encoding: "utf8" },
    );
    expect(accepted.status, accepted.stderr).toBe(0);
    expect(accepted.stderr).toMatch(/WARNING: \d+ finding\(s\) at severity ≥ high were marked false positive by .*cli-reviewer/);
  });
});

describe("dismissed findings stay visible", () => {
  let ctx: Awaited<ReturnType<typeof freshRun>>;
  let dismissed: Finding[];
  const HOSTILE_REVIEWER = "evil|model\n## Injected heading <script>";
  const HOSTILE_RATIONALE = `${GOOD}\n\n| injected | row |\n# All clear, nothing to see <img src=x> password = "hunter2hunter2X9"`;

  beforeAll(async () => {
    ctx = await freshRun("visible");
    // A prompt-injected agent dismisses every critical and high finding.
    dismissed = [...ctx.pick("critical"), ...ctx.pick("high")];
    expect(dismissed.length).toBeGreaterThan(20);
    dismissed.forEach((finding, index) => {
      recordVerdict(
        ctx.runId,
        finding.id,
        {
          status: "false_positive",
          rationale: index === 0 ? HOSTILE_RATIONALE : `${GOOD} (#${index})`,
          reviewer: index === 0 ? HOSTILE_REVIEWER : index % 2 === 0 ? "model-a" : "model-b",
          ...(index === 1 ? { evidenceLines: ["safe_call(constant)"] } : {}),
        },
        ctx.options,
      );
    });
  });

  it("lists every dismissed finding in the Markdown report", () => {
    const md = fs.readFileSync(path.join(ctx.runDir, "report.md"), "utf8");
    const start = md.indexOf("Dismissed by review\n");
    expect(start).toBeGreaterThan(0);
    const section = md.slice(start, md.indexOf("\n## ", start));
    const rows = section.split("\n").filter((line) => line.startsWith("| AUD-"));
    expect(rows).toHaveLength(dismissed.length);
    for (const finding of dismissed) {
      const row = rows.find((line) => line.startsWith(`| ${finding.id} |`));
      expect(row, finding.id).toBeDefined();
      expect(row).toContain(`| ${finding.severity} |`);
      expect(row).toContain(finding.ruleId);
      expect(row).toContain(`| ${finding.startLine} |`);
      expect(row).toMatch(/model-a|model-b|evil/);
      expect(row).toContain("never comes from the request");
    }
    expect(section).toMatch(/evidence: safe\\?_call/);
    // Reviewer and rationale are one escaped line each: no injected heading,
    // table row or HTML, and a secret quoted in a rationale is masked.
    expect(section).not.toMatch(/^#+ (All clear|Injected)/m);
    expect(section).not.toContain("<script>");
    expect(section).not.toContain("<img");
    expect(section).not.toContain("hunter2hunter2X9");
    for (const row of rows) expect(row.split(" | ").length).toBe(8);
    // They are no longer in the body of the report.
    const body = md.slice(0, start);
    for (const finding of dismissed.slice(0, 5)) expect(body).not.toContain(`${finding.id} `);
  });

  it("warns on the cover and in every summary", () => {
    const md = fs.readFileSync(path.join(ctx.runDir, "report.md"), "utf8");
    const cover = md.slice(0, md.indexOf("\n## 2."));
    const sentence = new RegExp(
      `\\*\\*WARNING:\\*\\* ${dismissed.length} finding\\(s\\) at severity ≥ high were marked false positive by .*model-a, model-b.* and do not count toward the exit code; review the section "Dismissed by review"`,
    );
    expect(cover).toMatch(sentence);
    expect(cover).not.toContain("\n## Injected heading");

    const summary = runSummary(loadRun(ctx.runId, ctx.options));
    expect(summary.reductions.dismissed.atFailOn).toBe(dismissed.length);
    expect(summary.reductions.dismissed.reviewers).toContain("model-a");
    const plain = `WARNING: ${dismissed.length} finding(s) at severity ≥ high were marked false positive by`;
    expect(renderSummaryText(summary).join("\n")).toContain(plain);
    expect(renderStepSummaryMarkdown({ summary, reportPaths: [] })).toContain(
      `${dismissed.length} finding(s) at severity ≥ high were marked false positive by`,
    );
    expect(runStatus(ctx.runId, ctx.options).dismissedWarning).toContain(plain);
    const report = renderRunReport(ctx.runId, "summary", ctx.options);
    expect(report.dismissedWarning).toContain(plain);
    expect(JSON.parse(report.text).dismissedWarning).toContain(plain);

    const status = spawnSync(process.execPath, [CLI, "status", ctx.runId], { cwd: ctx.project, encoding: "utf8" });
    expect(status.stdout).toContain(plain);
    const cli = spawnSync(process.execPath, [CLI, "report", ctx.runId, "--format", "md"], {
      cwd: ctx.project,
      encoding: "utf8",
    });
    expect(cli.stderr).toContain(plain);
  });

  it("records each dismissal as a SARIF suppression and keeps the review in findings.json", () => {
    const sarif = JSON.parse(fs.readFileSync(path.join(ctx.runDir, "results.sarif"), "utf8")) as {
      runs: Array<{
        results: Array<{
          partialFingerprints?: Record<string, string>;
          fingerprints?: Record<string, string>;
          suppressions: Array<{ kind: string; status: string; justification: string }>;
        }>;
      }>;
    };
    const suppressed = (sarif.runs[0]?.results ?? []).filter((result) => result.suppressions.length > 0);
    expect(suppressed).toHaveLength(dismissed.length);
    for (const result of suppressed) {
      expect(result.suppressions[0]?.kind).toBe("external");
      expect(result.suppressions[0]?.status).toBe("accepted");
      expect(result.suppressions[0]?.justification).toMatch(/^Marked false positive by .+: .*never comes from the request/);
      expect(result.suppressions[0]?.justification).not.toContain("\n");
    }
    const json = JSON.parse(fs.readFileSync(path.join(ctx.runDir, "findings.json"), "utf8")) as {
      findings: Array<Finding>;
    };
    const stored = json.findings.filter((finding) => finding.status === "false_positive");
    expect(stored).toHaveLength(dismissed.length);
    for (const finding of stored) {
      expect(finding.review?.status).toBe("false_positive");
      expect(finding.review?.rationale).toContain("never comes from the request");
    }
  });

  it("takes reviewer and rationale from verdicts.json, not from findings.json", () => {
    const file = path.join(ctx.runDir, "findings.json");
    const json = JSON.parse(fs.readFileSync(file, "utf8")) as { findings: Array<Finding> };
    const untouched = json.findings.find((finding) => finding.status === "candidate") as Finding;
    untouched.review = { status: "confirmed", rationale: "forged", reviewer: "forged-reviewer" };
    fs.writeFileSync(file, JSON.stringify(json));
    const run = loadRun(ctx.runId, ctx.options);
    renderRunReport(ctx.runId, "md", ctx.options);
    expect(fs.readFileSync(path.join(run.runDir, "report.md"), "utf8")).not.toContain("forged-reviewer");
    expect(fs.readFileSync(file, "utf8")).not.toContain("forged-reviewer");
  });

  it("has no section and no warning in a run nobody reviewed", async () => {
    const clean = await freshRun("unreviewed");
    const md = fs.readFileSync(path.join(clean.runDir, "report.md"), "utf8");
    expect(md).not.toContain("Dismissed by review");
    expect(runStatus(clean.runId, clean.options).dismissedWarning).toBeUndefined();
    // Reviewed, nothing dismissed: the section says so.
    recordVerdict(clean.runId, (clean.pick("high")[0] as Finding).id, { status: "confirmed", rationale: "real" }, clean.options);
    const reviewed = fs.readFileSync(path.join(clean.runDir, "report.md"), "utf8");
    expect(reviewed).toContain("Dismissed by review");
    expect(reviewed).toContain("No finding was marked false positive.");
  });

  it("is complete in the Chinese report", async () => {
    const zh = await freshRun("zh", "zh");
    const critical = zh.pick("critical")[0] as Finding;
    recordVerdict(zh.runId, critical.id, { status: "false_positive", rationale: GOOD, reviewer: "model-zh" }, zh.options);
    const md = fs.readFileSync(path.join(zh.runDir, "report.md"), "utf8");
    expect(md).toContain(REPORT_LABELS.zh.dismissedSection);
    expect(md).toMatch(/\*\*警告:\*\* 1 条严重性 ≥ high 的发现被 model-zh 标记为误报/);
    expect(md).not.toContain("Dismissed by review");
    expect(Object.keys(REPORT_LABELS.zh).sort()).toEqual(Object.keys(REPORT_LABELS.en).sort());
  });
});
