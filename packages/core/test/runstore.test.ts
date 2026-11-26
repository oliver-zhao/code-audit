import fs from "node:fs";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import {
  addFinding,
  assertSafeRegex,
  loadRun,
  queryFindings,
  readSnippet,
  recordVerdict,
  renderRunReport,
  resolveRunDir,
  reviewStats,
  RunStoreError,
  searchCode,
  type LoadedRun,
} from "../src/runstore.js";
import { scanProject } from "../src/scan.js";
import {
  VULNERABLE,
  cleanup,
  makeTempDir,
  writeFile,
} from "./helpers.js";

const temp = makeTempDir("runstore");
const project = path.join(temp, "project");
let cached: LoadedRun | undefined;

async function prepare(): Promise<{ run: LoadedRun; ref: string }> {
  if (!cached) {
    fs.cpSync(VULNERABLE, project, { recursive: true });
    // Default output (<root>/.audit/<run-id>) lets tests reopen by run id.
    const result = await scanProject({
      root: project,
      offline: true,
      formats: ["md", "json", "sarif"],
    });
    cached = loadRun(result.runId, { cwd: project });
    return { run: cached, ref: result.runId };
  }
  return { run: cached, ref: cached.runId };
}

afterAll(() => cleanup(temp));

describe("run store", () => {
  it("persists state.json and reopens a run by id", async () => {
    const { run, ref } = await prepare();
    expect(run.state?.phase).toBe("complete");
    expect(run.state?.progress?.files).toBeGreaterThan(0);
    expect(resolveRunDir(ref, { cwd: project })).toBe(run.runDir);
    expect(fs.existsSync(path.join(run.runDir, "state.json"))).toBe(true);
    expect(() => loadRun("does-not-exist", { cwd: project })).toThrow(
      RunStoreError,
    );
  });

  it("records verdicts with required rationale and keeps history", async () => {
    const { run, ref } = await prepare();
    const finding = run.findings[0];
    expect(finding).toBeDefined();
    if (!finding) return;
    expect(() =>
      recordVerdict(
        ref,
        finding.fingerprint,
        { status: "confirmed", rationale: "   " },
        { cwd: project },
      ),
    ).toThrow(/rationale/i);

    recordVerdict(
      ref,
      finding.fingerprint,
      { status: "needs_review", rationale: "first pass" },
      { cwd: project },
    );
    const result = recordVerdict(
      ref,
      finding.id,
      { status: "confirmed", rationale: "verified data flow" },
      { cwd: project },
    );
    expect(result.history).toBe(2);
    const reloaded = loadRun(ref, { cwd: project });
    expect(reloaded.verdicts[finding.fingerprint]?.status).toBe("confirmed");
    expect(reloaded.verdicts[finding.fingerprint]?.rationale).toBe(
      "verified data flow",
    );
    expect(reviewStats(reloaded).reviewed).toBe(1);
    expect(queryFindings(reloaded, { status: "confirmed" }).items[0]?.id).toBe(
      finding.id,
    );
  });

  it("adds a finding with evidence read from the repository", async () => {
    const { ref } = await prepare();
    const result = addFinding(
      ref,
      {
        file: "python/app.py",
        startLine: 14,
        title: "Operator-controlled SQL string",
        severity: "high",
        cwe: "CWE-200",
        rationale: "The name parameter reaches execute() without binding.",
        source: "manual review",
      },
      { cwd: project },
    );
    expect(result.promoted).toBe(false);
    expect(result.finding.kind).toBe("finding");
    expect(result.finding.provenance.engine).toBe("agent");
    expect(result.finding.source).toBe("manual review");
    expect(result.finding.evidence.length).toBeGreaterThan(0);

    const reloaded = loadRun(ref, { cwd: project });
    expect(
      reloaded.findings.some((item) => item.id === result.finding.id),
    ).toBe(true);
  });

  it("rejects path escapes and out-of-range lines when adding findings", async () => {
    const { ref } = await prepare();
    expect(() =>
      addFinding(
        ref,
        {
          file: "../../etc/passwd",
          startLine: 1,
          title: "escape",
          severity: "high",
          cwe: "CWE-89",
          rationale: "attempted escape",
        },
        { cwd: project },
      ),
    ).toThrow(RunStoreError);
    expect(() =>
      addFinding(
        ref,
        {
          file: "python/app.py",
          startLine: 99999,
          title: "out of range",
          severity: "high",
          cwe: "CWE-89",
          rationale: "line does not exist",
        },
        { cwd: project },
      ),
    ).toThrow(/out of range/i);
  });

  it("promotes a hotspot into a finding while keeping its fingerprint", async () => {
    const { run, ref } = await prepare();
    const hotspot = run.hotspots.find((item) => item.kind === "hotspot");
    expect(hotspot).toBeDefined();
    if (!hotspot) return;
    const result = addFinding(
      ref,
      {
        hotspotId: hotspot.id,
        rationale: "The dynamic query uses request input; confirmed injection.",
        source: "hotspot review",
      },
      { cwd: project },
    );
    expect(result.promoted).toBe(true);
    expect(result.finding.kind).toBe("finding");
    expect(result.finding.fingerprint).toBe(hotspot.fingerprint);
    const reloaded = loadRun(ref, { cwd: project });
    expect(
      reloaded.hotspots.some(
        (item) => item.fingerprint === hotspot.fingerprint,
      ),
    ).toBe(false);
    expect(
      reloaded.findings.some(
        (item) => item.fingerprint === hotspot.fingerprint,
      ),
    ).toBe(true);
  });

  it("reads redacted snippets and caps them at 400 lines", async () => {
    const { ref } = await prepare();
    const snippet = readSnippet(ref, "secrets/secrets.txt", 1, 4, {
      cwd: project,
    });
    expect(snippet.lines).toHaveLength(4);
    expect(snippet.content).not.toContain("AKIAFAKEFIXTURE00000");
    expect(snippet.content).toContain("aws_");

    writeFile(
      project,
      "long.txt",
      `${Array.from({ length: 500 }, (_, index) => `line ${index + 1}`).join("\n")}\n`,
    );
    const capped = readSnippet(ref, "long.txt", 1, 500, { cwd: project });
    expect(capped.endLine - capped.startLine + 1).toBe(400);
    expect(capped.truncated).toBe(true);
    expect(() =>
      readSnippet(ref, "node_modules/pkg/index.js", 1, 1, { cwd: project }),
    ).toThrow(/inventory/i);
  });

  it("searches with globs, regex guards and result caps", async () => {
    const { ref } = await prepare();
    const plain = searchCode(
      ref,
      { pattern: "os.system", maxResults: 5 },
      { cwd: project },
    );
    expect(plain.matches.length).toBeGreaterThan(0);
    expect(plain.matches.length).toBeLessThanOrEqual(5);

    const globbed = searchCode(
      ref,
      { pattern: "execute", glob: "python/**/*.py", maxResults: 10 },
      { cwd: project },
    );
    expect(
      globbed.matches.every((match) => match.file.startsWith("python/")),
    ).toBe(true);

    const regex = searchCode(
      ref,
      { pattern: "execute\\((.*)", regex: true, maxResults: 3 },
      { cwd: project },
    );
    expect(regex.matches.length).toBeGreaterThan(0);

    expect(() => assertSafeRegex("(a+)+")).toThrow(/nested quantifier/i);
    expect(() => assertSafeRegex("(")).toThrow(/invalid regex/i);
    expect(() => assertSafeRegex("a".repeat(300))).toThrow(/too long/i);
    expect(() =>
      searchCode(ref, { pattern: "x".repeat(300) }, { cwd: project }),
    ).toThrow(RunStoreError);
  });

  it("moves false positives out of the report body into 'Dismissed by review' and keeps them in JSON", async () => {
    const { run, ref } = await prepare();
    const finding = run.findings[0];
    expect(finding).toBeDefined();
    if (!finding) return;
    recordVerdict(
      ref,
      finding.fingerprint,
      {
        status: "false_positive",
        rationale: "constant value, not user input; checked the assignment at python/app.py:12",
      },
      { cwd: project },
    );

    const markdown = renderRunReport(ref, "md", { cwd: project });
    // Not in the body any more, but itemised for the human reader.
    const dismissedAt = markdown.text.indexOf("Dismissed by review\n");
    expect(dismissedAt).toBeGreaterThan(0);
    expect(markdown.text.slice(0, dismissedAt)).not.toContain(finding.id);
    expect(markdown.text.slice(dismissedAt)).toContain(`| ${finding.id} |`);
    expect(markdown.text).toContain("Review progress");
    expect(markdown.text).not.toContain("Candidate results, not reviewed");

    const json = renderRunReport(ref, "json", { cwd: project });
    const document = JSON.parse(json.text) as {
      findings: Array<{ id: string; status: string }>;
    };
    const kept = document.findings.find((item) => item.id === finding.id);
    expect(kept?.status).toBe("false_positive");
  });

  it("refuses to add a finding that duplicates an existing one on the same line and CWE", async () => {
    const { ref } = await prepare();
    let error: RunStoreError | undefined;
    try {
      addFinding(
        ref,
        {
          file: "python/app.py",
          startLine: 15,
          title: "Duplicate command injection",
          severity: "high",
          cwe: "CWE-78",
          rationale: "attempt to duplicate an existing finding",
        },
        { cwd: project },
      );
    } catch (caught) {
      error = caught as RunStoreError;
    }
    expect(error).toBeInstanceOf(RunStoreError);
    expect(error?.code).toBe("DUPLICATE_FINDING");
    expect(error?.message).toMatch(/already covers python\/app\.py:15/);
    expect(error?.message).toMatch(/audit_verdict/);
  });

  it("shows the host-agent reviewer on the cover once a verdict records one", async () => {
    const { run, ref } = await prepare();
    const finding = run.findings[0];
    expect(finding).toBeDefined();
    if (!finding) return;
    recordVerdict(
      ref,
      finding.fingerprint,
      {
        status: "confirmed",
        rationale: "traced source to sink",
        reviewer: "claude-test-model",
      },
      { cwd: project },
    );
    const markdown = renderRunReport(ref, "md", { cwd: project });
    expect(markdown.text).toContain("Reviewed by host agent");
    expect(markdown.text).toContain("claude-test-model");
  });
});
