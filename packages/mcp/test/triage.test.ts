/**
 * F3 end to end over MCP: a strict-evidence run triaged the way the skill
 * describes it - structured verdicts, a refused location, an independent
 * review that disagrees, a proof gap - and the ledger in every channel.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createAuditServer } from "../src/index.js";
import { MAX_RESPONSE_BYTES } from "../src/server.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "../../..");
const temp = fs.mkdtempSync(path.join(repoRoot, ".tmp-test-mcp-triage-"));
const project = path.join(temp, "project");
let client: Client;

interface Raw {
  text: string;
  isError?: boolean;
}

async function raw(name: string, args: Record<string, unknown>): Promise<Raw> {
  const result = (await client.callTool({ name, arguments: args })) as {
    content: Array<{ type: string; text: string }>;
    isError?: boolean;
  };
  return { text: result.content[0]?.text ?? "{}", ...(result.isError ? { isError: true } : {}) };
}

async function call(name: string, args: Record<string, unknown>): Promise<Record<string, unknown>> {
  const result = await raw(name, args);
  expect(result.isError, result.text.slice(0, 400)).toBeUndefined();
  expect(Buffer.byteLength(result.text, "utf8")).toBeLessThanOrEqual(MAX_RESPONSE_BYTES);
  return JSON.parse(result.text) as Record<string, unknown>;
}

async function callError(name: string, args: Record<string, unknown>): Promise<{ code: string; message: string }> {
  const result = await raw(name, args);
  expect(result.isError).toBe(true);
  return (JSON.parse(result.text) as { error: { code: string; message: string } }).error;
}

interface Item {
  id: string;
  kind: string;
  severity: string;
  status: string;
  file: string;
  start_line: number;
  independently_reviewed?: boolean;
  missing?: string;
}

async function allItems(runId: string, kind: string): Promise<Item[]> {
  const items: Item[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < 50; page += 1) {
    const result = (await call("audit_findings", { run_id: runId, kind, ...(cursor ? { cursor } : {}) })) as {
      items: Item[];
      next_cursor: string | null;
    };
    items.push(...result.items);
    if (!result.next_cursor) break;
    cursor = result.next_cursor;
  }
  return items;
}

async function allItemsBlind(runId: string): Promise<Item[]> {
  const items: Item[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < 50; page += 1) {
    const result = (await call("audit_findings", { run_id: runId, kind: "finding", blind: true, ...(cursor ? { cursor } : {}) })) as {
      items: Item[];
      next_cursor: string | null;
    };
    items.push(...result.items);
    if (!result.next_cursor) break;
    cursor = result.next_cursor;
  }
  return items;
}

beforeAll(async () => {
  fs.cpSync(path.join(repoRoot, "fixtures/vulnerable"), project, { recursive: true });
  const server = createAuditServer({ base: temp });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  client = new Client({ name: "code-audit-triage-test", version: "1.0.0" });
  await client.connect(clientTransport);
});

afterAll(async () => {
  await client.close();
  fs.rmSync(temp, { recursive: true, force: true });
});

describe("structured triage over MCP", () => {
  it("runs a full strict-evidence review", async () => {
    const tools = await client.listTools();
    const verdictTool = tools.tools.find((tool) => tool.name === "audit_verdict");
    const properties = Object.keys((verdictTool?.inputSchema as { properties: object }).properties);
    for (const field of ["role", "trace", "conditions", "control", "missing", "cwe", "severityOverride", "strict_evidence"]) {
      expect(properties).toContain(field);
    }

    const started = await call("audit_start", {
      root: project,
      offline: true,
      engines: ["builtin"],
      strict_evidence: true,
    });
    expect(started.strict_evidence).toBe(true);
    const runId = String(started.run_id);
    let status: Record<string, unknown> = {};
    for (let attempt = 0; attempt < 400; attempt += 1) {
      status = await call("audit_status", { run_id: runId });
      if (status.phase !== "running") break;
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    expect(status.phase).toBe("complete");
    expect(status.truncated).toBeUndefined();
    const triage = status.triage as { findings: { reviewed: number; unreviewed: number }; hotspots: { unreviewed: number } };
    expect(triage.findings.reviewed).toBe(0);
    expect(triage.findings.unreviewed).toBeGreaterThan(0);

    const findings = await allItems(runId, "finding");
    const highs = findings.filter((item) => item.severity === "high" || item.severity === "critical");
    expect(highs.length).toBeGreaterThanOrEqual(3);
    const [first, second, third] = highs as [Item, Item, Item];
    const read = await call("audit_read", { run_id: runId, file: first.file, startLine: first.start_line, endLine: first.start_line });
    expect(read.total_lines).toBeGreaterThanOrEqual(first.start_line);

    // Strict: confirmed without a trace is refused, with the field to add.
    const bare = await callError("audit_verdict", {
      run_id: runId,
      finding: first.id,
      status: "confirmed",
      rationale: "user input reaches the sink",
    });
    expect(bare.code).toBe("EVIDENCE_REQUIRED");
    expect(bare.message).toContain('"role":"source"');

    // A location outside the file is refused and named.
    const wrong = await callError("audit_verdict", {
      run_id: runId,
      finding: first.id,
      status: "confirmed",
      rationale: "user input reaches the sink",
      trace: [
        { file: first.file, line: first.start_line, role: "source" },
        { file: first.file, line: 100000, role: "sink" },
      ],
    });
    expect(wrong.code).toBe("EVIDENCE_LOCATION_INVALID");
    expect(wrong.message).toContain(`trace[1] (${first.file}:100000)`);
    const escaped = await callError("audit_verdict", {
      run_id: runId,
      finding: first.id,
      status: "confirmed",
      rationale: "user input reaches the sink",
      trace: [
        { file: "../../package.json", line: 1, role: "source" },
        { file: first.file, line: first.start_line, role: "sink" },
      ],
    });
    expect(escaped.code).toBe("EVIDENCE_LOCATION_INVALID");
    expect(escaped.message).toContain("leaves the audit root");

    const confirmed = await call("audit_verdict", {
      run_id: runId,
      finding: first.id,
      status: "confirmed",
      rationale: "user input reaches the sink",
      reviewer: "primary-model",
      trace: [
        { file: first.file, line: first.start_line, role: "source", note: "request value" },
        { file: first.file, line: first.start_line, role: "sink", note: "dangerous call" },
      ],
      conditions: { auth: "none", userInteraction: false },
    });
    expect(confirmed.status).toBe("confirmed");
    expect(confirmed.strictEvidence).toBe(true);

    // The independent reviewer lists blind: no verdict status, no review fields.
    const blindPage = (await call("audit_findings", { run_id: runId, kind: "finding", blind: true, limit: 20 })) as {
      blind: boolean;
      items: Item[];
    };
    expect(blindPage.blind).toBe(true);
    const blindFirst = (await allItemsBlind(runId)).find((item) => item.id === first.id);
    expect(blindFirst?.status).toBe("candidate");
    expect(blindFirst?.independently_reviewed).toBeUndefined();
    expect((await callError("audit_findings", { run_id: runId, blind: true, status: "confirmed" })).message).toMatch(
      /blind listing does not filter by status or minConfidence/,
    );
    const blindRead = await call("audit_read", { run_id: runId, file: first.file, startLine: first.start_line, blind: true });
    expect(blindRead.blind).toBe(true);

    // An independent review needs its own label and says how independent it is.
    const noIndependence = await callError("audit_verdict", {
      run_id: runId,
      finding: first.id,
      status: "false_positive",
      rationale: "x",
      reviewer: "fresh-subagent",
      role: "independent",
    });
    expect(noIndependence.message).toMatch(/needs independence/);
    const sameLabel = await callError("audit_verdict", {
      run_id: runId,
      finding: first.id,
      status: "confirmed",
      rationale: "same agent",
      reviewer: "primary-model",
      role: "independent",
      independence: "same-session",
      trace: [
        { file: first.file, line: first.start_line, role: "source" },
        { file: first.file, line: first.start_line, role: "sink" },
      ],
    });
    expect(sameLabel.code).toBe("INDEPENDENT_SAME_REVIEWER");

    // The fresh sub-agent disagrees.
    const independent = await call("audit_verdict", {
      run_id: runId,
      finding: first.id,
      status: "false_positive",
      rationale: `The value is fixed before the call; see ${first.file}:${first.start_line} where it is assigned from a constant.`,
      reviewer: "fresh-subagent",
      role: "independent",
      independence: "subagent",
      control: { file: first.file, line: first.start_line, note: "constant value" },
    });
    expect(independent.status).toBe("needs_review");
    expect(independent.requestedStatus).toBe("false_positive");
    expect(String(independent.disagreement)).toContain("fresh-subagent");
    expect(independent.dismissedWarning).toBeUndefined();
    // A sub-agent that forgot role cannot overwrite the decision.
    const forgot = await callError("audit_verdict", {
      run_id: runId,
      finding: first.id,
      status: "needs_review",
      rationale: "forgot the role",
      reviewer: "another-subagent",
    });
    expect(forgot.code).toBe("PRIMARY_REPLACE_REFUSED");
    // A second sub-agent agrees with the decision: resolved, the dissent stays visible.
    const resolved = await call("audit_verdict", {
      run_id: runId,
      finding: first.id,
      status: "confirmed",
      rationale: "traced it independently",
      reviewer: "second-subagent",
      role: "independent",
      independence: "subagent",
      trace: [
        { file: first.file, line: first.start_line, role: "source" },
        { file: first.file, line: first.start_line, role: "sink" },
      ],
    });
    expect(resolved.status).toBe("confirmed");
    expect(resolved.independentlyReviewed).toBe(true);
    expect(resolved.disputed).toBe(true);

    // A proof gap needs `missing` under strict evidence.
    const gapRefused = await callError("audit_verdict", {
      run_id: runId,
      finding: second.id,
      status: "proof_gap",
      rationale: "could not decide",
    });
    expect(gapRefused.code).toBe("EVIDENCE_REQUIRED");
    const gap = await call("audit_verdict", {
      run_id: runId,
      finding: second.id,
      status: "proof_gap",
      rationale: "could not decide",
      missing: "whether the handler is mounted behind the login middleware",
    });
    expect(gap.status).toBe("proof_gap");
    // A strict dismissal needs a control.
    const noControl = await callError("audit_verdict", {
      run_id: runId,
      finding: third.id,
      status: "false_positive",
      rationale: `Not reachable: the only caller is a unit test, see ${third.file}:${third.start_line}.`,
    });
    expect(noControl.code).toBe("EVIDENCE_REQUIRED");
    expect(noControl.message).toContain("needs control");
    // An independent review of a finding without a verdict.
    const orphan = await callError("audit_verdict", {
      run_id: runId,
      finding: third.id,
      status: "confirmed",
      rationale: "x",
      reviewer: "sub",
      role: "independent",
      independence: "subagent",
      trace: [
        { file: third.file, line: third.start_line, role: "source" },
        { file: third.file, line: third.start_line, role: "sink" },
      ],
    });
    expect(orphan.code).toBe("PRIMARY_VERDICT_REQUIRED");

    const listed = await allItems(runId, "finding");
    const byId = new Map(listed.map((item) => [item.id, item]));
    expect(byId.get(first.id)?.status).toBe("confirmed");
    expect(byId.get(first.id)?.independently_reviewed).toBe(true);
    expect(byId.get(second.id)?.status).toBe("proof_gap");
    expect(byId.get(second.id)?.independently_reviewed).toBe(false);
    expect(byId.get(second.id)?.missing).toContain("login middleware");
    expect(byId.get(third.id)?.independently_reviewed).toBeUndefined();

    const summary = await call("audit_report", { run_id: runId, format: "summary" });
    expect(summary.truncated).toBeUndefined();
    const parsed = JSON.parse(String(summary.text)) as {
      triage: { findings: { reviewed: number }; open: number; independentlyReviewed: number; disputed: number; proofGaps: Array<{ id: string; missing: string }> };
    };
    expect(parsed.triage.findings.reviewed).toBe(2);
    expect(parsed.triage.open).toBe(1);
    expect(parsed.triage.independentlyReviewed).toBe(1);
    expect(parsed.triage.disputed).toBe(1);
    expect(parsed.triage.proofGaps).toEqual([
      { id: second.id, location: `${second.file}:${second.start_line}`, missing: "whether the handler is mounted behind the login middleware" },
    ]);

    const md = await call("audit_report", { run_id: runId, format: "md" });
    const text = fs.readFileSync(String(md.path), "utf8");
    expect(text).toContain("### Review coverage");
    expect(text).toContain("- **Open proof gaps (1)**");
    expect(text).toContain("- **Disputed verdicts (1)**");
    expect(text).toContain("was disputed: fresh-subagent said false\\_positive (subagent)");
    expect(text).toContain("Review incomplete:");
    expect(text).not.toContain("No reportable issues found.");

    const sarif = await call("audit_report", { run_id: runId, format: "sarif" });
    const document = JSON.parse(fs.readFileSync(String(sarif.path), "utf8"));
    const gapResult = document.runs[0].results.find(
      (result: { properties: { status: string } }) => result.properties.status === "proof_gap",
    );
    expect(gapResult.suppressions).toEqual([]);
    expect(document.runs[0].properties.review.proofGaps).toBe(1);

    const verdicts = JSON.parse(fs.readFileSync(path.join(String(started.run_dir), "verdicts.json"), "utf8"));
    expect(verdicts.schemaVersion).toBe(2);
    expect(verdicts.strictEvidence).toBe(true);
  });

  it("keeps phase, counts and the dismissal warning within the size cap (M2, harness t7b)", async () => {
    // A repository can make every path long; the ledger must not push the
    // essential fields out of audit_status or break the summary JSON.
    const longRoot = path.join(temp, "long");
    const deep = ["a", "b", "c", "d"].map((letter) => letter.repeat(150)).join("/");
    const source = fs.readFileSync(path.join(repoRoot, "fixtures/vulnerable/python/app.py"), "utf8");
    for (let index = 0; index < 8; index += 1) {
      fs.mkdirSync(path.join(longRoot, deep), { recursive: true });
      fs.writeFileSync(path.join(longRoot, deep, `copy${index}.py`), source);
    }
    const started = await call("audit_start", { root: longRoot, offline: true, engines: ["builtin"] });
    const runId = String(started.run_id);
    for (let attempt = 0; attempt < 400; attempt += 1) {
      const state = await call("audit_status", { run_id: runId });
      if (state.phase !== "running") break;
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    const findings = await allItems(runId, "finding");
    const serious = findings.filter((item) => item.severity === "high" || item.severity === "critical");
    const dismissed = serious[0] as Item;
    await call("audit_verdict", {
      run_id: runId,
      finding: dismissed.id,
      status: "false_positive",
      rationale: `The value is a constant assigned at ${path.basename(dismissed.file)}:${dismissed.start_line} and never user controlled.`,
      evidenceLines: ["x = 1"],
    });
    for (const item of serious.slice(1, 12)) {
      await call("audit_verdict", { run_id: runId, finding: item.id, status: "proof_gap", rationale: "x", missing: "m".repeat(400) });
    }
    const status = await call("audit_status", { run_id: runId });
    expect(status.phase).toBe("complete");
    expect(typeof status.findings).toBe("number");
    expect(String(status.dismissedWarning)).toMatch(/^WARNING: /);
    const report = await call("audit_report", { run_id: runId, format: "summary" });
    const parsed = JSON.parse(String(report.text)) as Record<string, unknown>;
    expect(parsed.phase).toBe("complete");
    expect(String(parsed.dismissedWarning)).toMatch(/^WARNING: /);
    expect(report.truncated).toBeUndefined();
  });

  it("refuses a human decision and serves blind status and summary (M-n1, L-n4)", async () => {
    const started = await call("audit_start", { root: project, offline: true, engines: ["builtin"] });
    const runId = String(started.run_id);
    for (let attempt = 0; attempt < 400; attempt += 1) {
      const state = await call("audit_status", { run_id: runId });
      if (state.phase !== "running") break;
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    const findings = await allItems(runId, "finding");
    const high = findings.find((item) => item.severity === "high" || item.severity === "critical") as Item;
    await call("audit_verdict", {
      run_id: runId,
      finding: high.id,
      status: "false_positive",
      rationale: `The value is a constant assigned at ${high.file}:${high.start_line} and never user controlled.`,
      reviewer: "secret-label-p",
      evidenceLines: ["x = 1"],
    });
    const humanError = await callError("audit_verdict", {
      run_id: runId,
      finding: high.id,
      status: "confirmed",
      rationale: "a person decided",
      reviewer: "alice",
      role: "human",
      replace: true,
    });
    expect(humanError.code).toBe("HUMAN_DECISION_CLI_ONLY");
    expect(humanError.message).toContain("code-audit verdict");

    const open = await call("audit_status", { run_id: runId });
    expect(String(open.dismissedWarning)).toContain("secret-label-p");
    const blind = await call("audit_status", { run_id: runId, blind: true });
    expect(blind.blind).toBe(true);
    expect(blind.phase).toBe("complete");
    const text = JSON.stringify(blind);
    for (const hidden of ["\"dismissedWarning\"", "\"falsePositive\"", "\"triage\"", "secret-label-p", "\"reviewed\"", "\"unreviewed\""]) {
      expect(text, hidden).not.toContain(hidden);
    }
    const summary = await call("audit_report", { run_id: runId, format: "summary", blind: true });
    expect(summary.blind).toBe(true);
    const summaryText = String(summary.text);
    expect(JSON.parse(summaryText).phase).toBe("complete");
    for (const hidden of ["\"dismissedWarning\"", "\"falsePositive\"", "\"falsePositives\"", "\"triage\"", "secret-label-p"]) {
      expect(summaryText, hidden).not.toContain(hidden);
    }
    expect(JSON.stringify(summary)).not.toContain("false_positive");
    const md = await callError("audit_report", { run_id: runId, format: "md", blind: true });
    expect(md.code).toBe("BLIND_FORMAT");
  });
});
