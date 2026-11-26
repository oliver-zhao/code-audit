import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createAuditServer } from "../src/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "../../..");
const temp = fs.mkdtempSync(path.join(repoRoot, ".tmp-test-mcp-"));
const project = path.join(temp, "project");
let client: Client;
let runId: string;

async function call(
  name: string,
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const result = (await client.callTool({ name, arguments: args })) as {
    content: Array<{ type: string; text: string }>;
    isError?: boolean;
  };
  const text = result.content[0]?.text ?? "{}";
  expect(result.isError).toBeUndefined();
  return JSON.parse(text) as Record<string, unknown>;
}

async function callError(
  name: string,
  args: Record<string, unknown>,
): Promise<{ code: string; message: string }> {
  const result = (await client.callTool({ name, arguments: args })) as {
    content: Array<{ type: string; text: string }>;
    isError?: boolean;
  };
  expect(result.isError).toBe(true);
  const parsed = JSON.parse(result.content[0]?.text ?? "{}") as {
    error?: { code: string; message: string };
  };
  expect(parsed.error).toBeDefined();
  return parsed.error as { code: string; message: string };
}

beforeAll(async () => {
  fs.cpSync(path.join(repoRoot, "fixtures/vulnerable"), project, {
    recursive: true,
  });
  const server = createAuditServer();
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  client = new Client({ name: "code-audit-test", version: "1.0.0" });
  await client.connect(clientTransport);
});

afterAll(async () => {
  await client.close();
  fs.rmSync(temp, { recursive: true, force: true });
});

describe("MCP server", () => {
  it("exposes exactly the eight audit tools", async () => {
    const tools = await client.listTools();
    expect(tools.tools.map((tool) => tool.name).sort()).toEqual([
      "audit_add_finding",
      "audit_findings",
      "audit_read",
      "audit_report",
      "audit_search",
      "audit_start",
      "audit_status",
      "audit_verdict",
    ]);
    for (const tool of tools.tools) {
      expect(tool.description ?? "").not.toBe("");
    }
    for (const name of ["audit_read", "audit_search", "audit_findings"]) {
      const description =
        tools.tools.find((tool) => tool.name === name)?.description ?? "";
      expect(description.toLowerCase()).toContain("untrusted");
    }
  });

  it("starts a scan in the background and reports completion", async () => {
    const started = await call("audit_start", {
      root: project,
      offline: true,
    });
    expect(typeof started.run_id).toBe("string");
    expect(started.phase).toBe("running");
    runId = String(started.run_id);

    let status: Record<string, unknown> = {};
    for (let attempt = 0; attempt < 100; attempt += 1) {
      status = await call("audit_status", { run_id: runId });
      if (status.phase !== "running") break;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    expect(status.phase).toBe("complete");
    expect(status.findings).toBeGreaterThan(0);
    expect(status.hotspots).toBeGreaterThan(0);
  });

  it("paginates findings with a cursor and caps the response size", async () => {
    const first = (await call("audit_findings", {
      run_id: runId,
      kind: "finding",
      limit: 2,
    })) as {
      items: Array<{ id: string; kind: string }>;
      next_cursor: string | null;
      total: number;
    };
    expect(first.items).toHaveLength(2);
    expect(first.items[0]?.kind).toBe("finding");
    expect(first.next_cursor).toBe("2");
    const second = (await call("audit_findings", {
      run_id: runId,
      kind: "finding",
      limit: 2,
      cursor: first.next_cursor,
    })) as { items: Array<{ id: string }> };
    expect(second.items[0]?.id).not.toBe(first.items[0]?.id);

    const raw = (await client.callTool({
      name: "audit_findings",
      arguments: { run_id: runId, kind: "all", limit: 20 },
    })) as { content: Array<{ text: string }> };
    expect(Buffer.byteLength(raw.content[0]?.text ?? "", "utf8")).toBeLessThanOrEqual(
      8000,
    );
  });

  it("reads snippets with delimiters and redacts secrets", async () => {
    const snippet = (await call("audit_read", {
      run_id: runId,
      file: "secrets/secrets.txt",
      startLine: 1,
      endLine: 5,
    })) as { content: string; file: string };
    expect(snippet.content).toContain("<<<UNTRUSTED_REPOSITORY_CONTENT>>>");
    expect(snippet.content).toContain("<<<END_UNTRUSTED_REPOSITORY_CONTENT>>>");
    expect(snippet.content).not.toContain("AKIAFAKEFIXTURE00000");
    expect(snippet.content).not.toContain("Fake-Password-For-Fixture-Only-2026");
  });

  it("rejects path escapes and unknown run ids", async () => {
    const escape = await callError("audit_read", {
      run_id: runId,
      file: "../../etc/passwd",
    });
    expect(["PATH_OUTSIDE_ROOT", "FILE_NOT_IN_INVENTORY", "PATH_JAIL"]).toContain(
      escape.code,
    );
    const missing = await callError("audit_status", {
      run_id: "no-such-run",
    });
    expect(["RUN_NOT_FOUND", "RUN_STORE"]).toContain(missing.code);
  });

  it("requires a rationale for verdicts", async () => {
    const listing = await call("audit_findings", {
      run_id: runId,
      kind: "finding",
      limit: 1,
    });
    const target = (listing.items as Array<{ id: string }>)[0];
    expect(target).toBeDefined();
    const error = await callError("audit_verdict", {
      run_id: runId,
      finding: target?.id,
      status: "confirmed",
      rationale: " ",
    });
    expect(error.code).toBe("RATIONALE_REQUIRED");

    const verdict = (await call("audit_verdict", {
      run_id: runId,
      finding: target?.id,
      status: "likely",
      rationale: "data flow reaches the sink",
    })) as { status: string; reviewed: number };
    expect(verdict.status).toBe("likely");
    expect(verdict.reviewed).toBe(1);
  });

  it("rejects out-of-range add_finding lines and accepts valid ones", async () => {
    const error = await callError("audit_add_finding", {
      run_id: runId,
      file: "python/app.py",
      startLine: 99999,
      title: "bad",
      severity: "high",
      cwe: "CWE-89",
      rationale: "line does not exist",
    });
    expect(error.code).toBe("LINE_OUT_OF_RANGE");

    const added = (await call("audit_add_finding", {
      run_id: runId,
      file: "python/app.py",
      startLine: 14,
      title: "SQL string built with an operator",
      severity: "high",
      cwe: "CWE-200",
      rationale: "The name parameter reaches execute() without binding.",
      source: "mcp test",
    })) as { finding: { id: string; provenance: { engine: string } } };
    expect(added.finding.provenance.engine).toBe("agent");
    expect(added.finding.id).toMatch(/^AUD-\d{4}-\d{4}$/);
  });

  it("renders a report with verdicts merged", async () => {
    const summary = (await call("audit_report", {
      run_id: runId,
      format: "summary",
    })) as { text: string };
    const parsed = JSON.parse(summary.text) as {
      reviewed: number;
      unreviewed: number;
      findings: number;
    };
    expect(parsed.reviewed).toBe(1);
    expect(parsed.unreviewed).toBeGreaterThan(0);

    const markdown = (await call("audit_report", {
      run_id: runId,
      format: "md",
    })) as { text: string; path: string };
    expect(markdown.text).toContain("Source Code Security Audit Report");
    expect(markdown.text).toContain("Review progress");
    expect(fs.existsSync(markdown.path)).toBe(true);
  });
});

describe("MCP stdio entrypoint", () => {
  it("serves the same tools over stdio", async () => {
    const bin = path.join(here, "../dist/bin.js");
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [bin],
      cwd: project,
      stderr: "pipe",
    });
    const stdioClient = new Client({ name: "stdio-test", version: "1.0.0" });
    await stdioClient.connect(transport);
    const tools = await stdioClient.listTools();
    expect(tools.tools).toHaveLength(8);
    await stdioClient.close();
  });
});
