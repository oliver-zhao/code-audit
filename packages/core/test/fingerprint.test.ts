import fs from "node:fs";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { scanProject } from "../src/scan.js";
import { cleanup, makeTempDir, writeFile } from "./helpers.js";

const temp = makeTempDir("fingerprint");

afterAll(() => cleanup(temp));

describe("fingerprints", () => {
  it("stays stable when blank lines are inserted at the top of the file", async () => {
    const project = path.join(temp, "project");
    const source = "import os\nos.system(\"ls \" + command)\n";
    writeFile(project, "app.py", source);

    const first = await scanProject({
      root: project,
      out: path.join(temp, "out1"),
      offline: true,
      formats: ["json"],
    });
    const firstFinding = first.findings.find(
      (finding) => finding.ruleId === "py-command-injection",
    );
    expect(firstFinding).toBeDefined();

    writeFile(project, "app.py", `\n\n\n${source}`);
    const second = await scanProject({
      root: project,
      out: path.join(temp, "out2"),
      offline: true,
      formats: ["json"],
    });
    const secondFinding = second.findings.find(
      (finding) => finding.ruleId === "py-command-injection",
    );
    expect(secondFinding).toBeDefined();

    expect(secondFinding?.startLine).toBe((firstFinding?.startLine ?? 0) + 3);
    expect(secondFinding?.fingerprint).toBe(firstFinding?.fingerprint);
    expect(firstFinding?.fingerprint).toMatch(/^[a-f0-9]{64}$/);
  });

  it("deduplicates identical findings by fingerprint", async () => {
    const project = path.join(temp, "dedupe");
    writeFile(project, "app.py", "import os\nos.system(\"ls \" + cmd)\n");
    const result = await scanProject({
      root: project,
      out: path.join(temp, "out3"),
      offline: true,
      formats: ["json"],
    });
    const fingerprints = result.findings.map((finding) => finding.fingerprint);
    expect(new Set(fingerprints).size).toBe(fingerprints.length);
    expect(fs.existsSync(path.join(result.runDir, "findings.json"))).toBe(true);
  });
});

describe("repeated identical lines", () => {
  it("reports every occurrence and keeps fingerprints stable when lines move", async () => {
    const { scanProject } = await import("../src/scan.js");
    const fsMod = await import("node:fs");
    const osMod = await import("node:os");
    const pathMod = await import("node:path");
    const temp = fsMod.mkdtempSync(pathMod.join(osMod.tmpdir(), "code-audit-repeat-"));
    const project = pathMod.join(temp, "p");
    fsMod.mkdirSync(project);
    const line = '    os.system("ping " + request.args["h"])';
    const body = (prefix: string) =>
      `${prefix}import os\nfrom flask import request\ndef a():\n${line}\ndef b():\n${line}\ndef c():\n${line}\n`;
    const run = async (prefix: string, out: string) => {
      fsMod.writeFileSync(pathMod.join(project, "x.py"), body(prefix));
      const result = await scanProject({
        root: project,
        out: pathMod.join(temp, out),
        offline: true,
        engines: ["builtin"],
        noBaseline: true,
        noIgnoreFile: true,
      } as Parameters<typeof scanProject>[0]);
      return result.findings.filter((finding) => finding.ruleId === "py-command-injection");
    };
    try {
      const first = await run("", "o1");
      expect(first.map((finding) => finding.startLine)).toEqual([4, 6, 8]);
      expect(new Set(first.map((finding) => finding.fingerprint)).size).toBe(3);
      const moved = await run("\n\n# moved\n", "o2");
      expect(moved.map((finding) => finding.startLine)).toEqual([7, 9, 11]);
      expect(moved.map((finding) => finding.fingerprint)).toEqual(
        first.map((finding) => finding.fingerprint),
      );
    } finally {
      fsMod.rmSync(temp, { recursive: true, force: true });
    }
  });
});
