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
