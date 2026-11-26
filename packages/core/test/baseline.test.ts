import fs from "node:fs";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { scanProject } from "../src/scan.js";
import { BaselineError, buildBaseline, parseBaseline } from "../src/baseline.js";
import {
  VULNERABLE,
  cleanup,
  makeTempDir,
  writeFile,
} from "./helpers.js";

const temp = makeTempDir("baseline");

afterAll(() => cleanup(temp));

describe("baseline file", () => {
  it("rejects an unknown schema version", () => {
    const text = JSON.stringify({
      schemaVersion: 99,
      createdAt: "2026-01-01T00:00:00Z",
      tool: "code-audit 0.1.0",
      entries: [],
    });
    expect(() => parseBaseline(text, "x.json")).toThrow(BaselineError);
    expect(() => parseBaseline(text, "x.json")).toThrow(/schemaVersion/);
  });

  it("rejects invalid JSON", () => {
    expect(() => parseBaseline("{not json", "x.json")).toThrow(/not valid JSON/);
  });

  it("never writes evidence or secret values into the baseline", async () => {
    const project = path.join(temp, "proj-secrets");
    fs.cpSync(VULNERABLE, project, { recursive: true });
    const result = await scanProject({
      root: project,
      out: path.join(temp, "out-secrets"),
      offline: true,
      engines: ["builtin"],
      formats: ["json"],
    });
    const baseline = buildBaseline(result.findings, "2026-01-01T00:00:00Z", "code-audit 0.1.0");
    const serialized = JSON.stringify(baseline);
    expect(serialized).not.toContain("AKIAFAKEFIXTURE");
    expect(serialized).not.toContain("evidence");
    for (const entry of baseline.entries) {
      expect(Object.keys(entry).sort()).toEqual([
        "file",
        "fingerprint",
        "ruleId",
        "severity",
        "title",
      ]);
    }
    // Sorted by fingerprint for diff-friendliness.
    const fingerprints = baseline.entries.map((entry) => entry.fingerprint);
    expect(fingerprints).toEqual([...fingerprints].sort());
  });
});

describe("baseline workflow", () => {
  it("reports 0 new after baselining, then 1 new after adding a line", async () => {
    const project = path.join(temp, "proj");
    fs.cpSync(VULNERABLE, project, { recursive: true });

    const first = await scanProject({
      root: project,
      out: path.join(temp, "out1"),
      offline: true,
      engines: ["builtin"],
      formats: ["json"],
    });
    expect(first.findings.length).toBeGreaterThan(0);

    const baselinePath = path.join(project, ".code-audit-baseline.json");
    fs.writeFileSync(
      baselinePath,
      JSON.stringify(
        buildBaseline(first.findings, new Date().toISOString(), "code-audit 0.1.0"),
        null,
        2,
      ),
      "utf8",
    );

    const second = await scanProject({
      root: project,
      out: path.join(temp, "out2"),
      offline: true,
      engines: ["builtin"],
      formats: ["json", "md", "sarif"],
    });
    const newCount = second.findings.filter(
      (f) => f.baselineState === "new",
    ).length;
    const existingCount = second.findings.filter(
      (f) => f.baselineState === "existing",
    ).length;
    expect(newCount).toBe(0);
    expect(existingCount).toBe(first.findings.length);
    const run = second.run as { baseline: { new: number; existing: number; fixed: number } };
    expect(run.baseline.new).toBe(0);
    expect(run.baseline.fixed).toBe(0);

    // Add one vulnerable line to a file.
    const target = path.join(project, "python", "app.py");
    fs.appendFileSync(target, '\nos.system("ls " + command)\n', "utf8");
    const third = await scanProject({
      root: project,
      out: path.join(temp, "out3"),
      offline: true,
      engines: ["builtin"],
      formats: ["json"],
    });
    const thirdNew = third.findings.filter((f) => f.baselineState === "new");
    expect(thirdNew).toHaveLength(1);
    expect(thirdNew[0]?.ruleId).toBe("py-command-injection");
  });

  it("stays at 0 new when 5 blank lines are inserted at the top of a file", async () => {
    const project = path.join(temp, "proj-lines");
    fs.cpSync(VULNERABLE, project, { recursive: true });
    const first = await scanProject({
      root: project,
      out: path.join(temp, "out-lines1"),
      offline: true,
      engines: ["builtin"],
      formats: ["json"],
    });
    const baselinePath = path.join(project, ".code-audit-baseline.json");
    fs.writeFileSync(
      baselinePath,
      JSON.stringify(
        buildBaseline(first.findings, new Date().toISOString(), "code-audit 0.1.0"),
      ),
      "utf8",
    );

    const target = path.join(project, "go", "main.go");
    const original = fs.readFileSync(target, "utf8");
    fs.writeFileSync(target, `\n\n\n\n\n${original}`, "utf8");

    const second = await scanProject({
      root: project,
      out: path.join(temp, "out-lines2"),
      offline: true,
      engines: ["builtin"],
      formats: ["json"],
    });
    const newCount = second.findings.filter(
      (f) => f.baselineState === "new",
    ).length;
    expect(newCount).toBe(0);
  });

  it("counts findings as fixed when a vulnerable file is deleted", async () => {
    const project = path.join(temp, "proj-fixed");
    fs.cpSync(VULNERABLE, project, { recursive: true });
    const first = await scanProject({
      root: project,
      out: path.join(temp, "out-fixed1"),
      offline: true,
      engines: ["builtin"],
      formats: ["json"],
    });
    const baselinePath = path.join(project, ".code-audit-baseline.json");
    fs.writeFileSync(
      baselinePath,
      JSON.stringify(
        buildBaseline(first.findings, new Date().toISOString(), "code-audit 0.1.0"),
      ),
      "utf8",
    );

    // Delete a file that had findings.
    fs.rmSync(path.join(project, "python", "app.py"));
    const second = await scanProject({
      root: project,
      out: path.join(temp, "out-fixed2"),
      offline: true,
      engines: ["builtin"],
      formats: ["json", "md"],
    });
    const run = second.run as { baseline: { fixed: number } };
    expect(run.baseline.fixed).toBeGreaterThan(0);
    const md = fs.readFileSync(path.join(second.runDir, "report.md"), "utf8");
    expect(md).toContain("Fixed since baseline");
  });

  it("marks SARIF results with baselineState new/unchanged", async () => {
    const project = path.join(temp, "proj-sarif");
    fs.cpSync(VULNERABLE, project, { recursive: true });
    const first = await scanProject({
      root: project,
      out: path.join(temp, "out-sarif1"),
      offline: true,
      engines: ["builtin"],
      formats: ["json"],
    });
    fs.writeFileSync(
      path.join(project, ".code-audit-baseline.json"),
      JSON.stringify(
        buildBaseline(first.findings, new Date().toISOString(), "code-audit 0.1.0"),
      ),
      "utf8",
    );
    const second = await scanProject({
      root: project,
      out: path.join(temp, "out-sarif2"),
      offline: true,
      engines: ["builtin"],
      formats: ["sarif"],
    });
    const sarif = JSON.parse(
      fs.readFileSync(path.join(second.runDir, "results.sarif"), "utf8"),
    );
    const states = sarif.runs[0].results
      .map((r: { properties: { baselineState?: string } }) => r.properties.baselineState)
      .filter(Boolean);
    expect(states.length).toBeGreaterThan(0);
    for (const state of states) {
      expect(["new", "unchanged"]).toContain(state);
    }
  });

  it("returns exit 2 for a corrupt baseline", async () => {
    const project = path.join(temp, "proj-corrupt");
    fs.cpSync(VULNERABLE, project, { recursive: true });
    writeFile(project, ".code-audit-baseline.json", "{not valid json");
    await expect(
      scanProject({
        root: project,
        out: path.join(temp, "out-corrupt"),
        offline: true,
        engines: ["builtin"],
      }),
    ).rejects.toThrow(BaselineError);
  });
});