import fs from "node:fs";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { scanProject } from "../src/scan.js";
import {
  IgnoreFileError,
  loadIgnoreFile,
  matchIgnoreEntry,
} from "../src/ignore.js";
import {
  VULNERABLE,
  cleanup,
  makeTempDir,
  readAllOutputFiles,
  writeFile,
} from "./helpers.js";

const temp = makeTempDir("ignore");

afterAll(() => cleanup(temp));

const TODAY = "2026-11-26";

describe("ignore file loading", () => {
  it("returns undefined for a missing file", () => {
    expect(loadIgnoreFile(path.join(temp, "nope.yml"))).toBeUndefined();
  });

  it("loads a valid file with every entry type", () => {
    const file = path.join(temp, "valid.yml");
    writeFile(
      temp,
      "valid.yml",
      [
        "version: 1",
        "ignore:",
        '  - fingerprint: "' + "a".repeat(64) + '"',
        '    reason: "test fixture"',
        '    expires: "2027-06-30"',
        '  - rule: "py-weak-hash"',
        '    paths: ["tests/**", "legacy/*.py"]',
        '    reason: "MD5 for cache keys"',
        '  - paths: ["vendor/**"]',
        '    reason: "third-party"',
        '  - advisory: "GHSA-xxxx-xxxx-xxxx"',
        '    package: "django"',
        '    reason: "not reachable"',
        "",
      ].join("\n"),
    );
    const loaded = loadIgnoreFile(file);
    expect(loaded?.entries).toHaveLength(4);
  });

  it("rejects an entry with no reason", () => {
    const file = path.join(temp, "noreason.yml");
    writeFile(
      temp,
      "noreason.yml",
      ["version: 1", "ignore:", '  - paths: ["vendor/**"]', ""].join("\n"),
    );
    expect(() => loadIgnoreFile(file)).toThrow(IgnoreFileError);
    expect(() => loadIgnoreFile(file)).toThrow(/reason/);
  });

  it("rejects an entry with no selector", () => {
    const file = path.join(temp, "nosel.yml");
    writeFile(
      temp,
      "nosel.yml",
      ["version: 1", "ignore:", '  - reason: "nothing"', ""].join("\n"),
    );
    expect(() => loadIgnoreFile(file)).toThrow(/at least one of/);
  });

  it("names the entry index in an invalid file", () => {
    const file = path.join(temp, "badidx.yml");
    writeFile(
      temp,
      "badidx.yml",
      [
        "version: 1",
        "ignore:",
        '  - paths: ["vendor/**"]',
        '    reason: "ok"',
        '  - rule: "py-weak-hash"',
        "",
      ].join("\n"),
    );
    expect(() => loadIgnoreFile(file)).toThrow(/entry #1/);
  });
});

describe("ignore entry matching", () => {
  const entries = [
    { fingerprint: "a".repeat(64), reason: "exact" },
    { rule: "py-weak-hash", paths: ["tests/**"], reason: "rule+path" },
    { paths: ["vendor/**"], reason: "vendor" },
    {
      advisory: "GHSA-1111-2222-3333",
      package: "django",
      reason: "advisory",
      expires: "2020-01-01",
    },
  ];

  it("matches by fingerprint", () => {
    const match = matchIgnoreEntry(
      entries,
      { fingerprint: "a".repeat(64), ruleId: "x", file: "a.py" },
      TODAY,
    );
    expect(match?.entry).toBe(0);
    expect(match?.reason).toBe("exact");
  });

  it("matches by rule and path glob", () => {
    expect(
      matchIgnoreEntry(
        entries,
        { fingerprint: "b".repeat(64), ruleId: "py-weak-hash", file: "tests/a.py" },
        TODAY,
      )?.entry,
    ).toBe(1);
    expect(
      matchIgnoreEntry(
        entries,
        { fingerprint: "b".repeat(64), ruleId: "py-weak-hash", file: "src/a.py" },
        TODAY,
      ),
    ).toBeUndefined();
  });

  it("matches by path only", () => {
    expect(
      matchIgnoreEntry(
        entries,
        { fingerprint: "c".repeat(64), ruleId: "x", file: "vendor/lib/a.py" },
        TODAY,
      )?.entry,
    ).toBe(2);
  });

  it("does not match an expired entry", () => {
    expect(
      matchIgnoreEntry(
        entries,
        {
          fingerprint: "d".repeat(64),
          ruleId: "sca-ghsa-1111-2222-3333",
          file: "requirements.txt",
          advisoryId: "GHSA-1111-2222-3333",
          packageName: "django",
        },
        TODAY,
      ),
    ).toBeUndefined();
  });

  it("matches an advisory entry by package", () => {
    const match = matchIgnoreEntry(
      [{ advisory: "GHSA-1111-2222-3333", package: "django", reason: "ok" }],
      {
        fingerprint: "e".repeat(64),
        ruleId: "sca-ghsa-1111-2222-3333",
        file: "requirements.txt",
        advisoryId: "GHSA-1111-2222-3333",
        packageName: "django",
      },
      TODAY,
    );
    expect(match?.reason).toBe("ok");
  });
});

describe("ignore file in a scan", () => {
  it("suppresses findings by path and excludes them from statistics", async () => {
    const project = path.join(temp, "proj");
    fs.cpSync(VULNERABLE, project, { recursive: true });
    writeFile(
      project,
      ".code-audit-ignore",
      [
        "version: 1",
        "ignore:",
        '  - rule: "py-weak-hash"',
        '    paths: ["python/**"]',
        '    reason: "MD5 used for cache keys only"',
        "",
      ].join("\n"),
    );
    const result = await scanProject({
      root: project,
      out: path.join(temp, "out-ignore"),
      offline: true,
      engines: ["builtin"],
      formats: ["md", "json"],
    });
    const suppressed = result.findings.filter(
      (finding) => finding.status === "suppressed",
    );
    expect(suppressed.length).toBeGreaterThan(0);
    expect(
      suppressed.every((finding) => finding.ruleId === "py-weak-hash"),
    ).toBe(true);
    for (const finding of suppressed) {
      expect(finding.suppression).toMatchObject({ source: "ignore-file" });
    }
    const md = fs.readFileSync(path.join(result.runDir, "report.md"), "utf8");
    expect(md).toContain("Suppressed findings");
  });

  it("prints the ignore entry expiry date in the suppressed table", async () => {
    const project = path.join(temp, "proj-expires");
    fs.cpSync(VULNERABLE, project, { recursive: true });
    writeFile(
      project,
      ".code-audit-ignore",
      [
        "version: 1",
        "ignore:",
        '  - rule: "py-weak-hash"',
        '    paths: ["python/**"]',
        '    reason: "MD5 used for cache keys only"',
        '    expires: "2027-06-30"',
        "",
      ].join("\n"),
    );
    const result = await scanProject({
      root: project,
      out: path.join(temp, "out-expires"),
      offline: true,
      engines: ["builtin"],
      formats: ["md"],
    });
    const md = fs.readFileSync(path.join(result.runDir, "report.md"), "utf8");
    expect(md).toContain("2027-06-30");
    expect(md).not.toContain("see ignore file");
  });

  it("does not affect the exit code when findings are suppressed", async () => {
    const project = path.join(temp, "proj-exit");
    fs.cpSync(VULNERABLE, project, { recursive: true });
    // Suppress every rule that reaches the high threshold by path.
    writeFile(
      project,
      ".code-audit-ignore",
      [
        "version: 1",
        "ignore:",
        '  - paths: ["**"]',
        '    reason: "audit everything as suppressed"',
        "",
      ].join("\n"),
    );
    const result = await scanProject({
      root: project,
      out: path.join(temp, "out-exit"),
      offline: true,
      engines: ["builtin"],
      formats: ["json"],
    });
    const actionable = result.findings.filter(
      (finding) =>
        finding.status !== "suppressed" && finding.status !== "false_positive",
    );
    expect(actionable).toHaveLength(0);
  });

  it("warns about an expired entry and an unmatched entry", async () => {
    const project = path.join(temp, "proj-warn");
    fs.cpSync(VULNERABLE, project, { recursive: true });
    writeFile(
      project,
      ".code-audit-ignore",
      [
        "version: 1",
        "ignore:",
        '  - paths: ["vendor/**"]',
        '    reason: "third-party"',
        '  - rule: "py-weak-hash"',
        '    paths: ["python/**"]',
        '    reason: "expired"',
        '    expires: "2020-01-01"',
        "",
      ].join("\n"),
    );
    const result = await scanProject({
      root: project,
      out: path.join(temp, "out-warn"),
      offline: true,
      engines: ["builtin"],
      formats: ["json"],
    });
    expect(result.warnings).toContain("ignore entry #0 matched no finding");
    expect(result.warnings.some((w) => /ignore entry #1 expired on 2020-01-01/.test(w))).toBe(true);
  });

  it("returns exit 2 for an invalid ignore file", async () => {
    const project = path.join(temp, "proj-bad");
    fs.cpSync(VULNERABLE, project, { recursive: true });
    writeFile(
      project,
      ".code-audit-ignore",
      ["version: 1", "ignore:", '  - reason: "missing selector"', ""].join("\n"),
    );
    await expect(
      scanProject({
        root: project,
        out: path.join(temp, "out-bad"),
        offline: true,
        engines: ["builtin"],
      }),
    ).rejects.toThrow(IgnoreFileError);
  });

  it("keeps the secret-redaction guarantee for suppressed secret findings", async () => {
    const project = path.join(temp, "proj-secret");
    fs.cpSync(VULNERABLE, project, { recursive: true });
    writeFile(
      project,
      ".code-audit-ignore",
      [
        "version: 1",
        "ignore:",
        '  - rule: "secret-aws-access-key"',
        '    reason: "test key"',
        "",
      ].join("\n"),
    );
    const result = await scanProject({
      root: project,
      out: path.join(temp, "out-secret"),
      offline: true,
      engines: ["builtin"],
      formats: ["md", "json", "sarif"],
    });
    const output = readAllOutputFiles(result.runDir);
    expect(output).not.toContain("AKIAFAKEFIXTURE00000");
    const aws = result.findings.find(
      (finding) => finding.ruleId === "secret-aws-access-key",
    );
    expect(aws?.status).toBe("suppressed");
    expect(aws?.evidence).not.toContain("FAKEFIXTURE");
  });

  it("disables the ignore file with --no-ignore-file", async () => {
    const project = path.join(temp, "proj-noignore");
    fs.cpSync(VULNERABLE, project, { recursive: true });
    writeFile(
      project,
      ".code-audit-ignore",
      [
        "version: 1",
        "ignore:",
        '  - paths: ["**"]',
        '    reason: "suppress all"',
        "",
      ].join("\n"),
    );
    const result = await scanProject({
      root: project,
      out: path.join(temp, "out-noignore"),
      offline: true,
      engines: ["builtin"],
      noIgnoreFile: true,
      formats: ["json"],
    });
    expect(result.findings.some((f) => f.status === "suppressed")).toBe(false);
  });
});