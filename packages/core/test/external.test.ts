import fs from "node:fs";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import {
  crossEngineDedupe,
  discoverTools,
  findTool,
  loadOpengrepRules,
  mergeScaFindings,
  runGitleaks,
  runOsvScanner,
  runSemgrep,
  runTool,
  selectSastTool,
} from "../src/external/index.js";
import { createFinding } from "../src/finding.js";
import { groupAdvisories, type OsvDetail } from "../src/sca.js";
import { REPO_ROOT, cleanup, makeTempDir, writeFile } from "./helpers.js";

const temp = makeTempDir("external");

afterAll(() => cleanup(temp));

function fakeExe(dir: string, name: string, source: string): string {
  const target = path.join(dir, name);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(target, `#!/usr/bin/env node\n${source}\n`, "utf8");
  fs.chmodSync(target, 0o755);
  return target;
}

/** CommonJS fake executable (explicit path, so the extension is free). */
function fakeCjs(dir: string, name: string, source: string): string {
  const target = path.join(dir, `${name}.cjs`);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(target, `#!/usr/bin/env node\n${source}\n`, "utf8");
  fs.chmodSync(target, 0o755);
  return target;
}

/**
 * Source for a fake Opengrep/Semgrep that replays `report.json` and rejects any
 * flag outside `allowList` with exit code 2, like the real tools do. This
 * catches adapter bugs (for example passing Opengrep a flag it does not have)
 * without the real binary.
 */
function opengrepFake(allowList: string[]): string {
  return [
    "const fs = require('fs');",
    "const path = require('path');",
    "const args = process.argv.slice(2);",
    `const allowed = ${JSON.stringify(allowList)}.map((x) => x.split('=')[0]);`,
    "for (const a of args) {",
    "  if (!a.startsWith('--')) continue;",
    "  const flag = a.split('=')[0];",
    "  if (!allowed.includes(flag)) {",
    "    process.stderr.write(\"unknown option '\" + flag + \"'\\n\");",
    "    process.exit(2);",
    "  }",
    "}",
    "process.stdout.write(fs.readFileSync(path.join(__dirname, 'report.json'), 'utf8'));",
    "process.exit(1);",
  ].join("\n");
}

describe("tool discovery", () => {
  it("finds a fake tool and reads its version", async () => {
    const dir = path.join(temp, "disc-version");
    fakeExe(dir, "opengrep", "process.stdout.write('opengrep 1.2.3\\n');");
    const info = await findTool("opengrep", { pathEnv: dir });
    expect(info?.name).toBe("opengrep");
    expect(info?.version).toBe("opengrep 1.2.3");
    expect(info?.path).toBe(path.join(dir, "opengrep"));
  });

  it("returns undefined for a missing tool", async () => {
    const dir = path.join(temp, "disc-missing");
    fs.mkdirSync(dir, { recursive: true });
    expect(await findTool("gitleaks", { pathEnv: dir })).toBeUndefined();
    expect(await findTool("nope", { pathEnv: dir })).toBeUndefined();
  });

  it("kills a hanging tool at the timeout", async () => {
    const dir = path.join(temp, "disc-hang");
    fakeExe(dir, "semgrep", "setInterval(() => {}, 1000);");
    const started = Date.now();
    const info = await findTool("semgrep", { pathEnv: dir, timeoutMs: 300 });
    expect(Date.now() - started).toBeLessThan(5_000);
    expect(info?.path).toBe(path.join(dir, "semgrep"));
    expect(info?.version).toBeUndefined();
  });

  it("caps a tool that prints 10 MB", async () => {
    const dir = path.join(temp, "disc-flood");
    fakeExe(
      dir,
      "osv-scanner",
      "process.stdout.write('x'.repeat(10 * 1024 * 1024)); process.stdout.write('\\nosv-scanner 9.9.9\\n');",
    );
    const info = await findTool("osv-scanner", { pathEnv: dir, timeoutMs: 10_000 });
    expect(info?.version).toBeDefined();
    expect((info?.version ?? "").length).toBeLessThanOrEqual(200);
  });

  it("prefers opengrep over semgrep for SAST", async () => {
    const dir = path.join(temp, "disc-sast");
    fakeExe(dir, "opengrep", "process.stdout.write('opengrep 1.0.0\\n');");
    fakeExe(dir, "semgrep", "process.stdout.write('semgrep 2.0.0\\n');");
    const selected = await selectSastTool({ pathEnv: dir });
    expect(selected?.engine).toBe("opengrep");

    const onlySemgrep = path.join(temp, "disc-sast2");
    fakeExe(onlySemgrep, "semgrep", "process.stdout.write('semgrep 2.0.0\\n');");
    const fallback = await selectSastTool({ pathEnv: onlySemgrep });
    expect(fallback?.engine).toBe("semgrep");
  });

  it("discovers only the tools that exist", async () => {
    const dir = path.join(temp, "disc-all");
    fakeExe(dir, "gitleaks", "process.stdout.write('gitleaks 8.0.0\\n');");
    const tools = await discoverTools({ pathEnv: dir });
    expect(Object.keys(tools)).toEqual(["gitleaks"]);
  });
});

describe("safe runner", () => {
  it("passes arguments with spaces and semicolons as single arguments", async () => {
    const dir = path.join(temp, "run-args");
    const tool = fakeExe(
      dir,
      "printer",
      "process.stdout.write(JSON.stringify(process.argv.slice(2)));",
    );
    const result = await runTool(tool, ["a b", "c;d", "$HOME"], { timeoutMs: 5_000 });
    expect(result.exitCode).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual(["a b", "c;d", "$HOME"]);
  });

  it("does not forward unrelated environment variables", async () => {
    const dir = path.join(temp, "run-env");
    const tool = fakeExe(
      dir,
      "envcheck",
      "process.stdout.write(String(process.env.SECRET_M2_TEST ?? 'absent'));",
    );
    process.env.SECRET_M2_TEST = "do-not-forward";
    try {
      const result = await runTool(tool, [], { timeoutMs: 5_000 });
      expect(result.stdout).toBe("absent");
    } finally {
      delete process.env.SECRET_M2_TEST;
    }
  });

  it("reports a timeout", async () => {
    const dir = path.join(temp, "run-timeout");
    const tool = fakeExe(dir, "sleeper", "setInterval(() => {}, 1000);");
    const result = await runTool(tool, [], { timeoutMs: 300 });
    expect(result.timedOut).toBe(true);
    expect(result.exitCode).toBe(-1);
  });

  it("truncates oversized output", async () => {
    const dir = path.join(temp, "run-truncate");
    const tool = fakeExe(dir, "flood", "process.stdout.write('y'.repeat(1000));");
    const result = await runTool(tool, [], { timeoutMs: 5_000, maxOutputBytes: 10 });
    expect(result.truncated).toBe(true);
    expect(result.stdout.length).toBe(10);
  });

  it("reports a non-zero exit code", async () => {
    const dir = path.join(temp, "run-exit");
    const tool = fakeExe(dir, "failer", "process.exit(3);");
    const result = await runTool(tool, [], { timeoutMs: 5_000 });
    expect(result.exitCode).toBe(3);
    expect(result.timedOut).toBe(false);
  });
});

describe("gitleaks adapter", () => {
  it("parses a report, redacts secrets and drops out-of-root paths", async () => {
    const root = path.join(temp, "gitleaks-project");
    writeFile(root, "secrets.txt", "aws = AKIAABCDEFGHIJKLMNOP\n");
    const dir = path.join(temp, "gitleaks-bin");
    const rawSecret = "AKIAABCDEFGHIJKLMNOP";
    const report = [
      {
        RuleID: "aws-access-key",
        Description: "AWS key",
        File: "secrets.txt",
        StartLine: 1,
        EndLine: 1,
        Match: rawSecret,
        Secret: rawSecret,
      },
      {
        RuleID: "escape",
        Description: "outside",
        File: "../../etc/passwd",
        StartLine: 1,
        EndLine: 1,
        Match: "x",
        Secret: "x",
      },
    ];
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "report.json"), JSON.stringify(report));
    const tool = fakeCjs(
      dir,
      "gitleaks",
      [
        "const fs = require('fs');",
        "const path = require('path');",
        "const args = process.argv.slice(2);",
        "const i = args.indexOf('--report-path');",
        "fs.copyFileSync(path.join(__dirname, 'report.json'), args[i + 1]);",
        "process.exit(0);",
      ].join("\n"),
    );
    const result = await runGitleaks({
      root,
      toolPath: tool,
      version: "8.0.0",
      timeoutMs: 5_000,
    });
    expect(result.findings).toHaveLength(1);
    const finding = result.findings[0];
    expect(finding?.category).toBe("secrets");
    expect(finding?.provenance.engine).toBe("gitleaks");
    expect(finding?.provenance.rule).toBe("aws-access-key");
    expect(finding?.provenance.version).toBe("8.0.0");
    expect(finding?.file).toBe("secrets.txt");
    expect(finding?.evidence).not.toContain(rawSecret);
    expect(result.warnings.join("\n")).toContain("outside the audit root");
  });
});

describe("osv-scanner adapter", () => {
  it("treats exit code 1 as findings and parses vulnerabilities", async () => {
    const root = path.join(temp, "osv-project");
    writeFile(root, "package-lock.json", "{}");
    const dir = path.join(temp, "osv-bin");
    const report = {
      results: [
        {
          source: { path: "package-lock.json" },
          packages: [
            {
              package: { name: "lodash", version: "4.17.15", ecosystem: "npm" },
              vulnerabilities: [
                {
                  id: "GHSA-osv-1",
                  summary: "Prototype pollution",
                  database_specific: { severity: "HIGH", cwe_ids: ["CWE-1321"] },
                  affected: [{ ranges: [{ events: [{ fixed: "4.17.19" }] }] }],
                },
              ],
            },
          ],
        },
      ],
    };
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "report.json"), JSON.stringify(report));
    const tool = fakeCjs(
      dir,
      "osv-scanner",
      [
        "const fs = require('fs');",
        "const path = require('path');",
        "process.stdout.write(fs.readFileSync(path.join(__dirname, 'report.json'), 'utf8'));",
        "process.exit(1);",
      ].join("\n"),
    );
    const result = await runOsvScanner({
      root,
      toolPath: tool,
      version: "1.2.0",
      timeoutMs: 5_000,
    });
    expect(result.ok).toBe(true);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.provenance.engine).toBe("osv-scanner");
    expect(result.findings[0]?.fixedVersion).toBe("4.17.19");
    expect(result.reportedFiles).toEqual(["package-lock.json"]);
  });

  it("treats exit codes >= 127 as errors", async () => {
    const root = path.join(temp, "osv-project-2");
    writeFile(root, "package-lock.json", "{}");
    const dir = path.join(temp, "osv-bin-2");
    const tool = fakeCjs(dir, "osv-scanner", "process.exit(127);");
    const result = await runOsvScanner({
      root,
      toolPath: tool,
      timeoutMs: 5_000,
    });
    expect(result.ok).toBe(false);
    expect(result.findings).toHaveLength(0);
    expect(result.warnings.join("\n")).toContain("127");
  });

  it("treats 'No package sources found' as an empty success, not a failure", async () => {
    const root = path.join(temp, "osv-project-empty");
    fs.mkdirSync(root, { recursive: true });
    writeFile(root, "app.py", "print(1)\n");
    const dir = path.join(temp, "osv-bin-empty");
    const tool = fakeCjs(
      dir,
      "osv-scanner",
      [
        "process.stderr.write('No package sources found, --help for usage information.\\n');",
        "process.exit(128);",
      ].join("\n"),
    );
    const result = await runOsvScanner({
      root,
      toolPath: tool,
      timeoutMs: 5_000,
    });
    expect(result.ok).toBe(true);
    expect(result.findings).toHaveLength(0);
    expect(result.warnings).toEqual([]);
    expect(result.reportedFiles).toEqual([]);
  });
});

/** Fake osv-scanner that prints a report and exits 1 (vulnerabilities found). */
function fakeOsvScanner(name: string, report: unknown): string {
  const dir = path.join(temp, name);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "report.json"), JSON.stringify(report));
  return fakeCjs(
    dir,
    "osv-scanner",
    [
      "const fs = require('fs');",
      "const path = require('path');",
      "fs.writeSync(1, fs.readFileSync(path.join(__dirname, 'report.json')));",
      "process.exit(1);",
    ].join("\n"),
  );
}

/**
 * Hand-built in the shape of real OSV-Scanner 2.x JSON (see the recorded
 * sample): `vulnerabilities[]` holds one OSV record per id and `groups[]`
 * lists which ids are the same vulnerability. Modelled on the virtualenv
 * report from a real project (36 vulnerabilities in 20 groups), reduced to
 * 7 vulnerabilities in 3 groups.
 */
function virtualenvPackage(withGroups: boolean): Record<string, unknown> {
  const ecosystemRange = (fixed: string) => ({
    package: { ecosystem: "PyPI", name: "virtualenv", purl: "pkg:pypi/virtualenv" },
    ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed }] }],
  });
  const gitOnly = {
    package: { ecosystem: "PyPI", name: "virtualenv" },
    ranges: [
      {
        type: "GIT",
        repo: "https://github.com/pypa/virtualenv",
        events: [{ introduced: "0" }, { fixed: "86dddeda7c991f8529e1995bbff280fb7b761972" }],
      },
    ],
  };
  const pkg: Record<string, unknown> = {
    package: { name: "virtualenv", version: "21.7.1", ecosystem: "PyPI" },
    vulnerabilities: [
      {
        id: "PYSEC-2026-101",
        details: "PYSEC record without a summary.",
        aliases: ["CVE-2026-11111", "GHSA-aaaa-1111-aaaa"],
        affected: [gitOnly],
      },
      {
        id: "GHSA-aaaa-1111-aaaa",
        summary: "TOCTOU in virtualenv directory creation",
        aliases: ["CVE-2026-11111"],
        severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N" }],
        database_specific: { severity: "MODERATE", cwe_ids: ["CWE-362"] },
        affected: [ecosystemRange("21.8.0")],
      },
      {
        id: "CVE-2026-11111",
        aliases: ["GHSA-aaaa-1111-aaaa"],
        severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
        affected: [ecosystemRange("21.8.1")],
      },
      {
        id: "PYSEC-2026-102",
        summary: "Command injection through activation scripts",
        aliases: ["CVE-2026-22222"],
        database_specific: { severity: "HIGH" },
        affected: [ecosystemRange("21.9.0")],
      },
      {
        id: "CVE-2026-22222",
        aliases: ["PYSEC-2026-102"],
        affected: [ecosystemRange("21.9.0")],
      },
      {
        id: "PYSEC-2026-103",
        summary: "Only known to PyPA",
        affected: [ecosystemRange("21.7.2")],
      },
      {
        id: "MAL-2026-9",
        summary: "Grouped only by the scanner",
        affected: [ecosystemRange("21.7.3")],
      },
    ],
  };
  if (withGroups) {
    pkg.groups = [
      {
        ids: ["PYSEC-2026-101", "GHSA-aaaa-1111-aaaa", "CVE-2026-11111"],
        aliases: ["CVE-2026-11111", "GHSA-aaaa-1111-aaaa", "PYSEC-2026-101", "BIT-virtualenv-2026-11111"],
        max_severity: "9.8",
      },
      {
        ids: ["PYSEC-2026-102", "CVE-2026-22222"],
        aliases: ["CVE-2026-22222", "PYSEC-2026-102"],
        max_severity: "",
      },
      // No alias links these two; only the scanner's group does.
      { ids: ["PYSEC-2026-103", "MAL-2026-9"], aliases: ["PYSEC-2026-103", "MAL-2026-9"], max_severity: "3.1" },
    ];
  }
  return pkg;
}

describe("osv-scanner adapter: paths and advisory groups", () => {
  const uvLock = [
    "version = 1",
    "",
    "[[package]]",
    'name = "app"',
    'version = "0.1.0"',
    'source = { virtual = "." }',
    "",
    "[package.dev-dependencies]",
    'dev = [{ name = "virtualenv" }]',
    "",
    "[[package]]",
    'name = "virtualenv"',
    'version = "21.7.1"',
    'source = { registry = "https://pypi.org/simple" }',
    "",
  ].join("\n");

  it("reports findings with a root-relative file even when the tool prints absolute paths", async () => {
    const base = path.join(temp, "osv-abs");
    const root = path.join(base, "real-root");
    writeFile(root, "services/api/uv.lock", uvLock);
    writeFile(base, "outside/uv.lock", uvLock);
    // The audit root is reached through a symbolic link, as /tmp is on macOS.
    const linkedRoot = path.join(base, "linked-root");
    fs.symlinkSync(root, linkedRoot, "dir");
    fs.symlinkSync(path.join(base, "outside/uv.lock"), path.join(root, "escape.lock"));
    const tool = fakeOsvScanner("osv-abs-bin", {
      results: [
        {
          source: { path: path.join(linkedRoot, "services/api/uv.lock"), type: "lockfile" },
          packages: [virtualenvPackage(true)],
        },
        {
          source: { path: path.join(base, "outside/uv.lock"), type: "lockfile" },
          packages: [virtualenvPackage(true)],
        },
        {
          source: { path: path.join(linkedRoot, "escape.lock"), type: "lockfile" },
          packages: [virtualenvPackage(true)],
        },
        {
          source: { path: path.join(linkedRoot, "../outside/uv.lock"), type: "lockfile" },
          packages: [virtualenvPackage(true)],
        },
        { packages: [virtualenvPackage(true)] },
      ],
    });
    const result = await runOsvScanner({ root: linkedRoot, toolPath: tool, timeoutMs: 10_000 });
    expect(result.ok).toBe(true);
    expect(result.reportedFiles).toEqual(["services/api/uv.lock"]);
    expect(result.findings).toHaveLength(3);
    for (const finding of result.findings) {
      expect(finding.file).toBe("services/api/uv.lock");
      expect(path.isAbsolute(finding.file)).toBe(false);
      expect(finding.file).not.toContain("\\");
      expect(finding.file.startsWith("..")).toBe(false);
    }
    const dropped = result.warnings.filter((warning) => warning.includes("outside the root"));
    expect(dropped).toHaveLength(3);
    expect(result.warnings.join("\n")).toContain("without a source path");
    // Nothing from outside the root leaks into any finding.
    expect(JSON.stringify(result.findings)).not.toContain("outside");
  });

  it("emits one finding per group with the preferred id, top severity and best fix", async () => {
    const root = path.join(temp, "osv-groups");
    writeFile(root, "uv.lock", uvLock);
    const tool = fakeOsvScanner("osv-groups-bin", {
      results: [
        { source: { path: path.join(root, "uv.lock"), type: "lockfile" }, packages: [virtualenvPackage(true)] },
        // The same lockfile listed again must not duplicate findings.
        { source: { path: path.join(root, "uv.lock"), type: "unknown" }, packages: [virtualenvPackage(true)] },
      ],
    });
    const result = await runOsvScanner({ root, toolPath: tool, version: "2.7.1", timeoutMs: 10_000 });
    expect(result.findings.map((finding) => finding.advisoryId)).toEqual([
      "GHSA-aaaa-1111-aaaa",
      "CVE-2026-22222",
      "PYSEC-2026-103",
    ]);
    const [first, second, third] = result.findings;
    expect(first?.ruleId).toBe("sca-ghsa-aaaa-1111-aaaa");
    expect(first?.aliases).toEqual([
      "PYSEC-2026-101",
      "CVE-2026-11111",
      "BIT-virtualenv-2026-11111",
    ]);
    expect(first?.title).toContain("TOCTOU in virtualenv directory creation");
    expect(first?.cwe).toBe("CWE-362");
    // Highest severity of the three entries (and the group's max_severity).
    expect(first?.severity).toBe("critical");
    expect(first?.cvss).toBeCloseTo(9.8, 1);
    // The fix that satisfies every entry of the group; the GIT hash is ignored.
    expect(first?.fixedVersion).toBe("21.8.1");
    expect(second?.aliases).toEqual(["PYSEC-2026-102"]);
    expect(second?.severity).toBe("high");
    expect(second?.fixedVersion).toBe("21.9.0");
    expect(second?.title).toContain("Command injection");
    expect(third?.aliases).toEqual(["MAL-2026-9"]);
    expect(third?.severity).toBe("low");
    expect(third?.fixedVersion).toBe("21.7.3");
    for (const finding of result.findings) {
      expect(finding.aliases).not.toContain(finding.advisoryId);
      expect(finding.provenance).toMatchObject({ engine: "osv-scanner", version: "2.7.1" });
      // Location, directness and scope come from the lockfile itself.
      expect(finding.startLine).toBe(11);
      expect(finding.dependencyPath).toBe("uv dev dependency");
      expect((finding as Record<string, unknown>).dependencyScope).toBe("dev");
    }
  });

  it("groups by shared aliases when the report has no groups", async () => {
    const root = path.join(temp, "osv-nogroups");
    writeFile(root, "uv.lock", uvLock);
    const tool = fakeOsvScanner("osv-nogroups-bin", {
      results: [{ source: { path: "uv.lock" }, packages: [virtualenvPackage(false)] }],
    });
    const result = await runOsvScanner({ root, toolPath: tool, timeoutMs: 10_000 });
    expect(result.findings.map((finding) => finding.advisoryId)).toEqual([
      "GHSA-aaaa-1111-aaaa",
      "CVE-2026-22222",
      "PYSEC-2026-103",
      "MAL-2026-9",
    ]);
  });

  it("tolerates malformed entries without throwing", async () => {
    const root = path.join(temp, "osv-malformed");
    writeFile(root, "uv.lock", uvLock);
    const tool = fakeOsvScanner("osv-malformed-bin", {
      results: [
        null,
        { source: { path: "uv.lock" }, packages: "nope" },
        {
          source: { path: "uv.lock" },
          packages: [
            null,
            { package: { name: "virtualenv" } },
            { package: { name: "virtualenv", version: "21.7.1", ecosystem: "PyPI" }, vulnerabilities: [null, {}, { id: 7 }], groups: [null, { ids: "x" }] },
            { package: { name: "virtualenv", version: "21.7.1", ecosystem: "PyPI" }, vulnerabilities: [{ id: "OSV-1" }], groups: "x" },
          ],
        },
      ],
    });
    const result = await runOsvScanner({ root, toolPath: tool, timeoutMs: 10_000 });
    expect(result.ok).toBe(true);
    expect(result.findings.map((finding) => finding.advisoryId)).toEqual(["OSV-1"]);
    expect(result.findings[0]?.severity).toBe("medium");
  });
});

describe("opengrep/semgrep adapter", () => {
  it("maps severities, records the engine and strips the config path from rule ids", async () => {
    const root = path.join(temp, "sast-project");
    writeFile(root, "app.py", "eval(user_input)\n");
    const dir = path.join(temp, "sast-bin");
    const report = {
      results: [
        {
          check_id: "rules.opengrep.py-opengrep-eval",
          path: "app.py",
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            message: "eval is dangerous",
            severity: "ERROR",
            lines: "eval(user_input)",
            metadata: { cwe: "CWE-95", confidence: "HIGH" },
          },
        },
        {
          check_id: "rules.opengrep.go-opengrep-template-html",
          path: "app.py",
          start: { line: 2 },
          end: { line: 2 },
          extra: {
            message: "warning",
            severity: "WARNING",
            metadata: { cwe: ["CWE-79"] },
          },
        },
      ],
    };
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "report.json"), JSON.stringify(report));
    // The fake opengrep rejects any flag outside its allow-list with exit 2,
    // mirroring the real tool. Opengrep has no --metrics option.
    const tool = fakeCjs(dir, "opengrep", opengrepFake(["--json", "--quiet", "--disable-version-check", "--config"]));
    const result = await runSemgrep({
      root,
      toolPath: tool,
      engine: "opengrep",
      rulesDir: path.join(REPO_ROOT, "rules/opengrep"),
      version: "1.0.0",
      timeoutMs: 5_000,
    });
    expect(result.ok).toBe(true);
    expect(result.findings).toHaveLength(2);
    expect(result.findings[0]?.severity).toBe("high");
    expect(result.findings[0]?.confidence).toBe("high");
    expect(result.findings[0]?.provenance.engine).toBe("opengrep");
    expect(result.findings[0]?.provenance.rule).toBe("py-opengrep-eval");
    expect(result.findings[0]?.ruleId).toBe("py-opengrep-eval");
    expect(result.findings[1]?.severity).toBe("medium");
    expect(result.findings[1]?.confidence).toBe("medium");
    expect(result.findings[1]?.cwe).toBe("CWE-79");
    expect(result.findings[1]?.provenance.rule).toBe("go-opengrep-template-html");
  });

  it("passes --metrics=off to semgrep but never to opengrep", async () => {
    const root = path.join(temp, "sast-metrics");
    writeFile(root, "app.py", "eval(x)\n");
    const report = { results: [] };

    const opengrepDir = path.join(temp, "sast-metrics-og");
    fs.mkdirSync(opengrepDir, { recursive: true });
    fs.writeFileSync(path.join(opengrepDir, "report.json"), JSON.stringify(report));
    const opengrep = fakeCjs(
      opengrepDir,
      "opengrep",
      opengrepFake(["--json", "--quiet", "--disable-version-check", "--config"]),
    );
    const ogResult = await runSemgrep({
      root,
      toolPath: opengrep,
      engine: "opengrep",
      rulesDir: path.join(REPO_ROOT, "rules/opengrep"),
      timeoutMs: 5_000,
    });
    expect(ogResult.ok).toBe(true);

    const semgrepDir = path.join(temp, "sast-metrics-sg");
    fs.mkdirSync(semgrepDir, { recursive: true });
    fs.writeFileSync(path.join(semgrepDir, "report.json"), JSON.stringify(report));
    const semgrep = fakeCjs(
      semgrepDir,
      "semgrep",
      opengrepFake(["--json", "--quiet", "--metrics=off", "--disable-version-check", "--config"]),
    );
    const sgResult = await runSemgrep({
      root,
      toolPath: semgrep,
      engine: "semgrep",
      rulesDir: path.join(REPO_ROOT, "rules/opengrep"),
      timeoutMs: 5_000,
    });
    expect(sgResult.ok).toBe(true);
  });

  it("reports a tool failure when the fake rejects an unknown flag", async () => {
    const root = path.join(temp, "sast-badflag");
    writeFile(root, "app.py", "eval(x)\n");
    const dir = path.join(temp, "sast-badflag-bin");
    fs.mkdirSync(dir, { recursive: true });
    // Allow-list deliberately omits --quiet, so the adapter's --quiet is rejected.
    const tool = fakeCjs(dir, "opengrep", opengrepFake(["--json", "--config"]));
    const result = await runSemgrep({
      root,
      toolPath: tool,
      engine: "opengrep",
      rulesDir: path.join(REPO_ROOT, "rules/opengrep"),
      timeoutMs: 5_000,
    });
    expect(result.ok).toBe(false);
    expect(result.warnings.join("\n")).toContain("exited with code 2");
  });
});

describe("bundled opengrep rules", () => {
  it("are valid YAML with the required fields, two per language", () => {
    const ruleSet = loadOpengrepRules(path.join(REPO_ROOT, "rules/opengrep"));
    expect(ruleSet.errors).toEqual([]);
    expect(ruleSet.rules.length).toBeGreaterThanOrEqual(12);
    const counts = new Map<string, number>();
    for (const rule of ruleSet.rules) {
      expect(rule.id).toMatch(/^[a-z0-9-]+$/);
      expect(rule.languages.length).toBeGreaterThan(0);
      expect(rule.cwe).toMatch(/^CWE-\d+$/);
      for (const language of rule.languages) {
        counts.set(language, (counts.get(language) ?? 0) + 1);
      }
    }
    for (const language of ["python", "javascript", "java", "go", "csharp", "c", "rust"]) {
      expect(counts.get(language)).toBeGreaterThanOrEqual(2);
    }
  });
});

describe("cross-engine merge", () => {
  it("merges SAST findings from different engines on the same line and CWE", () => {
    const a = createFinding({
      ruleId: "py-builtin",
      title: "command injection",
      category: "sast",
      severity: "high",
      confidence: "high",
      cwe: "CWE-78",
      file: "app.py",
      startLine: 5,
      evidence: "os.system(x)",
      message: "m",
      remediation: "r",
      provenance: { engine: "builtin-rules" },
    });
    const b = createFinding({
      ruleId: "py-opengrep-exec",
      title: "command injection",
      category: "sast",
      severity: "critical",
      confidence: "medium",
      cwe: "CWE-78",
      file: "app.py",
      startLine: 5,
      evidence: "os.system(x)",
      message: "m",
      remediation: "r",
      provenance: { engine: "opengrep" },
    });
    const merged = crossEngineDedupe([a, b]);
    expect(merged).toHaveLength(1);
    expect(merged[0]?.severity).toBe("critical");
    expect(merged[0]?.confidence).toBe("high");
    expect(merged[0]?.provenance.engines).toEqual(
      expect.arrayContaining(["builtin-rules", "opengrep"]),
    );
  });

  it("merges SCA findings reported by both the built-in query and osv-scanner", () => {
    const base = {
      title: "lodash prototype pollution",
      category: "sca" as const,
      severity: "high" as const,
      confidence: "high" as const,
      file: "package-lock.json",
      startLine: 1,
      evidence: "lodash@4.17.15",
      message: "m",
      remediation: "r",
      package: "lodash",
      ecosystem: "npm",
      installedVersion: "4.17.15",
      fixedVersion: "4.17.19",
      advisoryId: "GHSA-1",
      aliases: ["GHSA-1"],
    };
    const builtin = createFinding({
      ...base,
      ruleId: "sca-ghsa-1",
      provenance: { engine: "osv" },
    });
    const external = createFinding({
      ...base,
      ruleId: "sca-ghsa-1",
      provenance: { engine: "osv-scanner" },
    });
    const merged = mergeScaFindings([builtin], [external]);
    expect(merged).toHaveLength(1);
    expect(merged[0]?.provenance.engines).toEqual(
      expect.arrayContaining(["osv", "osv-scanner"]),
    );
  });
});

describe("cross-engine SCA merge by alias", () => {
  const sca = (overrides: Record<string, unknown>) =>
    createFinding({
      ruleId: `sca-${String(overrides.advisoryId).toLowerCase()}`,
      title: "requests advisory",
      category: "sca",
      severity: "medium",
      confidence: "high",
      file: "requirements.txt",
      startLine: 1,
      evidence: "requests@2.19.0",
      message: "m",
      remediation: "r",
      package: "requests",
      ecosystem: "PyPI",
      installedVersion: "2.19.0",
      provenance: { engine: "osv" },
      ...overrides,
    } as Parameters<typeof createFinding>[0]);

  it("merges an osv-scanner group with the built-in finding for the same package and version", () => {
    const builtin = sca({
      advisoryId: "PYSEC-2018-28",
      aliases: ["CVE-2018-18074"],
      startLine: 2,
      endLine: 2,
      fixedVersion: "2.20.0",
    });
    const external = sca({
      advisoryId: "GHSA-x84v-xcm2-53pg",
      aliases: ["PYSEC-2018-28", "CVE-2018-18074"],
      severity: "high",
      package: "Requests",
      provenance: { engine: "osv-scanner" },
    });
    const otherVersion = sca({
      advisoryId: "GHSA-x84v-xcm2-53pg",
      aliases: ["PYSEC-2018-28"],
      installedVersion: "2.18.0",
      evidence: "requests@2.18.0",
      provenance: { engine: "osv-scanner" },
    });
    const unrelated = sca({
      advisoryId: "GHSA-j8r2-6x86-q33q",
      aliases: ["CVE-2023-32681"],
      provenance: { engine: "osv-scanner" },
    });
    const merged = mergeScaFindings([builtin], [external, otherVersion, unrelated]);
    expect(merged).toHaveLength(3);
    const first = merged[0];
    expect(first?.advisoryId).toBe("GHSA-x84v-xcm2-53pg");
    expect(first?.ruleId).toBe("sca-ghsa-x84v-xcm2-53pg");
    expect([...(first?.aliases ?? [])].sort()).toEqual(["CVE-2018-18074", "PYSEC-2018-28"]);
    expect(first?.severity).toBe("high");
    expect(first?.fixedVersion).toBe("2.20.0");
    expect(first?.startLine).toBe(2);
    expect(first?.provenance.engines).toEqual(expect.arrayContaining(["osv", "osv-scanner"]));
    expect(merged[1]?.installedVersion).toBe("2.18.0");
    expect(merged[2]?.advisoryId).toBe("GHSA-j8r2-6x86-q33q");
  });

  it("folds findings that a later one links together, and never merges findings without ids", () => {
    const a = sca({ advisoryId: "PYSEC-1", aliases: [] });
    const b = sca({ advisoryId: "CVE-2020-1", aliases: [] });
    const bridge = sca({
      advisoryId: "GHSA-aaaa-bbbb-cccc",
      aliases: ["PYSEC-1", "CVE-2020-1"],
      provenance: { engine: "osv-scanner" },
    });
    const merged = mergeScaFindings([a, b], [bridge]);
    expect(merged).toHaveLength(1);
    expect(merged[0]?.advisoryId).toBe("GHSA-aaaa-bbbb-cccc");
    expect([...(merged[0]?.aliases ?? [])].sort()).toEqual(["CVE-2020-1", "PYSEC-1"]);

    const noIdA = sca({ advisoryId: undefined, ruleId: "sca-a" });
    const noIdB = sca({ advisoryId: undefined, ruleId: "sca-b" });
    expect(mergeScaFindings([noIdA], [noIdB])).toHaveLength(2);
  });
});

describe("recorded real outputs", () => {
  const recordedDir = path.join(REPO_ROOT, "packages/core/test/recorded");

  function recorded(name: string): string {
    return path.join(recordedDir, name);
  }

  it("parses the recorded Opengrep JSON with bare rule ids", async () => {
    const root = REPO_ROOT;
    const dir = path.join(temp, "recorded-og");
    const tool = fakeCjs(
      dir,
      "opengrep",
      [
        "const fs = require('fs');",
        "const path = require('path');",
        `process.stdout.write(fs.readFileSync(${JSON.stringify(recorded("opengrep-vulnerable.json"))}, 'utf8'));`,
        "process.exit(1);",
      ].join("\n"),
    );
    const result = await runSemgrep({
      root,
      toolPath: tool,
      engine: "opengrep",
      rulesDir: path.join(REPO_ROOT, "rules/opengrep"),
      timeoutMs: 10_000,
    });
    expect(result.ok).toBe(true);
    expect(result.findings.length).toBe(12);
    for (const finding of result.findings) {
      expect(finding.provenance.rule).not.toContain("rules.opengrep.");
      expect(finding.file.startsWith("fixtures/vulnerable/")).toBe(true);
    }
    const ids = new Set(result.findings.map((f) => f.provenance.rule));
    expect(ids.has("c-opengrep-gets")).toBe(true);
    expect(ids.has("py-opengrep-eval")).toBe(true);
  });

  it("parses the recorded OSV-Scanner JSON with fixed versions and aliases", async () => {
    const dir = path.join(temp, "recorded-osv");
    const tool = fakeCjs(
      dir,
      "osv-scanner",
      [
        "const fs = require('fs');",
        `fs.writeSync(1, fs.readFileSync(${JSON.stringify(recorded("osv-scanner-vulnerable.json"))}));`,
        "process.exit(1);",
      ].join("\n"),
    );
    const result = await runOsvScanner({
      root: REPO_ROOT,
      toolPath: tool,
      version: "2.7.1",
      timeoutMs: 10_000,
    });
    expect(result.ok).toBe(true);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.reportedFiles).toContain("fixtures/vulnerable/sca/package-lock.json");
    const lodash = result.findings.find((f) => f.package === "lodash");
    expect(lodash).toBeDefined();
    expect(lodash?.ecosystem).toBe("npm");
    expect(lodash?.installedVersion).toBe("4.17.15");
    expect(lodash?.fixedVersion).toBeTruthy();
    expect(lodash?.aliases?.length).toBeGreaterThan(0);
  });

  it("collapses the recorded OSV-Scanner vulnerabilities into one finding per group", async () => {
    interface RecordedPackage {
      package: { name: string; version: string; ecosystem: string };
      vulnerabilities: Array<OsvDetail & { id: string }>;
      groups: Array<{ ids: string[] }>;
    }
    const document = JSON.parse(
      fs.readFileSync(recorded("osv-scanner-vulnerable.json"), "utf8"),
    ) as { results: Array<{ source: { path: string }; packages: RecordedPackage[] }> };

    // Independent count straight from the recorded JSON.
    const expectedGroups = new Set<string>();
    let vulnerabilityCount = 0;
    for (const entry of document.results) {
      for (const pkg of entry.packages) {
        vulnerabilityCount += pkg.vulnerabilities.length;
        for (const group of pkg.groups) {
          expectedGroups.add(
            [entry.source.path, pkg.package.name, pkg.package.version, [...group.ids].sort().join(",")].join("|"),
          );
        }
        // The alias-based grouping used by the built-in OSV path reproduces
        // the scanner's own groups on real data.
        const byAlias = groupAdvisories(
          pkg.vulnerabilities.map((vuln) => ({ id: vuln.id, detail: vuln })),
        ).map((group) => group.map((item) => item.id).sort().join(","));
        expect(byAlias.sort()).toEqual(pkg.groups.map((group) => [...group.ids].sort().join(",")).sort());
      }
    }
    expect(vulnerabilityCount).toBe(178);
    expect(expectedGroups.size).toBe(64);

    const dir = path.join(temp, "recorded-osv-groups");
    const tool = fakeCjs(
      dir,
      "osv-scanner",
      [
        "const fs = require('fs');",
        `fs.writeSync(1, fs.readFileSync(${JSON.stringify(recorded("osv-scanner-vulnerable.json"))}));`,
        "process.exit(1);",
      ].join("\n"),
    );
    const result = await runOsvScanner({ root: REPO_ROOT, toolPath: tool, timeoutMs: 10_000 });
    expect(result.findings).toHaveLength(expectedGroups.size);
    const keys = new Set(
      result.findings.map((f) => `${f.file}|${f.package}|${f.installedVersion}|${f.advisoryId}`),
    );
    expect(keys.size).toBe(result.findings.length);
    for (const finding of result.findings) {
      expect(path.isAbsolute(finding.file)).toBe(false);
      expect(finding.file.startsWith("fixtures/vulnerable/sca/")).toBe(true);
      // Every recorded group has a GHSA id, so it is always the advisory id.
      expect(finding.advisoryId).toMatch(/^GHSA-/);
      expect(finding.aliases).not.toContain(finding.advisoryId);
    }
    const django = result.findings.filter((f) => f.package === "django");
    expect(django).toHaveLength(38);
    // Declared on line 1 of fixtures/vulnerable/sca/requirements.txt.
    expect(django.every((f) => f.startLine === 1 && f.fixedVersion)).toBe(true);
    const requests = result.findings.filter((f) => f.package === "requests");
    expect(requests).toHaveLength(5);
    expect(requests.every((f) => f.startLine === 2)).toBe(true);
    const credentials = requests.find((f) => f.advisoryId === "GHSA-x84v-xcm2-53pg");
    expect(credentials?.aliases).toEqual(expect.arrayContaining(["PYSEC-2018-28", "CVE-2018-18074"]));
    expect(credentials?.fixedVersion).toBe("2.20.0");
  });

  it("parses the recorded Gitleaks JSON and keeps secrets redacted", async () => {
    const dir = path.join(temp, "recorded-gl");
    const tool = fakeCjs(
      dir,
      "gitleaks",
      [
        "const fs = require('fs');",
        "const path = require('path');",
        "const args = process.argv.slice(2);",
        "const i = args.indexOf('--report-path');",
        `fs.copyFileSync(${JSON.stringify(recorded("gitleaks-vulnerable.json"))}, args[i + 1]);`,
        "process.exit(0);",
      ].join("\n"),
    );
    const result = await runGitleaks({
      root: REPO_ROOT,
      toolPath: tool,
      version: "8.30.1",
      timeoutMs: 10_000,
    });
    expect(result.findings.length).toBe(1);
    const finding = result.findings[0];
    expect(finding?.file).toBe("fixtures/vulnerable/secrets/secrets.txt");
    expect(finding?.provenance.rule).toBe("private-key");
    expect(finding?.evidence).not.toContain("BEGIN");
    // Gitleaks already redacts to "REDACTED"; our own redactSecret masks it again.
    expect(finding?.evidence).toBe("********");
  });
});