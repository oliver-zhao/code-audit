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
    for (const language of ["python", "javascript", "java", "go", "csharp", "c"]) {
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