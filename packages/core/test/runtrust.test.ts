/**
 * Everything below an audited repository is prepared by someone else: its
 * `.audit/`, every run directory in it, run.json, state.json, index.json,
 * coverage.json, findings.json, verdicts.json and any symbolic link. These
 * tests plant such content and check that a later command neither reads nor
 * writes anything outside the repository the user is standing in.
 */
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { afterAll, describe, expect, it } from "vitest";
import { BaselineError, resolveBaselineOutput } from "../src/baseline.js";
import { loadRules } from "../src/rules.js";
import {
  RunStoreError,
  addFinding,
  loadRun,
  readSnippet,
  recordVerdict,
  registerRunIndex,
  renderRunReport,
  resolveRun,
  resolveRunDir,
  ruleSetHash,
  runStatus,
  searchCode,
} from "../src/runstore.js";
import {
  SafeFsError,
  appendFileNoFollow,
  ensureDirInside,
  printable,
  readFileNoFollow,
  writeFileAtomicNoFollow,
} from "../src/safeFs.js";
import { scanProject, type ScanResult } from "../src/scan.js";
import { CLI, REPO_ROOT, RULES_DIR, cleanup, makeTempDir, writeFile } from "./helpers.js";

const temp = fs.realpathSync(makeTempDir("runtrust"));

afterAll(() => cleanup(temp));

const SOURCE = 'import os\n\n\ndef run(c):\n    os.system("ls " + c)\n';
const VICTIM_NOTE = "internal design note: project codename BLUEHERON\n";

function cli(args: string[], cwd: string, env: Record<string, string> = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    cwd,
    encoding: "utf8",
    timeout: 60_000,
    env: { ...process.env, GITHUB_ACTIONS: "", GITHUB_STEP_SUMMARY: "", ...env },
  });
}

function scan(root: string, extra: Partial<Parameters<typeof scanProject>[0]> = {}): Promise<ScanResult> {
  return scanProject({ root, offline: true, engines: ["builtin"], noBaseline: true, ...extra });
}

function project(name: string, files: Record<string, string> = { "app.py": SOURCE }): string {
  const root = path.join(temp, name);
  fs.mkdirSync(root, { recursive: true });
  for (const [file, content] of Object.entries(files)) writeFile(root, file, content);
  return root;
}

function readJson<T>(file: string): T {
  return JSON.parse(fs.readFileSync(file, "utf8")) as T;
}

function snapshot(dir: string): Record<string, string> {
  const result: Record<string, string> = {};
  const walk = (current: string): void => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const absolute = path.join(current, entry.name);
      if (entry.isDirectory()) walk(absolute);
      else if (entry.isFile()) result[path.relative(dir, absolute)] = fs.readFileSync(absolute, "utf8");
      else result[path.relative(dir, absolute)] = `<${entry.isSymbolicLink() ? "symlink" : "other"}>`;
    }
  };
  walk(dir);
  return result;
}

/**
 * A repository with a run directory `.audit/<name>` whose run.json and
 * state.json name another project as the audit root.
 */
async function plantedRun(hostile: string, name: string, claimedRoot: string): Promise<string> {
  const real = await scan(hostile);
  const planted = path.join(hostile, ".audit", name);
  fs.renameSync(real.runDir, planted);
  const run = readJson<Record<string, unknown>>(path.join(planted, "run.json"));
  run.runId = name;
  run.args = { ...(run.args as object), root: claimedRoot, resolvedRoot: claimedRoot };
  fs.writeFileSync(path.join(planted, "run.json"), JSON.stringify(run));
  const state = readJson<Record<string, unknown>>(path.join(planted, "state.json"));
  fs.writeFileSync(
    path.join(planted, "state.json"),
    JSON.stringify({ ...state, runId: name, root: claimedRoot, runDir: planted }),
  );
  return planted;
}

// ---------------------------------------------------------------------------
// D8: the audit root comes from where the run directory is
// ---------------------------------------------------------------------------

describe("D8: a planted run.json cannot choose the audit root", () => {
  it("reads, searches and adds findings only in the directory that contains the run", async () => {
    const victim = project("d8-victim", { "notes.txt": VICTIM_NOTE, "app.py": SOURCE });
    const hostile = project("d8-hostile", { "main.py": "x = 1\n" });
    for (const [name, claimed] of [
      ["ABS", victim],
      ["REL", "../d8-victim"],
    ] as const) {
      await plantedRun(hostile, name, claimed);
      const options = { cwd: hostile };

      const loaded = loadRun(name, options);
      expect(loaded.root).toBe(hostile);
      expect(loaded.rootSource).toBe("location");
      expect(loaded.notices.join("\n")).toContain("run.json records the audit root");

      expect(() => readSnippet(name, "notes.txt", 1, undefined, options)).toThrow(/not part of the audit inventory/);
      const own = readSnippet(name, "main.py", 1, undefined, options);
      expect(own.root).toBe(hostile);
      expect(own.lines[0]?.text).toBe("x = 1");

      const search = searchCode(name, { pattern: "BLUEHERON" }, options);
      expect(search.total).toBe(0);
      expect(search.root).toBe(hostile);

      expect(() =>
        addFinding(
          name,
          { file: "notes.txt", startLine: 1, title: "t", severity: "low", cwe: "CWE-1", rationale: "r" },
          options,
        ),
      ).toThrow(/not part of the audit inventory/);
      expect(JSON.stringify(snapshot(path.join(hostile, ".audit", name)))).not.toContain("BLUEHERON");

      // The CLI, standing in the hostile repository.
      for (const args of [
        ["read", name, "notes.txt"],
        ["search", name, "BLUEHERON"],
        ["add-finding", name, "--file", "notes.txt", "--start", "1", "--title", "t", "--severity", "low", "--cwe", "CWE-1", "--rationale", "r"],
      ]) {
        const result = cli(args, hostile);
        expect(`${result.stdout}${result.stderr}`, args.join(" ")).not.toContain("BLUEHERON");
        expect(result.stderr).not.toMatch(/\n\s+at /);
      }
      // A --root that is neither where the run is nor ... is refused; this
      // one names a third directory.
      const third = project(`d8-third-${name}`);
      expect(() => readSnippet(name, "app.py", 1, undefined, { ...options, root: third })).toThrow(/--root/);
    }
  });

  it("needs --root for a run directory that is not at <root>/.audit/<run-id>", async () => {
    const root = project("d8-external");
    const other = project("d8-external-other", { "app.py": "y = 2\n" });
    const result = await scan(root, { out: path.join(temp, "d8-external-out") });

    const loaded = loadRun(result.runDir);
    expect(loaded.root).toBeUndefined();
    expect(loaded.recordedRoot).toBe(root);
    // Commands that do not read project files still work.
    expect(runStatus(result.runDir).root).toBeNull();
    expect(renderRunReport(result.runDir, "summary").runDir).toBe(result.runDir);

    for (const attempt of [
      () => readSnippet(result.runDir, "app.py"),
      () => searchCode(result.runDir, { pattern: "os" }),
      () =>
        addFinding(result.runDir, {
          file: "app.py",
          startLine: 1,
          title: "t",
          severity: "low",
          cwe: "CWE-1",
          rationale: "r",
        }),
    ]) {
      expect(attempt).toThrow(/Pass --root <dir>/);
    }
    // The user names the recorded root: accepted, compared as canonical paths.
    const confirmed = readSnippet(result.runDir, "app.py", 1, undefined, { root });
    expect(confirmed.root).toBe(root);
    expect(loadRun(result.runDir, { root }).rootSource).toBe("confirmed");
    // Any other directory is not a confirmation.
    expect(() => readSnippet(result.runDir, "app.py", 1, undefined, { root: other })).toThrow(RunStoreError);

    const refused = cli(["read", result.runDir, "app.py"], other);
    expect(refused.status).toBe(2);
    expect(refused.stderr).toContain("Pass --root <dir>");
    expect(refused.stderr).not.toContain("Usage:");
    const allowed = cli(["read", result.runDir, "app.py", "--root", root], other);
    expect(allowed.status).toBe(0);
    expect(allowed.stdout).toContain("os.system");
  });

  it("shows the run directory and the derived root at the top of status and report", async () => {
    const root = project("d8-status");
    const result = await scan(root);
    const status = cli(["status", result.runId], root);
    expect(status.status).toBe(0);
    const lines = status.stdout.split("\n");
    expect(lines[0]).toBe(`Directory: ${result.runDir}`);
    expect(lines[1]).toBe(`Root: ${root} (the directory that contains this run)`);
    const report = cli(["report", result.runId, "--format", "md"], root);
    expect(report.stderr).toContain(`Directory: ${result.runDir}`);
    expect(report.stderr).toContain(`Root: ${root}`);
    expect(report.stdout.startsWith("#")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// D9: baseline destination
// ---------------------------------------------------------------------------

describe("D9: baseline is written to the location-derived root only", () => {
  it("does not overwrite the baseline of the project a planted run names", async () => {
    const victim = project("d9-victim");
    const victimBaseline = path.join(victim, ".code-audit-baseline.json");
    fs.writeFileSync(victimBaseline, '{"mine":true}\n');
    const hostile = project("d9-hostile");
    await plantedRun(hostile, "EVIL", victim);

    const result = cli(["baseline", "EVIL"], hostile);
    expect(result.status).toBe(0);
    expect(fs.readFileSync(victimBaseline, "utf8")).toBe('{"mine":true}\n');
    expect(result.stdout).toContain(path.join(hostile, ".code-audit-baseline.json"));
    expect(fs.existsSync(path.join(hostile, ".code-audit-baseline.json"))).toBe(true);

    // A symbolic link planted at the default destination is replaced.
    fs.rmSync(path.join(hostile, ".code-audit-baseline.json"));
    fs.symlinkSync(victimBaseline, path.join(hostile, ".code-audit-baseline.json"));
    expect(cli(["baseline", "EVIL"], hostile).status).toBe(0);
    expect(fs.readFileSync(victimBaseline, "utf8")).toBe('{"mine":true}\n');
    expect(fs.lstatSync(path.join(hostile, ".code-audit-baseline.json")).isFile()).toBe(true);
  });

  it("asks for --output when the run directory shows no root", async () => {
    const root = project("d9-external");
    const result = await scan(root, { out: path.join(temp, "d9-external-out") });
    const refused = cli(["baseline", result.runDir], root);
    expect(refused.status).toBe(2);
    expect(refused.stderr).toContain("--output <file>");
    expect(fs.existsSync(path.join(root, ".code-audit-baseline.json"))).toBe(false);
    expect(() => resolveBaselineOutput({ runDir: result.runDir })).toThrow(BaselineError);
    const explicit = cli(["baseline", result.runDir, "--output", "chosen.json"], root);
    expect(explicit.status).toBe(0);
    expect(fs.existsSync(path.join(root, "chosen.json"))).toBe(true);
  });

  it("carries a false-positive verdict into the baseline", async () => {
    const root = project("d9-verdict");
    const first = await scan(root, { formats: ["json"] });
    const target = first.findings[0];
    expect(target).toBeDefined();
    recordVerdict(first.runId, target?.id ?? "", { status: "false_positive", rationale: "the value is a constant and never user input; see python/app.py:12 for the assignment" }, { cwd: root });
    expect(cli(["baseline", first.runId], root).status).toBe(0);
    const baseline = readJson<{ entries: Array<{ fingerprint: string }> }>(path.join(root, ".code-audit-baseline.json"));
    expect(baseline.entries.map((entry) => entry.fingerprint)).toContain(target?.fingerprint);
  });
});

// ---------------------------------------------------------------------------
// D10: symbolic links as run directories
// ---------------------------------------------------------------------------

describe("D10: a symlinked run directory cannot leave <root>/.audit", () => {
  it("refuses a link to another project's run by id, by path and through the index", async () => {
    const legit = project("d10-legit");
    const genuine = await scan(legit);
    const before = snapshot(genuine.runDir);
    const target = [...genuine.findings, ...genuine.hotspots][0]?.id ?? "";
    expect(target).not.toBe("");

    const hostile = project("d10-hostile");
    fs.mkdirSync(path.join(hostile, ".audit"), { recursive: true });
    fs.symlinkSync(genuine.runDir, path.join(hostile, ".audit", "LINK"));
    fs.symlinkSync(genuine.runDir, path.join(hostile, "elsewhere"));
    fs.writeFileSync(
      path.join(hostile, ".audit", "index.json"),
      JSON.stringify({
        schemaVersion: 1,
        runs: ["LINK", genuine.runDir, `.audit/../../d10-legit/.audit/${genuine.runId}`].map((runDir, index) => ({
          runId: `IDX${index}`,
          runDir,
          root: "x",
          phase: "complete",
          startedAt: "a",
          updatedAt: "a",
        })),
      }),
    );

    const verdict = { status: "false_positive" as const, rationale: "planted" };
    for (const ref of ["LINK", ".audit/LINK", path.join(hostile, ".audit", "LINK"), "elsewhere", "IDX0", "IDX1", "IDX2"]) {
      expect(() => recordVerdict(ref, target, verdict, { cwd: hostile }), ref).toThrow(RunStoreError);
      expect(() => addFinding(ref, { hotspotId: target, rationale: "r" }, { cwd: hostile }), ref).toThrow(RunStoreError);
      expect(() => renderRunReport(ref, "md", { cwd: hostile }), ref).toThrow(RunStoreError);
      const viaCli = cli(["verdict", ref, target, "--status", "false_positive", "--rationale", "planted"], hostile);
      expect(viaCli.status, ref).toBe(2);
    }
    expect(snapshot(genuine.runDir)).toEqual(before);
    expect(fs.existsSync(path.join(genuine.runDir, "verdicts.json"))).toBe(false);
  });

  it("refuses run directories behind a .audit that leaves the project, accepts links that stay inside", async () => {
    const legit = project("d10b-legit");
    const genuine = await scan(legit);
    const hostile = project("d10b-hostile");
    fs.symlinkSync(path.join(legit, ".audit"), path.join(hostile, ".audit"));
    expect(() => resolveRunDir(genuine.runId, { cwd: hostile })).toThrow(/symbolic link that leaves the project/);
    expect(() => resolveRunDir(path.join(hostile, ".audit", genuine.runId))).toThrow(RunStoreError);

    // An alias inside the same .audit is the same run of the same project.
    fs.symlinkSync(genuine.runId, path.join(legit, ".audit", "alias"));
    expect(resolveRun("alias", { cwd: legit })).toEqual({ runDir: genuine.runDir, derivedRoot: legit });
    // The MCP tools accept ids only.
    expect(() => resolveRunDir(genuine.runDir, { idsOnly: true })).toThrow(/a run id is expected/);
    expect(() => resolveRunDir(`../d10b-legit/.audit/${genuine.runId}`, { cwd: hostile, idsOnly: true })).toThrow(
      RunStoreError,
    );
  });
});

// ---------------------------------------------------------------------------
// D11: no write follows a symbolic link
// ---------------------------------------------------------------------------

describe("D11: files are written without following symbolic links", () => {
  it("writeFileAtomicNoFollow replaces a link, checks the parent, leaves no temp file", () => {
    const dir = path.join(temp, "d11-helper");
    const outside = path.join(temp, "d11-helper-outside");
    fs.mkdirSync(dir, { recursive: true });
    fs.mkdirSync(outside, { recursive: true });
    const precious = path.join(outside, "precious.txt");
    fs.writeFileSync(precious, "keep me");

    fs.symlinkSync(precious, path.join(dir, "report.md"));
    writeFileAtomicNoFollow(path.join(dir, "report.md"), "new", { expectedDir: dir });
    expect(fs.readFileSync(precious, "utf8")).toBe("keep me");
    expect(fs.lstatSync(path.join(dir, "report.md")).isFile()).toBe(true);
    expect(fs.readFileSync(path.join(dir, "report.md"), "utf8")).toBe("new");
    expect(fs.readdirSync(dir)).toEqual(["report.md"]);

    // The parent directory is a link to somewhere else: refused.
    fs.symlinkSync(outside, path.join(dir, "sub"));
    expect(() =>
      writeFileAtomicNoFollow(path.join(dir, "sub", "x.json"), "{}", { expectedDir: path.join(dir, "sub") }),
    ).toThrow(SafeFsError);
    expect(fs.readdirSync(outside)).toEqual(["precious.txt"]);
    // A directory is never replaced by a file.
    fs.mkdirSync(path.join(dir, "a-directory"));
    expect(() => writeFileAtomicNoFollow(path.join(dir, "a-directory"), "x")).toThrow(SafeFsError);

    // Append: O_NOFOLLOW on the path itself.
    fs.symlinkSync(precious, path.join(dir, "summary.md"));
    expect(() => appendFileNoFollow(path.join(dir, "summary.md"), "more")).toThrow(SafeFsError);
    expect(fs.readFileSync(precious, "utf8")).toBe("keep me");
    appendFileNoFollow(path.join(dir, "plain.md"), "a");
    appendFileNoFollow(path.join(dir, "plain.md"), "b");
    expect(fs.readFileSync(path.join(dir, "plain.md"), "utf8")).toBe("ab");

    // Read: a link is refused, a missing file is undefined.
    expect(() => readFileNoFollow(path.join(dir, "summary.md"), 1024)).toThrow(SafeFsError);
    expect(readFileNoFollow(path.join(dir, "missing"), 1024)).toBeUndefined();
    expect(() => readFileNoFollow(path.join(dir, "plain.md"), 1)).toThrow(/larger than/);

    // Directories: a link that leaves the base is refused, nothing is created behind it.
    fs.symlinkSync(outside, path.join(dir, "escape"));
    expect(() => ensureDirInside(dir, path.join(dir, "escape", "run"))).toThrow(/leaves/);
    expect(fs.readdirSync(outside)).toEqual(["precious.txt"]);
    expect(ensureDirInside(dir, path.join(dir, "x", "y"))).toBe(path.join(dir, "x", "y"));

    expect(printable("a\u001b[31mb\nc")).toBe("a?[31mb?c");
  });

  it("report, verdict and add-finding do not write through links planted in the run directory", async () => {
    const victim = project("d11-victim", { "precious.txt": "PRECIOUS\n", "other.txt": "OTHER\n" });
    const root = project("d11-root");
    const result = await scan(root);
    const before = snapshot(victim);
    const plant = (name: string, to: string): void => {
      fs.rmSync(path.join(result.runDir, name), { force: true });
      fs.symlinkSync(path.join(victim, to), path.join(result.runDir, name));
    };
    plant("report.md", "precious.txt");
    plant("results.sarif", "other.txt");

    for (const format of ["md", "sarif", "json"] as const) {
      const report = renderRunReport(result.runId, format, { cwd: root });
      expect(report.path).toBe(path.join(result.runDir, { md: "report.md", sarif: "results.sarif", json: "findings.json" }[format]));
    }
    expect(snapshot(victim)).toEqual(before);
    expect(fs.lstatSync(path.join(result.runDir, "report.md")).isFile()).toBe(true);
    expect(fs.lstatSync(path.join(result.runDir, "results.sarif")).isFile()).toBe(true);

    // Planted again: a verdict re-renders the reports, still without following.
    plant("report.md", "precious.txt");
    plant("results.sarif", "other.txt");
    const target = [...result.findings, ...result.hotspots][0]?.id ?? "";
    recordVerdict(result.runId, target, { status: "needs_review", rationale: "r" }, { cwd: root });
    expect(snapshot(victim)).toEqual(before);

    // Files the tool reads are not read through a link either.
    plant("verdicts.json", "other.txt");
    expect(() => recordVerdict(result.runId, target, { status: "likely", rationale: "r" }, { cwd: root })).toThrow(
      /symbolic link/,
    );
    expect(snapshot(victim)).toEqual(before);
    fs.rmSync(path.join(result.runDir, "verdicts.json"));

    // report --output: a link at the named file is replaced.
    fs.symlinkSync(path.join(victim, "precious.txt"), path.join(root, "out.md"));
    const output = cli(["report", result.runId, "--format", "md", "--output", "out.md"], root);
    expect(output.status).toBe(0);
    expect(snapshot(victim)).toEqual(before);
    expect(fs.lstatSync(path.join(root, "out.md")).isFile()).toBe(true);
  });

  it("the CI step summary is not appended through a link", () => {
    const victim = project("d11-step-victim", { "precious.txt": "PRECIOUS\n" });
    const root = project("d11-step-root");
    const link = path.join(temp, "d11-step-summary.md");
    fs.symlinkSync(path.join(victim, "precious.txt"), link);
    const result = cli(["scan", root, "--offline", "--no-external", "--ci"], root, {
      GITHUB_ACTIONS: "true",
      GITHUB_STEP_SUMMARY: link,
    });
    expect([0, 1]).toContain(result.status);
    expect(fs.readFileSync(path.join(victim, "precious.txt"), "utf8")).toBe("PRECIOUS\n");
  });
});

// ---------------------------------------------------------------------------
// D12: scan output
// ---------------------------------------------------------------------------

describe("D12: a scan does not write through links planted in its output location", () => {
  it("replaces a link at latest/report.md instead of overwriting its target", async () => {
    const victim = project("d12-victim", { "keep.txt": "KEEP\n" });
    const root = project("d12-latest");
    fs.mkdirSync(path.join(root, ".audit", "latest"), { recursive: true });
    fs.symlinkSync(path.join(victim, "keep.txt"), path.join(root, ".audit", "latest", "report.md"));
    await scan(root, { latestLink: true });
    expect(fs.readFileSync(path.join(victim, "keep.txt"), "utf8")).toBe("KEEP\n");
    expect(fs.lstatSync(path.join(root, ".audit", "latest", "report.md")).isFile()).toBe(true);
    expect(fs.readFileSync(path.join(root, ".audit", "latest", "report.md"), "utf8")).toContain("# ");
  });

  it("refuses a .audit, an --out inside the root, or a latest/ that is a link leaving the root", async () => {
    const elsewhere = path.join(temp, "d12-elsewhere");
    fs.mkdirSync(elsewhere, { recursive: true });

    const viaAudit = project("d12-audit-link");
    fs.symlinkSync(elsewhere, path.join(viaAudit, ".audit"));
    await expect(scan(viaAudit)).rejects.toThrow(/symbolic link that leaves/);

    const viaOut = project("d12-out-link");
    fs.symlinkSync(elsewhere, path.join(viaOut, "reports"));
    await expect(scan(viaOut, { out: path.join(viaOut, "reports") })).rejects.toThrow(/symbolic link that leaves/);
    await expect(scan(viaOut, { out: path.join(viaOut, "reports", "deeper") })).rejects.toThrow(
      /symbolic link that leaves/,
    );

    const viaLatest = project("d12-latest-link");
    fs.mkdirSync(path.join(viaLatest, ".audit"), { recursive: true });
    fs.symlinkSync(elsewhere, path.join(viaLatest, ".audit", "latest"));
    await expect(scan(viaLatest, { latestLink: true })).rejects.toThrow(/symbolic link that leaves/);

    expect(fs.readdirSync(elsewhere)).toEqual([]);

    // The CLI reports it as an ordinary error.
    const result = cli(["scan", ".", "--offline", "--no-external"], viaAudit);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("symbolic link that leaves");
    expect(result.stderr).not.toMatch(/\n\s+at /);
    expect(fs.readdirSync(elsewhere)).toEqual([]);
  });

  it("still follows a .audit link that stays inside the root, and an --out outside the root", async () => {
    const root = project("d12-inside");
    fs.mkdirSync(path.join(root, "build", "audit"), { recursive: true });
    fs.symlinkSync(path.join("build", "audit"), path.join(root, ".audit"));
    const inside = await scan(root);
    expect(inside.runDir).toBe(path.join(root, "build", "audit", inside.runId));
    expect(resolveRun(inside.runId, { cwd: root })).toEqual({ runDir: inside.runDir, derivedRoot: root });

    const out = path.join(temp, "d12-outside-out");
    const outside = await scan(root, { out, latestLink: true });
    expect(outside.runDir).toBe(path.join(out, outside.runId));
    expect(fs.existsSync(path.join(out, "latest", "findings.json"))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// D13: rules named by run.json are not loaded
// ---------------------------------------------------------------------------

describe("D13: later commands use the bundled rules unless --rules is given", () => {
  const plantedRules = [
    "version: 1",
    "rules:",
    "  - id: evil-rule",
    '    title: "Evil title"',
    "    severity: high",
    "    confidence: high",
    "    cwe: CWE-1",
    "    languages: [python]",
    '    pattern: "^(a+)+$"',
    "    redactEvidence: true",
    "    message: m",
    '    remediation: "EVIL REMEDIATION TEXT from repo rules"',
    "",
  ].join("\n");

  it("records a hash of the rule set and is silent while it matches", async () => {
    const root = project("d13-plain");
    const result = await scan(root);
    expect(result.run.rulesHash).toBe(ruleSetHash(loadRules(RULES_DIR)));
    const snippet = readSnippet(result.runId, "app.py", 1, undefined, { cwd: root });
    expect(snippet.notices).toEqual([]);
    expect(renderRunReport(result.runId, "md", { cwd: root }).notices).toEqual([]);
  });

  it("does not load a rules directory planted in run.json (a ReDoS rule would hang read)", async () => {
    const root = project("d13-planted", {
      "a.py": `x = 1\n${"a".repeat(60)}!\n`,
      "r/x.yml": plantedRules,
    });
    const result = await scan(root);
    for (const rulesHash of [undefined, "0".repeat(64)]) {
      const run = readJson<Record<string, unknown>>(path.join(result.runDir, "run.json"));
      run.rulesDir = path.join(root, "r");
      if (rulesHash === undefined) delete run.rulesHash;
      else run.rulesHash = rulesHash;
      fs.writeFileSync(path.join(result.runDir, "run.json"), JSON.stringify(run));

      const started = Date.now();
      const snippet = readSnippet(result.runId, "a.py", 1, undefined, { cwd: root });
      expect(Date.now() - started).toBeLessThan(5_000);
      expect(snippet.lines).toHaveLength(3);
      expect(snippet.notices.join("\n")).toMatch(/not loaded|not the one this run was scanned with/);
      const report = renderRunReport(result.runId, "md", { cwd: root });
      expect(report.text).not.toContain("EVIL REMEDIATION TEXT");
      expect(report.notices.join("\n")).toContain("--rules <dir>");
    }
    const viaCli = cli(["read", result.runId, "a.py"], root);
    expect(viaCli.status).toBe(0);
    expect(viaCli.stderr).toContain("warning: ");
    expect(viaCli.stderr).toContain("--rules <dir>");
  });

  it("uses the directory given with --rules on that command line", async () => {
    const root = project("d13-explicit", { "app.py": 'TOKEN_VALUE = "visible-marker-12345"\n' });
    const rules = path.join(temp, "d13-explicit-rules");
    writeFile(
      rules,
      "x.yml",
      [
        "version: 1",
        "rules:",
        "  - id: mask-marker",
        '    title: "Marker"',
        "    severity: low",
        "    confidence: low",
        "    cwe: CWE-1",
        "    languages: [python]",
        '    pattern: "visible-marker-[0-9]+"',
        "    redactEvidence: true",
        "    message: m",
        "    remediation: r",
        "",
      ].join("\n"),
    );
    const result = await scan(root);
    const explicit = loadRun(result.runId, { cwd: root, rulesDir: rules });
    expect(explicit.session.rulesDir).toBe(rules);
    const snippet = readSnippet(result.runId, "app.py", 1, undefined, { cwd: root, rulesDir: rules });
    expect(snippet.notices.join("\n")).toContain("not the one this run was scanned with");
    // A directory the user names must load.
    expect(() =>
      readSnippet(result.runId, "app.py", 1, undefined, { cwd: root, rulesDir: path.join(temp, "no-such-rules") }),
    ).toThrow();
    const viaCli = cli(["read", result.runId, "app.py", "--rules", rules], root);
    expect(viaCli.status).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// D14: malformed JSON in .audit and in run directories
// ---------------------------------------------------------------------------

const MALFORMED: Array<[string, string | Buffer]> = [
  ["wrong type", '{"runs":"x"}'],
  ["not JSON", "garbage"],
  ["array", "[]"],
  ["null", "null"],
  ["number", "42"],
  ["empty object", "{}"],
  ["empty file", ""],
  ["wrong member types", '{"schemaVersion":1,"runId":7,"runs":[1,2],"findings":"x","entries":{},"hotspots":3}'],
  ["__proto__ keys", '{"__proto__":{"polluted":true},"schemaVersion":1,"runs":[{"__proto__":{"x":1}}],"findings":[{"__proto__":{"status":"suppressed"}}],"entries":[{"__proto__":1}]}'],
  ["huge array", `{"schemaVersion":1,"runs":[${"1,".repeat(200_000)}1],"findings":[${"1,".repeat(200_000)}1],"entries":[${"1,".repeat(200_000)}1]}`],
  ["deeply nested", `${"[".repeat(20_000)}${"]".repeat(20_000)}`],
  ["deeply nested object", `{"schemaVersion":1,"args":${'{"a":'.repeat(5_000)}1${"}".repeat(5_000)}}`],
  ["non-UTF-8", Buffer.from([0x7b, 0x22, 0xff, 0xfe, 0x80, 0x22, 0x3a, 0xc3, 0x28, 0x7d])],
  ["control characters", '{"schemaVersion":1,"runId":"\\u001b[2J\\u001b[31mowned","runs":"\\u001b[31m"}'],
];

describe("D14: malformed files never crash a command", () => {
  it("rebuilds an invalid .audit/index.json with a warning", async () => {
    const root = project("d14-index");
    const first = await scan(root);
    for (const [label, content] of MALFORMED) {
      fs.writeFileSync(path.join(root, ".audit", "index.json"), content);
      const result = await scan(root);
      const index = readJson<{ schemaVersion: number; runs: Array<{ runId: string; runDir: string }> }>(
        path.join(root, ".audit", "index.json"),
      );
      expect(index.schemaVersion, label).toBe(1);
      const ids = index.runs.map((run) => run.runId);
      expect(ids, label).toContain(result.runId);
      // Rebuilt from the run directories, not just emptied.
      expect(ids, label).toContain(first.runId);
      expect(result.warnings.join("\n"), label).toContain(".audit/index.json was not valid and has been rebuilt");
      expect((result.run.warnings as string[]).join("\n"), label).toContain("index.json was not valid");
      expect(result.warnings.join("\n"), label).not.toContain("\u001b");
      expect(resolveRunDir(result.runId, { cwd: root }), label).toBe(result.runDir);
    }
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();

    // A valid index is kept and produces no warning.
    const quiet = await scan(root);
    expect(quiet.warnings.join("\n")).not.toContain("index.json");
    // An index that is a link is not written through.
    const outside = path.join(temp, "d14-index-outside.json");
    fs.writeFileSync(outside, "untouched");
    fs.rmSync(path.join(root, ".audit", "index.json"));
    fs.symlinkSync(outside, path.join(root, ".audit", "index.json"));
    registerRunIndex(root, {
      runId: quiet.runId,
      runDir: quiet.runDir,
      root,
      phase: "complete",
      startedAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-01-01T00:00:00.000Z",
    });
    expect(fs.readFileSync(outside, "utf8")).toBe("untouched");
    expect(fs.lstatSync(path.join(root, ".audit", "index.json")).isFile()).toBe(true);
  });

  it("fails with one clear line when a run file is malformed", async () => {
    const root = project("d14-run");
    const result = await scan(root);
    const options = { cwd: root };
    const target = [...result.findings, ...result.hotspots][0]?.id ?? "";
    const files = ["run.json", "findings.json", "coverage.json", "state.json", "verdicts.json", "agent-findings.json"];
    for (const file of files) {
      const full = path.join(result.runDir, file);
      const original = fs.existsSync(full) ? fs.readFileSync(full) : undefined;
      for (const [label, content] of MALFORMED) {
        const where = `${file} / ${label}`;
        fs.writeFileSync(full, content);
        const commands: Array<[string, () => unknown]> = [
          ["status", () => runStatus(result.runId, options)],
          ["summary", () => renderRunReport(result.runId, "summary", options)],
          ["md", () => renderRunReport(result.runId, "md", options)],
          ["sarif", () => renderRunReport(result.runId, "sarif", options)],
          ["verdict", () => recordVerdict(result.runId, target, { status: "likely", rationale: "r" }, options)],
          ["read", () => readSnippet(result.runId, "app.py", 1, undefined, options)],
        ];
        for (const [name, command] of commands) {
          let error: unknown;
          try {
            command();
          } catch (caught) {
            error = caught;
          }
          if (error === undefined) continue; // tolerated shape (for example an empty optional file)
          expect(error, `${where} / ${name}`).toBeInstanceOf(RunStoreError);
          const message = (error as Error).message;
          expect(message, `${where} / ${name}`).not.toContain("\n");
          expect(message, `${where} / ${name}`).not.toContain("\u001b");
          expect(message.length, `${where} / ${name}`).toBeLessThan(1500);
        }
        // Whatever was tolerated, nothing from the file became a prototype.
        expect(({} as Record<string, unknown>).polluted, where).toBeUndefined();
        if (original) fs.writeFileSync(full, original);
        else fs.rmSync(full, { force: true });
        // A refused command must not have left the run half-written.
        expect(() => runStatus(result.runId, options), where).not.toThrow();
        fs.rmSync(path.join(result.runDir, "verdicts.json"), { force: true });
      }
    }
  }, 120_000);

  it("CLI: coverage.json = {} fails report --format md with exit 2, status still works", async () => {
    const root = project("d14-coverage");
    const result = await scan(root);
    fs.writeFileSync(path.join(result.runDir, "coverage.json"), "{}");
    const report = cli(["report", result.runId, "--format", "md"], root);
    expect(report.status).toBe(2);
    expect(report.stderr).toContain("coverage.json");
    expect(report.stderr).toContain("not a valid code-audit file");
    expect(report.stderr).not.toMatch(/TypeError|\n\s+at /);
    expect(report.stderr).not.toContain("Usage:");
    expect(cli(["status", result.runId], root).status).toBe(0);

    fs.writeFileSync(path.join(result.runDir, "run.json"), '{"runId":{"a":1}}');
    const status = cli(["status", result.runId], root);
    expect(status.status).toBe(2);
    expect(status.stderr).toContain("run.json");
    expect(status.stderr).not.toMatch(/TypeError|\n\s+at /);
  });

  it("a finding with a __proto__ key is loaded as plain data", async () => {
    const root = project("d14-proto");
    const result = await scan(root);
    const file = path.join(result.runDir, "findings.json");
    const text = fs.readFileSync(file, "utf8").replace('"findings": [\n    {', '"findings": [\n    {"__proto__": {"cvss": "<b>", "status": "suppressed"},');
    expect(text).toContain("__proto__");
    fs.writeFileSync(file, text);
    const loaded = loadRun(result.runId, { cwd: root });
    const first = loaded.findings[0] as Record<string, unknown>;
    expect(Object.getPrototypeOf(first)).toBe(Object.prototype);
    expect(first.cvss).toBeUndefined();
    expect(first.status).toBe("candidate");
  });
});
