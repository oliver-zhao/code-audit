/**
 * `scan --since <ref> --diff-lines`: findings are kept only when their line
 * range touches a line that is new or changed since the ref. The old content
 * is read with `git cat-file blob <oid>` only - never through a command that
 * runs the audited repository's filters, textconv or fsmonitor.
 */
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { afterAll, describe, expect, it } from "vitest";
import { listChangedFiles, listChangedLines } from "../src/git.js";
import { scanProject } from "../src/scan.js";
import { CLI, REPO_ROOT, cleanup, makeTempDir } from "./helpers.js";

const temp = makeTempDir("difflines");
afterAll(() => {
  try {
    fs.rmSync(temp, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  } catch {
    cleanup(temp);
  }
});

const GIT_TEST_ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "test",
  GIT_AUTHOR_EMAIL: "test@example.invalid",
  GIT_COMMITTER_NAME: "test",
  GIT_COMMITTER_EMAIL: "test@example.invalid",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: "/dev/null",
};

function git(args: string[], cwd: string): string {
  const result = spawnSync("git", args, { cwd, encoding: "utf8", env: GIT_TEST_ENV });
  if (result.status !== 0) throw new Error(`git ${args.join(" ")} failed: ${result.stderr}`);
  return result.stdout;
}

function write(repo: string, rel: string, text: string): void {
  const target = path.join(repo, rel);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, text);
}

function makeRepo(name: string, files: Record<string, string>): string {
  const repo = path.join(temp, name);
  fs.mkdirSync(repo, { recursive: true });
  git(["init", "-q"], repo);
  for (const [rel, text] of Object.entries(files)) write(repo, rel, text);
  git(["add", "-A"], repo);
  git(["commit", "-qm", "init"], repo);
  return repo;
}

// Python with two code findings (command execution with a variable).
const OLD_APP = [
  "import os",
  "import subprocess",
  "",
  "def first(cmd):",
  "    os.system(cmd)",
  "",
  "def second(cmd):",
  "    subprocess.call(cmd, shell=True)",
  "",
].join("\n");

const NEW_APP = [
  "import os",
  "import subprocess",
  "",
  "def first(cmd):",
  "    os.system(cmd)",
  "",
  "def added(cmd):",
  "    os.system(cmd + ' --added')",
  "",
  "def second(cmd):",
  "    subprocess.call(cmd, shell=True)",
  "",
].join("\n");

async function scan(repo: string, name: string, extra: Record<string, unknown> = {}) {
  return scanProject({
    root: repo,
    out: path.join(temp, `out-${name}`),
    offline: true,
    engines: ["builtin"],
    formats: ["json"],
    ...extra,
  });
}

describe("listChangedLines", () => {
  it("returns the added lines of a modified file and the whole of a new file", async () => {
    const repo = makeRepo("lines-basic", { "a.py": OLD_APP, "same.py": "x = 1\n" });
    write(repo, "a.py", NEW_APP);
    write(repo, "new.py", "a = 1\nb = 2\n");
    const changed = await listChangedFiles(repo, "HEAD");
    expect(changed.files).toEqual(["a.py", "new.py"]);
    const lines = await listChangedLines(repo, "HEAD", changed.files);
    expect([...(lines.files.get("a.py")?.lines ?? [])].sort((a, b) => a - b)).toEqual([7, 8, 9]);
    expect(lines.files.get("new.py")).toEqual({ whole: "new-file" });
  });

  it("works with a subdirectory as the audit root and an older commit", async () => {
    const repo = makeRepo("lines-subdir", { "pkg/a.py": "one\ntwo\nthree\n", "top.py": "t\n" });
    write(repo, "pkg/a.py", "one\nTWO\nthree\n");
    git(["commit", "-qam", "second"], repo);
    write(repo, "pkg/a.py", "one\nTWO\nthree\nfour\n");
    const root = path.join(repo, "pkg");
    const changed = await listChangedFiles(root, "HEAD~1");
    expect(changed.files).toEqual(["a.py"]);
    const lines = await listChangedLines(root, "HEAD~1", changed.files);
    expect([...(lines.files.get("a.py")?.lines ?? [])].sort()).toEqual([2, 4]);
  });

  it("counts a file in full when it exceeds the line or edit-distance limits", async () => {
    const repo = makeRepo("lines-limits", { "a.txt": "a\nb\nc\n", "b.txt": "a\nb\nc\n" });
    write(repo, "a.txt", "a\nB\nc\n");
    write(repo, "b.txt", "x\ny\nz\n");
    const tooLong = await listChangedLines(repo, "HEAD", ["a.txt"], { maxLines: 2 });
    expect(tooLong.files.get("a.txt")).toEqual({ whole: "too-many-lines" });
    expect(tooLong.warnings.join("\n")).toMatch(/not diffed line by line/);
    const tooDifferent = await listChangedLines(repo, "HEAD", ["b.txt"], { maxEditDistance: 2 });
    expect(tooDifferent.files.get("b.txt")).toEqual({ whole: "edit-distance" });
  });

  it("treats a working file that is now a symbolic link as changed in full", async () => {
    const repo = makeRepo("lines-symlink", { "a.txt": "a\n", "target.txt": "t\n" });
    fs.rmSync(path.join(repo, "a.txt"));
    fs.symlinkSync("target.txt", path.join(repo, "a.txt"));
    const lines = await listChangedLines(repo, "HEAD", ["a.txt"]);
    expect(lines.files.get("a.txt")).toEqual({ whole: "not-a-regular-file" });
  });

  it("refuses a dangerous ref", async () => {
    const repo = makeRepo("lines-ref", { "a.txt": "a\n" });
    await expect(listChangedLines(repo, "--output=/tmp/x", ["a.txt"])).rejects.toThrow(/starts with '-'/);
    await expect(listChangedLines(repo, "no-such-ref", ["a.txt"])).rejects.toThrow(/ls-tree failed/);
  });
});

describe("scan --since --diff-lines", () => {
  it("keeps only findings on changed lines and reports how many were left out", async () => {
    const repo = makeRepo("scan-basic", { "app.py": OLD_APP, "other.py": OLD_APP });
    write(repo, "app.py", NEW_APP);

    const byFile = await scan(repo, "basic-files", { since: "HEAD" });
    const fileLevel = [...byFile.findings, ...byFile.hotspots].filter((f) => f.file === "app.py");
    // The control: without --diff-lines the old findings of app.py are reported.
    expect(fileLevel.some((finding) => finding.startLine === 5)).toBe(true);
    expect(fileLevel.some((finding) => finding.startLine === 8)).toBe(true);

    const byLine = await scan(repo, "basic-lines", { since: "HEAD", diffLines: true });
    const lineLevel = [...byLine.findings, ...byLine.hotspots];
    expect(lineLevel.length).toBeGreaterThan(0);
    for (const finding of lineLevel) {
      expect(finding.file).toBe("app.py");
      expect(finding.startLine).toBeGreaterThanOrEqual(7);
      expect(finding.startLine).toBeLessThanOrEqual(9);
    }
    const scope = byLine.run.scope as {
      since: string;
      changedFiles: number;
      diffLines: boolean;
      diffLinesFiltered: number;
    };
    expect(scope.diffLines).toBe(true);
    expect(scope.diffLinesFiltered).toBe(fileLevel.length - lineLevel.length);
    expect(scope.diffLinesFiltered).toBeGreaterThan(0);
    expect(byLine.coverage.scope?.diffLinesFiltered).toBe(scope.diffLinesFiltered);
    expect((byLine.run.args as { diffLines?: boolean }).diffLines).toBe(true);
  });

  it("keeps secret findings of a changed file even on unchanged lines", async () => {
    // A fake key built at run time (never a real one).
    const fakeKey = `AKIA${"Q".repeat(4)}${"7".repeat(4)}${"Z".repeat(8)}`;
    const old = `import os\naws_key = "${fakeKey}"\n\ndef f(cmd):\n    return 1\n`;
    const repo = makeRepo("scan-secret", { "conf.py": old });
    write(repo, "conf.py", `${old}\ndef g(cmd):\n    os.system(cmd)\n`);
    const full = await scan(repo, "secret-files", { since: "HEAD", includePlaceholders: true });
    const secrets = full.findings.filter((f) => f.category === "secrets" && f.startLine === 2);
    expect(secrets.length).toBeGreaterThan(0);
    const byLine = await scan(repo, "secret-lines", {
      since: "HEAD",
      diffLines: true,
      includePlaceholders: true,
    });
    expect(byLine.findings.filter((f) => f.category === "secrets" && f.startLine === 2).length).toBe(
      secrets.length,
    );
  });

  it("runs the diff filter before the baseline comparison", async () => {
    const repo = makeRepo("scan-baseline", { "app.py": OLD_APP });
    const first = await scan(repo, "baseline-first", {});
    const baselineFile = path.join(temp, "baseline-scan.json");
    const { buildBaseline } = await import("../src/baseline.js");
    fs.writeFileSync(
      baselineFile,
      JSON.stringify(buildBaseline(first.findings, new Date().toISOString(), "test")),
    );
    write(repo, "app.py", NEW_APP);
    const result = await scan(repo, "baseline-second", {
      since: "HEAD",
      diffLines: true,
      baseline: baselineFile,
    });
    const run = result.run as { baseline?: { new: number; existing: number; fixed: number } };
    expect(run.baseline).toBeDefined();
    // Only the added line's findings are compared; none of them is in the baseline.
    expect(run.baseline?.existing).toBe(0);
    expect(run.baseline?.new).toBe(result.findings.length);
  });

  it("is refused without --since", async () => {
    const repo = makeRepo("scan-nosince", { "a.py": "x = 1\n" });
    await expect(scan(repo, "nosince", { diffLines: true })).rejects.toThrow(/requires --since/);
    const cli = spawnSync(process.execPath, [CLI, "scan", repo, "--diff-lines", "--offline"], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      timeout: 60_000,
    });
    expect(cli.status).toBe(2);
    expect(cli.stderr).toMatch(/--diff-lines requires --since/);
  });

  it("prints the line scope in the CLI summary", () => {
    const repo = makeRepo("scan-cli", { "app.py": OLD_APP });
    write(repo, "app.py", NEW_APP);
    const cli = spawnSync(
      process.execPath,
      [
        CLI,
        "scan",
        repo,
        "--since",
        "HEAD",
        "--diff-lines",
        "--offline",
        "--engines",
        "builtin",
        "--out",
        path.join(temp, "out-cli"),
        "--fail-on",
        "critical",
      ],
      { cwd: REPO_ROOT, encoding: "utf8", timeout: 60_000 },
    );
    expect([0, 1]).toContain(cli.status);
    expect(cli.stdout).toMatch(/Scope: changed lines only \(--diff-lines\); \d+ results? on unchanged lines/);
  });
});

describe("--ignore-file with --untrusted", () => {
  it("applies an operator's ignore file outside the repository, never one inside it", async () => {
    const repo = makeRepo("ignore-untrusted", { "app.py": OLD_APP });
    const plain = await scan(repo, "ignore-plain", { untrusted: true });
    const target = [...plain.findings, ...plain.hotspots].find((f) => f.file === "app.py");
    expect(target).toBeDefined();
    const entry = `version: 1\nignore:\n  - rule: ${target?.ruleId}\n    paths: ["app.py"]\n    reason: accepted by the CI maintainer\n`;

    // Outside the repository, absolute: applied.
    const outside = path.join(temp, "operator-ignore.yml");
    fs.writeFileSync(outside, entry);
    const applied = await scan(repo, "ignore-outside", { untrusted: true, ignoreFile: outside });
    const suppressed = [...applied.findings, ...applied.hotspots].filter(
      (f) => f.ruleId === target?.ruleId && f.suppression?.source === "ignore-file",
    );
    expect(suppressed.length).toBeGreaterThan(0);
    expect((applied.run.args as { operatorIgnoreFile?: string }).operatorIgnoreFile).toBe(outside);
    expect((applied.run.repositoryControls as { ignoreFileFromRepository: boolean }).ignoreFileFromRepository).toBe(false);

    // Inside the repository (relative or absolute): not applied, with a warning.
    write(repo, "custom-ignore.yml", entry);
    for (const name of ["custom-ignore.yml", path.join(repo, "custom-ignore.yml")]) {
      const refused = await scan(repo, `ignore-inside-${name.length}`, { untrusted: true, ignoreFile: name });
      expect([...refused.findings, ...refused.hotspots].some((f) => f.suppression?.source === "ignore-file")).toBe(false);
      expect(refused.warnings.join("\n")).toMatch(/--ignore-file is not applied with --untrusted/);
    }

    // A symbolic link outside that points back into the repository: not applied.
    const link = path.join(temp, "ignore-link.yml");
    fs.symlinkSync(path.join(repo, "custom-ignore.yml"), link);
    const viaLink = await scan(repo, "ignore-link", { untrusted: true, ignoreFile: link });
    expect([...viaLink.findings, ...viaLink.hotspots].some((f) => f.suppression?.source === "ignore-file")).toBe(false);
  });
});

describe("--baseline with --untrusted", () => {
  it("applies an operator's baseline outside the repository, never one inside it", async () => {
    const repo = makeRepo("baseline-untrusted", { "app.py": OLD_APP });
    const first = await scan(repo, "bu-first", { untrusted: true });
    expect(first.findings.length).toBeGreaterThan(0);
    const { buildBaseline } = await import("../src/baseline.js");
    const document = JSON.stringify(buildBaseline(first.findings, new Date().toISOString(), "test"));

    const outside = path.join(temp, "operator-baseline.json");
    fs.writeFileSync(outside, document);
    const applied = await scan(repo, "bu-outside", { untrusted: true, baseline: outside });
    const run = applied.run as { baseline?: { new: number; existing: number }; args: { operatorBaseline?: string } };
    expect(run.baseline?.existing).toBe(first.findings.length);
    expect(run.baseline?.new).toBe(0);
    expect(run.args.operatorBaseline).toBe(outside);
    expect(applied.summary.exitCode.code).toBe(0);

    write(repo, ".code-audit-baseline.json", document);
    for (const name of [".code-audit-baseline.json", path.join(repo, ".code-audit-baseline.json")]) {
      const refused = await scan(repo, `bu-inside-${name.length}`, { untrusted: true, baseline: name });
      expect((refused.run as { baseline?: unknown }).baseline).toBeUndefined();
      expect(refused.warnings.join("\n")).toMatch(/--baseline is not applied with --untrusted/);
    }
    // The repository's default baseline is never read under --untrusted.
    const byDefault = await scan(repo, "bu-default", { untrusted: true });
    expect((byDefault.run as { baseline?: unknown }).baseline).toBeUndefined();
  });
});

/** A program that creates `marker` when it is run, whatever its arguments. */
function markerProgram(name: string): { program: string; marker: string } {
  const marker = path.join(temp, `${name}.marker`);
  const program = path.join(temp, `${name}.sh`);
  fs.writeFileSync(program, `#!/bin/sh\n: > ${JSON.stringify(marker)}\ncat 2>/dev/null\nexit 0\n`, "utf8");
  fs.chmodSync(program, 0o755);
  return { program, marker };
}

const MARKER_CASES: Array<{
  name: string;
  setup: (repo: string, program: string) => void;
  /** Plain git that does run the program: the configuration is live. */
  control?: string[];
  /** Delete the old blob of a.py, so a lazy fetch would be attempted. */
  missingBlob?: boolean;
}> = [
  {
    name: "filter-clean-smudge-process",
    setup: (repo, program) => {
      write(repo, ".gitattributes", "* filter=f\n");
      git(["config", "filter.f.clean", program], repo);
      git(["config", "filter.f.smudge", program], repo);
      git(["config", "filter.f.process", program], repo);
    },
    control: ["diff", "HEAD"],
  },
  {
    name: "textconv",
    setup: (repo, program) => {
      write(repo, ".gitattributes", "*.py diff=d\n");
      git(["config", "diff.d.textconv", program], repo);
    },
    // `cat-file --textconv` runs it; `cat-file blob` (what the scan uses) does not.
    control: ["cat-file", "--textconv", "HEAD:a.py"],
  },
  {
    name: "fsmonitor",
    setup: (repo, program) => {
      git(["config", "core.fsmonitor", program], repo);
    },
    control: ["status"],
  },
  {
    name: "diff-external-and-alias",
    setup: (repo, program) => {
      git(["config", "diff.external", program], repo);
      git(["config", "alias.cat-file", `!${program}`], repo);
    },
    control: ["diff", "HEAD"],
  },
  {
    name: "partial-clone-promisor",
    setup: (repo, program) => {
      // A promisor remote whose transport is a program: a lazy fetch of a
      // missing blob would run it.
      git(["config", "extensions.partialClone", "origin"], repo);
      git(["config", "remote.origin.url", `ext::${program}`], repo);
      git(["config", "remote.origin.promisor", "true"], repo);
      git(["config", "protocol.ext.allow", "always"], repo);
      git(["config", "core.sshCommand", program], repo);
    },
    missingBlob: true,
  },
];

describe("--diff-lines never runs a program configured by the audited repository", () => {
  for (const testCase of MARKER_CASES) {
    it(`${testCase.name}: the configured program is not run`, async () => {
      const repo = makeRepo(`marker-${testCase.name}`, { "a.py": OLD_APP, "b.py": "print('b')\n" });
      const { program, marker } = markerProgram(testCase.name);
      testCase.setup(repo, program);
      write(repo, "a.py", NEW_APP);
      write(repo, "c.py", "print('new')\n");
      let oldBlob = "";
      if (testCase.missingBlob) {
        oldBlob = git(["rev-parse", "HEAD:a.py"], repo).trim();
        fs.rmSync(path.join(repo, ".git", "objects", oldBlob.slice(0, 2), oldBlob.slice(2)));
      }
      fs.rmSync(marker, { force: true });

      const changed = await listChangedFiles(repo, "HEAD");
      const lines = await listChangedLines(repo, "HEAD", changed.files);
      expect(fs.existsSync(marker)).toBe(false);
      if (testCase.missingBlob) {
        // Not readable: the whole file counts as changed (fail open).
        expect(lines.files.get("a.py")).toEqual({ whole: "unreadable" });
      } else {
        expect([...(lines.files.get("a.py")?.lines ?? [])].sort()).toEqual([7, 8, 9]);
      }

      await scan(repo, `marker-${testCase.name}`, { since: "HEAD", diffLines: true });
      expect(fs.existsSync(marker)).toBe(false);

      const control = testCase.missingBlob ? ["cat-file", "blob", oldBlob] : testCase.control;
      if (control) {
        // The marker program does not speak the transport protocol: bounded.
        spawnSync("git", control, { cwd: repo, env: GIT_TEST_ENV, encoding: "utf8", timeout: 10_000 });
        expect(fs.existsSync(marker)).toBe(true);
      }
    });
  }
});

// ---------------------------------------------------------------------------
// Regressions from the adversarial review (F4_REVIEW.md).

describe("review fixes", () => {
  it("H1: lone CRs cannot move a new finding onto an unchanged line", async () => {
    const base = 'const express = require("express");\nconst app = express();\nfunction ok() { return 1; }\nmodule.exports = ok;\n';
    const repo = makeRepo("h1-lone-cr", { "app.js": base });
    const sink = 'app.get("/", (req, res) => { eval(req.query.code); });\n';
    // Line 1 (a changed line) ends with a comment that holds lone CRs.
    write(
      repo,
      "app.js",
      'const express = require("express"); //\r//\r//\r//\rx\nconst app = express();\nfunction ok() { return 1; }\n' + sink + "module.exports = ok;\n",
    );
    const byFile = await scan(repo, "h1-files", { since: "HEAD", untrusted: true });
    const target = byFile.findings.find((f) => f.file === "app.js" && /eval|injection/.test(f.ruleId));
    expect(target).toBeDefined();
    const byLine = await scan(repo, "h1-lines", { since: "HEAD", diffLines: true, untrusted: true });
    expect(byLine.findings.some((f) => f.fingerprint === target?.fingerprint)).toBe(true);
    expect(byLine.summary.exitCode.code).toBe(byFile.summary.exitCode.code);
  });

  it("H2: a tree:0 partial clone with an ext:: promisor runs nothing for --since and --diff-lines", async () => {
    const server = makeRepo("h2-server", { "a.py": OLD_APP });
    write(server, "a.py", NEW_APP);
    git(["commit", "-qam", "second"], server);
    git(["config", "uploadpack.allowFilter", "true"], server);
    const clone = path.join(temp, "h2-clone");
    git(
      ["-c", "protocol.file.allow=always", "clone", "-q", "--filter=tree:0", "--no-local", `file://${server}`, clone],
      temp,
    );
    const marker = path.join(temp, "h2.marker");
    git(["config", "remote.origin.url", `ext::sh -c touch% ${marker}`], clone);
    git(["config", "protocol.ext.allow", "always"], clone);
    write(clone, "a.py", `${NEW_APP}\nimport os\nos.system(x)\n`);
    fs.rmSync(marker, { force: true });

    for (const diffLines of [false, true]) {
      try {
        await scan(clone, `h2-${diffLines}`, { since: "HEAD~1", diffLines, untrusted: true });
      } catch {
        // The tree of HEAD~1 is missing and may not be fetched: an error is fine.
      }
      expect(fs.existsSync(marker), `diffLines=${diffLines}`).toBe(false);
    }
    await expect(listChangedFiles(clone, "HEAD~1")).rejects.toThrow();
    expect(fs.existsSync(marker)).toBe(false);
    // Control: plain git fetches the missing tree and runs the program.
    spawnSync("git", ["ls-tree", "-r", "HEAD~1"], { cwd: clone, env: GIT_TEST_ENV, encoding: "utf8", timeout: 20_000 });
    expect(fs.existsSync(marker)).toBe(true);
  });

  it("M1: a replace ref cannot swap the old blob", async () => {
    const repo = makeRepo("m1-replace", { "app.py": OLD_APP });
    const base = git(["rev-parse", "HEAD"], repo).trim();
    write(repo, "app.py", NEW_APP);
    git(["commit", "-qam", "add sink"], repo);
    const before = await scan(repo, "m1-before", { since: base, diffLines: true });
    const added = before.findings.filter((f) => f.file === "app.py" && f.startLine === 8);
    expect(added.length).toBeGreaterThan(0);
    // Make the old blob "be" the new one.
    const oldBlob = git(["rev-parse", `${base}:app.py`], repo).trim();
    const newBlob = git(["rev-parse", "HEAD:app.py"], repo).trim();
    git(["replace", "-f", oldBlob, newBlob], repo);
    expect(git(["cat-file", "blob", oldBlob], repo)).toBe(NEW_APP);
    const after = await scan(repo, "m1-after", { since: base, diffLines: true });
    expect(after.findings.filter((f) => f.file === "app.py" && f.startLine === 8).length).toBe(added.length);
    const lines = await listChangedLines(repo, base, ["app.py"]);
    expect([...(lines.files.get("app.py")?.lines ?? [])].sort()).toEqual([7, 8, 9]);
  });

  it("M3: an ignore file or baseline inside the root's git work tree is refused; an applied one is named", async () => {
    const repo = makeRepo("m3-mono", {
      "app/app.py": OLD_APP,
      ".code-audit-ignore": 'version: 1\nignore:\n  - paths: ["**"]\n    reason: "hide everything"\n',
    });
    const root = path.join(repo, "app");
    const plain = await scan(repo, "m3-plain", { root, untrusted: true } as Record<string, unknown>);
    expect(plain.findings.length).toBeGreaterThan(0);
    const { buildBaseline } = await import("../src/baseline.js");
    write(repo, "bl.json", JSON.stringify(buildBaseline(plain.findings, new Date().toISOString(), "test")));
    const refused = await scan(repo, "m3-refused", {
      root,
      untrusted: true,
      ignoreFile: path.join(repo, ".code-audit-ignore"),
      baseline: path.join(repo, "bl.json"),
    } as Record<string, unknown>);
    expect(refused.findings.some((f) => f.suppression?.source === "ignore-file")).toBe(false);
    expect((refused.run as { baseline?: unknown }).baseline).toBeUndefined();
    expect(refused.warnings.join("\n")).toMatch(/--ignore-file is not applied with --untrusted: .*git work tree/);
    expect(refused.warnings.join("\n")).toMatch(/--baseline is not applied with --untrusted/);

    // An accepted operator file is named in the warnings (run.json) and the CLI summary.
    const outside = path.join(temp, "m3-operator-ignore.yml");
    fs.writeFileSync(outside, 'version: 1\nignore:\n  - paths: ["**"]\n    reason: "operator"\n');
    const applied = await scan(repo, "m3-applied", { root, untrusted: true, ignoreFile: outside } as Record<string, unknown>);
    expect(applied.warnings).toContain(`--untrusted: applied the ignore file given with --ignore-file: ${outside}`);
    const runJson = JSON.parse(fs.readFileSync(path.join(applied.runDir, "run.json"), "utf8"));
    expect(runJson.warnings).toContain(`--untrusted: applied the ignore file given with --ignore-file: ${outside}`);
    const cli = spawnSync(
      process.execPath,
      [CLI, "scan", root, "--untrusted", "--offline", "--engines", "builtin", "--ignore-file", outside, "--out", path.join(temp, "out-m3-cli")],
      { cwd: REPO_ROOT, encoding: "utf8", timeout: 60_000 },
    );
    expect(cli.stdout).toContain(`WARNING: --untrusted, but the ignore file given with --ignore-file was applied: ${outside}`);
  });

  it("LOW 2: findings left out by --diff-lines are not counted as fixed", async () => {
    const repo = makeRepo("l2-fixed", { "app.py": OLD_APP });
    const first = await scan(repo, "l2-first", {});
    const { buildBaseline } = await import("../src/baseline.js");
    const baselineFile = path.join(temp, "l2-baseline.json");
    fs.writeFileSync(baselineFile, JSON.stringify(buildBaseline(first.findings, new Date().toISOString(), "test")));
    write(repo, "app.py", `${OLD_APP}# a comment\n`);
    const result = await scan(repo, "l2-second", { since: "HEAD", diffLines: true, baseline: baselineFile });
    const run = result.run as { baseline?: { new: number; existing: number; fixed: number } };
    expect((result.run.scope as { diffLinesFiltered: number }).diffLinesFiltered).toBeGreaterThan(0);
    expect(run.baseline?.fixed).toBe(0);
    // A finding that is really gone is still fixed.
    write(repo, "app.py", "import os\n# nothing left\n");
    const gone = await scan(repo, "l2-gone", { since: "HEAD", diffLines: true, baseline: baselineFile });
    expect((gone.run as { baseline?: { fixed: number } }).baseline?.fixed).toBe(first.findings.length);
  });

  it("LOW 1: deleting a guard line puts its neighbour in scope", async () => {
    const repo = makeRepo("l1-delete", {
      "a.txt": "one\nguard()\nsink()\nend\n",
    });
    write(repo, "a.txt", "one\nsink()\nend\n");
    const lines = await listChangedLines(repo, "HEAD", ["a.txt"]);
    expect([...(lines.files.get("a.txt")?.lines ?? [])].sort()).toEqual([1, 2]);
  });
});
