import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { afterAll, describe, expect, it } from "vitest";
import { scanProject } from "../src/scan.js";
import { GitScopeError, assertSafeRef, listChangedFiles } from "../src/git.js";
import {
  VULNERABLE,
  cleanup,
  makeTempDir,
  writeFile,
} from "./helpers.js";

const temp = makeTempDir("since");

afterAll(() => cleanup(temp));

function git(args: string[], cwd: string): void {
  const result = spawnSync("git", args, {
    cwd,
    encoding: "utf8",
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: "test",
      GIT_AUTHOR_EMAIL: "test@example.invalid",
      GIT_COMMITTER_NAME: "test",
      GIT_COMMITTER_EMAIL: "test@example.invalid",
    },
  });
  if (result.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed: ${result.stderr}`);
  }
}

function makeRepo(name: string): string {
  const repo = path.join(temp, name);
  fs.cpSync(VULNERABLE, repo, { recursive: true });
  git(["init", "-q"], repo);
  git(["add", "-A"], repo);
  git(["commit", "-qm", "init"], repo);
  return repo;
}

describe("safe ref validation", () => {
  it("rejects refs starting with a dash", () => {
    expect(() => assertSafeRef("--output=/tmp/x")).toThrow(GitScopeError);
  });
  it("rejects empty refs", () => {
    expect(() => assertSafeRef("   ")).toThrow(GitScopeError);
  });
  it("rejects refs with whitespace or control characters", () => {
    expect(() => assertSafeRef("HEAD rm")).toThrow(/whitespace|control/);
    expect(() => assertSafeRef("a\tb")).toThrow(/whitespace|control/);
    expect(() => assertSafeRef("a\nb")).toThrow(/whitespace|control/);
  });
  it("accepts a normal ref", () => {
    expect(assertSafeRef("HEAD")).toBe("HEAD");
  });
});

describe("--since incremental scan", () => {
  it("reports only findings in files changed since the ref", async () => {
    const repo = makeRepo("repo-basic");
    // Modify one file.
    fs.appendFileSync(path.join(repo, "go", "main.go"), "\n// touched\n", "utf8");

    const result = await scanProject({
      root: repo,
      out: path.join(temp, "out-basic"),
      offline: true,
      engines: ["builtin"],
      since: "HEAD",
      formats: ["json", "md"],
    });
    expect(result.findings.length).toBeGreaterThan(0);
    for (const finding of result.findings) {
      expect(finding.file).toBe("go/main.go");
    }
    const run = result.run as { scope: { since: string; changedFiles: number } };
    expect(run.scope.since).toBe("HEAD");
    const md = fs.readFileSync(path.join(result.runDir, "report.md"), "utf8");
    expect(md).toContain("files changed since HEAD");
  });

  it("keeps an unchanged vulnerable file out of scope", async () => {
    const repo = makeRepo("repo-unchanged");
    fs.appendFileSync(path.join(repo, "go", "main.go"), "\n// touched\n", "utf8");
    const result = await scanProject({
      root: repo,
      out: path.join(temp, "out-unchanged"),
      offline: true,
      engines: ["builtin"],
      since: "HEAD",
      formats: ["json"],
    });
    const files = new Set(result.findings.map((f) => f.file));
    expect(files.has("python/app.py")).toBe(false);
    expect(result.coverage.scope?.outOfScope).toBeGreaterThan(0);
  });

  it("includes a new untracked file in scope", async () => {
    const repo = makeRepo("repo-untracked");
    writeFile(repo, "python/newapp.py", 'import os\nos.system("ls " + c)\n');
    const result = await scanProject({
      root: repo,
      out: path.join(temp, "out-untracked"),
      offline: true,
      engines: ["builtin"],
      since: "HEAD",
      formats: ["json"],
    });
    const files = new Set(result.findings.map((f) => f.file));
    expect(files.has("python/newapp.py")).toBe(true);
  });

  it("excludes a file ignored by .gitignore", async () => {
    const repo = makeRepo("repo-gitignore");
    writeFile(repo, ".gitignore", "ignored/\n");
    writeFile(repo, "ignored/secret.py", 'import os\nos.system("ls " + c)\n');
    const result = await scanProject({
      root: repo,
      out: path.join(temp, "out-gitignore"),
      offline: true,
      engines: ["builtin"],
      since: "HEAD",
      formats: ["json"],
    });
    const files = new Set(result.findings.map((f) => f.file));
    expect(files.has("ignored/secret.py")).toBe(false);
  });

  it("does not crash on a deleted file", async () => {
    const repo = makeRepo("repo-deleted");
    fs.rmSync(path.join(repo, "python", "app.py"));
    const result = await scanProject({
      root: repo,
      out: path.join(temp, "out-deleted"),
      offline: true,
      engines: ["builtin"],
      since: "HEAD",
      formats: ["json"],
    });
    expect(result.findings.every((f) => f.file !== "python/app.py")).toBe(true);
  });

  it("returns exit 2 for a bad ref", async () => {
    const repo = makeRepo("repo-badref");
    // If the ref ever reached git as a flag, git would write this file.
    const marker = path.join(temp, "badref-output");
    await expect(
      scanProject({
        root: repo,
        out: path.join(temp, "out-badref"),
        offline: true,
        engines: ["builtin"],
        since: `--output=${marker}`,
      }),
    ).rejects.toThrow(GitScopeError);
    expect(fs.existsSync(marker)).toBe(false);
  });

  it("returns exit 2 for a non-repository", async () => {
    // Must live outside this checkout (which is a git repository itself), so
    // use the OS temp directory. On macOS that path sits below a symlink.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "code-audit-nonrepo-"));
    try {
      expect(
        spawnSync("git", ["-C", dir, "rev-parse", "--is-inside-work-tree"])
          .status,
      ).not.toBe(0);
      writeFile(dir, "app.py", 'import os\nos.system("ls " + c)\n');
      await expect(
        scanProject({
          root: dir,
          out: path.join(temp, "out-notrepo"),
          offline: true,
          engines: ["builtin"],
          since: "HEAD",
        }),
      ).rejects.toThrow(GitScopeError);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("works when the repository is reached through a symlinked parent", async () => {
    // macOS regression: the OS temp dir is below /var -> /private/var. Build
    // the same shape on every OS: <base>/alias -> <base>/real.
    const base = fs.mkdtempSync(path.join(os.tmpdir(), "code-audit-since-"));
    try {
      const real = path.join(base, "real");
      fs.mkdirSync(real);
      fs.symlinkSync(real, path.join(base, "alias"), "dir");
      const realRepo = path.join(real, "repo");
      fs.cpSync(VULNERABLE, realRepo, { recursive: true });
      git(["init", "-q"], realRepo);
      git(["add", "-A"], realRepo);
      git(["commit", "-qm", "init"], realRepo);
      fs.appendFileSync(path.join(realRepo, "go", "main.go"), "\n// touched\n");
      writeFile(realRepo, "python/newapp.py", 'import os\nos.system("ls " + c)\n');
      // A hostile symlink inside the repo must not widen the scope.
      writeFile(real, "outside/secret.py", 'import os\nos.system("ls " + c)\n');
      fs.symlinkSync(path.join(real, "outside"), path.join(realRepo, "escape"), "dir");

      for (const root of [
        path.join(base, "alias", "repo"),
        realRepo,
        fs.realpathSync.native(realRepo),
      ]) {
        const changed = await listChangedFiles(root, "HEAD");
        // The untracked symlink itself is listed by git but points outside the
        // root, so the jail drops it; nothing below it is ever listed.
        expect(changed.files).toEqual(["go/main.go", "python/newapp.py"]);
        expect(changed.warnings).toEqual([
          "ignored path outside audit root reported by git",
        ]);
      }

      const result = await scanProject({
        root: path.join(base, "alias", "repo"),
        out: path.join(temp, "out-symlinked"),
        offline: true,
        engines: ["builtin"],
        since: "HEAD",
        formats: ["json"],
      });
      const files = new Set(result.findings.map((f) => f.file));
      expect(files.has("go/main.go")).toBe(true);
      expect(files.has("python/newapp.py")).toBe(true);
      for (const file of files) {
        expect(["go/main.go", "python/newapp.py"]).toContain(file);
      }
    } finally {
      fs.rmSync(base, { recursive: true, force: true });
    }
  });

  it("returns exit 2 for an unknown ref", async () => {
    const repo = makeRepo("repo-unknownref");
    await expect(
      scanProject({
        root: repo,
        out: path.join(temp, "out-unknownref"),
        offline: true,
        engines: ["builtin"],
        since: "no-such-ref",
      }),
    ).rejects.toThrow(/unknown git ref/);
  });
});

const hasGit = spawnSync("git", ["--version"]).status === 0;

/** Write a fake `git` executable with an absolute node shebang. */
function fakeGit(dir: string, source: string): string {
  const target = path.join(dir, "git");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(target, `#!${process.execPath}\n${source}\n`, "utf8");
  fs.chmodSync(target, 0o755);
  return target;
}

describe("git hardening", () => {
  it.skipIf(!hasGit)(
    "does not execute a malicious core.fsmonitor from the target repository",
    async () => {
      const repo = makeRepo("repo-fsmonitor");
      const marker = path.join(temp, "fsmonitor-marker");
      const script = path.join(temp, "fsmonitor.sh");
      fs.writeFileSync(
        script,
        `#!/bin/sh\ntouch ${JSON.stringify(marker)}\n`,
        "utf8",
      );
      fs.chmodSync(script, 0o755);
      // The target repository is untrusted: its config points fsmonitor at a
      // program that would create a marker if it were ever executed.
      git(["config", "core.fsmonitor", script], repo);
      fs.appendFileSync(
        path.join(repo, "go", "main.go"),
        "\n// touched\n",
        "utf8",
      );

      const result = await listChangedFiles(repo, "HEAD");
      expect(result.files.length).toBeGreaterThan(0);
      expect(fs.existsSync(marker)).toBe(false);
    },
  );
});

describe("git failure handling", () => {
  it("throws GitScopeError when a git listing command times out", async () => {
    const root = path.join(temp, "fake-timeout-root");
    fs.mkdirSync(root, { recursive: true });
    const dir = path.join(temp, "fake-timeout");
    fakeGit(
      dir,
      [
        "const args = process.argv.slice(2);",
        'if (args.includes("rev-parse")) process.exit(0);',
        'if (args.includes("ls-tree")) { setInterval(() => {}, 1000); } else { process.exit(0); }',
      ].join("\n"),
    );
    await expect(
      listChangedFiles(root, "HEAD", { pathEnv: dir, timeoutMs: 300 }),
    ).rejects.toThrow(GitScopeError);
    await expect(
      listChangedFiles(root, "HEAD", { pathEnv: dir, timeoutMs: 300 }),
    ).rejects.toThrow(/timed out/);
  });

  it("throws GitScopeError when git output is truncated", async () => {
    const root = path.join(temp, "fake-truncated-root");
    fs.mkdirSync(root, { recursive: true });
    const dir = path.join(temp, "fake-truncated");
    fakeGit(
      dir,
      [
        "const args = process.argv.slice(2);",
        'if (args.includes("rev-parse")) process.exit(0);',
        'if (args.includes("ls-tree")) { process.stdout.write("a".repeat(100000)); process.exit(0); }',
        "process.exit(0);",
      ].join("\n"),
    );
    await expect(
      listChangedFiles(root, "HEAD", { pathEnv: dir, maxOutputBytes: 100 }),
    ).rejects.toThrow(GitScopeError);
    await expect(
      listChangedFiles(root, "HEAD", { pathEnv: dir, maxOutputBytes: 100 }),
    ).rejects.toThrow(/size limit/);
  });

  it("drops changed paths that escape the audit root and warns", async () => {
    const root = path.join(temp, "fake-jail-root");
    fs.mkdirSync(root, { recursive: true });
    fs.writeFileSync(path.join(root, "inside.txt"), "x\n", "utf8");
    const dir = path.join(temp, "fake-jail");
    fakeGit(
      dir,
      [
        "const args = process.argv.slice(2);",
        'if (args.includes("rev-parse")) process.exit(0);',
        'if (args.includes("ls-files") && args.includes("--others")) {',
        '  process.stdout.write("../outside.txt\\0/etc/passwd\\0inside.txt\\0");',
        "  process.exit(0);",
        "}",
        "process.exit(0);",
      ].join("\n"),
    );
    const result = await listChangedFiles(root, "HEAD", { pathEnv: dir });
    expect(result.files).toEqual(["inside.txt"]);
    expect(result.warnings).toContain(
      "ignored path outside audit root reported by git",
    );
  });
});