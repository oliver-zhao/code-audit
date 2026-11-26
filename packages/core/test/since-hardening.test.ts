/**
 * `scan --since` must never make git read, hash or convert a working-tree
 * file: that is where the audited repository's own `.gitattributes` and
 * `.git/config` get programs run (clean / smudge / process filters, textconv,
 * external diff, fsmonitor, hooks). Every "marker" test configures such a
 * program to create a file and asserts the file never appears.
 */
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { afterAll, describe, expect, it } from "vitest";
import { listChangedFiles } from "../src/git.js";
import { scanProject } from "../src/scan.js";
import { cleanup, makeTempDir } from "./helpers.js";

const temp = makeTempDir("since-hardening");
afterAll(() => {
  // The control commands can leave a git child (auto gc) writing for a moment.
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
  if (result.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed: ${result.stderr}`);
  }
  return result.stdout;
}

function write(repo: string, rel: string, text: string | Buffer): void {
  const target = path.join(repo, rel);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, text);
}

function makeRepo(name: string, files: Record<string, string>, initArgs: string[] = []): string {
  const repo = path.join(temp, name);
  fs.mkdirSync(repo, { recursive: true });
  git(["init", "-q", ...initArgs], repo);
  for (const [rel, text] of Object.entries(files)) write(repo, rel, text);
  git(["add", "-A"], repo);
  git(["commit", "-qm", "init"], repo);
  return repo;
}

/** A program that creates `marker` when it is run, whatever its arguments. */
function markerProgram(name: string): { program: string; marker: string } {
  const marker = path.join(temp, `${name}.marker`);
  const program = path.join(temp, `${name}.sh`);
  fs.writeFileSync(program, `#!/bin/sh\n: > ${JSON.stringify(marker)}\ncat 2>/dev/null\nexit 0\n`, "utf8");
  fs.chmodSync(program, 0o755);
  return { program, marker };
}

interface MarkerCase {
  name: string;
  /** Configure the repository; `program` creates the marker when run. */
  setup: (repo: string, program: string) => void;
  /**
   * A plain git command that does run the program with this configuration -
   * the proof that the configuration is live and the test can fail.
   */
  control?: string[];
}

const MARKER_CASES: MarkerCase[] = [
  {
    name: "filter-clean",
    setup: (repo, program) => {
      write(repo, ".gitattributes", "* filter=f\n");
      git(["config", "filter.f.clean", program], repo);
    },
    control: ["diff", "HEAD"],
  },
  {
    name: "filter-process",
    setup: (repo, program) => {
      write(repo, ".gitattributes", "* filter=f\n");
      git(["config", "filter.f.process", program], repo);
    },
    control: ["diff", "HEAD"],
  },
  {
    name: "filter-smudge",
    setup: (repo, program) => {
      write(repo, ".gitattributes", "* filter=f\n");
      git(["config", "filter.f.smudge", program], repo);
      git(["config", "filter.f.required", "true"], repo);
    },
    control: ["checkout", "HEAD", "--", "a.py"],
  },
  {
    name: "filter-in-info-attributes",
    setup: (repo, program) => {
      write(repo, ".git/info/attributes", "* filter=f\n");
      git(["config", "filter.f.clean", program], repo);
    },
    control: ["diff", "HEAD"],
  },
  {
    name: "textconv",
    setup: (repo, program) => {
      write(repo, ".gitattributes", "*.py diff=d\n");
      git(["config", "diff.d.textconv", program], repo);
    },
    control: ["diff", "--textconv", "HEAD"],
  },
  {
    name: "diff-external",
    setup: (repo, program) => {
      git(["config", "diff.external", program], repo);
    },
    control: ["diff", "HEAD"],
  },
  {
    name: "fsmonitor",
    setup: (repo, program) => {
      git(["config", "core.fsmonitor", program], repo);
    },
    control: ["status"],
  },
  {
    name: "ssh-command",
    setup: (repo, program) => {
      git(["config", "core.sshCommand", program], repo);
      git(["config", "remote.origin.url", "ssh://example.invalid/x.git"], repo);
    },
  },
  {
    name: "alias",
    setup: (repo, program) => {
      for (const command of ["rev-parse", "ls-tree", "ls-files", "diff", "status", "st"]) {
        git(["config", `alias.${command}`, `!${program}`], repo);
      }
    },
    control: ["st"],
  },
  {
    name: "hooks-path",
    setup: (repo, program) => {
      const hooks = path.join(repo, "evil-hooks");
      fs.mkdirSync(hooks);
      for (const hook of [
        "post-index-change",
        "pre-commit",
        "post-checkout",
        "reference-transaction",
        "pre-auto-gc",
        "fsmonitor-watchman",
      ]) {
        fs.copyFileSync(program, path.join(hooks, hook));
        fs.chmodSync(path.join(hooks, hook), 0o755);
      }
      git(["config", "core.hooksPath", hooks], repo);
    },
    control: ["commit", "-qam", "control"],
  },
  {
    name: "uploadpack-and-pager",
    setup: (repo, program) => {
      git(["config", "uploadpack.packObjectsHook", program], repo);
      git(["config", "core.pager", program], repo);
      git(["config", "pager.ls-files", program], repo);
      git(["config", "pager.ls-tree", program], repo);
      git(["config", "pager.rev-parse", program], repo);
      git(["config", "core.editor", program], repo);
      git(["config", "core.askPass", program], repo);
      git(["config", "credential.helper", `!${program}`], repo);
    },
  },
  {
    name: "include-path",
    setup: (repo, program) => {
      const extra = path.join(temp, "include-path.gitconfig");
      fs.writeFileSync(
        extra,
        `[core]\n\tfsmonitor = ${program}\n[filter "f"]\n\tclean = ${program}\n\tprocess = ${program}\n[diff]\n\texternal = ${program}\n`,
        "utf8",
      );
      write(repo, ".gitattributes", "* filter=f\n");
      git(["config", "include.path", extra], repo);
    },
    control: ["diff", "HEAD"],
  },
  {
    name: "include-if",
    setup: (repo, program) => {
      const extra = path.join(temp, "include-if.gitconfig");
      fs.writeFileSync(
        extra,
        `[core]\n\tfsmonitor = ${program}\n[filter "f"]\n\tclean = ${program}\n\tprocess = ${program}\n[diff]\n\texternal = ${program}\n`,
        "utf8",
      );
      write(repo, ".gitattributes", "* filter=f\n");
      git(["config", "includeIf.gitdir:**.path", extra], repo);
    },
    control: ["diff", "HEAD"],
  },
];

describe("--since never runs a program configured by the audited repository", () => {
  for (const testCase of MARKER_CASES) {
    it(`${testCase.name}: the configured program is not run`, async () => {
      const repo = makeRepo(`marker-${testCase.name}`, {
        "a.py": "print('a')\n",
        "b.py": "print('b')\n",
      });
      const { program, marker } = markerProgram(testCase.name);
      testCase.setup(repo, program);
      // A modified, a staged and an untracked file: every code path is taken.
      write(repo, "a.py", "print('changed')\n");
      write(repo, "c.py", "print('new')\n");
      fs.rmSync(marker, { force: true });

      const result = await listChangedFiles(repo, "HEAD");
      expect(fs.existsSync(marker)).toBe(false);
      expect(result.files).toContain("a.py");
      expect(result.files).toContain("c.py");
      expect(result.files).not.toContain("b.py");

      // The same through a whole scan.
      await scanProject({
        root: repo,
        out: path.join(temp, `out-${testCase.name}`),
        offline: true,
        engines: ["builtin"],
        since: "HEAD",
        formats: ["json"],
      });
      expect(fs.existsSync(marker)).toBe(false);

      // Control: the configuration is live - plain git does run the program.
      if (testCase.control) {
        spawnSync("git", testCase.control, { cwd: repo, env: GIT_TEST_ENV, encoding: "utf8" });
        expect(fs.existsSync(marker)).toBe(true);
      }
    });
  }
});

describe("--since change detection without git reading the working tree", () => {
  it("classifies modified, staged, untracked, ignored, deleted and renamed files", async () => {
    const repo = makeRepo("behaviour", {
      "same.py": "same\n",
      "modified.py": "old\n",
      "staged.py": "old\n",
      "staged-then-reverted.py": "old\n",
      "deleted.py": "gone\n",
      "rename-from.py": "moved content\n",
      "dir/nested.py": "nested\n",
      "name with space.py": "space\n",
      "café-文件.py": "unicode\n",
      ".gitignore": "ignored.py\nbuild/\n",
      "tracked-but-ignored/x.py": "tracked\n",
    });
    write(repo, "modified.py", "new\n");
    write(repo, "staged.py", "new\n");
    git(["add", "staged.py"], repo);
    write(repo, "staged-then-reverted.py", "new\n");
    git(["add", "staged-then-reverted.py"], repo);
    write(repo, "staged-then-reverted.py", "old\n");
    fs.rmSync(path.join(repo, "deleted.py"));
    git(["mv", "rename-from.py", "rename-to.py"], repo);
    write(repo, "untracked.py", "new\n");
    write(repo, "ignored.py", "ignored\n");
    write(repo, "build/out.py", "ignored\n");
    write(repo, "name with space.py", "space changed\n");
    write(repo, "café-文件.py", "unicode changed\n");

    const result = await listChangedFiles(repo, "HEAD");
    expect(result.files).toEqual(
      [
        "modified.py",
        "staged.py",
        "rename-to.py",
        "untracked.py",
        "name with space.py",
        "café-文件.py",
      ].sort(),
    );
    expect(result.directories).toEqual([]);
  });

  it("compares with an older commit and with a subdirectory as the audit root", async () => {
    const repo = makeRepo("older", { "pkg/a.py": "1\n", "pkg/b.py": "1\n", "top.py": "1\n" });
    write(repo, "pkg/a.py", "2\n");
    write(repo, "top.py", "2\n");
    git(["commit", "-qam", "second"], repo);
    expect((await listChangedFiles(repo, "HEAD")).files).toEqual([]);
    expect((await listChangedFiles(repo, "HEAD~1")).files).toEqual(["pkg/a.py", "top.py"]);
    // The audit root is a directory inside the repository.
    write(repo, "pkg/new.py", "n\n");
    expect((await listChangedFiles(path.join(repo, "pkg"), "HEAD~1")).files).toEqual([
      "a.py",
      "new.py",
    ]);
  });

  it("counts a file as changed when only line endings differ (fail open)", async () => {
    const repo = makeRepo("crlf", { "a.txt": "one\ntwo\n", "b.txt": "one\ntwo\n" });
    git(["config", "core.autocrlf", "true"], repo);
    // What a checkout with autocrlf writes: CRLF in the working tree, LF in
    // the blob. git itself reports no change for this file.
    write(repo, "a.txt", "one\r\ntwo\r\n");
    git(["add", "a.txt"], repo);
    expect(git(["diff", "--name-only", "HEAD"], repo).trim()).toBe("");
    const result = await listChangedFiles(repo, "HEAD");
    expect(result.files).toEqual(["a.txt"]);
  });

  it("treats an executable-bit change and a symlink change as changes", async () => {
    const repo = makeRepo("modes", { "run.sh": "#!/bin/sh\n", "plain.txt": "x\n", "target.txt": "t\n" });
    fs.symlinkSync("target.txt", path.join(repo, "link"));
    git(["add", "-A"], repo);
    git(["commit", "-qm", "link"], repo);
    expect((await listChangedFiles(repo, "HEAD")).files).toEqual([]);
    fs.chmodSync(path.join(repo, "run.sh"), 0o755);
    fs.rmSync(path.join(repo, "link"));
    fs.symlinkSync("plain.txt", path.join(repo, "link"));
    const result = await listChangedFiles(repo, "HEAD");
    expect(result.files).toContain("run.sh");
    expect(result.files.length).toBe(2);
  });

  it("puts every file of a submodule and of a nested repository in scope", async () => {
    const repo = makeRepo("with-submodule", { "main.py": "main\n" });
    const sub = path.join(repo, "sub");
    fs.mkdirSync(sub);
    git(["init", "-q"], sub);
    write(sub, "inner.py", 'password = "hunter2hunter2hunter2"\nimport os\nos.system(cmd)\n');
    git(["add", "-A"], sub);
    git(["commit", "-qm", "inner"], sub);
    git(["add", "sub"], repo); // recorded as a gitlink (mode 160000)
    git(["commit", "-qm", "add submodule"], repo);
    expect(git(["ls-tree", "HEAD", "sub"], repo)).toMatch(/^160000 commit/);
    // A second, untracked nested repository.
    const nested = path.join(repo, "nested");
    fs.mkdirSync(nested);
    git(["init", "-q"], nested);
    write(nested, "n.py", "n\n");
    git(["add", "-A"], nested);
    git(["commit", "-qm", "n"], nested);

    const result = await listChangedFiles(repo, "HEAD");
    expect(result.files).toEqual([]);
    expect(result.directories).toEqual(["nested", "sub"]);
    expect(result.warnings.join("\n")).toMatch(/sub\/ is a submodule or nested repository/);

    // In a scan: findings inside the submodule are in scope, the unchanged
    // file of the outer repository is not.
    write(repo, "main.py", "main\n");
    const scan = await scanProject({
      root: repo,
      out: path.join(temp, "out-submodule"),
      offline: true,
      engines: ["builtin"],
      since: "HEAD",
      formats: ["json"],
      includePlaceholders: true,
    });
    const files = new Set([...scan.findings, ...scan.hotspots].map((finding) => finding.file));
    expect(files.has("sub/inner.py")).toBe(true);
    expect(scan.warnings.join("\n")).toMatch(/submodule or nested repository/);
  });

  it("works in a sha256 repository", async () => {
    const probe = spawnSync("git", ["init", "-q", "--object-format=sha256", path.join(temp, "sha256-probe")], {
      env: GIT_TEST_ENV,
    });
    if (probe.status !== 0) return; // git without sha256 support
    const repo = makeRepo("sha256", { "a.py": "a\n", "b.py": "b\n" }, ["--object-format=sha256"]);
    expect(git(["rev-parse", "--show-object-format"], repo).trim()).toBe("sha256");
    write(repo, "a.py", "changed\n");
    expect((await listChangedFiles(repo, "HEAD")).files).toEqual(["a.py"]);
  });

  it("handles a 10,000-file repository in a few seconds", async () => {
    const repo = path.join(temp, "big");
    fs.mkdirSync(repo, { recursive: true });
    git(["init", "-q"], repo);
    for (let dir = 0; dir < 100; dir += 1) {
      const directory = path.join(repo, `d${dir}`);
      fs.mkdirSync(directory);
      for (let file = 0; file < 100; file += 1) {
        fs.writeFileSync(path.join(directory, `f${file}.py`), `x = ${dir * 100 + file}\n`);
      }
    }
    git(["add", "-A"], repo);
    git(["commit", "-qm", "big"], repo);
    write(repo, "d7/f7.py", "x = 'changed'\n");
    write(repo, "d99/new.py", "x = 'new'\n");
    const started = performance.now();
    const result = await listChangedFiles(repo, "HEAD");
    const elapsed = performance.now() - started;
    expect(result.files).toEqual(["d7/f7.py", "d99/new.py"]);
    process.stderr.write(`[since] 10,000-file repository: ${Math.round(elapsed)} ms\n`);
    expect(elapsed).toBeLessThan(15_000);
  }, 120_000);
});
