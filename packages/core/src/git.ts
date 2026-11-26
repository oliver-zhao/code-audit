import fs from "node:fs";
import path from "node:path";
import { runTool } from "./external/run.js";
import { BASELINE_FILE_NAME, IGNORE_FILE_NAME } from "./ignore.js";
import { LATEST_OUTPUT_FILES, RUN_OUTPUT_FILES } from "./meta.js";
import { resolveInside, toPosixRelative, validateAuditRoot } from "./pathJail.js";

export class GitScopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GitScopeError";
  }
}

/**
 * Reject a git ref before it reaches the command line. A ref that starts with
 * `-`, is empty, or contains whitespace or control characters is refused so it
 * can never be interpreted as a flag or inject arguments.
 */
export function assertSafeRef(ref: string): string {
  const value = ref.trim();
  if (!value) {
    throw new GitScopeError("--since requires a non-empty git ref");
  }
  if (value.startsWith("-")) {
    throw new GitScopeError(`refusing a git ref that starts with '-': ${ref}`);
  }
  if (/[\s\u0000-\u001f\u007f]/.test(value)) {
    throw new GitScopeError(
      `refusing a git ref with whitespace or control characters: ${ref}`,
    );
  }
  return value;
}

function notAGitRepository(root: string): GitScopeError {
  return new GitScopeError(
    `--since requires a git repository: ${root} is not one (or git is unavailable)`,
  );
}

/**
 * Hardening options passed to *every* git invocation. The audited repository is
 * untrusted: its `.git/config` can point `core.fsmonitor`, `core.sshCommand`,
 * `diff.external`, `core.pager` or a hooks path at arbitrary programs. These
 * command-line overrides win over the repository config and make sure no target
 * code is ever executed (rule D8).
 */
const GIT_HARDENING_ARGS = [
  "-c",
  "core.fsmonitor=false",
  "-c",
  "core.hooksPath=/dev/null",
  "-c",
  "core.pager=cat",
  "-c",
  "diff.external=",
  "-c",
  "core.untrackedCache=false",
  "-c",
  "protocol.allow=never",
  "--no-pager",
  "--no-optional-locks",
] as const;

/** Environment hardening for git only. */
const GIT_ENV: Record<string, string> = {
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_TERMINAL_PROMPT: "0",
  GIT_OPTIONAL_LOCKS: "0",
};

export interface ListChangedFilesOptions {
  /** Override PATH used to locate git (testing). */
  pathEnv?: string;
  /** Timeout for each git invocation (testing). */
  timeoutMs?: number;
  /** Output cap for each git invocation (testing). */
  maxOutputBytes?: number;
  /**
   * Directory the scan writes its run directories to (`--out`, absolute).
   * When it is inside the audit root, the files the tool itself wrote there
   * are not counted as changed. See `isOwnOutputFile`.
   */
  outputDir?: string;
}

/**
 * True for a file that code-audit itself wrote or reads as configuration, so
 * that it must not count as a change of the audited project:
 *
 * - anything under `<root>/.audit/` or `<root>/.code-audit/` (never audited:
 *   those directories are excluded from the inventory);
 * - `<root>/.code-audit-baseline.json` and `<root>/.code-audit-ignore` (never
 *   audited: control files);
 * - when `--out` points inside the root: the known output files of a run
 *   directory `<out>/<run>/` (one that holds a `run.json` or `state.json`) and
 *   of `<out>/latest/`, and only when git reports them as UNTRACKED.
 *
 * The last rule is deliberately narrow. A directory named like the output
 * directory can also hold files of the audited repository; those are tracked
 * by git, or have other names, and stay in scope.
 */
export function isOwnOutputFile(
  root: string,
  relPath: string,
  options: { untracked: boolean; outputDir?: string },
): boolean {
  const normalized = relPath.split("\\").join("/");
  if (normalized === BASELINE_FILE_NAME || normalized === IGNORE_FILE_NAME) return true;
  if (normalized.startsWith(".audit/") || normalized.startsWith(".code-audit/")) return true;
  if (!options.untracked || !options.outputDir) return false;
  const outRel = path.relative(root, options.outputDir).split(path.sep).join("/");
  if (!outRel || outRel.startsWith("..") || path.isAbsolute(outRel)) return false;
  if (!normalized.startsWith(`${outRel}/`)) return false;
  const rest = normalized.slice(outRel.length + 1).split("/");
  if (rest.length !== 2) return false;
  const [runName, fileName] = rest as [string, string];
  if (runName === "latest") return LATEST_OUTPUT_FILES.has(fileName);
  if (!RUN_OUTPUT_FILES.has(fileName)) return false;
  const runDir = path.join(options.outputDir, runName);
  return (
    fs.existsSync(path.join(runDir, "run.json")) || fs.existsSync(path.join(runDir, "state.json"))
  );
}

function gitArgs(root: string, args: readonly string[]): string[] {
  return ["-C", root, ...GIT_HARDENING_ARGS, ...args];
}

function runGit(
  root: string,
  args: readonly string[],
  options: ListChangedFilesOptions,
) {
  return runTool("git", gitArgs(root, args), {
    timeoutMs: options.timeoutMs,
    maxOutputBytes: options.maxOutputBytes,
    env: {
      ...GIT_ENV,
      ...(options.pathEnv ? { PATH: options.pathEnv } : {}),
    },
  });
}

function splitNul(output: string): string[] {
  return output
    .split("\0")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

export interface ChangedFilesResult {
  ref: string;
  files: string[];
  warnings: string[];
}

/**
 * List the files changed between `<ref>` and the working tree: committed,
 * staged, unstaged and untracked-but-not-ignored files.
 *
 * Returns project-relative POSIX paths. Every path is passed through the path
 * jail; paths that escape the audit root are dropped with a warning. Throws
 * `GitScopeError` when the target is not a git repository, git is missing, the
 * ref is unknown, a git invocation times out or produces truncated output.
 * Never falls back to a full scan.
 */
export async function listChangedFiles(
  rootInput: string,
  refInput: string,
  options: ListChangedFilesOptions = {},
): Promise<ChangedFilesResult> {
  const ref = assertSafeRef(refInput);
  // Work on the canonical real root. resolveInside() returns real paths, so
  // making them relative to a root reached through a symlinked parent (macOS:
  // /var -> /private/var, /tmp -> /private/tmp) would yield "../.." paths.
  const root = validateAuditRoot(rootInput).root;

  // Confirm the directory is a git repository and the ref resolves.
  const verify = await runGit(
    root,
    ["rev-parse", "--verify", "--quiet", `${ref}^{commit}`],
    options,
  );
  if (verify.timedOut) {
    throw new GitScopeError("git rev-parse timed out");
  }
  if (verify.truncated) {
    throw new GitScopeError("git rev-parse output exceeded the size limit");
  }
  if (verify.exitCode !== 0) {
    // Distinguish "not a repository" from "unknown ref".
    const inside = await runGit(
      root,
      ["rev-parse", "--is-inside-work-tree"],
      options,
    );
    if (inside.timedOut) {
      throw new GitScopeError("git rev-parse timed out");
    }
    if (inside.exitCode !== 0) {
      throw notAGitRepository(root);
    }
    throw new GitScopeError(`unknown git ref: ${ref}`);
  }

  const [committed, untracked] = await Promise.all([
    runGit(
      root,
      [
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--name-only",
        "-z",
        "--diff-filter=ACMR",
        ref,
        "--",
      ],
      options,
    ),
    runGit(
      root,
      ["ls-files", "-z", "--others", "--exclude-standard"],
      options,
    ),
  ]);

  if (committed.timedOut) {
    throw new GitScopeError("git diff timed out");
  }
  if (committed.truncated) {
    throw new GitScopeError("git diff output exceeded the size limit");
  }
  if (committed.exitCode !== 0) {
    throw new GitScopeError(
      `git diff failed: ${committed.stderr.trim() || `exit code ${committed.exitCode}`}`,
    );
  }
  if (untracked.timedOut) {
    throw new GitScopeError("git ls-files timed out");
  }
  if (untracked.truncated) {
    throw new GitScopeError("git ls-files output exceeded the size limit");
  }
  if (untracked.exitCode !== 0) {
    throw new GitScopeError(
      `git ls-files failed: ${untracked.stderr.trim() || `exit code ${untracked.exitCode}`}`,
    );
  }

  const outputDir = options.outputDir ? canonicalDir(options.outputDir) : undefined;
  const rawFiles = [
    ...splitNul(committed.stdout).map((entry) => ({ entry, untracked: false })),
    ...splitNul(untracked.stdout).map((entry) => ({ entry, untracked: true })),
  ].map((item) => ({ ...item, entry: item.entry.split("\\").join("/") }));

  // Path jail: git output is untrusted. Drop anything that escapes the root.
  const files: string[] = [];
  const warnings = new Set<string>();
  for (const { entry, untracked: isUntracked } of rawFiles) {
    let relative: string;
    try {
      const resolved = resolveInside(root, entry);
      relative = toPosixRelative(root, resolved);
    } catch {
      warnings.add("ignored path outside audit root reported by git");
      continue;
    }
    // The tool's own output and control files are not changes of the project.
    if (isOwnOutputFile(root, relative, { untracked: isUntracked, outputDir })) continue;
    files.push(relative);
  }

  return {
    ref,
    files: [...new Set(files)].sort(),
    warnings: [...warnings],
  };
}

/** Real path of a directory, or the resolved path when it does not exist. */
function canonicalDir(dir: string): string {
  try {
    return fs.realpathSync(dir);
  } catch {
    return path.resolve(dir);
  }
}

/**
 * Resolve a run id or run directory to a baseline file path is handled by the
 * caller; this helper only checks whether a directory looks like a git repo,
 * used by tests.
 */
export function isGitRepository(root: string): boolean {
  return fs.existsSync(path.join(root, ".git"));
}