import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
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
 * `diff.external`, `core.pager`, a hooks path or a `filter.<name>.*` driver at
 * arbitrary programs. These command-line overrides win over the repository
 * config, and - because content filters cannot be switched off by a wildcard -
 * no git command that reads, hashes or converts working-tree content is ever
 * run (see `listChangedFiles`), so no target code is executed (rule D8).
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
  "core.attributesFile=/dev/null",
  "-c",
  "protocol.allow=never",
  "--no-pager",
  "--no-optional-locks",
] as const;

/** Environment hardening for git only. */
const GIT_ENV: Record<string, string> = {
  GIT_CONFIG_NOSYSTEM: "1",
  // No ~/.gitconfig or XDG config either: only the repository config (which
  // the flags above override) and the command line remain.
  GIT_CONFIG_GLOBAL: os.devNull,
  GIT_ATTR_NOSYSTEM: "1",
  GIT_TERMINAL_PROMPT: "0",
  GIT_OPTIONAL_LOCKS: "0",
};

/**
 * The only git subcommands this module may run. None of them reads the content
 * of a working-tree file, so clean/smudge/process filters, textconv, external
 * diff, EOL conversion and hooks have nothing to run on.
 */
const ALLOWED_GIT_COMMANDS = new Set(["rev-parse", "ls-tree", "ls-files"]);

/** Output cap of the listing commands (one line per file of the repository). */
const LISTING_MAX_OUTPUT_BYTES = 256 * 1024 * 1024;

/** A working file larger than this is not hashed: it counts as changed. */
const MAX_HASHED_FILE_BYTES = 64 * 1024 * 1024;

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
  maxOutputBytes?: number,
) {
  if (!ALLOWED_GIT_COMMANDS.has(args[0] ?? "")) {
    throw new GitScopeError(`internal error: git ${String(args[0])} is not an allowed command`);
  }
  return runTool("git", gitArgs(root, args), {
    timeoutMs: options.timeoutMs,
    maxOutputBytes: options.maxOutputBytes ?? maxOutputBytes,
    env: {
      ...GIT_ENV,
      ...(options.pathEnv ? { PATH: options.pathEnv } : {}),
    },
  });
}

/** NUL-separated records, verbatim (file names may start or end with a space). */
function splitNul(output: string): string[] {
  return output.split("\0").filter((entry) => entry.length > 0);
}

function checked(
  result: Awaited<ReturnType<typeof runGit>>,
  name: string,
): string {
  if (result.timedOut) throw new GitScopeError(`git ${name} timed out`);
  if (result.truncated) {
    throw new GitScopeError(`git ${name} output exceeded the size limit`);
  }
  if (result.exitCode !== 0) {
    throw new GitScopeError(
      `git ${name} failed: ${result.stderr.trim() || `exit code ${result.exitCode}`}`,
    );
  }
  return result.stdout;
}

export interface ChangedFilesResult {
  ref: string;
  files: string[];
  /**
   * Directories (project-relative POSIX paths) whose content git does not
   * track file by file - submodules and nested repositories. They cannot be
   * compared without running git inside them, so every file below them is in
   * scope.
   */
  directories: string[];
  warnings: string[];
}

type ObjectFormat = "sha1" | "sha256";

interface TreeEntry {
  mode: string;
  oid: string;
}

/**
 * The git blob id of a working file, computed here: `hash("blob <size>\0" +
 * bytes)`. git is never asked to hash a working file, because that is where
 * it would run the repository's clean filter.
 */
function blobIdOfFile(absolute: string, size: number, format: ObjectFormat): string | undefined {
  const hash = createHash(format);
  hash.update(`blob ${size}\0`);
  let fd: number;
  try {
    fd = fs.openSync(absolute, "r");
  } catch {
    return undefined;
  }
  try {
    const buffer = Buffer.allocUnsafe(Math.min(1024 * 1024, Math.max(size, 1)));
    let total = 0;
    for (;;) {
      const read = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (read <= 0) break;
      total += read;
      hash.update(buffer.subarray(0, read));
    }
    // The file changed size while it was read: the header is wrong, and so is
    // the id. No id means "changed".
    if (total !== size) return undefined;
  } catch {
    return undefined;
  } finally {
    fs.closeSync(fd);
  }
  return hash.digest("hex");
}

function blobIdOfBytes(bytes: Buffer, format: ObjectFormat): string {
  const hash = createHash(format);
  hash.update(`blob ${bytes.length}\0`);
  hash.update(bytes);
  return hash.digest("hex");
}

/** Parse `git ls-tree -r -z --full-tree`: `<mode> <type> <oid>\t<path>`. */
function parseTree(output: string, prefix: string): Map<string, TreeEntry> {
  const tree = new Map<string, TreeEntry>();
  for (const record of splitNul(output)) {
    const tab = record.indexOf("\t");
    if (tab < 0) continue;
    const [mode, , oid] = record.slice(0, tab).split(" ");
    let file = record.slice(tab + 1);
    if (!mode || !oid) continue;
    if (prefix) {
      if (!file.startsWith(prefix)) continue;
      file = file.slice(prefix.length);
    }
    tree.set(file, { mode, oid: oid.toLowerCase() });
  }
  return tree;
}

/**
 * The path jail for a long list of paths from git. Same rule as
 * `resolveInside` - the canonical path, symbolic links followed, must stay
 * inside the audit root - with the canonical path of each parent directory
 * resolved once instead of once per file.
 */
class ListingJail {
  private readonly parents = new Map<string, string>();

  constructor(private readonly root: string) {}

  /** Project-relative POSIX path of `entry`; throws when it leaves the root. */
  relative(entry: string): string {
    const trimmed = entry.replace(/\/+$/, "");
    const segments = trimmed.split("/");
    if (
      trimmed === "" ||
      path.isAbsolute(trimmed) ||
      /^[A-Za-z]:/.test(trimmed) ||
      segments.some((segment) => segment === ".." || segment === "." || segment === "")
    ) {
      // Not a path git lists for a healthy repository: the full check decides.
      return toPosixRelative(this.root, resolveInside(this.root, entry));
    }
    const parentRel = segments.slice(0, -1).join("/");
    let parentReal = this.parents.get(parentRel);
    if (parentReal === undefined) {
      parentReal = parentRel === "" ? this.root : resolveInside(this.root, parentRel);
      this.parents.set(parentRel, parentReal);
    }
    const leaf = path.join(parentReal, segments[segments.length - 1] as string);
    let isLink = false;
    try {
      isLink = fs.lstatSync(leaf).isSymbolicLink();
    } catch {
      // missing: nothing to follow
    }
    // A symbolic link must lead to something inside the root; the path that
    // is reported is the link itself.
    if (isLink) resolveInside(this.root, leaf);
    return toPosixRelative(this.root, leaf);
  }
}

/**
 * List the files that differ between `<ref>` and the working tree: committed,
 * staged, unstaged and untracked-but-not-ignored files.
 *
 * git is never asked to look at the content of a working file. A `git diff`
 * or `git status` against the working tree runs the `filter.<name>.clean` /
 * `process` program that the repository's own `.gitattributes` and
 * `.git/config` name, and filters cannot be disabled by a wildcard. Instead:
 *
 * 1. `git ls-tree -r -z --full-tree <ref>` gives path, mode and blob id of
 *    every file of the ref (object database only);
 * 2. `git ls-files -z --cached` and `git ls-files -z --others
 *    --exclude-standard` give the tracked and the untracked, not ignored
 *    paths (index and directory listing only; nothing is hashed);
 * 3. the blob id of every such working file is computed in this process and
 *    compared with the tree.
 *
 * A file whose id differs is CHANGED - also when the only difference is one a
 * filter or line-ending conversion would have removed (fail open: more files
 * in scope, never fewer). Files that are new count as changed, files that no
 * longer exist are left out, and an executable-bit change counts as a change.
 * A submodule or nested repository is reported in `directories`: all of its
 * files are in scope.
 *
 * Returns project-relative POSIX paths. Every path is passed through the path
 * jail; paths that escape the audit root are dropped with a warning. Throws
 * `GitScopeError` when the target is not a git repository, git is missing, the
 * ref is unknown, a git invocation fails, times out or produces truncated
 * output. Never falls back to a full scan.
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
      const detail = inside.stderr.trim().split("\n")[0] ?? "";
      // Ownership refusals ("dubious ownership") are worth showing: the user
      // configuration that would allow the directory is deliberately not read.
      if (/dubious ownership|safe\.directory/i.test(inside.stderr)) {
        throw new GitScopeError(
          `--since: git refuses ${root} (${detail}). code-audit runs git without the user and system configuration, so a safe.directory entry there does not apply; run the scan as the owner of the repository`,
        );
      }
      throw notAGitRepository(root);
    }
    throw new GitScopeError(`unknown git ref: ${ref}`);
  }

  // Object format (sha1 / sha256) and the position of the audit root inside
  // the repository (empty when the root is the top level).
  const layout = checked(
    await runGit(root, ["rev-parse", "--show-object-format", "--show-prefix"], options),
    "rev-parse",
  ).split("\n");
  const format: ObjectFormat = (layout[0] ?? "").trim() === "sha256" ? "sha256" : "sha1";
  const prefix = (layout[1] ?? "").replace(/\r$/, "");

  const [treeResult, cachedResult, untrackedResult] = await Promise.all([
    runGit(root, ["ls-tree", "-r", "-z", "--full-tree", ref], options, LISTING_MAX_OUTPUT_BYTES),
    runGit(root, ["ls-files", "-z", "--cached"], options, LISTING_MAX_OUTPUT_BYTES),
    runGit(
      root,
      ["ls-files", "-z", "--others", "--exclude-standard"],
      options,
      LISTING_MAX_OUTPUT_BYTES,
    ),
  ]);
  const tree = parseTree(checked(treeResult, "ls-tree"), prefix);
  const tracked = splitNul(checked(cachedResult, "ls-files"));
  const untracked = splitNul(checked(untrackedResult, "ls-files"));

  const outputDir = options.outputDir ? canonicalDir(options.outputDir) : undefined;
  const candidates = new Map<string, boolean>();
  // A file of the ref that is neither in the index nor untracked (removed
  // from the index and ignored) is still compared when it exists.
  for (const entry of tree.keys()) candidates.set(entry, false);
  for (const entry of tracked) candidates.set(entry, false);
  for (const entry of untracked) if (!candidates.has(entry)) candidates.set(entry, true);

  const files = new Set<string>();
  const directories = new Set<string>();
  const warnings = new Set<string>();
  const jail = new ListingJail(root);
  for (const [rawEntry, isUntracked] of candidates) {
    const entry = rawEntry.split("\\").join("/");
    const asDirectory = entry.endsWith("/");
    // Path jail: git output is untrusted. Drop anything that escapes the root.
    let relative: string;
    try {
      relative = jail.relative(entry);
    } catch {
      warnings.add("ignored path outside audit root reported by git");
      continue;
    }
    if (relative === "") continue;
    // The tool's own output and control files are not changes of the project.
    if (isOwnOutputFile(root, relative, { untracked: isUntracked, outputDir })) continue;

    // The entry itself, not what a symbolic link points at.
    const direct = path.join(root, ...entry.replace(/\/+$/, "").split("/"));
    let stat: fs.Stats;
    try {
      stat = fs.lstatSync(direct);
    } catch {
      continue; // deleted (or never checked out): not in scope
    }
    const inTree = tree.get(rawEntry);

    if (stat.isDirectory()) {
      // A submodule (mode 160000) or a nested repository (`dir/` in the list
      // of untracked files). Its files are not compared one by one.
      if (inTree?.mode === "160000" || asDirectory || !inTree) {
        directories.add(relative);
        warnings.add(
          `--since: ${relative}/ is a submodule or nested repository; its files are not compared with ${ref} and are all in scope`,
        );
      }
      continue;
    }
    if (!inTree || isUntracked) {
      files.add(relative);
      continue;
    }
    if (stat.isSymbolicLink()) {
      let target: string;
      try {
        target = fs.readlinkSync(direct);
      } catch {
        files.add(relative);
        continue;
      }
      if (inTree.mode !== "120000" || blobIdOfBytes(Buffer.from(target, "utf8"), format) !== inTree.oid) {
        files.add(relative);
      }
      continue;
    }
    if (!stat.isFile() || inTree.mode === "120000" || inTree.mode === "160000") {
      files.add(relative);
      continue;
    }
    if (process.platform !== "win32") {
      const executable = (stat.mode & 0o111) !== 0;
      if (executable !== (inTree.mode === "100755")) {
        files.add(relative);
        continue;
      }
    }
    if (stat.size > MAX_HASHED_FILE_BYTES) {
      files.add(relative);
      continue;
    }
    if (blobIdOfFile(direct, stat.size, format) !== inTree.oid) files.add(relative);
  }

  return {
    ref,
    files: [...files].sort(),
    directories: [...directories].sort(),
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
/**
 * The hardening flags every git invocation of this package starts with (see
 * `GIT_HARDENING_ARGS`), for other modules that run git themselves (the
 * history scan). A copy: callers cannot change the shared list.
 */
export function gitHardeningArgs(): string[] {
  return [...GIT_HARDENING_ARGS];
}

/** The environment hardening of every git invocation (see `GIT_ENV`). A copy. */
export function gitHardenedEnv(): Record<string, string> {
  return { ...GIT_ENV };
}
