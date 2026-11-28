/**
 * Secret scan of the git history (`scan --history`), with Gitleaks.
 *
 * Gitleaks' git mode runs `git log -p` in the repository it is given. The
 * audited repository is untrusted: its `.git/config` can name programs
 * (`core.fsmonitor`, `filter.<name>.*`, `diff.<name>.textconv`, a hooks
 * path, an `ext::` promisor remote, ...), it may hide refs from a fetch, and
 * replace refs can swap a commit for another. So Gitleaks never sees the
 * audited repository. Instead:
 *
 * 1. `git rev-parse` finds the top level of the repository and resolves the
 *    refs of the range to commit ids;
 * 2. `git clone --mirror --no-local` copies every ref and object into a
 *    private temporary directory through git's own transport. The new
 *    repository's configuration is written by git and holds none of the
 *    original's drivers, hooks or attributes files; `--template=` leaves out
 *    the hook templates as well. `--no-local` makes git read objects through
 *    `upload-pack` instead of copying (or hard-linking) the object directory,
 *    which a symbolic link inside `.git/objects` could otherwise point
 *    anywhere. Replace refs and grafts are removed from the copy;
 * 3. Gitleaks scans that copy, with the user and system git configuration
 *    switched off and hardening options passed through `GIT_CONFIG_COUNT`.
 *    It runs without `--redact`: its report, inside the private temporary
 *    directory, carries each secret, which is read into memory to recognise
 *    the same secret again (deduplication, the placeholder check,
 *    `stillPresent`) and the report is deleted right after it is read. The
 *    value never goes anywhere else.
 *
 * Every git process started here (in the audited repository, for the clone,
 * in the copy, and the one Gitleaks starts) runs with no lazy fetch, no
 * replace objects and every transport protocol refused - except the file
 * transport of the clone itself. The temporary directory is removed when the
 * scan ends, also on error, timeout, SIGINT, SIGTERM, SIGHUP and exit.
 */
import { createHash, scrypt } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  ADJUSTMENT_PLACEHOLDER,
  createFinding,
  lowerConfidence,
  type Finding,
} from "../finding.js";
import { GitScopeError, gitHardenedEnv, gitHardeningArgs } from "../git.js";
import { PathJailError, resolveInside } from "../pathJail.js";
import { redactText, scrubValues } from "../redact.js";
import { redactSecret } from "../secrets.js";
import { gitleaksRuleConfidence, isGitleaksPlaceholder, secretHash } from "./gitleaks.js";
import { registerCleanup, type CleanupHandle } from "./cleanup.js";
import { runTool, type RunToolResult } from "./run.js";

/** Invalid `--history` value (CLI argument or MCP parameter). */
export class HistoryOptionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HistoryOptionError";
  }
}

/** Engine name of history results (`provenance.engine`, coverage). */
export const HISTORY_ENGINE = "gitleaks-history";

/** Default `--max-count` of the history scan. */
export const DEFAULT_HISTORY_MAX_COMMITS = 10_000;

/** Wall-clock limit of the whole history scan (clone, Gitleaks, processing). */
export const DEFAULT_HISTORY_TIMEOUT_MS = 5 * 60 * 1000;

/** Results of one report that are processed; the rest are dropped (partial). */
export const MAX_HISTORY_RESULTS = 5000;

/** A Gitleaks report larger than this is not parsed (partial). */
const MAX_REPORT_BYTES = 64 * 1024 * 1024;

/** A working-tree file larger than this is not searched for the value. */
const MAX_WORKING_FILE_BYTES = 5 * 1024 * 1024;

/** Longest accepted `--history` range. */
const MAX_RANGE_LENGTH = 512;

/**
 * scrypt parameters of the history fingerprint (see `historyFingerprint`):
 * about 0.7 ms of CPU per secret and 512 KiB of memory, roughly 2000 times
 * the cost of one SHA-256, so 5000 results take under 5 s of CPU.
 */
export const HISTORY_FINGERPRINT_SCRYPT = { N: 1 << 9, r: 8, p: 1 } as const;

export const HISTORY_REMEDIATION =
  "Rotate this credential (revoke it and issue a new one): it is in the git history, and deleting the file or rewriting the history is not enough, because existing clones, forks, caches and CI logs keep the old commits. After rotating, remove it from the current code if it is still there.";

export const HISTORY_REMEDIATION_ZH =
  "必须轮换该凭据（吊销并重新签发）：它存在于 git 历史中，仅删除文件或改写历史并不够，因为已有的克隆、分叉、缓存和 CI 日志仍保留旧提交。轮换之后，如果当前代码中仍有它，再将其移除。";

export const HISTORY_MESSAGE_ZH =
  "Gitleaks 在 git 历史中发现了凭据；所有输出中该值都已脱敏。";

/** Appended to the remediation of a current finding that is also in the history. */
export const HISTORY_ROTATE_NOTE =
  "This secret is also in the git history: rotate it; deleting the file or rewriting the history is not enough.";

export const HISTORY_ROTATE_NOTE_ZH =
  "该密钥也存在于 git 历史中：必须轮换，仅删除文件或改写历史并不够。";

/** A current finding with `history` attached, and the rotate sentence once. */
export function withHistoryNote(
  finding: Finding,
  history: { commit: string; date: string; occurrences: number },
): Finding {
  const remediation = finding.remediation.includes(HISTORY_ROTATE_NOTE)
    ? finding.remediation
    : `${finding.remediation} ${HISTORY_ROTATE_NOTE}`;
  return { ...finding, remediation, history: { ...history, stillPresent: true } };
}

/** A ref name of a `--history` range: `[A-Za-z0-9._/-]`, git's rules on top. */
const REF_CHARS = /^[A-Za-z0-9._/-]+$/;

function checkRef(ref: string, whole: string): void {
  const reject = (why: string): never => {
    throw new HistoryOptionError(`--history: refusing the range ${JSON.stringify(whole)}: ${why}`);
  };
  if (ref.length === 0) reject("a ref is empty");
  if (ref.startsWith("-")) reject("a ref starts with '-'");
  if (!REF_CHARS.test(ref)) reject("a ref may only contain letters, digits and . _ / -");
  if (
    ref.startsWith(".") ||
    ref.startsWith("/") ||
    ref.endsWith("/") ||
    ref.endsWith(".") ||
    ref.endsWith(".lock") ||
    ref.includes("..") ||
    ref.includes("//") ||
    ref.includes("/.")
  ) {
    reject("not a valid git ref name");
  }
}

function rangeSeparator(range: string): string | undefined {
  return range.includes("...") ? "..." : range.includes("..") ? ".." : undefined;
}

/**
 * Validate a `--history` revision range: `<ref>`, `<ref>..<ref>` or
 * `<ref>...<ref>`, where a ref is a branch, tag or commit id made of
 * `[A-Za-z0-9._/-]` that does not start with `-`. Returns the range.
 */
export function parseHistoryRange(value: string): string {
  if (typeof value !== "string") {
    throw new HistoryOptionError("--history: the range must be a string");
  }
  if (value.length === 0) throw new HistoryOptionError("--history: the range is empty");
  if (value.length > MAX_RANGE_LENGTH) {
    throw new HistoryOptionError("--history: the range is too long");
  }
  const separator = rangeSeparator(value);
  const parts = separator ? value.split(separator) : [value];
  if (parts.length > 2) {
    throw new HistoryOptionError(
      `--history: refusing the range ${JSON.stringify(value)}: use <ref>, <ref>..<ref> or <ref>...<ref>`,
    );
  }
  for (const part of parts) checkRef(part, value);
  return value;
}

/** Refs named by a validated range. */
export function historyRangeRefs(range: string): string[] {
  const separator = rangeSeparator(range);
  return separator ? range.split(separator) : [range];
}

/**
 * The `history` scan option (`--history[=<range>]`, MCP `history`):
 * undefined or false - no history scan; true - every reachable commit; a
 * string - that range (validated). Returns `{ range: null }` for all commits.
 */
export function parseHistoryOption(value: unknown): { range: string | null } | undefined {
  if (value === undefined || value === null || value === false) return undefined;
  if (value === true) return { range: null };
  if (typeof value === "string") return { range: parseHistoryRange(value) };
  throw new HistoryOptionError("--history must be true, false or a revision range");
}

/** `CODE_AUDIT_HISTORY_MAX_COMMITS`, else the default. */
export function historyMaxCommits(env: NodeJS.ProcessEnv = process.env): {
  value: number;
  warning?: string;
} {
  const raw = env.CODE_AUDIT_HISTORY_MAX_COMMITS;
  if (raw === undefined || raw.trim() === "") return { value: DEFAULT_HISTORY_MAX_COMMITS };
  const trimmed = raw.trim();
  const parsed = /^\d{1,9}$/.test(trimmed) ? Number(trimmed) : Number.NaN;
  if (!Number.isInteger(parsed) || parsed < 1) {
    return {
      value: DEFAULT_HISTORY_MAX_COMMITS,
      warning: `CODE_AUDIT_HISTORY_MAX_COMMITS is not a positive integer; using ${DEFAULT_HISTORY_MAX_COMMITS}`,
    };
  }
  return { value: parsed };
}

// ---------------------------------------------------------------------------
// git

/** Transport protocols refused for every git process of the history scan. */
const REFUSED_PROTOCOLS = ["ext", "fd", "file", "ssh", "git", "http", "https"] as const;

/**
 * Configuration that keeps git from fetching anything: `protocol.allow=never`
 * and the same for each protocol by name, because a `protocol.<name>.allow`
 * of the audited repository's own configuration is more specific than
 * `protocol.allow` and would otherwise win.
 */
const NO_FETCH_CONFIG: ReadonlyArray<readonly [string, string]> = [
  ["protocol.allow", "never"],
  ...REFUSED_PROTOCOLS.map((name) => [`protocol.${name}.allow`, "never"] as const),
];

const NO_FETCH_ARGS: readonly string[] = NO_FETCH_CONFIG.flatMap(([key, value]) => [
  "-c",
  `${key}=${value}`,
]);

/**
 * Environment of every git process here: the git.ts hardening, no lazy
 * fetch of missing objects of a partial clone (an `ext::` promisor remote
 * would run a command), no replace objects.
 */
function historyGitEnv(pathEnv?: string): Record<string, string> {
  return {
    ...gitHardenedEnv(),
    GIT_NO_LAZY_FETCH: "1",
    GIT_NO_REPLACE_OBJECTS: "1",
    ...(pathEnv ? { PATH: pathEnv } : {}),
  };
}

/**
 * Hardening options for the git that Gitleaks runs in the copy, passed as
 * `GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_n` / `GIT_CONFIG_VALUE_n` (command-line
 * level: they win over the copy's own configuration).
 */
const GITLEAKS_GIT_CONFIG: ReadonlyArray<readonly [string, string]> = [
  ["core.fsmonitor", "false"],
  ["core.hooksPath", os.devNull],
  ["core.pager", "cat"],
  ["core.attributesFile", os.devNull],
  ["diff.external", ""],
  ["log.showSignature", "false"],
  ...NO_FETCH_CONFIG,
];

/**
 * The `upload-pack` that serves the clone. git runs it for the source
 * repository, with the source's configuration and without the `-c` options
 * or `GIT_NO_LAZY_FETCH` / `GIT_NO_REPLACE_OBJECTS` of the clone (the local
 * transport clears them), so what it needs is part of the command: no lazy
 * fetch, no replace objects, no fsmonitor, no hooks, no transport, and no
 * hidden refs - `uploadpack.hideRefs` / `transfer.hideRefs` in the audited
 * repository could otherwise keep commits out of the scan. A later `!refs`
 * entry exposes every ref again. git runs this string through `sh`; it is a
 * constant.
 */
const UPLOAD_PACK_COMMAND = [
  "git",
  "--no-lazy-fetch",
  "--no-replace-objects",
  "-c core.fsmonitor=false",
  `-c core.hooksPath=${os.devNull}`,
  "-c uploadpack.hideRefs=!refs",
  "-c transfer.hideRefs=!refs",
  ...NO_FETCH_CONFIG.map(([key, value]) => `-c ${key}=${value}`),
  "upload-pack",
].join(" ");

const ALLOWED_GIT = new Set(["rev-parse", "clone", "rev-list", "cat-file", "for-each-ref", "update-ref"]);

interface GitRunOptions {
  pathEnv?: string;
  timeoutMs: number;
  maxOutputBytes?: number;
  cwd?: string;
  cleanup?: CleanupHandle;
}

function runHistoryGit(
  args: readonly string[],
  options: GitRunOptions,
  extraConfig: readonly string[] = [],
): Promise<RunToolResult> {
  // The subcommand follows `-C <dir>` when there is one.
  const command = args[0] === "-C" ? args[2] : args[0];
  if (!ALLOWED_GIT.has(command ?? "")) {
    throw new GitScopeError(`internal error: git ${String(command)} is not an allowed command`);
  }
  const lead = args[0] === "-C" ? args.slice(0, 2) : [];
  const rest = args[0] === "-C" ? args.slice(2) : args;
  return runTool(
    "git",
    [
      ...lead,
      "--no-lazy-fetch",
      "--no-replace-objects",
      ...gitHardeningArgs(),
      ...NO_FETCH_ARGS,
      ...extraConfig,
      ...rest,
    ],
    {
      cwd: options.cwd,
      timeoutMs: Math.max(1, options.timeoutMs),
      maxOutputBytes: options.maxOutputBytes,
      env: historyGitEnv(options.pathEnv),
      onSpawn: options.cleanup?.track,
      detached: true,
    },
  );
}

function gitFailure(result: RunToolResult, what: string): string {
  if (result.timedOut) return `${what} timed out`;
  const detail = result.stderr.trim().split("\n").filter(Boolean).slice(-1)[0] ?? "";
  return `${what} failed${detail ? `: ${detail.slice(0, 300)}` : ` (exit code ${result.exitCode})`}`;
}

export interface HistoryTarget {
  /** Top level of the repository (what is cloned). */
  topLevel: string;
  /** Position of the audit root in the repository (`""` or `dir/`). */
  prefix: string;
  /**
   * The range with every ref replaced by the commit id it names in the
   * audited repository; null for all refs. The copy is scanned with ids,
   * never with names.
   */
  resolvedRange: string | null;
  /** Commit ids of the range's refs. */
  commits: string[];
  /** The repository is shallow: commits before the boundary are missing. */
  shallow: boolean;
}

/** Why a shallow repository makes the history scan partial. */
export const SHALLOW_HISTORY_DETAIL =
  "the repository is a shallow clone: history before the shallow boundary was not scanned; fetch the full history (git fetch --unshallow, or fetch-depth: 0 in GitHub Actions) and scan again";

const COMMIT_ID = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;

/**
 * Locate the repository of `root` and resolve the refs of `range` to commit
 * ids. Runs only `git rev-parse` (no fetch, no replace objects). Throws
 * `GitScopeError` when `root` is not in a git work tree or a ref is unknown.
 */
export async function prepareHistoryTarget(
  root: string,
  range: string | null,
  options: { pathEnv?: string; timeoutMs?: number } = {},
): Promise<HistoryTarget> {
  const timeoutMs = options.timeoutMs ?? 30_000;
  const layout = await runHistoryGit(
    ["-C", root, "rev-parse", "--show-toplevel", "--show-prefix"],
    { pathEnv: options.pathEnv, timeoutMs },
  );
  if (layout.timedOut) throw new GitScopeError("--history: git rev-parse timed out");
  if (layout.exitCode !== 0) {
    if (/dubious ownership|safe\.directory/i.test(layout.stderr)) {
      throw new GitScopeError(
        `--history: git refuses ${root} (dubious ownership). code-audit runs git without the user and system configuration, so a safe.directory entry there does not apply; run the scan as the owner of the repository`,
      );
    }
    throw new GitScopeError(
      `--history requires a git work tree: ${root} is not in one (or git is unavailable)`,
    );
  }
  const [topLine, prefixLine] = layout.stdout.split("\n");
  const topLevel = (topLine ?? "").replace(/\r$/, "");
  const prefix = (prefixLine ?? "").replace(/\r$/, "");
  if (!topLevel || !path.isAbsolute(topLevel)) {
    throw new GitScopeError(`--history: git reported no top level for ${root}`);
  }
  // A shallow repository (a CI checkout with depth 1, or a `.git/shallow`
  // file written by hand) hides every commit before its boundary.
  const shallowCheck = await runHistoryGit(
    ["-C", root, "rev-parse", "--is-shallow-repository"],
    { pathEnv: options.pathEnv, timeoutMs },
  );
  if (shallowCheck.timedOut) throw new GitScopeError("--history: git rev-parse timed out");
  // Anything but a clear "false" counts as shallow (fail towards `partial`).
  const shallow = shallowCheck.exitCode !== 0 || shallowCheck.stdout.trim() !== "false";
  if (range === null) return { topLevel, prefix, resolvedRange: null, commits: [], shallow };
  const commits: string[] = [];
  for (const ref of historyRangeRefs(range)) {
    const verify = await runHistoryGit(
      ["-C", root, "rev-parse", "--verify", "--quiet", "--end-of-options", `${ref}^{commit}`],
      { pathEnv: options.pathEnv, timeoutMs },
    );
    if (verify.timedOut) throw new GitScopeError("--history: git rev-parse timed out");
    const id = verify.stdout.trim().toLowerCase();
    if (verify.exitCode !== 0 || !COMMIT_ID.test(id)) {
      throw new GitScopeError(`--history: unknown git ref: ${ref}`);
    }
    commits.push(id);
  }
  const separator = rangeSeparator(range);
  return {
    topLevel,
    prefix,
    resolvedRange: separator ? commits.join(separator) : (commits[0] as string),
    commits,
    shallow,
  };
}

// ---------------------------------------------------------------------------
// Gitleaks report

interface HistoryReportEntry {
  RuleID?: string;
  Description?: string;
  StartLine?: number;
  EndLine?: number;
  Match?: string;
  Secret?: string;
  File?: string;
  Commit?: string;
  Date?: string;
}

function reportEntries(document: unknown): HistoryReportEntry[] {
  if (Array.isArray(document)) {
    return document.filter(
      (entry): entry is HistoryReportEntry => Boolean(entry) && typeof entry === "object",
    );
  }
  return [];
}

/**
 * A repository path from the report, checked lexically (the file need not
 * exist any more): relative, no `.`/`..`/empty segment, no NUL.
 */
function safeRepoPath(file: string): string | undefined {
  if (!file || file.includes("\0") || file.startsWith("/") || /^[A-Za-z]:/.test(file)) {
    return undefined;
  }
  const segments = file.split("/");
  if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) {
    return undefined;
  }
  return file;
}

/** A date as an ISO-8601 string, or the empty string. */
function normalizedDate(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 64) return "";
  const time = Date.parse(value);
  return Number.isNaN(time) ? "" : new Date(time).toISOString();
}

/** The value Gitleaks reported, when the report carries it (not redacted). */
function secretOf(entry: HistoryReportEntry): string | undefined {
  const value = entry.Secret;
  if (typeof value !== "string" || value.length === 0 || value === "REDACTED") return undefined;
  return value;
}

/**
 * Evidence of a history result: the first line of what Gitleaks matched, with
 * every string literal masked and the secret masked wherever it (or one of
 * its lines) still appears.
 */
function historyEvidence(entry: HistoryReportEntry, file: string, secret: string | undefined): string {
  const match = typeof entry.Match === "string" ? entry.Match : "";
  if (!match) return "[redacted secret]";
  if (!secret) return redactSecret(match.split("\n")[0] ?? "");
  const firstLine = (match.split(/\r?\n/)[0] ?? "").trim();
  const clipped = firstLine.length > 400 ? `${firstLine.slice(0, 400)}...` : firstLine;
  const pieces = [secret, ...secret.split(/\r?\n/).map((line) => line.trim())].filter(
    (piece) => piece.length >= 4,
  );
  const masked = scrubValues(redactText(clipped, { file, maskAllStrings: true }), pieces);
  // Belt and braces: a secret of eight characters or more must not survive
  // in any form that still contains it whole.
  return pieces.some((piece) => piece.length >= 8 && masked.includes(piece))
    ? "[redacted secret]"
    : masked;
}

/** One history result; `identity` (the secret) is in memory only. */
interface ParsedResult {
  rule: string;
  description: string;
  file: string;
  commit: string;
  date: string;
  startLine: number;
  endLine: number;
  evidence: string;
  identity?: string;
  placeholder: boolean;
  /** Position in the report, for a stable order. */
  index: number;
}

/** A secret of the history, with the earliest commit it was added in. */
export interface HistoryCandidate {
  /** The finding to report when the current scan did not report the secret. */
  finding: Finding;
  /**
   * `gitleaks-<rule>\0<file>\0<sha256 of the secret>`: in memory only, to
   * recognise the same secret among the current Gitleaks results. Undefined
   * when the report did not carry the value.
   */
  matchKey?: string;
  history: { commit: string; date: string; occurrences: number };
  /** The file in the working tree still contains the value. */
  presentInWorkingTree: boolean;
  /** Lines (1-based) of the working-tree file where the value starts; at most 20. */
  workingLines: number[];
}

export interface HistoryScanResult {
  status: "ok" | "partial" | "failed";
  detail: string;
  range: string | null;
  /** Commits in the range (or reachable from any ref). */
  commits: number;
  /** Commits Gitleaks was asked to scan (`--max-count`). */
  maxCommits: number;
  /** Results in the Gitleaks report (before deduplication). */
  results: number;
  candidates: HistoryCandidate[];
  warnings: string[];
  timedOut: boolean;
}

/**
 * Fingerprint of a history finding: rule, file and the secret. The secret's
 * hash goes through scrypt (`HISTORY_FINGERPRINT_SCRYPT`) first, so that the
 * fingerprint (which is written to reports and baselines) cannot be used to
 * test guesses of a short password at the speed of SHA-256.
 */
export async function historyFingerprint(
  ruleId: string,
  file: string,
  secretSha256: string,
): Promise<string> {
  const stretched = await new Promise<string>((resolve, reject) => {
    scrypt(
      secretSha256,
      `code-audit-history-v2\0${ruleId}\0${file}`,
      32,
      { ...HISTORY_FINGERPRINT_SCRYPT },
      (error, key) => (error ? reject(error) : resolve(key.toString("hex"))),
    );
  });
  return createHash("sha256")
    .update(`${HISTORY_ENGINE}\n${ruleId}\n${file}\n${stretched}`)
    .digest("hex");
}

function shortCommit(commit: string): string {
  return commit.slice(0, 12);
}

/** Lines (1-based) where `value` starts in `content`; at most `limit`. */
function linesOf(content: string, value: string, limit = 20): number[] {
  const lines: number[] = [];
  let from = 0;
  let line = 1;
  let counted = 0;
  while (lines.length < limit) {
    const at = content.indexOf(value, from);
    if (at < 0) break;
    for (
      let index = content.indexOf("\n", counted);
      index >= 0 && index < at;
      index = content.indexOf("\n", index + 1)
    ) {
      line += 1;
      counted = index + 1;
    }
    lines.push(line);
    from = at + Math.max(1, value.length);
  }
  return lines;
}

/**
 * Turn a Gitleaks git-mode report (written without `--redact`) into
 * deduplicated candidates: one per (rule, file, secret), keeping the earliest
 * commit and counting the results folded into it. "Earliest" is the latest
 * position in `commitOrder` (commit ids newest first, as `git rev-list
 * --topo-order` prints them); commits not in it are compared by date, then by
 * position in the report. `readWorkingFile` returns the content of a file of
 * the working tree, or undefined. `deadline` (epoch ms) bounds the
 * fingerprint work; candidates not finished by then are dropped and
 * `truncated` is set. Exported for tests (recorded reports).
 */
export async function historyCandidatesFromReport(
  document: unknown,
  options: {
    prefix: string;
    version?: string;
    readWorkingFile: (file: string) => string | undefined;
    commitOrder?: readonly string[];
    maxResults?: number;
    deadline?: number;
  },
): Promise<{
  candidates: HistoryCandidate[];
  warnings: string[];
  results: number;
  truncated: boolean;
  outOfTime: boolean;
}> {
  const warnings = new Set<string>();
  const allEntries = reportEntries(document);
  const maxResults = options.maxResults ?? MAX_HISTORY_RESULTS;
  const truncated = allEntries.length > maxResults;
  const entries = truncated ? allEntries.slice(0, maxResults) : allEntries;
  if (truncated) {
    warnings.add(
      `history: ${allEntries.length} Gitleaks results, only the first ${maxResults} were processed`,
    );
  }
  const order = new Map<string, number>();
  (options.commitOrder ?? []).forEach((commit, index) => order.set(commit, index));

  const parsed: ParsedResult[] = [];
  let withoutValue = 0;
  entries.forEach((entry, index) => {
    const rule = typeof entry.RuleID === "string" && entry.RuleID ? entry.RuleID : "gitleaks-rule";
    const commit = typeof entry.Commit === "string" ? entry.Commit.toLowerCase() : "";
    if (!COMMIT_ID.test(commit)) {
      warnings.add("gitleaks history result without a valid commit id was dropped");
      return;
    }
    const repoPath = safeRepoPath(typeof entry.File === "string" ? entry.File : "");
    if (!repoPath) {
      warnings.add("gitleaks history result with an unusable file path was dropped");
      return;
    }
    // The audit root may be a directory inside the repository.
    if (options.prefix && !repoPath.startsWith(options.prefix)) return;
    const file = repoPath.slice(options.prefix.length);
    if (!file) return;
    const startLine =
      typeof entry.StartLine === "number" && entry.StartLine > 0 ? Math.trunc(entry.StartLine) : 1;
    const endLine =
      typeof entry.EndLine === "number" && entry.EndLine >= startLine
        ? Math.trunc(entry.EndLine)
        : startLine;
    const identity = secretOf(entry);
    if (identity === undefined) withoutValue += 1;
    parsed.push({
      rule,
      description:
        typeof entry.Description === "string" && entry.Description
          ? entry.Description.slice(0, 300)
          : "Gitleaks detected a credential",
      file,
      commit,
      date: normalizedDate(entry.Date),
      startLine,
      endLine,
      evidence: historyEvidence(entry, file, identity),
      ...(identity !== undefined ? { identity } : {}),
      placeholder: identity !== undefined && isGitleaksPlaceholder(rule, identity),
      index,
    });
  });
  if (withoutValue > 0) {
    warnings.add(
      `history: ${withoutValue} Gitleaks result(s) carried no value; they are not deduplicated`,
    );
  }

  // Deduplicate by (rule, file, secret).
  interface Group {
    first: ParsedResult;
    occurrences: number;
    hash?: string;
  }
  const groups = new Map<string, Group>();
  const earlier = (a: ParsedResult, b: ParsedResult): boolean => {
    if (a.commit !== b.commit) {
      const left = order.get(a.commit);
      const right = order.get(b.commit);
      // Newest first: a higher position is an older commit.
      if (left !== undefined && right !== undefined) return left > right;
      if (a.date && b.date && a.date !== b.date) return a.date < b.date;
      // Gitleaks reports newest first: a later entry is older.
      return a.index > b.index;
    }
    return a.startLine < b.startLine;
  };
  for (const result of parsed) {
    const hash = result.identity !== undefined ? secretHash(result.identity) : undefined;
    const key = hash
      ? `${result.rule}\0${result.file}\0${hash}`
      : `${result.rule}\0${result.file}\0@${result.commit}:${result.startLine}`;
    const group = groups.get(key);
    if (!group) {
      groups.set(key, { first: result, occurrences: 1, ...(hash ? { hash } : {}) });
      continue;
    }
    group.occurrences += 1;
    if (earlier(result, group.first)) group.first = result;
  }

  const workingCache = new Map<string, string | undefined>();
  const work: Array<() => Promise<HistoryCandidate>> = [];
  for (const group of groups.values()) {
    const first = group.first;
    const ruleId = `gitleaks-${first.rule}`;
    let workingLines: number[] = [];
    if (first.identity !== undefined) {
      if (!workingCache.has(first.file)) {
        if (workingCache.size >= 16) workingCache.clear();
        const content = options.readWorkingFile(first.file);
        workingCache.set(first.file, content?.replace(/\r\n/g, "\n"));
      }
      const content = workingCache.get(first.file);
      // Lines (1-based) where the value is in the working tree today.
      if (content !== undefined) workingLines = linesOf(content, first.identity);
    }
    const presentInWorkingTree = workingLines.length > 0;
    const occurrencesText = group.occurrences > 1 ? `, in ${group.occurrences} results` : "";
    const finding = createFinding({
      ruleId,
      title: `Gitleaks (git history): ${first.description}`,
      category: "secrets",
      severity: "high",
      confidence: gitleaksRuleConfidence(first.rule),
      cwe: "CWE-798",
      owasp: "A07:2021",
      file: first.file,
      startLine: first.startLine,
      endLine: first.endLine,
      evidence: first.evidence,
      message: `A credential was found in the git history by Gitleaks (added in commit ${shortCommit(first.commit)}${first.date ? ` on ${first.date.slice(0, 10)}` : ""}${occurrencesText}); the value is redacted in every output.`,
      remediation: HISTORY_REMEDIATION,
      references: ["CWE-798", "OWASP A07:2021"],
      provenance: {
        engine: HISTORY_ENGINE,
        rule: first.rule,
        ...(options.version ? { version: options.version } : {}),
      },
      history: {
        commit: first.commit,
        date: first.date,
        stillPresent: presentInWorkingTree,
        occurrences: group.occurrences,
      },
    });
    const hash = group.hash;
    const placeholder = first.placeholder;
    work.push(async () => {
      const fingerprint = hash
        ? await historyFingerprint(ruleId, first.file, hash)
        : createHash("sha256")
            .update(`${HISTORY_ENGINE}\n${ruleId}\n${first.file}\n${first.commit}\n${first.startLine}`)
            .digest("hex");
      const withFingerprint: Finding = { ...finding, fingerprint };
      return {
        finding: placeholder
          ? lowerConfidence(withFingerprint, ADJUSTMENT_PLACEHOLDER, "low")
          : withFingerprint,
        ...(hash ? { matchKey: `${ruleId}\0${first.file}\0${hash}` } : {}),
        history: { commit: first.commit, date: first.date, occurrences: group.occurrences },
        presentInWorkingTree,
        workingLines,
      };
    });
  }

  // scrypt runs on the libuv thread pool: a few at a time, so other
  // asynchronous work of the process is not starved, and within the deadline.
  const candidates: HistoryCandidate[] = [];
  let outOfTime = false;
  const concurrency = 2;
  for (let start = 0; start < work.length; start += concurrency) {
    if (options.deadline !== undefined && Date.now() > options.deadline) {
      outOfTime = true;
      break;
    }
    const batch = await Promise.all(work.slice(start, start + concurrency).map((task) => task()));
    candidates.push(...batch);
  }
  if (outOfTime) {
    warnings.add(
      `history: the time limit was reached while fingerprinting; ${work.length - candidates.length} of ${work.length} secret(s) were not reported`,
    );
  }
  return {
    candidates,
    warnings: [...warnings],
    results: allEntries.length,
    truncated,
    outOfTime,
  };
}

// ---------------------------------------------------------------------------
// The scan

export interface HistoryScanOptions {
  /** Canonical audit root. */
  root: string;
  target: HistoryTarget;
  toolPath: string;
  version?: string;
  range: string | null;
  untrusted: boolean;
  maxCommits?: number;
  timeoutMs?: number;
  pathEnv?: string;
}

/** A regular file inside the root (no symbolic link leaving it), else undefined. */
function controlFileInRoot(root: string, name: string): string | undefined {
  try {
    const resolved = resolveInside(root, name);
    return fs.statSync(resolved).isFile() ? resolved : undefined;
  } catch (error) {
    if (error instanceof PathJailError) return undefined;
    return undefined;
  }
}

/** A Gitleaks log line at error level (its git failed, for example). */
const GITLEAKS_ERROR_LINE = /(?:^|\s)(?:ERR|FTL)\s|level=(?:error|fatal)/m;

/**
 * Scan the git history of `options.target` with Gitleaks in an isolated
 * mirror clone. Never throws for a tool failure: the result says `failed` or
 * `partial` and why.
 */
export async function runGitleaksHistory(options: HistoryScanOptions): Promise<HistoryScanResult> {
  try {
    return await scanHistory(options);
  } catch (error) {
    return {
      status: "failed",
      detail: `history scan failed: ${error instanceof Error ? error.message : String(error)}`,
      range: options.range,
      commits: 0,
      maxCommits: options.maxCommits ?? DEFAULT_HISTORY_MAX_COMMITS,
      results: 0,
      candidates: [],
      warnings: [],
      timedOut: false,
    };
  }
}

async function scanHistory(options: HistoryScanOptions): Promise<HistoryScanResult> {
  const started = Date.now();
  const timeoutMs = options.timeoutMs ?? DEFAULT_HISTORY_TIMEOUT_MS;
  const deadline = started + timeoutMs;
  const remaining = (): number => Math.max(1, deadline - Date.now());
  const maxCommits = options.maxCommits ?? DEFAULT_HISTORY_MAX_COMMITS;
  const warnings: string[] = [];
  const base = {
    range: options.range,
    maxCommits,
    commits: 0,
    results: 0,
    candidates: [] as HistoryCandidate[],
    warnings,
    timedOut: false,
  };
  const failed = (detail: string, extra: Partial<HistoryScanResult> = {}): HistoryScanResult => ({
    ...base,
    ...extra,
    status: "failed",
    detail,
  });

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "code-audit-history-"));
  const cleanup = registerCleanup([tmp], { detached: true });
  try {
    fs.chmodSync(tmp, 0o700);
    const mirror = path.join(tmp, "repo.git");
    const ignoreDir = path.join(tmp, "ignore");
    fs.mkdirSync(ignoreDir, { mode: 0o700 });
    const reportPath = path.join(tmp, "report.json");
    const gitOptions = { pathEnv: options.pathEnv, cwd: tmp, cleanup };

    // 1. Isolated copy. Of the refused protocols, the file transport is
    // allowed again for this one clone: it is how `--no-local` reads a local
    // repository.
    const clone = await runHistoryGit(
      [
        "clone",
        "--mirror",
        "--no-local",
        "--no-hardlinks",
        "--quiet",
        "--template=",
        "--upload-pack",
        UPLOAD_PACK_COMMAND,
        "--",
        options.target.topLevel,
        mirror,
      ],
      { ...gitOptions, timeoutMs: remaining() },
      ["-c", "protocol.file.allow=always"],
    );
    if (clone.exitCode !== 0) {
      return {
        ...base,
        status: clone.timedOut ? "partial" : "failed",
        timedOut: clone.timedOut,
        detail: gitFailure(clone, "git clone of the repository"),
      };
    }

    // 2. No replace refs and no grafts in the copy: they could swap the
    // commit that added a secret for a clean one. (Every git here also runs
    // with GIT_NO_REPLACE_OBJECTS=1.)
    const replaceRefs = await runHistoryGit(
      ["-C", mirror, "for-each-ref", "--format=%(refname)", "refs/replace/"],
      { ...gitOptions, timeoutMs: remaining() },
    );
    if (replaceRefs.exitCode !== 0) return failed(gitFailure(replaceRefs, "git for-each-ref"));
    const replaced = replaceRefs.stdout.split("\n").filter((line) => line.startsWith("refs/replace/"));
    for (const ref of replaced) {
      const removed = await runHistoryGit(
        ["-C", mirror, "update-ref", "-d", "--end-of-options", ref],
        { ...gitOptions, timeoutMs: remaining() },
      );
      if (removed.exitCode !== 0) return failed(gitFailure(removed, "removing a replace ref"));
    }
    if (replaced.length > 0) {
      warnings.push(
        `history: the repository has ${replaced.length} replace ref(s); the history was scanned without them`,
      );
    }
    fs.rmSync(path.join(mirror, "info", "grafts"), { force: true });

    // 3. The commits of the range must be in the copy: a pseudo-ref or a ref
    // outside refs/ resolves in the audited repository to a commit the clone
    // does not have.
    for (const commit of options.target.commits) {
      const present = await runHistoryGit(
        ["-C", mirror, "cat-file", "-e", `${commit}^{commit}`],
        { ...gitOptions, timeoutMs: remaining() },
      );
      if (present.exitCode !== 0) {
        return failed(
          `commit ${shortCommit(commit)} of the range is not reachable from any ref of the repository (a pseudo-ref such as ORIG_HEAD, or a ref outside refs/); name a branch, tag or commit on one`,
        );
      }
    }

    // 4. Commits of the range, and their order (newest first).
    const revs = options.target.resolvedRange === null ? ["--all"] : [options.target.resolvedRange];
    const count = await runHistoryGit(
      ["-C", mirror, "rev-list", "--count", "--full-history", ...revs],
      { ...gitOptions, timeoutMs: remaining() },
    );
    const commits = Number.parseInt(count.stdout.trim(), 10);
    if (count.exitCode !== 0 || !Number.isInteger(commits)) {
      return failed(gitFailure(count, "git rev-list"));
    }
    const listing = await runHistoryGit(
      [
        "-C",
        mirror,
        "rev-list",
        "--full-history",
        "--topo-order",
        `--max-count=${maxCommits}`,
        ...revs,
      ],
      { ...gitOptions, timeoutMs: remaining(), maxOutputBytes: (maxCommits + 1) * 66 },
    );
    if (listing.exitCode !== 0 && !listing.truncated) {
      return failed(gitFailure(listing, "git rev-list"), { commits });
    }
    const commitOrder = listing.stdout
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => COMMIT_ID.test(line));

    // 5. Gitleaks on the copy, without --redact: the report stays in the
    // private directory and is deleted as soon as it has been read.
    const logOpts = ["--full-history", `--max-count=${maxCommits}`, ...revs].join(" ");
    const args = [
      "git",
      mirror,
      "--log-opts",
      logOpts,
      "--report-format",
      "json",
      "--report-path",
      reportPath,
      "--no-banner",
      "--no-color",
      "--exit-code",
      "0",
      // No .gitleaksignore of the working directory or the copy.
      "--gitleaks-ignore-path",
      ignoreDir,
    ];
    if (options.untrusted) {
      // Nothing of the audited repository may lower the result: no
      // `gitleaks:allow` comments, no configuration of its own (Gitleaks then
      // uses its default rules; the copy has no working tree to hold one).
      args.push("--ignore-gitleaks-allow");
    } else {
      // The project's own Gitleaks configuration applies to its history as
      // it does to the working tree.
      const config = controlFileInRoot(options.root, ".gitleaks.toml");
      if (config) args.push("--config", config);
      const ignore = controlFileInRoot(options.root, ".gitleaksignore");
      if (ignore) {
        const index = args.indexOf("--gitleaks-ignore-path");
        args[index + 1] = ignore;
      }
    }
    const configEnv: Record<string, string> = {
      GIT_CONFIG_COUNT: String(GITLEAKS_GIT_CONFIG.length),
    };
    GITLEAKS_GIT_CONFIG.forEach(([key, value], index) => {
      configEnv[`GIT_CONFIG_KEY_${index}`] = key;
      configEnv[`GIT_CONFIG_VALUE_${index}`] = value;
    });
    // Gitleaks gets the budget less a reserve for reading its report and
    // fingerprinting, so that a slow Gitleaks still leaves time for those.
    const reserveMs = Math.min(10_000, Math.floor(timeoutMs / 10));
    const run = await runTool(options.toolPath, args, {
      cwd: tmp,
      timeoutMs: Math.max(1, remaining() - reserveMs),
      env: { ...historyGitEnv(options.pathEnv), ...configEnv },
      onSpawn: cleanup.track,
      detached: true,
    });

    let document: unknown = [];
    let reportRead = false;
    let reportTooLarge = false;
    try {
      if (fs.statSync(reportPath).size > MAX_REPORT_BYTES) {
        reportTooLarge = true;
        warnings.push(
          `gitleaks history report is larger than ${MAX_REPORT_BYTES / (1024 * 1024)} MB and was not read`,
        );
      } else {
        const text = fs.readFileSync(reportPath, "utf8");
        fs.rmSync(reportPath, { force: true });
        try {
          document = JSON.parse(text);
          reportRead = true;
        } catch {
          // The parser's message can quote the report, which holds secrets.
          warnings.push("gitleaks history report could not be parsed");
        }
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        warnings.push("gitleaks history report could not be read");
      }
    } finally {
      fs.rmSync(reportPath, { force: true });
    }
    if (!run.timedOut && run.exitCode !== 0) {
      return failed(`gitleaks exited with code ${run.exitCode}`, { commits });
    }
    // With `--exit-code 0` Gitleaks exits 0 also when its `git log` failed;
    // it says so on an error-level log line (never quoted: it could hold
    // anything git printed).
    if (!run.timedOut && GITLEAKS_ERROR_LINE.test(`${run.stdout}\n${run.stderr}`)) {
      return failed("gitleaks reported an error (its git log of the copy failed)", { commits });
    }

    // 6. Deduplicate (in memory), within the same time budget.
    const parsed = await historyCandidatesFromReport(document, {
      prefix: options.target.prefix,
      version: options.version,
      commitOrder,
      deadline,
      readWorkingFile: (file) => {
        try {
          const resolved = resolveInside(options.root, file);
          const stat = fs.statSync(resolved);
          if (!stat.isFile() || stat.size > MAX_WORKING_FILE_BYTES) return undefined;
          return fs.readFileSync(resolved, "utf8");
        } catch {
          return undefined;
        }
      },
    });
    document = undefined;
    for (const warning of parsed.warnings) warnings.push(warning);

    const partialReasons: string[] = [];
    // Shallow source, or a shallow copy (the boundary travels with the clone).
    if (options.target.shallow || fs.existsSync(path.join(mirror, "shallow"))) {
      partialReasons.push(SHALLOW_HISTORY_DETAIL);
    }
    if (commits > maxCommits) {
      partialReasons.push(
        `${commits} commits, only the ${maxCommits} most recent were scanned (CODE_AUDIT_HISTORY_MAX_COMMITS)`,
      );
    }
    if (parsed.truncated) {
      partialReasons.push(`only the first ${MAX_HISTORY_RESULTS} of ${parsed.results} results were processed`);
    }
    if (parsed.outOfTime) {
      partialReasons.push("the time limit was reached while fingerprinting; some secrets are not reported");
    }
    if (reportTooLarge) partialReasons.push("the Gitleaks report was too large to read");
    if (run.timedOut) {
      partialReasons.push(
        `timed out after ${Math.round(timeoutMs / 1000)} s${reportRead ? "" : "; no results"}`,
      );
    }
    const scanned = Math.min(commits, maxCommits);
    return {
      ...base,
      commits,
      results: parsed.results,
      candidates: parsed.candidates,
      timedOut: run.timedOut,
      status: partialReasons.length > 0 ? "partial" : "ok",
      detail:
        partialReasons.length > 0
          ? partialReasons.join("; ")
          : `${scanned} commit(s) scanned, ${parsed.results} result(s), ${parsed.candidates.length} distinct secret(s)`,
    };
  } finally {
    cleanup.release();
  }
}
