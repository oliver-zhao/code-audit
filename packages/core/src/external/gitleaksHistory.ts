/**
 * Secret scan of the git history (`scan --history`), with Gitleaks.
 *
 * Gitleaks' git mode runs `git log -p` in the repository it is given. The
 * audited repository is untrusted: its `.git/config` can name programs
 * (`core.fsmonitor`, `filter.<name>.*`, `diff.<name>.textconv`, a hooks
 * path, ...) and it may hide refs from a fetch. So Gitleaks never sees the
 * audited repository. Instead:
 *
 * 1. `git rev-parse` (with the hardening of git.ts) finds the top level of
 *    the repository and checks the requested refs;
 * 2. `git clone --mirror --no-local` copies every ref and object into a
 *    private temporary directory through git's own transport. The new
 *    repository's configuration is written by git and holds none of the
 *    original's drivers, hooks or attributes files; `--template=` leaves out
 *    the hook templates as well. `--no-local` makes git read objects through
 *    `upload-pack` instead of copying (or hard-linking) the object directory,
 *    which a symbolic link inside `.git/objects` could otherwise point
 *    anywhere;
 * 3. Gitleaks scans that copy, with the user and system git configuration
 *    switched off and hardening options passed through `GIT_CONFIG_COUNT`;
 * 4. for each result the file at that commit is read back from the copy
 *    (`git cat-file blob`, which runs no filter), so that the secret can be
 *    recognised again - in memory only - for deduplication, the placeholder
 *    check and `stillPresent`.
 *
 * The temporary directory is removed when the scan ends, also on error.
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
import { redactText, scrubValues, splitLines } from "../redact.js";
import { redactSecret } from "../secrets.js";
import {
  gitleaksRuleConfidence,
  isGitleaksPlaceholder,
  rawSecretOf,
  secretHash,
  secretIdentityOf,
} from "./gitleaks.js";
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

/** Wall-clock limit of the whole history scan (clone, Gitleaks, read-back). */
export const DEFAULT_HISTORY_TIMEOUT_MS = 5 * 60 * 1000;

/** Results whose file is read back from the copy; the rest keep no identity. */
const MAX_BLOB_LOOKUPS = 2000;

/** Results of one report that are processed; the rest are dropped (partial). */
export const MAX_HISTORY_RESULTS = 5000;

/** A Gitleaks report larger than this is not parsed (partial). */
const MAX_REPORT_BYTES = 64 * 1024 * 1024;

/** A file at a commit larger than this is not read back. */
const MAX_BLOB_BYTES = 5 * 1024 * 1024;

/** Longest accepted `--history` range. */
const MAX_RANGE_LENGTH = 512;

export const HISTORY_REMEDIATION =
  "Rotate this credential (revoke it and issue a new one): it is in the git history, and deleting the file or rewriting the history is not enough, because existing clones, forks, caches and CI logs keep the old commits. After rotating, remove it from the current code if it is still there.";

export const HISTORY_REMEDIATION_ZH =
  "必须轮换该凭据（吊销并重新签发）：它存在于 git 历史中，仅删除文件或改写历史并不够，因为已有的克隆、分叉、缓存和 CI 日志仍保留旧提交。轮换之后，如果当前代码中仍有它，再将其移除。";

export const HISTORY_MESSAGE_ZH =
  "Gitleaks 在 git 历史中发现了凭据；所有输出中该值都已脱敏。";

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
  const separator = value.includes("...") ? "..." : value.includes("..") ? ".." : undefined;
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
  const separator = range.includes("...") ? "..." : range.includes("..") ? ".." : undefined;
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
  ["protocol.allow", "never"],
];

/**
 * The `upload-pack` that serves the clone. git runs it for the source
 * repository, with the source's configuration and without the `-c` options
 * of the clone (the local transport clears them), so the options it needs
 * are part of the command: no fsmonitor, no hooks, and no hidden refs -
 * `uploadpack.hideRefs` / `transfer.hideRefs` in the audited repository could
 * otherwise keep commits out of the scan. A later `!refs` entry exposes
 * every ref again. git runs this string through `sh`; it is a constant.
 */
const UPLOAD_PACK_COMMAND = [
  "git",
  "-c core.fsmonitor=false",
  `-c core.hooksPath=${os.devNull}`,
  "-c uploadpack.hideRefs=!refs",
  "-c transfer.hideRefs=!refs",
  "-c protocol.allow=never",
  "upload-pack",
].join(" ");

const ALLOWED_GIT = new Set(["rev-parse", "clone", "rev-list", "cat-file"]);

interface GitRunOptions {
  pathEnv?: string;
  timeoutMs: number;
  maxOutputBytes?: number;
  cwd?: string;
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
  return runTool("git", [...lead, ...gitHardeningArgs(), ...extraConfig, ...rest], {
    cwd: options.cwd,
    timeoutMs: Math.max(1, options.timeoutMs),
    maxOutputBytes: options.maxOutputBytes,
    env: {
      ...gitHardenedEnv(),
      ...(options.pathEnv ? { PATH: options.pathEnv } : {}),
    },
  });
}

function gitFailure(result: RunToolResult, what: string): string {
  if (result.timedOut) return `${what} timed out`;
  const detail = result.stderr.trim().split("\n").filter(Boolean).slice(-1)[0] ?? "";
  return `${what} failed${detail ? `: ${detail}` : ` (exit code ${result.exitCode})`}`;
}

export interface HistoryTarget {
  /** Top level of the repository (what is cloned). */
  topLevel: string;
  /** Position of the audit root in the repository (`""` or `dir/`). */
  prefix: string;
}

/**
 * Locate the repository of `root` and check that the refs of `range` exist.
 * Runs only `git rev-parse`, with the hardening of git.ts. Throws
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
  if (range !== null) {
    for (const ref of historyRangeRefs(range)) {
      const verify = await runHistoryGit(
        ["-C", root, "rev-parse", "--verify", "--quiet", "--end-of-options", `${ref}^{commit}`],
        { pathEnv: options.pathEnv, timeoutMs },
      );
      if (verify.timedOut) throw new GitScopeError("--history: git rev-parse timed out");
      if (verify.exitCode !== 0) throw new GitScopeError(`--history: unknown git ref: ${ref}`);
    }
  }
  return { topLevel, prefix };
}

// ---------------------------------------------------------------------------
// Gitleaks report

interface HistoryReportEntry {
  RuleID?: string;
  Description?: string;
  StartLine?: number;
  EndLine?: number;
  StartColumn?: number;
  EndColumn?: number;
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

const COMMIT_ID = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;

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

/** One history result after read-back; `identity` is in memory only. */
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
}

/** A secret of the history, with the earliest commit it was added in. */
export interface HistoryCandidate {
  /** The finding to report when the current scan did not report the secret. */
  finding: Finding;
  /**
   * `gitleaks-<rule>\0<file>\0<sha256 of the secret>`: in memory only, to
   * recognise the same secret among the current Gitleaks results. Undefined
   * when the value could not be read back.
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
 * hash goes through scrypt first, so that the fingerprint (which is written
 * to reports and baselines) cannot be used to confirm a guessed short
 * password at the speed of SHA-256.
 */
export async function historyFingerprint(
  ruleId: string,
  file: string,
  secretSha256: string,
): Promise<string> {
  const stretched = await new Promise<string>((resolve, reject) => {
    scrypt(
      secretSha256,
      `code-audit-history-v1\0${ruleId}\0${file}`,
      32,
      { N: 1 << 14, r: 8, p: 1 },
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

/**
 * Turn a Gitleaks git-mode report into deduplicated candidates: one per
 * (rule, file, secret), keeping the earliest commit (by date, then id) and
 * counting the results folded into it. `readBlob` returns the lines of a file
 * at a commit, or undefined; `readWorkingFile` the content of a file of the
 * working tree, or undefined. Exported for tests (recorded reports).
 */
export async function historyCandidatesFromReport(
  document: unknown,
  options: {
    prefix: string;
    version?: string;
    readBlob: (commit: string, repoPath: string) => Promise<readonly string[] | undefined>;
    readWorkingFile: (file: string) => string | undefined;
    maxBlobLookups?: number;
    maxResults?: number;
  },
): Promise<{
  candidates: HistoryCandidate[];
  warnings: string[];
  results: number;
  truncated: boolean;
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
  const maxLookups = options.maxBlobLookups ?? MAX_BLOB_LOOKUPS;
  const blobCache = new Map<string, Promise<readonly string[] | undefined>>();
  let lookupsRefused = 0;
  const blobOf = (commit: string, repoPath: string): Promise<readonly string[] | undefined> => {
    const key = `${commit}:${repoPath}`;
    const cached = blobCache.get(key);
    if (cached) return cached;
    if (blobCache.size >= maxLookups) {
      lookupsRefused += 1;
      return Promise.resolve(undefined);
    }
    const pending = options.readBlob(commit, repoPath);
    blobCache.set(key, pending);
    return pending;
  };

  const parsed: ParsedResult[] = [];
  for (const entry of entries) {
    const rule = typeof entry.RuleID === "string" && entry.RuleID ? entry.RuleID : "gitleaks-rule";
    const commit = typeof entry.Commit === "string" ? entry.Commit.toLowerCase() : "";
    if (!COMMIT_ID.test(commit)) {
      warnings.add("gitleaks history result without a valid commit id was dropped");
      continue;
    }
    const repoPath = safeRepoPath(typeof entry.File === "string" ? entry.File : "");
    if (!repoPath) {
      warnings.add("gitleaks history result with an unusable file path was dropped");
      continue;
    }
    // The audit root may be a directory inside the repository.
    if (options.prefix && !repoPath.startsWith(options.prefix)) continue;
    const file = repoPath.slice(options.prefix.length);
    if (!file) continue;
    const startLine =
      typeof entry.StartLine === "number" && entry.StartLine > 0 ? Math.trunc(entry.StartLine) : 1;
    const endLine =
      typeof entry.EndLine === "number" && entry.EndLine >= startLine
        ? Math.trunc(entry.EndLine)
        : startLine;
    const lines = await blobOf(commit, repoPath);
    const identity = lines ? secretIdentityOf(entry, lines) : undefined;
    const raw = lines ? rawSecretOf(entry, lines) : undefined;
    const placeholder = raw !== undefined && isGitleaksPlaceholder(rule, raw);
    // Evidence: the first reported line of the file at that commit, with
    // every string literal masked and the value itself masked wherever it
    // still appears; without the file, the (redacted) match of the report.
    let evidence: string;
    const lineText = lines?.[startLine - 1];
    if (lineText !== undefined) {
      const clipped = lineText.length > 400 ? `${lineText.slice(0, 400)}...` : lineText;
      evidence = scrubValues(
        redactText(clipped.trim(), { file, maskAllStrings: true }),
        [raw, identity].filter((value): value is string => typeof value === "string"),
      );
    } else {
      const match = typeof entry.Match === "string" ? entry.Match : "";
      evidence = match ? redactSecret(match) : "[redacted secret]";
    }
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
      evidence,
      ...(identity !== undefined ? { identity } : {}),
      placeholder,
    });
  }
  if (lookupsRefused > 0) {
    warnings.add(
      `history: ${lookupsRefused} result(s) were not read back from their commit (more than ${maxLookups} files); they are not deduplicated by value`,
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
    if (a.date && b.date && a.date !== b.date) return a.date < b.date;
    if (a.date && !b.date) return true;
    if (!a.date && b.date) return false;
    return a.commit < b.commit;
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

  const pending: Array<Promise<HistoryCandidate>> = [];
  const workingCache = new Map<string, string | undefined>();
  for (const group of groups.values()) {
    const first = group.first;
    const ruleId = `gitleaks-${first.rule}`;
    let presentInWorkingTree = false;
    const workingLines: number[] = [];
    if (first.identity !== undefined) {
      if (!workingCache.has(first.file)) {
        if (workingCache.size >= 16) workingCache.clear();
        const content = options.readWorkingFile(first.file);
        workingCache.set(first.file, content?.replace(/\r\n/g, "\n"));
      }
      const content = workingCache.get(first.file);
      // Lines (1-based) where the value is in the working tree today.
      if (content !== undefined) {
        let from = 0;
        let line = 1;
        let counted = 0;
        while (workingLines.length < 20) {
          const at = content.indexOf(first.identity, from);
          if (at < 0) break;
          for (let index = content.indexOf("\n", counted); index >= 0 && index < at; index = content.indexOf("\n", index + 1)) {
            line += 1;
            counted = index + 1;
          }
          workingLines.push(line);
          from = at + Math.max(1, first.identity.length);
        }
      }
      presentInWorkingTree = workingLines.length > 0;
    }
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
    const fingerprint: Promise<string> = hash
      ? historyFingerprint(ruleId, first.file, hash)
      : Promise.resolve(
          createHash("sha256")
            .update(`${HISTORY_ENGINE}\n${ruleId}\n${first.file}\n${first.commit}\n${first.startLine}`)
            .digest("hex"),
        );
    pending.push(
      fingerprint.then((value) => {
        const withFingerprint: Finding = { ...finding, fingerprint: value };
        return {
          finding: first.placeholder
            ? lowerConfidence(withFingerprint, ADJUSTMENT_PLACEHOLDER, "low")
            : withFingerprint,
          ...(hash ? { matchKey: `${ruleId}\0${first.file}\0${hash}` } : {}),
          history: { commit: first.commit, date: first.date, occurrences: group.occurrences },
          presentInWorkingTree,
          workingLines,
        };
      }),
    );
  }
  // scrypt runs on the libuv thread pool, several at a time.
  const candidates = await Promise.all(pending);
  return { candidates, warnings: [...warnings], results: allEntries.length, truncated };
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
  const remaining = (): number => Math.max(1, timeoutMs - (Date.now() - started));
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

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "code-audit-history-"));
  try {
    fs.chmodSync(tmp, 0o700);
    const mirror = path.join(tmp, "repo.git");
    const ignoreDir = path.join(tmp, "ignore");
    fs.mkdirSync(ignoreDir, { mode: 0o700 });
    const reportPath = path.join(tmp, "report.json");
    const gitOptions = { pathEnv: options.pathEnv, cwd: tmp };

    // 1. Isolated copy. `protocol.allow=never` of the hardening is opened for
    // the file transport of this one clone, which is how `--no-local` reads
    // a local repository.
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

    // 2. How many commits the range has (in the copy).
    const revs = options.range === null ? ["--all"] : [options.range];
    const count = await runHistoryGit(
      ["-C", mirror, "rev-list", "--count", "--full-history", ...revs],
      { ...gitOptions, timeoutMs: remaining() },
    );
    const commits = count.exitCode === 0 ? Number.parseInt(count.stdout.trim(), 10) || 0 : 0;
    if (count.exitCode !== 0) warnings.push(gitFailure(count, "history: git rev-list"));

    // 3. Gitleaks on the copy.
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
      "--redact",
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
    const run = await runTool(options.toolPath, args, {
      cwd: tmp,
      timeoutMs: remaining(),
      env: {
        ...gitHardenedEnv(),
        ...configEnv,
        ...(options.pathEnv ? { PATH: options.pathEnv } : {}),
      },
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
        document = JSON.parse(fs.readFileSync(reportPath, "utf8"));
        reportRead = true;
      }
    } catch (error) {
      const err = error as NodeJS.ErrnoException;
      if (err.code !== "ENOENT") {
        warnings.push(
          `gitleaks history report could not be parsed: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
    if (!run.timedOut && run.exitCode !== 0) {
      return {
        ...base,
        commits,
        status: "failed",
        detail: `gitleaks exited with code ${run.exitCode}`,
      };
    }

    // 4. Read back, deduplicate.
    const parsed = await historyCandidatesFromReport(document, {
      prefix: options.target.prefix,
      version: options.version,
      readBlob: async (commit, repoPath) => {
        const result = await runHistoryGit(
          ["-C", mirror, "cat-file", "blob", `${commit}:${repoPath}`],
          { ...gitOptions, timeoutMs: Math.min(30_000, remaining()), maxOutputBytes: MAX_BLOB_BYTES },
        );
        if (result.exitCode !== 0 || result.truncated) return undefined;
        return splitLines(result.stdout);
      },
      readWorkingFile: (file) => {
        try {
          const resolved = resolveInside(options.root, file);
          const stat = fs.statSync(resolved);
          if (!stat.isFile() || stat.size > MAX_BLOB_BYTES) return undefined;
          return fs.readFileSync(resolved, "utf8");
        } catch {
          return undefined;
        }
      },
    });
    for (const warning of parsed.warnings) warnings.push(warning);

    const partialReasons: string[] = [];
    if (commits > maxCommits) {
      partialReasons.push(
        `${commits} commits, only the ${maxCommits} most recent were scanned (CODE_AUDIT_HISTORY_MAX_COMMITS)`,
      );
    }
    if (parsed.truncated) {
      partialReasons.push(`only the first ${MAX_HISTORY_RESULTS} of ${parsed.results} results were processed`);
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
    try {
      fs.rmSync(tmp, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 });
    } catch {
      // best effort cleanup
    }
  }
}
