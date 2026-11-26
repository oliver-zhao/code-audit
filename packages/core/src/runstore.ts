import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { z } from "zod";
import {
  assignFindingIds,
  computeFingerprint,
  createFinding,
  dedupeFindings,
  severityAtLeast,
  sortFindings,
  type Confidence,
  type Finding,
  type Severity,
} from "./finding.js";
import {
  inventory,
  MAX_TEXT_FILE_BYTES,
  type InventoryResult,
  type InventoryFile,
} from "./inventory.js";
import { defaultRulesDir, LATEST_OUTPUT_FILES, TOOL_VERSION } from "./meta.js";
import { countPathContexts } from "./pathContext.js";
import {
  allowSensitiveRoot,
  resolveInside,
  toPosixRelative,
  validateAuditRoot,
} from "./pathJail.js";
import {
  applyVerdictConfidence,
  buildReportContext,
  countAdjustments,
  dismissedWarning,
  findingsJsonRun,
  renderFindingsJson,
  renderMarkdown,
  renderSarif,
  runPolicy,
  summarizeRun,
  summaryCountFields,
  type FindingSummary,
  type ReportContext,
  type RunPolicy,
} from "./report.js";
import {
  loadRules,
  MAX_LONG_LINE_MATCHED,
  MAX_PATTERN_LINE_LENGTH,
  redactionsForFile,
  type LoadedRule,
  type RuleSet,
} from "./rules.js";
import { compileGlob } from "./glob.js";
import { InterruptedError, runInterruptible } from "./interrupt.js";
import {
  LINE_MASK_ALL,
  LINE_MASK_STRINGS,
  isCredentialFinding,
  redactEvidence,
  redactLine,
  redactLineDetailed,
  redactText,
  scrubValues,
  sensitiveLines,
  splitLines,
  type RedactRange,
} from "./redact.js";
import {
  AgentFindingsSchema,
  CoverageSchema,
  FindingsEnvelopeSchema,
  MAX_RUN_FILE_BYTES,
  RunFileError,
  RunIndexSchema,
  RunRecordSchema,
  RunStateSchema,
  VerdictsSchema,
  parseRunFile,
} from "./runSchemas.js";
import {
  SafeFsError,
  canonicalPath,
  ensureDirInside,
  isPathInside,
  printable,
  readFileNoFollow,
  writeFileAtomicNoFollow,
} from "./safeFs.js";

export class RunStoreError extends Error {
  readonly code: string;

  constructor(message: string, code = "RUN_STORE") {
    super(message);
    this.name = "RunStoreError";
    this.code = code;
  }
}

export type RunPhase = "running" | "complete" | "failed";

export interface RunProgress {
  engine?: string;
  files?: number;
  rules?: number;
  dependencies?: number;
}

export interface RunState {
  schemaVersion: 1;
  runId: string;
  root: string;
  runDir: string;
  phase: RunPhase;
  startedAt: string;
  updatedAt: string;
  finishedAt?: string;
  progress?: RunProgress;
  error?: string;
  warnings?: string[];
}

export interface RunIndexEntry {
  runId: string;
  runDir: string;
  root: string;
  phase: RunPhase;
  startedAt: string;
  updatedAt: string;
}

interface RunIndexDocument {
  schemaVersion: 1;
  runs: RunIndexEntry[];
}

export const VERDICT_STATUSES = [
  "confirmed",
  "likely",
  "needs_review",
  "false_positive",
] as const;
export type VerdictStatus = (typeof VERDICT_STATUSES)[number];

export interface VerdictRecord {
  fingerprint: string;
  findingId?: string;
  status: VerdictStatus;
  rationale: string;
  evidenceLines?: string[];
  at: string;
  actor?: string;
  /** Host agent reviewer label (for example the model name). */
  reviewer?: string;
}

export interface VerdictsDocument {
  schemaVersion: 1;
  runId: string;
  entries: VerdictRecord[];
}

export type CurrentVerdicts = Record<string, VerdictRecord>;

/** How the audit root of a loaded run was established. */
export type RunRootSource =
  /** The run directory is `<root>/.audit/<run-id>`: the root is where it sits. */
  | "location"
  /** The user named the root on this command line (`--root`, MCP `root`). */
  | "confirmed";

export interface LoadedRun {
  /** Canonical path of the run directory. */
  runDir: string;
  runId: string;
  /**
   * The audit root, or undefined when the run directory does not show which
   * project it belongs to and the user has not named one. It never comes
   * from the content of the run directory alone. Commands that read project
   * files get it through `requireAuditRoot`.
   */
  root: string | undefined;
  rootSource?: RunRootSource;
  /** The root written in run.json, for display only; not trusted. */
  recordedRoot?: string;
  run: Record<string, unknown>;
  findings: Finding[];
  hotspots: Finding[];
  /** coverage.json, validated; empty when missing or invalid (see `requireCoverage`). */
  coverage: Record<string, unknown>;
  state: RunState | undefined;
  verdicts: CurrentVerdicts;
  verdictsDocument: VerdictsDocument;
  /** Things the user should see about this run (printed as warnings). */
  notices: string[];
  /** Shared across copies of this object; holds what is loaded on demand. */
  session: RunSession;
}

interface RunSession {
  /** `--rules` of this command line. */
  rulesDir?: string;
  ruleSet?: RuleSet | null;
  rootProblem?: string;
  coverageProblem?: string;
}

/** Run ids are one path component: letters, digits, `.`, `_`, `-`. */
const RUN_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/;

function isRunId(value: string): boolean {
  return RUN_ID_PATTERN.test(value) && value !== "latest";
}

function storeError(error: unknown): never {
  if (error instanceof RunFileError) throw new RunStoreError(error.message, error.code);
  if (error instanceof SafeFsError) throw new RunStoreError(error.message, error.code);
  throw error;
}

/** Write a file of the tool into `dir`, which must be a canonical path. */
function writeText(dir: string, name: string, text: string): string {
  try {
    return writeFileAtomicNoFollow(path.join(dir, name), text, { expectedDir: dir });
  } catch (error) {
    return storeError(error);
  }
}

function writeJson(dir: string, name: string, value: unknown): string {
  return writeText(dir, name, `${JSON.stringify(value, null, 2)}\n`);
}

/**
 * Read and validate a JSON file of a run directory or of `.audit`. Returns
 * undefined when the file does not exist. A symbolic link, an oversized file,
 * invalid JSON or a document that does not match the schema is an error with
 * a one-line message.
 */
function readRunFile<S extends z.ZodTypeAny>(
  dir: string,
  name: string,
  schema: S,
): z.infer<S> | undefined {
  const label = `${name} in ${dir}`;
  try {
    const buffer = readFileNoFollow(path.join(dir, name), MAX_RUN_FILE_BYTES);
    if (buffer === undefined) return undefined;
    return parseRunFile(buffer.toString("utf8"), schema, label);
  } catch (error) {
    if (error instanceof SafeFsError) {
      throw new RunStoreError(`cannot use ${label}: ${error.message}`, "RUN_STORE_READ");
    }
    return storeError(error);
  }
}

/** `runDir` must be the canonical path of the run directory. */
export function writeRunState(runDir: string, state: RunState): void {
  writeJson(runDir, "state.json", state);
}

export function readRunState(runDir: string): RunState | undefined {
  return readRunFile(runDir, "state.json", RunStateSchema);
}

/** Where a scan writes: see `prepareRunOutput`. */
export interface RunOutput {
  /** Canonical path of the new run directory. */
  runDir: string;
  /** Canonical path of the directory that holds run directories and `latest/`. */
  outDir: string;
  /** The directory no write may leave: the audit root, or an external `--out`. */
  base: string;
  /** True when the output directory is inside the audit root. */
  insideRoot: boolean;
}

/**
 * The part of `target` below the audit root when one of its ancestors is the
 * root under any spelling (a symlinked parent, `/tmp` vs `/private/tmp`).
 */
function relativeToRoot(rootReal: string, target: string): string | undefined {
  let current = target;
  for (;;) {
    try {
      if (canonicalPath(current) === rootReal) return path.relative(current, target);
    } catch {
      // does not exist (yet): look further up
    }
    const parent = path.dirname(current);
    if (parent === current) return undefined;
    current = parent;
  }
}

/**
 * Create the run directory of a scan.
 *
 * The default output `<root>/.audit` and any `--out` located inside the audit
 * root are created one component at a time below the root: when `.audit`, the
 * `--out` directory or a component of it is a symbolic link that leaves the
 * root, the scan is refused instead of writing the run somewhere else. An
 * `--out` outside the root is a directory the user named and is used as is;
 * nothing below it may leave it either.
 */
export function prepareRunOutput(
  root: string,
  out: string | undefined,
  runId: string,
): RunOutput {
  if (!isRunId(runId)) {
    throw new RunStoreError(`invalid run id: ${printable(runId)}`, "INVALID_RUN_ID");
  }
  try {
    const rootReal = canonicalPath(root);
    let base = rootReal;
    let outDir: string;
    if (out === undefined) {
      outDir = ensureDirInside(rootReal, path.join(rootReal, ".audit"));
    } else {
      const absolute = path.resolve(out);
      const relative = relativeToRoot(rootReal, absolute);
      if (relative !== undefined) {
        outDir = ensureDirInside(rootReal, path.join(rootReal, relative));
      } else {
        fs.mkdirSync(absolute, { recursive: true });
        outDir = canonicalPath(absolute);
        if (!isPathInside(rootReal, outDir)) base = outDir;
      }
    }
    const runDir = ensureDirInside(base, path.join(outDir, runId));
    return { runDir, outDir, base, insideRoot: base === rootReal };
  } catch (error) {
    return storeError(error);
  }
}

/**
 * Copy report files of a run to `<outDir>/latest/` (`--latest-link`). The
 * copies are regular files written through `writeFileAtomicNoFollow`: a
 * symbolic link planted at `latest/report.md` is replaced, never written
 * through, and a `latest` that is a link leaving the output base is refused.
 */
export function writeLatestCopies(output: RunOutput, names: readonly string[]): string {
  try {
    const latestDir = ensureDirInside(output.base, path.join(output.outDir, "latest"));
    for (const name of names) {
      if (!LATEST_OUTPUT_FILES.has(name)) continue;
      const buffer = readFileNoFollow(path.join(output.runDir, name), MAX_RUN_FILE_BYTES);
      if (buffer === undefined) continue;
      writeFileAtomicNoFollow(path.join(latestDir, name), buffer, { expectedDir: latestDir });
    }
    return latestDir;
  } catch (error) {
    return storeError(error);
  }
}

/** Write a file of a scan into its run directory (canonical path). */
export function writeRunFile(runDir: string, name: string, text: string): string {
  return writeText(runDir, name, text);
}

/** Entries kept in `.audit/index.json`. */
const MAX_INDEX_RUNS = 500;

interface AuditDir {
  /** Canonical audit root. */
  root: string;
  /** Canonical path of `<root>/.audit`. */
  auditDir: string;
}

/**
 * `<root>/.audit` of a project root, when it exists. Throws when `.audit` is
 * a symbolic link that leaves the root: run directories behind such a link
 * belong to something else.
 */
function auditDirOf(rootInput: string): AuditDir | undefined {
  let root: string;
  try {
    root = canonicalPath(path.resolve(rootInput));
  } catch {
    return undefined;
  }
  const candidate = path.join(root, ".audit");
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(candidate);
  } catch {
    return undefined;
  }
  let auditDir = candidate;
  if (stat.isSymbolicLink()) {
    try {
      auditDir = canonicalPath(candidate);
    } catch {
      return undefined;
    }
    if (auditDir === root || !isPathInside(root, auditDir)) {
      throw new RunStoreError(
        `${candidate} is a symbolic link that leaves the project (-> ${auditDir}); refusing to use the run directories behind it`,
        "RUN_DIR_ESCAPE",
      );
    }
  }
  try {
    if (!fs.statSync(auditDir).isDirectory()) return undefined;
  } catch {
    return undefined;
  }
  return { root, auditDir };
}

function hasRunJson(dir: string): boolean {
  try {
    return fs.lstatSync(path.join(dir, "run.json")).isFile();
  } catch {
    return false;
  }
}

/**
 * The run directory `candidate` (a path at or below an audit directory) when
 * its canonical path is a directory inside that audit directory. A symbolic
 * link that leads anywhere else is refused: it would make `verdict`,
 * `add-finding` and `report` write into another project's run.
 */
function runInAuditDir(audit: AuditDir, candidate: string): string | undefined {
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(candidate);
  } catch {
    return undefined;
  }
  let real: string;
  try {
    real = canonicalPath(candidate);
  } catch {
    return undefined;
  }
  if (real === audit.auditDir || !isPathInside(audit.auditDir, real)) {
    throw new RunStoreError(
      stat.isSymbolicLink()
        ? `${candidate} is a symbolic link that leaves ${audit.auditDir} (-> ${real}); refusing to use it as a run directory`
        : `${candidate} is not inside ${audit.auditDir}; refusing to use it as a run directory`,
      "RUN_DIR_ESCAPE",
    );
  }
  try {
    if (!fs.statSync(real).isDirectory()) return undefined;
  } catch {
    return undefined;
  }
  return real;
}

function readIndex(audit: AuditDir): { document?: RunIndexDocument; problem?: string } {
  try {
    const document = readRunFile(audit.auditDir, "index.json", RunIndexSchema);
    return document ? { document } : {};
  } catch (error) {
    return { problem: error instanceof Error ? error.message : String(error) };
  }
}

/** Index entries for the run directories that are really in `.audit`. */
function rebuildIndex(audit: AuditDir): RunIndexEntry[] {
  const runs: RunIndexEntry[] = [];
  let names: string[];
  try {
    names = fs.readdirSync(audit.auditDir).filter(isRunId).sort().reverse();
  } catch {
    return runs;
  }
  for (const name of names.slice(0, MAX_INDEX_RUNS)) {
    const dir = path.join(audit.auditDir, name);
    try {
      if (!fs.lstatSync(dir).isDirectory()) continue;
      const state = readRunState(dir);
      if (!state || state.runId !== name) continue;
      runs.push({
        runId: name,
        runDir: dir,
        root: audit.root,
        phase: state.phase,
        startedAt: state.startedAt,
        updatedAt: state.updatedAt,
      });
    } catch {
      // not a readable run directory: leave it out
    }
  }
  return runs;
}

/**
 * Add or replace the entry of a run in `<projectRoot>/.audit/index.json`.
 * An index that is not valid is rebuilt from the run directories in `.audit`.
 * Returns warnings for the caller to show.
 */
export function registerRunIndex(
  projectRoot: string,
  entry: RunIndexEntry,
): string[] {
  const warnings: string[] = [];
  let audit: AuditDir;
  try {
    const root = canonicalPath(projectRoot);
    audit = { root, auditDir: ensureDirInside(root, path.join(root, ".audit")) };
  } catch (error) {
    return storeError(error);
  }
  const { document, problem } = readIndex(audit);
  let existing: RunIndexEntry[];
  if (document) {
    existing = document.runs;
  } else {
    existing = problem ? rebuildIndex(audit) : [];
    if (problem) {
      warnings.push(
        `.audit/index.json was not valid and has been rebuilt from the run directories (${problem})`,
      );
    }
  }
  const runs = existing.filter((run) => run.runId !== entry.runId);
  runs.push(entry);
  runs.sort((a, b) => b.startedAt.localeCompare(a.startedAt));
  writeJson(audit.auditDir, "index.json", {
    schemaVersion: 1,
    runs: runs.slice(0, MAX_INDEX_RUNS),
  } satisfies RunIndexDocument);
  return warnings;
}

export interface ResolveRunOptions {
  /** Extra project roots whose `.audit` is searched for a run id. */
  roots?: string[];
  cwd?: string;
  /**
   * The audit root the user named on this command line (`--root`, MCP
   * `root`). Its `.audit` is searched first, and it confirms the root of a
   * run directory that does not sit at `<root>/.audit/<run-id>`.
   */
  root?: string;
  /** Rules directory named on this command line (`--rules`). */
  rulesDir?: string;
  /** Accept run ids only, never a path (the MCP tools). */
  idsOnly?: boolean;
  /**
   * `--allow-sensitive-root` of this command line: the audit root of the run
   * may be a credential directory. Never set by the MCP server.
   */
  allowSensitiveRoot?: boolean;
}

export interface ResolvedRun {
  /** Canonical path of the run directory. */
  runDir: string;
  /**
   * The directory that contains `.audit` when the run directory is
   * `<root>/.audit/<run-id>`; undefined for a run directory anywhere else.
   */
  derivedRoot?: string;
}

/**
 * Resolve a run id or a run directory.
 *
 * A run id is looked up only as `<root>/.audit/<run-id>` of the current
 * directory, of `options.root` and of `options.roots`. A path is the run
 * directory the user named. In both cases the canonical run directory must be
 * a real directory: under `.audit` it has to stay inside the canonical
 * `<root>/.audit`, and a path that is itself a symbolic link is refused, so a
 * link planted in a repository cannot direct a command at another project's
 * run. `.audit/index.json` is consulted for ids, under the same rule.
 */
export function resolveRun(ref: string, options: ResolveRunOptions = {}): ResolvedRun {
  const value = ref.trim();
  if (!value) throw new RunStoreError("run id or run directory is required", "RUN_ID_REQUIRED");
  const shown = printable(value);

  if (!options.idsOnly) {
    const direct = path.resolve(options.cwd ?? process.cwd(), value);
    let stat: fs.Stats | undefined;
    try {
      stat = fs.lstatSync(direct);
    } catch {
      stat = undefined;
    }
    if (stat && (stat.isDirectory() || stat.isSymbolicLink())) {
      if (path.basename(path.dirname(direct)) === ".audit") {
        const audit = auditDirOf(path.dirname(path.dirname(direct)));
        const runDir = audit
          ? runInAuditDir(audit, path.join(audit.auditDir, path.basename(direct)))
          : undefined;
        if (audit && runDir && hasRunJson(runDir)) return { runDir, derivedRoot: audit.root };
        throw new RunStoreError(
          `not an audit run directory (missing run.json): ${shown}`,
          "RUN_NOT_FOUND",
        );
      }
      let real: string;
      try {
        real = canonicalPath(direct);
      } catch {
        throw new RunStoreError(`audit run not found: ${shown}`, "RUN_NOT_FOUND");
      }
      if (stat.isSymbolicLink()) {
        throw new RunStoreError(
          `${shown} is a symbolic link (-> ${real}); pass the run directory itself`,
          "RUN_DIR_ESCAPE",
        );
      }
      if (!hasRunJson(real)) {
        throw new RunStoreError(
          `not an audit run directory (missing run.json): ${shown}`,
          "RUN_NOT_FOUND",
        );
      }
      // The same directory reached through another spelling of its path.
      if (path.basename(path.dirname(real)) === ".audit") {
        const audit = auditDirOf(path.dirname(path.dirname(real)));
        if (audit && audit.auditDir === path.dirname(real)) {
          return { runDir: real, derivedRoot: audit.root };
        }
      }
      return { runDir: real };
    }
  }

  if (!isRunId(value)) {
    throw new RunStoreError(
      options.idsOnly
        ? `audit run not found: ${shown} (a run id is expected, not a path)`
        : `audit run not found: ${shown}`,
      "RUN_NOT_FOUND",
    );
  }

  const searchRoots = [
    ...(options.root ? [options.root] : []),
    options.cwd ?? process.cwd(),
    ...(options.roots ?? []),
  ];
  const audits: AuditDir[] = [];
  let refusal: RunStoreError | undefined;
  for (const root of searchRoots) {
    try {
      const audit = auditDirOf(root);
      if (!audit || audits.some((known) => known.auditDir === audit.auditDir)) continue;
      audits.push(audit);
      const runDir = runInAuditDir(audit, path.join(audit.auditDir, value));
      if (runDir && hasRunJson(runDir)) return { runDir, derivedRoot: audit.root };
    } catch (error) {
      if (!(error instanceof RunStoreError)) throw error;
      refusal ??= error;
    }
  }
  for (const audit of audits) {
    const entry = readIndex(audit).document?.runs.find((run) => run.runId === value);
    if (!entry) continue;
    // The index is a file in the project, so it is not trusted to name a
    // directory anywhere on the machine: every run it lists was written to
    // `<root>/.audit/`, and only such a directory is accepted.
    try {
      const runDir = runInAuditDir(audit, path.resolve(audit.root, entry.runDir));
      if (runDir && hasRunJson(runDir)) return { runDir, derivedRoot: audit.root };
    } catch (error) {
      if (!(error instanceof RunStoreError)) throw error;
      refusal ??= error;
    }
  }
  if (refusal) throw refusal;
  throw new RunStoreError(`audit run not found: ${shown}`, "RUN_NOT_FOUND");
}

export function resolveRunDir(
  ref: string,
  options: ResolveRunOptions = {},
): string {
  return resolveRun(ref, options).runDir;
}

export function readVerdicts(runDir: string): VerdictsDocument {
  return (
    readRunFile(runDir, "verdicts.json", VerdictsSchema) ?? {
      schemaVersion: 1,
      runId: path.basename(runDir),
      entries: [],
    }
  );
}

export function currentVerdicts(document: VerdictsDocument): CurrentVerdicts {
  // No prototype: a fingerprint is a key chosen by a file in the repository.
  const current = Object.create(null) as CurrentVerdicts;
  for (const entry of document.entries) {
    current[entry.fingerprint] = entry;
  }
  return current;
}

function readAgentFindings(runDir: string): Finding[] {
  return readRunFile(runDir, "agent-findings.json", AgentFindingsSchema)?.findings ?? [];
}

function loadInventoryForRun(root: string): InventoryResult {
  return inventory(root);
}

/**
 * A hash of the rule files of a rule set (paths relative to the rules
 * directory, and contents). Recorded in run.json by the scan; a later command
 * compares it with the rule set it loaded.
 */
export function ruleSetHash(ruleSet: RuleSet): string {
  const hash = crypto.createHash("sha256");
  const files = [...ruleSet.files].sort();
  for (const file of files) {
    hash.update(path.relative(ruleSet.rulesDir, file).split(path.sep).join("/"));
    hash.update("\0");
    try {
      hash.update(fs.readFileSync(file));
    } catch {
      hash.update("<unreadable>");
    }
    hash.update("\0");
  }
  return hash.digest("hex");
}

/**
 * The rule set a command after the scan works with: the rules bundled with
 * the tool, or the directory given with `--rules` on that command line. The
 * `rulesDir` written in run.json is never loaded: that file is part of the
 * audited repository and could name rules prepared by its author. When the
 * rule set in use is not the one the run was scanned with, a notice says so.
 */
function runRuleSet(run: LoadedRun): RuleSet | null {
  const session = run.session;
  if (session.ruleSet !== undefined) return session.ruleSet;
  const explicit = session.rulesDir;
  const dir = explicit ?? defaultRulesDir();
  let ruleSet: RuleSet | null;
  try {
    ruleSet = loadRules(dir);
  } catch (error) {
    // A directory the user named must load; the bundled rules degrade.
    if (explicit !== undefined) throw error;
    ruleSet = null;
  }
  session.ruleSet = ruleSet;
  if (ruleSet) {
    const recordedHash = run.run.rulesHash;
    const recordedDir = run.run.rulesDir;
    if (typeof recordedHash === "string") {
      if (recordedHash !== ruleSetHash(ruleSet)) {
        run.notices.push(
          `the rule set in use (${ruleSet.rulesDir}) is not the one this run was scanned with` +
            (typeof recordedDir === "string" ? ` (run.json names ${printable(recordedDir)})` : "") +
            "; redaction and rule details come from the rules in use. Pass --rules <dir> to choose the rule set.",
        );
      }
    } else if (typeof recordedDir === "string" && path.resolve(recordedDir) !== ruleSet.rulesDir) {
      run.notices.push(
        `run.json names the rules directory ${printable(recordedDir)}; a path from a run file is not loaded. Using ${ruleSet.rulesDir}. Pass --rules <dir> to choose the rule set.`,
      );
    }
  }
  return ruleSet;
}

/**
 * Redaction of source lines shown outside a scan (read, search, agent-added
 * findings). Uses the shared `redactLine`, the multi-line state of
 * `sensitiveLines`, and what the `redactEvidence` rules of the rule set in
 * use match in the file, so these tools mask what the scan masks.
 */
class SourceRedactor {
  private readonly ranges = new Map<string, Map<number, RedactRange[]>>();

  constructor(private readonly ruleSet: RuleSet | null) {}

  private rangesFor(entry: InventoryFile): Map<number, RedactRange[]> {
    const cached = this.ranges.get(entry.relPath);
    if (cached) return cached;
    let result = new Map<number, RedactRange[]>();
    if (this.ruleSet && entry.scannable) {
      try {
        result = redactionsForFile(entry, this.ruleSet);
      } catch {
        result = new Map();
      }
    }
    this.ranges.set(entry.relPath, result);
    return result;
  }
  /**
   * A function that redacts line `index` (zero-based) of `lines`. With
   * `evidence` the line is trimmed and cut like scan evidence (starting at
   * `column` when it is longer than the evidence limit).
   */
  forFile(
    entry: InventoryFile,
    lines: string[],
  ): (
    index: number,
    options?: {
      maskAllStrings?: boolean;
      evidence?: boolean;
      column?: number;
      /** Receives the raw values that were masked on the line. */
      masked?: string[];
    },
  ) => string {
    const flags = sensitiveLines(lines);
    let ranges: Map<number, RedactRange[]> | undefined;
    return (index, options = {}) => {
      if (flags[index] === LINE_MASK_ALL) return "[private key content redacted]";
      ranges ??= this.rangesFor(entry);
      const redactOptions = {
        file: entry.relPath,
        ranges: ranges.get(index + 1),
        maskAllStrings: options.maskAllStrings || flags[index] === LINE_MASK_STRINGS,
      };
      const line = lines[index] ?? "";
      if (options.masked) {
        for (const value of redactLineDetailed(line, redactOptions).masked) {
          options.masked.push(value);
        }
      }
      if (options.evidence) {
        return redactEvidence(line, { ...redactOptions, column: options.column });
      }
      return redactLine(line, redactOptions);
    };
  }
}

function sourceRedactor(run: LoadedRun): SourceRedactor {
  return new SourceRedactor(runRuleSet(run));
}

function recordedRootOf(run: Record<string, unknown>): string | undefined {
  const args = run.args as Record<string, unknown> | undefined;
  if (typeof args?.resolvedRoot === "string" && args.resolvedRoot) return args.resolvedRoot;
  if (typeof args?.root === "string" && args.root) return args.root;
  return undefined;
}

function canonicalIfAbsolute(target: string | undefined): string | undefined {
  if (target === undefined || !path.isAbsolute(target)) return undefined;
  try {
    return canonicalPath(target);
  } catch {
    return undefined;
  }
}

/**
 * The audit root of a run.
 *
 * It is taken from where the run directory is, never from what the run
 * directory contains: for `<root>/.audit/<run-id>` it is the directory that
 * contains `.audit`. A run directory anywhere else (an external `--out`, a
 * copy) does not show which project it belongs to; the root written in its
 * run.json is used only when the user names the same directory with `--root`
 * (compared as canonical paths). Otherwise the run has no root, and the
 * commands that read project files refuse.
 */
function establishRoot(
  resolved: ResolvedRun,
  run: Record<string, unknown>,
  options: ResolveRunOptions,
  notices: string[],
  session: RunSession,
): { root: string | undefined; rootSource?: RunRootSource; recordedRoot?: string } {
  const recordedRoot = recordedRootOf(run);
  const recordedReal = canonicalIfAbsolute(recordedRoot);
  const derived = resolved.derivedRoot;
  const shownRecorded = recordedRoot === undefined ? "none" : printable(recordedRoot);

  if (options.allowSensitiveRoot) {
    if (options.root !== undefined && options.root !== "") allowSensitiveRoot(options.root);
    if (derived !== undefined) allowSensitiveRoot(derived);
  }
  if (options.root !== undefined && options.root !== "") {
    const named = validateAuditRoot(options.root).root;
    if (named === derived) return { root: named, rootSource: "location", recordedRoot };
    if (recordedReal !== undefined && named === recordedReal) {
      return { root: named, rootSource: "confirmed", recordedRoot };
    }
    throw new RunStoreError(
      `--root ${named} is neither the directory that contains this run (${
        derived ?? `none: ${resolved.runDir} is not at <root>/.audit/<run-id>`
      }) nor the root recorded in its run.json (${shownRecorded})`,
      "ROOT_MISMATCH",
    );
  }
  if (derived !== undefined) {
    if (recordedRoot !== undefined && recordedReal !== derived) {
      notices.push(
        `run.json records the audit root ${shownRecorded}; the root in use is ${derived}, the directory that contains this run`,
      );
    }
    return { root: derived, rootSource: "location", recordedRoot };
  }
  session.rootProblem =
    `the audit root of this run is not established: ${resolved.runDir} is not at <root>/.audit/<run-id>, ` +
    `and the root named in its run.json (${shownRecorded}) is not trusted on its own. ` +
    "Pass --root <dir> (MCP: the root argument) with that directory to confirm it.";
  return { root: undefined, recordedRoot };
}

/** The audit root of a run, for commands that read files of the project. */
export function requireAuditRoot(run: LoadedRun): string {
  if (run.root === undefined) {
    throw new RunStoreError(
      run.session.rootProblem ?? "the audit root of this run is not established",
      "ROOT_UNCONFIRMED",
    );
  }
  return validateAuditRoot(run.root).root;
}

/** coverage.json of a run, validated; an error when it is missing or invalid. */
function requireCoverage(run: LoadedRun): ReportContext["coverage"] {
  if (run.session.coverageProblem !== undefined) {
    throw new RunStoreError(run.session.coverageProblem, "RUN_STORE_CORRUPT");
  }
  return run.coverage as unknown as ReportContext["coverage"];
}

export function loadRun(
  ref: string,
  options: ResolveRunOptions = {},
): LoadedRun {
  const resolved = resolveRun(ref, options);
  const runDir = resolved.runDir;
  const run = readRunFile(runDir, "run.json", RunRecordSchema) as
    | Record<string, unknown>
    | undefined;
  if (!run) {
    throw new RunStoreError(`run.json is missing in ${runDir}`, "RUN_NOT_FOUND");
  }
  const envelope = readRunFile(runDir, "findings.json", FindingsEnvelopeSchema);
  const baseFindings = envelope?.findings ?? [];
  const baseHotspots = envelope?.hotspots ?? [];
  const added = readAgentFindings(runDir);
  const addedFingerprints = new Set(added.map((finding) => finding.fingerprint));
  const findings = dedupeFindings([...baseFindings, ...added]);
  const hotspots = baseHotspots.filter(
    (hotspot) => !addedFingerprints.has(hotspot.fingerprint),
  );
  const notices: string[] = [];
  const session: RunSession = {
    ...(options.rulesDir !== undefined && options.rulesDir !== ""
      ? { rulesDir: options.rulesDir }
      : {}),
  };
  let coverage: Record<string, unknown> = {};
  try {
    const document = readRunFile(runDir, "coverage.json", CoverageSchema);
    if (document) coverage = document as Record<string, unknown>;
    else session.coverageProblem = `coverage.json is missing in ${runDir}`;
  } catch (error) {
    if (!(error instanceof RunStoreError)) throw error;
    // Only the Markdown and SARIF reports need it: they fail with this message.
    session.coverageProblem = error.message;
  }
  const state = readRunState(runDir);
  const verdictsDocument = readVerdicts(runDir);
  const runId = typeof run.runId === "string" ? run.runId : path.basename(runDir);
  return {
    runDir,
    runId,
    ...establishRoot(resolved, run, options, notices, session),
    run,
    findings,
    hotspots,
    coverage,
    state,
    verdicts: currentVerdicts(verdictsDocument),
    verdictsDocument,
    notices,
    session,
  };
}

/**
 * A stored record with the current verdict of the run applied: the status of
 * the verdict, and the confidence that status implies (`applyVerdictConfidence`
 * raises a confidence the scan lowered when a reviewer confirmed the finding,
 * and restores the scan's value when a later verdict says otherwise). Every
 * reader - `findings`, `status`, the reports, the files - sees this form.
 */
function withVerdict(run: LoadedRun, finding: Finding): Finding {
  const verdict = run.verdicts[finding.fingerprint];
  // `review` always comes from verdicts.json, never from what findings.json
  // says about itself.
  const { review: _stale, ...stored } = finding;
  if (!verdict) return applyVerdictConfidence(stored);
  return applyVerdictConfidence({
    ...stored,
    status: verdict.status,
    review: {
      status: verdict.status,
      rationale: verdict.rationale,
      ...(verdict.reviewer ? { reviewer: verdict.reviewer } : {}),
      ...(verdict.actor ? { actor: verdict.actor } : {}),
      at: verdict.at,
      ...(verdict.evidenceLines ? { evidenceLines: verdict.evidenceLines } : {}),
    },
  });
}

export function effectiveFindings(run: LoadedRun): Finding[] {
  return run.findings.map((finding) => withVerdict(run, finding));
}

export function effectiveHotspots(run: LoadedRun): Finding[] {
  return run.hotspots.map((finding) => withVerdict(run, finding));
}

function findTarget(run: LoadedRun, target: string): Finding {
  const byId = [...run.findings, ...run.hotspots].find(
    (finding) => finding.id === target,
  );
  if (byId) return byId;
  const byFingerprint = [...run.findings, ...run.hotspots].find(
    (finding) => finding.fingerprint === target,
  );
  if (byFingerprint) return byFingerprint;
  throw new RunStoreError(
    `finding not found by id or fingerprint: ${target}`,
    "FINDING_NOT_FOUND",
  );
}

/** Severity from which a `false_positive` verdict needs evidence. */
export const DISMISSAL_EVIDENCE_SEVERITY: Severity = "high";
/** Shortest rationale accepted for such a verdict. */
export const DISMISSAL_MIN_RATIONALE = 40;

/** `path/to/file.ext:123` or `line 123` in a rationale. */
const LOCATION_REFERENCE = /(?:[\w@~+-]+[\\/])*[\w@~+-]+\.[A-Za-z0-9_]{1,12}:\d+|\blines?\s+\d+/i;

/**
 * Dismissing a finding at severity >= high takes more than a word. A
 * reviewing agent that was talked into "mark everything false positive" by
 * text in the repository produces short, generic rationales; a real review
 * can say what it looked at. Required: a rationale of at least
 * `DISMISSAL_MIN_RATIONALE` characters, and either `evidenceLines` (the code
 * that shows why) or a `file:line` reference in the rationale.
 */
function assertDismissalJustified(
  finding: Finding,
  status: VerdictStatus,
  rationale: string,
  evidenceLines: readonly string[] | undefined,
): void {
  if (status !== "false_positive" || finding.kind === "hotspot") return;
  if (!severityAtLeast(finding.severity, DISMISSAL_EVIDENCE_SEVERITY)) return;
  const problems: string[] = [];
  if (rationale.replace(/\s+/g, " ").length < DISMISSAL_MIN_RATIONALE) {
    problems.push(`a rationale of at least ${DISMISSAL_MIN_RATIONALE} characters that says why the code is safe`);
  }
  const hasEvidence = (evidenceLines ?? []).some((line) => line.trim().length >= 3);
  if (!hasEvidence && !LOCATION_REFERENCE.test(rationale)) {
    problems.push(
      "evidence: evidenceLines (CLI: --evidence-line) quoting the code that shows it, or a file:line reference in the rationale",
    );
  }
  if (problems.length === 0) return;
  throw new RunStoreError(
    `marking ${finding.id} (${finding.severity}) false positive requires ${problems.join(", and ")}. ` +
      "Dismissed findings are listed for the human reader with reviewer and rationale; use needs_review when unsure",
    "DISMISSAL_NEEDS_EVIDENCE",
  );
}

export interface RecordVerdictInput {
  status: VerdictStatus;
  rationale: string;
  evidenceLines?: string[];
  actor?: string;
  reviewer?: string;
}

export interface RecordVerdictResult {
  runId: string;
  runDir: string;
  fingerprint: string;
  findingId: string;
  status: VerdictStatus;
  rationale: string;
  history: number;
  reviewed: number;
  total: number;
  /** Derived files re-rendered with this verdict applied. */
  refreshed: string[];
  notices: string[];
  /** See `dismissedFields`: set while serious findings are dismissed. */
  dismissedWarning?: string;
}

export function recordVerdict(
  ref: string,
  target: string,
  input: RecordVerdictInput,
  options: ResolveRunOptions = {},
): RecordVerdictResult {
  if (!VERDICT_STATUSES.includes(input.status)) {
    throw new RunStoreError(
      `unsupported verdict status: ${String(input.status)}`,
      "INVALID_VERDICT",
    );
  }
  const rationale = input.rationale?.trim();
  if (!rationale) {
    throw new RunStoreError(
      "rationale is required for a verdict",
      "RATIONALE_REQUIRED",
    );
  }
  const run = loadRun(ref, options);
  const finding = findTarget(run, target);
  assertDismissalJustified(finding, input.status, rationale, input.evidenceLines);
  const entry: VerdictRecord = {
    fingerprint: finding.fingerprint,
    findingId: finding.id,
    status: input.status,
    rationale,
    ...(input.evidenceLines && input.evidenceLines.length > 0
      ? {
          evidenceLines: input.evidenceLines.map((line) => redactText(line)),
        }
      : {}),
    at: new Date().toISOString(),
    ...(input.actor ? { actor: input.actor } : {}),
    ...(input.reviewer ? { reviewer: input.reviewer } : {}),
  };
  const document: VerdictsDocument = {
    schemaVersion: 1,
    runId: run.runId,
    entries: [...run.verdictsDocument.entries, entry],
  };
  const current = currentVerdicts(document);
  const updated: LoadedRun = { ...run, verdictsDocument: document, verdicts: current };
  // Every derived file is rendered before anything is written, so a run that
  // cannot be rendered is left as it was.
  const artifacts = renderDerived(updated);
  writeJson(run.runDir, "verdicts.json", document);
  const refreshed = writeDerived(updated, artifacts);
  const total = run.findings.length + run.hotspots.length;
  return {
    runId: run.runId,
    runDir: run.runDir,
    fingerprint: finding.fingerprint,
    findingId: finding.id,
    status: input.status,
    rationale,
    history: document.entries.filter(
      (item) => item.fingerprint === finding.fingerprint,
    ).length,
    reviewed: Object.keys(current).length,
    total,
    refreshed,
    notices: run.notices,
    ...dismissedFields(updated),
  };
}

export interface FindingsFilter {
  kind?: "finding" | "hotspot" | "all";
  severity?: Severity;
  status?: string;
  language?: string;
  minConfidence?: Confidence;
}

export interface QueryFindingsResult {
  items: Finding[];
  total: number;
  nextCursor: string | null;
}

const CONFIDENCE_RANK: Record<Confidence, number> = {
  high: 3,
  medium: 2,
  low: 1,
};

export function queryFindings(
  run: LoadedRun,
  filter: FindingsFilter = {},
  cursor?: string,
  limit = 20,
): QueryFindingsResult {
  const pageSize = Math.max(1, Math.min(20, Math.trunc(limit)));
  let offset = 0;
  if (cursor !== undefined && cursor !== "") {
    const parsed = Number(cursor);
    if (!Number.isSafeInteger(parsed) || parsed < 0) {
      throw new RunStoreError(`invalid cursor: ${cursor}`, "INVALID_CURSOR");
    }
    offset = parsed;
  }

  const findings = effectiveFindings(run);
  const hotspots = effectiveHotspots(run);
  const kind = filter.kind ?? "all";
  let pool: Finding[] =
    kind === "finding" ? findings : kind === "hotspot" ? hotspots : [
      ...findings,
      ...hotspots,
    ];
  if (filter.severity) {
    pool = pool.filter((finding) => finding.severity === filter.severity);
  }
  if (filter.status) {
    pool = pool.filter((finding) => finding.status === filter.status);
  }
  if (filter.language) {
    pool = pool.filter((finding) => finding.language === filter.language);
  }
  if (filter.minConfidence) {
    const min = CONFIDENCE_RANK[filter.minConfidence];
    pool = pool.filter(
      (finding) => CONFIDENCE_RANK[finding.confidence] >= min,
    );
  }

  const items = pool.slice(offset, offset + pageSize);
  const next = offset + pageSize;
  return {
    items,
    total: pool.length,
    nextCursor: next < pool.length ? String(next) : null,
  };
}

export function queryRunFindings(
  ref: string,
  filter: FindingsFilter = {},
  cursor?: string,
  limit = 20,
  options: ResolveRunOptions = {},
): QueryFindingsResult {
  return queryFindings(loadRun(ref, options), filter, cursor, limit);
}

export interface ReadSnippetResult {
  file: string;
  startLine: number;
  endLine: number;
  totalLines: number;
  truncated: boolean;
  content: string;
  lines: Array<{ number: number; text: string }>;
  /** The audit root the file was read from. */
  root: string;
  notices: string[];
}

const MAX_SNIPPET_LINES = 400;

function findInventoryFile(
  inv: InventoryResult,
  file: string,
): InventoryResult["files"][number] | undefined {
  const normalized = file.split("\\").join("/").replace(/^\.\//, "");
  return inv.files.find((entry) => entry.relPath === normalized);
}

export function readSnippet(
  ref: string,
  file: string,
  startLine = 1,
  endLine?: number,
  options: ResolveRunOptions = {},
): ReadSnippetResult {
  const run = loadRun(ref, options);
  const root = requireAuditRoot(run);
  const inv = loadInventoryForRun(root);
  const entry = findInventoryFile(inv, file);
  if (!entry) {
    throw new RunStoreError(
      `file is not part of the audit inventory (excluded, binary, oversized, or missing): ${file}`,
      "FILE_NOT_IN_INVENTORY",
    );
  }
  if (entry.size > MAX_TEXT_FILE_BYTES) {
    throw new RunStoreError(
      `file exceeds the ${MAX_TEXT_FILE_BYTES} byte read limit: ${file}`,
      "FILE_TOO_LARGE",
    );
  }
  const absolute = resolveInside(root, entry.relPath);
  const text = fs.readFileSync(absolute, "utf8");
  const allLines = splitLines(text);
  const totalLines = allLines.length;
  const redact = sourceRedactor(run).forFile(entry, allLines);
  const start = Math.max(1, Math.trunc(startLine));
  if (start > totalLines) {
    throw new RunStoreError(
      `startLine ${start} is beyond the end of ${file} (${totalLines} lines)`,
      "LINE_OUT_OF_RANGE",
    );
  }
  const requestedEnd = endLine === undefined ? start + 199 : Math.trunc(endLine);
  const cappedEnd = Math.min(
    totalLines,
    Math.max(start, requestedEnd),
    start + MAX_SNIPPET_LINES - 1,
  );
  const truncated = cappedEnd < Math.min(totalLines, requestedEnd);
  const lines: Array<{ number: number; text: string }> = [];
  for (let index = start; index <= cappedEnd; index += 1) {
    lines.push({ number: index, text: redact(index - 1) });
  }
  return {
    file: entry.relPath,
    startLine: start,
    endLine: cappedEnd,
    totalLines,
    truncated,
    content: lines.map((line) => line.text).join("\n"),
    lines,
    root,
    notices: run.notices,
  };
}

export interface SearchInput {
  pattern: string;
  glob?: string;
  regex?: boolean;
  maxResults?: number;
  /**
   * Wall-clock limit of the whole search in milliseconds (default
   * `DEFAULT_SEARCH_TIMEOUT_MS`, at most `MAX_SEARCH_TIMEOUT_MS`). The CLI
   * lets the user set it; the MCP server never passes it.
   */
  timeoutMs?: number;
}

export interface SearchMatch {
  file: string;
  line: number;
  column: number;
  text: string;
}

export interface SearchResult {
  matches: SearchMatch[];
  total: number;
  truncated: boolean;
  searchedFiles: number;
  pattern: string;
  /** The audit root that was searched. */
  root: string;
  notices: string[];
}

const MAX_PATTERN_LENGTH = 256;
const MAX_SEARCH_RESULTS = 200;
const MAX_SEARCH_BYTES = 16 * 1024 * 1024;
/** At most this many files are searched; the result is marked truncated. */
export const MAX_SEARCH_FILES = 20_000;
/** Wall-clock limit of one search unless the caller sets another. */
export const DEFAULT_SEARCH_TIMEOUT_MS = 2000;
export const MAX_SEARCH_TIMEOUT_MS = 60_000;

/**
 * A structural check that rejects the most obvious catastrophic patterns
 * early, with a helpful message. It is NOT what keeps a search from hanging -
 * no such check can be complete (`(a|aa)+$` passes it). Every regex search
 * runs under a wall-clock limit that interrupts the match; see `searchCode`.
 */
export function assertSafeRegex(pattern: string): RegExp {
  if (pattern.length > MAX_PATTERN_LENGTH) {
    throw new RunStoreError(
      `regex is too long (${pattern.length} > ${MAX_PATTERN_LENGTH})`,
      "UNSAFE_REGEX",
    );
  }
  const nestedQuantifier = /\((?:\\.|[^()\\])*[*+][^()\\]*\)\s*[*+{]/;
  if (nestedQuantifier.test(pattern)) {
    throw new RunStoreError(
      "regex contains a nested quantifier that may backtrack excessively",
      "UNSAFE_REGEX",
    );
  }
  try {
    return new RegExp(pattern);
  } catch (error) {
    throw new RunStoreError(
      `invalid regex: ${error instanceof Error ? error.message : String(error)}`,
      "INVALID_REGEX",
    );
  }
}

function searchTimeout(elapsedMs: number, limitMs: number, searchedFiles: number, at?: string): RunStoreError {
  return new RunStoreError(
    `search stopped: it exceeded the time limit of ${limitMs} ms (${Math.round(elapsedMs)} ms, ${searchedFiles} file(s) searched${
      at ? `, in ${printable(at)}` : ""
    }). Use a simpler pattern (avoid nested or overlapping repetition), a literal search, or a narrower glob`,
    "SEARCH_TIMEOUT",
  );
}

/**
 * First match of `regex` in each line: `[zero-based line, column]` pairs.
 * A line longer than `MAX_PATTERN_LINE_LENGTH` is matched in windows of that
 * size that overlap by half, up to `MAX_LONG_LINE_MATCHED` characters, like
 * the rule engine does; `overLong` counts such lines.
 */
function matchLines(
  lines: readonly string[],
  find: (text: string) => number,
  limit: number,
  stats: { overLong: number },
): number[] {
  const found: number[] = [];
  const step = MAX_PATTERN_LINE_LENGTH / 2;
  for (let index = 0; index < lines.length && found.length < limit * 2; index += 1) {
    const line = lines[index] as string;
    if (line.length <= MAX_PATTERN_LINE_LENGTH) {
      const at = find(line);
      if (at >= 0) found.push(index, at);
      continue;
    }
    stats.overLong += 1;
    const end = Math.min(line.length, MAX_LONG_LINE_MATCHED);
    for (let offset = 0; offset < end; offset += step) {
      const at = find(line.slice(offset, offset + MAX_PATTERN_LINE_LENGTH));
      if (at >= 0) {
        found.push(index, offset + at);
        break;
      }
    }
  }
  return found;
}

/**
 * Search the files of the inventory.
 *
 * The pattern is chosen at run time - over MCP by a model that has read the
 * audited repository - and is matched against content the repository's author
 * wrote, so both sides of a catastrophic match can be hostile. Limits:
 *
 * - a literal pattern is searched with `indexOf`, never as a regex;
 * - a regex is matched inside `runInterruptible`, which terminates a match
 *   that does not return; the whole search (all files) has one wall-clock
 *   budget and fails with `SEARCH_TIMEOUT` when it is used up;
 * - lines are matched in windows of `MAX_PATTERN_LINE_LENGTH` characters;
 * - at most `MAX_SEARCH_FILES` files, `MAX_SEARCH_BYTES` bytes and
 *   `MAX_SEARCH_RESULTS` matches;
 * - the glob is matched without backtracking (`compileGlob`).
 */
export function searchCode(
  ref: string,
  input: SearchInput,
  options: ResolveRunOptions = {},
): SearchResult {
  const started = performance.now();
  const limitMs = Math.max(
    1,
    Math.min(
      MAX_SEARCH_TIMEOUT_MS,
      Number.isFinite(input.timeoutMs) && (input.timeoutMs as number) > 0
        ? Math.trunc(input.timeoutMs as number)
        : DEFAULT_SEARCH_TIMEOUT_MS,
    ),
  );
  const deadline = started + limitMs;
  const run = loadRun(ref, options);
  const root = requireAuditRoot(run);
  const pattern = input.pattern;
  if (!pattern) {
    throw new RunStoreError("search pattern is required", "PATTERN_REQUIRED");
  }
  if (pattern.length > MAX_PATTERN_LENGTH) {
    throw new RunStoreError(
      `${input.regex ? "regex" : "pattern"} is too long (${pattern.length} > ${MAX_PATTERN_LENGTH})`,
      input.regex ? "UNSAFE_REGEX" : "PATTERN_TOO_LONG",
    );
  }
  let find: (text: string) => number;
  if (input.regex) {
    const regex = assertSafeRegex(pattern);
    find = (text) => {
      const match = regex.exec(text);
      return match ? match.index : -1;
    };
  } else {
    find = (text) => text.indexOf(pattern);
  }
  let glob: ((relativePath: string) => boolean) | undefined;
  if (input.glob) {
    try {
      glob = compileGlob(input.glob);
    } catch (error) {
      throw new RunStoreError(error instanceof Error ? error.message : String(error), "INVALID_GLOB");
    }
  }
  const maxResults = Math.max(
    1,
    Math.min(MAX_SEARCH_RESULTS, input.maxResults ?? 50),
  );
  const inv = loadInventoryForRun(root);
  const matches: SearchMatch[] = [];
  const redactor = sourceRedactor(run);
  const stats = { overLong: 0 };
  let truncated = false;
  let searchedFiles = 0;
  let consumed = 0;

  for (const entry of inv.files) {
    if (!entry.scannable) continue;
    if (performance.now() > deadline) {
      throw searchTimeout(performance.now() - started, limitMs, searchedFiles);
    }
    if (glob && !glob(entry.relPath)) continue;
    if (entry.size > MAX_TEXT_FILE_BYTES) continue;
    if (consumed + entry.size > MAX_SEARCH_BYTES || searchedFiles >= MAX_SEARCH_FILES) {
      truncated = true;
      break;
    }
    const absolute = resolveInside(root, entry.relPath);
    const text = fs.readFileSync(absolute, "utf8");
    consumed += Buffer.byteLength(text, "utf8");
    searchedFiles += 1;
    const lines = splitLines(text);
    const remaining = maxResults - matches.length;
    let found: number[];
    if (input.regex) {
      // Only the matching runs under the interrupting limit: it is pure
      // computation over strings that are already in memory.
      try {
        found = runInterruptible(
          () => matchLines(lines, find, remaining, stats),
          Math.max(1, deadline - performance.now()),
        );
      } catch (error) {
        if (!(error instanceof InterruptedError)) throw error;
        throw searchTimeout(performance.now() - started, limitMs, searchedFiles, entry.relPath);
      }
    } else {
      found = matchLines(lines, find, remaining, stats);
    }
    if (found.length === 0) continue;
    const redact = redactor.forFile(entry, lines);
    for (let item = 0; item < found.length; item += 2) {
      const index = found[item] as number;
      const column = found[item + 1] as number;
      matches.push({
        file: entry.relPath,
        line: index + 1,
        column: column + 1,
        text: redact(index, { evidence: true, column }),
      });
      if (matches.length >= maxResults) {
        truncated = true;
        break;
      }
    }
    if (truncated) break;
  }
  const notices = [...run.notices];
  if (stats.overLong > 0) {
    notices.push(
      `${stats.overLong} line(s) longer than ${MAX_PATTERN_LINE_LENGTH} characters were searched in overlapping windows of that size, up to ${MAX_LONG_LINE_MATCHED} characters per line`,
    );
  }
  return {
    matches,
    total: matches.length,
    truncated,
    searchedFiles,
    pattern,
    root,
    notices,
  };
}

export interface AddFindingInput {
  file?: string;
  startLine?: number;
  endLine?: number;
  title?: string;
  severity?: Severity;
  cwe?: string;
  confidence?: Confidence;
  rationale: string;
  source?: string;
  hotspotId?: string;
  ruleId?: string;
  language?: string;
  message?: string;
  remediation?: string;
  reviewer?: string;
}

export interface AddFindingResult {
  runId: string;
  runDir: string;
  finding: Finding;
  promoted: boolean;
  /** Derived files re-rendered with the new finding. */
  refreshed: string[];
  notices: string[];
}

function nextFindingId(existing: Finding[], year: number): string {
  let max = 0;
  for (const finding of existing) {
    const match = /^AUD-\d{4}-(\d+)$/.exec(finding.id);
    if (match?.[1]) max = Math.max(max, Number(match[1]));
  }
  return `AUD-${year}-${String(max + 1).padStart(4, "0")}`;
}

function slugify(title: string): string {
  const slug = title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40);
  return slug || "manual";
}

function readEvidenceForRange(
  root: string,
  entry: InventoryFile,
  redactor: SourceRedactor,
  maskAllStrings: boolean,
  startLine: number,
  endLine?: number,
  masked?: string[],
): string {
  const relPath = entry.relPath;
  const absolute = resolveInside(root, relPath);
  const text = fs.readFileSync(absolute, "utf8");
  const lines = splitLines(text);
  if (startLine < 1 || startLine > lines.length) {
    throw new RunStoreError(
      `startLine ${startLine} is out of range for ${relPath} (${lines.length} lines)`,
      "LINE_OUT_OF_RANGE",
    );
  }
  const end = endLine ?? startLine;
  if (end < startLine || end > lines.length) {
    throw new RunStoreError(
      `endLine ${end} is out of range for ${relPath} (${lines.length} lines)`,
      "LINE_OUT_OF_RANGE",
    );
  }
  // The source line never becomes evidence as it is: it goes through the same
  // line redaction as scan evidence, and for a credential finding every
  // string literal is masked.
  const redact = redactor.forFile(entry, lines);
  const result: string[] = [];
  for (let index = startLine - 1; index < end; index += 1) {
    const line = lines[index] ?? "";
    // A very long line is cut like scan evidence.
    result.push(
      line.length > 2000
        ? redact(index, { evidence: true, maskAllStrings, masked })
        : redact(index, { maskAllStrings, masked }),
    );
  }
  return result.join("\n");
}

export function addFinding(
  ref: string,
  input: AddFindingInput,
  options: ResolveRunOptions = {},
): AddFindingResult {
  const rationale = input.rationale?.trim();
  if (!rationale) {
    throw new RunStoreError(
      "rationale is required when adding a finding",
      "RATIONALE_REQUIRED",
    );
  }
  const run = loadRun(ref, options);
  const year = new Date().getUTCFullYear();
  let finding: Finding;
  let promoted = false;

  if (input.hotspotId) {
    const hotspot = findTarget(run, input.hotspotId);
    if (hotspot.kind !== "hotspot") {
      throw new RunStoreError(
        `finding ${input.hotspotId} is not a hotspot`,
        "NOT_A_HOTSPOT",
      );
    }
    promoted = true;
    finding = createFinding({
      ruleId: input.ruleId ?? hotspot.ruleId,
      title: input.title ?? hotspot.title,
      category: hotspot.category,
      severity: input.severity ?? hotspot.severity,
      confidence: input.confidence ?? hotspot.confidence,
      kind: "finding",
      cwe: input.cwe ?? hotspot.cwe,
      owasp: hotspot.owasp,
      language: input.language ?? hotspot.language,
      file: hotspot.file,
      startLine: hotspot.startLine,
      endLine: hotspot.endLine,
      // A hotspot promoted to a credential finding gets the same treatment
      // as a new credential finding: every string literal is masked.
      evidence: redactText(hotspot.evidence, {
        file: hotspot.file,
        maskAllStrings: isCredentialFinding({
          cwe: input.cwe ?? hotspot.cwe,
          title: input.title ?? hotspot.title,
          ruleId: input.ruleId ?? hotspot.ruleId,
          category: hotspot.category,
        }),
      }),
      message: input.message ?? hotspot.message,
      remediation: input.remediation ?? hotspot.remediation,
      references: hotspot.references,
      source: input.source ?? "hotspot promotion",
      status: "needs_review",
      provenance: {
        engine: "agent",
        rule: hotspot.ruleId,
        version: TOOL_VERSION,
        ...(input.reviewer ? { reviewer: input.reviewer } : {}),
      },
      ...(hotspot.cvss === undefined ? {} : { cvss: hotspot.cvss }),
    });
    // Keep the hotspot fingerprint so verdicts and identity stay stable.
    finding = { ...finding, fingerprint: hotspot.fingerprint, id: hotspot.id };
  } else {
    if (!input.file) throw new RunStoreError("file is required", "FILE_REQUIRED");
    if (!input.startLine) {
      throw new RunStoreError("startLine is required", "LINE_REQUIRED");
    }
    const startLine = input.startLine;
    if (!input.title?.trim()) {
      throw new RunStoreError("title is required", "TITLE_REQUIRED");
    }
    if (!input.severity) {
      throw new RunStoreError("severity is required", "SEVERITY_REQUIRED");
    }
    if (!input.cwe?.trim()) {
      throw new RunStoreError("cwe is required", "CWE_REQUIRED");
    }
    const root = requireAuditRoot(run);
    const inv = loadInventoryForRun(root);
    const entry = findInventoryFile(inv, input.file);
    if (!entry) {
      throw new RunStoreError(
        `file is not part of the audit inventory (excluded, binary, oversized, or missing): ${input.file}`,
        "FILE_NOT_IN_INVENTORY",
      );
    }
    const endLine = input.endLine ?? startLine;
    const cweUpper = input.cwe.toUpperCase();
    const duplicate = [...run.findings, ...run.hotspots].find(
      (existing) =>
        existing.file === entry.relPath &&
        Boolean(existing.cwe) &&
        existing.cwe?.toUpperCase() === cweUpper &&
        existing.startLine <= endLine &&
        startLine <= existing.endLine,
    );
    if (duplicate) {
      const hint =
        duplicate.kind === "hotspot"
          ? `it is a hotspot; promote it with audit_add_finding (hotspot_id=${duplicate.id}) or \`code-audit add-finding --promote ${duplicate.id}\``
          : `record a verdict on ${duplicate.id} (audit_verdict, or \`code-audit verdict\`)`;
      throw new RunStoreError(
        `a ${duplicate.kind} already covers ${entry.relPath}:${duplicate.startLine} ` +
          `(${duplicate.id}, ${duplicate.cwe}); ${hint}`,
        "DUPLICATE_FINDING",
      );
    }
    const ruleId = input.ruleId ?? `agent-${slugify(input.title)}`;
    const maskedValues: string[] = [];
    const evidence = readEvidenceForRange(
      root,
      entry,
      sourceRedactor(run),
      isCredentialFinding({ cwe: input.cwe, title: input.title, ruleId }),
      startLine,
      input.endLine,
      maskedValues,
    );
    // Text the agent wrote about these lines may quote them: the values that
    // were masked in the evidence are masked there too.
    const scrub = (text: string): string => scrubValues(redactText(text), maskedValues);
    finding = createFinding({
      ruleId,
      title: scrub(input.title.trim()),
      category: "sast",
      severity: input.severity,
      confidence: input.confidence ?? "medium",
      kind: "finding",
      cwe: input.cwe,
      language: input.language ?? entry.language,
      file: entry.relPath,
      startLine,
      endLine: input.endLine,
      evidence,
      // Agent-written text may quote the source line.
      message: scrub(input.message ?? rationale),
      remediation:
        input.remediation ??
        "Review the code path and apply the fix described in the rationale.",
      source: input.source === undefined ? undefined : scrub(input.source),
      status: "needs_review",
      provenance: {
        engine: "agent",
        rule: ruleId,
        version: TOOL_VERSION,
        ...(input.source ? { source: scrub(input.source) } : {}),
        ...(input.reviewer ? { reviewer: input.reviewer } : {}),
      },
    });
  }

  if (!promoted) {
    finding = { ...finding, id: nextFindingId(run.findings, year) };
  }
  const existing = readAgentFindings(run.runDir);
  const merged = dedupeFindings([...existing, finding]);
  const allFindings = sortFindings(dedupeFindings([...run.findings, ...merged]));
  const remainingHotspots = run.hotspots.filter(
    (hotspot) => hotspot.fingerprint !== finding.fingerprint,
  );
  // findings.json keeps its `run` record (identity, thresholds, baseline);
  // it, the counts in run.json and the reports the run has are rendered again
  // with the new finding and the recorded verdicts, before anything is
  // written.
  const updated: LoadedRun = { ...run, findings: allFindings, hotspots: remainingHotspots };
  const artifacts = renderDerived(updated);
  writeJson(run.runDir, "agent-findings.json", {
    schemaVersion: 1,
    runId: run.runId,
    findings: merged,
  });
  const refreshed = writeDerived(updated, artifacts);
  return {
    runId: run.runId,
    runDir: run.runDir,
    finding,
    promoted,
    refreshed,
    notices: run.notices,
  };
}

/** findings.json of a stored run with its verdicts applied. */
function findingsJsonText(run: LoadedRun): string {
  return renderFindingsJson(
    { ...findingsJsonRun(run.run), review: reviewStats(run) },
    effectiveFindings(run),
    effectiveHotspots(run),
  );
}

/**
 * The counting model applied to a stored run: its findings and hotspots with
 * the recorded verdicts, counted with the policy recorded in run.json. Every
 * later command (`status`, `report`, the MCP tools) gets its numbers here.
 */
export function runSummary(run: LoadedRun): FindingSummary {
  return summarizeRun(run.run, effectiveFindings(run), effectiveHotspots(run));
}

export interface RunSummaryFields {
  /** Headline: active findings at confidence >= the run's `--min-confidence`. */
  findings: number;
  /** The headline by severity. */
  findingCounts: FindingSummary["headline"]["bySeverity"];
  /** Active findings below the threshold; never part of `findings`. */
  lowConfidenceCandidates: number;
  /** Active hotspots (not suppressed, not marked false positive). */
  hotspots: number;
  /** Every stored record whatever its status; `reviewed` / `unreviewed` refer to these. */
  records: { findings: number; hotspots: number };
  /** The thresholds and switches the run was scanned with. */
  policy: RunPolicy;
  summary: FindingSummary;
}

/** The count fields shared by `status` and `report --format summary`. */
export function runSummaryFields(run: LoadedRun): RunSummaryFields {
  const counts = summaryCountFields(runSummary(run));
  return {
    findings: counts.findings,
    findingCounts: counts.findingCounts,
    lowConfidenceCandidates: counts.lowConfidenceCandidates,
    hotspots: counts.hotspotCount,
    records: { findings: run.findings.length, hotspots: run.hotspots.length },
    policy: runPolicy(run.run),
    summary: counts.summary,
  };
}

export interface ReviewStats {
  reviewed: number;
  unreviewed: number;
  total: number;
  falsePositive: number;
}

export function reviewStats(run: LoadedRun): ReviewStats {
  const all = [...run.findings, ...run.hotspots];
  const reviewed = all.filter(
    (finding) => run.verdicts[finding.fingerprint] !== undefined,
  ).length;
  const falsePositive = run.findings.filter(
    (finding) => run.verdicts[finding.fingerprint]?.status === "false_positive",
  ).length;
  return {
    reviewed,
    unreviewed: all.length - reviewed,
    total: all.length,
    falsePositive,
  };
}

export type ReportOutputFormat = "md" | "json" | "sarif" | "summary";

export interface RunReportResult {
  runId: string;
  runDir: string;
  /** The audit root in use, when established; see `LoadedRun.root`. */
  root?: string;
  format: ReportOutputFormat;
  text: string;
  reviewed: number;
  unreviewed: number;
  falsePositive: number;
  total: number;
  path?: string;
  /** Every file this call wrote (the requested one and the refreshed ones). */
  refreshed: string[];
  notices: string[];
  /** See `dismissedFields`. */
  dismissedWarning?: string;
}

const REPORT_FILE: Record<Exclude<ReportOutputFormat, "summary">, string> = {
  md: "report.md",
  json: "findings.json",
  sarif: "results.sarif",
};

function existsNoFollow(file: string): boolean {
  try {
    return !fs.lstatSync(file).isDirectory();
  } catch {
    return false;
  }
}

function reportContextOf(run: LoadedRun): ReportContext {
  const reviewerSet = new Set<string>();
  for (const entry of run.verdictsDocument.entries) {
    if (entry.reviewer) reviewerSet.add(entry.reviewer);
  }
  for (const finding of run.findings) {
    const reviewer = (finding.provenance as { reviewer?: unknown }).reviewer;
    if (typeof reviewer === "string" && reviewer) reviewerSet.add(reviewer);
  }
  const reviewers = [...reviewerSet].sort();
  const agentReviewed =
    reviewers.length > 0 ||
    run.verdictsDocument.entries.length > 0 ||
    run.findings.some((finding) => finding.provenance.engine === "agent");
  return buildReportContext(run.run, {
    findings: effectiveFindings(run),
    hotspots: effectiveHotspots(run),
    coverage: requireCoverage(run),
    rules: runRuleSet(run)?.rules ?? [],
    reviewStats: reviewStats(run),
    reviewers,
    agentReviewed,
  });
}

interface DerivedArtifacts {
  /** The run with the refreshed run.json record. */
  run: LoadedRun;
  /** File name in the run directory -> new text. */
  files: Map<string, string>;
}

/**
 * Everything in a run directory that is computed from the findings, the
 * agent-added findings and the verdicts: findings.json, the counts in
 * run.json, and report.md / results.sarif when the run has them (or when
 * `also` asks for them). All of it comes from the one counting model, with
 * the verdicts applied, so `status`, the files and the reports cannot
 * disagree. Nothing is written here.
 */
function renderDerived(
  run: LoadedRun,
  also: ReadonlyArray<Exclude<ReportOutputFormat, "summary">> = [],
): DerivedArtifacts {
  const findings = effectiveFindings(run);
  const hotspots = effectiveHotspots(run);
  const { findings: _headline, ...countFields } = summaryCountFields(
    summarizeRun(run.run, findings, hotspots),
  );
  const record: Record<string, unknown> = {
    ...run.run,
    ...countFields,
    pathContext: countPathContexts(findings),
    adjustments: countAdjustments(findings),
    review: reviewStats(run),
  };
  const current: LoadedRun = { ...run, run: record };
  const files = new Map<string, string>();
  files.set("run.json", `${JSON.stringify(record, null, 2)}\n`);
  files.set("findings.json", findingsJsonText(current));
  const wants = (format: "md" | "sarif"): boolean =>
    also.includes(format) || existsNoFollow(path.join(run.runDir, REPORT_FILE[format]));
  if (wants("md") || wants("sarif")) {
    const context = reportContextOf(current);
    if (wants("md")) files.set("report.md", renderMarkdown(context));
    if (wants("sarif")) files.set("results.sarif", renderSarif(context));
  }
  return { run: current, files };
}

/**
 * Write what `renderDerived` produced: into the run directory and, when
 * `<out>/latest/` holds copies of this very run, over those copies as well.
 * Returns the paths written.
 */
function writeDerived(run: LoadedRun, artifacts: DerivedArtifacts): string[] {
  const written: string[] = [];
  for (const [name, text] of artifacts.files) {
    written.push(writeText(run.runDir, name, text));
  }
  const latestDir = path.join(path.dirname(run.runDir), "latest");
  let latest: fs.Stats | undefined;
  try {
    latest = fs.lstatSync(latestDir);
  } catch {
    latest = undefined;
  }
  if (!latest) return written;
  if (!latest.isDirectory()) {
    run.notices.push(`${latestDir} is not a directory; the copies in it were not refreshed`);
    return written;
  }
  let latestRunId: unknown;
  try {
    const envelope = readRunFile(latestDir, "findings.json", FindingsEnvelopeSchema) as
      | { run?: { runId?: unknown } }
      | undefined;
    latestRunId = envelope?.run?.runId;
  } catch {
    latestRunId = undefined;
  }
  // `latest/` may hold another (newer) run: only copies of this run change.
  if (latestRunId !== run.runId) return written;
  for (const name of LATEST_OUTPUT_FILES) {
    const text = artifacts.files.get(name);
    if (text === undefined || !existsNoFollow(path.join(latestDir, name))) continue;
    written.push(writeText(latestDir, name, text));
  }
  return written;
}

export function renderRunReport(
  ref: string,
  format: ReportOutputFormat = "summary",
  options: ResolveRunOptions = {},
): RunReportResult {
  const run = loadRun(ref, options);
  const stats = reviewStats(run);
  const warnings = Array.isArray(run.run.warnings) ? run.run.warnings : [];

  let text: string;
  let outputPath: string | undefined;
  let refreshed: string[] = [];
  if (format === "summary") {
    const runRecord = run.run as { baseline?: unknown; scope?: unknown };
    text = JSON.stringify(
      {
        runId: run.runId,
        runDir: run.runDir,
        root: run.root ?? null,
        phase: run.state?.phase ?? "complete",
        ...runSummaryFields(run),
        reviewed: stats.reviewed,
        unreviewed: stats.unreviewed,
        falsePositive: stats.falsePositive,
        ...dismissedFields(run),
        ...(runRecord.baseline ? { baseline: runRecord.baseline } : {}),
        ...(runRecord.scope ? { scope: runRecord.scope } : {}),
        warnings,
      },
      null,
      2,
    );
  } else {
    // The requested file is written and every other derived file of the run
    // is refreshed with it, all from the same state.
    const artifacts = renderDerived(run, [format]);
    refreshed = writeDerived(run, artifacts);
    text = artifacts.files.get(REPORT_FILE[format]) ?? "";
    outputPath = path.join(run.runDir, REPORT_FILE[format]);
  }

  return {
    runId: run.runId,
    runDir: run.runDir,
    ...(run.root !== undefined ? { root: run.root } : {}),
    format,
    text,
    reviewed: stats.reviewed,
    unreviewed: stats.unreviewed,
    falsePositive: stats.falsePositive,
    total: stats.total,
    ...(outputPath ? { path: outputPath } : {}),
    refreshed,
    notices: run.notices,
    ...dismissedFields(run),
  };
}

/**
 * `dismissedWarning`: the cover warning about findings at severity >=
 * `--fail-on` that were marked false positive, when there are any. The same
 * sentence as on the report cover.
 */
function dismissedFields(run: LoadedRun): { dismissedWarning?: string } {
  const warning = dismissedWarning(runSummary(run), "en");
  return warning ? { dismissedWarning: `WARNING: ${warning}` } : {};
}

export function runStatus(ref: string, options: ResolveRunOptions = {}) {
  const run = loadRun(ref, options);
  const stats = reviewStats(run);
  const runRecord = run.run as {
    baseline?: { path: string; entries: number; new: number; existing: number; fixed: number };
    scope?: { since: string; changedFiles: number };
  };
  return {
    runId: run.runId,
    runDir: run.runDir,
    /** Where the run directory is; null when that does not show the project. */
    root: run.root ?? null,
    rootSource: run.rootSource ?? null,
    ...(run.recordedRoot !== undefined ? { recordedRoot: run.recordedRoot } : {}),
    phase: run.state?.phase ?? "unknown",
    startedAt: run.state?.startedAt ?? run.run.startedAt,
    finishedAt: run.state?.finishedAt ?? run.run.finishedAt,
    updatedAt: run.state?.updatedAt,
    progress: run.state?.progress,
    error: run.state?.error,
    // Headline numbers of the counting model; `records` are the raw totals.
    ...runSummaryFields(run),
    reviewed: stats.reviewed,
    unreviewed: stats.unreviewed,
    falsePositive: stats.falsePositive,
    ...dismissedFields(run),
    ...(runRecord.baseline ? { baseline: runRecord.baseline } : {}),
    ...(runRecord.scope ? { scope: runRecord.scope } : {}),
    warnings: Array.isArray(run.run.warnings) ? run.run.warnings : [],
    notices: run.notices,
  };
}
