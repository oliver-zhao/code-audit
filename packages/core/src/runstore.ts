import crypto from "node:crypto";
import { Worker } from "node:worker_threads";
import fs from "node:fs";
import path from "node:path";
import type { z } from "zod";
import {
  assignFindingIds,
  computeFingerprint,
  createFinding,
  dedupeFindings,
  SEVERITIES,
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
  PathJailError,
  allowSensitiveRoot,
  isInsideCanonical,
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
  triageCoverage,
  type FindingSummary,
  type TriageKindCount,
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
import { HumanDecisionError, assertHumanContext, processHumanContext } from "./humanGate.js";
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
  MAX_TRACE_STEPS,
  MAX_VERDICT_TEXT,
  MAX_VERDICTS_PER_FINDING,
  MIN_MISSING_LENGTH,
  RunFileError,
  RunIndexSchema,
  RunRecordSchema,
  RunStateSchema,
  VERDICTS_SCHEMA_VERSION,
  VerdictsSchema,
  parseRunFile,
  type TraceStepSchema,
  type VerdictConditionsSchema,
  type VerdictControlSchema,
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
  "proof_gap",
] as const;
export type VerdictStatus = (typeof VERDICT_STATUSES)[number];

export const VERDICT_ROLES = ["primary", "independent", "human"] as const;
export type VerdictRole = (typeof VERDICT_ROLES)[number];

export const INDEPENDENCE_KINDS = ["subagent", "same-session"] as const;
/** How an independent review was made: a fresh sub-agent, or a devil's-advocate pass in the same session. */
export type Independence = (typeof INDEPENDENCE_KINDS)[number];

export type TraceStep = z.infer<typeof TraceStepSchema>;
export type VerdictConditions = z.infer<typeof VerdictConditionsSchema>;
export type VerdictControl = z.infer<typeof VerdictControlSchema>;

/**
 * One entry of verdicts.json: what one reviewer decided, stored once. The
 * file is append-only; the current state of a finding is computed from all
 * of its entries (`currentVerdicts`).
 */
export interface VerdictRecord {
  fingerprint: string;
  findingId?: string;
  /** The status this reviewer gave. */
  status: VerdictStatus;
  rationale: string;
  evidenceLines?: string[];
  at: string;
  actor?: string;
  /** Host agent reviewer label (for example the model name). */
  reviewer?: string;
  /** Role of the reviewer who wrote this entry; absent (schemaVersion 1) means primary. */
  role?: VerdictRole;
  /** For role independent: a fresh sub-agent or a same-session devil's-advocate pass. */
  independence?: Independence;
  /** A primary verdict that knowingly replaced another reviewer's reviewed decision. */
  replace?: boolean;
  /** Source-to-sink path, at most `MAX_TRACE_STEPS` steps; every location was checked. */
  trace?: TraceStep[];
  conditions?: VerdictConditions;
  /** The code that makes a `false_positive` safe; the location was checked. */
  control?: VerdictControl;
  /** The fact a `proof_gap` verdict could not establish. */
  missing?: string;
  cwe?: string;
  /** A reviewer's view of the severity. Recorded and shown; never changes the counted severity. */
  severityOverride?: { severity: Severity; reason: string };
}

export interface VerdictsDocument {
  schemaVersion: 1 | 2;
  runId: string;
  /** See `VerdictsSchema.strictEvidence`. */
  strictEvidence?: boolean;
  entries: VerdictRecord[];
}

/** One entry of a finding's review history, as reports show it. */
export interface VerdictHistoryItem {
  reviewer: string;
  role: VerdictRole;
  status: VerdictStatus;
  at: string;
  rationale: string;
  independence?: Independence;
  /** A later primary verdict replaced the decision this entry belongs to. */
  superseded: boolean;
  /** An independent entry whose status contradicted the primary verdict of its time. */
  disagreed: boolean;
  replace?: boolean;
}

/**
 * The current decision on a finding: the latest primary verdict (its status,
 * rationale and evidence), with what the independent reviews make of it.
 * `status` is the effective status: `needs_review` while a disagreement is
 * open.
 */
export interface CurrentVerdict extends VerdictRecord {
  /** The status of the latest primary verdict. */
  primaryStatus: VerdictStatus;
  /** Every entry of the finding, oldest first. Nothing is ever removed. */
  history: VerdictHistoryItem[];
  /**
   * True when an independent reviewer whose label differs from every primary
   * label agreed with the latest primary verdict, after the last dissent.
   */
  independentlyReviewed: boolean;
  /** The independent review that made `independentlyReviewed` true. */
  independentReview?: VerdictHistoryItem;
  /** An independent reviewer disagreed at some point (shown even once resolved). */
  disputed: boolean;
  /** The latest dissenting independent review. */
  dissent?: VerdictHistoryItem;
  /** A dissent that no qualifying independent agreement has answered yet. */
  disputeOpen: boolean;
  /** Set when the decision is a person's (`--role human` on the CLI). */
  decidedByPerson?: { reviewer: string; at: string };
}

export type CurrentVerdicts = Record<string, CurrentVerdict>;

/** How the audit root of a loaded run was established. */
export type RunRootSource =
  /** The run directory is `<root>/.audit/<run-id>`: the root is where it sits. */
  | "location"
  /** The user named the root on this command line (`--root`, MCP `root`). */
  | "confirmed"
  /**
   * run.json names a directory inside the one that contains the run: an
   * audit of part of a project (`code-audit skill <dir>` writes its run to
   * `<cwd>/.audit`). Taking it cannot leave the directory the location shows.
   */
  | "recorded-inside";

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
  /** Invalid entries of verdicts.json that were ignored; also in `notices`. */
  verdictWarnings?: string[];
  /** Shared across copies of this object; holds what is loaded on demand. */
  session: RunSession;
}

interface RunSession {
  /** `--rules` of this command line. */
  rulesDir?: string;
  ruleSet?: RuleSet | null;
  rootProblem?: string;
  /** Error code of `rootProblem` (default ROOT_UNCONFIRMED). */
  rootProblemCode?: string;
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
    (readRunFile(runDir, "verdicts.json", VerdictsSchema) as VerdictsDocument | undefined) ?? {
      schemaVersion: VERDICTS_SCHEMA_VERSION,
      runId: path.basename(runDir),
      entries: [],
    }
  );
}

/**
 * Turn on strict evidence for every later verdict of a run (`audit_start`
 * with `strict_evidence`). Writes verdicts.json of the new run directory,
 * which must be canonical and hold no verdicts yet.
 */
export function initRunVerdicts(runDir: string, runId: string, settings: { strictEvidence: boolean }): void {
  const existing = readVerdicts(runDir);
  writeJson(runDir, "verdicts.json", {
    schemaVersion: VERDICTS_SCHEMA_VERSION,
    runId,
    ...(settings.strictEvidence || existing.strictEvidence ? { strictEvidence: true } : {}),
    entries: existing.entries,
  } satisfies VerdictsDocument);
}

/** The label a verdict entry is known by (stored and shown as given). */
export function verdictLabel(entry: Pick<VerdictRecord, "reviewer" | "actor">): string {
  return (entry.reviewer || entry.actor || UNNAMED_REVIEWER).trim() || UNNAMED_REVIEWER;
}

/**
 * The form in which reviewer labels are compared: NFKC, without zero-width,
 * soft-hyphen and bidi control characters, trimmed and case-folded, so `P`,
 * `p` and `p` followed by a zero-width space are one reviewer.
 */
export function normalizeReviewerLabel(label: string): string {
  return label
    .normalize("NFKC")
    .replace(/[\u00AD\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/g, "")
    .trim()
    .toLowerCase();
}

/** Roles whose entry is a decision (the latest one is current). */
function isDecisionRole(role: VerdictRole): boolean {
  return role === "primary" || role === "human";
}

/**
 * Whether an independent reviewer's status contradicts the primary one.
 * Equal statuses agree, and so do confirmed and likely (both say the finding
 * is real); every other difference - confirmed or likely against
 * false_positive, anything against proof_gap or needs_review - is a
 * disagreement.
 */
export function verdictsDisagree(primary: VerdictStatus, independent: VerdictStatus): boolean {
  if (primary === independent) return false;
  const real = (status: VerdictStatus): boolean => status === "confirmed" || status === "likely";
  return !(real(primary) && real(independent));
}

/**
 * The current decision of one finding from its entries, oldest first.
 *
 * - The latest primary entry is the decision (a schemaVersion 1 entry is a
 *   primary one).
 * - An independent entry disagrees when its status contradicts the primary
 *   decision of its time (`verdictsDisagree`). A disagreement is never
 *   erased: it stays open, and the status is `needs_review`, until an
 *   independent reviewer whose label differs from every primary label of the
 *   finding agrees with the latest primary decision, after the last dissent.
 * - Only such an agreement makes `independentlyReviewed` true.
 */
function foldVerdicts(entries: readonly VerdictRecord[]): CurrentVerdict {
  let latestPrimary = -1;
  const primaryLabels = new Set<string>();
  entries.forEach((entry, index) => {
    if (isDecisionRole(entry.role ?? "primary")) {
      latestPrimary = index;
      primaryLabels.add(normalizeReviewerLabel(verdictLabel(entry)));
    }
  });
  // A file without any primary entry (hand-made): its first entry decides.
  if (latestPrimary < 0) {
    latestPrimary = 0;
    primaryLabels.add(normalizeReviewerLabel(verdictLabel(entries[0] as VerdictRecord)));
  }
  const decision = entries[latestPrimary] as VerdictRecord;
  let primaryOfTime: VerdictRecord | undefined;
  let lastDissent = -1;
  const history: VerdictHistoryItem[] = entries.map((entry, index) => {
    const stored: VerdictRole = entry.role ?? "primary";
    const role: VerdictRole = index === latestPrimary && stored === "independent" ? "primary" : stored;
    if (isDecisionRole(role)) primaryOfTime = entry;
    const disagreed =
      role === "independent" &&
      primaryOfTime !== undefined &&
      verdictsDisagree(primaryOfTime.status, entry.status);
    if (disagreed) lastDissent = index;
    return {
      reviewer: verdictLabel(entry),
      role,
      status: entry.status,
      at: entry.at,
      rationale: entry.rationale,
      ...(entry.independence ? { independence: entry.independence } : {}),
      superseded: index < latestPrimary,
      disagreed,
      ...(entry.replace ? { replace: true } : {}),
    };
  });
  let independentReview: VerdictHistoryItem | undefined;
  history.forEach((item, index) => {
    if (
      item.role === "independent" &&
      index > latestPrimary &&
      index > lastDissent &&
      !primaryLabels.has(normalizeReviewerLabel(item.reviewer)) &&
      !verdictsDisagree(decision.status, item.status)
    ) {
      independentReview ??= item;
    }
  });
  // A person's decision (CLI `--role human`) settles every dispute.
  const byPerson = (decision.role ?? "primary") === "human";
  const disputeOpen = !byPerson && lastDissent >= 0 && independentReview === undefined;
  const { role: _role, independence: _independence, replace: _replace, ...base } = decision;
  return {
    ...base,
    role: byPerson ? "human" : "primary",
    ...(byPerson ? { decidedByPerson: { reviewer: verdictLabel(decision), at: decision.at } } : {}),
    status: disputeOpen ? "needs_review" : decision.status,
    primaryStatus: decision.status,
    history,
    independentlyReviewed: independentReview !== undefined,
    ...(independentReview ? { independentReview } : {}),
    disputed: lastDissent >= 0,
    ...(lastDissent >= 0 ? { dissent: history[lastDissent] as VerdictHistoryItem } : {}),
    disputeOpen,
  };
}

/**
 * Why a stored `role: "human"` entry is not a decision this tool wrote, or
 * undefined when it is one: it must have a reviewer label, the replace flag
 * recorded at write time, and - dismissing a high or critical finding - the
 * evidence `assertDismissalJustified` requires. verdicts.json lives in the
 * run directory; whoever can edit it can still forge any other record.
 */
function invalidHumanEntry(entry: VerdictRecord, finding: Finding | undefined): string | undefined {
  if (entry.role !== "human") return undefined;
  if (!entry.reviewer?.trim()) return "no reviewer label";
  if (entry.replace !== true) return "no replace flag";
  if (
    finding &&
    entry.status === "false_positive" &&
    finding.kind !== "hotspot" &&
    severityAtLeast(finding.severity, DISMISSAL_EVIDENCE_SEVERITY)
  ) {
    const longEnough = entry.rationale.replace(/\s+/g, " ").length >= DISMISSAL_MIN_RATIONALE;
    const evidence =
      entry.control !== undefined ||
      (entry.evidenceLines ?? []).some((line) => line.trim().length >= 3) ||
      LOCATION_REFERENCE.test(entry.rationale);
    if (!longEnough || !evidence) return "a high or critical dismissal without the required evidence";
  }
  return undefined;
}

/** Human entries of a document that are not valid, with the reason. */
export function invalidHumanEntries(
  document: VerdictsDocument,
  findings: readonly Finding[] = [],
): Array<{ index: number; findingId?: string; reason: string }> {
  const byFingerprint = new Map(findings.map((finding) => [finding.fingerprint, finding]));
  const result: Array<{ index: number; findingId?: string; reason: string }> = [];
  document.entries.forEach((entry, index) => {
    const reason = invalidHumanEntry(entry, byFingerprint.get(entry.fingerprint));
    if (reason) result.push({ index, ...(entry.findingId ? { findingId: entry.findingId } : {}), reason });
  });
  return result;
}

/**
 * The current decision of every fingerprint. With `findings`, a human entry
 * that `invalidHumanEntry` rejects is left out (and reported by `loadRun`).
 */
export function currentVerdicts(document: VerdictsDocument, findings?: readonly Finding[]): CurrentVerdicts {
  const ignored = new Set(invalidHumanEntries(document, findings ?? []).map((item) => item.index));
  // No prototype: a fingerprint is a key chosen by a file in the repository.
  const grouped = new Map<string, VerdictRecord[]>();
  for (const [index, entry] of document.entries.entries()) {
    if (ignored.has(index)) continue;
    const list = grouped.get(entry.fingerprint);
    if (list) list.push(entry);
    else grouped.set(entry.fingerprint, [entry]);
  }
  const current = Object.create(null) as CurrentVerdicts;
  for (const [fingerprint, entries] of grouped) current[fingerprint] = foldVerdicts(entries);
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

/** "archive" or "git" when skill.json of the run says its target was a temporary copy. */
function temporaryTargetKind(runDir: string): "archive" | "git" | undefined {
  try {
    const document = JSON.parse(fs.readFileSync(path.join(runDir, "skill.json"), "utf8")) as { target?: { kind?: unknown } };
    const kind = document.target?.kind;
    return kind === "archive" || kind === "git" ? kind : undefined;
  } catch {
    return undefined;
  }
}

function isDirectorySafe(target: string): boolean {
  try {
    return fs.statSync(target).isDirectory();
  } catch {
    return false;
  }
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
  // `code-audit skill` / audit_skill of an archive or a git URL scans a
  // temporary copy that is deleted when the scan ends: the findings stay
  // readable, the files do not. No other root is substituted.
  const temporary = temporaryTargetKind(resolved.runDir);
  if (temporary !== undefined && (recordedRoot === undefined || !isDirectorySafe(recordedRoot))) {
    session.rootProblem =
      `this run's files were unpacked from ${temporary === "git" ? "a git clone" : "an archive"} to a temporary directory that no longer exists; ` +
      "the findings can be read (audit_findings, the reports) but the files cannot be read, searched or cited as evidence. " +
      "To review the files, unpack or clone the package into a directory and run audit_skill on that directory.";
    session.rootProblemCode = "RUN_FILES_DELETED";
    return { root: undefined, recordedRoot };
  }
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
    // The run's finding paths are relative to the root it recorded. A
    // recorded root inside the derived one is used, so that reading files,
    // checking evidence and adding findings agree with those paths.
    if (recordedReal !== undefined && recordedReal !== derived && isInsideCanonical(derived, recordedReal) && isDirectorySafe(recordedReal)) {
      return { root: recordedReal, rootSource: "recorded-inside", recordedRoot };
    }
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
      run.session.rootProblemCode ?? "ROOT_UNCONFIRMED",
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
  const allRecords = [...findings, ...hotspots];
  const verdictWarnings = invalidHumanEntries(verdictsDocument, allRecords).map(
    (item) =>
      `ignored an invalid human decision entry${item.findingId ? ` for ${printable(item.findingId, 40)}` : ""} ` +
      `in verdicts.json (${item.reason}); a person's decision is written only by the CLI`,
  );
  for (const warning of verdictWarnings) notices.push(warning);
  return {
    runDir,
    runId,
    ...establishRoot(resolved, run, options, notices, session),
    run,
    findings,
    hotspots,
    coverage,
    state,
    verdicts: currentVerdicts(verdictsDocument, allRecords),
    verdictsDocument,
    notices,
    verdictWarnings,
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
/** Characters of a rationale carried in a finding's `review.history`. */
const HISTORY_RATIONALE_MAX = 300;
/** Entries of `review.history` carried in a finding (the newest). */
const HISTORY_SHOWN = 50;

/** A history item for findings.json and the reports: redacted, short. */
function historyView(item: VerdictHistoryItem): VerdictHistoryItem {
  return {
    ...item,
    reviewer: redactText(item.reviewer).slice(0, 200),
    rationale: redactText(item.rationale.slice(0, HISTORY_RATIONALE_MAX)),
  };
}

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
      // Written redacted since schemaVersion 2; older files are redacted here.
      rationale: redactText(verdict.rationale),
      ...(verdict.reviewer ? { reviewer: redactText(verdict.reviewer) } : {}),
      ...(verdict.actor ? { actor: redactText(verdict.actor) } : {}),
      at: verdict.at,
      ...(verdict.evidenceLines ? { evidenceLines: verdict.evidenceLines } : {}),
      ...(verdict.trace ? { trace: verdict.trace } : {}),
      ...(verdict.conditions ? { conditions: verdict.conditions } : {}),
      ...(verdict.control ? { control: verdict.control } : {}),
      ...(verdict.missing ? { missing: verdict.missing } : {}),
      ...(verdict.cwe ? { cwe: verdict.cwe } : {}),
      ...(verdict.severityOverride ? { severityOverride: verdict.severityOverride } : {}),
      primaryStatus: verdict.primaryStatus,
      history: verdict.history.slice(-HISTORY_SHOWN).map(historyView),
      independentlyReviewed: verdict.independentlyReviewed,
      ...(verdict.independentReview
        ? { independentReview: historyView(verdict.independentReview), independentStatus: verdict.independentReview.status }
        : {}),
      disputed: verdict.disputed,
      ...(verdict.dissent ? { dissent: historyView(verdict.dissent) } : {}),
      disputeOpen: verdict.disputeOpen,
      ...(verdict.decidedByPerson
        ? { decidedByPerson: { reviewer: redactText(verdict.decidedByPerson.reviewer).slice(0, 200), at: verdict.decidedByPerson.at } }
        : {}),
    },
  });
}

/** True when a qualifying independent reviewer agreed with the current decision. */
export function isIndependentlyReviewed(verdict: CurrentVerdict | undefined): boolean {
  return verdict?.independentlyReviewed === true;
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
  hasControl = false,
): void {
  if (status !== "false_positive" || finding.kind === "hotspot") return;
  if (!severityAtLeast(finding.severity, DISMISSAL_EVIDENCE_SEVERITY)) return;
  const problems: string[] = [];
  if (rationale.replace(/\s+/g, " ").length < DISMISSAL_MIN_RATIONALE) {
    problems.push(`a rationale of at least ${DISMISSAL_MIN_RATIONALE} characters that says why the code is safe`);
  }
  // A checked `control` location is a file:line reference.
  const hasEvidence = hasControl || (evidenceLines ?? []).some((line) => line.trim().length >= 3);
  if (!hasEvidence && !LOCATION_REFERENCE.test(rationale)) {
    problems.push(
      "evidence: evidenceLines (CLI: --evidence-line) quoting the code that shows it, a control {file, line, note} naming the protecting code, or a file:line reference in the rationale",
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
  /**
   * `primary` (default): the decision. `independent`: a second reviewer who
   * did not see the primary decision checks it; see `recordVerdict`.
   */
  role?: VerdictRole;
  /** Required with role independent: a fresh sub-agent, or a same-session devil's-advocate pass. */
  independence?: Independence;
  /**
   * A primary verdict that replaces the decision of another reviewer on a
   * finding that has an independent review is refused unless this is true.
   */
  replace?: boolean;
  /** Source-to-sink path; every location must exist in the audit root. */
  trace?: TraceStep[];
  conditions?: VerdictConditions;
  /** The code that makes a false positive safe; the location must exist. */
  control?: VerdictControl;
  /** For `proof_gap`: the fact that could not be established (>= 20 characters). */
  missing?: string;
  /** `CWE-<n>`: the weakness the reviewer sees. */
  cwe?: string;
  /** A reviewer's view of the severity; recorded and shown, never counted. */
  severityOverride?: { severity: Severity; reason: string };
  /**
   * Require structured evidence for this verdict (`trace` for confirmed,
   * `control` for false_positive, `missing` for proof_gap). A run started
   * with strict evidence requires it for every verdict; `false` here does
   * not turn that off.
   */
  strictEvidence?: boolean;
}

export interface RecordVerdictResult {
  runId: string;
  runDir: string;
  fingerprint: string;
  findingId: string;
  /** The current status after this verdict (see `role`). */
  status: VerdictStatus;
  rationale: string;
  /** Role this verdict was recorded with. */
  role: VerdictRole;
  /** The status this call asked for; differs from `status` after a disagreement. */
  requestedStatus: VerdictStatus;
  /** True when a qualifying independent reviewer agreed with the current decision. */
  independentlyReviewed: boolean;
  /** Set while an independent review's disagreement is open. */
  disagreement?: string;
  /** An independent reviewer disagreed at some point (also once resolved). */
  disputed: boolean;
  /** Whether structured evidence was required for this verdict. */
  strictEvidence: boolean;
  history: number;
  reviewed: number;
  total: number;
  /** Derived files re-rendered with this verdict applied. */
  refreshed: string[];
  notices: string[];
  /** See `dismissedFields`: set while serious findings are dismissed. */
  dismissedWarning?: string;
}

/** Label of a reviewer who gave none. */
export const UNNAMED_REVIEWER = "unnamed reviewer";
/** Characters kept of a rationale, `missing` or a severity override reason. */
const REVIEWER_RATIONALE_MAX = MAX_VERDICT_TEXT;
/** Characters kept of a note. */
const EVIDENCE_TEXT_MAX = 2000;
/** Evidence lines kept per verdict, and characters per line. */
const MAX_EVIDENCE_LINES = 20;
const EVIDENCE_LINE_MAX = 1000;

const TRACE_EXAMPLE =
  '[{"file":"src/routes.py","line":12,"role":"source","note":"name = request.args[\\"name\\"]"},' +
  '{"file":"src/db.py","line":40,"role":"sink","note":"cursor.execute(sql)"}]';
const CONTROL_EXAMPLE =
  '{"file":"src/db.py","line":38,"note":"name is passed as a bound query parameter"}';
const MISSING_EXAMPLE =
  '"whether /admin/export can be reached without the admin role"';

interface StructuredEvidence {
  trace?: TraceStep[];
  conditions?: VerdictConditions;
  control?: VerdictControl;
  missing?: string;
  cwe?: string;
  severityOverride?: { severity: Severity; reason: string };
}

function evidenceError(message: string): never {
  throw new RunStoreError(message, "INVALID_EVIDENCE");
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Agent-written text stored with a verdict: trimmed, redacted, cut. */
function evidenceText(value: unknown, label: string, max = EVIDENCE_TEXT_MAX): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string") evidenceError(`${label} must be a string`);
  const text = value.trim();
  return text ? redactText(text).slice(0, max) : undefined;
}

function locationShape(
  value: unknown,
  label: string,
  example: string,
): { file: string; line: number } {
  if (!isPlainRecord(value)) {
    evidenceError(`${label} must be an object like ${example}`);
  }
  if (typeof value.file !== "string" || value.file.trim() === "") {
    evidenceError(
      `${label}.file is missing: give the path relative to the audit root, as audit_findings and audit_read show it (for example "src/app.py")`,
    );
  }
  const file = value.file.trim();
  if (typeof value.line !== "number" || !Number.isInteger(value.line) || value.line < 1) {
    evidenceError(`${label}.line is missing or not a line number: give the line (an integer >= 1) in ${printable(file, 200)}`);
  }
  return { file, line: value.line };
}

/**
 * Check the shape of the structured fields of a verdict and bring them into
 * the stored form. Each message names the field and says how to fill it:
 * small models rely on that to correct a call.
 */
function normalizeEvidence(input: RecordVerdictInput): StructuredEvidence {
  const evidence: StructuredEvidence = {};
  if (input.trace !== undefined && input.trace !== null) {
    if (!Array.isArray(input.trace)) {
      evidenceError(`trace must be a list of steps, for example ${TRACE_EXAMPLE}`);
    }
    if (input.trace.length > MAX_TRACE_STEPS) {
      evidenceError(
        `trace has ${input.trace.length} steps; at most ${MAX_TRACE_STEPS} are accepted: keep the source, the sink and the steps in between that matter`,
      );
    }
    const steps: TraceStep[] = [];
    input.trace.forEach((step: unknown, index) => {
      const label = `trace[${index}]`;
      const location = locationShape(step, label, TRACE_EXAMPLE);
      const role = (step as Record<string, unknown>).role;
      if (role !== "source" && role !== "propagation" && role !== "sink") {
        evidenceError(
          `${label}.role must be "source", "propagation" or "sink" (got ${printable(JSON.stringify(role) ?? "nothing", 40)}): "source" is where untrusted input enters, "sink" the dangerous call`,
        );
      }
      const note = evidenceText((step as Record<string, unknown>).note, `${label}.note`);
      steps.push({ ...location, role, ...(note ? { note } : {}) });
    });
    if (steps.length > 0) evidence.trace = steps;
  }
  if (input.conditions !== undefined && input.conditions !== null) {
    const conditions: unknown = input.conditions;
    if (!isPlainRecord(conditions)) {
      evidenceError('conditions must be an object like {"auth":"user","userInteraction":false}');
    }
    const result: VerdictConditions = {};
    if (conditions.auth !== undefined) {
      if (!["none", "user", "admin", "unknown"].includes(conditions.auth as string)) {
        evidenceError(
          'conditions.auth must be "none" (no login), "user" (any logged-in user), "admin" or "unknown"',
        );
      }
      result.auth = conditions.auth as VerdictConditions["auth"];
    }
    if (conditions.userInteraction !== undefined) {
      if (typeof conditions.userInteraction !== "boolean") {
        evidenceError("conditions.userInteraction must be true or false: does the attack need a victim to act?");
      }
      result.userInteraction = conditions.userInteraction;
    }
    const note = evidenceText(conditions.note, "conditions.note");
    if (note) result.note = note;
    if (Object.keys(result).length > 0) evidence.conditions = result;
  }
  if (input.control !== undefined && input.control !== null) {
    const location = locationShape(input.control, "control", CONTROL_EXAMPLE);
    const note = evidenceText((input.control as unknown as Record<string, unknown>).note, "control.note");
    if (!note) {
      evidenceError(
        "control.note is missing: say in one sentence how the code at control.file:control.line makes the finding safe",
      );
    }
    evidence.control = { ...location, note };
  }
  if (input.missing !== undefined && input.missing !== null) {
    const missing = evidenceText(input.missing, "missing", REVIEWER_RATIONALE_MAX);
    if (!missing || missing.replace(/\s+/g, " ").length < MIN_MISSING_LENGTH) {
      evidenceError(
        `missing must say in at least ${MIN_MISSING_LENGTH} characters which fact you could not establish, for example ${MISSING_EXAMPLE}`,
      );
    }
    evidence.missing = missing;
  }
  if (input.cwe !== undefined && input.cwe !== null && String(input.cwe).trim() !== "") {
    const cwe = String(input.cwe).trim().toUpperCase();
    if (!/^CWE-\d{1,6}$/.test(cwe)) {
      evidenceError(`cwe must look like CWE-89 (got ${printable(String(input.cwe), 40)})`);
    }
    evidence.cwe = cwe;
  }
  if (input.severityOverride !== undefined && input.severityOverride !== null) {
    const override: unknown = input.severityOverride;
    if (!isPlainRecord(override)) {
      evidenceError('severityOverride must be an object like {"severity":"medium","reason":"needs an admin session"}');
    }
    if (!(SEVERITIES as readonly unknown[]).includes(override.severity)) {
      evidenceError(`severityOverride.severity must be one of ${SEVERITIES.join(", ")}`);
    }
    const reason = evidenceText(override.reason, "severityOverride.reason");
    if (!reason) {
      evidenceError("severityOverride.reason is missing: say why the severity differs from the rule's");
    }
    evidence.severityOverride = { severity: override.severity as Severity, reason };
  }
  return evidence;
}

/**
 * Fields that belong to some statuses only: `control` to false_positive,
 * `missing` to proof_gap, `severityOverride` to confirmed and likely
 * (findings that are real). Anything else is refused, so a report never
 * shows evidence that does not fit the decision.
 */
function assertFieldsFitStatus(status: VerdictStatus, evidence: StructuredEvidence): void {
  const problems: string[] = [];
  if (evidence.control && status !== "false_positive") {
    problems.push(`control belongs to false_positive only (this verdict is ${status}): remove it`);
  }
  if (evidence.missing && status !== "proof_gap") {
    problems.push(`missing belongs to proof_gap only (this verdict is ${status}): remove it, or record proof_gap`);
  }
  if (evidence.severityOverride && status !== "confirmed" && status !== "likely") {
    problems.push(`severityOverride belongs to confirmed and likely only (this verdict is ${status}): remove it`);
  }
  if (problems.length > 0) evidenceError(problems.join("; "));
}

/** With strict evidence: what each status must carry. */
function assertStrictEvidence(status: VerdictStatus, evidence: StructuredEvidence): void {
  const prefix = "strict evidence is on for this verdict: ";
  const roles = new Set((evidence.trace ?? []).map((step) => step.role));
  if (status === "confirmed") {
    const absent = (["source", "sink"] as const).filter((role) => !roles.has(role));
    if (absent.length === 0) return;
    throw new RunStoreError(
      `${prefix}a confirmed verdict needs trace with at least one step of role "source" and one of role "sink" ` +
        `(no ${absent.map((role) => `"${role}"`).join(" and no ")} step given). Example: trace: ${TRACE_EXAMPLE}. ` +
        "If you cannot show both ends, record proof_gap with missing set to what you could not establish",
      "EVIDENCE_REQUIRED",
    );
  }
  if (status === "likely" && !roles.has("sink")) {
    throw new RunStoreError(
      `${prefix}a likely verdict needs trace with at least one step of role "sink" (the dangerous call you checked), ` +
        `for example trace: [{"file":"src/db.py","line":40,"role":"sink","note":"cursor.execute(sql)"}]. ` +
        "If you have not looked at the sink, record proof_gap with missing set to what you could not establish",
      "EVIDENCE_REQUIRED",
    );
  }
  if (status === "false_positive" && !evidence.control) {
    throw new RunStoreError(
      `${prefix}a false_positive verdict needs control: the file, line and note of the code that makes it safe, ` +
        `for example control: ${CONTROL_EXAMPLE}. If you cannot point at that code, use needs_review or proof_gap`,
      "EVIDENCE_REQUIRED",
    );
  }
  if (status === "proof_gap" && !evidence.missing) {
    throw new RunStoreError(
      `${prefix}a proof_gap verdict needs missing: the fact you could not establish, in at least ${MIN_MISSING_LENGTH} characters, ` +
        `for example missing: ${MISSING_EXAMPLE}`,
      "EVIDENCE_REQUIRED",
    );
  }
}

/** Lines of a text: a trailing line break does not start another line. */
export function textLineCount(text: string): number {
  if (text === "") return 0;
  const lines = splitLines(text);
  return lines[lines.length - 1] === "" ? lines.length - 1 : lines.length;
}

/**
 * Every `trace` step and the `control` must name a line that exists: a file
 * the run itself scanned (coverage.json `scannedFiles`: the inventory of the
 * scan, with its own options such as `--untrusted`), reached through the path
 * jail of the audit root (no absolute path, no `..` or symbolic link that
 * leaves the root), still a regular text file, and a line within it. Returns
 * the evidence with each file as its path relative to the root. Throws
 * `EVIDENCE_LOCATION_INVALID` naming every bad item.
 */
function checkEvidenceLocations(run: LoadedRun, evidence: StructuredEvidence): StructuredEvidence {
  const items: Array<{ label: string; file: string; line: number; set: (file: string) => void }> = [];
  const trace = evidence.trace?.map((step) => ({ ...step }));
  trace?.forEach((step, index) =>
    items.push({ label: `trace[${index}]`, file: step.file, line: step.line, set: (file) => (step.file = file) }),
  );
  const control = evidence.control ? { ...evidence.control } : undefined;
  if (control) {
    items.push({ label: "control", file: control.file, line: control.line, set: (file) => (control.file = file) });
  }
  if (items.length === 0) return evidence;
  const root = requireAuditRoot(run);
  const scanned = new Set(requireCoverage(run).scannedFiles.map((entry) => entry.path));
  const lineCounts = new Map<string, number>();
  const problems: string[] = [];
  for (const item of items) {
    const shown = `${item.label} (${printable(item.file, 200)}:${item.line})`;
    if (path.isAbsolute(item.file) || path.win32.isAbsolute(item.file)) {
      problems.push(`${shown}: an absolute path is not accepted, use the path relative to the audit root`);
      continue;
    }
    let resolved: string;
    try {
      resolved = resolveInside(root, item.file);
    } catch (error) {
      // The message of the jail names the resolved target; it is not echoed.
      problems.push(
        error instanceof PathJailError
          ? `${shown}: the path leaves the audit root`
          : `${shown}: the path cannot be resolved inside the audit root`,
      );
      continue;
    }
    const relPath = toPosixRelative(root, resolved);
    if (!scanned.has(relPath)) {
      problems.push(`${shown}: not a file this run scanned (missing, excluded, binary, oversized or created after the scan)`);
      continue;
    }
    let count = lineCounts.get(relPath);
    if (count === undefined) {
      let stat: fs.Stats;
      try {
        stat = fs.statSync(resolved);
      } catch {
        problems.push(`${shown}: no such file under the audit root ${printable(root, 200)} (paths are relative to it)`);
        continue;
      }
      if (!stat.isFile() || stat.size > MAX_TEXT_FILE_BYTES) {
        problems.push(`${shown}: not a regular text file within the read limit`);
        continue;
      }
      count = textLineCount(fs.readFileSync(resolved, "utf8"));
      lineCounts.set(relPath, count);
    }
    if (item.line > count) {
      problems.push(`${shown}: line ${item.line} is beyond the end of ${relPath} (${count} lines)`);
      continue;
    }
    item.set(relPath);
  }
  if (problems.length > 0) {
    const more = problems.length > 5 ? `; ${problems.length - 5} more` : "";
    throw new RunStoreError(
      `${problems.slice(0, 5).join("; ")}${more}. Every trace step and the control must name a file of the audit root ` +
        "by its path relative to the root (as audit_findings and audit_read show it) and a line that exists in that file. " +
        "Check the location with audit_read, fix the item named here and call audit_verdict again",
      "EVIDENCE_LOCATION_INVALID",
    );
  }
  return { ...evidence, ...(trace ? { trace } : {}), ...(control ? { control } : {}) };
}

/** Name of the lock file that serialises verdict writes of a run. */
export const VERDICT_LOCK_FILE = "verdicts.json.lock";
/** How long a verdict waits for another writer of the same run. */
const LOCK_TIMEOUT_MS = 15_000;
/** A lock not refreshed for this long is left over from a writer that died. */
const LOCK_STALE_MS = 120_000;

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/**
 * Run `fn` holding the verdict lock of a run directory: a lock file created
 * with O_EXCL (which also refuses a planted symbolic link), retried until
 * `LOCK_TIMEOUT_MS`. Two processes (an agent and its independent sub-agent
 * with its own MCP server) then read, merge and write verdicts.json one
 * after the other instead of overwriting each other.
 */
export function withRunLock<T>(runDir: string, fn: () => T): T {
  const lock = path.join(runDir, VERDICT_LOCK_FILE);
  const token = `${process.pid}:${crypto.randomBytes(12).toString("hex")}`;
  const deadline = Date.now() + LOCK_TIMEOUT_MS;
  const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;
  /** The token in a lock file, or undefined when it cannot be read as one. */
  const tokenIn = (file: string): string | undefined => {
    let fd: number | undefined;
    try {
      fd = fs.openSync(file, fs.constants.O_RDONLY | NOFOLLOW);
      const buffer = Buffer.alloc(200);
      const read = fs.readSync(fd, buffer, 0, buffer.length, 0);
      return buffer.subarray(0, read).toString("utf8").trim();
    } catch {
      return undefined;
    } finally {
      if (fd !== undefined) fs.closeSync(fd);
    }
  };
  /** A lock path that this tool never writes: refused at once, with what to do. */
  const invalid = (what: string): never => {
    throw new RunStoreError(
      `the verdict lock ${lock} is ${what}, not a lock file this tool wrote; nothing was recorded. ` +
        "Remove it (a person, not an agent: check first that it is not yours) and record the verdict again",
      "RUN_LOCK_INVALID",
    );
  };
  for (;;) {
    let fd: number | undefined;
    try {
      fd = fs.openSync(lock, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | NOFOLLOW, 0o600);
      fs.writeSync(fd, `${token}\n`);
      fs.closeSync(fd);
      break;
    } catch (error) {
      if (fd !== undefined) fs.closeSync(fd);
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
        throw new RunStoreError(`cannot create the verdict lock ${lock}: ${(error as Error).message}`, "RUN_STORE_WRITE");
      }
    }
    let stat: fs.Stats;
    try {
      stat = fs.lstatSync(lock);
    } catch {
      continue; // Released meanwhile.
    }
    if (stat.isSymbolicLink()) invalid("a symbolic link");
    if (stat.isDirectory()) invalid("a directory");
    if (!stat.isFile()) invalid("not a regular file");
    if (Date.now() - stat.mtimeMs > LOCK_STALE_MS) {
      // Retry at once only when this writer removed the stale lock; when
      // another writer is taking over, wait like any other writer.
      if (takeOverStaleLock(lock, token, tokenIn)) continue;
    }
    if (Date.now() > deadline) {
      throw new RunStoreError(
        `another process is writing verdicts of this run (lock file ${lock}, held by ${printable(tokenIn(lock) ?? "an unknown writer", 60)}); ` +
          `call audit_verdict again in a moment. A lock its writer has not refreshed for ${LOCK_STALE_MS / 1000} seconds is taken over`,
        "RUN_LOCKED",
      );
    }
    sleepSync(15 + Math.floor(Math.random() * 20));
  }
  // While the write runs (synchronously), a worker thread refreshes the
  // lock's mtime every LOCK_REFRESH_MS, so a slow write is never judged
  // stale. It only touches a lock that still holds this writer's token.
  const heartbeat = startLockHeartbeat(lock, token);
  try {
    return fn();
  } finally {
    heartbeat?.terminate().catch(() => undefined);
    // Only our own lock is removed.
    if (tokenIn(lock) === token) {
      try {
        fs.unlinkSync(lock);
      } catch {
        // Already gone.
      }
    }
  }
}

/** A takeover mutex older than this was left by a writer that died during a takeover. */
const TAKEOVER_STALE_MS = 5_000;

/**
 * Remove a lock that nobody refreshed for LOCK_STALE_MS (its writer died),
 * so that the normal O_EXCL create can run again.
 *
 * Takeovers are serialised by `<lock>.takeover`, created with O_EXCL: under
 * it, the lock is checked again - a live writer may have replaced the stale
 * lock since this writer looked - and only a lock that is still stale is
 * moved, to a name unique to this writer (`<lock>.stale.<token>`; the lock
 * path is never renamed over). The moved file must still hold the token
 * read before the move; if it does not, it is put back with link(), which
 * never overwrites a lock that appeared meanwhile.
 */
function takeOverStaleLock(
  lock: string,
  token: string,
  tokenIn: (file: string) => string | undefined,
): boolean {
  const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;
  const mutex = `${lock}.takeover`;
  let fd: number | undefined;
  try {
    fd = fs.openSync(mutex, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | NOFOLLOW, 0o600);
    fs.writeSync(fd, `${token}\n`);
    fs.closeSync(fd);
    fd = undefined;
  } catch (error) {
    if (fd !== undefined) fs.closeSync(fd);
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
      throw new RunStoreError(`cannot create the lock takeover file ${mutex}: ${(error as Error).message}`, "RUN_STORE_WRITE");
    }
    // Another writer is taking over, or one died doing so.
    let stat: fs.Stats | undefined;
    try {
      stat = fs.lstatSync(mutex);
    } catch {
      return false; // Gone already.
    }
    if (!stat.isFile()) {
      const what = stat.isSymbolicLink() ? "a symbolic link" : stat.isDirectory() ? "a directory" : "not a regular file";
      throw new RunStoreError(
        `the lock takeover file ${mutex} is ${what}, not one this tool wrote; nothing was recorded. ` +
          "Remove it (a person, not an agent: check first that it is not yours) and record the verdict again",
        "RUN_LOCK_INVALID",
      );
    }
    // A takeover takes milliseconds: one older than TAKEOVER_STALE_MS was
    // left by a writer that died during it.
    if (Date.now() - stat.mtimeMs > TAKEOVER_STALE_MS) fs.rmSync(mutex, { force: true });
    return false;
  }
  try {
    let stat: fs.Stats;
    try {
      stat = fs.lstatSync(lock);
    } catch {
      return true; // Released meanwhile: try to create it now.
    }
    if (!stat.isFile() || Date.now() - stat.mtimeMs <= LOCK_STALE_MS) return false;
    const stale = tokenIn(lock);
    const moved = `${lock}.stale.${token.replace(/[^A-Za-z0-9]/g, "")}`;
    try {
      fs.renameSync(lock, moved);
    } catch {
      return true; // Released meanwhile.
    }
    if (tokenIn(moved) !== stale) {
      try {
        fs.linkSync(moved, lock);
      } catch {
        // A lock appeared meanwhile; it stands.
      }
    }
    fs.rmSync(moved, { force: true });
    return true;
  } finally {
    if (tokenIn(mutex) === token) fs.rmSync(mutex, { force: true });
  }
}

/** How often a held lock is refreshed. */
export const LOCK_REFRESH_MS = 10_000;

/** `CODE_AUDIT_LOCK_REFRESH_MS` (tests only) shortens the refresh interval; never longer than the default. */
function lockRefreshMs(): number {
  const value = Number(process.env.CODE_AUDIT_LOCK_REFRESH_MS);
  return Number.isFinite(value) && value >= 20 && value < LOCK_REFRESH_MS ? value : LOCK_REFRESH_MS;
}

const HEARTBEAT_SOURCE = `
const { workerData } = require("node:worker_threads");
const fs = require("node:fs");
setInterval(() => {
  try {
    const fd = fs.openSync(workerData.lock, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const buffer = Buffer.alloc(200);
    const read = fs.readSync(fd, buffer, 0, buffer.length, 0);
    fs.closeSync(fd);
    if (buffer.subarray(0, read).toString("utf8").trim() !== workerData.token) return;
    const now = new Date();
    fs.utimesSync(workerData.lock, now, now);
  } catch {}
}, workerData.every);
`;

function startLockHeartbeat(lock: string, token: string): Worker | undefined {
  try {
    const worker = new Worker(HEARTBEAT_SOURCE, {
      eval: true,
      workerData: { lock, token, every: lockRefreshMs() },
    });
    worker.unref();
    return worker;
  } catch {
    return undefined;
  }
}

/**
 * Refuse to write a run file the reader would refuse (`MAX_RUN_FILE_BYTES`):
 * a verdict that would make the run unreadable is not recorded.
 */
function assertStorable(name: string, text: string): void {
  const bytes = Buffer.byteLength(text, "utf8");
  if (bytes > MAX_RUN_FILE_BYTES) {
    throw new RunStoreError(
      `recording this verdict would make ${name} ${bytes} bytes, over the ${MAX_RUN_FILE_BYTES} byte limit of the run store; ` +
        "nothing was written. Shorten the rationale and notes, or render the report of the run as it is",
      "VERDICT_STORE_FULL",
    );
  }
}

/**
 * Record a verdict.
 *
 * verdicts.json is append-only and every entry is one reviewer's decision,
 * stored once (`currentVerdicts` computes the current state):
 *
 * - `primary` (the default): the decision. On a finding that has an
 *   independent review, replacing the decision of another reviewer label
 *   needs `replace: true`.
 * - `independent`: a second review by a reviewer who did not see the
 *   decision. It needs an existing decision, a reviewer label that differs
 *   from every primary label of the finding, and `independence`. A
 *   disagreement keeps the finding at `needs_review` until a qualifying
 *   independent reviewer agrees with the latest decision; it is never
 *   erased. An independent review alone can never dismiss a finding.
 *
 * The run directory is locked (`withRunLock`) from reading the verdicts to
 * writing them; a write the reader could not load is refused.
 */
/**
 * Test-only: skips the terminal and environment checks of a human decision.
 * Not exported; tests use the same registered symbol.
 */
const HUMAN_GATE_TEST_BYPASS = Symbol.for("code-audit.test-only.skip-human-gate");

export interface RecordVerdictAccess {
  /**
   * A person at a terminal confirmed the decision (the CLI's checks in
   * humanGate.ts passed). Only then is `role: "human"` accepted; the MCP
   * server never sets it.
   */
  human?: boolean;
  /** The call comes from the CLI: messages name its flags (`--replace`). */
  cli?: boolean;
}

export function recordVerdict(
  ref: string,
  target: string,
  input: RecordVerdictInput,
  options: ResolveRunOptions = {},
  access: RecordVerdictAccess = {},
): RecordVerdictResult {
  if (!VERDICT_STATUSES.includes(input.status)) {
    throw new RunStoreError(
      `unsupported verdict status: ${String(input.status)}; use one of ${VERDICT_STATUSES.join(", ")}`,
      "INVALID_VERDICT",
    );
  }
  const role: VerdictRole = input.role ?? "primary";
  if (!VERDICT_ROLES.includes(role)) {
    throw new RunStoreError(
      `role must be "primary" (your own decision, the default) or "independent" (a check of someone else's verdict)`,
      "INVALID_VERDICT",
    );
  }
  if (role === "human" && access.human !== true) {
    throw new RunStoreError(
      'role "human" records a person\'s decision; a person can record this decision with the code-audit CLI ' +
        "(see `code-audit verdict --help`). An agent must not record it",
      "HUMAN_DECISION_CLI_ONLY",
    );
  }
  const flag = (cliForm: string, mcpForm: string): string => (access.cli ? cliForm : mcpForm);
  const reviewerInput = input.reviewer?.trim() ? redactText(input.reviewer.trim()).slice(0, 200) : undefined;
  const actorInput = input.actor?.trim() ? redactText(input.actor.trim()).slice(0, 200) : undefined;
  if (role === "human") {
    // The same checks as the CLI: not in an agent's shell, and at a terminal.
    if ((access as Record<symbol, unknown>)[HUMAN_GATE_TEST_BYPASS] !== true) {
      try {
        assertHumanContext(processHumanContext());
      } catch (error) {
        if (error instanceof HumanDecisionError) throw new RunStoreError(error.message, error.code);
        throw error;
      }
    }
    if (!reviewerInput) {
      throw new RunStoreError("a human decision needs --reviewer <your name>; it is shown as \"decided by a person (<name>)\"", "INVALID_VERDICT");
    }
    if (input.replace !== true) {
      throw new RunStoreError(
        "a human decision replaces the current verdict and closes any dispute: pass --replace to confirm",
        "INVALID_VERDICT",
      );
    }
  }
  if (role === "independent") {
    if (!reviewerInput) {
      throw new RunStoreError(
        'an independent verdict needs reviewer: your own label, different from the label of the primary reviewer (for example "subagent-1")',
        "INVALID_VERDICT",
      );
    }
    if (!INDEPENDENCE_KINDS.includes(input.independence as Independence)) {
      throw new RunStoreError(
        'an independent verdict needs independence: "subagent" when you are a fresh sub-agent that did not see the first verdict, ' +
          'or "same-session" for a devil\'s-advocate pass in the session that made it',
        "INVALID_VERDICT",
      );
    }
  }
  if (role !== "independent" && input.independence !== undefined) {
    throw new RunStoreError('independence belongs to role "independent" only: remove it, or set role "independent"', "INVALID_VERDICT");
  }
  const rawRationale = input.rationale?.trim();
  if (!rawRationale) {
    throw new RunStoreError(
      "rationale is required for a verdict",
      "RATIONALE_REQUIRED",
    );
  }
  const shaped = normalizeEvidence(input);
  assertFieldsFitStatus(input.status, shaped);
  const notices: string[] = [];
  const rationale = redactText(rawRationale).slice(0, REVIEWER_RATIONALE_MAX);
  if (rawRationale.length > REVIEWER_RATIONALE_MAX) {
    notices.push(`the rationale was cut to ${REVIEWER_RATIONALE_MAX} characters`);
  }
  const runDir = resolveRun(ref, options).runDir;
  return withRunLock(runDir, () => {
    // Read under the lock: what another process wrote meanwhile is kept.
    const run = loadRun(ref, options);
    const finding = findTarget(run, target);
    const strict = input.strictEvidence === true || run.verdictsDocument.strictEvidence === true;
    if (strict) assertStrictEvidence(input.status, shaped);
    const evidence = checkEvidenceLocations(run, shaped);
    assertDismissalJustified(finding, input.status, rawRationale, input.evidenceLines, evidence.control !== undefined);
    const previous = run.verdicts[finding.fingerprint];
    const label = reviewerInput ?? actorInput ?? UNNAMED_REVIEWER;
    if (previous && previous.history.length >= MAX_VERDICTS_PER_FINDING) {
      throw new RunStoreError(
        `${finding.id} already has ${previous.history.length} verdicts, the most one finding keeps (${MAX_VERDICTS_PER_FINDING}); ` +
          "nothing was written. Leave the current decision for a person to settle",
        "VERDICT_LIMIT",
      );
    }
    const labelKey = normalizeReviewerLabel(label);
    if (previous?.decidedByPerson && role !== "human") {
      throw new RunStoreError(
        `${finding.id} was decided by a person (${printable(previous.decidedByPerson.reviewer, 80)}); ` +
          "only another human decision from the command line can change it. Report your view to the user instead",
        "HUMAN_DECISION_STANDS",
      );
    }
    if (role === "independent") {
      if (!previous) {
        throw new RunStoreError(
          `${finding.id} has no verdict yet, and an independent review checks an existing one. ` +
            'Record the first verdict with role "primary" (the default); then a reviewer who has not seen it records role "independent"',
          "PRIMARY_VERDICT_REQUIRED",
        );
      }
      const primaryLabels = new Set(
        previous.history
          .filter((item) => isDecisionRole(item.role))
          .map((item) => normalizeReviewerLabel(item.reviewer)),
      );
      if (primaryLabels.has(labelKey)) {
        throw new RunStoreError(
          `reviewer ${printable(label, 80)} already recorded a primary verdict on ${finding.id}, so it cannot review it independently ` +
            "(labels are compared ignoring case, Unicode form and invisible characters). " +
            "An independent review comes from a reviewer that did not make the decision: a fresh sub-agent with its own label",
          "INDEPENDENT_SAME_REVIEWER",
        );
      }
    } else if (role === "primary" && previous) {
      const decidedBy = previous.history.filter((item) => isDecisionRole(item.role)).at(-1)?.reviewer;
      if (decidedBy !== undefined && normalizeReviewerLabel(decidedBy) !== labelKey && input.replace !== true) {
        throw new RunStoreError(
          `${finding.id} has a primary verdict by ${printable(decidedBy, 80)}; a primary verdict by ${printable(label, 80)} would replace it. ` +
            `If you are reviewing that verdict, pass ${flag("--role independent --independence subagent|same-session", 'role "independent" (with independence')} and your own reviewer label${access.cli ? "" : ")"}. ` +
            `To replace the decision on purpose, call again with ${flag("--replace", "replace: true")}; the replacement is shown in the report`,
          "PRIMARY_REPLACE_REFUSED",
        );
      }
    }
    const evidenceLines =
      input.evidenceLines && input.evidenceLines.length > 0
        ? input.evidenceLines
            .slice(0, MAX_EVIDENCE_LINES)
            .map((line) => redactText(String(line)).slice(0, EVIDENCE_LINE_MAX))
        : undefined;
    const entry: VerdictRecord = {
      fingerprint: finding.fingerprint,
      findingId: finding.id,
      status: input.status,
      rationale,
      ...(evidenceLines ? { evidenceLines } : {}),
      at: new Date().toISOString(),
      ...(actorInput ? { actor: actorInput } : {}),
      ...(reviewerInput ? { reviewer: reviewerInput } : {}),
      role,
      ...(role === "independent" ? { independence: input.independence as Independence } : {}),
      ...((role === "primary" && input.replace === true && previous) || role === "human" ? { replace: true } : {}),
      ...evidence,
    };
    const document: VerdictsDocument = {
      schemaVersion: VERDICTS_SCHEMA_VERSION,
      runId: run.runId,
      ...(run.verdictsDocument.strictEvidence ? { strictEvidence: true } : {}),
      entries: [...run.verdictsDocument.entries, entry],
    };
    const current = currentVerdicts(document, [...run.findings, ...run.hotspots]);
    const updated: LoadedRun = { ...run, verdictsDocument: document, verdicts: current };
    // Every file is rendered and measured before anything is written, so a
    // run that cannot be rendered, or would not load again, is left as it was.
    const verdictsText = `${JSON.stringify(document, null, 2)}\n`;
    assertStorable("verdicts.json", verdictsText);
    const artifacts = renderDerived(updated);
    for (const [name, text] of artifacts.files) assertStorable(name, text);
    writeText(run.runDir, "verdicts.json", verdictsText);
    const refreshed = writeDerived(updated, artifacts);
    const now = current[finding.fingerprint] as CurrentVerdict;
    const total = run.findings.length + run.hotspots.length;
    const dissent = now.dissent;
    return {
      runId: run.runId,
      runDir: run.runDir,
      fingerprint: finding.fingerprint,
      findingId: finding.id,
      status: now.status,
      rationale: now.rationale,
      role,
      requestedStatus: input.status,
      independentlyReviewed: now.independentlyReviewed,
      ...(now.disputeOpen && dissent
        ? {
            disagreement:
              `independent reviewer ${dissent.reviewer} said ${dissent.status} while the decision was ` +
              `${now.primaryStatus}; the status is needs_review until a person decides or an independent reviewer ` +
              "with another label agrees with the decision",
          }
        : {}),
      disputed: now.disputed,
      strictEvidence: strict,
      history: now.history.length,
      reviewed: Object.keys(current).length,
      total,
      refreshed,
      notices: [...run.notices, ...notices],
      ...dismissedFields(updated),
    };
  });
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

/** True when this Node.js accepts inline modifier groups such as `(?i:...)` (V8 12.5+, Node 23+). */
function supportsModifierGroups(): boolean {
  try {
    return new RegExp("(?i:a)").test("A");
  } catch {
    return false;
  }
}

/**
 * The hint for a pattern written for another regex dialect: an inline flag
 * group such as `(?i)` (PCRE, Python, Go) or a possessive quantifier.
 */
export function regexSyntaxHint(pattern: string, modifierGroups = supportsModifierGroups()): string {
  if (/\(\?(?:[a-zA-Z]+|[a-zA-Z]*-[a-zA-Z]+)[:)]/.test(pattern)) {
    const scoped = modifierGroups
      ? " This Node.js accepts a scoped group instead: write (?i:yaml|cursor) for a case-insensitive part."
      : " Spell both cases where they matter, e.g. [Yy]aml or (?:cursor|Cursor).";
    return `. The pattern is a JavaScript regular expression, which has no flag group for the whole pattern such as (?i). The search is case-sensitive and has no case-insensitive option.${scoped}`;
  }
  if (/[*+?}][+]/.test(pattern)) {
    return ". The pattern is a JavaScript regular expression, which has no possessive quantifiers (*+, ++).";
  }
  return ". The pattern is a JavaScript regular expression (no inline flags, possessive quantifiers or \\A/\\Z anchors); the search is case-sensitive.";
}

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
      `invalid regex: ${error instanceof Error ? error.message : String(error)}${regexSyntaxHint(pattern)}`,
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
  /** Records whose current verdict is needs_review or proof_gap: reviewed, still undecided. */
  open: number;
  /** Records whose current verdict is proof_gap. */
  proofGaps: number;
  /** Records whose current verdict an independent reviewer has checked. */
  independentlyReviewed: number;
}

export function reviewStats(run: LoadedRun): ReviewStats {
  const all = [...run.findings, ...run.hotspots];
  const verdicts = all.map((finding) => run.verdicts[finding.fingerprint]);
  const reviewed = verdicts.filter((verdict) => verdict !== undefined).length;
  const falsePositive = run.findings.filter(
    (finding) => run.verdicts[finding.fingerprint]?.status === "false_positive",
  ).length;
  return {
    reviewed,
    unreviewed: all.length - reviewed,
    total: all.length,
    falsePositive,
    open: verdicts.filter(
      (verdict) => verdict?.status === "needs_review" || verdict?.status === "proof_gap",
    ).length,
    proofGaps: verdicts.filter((verdict) => verdict?.status === "proof_gap").length,
    independentlyReviewed: verdicts.filter(isIndependentlyReviewed).length,
  };
}

/** Rules per kind listed in `triageSummary`; the rest is counted. */
const TRIAGE_SUMMARY_RULES = 10;
/** Proof gaps listed in `triageSummary`; the rest is counted. */
const TRIAGE_SUMMARY_GAPS = 3;

/**
 * The review ledger of a run for `status` and `report --format summary`
 * (see `triageCoverage`): per kind the totals and, by rule, how many records
 * nobody has reviewed; then the open proof gaps. Kept compact (rule id ->
 * count, short lists) so the MCP response stays within its size cap; the
 * Markdown report has the full tables.
 */
export function triageSummary(run: LoadedRun) {
  const triage = triageCoverage(effectiveFindings(run), effectiveHotspots(run));
  const kind = (counts: TriageKindCount) => {
    const pending = counts.byRule.filter((row) => row.unreviewed > 0);
    const byRule = Object.create(null) as Record<string, number>;
    // Rule ids of agent-added and external findings are not ours: cut.
    for (const row of pending.slice(0, TRIAGE_SUMMARY_RULES)) byRule[printable(row.ruleId, 100)] = row.unreviewed;
    return {
      total: counts.total,
      reviewed: counts.reviewed,
      unreviewed: counts.unreviewed,
      unreviewedByRule: { ...byRule },
      ...(pending.length > TRIAGE_SUMMARY_RULES
        ? { moreRules: pending.length - TRIAGE_SUMMARY_RULES }
        : {}),
    };
  };
  return {
    findings: kind(triage.findings),
    hotspots: kind(triage.hotspots),
    open: triage.open,
    independentlyReviewed: triage.independentlyReviewed,
    disputed: triage.disputed,
    disputesOpen: triage.disputesOpen,
    // Paths and text come from the repository and the reviewer: cut, so the
    // ledger cannot push the counts out of a size-capped response.
    proofGaps: triage.proofGaps.slice(0, TRIAGE_SUMMARY_GAPS).map((gap) => ({
      id: printable(gap.id, 40),
      location: `${printable(gap.file, 140)}:${gap.line}`,
      ...(gap.missing ? { missing: printable(redactText(gap.missing), 160) } : {}),
    })),
    ...(triage.proofGaps.length > TRIAGE_SUMMARY_GAPS
      ? { moreProofGaps: triage.proofGaps.length - TRIAGE_SUMMARY_GAPS }
      : {}),
  };
}

/**
 * The headline counts of a run as the scan left them, before any verdict:
 * for a blind caller (an independent reviewer), whom verdict-adjusted
 * counts would tell that a finding was dismissed or confirmed.
 */
export function scanTimeCounts(ref: string, options: ResolveRunOptions = {}) {
  const run = loadRun(ref, options);
  const reset = (finding: Finding): Finding => {
    const { review: _review, confidenceBeforeVerdict, ...rest } = finding as Finding & {
      confidenceBeforeVerdict?: Confidence;
    };
    if (!run.verdicts[finding.fingerprint]) return rest as Finding;
    const status = rest.suppression
      ? "suppressed"
      : rest.provenance.engine === "agent"
        ? "needs_review"
        : "candidate";
    return { ...rest, status, confidence: confidenceBeforeVerdict ?? rest.confidence } as Finding;
  };
  const counts = summaryCountFields(
    summarizeRun(run.run, run.findings.map(reset), run.hotspots.map(reset)),
  );
  return {
    findings: counts.findings,
    findingCounts: counts.findingCounts,
    lowConfidenceCandidates: counts.lowConfidenceCandidates,
    hotspots: counts.hotspotCount,
    summary: counts.summary,
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
    // Labels are agent-written: redacted (older files were written as given).
    if (entry.reviewer) reviewerSet.add(redactText(entry.reviewer));
  }
  for (const finding of run.findings) {
    const reviewer = (finding.provenance as { reviewer?: unknown }).reviewer;
    if (typeof reviewer === "string" && reviewer) reviewerSet.add(redactText(reviewer));
  }
  const reviewers = [...reviewerSet].sort();
  const agentReviewed =
    reviewers.length > 0 ||
    run.verdictsDocument.entries.length > 0 ||
    run.findings.some((finding) => finding.provenance.engine === "agent");
  const runRecord = run.verdictWarnings?.length
    ? {
        ...run.run,
        warnings: [...(Array.isArray(run.run.warnings) ? run.run.warnings : []), ...run.verdictWarnings],
      }
    : run.run;
  return buildReportContext(runRecord, {
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
  const warnings = [...(Array.isArray(run.run.warnings) ? run.run.warnings : []), ...(run.verdictWarnings ?? [])];

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
        triage: triageSummary(run),
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
    triage: triageSummary(run),
    ...dismissedFields(run),
    ...(runRecord.baseline ? { baseline: runRecord.baseline } : {}),
    ...(runRecord.scope ? { scope: runRecord.scope } : {}),
    warnings: [...(Array.isArray(run.run.warnings) ? run.run.warnings : []), ...(run.verdictWarnings ?? [])],
    notices: run.notices,
  };
}
