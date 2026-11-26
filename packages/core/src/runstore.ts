import fs from "node:fs";
import path from "node:path";
import {
  assignFindingIds,
  computeFingerprint,
  createFinding,
  dedupeFindings,
  isActionable,
  sortFindings,
  type Confidence,
  type Finding,
  type Severity,
} from "./finding.js";
import {
  inventory,
  MAX_TEXT_FILE_BYTES,
  type InventoryResult,
} from "./inventory.js";
import { defaultRulesDir, TOOL_NAME, TOOL_VERSION } from "./meta.js";
import { resolveInside, toPosixRelative, validateAuditRoot } from "./pathJail.js";
import {
  renderFindingsJson,
  renderMarkdown,
  renderSarif,
  type ReportContext,
  type ReportLang,
} from "./report.js";
import { loadRules, type LoadedRule } from "./rules.js";
import {
  isPrivateKeyBoundary,
  redactSecret,
  redactSecretsInText,
} from "./secrets.js";

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

export interface LoadedRun {
  runDir: string;
  runId: string;
  root: string;
  run: Record<string, unknown>;
  findings: Finding[];
  hotspots: Finding[];
  coverage: Record<string, unknown>;
  state: RunState | undefined;
  verdicts: CurrentVerdicts;
  verdictsDocument: VerdictsDocument;
}

function writeJsonAtomic(file: string, value: unknown): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temp = `${file}.tmp-${process.pid}-${Date.now()}`;
  fs.writeFileSync(temp, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  fs.renameSync(temp, file);
}

function readJson<T>(file: string): T | undefined {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8")) as T;
  } catch (error) {
    const err = error as NodeJS.ErrnoException;
    if (err.code === "ENOENT") return undefined;
    throw new RunStoreError(
      `cannot read ${path.basename(file)} in ${path.dirname(file)}: ${
        error instanceof Error ? error.message : String(error)
      }`,
      "RUN_STORE_READ",
    );
  }
}

export function writeRunState(runDir: string, state: RunState): void {
  writeJsonAtomic(path.join(runDir, "state.json"), state);
}

export function readRunState(runDir: string): RunState | undefined {
  return readJson<RunState>(path.join(runDir, "state.json"));
}

function indexFile(projectRoot: string): string {
  return path.join(projectRoot, ".audit", "index.json");
}

export function registerRunIndex(
  projectRoot: string,
  entry: RunIndexEntry,
): void {
  const file = indexFile(projectRoot);
  const existing = readJson<RunIndexDocument>(file) ?? {
    schemaVersion: 1 as const,
    runs: [],
  };
  const runs = existing.runs.filter((run) => run.runId !== entry.runId);
  runs.push(entry);
  runs.sort((a, b) => b.startedAt.localeCompare(a.startedAt));
  writeJsonAtomic(file, { schemaVersion: 1, runs } satisfies RunIndexDocument);
}

function maybeAddRunIndex(
  document: LoadedRun,
  entry: RunIndexEntry,
): void {
  const file = indexFile(document.root);
  const existing = readJson<RunIndexDocument>(file);
  if (!existing) return;
  const runs = existing.runs.filter((run) => run.runId !== entry.runId);
  runs.push(entry);
  writeJsonAtomic(file, { schemaVersion: 1, runs } satisfies RunIndexDocument);
}

function isRunDirectory(candidate: string): boolean {
  return fs.existsSync(path.join(candidate, "run.json"));
}

export interface ResolveRunOptions {
  /** Extra project roots to search for `.audit/index.json`. */
  roots?: string[];
  cwd?: string;
}

/**
 * Resolve a run id or a run directory. Runs started by the MCP server or the
 * CLI with the default output live under `<root>/.audit/<run-id>` and are also
 * listed in `<root>/.audit/index.json`.
 */
export function resolveRunDir(
  ref: string,
  options: ResolveRunOptions = {},
): string {
  const value = ref.trim();
  if (!value) throw new RunStoreError("run id or run directory is required", "RUN_ID_REQUIRED");

  const direct = path.resolve(value);
  if (fs.existsSync(direct) && fs.statSync(direct).isDirectory()) {
    if (isRunDirectory(direct)) return direct;
    throw new RunStoreError(
      `not an audit run directory (missing run.json): ${value}`,
      "RUN_NOT_FOUND",
    );
  }

  const searchRoots = [
    options.cwd ?? process.cwd(),
    ...(options.roots ?? []),
  ];
  for (const root of searchRoots) {
    const candidate = path.join(path.resolve(root), ".audit", value);
    if (isRunDirectory(candidate)) return candidate;
  }
  for (const root of searchRoots) {
    const index = readJson<RunIndexDocument>(indexFile(path.resolve(root)));
    const entry = index?.runs.find((run) => run.runId === value);
    if (entry && isRunDirectory(entry.runDir)) return entry.runDir;
  }

  // A bare id can also be a path relative to the current directory.
  if (isRunDirectory(direct)) return direct;
  throw new RunStoreError(`audit run not found: ${value}`, "RUN_NOT_FOUND");
}

export function readVerdicts(runDir: string): VerdictsDocument {
  return (
    readJson<VerdictsDocument>(path.join(runDir, "verdicts.json")) ?? {
      schemaVersion: 1,
      runId: path.basename(runDir),
      entries: [],
    }
  );
}

export function currentVerdicts(document: VerdictsDocument): CurrentVerdicts {
  const current: CurrentVerdicts = {};
  for (const entry of document.entries) {
    current[entry.fingerprint] = entry;
  }
  return current;
}

function readAgentFindings(runDir: string): Finding[] {
  const document = readJson<{ findings?: Finding[] }>(
    path.join(runDir, "agent-findings.json"),
  );
  return document?.findings ?? [];
}

function loadInventoryForRun(root: string): InventoryResult {
  return inventory(root);
}

export function loadRun(
  ref: string,
  options: ResolveRunOptions = {},
): LoadedRun {
  const runDir = resolveRunDir(ref, options);
  const run = readJson<Record<string, unknown>>(path.join(runDir, "run.json"));
  if (!run) {
    throw new RunStoreError(`run.json is missing in ${runDir}`, "RUN_NOT_FOUND");
  }
  const envelope = readJson<{
    findings?: Finding[];
    hotspots?: Finding[];
  }>(path.join(runDir, "findings.json"));
  const baseFindings = envelope?.findings ?? [];
  const baseHotspots = envelope?.hotspots ?? [];
  const added = readAgentFindings(runDir);
  const addedFingerprints = new Set(added.map((finding) => finding.fingerprint));
  const findings = dedupeFindings([...baseFindings, ...added]);
  const hotspots = baseHotspots.filter(
    (hotspot) => !addedFingerprints.has(hotspot.fingerprint),
  );
  const coverage =
    readJson<Record<string, unknown>>(path.join(runDir, "coverage.json")) ?? {};
  const state = readRunState(runDir);
  const verdictsDocument = readVerdicts(runDir);
  const root = runRoot(run);
  const runId = typeof run.runId === "string" ? run.runId : path.basename(runDir);
  return {
    runDir,
    runId,
    root,
    run,
    findings,
    hotspots,
    coverage,
    state,
    verdicts: currentVerdicts(verdictsDocument),
    verdictsDocument,
  };
}

function runRoot(run: Record<string, unknown>): string {
  const args = run.args as Record<string, unknown> | undefined;
  const resolved = args?.resolvedRoot;
  if (typeof resolved === "string") return validateAuditRoot(resolved).root;
  if (typeof args?.root === "string") return validateAuditRoot(args.root).root;
  throw new RunStoreError("run.json has no audit root", "RUN_STORE_CORRUPT");
}

export function effectiveFindings(run: LoadedRun): Finding[] {
  const apply = (finding: Finding): Finding => {
    const verdict = run.verdicts[finding.fingerprint];
    return verdict ? { ...finding, status: verdict.status } : finding;
  };
  return run.findings.map(apply);
}

export function effectiveHotspots(run: LoadedRun): Finding[] {
  const apply = (finding: Finding): Finding => {
    const verdict = run.verdicts[finding.fingerprint];
    return verdict ? { ...finding, status: verdict.status } : finding;
  };
  return run.hotspots.map(apply);
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

export interface RecordVerdictInput {
  status: VerdictStatus;
  rationale: string;
  evidenceLines?: string[];
  actor?: string;
  reviewer?: string;
}

export interface RecordVerdictResult {
  runId: string;
  fingerprint: string;
  findingId: string;
  status: VerdictStatus;
  rationale: string;
  history: number;
  reviewed: number;
  total: number;
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
  const document = run.verdictsDocument;
  const entry: VerdictRecord = {
    fingerprint: finding.fingerprint,
    findingId: finding.id,
    status: input.status,
    rationale,
    ...(input.evidenceLines && input.evidenceLines.length > 0
      ? {
          evidenceLines: input.evidenceLines.map((line) =>
            redactSecretsInText(line),
          ),
        }
      : {}),
    at: new Date().toISOString(),
    ...(input.actor ? { actor: input.actor } : {}),
    ...(input.reviewer ? { reviewer: input.reviewer } : {}),
  };
  document.entries.push(entry);
  document.runId = run.runId;
  writeJsonAtomic(path.join(run.runDir, "verdicts.json"), document);
  const current = currentVerdicts(document);
  const total = run.findings.length + run.hotspots.length;
  return {
    runId: run.runId,
    fingerprint: finding.fingerprint,
    findingId: finding.id,
    status: input.status,
    rationale,
    history: document.entries.filter(
      (item) => item.fingerprint === finding.fingerprint,
    ).length,
    reviewed: Object.keys(current).length,
    total,
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
  const inv = loadInventoryForRun(run.root);
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
  const absolute = resolveInside(run.root, entry.relPath);
  const text = fs.readFileSync(absolute, "utf8");
  const allLines = text.split(/\r?\n/);
  const totalLines = allLines.length;
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
  let inPrivateKey = false;
  for (let index = 1; index <= cappedEnd; index += 1) {
    const raw = allLines[index - 1] ?? "";
    const boundary = isPrivateKeyBoundary(raw);
    const inside = inPrivateKey || boundary;
    if (index >= start) {
      lines.push({
        number: index,
        text: inside
          ? "[private key content redacted]"
          : redactSecretsInText(raw),
      });
    }
    if (boundary) {
      inPrivateKey = /-----BEGIN /.test(raw) && !/-----END /.test(raw);
    }
  }
  return {
    file: entry.relPath,
    startLine: start,
    endLine: cappedEnd,
    totalLines,
    truncated,
    content: lines.map((line) => line.text).join("\n"),
    lines,
  };
}

export interface SearchInput {
  pattern: string;
  glob?: string;
  regex?: boolean;
  maxResults?: number;
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
}

const MAX_PATTERN_LENGTH = 256;
const MAX_SEARCH_RESULTS = 200;
const MAX_SEARCH_BYTES = 16 * 1024 * 1024;

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function globToRegExp(glob: string): RegExp {
  let source = "";
  for (let index = 0; index < glob.length; index += 1) {
    const char = glob[index] ?? "";
    if (char === "*") {
      if (glob[index + 1] === "*") {
        index += 1;
        if (glob[index + 1] === "/") {
          index += 1;
          source += "(?:.*/)?";
        } else {
          source += ".*";
        }
      } else {
        source += "[^/]*";
      }
    } else if (char === "?") {
      source += "[^/]";
    } else {
      source += escapeRegExp(char);
    }
  }
  return new RegExp(`^${source}$`);
}

/** Reject patterns that are likely to backtrack catastrophically. */
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

export function searchCode(
  ref: string,
  input: SearchInput,
  options: ResolveRunOptions = {},
): SearchResult {
  const run = loadRun(ref, options);
  const pattern = input.pattern;
  if (!pattern) {
    throw new RunStoreError("search pattern is required", "PATTERN_REQUIRED");
  }
  const regex = input.regex
    ? assertSafeRegex(pattern)
    : assertSafeRegex(escapeRegExp(pattern));
  const glob = input.glob ? globToRegExp(input.glob) : undefined;
  const maxResults = Math.max(
    1,
    Math.min(MAX_SEARCH_RESULTS, input.maxResults ?? 50),
  );
  const inv = loadInventoryForRun(run.root);
  const matches: SearchMatch[] = [];
  let truncated = false;
  let searchedFiles = 0;
  let consumed = 0;

  for (const entry of inv.files) {
    if (!entry.scannable) continue;
    if (glob && !glob.test(entry.relPath)) continue;
    if (entry.size > MAX_TEXT_FILE_BYTES) continue;
    if (consumed + entry.size > MAX_SEARCH_BYTES) {
      truncated = true;
      break;
    }
    const absolute = resolveInside(run.root, entry.relPath);
    const text = fs.readFileSync(absolute, "utf8");
    consumed += Buffer.byteLength(text, "utf8");
    searchedFiles += 1;
    const lines = text.split(/\r?\n/);
    let inPrivateKey = false;
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index] ?? "";
      const boundary = isPrivateKeyBoundary(line);
      const inside = inPrivateKey || boundary;
      const match = regex.exec(line);
      if (match) {
        matches.push({
          file: entry.relPath,
          line: index + 1,
          column: (match.index ?? 0) + 1,
          text: inside
            ? "[private key content redacted]"
            : redactSecretsInText(line.trim().slice(0, 400)),
        });
        if (matches.length >= maxResults) {
          truncated = true;
          break;
        }
      }
      if (boundary) {
        inPrivateKey = /-----BEGIN /.test(line) && !/-----END /.test(line);
      }
    }
    if (truncated) break;
  }
  return {
    matches,
    total: matches.length,
    truncated,
    searchedFiles,
    pattern,
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
  finding: Finding;
  promoted: boolean;
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
  relPath: string,
  startLine: number,
  endLine?: number,
): string {
  const absolute = resolveInside(root, relPath);
  const text = fs.readFileSync(absolute, "utf8");
  const lines = text.split(/\r?\n/);
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
  let inPrivateKey = false;
  return lines
    .slice(startLine - 1, end)
    .map((line) => {
      const boundary = isPrivateKeyBoundary(line);
      const inside = inPrivateKey || boundary;
      if (boundary) {
        inPrivateKey = /-----BEGIN /.test(line) && !/-----END /.test(line);
      }
      return inside ? "[private key content redacted]" : redactSecretsInText(line);
    })
    .join("\n");
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
      evidence: hotspot.evidence,
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
    const inv = loadInventoryForRun(run.root);
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
          ? `it is a hotspot; promote it with audit_add_finding (hotspot_id=${duplicate.id})`
          : `record a verdict with audit_verdict on ${duplicate.id}`;
      throw new RunStoreError(
        `a ${duplicate.kind} already covers ${entry.relPath}:${duplicate.startLine} ` +
          `(${duplicate.id}, ${duplicate.cwe}); ${hint}`,
        "DUPLICATE_FINDING",
      );
    }
    const evidence = readEvidenceForRange(
      run.root,
      entry.relPath,
      startLine,
      input.endLine,
    );
    const ruleId = input.ruleId ?? `agent-${slugify(input.title)}`;
    finding = createFinding({
      ruleId,
      title: input.title.trim(),
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
      message: input.message ?? rationale,
      remediation:
        input.remediation ??
        "Review the code path and apply the fix described in the rationale.",
      source: input.source,
      status: "needs_review",
      provenance: {
        engine: "agent",
        rule: ruleId,
        version: TOOL_VERSION,
        ...(input.source ? { source: input.source } : {}),
        ...(input.reviewer ? { reviewer: input.reviewer } : {}),
      },
    });
  }

  if (!promoted) {
    finding = { ...finding, id: nextFindingId(run.findings, year) };
  }
  const existing = readAgentFindings(run.runDir);
  const merged = dedupeFindings([...existing, finding]);
  writeJsonAtomic(path.join(run.runDir, "agent-findings.json"), {
    schemaVersion: 1,
    runId: run.runId,
    findings: merged,
  });

  const allFindings = sortFindings(dedupeFindings([...run.findings, ...merged]));
  const remainingHotspots = run.hotspots.filter(
    (hotspot) => hotspot.fingerprint !== finding.fingerprint,
  );
  writeJsonAtomic(
    path.join(run.runDir, "findings.json"),
    {
      schemaVersion: 1,
      run: {
        runId: run.runId,
        tool: { name: TOOL_NAME, version: TOOL_VERSION },
        findingCounts: countBySeverity(allFindings),
        hotspotCount: remainingHotspots.length,
      },
      findings: allFindings,
      hotspots: remainingHotspots,
    },
  );
  return { runId: run.runId, finding, promoted };
}

function countBySeverity(findings: Finding[]): Record<string, number> {
  const counts: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const finding of findings) {
    if (!isActionable(finding)) continue;
    counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;
  }
  return counts;
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
  format: ReportOutputFormat;
  text: string;
  reviewed: number;
  unreviewed: number;
  falsePositive: number;
  total: number;
  path?: string;
}

function reportRules(run: LoadedRun): LoadedRule[] {
  const dir =
    typeof run.run.rulesDir === "string" ? run.run.rulesDir : defaultRulesDir();
  try {
    return loadRules(dir).rules;
  } catch {
    return [];
  }
}

export function renderRunReport(
  ref: string,
  format: ReportOutputFormat = "summary",
  options: ResolveRunOptions = {},
): RunReportResult {
  const run = loadRun(ref, options);
  const stats = reviewStats(run);
  const findings = effectiveFindings(run);
  const hotspots = effectiveHotspots(run);
  const args = (run.run.args ?? {}) as Record<string, unknown>;
  const tool = (run.run.tool ?? {}) as Record<string, unknown>;
  const lang: ReportLang = args.lang === "zh" ? "zh" : "en";
  const coverage = run.coverage as unknown as ReportContext["coverage"];
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
  const summary = {
    runId: run.runId,
    phase: run.state?.phase ?? "complete",
    findings: findings.filter(isActionable).length,
    hotspots: hotspots.length,
    reviewed: stats.reviewed,
    unreviewed: stats.unreviewed,
    falsePositive: stats.falsePositive,
    findingCounts: countBySeverity(findings),
    warnings: Array.isArray(run.run.warnings) ? run.run.warnings : [],
  };

  let text: string;
  let outputPath: string | undefined;
  if (format === "summary") {
    text = JSON.stringify(summary, null, 2);
  } else if (format === "json") {
    text = renderFindingsJson(
      {
        runId: run.runId,
        tool,
        startedAt: run.run.startedAt,
        finishedAt: run.run.finishedAt,
        durationMs: run.run.durationMs,
        rulesCount: run.run.rulesCount,
        profile: args.profile ?? "standard",
        offline: Boolean(args.offline),
        failOn: args.failOn ?? "high",
        minConfidence: args.minConfidence ?? "medium",
        findingCounts: summary.findingCounts,
        confidenceCounts: (run.run.confidenceCounts ?? {}) as Record<string, number>,
        suppressedCount: run.run.suppressedCount ?? 0,
        warnings: summary.warnings,
        review: stats,
      },
      findings,
      hotspots,
    );
  } else {
    const context: ReportContext = {
      runId: run.runId,
      target:
        typeof args.root === "string"
          ? args.root
          : typeof run.run.resolvedRoot === "string"
            ? run.run.resolvedRoot
            : run.root,
      startedAt: typeof run.run.startedAt === "string" ? run.run.startedAt : "",
      finishedAt: typeof run.run.finishedAt === "string" ? run.run.finishedAt : "",
      durationMs:
        typeof run.run.durationMs === "number" ? run.run.durationMs : 0,
      toolVersion:
        typeof tool.version === "string" ? tool.version : TOOL_VERSION,
      nodeVersion:
        typeof tool.node === "string" ? tool.node : process.version,
      profile: typeof args.profile === "string" ? args.profile : "standard",
      offline: Boolean(args.offline),
      lang,
      rules: reportRules(run),
      findings,
      hotspots,
      coverage,
      warnings: summary.warnings,
      reviewStats: stats,
      reviewers,
      agentReviewed,
    };
    if (format === "md") {
      text = renderMarkdown(context);
      outputPath = path.join(run.runDir, "report.md");
    } else {
      text = renderSarif(context);
      outputPath = path.join(run.runDir, "results.sarif");
    }
    fs.writeFileSync(outputPath, text, "utf8");
  }

  return {
    runId: run.runId,
    runDir: run.runDir,
    format,
    text,
    reviewed: stats.reviewed,
    unreviewed: stats.unreviewed,
    falsePositive: stats.falsePositive,
    total: stats.total,
    ...(outputPath ? { path: outputPath } : {}),
  };
}

export function runStatus(ref: string, options: ResolveRunOptions = {}) {
  const run = loadRun(ref, options);
  const stats = reviewStats(run);
  return {
    runId: run.runId,
    runDir: run.runDir,
    root: run.root,
    phase: run.state?.phase ?? "unknown",
    startedAt: run.state?.startedAt ?? run.run.startedAt,
    finishedAt: run.state?.finishedAt ?? run.run.finishedAt,
    updatedAt: run.state?.updatedAt,
    progress: run.state?.progress,
    error: run.state?.error,
    findings: run.findings.length,
    hotspots: run.hotspots.length,
    reviewed: stats.reviewed,
    unreviewed: stats.unreviewed,
    falsePositive: stats.falsePositive,
    findingCounts: countBySeverity(effectiveFindings(run)),
    warnings: Array.isArray(run.run.warnings) ? run.run.warnings : [],
  };
}
