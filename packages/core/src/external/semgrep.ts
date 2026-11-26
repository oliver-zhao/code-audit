import { splitLines } from "../redact.js";
import { createFinding, type Confidence, type Finding, type Severity } from "../finding.js";
import { PathJailError, resolveInside, toPosixRelative } from "../pathJail.js";
import { loadOpengrepRules } from "./opengrepRules.js";
import { runTool } from "./run.js";
import type { ExternalRunOutcome } from "./gitleaks.js";

export interface SemgrepResult {
  findings: Finding[];
  warnings: string[];
  outcome: ExternalRunOutcome;
  ok: boolean;
}

interface SemgrepResultEntry {
  check_id?: string;
  path?: string;
  start?: { line?: number };
  end?: { line?: number };
  extra?: {
    message?: string;
    severity?: string;
    lines?: string;
    metadata?: {
      cwe?: string | string[];
      confidence?: string;
      [key: string]: unknown;
    };
  };
}

function severityFromTool(value: string | undefined): Severity {
  switch ((value ?? "").toUpperCase()) {
    case "ERROR":
      return "high";
    case "WARNING":
      return "medium";
    case "INFO":
      return "low";
    default:
      return "medium";
  }
}

function confidenceFromTool(value: string | undefined): Confidence {
  switch ((value ?? "").toUpperCase()) {
    case "HIGH":
      return "high";
    case "LOW":
      return "low";
    case "MEDIUM":
      return "medium";
    default:
      return "medium";
  }
}

function firstCwe(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) return value[0];
  if (typeof value === "string" && value.trim()) return value.trim();
  return undefined;
}

function evidenceFrom(entry: SemgrepResultEntry): string {
  const lines = entry.extra?.lines?.trim();
  if (!lines) return entry.check_id ?? "semgrep result";
  const first = splitLines(lines)[0]?.trim() ?? lines;
  return first.slice(0, 400);
}

/**
 * Opengrep prefixes the rule id with the config directory path, for example
 * `rules.opengrep.cs-opengrep-process-start`. Resolve it back to the bare id
 * loaded from the rules directory by matching a known id as a suffix; when no
 * known id matches, keep the full check_id unchanged.
 */
export function resolveRuleId(checkId: string, knownIds: Set<string>): string {
  if (knownIds.has(checkId)) return checkId;
  let best: string | undefined;
  for (const id of knownIds) {
    if (checkId.endsWith(`.${id}`) || checkId.endsWith(`:${id}`) || checkId.endsWith(`/${id}`)) {
      if (!best || id.length > best.length) best = id;
    }
  }
  return best ?? checkId;
}

/**
 * Build the argument list for Opengrep or Semgrep.
 *
 * The two tools do not share every flag: Opengrep rejects `--metrics=off`
 * (it has no metrics option at all), while Semgrep requires it to disable
 * telemetry. Everything else (`--json`, `--quiet`, `--disable-version-check`,
 * a local `--config` directory and the target) is accepted by both. The
 * registry is never contacted: `--config` always points at a local directory.
 */
export function sastArgs(options: {
  engine: "opengrep" | "semgrep";
  rulesDir: string;
  root: string;
}): string[] {
  const args = ["scan", "--json", "--quiet"];
  // Opengrep 1.33 has no --metrics flag and exits 2 when it is passed.
  if (options.engine === "semgrep") args.push("--metrics=off");
  args.push("--disable-version-check", "--config", options.rulesDir, options.root);
  return args;
}

/**
 * Run Opengrep or Semgrep with a local rules directory and convert the JSON
 * output into findings. The registry is never contacted: `--config` always
 * points at a local directory and (for Semgrep) `--metrics=off` disables
 * telemetry. Opengrep does not accept `--metrics=off`.
 */
export async function runSemgrep(options: {
  root: string;
  toolPath: string;
  engine: "opengrep" | "semgrep";
  rulesDir: string;
  version?: string;
  timeoutMs?: number;
  maxOutputBytes?: number;
}): Promise<SemgrepResult> {
  const warnings: string[] = [];
  const findings: Finding[] = [];
  const args = sastArgs({
    engine: options.engine,
    rulesDir: options.rulesDir,
    root: options.root,
  });
  const knownRuleIds = new Set(
    loadOpengrepRules(options.rulesDir).rules.map((rule) => rule.id),
  );

  const result = await runTool(options.toolPath, args, {
    cwd: options.root,
    timeoutMs: options.timeoutMs,
    maxOutputBytes: options.maxOutputBytes,
  });
  const outcome: ExternalRunOutcome = {
    exitCode: result.exitCode,
    timedOut: result.timedOut,
    truncated: result.truncated,
    stdout: result.stdout,
    stderr: result.stderr,
  };

  if (result.timedOut) {
    warnings.push(`${options.engine} timed out; its results were not used`);
    return { findings, warnings, outcome, ok: false };
  }
  // Opengrep/Semgrep use exit code 1 when findings exist; 0 means clean.
  if (result.exitCode !== 0 && result.exitCode !== 1) {
    warnings.push(
      `${options.engine} exited with code ${result.exitCode}; its results were not used`,
    );
    return { findings, warnings, outcome, ok: false };
  }

  let document: unknown;
  try {
    document = JSON.parse(result.stdout);
  } catch (error) {
    warnings.push(
      `${options.engine} output could not be parsed: ${error instanceof Error ? error.message : String(error)}`,
    );
    return { findings, warnings, outcome, ok: false };
  }

  const rawResults = (document as { results?: unknown } | null)?.results;
  if (!Array.isArray(rawResults)) {
    warnings.push(`${options.engine} output had no results array; no results were used`);
    return { findings, warnings, outcome, ok: true };
  }

  for (const raw of rawResults as SemgrepResultEntry[]) {
    const checkId = raw.check_id;
    const rawPath = raw.path;
    if (!checkId || !rawPath) continue;
    const ruleId = resolveRuleId(checkId, knownRuleIds);
    let resolved: string;
    try {
      resolved = resolveInside(options.root, rawPath);
    } catch (error) {
      if (error instanceof PathJailError) {
        warnings.push(
          `${options.engine} result outside the audit root was dropped: ${rawPath} (${checkId})`,
        );
        continue;
      }
      throw error;
    }
    const relative = toPosixRelative(options.root, resolved);
    const startLine =
      typeof raw.start?.line === "number" && raw.start.line > 0
        ? Math.trunc(raw.start.line)
        : 1;
    const endLine =
      typeof raw.end?.line === "number" && raw.end.line >= startLine
        ? Math.trunc(raw.end.line)
        : startLine;
    const metadata = raw.extra?.metadata ?? {};
    const cwe = firstCwe(metadata.cwe);
    findings.push(
      createFinding({
        ruleId,
        title: ruleId,
        category: "sast",
        severity: severityFromTool(raw.extra?.severity),
        confidence: confidenceFromTool(metadata.confidence),
        cwe,
        file: relative,
        startLine,
        endLine,
        evidence: evidenceFrom(raw),
        message: raw.extra?.message ?? ruleId,
        remediation:
          "Review the flagged code path and apply the fix described in the rule message.",
        references: cwe ? [cwe] : undefined,
        provenance: {
          engine: options.engine,
          rule: ruleId,
          ...(options.version ? { version: options.version } : {}),
        },
      }),
    );
  }

  return { findings, warnings, outcome, ok: true };
}