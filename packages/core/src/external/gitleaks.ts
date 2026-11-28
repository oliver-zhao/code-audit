import { createHash } from "node:crypto";
import { safeLineRange } from "./lines.js";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  ADJUSTMENT_PLACEHOLDER,
  createFinding,
  lowerConfidence,
  type Confidence,
  type Finding,
} from "../finding.js";
import { classifySecretValue, isPlaceholderSecret } from "../placeholder.js";
import { isProviderCredentialRule } from "../pathContext.js";
import { splitLines } from "../redact.js";
import { PathJailError, resolveInside, toPosixRelative } from "../pathJail.js";
import { redactSecret } from "../secrets.js";
import { registerCleanup } from "./cleanup.js";
import { runTool } from "./run.js";

export interface ExternalRunOutcome {
  exitCode: number;
  timedOut: boolean;
  truncated: boolean;
  stdout: string;
  stderr: string;
}

export interface GitleaksResult {
  findings: Finding[];
  warnings: string[];
  outcome: ExternalRunOutcome;
  /**
   * SHA-256 (hex) of the secret behind each finding whose value could be
   * read back from the file (see `secretIdentityOf`). In memory only: never
   * written to a report. The history scan uses it to recognise the same
   * secret in an old commit.
   */
  secretHashes: Map<Finding, string>;
}

/** SHA-256 (hex) of a secret value; in memory only. */
export function secretHash(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

/**
 * The value that identifies the secret of a report entry: the raw secret
 * when it can be located exactly (`rawSecretOf`), else the text of the
 * reported lines (a multi-line private key, for example). Undefined when the
 * lines are not in `fileLines`. The result is only ever hashed or compared in
 * memory.
 */
export function secretIdentityOf(
  entry: Parameters<typeof rawSecretOf>[0],
  fileLines: readonly string[],
): string | undefined {
  const raw = rawSecretOf(entry, fileLines);
  if (raw !== undefined) return raw;
  const startLine = entry.StartLine;
  if (typeof startLine !== "number" || startLine < 1 || startLine > fileLines.length) {
    return undefined;
  }
  const endLine =
    typeof entry.EndLine === "number" && entry.EndLine >= startLine
      ? Math.min(entry.EndLine, fileLines.length, startLine + 400)
      : startLine;
  const text = fileLines.slice(startLine - 1, endLine).join("\n").trim();
  return text.length > 0 ? text : undefined;
}

/**
 * True when the value of a finding of Gitleaks rule `ruleId` is an obvious
 * placeholder. A token in a provider format cannot be made to contain a
 * placeholder word, so containing one is enough there. Any other value must
 * be a placeholder (or a reference) as a whole: `example-Pr0d!` is a password.
 */
export function isGitleaksPlaceholder(ruleId: string, rawSecret: string): boolean {
  return isProviderCredentialRule(`gitleaks-${ruleId}`)
    ? isPlaceholderSecret(rawSecret)
    : classifySecretValue(rawSecret) !== "value";
}

interface GitleaksReportEntry {
  RuleID?: string;
  ruleId?: string;
  Description?: string;
  StartLine?: number;
  EndLine?: number;
  StartColumn?: number;
  EndColumn?: number;
  Match?: string;
  Secret?: string;
  File?: string;
  Fingerprint?: string;
  Tags?: string[];
}

function reportEntries(document: unknown): GitleaksReportEntry[] {
  if (Array.isArray(document)) return document as GitleaksReportEntry[];
  if (document && typeof document === "object") {
    const record = document as { findings?: unknown };
    if (Array.isArray(record.findings)) return record.findings as GitleaksReportEntry[];
  }
  return [];
}

const REDACTION_MARK = "REDACTED";

/*
 * Confidence mapping of Gitleaks rules
 * ------------------------------------
 * - high: rules that match a provider-specific token format (fixed prefix
 *   and length: `aws-access-token`, `github-pat`, `slack-bot-token`,
 *   `stripe-access-token`, `private-key`, ...). This is the default for
 *   every rule not listed below.
 * - medium: rules without such a format, which decide by a keyword next to
 *   a value and its entropy: `generic-api-key`, the `curl-auth-*` rules,
 *   `hashicorp-tf-password` and `kubernetes-secret-yaml`. They match
 *   documentation examples and test data as readily as live credentials, so
 *   path context (docs, tests, examples) may take them below the default
 *   threshold; in ordinary source they still count.
 */
const GITLEAKS_HEURISTIC_RULE =
  /^(?:generic-[a-z0-9-]+|curl-auth-[a-z0-9-]+|hashicorp-tf-password|kubernetes-secret-yaml)$/;

/** Base confidence of a Gitleaks rule; see the mapping above. */
export function gitleaksRuleConfidence(ruleId: string): Confidence {
  return GITLEAKS_HEURISTIC_RULE.test(ruleId) ? "medium" : "high";
}

/** Files larger than this are not re-read to classify a secret value. */
const MAX_RAW_LOOKUP_BYTES = 5 * 1024 * 1024;

/**
 * Recover the raw secret of a report entry from the source file, in memory
 * only, so it can be classified as a placeholder. Gitleaks runs with
 * `--redact`, so the report carries `REDACTED` in place of the value; what it
 * does carry is the line, the columns of the match and the text around the
 * secret (`Match` is `password = "REDACTED"`).
 *
 * Returns undefined whenever the value cannot be located with certainty; the
 * finding then keeps its confidence.
 */
export function rawSecretOf(
  entry: {
    StartLine?: number;
    EndLine?: number;
    StartColumn?: number;
    EndColumn?: number;
    Match?: string;
    Secret?: string;
  },
  fileLines: readonly string[],
): string | undefined {
  // A report written without --redact (not ours, but be exact about it).
  if (typeof entry.Secret === "string" && entry.Secret && entry.Secret !== REDACTION_MARK) {
    return entry.Secret;
  }
  const startLine = entry.StartLine;
  if (typeof startLine !== "number" || startLine < 1 || startLine > fileLines.length) {
    return undefined;
  }
  const endLine =
    typeof entry.EndLine === "number" && entry.EndLine >= startLine
      ? Math.min(entry.EndLine, fileLines.length, startLine + 50)
      : startLine;
  const text = fileLines.slice(startLine - 1, endLine).join("\n");
  const match = entry.Match ?? "";
  const mark = match.indexOf(REDACTION_MARK);
  const prefix = mark >= 0 ? match.slice(0, mark) : "";
  const suffix = mark >= 0 ? match.slice(mark + REDACTION_MARK.length) : "";
  const startColumn = typeof entry.StartColumn === "number" ? entry.StartColumn : undefined;
  const endColumn = typeof entry.EndColumn === "number" ? entry.EndColumn : undefined;

  const singleLine = endLine === startLine;
  const STRIP_LEFT = /^[\s"'`=:,;(\[{]+/;
  const STRIP_RIGHT = /[\s"'`=:,;)\]}]+$/;

  // Where the value starts: right after the text that precedes it in `Match`
  // (the occurrence nearest the reported column), else at the column.
  let valueStart: number;
  let startFromColumn = false;
  if (prefix.length > 0) {
    let best = -1;
    let bestDistance = Number.POSITIVE_INFINITY;
    let from = 0;
    for (let guard = 0; guard < 200; guard += 1) {
      const at = text.indexOf(prefix, from);
      if (at < 0) break;
      const distance = startColumn === undefined ? 0 : Math.abs(at - (startColumn - 2));
      if (distance < bestDistance) {
        bestDistance = distance;
        best = at;
      }
      from = at + 1;
    }
    if (best < 0) return undefined;
    valueStart = best + prefix.length;
  } else {
    if (startColumn === undefined) return undefined;
    // Gitleaks columns are off by one in a version- and line-dependent way:
    // take the widest reading and strip the delimiter it can add.
    valueStart = Math.max(0, startColumn - 2);
    startFromColumn = true;
  }

  // Where it ends: at the first occurrence of the text that follows it in
  // `Match`, else at the column. Never further: text after the match (a
  // comment saying "example") must not take part in the decision.
  let valueEnd: number;
  let endFromColumn = false;
  if (suffix.length > 0) {
    valueEnd = text.indexOf(suffix, valueStart);
    if (valueEnd < 0) return undefined;
  } else {
    if (endColumn === undefined || !singleLine) return undefined;
    valueEnd = Math.min(text.length, Math.max(0, endColumn));
    endFromColumn = true;
  }
  if (valueEnd <= valueStart) return undefined;
  let value = text.slice(valueStart, valueEnd);
  if (startFromColumn) value = value.replace(STRIP_LEFT, "");
  if (endFromColumn) value = value.replace(STRIP_RIGHT, "");
  return value.length > 0 ? value : undefined;
}

/**
 * Run Gitleaks in no-git mode over the audit root and convert its JSON report
 * into findings. The raw secret is never stored: the report is requested with
 * --redact and every Match/Secret value is redacted again before use.
 *
 * A finding whose value is an obvious placeholder (see `isPlaceholderSecret`
 * for provider token formats, `classifySecretValue` for everything else)
 * gets low confidence and the adjustment `placeholder-value`. For that one
 * decision the value is read back from the source file and discarded.
 */
export async function runGitleaks(options: {
  root: string;
  toolPath: string;
  version?: string;
  timeoutMs?: number;
  maxOutputBytes?: number;
}): Promise<GitleaksResult> {
  const warnings: string[] = [];
  const findings: Finding[] = [];
  const secretHashes = new Map<Finding, string>();
  // The report goes into a private directory of its own (mode 0700), which
  // a later run can recognise and sweep if this one is killed.
  const reportDir = fs.mkdtempSync(path.join(os.tmpdir(), "code-audit-gitleaks-"));
  const reportPath = path.join(reportDir, "report.json");

  const args = [
    "detect",
    "--no-git",
    "--source",
    options.root,
    "--report-format",
    "json",
    "--report-path",
    reportPath,
    "--redact",
    "--no-banner",
    "--exit-code",
    "0",
  ];

  // Killed (with everything it started) and its report removed on SIGINT,
  // SIGTERM, SIGHUP or exit while it runs.
  const cleanup = registerCleanup([reportDir]);
  let result: Awaited<ReturnType<typeof runTool>>;
  try {
    result = await runTool(options.toolPath, args, {
      cwd: options.root,
      timeoutMs: options.timeoutMs,
      maxOutputBytes: options.maxOutputBytes,
      onSpawn: cleanup.track,
    });
  } catch (error) {
    cleanup.release();
    throw error;
  }
  const outcome: ExternalRunOutcome = {
    exitCode: result.exitCode,
    timedOut: result.timedOut,
    truncated: result.truncated,
    stdout: result.stdout,
    stderr: result.stderr,
  };

  let document: unknown;
  try {
    document = JSON.parse(fs.readFileSync(reportPath, "utf8"));
  } catch (error) {
    const err = error as NodeJS.ErrnoException;
    if (err.code !== "ENOENT") {
      warnings.push(
        `gitleaks report could not be parsed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    document = [];
  } finally {
    // Removes the report directory as well.
    cleanup.release();
  }

  const lineCache = new Map<string, readonly string[] | undefined>();
  const linesOf = (file: string): readonly string[] | undefined => {
    if (lineCache.has(file)) return lineCache.get(file);
    let lines: string[] | undefined;
    try {
      if (fs.statSync(file).size <= MAX_RAW_LOOKUP_BYTES) {
        lines = splitLines(fs.readFileSync(file, "utf8"));
      }
    } catch {
      lines = undefined;
    }
    // Keep at most a few files in memory; results come grouped by file.
    if (lineCache.size >= 8) lineCache.clear();
    lineCache.set(file, lines);
    return lines;
  };

  for (const entry of reportEntries(document)) {
    const ruleId = entry.RuleID ?? entry.ruleId ?? "gitleaks-rule";
    const rawFile = entry.File ?? "";
    if (!rawFile) {
      warnings.push(`gitleaks result without a file path was dropped (rule ${ruleId})`);
      continue;
    }
    let resolved: string;
    try {
      resolved = resolveInside(options.root, rawFile);
    } catch (error) {
      if (error instanceof PathJailError) {
        warnings.push(
          `gitleaks result outside the audit root was dropped: ${rawFile} (${ruleId})`,
        );
        continue;
      }
      throw error;
    }
    const relative = toPosixRelative(options.root, resolved);
    const { startLine, endLine } = safeLineRange(entry.StartLine, entry.EndLine, (field, value) =>
      warnings.push(
        `gitleaks result in ${relative} has an invalid ${field} (${String(value).slice(0, 40)}); line 1 or the start line was used`,
      ),
    );
    const rawMatch = entry.Match ?? entry.Secret ?? "";
    const redacted = rawMatch ? redactSecret(rawMatch) : "[redacted secret]";
    const description = entry.Description ?? "Gitleaks detected a credential";

    const fileLines = linesOf(resolved);
    const rawSecret = fileLines ? rawSecretOf(entry, fileLines) : undefined;
    const placeholder = rawSecret !== undefined && isGitleaksPlaceholder(ruleId, rawSecret);
    const identity = fileLines ? secretIdentityOf(entry, fileLines) : undefined;

    const finding = createFinding({
        ruleId: `gitleaks-${ruleId}`,
        title: `Gitleaks: ${description}`,
        category: "secrets",
        severity: "high",
        confidence: gitleaksRuleConfidence(ruleId),
        cwe: "CWE-798",
        owasp: "A07:2021",
        file: relative,
        startLine,
        endLine,
        evidence: redacted,
        message: "A credential was detected by Gitleaks; the value is redacted in every output.",
        remediation:
          "Revoke and rotate the credential, move it to a secrets manager, and purge it from version control history.",
        references: ["CWE-798", "OWASP A07:2021"],
        provenance: {
          engine: "gitleaks",
          rule: ruleId,
          ...(options.version ? { version: options.version } : {}),
        },
    });
    const result = placeholder
      ? lowerConfidence(finding, ADJUSTMENT_PLACEHOLDER, "low")
      : finding;
    if (identity !== undefined) secretHashes.set(result, secretHash(identity));
    findings.push(result);
  }

  return { findings, warnings, outcome, secretHashes };
}