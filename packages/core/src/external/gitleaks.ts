import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createFinding, type Finding } from "../finding.js";
import { PathJailError, resolveInside, toPosixRelative } from "../pathJail.js";
import { redactSecret } from "../secrets.js";
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
}

interface GitleaksReportEntry {
  RuleID?: string;
  ruleId?: string;
  Description?: string;
  StartLine?: number;
  EndLine?: number;
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

/**
 * Run Gitleaks in no-git mode over the audit root and convert its JSON report
 * into findings. The raw secret is never stored: the report is requested with
 * --redact and every Match/Secret value is redacted again before use.
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
  const reportPath = path.join(
    os.tmpdir(),
    `code-audit-gitleaks-${process.pid}-${Date.now()}-${Math.random()
      .toString(16)
      .slice(2)}.json`,
  );

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
    try {
      fs.rmSync(reportPath, { force: true });
    } catch {
      // best effort cleanup
    }
  }

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
    const startLine =
      typeof entry.StartLine === "number" && entry.StartLine > 0
        ? Math.trunc(entry.StartLine)
        : 1;
    const endLine =
      typeof entry.EndLine === "number" && entry.EndLine >= startLine
        ? Math.trunc(entry.EndLine)
        : startLine;
    const rawMatch = entry.Match ?? entry.Secret ?? "";
    const redacted = rawMatch ? redactSecret(rawMatch) : "[redacted secret]";
    const description = entry.Description ?? "Gitleaks detected a credential";

    findings.push(
      createFinding({
        ruleId: `gitleaks-${ruleId}`,
        title: `Gitleaks: ${description}`,
        category: "secrets",
        severity: "high",
        confidence: "high",
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
      }),
    );
  }

  return { findings, warnings, outcome };
}