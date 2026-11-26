import { createFinding, type Finding } from "../finding.js";
import { PathJailError, resolveInside, toPosixRelative } from "../pathJail.js";
import {
  extractFixedVersion,
  extractSeverity,
  normalizePackageName,
  type OsvDetail,
} from "../sca.js";
import { runTool } from "./run.js";
import type { ExternalRunOutcome } from "./gitleaks.js";

export interface OsvScannerResult {
  findings: Finding[];
  warnings: string[];
  /** Lockfile paths (relative to the root) the tool reported on. */
  reportedFiles: string[];
  outcome: ExternalRunOutcome;
  /** True when the tool ran and produced a usable report. */
  ok: boolean;
}

interface OsvScannerPackage {
  package?: { name?: string; version?: string; ecosystem?: string };
  vulnerabilities?: OsvDetail[];
}

interface OsvScannerResultEntry {
  source?: { path?: string; type?: string };
  packages?: OsvScannerPackage[];
}

function truncate(value: string, max = 300): string {
  const singleLine = value.replace(/\s+/g, " ").trim();
  return singleLine.length > max ? `${singleLine.slice(0, max)}…` : singleLine;
}

/**
 * Run OSV-Scanner over the audit root and convert its JSON output into SCA
 * findings. Exit code 1 means vulnerabilities were found and is not an error.
 */
export async function runOsvScanner(options: {
  root: string;
  toolPath: string;
  version?: string;
  offline?: boolean;
  timeoutMs?: number;
  maxOutputBytes?: number;
}): Promise<OsvScannerResult> {
  const warnings: string[] = [];
  const findings: Finding[] = [];
  const reportedFiles: string[] = [];
  const args = ["scan", "source", "--format", "json", "--recursive"];
  if (options.offline) args.push("--offline");
  args.push(options.root);

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
    warnings.push("osv-scanner timed out; its results were not used");
    return { findings, warnings, reportedFiles, outcome, ok: false };
  }
  // osv-scanner prints "No package sources found" and exits non-zero (128)
  // when the tree has no lockfiles. That is an empty result, not a failure.
  if (result.exitCode !== 0 && /no package sources found/i.test(result.stderr)) {
    return { findings, warnings, reportedFiles, outcome, ok: true };
  }
  if (result.exitCode >= 127) {
    warnings.push(
      `osv-scanner failed with exit code ${result.exitCode}; its results were not used`,
    );
    return { findings, warnings, reportedFiles, outcome, ok: false };
  }
  if (result.exitCode !== 0 && result.exitCode !== 1) {
    warnings.push(
      `osv-scanner exited with code ${result.exitCode}; its results were not used`,
    );
    return { findings, warnings, reportedFiles, outcome, ok: false };
  }

  let document: unknown;
  try {
    document = JSON.parse(result.stdout);
  } catch (error) {
    warnings.push(
      `osv-scanner output could not be parsed: ${error instanceof Error ? error.message : String(error)}`,
    );
    return { findings, warnings, reportedFiles, outcome, ok: false };
  }

  const results = (document as { results?: unknown } | null)?.results;
  if (!Array.isArray(results)) {
    warnings.push("osv-scanner output had an unexpected shape; no results were used");
    return { findings, warnings, reportedFiles, outcome, ok: false };
  }

  for (const rawEntry of results as OsvScannerResultEntry[]) {
    const sourcePath = rawEntry.source?.path;
    if (sourcePath) {
      try {
        const resolved = resolveInside(options.root, sourcePath);
        reportedFiles.push(toPosixRelative(options.root, resolved));
      } catch (error) {
        if (error instanceof PathJailError) {
          warnings.push(`osv-scanner reported a path outside the root: ${sourcePath}`);
        } else {
          throw error;
        }
      }
    }

    for (const pkgEntry of rawEntry.packages ?? []) {
      const name = pkgEntry.package?.name;
      const version = pkgEntry.package?.version;
      const ecosystem = pkgEntry.package?.ecosystem ?? "";
      if (!name || !version) continue;
      for (const vuln of pkgEntry.vulnerabilities ?? []) {
        const vulnId = vuln.id;
        if (!vulnId) continue;
        const { severity, cvss } = extractSeverity(vuln);
        const fixedVersion = extractFixedVersion(vuln, { name, version, ecosystem });
        const aliases = vuln.aliases ?? [];
        const summary = vuln.summary ?? `OSV advisory ${vulnId}`;
        const cwe = vuln.database_specific?.cwe_ids?.[0] ?? "CWE-1104";
        const references = [
          `https://osv.dev/vulnerability/${vulnId}`,
          ...(vuln.references ?? [])
            .map((reference) => reference.url)
            .filter((url): url is string => Boolean(url)),
        ].slice(0, 5);
        findings.push(
          createFinding({
            ruleId: `sca-${vulnId.toLowerCase()}`,
            title: truncate(`${name}@${version}: ${summary}`, 160),
            category: "sca",
            severity,
            confidence: "high",
            cvss,
            cwe,
            owasp: "A06:2021",
            file: sourcePath ?? "package-lock.json",
            startLine: 1,
            evidence: `${name}@${version}`,
            message: truncate(vuln.details ?? summary, 500),
            remediation: fixedVersion
              ? `Upgrade ${name} to ${fixedVersion} or later; rerun the dependency audit and regression tests.`
              : `Upgrade ${name} to the latest stable or vendor-recommended version; confirm the impact before choosing mitigations.`,
            references,
            package: name,
            ecosystem,
            installedVersion: version,
            fixedVersion,
            advisoryId: vulnId,
            aliases: [...new Set([vulnId, ...aliases])],
            dependencyPath: "osv-scanner",
            reachable: "unknown",
            provenance: {
              engine: "osv-scanner",
              rule: vulnId,
              ...(options.version ? { version: options.version } : {}),
            },
          }),
        );
      }
    }
  }

  return { findings, warnings, reportedFiles, outcome, ok: true };
}

/** Dedupe key shared by built-in and OSV-Scanner SCA findings. */
export function scaDedupeKey(finding: {
  ecosystem?: string;
  package?: string;
  installedVersion?: string;
  advisoryId?: string;
  aliases?: string[];
}): string {
  const ecosystem = (finding.ecosystem ?? "").toLowerCase();
  const name = normalizePackageName(finding.package ?? "", finding.ecosystem);
  const version = finding.installedVersion ?? "";
  const vuln = finding.advisoryId ?? finding.aliases?.[0] ?? "";
  return `${ecosystem}\u0000${name}\u0000${version}\u0000${vuln}`;
}