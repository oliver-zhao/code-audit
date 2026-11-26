import fs from "node:fs";
import type { Finding } from "../finding.js";
import {
  PathJailError,
  resolveInside,
  toPosixRelative,
  validateAuditRoot,
} from "../pathJail.js";
import {
  buildScaFinding,
  describeDependencyPath,
  groupAdvisories,
  normalizePackageName,
  parseLockfile,
  readSiblingManifest,
  summarizeAdvisoryGroup,
  type OsvDetail,
  type ScaPackage,
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

/** `groups[]` entry: ids of one vulnerability under its different names. */
interface OsvScannerGroup {
  ids?: unknown;
  aliases?: unknown;
  max_severity?: unknown;
}

interface OsvScannerPackage {
  package?: { name?: string; version?: string; ecosystem?: string };
  vulnerabilities?: OsvDetail[];
  groups?: OsvScannerGroup[];
}

interface OsvScannerResultEntry {
  source?: { path?: string; type?: string };
  packages?: OsvScannerPackage[];
}

function stringList(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string" && item.length > 0)
    : [];
}

const MAX_LOCKFILE_BYTES = 32 * 1024 * 1024;

/**
 * Parse a lockfile OSV-Scanner reported on with the built-in parsers, to
 * recover what its JSON lacks: the line of each package, whether it is a
 * direct dependency, and its scope. Failure only loses that extra detail.
 *
 * OSV-Scanner follows `-r` includes and reports the included pins under the
 * top-level requirements file. The index therefore also holds packages from
 * included files (`pkg.file` differs from `rel`), so a finding can be placed
 * on the file and line where the pin really is. That is also where the
 * built-in engine reports it, which lets the two findings merge. A pin in the
 * reported file itself always wins over one in an include.
 */
function lockfilePackages(root: string, rel: string, abs: string): Map<string, ScaPackage> {
  const index = new Map<string, ScaPackage>();
  try {
    const stat = fs.statSync(abs);
    if (!stat.isFile() || stat.size > MAX_LOCKFILE_BYTES) return index;
    const parsed = parseLockfile(rel, fs.readFileSync(abs, "utf8"), {
      root,
      directNames: readSiblingManifest(root, rel),
    });
    const keyOf = (pkg: ScaPackage): string =>
      `${normalizePackageName(pkg.name, pkg.ecosystem)}\u0000${pkg.version}`;
    for (const pkg of parsed.packages) {
      if (pkg.file === rel && !index.has(keyOf(pkg))) index.set(keyOf(pkg), pkg);
    }
    for (const pkg of parsed.packages) {
      if (pkg.file !== rel && !index.has(keyOf(pkg))) index.set(keyOf(pkg), pkg);
    }
  } catch {
    // Unreadable or unsupported: fall back to line 1.
  }
  return index;
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

  // OSV-Scanner prints absolute paths. Findings must carry a path relative
  // to the canonical audit root, and nothing outside the root is reported.
  let realRoot: string;
  try {
    realRoot = validateAuditRoot(options.root).root;
  } catch (error) {
    warnings.push(
      `osv-scanner results were not used: ${error instanceof Error ? error.message : String(error)}`,
    );
    return { findings, warnings, reportedFiles, outcome, ok: false };
  }

  const seen = new Set<string>();
  const lockfileCache = new Map<string, Map<string, ScaPackage>>();
  for (const rawEntry of results as OsvScannerResultEntry[]) {
    if (!rawEntry || typeof rawEntry !== "object") continue;
    const sourcePath = rawEntry.source?.path;
    const packageEntries = Array.isArray(rawEntry.packages) ? rawEntry.packages : [];
    if (typeof sourcePath !== "string" || sourcePath.length === 0) {
      if (packageEntries.length > 0) {
        warnings.push(
          `osv-scanner reported ${packageEntries.length} package(s) without a source path; they were dropped`,
        );
      }
      continue;
    }
    let abs: string;
    try {
      abs = resolveInside(realRoot, sourcePath);
    } catch (error) {
      if (!(error instanceof PathJailError)) throw error;
      warnings.push(
        `osv-scanner reported a path outside the root: ${sourcePath}; its ${packageEntries.length} package(s) were dropped`,
      );
      continue;
    }
    const file = toPosixRelative(realRoot, abs);
    if (!reportedFiles.includes(file)) reportedFiles.push(file);

    let known = lockfileCache.get(file);
    if (!known) {
      known = lockfilePackages(realRoot, file, abs);
      lockfileCache.set(file, known);
    }

    for (const pkgEntry of packageEntries) {
      const name = pkgEntry?.package?.name;
      const version = pkgEntry?.package?.version;
      const ecosystem = pkgEntry?.package?.ecosystem ?? "";
      if (typeof name !== "string" || typeof version !== "string" || !name || !version) {
        continue;
      }
      const vulnerabilities = Array.isArray(pkgEntry.vulnerabilities)
        ? pkgEntry.vulnerabilities.filter(
            (vuln): vuln is OsvDetail & { id: string } =>
              Boolean(vuln) && typeof vuln.id === "string" && vuln.id.length > 0,
          )
        : [];
      const scannerGroups = (Array.isArray(pkgEntry.groups) ? pkgEntry.groups : []).map(
        (group) => ({
          ids: stringList(group?.ids),
          aliases: stringList(group?.aliases),
          maxSeverity: Number.parseFloat(String(group?.max_severity ?? "")),
        }),
      );
      // One finding per group: `groups[].ids` are the same advisory under
      // its PYSEC / GHSA / CVE names. Without `groups`, shared aliases decide.
      const groups = groupAdvisories(
        vulnerabilities.map((vuln) => ({ id: vuln.id, detail: vuln })),
        scannerGroups.map((group) => group.ids),
      );
      const located = known.get(`${normalizePackageName(name, ecosystem)}\u0000${version}`);
      for (const group of groups) {
        const ids = new Set(group.map((entry) => entry.id));
        const matching = scannerGroups.filter((candidate) =>
          candidate.ids.some((id) => ids.has(id)),
        );
        const scores = matching
          .map((candidate) => candidate.maxSeverity)
          .filter((score) => Number.isFinite(score));
        const advisory = summarizeAdvisoryGroup(
          group,
          { name, version, ecosystem },
          {
            aliases: matching.flatMap((candidate) => candidate.aliases),
            ...(scores.length > 0 ? { maxSeverityScore: scores.reduce((a, b) => Math.max(a, b)) } : {}),
          },
        );
        // Report the pin where it is declared (an `-r` include), if known.
        const findingFile = located?.file ?? file;
        // The same lockfile can appear in several result entries.
        const key = `${findingFile}\u0000${scaDedupeKey({
          ecosystem,
          package: name,
          installedVersion: version,
          advisoryId: advisory.advisoryId,
        })}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push(
          buildScaFinding({
            advisory,
            name,
            version,
            ecosystem,
            file: findingFile,
            line: located?.line ?? 1,
            dependencyPath: located ? describeDependencyPath(located) : "osv-scanner",
            scope: located?.scope,
            provenance: {
              engine: "osv-scanner",
              rule: advisory.advisoryId,
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