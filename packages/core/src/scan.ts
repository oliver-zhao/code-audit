import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { CoverageReport, CoverageEngine } from "./coverage.js";
import {
  assignFindingIds,
  assignHotspotIds,
  createFinding,
  dedupeFindings,
  isActionable,
  sortFindings,
  type Confidence,
  type Finding,
  type Severity,
} from "./finding.js";
import { inventory, type InventoryResult } from "./inventory.js";
import { SOURCE_LANGUAGES, type Language } from "./language.js";
import { defaultRulesDir, TOOL_NAME, TOOL_VERSION } from "./meta.js";
import { validateAuditRoot } from "./pathJail.js";
import { renderFindingsJson, renderMarkdown, renderSarif, type ReportLang } from "./report.js";
import { loadRules, scanRules, type LoadedRule, type RuleSet } from "./rules.js";
import { registerRunIndex, writeRunState } from "./runstore.js";
import { runSca, type HttpClient, type ScaResult } from "./sca.js";
import { scanSecrets } from "./secrets.js";
import {
  crossEngineDedupe,
  defaultOpengrepRulesDir,
  findTool,
  mergeScaFindings,
  runGitleaks,
  runOsvScanner,
  runSemgrep,
  selectSastTool,
  type ToolInfo,
} from "./external/index.js";

export { defaultRulesDir, TOOL_NAME, TOOL_VERSION };

export type ReportFormat = "md" | "json" | "sarif";
export const ALL_FORMATS: ReportFormat[] = ["md", "json", "sarif"];

export type EngineName =
  | "builtin"
  | "opengrep"
  | "semgrep"
  | "osv-scanner"
  | "gitleaks";

export const ALL_ENGINES: EngineName[] = [
  "builtin",
  "opengrep",
  "semgrep",
  "osv-scanner",
  "gitleaks",
];

export interface ScanOptions {
  root: string;
  profile?: "quick" | "standard";
  formats?: ReportFormat[];
  out?: string;
  offline?: boolean;
  failOn?: Severity;
  minConfidence?: Confidence;
  lang?: ReportLang;
  rulesDir?: string;
  /** Opengrep/Semgrep rules directory; defaults to rules/opengrep. */
  opengrepRulesDir?: string;
  /** Explicit engine list; defaults to every engine. */
  engines?: EngineName[];
  /** Override PATH used to discover external tools (testing). */
  pathEnv?: string;
  http?: HttpClient;
  now?: () => Date;
  /** Pre-allocated run id, used by the MCP server to answer before scanning. */
  runId?: string;
}

export interface ScanResult {
  runId: string;
  runDir: string;
  findings: Finding[];
  hotspots: Finding[];
  coverage: CoverageReport;
  warnings: string[];
  run: Record<string, unknown>;
  durationMs: number;
}

export function makeRunId(date: Date): string {
  const stamp = date
    .toISOString()
    .replace(/[-:]/g, "")
    .replace(/\.\d{3}Z$/, "Z");
  return `${stamp}-${crypto.randomBytes(4).toString("hex")}`;
}

function categoryFor(rule: LoadedRule, language: Language): "sast" | "config" {
  return SOURCE_LANGUAGES.includes(language) ? "sast" : "config";
}

function countSeverities(findings: Finding[]): Record<string, number> {
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

function countConfidences(findings: Finding[]): Record<string, number> {
  const counts: Record<string, number> = { high: 0, medium: 0, low: 0 };
  for (const finding of findings) {
    if (!isActionable(finding)) continue;
    counts[finding.confidence] = (counts[finding.confidence] ?? 0) + 1;
  }
  return counts;
}

function buildCoverage(
  inv: InventoryResult,
  ruleSet: RuleSet,
  ruleScannedFiles: number,
  secretScannedFiles: number,
  engines: CoverageEngine[],
  warnings: string[],
  suppressed: CoverageReport["suppressed"],
): CoverageReport {
  const scannedFiles = inv.files.map((file) => {
    const fileEngines: string[] = [];
    if (file.isLockfile) {
      fileEngines.push("sca");
    } else if (file.scannable) {
      fileEngines.push("builtin-secrets");
      if (file.language !== "unknown") fileEngines.push("builtin-rules");
    }
    return {
      path: file.relPath,
      language: file.language,
      loc: file.loc,
      engines: fileEngines,
    };
  });

  return {
    root: inv.root,
    stats: inv.stats,
    languages: inv.languages,
    scannedFiles,
    skipped: inv.skipped.map((entry) => ({
      path: entry.relPath,
      reason: entry.reason,
    })),
    manifests: inv.manifests,
    engines,
    rulesCount: ruleSet.rules.length,
    warnings,
    suppressed,
  };
}

function emptyRuleScan(): {
  hits: Array<never>;
  suppressed: Array<never>;
  warnings: string[];
  scannedFiles: number;
} {
  return { hits: [], suppressed: [], warnings: [], scannedFiles: 0 };
}

function emptySecretScan(): { findings: Finding[]; warnings: string[]; scannedFiles: number } {
  return { findings: [], warnings: [], scannedFiles: 0 };
}

function emptySca(): ScaResult {
  return {
    findings: [],
    warnings: [],
    packages: [],
    queriedPackages: 0,
    vulnIds: [],
    unresolvedManifests: [],
    degraded: false,
  };
}

function resolveEngines(options: ScanOptions): Set<EngineName> {
  if (options.engines) return new Set(options.engines);
  return new Set(ALL_ENGINES);
}

interface ExternalToolRecord {
  name: string;
  path: string;
  version?: string;
}

export async function scanProject(options: ScanOptions): Promise<ScanResult> {
  const started = (options.now ?? (() => new Date()))();
  const startedMs = Date.now();
  const validated = validateAuditRoot(options.root);
  const formats = options.formats ?? ALL_FORMATS;
  const profile = options.profile ?? "standard";
  const lang = options.lang ?? "en";
  const offline = options.offline ?? false;
  const failOn = options.failOn ?? "high";
  const minConfidence = options.minConfidence ?? "medium";
  const ruleSet = loadRules(options.rulesDir ?? defaultRulesDir());
  const selected = resolveEngines(options);
  const builtinEnabled = selected.has("builtin");
  const pathEnv = options.pathEnv;

  const runId = options.runId ?? makeRunId(started);
  const runDir = options.out
    ? path.join(path.resolve(options.out), runId)
    : path.join(validated.root, ".audit", runId);
  fs.mkdirSync(runDir, { recursive: true });
  writeRunState(runDir, {
    schemaVersion: 1,
    runId,
    root: validated.root,
    runDir,
    phase: "running",
    startedAt: started.toISOString(),
    updatedAt: started.toISOString(),
    progress: { engine: "inventory" },
  });

  try {
    return await executeScan();
  } catch (error) {
    writeRunState(runDir, {
      schemaVersion: 1,
      runId,
      root: validated.root,
      runDir,
      phase: "failed",
      startedAt: started.toISOString(),
      updatedAt: new Date().toISOString(),
      finishedAt: new Date().toISOString(),
      error: error instanceof Error ? error.message : String(error),
    });
    throw error;
  }

  async function executeScan(): Promise<ScanResult> {
    const inv = inventory(validated.root);
    const ruleScan = builtinEnabled ? scanRules(inv.files, ruleSet) : emptyRuleScan();
    const secretScan = builtinEnabled ? scanSecrets(inv.files) : emptySecretScan();

    const ruleFindings: Finding[] = [];
    const ruleHotspots: Finding[] = [];
    for (const hit of ruleScan.hits) {
      const finding = createFinding({
        ruleId: hit.rule.id,
        title: hit.rule.title,
        category: categoryFor(hit.rule, hit.file.language),
        severity: hit.rule.severity,
        confidence: hit.rule.confidence,
        kind: hit.rule.kind,
        cwe: hit.rule.cwe,
        owasp: hit.rule.owasp,
        language: hit.file.language,
        file: hit.file.relPath,
        startLine: hit.line,
        evidence: hit.evidence,
        message: hit.rule.message,
        remediation: hit.rule.remediation,
        references: hit.rule.references ?? [
          hit.rule.cwe,
          ...(hit.rule.owasp ? [hit.rule.owasp] : []),
        ],
        provenance: { engine: "builtin-rules", rule: hit.rule.id, version: TOOL_VERSION },
      });
      if (hit.rule.kind === "hotspot") ruleHotspots.push(finding);
      else ruleFindings.push(finding);
    }

    const warnings = [...inv.warnings, ...ruleScan.warnings, ...secretScan.warnings];
    if (ruleScan.suppressed.length > 0) {
      warnings.push(
        `${ruleScan.suppressed.length} candidate(s) suppressed by inline code-audit:ignore`,
      );
    }

    const engines: CoverageEngine[] = [];
    const externalTools: ExternalToolRecord[] = [];
    const externalSastSecrets: Finding[] = [];
    const externalSca: Finding[] = [];
    let osvReportedFiles: string[] = [];

    if (builtinEnabled) {
      engines.push({
        name: "builtin-rules",
        enabled: true,
        status: "ok",
        detail: `${ruleSet.rules.length} YAML rules, scanned ${ruleScan.scannedFiles} files`,
      });
      engines.push({
        name: "builtin-secrets",
        enabled: true,
        status: "ok",
        detail: `scanned ${secretScan.scannedFiles} text files`,
      });
    } else {
      engines.push({
        name: "builtin-rules",
        enabled: false,
        status: "disabled",
        detail: "not selected by --engines",
      });
      engines.push({
        name: "builtin-secrets",
        enabled: false,
        status: "disabled",
        detail: "not selected by --engines",
      });
    }

    if (!selected.has("opengrep") && !selected.has("semgrep")) {
      engines.push({
        name: "opengrep",
        enabled: false,
        status: "disabled",
        detail: "not selected by --engines",
      });
    }
    if (!selected.has("osv-scanner")) {
      engines.push({
        name: "osv-scanner",
        enabled: false,
        status: "disabled",
        detail: "not selected by --engines",
      });
    }
    if (!selected.has("gitleaks")) {
      engines.push({
        name: "gitleaks",
        enabled: false,
        status: "disabled",
        detail: "not selected by --engines",
      });
    }

    // ---- External engines (Opengrep/Semgrep, OSV-Scanner, Gitleaks) ----
    // The three tools are independent, so they run concurrently. Each returns a
    // normalized outcome; a missing, failing or slow tool never fails the scan.
    interface EngineOutcome {
      engine: CoverageEngine;
      findings: Finding[];
      warnings: string[];
      reportedFiles: string[];
      tool?: ExternalToolRecord;
    }

    const runSastEngine = async (): Promise<EngineOutcome> => {
      let selection: Awaited<ReturnType<typeof selectSastTool>> | undefined;
      if (selected.has("opengrep")) {
        selection = await selectSastTool({ pathEnv });
      } else {
        const semgrep = await findTool("semgrep", { pathEnv });
        selection = semgrep ? { engine: "semgrep", info: semgrep } : undefined;
      }
      if (!selection) {
        return {
          engine: { name: "opengrep", enabled: false, status: "missing", detail: "not found on PATH" },
          findings: [],
          warnings: ["external SAST tool not found (opengrep/semgrep); skipped"],
          reportedFiles: [],
        };
      }
      const info: ToolInfo = selection.info;
      const version = info.version ?? "unknown";
      const tool: ExternalToolRecord = {
        name: selection.engine,
        path: info.path,
        ...(info.version ? { version: info.version } : {}),
      };
      const startedAt = Date.now();
      const result = await runSemgrep({
        root: validated.root,
        toolPath: info.path,
        engine: selection.engine,
        rulesDir: options.opengrepRulesDir ?? defaultOpengrepRulesDir(),
        version: info.version,
      });
      const durationMs = Date.now() - startedAt;
      const base = { name: selection.engine, enabled: true, durationMs };
      if (result.ok) {
        return {
          engine: { ...base, status: "ok", detail: `${result.findings.length} results, version ${version} (${durationMs} ms)` },
          findings: result.findings,
          warnings: result.warnings,
          reportedFiles: [],
          tool,
        };
      }
      if (result.outcome.timedOut) {
        return { engine: { ...base, status: "timeout", detail: "timed out" }, findings: [], warnings: result.warnings, reportedFiles: [], tool };
      }
      return { engine: { ...base, status: "failed", detail: `exit code ${result.outcome.exitCode}` }, findings: [], warnings: result.warnings, reportedFiles: [], tool };
    };

    const runOsvEngine = async (): Promise<EngineOutcome> => {
      const info = await findTool("osv-scanner", { pathEnv });
      if (!info) {
        return {
          engine: { name: "osv-scanner", enabled: false, status: "missing", detail: "not found on PATH" },
          findings: [],
          warnings: ["external tool not found: osv-scanner (skipped)"],
          reportedFiles: [],
        };
      }
      const version = info.version ?? "unknown";
      const tool: ExternalToolRecord = {
        name: "osv-scanner",
        path: info.path,
        ...(info.version ? { version: info.version } : {}),
      };
      const startedAt = Date.now();
      const result = await runOsvScanner({
        root: validated.root,
        toolPath: info.path,
        version: info.version,
        offline,
      });
      const durationMs = Date.now() - startedAt;
      const base = { name: "osv-scanner", enabled: true, durationMs };
      if (result.ok) {
        return {
          engine: { ...base, status: "ok", detail: `${result.findings.length} results, version ${version} (${durationMs} ms)` },
          findings: result.findings,
          warnings: result.warnings,
          reportedFiles: result.reportedFiles,
          tool,
        };
      }
      if (result.outcome.timedOut) {
        return { engine: { ...base, status: "timeout", detail: "timed out" }, findings: [], warnings: result.warnings, reportedFiles: [], tool };
      }
      return { engine: { ...base, status: "failed", detail: `exit code ${result.outcome.exitCode}` }, findings: [], warnings: result.warnings, reportedFiles: [], tool };
    };

    const runGitleaksEngine = async (): Promise<EngineOutcome> => {
      const info = await findTool("gitleaks", { pathEnv });
      if (!info) {
        return {
          engine: { name: "gitleaks", enabled: false, status: "missing", detail: "not found on PATH" },
          findings: [],
          warnings: ["external tool not found: gitleaks (skipped)"],
          reportedFiles: [],
        };
      }
      const version = info.version ?? "unknown";
      const tool: ExternalToolRecord = {
        name: "gitleaks",
        path: info.path,
        ...(info.version ? { version: info.version } : {}),
      };
      const startedAt = Date.now();
      const result = await runGitleaks({
        root: validated.root,
        toolPath: info.path,
        version: info.version,
      });
      const durationMs = Date.now() - startedAt;
      const base = { name: "gitleaks", enabled: true, durationMs };
      if (result.outcome.timedOut) {
        return { engine: { ...base, status: "timeout", detail: "timed out" }, findings: [], warnings: result.warnings, reportedFiles: [], tool };
      }
      if (result.outcome.exitCode !== 0) {
        return { engine: { ...base, status: "failed", detail: `exit code ${result.outcome.exitCode}` }, findings: [], warnings: result.warnings, reportedFiles: [], tool };
      }
      return {
        engine: { ...base, status: "ok", detail: `${result.findings.length} results, version ${version} (${durationMs} ms)` },
        findings: result.findings,
        warnings: result.warnings,
        reportedFiles: [],
        tool,
      };
    };

    const externalTasks: Array<() => Promise<EngineOutcome>> = [];
    if (selected.has("opengrep") || selected.has("semgrep")) externalTasks.push(runSastEngine);
    if (selected.has("osv-scanner")) externalTasks.push(runOsvEngine);
    if (selected.has("gitleaks")) externalTasks.push(runGitleaksEngine);
    const outcomes = await Promise.all(externalTasks.map((task) => task()));
    for (const outcome of outcomes) {
      engines.push(outcome.engine);
      warnings.push(...outcome.warnings);
      if (outcome.tool) externalTools.push(outcome.tool);
      if (outcome.engine.status !== "ok") continue;
      if (outcome.engine.name === "osv-scanner") {
        externalSca.push(...outcome.findings);
        osvReportedFiles = outcome.reportedFiles;
      } else {
        externalSastSecrets.push(...outcome.findings);
      }
    }

    // ---- Built-in SCA (skips lockfiles already covered by OSV-Scanner) ----
    const scaResult = builtinEnabled
      ? await runSca({
          root: validated.root,
          inventory: inv,
          offline,
          http: options.http,
          timeoutMs: 10_000,
          skipLockfiles: osvReportedFiles,
        })
      : emptySca();
    warnings.push(...scaResult.warnings);
    engines.push({
      name: "osv",
      enabled: builtinEnabled && !offline,
      status: !builtinEnabled
        ? "disabled"
        : offline
          ? "offline"
          : scaResult.degraded
            ? "degraded"
            : "ok",
      detail: !builtinEnabled
        ? "builtin engine not selected"
        : offline
          ? "offline mode; queries skipped"
          : `${scaResult.packages.length} dependencies, queried ${scaResult.queriedPackages}` +
            (scaResult.unresolvedManifests.length > 0
              ? `; ${scaResult.unresolvedManifests.length} manifest(s) with unresolved entries`
              : ""),
    });

    const mergedSca = mergeScaFindings(scaResult.findings, externalSca);
    const mergedSastSecrets = crossEngineDedupe([
      ...ruleFindings,
      ...secretScan.findings,
      ...externalSastSecrets,
    ]);
    const merged = dedupeFindings([...mergedSastSecrets, ...mergedSca]);
    const sorted = sortFindings(merged);
    const findings = assignFindingIds(sorted, started.getUTCFullYear());
    const hotspots = assignHotspotIds(
      sortFindings(dedupeFindings(ruleHotspots)),
      started.getUTCFullYear(),
    );

    const coverage = buildCoverage(
      inv,
      ruleSet,
      ruleScan.scannedFiles,
      secretScan.scannedFiles,
      engines,
      warnings,
      ruleScan.suppressed,
    );

    const finished = new Date();
    const durationMs = Math.max(0, Date.now() - startedMs);

    const findingCounts = countSeverities(findings);
    const run = {
      runId,
      tool: {
        name: TOOL_NAME,
        version: TOOL_VERSION,
        node: process.version,
      },
      args: {
        root: validated.input,
        resolvedRoot: validated.root,
        profile,
        formats,
        out: options.out ?? null,
        offline,
        failOn,
        minConfidence,
        lang,
        engines: [...selected],
      },
      startedAt: started.toISOString(),
      finishedAt: finished.toISOString(),
      durationMs,
      rulesCount: ruleSet.rules.length,
      rulesDir: ruleSet.rulesDir,
      externalTools,
      inventory: {
        files: inv.stats.files,
        scannedFiles: inv.stats.scannedFiles,
        skippedFiles: inv.stats.skippedFiles,
        loc: inv.stats.loc,
      },
      sca: {
        packages: scaResult.packages.length,
        queriedPackages: scaResult.queriedPackages,
        vulnIds: scaResult.vulnIds,
        unresolvedManifests: scaResult.unresolvedManifests,
        degraded: scaResult.degraded,
      },
      findingCounts,
      confidenceCounts: countConfidences(findings),
      hotspotCount: hotspots.length,
      suppressedCount: ruleScan.suppressed.length,
      warnings,
    };

    const reportContext = {
      runId,
      target: validated.input,
      startedAt: started.toISOString(),
      finishedAt: finished.toISOString(),
      durationMs,
      toolVersion: TOOL_VERSION,
      nodeVersion: process.version,
      profile,
      offline,
      lang,
      rules: ruleSet.rules,
      findings,
      hotspots,
      coverage,
      warnings,
    };

    fs.writeFileSync(
      path.join(runDir, "run.json"),
      `${JSON.stringify(run, null, 2)}\n`,
      "utf8",
    );
    fs.writeFileSync(
      path.join(runDir, "coverage.json"),
      `${JSON.stringify(coverage, null, 2)}\n`,
      "utf8",
    );
    fs.writeFileSync(
      path.join(runDir, "findings.json"),
      renderFindingsJson(
        {
          runId,
          tool: run.tool,
          startedAt: run.startedAt,
          finishedAt: run.finishedAt,
          durationMs,
          rulesCount: run.rulesCount,
          profile,
          offline,
          failOn,
          minConfidence,
          findingCounts,
          confidenceCounts: run.confidenceCounts,
          suppressedCount: run.suppressedCount,
          warnings,
        },
        findings,
        hotspots,
      ),
      "utf8",
    );
    if (formats.includes("md")) {
      fs.writeFileSync(
        path.join(runDir, "report.md"),
        renderMarkdown(reportContext),
        "utf8",
      );
    }
    if (formats.includes("sarif")) {
      fs.writeFileSync(
        path.join(runDir, "results.sarif"),
        renderSarif(reportContext),
        "utf8",
      );
    }

    const completedState = {
      schemaVersion: 1 as const,
      runId,
      root: validated.root,
      runDir,
      phase: "complete" as const,
      startedAt: started.toISOString(),
      updatedAt: finished.toISOString(),
      finishedAt: finished.toISOString(),
      progress: {
        engine: "complete",
        files: inv.stats.scannedFiles,
        rules: ruleSet.rules.length,
        dependencies: scaResult.packages.length,
      },
      warnings,
    };
    writeRunState(runDir, completedState);
    if (
      !options.out ||
      path.resolve(options.out) === path.join(validated.root, ".audit")
    ) {
      registerRunIndex(validated.root, {
        runId,
        runDir,
        root: validated.root,
        phase: "complete",
        startedAt: started.toISOString(),
        updatedAt: finished.toISOString(),
      });
    }

    return { runId, runDir, findings, hotspots, coverage, warnings, run, durationMs };
  }
}