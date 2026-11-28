import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { CoverageReport, CoverageEngine } from "./coverage.js";
import {
  ADJUSTMENT_DEV_DEPENDENCY,
  ADJUSTMENT_OPTIONAL_DEPENDENCY,
  ADJUSTMENT_PLACEHOLDER,
  PATH_CONTEXTS,
  assignFindingIds,
  assignHotspotIds,
  createFinding,
  lowerConfidence,
  restoreConfidence,
  dedupeFindings,
  disambiguateFingerprints,
  sortFindings,
  type Confidence,
  type Finding,
  type Severity,
} from "./finding.js";
import { scanBinaryRules } from "./binaryRules.js";
import { inventory, type InventoryResult } from "./inventory.js";
import { SOURCE_LIKE_LANGUAGES, type Language } from "./language.js";
import { defaultRulesDir, TOOL_NAME, TOOL_VERSION } from "./meta.js";
import { validateAuditRoot } from "./pathJail.js";
import {
  applyPathContext,
  countPathContexts,
  type PathContextFile,
} from "./pathContext.js";
import {
  buildReportContext,
  countAdjustments,
  findingsJsonRun,
  renderFindingsJson,
  renderMarkdown,
  renderSarif,
  singleLineText,
  summarizeRun,
  summaryCountFields,
  type FindingSummary,
  type ReportLang,
  type RepositoryControls,
} from "./report.js";
import {
  loadRules,
  scanRules,
  type LoadedRule,
  type RuleHit,
  type RuleScanResult,
  type RuleSet,
} from "./rules.js";
import { isCredentialFinding, redactText } from "./redact.js";
import {
  prepareRunOutput,
  registerRunIndex,
  ruleSetHash,
  writeLatestCopies,
  writeRunFile,
  writeRunState,
} from "./runstore.js";
import { runSca, manifestLockfileIssues, type HttpClient, type ScaResult } from "./sca.js";
import { scanSecrets } from "./secrets.js";
import {
  loadIgnoreFile,
  matchIgnoreEntry,
  resolveIgnoreFile,
  type IgnoreEntry,
} from "./ignore.js";
import {
  buildBaseline,
  compareBaseline,
  readBaseline,
  serializeBaseline,
  type BaselineComparison,
  type BaselineDocument,
  type BaselineEntry,
} from "./baseline.js";
import { listChangedFiles } from "./git.js";
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
export type { RepositoryControls };

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
  /** Path to a `.code-audit-ignore` file; defaults to `<root>/.code-audit-ignore`. */
  ignoreFile?: string;
  /** Disable the ignore file entirely (audits that must see everything). */
  noIgnoreFile?: boolean;
  /**
   * Do not honour inline `code-audit:ignore` comments. The comments come from
   * the audited repository; an audit that must see everything sets this.
   */
  noInlineIgnore?: boolean;
  /** Path to a baseline file; defaults to `<root>/.code-audit-baseline.json`. */
  baseline?: string;
  /** Disable the automatic baseline file. */
  noBaseline?: boolean;
  /** Treat existing (baseline) findings as failing too. */
  failOnExisting?: boolean;
  /** Only report findings in files changed since this git ref. */
  since?: string;
  /** Write the baseline to this path instead of the default location. */
  baselineOutput?: string;
  /** Copy the produced report files to `<out>/latest/` after a successful write. */
  latestLink?: boolean;
  /**
   * Do not lower the confidence of findings in test, docs, example, vendored
   * and generated files. The path context is still recorded on each finding.
   */
  includeTests?: boolean;
  /** Do not lower the confidence of advisories in dev-only dependencies. */
  includeDev?: boolean;
  /**
   * Report secrets whose value looks like a placeholder (`changeme`,
   * `AKIA...EXAMPLE`) at the detector's normal confidence.
   */
  includePlaceholders?: boolean;
  /**
   * Audit of a repository that is not trusted. Turns off everything the
   * audited repository could use to lower what counts toward the exit code:
   * implies `noIgnoreFile`, `noBaseline`, `noInlineIgnore`, `includeTests`,
   * `includeDev` and `includePlaceholders`, scans default-excluded directories
   * (all but `.git`) and the tool's own adapter files.
   */
  untrusted?: boolean;
}

/** True when `file` is `root` or lies below it (both absolute). */
function isInsideRoot(root: string, file: string): boolean {
  let real = file;
  try {
    real = fs.realpathSync(file);
  } catch {
    real = path.resolve(file);
  }
  const relative = path.relative(root, real);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

/**
 * Configuration files of the external engines. Each engine reads its own from
 * the directory it scans, so the audited repository can narrow what that
 * engine reports; the scan says so when one is present.
 */
const EXTERNAL_CONTROL_FILES: ReadonlyArray<{ engines: EngineName[]; files: string[] }> = [
  { engines: ["gitleaks"], files: [".gitleaks.toml", ".gitleaksignore"] },
  { engines: ["opengrep", "semgrep"], files: [".semgrepignore"] },
  { engines: ["osv-scanner"], files: ["osv-scanner.toml"] },
];

export interface ScanResult {
  runId: string;
  runDir: string;
  findings: Finding[];
  hotspots: Finding[];
  coverage: CoverageReport;
  warnings: string[];
  run: Record<string, unknown>;
  /**
   * The counting model applied with the policy recorded in `run.args`; the
   * same object as `run.summary` and `run.summary` in findings.json.
   */
  summary: FindingSummary;
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
  return SOURCE_LIKE_LANGUAGES.includes(language) ? "sast" : "config";
}

function buildCoverage(
  inv: InventoryResult,
  ruleSet: RuleSet,
  ruleScannedFiles: number,
  secretScannedFiles: number,
  engines: CoverageEngine[],
  warnings: string[],
  suppressed: CoverageReport["suppressed"],
  scope?: { outOfScope: number; sinceRef?: string; changedFileCount: number },
  pathContextLowering = true,
): CoverageReport {
  const pathContextFiles = Object.fromEntries(
    PATH_CONTEXTS.map((context) => [context, 0]),
  ) as NonNullable<CoverageReport["pathContext"]>["files"];
  for (const file of inv.files) {
    if (file.pathContext) pathContextFiles[file.pathContext] += 1;
  }
  const scannedFiles = inv.files.map((file) => {
    const fileEngines: string[] = [];
    if (file.isLockfile) fileEngines.push("sca");
    if (file.scannable) {
      fileEngines.push("builtin-secrets");
      if (file.language !== "unknown") fileEngines.push("builtin-rules");
    } else if (file.isLockfile) {
      // Generated lockfile: high-confidence secret detectors only, no rules.
      fileEngines.push("builtin-secrets:high-confidence");
    }
    return {
      path: file.relPath,
      language: file.language,
      loc: file.loc,
      engines: fileEngines,
      ...(file.pathContext ? { pathContext: file.pathContext } : {}),
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
    pathContext: { lowering: pathContextLowering, files: pathContextFiles },
    ...(inv.binaryListIncomplete.length > 0 ? { binaryListIncomplete: inv.binaryListIncomplete } : {}),
    ...(scope
      ? {
          scope: {
            since: scope.sinceRef ?? null,
            changedFiles: scope.changedFileCount,
            outOfScope: scope.outOfScope,
          },
        }
      : {}),
  };
}

function emptyRuleScan(): RuleScanResult {
  return {
    hits: [],
    suppressedHits: [],
    suppressed: [],
    warnings: [],
    scannedFiles: 0,
    redactions: new Map(),
  };
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
  if (options.profile === "quick") return new Set<EngineName>(["builtin"]);
  return new Set(ALL_ENGINES);
}

interface ExternalToolRecord {
  name: string;
  path: string;
  version?: string;
}

/**
 * Evidence from an external engine is text of the audited repository like any
 * other: it goes through the shared line redaction. On a line where a
 * `redactEvidence` rule matched, or for a credential finding, every string
 * literal is masked (the column ranges of the built-in match cannot be mapped
 * onto the external tool's snippet).
 */
function redactExternalEvidence(finding: Finding, ruleScan: RuleScanResult): Finding {
  const lines = ruleScan.redactions.get(finding.file);
  let onRedactedLine = false;
  if (lines) {
    for (let line = finding.startLine; line <= finding.endLine; line += 1) {
      if (lines.has(line)) onRedactedLine = true;
      if (line - finding.startLine > 50) break;
    }
  }
  const evidence = redactText(finding.evidence, {
    file: finding.file,
    maskAllStrings: onRedactedLine || isCredentialFinding(finding),
  });
  return evidence === finding.evidence ? finding : { ...finding, evidence };
}

export async function scanProject(options: ScanOptions): Promise<ScanResult> {
  const started = (options.now ?? (() => new Date()))();
  const startedMs = Date.now();
  const validated = validateAuditRoot(options.root);
  const formats = options.formats ?? ALL_FORMATS;
  const profile = options.profile ?? "standard";
  const lang = options.lang ?? "en";
  // `quick`: built-in engines only and no network, so a scan finishes in
  // seconds (pre-commit hooks, editor saves). An explicit engine list still
  // wins; `standard` runs every installed engine and queries OSV.dev.
  const offline = options.offline === true || profile === "quick";
  const failOn = options.failOn ?? "high";
  const minConfidence = options.minConfidence ?? "medium";
  const ruleSet = loadRules(options.rulesDir ?? defaultRulesDir());
  const selected = resolveEngines(options);
  // `--untrusted`: nothing the audited repository contains may lower the result.
  const untrusted = options.untrusted === true;
  const noIgnoreFile = untrusted || options.noIgnoreFile === true;
  const noBaseline = untrusted || options.noBaseline === true;
  const noInlineIgnore = untrusted || options.noInlineIgnore === true;
  const builtinEnabled = selected.has("builtin");
  const pathEnv = options.pathEnv;

  const runId = options.runId ?? makeRunId(started);
  // The run directory is created below the audit root (or below an `--out`
  // outside it) one component at a time: a `.audit`, `--out` or `latest` that
  // is a symbolic link leaving that directory is refused, and every file is
  // written without following a link at its path.
  const output = prepareRunOutput(validated.root, options.out, runId);
  const runDir = output.runDir;
  // Runs in the project's own `.audit` are listed in `.audit/index.json`.
  const indexed = ((): boolean => {
    try {
      return fs.realpathSync.native(path.join(validated.root, ".audit")) === output.outDir;
    } catch {
      return false;
    }
  })();
  const outputWarnings: string[] = [];
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
  if (indexed) {
    outputWarnings.push(
      ...registerRunIndex(validated.root, {
        runId,
        runDir,
        root: validated.root,
        phase: "running",
        startedAt: started.toISOString(),
        updatedAt: started.toISOString(),
      }),
    );
  }

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
    if (indexed) {
      registerRunIndex(validated.root, {
        runId,
        runDir,
        root: validated.root,
        phase: "failed",
        startedAt: started.toISOString(),
        updatedAt: new Date().toISOString(),
      });
    }
    throw error;
  }

  async function executeScan(): Promise<ScanResult> {
    const inv = inventory(validated.root, { ownRunDirs: [runDir], untrusted });
    const ruleScan = builtinEnabled
      ? scanRules(inv.files, ruleSet, { inlineIgnore: !noInlineIgnore })
      : emptyRuleScan();
    // Files recognised as the tool's own output are not matched against rules
    // but still go through the secret detectors.
    const secretScan = builtinEnabled
      ? scanSecrets([...inv.files, ...inv.toolOutput], {
          lineRedactions: (file) => ruleScan.redactions.get(file),
        })
      : emptySecretScan();

    const findingOfHit = (hit: RuleHit): Finding =>
      createFinding({
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

    const ruleFindings: Finding[] = [];
    const ruleHotspots: Finding[] = [];
    // Binary files in skill and plugin directories (see `binaryRules.ts`).
    const binaryHits = builtinEnabled ? scanBinaryRules(inv.binaries, ruleSet) : [];
    for (const hit of [...ruleScan.hits, ...binaryHits]) {
      const finding = findingOfHit(hit);
      if (hit.rule.kind === "hotspot") ruleHotspots.push(finding);
      else ruleFindings.push(finding);
    }
    // Candidates that an inline `code-audit:ignore` comment suppressed stay in
    // the results, marked as suppressed: the comment comes from the audited
    // repository, so what it hides must remain visible to the reviewer.
    const inlineSuppressedFindings: Finding[] = [];
    const inlineSuppressedHotspots: Finding[] = [];
    for (const hit of ruleScan.suppressedHits) {
      const finding: Finding = {
        ...findingOfHit(hit),
        status: "suppressed",
        suppression: { source: "inline", reason: hit.suppressedBy ?? "" },
      };
      if (hit.rule.kind === "hotspot") inlineSuppressedHotspots.push(finding);
      else inlineSuppressedFindings.push(finding);
    }

    // Manifest hygiene: one low-confidence hotspot per manifest that has no
    // lockfile next to it. This reuses the inventory detection that already
    // produces the "no matching lockfile found" warning.
    const lockfileHotspots: Finding[] = builtinEnabled
      ? manifestLockfileIssues(inv).map((issue) =>
          createFinding({
            ruleId: "dep-missing-lockfile",
            title: "Manifest has no lockfile next to it",
            category: "config",
            severity: "low",
            confidence: "low",
            kind: "hotspot",
            cwe: "CWE-1104",
            owasp: "A06:2021",
            language: issue.manifest === "package.json" ? "json" : "yaml",
            file: issue.file,
            startLine: issue.line,
            evidence: `no lockfile next to ${issue.manifest}`,
            message:
              "A manifest without a lockfile resolves floating versions, so builds are not reproducible.",
            remediation: /\.(?:cs|fs|vb)proj$/i.test(issue.manifest)
              ? "Set RestorePackagesWithLockFile to true (in the project or Directory.Build.props), commit packages.lock.json and restore with --locked-mode."
              : "Commit a lockfile (package-lock.json, pnpm-lock.yaml, yarn.lock, poetry.lock or requirements.txt) and install with it.",
            provenance: {
              engine: "builtin-rules",
              rule: "dep-missing-lockfile",
              version: TOOL_VERSION,
            },
          }),
        )
      : [];

    const warnings = [...inv.warnings, ...ruleScan.warnings, ...secretScan.warnings];
    warnings.push(...outputWarnings);
    if (ruleScan.suppressed.length > 0) {
      warnings.push(
        `${ruleScan.suppressed.length} candidate(s) suppressed by inline code-audit:ignore comments in the audited repository; they are listed under suppressed findings (use --no-inline-ignore to report them as active)`,
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
      for (const warning of outcome.warnings) warnings.push(warning);
      if (outcome.tool) externalTools.push(outcome.tool);
      if (outcome.engine.status !== "ok") continue;
      if (outcome.engine.name === "osv-scanner") {
        for (const finding of outcome.findings) externalSca.push(finding);
        osvReportedFiles = outcome.reportedFiles;
      } else {
        for (const finding of outcome.findings) {
          externalSastSecrets.push(redactExternalEvidence(finding, ruleScan));
        }
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
    for (const warning of scaResult.warnings) warnings.push(warning);
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

    // ---- Confidence adjustments (never drop, always say why) ----
    // Path context: what the inventory knows about each file. A file reported
    // only by an external engine (the inventory skipped it) is classified by
    // its path alone.
    const fileInfo = new Map<string, PathContextFile>();
    for (const file of inv.files) {
      fileInfo.set(file.relPath, {
        pathContext: file.pathContext,
        pathContextSource: file.pathContextSource,
        kind: file.kind,
        language: file.language,
      });
    }
    const includeTests = untrusted || options.includeTests === true;
    const includeDev = untrusted || options.includeDev === true;
    const includePlaceholders = untrusted || options.includePlaceholders === true;
    // Placeholder classification is made by the secret detectors; with
    // `--include-placeholders` the detector's own confidence is kept.
    const withPlaceholderPolicy = (finding: Finding): Finding =>
      includePlaceholders && finding.adjustments?.includes(ADJUSTMENT_PLACEHOLDER)
        ? restoreConfidence(finding)
        : finding;
    // A finding inside a Rust `#[cfg(test)]` module of a file that has no
    // path context of its own is treated like one in a test path.
    const testRegions = ruleScan.testRegions;
    const inTestRegion = (finding: Finding): boolean =>
      testRegions?.get(finding.file)?.some(
        (region) => finding.startLine >= region.from && finding.startLine <= region.to,
      ) === true;
    const withPathContext = (finding: Finding): Finding => {
      const info = fileInfo.get(finding.file);
      if (!info?.pathContext && inTestRegion(finding)) {
        return applyPathContext(
          finding,
          { ...info, pathContext: "test", pathContextSource: "region" },
          { includeTests },
        );
      }
      return applyPathContext(finding, info, { includeTests });
    };
    // Dev-only dependencies: an advisory in build or test tooling rarely
    // affects what is shipped. It becomes a low-confidence candidate (out of
    // the headline and the exit code at the default threshold) and stays
    // listed with full data; an optional dependency is lowered one step.
    // `--include-dev` restores full weight for both.
    const withDevScope = (finding: Finding): Finding => {
      if (includeDev || finding.category !== "sca") return finding;
      if (finding.dependencyScope === "dev") {
        return lowerConfidence(finding, ADJUSTMENT_DEV_DEPENDENCY, "low");
      }
      if (finding.dependencyScope === "optional") {
        return lowerConfidence(finding, ADJUSTMENT_OPTIONAL_DEPENDENCY, "step");
      }
      return finding;
    };

    const mergedSca = mergeScaFindings(scaResult.findings, externalSca).map(withDevScope);
    const mergedSastSecrets = crossEngineDedupe([
      ...ruleFindings,
      ...secretScan.findings.map(withPlaceholderPolicy),
      ...externalSastSecrets.map(withPlaceholderPolicy),
    ]);
    const merged = dedupeFindings(
      disambiguateFingerprints([
        ...mergedSastSecrets,
        ...mergedSca,
        ...inlineSuppressedFindings,
      ]),
    ).map(withPathContext);
    const sorted = sortFindings(merged);
    let findings = assignFindingIds(sorted, started.getUTCFullYear());
    let hotspots = assignHotspotIds(
      sortFindings(
        dedupeFindings(
          disambiguateFingerprints([
            ...ruleHotspots,
            ...lockfileHotspots,
            ...inlineSuppressedHotspots,
          ]),
        ).map(withPathContext),
      ),
      started.getUTCFullYear(),
    );

    // ---- Ignore file: mark matching findings and hotspots as suppressed ----
    const ignorePath = resolveIgnoreFile({
      root: validated.root,
      ignoreFile: options.ignoreFile,
      noIgnoreFile,
    });
    let ignoreEntries: IgnoreEntry[] = [];
    if (ignorePath) {
      const loaded = loadIgnoreFile(ignorePath);
      ignoreEntries = loaded?.entries ?? [];
      const today = started.toISOString().slice(0, 10);
      const matchedEntries = new Set<number>();
      const applySuppression = (finding: Finding): Finding => {
        if (finding.suppression) return finding;
        const match = matchIgnoreEntry(
          ignoreEntries,
          {
            fingerprint: finding.fingerprint,
            ruleId: finding.ruleId,
            file: finding.file,
            advisoryId: finding.advisoryId,
            aliases: finding.aliases,
            packageName: finding.package,
          },
          today,
        );
        if (!match) return finding;
        matchedEntries.add(match.entry);
        const matchedEntry = ignoreEntries[match.entry];
        return {
          ...finding,
          status: "suppressed",
          suppression: {
            source: "ignore-file",
            entry: match.entry,
            reason: match.reason,
            ...(matchedEntry?.expires ? { expires: matchedEntry.expires } : {}),
          },
        };
      };
      findings = findings.map(applySuppression);
      hotspots = hotspots.map(applySuppression);
      for (let index = 0; index < ignoreEntries.length; index += 1) {
        const entry = ignoreEntries[index];
        if (!entry) continue;
        if (entry.expires && entry.expires < today) {
          warnings.push(`ignore entry #${index} expired on ${entry.expires}`);
        } else if (!matchedEntries.has(index)) {
          warnings.push(`ignore entry #${index} matched no finding`);
        }
      }
    }

    // ---- Incremental scope: keep only findings in files changed since <ref> --
    let changedFiles: Set<string> | undefined;
    let sinceRef: string | undefined;
    let outOfScope = 0;
    if (options.since) {
      const scope = await listChangedFiles(validated.root, options.since, {
        pathEnv,
        outputDir: path.dirname(runDir),
      });
      sinceRef = scope.ref;
      for (const warning of scope.warnings) warnings.push(warning);
      changedFiles = new Set(scope.files);
      // Paths from git and paths from the directory walk can spell one file
      // differently: Unicode normalisation (macOS), and letter case on a
      // case-insensitive file system. Compared in one canonical form, so
      // that a spelling difference never takes a changed file out of scope.
      const caseInsensitive = process.platform === "darwin" || process.platform === "win32";
      const canonical = (file: string): string => {
        const normalized = file.normalize("NFC");
        return caseInsensitive ? normalized.toLowerCase() : normalized;
      };
      const changedCanonical = new Set(scope.files.map(canonical));
      // Submodules and nested repositories are not compared file by file:
      // everything below them is in scope.
      const scopeDirectories = scope.directories.map((dir) => `${canonical(dir)}/`);
      const inScope = (file: string): boolean => {
        const name = canonical(file);
        return changedCanonical.has(name) || scopeDirectories.some((dir) => name.startsWith(dir));
      };
      const beforeFindings = findings.length;
      const beforeHotspots = hotspots.length;
      findings = findings.filter((finding) => inScope(finding.file));
      hotspots = hotspots.filter((hotspot) => inScope(hotspot.file));
      outOfScope =
        beforeFindings - findings.length + (beforeHotspots - hotspots.length);
    }

    // ---- Baseline: mark new/existing and compute fixed ----
    let baselineDoc: BaselineDocument | undefined;
    let baselinePath: string | undefined;
    let baselineCounts: BaselineComparison | undefined;
    let baselineFixed: BaselineEntry[] = [];
    if (!noBaseline) {
      const explicit = options.baseline
        ? path.isAbsolute(options.baseline)
          ? path.resolve(options.baseline)
          : path.resolve(validated.root, options.baseline)
        : undefined;
      const defaultPath = path.join(validated.root, ".code-audit-baseline.json");
      const resolved = explicit ?? (fs.existsSync(defaultPath) ? defaultPath : undefined);
      if (resolved) {
        baselineDoc = readBaseline(resolved);
        baselinePath = resolved;
        const comparison = compareBaseline(baselineDoc, findings);
        baselineCounts = comparison.counts;
        baselineFixed = comparison.fixed;
        findings = findings.map((finding) => {
          const state = comparison.states.get(finding.fingerprint);
          return state ? { ...finding, baselineState: state } : finding;
        });
      }
    }

    // ---- What the audited repository itself contributed to the result ----
    const repositoryControls: RepositoryControls = {
      untrusted,
      baselineFromRepository: baselinePath !== undefined && isInsideRoot(validated.root, baselinePath),
      ignoreFileFromRepository:
        ignorePath !== undefined &&
        fs.existsSync(ignorePath) &&
        isInsideRoot(validated.root, ignorePath),
      // With `--untrusted` only the tool's own `.audit/` directory is left.
      toolOutputFiles: untrusted ? 0 : inv.toolOutput.length + inv.toolOutputUnread,
      excludedSourceFiles: inv.excludedSource,
    };
    if (inv.toolOutputUnread > 0) {
      warnings.push(
        `${inv.toolOutputUnread} file(s) recognised as code-audit output were too large or unreadable and were not scanned for secrets`,
      );
    }
    for (const control of EXTERNAL_CONTROL_FILES) {
      if (!control.engines.some((engine) => selected.has(engine))) continue;
      const present = control.files.filter((name) => fs.existsSync(path.join(validated.root, name)));
      if (present.length > 0) {
        warnings.push(
          `the audited repository supplies ${present.join(" and ")}: ${control.engines.join(" / ")} reads it and may report less because of it (run with --engines builtin, or remove the file from a copy, to rule that out)`,
        );
      }
    }

    // Warnings quote file names of the audited repository: one line each,
    // control characters replaced, capped. (In place: coverage and the run
    // record share this array.)
    for (let index = 0; index < warnings.length; index += 1) {
      warnings[index] = singleLineText(warnings[index] as string, 500);
    }

    const coverage = buildCoverage(
      inv,
      ruleSet,
      ruleScan.scannedFiles,
      secretScan.scannedFiles,
      engines,
      warnings,
      ruleScan.suppressed,
      { outOfScope, sinceRef, changedFileCount: changedFiles?.size ?? 0 },
      !includeTests,
    );

    // The path classification comes from the audited repository. Counts go
    // into the run so every report can show how much it changed.
    const pathContextCounts = countPathContexts(findings);
    const adjustmentCounts = countAdjustments(findings);
    const sourceFiles = inv.files.filter((file) => file.kind === "source");
    const contextSourceFiles = sourceFiles.filter((file) => file.pathContext).length;
    // A project whose code mostly sits in such paths is either laid out
    // unusually or laid out to be overlooked: say it once, in words.
    if (
      !includeTests &&
      pathContextCounts.lowered > 0 &&
      sourceFiles.length >= 4 &&
      contextSourceFiles * 2 > sourceFiles.length
    ) {
      warnings.push(
        `${contextSourceFiles} of ${sourceFiles.length} source files are classified as test, docs, example, vendored or generated by their path; the confidence of ${pathContextCounts.lowered} finding(s) was lowered for that reason (use --include-tests to keep the reported confidence)`,
      );
    }

    const finished = new Date();
    const durationMs = Math.max(0, Date.now() - startedMs);

    // Everything a later `report` / `status` needs to print the same numbers
    // is recorded here: the effective policy in `args`, the baseline result.
    const baselineUsed = Boolean(baselineDoc && baselinePath && baselineCounts);
    const runRecord: Record<string, unknown> = {
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
        failOnExisting: options.failOnExisting === true,
        baselineUsed,
        lang,
        engines: [...selected],
        inlineIgnore: !noInlineIgnore,
        noInlineIgnore,
        includeTests,
        includeDev,
        includePlaceholders,
        untrusted,
      },
      startedAt: started.toISOString(),
      finishedAt: finished.toISOString(),
      durationMs,
      rulesCount: ruleSet.rules.length,
      rulesDir: ruleSet.rulesDir,
      rulesHash: ruleSetHash(ruleSet),
      repositoryControls,
      externalTools,
      inventory: {
        files: inv.stats.files,
        scannedFiles: inv.stats.scannedFiles,
        partialFiles: inv.stats.partialFiles,
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
      ...(baselineDoc && baselinePath && baselineCounts
        ? {
            baseline: {
              path: baselinePath,
              entries: baselineDoc.entries.length,
              new: baselineCounts.new,
              existing: baselineCounts.existing,
              fixed: baselineCounts.fixed,
            },
            baselineFixed,
          }
        : {}),
      ...(sinceRef
        ? { scope: { since: sinceRef, changedFiles: changedFiles?.size ?? 0 } }
        : {}),
      warnings,
    };
    // One summary for run.json, findings.json, the reports and the caller.
    const summary = summarizeRun(runRecord, findings, hotspots);
    const { findings: _headlineTotal, ...countFields } = summaryCountFields(summary);
    const run: Record<string, unknown> = {
      ...runRecord,
      ...countFields,
      pathContext: pathContextCounts,
      adjustments: adjustmentCounts,
    };

    const reportContext = buildReportContext(run, {
      findings,
      hotspots,
      coverage,
      rules: ruleSet.rules,
    });

    writeRunFile(runDir, "run.json", `${JSON.stringify(run, null, 2)}\n`);
    writeRunFile(runDir, "coverage.json", `${JSON.stringify(coverage, null, 2)}\n`);
    writeRunFile(
      runDir,
      "findings.json",
      renderFindingsJson(findingsJsonRun(run), findings, hotspots),
    );
    if (formats.includes("md")) {
      writeRunFile(runDir, "report.md", renderMarkdown(reportContext));
    }
    if (formats.includes("sarif")) {
      writeRunFile(runDir, "results.sarif", renderSarif(reportContext));
    }

    // --latest-link: plain copies (never a symlink) of the produced report
    // files under `<out>/latest/`, so CI can reference a stable path.
    if (options.latestLink) {
      const produced = ["findings.json"];
      if (formats.includes("md")) produced.push("report.md");
      if (formats.includes("sarif")) produced.push("results.sarif");
      writeLatestCopies(output, produced);
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
    if (indexed) {
      registerRunIndex(validated.root, {
        runId,
        runDir,
        root: validated.root,
        phase: "complete",
        startedAt: started.toISOString(),
        updatedAt: finished.toISOString(),
      });
    }

    return { runId, runDir, findings, hotspots, coverage, warnings, run, summary, durationMs };
  }
}