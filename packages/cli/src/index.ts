#!/usr/bin/env node
import {
  ALL_ENGINES,
  ALL_FORMATS,
  CONFIDENCES,
  SEVERITIES,
  TOOL_VERSION,
  buildBaseline,
  confidenceAtLeast,
  defaultOpengrepRulesDir,
  defaultRulesDir,
  discoverTools,
  isActionable,
  loadOpengrepRules,
  loadRules,
  renderStepSummaryMarkdown,
  renderAnnotations,
  renderWarningAnnotations,
  scanProject,
  serializeBaseline,
  severityAtLeast,
  type BaselineComparison,
  type Confidence,
  type EngineName,
  type ReportFormat,
  type Severity,
} from "@code-audit/core";
import { runMcpServer } from "@code-audit/mcp";
import fs from "node:fs";
import path from "node:path";
import { INSTALL_HOSTS, installAdapter, type InstallHost } from "./install.js";
import { isQueryCommand, runQueryCommand } from "./query.js";

class CliError extends Error {}

const USAGE = `code-audit ${TOOL_VERSION}

Usage:
  code-audit scan <path> [--profile quick|standard] [--format md,json,sarif]
                        [--out <dir>] [--offline] [--no-external]
                        [--engines builtin,opengrep,semgrep,osv-scanner,gitleaks]
                        [--fail-on low|medium|high|critical]
                        [--min-confidence low|medium|high] [--lang en|zh]
                        [--rules <dir>] [--ignore-file <path>] [--no-ignore-file]
                        [--no-inline-ignore]
                        [--baseline <file>] [--no-baseline] [--fail-on-existing]
                        [--since <git-ref>] [--ci] [--latest-link]
  code-audit baseline <run-id|run-dir> [--output <file>]
  code-audit status <run-id|run-dir> [--json]
  code-audit findings <run-id|run-dir> [--kind finding|hotspot|all]
                        [--severity <s>] [--status <s>] [--language <l>]
                        [--min-confidence low|medium|high] [--limit N]
                        [--cursor <c>] [--json]
  code-audit read <run-id|run-dir> <file> [--start N] [--end N] [--json]
  code-audit search <run-id|run-dir> <pattern> [--glob <g>] [--regex]
                        [--max-results N] [--json]
  code-audit verdict <run-id|run-dir> <finding-id|fingerprint>
                        --status confirmed|likely|needs_review|false_positive
                        --rationale <text> [--evidence-line <text>]
                        [--actor <name>] [--reviewer <name>] [--json]
  code-audit add-finding <run-id|run-dir> --rationale <text>
                        [--file <f> --start N [--end N] --title <t>
                         --severity <s> --cwe <cwe> [--confidence <c>]
                         [--source <s>] [--rule-id <id>] [--reviewer <name>]]
                        [--promote <hotspot-id|fingerprint>] [--json]
  code-audit report <run-id|run-dir> [--format md|json|sarif|summary]
                        [--output <file>] [--json]
  code-audit mcp
  code-audit install --host opencode|dsh|claude-code|codex [--project <dir>] [--dry-run]
  code-audit doctor [--json]
  code-audit --help

Exit codes:
  0  completed and no finding reached the thresholds
  1  at least one finding reached --fail-on and --min-confidence
  2  runtime error (arguments, path, rule loading, ...)
`;

interface ToolMeta {
  name: string;
  url: string;
  install: string;
}

const TOOL_META: ToolMeta[] = [
  {
    name: "opengrep",
    url: "https://github.com/opengrep/opengrep",
    install: "install opengrep with your package manager or from the release page",
  },
  {
    name: "semgrep",
    url: "https://semgrep.dev",
    install: "install semgrep with your package manager (pipx install semgrep)",
  },
  {
    name: "osv-scanner",
    url: "https://google.github.io/osv-scanner/",
    install: "install osv-scanner with your package manager or from the release page",
  },
  {
    name: "gitleaks",
    url: "https://github.com/gitleaks/gitleaks",
    install: "install gitleaks with your package manager or from the release page",
  },
];

function takeValue(args: string[], index: number, flag: string): string {
  const value = args[index];
  if (!value || value.startsWith("--")) {
    throw new CliError(`${flag} requires a value`);
  }
  return value;
}

interface ScanArgs {
  root: string;
  profile: "quick" | "standard";
  formats: ReportFormat[];
  out?: string;
  offline: boolean;
  failOn: Severity;
  minConfidence: Confidence;
  lang: "zh" | "en";
  rulesDir?: string;
  engines?: EngineName[];
  ignoreFile?: string;
  noIgnoreFile: boolean;
  noInlineIgnore: boolean;
  baseline?: string;
  noBaseline: boolean;
  failOnExisting: boolean;
  since?: string;
  ci: boolean;
  latestLink: boolean;
}

function parseScanArgs(args: string[]): ScanArgs {
  let root: string | undefined;
  let profile: "quick" | "standard" = "standard";
  let formats: ReportFormat[] = [...ALL_FORMATS];
  let out: string | undefined;
  let offline = false;
  let failOn: Severity = "high";
  let minConfidence: Confidence = "medium";
  let lang: "zh" | "en" = "en";
  let rulesDir: string | undefined;
  let engines: EngineName[] | undefined;
  let ignoreFile: string | undefined;
  let noIgnoreFile = false;
  let noInlineIgnore = false;
  let baseline: string | undefined;
  let noBaseline = false;
  let failOnExisting = false;
  let since: string | undefined;
  let ci = false;
  let latestLink = false;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index] ?? "";
    if (arg === "--help" || arg === "-h") {
      process.stdout.write(USAGE);
      process.exit(0);
    } else if (arg === "--profile") {
      const value = takeValue(args, index + 1, arg);
      index += 1;
      if (value !== "quick" && value !== "standard") {
        throw new CliError(`--profile supports quick|standard, received ${value}`);
      }
      profile = value;
    } else if (arg === "--format") {
      const value = takeValue(args, index + 1, arg);
      index += 1;
      const parsed = value
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean);
      if (parsed.length === 0) throw new CliError("--format cannot be empty");
      for (const format of parsed) {
        if (!ALL_FORMATS.includes(format as ReportFormat)) {
          throw new CliError(`unknown --format: ${format}`);
        }
      }
      formats = [...new Set(parsed)] as ReportFormat[];
    } else if (arg === "--out") {
      out = takeValue(args, index + 1, arg);
      index += 1;
    } else if (arg === "--offline") {
      offline = true;
    } else if (arg === "--fail-on") {
      const value = takeValue(args, index + 1, arg);
      index += 1;
      if (!SEVERITIES.includes(value as Severity)) {
        throw new CliError(`--fail-on supports ${SEVERITIES.join("|")}`);
      }
      failOn = value as Severity;
    } else if (arg === "--min-confidence") {
      const value = takeValue(args, index + 1, arg);
      index += 1;
      if (!CONFIDENCES.includes(value as Confidence)) {
        throw new CliError(`--min-confidence supports ${CONFIDENCES.join("|")}`);
      }
      minConfidence = value as Confidence;
    } else if (arg === "--lang") {
      const value = takeValue(args, index + 1, arg);
      index += 1;
      if (value !== "zh" && value !== "en") {
        throw new CliError("--lang supports en|zh");
      }
      lang = value;
    } else if (arg === "--rules") {
      rulesDir = takeValue(args, index + 1, arg);
      index += 1;
    } else if (arg === "--no-external") {
      engines = ["builtin"];
    } else if (arg === "--engines") {
      const value = takeValue(args, index + 1, arg);
      index += 1;
      const parsed = value
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean);
      if (parsed.length === 0) throw new CliError("--engines cannot be empty");
      for (const engine of parsed) {
        if (!ALL_ENGINES.includes(engine as EngineName)) {
          throw new CliError(
            `--engines supports ${ALL_ENGINES.join("|")}, received ${engine}`,
          );
        }
      }
      engines = [...new Set(parsed)] as EngineName[];
    } else if (arg === "--ignore-file") {
      ignoreFile = takeValue(args, index + 1, arg);
      index += 1;
    } else if (arg === "--no-ignore-file") {
      noIgnoreFile = true;
    } else if (arg === "--no-inline-ignore") {
      noInlineIgnore = true;
    } else if (arg === "--baseline") {
      baseline = takeValue(args, index + 1, arg);
      index += 1;
    } else if (arg === "--no-baseline") {
      noBaseline = true;
    } else if (arg === "--fail-on-existing") {
      failOnExisting = true;
    } else if (arg === "--since") {
      since = takeValue(args, index + 1, arg);
      index += 1;
    } else if (arg === "--ci") {
      ci = true;
    } else if (arg === "--latest-link") {
      latestLink = true;
    } else if (arg.startsWith("-")) {
      throw new CliError(`unknown argument: ${arg}`);
    } else if (!root) {
      root = arg;
    } else {
      throw new CliError(`unexpected positional argument: ${arg}`);
    }
  }

  if (!root) throw new CliError("scan requires a target path");
  return {
    root,
    profile,
    formats,
    out,
    offline,
    failOn,
    minConfidence,
    lang,
    rulesDir,
    engines,
    ignoreFile,
    noIgnoreFile,
    noInlineIgnore,
    baseline,
    noBaseline,
    failOnExisting,
    since,
    ci,
    latestLink,
  };
}

async function runScan(args: string[]): Promise<number> {
  const parsed = parseScanArgs(args);
  const result = await scanProject({
    root: parsed.root,
    profile: parsed.profile,
    formats: parsed.formats,
    out: parsed.out,
    offline: parsed.offline,
    failOn: parsed.failOn,
    minConfidence: parsed.minConfidence,
    lang: parsed.lang,
    rulesDir: parsed.rulesDir,
    engines: parsed.engines,
    ignoreFile: parsed.ignoreFile,
    noIgnoreFile: parsed.noIgnoreFile,
    noInlineIgnore: parsed.noInlineIgnore,
    baseline: parsed.baseline,
    noBaseline: parsed.noBaseline,
    failOnExisting: parsed.failOnExisting,
    since: parsed.since,
    latestLink: parsed.latestLink,
  });

  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  } as Record<string, number>;
  for (const finding of result.findings) {
    if (isActionable(finding)) {
      counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;
    }
  }

  const run = result.run as {
    baseline?: { path: string; entries: number; new: number; existing: number; fixed: number };
    scope?: { since: string; changedFiles: number };
  };
  const baseline = run.baseline;
  const scope = run.scope;

  if (parsed.ci) {
    // CI mode: no colour, no progress lines, compact summary at the end.
    const annotations = renderAnnotations(result.findings);
    for (const line of annotations) process.stdout.write(`${line}\n`);
    const warningAnnotations = renderWarningAnnotations(result.warnings);
    for (const line of warningAnnotations) process.stdout.write(`${line}\n`);
    const reportPaths = [
      path.join(result.runDir, "report.md"),
      path.join(result.runDir, "results.sarif"),
      path.join(result.runDir, "findings.json"),
    ];
    const summary = renderStepSummaryMarkdown({
      findingCounts: counts,
      total: result.findings.filter(isActionable).length,
      hotspots: result.hotspots.length,
      ...(baseline
        ? { baseline: { new: baseline.new, existing: baseline.existing, fixed: baseline.fixed } }
        : {}),
      reportPaths,
      warnings: result.warnings,
    });
    process.stdout.write(summary);
    const stepSummary = process.env.GITHUB_STEP_SUMMARY;
    if (stepSummary) {
      try {
        fs.appendFileSync(stepSummary, summary, "utf8");
      } catch {
        // A read-only or missing step-summary path must not fail the run.
      }
    }
  } else {
    // Suppressed candidates are not counted as findings, and are never hidden.
    const notSuppressed = (finding: { status: string }): boolean =>
      finding.status !== "suppressed";
    const suppressedAll = [...result.findings, ...result.hotspots].filter(
      (finding) => finding.status === "suppressed",
    );
    const suppressedInline = suppressedAll.filter(
      (finding) => finding.suppression?.source === "inline",
    ).length;
    process.stdout.write(
      [
        `code-audit scan completed: ${result.runId}`,
        `Files: ${result.coverage.stats.scannedFiles} scanned${
          (result.coverage.stats.partialFiles ?? 0) > 0
            ? ` (${result.coverage.stats.partialFiles} partially: generated lockfiles, dependencies and high-confidence secrets only)`
            : ""
        } / ${result.coverage.stats.skippedFiles} skipped, LOC ${result.coverage.stats.loc}`,
        `Rules: ${result.coverage.rulesCount}`,
        ...(baseline
          ? [`Baseline: New: ${baseline.new} · Existing: ${baseline.existing} · Fixed: ${baseline.fixed}`]
          : []),
        ...(scope ? [`Scope: files changed since ${scope.since} (${scope.changedFiles} files)`] : []),
        `Findings: ${result.findings.filter(notSuppressed).length} (critical ${counts.critical}, high ${counts.high}, medium ${counts.medium}, low ${counts.low}, info ${counts.info})`,
        `Hotspots: ${result.hotspots.filter(notSuppressed).length}`,
        ...(suppressedAll.length > 0
          ? [
              `Suppressed: ${suppressedAll.length} (ignore file ${suppressedAll.length - suppressedInline}, inline comments ${suppressedInline}); listed in the report`,
            ]
          : []),
        `Duration: ${result.durationMs} ms`,
        `Report directory: ${result.runDir}`,
        "",
      ].join("\n"),
    );
    for (const warning of result.warnings.slice(0, 20)) {
      process.stderr.write(`warning: ${warning}\n`);
    }
    if (result.warnings.length > 20) {
      process.stderr.write(
        `warning: ${result.warnings.length - 20} more warnings; see run.json\n`,
      );
    }
  }

  const baselineActive = Boolean(baseline) && !parsed.failOnExisting;
  const failing = result.findings.some((finding) => {
    if (!isActionable(finding)) return false;
    if (!severityAtLeast(finding.severity, parsed.failOn)) return false;
    if (!confidenceAtLeast(finding.confidence, parsed.minConfidence)) return false;
    if (baselineActive && finding.baselineState === "existing") return false;
    return true;
  });
  return failing ? 1 : 0;
}

async function runBaselineCommand(args: string[]): Promise<number> {
  let ref = "";
  let output: string | undefined;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index] ?? "";
    if (arg === "--help" || arg === "-h") {
      process.stdout.write(USAGE);
      process.exit(0);
    } else if (arg === "--output") {
      output = takeValue(args, index + 1, arg);
      index += 1;
    } else if (arg.startsWith("-")) {
      throw new CliError(`baseline unknown argument: ${arg}`);
    } else if (!ref) {
      ref = arg;
    } else {
      throw new CliError(`baseline unexpected positional argument: ${arg}`);
    }
  }
  if (!ref) throw new CliError("baseline requires a run id or run directory");

  const { loadRun, resolveRunDir } = await import("@code-audit/core");
  const runDir = resolveRunDir(ref);
  const loaded = loadRun(runDir);
  const baseline = buildBaseline(
    loaded.findings,
    new Date().toISOString(),
    `code-audit ${TOOL_VERSION}`,
  );
  const target =
    output ??
    path.join(loaded.root, ".code-audit-baseline.json");
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, serializeBaseline(baseline), "utf8");
  process.stdout.write(
    `baseline written to ${target} (${baseline.entries.length} entries)\n`,
  );
  return 0;
}

async function runDoctor(args: string[]): Promise<number> {
  const asJson = args.includes("--json");
  const unknown = args.filter((arg) => arg !== "--json");
  if (unknown.length > 0) throw new CliError(`doctor unknown arguments: ${unknown.join(" ")}`);

  const major = Number(process.versions.node.split(".")[0] ?? 0);
  const nodeOk = major >= 22;

  let rulesCount = 0;
  let rulesDir = defaultRulesDir();
  let rulesError: string | undefined;
  try {
    const ruleSet = loadRules(rulesDir);
    rulesCount = ruleSet.rules.length;
    rulesDir = ruleSet.rulesDir;
  } catch (error) {
    rulesError = error instanceof Error ? error.message : String(error);
  }

  const opengrepRulesDir = defaultOpengrepRulesDir();
  let opengrepCount = 0;
  let opengrepError: string | undefined;
  try {
    opengrepCount = loadOpengrepRules(opengrepRulesDir).rules.length;
  } catch (error) {
    opengrepError = error instanceof Error ? error.message : String(error);
  }

  const discovered = await discoverTools();
  const externalTools = TOOL_META.map((meta) => {
    const info = discovered[meta.name as keyof typeof discovered];
    return {
      name: meta.name,
      found: Boolean(info),
      path: info?.path ?? null,
      version: info?.version ?? null,
      url: meta.url,
      install: meta.install,
    };
  });

  const sastAvailable = externalTools.some(
    (tool) => (tool.name === "opengrep" || tool.name === "semgrep") && tool.found,
  );
  const osvAvailable = externalTools.some(
    (tool) => tool.name === "osv-scanner" && tool.found,
  );
  const gitleaksAvailable = externalTools.some(
    (tool) => tool.name === "gitleaks" && tool.found,
  );
  const tier1 = [
    ...(sastAvailable ? ["opengrep/semgrep"] : []),
    ...(osvAvailable ? ["osv-scanner"] : []),
    ...(gitleaksAvailable ? ["gitleaks"] : []),
  ];
  const tier = {
    active: tier1.length > 0 ? "Tier 0 + Tier 1" : "Tier 0 only",
    tier0: "builtin-rules, builtin-secrets, builtin-osv",
    tier1,
  };

  const report = {
    node: {
      version: process.versions.node,
      ok: nodeOk,
      required: ">=22",
    },
    rules: {
      dir: rulesDir,
      count: rulesCount,
      opengrepDir: opengrepRulesDir,
      opengrepCount,
      error: rulesError ?? null,
      opengrepError: opengrepError ?? null,
    },
    externalTools,
    tier,
  };

  if (asJson) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    return nodeOk ? 0 : 1;
  }

  process.stdout.write(`code-audit doctor (${TOOL_VERSION})\n`);
  process.stdout.write(
    `Node.js: ${process.versions.node} ${nodeOk ? "OK" : "requires >=22"}\n`,
  );
  process.stdout.write(
    `Rules: ${rulesCount} built-in (${rulesDir})${rulesError ? ` error: ${rulesError}` : ""}\n`,
  );
  process.stdout.write(
    `Opengrep rules: ${opengrepCount} (${opengrepRulesDir})${opengrepError ? ` error: ${opengrepError}` : ""}\n`,
  );
  process.stdout.write(`Active tier: ${tier.active}\n`);
  process.stdout.write("External tools (detection only, not invoked):\n");
  for (const tool of externalTools) {
    if (tool.found) {
      process.stdout.write(
        `  ${tool.name.padEnd(14)} found  ${tool.path ?? ""}${tool.version ? ` (${tool.version})` : ""}\n`,
      );
    } else {
      process.stdout.write(`  ${tool.name.padEnd(14)} missing\n`);
      process.stdout.write(
        `    ${tool.url} — ${tool.install}.\n`,
      );
    }
  }
  return nodeOk ? 0 : 1;
}

interface InstallArgs {
  host: InstallHost;
  project: string;
  dryRun: boolean;
}

function parseInstallArgs(args: string[]): InstallArgs {
  let host: InstallHost | undefined;
  let project = process.cwd();
  let dryRun = false;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index] ?? "";
    if (arg === "--help" || arg === "-h") {
      process.stdout.write(USAGE);
      process.exit(0);
    } else if (arg === "--host") {
      const value = takeValue(args, index + 1, arg);
      index += 1;
      if (!INSTALL_HOSTS.includes(value as InstallHost)) {
        throw new CliError(
          `--host supports ${INSTALL_HOSTS.join("|")}, received ${value}`,
        );
      }
      host = value as InstallHost;
    } else if (arg === "--project") {
      project = takeValue(args, index + 1, arg);
      index += 1;
    } else if (arg === "--dry-run") {
      dryRun = true;
    } else if (arg.startsWith("-")) {
      throw new CliError(`install unknown argument: ${arg}`);
    } else {
      throw new CliError(`install unexpected positional argument: ${arg}`);
    }
  }
  if (!host) throw new CliError("install requires --host");
  return { host, project, dryRun };
}

function runInstall(args: string[]): number {
  const parsed = parseInstallArgs(args);
  const result = installAdapter(parsed);
  process.stdout.write(
    [
      `code-audit install --host ${result.host}${result.dryRun ? " (dry run)" : ""}`,
      `Project: ${result.project}`,
      ...result.actions.map(
        (action) =>
          `  ${action.action.padEnd(9)} ${action.path}${action.backup ? ` (backup: ${action.backup})` : ""}`,
      ),
      "",
    ].join("\n"),
  );
  return 0;
}

async function main(): Promise<void> {  const argv = process.argv.slice(2);
  const command = argv[0];
  try {
    if (!command || command === "--help" || command === "-h") {
      process.stdout.write(USAGE);
      process.exitCode = 0;
      return;
    }
    if (command === "scan") {
      process.exitCode = await runScan(argv.slice(1));
      return;
    }
    if (command === "baseline") {
      process.exitCode = await runBaselineCommand(argv.slice(1));
      return;
    }
    if (command === "doctor") {
      process.exitCode = await runDoctor(argv.slice(1));
      return;
    }
    if (command === "install") {
      process.exitCode = runInstall(argv.slice(1));
      return;
    }
    if (isQueryCommand(command)) {
      process.exitCode = runQueryCommand(command, argv.slice(1));
      return;
    }
    if (command === "mcp") {
      if (argv.length > 1) {
        throw new CliError(`mcp does not accept arguments: ${argv.slice(1).join(" ")}`);
      }
      await runMcpServer();
      return;
    }
    throw new CliError(`unknown command: ${command}`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`code-audit: ${message}\n`);
    if (error instanceof CliError) {
      process.stderr.write(`\n${USAGE}`);
    }
    process.exitCode = 2;
  }
}

void main();
