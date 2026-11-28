#!/usr/bin/env node
import {
  ALL_ENGINES,
  ALL_FORMATS,
  CONFIDENCES,
  SEVERITIES,
  TOOL_VERSION,
  allowSensitiveRoot,
  appendFileNoFollow,
  buildBaseline,
  countOptionsOf,
  defaultOpengrepRulesDir,
  defaultRulesDir,
  discoverTools,
  monorepoRootDir,
  loadOpengrepRules,
  loadRules,
  renderRunScopeText,
  renderStepSummaryMarkdown,
  renderSummaryText,
  renderAnnotations,
  renderWarningAnnotations,
  runPolicy,
  scanProject,
  type BaselineComparison,
  type Confidence,
  type EngineName,
  type ReportFormat,
  type Severity,
  initRunVerdicts,
} from "@code-audit/core";
import { runMcpServer } from "@code-audit/mcp";
import fs from "node:fs";
import path from "node:path";
import {
  DEFAULT_MCP_COMMAND,
  INSTALL_HOSTS,
  bundledMcpCommand,
  inspectInstall,
  installAdapter,
  resolveCommand,
  uninstallAdapter,
  type InstallAction,
  type InstallHost,
  type ProjectInstallStatus,
} from "./install.js";
import { isQueryCommand, runQueryCommand } from "./query.js";

class CliError extends Error {}

const USAGE = `code-audit ${TOOL_VERSION}

Usage:
  code-audit scan <path> [--profile quick|standard] [--format md,json,sarif]
                        [--out <dir>] [--offline] [--no-external]
                        [--engines builtin,opengrep,semgrep,osv-scanner,gitleaks]
                        [--fail-on info|low|medium|high|critical]
                        [--min-confidence low|medium|high] [--lang en|zh]
                        [--rules <dir>] [--ignore-file <path>] [--no-ignore-file]
                        [--no-inline-ignore] [--include-tests] [--include-dev]
                        [--include-placeholders] [--untrusted]
                        [--baseline <file>] [--no-baseline] [--fail-on-existing]
                        [--since <git-ref>] [--ci] [--latest-link]
                        [--allow-sensitive-root]
                        [--strict-evidence]
  code-audit baseline <run-id|run-dir> [--output <file>]
  code-audit status <run-id|run-dir> [--root <dir>] [--json]
  code-audit findings <run-id|run-dir> [--kind finding|hotspot|all]
                        [--severity <s>] [--status <s>] [--language <l>]
                        [--min-confidence low|medium|high] [--limit N]
                        [--cursor <c>] [--json]
  code-audit read <run-id|run-dir> <file> [--start N] [--end N] [--json]
  code-audit search <run-id|run-dir> <pattern> [--glob <g>] [--regex]
                        [--max-results N] [--timeout-ms N] [--json]
  code-audit verdict <run-id|run-dir> <finding-id|fingerprint>
                        --status confirmed|likely|needs_review|false_positive|proof_gap
                        --rationale <text> [--evidence-line <text>]
                        [--actor <name>] [--reviewer <name>] [--json]
                        [--role primary|independent|human]
                        [--independence subagent|same-session] [--replace]
                        [--trace <file:line:role[:note]>]... [--control <file:line[:note]>]
                        [--missing <text>] [--cwe <CWE-n>]
  code-audit add-finding <run-id|run-dir> --rationale <text>
                        [--file <f> --start N [--end N] --title <t>
                         --severity <s> --cwe <cwe> [--confidence <c>]
                         [--source <s>] [--rule-id <id>] [--reviewer <name>]]
                        [--promote <hotspot-id|fingerprint>] [--json]
  code-audit report <run-id|run-dir> [--format md|json|sarif|summary]
                        [--output <file>] [--json]
  Run commands (status ... report) also accept:
                        [--root <dir>]   audit root; required to read project
                                         files when the run directory is not
                                         <root>/.audit/<run-id>
                        [--rules <dir>]  rule set for this command (default:
                                         the bundled rules)
                        [--allow-sensitive-root]  read project files of a run
                                         whose root is a credential directory
  search: a --regex search is interrupted after --timeout-ms (default 2000,
          at most 60000) and fails with SEARCH_TIMEOUT; without --regex the
          pattern is literal text.
  code-audit mcp [--base <dir>]         stdio MCP server (same as code-audit-mcp);
                                        audits only inside <dir> (default: the
                                        working directory, or CODE_AUDIT_MCP_BASE)
  code-audit install --host opencode|dsh|claude-code|codex [--project <dir>]
                        [--mcp-command <path> | --absolute] [--force] [--dry-run]
  code-audit install --uninstall --host <host> [--project <dir>] [--dry-run]
  code-audit doctor [--project <dir>] [--json]
  code-audit --help | -h                (also after any command)
  code-audit --version | -V

Scan options:
  --out <dir>            write the run to <dir>/<run-id> (default <path>/.audit)
  --format <list>        report files to write: md,json,sarif (default: all)
  --offline              no OSV.dev queries; dependencies are listed, not checked
  --no-external          built-in engines only (same as --engines builtin)
  --engines <list>       engines to run; default: builtin plus every installed
                         external scanner (opengrep is preferred over semgrep)
  --fail-on <severity>   lowest severity that makes the exit code 1 (default high)
  --min-confidence <c>   lowest confidence counted in the headline and the exit
                         code (default medium)
  --lang en|zh           report language (default en)
  --rules <dir>          load rules from <dir> instead of the bundled rule set
  --ignore-file <path>   ignore file to use (default <path>/.code-audit-ignore)
  --no-ignore-file       do not apply an ignore file
  --no-inline-ignore     do not honour code-audit:ignore comments
  --include-tests        do not lower confidence in test/docs/example/vendored paths
  --include-dev          count dev and optional dependency advisories at full weight
  --include-placeholders report placeholder-looking secrets at normal confidence
  --baseline <file>      baseline to compare with (default
                         <path>/.code-audit-baseline.json when present)
  --no-baseline          do not use a baseline
  --fail-on-existing     findings already in the baseline count toward the exit code
  --since <git-ref>      report only findings in files changed since the ref
  --ci                   CI output: annotations (GitHub Actions) and a Markdown summary
  --latest-link          also copy the reports to <out>/latest/
  --allow-sensitive-root audit a credential or configuration directory (~/.ssh,
                         ~/.aws, ~/.config, /etc, ...) or one below it; refused
                         without this flag
  --strict-evidence      every verdict of this run needs structured evidence
                         (trace, control or missing; see docs/mcp.md)
  --profile <name>       standard (default): every installed engine, OSV.dev lookups;
                         quick: built-in engines only, no network (same as
                         --no-external --offline; --engines still applies)

Auditing a repository you do not trust:
  --untrusted  ignore everything the audited repository could use to lower the
               result: implies --no-ignore-file --no-baseline --no-inline-ignore
               --include-tests --include-dev --include-placeholders, scans
               default-excluded directories (build, dist, vendor, ...; not .git)
               and the tool's own adapter files and earlier reports.

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
  includeTests: boolean;
  includeDev: boolean;
  includePlaceholders: boolean;
  untrusted: boolean;
  allowSensitiveRoot: boolean;
  strictEvidence: boolean;
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
  let includeTests = false;
  let includeDev = false;
  let includePlaceholders = false;
  let untrusted = false;
  let allowSensitive = false;
  let strictEvidence = false;

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
    } else if (arg === "--include-tests") {
      includeTests = true;
    } else if (arg === "--include-dev") {
      includeDev = true;
    } else if (arg === "--include-placeholders") {
      includePlaceholders = true;
    } else if (arg === "--untrusted") {
      untrusted = true;
    } else if (arg === "--allow-sensitive-root") {
      allowSensitive = true;
    } else if (arg === "--strict-evidence") {
      strictEvidence = true;
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
    includeTests,
    includeDev,
    includePlaceholders,
    untrusted,
    allowSensitiveRoot: allowSensitive,
    strictEvidence,
  };
}

async function runScan(args: string[]): Promise<number> {
  const parsed = parseScanArgs(args);
  // A human at a shell may audit a credential directory on purpose.
  if (parsed.allowSensitiveRoot) allowSensitiveRoot(parsed.root);
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
    includeTests: parsed.includeTests,
    includeDev: parsed.includeDev,
    includePlaceholders: parsed.includePlaceholders,
    untrusted: parsed.untrusted,
  });
  // Every later verdict of this run needs structured evidence.
  if (parsed.strictEvidence) initRunVerdicts(result.runDir, result.runId, { strictEvidence: true });

  const run = result.run as {
    baseline?: { path: string; entries: number; new: number; existing: number; fixed: number };
    scope?: { since: string; changedFiles: number };
  };
  const baseline = run.baseline;
  const scope = run.scope;

  // One counting model for every number printed below and for the exit
  // code: the summary of the run, computed with the policy recorded in
  // run.json (the same one report.md, results.sarif and findings.json use).
  const summary = result.summary;
  const countOptions = countOptionsOf(runPolicy(result.run));

  if (parsed.ci) {
    // CI mode: no colour, no progress lines, compact summary at the end.
    const annotations = renderAnnotations(result.findings, countOptions);
    for (const line of annotations) process.stdout.write(`${line}\n`);
    const warningAnnotations = renderWarningAnnotations(result.warnings);
    for (const line of warningAnnotations) process.stdout.write(`${line}\n`);
    // Only the files this run wrote (`--format` can leave some out).
    const reportPaths = ["report.md", "results.sarif", "findings.json"]
      .map((name) => path.join(result.runDir, name))
      .filter((file) => fs.existsSync(file));
    const stepSummaryText = renderStepSummaryMarkdown({
      summary,
      ...(baseline
        ? { baseline: { new: baseline.new, existing: baseline.existing, fixed: baseline.fixed } }
        : {}),
      ...(scope ? { scope } : {}),
      reportPaths,
      warnings: result.warnings,
    });
    process.stdout.write(stepSummaryText);
    const stepSummary = process.env.GITHUB_STEP_SUMMARY;
    if (stepSummary) {
      try {
        // Never through a symbolic link at that path.
        appendFileNoFollow(stepSummary, stepSummaryText);
      } catch {
        // A read-only or missing step-summary path must not fail the run.
      }
    }
  } else {
    process.stdout.write(
      [
        `code-audit scan completed: ${result.runId}`,
        `Files: ${result.coverage.stats.scannedFiles} scanned${
          (result.coverage.stats.partialFiles ?? 0) > 0
            ? ` (${result.coverage.stats.partialFiles} partially: generated lockfiles, dependencies and high-confidence secrets only)`
            : ""
        } / ${result.coverage.stats.skippedFiles} skipped, LOC ${result.coverage.stats.loc}`,
        `Rules: ${result.coverage.rulesCount}`,
        ...renderRunScopeText({ baseline, scope }),
        // Headline, low-confidence candidates, hotspots, suppressed (never
        // hidden) and the line that explains the exit code.
        ...renderSummaryText(summary),
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

  // Active, severity >= --fail-on, confidence >= --min-confidence, and new
  // when a baseline is active: the number every report prints.
  return summary.exitCode.code;
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

  const { effectiveFindings, loadRun, resolveBaselineOutput, writeBaselineFile } =
    await import("@code-audit/core");
  const loaded = loadRun(ref);
  for (const notice of loaded.notices) process.stderr.write(`warning: ${notice}\n`);
  // Every finding of the run that is not suppressed, including those a
  // reviewer marked false positive: verdicts stay with their run, and the
  // baseline is what carries the decision to the next scan.
  const baseline = buildBaseline(
    effectiveFindings(loaded),
    new Date().toISOString(),
    `code-audit ${TOOL_VERSION}`,
    { includeFalsePositives: true },
  );
  // The default destination is the root derived from where the run directory
  // is (`<root>/.audit/<run-id>`), never a root named inside the run. Throws
  // (exit 2) when there is none and no --output was given.
  const derivedRoot = loaded.rootSource === "location" ? loaded.root : undefined;
  const target = resolveBaselineOutput({ runDir: loaded.runDir, root: derivedRoot, output });
  const written = writeBaselineFile(
    target,
    baseline,
    output === undefined || output === "" ? derivedRoot : undefined,
  );
  process.stdout.write(`Run directory: ${loaded.runDir}\n`);
  process.stdout.write(
    `baseline written to ${written} (${baseline.entries.length} entries)\n`,
  );
  return 0;
}

async function runDoctor(args: string[]): Promise<number> {
  let asJson = false;
  let projectArg: string | undefined;
  const unknown: string[] = [];
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index] ?? "";
    if (arg === "--json") {
      asJson = true;
    } else if (arg === "--project") {
      projectArg = takeValue(args, index + 1, arg);
      index += 1;
    } else {
      unknown.push(arg);
    }
  }
  if (unknown.length > 0) throw new CliError(`doctor unknown arguments: ${unknown.join(" ")}`);

  const mcpPath = resolveCommand(DEFAULT_MCP_COMMAND) ?? null;
  const mcp = {
    command: DEFAULT_MCP_COMMAND,
    onPath: mcpPath !== null,
    path: mcpPath,
    bundled: bundledMcpCommand(),
    bundledExists: fs.existsSync(bundledMcpCommand()),
  };
  const project: ProjectInstallStatus | undefined =
    projectArg === undefined ? undefined : inspectInstall(projectArg);

  const major = Number(process.versions.node.split(".")[0] ?? 0);
  const nodeOk = major >= 22;

  let rulesCount = 0;
  let hotspotRules = 0;
  let rulesDir = defaultRulesDir();
  let rulesError: string | undefined;
  try {
    const ruleSet = loadRules(rulesDir);
    rulesCount = ruleSet.rules.length;
    hotspotRules = ruleSet.rules.filter((rule) => rule.kind === "hotspot").length;
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
      findingRules: rulesCount - hotspotRules,
      hotspotRules,
      opengrepDir: opengrepRulesDir,
      opengrepCount,
      error: rulesError ?? null,
      opengrepError: opengrepError ?? null,
    },
    externalTools,
    tier,
    mcp,
    ...(project ? { project } : {}),
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
    `Rules: ${rulesCount} built-in: ${rulesCount - hotspotRules} finding, ${hotspotRules} hotspot (${rulesDir})${rulesError ? ` error: ${rulesError}` : ""}\n`,
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
  process.stdout.write(
    mcp.onPath
      ? `MCP server: ${mcp.command} found on PATH (${mcp.path ?? ""})\n`
      : [
          `MCP server: ${mcp.command} NOT found on PATH`,
          `  Host configs that use the bare command will fail to start it. Add ${path.dirname(mcp.bundled)} to PATH,`,
          "  or re-run `code-audit install` with --absolute or --mcp-command <path>.",
          ...(mcp.bundledExists || monorepoRootDir() === undefined
            ? []
            : [`  ${mcp.bundled} is missing; run \`pnpm build && pnpm run link:local\`.`]),
          "",
        ].join("\n"),
  );
  process.stdout.write(
    "  (checked with this shell's PATH; a GUI-launched host may see a shorter one)\n",
  );
  if (project) {
    process.stdout.write(`Project: ${project.project}\n`);
    if (project.hosts.length === 0) {
      process.stdout.write(
        `  no host adapters installed${project.manifest ? "" : " (no .code-audit/installed.json)"}\n`,
      );
    }
    for (const host of project.hosts) {
      const missing = host.files.filter((file) => !file.present);
      const command =
        host.mcpCommand === null
          ? `no MCP entry found in ${host.configFile ?? "the host config"}`
          : host.mcpCommandResolved
            ? `MCP command ${host.mcpCommand} resolves${
                host.mcpCommandResolved === host.mcpCommand
                  ? ""
                  : ` (${host.mcpCommandResolved})`
              }`
            : `MCP command ${host.mcpCommand} does NOT resolve`;
      process.stdout.write(
        `  ${host.host.padEnd(12)} installed  ${command}${
          missing.length > 0
            ? `; missing files: ${missing.map((file) => file.path).join(", ")}`
            : ""
        }\n`,
      );
    }
  }
  return nodeOk ? 0 : 1;
}

interface InstallArgs {
  host: InstallHost;
  project: string;
  dryRun: boolean;
  uninstall: boolean;
  mcpCommand?: string;
  absolute: boolean;
  force: boolean;
}

function parseInstallArgs(args: string[]): InstallArgs {
  let host: InstallHost | undefined;
  let project = process.cwd();
  let dryRun = false;
  let uninstall = false;
  let absolute = false;
  let force = false;
  let mcpCommand: string | undefined;
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
    } else if (arg === "--mcp-command") {
      mcpCommand = takeValue(args, index + 1, arg);
      index += 1;
    } else if (arg === "--absolute") {
      absolute = true;
    } else if (arg === "--force") {
      force = true;
    } else if (arg === "--uninstall") {
      uninstall = true;
    } else if (arg === "--dry-run") {
      dryRun = true;
    } else if (arg.startsWith("-")) {
      throw new CliError(`install unknown argument: ${arg}`);
    } else {
      throw new CliError(`install unexpected positional argument: ${arg}`);
    }
  }
  if (!host) throw new CliError("install requires --host");
  if (absolute && mcpCommand !== undefined) {
    throw new CliError("--absolute and --mcp-command are mutually exclusive");
  }
  if (uninstall && (absolute || mcpCommand !== undefined)) {
    throw new CliError("--uninstall does not accept --absolute or --mcp-command");
  }
  if (uninstall && force) {
    throw new CliError("--uninstall does not accept --force");
  }
  return {
    host,
    project,
    dryRun,
    uninstall,
    absolute,
    force,
    ...(mcpCommand !== undefined ? { mcpCommand } : {}),
  };
}

const PLANNED_LABEL: Partial<Record<InstallAction["action"], string>> = {
  created: "would create",
  updated: "would update",
  removed: "would remove",
  restored: "would restore",
};

/**
 * One line per planned file. When the plan was refused nothing was written,
 * so the other files are shown as what the command would have done.
 */
function actionLines(actions: InstallAction[], notApplied = false): string[] {
  return actions.map((action) => {
    const label = (notApplied && PLANNED_LABEL[action.action]) || action.action;
    return `  ${label.padEnd(9)} ${action.path}${action.note ? ` (${action.note})` : ""}${action.backup ? ` (backup: ${action.backup})` : ""}`;
  });
}

/** Refusals go to stderr; a refused plan means nothing was written. */
function reportRefusals(refused: InstallAction[], dryRun: boolean): number {
  if (refused.length === 0) return 0;
  for (const action of refused) {
    process.stderr.write(`code-audit: ${action.note ?? action.path}\n`);
  }
  process.stderr.write(
    dryRun
      ? "code-audit: the command would stop here without changing any file.\n"
      : "code-audit: nothing was changed.\n",
  );
  return 2;
}

function runInstall(args: string[]): number {
  const parsed = parseInstallArgs(args);
  if (parsed.uninstall) {
    const result = uninstallAdapter(parsed);
    const blocked = result.refused.length > 0;
    process.stdout.write(
      [
        `code-audit install --uninstall --host ${result.host}${result.dryRun ? " (dry run)" : ""}${blocked ? " (refused, nothing changed)" : ""}`,
        `Project: ${result.project}`,
        ...(result.recorded
          ? []
          : [
              `  no install of ${result.host} is recorded in .code-audit/installed.json`,
            ]),
        ...actionLines(result.actions, blocked && !result.dryRun),
        ...(result.actions.length === 0 ? ["  nothing to remove"] : []),
        ...(result.backups.length > 0
          ? [
              "Backups of your earlier files were left in place:",
              ...result.backups.map((backup) => `  ${backup}`),
            ]
          : []),
        "",
      ].join("\n"),
    );
    return reportRefusals(result.refused, result.dryRun);
  }
  const result = installAdapter(parsed);
  const blocked = result.refused.length > 0;
  process.stdout.write(
    [
      `code-audit install --host ${result.host}${result.dryRun ? " (dry run)" : ""}${blocked ? " (refused, nothing changed)" : ""}`,
      `Project: ${result.project}`,
      ...actionLines(result.actions, blocked && !result.dryRun),
      ...result.commandChanges.map(
        (change) =>
          `MCP command changed in ${change.file}: ${JSON.stringify(change.from)} -> ${JSON.stringify(change.to)}`,
      ),
      `MCP command: ${result.mcpCommand}${
        result.mcpCommandResolved &&
        result.mcpCommandResolved !== result.mcpCommand
          ? ` (${result.mcpCommandResolved})`
          : ""
      }`,
      "",
      ...(blocked
        ? []
        : ["Next steps:", ...result.nextSteps.map((step) => `  ${step}`), ""]),
    ].join("\n"),
  );
  if (blocked) return reportRefusals(result.refused, result.dryRun);
  for (const warning of result.warnings) {
    process.stderr.write(`warning: ${warning}\n`);
  }
  return 0;
}

async function main(): Promise<void> {
  // `code-audit ... | head`: the reader closed the pipe. End quietly instead
  // of crashing with a stack trace; a command that had not decided its exit
  // code yet ends like a process killed by SIGPIPE (non-zero), so a pipeline
  // can never turn an unfinished scan into a success.
  process.stdout.on("error", (error: NodeJS.ErrnoException) => {
    if (error.code === "EPIPE") process.exit(process.exitCode ?? 141);
    throw error;
  });
  const argv = process.argv.slice(2);
  const command = argv[0];
  try {
    // `--help` after a command prints the same text. No flag takes a value
    // that starts with a dash, so this cannot swallow an argument.
    if (!command || argv.includes("--help") || argv.includes("-h")) {
      process.stdout.write(USAGE);
      process.exitCode = 0;
      return;
    }
    if (command === "--version" || command === "-V") {
      process.stdout.write(`${TOOL_VERSION}\n`);
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
      // Only `--base <dir>`; the server parses and rejects anything else.
      await runMcpServer(argv.slice(1));
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
