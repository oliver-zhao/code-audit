import {
  CONFIDENCES,
  SEVERITIES,
  VERDICT_STATUSES,
  addFinding,
  queryRunFindings,
  readSnippet,
  recordVerdict,
  renderRunReport,
  renderRunScopeText,
  renderSummaryText,
  runStatus,
  searchCode,
  writeFileAtomicNoFollow,
  type Confidence,
  type FindingsFilter,
  type ReportOutputFormat,
  type ResolveRunOptions,
  type Severity,
} from "@code-audit/core";

class QueryError extends Error {}

function takeValue(args: string[], index: number, flag: string): string {
  const value = args[index];
  if (!value || value.startsWith("--")) {
    throw new QueryError(`${flag} requires a value`);
  }
  return value;
}

function parseInteger(value: string, flag: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new QueryError(`${flag} requires a non-negative integer`);
  }
  return parsed;
}

function assertChoice<T extends string>(
  value: string,
  allowed: readonly T[],
  flag: string,
): T {
  if (!(allowed as readonly string[]).includes(value)) {
    throw new QueryError(
      `${flag} supports ${allowed.join("|")}, received ${value}`,
    );
  }
  return value as T;
}

function printJson(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

interface ParsedRunCommand {
  ref: string;
  json: boolean;
  positionals: string[];
  flags: Map<string, string[]>;
}

function parseRunCommand(
  args: string[],
  allowedFlags: string[],
  positionalCount: number,
  command: string,
  booleanFlags: string[] = [],
): ParsedRunCommand {
  const positionals: string[] = [];
  const flags = new Map<string, string[]>();
  let json = false;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index] ?? "";
    if (arg === "--json") {
      json = true;
    } else if (arg === "--help" || arg === "-h") {
      throw new QueryError(`${command}: see code-audit --help`);
    } else if (arg.startsWith("--")) {
      const name = arg.slice(2);
      if (!allowedFlags.includes(name) && !COMMON_FLAGS.includes(name)) {
        throw new QueryError(`${command} unknown flag: --${name}`);
      }
      if (booleanFlags.includes(name) || COMMON_BOOLEAN_FLAGS.includes(name)) {
        flags.set(name, ["true"]);
        continue;
      }
      const value = takeValue(args, index + 1, arg);
      index += 1;
      const list = flags.get(name) ?? [];
      list.push(value);
      flags.set(name, list);
    } else if (arg.startsWith("-")) {
      throw new QueryError(`${command} unknown argument: ${arg}`);
    } else {
      positionals.push(arg);
    }
  }
  if (positionals.length !== positionalCount) {
    throw new QueryError(
      `${command} expects ${positionalCount} positional argument(s), received ${positionals.length}`,
    );
  }
  return { ref: positionals[0] ?? "", json, positionals, flags };
}

function single(
  flags: Map<string, string[]>,
  name: string,
): string | undefined {
  return flags.get(name)?.[0];
}

/**
 * Flags every run command accepts. `--root <dir>` names the audit root on
 * this command line: its `.audit` is searched for the run id, and it confirms
 * the root of a run directory that is not at `<root>/.audit/<run-id>`.
 * `--rules <dir>` chooses the rule set for this command; without it the
 * bundled rules are used, never a directory named inside the run.
 */
const COMMON_FLAGS = ["root", "rules", "allow-sensitive-root"];
const COMMON_BOOLEAN_FLAGS = ["allow-sensitive-root"];

function runOptions(parsed: ParsedRunCommand): ResolveRunOptions {
  const root = single(parsed.flags, "root");
  const rulesDir = single(parsed.flags, "rules");
  return {
    ...(root !== undefined ? { root } : {}),
    ...(rulesDir !== undefined ? { rulesDir } : {}),
    ...(parsed.flags.has("allow-sensitive-root") ? { allowSensitiveRoot: true } : {}),
  };
}

function printNotices(notices: readonly string[] | undefined): void {
  for (const notice of new Set(notices ?? [])) {
    process.stderr.write(`warning: ${notice}\n`);
  }
}

/** What the user is looking at: the run directory and how its root is known. */
function locationLines(run: {
  runDir: string;
  root?: string | null;
  rootSource?: string | null;
}): string[] {
  const root =
    run.root === undefined || run.root === null
      ? "not established (the run directory is not at <root>/.audit/<run-id>; pass --root <dir> to confirm it)"
      : run.rootSource === "confirmed"
        ? `${run.root} (confirmed with --root)`
        : `${run.root} (the directory that contains this run)`;
  return [`Directory: ${run.runDir}`, `Root: ${root}`];
}

function runStatusCommand(args: string[], command: string): number {
  const parsed = parseRunCommand(args, [], 1, command);
  const status = runStatus(parsed.ref, runOptions(parsed));
  printNotices(status.notices);
  if (parsed.json) {
    printJson(status);
    return 0;
  }
  process.stdout.write(
    [
      // First, so it is clear which directory these numbers were read from.
      ...locationLines(status),
      `Run: ${status.runId}`,
      `Phase: ${status.phase}`,
      `Started: ${status.startedAt ?? "?"}`,
      `Finished: ${status.finishedAt ?? "?"}`,
      ...renderRunScopeText(status),
      // The same lines as the scan printed, recomputed with the recorded
      // thresholds and the verdicts recorded since.
      ...renderSummaryText(status.summary),
      `Records: ${status.records.findings} findings, ${status.records.hotspots} hotspots (every status, any confidence)`,
      `Reviewed: ${status.reviewed} / ${status.records.findings + status.records.hotspots}`,
      ...(status.error ? [`Error: ${status.error}`] : []),
      "",
    ].join("\n"),
  );
  return 0;
}

function buildFindingsFilter(parsed: ParsedRunCommand): FindingsFilter {
  const filter: FindingsFilter = {};
  const kind = single(parsed.flags, "kind");
  if (kind) {
    filter.kind = assertChoice(
      kind,
      ["finding", "hotspot", "all"] as const,
      "--kind",
    );
  }
  const severity = single(parsed.flags, "severity");
  if (severity) {
    filter.severity = assertChoice(
      severity,
      SEVERITIES,
      "--severity",
    ) as Severity;
  }
  const language = single(parsed.flags, "language");
  if (language) filter.language = language;
  const status = single(parsed.flags, "status");
  if (status) filter.status = status;
  const minConfidence = single(parsed.flags, "min-confidence");
  if (minConfidence) {
    filter.minConfidence = assertChoice(
      minConfidence,
      CONFIDENCES,
      "--min-confidence",
    ) as Confidence;
  }
  return filter;
}

function runFindingsCommand(args: string[]): number {
  const parsed = parseRunCommand(
    args,
    [
      "kind",
      "severity",
      "status",
      "language",
      "min-confidence",
      "limit",
      "cursor",
    ],
    1,
    "findings",
  );
  const limitValue = single(parsed.flags, "limit");
  const result = queryRunFindings(
    parsed.ref,
    buildFindingsFilter(parsed),
    single(parsed.flags, "cursor"),
    limitValue ? parseInteger(limitValue, "--limit") : 20,
    runOptions(parsed),
  );
  if (parsed.json) {
    printJson({
      run_id: parsed.ref,
      total: result.total,
      next_cursor: result.nextCursor,
      items: result.items,
    });
    return 0;
  }
  for (const item of result.items) {
    process.stdout.write(
      `${item.id} ${item.kind} ${item.severity} ${item.confidence} ${item.status} ${item.ruleId} ${item.file}:${item.startLine}\n`,
    );
  }
  process.stdout.write(
    `total ${result.total}; next cursor ${result.nextCursor ?? "none"}\n`,
  );
  return 0;
}

function runReadCommand(args: string[]): number {
  const parsed = parseRunCommand(
    args,
    ["start", "end"],
    2,
    "read",
  );
  const startValue = single(parsed.flags, "start");
  const endValue = single(parsed.flags, "end");
  const snippet = readSnippet(
    parsed.ref,
    parsed.positionals[1] ?? "",
    startValue ? parseInteger(startValue, "--start") || 1 : 1,
    endValue ? parseInteger(endValue, "--end") || undefined : undefined,
    runOptions(parsed),
  );
  printNotices(snippet.notices);
  if (parsed.json) {
    printJson(snippet);
    return 0;
  }
  process.stdout.write(
    `--- ${snippet.file}:${snippet.startLine}-${snippet.endLine} of ${snippet.totalLines}${snippet.truncated ? " (truncated)" : ""} ---\n`,
  );
  for (const line of snippet.lines) {
    process.stdout.write(`${String(line.number).padStart(6)} | ${line.text}\n`);
  }
  process.stdout.write("--- end ---\n");
  return 0;
}

function runSearchCommand(args: string[]): number {
  const parsed = parseRunCommand(
    args,
    ["glob", "max-results", "regex", "timeout-ms"],
    2,
    "search",
    ["regex"],
  );
  const maxValue = single(parsed.flags, "max-results");
  const timeoutValue = single(parsed.flags, "timeout-ms");
  const result = searchCode(
    parsed.ref,
    {
      pattern: parsed.positionals[1] ?? "",
      glob: single(parsed.flags, "glob"),
      regex: parsed.flags.has("regex"),
      maxResults: maxValue ? parseInteger(maxValue, "--max-results") || 1 : 50,
      ...(timeoutValue ? { timeoutMs: parseInteger(timeoutValue, "--timeout-ms") || 1 } : {}),
    },
    runOptions(parsed),
  );
  printNotices(result.notices);
  if (parsed.json) {
    printJson({
      run_id: parsed.ref,
      total: result.total,
      truncated: result.truncated,
      pattern: result.pattern,
      matches: result.matches,
    });
    return 0;
  }
  for (const match of result.matches) {
    process.stdout.write(
      `${match.file}:${match.line}:${match.column}: ${match.text}\n`,
    );
  }
  process.stdout.write(
    `${result.total} match(es) in ${result.searchedFiles} file(s)${result.truncated ? " (truncated)" : ""}\n`,
  );
  return 0;
}

function runVerdictCommand(args: string[]): number {
  const parsed = parseRunCommand(
    args,
    ["status", "rationale", "evidence-line", "actor", "reviewer"],
    2,
    "verdict",
  );
  const statusValue = single(parsed.flags, "status");
  if (!statusValue) throw new QueryError("verdict requires --status");
  const rationale = single(parsed.flags, "rationale");
  if (!rationale) throw new QueryError("verdict requires --rationale");
  const result = recordVerdict(
    parsed.ref,
    parsed.positionals[1] ?? "",
    {
      status: assertChoice(statusValue, VERDICT_STATUSES, "--status"),
      rationale,
      evidenceLines: parsed.flags.get("evidence-line"),
      actor: single(parsed.flags, "actor"),
      reviewer: single(parsed.flags, "reviewer"),
    },
    runOptions(parsed),
  );
  printNotices(result.notices);
  if (parsed.json) {
    printJson(result);
    return 0;
  }
  process.stdout.write(
    `Verdict recorded for ${result.findingId} (${result.status}); reviewed ${result.reviewed}/${result.total}\n`,
  );
  if (result.dismissedWarning) process.stderr.write(`${result.dismissedWarning}\n`);
  return 0;
}

function runAddFindingCommand(args: string[]): number {
  const parsed = parseRunCommand(
    args,
    [
      "file",
      "start",
      "end",
      "title",
      "severity",
      "cwe",
      "confidence",
      "rationale",
      "source",
      "promote",
      "rule-id",
      "reviewer",
    ],
    1,
    "add-finding",
  );
  const rationale = single(parsed.flags, "rationale");
  if (!rationale) throw new QueryError("add-finding requires --rationale");
  const startValue = single(parsed.flags, "start");
  const endValue = single(parsed.flags, "end");
  const severity = single(parsed.flags, "severity");
  const confidence = single(parsed.flags, "confidence");
  const result = addFinding(parsed.ref, {
    rationale,
    hotspotId: single(parsed.flags, "promote"),
    file: single(parsed.flags, "file"),
    startLine: startValue ? parseInteger(startValue, "--start") : undefined,
    endLine: endValue ? parseInteger(endValue, "--end") : undefined,
    title: single(parsed.flags, "title"),
    severity: severity
      ? (assertChoice(severity, SEVERITIES, "--severity") as Severity)
      : undefined,
    cwe: single(parsed.flags, "cwe"),
    confidence: confidence
      ? (assertChoice(confidence, CONFIDENCES, "--confidence") as Confidence)
      : undefined,
    source: single(parsed.flags, "source"),
    ruleId: single(parsed.flags, "rule-id"),
    reviewer: single(parsed.flags, "reviewer"),
  }, runOptions(parsed));
  printNotices(result.notices);
  if (parsed.json) {
    printJson(result);
    return 0;
  }
  process.stdout.write(
    `${result.promoted ? "Promoted hotspot to" : "Added"} ${result.finding.id} ${result.finding.severity} ${result.finding.file}:${result.finding.startLine}\n`,
  );
  return 0;
}

function runReportCommand(args: string[]): number {
  const parsed = parseRunCommand(args, ["format", "output"], 1, "report");
  const formatValue = single(parsed.flags, "format") ?? "summary";
  const format = assertChoice(
    formatValue,
    ["md", "json", "sarif", "summary"] as const,
    "--format",
  ) as ReportOutputFormat;
  const report = renderRunReport(parsed.ref, format, runOptions(parsed));
  printNotices(report.notices);
  // The report itself goes to stdout or a file; what was read goes to stderr.
  for (const line of locationLines(report)) process.stderr.write(`${line}\n`);
  if (report.dismissedWarning) process.stderr.write(`${report.dismissedWarning}\n`);
  const output = single(parsed.flags, "output");
  if (output) {
    // A path the user named: its directory is followed, a symbolic link at
    // the file itself is replaced, not written through.
    writeFileAtomicNoFollow(output, report.text);
    process.stdout.write(`report written to ${output}\n`);
    return 0;
  }
  process.stdout.write(report.text);
  if (!report.text.endsWith("\n")) process.stdout.write("\n");
  return 0;
}

export function isQueryCommand(command: string): boolean {
  return [
    "status",
    "findings",
    "read",
    "search",
    "verdict",
    "add-finding",
    "report",
  ].includes(command);
}

export function runQueryCommand(command: string, args: string[]): number {
  switch (command) {
    case "status":
      return runStatusCommand(args, command);
    case "findings":
      return runFindingsCommand(args);
    case "read":
      return runReadCommand(args);
    case "search":
      return runSearchCommand(args);
    case "verdict":
      return runVerdictCommand(args);
    case "add-finding":
      return runAddFindingCommand(args);
    case "report":
      return runReportCommand(args);
    default:
      throw new QueryError(`unknown command: ${command}`);
  }
}
