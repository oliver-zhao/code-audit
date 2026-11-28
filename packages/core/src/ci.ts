import {
  SEVERITY_ORDER,
  type Confidence,
  type Finding,
  type Severity,
} from "./finding.js";
import {
  countsTowardExitCode,
  escapeMarkdown,
  groupVulnerablePackages,
  renderHeadlineMarkdown,
  renderRunScopeText,
  type FindingSummary,
} from "./report.js";

/** GitHub workflow-command escaping for a message property value. */
export function escapeAnnotationMessage(message: string): string {
  return message
    .replace(/%/g, "%25")
    .replace(/\r/g, "%0D")
    .replace(/\n/g, "%0A");
}

/** GitHub workflow-command escaping for a property value (file, title, ...). */
export function escapeAnnotationProperty(value: string): string {
  return escapeAnnotationMessage(value)
    .replace(/:/g, "%3A")
    .replace(/,/g, "%2C");
}

export interface AnnotationOptions {
  /** Environment; annotations are only emitted when GITHUB_ACTIONS is "true". */
  env?: NodeJS.ProcessEnv;
  /** Maximum number of annotation lines; defaults to 50. */
  cap?: number;
  /** `--fail-on` of the run; defaults to high. */
  failOn?: Severity;
  /** `--min-confidence` of the run; defaults to medium. */
  minConfidence?: Confidence;
  /** True when a baseline is active: existing findings are not annotated. */
  newOnly?: boolean;
}

/**
 * Render one `::warning::` line per run warning (expired or unmatched ignore
 * entries, skipped OSV queries, ...). These are never counted against the
 * finding annotation cap.
 */
export function renderWarningAnnotations(
  warnings: readonly string[],
  options: AnnotationOptions = {},
): string[] {
  const env = options.env ?? process.env;
  if (env.GITHUB_ACTIONS !== "true") return [];
  return warnings.map(
    (warning) => `::warning::${escapeAnnotationMessage(warning)}`,
  );
}

/**
 * Render GitHub workflow annotations for the findings that count toward the
 * exit code (active, severity >= failOn, confidence >= minConfidence, new when
 * a baseline is active) and for nothing else, so the annotations explain a
 * failed job. Code, secret and configuration findings get one annotation each;
 * dependency advisories are folded into one annotation per vulnerable package
 * per lockfile. Critical/high use `::error`, medium and below `::warning`.
 * Highest severity first, capped at 50. Evidence is never included.
 */
export function renderAnnotations(
  findings: readonly Finding[],
  options: AnnotationOptions = {},
): string[] {
  const env = options.env ?? process.env;
  if (env.GITHUB_ACTIONS !== "true") return [];
  const cap = Math.max(0, Math.trunc(options.cap ?? 50));
  const counting = findings.filter((finding) =>
    countsTowardExitCode(finding, {
      failOn: options.failOn,
      minConfidence: options.minConfidence,
      newOnly: options.newOnly,
    }),
  );
  interface Item {
    severity: Severity;
    file: string;
    line: number;
    title: string;
    message: string;
  }
  const items: Item[] = [];
  for (const finding of counting) {
    if (finding.category === "sca") continue;
    items.push({
      severity: finding.severity,
      file: finding.file,
      line: finding.startLine,
      title: finding.ruleId,
      message: finding.message ?? finding.title,
    });
  }
  for (const pkg of groupVulnerablePackages(counting)) {
    const shown = pkg.advisoryIds.slice(0, 5).join(", ");
    const more = pkg.advisoryIds.length - 5;
    items.push({
      severity: pkg.maxSeverity,
      file: pkg.file,
      line: pkg.line,
      title: `${pkg.package}@${pkg.installed}`,
      message:
        `${pkg.package} ${pkg.installed} (${pkg.scope} dependency): ` +
        `${pkg.advisories.length} ${pkg.advisories.length === 1 ? "advisory" : "advisories"}, ` +
        `highest severity ${pkg.maxSeverity}: ${shown}${more > 0 ? ` +${more} more` : ""}. ` +
        (pkg.recommendedUpgrade === "—"
          ? "No fixed version known."
          : `Recommended upgrade: ${pkg.recommendedUpgrade}.`),
    });
  }
  // Stable sort: input order is kept within one severity.
  items.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);
  return items.slice(0, cap).map((item) => {
    const level =
      item.severity === "critical" || item.severity === "high" ? "error" : "warning";
    return `::${level} file=${escapeAnnotationProperty(item.file)},line=${item.line},title=${escapeAnnotationProperty(item.title)}::${escapeAnnotationMessage(item.message)}`;
  });
}

/**
 * Markdown summary for the GitHub Actions job summary and the `--ci` output.
 * It shows the same headline block (verdict line, severity x category table,
 * separate low-confidence and hotspot numbers) as the report cover.
 */
export function renderStepSummaryMarkdown(input: {
  summary: FindingSummary;
  baseline?: { new: number; existing: number; fixed: number };
  /** Present when `--since` limited the run to changed files. */
  scope?: { since: string; changedFiles: number; diffLines?: boolean; diffLinesFiltered?: number };
  reportPaths: string[];
  warnings?: string[];
}): string {
  const lines: string[] = [];
  lines.push("## code-audit summary", "");
  lines.push(...renderHeadlineMarkdown(input.summary, "en"));
  for (const line of renderRunScopeText(input)) {
    // The git ref of `--since` is a command-line value, but it is still
    // escaped like every other text that reaches Markdown.
    lines.push(`- ${escapeMarkdown(line)}`);
  }
  for (const reportPath of input.reportPaths) {
    lines.push(`- Report: \`${reportPath.replace(/`/g, "'")}\``);
  }
  if (input.warnings && input.warnings.length > 0) {
    lines.push("", "### Warnings", "");
    for (const warning of input.warnings) {
      // Warnings can quote file names from the audited repository.
      lines.push(`- ${escapeMarkdown(warning)}`);
    }
  }
  lines.push("");
  return lines.join("\n");
}
