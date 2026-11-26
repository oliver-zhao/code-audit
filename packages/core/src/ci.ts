import type { Finding } from "./finding.js";

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
 * Render one GitHub workflow annotation per actionable finding that counts
 * toward the exit code. Critical/high findings use `::error`; medium and below
 * use `::warning`. Evidence of a secret finding is never included.
 */
export function renderAnnotations(
  findings: readonly Finding[],
  options: AnnotationOptions = {},
): string[] {
  const env = options.env ?? process.env;
  if (env.GITHUB_ACTIONS !== "true") return [];
  const cap = Math.max(0, Math.trunc(options.cap ?? 50));
  const lines: string[] = [];
  for (const finding of findings) {
    if (lines.length >= cap) break;
    if (finding.status === "suppressed" || finding.status === "false_positive") {
      continue;
    }
    const level =
      finding.severity === "critical" || finding.severity === "high"
        ? "error"
        : "warning";
    const file = escapeAnnotationProperty(finding.file);
    const title = escapeAnnotationProperty(finding.ruleId);
    const message = escapeAnnotationMessage(
      finding.message ?? finding.title,
    );
    lines.push(
      `::${level} file=${file},line=${finding.startLine},title=${title}::${message}`,
    );
  }
  return lines;
}

/**
 * Build a short Markdown summary table (the same shape as the report cover) for
 * the GitHub Actions job summary.
 */
export function renderStepSummaryMarkdown(input: {
  findingCounts: Record<string, number>;
  total: number;
  hotspots: number;
  baseline?: { new: number; existing: number; fixed: number };
  reportPaths: string[];
  warnings?: string[];
}): string {
  const lines: string[] = [];
  lines.push("## code-audit summary", "");
  lines.push(`- Total findings: **${input.total}**`);
  lines.push(
    `- ${["critical", "high", "medium", "low", "info"]
      .map((severity) => `${severity}: ${input.findingCounts[severity] ?? 0}`)
      .join(" · ")}`,
  );
  lines.push(`- Hotspots: ${input.hotspots}`);
  if (input.baseline) {
    lines.push(
      `- Baseline: New: ${input.baseline.new} · Existing: ${input.baseline.existing} · Fixed: ${input.baseline.fixed}`,
    );
  }
  for (const reportPath of input.reportPaths) {
    lines.push(`- Report: \`${reportPath}\``);
  }
  if (input.warnings && input.warnings.length > 0) {
    lines.push("", "### Warnings", "");
    for (const warning of input.warnings) {
      lines.push(`- ${warning}`);
    }
  }
  lines.push("");
  return lines.join("\n");
}