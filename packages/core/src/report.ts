import {
  CONFIDENCE_ORDER,
  SEVERITIES,
  SEVERITY_ORDER,
  isActionable,
  type Finding,
  type Severity,
} from "./finding.js";
import type { CoverageReport } from "./coverage.js";
import type { BaselineEntry } from "./baseline.js";
import { localizeRule, type LoadedRule } from "./rules.js";
import { compareVersions } from "./sca.js";
import { comparePypiVersions } from "./pypi.js";

export type ReportLang = "zh" | "en";

export interface ReportContext {
  runId: string;
  target: string;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  toolVersion: string;
  nodeVersion: string;
  profile: string;
  offline: boolean;
  lang: ReportLang;
  rules: LoadedRule[];
  findings: Finding[];
  hotspots?: Finding[];
  coverage: CoverageReport;
  warnings: string[];
  reviewStats?: {
    reviewed: number;
    unreviewed: number;
    total: number;
    falsePositive: number;
  };
  /** Distinct host-agent reviewer labels recorded on verdicts or findings. */
  reviewers?: string[];
  /** True when verdicts or agent-added findings exist for this run. */
  agentReviewed?: boolean;
  /** Present when a baseline was used for this run. */
  baseline?: {
    path: string;
    entries: number;
    new: number;
    existing: number;
    fixed: number;
  };
  /** Baseline entries that are no longer present in this run. */
  baselineFixed?: BaselineEntry[];
  /** Present when --since limited the report to changed files. */
  scope?: { since: string; changedFiles: number };
}

const LABELS = {
  zh: {
    title: "源代码安全审计报告",
    unverified: "候选结果，未经复核（unverified）",
    disclaimer: "确定性扫描产出候选；请由宿主 Agent 或人工复核后再决策。",
    cover: "封面",
    summary: "执行摘要",
    scope: "范围与方法",
    stats: "风险统计",
    details: "详细发现",
    dependencies: "依赖漏洞",
    coverage: "覆盖率与限制",
    roadmap: "修复路线图",
    appendix: "附录：规则列表",
    target: "目标",
    runId: "运行 ID",
    date: "日期",
    range: "范围",
    tools: "工具版本",
    model: "模型",
    modelNone: "未调用 LLM（确定性引擎）",
    modelReviewed: "由宿主 Agent 复核",
    reviewer: "复核者",
    total: "检出总数",
    bySeverity: "按严重性",
    byCategory: "按类别",
    byLanguage: "按语言",
    top: "Top 5 风险",
    none: "未发现可报告的问题。",
    file: "文件",
    line: "行",
    severity: "严重性",
    status: "状态",
    confidence: "置信度",
    cwe: "CWE",
    owasp: "OWASP",
    category: "类别",
    evidence: "证据",
    message: "说明",
    remediation: "修复建议",
    engine: "引擎",
    package: "包",
    version: "当前版本",
    fixed: "修复版本",
    advisory: "公告",
    dependencyPath: "依赖路径",
    reachable: "可达性",
    unknown: "未知",
    scanned: "已扫描文件",
    partialFiles: "部分分析：生成的锁文件仅用于依赖分析和高置信度密钥检测",
    skipped: "跳过文件",
    languages: "语言",
    loc: "LOC",
    engines: "已启用引擎",
    warnings: "警告",
    noneSkipped: "无跳过文件。",
    noneWarnings: "无警告。",
    immediate: "立即（Critical/High）",
    thisWeek: "本周（Medium）",
    thisMonth: "本月（Low/Info）",
    noItems: "无。",
    ruleId: "规则 ID",
    ruleTitle: "标题",
    ruleLanguage: "语言",
    excludeNote: "排除目录与文件见覆盖率章节。",
    scaNote: "依赖漏洞来自锁文件与 OSV.dev 查询；offline 模式不查询。",
    reachabilityNote: "可达性未通过运行时验证，统一标记为未知。",
    confidenceNote: "置信度反映匹配行中可见的输入控制程度；低置信度的仅 API 命中需要人工复核。",
    externalNote: "未运行外部扫描器（M0 无 Opengrep/OSV-Scanner/Gitleaks 适配）",
    lockfileNote: "生成的锁文件只用于 SCA 和高置信度密钥检测，不进入源码规则扫描",
    files: "文件数",
    count: "数量",
    reason: "原因",
    detail: "说明",
    references: "参考",
    moreSkipped: "条跳过记录已省略。",
    vulnerabilities: "漏洞数",
    maxSeverity: "最高严重性",
    recommendedUpgrade: "建议升级版本",
    uniqueAdvisories: "条独立公告；完整细节见 findings.json 与 results.sarif。",
    hotspots: "复核热点",
    hotspotsNote: "以下为危险 API 的使用位置，未确认存在漏洞；请由宿主 Agent 或人工结合上下文复核。明细见 findings.json 的 hotspots 数组。",
    noneHotspots: "无复核热点。",
    scanProfile: "Profile",
    offline: "离线模式",
    yes: "是",
    no: "否",
    reviewed: "已复核",
    unreviewed: "未复核",
    reviewNote: "复核进度",
    falsePositiveExcluded: "条误报已排除",
    baselineSummary: "基线对比",
    suppressed: "被抑制的发现",
    suppressedNote: "以下发现被 .code-audit-ignore 或行内 code-audit:ignore 抑制，仍保留在 findings.json 中，但不计入统计与退出码。",
    suppressedColumns: "编号,规则,文件:行,原因,过期",
    fixedSinceBaseline: "自基线以来已修复",
    fixedNote: "以下基线条目在本次运行中已不存在。",
    scopeNote: "范围",
  },
  en: {
    title: "Source Code Security Audit Report",
    unverified: "Candidate results, not reviewed (unverified)",
    disclaimer: "Deterministic scan produced candidates; review before acting.",
    cover: "Cover",
    summary: "Executive Summary",
    scope: "Scope and Method",
    stats: "Risk Statistics",
    details: "Detailed Findings",
    dependencies: "Dependency Vulnerabilities",
    coverage: "Coverage and Limitations",
    roadmap: "Remediation Roadmap",
    appendix: "Appendix: Rule List",
    target: "Target",
    runId: "Run ID",
    date: "Date",
    range: "Range",
    tools: "Tool version",
    model: "Model",
    modelNone: "No LLM invoked (deterministic engines)",
    modelReviewed: "Reviewed by host agent",
    reviewer: "Reviewer",
    total: "Total findings",
    bySeverity: "By severity",
    byCategory: "By category",
    byLanguage: "By language",
    top: "Top 5 risks",
    none: "No reportable issues found.",
    file: "File",
    line: "Line",
    severity: "Severity",
    status: "Status",
    confidence: "Confidence",
    cwe: "CWE",
    owasp: "OWASP",
    category: "Category",
    evidence: "Evidence",
    message: "Description",
    remediation: "Remediation",
    engine: "Engine",
    package: "Package",
    version: "Installed",
    fixed: "Fixed",
    advisory: "Advisory",
    dependencyPath: "Dependency path",
    reachable: "Reachability",
    unknown: "unknown",
    scanned: "Scanned files",
    partialFiles:
      "partially: generated lockfiles are read for dependencies and high-confidence secrets only",
    skipped: "Skipped files",
    languages: "Languages",
    loc: "LOC",
    engines: "Enabled engines",
    warnings: "Warnings",
    noneSkipped: "No skipped files.",
    noneWarnings: "No warnings.",
    immediate: "Immediate (Critical/High)",
    thisWeek: "This week (Medium)",
    thisMonth: "This month (Low/Info)",
    noItems: "None.",
    ruleId: "Rule ID",
    ruleTitle: "Title",
    ruleLanguage: "Language",
    excludeNote: "Excluded directories and files are described in the coverage section.",
    scaNote: "Dependency vulnerabilities come from lockfiles and OSV.dev; offline mode skips queries.",
    reachabilityNote: "Reachability is not verified at runtime and is reported as unknown.",
    confidenceNote: "Confidence reflects how much input control is visible on the matched line; low-confidence API-only hits need manual review.",
    externalNote: "External scanners not run (M0 has no Opengrep/OSV-Scanner/Gitleaks adapters)",
    lockfileNote: "Generated lockfiles are used for SCA and high-confidence secret detection only; source rules skip them",
    files: "Files",
    count: "Count",
    reason: "Reason",
    detail: "Detail",
    references: "References",
    moreSkipped: "more skipped entries omitted.",
    vulnerabilities: "Vulnerabilities",
    maxSeverity: "Max severity",
    recommendedUpgrade: "Recommended upgrade",
    uniqueAdvisories: "unique advisories; full details are in findings.json and results.sarif.",
    hotspots: "Review hotspots",
    hotspotsNote: "These are uses of dangerous APIs, not confirmed vulnerabilities; a host agent or human should review them in context. Details are in the hotspots array of findings.json.",
    noneHotspots: "No hotspots to review.",
    scanProfile: "Profile",
    offline: "Offline",
    yes: "yes",
    no: "no",
    reviewed: "reviewed",
    unreviewed: "unreviewed",
    reviewNote: "Review progress",
    falsePositiveExcluded: "false positive(s) excluded",
    baselineSummary: "Baseline",
    suppressed: "Suppressed findings",
    suppressedNote: "These findings were suppressed by .code-audit-ignore or an inline code-audit:ignore comment. They remain in findings.json but are excluded from statistics and the exit code.",
    suppressedColumns: "id,rule,file:line,reason,expires",
    fixedSinceBaseline: "Fixed since baseline",
    fixedNote: "These baseline entries are no longer present in this run.",
    scopeNote: "Scope",
  },
} as const;

/**
 * Escape repository-controlled strings before putting them into Markdown.
 * HTML entities stop raw HTML injection; escaping brackets/parentheses stops
 * Markdown link injection such as `](javascript:...)`.
 */
export function escapeMarkdown(value: string): string {
  return value
    .replace(/\\/g, "\\\\")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/`/g, "\\`")
    .replace(/\[/g, "\\[")
    .replace(/\]/g, "\\]")
    .replace(/\(/g, "\\(")
    .replace(/\)/g, "\\)")
    .replace(/\|/g, "\\|")
    .replace(/\*/g, "\\*")
    .replace(/_/g, "\\_");
}

/** Text placed inside a fenced block: keep entities, defuse the closing fence. */
export function escapeCodeBlock(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\[/g, "&#91;")
    .replace(/\]/g, "&#93;")
    .replace(/\(/g, "&#40;")
    .replace(/\)/g, "&#41;")
    .replace(/~~~/g, "~ ~ ~");
}

function codeBlock(value: string): string {
  return ["~~~text", escapeCodeBlock(value), "~~~"].join("\n");
}

function countBy<T extends string>(
  values: T[],
): Record<string, number> {
  const result: Record<string, number> = {};
  for (const value of values) result[value] = (result[value] ?? 0) + 1;
  return result;
}

function tableRow(values: string[]): string {
  return `| ${values.join(" | ")} |`;
}

function formatDate(iso: string): string {
  return iso.replace("T", " ").replace(/\.\d+Z$/, "Z");
}

function truncate(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max)}…` : value;
}

function majorOf(version: string): number {
  // Skip a leading "v" and a PEP 440 epoch ("1!2.0" has major 2).
  const match = /^[vV]?(?:\d+!)?(\d+)/.exec(version.trim());
  return match?.[1] ? Number(match[1]) : Number.NaN;
}

function versionComparator(ecosystem: string | undefined): (a: string, b: string) => number {
  return ecosystem === "PyPI" ? comparePypiVersions : compareVersions;
}

function maxVersion(
  versions: string[],
  compare: (a: string, b: string) => number = compareVersions,
): string | undefined {
  let best: string | undefined;
  for (const version of versions) {
    if (!best || compare(version, best) > 0) best = version;
  }
  return best;
}

/**
 * Recommend an upgrade for a package from the per-advisory minimum fixed
 * versions. The overall minimum that fixes every advisory is used only when it
 * stays in the same major version as the installed release; otherwise both the
 * best same-major fix and the version that fixes everything are shown.
 */
export function recommendUpgrade(
  installed: string,
  fixes: string[],
  ecosystem?: string,
): string {
  const compare = versionComparator(ecosystem);
  const valid = fixes.filter((version) => !Number.isNaN(majorOf(version)));
  if (valid.length === 0) return "—";
  const overall = maxVersion(valid, compare) as string;
  const installedMajor = majorOf(installed);
  if (majorOf(overall) === installedMajor) return overall;
  const sameMajor = valid.filter((version) => majorOf(version) === installedMajor);
  const sameBest = maxVersion(sameMajor, compare);
  if (!sameBest) return `${overall} (fixes all; no same-major fix)`;
  const open = valid.filter((version) => compare(version, sameBest) > 0).length;
  const sameLabel =
    open > 0 ? `${sameBest} (same major, ${open} open)` : `${sameBest} (same major)`;
  return `${sameLabel} / ${overall} (fixes all)`;
}

export function renderMarkdown(context: ReportContext): string {
  const l = LABELS[context.lang];
  const ruleById = new Map(context.rules.map((rule) => [rule.id, rule]));
  const ruleText = (
    finding: Finding,
  ): { title: string; message: string; remediation: string } => {
    const rule = ruleById.get(finding.ruleId);
    if (rule) return localizeRule(rule, context.lang);
    return {
      title: finding.title,
      message: finding.message ?? "",
      remediation: finding.remediation,
    };
  };
  const actionable = context.findings.filter(isActionable);
  const sast = actionable.filter((finding) => finding.category !== "sca");
  const sca = actionable.filter((finding) => finding.category === "sca");
  const severityCounts = countBy(actionable.map((finding) => finding.severity));
  const categoryCounts = countBy(actionable.map((finding) => finding.category));
  const languageCounts = countBy(
    actionable.map((finding) => finding.language ?? l.unknown),
  );
  const top = [...actionable]
    .sort((a, b) => {
      const severity = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
      if (severity !== 0) return severity;
      const confidence =
        CONFIDENCE_ORDER[b.confidence] - CONFIDENCE_ORDER[a.confidence];
      if (confidence !== 0) return confidence;
      return a.file.localeCompare(b.file);
    })
    .slice(0, 5);

  const lines: string[] = [];
  const heading = (level: number, text: string): void => {
    lines.push(`${"#".repeat(level)} ${text}`, "");
  };

  heading(1, l.title);
  const reviewStats = context.reviewStats;
  if (!reviewStats || reviewStats.reviewed === 0) {
    lines.push(`> **${l.unverified}**`, "");
  }
  lines.push(`> ${l.disclaimer}`, "");
  if (reviewStats && reviewStats.reviewed > 0) {
    lines.push(
      `> ${l.reviewNote}: ${reviewStats.reviewed} ${l.reviewed} / ${reviewStats.unreviewed} ${l.unreviewed}` +
        (reviewStats.falsePositive > 0
          ? ` (${reviewStats.falsePositive} ${l.falsePositiveExcluded})`
          : ""),
      "",
    );
  }

  heading(2, `1. ${l.cover}`);
  const modelLine =
    context.reviewers && context.reviewers.length > 0
      ? `${l.model}: ${l.modelReviewed} (${l.reviewer}: ${context.reviewers
          .map((reviewer) => escapeMarkdown(reviewer))
          .join(", ")})`
      : context.agentReviewed
        ? `${l.model}: ${l.modelReviewed}`
        : `${l.model}: ${l.modelNone}`;
  lines.push(
    `- ${l.target}: \`${escapeMarkdown(context.target)}\``,
    `- ${l.runId}: \`${escapeMarkdown(context.runId)}\``,
    `- ${l.date}: ${formatDate(context.startedAt)}`,
    `- ${l.range}: ${escapeMarkdown(context.coverage.root)}`,
    `- ${l.tools}: code-audit ${escapeMarkdown(context.toolVersion)}, Node.js ${escapeMarkdown(context.nodeVersion)}`,
    `- ${modelLine}`,
    `- ${l.scanProfile}: ${escapeMarkdown(context.profile)}`,
    `- ${l.offline}: ${context.offline ? l.yes : l.no}`,
    ...(context.scope
      ? [
          `- ${l.scopeNote}: files changed since ${escapeMarkdown(context.scope.since)} (${context.scope.changedFiles} files)`,
        ]
      : []),
    "",
  );

  heading(2, `2. ${l.summary}`);
  lines.push(`- ${l.total}: **${actionable.length}**`);
  if (context.baseline) {
    lines.push(
      `- ${l.baselineSummary}: New: ${context.baseline.new} · Existing: ${context.baseline.existing} · Fixed: ${context.baseline.fixed}`,
    );
  }
  if (reviewStats) {
    lines.push(
      `- ${l.reviewNote}: ${reviewStats.reviewed} ${l.reviewed} / ${reviewStats.unreviewed} ${l.unreviewed}`,
    );
  }
  lines.push(
    `- ${SEVERITIES.map(
      (severity) => `${severity}: ${severityCounts[severity] ?? 0}`,
    ).join(" · ")}`,
    "",
  );
  lines.push(`> ${l.confidenceNote}`, "");
  if (top.length === 0) {
    lines.push(l.none, "");
  } else {
    heading(3, l.top);
    for (const [index, finding] of top.entries()) {
      const text = ruleText(finding);
      lines.push(
        `${index + 1}. **${escapeMarkdown(finding.severity.toUpperCase())}** [${escapeMarkdown(finding.confidence)}] — ${escapeMarkdown(text.title)} (${escapeMarkdown(finding.file)}:${finding.startLine})`,
      );
    }
    lines.push("");
  }

  heading(2, `3. ${l.scope}`);
  lines.push(
    tableRow([l.languages, l.files, l.loc]),
    tableRow(["---", "---:", "---:"]),
  );
  for (const [language, stats] of Object.entries(context.coverage.languages).sort()) {
    lines.push(
      tableRow([escapeMarkdown(language), String(stats.files), String(stats.loc)]),
    );
  }
  lines.push("");
  lines.push(
    `- ${l.scanned}: ${context.coverage.stats.scannedFiles}` +
      ((context.coverage.stats.partialFiles ?? 0) > 0
        ? ` (${context.coverage.stats.partialFiles} ${l.partialFiles})`
        : ""),
    `- ${l.skipped}: ${context.coverage.stats.skippedFiles}`,
    `- ${l.loc}: ${context.coverage.stats.loc}`,
    `- ${l.excludeNote}`,
    "",
  );
  heading(3, l.engines);
  lines.push(
    tableRow([l.engine, l.status, l.detail]),
    tableRow(["---", "---", "---"]),
  );
  for (const engine of context.coverage.engines) {
    lines.push(
      tableRow([
        escapeMarkdown(engine.name),
        escapeMarkdown(engine.status),
        escapeMarkdown(engine.detail ?? ""),
      ]),
    );
  }
  lines.push("");

  heading(2, `4. ${l.stats}`);
  heading(3, l.bySeverity);
  lines.push(tableRow([l.severity, l.count]), tableRow(["---", "---:"]));
  for (const severity of SEVERITIES) {
    lines.push(tableRow([severity, String(severityCounts[severity] ?? 0)]));
  }
  lines.push("");
  heading(3, l.byCategory);
  lines.push(tableRow([l.category, l.count]), tableRow(["---", "---:"]));
  for (const [category, count] of Object.entries(categoryCounts).sort()) {
    lines.push(tableRow([escapeMarkdown(category), String(count)]));
  }
  lines.push("");
  heading(3, l.byLanguage);
  lines.push(tableRow([l.languages, l.count]), tableRow(["---", "---:"]));
  for (const [language, count] of Object.entries(languageCounts).sort()) {
    lines.push(tableRow([escapeMarkdown(language), String(count)]));
  }
  lines.push("");

  heading(2, `5. ${l.details}`);
  if (sast.length === 0) {
    lines.push(l.none, "");
  } else {
    for (const finding of sast) {
      const text = ruleText(finding);
      heading(3, `${escapeMarkdown(finding.id)} ${escapeMarkdown(text.title)}`);
      lines.push(
        tableRow([l.severity, l.status, l.confidence, l.cwe, l.owasp]),
        tableRow(["---", "---", "---", "---", "---"]),
        tableRow([
          escapeMarkdown(finding.severity),
          escapeMarkdown(finding.status),
          escapeMarkdown(finding.confidence),
          escapeMarkdown(finding.cwe ?? "—"),
          escapeMarkdown(finding.owasp ?? "—"),
        ]),
        "",
        tableRow([l.file, l.line, l.category, l.engine]),
        tableRow(["---", "---", "---", "---"]),
        tableRow([
          escapeMarkdown(finding.file),
          String(finding.startLine),
          escapeMarkdown(finding.category),
          escapeMarkdown(finding.provenance.engine),
        ]),
        "",
      );
      if (text.message) {
        lines.push(`**${l.message}**: ${escapeMarkdown(text.message)}`, "");
      }
      lines.push(`**${l.evidence}**:`, "", codeBlock(truncate(finding.evidence, 2000)), "");
      lines.push(`**${l.remediation}**: ${escapeMarkdown(text.remediation)}`, "");
      if (finding.references && finding.references.length > 0) {
        lines.push(
          `**${l.references}**: ${finding.references
            .map((reference) => escapeMarkdown(reference))
            .join(", ")}`,
          "",
        );
      }
    }
  }

  heading(2, `5a. ${l.suppressed}`);
  lines.push(`> ${l.suppressedNote}`, "");
  const suppressedFindings = context.findings.filter(
    (finding) => finding.status === "suppressed",
  );
  const suppressedHotspots = (context.hotspots ?? []).filter(
    (hotspot) => hotspot.status === "suppressed",
  );
  const allSuppressed = [...suppressedFindings, ...suppressedHotspots];
  if (allSuppressed.length === 0) {
    lines.push(l.noItems, "");
  } else {
    lines.push(
      tableRow(["ID", l.ruleId, l.file, l.line, "source", l.reason, "expires"]),
      tableRow(["---", "---", "---", "---", "---", "---", "---"]),
    );
    for (const finding of allSuppressed) {
      lines.push(
        tableRow([
          escapeMarkdown(finding.id),
          escapeMarkdown(finding.ruleId),
          escapeMarkdown(finding.file),
          String(finding.startLine),
          // "inline" is a comment in the audited repository itself.
          finding.suppression?.source === "inline"
            ? "inline comment"
            : (finding.suppression?.source ?? "—"),
          escapeMarkdown(finding.suppression?.reason || "no reason given"),
          finding.suppression?.expires ?? "—",
        ]),
      );
    }
    lines.push("");
  }

  const hotspots = (context.hotspots ?? []).filter(isActionable);
  heading(2, `6. ${l.hotspots}`);
  lines.push(`> ${l.hotspotsNote}`, "");
  if (hotspots.length === 0) {
    lines.push(l.noneHotspots, "");
  } else {
    const byFile = new Map<string, Finding[]>();
    for (const hotspot of hotspots) {
      const list = byFile.get(hotspot.file) ?? [];
      list.push(hotspot);
      byFile.set(hotspot.file, list);
    }
    for (const [file, items] of [...byFile.entries()].sort((a, b) =>
      a[0].localeCompare(b[0]),
    )) {
      heading(3, escapeMarkdown(file));
      lines.push(tableRow([l.ruleId, l.line]), tableRow(["---", "---:"]));
      for (const item of [...items].sort((a, b) => a.startLine - b.startLine)) {
        lines.push(tableRow([escapeMarkdown(item.ruleId), String(item.startLine)]));
      }
      lines.push("");
    }
  }

  heading(2, `7. ${l.dependencies}`);
  lines.push(`> ${l.scaNote}`, "");
  if (sca.length === 0) {
    lines.push(l.none, "");
  } else {
    interface ScaGroup {
      package: string;
      ecosystem: string;
      installed: string;
      file: string;
      count: number;
      maxSeverity: Severity;
      advisoryFixes: Map<string, string>;
      advisoryIds: Set<string>;
    }
    const groups = new Map<string, ScaGroup>();
    for (const finding of sca) {
      const key = `${finding.ecosystem ?? ""}\u0000${finding.package ?? ""}\u0000${finding.installedVersion ?? ""}`;
      let group = groups.get(key);
      if (!group) {
        group = {
          package: finding.package ?? "—",
          ecosystem: finding.ecosystem ?? "",
          installed: finding.installedVersion ?? "—",
          file: `${finding.file}:${finding.startLine}`,
          count: 0,
          maxSeverity: "info",
          advisoryFixes: new Map<string, string>(),
          advisoryIds: new Set<string>(),
        };
        groups.set(key, group);
      }
      group.count += 1;
      if (SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[group.maxSeverity]) {
        group.maxSeverity = finding.severity;
      }
      const advisoryId = finding.advisoryId ?? finding.ruleId;
      const fixed = finding.fixedVersion;
      const compare = versionComparator(group.ecosystem);
      if (fixed && group.installed !== "—" && compare(fixed, group.installed) > 0) {
        const previous = group.advisoryFixes.get(advisoryId);
        if (!previous || compare(fixed, previous) < 0) {
          group.advisoryFixes.set(advisoryId, fixed);
        }
      }
      if (finding.advisoryId) group.advisoryIds.add(finding.advisoryId);
    }
    const ordered = [...groups.values()].sort(
      (a, b) =>
        SEVERITY_ORDER[b.maxSeverity] - SEVERITY_ORDER[a.maxSeverity] ||
        a.package.localeCompare(b.package),
    );
    lines.push(
      tableRow([
        l.package,
        l.version,
        l.vulnerabilities,
        l.maxSeverity,
        l.recommendedUpgrade,
        l.file,
      ]),
      tableRow(["---", "---", "---:", "---", "---", "---"]),
    );
    for (const group of ordered) {
      lines.push(
        tableRow([
          escapeMarkdown(group.package),
          escapeMarkdown(group.installed),
          String(group.count),
          escapeMarkdown(group.maxSeverity),
          escapeMarkdown(
            recommendUpgrade(
              group.installed,
              [...group.advisoryFixes.values()],
              group.ecosystem,
            ),
          ),
          escapeMarkdown(group.file),
        ]),
      );
    }
    const uniqueAdvisories = new Set<string>();
    for (const group of groups.values()) {
      for (const advisoryId of group.advisoryIds) uniqueAdvisories.add(advisoryId);
    }
    lines.push(
      "",
      `> ${l.reachabilityNote}`,
      `> ${uniqueAdvisories.size} ${l.uniqueAdvisories}`,
      "",
    );
  }

  if (context.baselineFixed && context.baselineFixed.length > 0) {
    heading(2, `7a. ${l.fixedSinceBaseline}`);
    lines.push(`> ${l.fixedNote}`, "");
    lines.push(
      tableRow([l.ruleId, l.file, l.severity, "Title"]),
      tableRow(["---", "---", "---", "---"]),
    );
    for (const entry of context.baselineFixed) {
      lines.push(
        tableRow([
          escapeMarkdown(entry.ruleId),
          escapeMarkdown(entry.file),
          escapeMarkdown(entry.severity),
          escapeMarkdown(entry.title),
        ]),
      );
    }
    lines.push("");
  }

  heading(2, `8. ${l.coverage}`);
  heading(3, l.skipped);
  if (context.coverage.skipped.length === 0) {
    lines.push(l.noneSkipped, "");
  } else {
    lines.push(tableRow([l.file, l.reason]), tableRow(["---", "---"]));
    for (const skipped of context.coverage.skipped.slice(0, 200)) {
      lines.push(
        tableRow([escapeMarkdown(skipped.path), escapeMarkdown(skipped.reason)]),
      );
    }
    if (context.coverage.skipped.length > 200) {
      lines.push(
        "",
        `> ${context.coverage.skipped.length - 200} ${l.moreSkipped}`,
      );
    }
    lines.push("");
  }
  heading(3, l.warnings);
  if (context.warnings.length === 0) {
    lines.push(l.noneWarnings, "");
  } else {
    for (const warning of context.warnings) {
      lines.push(`- ${escapeMarkdown(warning)}`);
    }
    lines.push("");
  }
  lines.push(
    `- ${l.externalNote}`,
    `- ${l.lockfileNote}`,
    "",
  );

  heading(2, `9. ${l.roadmap}`);
  const roadmap = (severity: Severity[]): Finding[] =>
    actionable.filter((finding) => severity.includes(finding.severity));
  const groups: Array<[string, Finding[]]> = [
    [l.immediate, roadmap(["critical", "high"])],
    [l.thisWeek, roadmap(["medium"])],
    [l.thisMonth, roadmap(["low", "info"])],
  ];
  for (const [title, findings] of groups) {
    heading(3, title);
    if (findings.length === 0) {
      lines.push(l.noItems, "");
    } else {
      for (const finding of findings) {
        const text = ruleText(finding);
        lines.push(
          `- ${escapeMarkdown(finding.id)} ${escapeMarkdown(text.title)} (${escapeMarkdown(finding.file)}:${finding.startLine})`,
        );
      }
      lines.push("");
    }
  }

  heading(2, `10. ${l.appendix}`);
  lines.push(
    tableRow([l.ruleId, l.ruleTitle, l.severity, l.confidence, l.cwe, l.ruleLanguage]),
    tableRow(["---", "---", "---", "---", "---", "---"]),
  );
  for (const rule of context.rules) {
    const text = localizeRule(rule, context.lang);
    lines.push(
      tableRow([
        escapeMarkdown(rule.id),
        escapeMarkdown(text.title),
        escapeMarkdown(rule.severity),
        escapeMarkdown(rule.confidence),
        escapeMarkdown(rule.cwe),
        escapeMarkdown(rule.languages.join(", ")),
      ]),
    );
  }
  lines.push("");

  return `${lines.join("\n").replace(/\n{3,}/g, "\n\n")}\n`;
}

function sarifLevel(severity: Severity): "error" | "warning" | "note" {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "note";
}

export function renderSarif(context: ReportContext): string {
  interface SarifRule {
    id: string;
    name: string;
    shortDescription: { text: string };
    fullDescription: { text: string };
    help: { text: string };
    defaultConfiguration: { level: string };
    properties: Record<string, unknown>;
  }

  const rules: SarifRule[] = [];
  const ruleIndex = new Map<string, number>();

  const addRule = (
    id: string,
    title: string,
    severity: Severity,
    confidence: string,
    kind: "finding" | "hotspot",
    cwe: string | undefined,
    owasp: string | undefined,
    help: string,
  ): void => {
    if (ruleIndex.has(id)) return;
    ruleIndex.set(id, rules.length);
    rules.push({
      id,
      name: id,
      shortDescription: { text: title },
      fullDescription: { text: help },
      help: { text: help },
      defaultConfiguration: {
        level: kind === "hotspot" ? "note" : sarifLevel(severity),
      },
      properties: {
        tags: ["security", ...(cwe ? [cwe] : []), ...(owasp ? [owasp] : [])],
        severity,
        confidence,
        kind,
      },
    });
  };

  for (const rule of context.rules) {
    addRule(
      rule.id,
      rule.title,
      rule.severity,
      rule.confidence,
      rule.kind,
      rule.cwe,
      rule.owasp,
      `${rule.message}\n\n${rule.remediation}`,
    );
  }
  const allFindings = [...context.findings, ...(context.hotspots ?? [])];
  for (const finding of allFindings) {
    addRule(
      finding.ruleId,
      finding.title,
      finding.severity,
      finding.confidence,
      finding.kind,
      finding.cwe,
      finding.owasp,
      `${finding.message ?? finding.title}\n\n${finding.remediation}`,
    );
  }

  const results = allFindings.map((finding) => ({
    ruleId: finding.ruleId,
    ruleIndex: ruleIndex.get(finding.ruleId) ?? 0,
    level: finding.kind === "hotspot" ? "note" : sarifLevel(finding.severity),
    rank: Math.min(
      100,
      SEVERITY_ORDER[finding.severity] * 15 +
        CONFIDENCE_ORDER[finding.confidence] * 5,
    ),
    message: {
      text: `${finding.title}${finding.message ? `\n\n${finding.message}` : ""}`,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: encodeURI(finding.file).replace(/#/g, "%23"),
            uriBaseId: "%SRCROOT%",
          },
          region: {
            startLine: finding.startLine,
            endLine: finding.endLine,
            snippet: { text: finding.evidence },
          },
        },
      },
    ],
    partialFingerprints: {
      primaryLocationLineHash: finding.fingerprint,
      codeAuditFingerprint: finding.fingerprint,
    },
    properties: {
      severity: finding.severity,
      status: finding.status,
      confidence: finding.confidence,
      kind: finding.kind,
      category: finding.category,
      fingerprint: finding.fingerprint,
      ...(finding.baselineState
        ? {
            baselineState:
              finding.baselineState === "new" ? "new" : "unchanged",
          }
        : {}),
      ...(finding.cwe ? { cwe: finding.cwe } : {}),
      ...(finding.owasp ? { owasp: finding.owasp } : {}),
    },
  }));

  const document = {
    $schema:
      "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "code-audit",
            version: context.toolVersion,
            informationUri: "https://github.com/code-audit/code-audit",
            rules,
          },
        },
        originalUriBaseIds: {
          "%SRCROOT%": { uri: `file://${context.coverage.root}/` },
        },
        invocations: [
          {
            executionSuccessful: true,
            startTimeUtc: context.startedAt,
            endTimeUtc: context.finishedAt,
          },
        ],
        results,
      },
    ],
  };

  return `${JSON.stringify(document, null, 2)}\n`;
}

export function renderFindingsJson(
  run: Record<string, unknown>,
  findings: Finding[],
  hotspots: Finding[] = [],
): string {
  return `${JSON.stringify({ schemaVersion: 1, run, findings, hotspots }, null, 2)}\n`;
}
