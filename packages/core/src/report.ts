import {
  CONFIDENCES,
  CONFIDENCE_ORDER,
  SEVERITIES,
  SEVERITY_ORDER,
  confidenceAtLeast,
  isActionable,
  severityAtLeast,
  type Confidence,
  type Finding,
  type Severity,
} from "./finding.js";
import type { CoverageReport } from "./coverage.js";
import type { BaselineEntry } from "./baseline.js";
import { localizeRule, type LoadedRule } from "./rules.js";
import { compareVersions } from "./sca.js";
import { comparePypiVersions } from "./pypi.js";
import { countPathContexts } from "./pathContext.js";
import { redactText } from "./redact.js";

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
  /** `--min-confidence` of the run; the headline counts findings at or above it. Defaults to medium. */
  minConfidence?: Confidence;
  /** `--fail-on` of the run. Defaults to high. */
  failOn?: Severity;
  /** `--fail-on-existing`: baseline entries count toward the exit code again. */
  failOnExisting?: boolean;
  /** `run.pathContext` counts recorded by the scan, when available. */
  pathContext?: Record<string, number>;
  /** `run.repositoryControls`: run-level facts behind the cover warnings. */
  repositoryControls?: Partial<RepositoryControls>;
}

const EN = {
  title: "Source Code Security Audit Report",
  unverified: "Candidate results, not reviewed (unverified)",
  disclaimer: "Deterministic scan produced candidates; review before acting.",
  summary: "Executive Summary",
  findingsSection: "Findings: code, secrets and configuration",
  dependencies: "Dependency Vulnerabilities",
  lowConfidence: "Low-confidence candidates",
  hotspots: "Review hotspots",
  suppressed: "Suppressed findings",
  fixedSinceBaseline: "Fixed since baseline",
  coverage: "Coverage and Limitations",
  appendix: "Appendix: Rules triggered in this run",
  target: "Target",
  runId: "Run ID",
  date: "Date",
  range: "Range",
  tools: "Tool version",
  model: "Model",
  modelNone: "No LLM invoked (deterministic engines)",
  modelReviewed: "Reviewed by host agent",
  reviewer: "Reviewer",
  scanProfile: "Profile",
  offline: "Offline",
  yes: "yes",
  no: "no",
  scopeNote: "Scope",
  scopeChanged: "files changed since {ref} ({n} files)",
  scopeChangedOne: "files changed since {ref} (1 file)",
  baselineSummary: "Baseline",
  baselineCounts: "New: {new} · Existing: {existing} · Fixed: {fixed}",
  reviewed: "reviewed",
  unreviewed: "unreviewed",
  reviewNote: "Review progress",
  falsePositiveExcluded: "false positive(s) excluded",
  // Findings a reviewer dismissed; see `dismissedWarning`.
  dismissedSection: "Dismissed by review",
  dismissedNote:
    "Every finding and hotspot that a reviewer (a host agent or a person) marked false positive in this run. They are excluded from the numbers above and from the exit code. A reviewing agent reads the audited repository and can be misled by it: check each dismissal, starting with the highest severity.",
  dismissedNone: "No finding was marked false positive.",
  dismissedReviewer: "Reviewer",
  dismissedRationale: "Rationale",
  dismissedEvidence: "evidence",
  dismissedKind: "Kind",
  dismissedKindFinding: "finding",
  dismissedKindHotspot: "hotspot",
  dismissedUnnamed: "unnamed reviewer",
  dismissedNoVerdict: "no verdict record",
  dismissedMore: "… and {n} more; all of them are in findings.json (status false_positive) and verdicts.json.",
  warnDismissed:
    "{n} finding(s) at severity ≥ {failOn} were marked false positive by {reviewers} and do not count toward the exit code; review the section \"Dismissed by review\".",
  warnDismissedMore: "and {n} more",
  // Counting model.
  verdictFail: "{n} findings count toward the exit code",
  verdictFailOne: "1 finding counts toward the exit code",
  verdictPass: "No finding counts toward the exit code",
  verdictThresholds: "severity ≥ {failOn}, confidence ≥ {minConfidence}",
  verdictThresholdsNewOnly:
    "severity ≥ {failOn}, confidence ≥ {minConfidence}, new since the baseline only",
  verdictLine: "**{head}** ({thresholds}); a scan with these thresholds exits {code}.",
  // After a review the numbers include the verdicts of this run, which a new
  // scan does not have: the line must not promise that scan's exit code.
  verdictLineReviewed:
    "**{head}** ({thresholds}); this is the result of this reviewed run (exit code {code}), not of a new scan. Verdicts are stored with this run only: a new scan starts without them and reports these findings again. To carry them forward, write a baseline from this run (`code-audit baseline <run>`; findings marked false positive are recorded as existing) or add entries to `.code-audit-ignore`.",
  headlineHeading: "Findings at confidence ≥ {minConfidence}",
  headlineNote:
    "Counted: active findings (not suppressed, not marked false positive) at confidence ≥ {minConfidence}. Low-confidence candidates and review hotspots are listed separately and are not part of these numbers.",
  category: "Category",
  catCode: "Code",
  catSecrets: "Secrets",
  catConfig: "Configuration / IaC",
  catDependencies: "Dependencies (advisories)",
  catDependency: "Dependency",
  total: "Total",
  depLine:
    "Dependency advisories: {advisories} · vulnerable packages (distinct package@version): {packages}",
  depScopes:
    "by scope, advisories / packages: runtime {ra} / {rp} · dev/optional {da} / {dp} · unknown scope {ua} / {up}",
  lowLine:
    "Low-confidence candidates (confidence below {minConfidence}, not counted above): {n}",
  lowBreakdown:
    "code {code} · secrets {secrets} · configuration/IaC {config} · dependency advisories {advisories}",
  lowPackages: "(vulnerable packages: {packages})",
  hotspotLine: "Review hotspots (uses of dangerous APIs, not counted above): {n}",
  loweredLine: "Confidence lowered by the scan on {n} active findings",
  loweredLineOne: "Confidence lowered by the scan on 1 active finding",
  loweredReasons:
    "path context {path} · placeholder value {placeholder} · dev dependency {dev}",
  loweredOptional: "optional dependency {n}",
  loweredOther: "other {n}",
  devSetAside:
    "Dev/optional dependency advisories set aside: {advisories} (vulnerable packages: {packages}) — their confidence was lowered below {minConfidence}, so they are not counted above and do not affect the exit code; they are listed with full data under “{heading}”. Use `--include-dev` to count them at full weight.",
  topMore: "{n} more critical/high findings are listed in the sections below.",
  topMoreOne: "1 more critical/high finding is listed in the sections below.",
  loweredOut:
    "{n} of them dropped below the threshold: not counted above, listed under low-confidence candidates",
  loweredNoneOut: "none dropped below the threshold, so all of them are still counted above",
  excludedLine: "Excluded from all numbers above: {suppressed} suppressed (ignore file {file}, inline comments {inline}) · {fp} marked false positive",
  // Reductions the audited repository controls; see `reductionWarnings`.
  warningWord: "WARNING",
  warnDemoted:
    "{n} finding(s) at severity ≥ {failOn} do not count toward the exit code because the scan lowered their confidence below {minConfidence}: {reasons}. `--untrusted` turns all of these off.",
  warnDemotedPath: "path context (test, docs, example, vendored, generated) {n}, off with `--include-tests`",
  warnDemotedDev: "dev-only dependency {n}, off with `--include-dev`",
  warnDemotedOptional: "optional dependency {n}, off with `--include-dev`",
  warnDemotedPlaceholder: "placeholder-looking secret value {n}, off with `--include-placeholders`",
  warnDemotedOther: "other {n}",
  warnBaseline:
    "baseline loaded from the audited repository: {n} finding(s) treated as existing ({m} at severity ≥ {failOn} would otherwise count toward the exit code). Use `--no-baseline` or `--fail-on-existing` to count them.",
  warnIgnoreFile:
    "ignore file from the audited repository suppressed {n} finding(s) ({m} at severity ≥ {failOn}). Use `--no-ignore-file` to report them.",
  warnInline:
    "inline `code-audit:ignore` comments in the audited repository suppressed {n} finding(s) ({m} at severity ≥ {failOn}). Use `--no-inline-ignore` to report them.",
  warnToolOutput:
    "{n} file(s) in the audited repository look like code-audit output (outside `.audit/`): they were scanned for secrets only, not matched against rules. `--untrusted` scans them in full.",
  warnExcluded:
    "{n} source file(s) in default-excluded directories were not read ({dirs}). `--untrusted` scans them.",
  warnExcludedAtLeast:
    "at least {n} source file(s) in default-excluded directories were not read ({dirs}; counting stopped early). `--untrusted` scans them.",
  pathContextLine: "Active findings in non-production paths",
  top: "Top risks",
  topNone: "No finding at confidence ≥ {minConfidence}.",
  moreLocations: "+{n} more",
  locations: "Locations",
  location: "Location",
  advisoriesWord: "advisories",
  advisoryWord: "advisory",
  upgradeTo: "upgrade to",
  runDetails: "Run details",
  priorities: "Remediation priorities",
  priority: "Priority",
  immediate: "Immediate (Critical/High)",
  thisWeek: "This week (Medium)",
  thisMonth: "This month (Low/Info)",
  codeFindings: "Code, secrets and configuration findings",
  vulnerablePackages: "Vulnerable packages",
  none: "No reportable issues found.",
  noItems: "None.",
  file: "File",
  line: "Line",
  severity: "Severity",
  status: "Status",
  confidence: "Confidence",
  cwe: "CWE",
  evidence: "Evidence",
  message: "Description",
  remediation: "Remediation",
  references: "References",
  engine: "Engine",
  adjustments: "adjusted",
  groupMeta: "{n} locations",
  groupMetaOne: "1 location",
  groupNonProd: "{n} in test, docs, example, vendored or generated paths",
  moreInJson: "{n} more are listed in findings.json.",
  otherLocations: "Other locations",
  package: "Package",
  version: "Installed",
  scope: "Scope",
  relation: "Relation",
  direct: "direct",
  transitive: "transitive",
  scopeRuntime: "runtime",
  scopeDev: "dev",
  scopeOptional: "optional",
  scopeUnknown: "unknown",
  advisories: "Advisories",
  maxSeverity: "Max severity",
  recommendedUpgrade: "Recommended upgrade",
  advisoryIds: "Advisory IDs",
  lockfile: "Lockfile",
  lowConfidenceCount: "{n} low confidence",
  allLowConfidence: "all low confidence",
  depRuntimeHeading: "Runtime and unknown-scope dependencies",
  depDevHeading: "Development and optional dependencies",
  depDetailHeading: "Critical and high advisories in runtime dependencies",
  depDetailSummary: "{package} {version} — critical/high advisories: {n}",
  fixedIn: "fixed in {version}",
  noFix: "no fixed version known",
  aliases: "aliases",
  scaNote:
    "One row per vulnerable package version per lockfile. Dependency vulnerabilities come from lockfiles and OSV.dev; offline mode skips queries. The full per-advisory detail is in findings.json and results.sarif.",
  reachabilityNote: "Reachability is not verified at runtime and is reported as unknown.",
  uniqueAdvisories:
    "Advisory findings: {advisories} (distinct advisory ids: {unique}) · vulnerable package versions: {packages} · table rows: {rows} · lockfiles: {lockfiles}.",
  lowConfidenceNote:
    "Active findings below the confidence threshold ({minConfidence}). They are not counted in the summary and never affect the exit code at this threshold. `a → b` marks a confidence that the scan lowered. Full detail is in findings.json.",
  lowConfidenceSca:
    "Low-confidence dependency advisories: {advisories} (vulnerable packages: {packages}). They are listed in the dependency section, marked in the Advisories column.",
  noneLowConfidence: "No low-confidence candidates.",
  hotspotsNote:
    "These are uses of dangerous APIs, not confirmed vulnerabilities; a host agent or human should review them in context. Details are in the hotspots array of findings.json.",
  noneHotspots: "No hotspots to review.",
  ruleId: "Rule ID",
  ruleTitle: "Title",
  ruleLanguage: "Language",
  count: "Count",
  suppressedNote:
    "These findings were suppressed by .code-audit-ignore or an inline code-audit:ignore comment. They remain in findings.json but are excluded from statistics and the exit code.",
  source: "Source",
  sourceInline: "inline comment",
  reason: "Reason",
  noReason: "no reason given",
  expires: "Expires",
  fixedNote: "These baseline entries are no longer present in this run.",
  moreInBaseline: "{n} more fixed entries are omitted.",
  languages: "Languages",
  files: "Files",
  loc: "LOC",
  scanned: "Scanned files",
  partialFiles:
    "partially: generated lockfiles are read for dependencies and high-confidence secrets only",
  skipped: "Skipped files",
  skippedByReason: "{n} skipped; the full list is in coverage.json.",
  example: "Example",
  engines: "Enabled engines",
  detail: "Detail",
  warnings: "Warnings",
  noneSkipped: "No skipped files.",
  noneWarnings: "No warnings.",
  moreWarnings: "{n} more warnings are in run.json.",
  pathContextCounts: "Scanned files in non-production paths",
  pathContextLowering:
    "findings in these files have their confidence lowered (shown as `a → b`)",
  pathContextNotLowering: "confidence is not lowered for them in this run",
  lockfileNote:
    "Generated lockfiles are used for SCA and high-confidence secret detection only; source rules skip them",
  confidenceNote:
    "Confidence reflects how much input control is visible on the matched line; low-confidence API-only hits need manual review.",
  hits: "Hits",
  appendixNote:
    "{loaded} rules were loaded; only the {shown} that produced a finding or hotspot are listed. The complete rule list is in results.sarif (tool.driver.rules).",
};

type Labels = typeof EN;

const ZH: Labels = {
  title: "源代码安全审计报告",
  unverified: "候选结果，未经复核（unverified）",
  disclaimer: "确定性扫描产出候选；请由宿主 Agent 或人工复核后再决策。",
  summary: "执行摘要",
  findingsSection: "发现：代码、密钥与配置",
  dependencies: "依赖漏洞",
  lowConfidence: "低置信度候选",
  hotspots: "复核热点",
  suppressed: "被抑制的发现",
  fixedSinceBaseline: "自基线以来已修复",
  coverage: "覆盖率与限制",
  appendix: "附录：本次运行触发的规则",
  target: "目标",
  runId: "运行 ID",
  date: "日期",
  range: "范围",
  tools: "工具版本",
  model: "模型",
  modelNone: "未调用 LLM（确定性引擎）",
  modelReviewed: "由宿主 Agent 复核",
  reviewer: "复核者",
  scanProfile: "扫描配置",
  offline: "离线模式",
  yes: "是",
  no: "否",
  scopeNote: "范围",
  scopeChanged: "自 {ref} 以来变更的文件（{n} 个）",
  scopeChangedOne: "自 {ref} 以来变更的文件（1 个）",
  baselineSummary: "基线对比",
  baselineCounts: "新增：{new} · 已有：{existing} · 已修复：{fixed}",
  reviewed: "已复核",
  unreviewed: "未复核",
  reviewNote: "复核进度",
  falsePositiveExcluded: "条误报已排除",
  dismissedSection: "复核中被驳回的发现",
  dismissedNote:
    "本次运行中被复核者（宿主 Agent 或人工）标记为误报的全部发现与热点。它们不计入以上数字和退出码。复核 Agent 会读取被审计仓库的内容，可能被其误导：请逐条核对，从严重性最高的开始。",
  dismissedNone: "没有发现被标记为误报。",
  dismissedReviewer: "复核者",
  dismissedRationale: "理由",
  dismissedEvidence: "证据",
  dismissedKind: "类型",
  dismissedKindFinding: "发现",
  dismissedKindHotspot: "热点",
  dismissedUnnamed: "未署名的复核者",
  dismissedNoVerdict: "无裁决记录",
  dismissedMore: "……另有 {n} 条；全部记录在 findings.json（status 为 false_positive）和 verdicts.json 中。",
  warnDismissed:
    "{n} 条严重性 ≥ {failOn} 的发现被 {reviewers} 标记为误报，不计入退出码；请核对“复核中被驳回的发现”一节。",
  warnDismissedMore: "以及另外 {n} 个",
  verdictFail: "{n} 条发现计入退出码",
  verdictFailOne: "1 条发现计入退出码",
  verdictPass: "没有发现计入退出码",
  verdictThresholds: "严重性 ≥ {failOn}，置信度 ≥ {minConfidence}",
  verdictThresholdsNewOnly:
    "严重性 ≥ {failOn}，置信度 ≥ {minConfidence}，仅统计基线之后新增的发现",
  verdictLine: "**{head}**（{thresholds}）；按此阈值扫描的退出码为 {code}。",
  verdictLineReviewed:
    "**{head}**（{thresholds}）；这是本次已复核运行的结果（退出码 {code}），不是重新扫描的结果。裁定只保存在本次运行中：重新扫描不会沿用，这些发现会再次出现。要延续裁定，请用本次运行写入基线（`code-audit baseline <run>`；标记为误报的发现会记为既有项），或在 `.code-audit-ignore` 中添加条目。",
  headlineHeading: "置信度 ≥ {minConfidence} 的发现",
  headlineNote:
    "统计口径：有效发现（未被抑制、未标记为误报）且置信度 ≥ {minConfidence}。低置信度候选与复核热点单独列出，不计入这些数字。",
  category: "类别",
  catCode: "代码",
  catSecrets: "密钥",
  catConfig: "配置 / IaC",
  catDependencies: "依赖（公告）",
  catDependency: "依赖",
  total: "合计",
  depLine: "依赖公告：{advisories} · 存在漏洞的包（不同的 包@版本）：{packages}",
  depScopes:
    "按依赖范围（公告数 / 包数）：运行时 {ra} / {rp} · 开发/可选 {da} / {dp} · 范围未知 {ua} / {up}",
  lowLine: "低置信度候选（置信度低于 {minConfidence}，不计入上表）：{n}",
  lowBreakdown: "代码 {code} · 密钥 {secrets} · 配置/IaC {config} · 依赖公告 {advisories}",
  lowPackages: "（涉及的包：{packages}）",
  hotspotLine: "复核热点（危险 API 的使用位置，不计入上表）：{n}",
  loweredLine: "{n} 条有效发现的置信度被调低",
  loweredLineOne: "1 条有效发现的置信度被调低",
  loweredReasons: "路径上下文 {path} · 占位值 {placeholder} · 开发依赖 {dev}",
  loweredOptional: "可选依赖 {n}",
  loweredOther: "其他 {n}",
  devSetAside:
    "已搁置的开发/可选依赖公告：{advisories}（涉及的包：{packages}）— 其置信度被调低到 {minConfidence} 以下，因此不计入上表，也不影响退出码；完整数据列在“{heading}”中。使用 `--include-dev` 可按完整权重统计。",
  topMore: "另有 {n} 条 Critical/High 发现列在后面的章节中。",
  topMoreOne: "另有 1 条 Critical/High 发现列在后面的章节中。",
  loweredOut: "其中 {n} 条降到阈值以下：未计入上表，列在低置信度候选中",
  loweredNoneOut: "没有发现因此降到阈值以下，全部仍计入上表",
  excludedLine:
    "以上数字均不包含：{suppressed} 条被抑制（忽略文件 {file}，行内注释 {inline}） · {fp} 条标记为误报",
  warningWord: "警告",
  warnDemoted:
    "{n} 条严重性 ≥ {failOn} 的发现因置信度被扫描调低到 {minConfidence} 以下而不计入退出码：{reasons}。使用 `--untrusted` 可关闭以上全部调整。",
  warnDemotedPath: "路径上下文（测试、文档、示例、第三方、生成代码）{n}，用 `--include-tests` 关闭",
  warnDemotedDev: "仅开发依赖 {n}，用 `--include-dev` 关闭",
  warnDemotedOptional: "可选依赖 {n}，用 `--include-dev` 关闭",
  warnDemotedPlaceholder: "疑似占位符的密钥值 {n}，用 `--include-placeholders` 关闭",
  warnDemotedOther: "其他 {n}",
  warnBaseline:
    "基线文件来自被审计的仓库：{n} 条发现被视为已存在（其中 {m} 条严重性 ≥ {failOn}，否则会计入退出码）。使用 `--no-baseline` 或 `--fail-on-existing` 将其计入。",
  warnIgnoreFile:
    "来自被审计仓库的忽略文件抑制了 {n} 条发现（其中 {m} 条严重性 ≥ {failOn}）。使用 `--no-ignore-file` 可报告它们。",
  warnInline:
    "被审计仓库中的行内 `code-audit:ignore` 注释抑制了 {n} 条发现（其中 {m} 条严重性 ≥ {failOn}）。使用 `--no-inline-ignore` 可报告它们。",
  warnToolOutput:
    "被审计仓库中有 {n} 个文件看起来是 code-audit 的输出（位于 `.audit/` 之外）：仅做了密钥检测，未做规则匹配。使用 `--untrusted` 可完整扫描。",
  warnExcluded:
    "默认排除目录中有 {n} 个源文件未被读取（{dirs}）。使用 `--untrusted` 可扫描它们。",
  warnExcludedAtLeast:
    "默认排除目录中至少有 {n} 个源文件未被读取（{dirs}；计数提前停止）。使用 `--untrusted` 可扫描它们。",
  pathContextLine: "位于非生产路径的有效发现",
  top: "主要风险",
  topNone: "没有置信度 ≥ {minConfidence} 的发现。",
  moreLocations: "另有 {n} 处",
  locations: "位置",
  location: "位置",
  advisoriesWord: "条公告",
  advisoryWord: "条公告",
  upgradeTo: "升级到",
  runDetails: "运行信息",
  priorities: "修复优先级",
  priority: "优先级",
  immediate: "立即（Critical/High）",
  thisWeek: "本周（Medium）",
  thisMonth: "本月（Low/Info）",
  codeFindings: "代码、密钥与配置发现",
  vulnerablePackages: "存在漏洞的包",
  none: "未发现可报告的问题。",
  noItems: "无。",
  file: "文件",
  line: "行",
  severity: "严重性",
  status: "状态",
  confidence: "置信度",
  cwe: "CWE",
  evidence: "证据",
  message: "说明",
  remediation: "修复建议",
  references: "参考",
  engine: "引擎",
  adjustments: "调整原因",
  groupMeta: "{n} 处",
  groupMetaOne: "1 处",
  groupNonProd: "其中 {n} 处位于测试、文档、示例、第三方或生成路径",
  moreInJson: "另有 {n} 条见 findings.json。",
  otherLocations: "其他位置",
  package: "包",
  version: "当前版本",
  scope: "依赖范围",
  relation: "依赖关系",
  direct: "直接",
  transitive: "传递",
  scopeRuntime: "运行时",
  scopeDev: "开发",
  scopeOptional: "可选",
  scopeUnknown: "未知",
  advisories: "公告数",
  maxSeverity: "最高严重性",
  recommendedUpgrade: "建议升级版本",
  advisoryIds: "公告 ID",
  lockfile: "锁文件",
  lowConfidenceCount: "{n} 条低置信度",
  allLowConfidence: "全部为低置信度",
  depRuntimeHeading: "运行时与范围未知的依赖",
  depDevHeading: "开发与可选依赖",
  depDetailHeading: "运行时依赖中的 Critical/High 公告",
  depDetailSummary: "{package} {version} — Critical/High 公告：{n}",
  fixedIn: "修复版本 {version}",
  noFix: "暂无已知修复版本",
  aliases: "别名",
  scaNote:
    "每个锁文件中每个存在漏洞的包版本占一行。依赖漏洞来自锁文件与 OSV.dev 查询；offline 模式不查询。每条公告的完整细节见 findings.json 与 results.sarif。",
  reachabilityNote: "可达性未通过运行时验证，统一标记为未知。",
  uniqueAdvisories:
    "公告发现：{advisories}（不同的公告 ID：{unique}） · 存在漏洞的包版本：{packages} · 表格行数：{rows} · 锁文件：{lockfiles}。",
  lowConfidenceNote:
    "置信度低于阈值（{minConfidence}）的有效发现。它们不计入摘要，在此阈值下也不影响退出码。`a → b` 表示扫描调低了置信度。完整细节见 findings.json。",
  lowConfidenceSca:
    "低置信度依赖公告：{advisories}（涉及的包：{packages}）。它们列在依赖章节中，并在“公告数”一列标注。",
  noneLowConfidence: "无低置信度候选。",
  hotspotsNote:
    "以下为危险 API 的使用位置，未确认存在漏洞；请由宿主 Agent 或人工结合上下文复核。明细见 findings.json 的 hotspots 数组。",
  noneHotspots: "无复核热点。",
  ruleId: "规则 ID",
  ruleTitle: "标题",
  ruleLanguage: "语言",
  count: "数量",
  suppressedNote:
    "以下发现被 .code-audit-ignore 或行内 code-audit:ignore 抑制，仍保留在 findings.json 中，但不计入统计与退出码。",
  source: "来源",
  sourceInline: "行内注释",
  reason: "原因",
  noReason: "未给出原因",
  expires: "过期",
  fixedNote: "以下基线条目在本次运行中已不存在。",
  moreInBaseline: "另有 {n} 条已修复条目已省略。",
  languages: "语言",
  files: "文件数",
  loc: "LOC",
  scanned: "已扫描文件",
  partialFiles: "部分分析：生成的锁文件仅用于依赖分析和高置信度密钥检测",
  skipped: "跳过文件",
  skippedByReason: "共跳过 {n} 项；完整列表见 coverage.json。",
  example: "示例",
  engines: "已启用引擎",
  detail: "说明",
  warnings: "警告",
  noneSkipped: "无跳过文件。",
  noneWarnings: "无警告。",
  moreWarnings: "另有 {n} 条警告见 run.json。",
  pathContextCounts: "位于非生产路径的已扫描文件",
  pathContextLowering: "这些文件中的发现会被调低置信度（以 `a → b` 标示）",
  pathContextNotLowering: "本次运行未对它们调低置信度",
  lockfileNote: "生成的锁文件只用于 SCA 和高置信度密钥检测，不进入源码规则扫描",
  confidenceNote:
    "置信度反映匹配行中可见的输入控制程度；低置信度的仅 API 命中需要人工复核。",
  hits: "命中数",
  appendixNote:
    "共加载 {loaded} 条规则；此处只列出产生发现或热点的 {shown} 条。完整规则列表见 results.sarif（tool.driver.rules）。",
};

const SECRET_MESSAGE_ZH = "检测到可能的明文凭据；所有报告中的证据均已脱敏。";
const CREDENTIAL_FILE_REMEDIATION_ZH =
  "轮换该凭据，把该文件从仓库及历史中删除，并在运行时由环境变量或凭据存储提供该值。";

/**
 * Chinese text of the findings that built-in detectors create without a YAML
 * rule (the secret detectors and the missing-lockfile hotspot). YAML rules
 * carry their own translation, see `localizeRule`.
 */
export const BUILTIN_FINDING_TEXT_ZH: Readonly<
  Record<string, { title: string; message: string; remediation: string }>
> = {
  "secret-aws-access-key": {
    title: "硬编码的 AWS 访问密钥",
    message: SECRET_MESSAGE_ZH,
    remediation:
      "立即在 AWS IAM 中轮换该密钥，改用环境变量或实例角色，并从 Git 历史中清除该密钥。",
  },
  "secret-github-token": {
    title: "硬编码的 GitHub 令牌",
    message: SECRET_MESSAGE_ZH,
    remediation:
      "在 GitHub 设置中吊销该令牌，改用短期凭据或 GitHub App，并从提交历史中清除。",
  },
  "secret-slack-token": {
    title: "硬编码的 Slack 令牌",
    message: SECRET_MESSAGE_ZH,
    remediation: "在 Slack 管理后台吊销该令牌，并把凭据存放到密钥管理服务中。",
  },
  "secret-private-key": {
    title: "仓库中提交了私钥块",
    message: SECRET_MESSAGE_ZH,
    remediation: "立即吊销并重新生成密钥，把它移入密钥管理服务，并从 Git 历史中删除。",
  },
  "secret-generic-assignment": {
    title: "可能的硬编码密码或 API 密钥赋值",
    message: SECRET_MESSAGE_ZH,
    remediation:
      "把凭据移到环境变量或密钥管理服务中，轮换已暴露的值，不要提交明文凭据。",
  },
  "secret-url-credentials": {
    title: "URL 中嵌入了凭据",
    message: SECRET_MESSAGE_ZH,
    remediation:
      "从 URL 中移除凭据并轮换，改由环境变量、keyring 或包管理器的凭据存储提供（pip：用密钥注入 PIP_INDEX_URL，或使用 netrc 文件）。",
  },
  "secret-netrc-password": {
    title: ".netrc 文件中的密码",
    message: SECRET_MESSAGE_ZH,
    remediation: CREDENTIAL_FILE_REMEDIATION_ZH,
  },
  "secret-pgpass-password": {
    title: "PostgreSQL .pgpass 文件中的密码",
    message: SECRET_MESSAGE_ZH,
    remediation: CREDENTIAL_FILE_REMEDIATION_ZH,
  },
  "secret-npmrc-auth": {
    title: ".npmrc 中的仓库凭据",
    message: SECRET_MESSAGE_ZH,
    remediation:
      "吊销该令牌，把它从仓库及历史中删除，并写成 `_authToken=${NPM_TOKEN}`，让值来自环境变量。",
  },
  "secret-pypirc-password": {
    title: ".pypirc 或 pip.conf 中的包索引密码",
    message: SECRET_MESSAGE_ZH,
    remediation: CREDENTIAL_FILE_REMEDIATION_ZH,
  },
  "secret-docker-auth": {
    title: "Docker 配置文件中的镜像仓库凭据",
    message: SECRET_MESSAGE_ZH,
    remediation:
      "退出该镜像仓库的登录并吊销凭据，把该文件从仓库及历史中删除，改用凭据助手（credsStore）而不是内联的 auths。",
  },
  "secret-kubeconfig-credential": {
    title: "kubeconfig 文件中的集群凭据",
    message: SECRET_MESSAGE_ZH,
    remediation:
      "在集群中吊销该令牌或客户端证书，把该文件从仓库及历史中删除，改用 exec 凭据插件或短期令牌。",
  },
  "dep-missing-lockfile": {
    title: "清单文件旁没有锁文件",
    message: "没有锁文件的清单会解析浮动版本，构建不可复现。",
    remediation:
      "提交锁文件（package-lock.json、pnpm-lock.yaml、yarn.lock、poetry.lock 或 requirements.txt），并按锁文件安装。",
  },
};

/** Bilingual label table of the Markdown report; both languages have the same keys. */
export const REPORT_LABELS: Record<ReportLang, Labels> = { en: EN, zh: ZH };

function fmt(template: string, values: Record<string, string | number>): string {
  return template.replace(/\{(\w+)\}/g, (match, key: string) =>
    key in values ? String(values[key]) : match,
  );
}

/** Longest repository-derived string that reaches a report in one piece. */
export const MARKDOWN_TEXT_MAX = 1000;

/**
 * One line of plain text from a string the audited repository controls (a
 * file name, an ignore reason, a package name, an advisory title, a
 * warning): line breaks become a visible `⏎`, tabs a space, every other
 * control character and every bidirectional-override character a visible
 * `�`, and the result is cut to `max` characters. A file name with newlines
 * in it can therefore never start a new line in a report, a table or the
 * terminal.
 */
export function singleLineText(value: string, max = MARKDOWN_TEXT_MAX): string {
  const flat = value
    .replace(/\r\n|[\n\r\u000b\u000c\u0085\u2028\u2029]/g, "⏎")
    .replace(/\t/g, " ")
    // C0 and C1 controls, DEL, bidi embeddings / overrides / isolates.
    .replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, "\ufffd");
  return flat.length > max ? `${flat.slice(0, max)}…` : flat;
}

/**
 * Escape repository-controlled strings before putting them into Markdown.
 *
 * - The text is made a single line and capped first (`singleLineText`), so
 *   it cannot end the line, table row or list item it is placed in.
 * - HTML entities stop raw HTML; escaped brackets and parentheses stop link
 *   injection such as `](javascript:...)`; escaped `|` keeps table cells.
 * - Nothing in it can start a block construct even at the start of a line or
 *   list item: `~` and the backtick (code fence) are escaped everywhere, a
 *   leading `#` (heading), a leading list marker (`- `, `+ `, `1. `) and a string made
 *   only of `-` / `=` (thematic break, setext underline) are escaped, `>` is
 *   an entity, and leading white space (indented code) is removed.
 */
export function escapeMarkdown(value: string, max = MARKDOWN_TEXT_MAX): string {
  return singleLineText(value, max)
    .replace(/^\s+/, "")
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
    .replace(/_/g, "\\_")
    .replace(/^#/, "\\#")
    .replace(/~/g, "\\~")
    // A list marker needs a space after it; a rule or setext underline is a
    // line of nothing but such characters.
    .replace(/^([-+])(?=\s|$)/, "\\$1")
    .replace(/^([-=])(?=[-=\s]*$)/, "\\$1")
    .replace(/^(\d{1,9})\.(?=\s|$)/, "$1\\.");
}

/**
 * Text placed inside a fenced block: defuse the closing fence and keep the
 * content inert even in a renderer that mishandles fences. Angle brackets stay
 * encoded, so no raw HTML can come out of evidence, and a `](` sequence is
 * broken up, so no `[text](url)` link can either. Plain brackets and
 * parentheses are left alone, which keeps code evidence readable. Line feeds
 * stay (evidence can span lines); other control characters are replaced.
 */
export function escapeCodeBlock(value: string): string {
  return value
    .replace(/\r\n?|[\u000b\u000c\u0085\u2028\u2029]/g, "\n")
    .replace(/[\u0000-\u0008\u000e-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, "\ufffd")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\]\(/g, "]&#40;")
    .replace(/~~~/g, "~ ~ ~");
}

/** Text placed in a raw HTML element such as `<summary>`: one line, capped. */
function escapeHtml(value: string): string {
  return singleLineText(value, 300)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function codeBlock(value: string): string {
  return ["~~~text", escapeCodeBlock(value), "~~~"].join("\n");
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

// ---------------------------------------------------------------------------
// Counting model
//
// One definition of every number shown to a user. It is used by the Markdown
// cover, the CLI summary, the `--ci` / GitHub step summary, the MCP status and
// report summaries and `run.summary` in findings.json.
// ---------------------------------------------------------------------------

export const HEADLINE_CATEGORIES = [
  "code",
  "secrets",
  "config",
  "dependencies",
] as const;
export type HeadlineCategory = (typeof HEADLINE_CATEGORIES)[number];

export function headlineCategory(finding: Finding): HeadlineCategory {
  if (finding.category === "sca") return "dependencies";
  if (finding.category === "secrets") return "secrets";
  if (finding.category === "config") return "config";
  return "code";
}

export interface CountOptions {
  /** `--min-confidence`; the headline counts findings at or above it. Default medium. */
  minConfidence?: Confidence;
  /** `--fail-on`. Default high. */
  failOn?: Severity;
  /**
   * True when a baseline is active without `--fail-on-existing`: findings
   * marked `baselineState: "existing"` do not count toward the exit code.
   */
  newOnly?: boolean;
  /** `run.repositoryControls`: run-level facts for `summary.reductions`. */
  controls?: Partial<RepositoryControls>;
}

/**
 * Facts about a run that say how much the audited repository itself shaped
 * the result; written by the scan as `run.repositoryControls`.
 */
export interface RepositoryControls {
  /** `--untrusted` was set. */
  untrusted: boolean;
  /** The baseline file that was applied lies inside the audited repository. */
  baselineFromRepository: boolean;
  /** The ignore file that was applied lies inside the audited repository. */
  ignoreFileFromRepository: boolean;
  /** Files recognised as the tool's own output: secret detectors only. */
  toolOutputFiles: number;
  /** Source files in default-excluded directories, which were not read. */
  excludedSourceFiles: { total: number; truncated: boolean; byDirectory: Record<string, number> };
}

/** `run.repositoryControls` of a run record, with defaults for older runs. */
export function repositoryControlsOf(run: Record<string, unknown>): RepositoryControls {
  const raw = recordOf(run.repositoryControls);
  const excluded = recordOf(raw.excludedSourceFiles);
  const byDirectory: Record<string, number> = {};
  for (const [name, count] of Object.entries(recordOf(excluded.byDirectory))) {
    if (typeof count === "number" && Number.isFinite(count)) byDirectory[name] = count;
  }
  const count = (value: unknown): number =>
    typeof value === "number" && Number.isFinite(value) && value > 0 ? Math.trunc(value) : 0;
  return {
    untrusted: raw.untrusted === true,
    baselineFromRepository: raw.baselineFromRepository === true,
    ignoreFileFromRepository: raw.ignoreFileFromRepository === true,
    toolOutputFiles: count(raw.toolOutputFiles),
    excludedSourceFiles: {
      total: count(excluded.total),
      truncated: excluded.truncated === true,
      byDirectory,
    },
  };
}

/**
 * The effect of a reviewer's verdict on confidence. The scan lowers
 * confidence from what the audited repository says about itself (a path, a
 * placeholder-looking value, a dev-only dependency); a reviewer who looked at
 * the finding outranks that:
 *
 * - `confirmed`: confidence becomes high;
 * - `likely`: confidence becomes what the engine reported before any
 *   lowering, and at least medium.
 *
 * The confidence the scan left is kept in `confidenceBeforeVerdict`, so the
 * function is idempotent and a later verdict of another status brings the
 * scan's value back. Every place that counts or renders findings applies it
 * (the counting model does so itself), so a confirmed finding counts toward
 * the exit code and is shown with its status wherever it is listed.
 */
export function applyVerdictConfidence<T extends Finding>(finding: T): T {
  const record = finding as T & { confidenceBeforeVerdict?: unknown };
  const stored = (CONFIDENCES as readonly unknown[]).includes(record.confidenceBeforeVerdict)
    ? (record.confidenceBeforeVerdict as Confidence)
    : undefined;
  const scanned = stored ?? finding.confidence;
  let target: Confidence = scanned;
  if (finding.status === "confirmed") target = "high";
  else if (finding.status === "likely") {
    const original = confidenceOriginalOf(finding) ?? scanned;
    target = CONFIDENCE_ORDER[original] >= CONFIDENCE_ORDER.medium ? original : "medium";
    if (CONFIDENCE_ORDER[target] < CONFIDENCE_ORDER[scanned]) target = scanned;
  }
  if (target === scanned) {
    if (stored === undefined) return finding;
    const { confidenceBeforeVerdict: _dropped, ...rest } = record;
    return { ...(rest as unknown as T), confidence: scanned };
  }
  if (finding.confidence === target && stored !== undefined) return finding;
  return { ...finding, confidence: target, confidenceBeforeVerdict: scanned };
}

/** Path context recorded on a finding (`test`, `docs`, ...), if any. */
export function pathContextOf(finding: Finding): string | undefined {
  const value = (finding as Record<string, unknown>).pathContext;
  return typeof value === "string" && value ? value : undefined;
}

function adjustmentsOf(finding: Finding): string[] {
  const value = (finding as Record<string, unknown>).adjustments;
  return Array.isArray(value)
    ? value.filter((entry): entry is string => typeof entry === "string")
    : [];
}

function confidenceOriginalOf(finding: Finding): Confidence | undefined {
  const value = (finding as Record<string, unknown>).confidenceOriginal;
  return (CONFIDENCES as readonly unknown[]).includes(value)
    ? (value as Confidence)
    : undefined;
}

/** True when the scan lowered the confidence of this finding. */
export function confidenceWasLowered(finding: Finding): boolean {
  const original = confidenceOriginalOf(finding);
  if (original) {
    return CONFIDENCE_ORDER[original] > CONFIDENCE_ORDER[finding.confidence];
  }
  return adjustmentsOf(finding).length > 0;
}

type DependencyScopeGroup = "runtime" | "devOptional" | "unknown";

function scopeGroup(finding: Finding): DependencyScopeGroup {
  const scope = finding.dependencyScope;
  if (scope === "runtime") return "runtime";
  if (scope === "dev" || scope === "optional") return "devOptional";
  return "unknown";
}

/** A package that is runtime anywhere is runtime; unknown outranks dev/optional. */
const SCOPE_GROUP_RANK: Record<DependencyScopeGroup, number> = {
  runtime: 0,
  unknown: 1,
  devOptional: 2,
};

/**
 * Identity of a vulnerable package: ecosystem + name + installed version.
 * PyPI names are case-insensitive and treat `-`, `_` and `.` alike (PEP 503),
 * so `PyYAML` and `pyyaml` in two requirements files are one package.
 */
function packageKey(finding: Finding): string {
  const ecosystem = finding.ecosystem ?? "";
  const raw = finding.package ?? finding.evidence;
  const name =
    ecosystem === "PyPI" ? raw.toLowerCase().replace(/[-_.]+/g, "-") : raw;
  return `${ecosystem}\u0000${name}\u0000${finding.installedVersion ?? ""}`;
}

export interface DependencyCount {
  advisories: number;
  /** Distinct package@version. */
  vulnerablePackages: number;
}

function countDependencies(findings: Finding[]): DependencyCount & {
  byScope: Record<DependencyScopeGroup, DependencyCount>;
} {
  const byScope: Record<DependencyScopeGroup, DependencyCount> = {
    runtime: { advisories: 0, vulnerablePackages: 0 },
    devOptional: { advisories: 0, vulnerablePackages: 0 },
    unknown: { advisories: 0, vulnerablePackages: 0 },
  };
  const packages = new Map<string, DependencyScopeGroup>();
  for (const finding of findings) {
    const group = scopeGroup(finding);
    byScope[group].advisories += 1;
    const key = packageKey(finding);
    const previous = packages.get(key);
    if (!previous || SCOPE_GROUP_RANK[group] < SCOPE_GROUP_RANK[previous]) {
      packages.set(key, group);
    }
  }
  for (const group of packages.values()) byScope[group].vulnerablePackages += 1;
  return {
    advisories: findings.length,
    vulnerablePackages: packages.size,
    byScope,
  };
}

function zeroSeverities(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

function zeroCategories(): Record<HeadlineCategory, number> {
  return { code: 0, secrets: 0, config: 0, dependencies: 0 };
}

export interface FindingSummary {
  thresholds: { minConfidence: Confidence; failOn: Severity; newOnly: boolean };
  /** Active findings (not suppressed, not false positive) at confidence >= minConfidence. */
  headline: {
    total: number;
    bySeverity: Record<Severity, number>;
    byCategory: Record<HeadlineCategory, number>;
    matrix: Record<HeadlineCategory, Record<Severity, number>>;
  };
  /** Dependency part of the headline: advisories and distinct package@version. */
  dependencies: DependencyCount & {
    byScope: Record<DependencyScopeGroup, DependencyCount>;
  };
  /**
   * Advisories in dev-only or optional dependencies that the scan lowered
   * from at-or-above the threshold to below it (`dev-dependency`,
   * `optional-dependency`). They are part of `lowConfidence`, not of the
   * headline; `--include-dev` counts them at full weight.
   */
  dependenciesSetAside: DependencyCount;
  /** Every active finding, whatever its confidence. */
  active: {
    total: number;
    bySeverity: Record<Severity, number>;
    byConfidence: Record<Confidence, number>;
  };
  /** Active findings below minConfidence; never part of the headline. */
  lowConfidence: {
    total: number;
    byCategory: Record<HeadlineCategory, number>;
    dependencies: DependencyCount;
  };
  /** Active review hotspots; never part of the headline. */
  hotspots: number;
  suppressed: { total: number; ignoreFile: number; inline: number };
  falsePositives: number;
  /** Active findings whose confidence the scan lowered, by reason. */
  confidenceLowered: {
    total: number;
    /** Lowered from at-or-above the threshold to below it. */
    outOfHeadline: number;
    pathContext: number;
    placeholder: number;
    devDependency: number;
    optionalDependency: number;
    other: number;
  };
  /** Active findings per path context (test, docs, example, vendored, generated). */
  pathContext: Record<string, number>;
  /**
   * Everything the audited repository itself took out of the exit-code set
   * or kept away from the scan. Each non-zero entry is printed as a WARNING
   * on the report cover and in the terminal, `--ci` and step summaries
   * (`reductionWarnings`), with the flag that turns it off.
   */
  reductions: {
    /**
     * Active findings at severity >= failOn that would count toward the exit
     * code with the confidence the engine reported, and do not because the
     * scan lowered it. A finding with two reasons is counted under both.
     */
    demoted: {
      total: number;
      pathContext: number;
      placeholder: number;
      devDependency: number;
      optionalDependency: number;
      other: number;
    };
    /** Findings a baseline marks as existing, when they do not count. */
    baseline: { fromRepository: boolean; existing: number; atFailOn: number };
    ignoreFile: { fromRepository: boolean; suppressed: number; atFailOn: number };
    inline: { suppressed: number; atFailOn: number };
    /**
     * Findings a reviewer marked false positive in this run. Not something
     * the repository controls directly, but a reviewing agent reads the
     * repository and can be talked into dismissing findings, so the
     * dismissals at severity >= failOn are a cover WARNING too.
     */
    dismissed: {
      /** Findings (not hotspots) with a false_positive verdict. */
      total: number;
      atFailOn: number;
      /** Reviewer labels of the dismissals at severity >= failOn, sanitised. */
      reviewers: string[];
      /** Dismissals at severity >= failOn without a reviewer label. */
      unnamed: number;
    };
    toolOutputFiles: number;
    excludedSourceFiles: { total: number; truncated: boolean; byDirectory: Record<string, number> };
    untrusted: boolean;
  };
  exitCode: { counting: number; code: 0 | 1 };
}

/** A reviewer label as shown in a warning: one line, plain characters, short. */
export function reviewerLabel(value: string): string {
  return value
    .replace(/[^A-Za-z0-9._@:/ +()-]/g, "?")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 48);
}

/** Who dismissed a finding, from its current verdict; undefined when unnamed. */
export function dismissedBy(finding: Finding): string | undefined {
  const review = finding.review;
  const label = reviewerLabel(review?.reviewer || review?.actor || "");
  return label === "" ? undefined : label;
}

function dismissedSummary(
  all: readonly Finding[],
  atFailOn: (finding: Finding) => boolean,
): FindingSummary["reductions"]["dismissed"] {
  const dismissed = all.filter((finding) => finding.status === "false_positive");
  const serious = dismissed.filter(atFailOn);
  const reviewers = new Set<string>();
  let unnamed = 0;
  for (const finding of serious) {
    const label = dismissedBy(finding);
    if (label) reviewers.add(label);
    else unnamed += 1;
  }
  return {
    total: dismissed.length,
    atFailOn: serious.length,
    reviewers: [...reviewers].sort(),
    unnamed,
  };
}

/** The exit-code rule: active, severity >= failOn, confidence >= minConfidence, new when a baseline is active. */
export function countsTowardExitCode(
  finding: Finding,
  options: CountOptions = {},
): boolean {
  if (!isActionable(finding)) return false;
  if (finding.kind === "hotspot") return false;
  if (!severityAtLeast(finding.severity, options.failOn ?? "high")) return false;
  const confidence = applyVerdictConfidence(finding).confidence;
  if (!confidenceAtLeast(confidence, options.minConfidence ?? "medium")) {
    return false;
  }
  if (options.newOnly && finding.baselineState === "existing") return false;
  return true;
}

export function summarizeFindings(
  rawFindings: readonly Finding[],
  rawHotspots: readonly Finding[] = [],
  options: CountOptions = {},
): FindingSummary {
  // A reviewer's confirmed / likely verdict outranks the scan's lowering.
  const findings = rawFindings.map(applyVerdictConfidence);
  const hotspots = rawHotspots.map(applyVerdictConfidence);
  const minConfidence = options.minConfidence ?? "medium";
  const failOn = options.failOn ?? "high";
  const newOnly = Boolean(options.newOnly);
  const active = findings.filter(isActionable);
  const headline = active.filter((finding) =>
    confidenceAtLeast(finding.confidence, minConfidence),
  );
  const low = active.filter(
    (finding) => !confidenceAtLeast(finding.confidence, minConfidence),
  );

  const bySeverity = zeroSeverities();
  const byCategory = zeroCategories();
  const matrix = {
    code: zeroSeverities(),
    secrets: zeroSeverities(),
    config: zeroSeverities(),
    dependencies: zeroSeverities(),
  };
  for (const finding of headline) {
    const category = headlineCategory(finding);
    bySeverity[finding.severity] += 1;
    byCategory[category] += 1;
    matrix[category][finding.severity] += 1;
  }

  const lowByCategory = zeroCategories();
  for (const finding of low) lowByCategory[headlineCategory(finding)] += 1;
  const lowDependencies = countDependencies(
    low.filter((finding) => finding.category === "sca"),
  );

  const lowered = {
    total: 0,
    outOfHeadline: 0,
    pathContext: 0,
    placeholder: 0,
    devDependency: 0,
    optionalDependency: 0,
    other: 0,
  };
  const pathContext: Record<string, number> = {};
  const demoted = {
    total: 0,
    pathContext: 0,
    placeholder: 0,
    devDependency: 0,
    optionalDependency: 0,
    other: 0,
  };
  const setAside: Finding[] = [];
  const activeBySeverity = zeroSeverities();
  const activeByConfidence: Record<Confidence, number> = { high: 0, medium: 0, low: 0 };
  for (const finding of active) {
    activeBySeverity[finding.severity] += 1;
    activeByConfidence[finding.confidence] += 1;
    const context = pathContextOf(finding);
    if (context) pathContext[context] = (pathContext[context] ?? 0) + 1;
    if (!confidenceWasLowered(finding)) continue;
    lowered.total += 1;
    const original = confidenceOriginalOf(finding);
    const reasons = adjustmentsOf(finding);
    if (
      !confidenceAtLeast(finding.confidence, minConfidence) &&
      (!original || confidenceAtLeast(original, minConfidence))
    ) {
      lowered.outOfHeadline += 1;
      // Would it count toward the exit code with the reported confidence?
      if (
        finding.kind !== "hotspot" &&
        severityAtLeast(finding.severity, failOn) &&
        !(newOnly && finding.baselineState === "existing")
      ) {
        demoted.total += 1;
        let known = false;
        const bump = (key: "pathContext" | "placeholder" | "devDependency" | "optionalDependency", prefix: string): void => {
          if (reasons.some((reason) => reason.startsWith(prefix))) {
            demoted[key] += 1;
            known = true;
          }
        };
        bump("pathContext", "path-context");
        bump("placeholder", "placeholder");
        bump("devDependency", "dev-dependency");
        bump("optionalDependency", "optional-dependency");
        if (!known) demoted.other += 1;
      }
      if (
        finding.category === "sca" &&
        reasons.some(
          (reason) => reason === "dev-dependency" || reason === "optional-dependency",
        )
      ) {
        setAside.push(finding);
      }
    }
    let known = false;
    if (reasons.some((reason) => reason.startsWith("path-context"))) {
      lowered.pathContext += 1;
      known = true;
    }
    if (reasons.some((reason) => reason.startsWith("placeholder"))) {
      lowered.placeholder += 1;
      known = true;
    }
    if (reasons.some((reason) => reason.startsWith("dev-dependency"))) {
      lowered.devDependency += 1;
      known = true;
    }
    if (reasons.some((reason) => reason.startsWith("optional-dependency"))) {
      lowered.optionalDependency += 1;
      known = true;
    }
    if (!known) lowered.other += 1;
  }

  const setAsideCount = countDependencies(setAside);
  const all = [...findings, ...hotspots];
  const suppressedAll = all.filter((finding) => finding.status === "suppressed");
  const inline = suppressedAll.filter(
    (finding) => finding.suppression?.source === "inline",
  ).length;
  const counting = findings.filter((finding) =>
    countsTowardExitCode(finding, { minConfidence, failOn, newOnly }),
  ).length;
  const controls = options.controls ?? {};
  const atFailOn = (finding: Finding): boolean =>
    finding.kind !== "hotspot" && severityAtLeast(finding.severity, failOn);
  const existing = newOnly
    ? active.filter((finding) => finding.baselineState === "existing")
    : [];
  const byIgnoreFile = suppressedAll.filter((finding) => finding.suppression?.source !== "inline");
  const byInline = suppressedAll.filter((finding) => finding.suppression?.source === "inline");

  return {
    thresholds: { minConfidence, failOn, newOnly },
    headline: { total: headline.length, bySeverity, byCategory, matrix },
    dependencies: countDependencies(
      headline.filter((finding) => finding.category === "sca"),
    ),
    dependenciesSetAside: {
      advisories: setAsideCount.advisories,
      vulnerablePackages: setAsideCount.vulnerablePackages,
    },
    active: {
      total: active.length,
      bySeverity: activeBySeverity,
      byConfidence: activeByConfidence,
    },
    lowConfidence: {
      total: low.length,
      byCategory: lowByCategory,
      dependencies: {
        advisories: lowDependencies.advisories,
        vulnerablePackages: lowDependencies.vulnerablePackages,
      },
    },
    hotspots: hotspots.filter(isActionable).length,
    suppressed: {
      total: suppressedAll.length,
      ignoreFile: suppressedAll.length - inline,
      inline,
    },
    falsePositives: all.filter((finding) => finding.status === "false_positive")
      .length,
    confidenceLowered: lowered,
    pathContext,
    reductions: {
      demoted,
      baseline: {
        fromRepository: controls.baselineFromRepository === true,
        existing: existing.length,
        atFailOn: existing.filter(
          (finding) => atFailOn(finding) && confidenceAtLeast(finding.confidence, minConfidence),
        ).length,
      },
      ignoreFile: {
        fromRepository: controls.ignoreFileFromRepository === true,
        suppressed: byIgnoreFile.length,
        atFailOn: byIgnoreFile.filter(atFailOn).length,
      },
      inline: { suppressed: byInline.length, atFailOn: byInline.filter(atFailOn).length },
      dismissed: dismissedSummary(all, atFailOn),
      toolOutputFiles: controls.toolOutputFiles ?? 0,
      excludedSourceFiles: controls.excludedSourceFiles ?? {
        total: 0,
        truncated: false,
        byDirectory: {},
      },
      untrusted: controls.untrusted === true,
    },
    exitCode: { counting, code: counting > 0 ? 1 : 0 },
  };
}

// ---------------------------------------------------------------------------
// Run policy
//
// The thresholds and switches a scan ran with are recorded once, in the args
// of run.json, and read back through `runPolicy` by every renderer and every
// later command (`report`, `status`, the MCP tools). Nothing else decides
// which thresholds a number is computed with.
// ---------------------------------------------------------------------------

export interface RunPolicy {
  /** `--fail-on`. */
  failOn: Severity;
  /** `--min-confidence`. */
  minConfidence: Confidence;
  /** `--fail-on-existing`. */
  failOnExisting: boolean;
  /** A baseline file was applied to the run. */
  baselineUsed: boolean;
  /** `--include-tests`. */
  includeTests: boolean;
  /** `--include-dev`. */
  includeDev: boolean;
  /** `--no-inline-ignore`. */
  noInlineIgnore: boolean;
  /** Engines selected for the run. */
  engines: string[];
}

function recordOf(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

/**
 * The policy of a run, from run.json (`args`) or from the `run` object of
 * findings.json (the same fields at the top level). Missing or invalid values
 * fall back to the scan defaults, so runs written by older versions still
 * render.
 */
export function runPolicy(run: Record<string, unknown>): RunPolicy {
  const args = recordOf(run.args);
  const pick = (key: string): unknown => (key in args ? args[key] : run[key]);
  const failOn = pick("failOn");
  const minConfidence = pick("minConfidence");
  const baselineUsed = pick("baselineUsed");
  const noInlineIgnore = pick("noInlineIgnore");
  const engines = pick("engines");
  return {
    failOn: (SEVERITIES as readonly unknown[]).includes(failOn) ? (failOn as Severity) : "high",
    minConfidence: (CONFIDENCES as readonly unknown[]).includes(minConfidence)
      ? (minConfidence as Confidence)
      : "medium",
    failOnExisting: pick("failOnExisting") === true,
    baselineUsed: typeof baselineUsed === "boolean" ? baselineUsed : Boolean(run.baseline),
    includeTests: pick("includeTests") === true,
    includeDev: pick("includeDev") === true,
    noInlineIgnore:
      typeof noInlineIgnore === "boolean" ? noInlineIgnore : pick("inlineIgnore") === false,
    engines: Array.isArray(engines)
      ? engines.filter((engine): engine is string => typeof engine === "string")
      : [],
  };
}

/** Options of the counting model for a run policy. */
export function countOptionsOf(policy: RunPolicy): Required<Omit<CountOptions, "controls">> {
  return {
    failOn: policy.failOn,
    minConfidence: policy.minConfidence,
    newOnly: policy.baselineUsed && !policy.failOnExisting,
  };
}

/** The summary of a run: its findings counted with its own recorded policy. */
export function summarizeRun(
  run: Record<string, unknown>,
  findings: readonly Finding[],
  hotspots: readonly Finding[] = [],
): FindingSummary {
  return summarizeFindings(findings, hotspots, {
    ...countOptionsOf(runPolicy(run)),
    controls: repositoryControlsOf(run),
  });
}

/**
 * The count fields of run.json, findings.json (`run`), `status` and
 * `report --format summary`. The older names are kept for readers of those
 * files; every value comes from the one summary:
 *
 * - `findings` / `findingCounts`: the headline (active findings at confidence
 *   >= `--min-confidence`), total and by severity;
 * - `confidenceCounts`: all active findings by confidence;
 * - `lowConfidenceCandidates`, `hotspotCount` (active hotspots),
 *   `suppressedCount`, `falsePositiveCount`.
 */
export function summaryCountFields(summary: FindingSummary): {
  findings: number;
  findingCounts: Record<Severity, number>;
  confidenceCounts: Record<Confidence, number>;
  lowConfidenceCandidates: number;
  hotspotCount: number;
  suppressedCount: number;
  falsePositiveCount: number;
  summary: FindingSummary;
} {
  return {
    findings: summary.headline.total,
    findingCounts: summary.headline.bySeverity,
    confidenceCounts: summary.active.byConfidence,
    lowConfidenceCandidates: summary.lowConfidence.total,
    hotspotCount: summary.hotspots,
    suppressedCount: summary.suppressed.total,
    falsePositiveCount: summary.falsePositives,
    summary,
  };
}

/** Active findings per confidence adjustment reason. */
export function countAdjustments(findings: readonly Finding[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const finding of findings) {
    if (!isActionable(finding)) continue;
    for (const reason of adjustmentsOf(finding)) {
      counts[reason] = (counts[reason] ?? 0) + 1;
    }
  }
  return counts;
}

/**
 * The `run` object of findings.json for a run.json record: identity, the
 * policy at the top level, baseline and scope. Counts are added by
 * `renderFindingsJson` from the findings themselves.
 */
export function findingsJsonRun(run: Record<string, unknown>): Record<string, unknown> {
  const args = recordOf(run.args);
  const policy = runPolicy(run);
  return {
    runId: run.runId,
    tool: run.tool,
    startedAt: run.startedAt,
    finishedAt: run.finishedAt,
    durationMs: run.durationMs,
    rulesCount: run.rulesCount,
    profile: typeof args.profile === "string" ? args.profile : "standard",
    offline: args.offline === true,
    ...policy,
    ...(run.repositoryControls ? { repositoryControls: repositoryControlsOf(run) } : {}),
    ...(run.baseline ? { baseline: run.baseline } : {}),
    ...(run.scope ? { scope: run.scope } : {}),
    warnings: Array.isArray(run.warnings) ? run.warnings : [],
  };
}

/** What a renderer needs besides run.json. */
export interface ReportInputs {
  findings: Finding[];
  hotspots: Finding[];
  coverage: CoverageReport;
  rules: LoadedRule[];
  reviewStats?: ReportContext["reviewStats"];
  reviewers?: string[];
  agentReviewed?: boolean;
}

/**
 * The report context of a run, from its run.json record. The scan and a later
 * `code-audit report <run>` both build the context here, so the cover and
 * SARIF of a run are computed with the thresholds the run was scanned with.
 */
export function buildReportContext(
  run: Record<string, unknown>,
  inputs: ReportInputs,
): ReportContext {
  const args = recordOf(run.args);
  const tool = recordOf(run.tool);
  const policy = runPolicy(run);
  const baseline = recordOf(run.baseline);
  const scope = recordOf(run.scope);
  const number = (value: unknown): number => (typeof value === "number" ? value : 0);
  const fixed = Array.isArray(run.baselineFixed)
    ? (run.baselineFixed as BaselineEntry[])
    : undefined;
  return {
    runId: typeof run.runId === "string" ? run.runId : "",
    target:
      typeof args.root === "string"
        ? args.root
        : typeof args.resolvedRoot === "string"
          ? args.resolvedRoot
          : inputs.coverage.root,
    startedAt: typeof run.startedAt === "string" ? run.startedAt : "",
    finishedAt: typeof run.finishedAt === "string" ? run.finishedAt : "",
    durationMs: number(run.durationMs),
    toolVersion: typeof tool.version === "string" ? tool.version : "",
    nodeVersion: typeof tool.node === "string" ? tool.node : process.version,
    profile: typeof args.profile === "string" ? args.profile : "standard",
    offline: args.offline === true,
    lang: args.lang === "zh" ? "zh" : "en",
    rules: inputs.rules,
    // Confirmed / likely verdicts restore confidence for every renderer.
    findings: inputs.findings.map(applyVerdictConfidence),
    hotspots: inputs.hotspots.map(applyVerdictConfidence),
    coverage: inputs.coverage,
    warnings: Array.isArray(run.warnings)
      ? run.warnings.filter((warning): warning is string => typeof warning === "string")
      : [],
    minConfidence: policy.minConfidence,
    failOn: policy.failOn,
    failOnExisting: policy.failOnExisting,
    ...(policy.baselineUsed
      ? {
          baseline: {
            path: typeof baseline.path === "string" ? baseline.path : "",
            entries: number(baseline.entries),
            new: number(baseline.new),
            existing: number(baseline.existing),
            fixed: number(baseline.fixed),
          },
          ...(fixed ? { baselineFixed: fixed } : {}),
        }
      : {}),
    ...(typeof scope.since === "string"
      ? { scope: { since: scope.since, changedFiles: number(scope.changedFiles) } }
      : {}),
    ...(run.pathContext ? { pathContext: run.pathContext as Record<string, number> } : {}),
    repositoryControls: repositoryControlsOf(run),
    ...(inputs.reviewStats ? { reviewStats: inputs.reviewStats } : {}),
    ...(inputs.reviewers ? { reviewers: inputs.reviewers } : {}),
    ...(inputs.agentReviewed !== undefined ? { agentReviewed: inputs.agentReviewed } : {}),
  };
}

/** The summary a renderer shows for a report context. */
export function summarizeContext(context: ReportContext): FindingSummary {
  return summarizeFindings(context.findings, context.hotspots ?? [], {
    minConfidence: context.minConfidence ?? "medium",
    failOn: context.failOn ?? "high",
    newOnly: Boolean(context.baseline) && !context.failOnExisting,
    ...(context.repositoryControls ? { controls: context.repositoryControls } : {}),
  });
}

// ---------------------------------------------------------------------------
// Top risks
// ---------------------------------------------------------------------------

export interface TopRiskLimits {
  /** Entries shown. */
  total: number;
  /** Dependency entries (one per package@version) among them. */
  dependencies: number;
  /** Entries of one rule among them. */
  perRule: number;
}

export const TOP_RISK_LIMITS: TopRiskLimits = { total: 10, dependencies: 3, perRule: 2 };

/**
 * Pick the top risks from entries that are already in risk order (severity
 * first). The order is kept; an entry is passed over when the list already
 * holds `dependencies` dependency entries or `perRule` entries of its rule,
 * so one long advisory list or one noisy rule cannot fill the list. When that
 * leaves the list short, the entries passed over fill the remaining places,
 * again in risk order.
 */
export function selectTopRisks<T>(
  ordered: readonly T[],
  describe: (entry: T) => { dependency: boolean; ruleId: string },
  limits: TopRiskLimits = TOP_RISK_LIMITS,
): { shown: T[]; capped: number } {
  const picked = new Set<number>();
  let dependencies = 0;
  const perRule = new Map<string, number>();
  for (let index = 0; index < ordered.length && picked.size < limits.total; index += 1) {
    const { dependency, ruleId } = describe(ordered[index] as T);
    if (dependency) {
      if (dependencies >= limits.dependencies) continue;
      dependencies += 1;
    } else {
      const count = perRule.get(ruleId) ?? 0;
      if (count >= limits.perRule) continue;
      perRule.set(ruleId, count + 1);
    }
    picked.add(index);
  }
  let capped = 0;
  const lastPicked = Math.max(-1, ...picked);
  for (let index = 0; index < lastPicked; index += 1) {
    if (!picked.has(index)) capped += 1;
  }
  for (let index = 0; index < ordered.length && picked.size < limits.total; index += 1) {
    picked.add(index);
  }
  return {
    shown: ordered.filter((_, index) => picked.has(index)),
    capped,
  };
}

// ---------------------------------------------------------------------------
// Vulnerable packages: one entry per package@version per lockfile.
// ---------------------------------------------------------------------------

export interface VulnerablePackage {
  package: string;
  ecosystem: string;
  installed: string;
  file: string;
  line: number;
  scope: "runtime" | "optional" | "dev" | "unknown";
  relation: "direct" | "transitive" | "unknown";
  /** Advisories of this package, highest severity first. */
  advisories: Finding[];
  maxSeverity: Severity;
  maxConfidence: Confidence;
  /** Advisory ids, highest severity first, without duplicates. */
  advisoryIds: string[];
  recommendedUpgrade: string;
}

const SCOPE_RANK: Record<VulnerablePackage["scope"], number> = {
  runtime: 0,
  unknown: 1,
  optional: 2,
  dev: 3,
};

function relationOf(finding: Finding): VulnerablePackage["relation"] {
  const text = finding.dependencyPath ?? "";
  if (/\btransitive\b/i.test(text)) return "transitive";
  if (/\bdirect\b/i.test(text)) return "direct";
  return "unknown";
}

export function groupVulnerablePackages(
  findings: readonly Finding[],
): VulnerablePackage[] {
  const groups = new Map<string, VulnerablePackage>();
  for (const finding of findings) {
    if (finding.category !== "sca") continue;
    const key = `${finding.file}\u0000${packageKey(finding)}`;
    let group = groups.get(key);
    if (!group) {
      group = {
        package: finding.package ?? finding.evidence,
        ecosystem: finding.ecosystem ?? "",
        installed: finding.installedVersion ?? "—",
        file: finding.file,
        line: finding.startLine,
        scope: finding.dependencyScope ?? "unknown",
        relation: relationOf(finding),
        advisories: [],
        maxSeverity: finding.severity,
        maxConfidence: finding.confidence,
        advisoryIds: [],
        recommendedUpgrade: "—",
      };
      groups.set(key, group);
    }
    group.advisories.push(finding);
    const scope = finding.dependencyScope ?? "unknown";
    if (SCOPE_RANK[scope] < SCOPE_RANK[group.scope]) group.scope = scope;
    const relation = relationOf(finding);
    if (relation === "direct" || group.relation === "unknown") {
      group.relation = relation === "unknown" ? group.relation : relation;
    }
    if (SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[group.maxSeverity]) {
      group.maxSeverity = finding.severity;
    }
    if (
      CONFIDENCE_ORDER[finding.confidence] > CONFIDENCE_ORDER[group.maxConfidence]
    ) {
      group.maxConfidence = finding.confidence;
    }
  }
  for (const group of groups.values()) {
    group.advisories.sort(
      (a, b) =>
        SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] ||
        (a.advisoryId ?? a.ruleId).localeCompare(b.advisoryId ?? b.ruleId),
    );
    const compare = versionComparator(group.ecosystem);
    const fixes = new Map<string, string>();
    const ids = new Set<string>();
    for (const finding of group.advisories) {
      const advisoryId = finding.advisoryId ?? finding.ruleId;
      ids.add(advisoryId);
      const fixed = finding.fixedVersion;
      if (fixed && group.installed !== "—" && compare(fixed, group.installed) > 0) {
        const previous = fixes.get(advisoryId);
        if (!previous || compare(fixed, previous) < 0) fixes.set(advisoryId, fixed);
      }
    }
    group.advisoryIds = [...ids];
    group.recommendedUpgrade = recommendUpgrade(
      group.installed,
      [...fixes.values()],
      group.ecosystem,
    );
  }
  return [...groups.values()].sort(
    (a, b) =>
      SCOPE_RANK[a.scope] - SCOPE_RANK[b.scope] ||
      SEVERITY_ORDER[b.maxSeverity] - SEVERITY_ORDER[a.maxSeverity] ||
      b.advisories.length - a.advisories.length ||
      a.package.localeCompare(b.package) ||
      a.file.localeCompare(b.file),
  );
}

// ---------------------------------------------------------------------------
// Shared renderings of the summary.
// ---------------------------------------------------------------------------

/**
 * One sentence per way the audited repository reduced what counts toward the
 * exit code or what was scanned, each with its counts and the flag that turns
 * it off. Empty when nothing was reduced. The text holds numbers, thresholds
 * and names from fixed lists only (no file names), so it is safe in a
 * terminal; the labels use backticks for flags, which Markdown renders as
 * code.
 */
/**
 * The warning for findings at severity >= `--fail-on` that a reviewer marked
 * false positive; undefined when there is none. Shown on the report cover and
 * in the terminal, `--ci`, step and MCP summaries, so a review that dismissed
 * serious findings never yields a clean-looking result without saying so.
 */
export function dismissedWarning(summary: FindingSummary, lang: ReportLang = "en"): string | undefined {
  const dismissed = summary.reductions.dismissed;
  if (dismissed.atFailOn === 0) return undefined;
  const l = REPORT_LABELS[lang];
  const shown = dismissed.reviewers.slice(0, 5);
  const names = [...shown];
  if (dismissed.reviewers.length > shown.length) {
    names.push(fmt(l.warnDismissedMore, { n: dismissed.reviewers.length - shown.length }));
  }
  if (dismissed.unnamed > 0 || names.length === 0) names.push(l.dismissedUnnamed);
  return fmt(l.warnDismissed, {
    n: dismissed.atFailOn,
    failOn: summary.thresholds.failOn,
    reviewers: names.join(", "),
  });
}

export function reductionWarnings(summary: FindingSummary, lang: ReportLang = "en"): string[] {
  const l = REPORT_LABELS[lang];
  const { failOn, minConfidence, newOnly } = summary.thresholds;
  const reductions = summary.reductions;
  const lines: string[] = [];
  const demoted = reductions.demoted;
  if (demoted.total > 0) {
    const reasons: string[] = [];
    if (demoted.pathContext > 0) reasons.push(fmt(l.warnDemotedPath, { n: demoted.pathContext }));
    if (demoted.devDependency > 0) reasons.push(fmt(l.warnDemotedDev, { n: demoted.devDependency }));
    if (demoted.optionalDependency > 0) {
      reasons.push(fmt(l.warnDemotedOptional, { n: demoted.optionalDependency }));
    }
    if (demoted.placeholder > 0) reasons.push(fmt(l.warnDemotedPlaceholder, { n: demoted.placeholder }));
    if (demoted.other > 0) reasons.push(fmt(l.warnDemotedOther, { n: demoted.other }));
    lines.push(
      fmt(l.warnDemoted, { n: demoted.total, failOn, minConfidence, reasons: reasons.join("; ") }),
    );
  }
  if (reductions.baseline.fromRepository && newOnly && reductions.baseline.existing > 0) {
    lines.push(
      fmt(l.warnBaseline, {
        n: reductions.baseline.existing,
        m: reductions.baseline.atFailOn,
        failOn,
      }),
    );
  }
  if (reductions.ignoreFile.fromRepository && reductions.ignoreFile.suppressed > 0) {
    lines.push(
      fmt(l.warnIgnoreFile, {
        n: reductions.ignoreFile.suppressed,
        m: reductions.ignoreFile.atFailOn,
        failOn,
      }),
    );
  }
  if (reductions.inline.suppressed > 0) {
    lines.push(
      fmt(l.warnInline, { n: reductions.inline.suppressed, m: reductions.inline.atFailOn, failOn }),
    );
  }
  if (reductions.toolOutputFiles > 0) {
    lines.push(fmt(l.warnToolOutput, { n: reductions.toolOutputFiles }));
  }
  const dismissed = dismissedWarning(summary, lang);
  if (dismissed) lines.push(dismissed);
  const excluded = reductions.excludedSourceFiles;
  if (excluded.total > 0) {
    const dirs = Object.entries(excluded.byDirectory)
      .filter(([, count]) => count > 0)
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .slice(0, 8)
      .map(([name, count]) => `${name.replace(/[^A-Za-z0-9._-]/g, "?").slice(0, 40)}/ ${count}`)
      .join(", ");
    lines.push(
      fmt(excluded.truncated ? l.warnExcludedAtLeast : l.warnExcluded, { n: excluded.total, dirs }),
    );
  }
  return lines;
}

function verdictSentence(summary: FindingSummary, l: Labels, reviewed = false): string {
  const { failOn, minConfidence, newOnly } = summary.thresholds;
  const thresholds = fmt(
    newOnly ? l.verdictThresholdsNewOnly : l.verdictThresholds,
    { failOn, minConfidence },
  );
  const head =
    summary.exitCode.counting === 0
      ? l.verdictPass
      : summary.exitCode.counting === 1
        ? l.verdictFailOne
        : fmt(l.verdictFail, { n: summary.exitCode.counting });
  return fmt(reviewed ? l.verdictLineReviewed : l.verdictLine, {
    head,
    thresholds,
    code: summary.exitCode.code,
  });
}

/**
 * The headline block: verdict line, severity x category table and the
 * separate numbers. The Markdown cover and the CI step summary both use it.
 */
export function renderHeadlineMarkdown(
  summary: FindingSummary,
  lang: ReportLang = "en",
  /** `reviewed`: the run has verdicts or agent-added findings. */
  options: { reviewed?: boolean } = {},
): string[] {
  const l = REPORT_LABELS[lang];
  const { minConfidence } = summary.thresholds;
  const lines: string[] = [];
  lines.push(verdictSentence(summary, l, options.reviewed === true), "");
  const reduced = reductionWarnings(summary, lang);
  if (reduced.length > 0) {
    for (const warning of reduced) lines.push(`> **${l.warningWord}:** ${warning}`, ">");
    lines.pop();
    lines.push("");
  }
  lines.push(`**${fmt(l.headlineHeading, { minConfidence })}**`, "");
  lines.push(
    tableRow([l.category, ...SEVERITIES.map(capitalize), l.total]),
    tableRow(["---", ...SEVERITIES.map(() => "---:"), "---:"]),
  );
  const names: Record<HeadlineCategory, string> = {
    code: l.catCode,
    secrets: l.catSecrets,
    config: l.catConfig,
    dependencies: l.catDependencies,
  };
  for (const category of HEADLINE_CATEGORIES) {
    lines.push(
      tableRow([
        names[category],
        ...SEVERITIES.map((severity) =>
          String(summary.headline.matrix[category][severity]),
        ),
        String(summary.headline.byCategory[category]),
      ]),
    );
  }
  lines.push(
    tableRow([
      `**${l.total}**`,
      ...SEVERITIES.map((severity) => `**${summary.headline.bySeverity[severity]}**`),
      `**${summary.headline.total}**`,
    ]),
    "",
  );
  const dependencies = summary.dependencies;
  if (dependencies.advisories > 0) {
    lines.push(
      `- ${fmt(l.depLine, {
        advisories: dependencies.advisories,
        packages: dependencies.vulnerablePackages,
      })} — ${fmt(l.depScopes, {
        ra: dependencies.byScope.runtime.advisories,
        rp: dependencies.byScope.runtime.vulnerablePackages,
        da: dependencies.byScope.devOptional.advisories,
        dp: dependencies.byScope.devOptional.vulnerablePackages,
        ua: dependencies.byScope.unknown.advisories,
        up: dependencies.byScope.unknown.vulnerablePackages,
      })}`,
    );
  }
  const low = summary.lowConfidence;
  lines.push(
    `- ${fmt(l.lowLine, { minConfidence, n: low.total })}` +
      (low.total > 0
        ? ` — ${fmt(l.lowBreakdown, {
            code: low.byCategory.code,
            secrets: low.byCategory.secrets,
            config: low.byCategory.config,
            advisories: low.dependencies.advisories,
          })}${
            low.dependencies.advisories > 0
              ? ` ${fmt(l.lowPackages, { packages: low.dependencies.vulnerablePackages })}`
              : ""
          }`
        : ""),
    `- ${fmt(l.hotspotLine, { n: summary.hotspots })}`,
  );
  const lowered = summary.confidenceLowered;
  if (lowered.total > 0) {
    lines.push(
      `- ${lowered.total === 1 ? l.loweredLineOne : fmt(l.loweredLine, { n: lowered.total })}: ${fmt(l.loweredReasons, {
        path: lowered.pathContext,
        placeholder: lowered.placeholder,
        dev: lowered.devDependency,
      })}${
        lowered.optionalDependency > 0
          ? ` · ${fmt(l.loweredOptional, { n: lowered.optionalDependency })}`
          : ""
      }${lowered.other > 0 ? ` · ${fmt(l.loweredOther, { n: lowered.other })}` : ""}; ${
        lowered.outOfHeadline > 0
          ? fmt(l.loweredOut, { n: lowered.outOfHeadline })
          : l.loweredNoneOut
      }`,
    );
  }
  if (summary.dependenciesSetAside.advisories > 0) {
    lines.push(
      `- ${fmt(l.devSetAside, {
        advisories: summary.dependenciesSetAside.advisories,
        packages: summary.dependenciesSetAside.vulnerablePackages,
        minConfidence,
        heading: l.depDevHeading,
      })}`,
    );
  }
  const contexts = Object.entries(summary.pathContext).sort();
  if (contexts.length > 0) {
    lines.push(
      `- ${l.pathContextLine}: ${contexts
        .map(([context, count]) => `${escapeMarkdown(context)} ${count}`)
        .join(" · ")}`,
    );
  }
  if (summary.suppressed.total > 0 || summary.falsePositives > 0) {
    lines.push(
      `- ${fmt(l.excludedLine, {
        suppressed: summary.suppressed.total,
        file: summary.suppressed.ignoreFile,
        inline: summary.suppressed.inline,
        fp: summary.falsePositives,
      })}`,
    );
  }
  lines.push("", `> ${fmt(l.headlineNote, { minConfidence })}`, "");
  return lines;
}

/** `Baseline: ...` and `Scope: ...` lines of a run, for the terminal and the CI summary. */
export function renderRunScopeText(run: {
  baseline?: { new: number; existing: number; fixed: number };
  scope?: { since: string; changedFiles: number };
}): string[] {
  const lines: string[] = [];
  if (run.baseline) {
    lines.push(
      `Baseline: New: ${run.baseline.new} · Existing: ${run.baseline.existing} · Fixed: ${run.baseline.fixed}`,
    );
  }
  if (run.scope) {
    lines.push(
      `Scope: files changed since ${run.scope.since} (${run.scope.changedFiles} ${run.scope.changedFiles === 1 ? "file" : "files"})`,
    );
  }
  return lines;
}

/** Plain-text summary lines for the terminal (English, no Markdown). */
export function renderSummaryText(summary: FindingSummary): string[] {
  const { minConfidence, failOn, newOnly } = summary.thresholds;
  const severity = summary.headline.bySeverity;
  const category = summary.headline.byCategory;
  const lines: string[] = [
    `Findings: ${summary.headline.total} (critical ${severity.critical}, high ${severity.high}, medium ${severity.medium}, low ${severity.low}, info ${severity.info}) at confidence >= ${minConfidence}`,
    `  by category: code ${category.code}, secrets ${category.secrets}, config/IaC ${category.config}, dependencies ${category.dependencies}`,
  ];
  const dependencies = summary.dependencies;
  if (dependencies.advisories > 0) {
    lines.push(
      `  dependencies: advisories ${dependencies.advisories}, vulnerable packages ${dependencies.vulnerablePackages}; advisories/packages by scope: runtime ${dependencies.byScope.runtime.advisories}/${dependencies.byScope.runtime.vulnerablePackages}, dev/optional ${dependencies.byScope.devOptional.advisories}/${dependencies.byScope.devOptional.vulnerablePackages}, unknown ${dependencies.byScope.unknown.advisories}/${dependencies.byScope.unknown.vulnerablePackages}`,
    );
  }
  const low = summary.lowConfidence;
  lines.push(
    `Low-confidence candidates: ${low.total} (not counted above` +
      (low.total > 0
        ? `; code ${low.byCategory.code}, secrets ${low.byCategory.secrets}, config/IaC ${low.byCategory.config}, dependency advisories ${low.dependencies.advisories})`
        : ")"),
    `Hotspots: ${summary.hotspots} (not counted above)`,
  );
  const lowered = summary.confidenceLowered;
  if (lowered.total > 0) {
    lines.push(
      `Confidence lowered: ${lowered.total} (path context ${lowered.pathContext}, placeholder value ${lowered.placeholder}, dev dependency ${lowered.devDependency}${lowered.optionalDependency > 0 ? `, optional dependency ${lowered.optionalDependency}` : ""}${lowered.other > 0 ? `, other ${lowered.other}` : ""}); ${lowered.outOfHeadline > 0 ? `${lowered.outOfHeadline} dropped below the threshold (not counted above)` : "none dropped below the threshold"}`,
    );
  }
  if (summary.dependenciesSetAside.advisories > 0) {
    lines.push(
      `Dev/optional dependencies set aside: ${summary.dependenciesSetAside.advisories} advisories in ${summary.dependenciesSetAside.vulnerablePackages} ${summary.dependenciesSetAside.vulnerablePackages === 1 ? "package" : "packages"} (confidence lowered below ${minConfidence}: not counted above, no effect on the exit code; --include-dev counts them at full weight)`,
    );
  }
  if (summary.suppressed.total > 0) {
    lines.push(
      `Suppressed: ${summary.suppressed.total} (ignore file ${summary.suppressed.ignoreFile}, inline comments ${summary.suppressed.inline}); listed in the report`,
    );
  }
  if (summary.falsePositives > 0) {
    lines.push(
      `False positives excluded: ${summary.falsePositives} (each one is listed with reviewer and rationale under "Dismissed by review" in the report)`,
    );
  }
  for (const warning of reductionWarnings(summary, "en")) {
    lines.push(`WARNING: ${warning.replace(/`/g, "")}`);
  }
  lines.push(
    `Exit code: ${summary.exitCode.code} - ${summary.exitCode.counting === 1 ? "1 finding counts" : `${summary.exitCode.counting} findings count`} toward the exit code (severity >= ${failOn}, confidence >= ${minConfidence}${newOnly ? ", new since the baseline only" : ""})`,
  );
  return lines;
}

function capitalize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

// ---------------------------------------------------------------------------
// Markdown report
// ---------------------------------------------------------------------------

/** Detail blocks (with evidence) shown per rule before the location table starts. */
const DETAIL_BLOCKS_PER_RULE = 3;
/** Rows of the location table per rule; the rest is in findings.json. */
const TABLE_ROWS_PER_RULE = 40;
/** Locations shown inline per rule for low-confidence candidates and hotspots. */
const INLINE_LOCATIONS = 5;
const ADVISORY_IDS_SHOWN = 3;
const ADVISORY_DETAILS_PER_PACKAGE = 10;
const SKIPPED_EXAMPLES = 3;
const WARNINGS_SHOWN = 40;
const FIXED_SHOWN = 100;
/** Rows of the "Dismissed by review" table; the rest is counted. */
const DISMISSED_SHOWN = 500;
/** Characters of a verdict rationale shown in that table. */
const DISMISSED_RATIONALE_MAX = 300;

/** Longest file path shown in one piece. */
const PATH_TEXT_MAX = 300;

const KNOWN_PATH_CONTEXTS = ["test", "docs", "example", "vendored", "generated"];

function contextTag(finding: Finding): string {
  const context = pathContextOf(finding);
  if (!context) return "";
  const safe = KNOWN_PATH_CONTEXTS.includes(context)
    ? context
    : context.replace(/[^A-Za-z0-9_-]/g, "").slice(0, 20) || "other";
  return ` \`${safe}\``;
}

function locationText(finding: Finding): string {
  return `${escapeMarkdown(finding.file, PATH_TEXT_MAX)}:${finding.startLine}${contextTag(finding)}`;
}

/** Statuses a reviewer (or `add-finding`) set; `candidate` is the scan's own. */
function verdictStatus(finding: Finding): string | undefined {
  return finding.status === "candidate" || finding.status === "suppressed"
    ? undefined
    : finding.status.replace(/[^a-z_]/g, "");
}

function confidenceText(finding: Finding): string {
  const original = confidenceOriginalOf(finding);
  return original && original !== finding.confidence
    ? `${original} → ${finding.confidence}`
    : finding.confidence;
}

/** Runtime / first-party source ranks before tests, docs, examples and dev dependencies. */
function productionRank(finding: Finding): number {
  if (pathContextOf(finding)) return 2;
  if (finding.category !== "sca") return 0;
  const group = scopeGroup(finding);
  return group === "runtime" ? 0 : group === "unknown" ? 1 : 2;
}

const CATEGORY_RANK: Record<HeadlineCategory, number> = {
  secrets: 0,
  code: 1,
  config: 2,
  dependencies: 3,
};

/** Severity, then confidence, then production over non-production, then category. */
function compareRisk(a: Finding, b: Finding): number {
  return (
    SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] ||
    CONFIDENCE_ORDER[b.confidence] - CONFIDENCE_ORDER[a.confidence] ||
    productionRank(a) - productionRank(b) ||
    CATEGORY_RANK[headlineCategory(a)] - CATEGORY_RANK[headlineCategory(b)] ||
    a.file.localeCompare(b.file) ||
    a.startLine - b.startLine ||
    a.ruleId.localeCompare(b.ruleId)
  );
}

interface RuleGroup {
  ruleId: string;
  /** Members in risk order; the first one represents the group. */
  findings: Finding[];
}

function groupByRule(findings: Finding[]): RuleGroup[] {
  const groups = new Map<string, Finding[]>();
  for (const finding of findings) {
    const list = groups.get(finding.ruleId);
    if (list) list.push(finding);
    else groups.set(finding.ruleId, [finding]);
  }
  const result: RuleGroup[] = [];
  for (const [ruleId, list] of groups) {
    result.push({ ruleId, findings: [...list].sort(compareRisk) });
  }
  return result.sort(
    (a, b) =>
      compareRisk(a.findings[0] as Finding, b.findings[0] as Finding) ||
      b.findings.length - a.findings.length,
  );
}

function oneLine(value: string, max: number): string {
  return truncate(value.replace(/\s+/g, " ").trim(), max);
}

export function renderMarkdown(input: ReportContext): string {
  // Confirmed / likely verdicts restore confidence (idempotent).
  const context: ReportContext = {
    ...input,
    findings: input.findings.map(applyVerdictConfidence),
    ...(input.hotspots ? { hotspots: input.hotspots.map(applyVerdictConfidence) } : {}),
  };
  const l = REPORT_LABELS[context.lang];
  const minConfidence = context.minConfidence ?? "medium";
  const ruleById = new Map(context.rules.map((rule) => [rule.id, rule]));
  const ruleText = (
    finding: Finding,
  ): { title: string; message: string; remediation: string } => {
    const rule = ruleById.get(finding.ruleId);
    if (rule) return localizeRule(rule, context.lang);
    const builtin = context.lang === "zh" ? BUILTIN_FINDING_TEXT_ZH[finding.ruleId] : undefined;
    // Only the detector's own findings: an agent-added finding that reuses
    // the rule id keeps the text its author wrote.
    if (builtin && finding.provenance.engine !== "agent") return builtin;
    return {
      title: finding.title,
      message: finding.message ?? "",
      remediation: finding.remediation,
    };
  };
  const allHotspots = context.hotspots ?? [];
  const summary = summarizeContext(context);
  const active = context.findings.filter(isActionable);
  const headline = active.filter((finding) =>
    confidenceAtLeast(finding.confidence, minConfidence),
  );
  const lowConfidence = active.filter(
    (finding) => !confidenceAtLeast(finding.confidence, minConfidence),
  );
  const headlineCode = headline.filter((finding) => finding.category !== "sca");
  const lowCode = lowConfidence.filter((finding) => finding.category !== "sca");
  const activeSca = active.filter((finding) => finding.category === "sca");
  const packages = groupVulnerablePackages(activeSca);
  // Headline packages as counted on the cover: distinct package@version,
  // merged across the lockfiles that pin them.
  const distinctPackages: Array<VulnerablePackage & { files: number }> = [];
  {
    const byKey = new Map<string, Finding[]>();
    for (const finding of headline) {
      if (finding.category !== "sca") continue;
      const list = byKey.get(packageKey(finding)) ?? [];
      list.push(finding);
      byKey.set(packageKey(finding), list);
    }
    for (const list of byKey.values()) {
      const perFile = groupVulnerablePackages(list);
      const first = perFile[0] as VulnerablePackage;
      const merged = groupVulnerablePackages(
        list.map((finding) => ({ ...finding, file: first.file })),
      )[0] as VulnerablePackage;
      distinctPackages.push({ ...merged, line: first.line, files: perFile.length });
    }
  }
  const scopeLabel: Record<VulnerablePackage["scope"], string> = {
    runtime: l.scopeRuntime,
    dev: l.scopeDev,
    optional: l.scopeOptional,
    unknown: l.scopeUnknown,
  };
  const relationLabel: Record<VulnerablePackage["relation"], string> = {
    direct: l.direct,
    transitive: l.transitive,
    unknown: "—",
  };
  const categoryLabel: Record<HeadlineCategory, string> = {
    code: l.catCode,
    secrets: l.catSecrets,
    config: l.catConfig,
    dependencies: l.catDependency,
  };

  const lines: string[] = [];
  const heading = (level: number, text: string): void => {
    lines.push(`${"#".repeat(level)} ${text}`, "");
  };
  let sectionNumber = 0;
  const section = (text: string): void => {
    sectionNumber += 1;
    heading(2, `${sectionNumber}. ${text}`);
  };

  // ---- Title and review state ------------------------------------------
  heading(1, l.title);
  const reviewStats = context.reviewStats;
  if (!reviewStats || reviewStats.reviewed === 0) {
    lines.push(`> **${l.unverified}**`, ">");
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

  // ---- 1. Executive summary --------------------------------------------
  section(l.summary);
  lines.push(
    ...renderHeadlineMarkdown(summary, context.lang, { reviewed: context.agentReviewed === true }),
  );

  // Top risks: one entry per rule or per vulnerable package.
  interface RiskItem {
    representative: Finding;
    count: number;
    text: string;
    dependency: boolean;
    /** Critical and high findings this entry stands for. */
    criticalHigh: number;
  }
  const isCriticalHigh = (finding: Finding): boolean =>
    finding.severity === "critical" || finding.severity === "high";
  const risks: RiskItem[] = [];
  for (const group of groupByRule(headlineCode)) {
    const first = group.findings[0] as Finding;
    const more = group.findings.length - 1;
    risks.push({
      representative: first,
      count: group.findings.length,
      dependency: false,
      criticalHigh: group.findings.filter(isCriticalHigh).length,
      text:
        `${categoryLabel[headlineCategory(first)]} — ${escapeMarkdown(ruleText(first).title)} — ${locationText(first)}` +
        (more > 0 ? ` (${fmt(l.moreLocations, { n: more })})` : ""),
    });
  }
  for (const pkg of distinctPackages) {
    const first = [...pkg.advisories].sort(compareRisk)[0] as Finding;
    const advisoryCount = pkg.advisoryIds.length;
    risks.push({
      representative: first,
      count: advisoryCount,
      dependency: true,
      criticalHigh: pkg.advisories.filter(isCriticalHigh).length,
      text:
        `${categoryLabel.dependencies} — ${escapeMarkdown(pkg.package)} ${escapeMarkdown(pkg.installed)} (${scopeLabel[pkg.scope]}` +
        (pkg.relation === "unknown" ? "" : `, ${relationLabel[pkg.relation]}`) +
        `): ${advisoryCount} ${advisoryCount === 1 ? l.advisoryWord : l.advisoriesWord}` +
        (pkg.recommendedUpgrade === "—"
          ? ""
          : `, ${l.upgradeTo} ${escapeMarkdown(pkg.recommendedUpgrade)}`) +
        ` — ${escapeMarkdown(pkg.file)}` +
        (pkg.files > 1 ? ` (${fmt(l.moreLocations, { n: pkg.files - 1 })})` : ""),
    });
  }
  risks.sort(
    (a, b) =>
      compareRisk(a.representative, b.representative) || b.count - a.count,
  );
  heading(3, l.top);
  if (risks.length === 0) {
    lines.push(fmt(l.topNone, { minConfidence }), "");
  } else {
    // Severity first; at most three packages and two entries of one rule, so
    // a long advisory list cannot push code and secret findings out.
    const top = selectTopRisks(risks, (risk) => ({
      dependency: risk.dependency,
      ruleId: risk.representative.ruleId,
    })).shown;
    for (const [index, risk] of top.entries()) {
      const finding = risk.representative;
      const reviewed = verdictStatus(finding);
      lines.push(
        `${index + 1}. **${finding.severity.toUpperCase()}** · ${confidenceText(finding)}${
          reviewed ? ` · ${l.status}: ${reviewed}` : ""
        } · ${risk.text}`,
      );
    }
    lines.push("");
    const more =
      headline.filter(isCriticalHigh).length -
      top.reduce((sum, risk) => sum + risk.criticalHigh, 0);
    if (more > 0) {
      lines.push(more === 1 ? l.topMoreOne : fmt(l.topMore, { n: more }), "");
    }
  }

  // Remediation priorities: what to fix first, as counts.
  if (headline.length > 0) {
    heading(3, l.priorities);
    lines.push(
      tableRow([l.priority, l.codeFindings, l.vulnerablePackages]),
      tableRow(["---", "---:", "---:"]),
    );
    const buckets: Array<[string, Severity[]]> = [
      [l.immediate, ["critical", "high"]],
      [l.thisWeek, ["medium"]],
      [l.thisMonth, ["low", "info"]],
    ];
    for (const [title, severities] of buckets) {
      lines.push(
        tableRow([
          title,
          String(
            headlineCode.filter((finding) => severities.includes(finding.severity))
              .length,
          ),
          String(
            distinctPackages.filter((pkg) => severities.includes(pkg.maxSeverity))
              .length,
          ),
        ]),
      );
    }
    lines.push("");
  }
  lines.push(`> ${l.confidenceNote}`, "");

  const modelLine =
    context.reviewers && context.reviewers.length > 0
      ? `${l.model}: ${l.modelReviewed} (${l.reviewer}: ${context.reviewers
          .map((reviewer) => escapeMarkdown(reviewer))
          .join(", ")})`
      : context.agentReviewed
        ? `${l.model}: ${l.modelReviewed}`
        : `${l.model}: ${l.modelNone}`;
  heading(3, l.runDetails);
  lines.push(
    `- ${l.target}: \`${escapeMarkdown(context.target)}\``,
    `- ${l.runId}: \`${escapeMarkdown(context.runId)}\` · ${l.date}: ${formatDate(context.startedAt)}`,
    `- ${l.range}: ${escapeMarkdown(context.coverage.root)}`,
    `- ${l.tools}: code-audit ${escapeMarkdown(context.toolVersion)}, Node.js ${escapeMarkdown(context.nodeVersion)} · ${l.scanProfile}: ${escapeMarkdown(context.profile)} · ${l.offline}: ${context.offline ? l.yes : l.no}`,
    `- ${modelLine}`,
  );
  if (context.scope) {
    lines.push(
      `- ${l.scopeNote}: ${fmt(
        context.scope.changedFiles === 1 ? l.scopeChangedOne : l.scopeChanged,
        { ref: escapeMarkdown(context.scope.since), n: context.scope.changedFiles },
      )}`,
    );
  }
  if (context.baseline) {
    lines.push(
      `- ${l.baselineSummary}: ${fmt(l.baselineCounts, {
        new: context.baseline.new,
        existing: context.baseline.existing,
        fixed: context.baseline.fixed,
      })}`,
    );
  }
  if (reviewStats) {
    lines.push(
      `- ${l.reviewNote}: ${reviewStats.reviewed} ${l.reviewed} / ${reviewStats.unreviewed} ${l.unreviewed}`,
    );
  }
  lines.push("");

  // ---- 2. Code, secrets and configuration findings -----------------------
  section(l.findingsSection);
  if (headlineCode.length === 0) {
    lines.push(l.none, "");
  }
  for (const group of groupByRule(headlineCode)) {
    const first = group.findings[0] as Finding;
    const text = ruleText(first);
    const hasRule = ruleById.has(group.ruleId);
    heading(3, `${escapeMarkdown(text.title)} — \`${escapeMarkdown(group.ruleId)}\``);
    const nonProduction = group.findings.filter((finding) =>
      pathContextOf(finding),
    ).length;
    const severities = [...new Set(group.findings.map((finding) => finding.severity))];
    lines.push(
      [
        `**${severities.map((severity) => severity.toUpperCase()).join(" / ")}**`,
        categoryLabel[headlineCategory(first)],
        ...(first.cwe ? [escapeMarkdown(first.cwe)] : []),
        ...(first.owasp ? [escapeMarkdown(first.owasp)] : []),
        (group.findings.length === 1
          ? l.groupMetaOne
          : fmt(l.groupMeta, { n: group.findings.length })) +
          (nonProduction > 0
            ? ` (${fmt(l.groupNonProd, { n: nonProduction })})`
            : ""),
      ].join(" · "),
      "",
    );
    if (text.message) {
      lines.push(`**${l.message}**: ${escapeMarkdown(text.message)}`, "");
    }
    lines.push(`**${l.remediation}**: ${escapeMarkdown(text.remediation)}`, "");
    // CWE and OWASP are already on the line above; list only what adds to it.
    const references = (first.references ?? []).filter(
      (reference) =>
        reference !== first.cwe &&
        reference !== first.owasp &&
        reference !== `OWASP ${first.owasp ?? ""}`,
    );
    if (references.length > 0) {
      lines.push(
        `**${l.references}**: ${references
          .slice(0, 5)
          .map((reference) => escapeMarkdown(reference))
          .join(", ")}`,
        "",
      );
    }
    for (const finding of group.findings.slice(0, DETAIL_BLOCKS_PER_RULE)) {
      const adjustments = adjustmentsOf(finding);
      lines.push(
        [
          `**${escapeMarkdown(finding.id)}** · ${locationText(finding)}`,
          ...(severities.length > 1 ? [`${l.severity}: ${finding.severity}`] : []),
          `${l.confidence}: ${confidenceText(finding)}`,
          ...(adjustments.length > 0
            ? [`${l.adjustments}: ${adjustments.map((entry) => escapeMarkdown(entry)).join(", ")}`]
            : []),
          `${l.status}: ${escapeMarkdown(finding.status)}`,
          `${l.engine}: ${escapeMarkdown(finding.provenance.engine)}`,
        ].join(" · "),
        "",
      );
      // A finding without a bundled rule (agent-added, external engine) can
      // carry its own description.
      const ownMessage = hasRule ? "" : ruleText(finding).message;
      if (finding !== first && ownMessage && ownMessage !== text.message) {
        lines.push(`${l.message}: ${escapeMarkdown(oneLine(ownMessage, 500))}`, "");
      }
      lines.push(codeBlock(truncate(finding.evidence, 800)), "");
    }
    const rest = group.findings.slice(DETAIL_BLOCKS_PER_RULE);
    if (rest.length > 0) {
      lines.push(`**${l.otherLocations}**`, "");
      lines.push(
        tableRow(["ID", l.location, l.severity, l.confidence, l.status, l.evidence]),
        tableRow(["---", "---", "---", "---", "---", "---"]),
      );
      for (const finding of rest.slice(0, TABLE_ROWS_PER_RULE)) {
        lines.push(
          tableRow([
            escapeMarkdown(finding.id),
            locationText(finding),
            finding.severity,
            confidenceText(finding),
            escapeMarkdown(finding.status),
            escapeMarkdown(oneLine(finding.evidence, 70)),
          ]),
        );
      }
      lines.push("");
      if (rest.length > TABLE_ROWS_PER_RULE) {
        lines.push(
          `> ${fmt(l.moreInJson, { n: rest.length - TABLE_ROWS_PER_RULE })}`,
          "",
        );
      }
    }
  }

  // ---- 3. Dependencies ---------------------------------------------------
  section(l.dependencies);
  lines.push(`> ${l.scaNote}`, "");
  if (packages.length === 0) {
    lines.push(l.none, "");
  } else {
    const packageTable = (rows: VulnerablePackage[]): void => {
      lines.push(
        tableRow([
          l.package,
          l.version,
          l.scope,
          l.relation,
          l.advisories,
          l.maxSeverity,
          l.recommendedUpgrade,
          l.advisoryIds,
          l.lockfile,
        ]),
        tableRow(["---", "---", "---", "---", "---:", "---", "---", "---", "---"]),
      );
      for (const pkg of rows) {
        const low = pkg.advisories.filter(
          (finding) => !confidenceAtLeast(finding.confidence, minConfidence),
        ).length;
        const lowNote =
          low === 0
            ? ""
            : low === pkg.advisories.length
              ? ` (${l.allLowConfidence})`
              : ` (${fmt(l.lowConfidenceCount, { n: low })})`;
        const ids = pkg.advisoryIds
          .slice(0, ADVISORY_IDS_SHOWN)
          .map((id) => escapeMarkdown(id))
          .join(", ");
        const moreIds = pkg.advisoryIds.length - ADVISORY_IDS_SHOWN;
        // Verdict statuses of the advisories in this row, with counts.
        const statusCounts = new Map<string, number>();
        for (const advisory of pkg.advisories) {
          const reviewed = verdictStatus(advisory);
          if (reviewed) statusCounts.set(reviewed, (statusCounts.get(reviewed) ?? 0) + 1);
        }
        const statusNote =
          statusCounts.size === 0
            ? ""
            : ` (${l.status}: ${[...statusCounts.entries()]
                .map(([name, count]) => `${name} ${count}`)
                .join(", ")})`;
        lines.push(
          tableRow([
            escapeMarkdown(pkg.package),
            escapeMarkdown(pkg.installed),
            scopeLabel[pkg.scope],
            relationLabel[pkg.relation],
            `${pkg.advisories.length}${lowNote}${statusNote}`,
            pkg.maxSeverity,
            escapeMarkdown(pkg.recommendedUpgrade),
            ids + (moreIds > 0 ? ` ${fmt(l.moreLocations, { n: moreIds })}` : ""),
            `${escapeMarkdown(pkg.file, PATH_TEXT_MAX)}:${pkg.line}${contextTag(pkg.advisories[0] as Finding)}`,
          ]),
        );
      }
      lines.push("");
    };
    const isDev = (pkg: VulnerablePackage): boolean =>
      pkg.scope === "dev" || pkg.scope === "optional";
    const main = packages.filter((pkg) => !isDev(pkg));
    const dev = packages.filter(isDev);
    heading(3, l.depRuntimeHeading);
    if (main.length === 0) lines.push(l.noItems, "");
    else packageTable(main);
    if (dev.length > 0) {
      heading(3, l.depDevHeading);
      packageTable(dev);
    }

    const detailed = main
      .filter((pkg) => pkg.scope === "runtime")
      .map((pkg) => ({
        pkg,
        advisories: pkg.advisories.filter(
          (finding) =>
            (finding.severity === "critical" || finding.severity === "high") &&
            confidenceAtLeast(finding.confidence, minConfidence),
        ),
      }))
      .filter((entry) => entry.advisories.length > 0);
    if (detailed.length > 0) {
      heading(3, l.depDetailHeading);
      for (const { pkg, advisories } of detailed) {
        lines.push(
          "<details>",
          `<summary>${fmt(l.depDetailSummary, {
            package: escapeHtml(pkg.package),
            version: escapeHtml(pkg.installed),
            n: advisories.length,
          })} — ${escapeHtml(pkg.file)}</summary>`,
          "",
        );
        for (const finding of advisories.slice(0, ADVISORY_DETAILS_PER_PACKAGE)) {
          const prefix = `${pkg.package}@${pkg.installed}: `;
          const title = finding.title.startsWith(prefix)
            ? finding.title.slice(prefix.length)
            : finding.title;
          const aliases = (finding.aliases ?? []).slice(0, 4);
          lines.push(
            `- **${finding.severity.toUpperCase()}** ${escapeMarkdown(finding.advisoryId ?? finding.ruleId)}` +
              (aliases.length > 0
                ? ` (${l.aliases}: ${aliases.map((alias) => escapeMarkdown(alias)).join(", ")})`
                : "") +
              ` — ${escapeMarkdown(oneLine(title, 160))} — ` +
              (finding.fixedVersion
                ? fmt(l.fixedIn, { version: escapeMarkdown(finding.fixedVersion) })
                : l.noFix) +
              ` · ${escapeMarkdown(finding.id)}` +
              (verdictStatus(finding) ? ` · ${l.status}: ${verdictStatus(finding)}` : ""),
          );
        }
        if (advisories.length > ADVISORY_DETAILS_PER_PACKAGE) {
          lines.push(
            `- ${fmt(l.moreInJson, { n: advisories.length - ADVISORY_DETAILS_PER_PACKAGE })}`,
          );
        }
        lines.push("", "</details>", "");
      }
    }
    const unique = new Set(
      activeSca.map((finding) => finding.advisoryId ?? finding.ruleId),
    );
    lines.push(
      `> ${fmt(l.uniqueAdvisories, {
        advisories: activeSca.length,
        unique: unique.size,
        packages: new Set(activeSca.map(packageKey)).size,
        rows: packages.length,
        lockfiles: new Set(packages.map((pkg) => pkg.file)).size,
      })} ${l.reachabilityNote}`,
      "",
    );
  }

  // Compact per-rule table shared by low-confidence candidates and hotspots.
  const ruleTable = (items: Finding[]): void => {
    lines.push(
      tableRow([l.severity, l.ruleId, l.ruleTitle, l.count, l.locations]),
      tableRow(["---", "---", "---", "---:", "---"]),
    );
    for (const group of groupByRule(items)) {
      const first = group.findings[0] as Finding;
      const shown = group.findings.slice(0, INLINE_LOCATIONS).map((finding) => {
        const original = confidenceOriginalOf(finding);
        const reviewed = verdictStatus(finding);
        const notes = [
          ...(original && original !== finding.confidence ? [confidenceText(finding)] : []),
          ...(reviewed ? [`${l.status}: ${reviewed}`] : []),
        ];
        return locationText(finding) + (notes.length > 0 ? ` (${notes.join(", ")})` : "");
      });
      const more = group.findings.length - shown.length;
      lines.push(
        tableRow([
          first.severity,
          escapeMarkdown(group.ruleId),
          escapeMarkdown(ruleText(first).title),
          String(group.findings.length),
          shown.join("; ") +
            (more > 0 ? `; ${fmt(l.moreLocations, { n: more })}` : ""),
        ]),
      );
    }
    lines.push("");
  };

  // ---- 4. Low-confidence candidates -------------------------------------
  section(l.lowConfidence);
  lines.push(`> ${fmt(l.lowConfidenceNote, { minConfidence })}`, "");
  if (lowConfidence.length === 0) {
    lines.push(l.noneLowConfidence, "");
  } else {
    if (lowCode.length > 0) ruleTable(lowCode);
    if (summary.lowConfidence.dependencies.advisories > 0) {
      lines.push(
        fmt(l.lowConfidenceSca, {
          advisories: summary.lowConfidence.dependencies.advisories,
          packages: summary.lowConfidence.dependencies.vulnerablePackages,
        }),
        "",
      );
    }
  }

  // ---- 5. Hotspots -------------------------------------------------------
  const hotspots = allHotspots.filter(isActionable);
  section(l.hotspots);
  lines.push(`> ${l.hotspotsNote}`, "");
  if (hotspots.length === 0) {
    lines.push(l.noneHotspots, "");
  } else {
    ruleTable(hotspots);
  }

  // ---- 6. Suppressed -----------------------------------------------------
  section(l.suppressed);
  lines.push(`> ${l.suppressedNote}`, "");
  const allSuppressed = [...context.findings, ...allHotspots].filter(
    (finding) => finding.status === "suppressed",
  );
  if (allSuppressed.length === 0) {
    lines.push(l.noItems, "");
  } else {
    lines.push(
      tableRow(["ID", l.ruleId, l.file, l.line, l.source, l.reason, l.expires]),
      tableRow(["---", "---", "---", "---", "---", "---", "---"]),
    );
    for (const finding of allSuppressed) {
      lines.push(
        tableRow([
          escapeMarkdown(finding.id),
          escapeMarkdown(finding.ruleId),
          `${escapeMarkdown(finding.file, PATH_TEXT_MAX)}${contextTag(finding)}`,
          String(finding.startLine),
          // "inline" is a comment in the audited repository itself.
          finding.suppression?.source === "inline"
            ? l.sourceInline
            : escapeMarkdown(finding.suppression?.source ?? "—"),
          escapeMarkdown(finding.suppression?.reason || l.noReason, 300),
          escapeMarkdown(finding.suppression?.expires ?? "—"),
        ]),
      );
    }
    lines.push("");
  }

  // ---- Dismissed by review ---------------------------------------------
  // Every record with a false_positive verdict, itemised: who dismissed it
  // and why. A reviewing agent can be prompt-injected by the repository it
  // reads; without this list a mass dismissal would leave only a count.
  const allDismissed = [...context.findings, ...allHotspots]
    .filter((finding) => finding.status === "false_positive")
    .sort(
      (a, b) =>
        (a.kind === "hotspot" ? 1 : 0) - (b.kind === "hotspot" ? 1 : 0) ||
        SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] ||
        a.file.localeCompare(b.file) ||
        a.startLine - b.startLine,
    );
  if (allDismissed.length > 0 || context.agentReviewed) {
    section(l.dismissedSection);
    lines.push(`> ${l.dismissedNote}`, "");
    if (allDismissed.length === 0) {
      lines.push(l.dismissedNone, "");
    } else {
      lines.push(
        tableRow([
          "ID",
          l.dismissedKind,
          l.severity,
          l.ruleId,
          l.file,
          l.line,
          l.dismissedReviewer,
          l.dismissedRationale,
        ]),
        tableRow(["---", "---", "---", "---", "---", "---", "---", "---"]),
      );
      for (const finding of allDismissed.slice(0, DISMISSED_SHOWN)) {
        const review = finding.review;
        const evidence = (review?.evidenceLines ?? [])
          .map((line) => singleLineText(line, 120))
          .filter((line) => line.length > 0)
          .slice(0, 2);
        const rationale = review
          ? `${redactText(singleLineText(review.rationale, DISMISSED_RATIONALE_MAX))}${
              evidence.length > 0 ? ` (${l.dismissedEvidence}: ${evidence.join(" / ")})` : ""
            }`
          : l.dismissedNoVerdict;
        lines.push(
          tableRow([
            escapeMarkdown(finding.id),
            finding.kind === "hotspot" ? l.dismissedKindHotspot : l.dismissedKindFinding,
            finding.severity,
            escapeMarkdown(finding.ruleId),
            `${escapeMarkdown(finding.file, PATH_TEXT_MAX)}${contextTag(finding)}`,
            String(finding.startLine),
            escapeMarkdown(dismissedBy(finding) ?? l.dismissedUnnamed, 60),
            escapeMarkdown(rationale, DISMISSED_RATIONALE_MAX + 300),
          ]),
        );
      }
      if (allDismissed.length > DISMISSED_SHOWN) {
        lines.push("", fmt(l.dismissedMore, { n: allDismissed.length - DISMISSED_SHOWN }));
      }
      lines.push("");
    }
  }

  // ---- 7. Fixed since baseline ------------------------------------------
  if (context.baselineFixed && context.baselineFixed.length > 0) {
    section(l.fixedSinceBaseline);
    lines.push(`> ${l.fixedNote}`, "");
    lines.push(
      tableRow([l.ruleId, l.file, l.severity, l.ruleTitle]),
      tableRow(["---", "---", "---", "---"]),
    );
    for (const entry of context.baselineFixed.slice(0, FIXED_SHOWN)) {
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
    if (context.baselineFixed.length > FIXED_SHOWN) {
      lines.push(
        `> ${fmt(l.moreInBaseline, { n: context.baselineFixed.length - FIXED_SHOWN })}`,
        "",
      );
    }
  }

  // ---- 8. Coverage -------------------------------------------------------
  section(l.coverage);
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
    `- ${l.lockfileNote}`,
  );
  // Files per path context, from coverage.json; `run.pathContext` when only
  // that is available.
  const coverageContext = context.coverage.pathContext;
  const recordedContexts = Object.entries(
    coverageContext?.files ?? context.pathContext ?? {},
  ).filter(
    ([name, count]) => name !== "lowered" && typeof count === "number" && count > 0,
  );
  if (recordedContexts.length > 0) {
    lines.push(
      `- ${l.pathContextCounts}: ${recordedContexts
        .map(([name, count]) => `${escapeMarkdown(name)} ${count}`)
        .join(" · ")}` +
        (coverageContext
          ? ` — ${coverageContext.lowering ? l.pathContextLowering : l.pathContextNotLowering}`
          : ""),
    );
  }
  lines.push("");
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
  heading(3, l.skipped);
  if (context.coverage.skipped.length === 0) {
    lines.push(l.noneSkipped, "");
  } else {
    const byReason = new Map<string, string[]>();
    for (const skipped of context.coverage.skipped) {
      const list = byReason.get(skipped.reason) ?? [];
      list.push(skipped.path);
      byReason.set(skipped.reason, list);
    }
    lines.push(
      tableRow([l.reason, l.count, l.example]),
      tableRow(["---", "---:", "---"]),
    );
    for (const [reason, paths] of [...byReason.entries()].sort(
      (a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]),
    )) {
      const more = paths.length - SKIPPED_EXAMPLES;
      lines.push(
        tableRow([
          escapeMarkdown(reason),
          String(paths.length),
          paths
            .slice(0, SKIPPED_EXAMPLES)
            .map((entry) => escapeMarkdown(entry, PATH_TEXT_MAX))
            .join(", ") + (more > 0 ? `, ${fmt(l.moreLocations, { n: more })}` : ""),
        ]),
      );
    }
    lines.push(
      "",
      `> ${fmt(l.skippedByReason, { n: context.coverage.skipped.length })}`,
      "",
    );
  }
  heading(3, l.warnings);
  if (context.warnings.length === 0) {
    lines.push(l.noneWarnings, "");
  } else {
    for (const warning of context.warnings.slice(0, WARNINGS_SHOWN)) {
      lines.push(`- ${escapeMarkdown(warning)}`);
    }
    if (context.warnings.length > WARNINGS_SHOWN) {
      lines.push(
        `- ${fmt(l.moreWarnings, { n: context.warnings.length - WARNINGS_SHOWN })}`,
      );
    }
    lines.push("");
  }

  // ---- 9. Appendix: rules that fired ------------------------------------
  section(l.appendix);
  const hits = new Map<string, number>();
  for (const finding of [...context.findings, ...allHotspots]) {
    hits.set(finding.ruleId, (hits.get(finding.ruleId) ?? 0) + 1);
  }
  const fired = context.rules.filter((rule) => hits.has(rule.id));
  lines.push(
    `> ${fmt(l.appendixNote, { loaded: context.rules.length, shown: fired.length })}`,
    "",
  );
  if (fired.length > 0) {
    lines.push(
      tableRow([
        l.ruleId,
        l.ruleTitle,
        l.severity,
        l.confidence,
        l.cwe,
        l.ruleLanguage,
        l.hits,
      ]),
      tableRow(["---", "---", "---", "---", "---", "---", "---:"]),
    );
    for (const rule of fired) {
      const text = localizeRule(rule, context.lang);
      lines.push(
        tableRow([
          escapeMarkdown(rule.id),
          escapeMarkdown(text.title),
          escapeMarkdown(rule.severity),
          escapeMarkdown(rule.confidence),
          escapeMarkdown(rule.cwe),
          escapeMarkdown(rule.languages.join(", ")),
          String(hits.get(rule.id) ?? 0),
        ]),
      );
    }
    lines.push("");
  }

  return `${lines.join("\n").replace(/\n{3,}/g, "\n\n")}\n`;
}

function sarifLevel(severity: Severity): "error" | "warning" | "note" {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "note";
}

export function renderSarif(input: ReportContext): string {
  const context: ReportContext = {
    ...input,
    findings: input.findings.map(applyVerdictConfidence),
    ...(input.hotspots ? { hotspots: input.hotspots.map(applyVerdictConfidence) } : {}),
  };
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
  // Same thresholds and the same rule as the cover and the exit code.
  const summary = summarizeContext(context);
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

  const results = allFindings.map((finding) => {
    const pathContext = pathContextOf(finding);
    const confidenceOriginal = confidenceOriginalOf(finding);
    const adjustments = adjustmentsOf(finding);
    return {
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
      ...(pathContext ? { pathContext } : {}),
      ...(finding.dependencyScope
        ? { dependencyScope: finding.dependencyScope }
        : {}),
      ...(confidenceOriginal ? { confidenceOriginal } : {}),
      ...(adjustments.length > 0 ? { adjustments } : {}),
      countsTowardExitCode: countsTowardExitCode(finding, summary.thresholds),
    },
    // SARIF 3.27.23: an empty array states "not suppressed"; a suppressed
    // result names where the suppression lives and the reason given for it.
    // A false_positive verdict is a suppression made outside the source: by
    // a reviewer (a host agent or a person) of this run.
    suppressions:
      finding.status === "suppressed"
        ? [
            {
              kind:
                finding.suppression?.source === "inline" ? "inSource" : "external",
              status: "accepted",
              justification: finding.suppression?.reason || "no reason given",
            },
          ]
        : finding.status === "false_positive"
          ? [
              {
                kind: "external",
                status: "accepted",
                justification: `Marked false positive by ${dismissedBy(finding) ?? "an unnamed reviewer"}: ${
                  finding.review
                    ? redactText(singleLineText(finding.review.rationale, DISMISSED_RATIONALE_MAX))
                    : "no verdict record"
                }`,
              },
            ]
          : [],
    };
  });

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
        // The thresholds of the run and what they make of the results.
        properties: {
          failOn: summary.thresholds.failOn,
          minConfidence: summary.thresholds.minConfidence,
          newOnly: summary.thresholds.newOnly,
          headline: {
            total: summary.headline.total,
            bySeverity: summary.headline.bySeverity,
          },
          lowConfidenceCandidates: summary.lowConfidence.total,
          hotspots: summary.hotspots,
          exitCode: summary.exitCode,
        },
      },
    ],
  };

  return `${JSON.stringify(document, null, 2)}\n`;
}

/**
 * findings.json. Every count in `run` (`summary` and the older count fields)
 * is computed here from the findings themselves with the policy recorded in
 * `run`: the thresholds at the top level, as written by `findingsJsonRun`.
 */
export function renderFindingsJson(
  run: Record<string, unknown>,
  storedFindings: Finding[],
  storedHotspots: Finding[] = [],
): string {
  const findings = storedFindings.map(applyVerdictConfidence);
  const hotspots = storedHotspots.map(applyVerdictConfidence);
  const { findings: _total, ...counts } = summaryCountFields(
    summarizeRun(run, findings, hotspots),
  );
  return `${JSON.stringify(
    {
      schemaVersion: 1,
      run: {
        ...run,
        ...counts,
        pathContext: countPathContexts(findings),
        adjustments: countAdjustments(findings),
      },
      findings,
      hotspots,
    },
    null,
    2,
  )}\n`;
}
