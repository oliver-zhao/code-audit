import crypto from "node:crypto";
import { z } from "zod";

export const SEVERITIES = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
] as const;

export const SeveritySchema = z.enum(SEVERITIES);
export type Severity = z.infer<typeof SeveritySchema>;

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

export const FindingStatusSchema = z.enum([
  "candidate",
  "confirmed",
  "likely",
  "needs_review",
  "false_positive",
  "suppressed",
  // A reviewer could not prove or refute the finding and named the missing
  // fact (`review.missing`). Counted like needs_review: open, not dismissed.
  "proof_gap",
]);
export type FindingStatus = z.infer<typeof FindingStatusSchema>;

export const CONFIDENCES = ["high", "medium", "low"] as const;

export const ConfidenceSchema = z.enum(CONFIDENCES);
export type Confidence = z.infer<typeof ConfidenceSchema>;

export const CONFIDENCE_ORDER: Record<Confidence, number> = {
  high: 3,
  medium: 2,
  low: 1,
};

export const FindingKindSchema = z.enum(["finding", "hotspot"]);
export type FindingKind = z.infer<typeof FindingKindSchema>;

/** How a finding came to be suppressed. */
export const SuppressionSchema = z.object({
  source: z.enum(["ignore-file", "inline"]),
  entry: z.number().int().nonnegative().optional(),
  reason: z.string(),
  /** Ignore-file expiry date (YYYY-MM-DD), when the entry has one. */
  expires: z.string().optional(),
});
export type Suppression = z.infer<typeof SuppressionSchema>;

export const PATH_CONTEXTS = ["test", "docs", "example", "vendored", "generated"] as const;

/**
 * What kind of non-product file a finding is in, decided from the file's path
 * (and, for `generated`, a header comment). Absent for ordinary source.
 */
export const PathContextSchema = z.enum(PATH_CONTEXTS);
export type PathContext = z.infer<typeof PathContextSchema>;

export const FindingCategorySchema = z.enum([
  "sast",
  "secrets",
  "sca",
  "config",
]);
export type FindingCategory = z.infer<typeof FindingCategorySchema>;

export const ProvenanceSchema = z
  .object({
    engine: z.string(),
    rule: z.string().optional(),
    version: z.string().optional(),
    /** All engines that reported this finding after cross-engine dedupe. */
    engines: z.array(z.string()).optional(),
  })
  .passthrough();

/**
 * Where a secret was found in the git history (`scan --history`). Only the
 * commit id and its date: never the author's name or e-mail address, nor the
 * commit message.
 */
export const FindingHistorySchema = z
  .object({
    /** Earliest commit (by date) in which the secret was added. */
    commit: z.string(),
    /** Date of that commit (ISO 8601, as Gitleaks reports it). */
    date: z.string(),
    /**
     * True when the secret is still in the working tree: the current scan
     * reported the same rule for the same value in the same file, or the
     * file there still contains the value.
     */
    stillPresent: z.boolean(),
    /** Number of history results folded into this finding (at least 1). */
    occurrences: z.number().int().positive(),
  })
  .passthrough();
export type FindingHistory = z.infer<typeof FindingHistorySchema>;
/** One entry of a verdict's review history (see runstore `VerdictHistoryItem`). */
const ReviewHistoryItemSchema = z.object({
  reviewer: z.string(),
  role: z.string(),
  status: z.string(),
  at: z.string(),
  rationale: z.string(),
  independence: z.string().optional(),
  superseded: z.boolean().optional(),
  disagreed: z.boolean().optional(),
  replace: z.boolean().optional(),
});

export const FindingSchema = z
  .object({
    id: z.string().min(1),
    ruleId: z.string().min(1),
    title: z.string(),
    category: FindingCategorySchema,
    kind: FindingKindSchema.default("finding"),
    severity: SeveritySchema,
    confidence: ConfidenceSchema.default("medium"),
    status: FindingStatusSchema.default("candidate"),
    cwe: z.string().optional(),
    owasp: z.string().optional(),
    cvss: z.number().min(0).max(10).optional(),
    language: z.string().optional(),
    file: z.string(),
    startLine: z.number().int().positive(),
    endLine: z.number().int().positive(),
    symbol: z.string().optional(),
    evidence: z.string(),
    source: z.string().optional(),
    sink: z.string().optional(),
    dataflow: z.array(z.string()).optional(),
    exploitability: z.string().optional(),
    impact: z.string().optional(),
    message: z.string().optional(),
    remediation: z.string(),
    references: z.array(z.string()).optional(),
    provenance: ProvenanceSchema,
    fingerprint: z.string().regex(/^[a-f0-9]{64}$/),
    /** Present when the finding was suppressed by an ignore file or inline comment. */
    suppression: SuppressionSchema.optional(),
    /** Present when a baseline was used: whether this finding is new or existing. */
    baselineState: z.enum(["new", "existing"]).optional(),
    // SCA-specific fields.
    package: z.string().optional(),
    ecosystem: z.string().optional(),
    installedVersion: z.string().optional(),
    fixedVersion: z.string().optional(),
    advisoryId: z.string().optional(),
    aliases: z.array(z.string()).optional(),
    dependencyPath: z.string().optional(),
    reachable: z.enum(["yes", "no", "unknown"]).optional(),
    dependencyScope: z.enum(["runtime", "optional", "dev", "unknown"]).optional(),
    /** Path classification of `file`; absent for ordinary source. */
    pathContext: PathContextSchema.optional(),
    /**
     * The confidence the engine reported, present only when `confidence` was
     * lowered because of `pathContext`, a placeholder value or a dev-only
     * dependency. `adjustments` says why.
     */
    confidenceOriginal: ConfidenceSchema.optional(),
    /**
     * Machine-readable reasons `confidence` was lowered, in the order they
     * were applied: `path-context:<context>`, `placeholder-value`,
     * `dev-dependency`, `optional-dependency`. A reason is listed only when it
     * changed the confidence.
     */
    adjustments: z.array(z.string()).optional(),
    /**
     * The confidence the scan left, present only while a `confirmed` or
     * `likely` verdict has raised `confidence` (see `applyVerdictConfidence`
     * in report.ts).
     */
    confidenceBeforeVerdict: ConfidenceSchema.optional(),
    /**
     * The current review verdict of the run, present only on records read
     * through the run store (never trusted from findings.json: it is
     * recomputed from verdicts.json every time). Reports list who dismissed
     * a finding and why from it.
     */
    history: FindingHistorySchema.optional(),
    review: z
      .object({
        status: z.string(),
        rationale: z.string(),
        reviewer: z.string().optional(),
        actor: z.string().optional(),
        at: z.string().optional(),
        evidenceLines: z.array(z.string()).optional(),
        // Structured evidence of verdicts.json schemaVersion 2.
        trace: z
          .array(
            z.object({
              file: z.string(),
              line: z.number(),
              role: z.string(),
              note: z.string().optional(),
            }),
          )
          .optional(),
        conditions: z
          .object({
            auth: z.string().optional(),
            userInteraction: z.boolean().optional(),
            note: z.string().optional(),
          })
          .optional(),
        control: z
          .object({ file: z.string(), line: z.number(), note: z.string() })
          .optional(),
        missing: z.string().optional(),
        cwe: z.string().optional(),
        severityOverride: z
          .object({ severity: z.string(), reason: z.string() })
          .optional(),
        /** Status of the latest primary verdict (differs from `status` while a dispute is open). */
        primaryStatus: z.string().optional(),
        /** The review history, oldest first; nothing is removed. */
        history: z.array(ReviewHistoryItemSchema).optional(),
        /**
         * True when an independent reviewer whose label differs from every
         * primary label agreed with the current decision.
         */
        independentlyReviewed: z.boolean().optional(),
        independentReview: ReviewHistoryItemSchema.optional(),
        /** An independent reviewer disagreed at some point. */
        disputed: z.boolean().optional(),
        dissent: ReviewHistoryItemSchema.optional(),
        disputeOpen: z.boolean().optional(),
        /** Set when a person decided (CLI `--role human`); it settles any dispute. */
        decidedByPerson: z.object({ reviewer: z.string(), at: z.string() }).optional(),
      })
      .optional(),
  })
  .passthrough();

export type Finding = z.infer<typeof FindingSchema>;

export interface FindingInit {
  ruleId: string;
  title: string;
  category: FindingCategory;
  severity: Severity;
  kind?: FindingKind;
  file: string;
  startLine: number;
  endLine?: number;
  evidence: string;
  remediation: string;
  language?: string;
  cwe?: string;
  owasp?: string;
  cvss?: number;
  confidence?: Confidence;
  status?: FindingStatus;
  symbol?: string;
  source?: string;
  sink?: string;
  dataflow?: string[];
  exploitability?: string;
  impact?: string;
  message?: string;
  references?: string[];
  provenance: { engine: string; rule?: string; version?: string; engines?: string[] };
  package?: string;
  ecosystem?: string;
  installedVersion?: string;
  fixedVersion?: string;
  advisoryId?: string;
  aliases?: string[];
  dependencyPath?: string;
  reachable?: "yes" | "no" | "unknown";
  dependencyScope?: "runtime" | "optional" | "dev" | "unknown";
  pathContext?: PathContext;
  confidenceOriginal?: Confidence;
  adjustments?: string[];
  history?: FindingHistory;
}

/**
 * Fingerprint = sha256(ruleId + relative path + whitespace-free evidence).
 * Line numbers are intentionally absent, so moving code does not create a new
 * finding.
 *
 * Evidence is redacted before it gets here, and the mask depends only on the
 * length of a secret (plus its first and last 2 characters when it is 16
 * characters or longer). Consequences, both intended:
 * - two different secrets of the same length assigned to the same name have
 *   the same base fingerprint; `disambiguateFingerprints` keeps them apart by
 *   occurrence;
 * - a rotated secret of the same length keeps its fingerprint, so a baseline
 *   or ignore entry for the old value also covers the new one.
 */
export function computeFingerprint(
  ruleId: string,
  relativePath: string,
  evidence: string,
): string {
  const normalized = evidence.replace(/\s+/g, "");
  return crypto
    .createHash("sha256")
    .update(`${ruleId}\n${relativePath.split("\\").join("/")}\n${normalized}`)
    .digest("hex");
}

export const ADJUSTMENT_PLACEHOLDER = "placeholder-value";
export const ADJUSTMENT_DEV_DEPENDENCY = "dev-dependency";
export const ADJUSTMENT_OPTIONAL_DEPENDENCY = "optional-dependency";
export const ADJUSTMENT_PATH_CONTEXT_PREFIX = "path-context:";

/**
 * Lower the confidence of a finding and record why. `to` is either one step
 * down (high -> medium -> low) or straight to low. When the confidence does not
 * change (it is already low) the finding is returned as is: an adjustment is
 * recorded only when it had an effect. The finding is never dropped.
 */
export function lowerConfidence<T extends { confidence: Confidence; confidenceOriginal?: Confidence; adjustments?: string[] }>(
  finding: T,
  reason: string,
  to: "step" | "low",
): T {
  const lowered: Confidence =
    to === "low" || finding.confidence === "medium" ? "low" : finding.confidence === "high" ? "medium" : "low";
  if (lowered === finding.confidence) return finding;
  return {
    ...finding,
    confidence: lowered,
    confidenceOriginal: finding.confidenceOriginal ?? finding.confidence,
    adjustments: [...(finding.adjustments ?? []), reason],
  };
}

/** Undo every confidence adjustment of a finding. */
export function restoreConfidence<T extends { confidence: Confidence; confidenceOriginal?: Confidence; adjustments?: string[] }>(
  finding: T,
): T {
  if (finding.confidenceOriginal === undefined && finding.adjustments === undefined) return finding;
  const { confidenceOriginal, adjustments: _adjustments, ...rest } = finding;
  return { ...(rest as unknown as T), confidence: confidenceOriginal ?? finding.confidence };
}

let tempCounter = 0;

export function createFinding(init: FindingInit): Finding {
  tempCounter += 1;
  const fingerprint = computeFingerprint(
    init.ruleId,
    init.file,
    init.evidence,
  );
  const candidate = {
    id: `TMP-${process.pid}-${tempCounter}`,
    ...init,
    endLine: init.endLine ?? init.startLine,
    confidence: init.confidence ?? "medium",
    status: init.status ?? "candidate",
    kind: init.kind ?? "finding",
    fingerprint,
  };
  return FindingSchema.parse(candidate);
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const severity = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
    if (severity !== 0) return severity;
    const confidence =
      CONFIDENCE_ORDER[b.confidence] - CONFIDENCE_ORDER[a.confidence];
    if (confidence !== 0) return confidence;
    if (a.file !== b.file) return a.file.localeCompare(b.file);
    if (a.startLine !== b.startLine) return a.startLine - b.startLine;
    return a.ruleId.localeCompare(b.ruleId);
  });
}

/**
 * Give repeated occurrences of the same weakness in one file distinct
 * fingerprints.
 *
 * The base fingerprint is line-independent (rule + file + evidence), so two
 * identical vulnerable lines in one file share it and the second would be
 * dropped by `dedupeFindings`. Occurrences are ordered by line; the first keeps
 * the base fingerprint (so existing baselines and ignore files stay valid) and
 * the n-th gets `sha256(base + "#" + n)`. Counting occurrences instead of using
 * line numbers keeps fingerprints stable when unrelated code moves.
 *
 * Entries with the same fingerprint AND the same start line are true
 * duplicates and are left alone for `dedupeFindings` to collapse.
 */
export function disambiguateFingerprints(findings: Finding[]): Finding[] {
  const groups = new Map<string, Finding[]>();
  for (const finding of findings) {
    const group = groups.get(finding.fingerprint);
    if (group) group.push(finding);
    else groups.set(finding.fingerprint, [finding]);
  }
  const replacement = new Map<Finding, string>();
  for (const [base, group] of groups) {
    if (group.length < 2) continue;
    const lines = [...new Set(group.map((finding) => finding.startLine))].sort(
      (left, right) => left - right,
    );
    if (lines.length < 2) continue;
    for (const finding of group) {
      const occurrence = lines.indexOf(finding.startLine);
      if (occurrence === 0) continue;
      replacement.set(
        finding,
        crypto.createHash("sha256").update(`${base}#${occurrence + 1}`).digest("hex"),
      );
    }
  }
  if (replacement.size === 0) return findings;
  return findings.map((finding) => {
    const fingerprint = replacement.get(finding);
    return fingerprint ? { ...finding, fingerprint } : finding;
  });
}

/** Deduplicate by fingerprint; first occurrence wins. */
export function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const result: Finding[] = [];
  for (const finding of findings) {
    if (seen.has(finding.fingerprint)) continue;
    seen.add(finding.fingerprint);
    result.push(finding);
  }
  return result;
}

export function assignFindingIds(
  findings: Finding[],
  year = new Date().getUTCFullYear(),
): Finding[] {
  return findings.map((finding, index) => ({
    ...finding,
    id: `AUD-${year}-${String(index + 1).padStart(4, "0")}`,
  }));
}

export function assignHotspotIds(
  hotspots: Finding[],
  year = new Date().getUTCFullYear(),
): Finding[] {
  return hotspots.map((hotspot, index) => ({
    ...hotspot,
    id: `HOT-${year}-${String(index + 1).padStart(4, "0")}`,
  }));
}

export function severityAtLeast(
  actual: Severity,
  threshold: Severity,
): boolean {
  return SEVERITY_ORDER[actual] >= SEVERITY_ORDER[threshold];
}

export function confidenceAtLeast(
  actual: Confidence,
  threshold: Confidence,
): boolean {
  return CONFIDENCE_ORDER[actual] >= CONFIDENCE_ORDER[threshold];
}

export function isActionable(finding: Finding): boolean {
  return finding.status !== "false_positive" && finding.status !== "suppressed";
}
