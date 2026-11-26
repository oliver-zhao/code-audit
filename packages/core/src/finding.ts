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
}

/**
 * Fingerprint = sha256(ruleId + relative path + whitespace-free evidence).
 * Line numbers are intentionally absent, so moving code does not create a new
 * finding.
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
