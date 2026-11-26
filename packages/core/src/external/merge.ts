import {
  CONFIDENCE_ORDER,
  SEVERITY_ORDER,
  type Finding,
} from "../finding.js";
import { scaDedupeKey } from "./osvScanner.js";

function enginesOf(finding: Finding): string[] {
  const provenance = finding.provenance;
  if (Array.isArray(provenance.engines) && provenance.engines.length > 0) {
    return [...new Set([provenance.engine, ...provenance.engines])];
  }
  return [provenance.engine];
}

function mergeEngines(a: Finding, b: Finding): string[] {
  return [...new Set([...enginesOf(a), ...enginesOf(b)])];
}

function higherSeverity(a: Finding, b: Finding): Finding {
  return SEVERITY_ORDER[b.severity] > SEVERITY_ORDER[a.severity] ? b : a;
}

function higherConfidence(a: Finding, b: Finding): Finding {
  return CONFIDENCE_ORDER[b.confidence] > CONFIDENCE_ORDER[a.confidence] ? b : a;
}

function sameCwe(a: Finding, b: Finding): boolean {
  if (!a.cwe || !b.cwe) return false;
  return a.cwe.toUpperCase() === b.cwe.toUpperCase();
}

function rangesOverlap(a: Finding, b: Finding): boolean {
  return a.startLine <= b.endLine && b.startLine <= a.endLine;
}

function mergePair(a: Finding, b: Finding): Finding {
  const bySeverity = higherSeverity(a, b);
  const primary = higherConfidence(bySeverity, bySeverity === a ? b : a);
  const engines = mergeEngines(a, b);
  return {
    ...primary,
    severity: bySeverity.severity,
    confidence: higherConfidence(a, b).confidence,
    provenance: { ...primary.provenance, engines },
  };
}

/**
 * Cross-engine dedupe for SAST and secrets findings.
 *
 * Two findings are merged when they are in the same file, their line ranges
 * overlap, they share a CWE, and they come from different engines. The merged
 * finding keeps the highest severity and confidence and lists every engine in
 * `provenance.engines`.
 */
export function crossEngineDedupe(findings: Finding[]): Finding[] {
  const kept: Finding[] = [];
  for (const finding of findings) {
    let merged = false;
    for (let index = 0; index < kept.length; index += 1) {
      const existing = kept[index];
      if (!existing) continue;
      if (existing.file !== finding.file) continue;
      if (!sameCwe(existing, finding)) continue;
      if (!rangesOverlap(existing, finding)) continue;
      const existingEngines = enginesOf(existing);
      const findingEngines = enginesOf(finding);
      if (existingEngines.every((engine) => findingEngines.includes(engine))) {
        continue;
      }
      kept[index] = mergePair(existing, finding);
      merged = true;
      break;
    }
    if (!merged) kept.push(finding);
  }
  return kept;
}

/**
 * Merge SCA findings from the built-in OSV query and an external scanner.
 * Findings are deduped by (ecosystem, normalized name, version, advisory id or
 * alias); duplicates keep the highest severity and list both engines.
 */
export function mergeScaFindings(
  primary: Finding[],
  secondary: Finding[],
): Finding[] {
  const result: Finding[] = [];
  const index = new Map<string, number>();

  const add = (finding: Finding): void => {
    const key = scaDedupeKey(finding);
    const existingIndex = index.get(key);
    if (existingIndex === undefined) {
      index.set(key, result.length);
      result.push(finding);
      return;
    }
    const existing = result[existingIndex];
    if (!existing) return;
    const bySeverity = higherSeverity(existing, finding);
    const primaryFinding = higherConfidence(bySeverity, bySeverity === existing ? finding : existing);
    const aliases = [
      ...new Set([...(existing.aliases ?? []), ...(finding.aliases ?? [])]),
    ];
    const fixedVersion =
      existing.fixedVersion && finding.fixedVersion
        ? existing.fixedVersion
        : existing.fixedVersion ?? finding.fixedVersion;
    result[existingIndex] = {
      ...primaryFinding,
      severity: bySeverity.severity,
      confidence: higherConfidence(existing, finding).confidence,
      aliases,
      fixedVersion,
      provenance: {
        ...primaryFinding.provenance,
        engines: mergeEngines(existing, finding),
      },
    };
  };

  for (const finding of primary) add(finding);
  for (const finding of secondary) add(finding);
  return result;
}