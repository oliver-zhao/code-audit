import {
  ADJUSTMENT_PLACEHOLDER,
  CONFIDENCE_ORDER,
  SEVERITY_ORDER,
  lowerConfidence,
  restoreConfidence,
  type Finding,
} from "../finding.js";
import { scaRemediation } from "../sca.js";
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

/** Rule ids behind a finding: `provenance.rules` after a merge, else its own. */
function rulesOf(finding: Finding): string[] {
  const rules = (finding.provenance as { rules?: unknown }).rules;
  if (Array.isArray(rules) && rules.length > 0) {
    return rules.filter((rule): rule is string => typeof rule === "string");
  }
  return [finding.provenance.rule ?? finding.ruleId];
}

function isPlaceholderAdjusted(finding: Finding): boolean {
  return finding.adjustments?.includes(ADJUSTMENT_PLACEHOLDER) ?? false;
}

function mergePair(first: Finding, second: Finding): Finding {
  // A placeholder verdict survives a merge only when both engines reached it:
  // two findings on one line can be about two different values. The merge
  // works on the confidences the engines reported and the adjustment is
  // applied again to the result.
  const bothPlaceholder = isPlaceholderAdjusted(first) && isPlaceholderAdjusted(second);
  const a = restoreConfidence(first);
  const b = restoreConfidence(second);
  const merged = mergePairUnadjusted(a, b);
  return bothPlaceholder ? lowerConfidence(merged, ADJUSTMENT_PLACEHOLDER, "low") : merged;
}

function mergePairUnadjusted(a: Finding, b: Finding): Finding {
  const bySeverity = higherSeverity(a, b);
  const primary = higherConfidence(bySeverity, bySeverity === a ? b : a);
  const engines = mergeEngines(a, b);
  const rules = [...new Set([...rulesOf(a), ...rulesOf(b)])];
  return {
    ...primary,
    severity: bySeverity.severity,
    confidence: higherConfidence(a, b).confidence,
    provenance: {
      ...primary.provenance,
      engines,
      // Only recorded when several rules were folded into this finding.
      ...(rules.length > 1 ? { rules } : {}),
    },
  };
}

/**
 * External SAST engines whose own results are collapsed when two of their
 * rules flag the same code for the same weakness (for example a pattern rule
 * and a taint rule both reporting `eval` on one line). Built-in rule hits are
 * deduplicated by the rule engine itself, and secret findings are never
 * collapsed this way: two different secrets on one line are two findings.
 */
const SAME_ENGINE_COLLAPSE = new Set(["opengrep", "semgrep"]);

function collapsibleWithinEngine(a: Finding, b: Finding, engines: string[]): boolean {
  return (
    a.category === "sast" &&
    b.category === "sast" &&
    a.ruleId !== b.ruleId &&
    engines.every((engine) => SAME_ENGINE_COLLAPSE.has(engine))
  );
}

/**
 * Cross-engine dedupe for SAST and secrets findings.
 *
 * Two findings are merged when they are in the same file, their line ranges
 * overlap, they share a CWE, and they come from different engines. Two
 * results of the same external SAST engine that meet the same conditions but
 * come from different rules are merged too. The merged finding keeps the
 * highest severity and confidence, lists every engine in `provenance.engines`
 * and, when more than one rule contributed, every rule id in
 * `provenance.rules`.
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
      if (
        existingEngines.every((engine) => findingEngines.includes(engine)) &&
        !collapsibleWithinEngine(existing, finding, findingEngines)
      ) {
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

function scaIdentity(finding: Finding): { scope: string; ids: string[] } {
  // The file is part of the identity: the same vulnerable release pinned in
  // two lockfiles is two findings, one per file that has to be changed.
  const scope = `${finding.file}\u0000${scaDedupeKey({
    ecosystem: finding.ecosystem,
    package: finding.package,
    installedVersion: finding.installedVersion,
    advisoryId: "",
  })}`;
  const ids = [finding.advisoryId, ...(finding.aliases ?? [])]
    .filter((id): id is string => typeof id === "string" && id.length > 0)
    .map((id) => id.toUpperCase());
  // A finding without any advisory id is only ever equal to itself.
  return { scope, ids: ids.length > 0 ? ids : [`RULE:${finding.ruleId}`] };
}

function preferredAdvisoryRank(id: string | undefined): number {
  if (!id) return 0;
  if (/^GHSA-/i.test(id)) return 3;
  if (/^CVE-/i.test(id)) return 2;
  return 1;
}

/**
 * Merge SCA findings from the built-in OSV query and an external scanner.
 *
 * Two findings are the same vulnerability when they are for the same
 * (file, ecosystem, normalized name, version) and their advisory id / alias sets
 * intersect, so a group reported as GHSA-y by one engine merges with the
 * PYSEC-x (alias GHSA-y) reported by the other. The merged finding keeps the
 * highest severity and confidence, the union of aliases, the preferred
 * advisory id (GHSA, then CVE) and lists every engine.
 */
export function mergeScaFindings(
  primary: Finding[],
  secondary: Finding[],
): Finding[] {
  const result: Array<Finding | undefined> = [];
  const index = new Map<string, number>();

  const add = (finding: Finding): void => {
    const { scope, ids } = scaIdentity(finding);
    const keys = ids.map((id) => `${scope}${id}`);
    const hits = [
      ...new Set(
        keys
          .map((key) => index.get(key))
          .filter((slot): slot is number => slot !== undefined),
      ),
    ].sort((a, b) => a - b);
    const target = hits[0];
    if (target === undefined) {
      for (const key of keys) index.set(key, result.length);
      result.push(finding);
      return;
    }
    // The new finding can bridge several earlier ones; fold them all in.
    let merged = result[target] as Finding;
    for (const slot of hits.slice(1)) {
      const other = result[slot];
      if (!other) continue;
      merged = mergeScaPair(merged, other);
      result[slot] = undefined;
    }
    merged = mergeScaPair(merged, finding);
    result[target] = merged;
    for (const id of scaIdentity(merged).ids) index.set(`${scope}${id}`, target);
  };

  for (const finding of primary) add(finding);
  for (const finding of secondary) add(finding);
  return result.filter((finding): finding is Finding => finding !== undefined);
}

function mergeScaPair(existing: Finding, finding: Finding): Finding {
  const bySeverity = higherSeverity(existing, finding);
  let base = higherConfidence(bySeverity, bySeverity === existing ? finding : existing);
  let other = base === existing ? finding : existing;
  // Prefer the finding named after the GHSA (then CVE) id, so rule id,
  // fingerprint and advisory id stay consistent with each other.
  if (preferredAdvisoryRank(other.advisoryId) > preferredAdvisoryRank(base.advisoryId)) {
    [base, other] = [other, base];
  }
  // Keep the location from the finding that knows where the package is declared.
  if (base.startLine <= 1 && other.startLine > 1) {
    base = { ...base, startLine: other.startLine, endLine: other.endLine };
  }
  const advisoryId = base.advisoryId ?? other.advisoryId;
  const aliases = [
    ...new Set(
      [
        existing.advisoryId,
        finding.advisoryId,
        ...(existing.aliases ?? []),
        ...(finding.aliases ?? []),
      ].filter((id): id is string => typeof id === "string" && id.length > 0),
    ),
  ].filter((id) => id !== advisoryId);
  // The fixed version and the remediation text must name the same release:
  // both come from `base`, or, when only the other finding knows a fix, the
  // text is rebuilt for that version.
  const fixedVersion = base.fixedVersion ?? other.fixedVersion;
  const cvss =
    existing.cvss !== undefined && finding.cvss !== undefined
      ? Math.max(existing.cvss, finding.cvss)
      : existing.cvss ?? finding.cvss;
  const merged: Finding = {
    ...base,
    severity: bySeverity.severity,
    confidence: higherConfidence(existing, finding).confidence,
    aliases,
    provenance: {
      ...base.provenance,
      engines: mergeEngines(existing, finding),
    },
  };
  if (advisoryId !== undefined) merged.advisoryId = advisoryId;
  if (fixedVersion !== undefined) {
    merged.fixedVersion = fixedVersion;
    if (base.fixedVersion === undefined) {
      merged.remediation = scaRemediation(base.package ?? other.package ?? "", fixedVersion);
    }
  }
  if (cvss !== undefined) merged.cvss = cvss;
  return merged;
}
