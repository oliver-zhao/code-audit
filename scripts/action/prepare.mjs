#!/usr/bin/env node
// Runs inside the code-audit GitHub Action after the scan (pure Node, no
// dependencies). Reads the findings.json of the run and
//
//   1. writes the step outputs findings-count, new-findings-count (and the
//      exit code is passed through by the caller) to $GITHUB_OUTPUT;
//   2. writes comment-data.json: the data the separate, privileged comment
//      workflow turns into pull request comments (scripts/action/comment.mjs).
//
// Usage: node prepare.mjs <findings.json> <comment-data.json>
//
// Everything below is built from the scanner's own output, but the comment
// workflow must still treat comment-data.json as untrusted: a pull request
// from a fork can change the workflow that produces it.
import fs from "node:fs";
import { pathToFileURL } from "node:url";

export const COMMENT_DATA_SCHEMA_VERSION = 1;
/** At most this many findings are carried to the comment workflow. */
export const MAX_COMMENT_FINDINGS = 200;

const CONFIDENCE_RANK = { low: 0, medium: 1, high: 2 };
const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

function clip(value, max) {
  return typeof value === "string" ? value.slice(0, max) : undefined;
}

/**
 * The findings that count: active (not suppressed, not dismissed), at
 * confidence >= the run's min-confidence and, when a baseline is used, new.
 */
export function countedFindings(document) {
  const run = document.run ?? {};
  const minConfidence = CONFIDENCE_RANK[run.minConfidence] ?? 1;
  const baselineUsed = run.baselineUsed === true;
  return (Array.isArray(document.findings) ? document.findings : []).filter(
    (finding) =>
      finding &&
      finding.status !== "suppressed" &&
      finding.status !== "false_positive" &&
      (CONFIDENCE_RANK[finding.confidence] ?? 0) >= minConfidence &&
      (!baselineUsed || finding.baselineState !== "existing"),
  );
}

export function buildCommentData(document, context) {
  const run = document.run ?? {};
  const summary = run.summary ?? {};
  const counted = countedFindings(document).sort(
    (a, b) =>
      (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0) ||
      String(a.file).localeCompare(String(b.file)) ||
      (a.startLine ?? 0) - (b.startLine ?? 0),
  );
  const headline = summary.headline?.total ?? counted.length;
  return {
    schemaVersion: COMMENT_DATA_SCHEMA_VERSION,
    tool: "code-audit",
    toolVersion: clip(run.tool?.version, 40) ?? "",
    pullRequest: context.pullRequest,
    headSha: context.headSha,
    baseSha: context.baseSha,
    mode: context.mode,
    summary: {
      findings: headline,
      newFindings: run.baseline ? run.baseline.new : headline,
      hotspots: typeof run.hotspotCount === "number" ? run.hotspotCount : 0,
      failOn: run.failOn ?? "high",
      minConfidence: run.minConfidence ?? "medium",
      exitCode: context.exitCode,
      truncated: counted.length > MAX_COMMENT_FINDINGS,
    },
    findings: counted.slice(0, MAX_COMMENT_FINDINGS).map((finding) => ({
      fingerprint: finding.fingerprint,
      ruleId: finding.ruleId,
      severity: finding.severity,
      confidence: finding.confidence,
      title: clip(finding.title, 200) ?? "",
      file: clip(finding.file, 500) ?? "",
      startLine: finding.startLine,
      endLine: finding.endLine,
      ...(finding.cwe ? { cwe: clip(finding.cwe, 20) } : {}),
      ...(finding.evidence ? { evidence: clip(finding.evidence, 500) } : {}),
    })),
  };
}

function writeOutputs(values) {
  const file = process.env.GITHUB_OUTPUT;
  const text = Object.entries(values)
    .map(([key, value]) => `${key}=${String(value).replace(/[\r\n]/g, " ")}\n`)
    .join("");
  if (file) fs.appendFileSync(file, text);
  else process.stdout.write(text);
}

function main() {
  const [findingsPath, outPath] = process.argv.slice(2);
  if (!findingsPath || !outPath) {
    process.stderr.write("usage: prepare.mjs <findings.json> <comment-data.json>\n");
    process.exit(2);
  }
  const document = JSON.parse(fs.readFileSync(findingsPath, "utf8"));
  const pr = Number.parseInt(process.env.CODE_AUDIT_PR_NUMBER ?? "", 10);
  const data = buildCommentData(document, {
    pullRequest: Number.isSafeInteger(pr) && pr > 0 ? pr : null,
    headSha: process.env.CODE_AUDIT_HEAD_SHA ?? "",
    baseSha: process.env.CODE_AUDIT_BASE_SHA ?? "",
    mode: process.env.CODE_AUDIT_MODE === "diff" ? "diff" : "full",
    exitCode: Number.parseInt(process.env.CODE_AUDIT_EXIT_CODE ?? "0", 10) || 0,
  });
  fs.writeFileSync(outPath, `${JSON.stringify(data, null, 2)}\n`);
  writeOutputs({
    "findings-count": data.summary.findings,
    "new-findings-count": data.summary.newFindings,
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(fs.realpathSync(process.argv[1])).href) {
  main();
}
