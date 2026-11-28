#!/usr/bin/env node
// Posts code-audit results to a pull request (pure Node, no dependencies).
//
// Runs in the privileged second stage (a `workflow_run` workflow with
// `pull-requests: write`) and never checks out or runs pull request code.
// Its only input besides GitHub's own event payload is comment-data.json from
// the artifact of the first stage - and a pull request from a fork can change
// the workflow that produced it, so EVERY value in it is untrusted:
//
// - the file is size-capped and validated field by field (schema below); any
//   error rejects the whole file;
// - the pull request number in it must be the one GitHub associates with the
//   triggering run (workflow_run.pull_requests, or for a fork - where that
//   list is empty - the open pull request whose head is the run's head
//   repository, branch and commit); the head commit must match too;
// - comment bodies are a fixed template; text that comes from the file
//   (titles, file names, evidence) is shown only inside code spans or fenced
//   code blocks, with backticks replaced and `@` mentions broken, so it
//   cannot add Markdown, links, HTML or notifications;
// - at most MAX_INLINE inline comments, each marked with a hidden
//   `<!-- code-audit:<fingerprint> -->` so a later run updates instead of
//   adding; the rest goes into one summary comment, also updated in place.
//   Only comments written by the workflow's own account are updated.
//
// Usage: node comment.mjs <comment-data.json>
// Environment: GITHUB_REPOSITORY, GITHUB_EVENT_PATH (workflow_run payload),
// GH_TOKEN (for gh), optional CODE_AUDIT_COMMENT_AUTHOR (default
// github-actions[bot]), CODE_AUDIT_MAX_INLINE (default 20, at most 50).
import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

export const MAX_DATA_BYTES = 2 * 1024 * 1024;
export const MAX_FINDINGS = 200;
export const DEFAULT_MAX_INLINE = 20;
export const MAX_SUMMARY_ITEMS = 50;
export const SUMMARY_MARKER = "<!-- code-audit:summary -->";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const CONFIDENCES = ["high", "medium", "low"];
const SHA = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const FINGERPRINT = /^[0-9a-f]{64}$/;
const RULE_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,150}$/;
const CWE = /^CWE-[0-9]{1,6}$/;
const TOOL_VERSION = /^[0-9A-Za-z.+-]{1,40}$/;
const REPOSITORY = /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/;

export function marker(fingerprint) {
  if (!FINGERPRINT.test(fingerprint)) throw new Error("invalid fingerprint");
  return `<!-- code-audit:${fingerprint} -->`;
}

// ---------------------------------------------------------------------------
// Escaping

/** Control, zero-width and bidirectional characters, except \n and \t. */
// eslint-disable-next-line no-control-regex
const INVISIBLE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f­؜᠎​-‏‪-‮⁠-⁩﻿]/g;

function neutralize(text) {
  return (
    String(text)
      .replace(/\r\n?/g, "\n")
      .replace(INVISIBLE, "")
      // A backtick could close the code span or fence: use a look-alike.
      .replace(/`/g, "ˋ")
      // `@name` must never notify anyone: break it with a zero-width space.
      .replace(/@/g, "@​")
  );
}

function cap(text, max) {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

/** Untrusted text as one inline code span. */
export function codeSpan(text, max = 200) {
  const value = cap(neutralize(text).replace(/[\n\t]+/g, " ").trim(), max);
  return `\`${value === "" ? " " : value}\``;
}

/** Untrusted text as a fenced code block. */
export function codeBlock(text, max = 500) {
  const lines = cap(neutralize(text), max).split("\n").slice(0, 20);
  return ["```text", ...lines, "```"].join("\n");
}

// ---------------------------------------------------------------------------
// Validation of comment-data.json

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isLine(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 10_000_000;
}

function isCount(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 100_000_000;
}

function shortString(value, max) {
  return typeof value === "string" && value.length <= max;
}

/** Validate the parsed file. Returns the list of problems (empty: valid). */
export function validateCommentData(data) {
  const errors = [];
  const check = (ok, message) => {
    if (!ok) errors.push(message);
  };
  if (!isRecord(data)) return ["the document is not an object"];
  check(data.schemaVersion === 1, "schemaVersion must be 1");
  check(data.tool === "code-audit", "tool must be code-audit");
  check(data.toolVersion === undefined || shortString(data.toolVersion, 40), "toolVersion is invalid");
  check(Number.isSafeInteger(data.pullRequest) && data.pullRequest > 0, "pullRequest must be a positive integer");
  check(typeof data.headSha === "string" && SHA.test(data.headSha), "headSha must be a full commit id");
  check(data.baseSha === "" || (typeof data.baseSha === "string" && SHA.test(data.baseSha)), "baseSha must be a full commit id");
  check(data.mode === "diff" || data.mode === "full", "mode must be diff or full");
  const summary = data.summary;
  if (!isRecord(summary)) {
    errors.push("summary must be an object");
  } else {
    check(isCount(summary.findings), "summary.findings must be a count");
    check(isCount(summary.newFindings), "summary.newFindings must be a count");
    check(isCount(summary.hotspots), "summary.hotspots must be a count");
    check(SEVERITIES.includes(summary.failOn), "summary.failOn is invalid");
    check(CONFIDENCES.includes(summary.minConfidence), "summary.minConfidence is invalid");
    check(Number.isSafeInteger(summary.exitCode) && summary.exitCode >= 0 && summary.exitCode <= 255, "summary.exitCode is invalid");
    check(typeof summary.truncated === "boolean", "summary.truncated must be a boolean");
  }
  if (!Array.isArray(data.findings)) {
    errors.push("findings must be an array");
  } else {
    check(data.findings.length <= MAX_FINDINGS, `findings has more than ${MAX_FINDINGS} entries`);
    const seen = new Set();
    data.findings.slice(0, MAX_FINDINGS).forEach((finding, index) => {
      const at = `findings[${index}]`;
      if (!isRecord(finding)) {
        errors.push(`${at} is not an object`);
        return;
      }
      check(typeof finding.fingerprint === "string" && FINGERPRINT.test(finding.fingerprint), `${at}.fingerprint is invalid`);
      check(!seen.has(finding.fingerprint), `${at}.fingerprint is a duplicate`);
      seen.add(finding.fingerprint);
      check(typeof finding.ruleId === "string" && RULE_ID.test(finding.ruleId), `${at}.ruleId is invalid`);
      check(SEVERITIES.includes(finding.severity), `${at}.severity is invalid`);
      check(CONFIDENCES.includes(finding.confidence), `${at}.confidence is invalid`);
      check(shortString(finding.title, 200), `${at}.title is invalid`);
      check(shortString(finding.file, 500) && finding.file.length > 0, `${at}.file is invalid`);
      check(isLine(finding.startLine) && isLine(finding.endLine) && finding.endLine >= finding.startLine, `${at} line range is invalid`);
      check(finding.cwe === undefined || (typeof finding.cwe === "string" && CWE.test(finding.cwe)), `${at}.cwe is invalid`);
      check(finding.evidence === undefined || shortString(finding.evidence, 500), `${at}.evidence is invalid`);
    });
  }
  return errors;
}

/** Read and validate comment-data.json; throws with every problem. */
export function loadCommentData(file) {
  const stat = fs.lstatSync(file);
  if (!stat.isFile()) throw new Error(`${file} is not a regular file`);
  if (stat.size > MAX_DATA_BYTES) throw new Error(`${file} is larger than ${MAX_DATA_BYTES} bytes`);
  let data;
  try {
    data = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (error) {
    throw new Error(`comment data is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  const errors = validateCommentData(data);
  if (errors.length > 0) {
    throw new Error(`comment data rejected:\n- ${errors.slice(0, 20).join("\n- ")}`);
  }
  return data;
}

// ---------------------------------------------------------------------------
// Comment bodies (fixed templates)

const SEVERITY_LABEL = { critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW", info: "INFO" };

function footer(data) {
  const version = typeof data.toolVersion === "string" && TOOL_VERSION.test(data.toolVersion) ? ` ${data.toolVersion}` : "";
  return `<sub>Reported by code-audit${version}. Text taken from the repository is shown as code.</sub>`;
}

export function renderInlineBody(finding, data) {
  const parts = [
    marker(finding.fingerprint),
    `**code-audit: ${SEVERITY_LABEL[finding.severity]}** (confidence ${finding.confidence}) ${codeSpan(finding.ruleId, 160)}${finding.cwe ? ` ${finding.cwe}` : ""}`,
    "",
    codeSpan(finding.title, 200),
  ];
  if (finding.evidence) parts.push("", codeBlock(finding.evidence, 500));
  parts.push("", footer(data));
  return parts.join("\n");
}

function location(finding) {
  return finding.startLine > 0 ? `${finding.file}:${finding.startLine}` : finding.file;
}

export function renderSummaryBody(data, rest, inlined) {
  const s = data.summary;
  const lines = [
    SUMMARY_MARKER,
    "### code-audit",
    "",
    `- Findings at confidence >= ${s.minConfidence}: **${s.findings}** (new: **${s.newFindings}**), review hotspots: ${s.hotspots}`,
    `- Mode: ${data.mode === "diff" ? "changed lines of this pull request" : "full scan"}; fails on ${s.failOn} and above; scan exit code ${s.exitCode}`,
    `- Inline comments on changed lines: ${inlined}`,
  ];
  if (rest.length > 0) {
    lines.push("", "Other findings (not on a line of this pull request's diff, or over the inline limit):", "");
    for (const finding of rest.slice(0, MAX_SUMMARY_ITEMS)) {
      lines.push(
        `- **${SEVERITY_LABEL[finding.severity]}** ${codeSpan(finding.ruleId, 160)} in ${codeSpan(location(finding), 300)}: ${codeSpan(finding.title, 200)}`,
      );
    }
    if (rest.length > MAX_SUMMARY_ITEMS) {
      lines.push(`- ... and ${rest.length - MAX_SUMMARY_ITEMS} more (see the SARIF results or the artifact)`);
    }
  }
  if (s.truncated) lines.push("", "The result list was truncated; the artifact of the scan has all of it.");
  if (s.findings === 0 && rest.length === 0 && inlined === 0) {
    lines.push("", "No finding reached the reporting threshold. This is not a guarantee of safety.");
  }
  lines.push("", footer(data));
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Pull request diff

/** Line numbers of the new file that a review comment can be placed on. */
export function rightSideLines(patch) {
  const lines = new Set();
  if (typeof patch !== "string") return lines;
  let line = 0;
  let inHunk = false;
  for (const text of patch.split("\n")) {
    const header = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(text);
    if (header) {
      line = Number.parseInt(header[1], 10);
      inHunk = true;
      continue;
    }
    if (!inHunk) continue;
    if (text.startsWith("+") || text.startsWith(" ")) {
      lines.add(line);
      line += 1;
    } else if (text.startsWith("-") || text.startsWith("\\")) {
      // removed line or "\ No newline at end of file"
    } else if (text === "") {
      // trailing newline of the patch
    }
  }
  return lines;
}

// ---------------------------------------------------------------------------
// GitHub API through the gh CLI

export function makeGh(options = {}) {
  const command = options.command ?? "gh";
  return (method, endpoint, body) => {
    const args = ["api", "--method", method, "-H", "Accept: application/vnd.github+json", endpoint];
    if (body !== undefined) args.push("--input", "-");
    const result = spawnSync(command, args, {
      encoding: "utf8",
      input: body === undefined ? "" : JSON.stringify(body),
      maxBuffer: 64 * 1024 * 1024,
      timeout: 60_000,
      shell: false,
    });
    if (result.error) throw new Error(`gh ${method} ${endpoint}: ${result.error.message}`);
    if (result.status !== 0) {
      throw new Error(`gh ${method} ${endpoint} failed: ${(result.stderr || result.stdout || "").trim().slice(0, 300)}`);
    }
    const text = result.stdout.trim();
    return text === "" ? null : JSON.parse(text);
  };
}

function paginate(gh, endpoint, maxPages = 30) {
  const all = [];
  for (let page = 1; page <= maxPages; page += 1) {
    const separator = endpoint.includes("?") ? "&" : "?";
    const items = gh("GET", `${endpoint}${separator}per_page=100&page=${page}`);
    if (!Array.isArray(items)) break;
    all.push(...items);
    if (items.length < 100) break;
  }
  return all;
}

/**
 * The pull request GitHub associates with the triggering run - never the
 * number from the artifact alone.
 */
export function trustedPullRequest(event, repo, gh) {
  const run = event?.workflow_run;
  if (!isRecord(run)) throw new Error("not a workflow_run event");
  if (run.event !== "pull_request") throw new Error(`the triggering run was started by ${String(run.event)}, not pull_request`);
  const headSha = typeof run.head_sha === "string" ? run.head_sha : "";
  if (!SHA.test(headSha)) throw new Error("the triggering run has no head commit");
  const listed = Array.isArray(run.pull_requests)
    ? run.pull_requests
        .filter((pr) => isRecord(pr) && Number.isSafeInteger(pr.number))
        .filter((pr) => !isRecord(pr.head) || pr.head.sha === undefined || pr.head.sha === headSha)
        .map((pr) => pr.number)
    : [];
  if (listed.length > 0) return { numbers: listed, headSha };
  // A pull request from a fork: GitHub leaves pull_requests empty. Find the
  // open pull request whose head is the run's head repository, branch and commit.
  const owner = run.head_repository?.owner?.login;
  const branch = run.head_branch;
  if (typeof owner !== "string" || typeof branch !== "string" || owner === "" || branch === "") {
    throw new Error("the triggering run names no head repository or branch");
  }
  const candidates = paginate(
    gh,
    `repos/${repo}/pulls?state=open&head=${encodeURIComponent(`${owner}:${branch}`)}`,
    5,
  );
  const numbers = candidates
    .filter((pr) => isRecord(pr) && pr.head?.sha === headSha && Number.isSafeInteger(pr.number))
    .filter((pr) => pr.head?.repo?.full_name === run.head_repository?.full_name)
    .map((pr) => pr.number);
  return { numbers, headSha };
}

// ---------------------------------------------------------------------------
// Main flow

export function postComments({ data, event, repo, gh, author = "github-actions[bot]", maxInline = DEFAULT_MAX_INLINE, log = () => {} }) {
  if (!REPOSITORY.test(repo)) throw new Error("GITHUB_REPOSITORY is invalid");
  const trusted = trustedPullRequest(event, repo, gh);
  if (!trusted.numbers.includes(data.pullRequest)) {
    throw new Error(
      `refusing: the artifact names pull request #${data.pullRequest}, but the triggering run belongs to ${trusted.numbers.length > 0 ? trusted.numbers.map((n) => `#${n}`).join(", ") : "no open pull request"}`,
    );
  }
  if (data.headSha !== trusted.headSha) {
    throw new Error("refusing: the artifact was produced for a different head commit than the triggering run");
  }
  const pr = data.pullRequest;

  // Lines of the pull request's diff (RIGHT side) per file.
  const diff = new Map();
  for (const file of paginate(gh, `repos/${repo}/pulls/${pr}/files`)) {
    if (isRecord(file) && typeof file.filename === "string") diff.set(file.filename, rightSideLines(file.patch));
  }

  // Earlier comments of this tool (by this account only).
  const ours = (comment) => isRecord(comment) && comment.user?.login === author && typeof comment.body === "string";
  const existingInline = new Map();
  for (const comment of paginate(gh, `repos/${repo}/pulls/${pr}/comments`)) {
    if (!ours(comment)) continue;
    const match = /^<!-- code-audit:([0-9a-f]{64}) -->/.exec(comment.body);
    if (match && !existingInline.has(match[1])) existingInline.set(match[1], comment.id);
  }
  let summaryId;
  for (const comment of paginate(gh, `repos/${repo}/issues/${pr}/comments`)) {
    if (ours(comment) && comment.body.startsWith(SUMMARY_MARKER)) {
      summaryId = comment.id;
      break;
    }
  }

  const rest = [];
  let inlined = 0;
  for (const finding of data.findings) {
    const lines = diff.get(finding.file);
    let line;
    if (lines && finding.startLine > 0) {
      for (let candidate = finding.startLine; candidate <= Math.min(finding.endLine, finding.startLine + 1000); candidate += 1) {
        if (lines.has(candidate)) {
          line = candidate;
          break;
        }
      }
    }
    if (line === undefined || inlined >= maxInline) {
      rest.push(finding);
      continue;
    }
    const body = renderInlineBody(finding, data);
    const existing = existingInline.get(finding.fingerprint);
    try {
      if (existing !== undefined && Number.isSafeInteger(existing)) {
        gh("PATCH", `repos/${repo}/pulls/comments/${existing}`, { body });
        log(`updated inline comment for ${finding.fingerprint.slice(0, 12)}`);
      } else {
        gh("POST", `repos/${repo}/pulls/${pr}/comments`, {
          body,
          commit_id: data.headSha,
          path: finding.file,
          line,
          side: "RIGHT",
        });
        log(`added inline comment for ${finding.fingerprint.slice(0, 12)}`);
      }
      inlined += 1;
    } catch (error) {
      log(`inline comment not possible (${error instanceof Error ? error.message : String(error)}); listed in the summary`);
      rest.push(finding);
    }
  }

  const summary = renderSummaryBody(data, rest, inlined);
  if (summaryId !== undefined && Number.isSafeInteger(summaryId)) {
    gh("PATCH", `repos/${repo}/issues/comments/${summaryId}`, { body: summary });
    log("updated the summary comment");
  } else {
    gh("POST", `repos/${repo}/issues/${pr}/comments`, { body: summary });
    log("added the summary comment");
  }
  return { pullRequest: pr, inlined, summarized: rest.length };
}

function main() {
  const file = process.argv[2];
  if (!file) {
    process.stderr.write("usage: comment.mjs <comment-data.json>\n");
    return 2;
  }
  try {
    const data = loadCommentData(file);
    const eventPath = process.env.GITHUB_EVENT_PATH;
    if (!eventPath) throw new Error("GITHUB_EVENT_PATH is not set");
    const event = JSON.parse(fs.readFileSync(eventPath, "utf8"));
    const requested = Number.parseInt(process.env.CODE_AUDIT_MAX_INLINE ?? "", 10);
    const result = postComments({
      data,
      event,
      repo: process.env.GITHUB_REPOSITORY ?? "",
      gh: makeGh(),
      author: process.env.CODE_AUDIT_COMMENT_AUTHOR || "github-actions[bot]",
      maxInline: Number.isSafeInteger(requested) && requested >= 0 ? Math.min(requested, 50) : DEFAULT_MAX_INLINE,
      log: (line) => process.stdout.write(`${line}\n`),
    });
    process.stdout.write(
      `code-audit: pull request #${result.pullRequest}: ${result.inlined} inline comment(s), ${result.summarized} finding(s) in the summary\n`,
    );
    return 0;
  } catch (error) {
    process.stderr.write(`code-audit comment: ${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(fs.realpathSync(process.argv[1])).href) {
  process.exitCode = main();
}
