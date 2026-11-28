/**
 * The GitHub Action: action.yml, comment/action.yml, the example workflows,
 * the self-scan workflow and the scripts in scripts/action/. No network: the
 * comment script talks to a fake `gh` executable put first on PATH.
 */
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { afterAll, describe, expect, it } from "vitest";
import { scanProject } from "../src/scan.js";
import { REPO_ROOT, cleanup, makeTempDir } from "./helpers.js";
// Plain ES modules without type declarations.
// @ts-ignore untyped .mjs
import * as comment from "../../../scripts/action/comment.mjs";
// @ts-ignore untyped .mjs
import * as prepare from "../../../scripts/action/prepare.mjs";

const temp = makeTempDir("action");
afterAll(() => {
  try {
    fs.rmSync(temp, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  } catch {
    cleanup(temp);
  }
});

const ACTION_FILES = [
  "action.yml",
  "comment/action.yml",
  "examples/workflows/code-audit-pr.yml",
  "examples/workflows/code-audit-comment.yml",
  ".github/workflows/code-audit.yml",
];

function read(rel: string): string {
  return fs.readFileSync(path.join(REPO_ROOT, rel), "utf8");
}

const FP = (n: number): string => n.toString(16).padStart(64, "0");
const HEAD = "a".repeat(40);
const BASE = "b".repeat(40);

// ---------------------------------------------------------------------------
describe("action.yml and the workflows", () => {
  it("produce no finding or hotspot with the github-actions rules", async () => {
    // The rules apply to .github/workflows/*.yml: put every file there.
    const root = path.join(temp, "static");
    fs.mkdirSync(path.join(root, ".github", "workflows"), { recursive: true });
    for (const rel of ACTION_FILES) {
      const name = rel.replace(/[/.]/g, "_").replace(/_yml$/, ".yml");
      fs.copyFileSync(path.join(REPO_ROOT, rel), path.join(root, ".github", "workflows", name));
    }
    const result = await scanProject({
      root,
      out: path.join(temp, "out-static"),
      offline: true,
      engines: ["builtin"],
      formats: ["json"],
      untrusted: true,
    });
    const items = [...result.findings, ...result.hotspots].map((f) => `${f.ruleId} ${f.file}:${f.startLine}`);
    expect(items).toEqual([]);
    expect(result.coverage.stats.scannedFiles).toBe(ACTION_FILES.length);
  });

  it("pin every third-party action to a full commit SHA with the version in a comment", () => {
    for (const rel of ACTION_FILES) {
      for (const line of read(rel).split("\n")) {
        const match = /^\s*(?:-\s*)?uses:\s*(\S+)(.*)$/.exec(line);
        if (!match) continue;
        const [, ref, rest] = match as unknown as [string, string, string];
        if (ref === "./") continue;
        expect(ref, `${rel}: ${line}`).toMatch(/^[\w.-]+\/[\w./-]+@[0-9a-f]{40}$/);
        expect(rest, `${rel}: ${line}`).toMatch(/^\s*# v\d+\.\d+\.\d+|^\s*# vX\.Y\.Z/);
      }
    }
  });

  it("never expand an expression inside a run script", () => {
    for (const rel of ACTION_FILES) {
      const lines = read(rel).split("\n");
      let runIndent = -1;
      for (const line of lines) {
        const indent = line.length - line.trimStart().length;
        if (runIndent >= 0 && line.trim() !== "" && indent <= runIndent) runIndent = -1;
        const run = /^(\s*)(?:-\s*)?run:\s*(.*)$/.exec(line);
        if (run) {
          expect(run[2], `${rel}: ${line}`).not.toMatch(/\$\{\{/);
          if (/^[|>]/.test(run[2] ?? "")) runIndent = indent;
          continue;
        }
        if (runIndent >= 0) expect(line, `${rel}: ${line}`).not.toMatch(/\$\{\{/);
      }
    }
  });

  it("use no pull_request_target, and the comment stage checks nothing out", () => {
    for (const rel of ACTION_FILES) {
      expect(read(rel), rel).not.toMatch(/^\s*pull_request_target\s*:|on:\s*\[?[^\n]*pull_request_target/m);
    }
    const commentWorkflow = read("examples/workflows/code-audit-comment.yml");
    const commentAction = read("comment/action.yml");
    for (const text of [commentWorkflow, commentAction]) {
      expect(text).not.toMatch(/actions\/checkout/);
      expect(text).not.toMatch(/pnpm|npm (?:install|ci)|run:\s*\.\//);
    }
    expect(commentWorkflow).toMatch(/workflow_run:/);
    expect(commentWorkflow).toMatch(/pull-requests: write/);
    expect(commentWorkflow).toMatch(/actions: read/);
    const pr = read("examples/workflows/code-audit-pr.yml");
    expect(pr).toMatch(/^\s*pull_request:\s*$/m);
    expect(pr).toMatch(/security-events: write/);
    expect(pr).not.toMatch(/pull-requests: write/);
  });

  it("declare the inputs and outputs of the specification", () => {
    const action = read("action.yml");
    for (const input of ["fail-on", "min-confidence", "mode", "baseline", "engines", "upload-sarif", "comment", "version"]) {
      expect(action).toMatch(new RegExp(`^  ${input}:`, "m"));
    }
    for (const output of ["findings-count", "new-findings-count", "sarif-file", "exit-code"]) {
      expect(action).toMatch(new RegExp(`^  ${output}:`, "m"));
    }
    expect(action).toMatch(/--untrusted/);
    expect(action).toMatch(/--diff-lines/);
    expect(action).toMatch(/using: composite/);
  });
});

// ---------------------------------------------------------------------------
describe("comment template escaping", () => {
  const data = {
    schemaVersion: 1,
    tool: "code-audit",
    toolVersion: "0.4.0",
    pullRequest: 7,
    headSha: HEAD,
    baseSha: BASE,
    mode: "diff",
    summary: { findings: 1, newFindings: 1, hotspots: 0, failOn: "high", minConfidence: "medium", exitCode: 1, truncated: false },
    findings: [],
  };
  const hostile = {
    fingerprint: FP(1),
    ruleId: "py-sql-injection",
    severity: "high",
    confidence: "high",
    title: "```\n# Heading @octocat [click](https://evil.example) <script>alert(1)</script>",
    file: "src/`a`@b [x](javascript:alert(1)).py",
    startLine: 3,
    endLine: 3,
    evidence: "x = 1\n```\n<img src=x onerror=alert(1)> @admin ping\n[link](https://evil.example)‮​",
  };

  it("keeps repository text inside code and breaks mentions", () => {
    const body: string = comment.renderInlineBody(hostile, data);
    expect(body.startsWith(`<!-- code-audit:${FP(1)} -->\n`)).toBe(true);
    // No backtick from the input survives: it could close the code span or fence.
    const fences = body.match(/```/g) ?? [];
    expect(fences.length).toBe(2);
    expect(body).not.toContain("`a`");
    // Every @ is followed by a zero-width space.
    expect(body).not.toMatch(/@(?!​)/);
    expect(body).toContain("@​octocat");
    expect(body).toContain("@​admin");
    // Bidirectional overrides are removed.
    expect(body).not.toContain("‮");
    // The hostile title is a single code span on one line.
    const titleLine = body.split("\n").find((line) => line.includes("Heading"));
    expect(titleLine?.startsWith("`")).toBe(true);
    expect(titleLine?.endsWith("`")).toBe(true);
    // Markdown/HTML outside code: only the fixed template's parts.
    const outsideCode = body
      .replace(/```text\n[\s\S]*?\n```/g, "")
      .replace(/`[^`\n]*`/g, "");
    expect(outsideCode).not.toMatch(/<script|<img|\]\(|javascript:|# Heading/);
  });

  it("escapes the summary list the same way", () => {
    const body: string = comment.renderSummaryBody({ ...data, findings: [hostile] }, [hostile], 0);
    expect(body.startsWith(comment.SUMMARY_MARKER)).toBe(true);
    const outsideCode = body.replace(/`[^`\n]*`/g, "");
    expect(outsideCode).not.toMatch(/<script|<img|\]\(|javascript:|@octocat/);
    expect(body).not.toMatch(/@(?!​)/);
  });

  it("says that no finding is not a guarantee", () => {
    const body: string = comment.renderSummaryBody(
      { ...data, summary: { ...data.summary, findings: 0, newFindings: 0 } },
      [],
      0,
    );
    expect(body).toMatch(/not a guarantee of safety/);
  });

  it("reads the right-side lines of a patch", () => {
    const patch = "@@ -1,3 +1,4 @@\n a\n-b\n+B\n+C\n c\n@@ -10,2 +11,2 @@\n x\n-y\n+Y\n\\ No newline at end of file";
    expect([...comment.rightSideLines(patch)].sort((a: number, b: number) => a - b)).toEqual([1, 2, 3, 4, 11, 12]);
    expect(comment.rightSideLines(undefined).size).toBe(0);
  });
});

// ---------------------------------------------------------------------------
describe("comment data validation", () => {
  const valid = () => ({
    schemaVersion: 1,
    tool: "code-audit",
    toolVersion: "0.4.0",
    pullRequest: 7,
    headSha: HEAD,
    baseSha: BASE,
    mode: "diff",
    summary: { findings: 1, newFindings: 1, hotspots: 0, failOn: "high", minConfidence: "medium", exitCode: 1, truncated: false },
    findings: [
      { fingerprint: FP(1), ruleId: "py-sql-injection", severity: "high", confidence: "high", title: "t", file: "a.py", startLine: 1, endLine: 1 },
    ],
  });

  it("accepts the output of prepare.mjs", () => {
    expect(comment.validateCommentData(valid())).toEqual([]);
  });

  it("rejects malformed or hostile fields", () => {
    const cases: Array<[string, (d: ReturnType<typeof valid>) => void]> = [
      ["pullRequest", (d) => ((d as { pullRequest: unknown }).pullRequest = "7")],
      ["headSha", (d) => (d.headSha = "HEAD; rm -rf /")],
      ["fingerprint", (d) => ((d.findings[0] as { fingerprint: string }).fingerprint = "x -->")],
      ["ruleId", (d) => ((d.findings[0] as { ruleId: string }).ruleId = "rule\n**bold**")],
      ["severity", (d) => ((d.findings[0] as { severity: string }).severity = "urgent")],
      ["line", (d) => ((d.findings[0] as { startLine: number }).startLine = -1)],
      ["evidence", (d) => ((d.findings[0] as { evidence?: string }).evidence = "x".repeat(501))],
      ["duplicate", (d) => d.findings.push({ ...(d.findings[0] as object) } as never)],
      ["count", (d) => ((d.summary as { findings: number }).findings = 1.5)],
      ["schema", (d) => ((d as { schemaVersion: number }).schemaVersion = 2)],
    ];
    for (const [name, mutate] of cases) {
      const data = valid();
      mutate(data);
      expect(comment.validateCommentData(data).length, name).toBeGreaterThan(0);
    }
    expect(comment.validateCommentData([])).not.toEqual([]);
  });

  it("refuses oversized files and symbolic links", () => {
    const big = path.join(temp, "big.json");
    fs.writeFileSync(big, " ".repeat(comment.MAX_DATA_BYTES + 1));
    expect(() => comment.loadCommentData(big)).toThrow(/larger than/);
    const good = path.join(temp, "good.json");
    fs.writeFileSync(good, JSON.stringify(valid()));
    const link = path.join(temp, "link.json");
    fs.symlinkSync(good, link);
    expect(() => comment.loadCommentData(link)).toThrow(/not a regular file/);
    expect(comment.loadCommentData(good).pullRequest).toBe(7);
  });
});

// ---------------------------------------------------------------------------
// The fake gh: answers from a route table, logs every call.
const FAKE_GH = `#!/usr/bin/env node
import fs from "node:fs";
const args = process.argv.slice(2);
const input = fs.readFileSync(0, "utf8");
const method = args[args.indexOf("--method") + 1];
const endpoint = args.find((a, i) => i > 0 && !a.startsWith("-") && args[i - 1] !== "--method" && args[i - 1] !== "-H" && args[i - 1] !== "--input");
fs.appendFileSync(process.env.FAKE_GH_LOG, JSON.stringify({ method, endpoint, body: input ? JSON.parse(input) : undefined }) + "\\n");
const routes = JSON.parse(fs.readFileSync(process.env.FAKE_GH_ROUTES, "utf8"));
for (const route of routes) {
  if (route.method === method && new RegExp(route.match).test(endpoint)) {
    if (route.status && route.status >= 400) { process.stderr.write("gh: HTTP " + route.status); process.exit(1); }
    process.stdout.write(JSON.stringify(route.body ?? {}));
    process.exit(0);
  }
}
if (method === "GET") { process.stdout.write("[]"); process.exit(0); }
process.stdout.write(JSON.stringify({ id: 1 }));
`;

interface Call {
  method: string;
  endpoint: string;
  body?: { body?: string; path?: string; line?: number; commit_id?: string; side?: string };
}

function fakeGh(name: string, routes: unknown[]) {
  const dir = path.join(temp, `gh-${name}`);
  fs.mkdirSync(dir, { recursive: true });
  const gh = path.join(dir, "gh");
  fs.writeFileSync(gh, FAKE_GH);
  fs.chmodSync(gh, 0o755);
  const log = path.join(dir, "log.jsonl");
  fs.writeFileSync(log, "");
  const routesFile = path.join(dir, "routes.json");
  fs.writeFileSync(routesFile, JSON.stringify(routes));
  return {
    dir,
    env: { ...process.env, PATH: `${dir}${path.delimiter}${process.env.PATH ?? ""}`, FAKE_GH_LOG: log, FAKE_GH_ROUTES: routesFile },
    calls: (): Call[] =>
      fs
        .readFileSync(log, "utf8")
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line) as Call),
  };
}

function findingsData(count: number, overrides: Record<string, unknown> = {}) {
  return {
    schemaVersion: 1,
    tool: "code-audit",
    toolVersion: "0.4.0",
    pullRequest: 7,
    headSha: HEAD,
    baseSha: BASE,
    mode: "diff",
    summary: { findings: count, newFindings: count, hotspots: 2, failOn: "high", minConfidence: "medium", exitCode: count > 0 ? 1 : 0, truncated: false },
    findings: Array.from({ length: count }, (_, index) => ({
      fingerprint: FP(index + 1),
      ruleId: "py-command-injection",
      severity: "high",
      confidence: "high",
      title: `finding ${index + 1} @someone`,
      file: index % 2 === 0 ? "src/app.py" : "src/other.py",
      startLine: index + 1,
      endLine: index + 1,
      evidence: "os.system(cmd)",
    })),
    ...overrides,
  };
}

function workflowRunEvent(overrides: Record<string, unknown> = {}) {
  return {
    workflow_run: {
      id: 99,
      event: "pull_request",
      head_sha: HEAD,
      head_branch: "feature",
      head_repository: { full_name: "octo/repo", owner: { login: "octo" } },
      pull_requests: [{ number: 7, head: { sha: HEAD } }],
      ...overrides,
    },
  };
}

/** Patch covering lines 1..n of a new file. */
function addedPatch(n: number): string {
  return [`@@ -0,0 +1,${n} @@`, ...Array.from({ length: n }, (_, i) => `+line ${i + 1}`)].join("\n");
}

function runComment(name: string, data: unknown, event: unknown, routes: unknown[], extraEnv: Record<string, string> = {}) {
  const fake = fakeGh(name, routes);
  const dataFile = path.join(fake.dir, "comment-data.json");
  fs.writeFileSync(dataFile, JSON.stringify(data));
  const eventFile = path.join(fake.dir, "event.json");
  fs.writeFileSync(eventFile, JSON.stringify(event));
  const result = spawnSync(process.execPath, [path.join(REPO_ROOT, "scripts/action/comment.mjs"), dataFile], {
    encoding: "utf8",
    env: { ...fake.env, GITHUB_REPOSITORY: "octo/repo", GITHUB_EVENT_PATH: eventFile, GH_TOKEN: "fake-token-for-tests", ...extraEnv },
    timeout: 60_000,
  });
  return { ...result, calls: fake.calls() };
}

const FILES_ROUTE = {
  method: "GET",
  match: "^repos/octo/repo/pulls/7/files\\?.*page=1$",
  body: [
    { filename: "src/app.py", patch: addedPatch(100) },
    { filename: "src/other.py", patch: addedPatch(100) },
  ],
};

describe("comment.mjs with a fake gh", () => {
  it("posts inline comments on diff lines and one summary", () => {
    const result = runComment("basic", findingsData(3), workflowRunEvent(), [FILES_ROUTE]);
    expect(result.stderr).toBe("");
    expect(result.status).toBe(0);
    const posts = result.calls.filter((call) => call.method === "POST");
    const inline = posts.filter((call) => call.endpoint === "repos/octo/repo/pulls/7/comments");
    expect(inline).toHaveLength(3);
    for (const call of inline) {
      expect(call.body?.commit_id).toBe(HEAD);
      expect(call.body?.side).toBe("RIGHT");
      expect(call.body?.body).toMatch(/^<!-- code-audit:[0-9a-f]{64} -->/);
      expect(call.body?.body).not.toMatch(/@(?!​)/);
    }
    expect(inline.map((call) => [call.body?.path, call.body?.line])).toEqual([
      ["src/app.py", 1],
      ["src/other.py", 2],
      ["src/app.py", 3],
    ]);
    const summary = posts.filter((call) => call.endpoint === "repos/octo/repo/issues/7/comments");
    expect(summary).toHaveLength(1);
    expect(summary[0]?.body?.body?.startsWith(comment.SUMMARY_MARKER)).toBe(true);
    expect(summary[0]?.body?.body).toMatch(/Inline comments on changed lines: 3/);
  });

  it("caps inline comments at 20 and lists the rest in the summary", () => {
    const result = runComment("cap", findingsData(30), workflowRunEvent(), [FILES_ROUTE]);
    expect(result.status).toBe(0);
    const inline = result.calls.filter((call) => call.method === "POST" && call.endpoint.endsWith("/pulls/7/comments"));
    expect(inline).toHaveLength(20);
    const summary = result.calls.find((call) => call.method === "POST" && call.endpoint.endsWith("/issues/7/comments"));
    expect(summary?.body?.body).toMatch(/Inline comments on changed lines: 20/);
    expect((summary?.body?.body?.match(/^- \*\*HIGH\*\*/gm) ?? []).length).toBe(10);
  });

  it("lists findings outside the diff in the summary only", () => {
    const data = findingsData(2);
    (data.findings[1] as { file: string }).file = "src/untouched.py";
    const result = runComment("outside", data, workflowRunEvent(), [FILES_ROUTE]);
    expect(result.status).toBe(0);
    const inline = result.calls.filter((call) => call.method === "POST" && call.endpoint.endsWith("/pulls/7/comments"));
    expect(inline).toHaveLength(1);
    const summary = result.calls.find((call) => call.endpoint.endsWith("/issues/7/comments") && call.method === "POST");
    expect(summary?.body?.body).toContain("src/untouched.py:2");
  });

  it("updates its own earlier comments instead of adding new ones", () => {
    const routes = [
      FILES_ROUTE,
      {
        method: "GET",
        match: "^repos/octo/repo/pulls/7/comments\\?.*page=1$",
        body: [
          { id: 501, user: { login: "github-actions[bot]" }, body: `<!-- code-audit:${FP(1)} -->\nold` },
          // Same marker, written by someone else: never touched.
          { id: 502, user: { login: "mallory" }, body: `<!-- code-audit:${FP(2)} -->\nfake` },
        ],
      },
      {
        method: "GET",
        match: "^repos/octo/repo/issues/7/comments\\?.*page=1$",
        body: [
          { id: 601, user: { login: "mallory" }, body: `${comment.SUMMARY_MARKER}\nfake` },
          { id: 602, user: { login: "github-actions[bot]" }, body: `${comment.SUMMARY_MARKER}\nold` },
        ],
      },
    ];
    const result = runComment("update", findingsData(2), workflowRunEvent(), routes);
    expect(result.status).toBe(0);
    const patches = result.calls.filter((call) => call.method === "PATCH").map((call) => call.endpoint);
    expect(patches).toEqual(["repos/octo/repo/pulls/comments/501", "repos/octo/repo/issues/comments/602"]);
    const posts = result.calls.filter((call) => call.method === "POST");
    expect(posts.map((call) => call.endpoint)).toEqual(["repos/octo/repo/pulls/7/comments"]);
    expect(posts[0]?.body?.body).toContain(FP(2));
  });

  it("refuses an artifact whose pull request number is not the triggering run's", () => {
    const result = runComment("mismatch", findingsData(1, { pullRequest: 8 }), workflowRunEvent(), [FILES_ROUTE]);
    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(/refusing: the artifact names pull request #8/);
    expect(result.calls.filter((call) => call.method !== "GET")).toEqual([]);
  });

  it("refuses an artifact for another head commit", () => {
    const result = runComment("headsha", findingsData(1, { headSha: "c".repeat(40) }), workflowRunEvent(), [FILES_ROUTE]);
    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(/different head commit/);
    expect(result.calls.filter((call) => call.method !== "GET")).toEqual([]);
  });

  it("refuses runs that were not started by a pull request and invalid data", () => {
    const push = runComment("push", findingsData(1), workflowRunEvent({ event: "push" }), [FILES_ROUTE]);
    expect(push.status).toBe(1);
    expect(push.calls).toEqual([]);
    const bad = runComment("invalid", { ...findingsData(1), headSha: "nope" }, workflowRunEvent(), [FILES_ROUTE]);
    expect(bad.status).toBe(1);
    expect(bad.stderr).toMatch(/comment data rejected/);
    expect(bad.calls).toEqual([]);
  });

  it("finds a fork's pull request by head repository, branch and commit", () => {
    const event = workflowRunEvent({
      pull_requests: [],
      head_repository: { full_name: "fork-owner/repo", owner: { login: "fork-owner" } },
    });
    const pulls = {
      method: "GET",
      match: "^repos/octo/repo/pulls\\?state=open&head=fork-owner%3Afeature",
      body: [{ number: 7, head: { sha: HEAD, repo: { full_name: "fork-owner/repo" } } }],
    };
    const ok = runComment("fork", findingsData(1), event, [pulls, FILES_ROUTE]);
    expect(ok.stderr).toBe("");
    expect(ok.status).toBe(0);
    // The open pull request moved on to another commit: refused.
    const moved = {
      ...pulls,
      body: [{ number: 7, head: { sha: "d".repeat(40), repo: { full_name: "fork-owner/repo" } } }],
    };
    const refused = runComment("fork-moved", findingsData(1), event, [moved, FILES_ROUTE]);
    expect(refused.status).toBe(1);
    expect(refused.stderr).toMatch(/no open pull request/);
  });

  it("falls back to the summary when an inline comment is rejected by the API", () => {
    const routes = [FILES_ROUTE, { method: "POST", match: "^repos/octo/repo/pulls/7/comments$", status: 422 }];
    const result = runComment("reject", findingsData(1), workflowRunEvent(), routes);
    expect(result.status).toBe(0);
    const summary = result.calls.find((call) => call.method === "POST" && call.endpoint.endsWith("/issues/7/comments"));
    expect(summary?.body?.body).toMatch(/Inline comments on changed lines: 0/);
    expect(summary?.body?.body).toContain("src/app.py:1");
  });
});

// ---------------------------------------------------------------------------
describe("prepare.mjs", () => {
  it("builds valid comment data from findings.json and counts like the scan", () => {
    const finding = (n: number, extra: Record<string, unknown> = {}) => ({
      fingerprint: FP(n),
      ruleId: "py-sql-injection",
      severity: "high",
      confidence: "high",
      status: "candidate",
      title: "SQL",
      file: "a.py",
      startLine: n,
      endLine: n,
      evidence: "cursor.execute(q)",
      ...extra,
    });
    const document = {
      run: {
        tool: { version: "0.4.0" },
        minConfidence: "medium",
        failOn: "high",
        hotspotCount: 3,
        baselineUsed: true,
        baseline: { new: 1, existing: 1, fixed: 0 },
        summary: { headline: { total: 1 } },
      },
      findings: [
        finding(1, { baselineState: "new" }),
        finding(2, { baselineState: "existing" }),
        finding(3, { status: "suppressed" }),
        finding(4, { confidence: "low" }),
      ],
    };
    const data = prepare.buildCommentData(document, {
      pullRequest: 7,
      headSha: HEAD,
      baseSha: BASE,
      mode: "diff",
      exitCode: 1,
    });
    expect(comment.validateCommentData(data)).toEqual([]);
    expect(data.findings.map((f: { fingerprint: string }) => f.fingerprint)).toEqual([FP(1)]);
    expect(data.summary).toMatchObject({ findings: 1, newFindings: 1, hotspots: 3, exitCode: 1 });

    // As a script: outputs to $GITHUB_OUTPUT.
    const dir = path.join(temp, "prepare");
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "findings.json"), JSON.stringify(document));
    const output = path.join(dir, "output.txt");
    const run = spawnSync(
      process.execPath,
      [path.join(REPO_ROOT, "scripts/action/prepare.mjs"), path.join(dir, "findings.json"), path.join(dir, "comment-data.json")],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          GITHUB_OUTPUT: output,
          CODE_AUDIT_PR_NUMBER: "7",
          CODE_AUDIT_HEAD_SHA: HEAD,
          CODE_AUDIT_BASE_SHA: BASE,
          CODE_AUDIT_MODE: "diff",
          CODE_AUDIT_EXIT_CODE: "1",
        },
      },
    );
    expect(run.status).toBe(0);
    expect(fs.readFileSync(output, "utf8")).toBe("findings-count=1\nnew-findings-count=1\n");
    const written = JSON.parse(fs.readFileSync(path.join(dir, "comment-data.json"), "utf8"));
    expect(comment.validateCommentData(written)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// scripts/action/prepare.sh and the Scan step of action.yml, run locally.

const GIT_ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "test",
  GIT_AUTHOR_EMAIL: "test@example.invalid",
  GIT_COMMITTER_NAME: "test",
  GIT_COMMITTER_EMAIL: "test@example.invalid",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: "/dev/null",
};

function gitIn(cwd: string, args: string[]): string {
  const result = spawnSync("git", args, { cwd, encoding: "utf8", env: GIT_ENV });
  if (result.status !== 0) throw new Error(`git ${args.join(" ")}: ${result.stderr}`);
  return result.stdout.trim();
}

/** The `run: |` block of the step with `id: <id>` in action.yml. */
function stepScript(id: string): string {
  const text = read("action.yml");
  const start = text.indexOf(`      id: ${id}\n`);
  expect(start).toBeGreaterThan(0);
  const run = text.indexOf("      run: |\n", start);
  const lines: string[] = [];
  for (const line of text.slice(run + "      run: |\n".length).split("\n")) {
    if (line.trim() !== "" && !line.startsWith("        ")) break;
    lines.push(line.slice(8));
  }
  return lines.join("\n");
}

function parseOutputs(file: string): Record<string, string> {
  const outputs: Record<string, string> = {};
  for (const line of fs.readFileSync(file, "utf8").split("\n")) {
    const eq = line.indexOf("=");
    if (eq > 0) outputs[line.slice(0, eq)] = line.slice(eq + 1);
  }
  return outputs;
}

const VULNERABLE_PY = "import os\n\ndef run(cmd):\n    os.system(cmd)\n";

function setUpPullRequest(name: string) {
  const root = path.join(temp, name);
  const workspace = path.join(root, "workspace");
  const runnerTemp = path.join(root, "runner-temp");
  const actionPath = path.join(root, "action");
  fs.mkdirSync(workspace, { recursive: true });
  fs.mkdirSync(runnerTemp, { recursive: true });
  fs.mkdirSync(actionPath, { recursive: true });
  // A stand-in for the Action's source: only what prepare.sh copies.
  fs.writeFileSync(path.join(actionPath, "package.json"), '{"packageManager":"pnpm@11.21.0"}\n');
  gitIn(workspace, ["init", "-q", "-b", "main"]);
  // Base: an ignore file that suppresses nothing relevant.
  fs.writeFileSync(
    path.join(workspace, ".code-audit-ignore"),
    'version: 1\nignore:\n  - rule: "py-unused-placeholder"\n    reason: "base branch entry"\n',
  );
  fs.writeFileSync(path.join(workspace, "old.py"), VULNERABLE_PY);
  gitIn(workspace, ["add", "-A"]);
  gitIn(workspace, ["commit", "-qm", "base"]);
  const base = gitIn(workspace, ["rev-parse", "HEAD"]);
  // The pull request: new vulnerable code, and an ignore file that would hide it.
  gitIn(workspace, ["checkout", "-q", "-b", "feature"]);
  fs.writeFileSync(path.join(workspace, "new.py"), VULNERABLE_PY);
  fs.writeFileSync(
    path.join(workspace, ".code-audit-ignore"),
    'version: 1\nignore:\n  - paths: ["**"]\n    reason: "the pull request hides everything"\n',
  );
  gitIn(workspace, ["add", "-A"]);
  gitIn(workspace, ["commit", "-qm", "pr"]);
  const head = gitIn(workspace, ["rev-parse", "HEAD"]);
  return { root, workspace, runnerTemp, actionPath, base, head };
}

let outputCounter = 0;

function prepareEnv(setup: ReturnType<typeof setUpPullRequest>, overrides: Record<string, string> = {}) {
  outputCounter += 1;
  const output = path.join(setup.root, `github-output-${outputCounter}`);
  fs.writeFileSync(output, "");
  return {
    output,
    env: {
      ...GIT_ENV,
      GITHUB_WORKSPACE: setup.workspace,
      RUNNER_TEMP: setup.runnerTemp,
      GITHUB_OUTPUT: output,
      GITHUB_REPOSITORY: "octo/repo",
      ACTION_PATH: setup.actionPath,
      INPUT_PATH: ".",
      INPUT_FAIL_ON: "high",
      INPUT_MIN_CONFIDENCE: "medium",
      INPUT_MODE: "",
      INPUT_BASELINE: "",
      INPUT_ENGINES: "builtin",
      INPUT_OFFLINE: "true",
      INPUT_UPLOAD_SARIF: "true",
      INPUT_COMMENT: "true",
      INPUT_ARTIFACT_NAME: "code-audit-results",
      INPUT_VERSION: "",
      EVENT_NAME: "pull_request",
      PR_BASE_SHA: setup.base,
      PR_HEAD_SHA: setup.head,
      PR_NUMBER: "7",
      PR_HEAD_REPO: "octo/repo",
      ...overrides,
    },
  };
}

function runPrepare(env: NodeJS.ProcessEnv) {
  return spawnSync("bash", [path.join(REPO_ROOT, "scripts/action/prepare.sh")], {
    encoding: "utf8",
    env,
    timeout: 60_000,
  });
}

describe("prepare.sh and the Scan step", () => {
  it("scans the changed lines with the base commit's ignore file, not the pull request's", () => {
    const setup = setUpPullRequest("pr-flow");
    const { env, output } = prepareEnv(setup);
    const prep = runPrepare(env);
    expect(prep.stderr).toBe("");
    expect(prep.status).toBe(0);
    const outputs = parseOutputs(output);
    expect(outputs.mode).toBe("diff");
    expect(outputs["base-sha"]).toBe(setup.base);
    expect(outputs["head-sha"]).toBe(setup.head);
    expect(outputs["pr-number"]).toBe("7");
    expect(outputs.comment).toBe("true");
    expect(outputs.fork).toBe("false");
    expect(fs.readFileSync(outputs["ignore-file"] as string, "utf8")).toMatch(/base branch entry/);
    expect(path.isAbsolute(outputs["package-json"] as string)).toBe(false);
    expect(fs.existsSync(path.join(setup.workspace, outputs["package-json"] as string))).toBe(true);

    // The Scan step, with the CLI of this repository.
    const cliRoot = path.join(setup.root, "cli-src");
    fs.mkdirSync(path.join(cliRoot, "packages", "cli"), { recursive: true });
    fs.symlinkSync(path.join(REPO_ROOT, "packages", "cli", "dist"), path.join(cliRoot, "packages", "cli", "dist"));
    const scanOutput = path.join(setup.root, "scan-output");
    fs.writeFileSync(scanOutput, "");
    const scan = spawnSync("bash", ["-c", stepScript("scan")], {
      encoding: "utf8",
      env: {
        ...GIT_ENV,
        GITHUB_OUTPUT: scanOutput,
        SRC: cliRoot,
        OUT: outputs.out,
        TARGET: outputs.target,
        MODE: outputs.mode,
        BASE_SHA: outputs["base-sha"],
        IGNORE_FILE: outputs["ignore-file"],
        BASELINE_FILE: outputs["baseline-file"],
        FAIL_ON: outputs["fail-on"],
        MIN_CONFIDENCE: outputs["min-confidence"],
        ENGINES: outputs.engines,
        OFFLINE: outputs.offline,
      },
      timeout: 120_000,
    });
    const scanOutputs = parseOutputs(scanOutput);
    expect(scanOutputs["exit-code"], scan.stderr).toMatch(/^[01]$/);
    expect(fs.existsSync(scanOutputs["sarif-file"] as string)).toBe(true);
    const findings = JSON.parse(fs.readFileSync(path.join(outputs.out as string, "latest", "findings.json"), "utf8"));
    const active = [...findings.findings, ...findings.hotspots].filter(
      (f: { status: string }) => f.status !== "suppressed",
    );
    // The new file's finding is reported (the PR's ignore file is not used)...
    expect(active.some((f: { file: string }) => f.file === "new.py")).toBe(true);
    // ...and the unchanged file is out of scope (diff mode).
    expect(active.some((f: { file: string }) => f.file === "old.py")).toBe(false);
    expect(findings.run.scope).toMatchObject({ since: setup.base, diffLines: true });
  });

  it("reads the baseline from the base commit and rejects unsafe inputs", () => {
    const setup = setUpPullRequest("pr-inputs");
    // A baseline only in the pull request: not used.
    fs.writeFileSync(path.join(setup.workspace, "bl.json"), "{}\n");
    const { env, output } = prepareEnv(setup, { INPUT_BASELINE: "bl.json" });
    const prep = runPrepare(env);
    expect(prep.status).toBe(0);
    expect(parseOutputs(output)["baseline-file"]).toBe("");
    expect(prep.stdout).toMatch(/baseline bl\.json is not in commit/);

    const bad: Array<Record<string, string>> = [
      { INPUT_FAIL_ON: "high --no-ignore-file" },
      { INPUT_MIN_CONFIDENCE: "medium\nevil=1" },
      { INPUT_ENGINES: "builtin;touch /tmp/x" },
      { INPUT_MODE: "everything" },
      { INPUT_PATH: "../.." },
      { INPUT_PATH: "/etc" },
      { INPUT_BASELINE: "../outside.json" },
      { INPUT_ARTIFACT_NAME: "a/b" },
      { INPUT_VERSION: "1.0; rm" },
      { INPUT_OFFLINE: "yes" },
      { PR_BASE_SHA: "main" },
      { PR_NUMBER: "7 8" },
      { EVENT_NAME: "push", INPUT_MODE: "diff" },
    ];
    for (const overrides of bad) {
      const run = runPrepare(prepareEnv(setup, overrides).env);
      expect(run.status, JSON.stringify(overrides)).toBe(2);
      expect(run.stdout, JSON.stringify(overrides)).toMatch(/::error::code-audit: /);
    }
  });

  it("uses full mode and the pushed commit's ignore file on push", () => {
    const setup = setUpPullRequest("push-flow");
    const { env, output } = prepareEnv(setup, {
      EVENT_NAME: "push",
      PR_BASE_SHA: "",
      PR_HEAD_SHA: "",
      PR_NUMBER: "",
      GITHUB_SHA: setup.head,
    });
    const prep = runPrepare(env);
    expect(prep.stderr).toBe("");
    expect(prep.status).toBe(0);
    const outputs = parseOutputs(output);
    expect(outputs.mode).toBe("full");
    expect(outputs["base-sha"]).toBe("");
    expect(outputs.comment).toBe("false");
    expect(fs.readFileSync(outputs["ignore-file"] as string, "utf8")).toMatch(/hides everything/);
  });

  it("asks for fetch-depth 0 when the base commit is missing", () => {
    const setup = setUpPullRequest("pr-shallow");
    const { env } = prepareEnv(setup, { PR_BASE_SHA: "e".repeat(40) });
    const prep = runPrepare(env);
    expect(prep.status).toBe(2);
    expect(prep.stdout).toMatch(/fetch-depth: 0/);
  });

  it("M2: a subdirectory path gives repository-relative paths to comments and SARIF", () => {
    const setup = setUpPullRequest("pr-subdir");
    fs.mkdirSync(path.join(setup.workspace, "app"));
    fs.writeFileSync(path.join(setup.workspace, "app", "app.py"), VULNERABLE_PY);
    const { env, output } = prepareEnv(setup, { INPUT_PATH: "app" });
    const prep = runPrepare(env);
    expect(prep.stderr).toBe("");
    expect(prep.status).toBe(0);
    const outputs = parseOutputs(output);
    expect(outputs["path-prefix"]).toBe("app/");
    expect(fs.realpathSync(outputs["repo-root"] as string)).toBe(fs.realpathSync(setup.workspace));

    // findings.json and SARIF as the scanner writes them for the subdirectory.
    const dir = path.join(setup.root, "latest");
    fs.mkdirSync(dir);
    const finding = {
      fingerprint: FP(9),
      ruleId: "py-command-injection",
      severity: "high",
      confidence: "high",
      status: "candidate",
      title: "t",
      file: "app.py",
      startLine: 4,
      endLine: 4,
    };
    fs.writeFileSync(
      path.join(dir, "findings.json"),
      JSON.stringify({ run: { minConfidence: "medium", failOn: "high", summary: { headline: { total: 1 } } }, findings: [finding] }),
    );
    fs.writeFileSync(
      path.join(dir, "results.sarif"),
      JSON.stringify({
        runs: [
          {
            originalUriBaseIds: { "%SRCROOT%": { uri: `file://${outputs.target}/` } },
            results: [{ locations: [{ physicalLocation: { artifactLocation: { uri: "app.py", uriBaseId: "%SRCROOT%" } } }] }],
          },
        ],
      }),
    );
    const githubOutput = path.join(setup.root, "result-output");
    fs.writeFileSync(githubOutput, "");
    const run = spawnSync(
      process.execPath,
      [path.join(REPO_ROOT, "scripts/action/prepare.mjs"), path.join(dir, "findings.json"), path.join(dir, "comment-data.json")],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          GITHUB_OUTPUT: githubOutput,
          CODE_AUDIT_PR_NUMBER: "7",
          CODE_AUDIT_HEAD_SHA: HEAD,
          CODE_AUDIT_BASE_SHA: BASE,
          CODE_AUDIT_MODE: "diff",
          CODE_AUDIT_EXIT_CODE: "1",
          CODE_AUDIT_PATH_PREFIX: outputs["path-prefix"],
          CODE_AUDIT_REPO_ROOT: outputs["repo-root"],
          CODE_AUDIT_SARIF_IN: path.join(dir, "results.sarif"),
          CODE_AUDIT_SARIF_OUT: path.join(dir, "results-repo.sarif"),
        },
      },
    );
    expect(run.stderr).toBe("");
    expect(run.status).toBe(0);
    const data = JSON.parse(fs.readFileSync(path.join(dir, "comment-data.json"), "utf8"));
    expect(data.findings[0].file).toBe("app/app.py");
    expect(parseOutputs(githubOutput)["sarif-file"]).toBe(path.join(dir, "results-repo.sarif"));
    const sarif = JSON.parse(fs.readFileSync(path.join(dir, "results-repo.sarif"), "utf8"));
    expect(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri).toBe("app/app.py");
    expect(sarif.runs[0].originalUriBaseIds["%SRCROOT%"].uri).toBe(`file://${outputs["repo-root"]}/`);

    // The comment goes on the file of the finding, not on a root file of the same name.
    const result = runComment(
      "subdir",
      data,
      workflowRunEvent(),
      [
        {
          method: "GET",
          match: "^repos/octo/repo/pulls/7/files\\?.*page=1$",
          body: [
            { filename: "app.py", patch: addedPatch(10) },
            { filename: "app/app.py", patch: addedPatch(10) },
          ],
        },
      ],
    );
    expect(result.status).toBe(0);
    const inline = result.calls.filter((call) => call.method === "POST" && call.endpoint.endsWith("/pulls/7/comments"));
    expect(inline.map((call) => call.body?.path)).toEqual(["app/app.py"]);
    expect(() => prepare.normalizePrefix("../")).toThrow();
    expect(() => prepare.normalizePrefix("a//")).toThrow();
    expect(() => prepare.normalizePrefix("a")).toThrow();
  });

  it("LOW 3: refuses a path that is or passes through a symbolic link", () => {
    const setup = setUpPullRequest("pr-symlink");
    fs.mkdirSync(path.join(setup.workspace, "real", "inner"), { recursive: true });
    fs.symlinkSync("real", path.join(setup.workspace, "link"));
    for (const input of ["link", "link/inner", "real/../link"]) {
      const run = runPrepare(prepareEnv(setup, { INPUT_PATH: input }).env);
      expect(run.status, input).toBe(2);
      expect(run.stdout, input).toMatch(/symbolic link|'\.\.'/);
    }
    const ok = runPrepare(prepareEnv(setup, { INPUT_PATH: "real/inner" }).env);
    expect(ok.status).toBe(0);
  });
});
