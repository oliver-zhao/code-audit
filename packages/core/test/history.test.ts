/**
 * `scan --history`: range validation, parsing and deduplication of a recorded
 * Gitleaks git-mode report, and the isolated-clone pipeline with a fake
 * `gitleaks` (no real scanner needed; the real one is exercised in
 * realtools.test.ts).
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { afterAll, describe, expect, it } from "vitest";
import {
  DEFAULT_HISTORY_MAX_COMMITS,
  HISTORY_ENGINE,
  HistoryOptionError,
  historyCandidatesFromReport,
  historyFingerprint,
  historyMaxCommits,
  parseHistoryOption,
  parseHistoryRange,
} from "../src/external/index.js";
import { GitScopeError } from "../src/git.js";
import { scanProject } from "../src/scan.js";
import { CLI, cleanup, makeTempDir } from "./helpers.js";
import {
  FAKE_KEY_1,
  FAKE_KEY_2,
  GIT_TEST_ENV,
  commitAll,
  git,
  makeExtPromisorRepository,
  makeHostileRepository as makeHostile,
  makeReplacedRepository,
  newRepo as newRepoIn,
  write,
} from "./historyRepo.js";

const temp = makeTempDir("history");
afterAll(() => {
  try {
    fs.rmSync(temp, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  } catch {
    cleanup(temp);
  }
});

const newRepo = (name: string): string => newRepoIn(temp, name);
const makeHostileRepository = (name: string) => makeHostile(temp, name);

const RECORDED = path.join(path.dirname(new URL(import.meta.url).pathname), "recorded");

describe("--history range validation", () => {
  it("accepts refs, two-dot and three-dot ranges and commit ids", () => {
    for (const value of [
      "main",
      "v1.2.3",
      "feature/x-1_2",
      "origin/main..HEAD",
      "v1.0...main",
      "a".repeat(40),
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "1111111111111111111111111111111111111111..main",
    ]) {
      expect(parseHistoryRange(value)).toBe(value);
    }
  });

  it("rejects option injection, shell syntax and malformed ranges", () => {
    for (const value of [
      "--output=/tmp/x",
      "-p",
      "a;b",
      "a b",
      "$(touch x)",
      "`id`",
      "a|b",
      "HEAD~1",
      "HEAD^",
      "main@{1}",
      "",
      "a..",
      "..b",
      "a..b..c",
      "a....b",
      "a..-b",
      "a/../b",
      ".hidden",
      "a/",
      "/abs",
      "x.lock",
      "a\nb",
      "a\0b",
      "x".repeat(600),
    ]) {
      expect(() => parseHistoryRange(value), value).toThrow(HistoryOptionError);
    }
  });

  it("parses the option value", () => {
    expect(parseHistoryOption(undefined)).toBeUndefined();
    expect(parseHistoryOption(false)).toBeUndefined();
    expect(parseHistoryOption(true)).toEqual({ range: null });
    expect(parseHistoryOption("main..dev")).toEqual({ range: "main..dev" });
    expect(() => parseHistoryOption("--all")).toThrow(HistoryOptionError);
    expect(() => parseHistoryOption(5)).toThrow(HistoryOptionError);
    expect(() => parseHistoryOption({})).toThrow(HistoryOptionError);
  });

  it("reads CODE_AUDIT_HISTORY_MAX_COMMITS", () => {
    expect(historyMaxCommits({}).value).toBe(DEFAULT_HISTORY_MAX_COMMITS);
    expect(historyMaxCommits({ CODE_AUDIT_HISTORY_MAX_COMMITS: "25" }).value).toBe(25);
    for (const bad of ["0", "-3", "abc", "1e3", "99999999999"]) {
      const parsed = historyMaxCommits({ CODE_AUDIT_HISTORY_MAX_COMMITS: bad });
      expect(parsed.value).toBe(DEFAULT_HISTORY_MAX_COMMITS);
      expect(parsed.warning).toBeDefined();
    }
  });
});

describe("history report parsing and deduplication (recorded report)", () => {
  // The recorded report has placeholders where Gitleaks (run without
  // --redact) puts the secret; the synthetic keys are filled in here.
  const document = JSON.parse(
    fs
      .readFileSync(path.join(RECORDED, "gitleaks-history.json"), "utf8")
      .replaceAll("__FAKE_KEY_1__", FAKE_KEY_1)
      .replaceAll("__FAKE_KEY_2__", FAKE_KEY_2),
  ) as unknown;
  const parse = () =>
    historyCandidatesFromReport(document, {
      prefix: "app/",
      version: "8.30.1",
      readWorkingFile: (file) => (file === "other.py" ? `k = "${FAKE_KEY_2}"\n` : undefined),
    });

  it("reports one finding per rule, file and secret with the earliest commit", async () => {
    const { candidates, warnings, results } = await parse();
    expect(results).toBe(7);
    expect(candidates).toHaveLength(2);
    const config = candidates.find((candidate) => candidate.finding.file === "config.py");
    const other = candidates.find((candidate) => candidate.finding.file === "other.py");
    expect(config?.history).toEqual({
      commit: "1111111111111111111111111111111111111111",
      date: "2024-01-01T10:00:00.000Z",
      occurrences: 3,
    });
    expect(config?.finding.startLine).toBe(2);
    expect(config?.finding.history?.stillPresent).toBe(false);
    expect(config?.presentInWorkingTree).toBe(false);
    expect(other?.finding.history?.stillPresent).toBe(true);
    expect(other?.presentInWorkingTree).toBe(true);
    expect(other?.workingLines).toEqual([1]);
    expect(config?.workingLines).toEqual([]);
    expect(config?.finding.ruleId).toBe("gitleaks-aws-access-token");
    expect(config?.finding.provenance.engine).toBe(HISTORY_ENGINE);
    expect(config?.finding.severity).toBe("high");
    expect(config?.finding.confidence).toBe("high");
    expect(config?.finding.remediation).toMatch(/rotate/i);
    expect(config?.finding.remediation).toMatch(/rewriting the history is not enough/);
    // Path outside the audit root and an invalid commit id are dropped.
    expect(warnings.join("\n")).toContain("unusable file path");
    expect(warnings.join("\n")).toContain("valid commit id");
    expect(candidates.some((candidate) => candidate.finding.file.includes(".."))).toBe(false);
  });

  it("never carries the secret, its hash, the author or the commit message", async () => {
    const { candidates, warnings } = await parse();
    const text = JSON.stringify([candidates.map((candidate) => candidate.finding), warnings]);
    expect(text).not.toContain(FAKE_KEY_1);
    expect(text).not.toContain(FAKE_KEY_2);
    expect(text).not.toContain("Recorded Author");
    expect(text).not.toContain("recorded-author@example.invalid");
    expect(text).not.toContain("moves the key");
    const crypto = await import("node:crypto");
    const hash = crypto.createHash("sha256").update(FAKE_KEY_1).digest("hex");
    expect(text).not.toContain(hash);
    // The evidence is the match, masked.
    const config = candidates.find((candidate) => candidate.finding.file === "config.py");
    expect(config?.finding.evidence).toMatch(/^AKIA\*+BN$/);
  });

  it("uses a stable fingerprint of rule, file and secret", async () => {
    const first = await parse();
    const second = await parse();
    const fingerprints = (result: typeof first) =>
      result.candidates.map((candidate) => candidate.finding.fingerprint).sort();
    expect(fingerprints(first)).toEqual(fingerprints(second));
    const crypto = await import("node:crypto");
    const hash = crypto.createHash("sha256").update(FAKE_KEY_1).digest("hex");
    const config = first.candidates.find((candidate) => candidate.finding.file === "config.py");
    expect(config?.finding.fingerprint).toBe(
      await historyFingerprint("gitleaks-aws-access-token", "config.py", hash),
    );
    expect(config?.finding.fingerprint).toMatch(/^[a-f0-9]{64}$/);
  });

  it("keeps results apart only when the report carries no value", async () => {
    const redacted = (document as Array<Record<string, unknown>>).map((entry) => ({
      ...entry,
      Secret: "REDACTED",
      Match: "REDACTED",
    }));
    const { candidates, warnings } = await historyCandidatesFromReport(redacted, {
      prefix: "app/",
      readWorkingFile: () => undefined,
    });
    expect(candidates.filter((candidate) => candidate.finding.file === "config.py")).toHaveLength(3);
    expect(warnings.join("\n")).toContain("carried no value");
    for (const candidate of candidates) expect(candidate.matchKey).toBeUndefined();
  });

  it("caps the number of results it processes", async () => {
    const result = await historyCandidatesFromReport(document, {
      prefix: "app/",
      readWorkingFile: () => undefined,
      maxResults: 2,
    });
    expect(result.truncated).toBe(true);
    expect(result.results).toBe(7);
    expect(result.candidates.length).toBeLessThanOrEqual(2);
    expect(result.warnings.join("\n")).toContain("only the first 2");
  });

  it("deduplicates thousands of results of one secret without any read-back (M2)", async () => {
    const entries = Array.from({ length: 2600 }, (_, index) => ({
      RuleID: "aws-access-token",
      StartLine: 1,
      EndLine: 1,
      Match: FAKE_KEY_1,
      Secret: FAKE_KEY_1,
      File: "cfg.py",
      // Newest first, as Gitleaks reports them.
      Commit: (2600 - index).toString(16).padStart(40, "0"),
      Date: new Date(Date.UTC(2024, 0, 1) + (2600 - index) * 60_000).toISOString(),
    }));
    const { candidates } = await historyCandidatesFromReport(entries, {
      prefix: "",
      readWorkingFile: () => undefined,
    });
    expect(candidates).toHaveLength(1);
    expect(candidates[0]?.history.occurrences).toBe(2600);
    expect(candidates[0]?.history.commit).toBe((1).toString(16).padStart(40, "0"));
  });

  it("takes the earliest commit from the rev-list order, not the commit id (L2)", async () => {
    const older = "f".repeat(40);
    const newer = "0".repeat(40);
    const sameDate = "2025-01-01T00:00:00Z";
    const entry = (commit: string) => ({
      RuleID: "aws-access-token",
      StartLine: 1,
      Match: FAKE_KEY_1,
      Secret: FAKE_KEY_1,
      File: "a.py",
      Commit: commit,
      Date: sameDate,
    });
    const { candidates } = await historyCandidatesFromReport([entry(newer), entry(older)], {
      prefix: "",
      readWorkingFile: () => undefined,
      commitOrder: [newer, "1".repeat(40), older],
    });
    expect(candidates[0]?.history.commit).toBe(older);
    // Without an order, the report order (newest first) decides a date tie.
    const unordered = await historyCandidatesFromReport([entry(newer), entry(older)], {
      prefix: "",
      readWorkingFile: () => undefined,
    });
    expect(unordered.candidates[0]?.history.commit).toBe(older);
  });

  it("fingerprints 5000 distinct secrets within a few seconds and honours the deadline (L3)", async () => {
    const entries = Array.from({ length: 5000 }, (_, index) => {
      const key = `${["AKIA", "SYNTH"].join("")}${index.toString().padStart(11, "0")}`;
      return {
        RuleID: "aws-access-token",
        StartLine: index + 1,
        Match: key,
        Secret: key,
        File: "many.py",
        Commit: "a".repeat(40),
        Date: "2025-01-01T00:00:00Z",
      };
    });
    const started = Date.now();
    const result = await historyCandidatesFromReport(entries, {
      prefix: "",
      readWorkingFile: () => undefined,
    });
    expect(result.candidates).toHaveLength(5000);
    expect(Date.now() - started).toBeLessThan(30_000);
    const late = await historyCandidatesFromReport(entries.slice(0, 50), {
      prefix: "",
      readWorkingFile: () => undefined,
      deadline: Date.now() - 1,
    });
    expect(late.outOfTime).toBe(true);
    expect(late.candidates.length).toBeLessThan(50);
  }, 60_000);

  it("lowers a placeholder value and honours the prefix of the audit root", async () => {
    const placeholderKey = ["AKIA", "IOSFODNN7", "EXAMPLE"].join("");
    const { candidates } = await historyCandidatesFromReport(
      [
        {
          RuleID: "aws-access-token",
          StartLine: 1,
          EndLine: 1,
          Match: placeholderKey,
          Secret: placeholderKey,
          File: "docs.py",
          Commit: "4".repeat(40),
          Date: "2024-01-01T00:00:00Z",
        },
      ],
      { prefix: "", readWorkingFile: () => undefined },
    );
    expect(candidates).toHaveLength(1);
    expect(candidates[0]?.finding.confidence).toBe("low");
    expect(candidates[0]?.finding.adjustments).toContain("placeholder-value");
  });
});

// ---------------------------------------------------------------------------
// Pipeline with a fake gitleaks

interface FakeLog {
  calls: Array<{
    args: string[];
    env: Record<string, string | undefined>;
    cwd: string;
    refs?: string;
    pid: number;
    logHasKey?: boolean;
    grandchild?: number;
  }>;
}

/**
 * A fake `gitleaks`. `git` mode: records its arguments, environment and the
 * refs of the repository it was given, runs `git log -p` there the way the
 * real tool does (so a live driver in that repository would run), and writes
 * `history.json` from its directory as the report. `detect` mode writes
 * `current.json`.
 */
function installFakeGitleaks(name: string): { dir: string; log: string } {
  const dir = path.join(temp, `fake-${name}`);
  fs.mkdirSync(dir, { recursive: true });
  const log = path.join(dir, "log.json");
  const script = path.join(dir, "fake.cjs");
  fs.writeFileSync(
    script,
    [
      "const fs = require('fs');",
      "const path = require('path');",
      "const cp = require('child_process');",
      "const args = process.argv.slice(2);",
      "if (args[0] === 'version') { process.stdout.write('8.30.1\\n'); process.exit(0); }",
      `const log = ${JSON.stringify(log)};`,
      "const entries = fs.existsSync(log) ? JSON.parse(fs.readFileSync(log, 'utf8')) : { calls: [] };",
      "const e = process.env;",
      "const call = { args, pid: process.pid, env: { GIT_CONFIG_GLOBAL: e.GIT_CONFIG_GLOBAL, GIT_CONFIG_NOSYSTEM: e.GIT_CONFIG_NOSYSTEM, GIT_ATTR_NOSYSTEM: e.GIT_ATTR_NOSYSTEM, GIT_CONFIG_COUNT: e.GIT_CONFIG_COUNT, GIT_CONFIG_KEY_0: e.GIT_CONFIG_KEY_0, GIT_NO_LAZY_FETCH: e.GIT_NO_LAZY_FETCH, GIT_NO_REPLACE_OBJECTS: e.GIT_NO_REPLACE_OBJECTS }, cwd: process.cwd() };",
      "const out = args[args.indexOf('--report-path') + 1];",
      "const keyFile = path.join(__dirname, 'key.txt');",
      "if (args[0] === 'git') {",
      "  const repo = args[1];",
      "  fs.copyFileSync(path.join(__dirname, 'history.json'), out);",
      "  call.refs = cp.spawnSync('git', ['-C', repo, 'for-each-ref', '--format=%(refname)'], { encoding: 'utf8' }).stdout;",
      "  const opts = args[args.indexOf('--log-opts') + 1].split(' ');",
      "  const logged = cp.spawnSync('git', ['-C', repo, 'log', '-p', '-U0', ...opts], { encoding: 'utf8', maxBuffer: 1 << 26 }).stdout || '';",
      "  if (fs.existsSync(keyFile)) call.logHasKey = logged.includes(fs.readFileSync(keyFile, 'utf8'));",
      "  cp.spawnSync('git', ['-C', repo, 'log', '-p', '--textconv', '--ext-diff', '-1', '--all'], { encoding: 'utf8' });",
      "} else {",
      "  const current = path.join(__dirname, 'current.json');",
      "  fs.writeFileSync(out, fs.existsSync(current) ? fs.readFileSync(current) : '[]');",
      "}",
      "const grandchildFile = path.join(__dirname, 'grandchild.txt');",
      "if (args[0] === 'git' && fs.existsSync(grandchildFile)) {",
      "  const sleeper = cp.spawn('sleep', [fs.readFileSync(grandchildFile, 'utf8').trim()], { stdio: ['ignore', 'inherit', 'inherit'] });",
      "  call.grandchild = sleeper.pid;",
      "}",
      "entries.calls.push(call);",
      "fs.writeFileSync(log, JSON.stringify(entries));",
      "const stderrFile = path.join(__dirname, 'stderr.txt');",
      "if (args[0] === 'git' && fs.existsSync(stderrFile)) process.stderr.write(fs.readFileSync(stderrFile, 'utf8'));",
      "const sleepFile = path.join(__dirname, 'sleep.txt');",
      "if (args[0] === 'git' && fs.existsSync(sleepFile)) { setTimeout(() => process.exit(0), Number(fs.readFileSync(sleepFile, 'utf8'))); }",
      "const detectSleepFile = path.join(__dirname, 'detect-sleep.txt');",
      "if (args[0] !== 'git' && fs.existsSync(detectSleepFile)) { setTimeout(() => process.exit(0), Number(fs.readFileSync(detectSleepFile, 'utf8'))); }",
    ].join("\n"),
  );
  const launcher = path.join(dir, "gitleaks");
  fs.writeFileSync(launcher, `#!/bin/sh\nexec ${JSON.stringify(process.execPath)} ${JSON.stringify(script)} "$@"\n`);
  fs.chmodSync(launcher, 0o755);
  fs.writeFileSync(path.join(dir, "history.json"), "[]");
  return { dir, log };
}

function readFakeLog(log: string): FakeLog {
  return fs.existsSync(log) ? (JSON.parse(fs.readFileSync(log, "utf8")) as FakeLog) : { calls: [] };
}

function historyEntry(
  commit: string,
  file: string,
  line: number,
  column: number,
  date: string,
  secret: string = FAKE_KEY_1,
) {
  return {
    RuleID: "aws-access-token",
    Description: "Identified a pattern that may indicate AWS credentials.",
    StartLine: line,
    EndLine: line,
    StartColumn: column,
    EndColumn: column + 19,
    Match: secret,
    Secret: secret,
    File: file,
    Commit: commit,
    Author: "Synthetic Author",
    Email: "synthetic-author@example.invalid",
    Date: date,
    Message: "synthetic message",
  };
}

const pathWith = (dir: string): string => [dir, process.env.PATH ?? ""].join(path.delimiter);

describe("history scan pipeline (fake gitleaks)", () => {
  it("reports a deleted secret once with stillPresent=false and cleans up the clone", async () => {
    const repo = newRepo("deleted");
    write(repo, "config.py", `x = 1\naws_key = "${FAKE_KEY_1}"\n`);
    const added = commitAll(repo, "add");
    fs.rmSync(path.join(repo, "config.py"));
    const removed = commitAll(repo, "remove");
    write(repo, "app.py", "print(1)\n");
    commitAll(repo, "again");
    const fake = installFakeGitleaks("deleted");
    fs.writeFileSync(
      path.join(fake.dir, "history.json"),
      JSON.stringify([historyEntry(added, "config.py", 2, 13, "2024-01-01T00:00:00Z")]),
    );
    const result = await scanProject({
      root: repo,
      out: path.join(temp, "out-deleted"),
      offline: true,
      formats: ["json", "md", "sarif"],
      engines: ["builtin", "gitleaks"],
      pathEnv: pathWith(fake.dir),
      history: true,
    });
    const history = result.findings.filter((finding) => finding.history);
    expect(history).toHaveLength(1);
    expect(history[0]?.history).toMatchObject({ commit: added, stillPresent: false, occurrences: 1 });
    expect(history[0]?.provenance.engine).toBe(HISTORY_ENGINE);
    expect(result.coverage.history?.status).toBe("ok");
    expect(result.coverage.history?.commits).toBe(3);
    expect(result.coverage.history?.findings).toBe(1);
    expect(removed).not.toBe(added);

    // Gitleaks ran on a mirror clone in a temporary directory, never on the
    // audited repository, and the clone is gone.
    const calls = readFakeLog(fake.log).calls.filter((call) => call.args[0] === "git");
    expect(calls).toHaveLength(1);
    const call = calls[0]!;
    const mirror = call.args[1] as string;
    expect(path.basename(mirror)).toBe("repo.git");
    expect(path.basename(path.dirname(mirror))).toMatch(/^code-audit-history-/);
    expect(mirror.startsWith(fs.realpathSync(repo))).toBe(false);
    expect(mirror.startsWith(repo)).toBe(false);
    expect(fs.existsSync(path.dirname(mirror))).toBe(false);
    expect(call.args[call.args.indexOf("--log-opts") + 1]).toBe(
      "--full-history --max-count=10000 --all",
    );
    // Without --redact (the value is needed in memory); the report is gone.
    expect(call.args).not.toContain("--redact");
    expect(call.env.GIT_NO_LAZY_FETCH).toBe("1");
    expect(call.env.GIT_NO_REPLACE_OBJECTS).toBe("1");
    expect(call.args).toContain("--no-banner");
    expect(call.args[call.args.indexOf("--exit-code") + 1]).toBe("0");
    expect(call.env.GIT_CONFIG_GLOBAL).toBe("/dev/null");
    expect(call.env.GIT_CONFIG_NOSYSTEM).toBe("1");
    expect(call.env.GIT_ATTR_NOSYSTEM).toBe("1");
    expect(Number(call.env.GIT_CONFIG_COUNT)).toBeGreaterThan(0);

    // Outputs: history in JSON, SARIF and Markdown; no secret, no author.
    const outputs = ["findings.json", "results.sarif", "report.md", "run.json", "coverage.json"]
      .map((name) => fs.readFileSync(path.join(result.runDir, name), "utf8"))
      .join("\n");
    expect(outputs).not.toContain(FAKE_KEY_1);
    expect(outputs).not.toContain("Synthetic Author");
    expect(outputs).not.toContain("synthetic-author@example.invalid");
    expect(outputs).not.toContain("synthetic message");
    const sarif = JSON.parse(fs.readFileSync(path.join(result.runDir, "results.sarif"), "utf8")) as {
      runs: Array<{ results: Array<{ properties: { history?: { commit: string } } }> }>;
    };
    expect(sarif.runs[0]?.results.some((entry) => entry.properties.history?.commit === added)).toBe(true);
    const markdown = fs.readFileSync(path.join(result.runDir, "report.md"), "utf8");
    expect(markdown).toContain(`added in commit \`${added.slice(0, 12)}\``);
    expect(markdown).toContain("still in the working tree: no");
    expect(markdown).toContain("Git history");
  }, 60_000);

  it("adds the history to a secret the current scan reports instead of reporting it twice", async () => {
    const repo = newRepo("present");
    write(repo, "live.py", `k = "${FAKE_KEY_2}"\n`);
    const added = commitAll(repo, "add");
    write(repo, "other.py", "print(1)\n");
    commitAll(repo, "more");
    const fake = installFakeGitleaks("present");
    fs.writeFileSync(
      path.join(fake.dir, "history.json"),
      JSON.stringify([historyEntry(added, "live.py", 1, 7, "2024-01-01T00:00:00Z", FAKE_KEY_2)]),
    );
    fs.writeFileSync(
      path.join(fake.dir, "current.json"),
      JSON.stringify([
        {
          ...historyEntry("", "live.py", 1, 7, ""),
          Match: "REDACTED",
          Secret: "REDACTED",
          Commit: "",
          Date: "",
        },
      ]),
    );
    const result = await scanProject({
      root: repo,
      out: path.join(temp, "out-present"),
      offline: true,
      formats: ["json"],
      engines: ["builtin", "gitleaks"],
      pathEnv: pathWith(fake.dir),
      history: true,
      lang: "zh",
    });
    const onLive = result.findings.filter((finding) => finding.file === "live.py");
    expect(onLive).toHaveLength(1);
    expect(onLive[0]?.history).toMatchObject({ commit: added, stillPresent: true });
    expect(onLive[0]?.provenance.engines).toContain("gitleaks");
    expect(result.coverage.history?.annotated).toBe(1);
    expect(result.coverage.history?.findings).toBe(0);
  }, 60_000);

  it("passes no repository configuration under --untrusted and marks a limit as partial", async () => {
    const repo = newRepo("untrusted");
    write(repo, ".gitleaks.toml", "title = 'repo config'\n");
    write(repo, ".gitleaksignore", "x\n");
    commitAll(repo, "one");
    write(repo, "a.py", "print(1)\n");
    commitAll(repo, "two");
    write(repo, "b.py", "print(2)\n");
    const head = commitAll(repo, "three");
    const fake = installFakeGitleaks("untrusted");
    const previous = process.env.CODE_AUDIT_HISTORY_MAX_COMMITS;
    process.env.CODE_AUDIT_HISTORY_MAX_COMMITS = "2";
    try {
      const untrusted = await scanProject({
        root: repo,
        out: path.join(temp, "out-untrusted"),
        offline: true,
        formats: ["json"],
        engines: ["builtin"],
        pathEnv: pathWith(fake.dir),
        history: "main",
        untrusted: true,
      });
      expect(untrusted.coverage.history?.status).toBe("partial");
      expect(untrusted.coverage.history?.detail).toContain("CODE_AUDIT_HISTORY_MAX_COMMITS");
      const trusted = await scanProject({
        root: repo,
        out: path.join(temp, "out-trusted"),
        offline: true,
        formats: ["json"],
        engines: ["builtin"],
        pathEnv: pathWith(fake.dir),
        history: "main",
      });
      expect(trusted.coverage.history?.status).toBe("partial");
    } finally {
      if (previous === undefined) delete process.env.CODE_AUDIT_HISTORY_MAX_COMMITS;
      else process.env.CODE_AUDIT_HISTORY_MAX_COMMITS = previous;
    }
    const calls = readFakeLog(fake.log).calls.filter((call) => call.args[0] === "git");
    expect(calls).toHaveLength(2);
    const [untrustedCall, trustedCall] = calls as [FakeLog["calls"][0], FakeLog["calls"][0]];
    expect(untrustedCall.args[untrustedCall.args.indexOf("--log-opts") + 1]).toBe(
      // The ref is resolved in the audited repository: the copy gets the id.
      `--full-history --max-count=2 ${head}`,
    );
    expect(untrustedCall.args).toContain("--ignore-gitleaks-allow");
    expect(untrustedCall.args).not.toContain("--config");
    const ignorePath = untrustedCall.args[untrustedCall.args.indexOf("--gitleaks-ignore-path") + 1] as string;
    expect(ignorePath.startsWith(fs.realpathSync(repo))).toBe(false);
    expect(trustedCall.args).toContain("--config");
    expect(trustedCall.args[trustedCall.args.indexOf("--config") + 1]).toBe(
      path.join(fs.realpathSync(repo), ".gitleaks.toml"),
    );
    expect(trustedCall.args).not.toContain("--ignore-gitleaks-allow");
  }, 60_000);

  it("is skipped without gitleaks, and fails on a non-repository or an unknown ref", async () => {
    const repo = newRepo("skipped");
    write(repo, "a.py", "print(1)\n");
    commitAll(repo, "one");
    const empty = path.join(temp, "empty-bin");
    fs.mkdirSync(empty, { recursive: true });
    const skipped = await scanProject({
      root: repo,
      out: path.join(temp, "out-skipped"),
      offline: true,
      formats: ["json"],
      engines: ["builtin"],
      pathEnv: empty,
      history: true,
    });
    expect(skipped.coverage.history?.status).toBe("skipped");
    expect(skipped.coverage.engines.find((engine) => engine.name === HISTORY_ENGINE)?.status).toBe(
      "skipped",
    );
    expect(skipped.warnings.join("\n")).toContain("history scan skipped");

    const fake = installFakeGitleaks("errors");
    await expect(
      scanProject({
        root: repo,
        out: path.join(temp, "out-unknown-ref"),
        offline: true,
        formats: ["json"],
        engines: ["builtin"],
        pathEnv: pathWith(fake.dir),
        history: "no-such-branch",
      }),
    ).rejects.toThrow(/unknown git ref/);
    // A directory inside the test temp dir is inside the worktree's own
    // repository; use the system temp directory instead.
    const outside = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "code-audit-not-repo-"));
    try {
      write(outside, "a.py", "print(1)\n");
      await expect(
        scanProject({
          root: outside,
          out: path.join(temp, "out-not-repo"),
          offline: true,
          formats: ["json"],
          engines: ["builtin"],
          pathEnv: pathWith(fake.dir),
          history: true,
        }),
      ).rejects.toThrow(GitScopeError);
    } finally {
      fs.rmSync(outside, { recursive: true, force: true });
    }
    await expect(
      scanProject({
        root: repo,
        out: path.join(temp, "out-bad-range"),
        offline: true,
        formats: ["json"],
        engines: ["builtin"],
        history: "--output=/tmp/x",
      }),
    ).rejects.toThrow(HistoryOptionError);
    expect(fs.existsSync(path.join(temp, "out-bad-range"))).toBe(false);
  }, 60_000);

  it("scans the audit root's directory of a larger repository only", async () => {
    const repo = newRepo("subdir");
    write(repo, "sub/config.py", `x = 1\naws_key = "${FAKE_KEY_1}"\n`);
    write(repo, "elsewhere/config.py", `x = 1\naws_key = "${FAKE_KEY_1}"\n`);
    const added = commitAll(repo, "add");
    const fake = installFakeGitleaks("subdir");
    fs.writeFileSync(
      path.join(fake.dir, "history.json"),
      JSON.stringify([
        historyEntry(added, "sub/config.py", 2, 13, "2024-01-01T00:00:00Z"),
        historyEntry(added, "elsewhere/config.py", 2, 13, "2024-01-01T00:00:00Z"),
      ]),
    );
    const result = await scanProject({
      root: path.join(repo, "sub"),
      out: path.join(temp, "out-subdir"),
      offline: true,
      formats: ["json"],
      engines: ["builtin"],
      pathEnv: pathWith(fake.dir),
      history: true,
    });
    const history = result.findings.filter((finding) => finding.history);
    expect(history.map((finding) => finding.file)).toEqual(["config.py"]);
    // The value is still in the working tree. Gitleaks' current scan was not
    // selected; the built-in detector reports it on that line, so that
    // finding gets the history and there is no second one.
    expect(history[0]?.history).toMatchObject({ commit: added, stillPresent: true });
    expect(history[0]?.provenance.engine).toBe("builtin-secrets");
    expect(result.findings.filter((finding) => finding.provenance.engine === HISTORY_ENGINE)).toEqual([]);
    expect(result.coverage.history?.annotated).toBe(1);
  }, 60_000);
});

describe("history scan: fixes after review (fake gitleaks)", () => {
  it("never fetches lazily from an ext:: promisor remote (H1)", async () => {
    const promisor = makeExtPromisorRepository(temp, "ext-promisor");
    const fake = installFakeGitleaks("ext-promisor");
    // A ref to a missing object: rev-parse in the audited repository.
    await expect(
      scanProject({
        root: promisor.repo,
        out: path.join(temp, "out-ext-ref"),
        offline: true,
        formats: ["json"],
        engines: ["builtin"],
        pathEnv: pathWith(fake.dir),
        history: "evil",
        untrusted: true,
      }),
    ).rejects.toThrow(/unknown git ref/);
    expect(fs.existsSync(promisor.marker)).toBe(false);
    // Every reachable commit: the clone, upload-pack, rev-list, gitleaks.
    const all = await scanProject({
      root: promisor.repo,
      out: path.join(temp, "out-ext-all"),
      offline: true,
      formats: ["json"],
      engines: ["builtin"],
      pathEnv: pathWith(fake.dir),
      history: true,
    });
    expect(fs.existsSync(promisor.marker)).toBe(false);
    expect(all.coverage.history?.status).not.toBe("ok");
    // Control: plain git does fetch lazily and runs the command.
    // (The marker program then waits on stdin; the timeout ends it.)
    spawnSync("git", ["cat-file", "-p", promisor.missingBlob], {
      cwd: promisor.repo,
      env: GIT_TEST_ENV,
      encoding: "utf8",
      input: "",
      timeout: 10_000,
      killSignal: "SIGKILL",
    });
    expect(fs.existsSync(promisor.marker)).toBe(true);
  }, 60_000);

  it("scans the commits that replace refs hide (H2)", async () => {
    const replaced = makeReplacedRepository(temp, "replaced");
    const fake = installFakeGitleaks("replaced");
    fs.writeFileSync(path.join(fake.dir, "key.txt"), FAKE_KEY_2);
    const result = await scanProject({
      root: replaced.repo,
      out: path.join(temp, "out-replaced"),
      offline: true,
      formats: ["json"],
      engines: ["builtin"],
      pathEnv: pathWith(fake.dir),
      history: true,
    });
    const call = readFakeLog(fake.log).calls.find((entry) => entry.args[0] === "git");
    expect(call?.refs).not.toContain("refs/replace/");
    expect(call?.env.GIT_NO_REPLACE_OBJECTS).toBe("1");
    // `git log -p` in the copy shows the secret of the replaced commit.
    expect(call?.logHasKey).toBe(true);
    expect(result.warnings.join("\n")).toContain("replace ref");
    // Control: in the audited repository, plain git log hides it.
    const plain = spawnSync("git", ["log", "-p", "--all"], {
      cwd: replaced.repo,
      env: GIT_TEST_ENV,
      encoding: "utf8",
    });
    expect(plain.stdout.includes(FAKE_KEY_2)).toBe(false);
  }, 60_000);

  it("fails, never ok, for a ref whose commit the copy does not have, or a git error inside gitleaks (M4)", async () => {
    const repo = newRepo("pseudo-ref");
    write(repo, "a.py", "print(1)\n");
    commitAll(repo, "one");
    write(repo, "b.py", "print(2)\n");
    commitAll(repo, "two");
    // ORIG_HEAD names a commit that no ref reaches any more.
    git(["reset", "-q", "--hard", "HEAD~1"], repo);
    const fake = installFakeGitleaks("pseudo-ref");
    const pseudo = await scanProject({
      root: repo,
      out: path.join(temp, "out-pseudo"),
      offline: true,
      formats: ["json", "md"],
      engines: ["builtin"],
      pathEnv: pathWith(fake.dir),
      history: "ORIG_HEAD",
    });
    expect(pseudo.coverage.history?.status).toBe("failed");
    expect(pseudo.coverage.history?.detail).toContain("not reachable");
    const markdown = fs.readFileSync(path.join(pseudo.runDir, "report.md"), "utf8");
    expect(markdown).toMatch(/\*\*WARNING:\*\* the git history scan is failed/);

    fs.writeFileSync(path.join(fake.dir, "stderr.txt"), '5:41PM ERR error="stderr is not empty"\n');
    const gitError = await scanProject({
      root: repo,
      out: path.join(temp, "out-gitleaks-err"),
      offline: true,
      formats: ["json"],
      engines: ["builtin"],
      pathEnv: pathWith(fake.dir),
      history: true,
    });
    expect(gitError.coverage.history?.status).toBe("failed");
    expect(gitError.coverage.history?.detail).toContain("gitleaks reported an error");
  }, 60_000);

  it("keeps deduplication and stillPresent right when the time runs out (M3)", async () => {
    const repo = newRepo("timeout");
    write(repo, "creds.txt", `aws_key = "${FAKE_KEY_1}"\n`);
    const first = commitAll(repo, "add");
    write(repo, "creds.txt", `x = 1\naws_key = "${FAKE_KEY_1}"\n`);
    const second = commitAll(repo, "move");
    const fake = installFakeGitleaks("timeout");
    fs.writeFileSync(
      path.join(fake.dir, "history.json"),
      JSON.stringify([
        historyEntry(second, "creds.txt", 2, 13, "2024-02-01T00:00:00Z"),
        historyEntry(first, "creds.txt", 1, 13, "2024-01-01T00:00:00Z"),
      ]),
    );
    fs.writeFileSync(path.join(fake.dir, "sleep.txt"), "30000");
    const result = await scanProject({
      root: repo,
      out: path.join(temp, "out-timeout"),
      offline: true,
      formats: ["json", "md"],
      engines: ["builtin"],
      pathEnv: pathWith(fake.dir),
      history: true,
      historyTimeoutMs: 6000,
    });
    expect(result.coverage.history?.status).toBe("partial");
    expect(result.coverage.history?.detail).toContain("timed out");
    const withHistory = result.findings.filter((finding) => finding.history);
    expect(withHistory).toHaveLength(1);
    expect(withHistory[0]?.history).toMatchObject({ commit: first, stillPresent: true, occurrences: 2 });
    expect(withHistory[0]?.remediation).toContain("also in the git history");
    const call = readFakeLog(fake.log).calls.find((entry) => entry.args[0] === "git");
    expect(fs.existsSync(path.dirname(call?.args[1] as string))).toBe(false);
    const markdown = fs.readFileSync(path.join(result.runDir, "report.md"), "utf8");
    expect(markdown).toMatch(/\*\*WARNING:\*\* the git history scan is partial/);
    expect(markdown).toContain("This secret is also in the git history");
  }, 60_000);

  for (const signal of ["SIGTERM", "SIGINT"] as const) {
    it(`kills gitleaks and removes the copy on ${signal} (M1)`, async () => {
      const repo = newRepo(`signal-${signal}`);
      write(repo, "a.py", `aws_key = "${FAKE_KEY_1}"\n`);
      commitAll(repo, "one");
      const fake = installFakeGitleaks(`signal-${signal}`);
      fs.writeFileSync(path.join(fake.dir, "sleep.txt"), "60000");
      const child = spawn(
        process.execPath,
        [CLI, "scan", repo, "--history", "--offline", "--no-external", "--format", "json", "--out", path.join(temp, `out-signal-${signal}`)],
        { env: { ...process.env, PATH: pathWith(fake.dir) }, stdio: "ignore" },
      );
      const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
      let call: FakeLog["calls"][0] | undefined;
      for (let attempt = 0; attempt < 200 && !call; attempt += 1) {
        await new Promise((resolve) => setTimeout(resolve, 100));
        call = readFakeLog(fake.log).calls.find((entry) => entry.args[0] === "git");
      }
      expect(call).toBeDefined();
      const tmp = path.dirname(call?.args[1] as string);
      expect(fs.existsSync(tmp)).toBe(true);
      child.kill(signal);
      await exited;
      expect(fs.existsSync(tmp)).toBe(false);
      await new Promise((resolve) => setTimeout(resolve, 300));
      expect(() => process.kill(call?.pid as number, 0)).toThrow();
    }, 60_000);
  }
});

function isAlive(pid: number | undefined): boolean {
  if (pid === undefined) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

describe("history scan: fixes after re-review (fake gitleaks)", () => {
  it("marks a depth-1 clone partial and says to fetch the full history (N1)", async () => {
    const source = newRepo("shallow-source");
    write(source, "a.py", `aws_key = "${FAKE_KEY_1}"\n`);
    commitAll(source, "secret");
    fs.rmSync(path.join(source, "a.py"));
    commitAll(source, "rm");
    write(source, "b.py", "print(1)\n");
    commitAll(source, "more");
    const shallow = path.join(temp, "shallow-ci");
    git(["-c", "protocol.file.allow=always", "clone", "-q", "--depth", "1", `file://${source}`, shallow], temp);
    const fake = installFakeGitleaks("shallow-ci");
    const result = await scanProject({
      root: shallow,
      out: path.join(temp, "out-shallow-ci"),
      offline: true,
      formats: ["json", "md"],
      engines: ["builtin"],
      pathEnv: pathWith(fake.dir),
      history: true,
    });
    expect(result.coverage.history?.status).toBe("partial");
    expect(result.coverage.history?.detail).toContain("shallow");
    expect(result.coverage.history?.detail).toContain("fetch-depth: 0");
    expect(result.coverage.history?.detail).toContain("git fetch --unshallow");
    const markdown = fs.readFileSync(path.join(result.runDir, "report.md"), "utf8");
    expect(markdown).toMatch(/\*\*WARNING:\*\* the git history scan is partial \(the repository is a shallow clone/);
  }, 60_000);

  it("marks a repository with a hand-written .git/shallow partial (N1)", async () => {
    const repo = newRepo("fake-shallow");
    write(repo, "base.txt", "x\n");
    commitAll(repo, "base");
    write(repo, "a.py", `aws_key = "${FAKE_KEY_1}"\n`);
    commitAll(repo, "secret");
    fs.rmSync(path.join(repo, "a.py"));
    const head = commitAll(repo, "rm");
    // Every object is present, but git now stops at HEAD.
    fs.writeFileSync(path.join(repo, ".git", "shallow"), `${head}\n`);
    const fake = installFakeGitleaks("fake-shallow");
    const result = await scanProject({
      root: repo,
      out: path.join(temp, "out-fake-shallow"),
      offline: true,
      formats: ["json"],
      engines: ["builtin"],
      pathEnv: pathWith(fake.dir),
      history: true,
      untrusted: true,
    });
    expect(result.coverage.history?.status).toBe("partial");
    expect(result.coverage.history?.detail).toContain("shallow");
    expect(result.warnings.join("\n")).toContain("shallow");
  }, 60_000);

  it("kills the process group on a timeout and does not wait for pipes a grandchild holds (N2)", async () => {
    const repo = newRepo("grandchild");
    write(repo, "creds.txt", `aws_key = "${FAKE_KEY_1}"\n`);
    const added = commitAll(repo, "add");
    const fake = installFakeGitleaks("grandchild");
    fs.writeFileSync(
      path.join(fake.dir, "history.json"),
      JSON.stringify([historyEntry(added, "creds.txt", 1, 13, "2024-01-01T00:00:00Z")]),
    );
    fs.writeFileSync(path.join(fake.dir, "grandchild.txt"), "60");
    const started = Date.now();
    const result = await scanProject({
      root: repo,
      out: path.join(temp, "out-grandchild"),
      offline: true,
      formats: ["json"],
      engines: ["builtin"],
      pathEnv: pathWith(fake.dir),
      history: true,
      historyTimeoutMs: 6000,
    });
    expect(Date.now() - started).toBeLessThan(20_000);
    expect(result.coverage.history?.status).toBe("partial");
    // The report was processed: the still-present key carries its history.
    const withHistory = result.findings.filter((finding) => finding.history);
    expect(withHistory).toHaveLength(1);
    expect(withHistory[0]?.history).toMatchObject({ commit: added, stillPresent: true });
    const call = readFakeLog(fake.log).calls.find((entry) => entry.args[0] === "git");
    expect(call?.grandchild).toBeDefined();
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(isAlive(call?.pid)).toBe(false);
    expect(isAlive(call?.grandchild)).toBe(false);
  }, 60_000);

  it("leaves no tool running when the host kills the scanner's process group with SIGKILL (N4)", async () => {
    const repo = newRepo("group-kill");
    write(repo, "a.py", `aws_key = "${FAKE_KEY_1}"\n`);
    commitAll(repo, "one");
    const fake = installFakeGitleaks("group-kill");
    fs.writeFileSync(path.join(fake.dir, "sleep.txt"), "60000");
    fs.writeFileSync(path.join(fake.dir, "detect-sleep.txt"), "60000");
    fs.writeFileSync(path.join(fake.dir, "grandchild.txt"), "60");
    // The CLI leads its own process group, like a server started by a host.
    const child = spawn(
      process.execPath,
      [CLI, "scan", repo, "--history", "--offline", "--engines", "builtin,gitleaks", "--format", "json", "--out", path.join(temp, "out-group-kill")],
      { env: { ...process.env, PATH: pathWith(fake.dir) }, stdio: "ignore", detached: true },
    );
    const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
    let calls: FakeLog["calls"] = [];
    // Wait until both tools run; on a slow host the working-tree scan may
    // still be queued behind the history scan, so one running tool is enough.
    for (let attempt = 0; attempt < 400 && calls.length < 2; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 100));
      calls = readFakeLog(fake.log).calls;
    }
    expect(calls.length).toBeGreaterThanOrEqual(1);
    for (const call of calls) expect(["detect", "git"]).toContain(call.args[0]);
    const pids = calls.flatMap((call) => [call.pid, ...(call.grandchild ? [call.grandchild] : [])]);
    for (const pid of pids) expect(isAlive(pid)).toBe(true);
    process.kill(-(child.pid as number), "SIGKILL");
    await exited;
    await new Promise((resolve) => setTimeout(resolve, 500));
    for (const pid of pids) expect(isAlive(pid), String(pid)).toBe(false);
  }, 90_000);

  it("kills the working-tree gitleaks and removes its report on SIGTERM (N3)", async () => {
    const repo = newRepo("detect-signal");
    write(repo, "a.py", "print(1)\n");
    commitAll(repo, "one");
    const fake = installFakeGitleaks("detect-signal");
    fs.writeFileSync(path.join(fake.dir, "detect-sleep.txt"), "60000");
    const child = spawn(
      process.execPath,
      [CLI, "scan", repo, "--offline", "--engines", "builtin,gitleaks", "--format", "json", "--out", path.join(temp, "out-detect-signal")],
      { env: { ...process.env, PATH: pathWith(fake.dir) }, stdio: "ignore" },
    );
    const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
    let call: FakeLog["calls"][0] | undefined;
    for (let attempt = 0; attempt < 200 && !call; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 100));
      call = readFakeLog(fake.log).calls.find((entry) => entry.args[0] === "detect");
    }
    expect(call).toBeDefined();
    const report = call?.args[call.args.indexOf("--report-path") + 1] as string;
    expect(fs.existsSync(report)).toBe(true);
    child.kill("SIGTERM");
    await exited;
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(fs.existsSync(report)).toBe(false);
    expect(isAlive(call?.pid)).toBe(false);
  }, 60_000);
});

describe("history scan of a hostile repository (fake gitleaks)", () => {
  it("runs none of the programs the repository configures and sees hidden refs", async () => {
    const hostile = makeHostileRepository("hostile-fake");
    const fake = installFakeGitleaks("hostile");
    const result = await scanProject({
      root: hostile.repo,
      out: path.join(temp, "out-hostile"),
      offline: true,
      formats: ["json"],
      engines: ["builtin", "gitleaks"],
      pathEnv: pathWith(fake.dir),
      history: true,
    });
    expect(fs.existsSync(hostile.marker)).toBe(false);
    expect(result.coverage.history?.status).toBe("ok");
    // `uploadpack.hideRefs` in the audited repository did not hide a ref.
    const call = readFakeLog(fake.log).calls.find((entry) => entry.args[0] === "git");
    expect(call?.refs).toContain("refs/hidden/side");
    expect(call?.refs).toContain("refs/heads/main");

    // Control: the configuration is live - plain git runs the program.
    spawnSync("git", ["log", "-p", "-1", "--textconv", "--", "a.py"], {
      cwd: hostile.repo,
      env: GIT_TEST_ENV,
      encoding: "utf8",
    });
    expect(fs.existsSync(hostile.marker)).toBe(true);
  }, 60_000);
});

describe("CLI --history", () => {
  it("rejects injected ranges with exit code 2 and writes nothing", () => {
    const repo = newRepo("cli");
    write(repo, "a.py", "print(1)\n");
    commitAll(repo, "one");
    const target = path.join(temp, "cli-injected-x");
    for (const value of [`--output=${target}`, "a;b", "$(id)", "a..b..c"]) {
      const out = path.join(temp, "cli-out");
      const result = spawnSync(
        process.execPath,
        [CLI, "scan", repo, "--offline", "--no-external", `--history=${value}`, "--out", out],
        { encoding: "utf8" },
      );
      expect(result.status, value).toBe(2);
      expect(result.stderr).toContain("--history");
      expect(fs.existsSync(target)).toBe(false);
      expect(fs.existsSync(out)).toBe(false);
    }
  }, 60_000);

  it("does not take the next argument as a range", () => {
    const repo = newRepo("cli-bare");
    write(repo, "a.py", "print(1)\n");
    commitAll(repo, "one");
    const result = spawnSync(
      process.execPath,
      [CLI, "scan", "--history", repo, "--offline", "--no-external", "--format", "json", "--out", path.join(temp, "cli-bare-out")],
      { encoding: "utf8" },
    );
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("Git history:");
  }, 60_000);
});
