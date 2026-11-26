import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { afterAll, describe, expect, it } from "vitest";
import { BaselineError, resolveBaselineOutput } from "../src/baseline.js";
import type { Finding } from "../src/finding.js";
import { isOwnOutputFile, listChangedFiles } from "../src/git.js";
import { loadRules, scanRules } from "../src/rules.js";
import { inventory } from "../src/inventory.js";
import {
  RunStoreError,
  effectiveFindings,
  effectiveHotspots,
  loadRun,
  recordVerdict,
  resolveRunDir,
} from "../src/runstore.js";
import { scanProject } from "../src/scan.js";
import { CLI, REPO_ROOT, RULES_DIR, VULNERABLE, cleanup, makeTempDir, writeFile } from "./helpers.js";

const temp = makeTempDir("trust");

afterAll(() => cleanup(temp));

function git(args: string[], cwd: string): void {
  const result = spawnSync("git", args, {
    cwd,
    encoding: "utf8",
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: "test",
      GIT_AUTHOR_EMAIL: "test@example.invalid",
      GIT_COMMITTER_NAME: "test",
      GIT_COMMITTER_EMAIL: "test@example.invalid",
    },
  });
  if (result.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed: ${result.stderr}`);
  }
}

function cli(args: string[], cwd = REPO_ROOT) {
  return spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: "utf8", timeout: 60_000 });
}

// ---------------------------------------------------------------------------
// GitHub Actions: expressions are code only inside run: / script:
// ---------------------------------------------------------------------------

describe("withinKeys", () => {
  it("is validated by the rule schema", () => {
    const dir = path.join(temp, "rules-within");
    const rule = (extra: string): string =>
      [
        "version: 1",
        "rules:",
        "  - id: t-within",
        "    title: t",
        "    severity: low",
        "    confidence: low",
        "    cwe: CWE-94",
        "    pattern: x",
        "    message: m",
        "    remediation: r",
        extra,
        "",
      ].join("\n");
    writeFile(dir, "ok/r.yml", rule("    languages: [yaml]\n    withinKeys: [run, script]"));
    expect(loadRules(path.join(dir, "ok")).rules[0]?.withinKeys).toEqual(["run", "script"]);
    writeFile(dir, "lang/r.yml", rule("    languages: [yaml, json]\n    withinKeys: [run]"));
    expect(() => loadRules(path.join(dir, "lang"))).toThrow(/withinKeys is only supported/);
    writeFile(dir, "empty/r.yml", rule("    languages: [yaml]\n    withinKeys: []"));
    expect(() => loadRules(path.join(dir, "empty"))).toThrow(/withinKeys/);
    writeFile(dir, "bad/r.yml", rule('    languages: [yaml]\n    withinKeys: ["a b"]'));
    expect(() => loadRules(path.join(dir, "bad"))).toThrow(/plain YAML keys/);
  });
});

describe("gha-script-injection", () => {
  const ruleSet = loadRules(RULES_DIR);
  const scanWorkflow = (name: string, lines: string[]) => {
    const root = path.join(temp, name);
    writeFile(root, ".github/workflows/w.yml", `${lines.join("\n")}\n`);
    const result = scanRules(inventory(root).files, ruleSet, { inlineIgnore: false });
    return result.hits
      .filter((hit) => hit.rule.id.startsWith("gha-") && hit.rule.id !== "gha-pull-request-target")
      .map((hit) => `${hit.line} ${hit.rule.id} ${hit.rule.kind} ${hit.rule.severity}/${hit.rule.confidence}`)
      .sort((a, b) => Number.parseInt(a, 10) - Number.parseInt(b, 10));
  };

  it("does not fire on expressions passed as data", () => {
    // The httpie and flask shapes: with: inputs, concurrency:, env:, if:.
    expect(
      scanWorkflow("gha-data", [
        "on:",
        "  workflow_dispatch:",
        "    inputs:",
        "      branch: {}",
        "  pull_request:",
        "concurrency: ${{ github.event.inputs.branch }}",
        "jobs:",
        "  a:",
        "    concurrency:",
        "      group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}",
        "    if: ${{ github.event.pull_request.title != 'x' }}",
        "    env:",
        "      TITLE: ${{ github.event.pull_request.title }}",
        "    steps:",
        "      - uses: actions/checkout@v4",
        "        with:",
        "          ref: ${{ github.event.inputs.branch }}",
        "      - uses: peter-evans/create-or-update-comment@v4",
        "        with:",
        "          issue-number: ${{ github.event.pull_request.number }}",
        "          body: ${{ github.event.pull_request.body }}",
        "      - uses: actions/upload-release-asset@v1",
        "        with:",
        "          asset_name: httpie-${{ github.event.inputs.tag_name }}.deb",
        "      - name: safe",
        "        env:",
        "          ISSUE_URL: ${{ github.event.issue.html_url }}",
        '        run: gh issue close "$ISSUE_URL" --comment "$TITLE"',
      ]),
    ).toEqual([]);
  });

  it("applies the severity policy inside run: and script: bodies", () => {
    expect(
      scanWorkflow("gha-code", [
        "on:", //                                                                   1
        "  workflow_dispatch:", //                                                  2
        "    inputs:", //                                                           3
        "      tag: {}", //                                                         4
        "jobs:", //                                                                 5
        "  a:", //                                                                  6
        "    steps:", //                                                            7
        '      - run: echo "${{ github.event.issue.title }}"', //                   8
        "      - name: block", //                                                   9
        "        run: |", //                                                       10
        "          echo start", //                                                 11
        '          echo "${{ github.event.comment.body }}"', //                    12
        "", //                                                                     13
        '          echo "${{ github.head_ref }}"', //                              14
        '          echo "${{ github.event.pull_request.number }}"', //             15
        '          echo "${{ github.event.pull_request.head.sha }} ${{ github.event.issue.id }}"', // 16
        '          export API="releases/tags/${{ github.event.inputs.tag }}"', //  17
        '          echo "${{ inputs.tag }}"', //                                   18
        '          echo "${{ github.event.issue.html_url }}"', //                  19
        '          echo "${{ steps.x.inputs.tag }} ${{ matrix.inputs.tag }}"', //  20
        "        env:", //                                                         21
        "          BODY: ${{ github.event.issue.body }}", //                       22
        "      - run: >-", //                                                      23
        "          echo ${{ github.event.head_commit.message }}", //               24
        '      - { name: flow, run: "echo ${{ github.event.review.body }}" }', //  25
        "      - uses: actions/github-script@v7", //                               26
        "        with:", //                                                        27
        "          script: |", //                                                  28
        '            console.log("${{ github.event.discussion.title }}")', //      29
        "          retries: ${{ github.event.issue.title }}", //                   30
        '      - run: echo "${{ github.event.pull_request.number || github.event.pull_request.head.ref }}"', // 31
        '      - run: echo "${{ github.event.commits[0].message }} ${{ github.event.pages.*.page_name }}"', // 32
        '      - run: echo "${{ toJSON(github.event) }}"', //                      33
      ]),
    ).toEqual([
      "8 gha-script-injection finding high/high",
      "12 gha-script-injection finding high/high",
      "14 gha-script-injection finding high/high",
      "17 gha-script-injection-input finding medium/medium",
      "18 gha-script-injection-input finding medium/medium",
      "19 gha-event-field-in-script hotspot medium/low",
      "24 gha-script-injection finding high/high",
      "25 gha-script-injection finding high/high",
      "29 gha-script-injection finding high/high",
      "31 gha-script-injection finding high/high",
      "32 gha-script-injection finding high/high",
      "33 gha-event-field-in-script hotspot medium/low",
    ]);
  });

  it("reports an input as a hotspot only when the workflow cannot be dispatched", () => {
    expect(
      scanWorkflow("gha-no-dispatch", [
        "on: push",
        "jobs:",
        "  a:",
        "    steps:",
        '      - run: echo "${{ github.event.inputs.tag }}"',
        '      - run: echo "${{ inputs.tag }}"',
      ]),
    ).toEqual(["5 gha-event-field-in-script hotspot medium/low"]);
  });

  it("still sees a script whose text is reached through a YAML alias", () => {
    expect(
      scanWorkflow("gha-alias", [
        "on: issues",
        'x-cmd: &cmd echo "${{ github.event.issue.title }}"',
        "jobs:",
        "  a:",
        "    steps:",
        "      - run: *cmd",
      ]),
    ).toEqual(["2 gha-script-injection finding high/high"]);
  });
});

// ---------------------------------------------------------------------------
// --since must not count the tool's own output
// ---------------------------------------------------------------------------

describe("--since and the tool's own files", () => {
  function makeRepo(name: string): string {
    const repo = path.join(temp, name);
    writeFile(repo, "app.py", 'import os\n\n\ndef run(c):\n    os.system("ls " + c)\n');
    git(["init", "-q"], repo);
    git(["add", "-A"], repo);
    git(["commit", "-qm", "init"], repo);
    return repo;
  }

  it("classifies own output narrowly", () => {
    const root = path.join(temp, "own-unit");
    const out = path.join(root, "audit-out");
    writeFile(root, "audit-out/20260101T000000Z-aaaaaaaa/run.json", "{}");
    writeFile(root, "audit-out/notarun/report.md", "x");
    const own = (file: string, untracked = true, outputDir: string | null = out): boolean =>
      isOwnOutputFile(root, file, { untracked, outputDir: outputDir ?? undefined });
    expect(own(".audit/index.json")).toBe(true);
    expect(own(".audit/20260101T000000Z-aaaaaaaa/report.md", false, null)).toBe(true);
    expect(own(".code-audit-baseline.json", false, null)).toBe(true);
    expect(own(".code-audit-ignore", false, null)).toBe(true);
    expect(own("audit-out/20260101T000000Z-aaaaaaaa/report.md")).toBe(true);
    expect(own("audit-out/latest/results.sarif")).toBe(true);
    // Not the root-level control file, not a known output name, not a run
    // directory, tracked by git, or no output directory inside the root.
    expect(own("sub/.code-audit-ignore")).toBe(false);
    expect(own("sub/.audit/x.py")).toBe(false);
    expect(own("audit-out/20260101T000000Z-aaaaaaaa/evil.py")).toBe(false);
    expect(own("audit-out/20260101T000000Z-aaaaaaaa/sub/report.md")).toBe(false);
    expect(own("audit-out/notarun/report.md")).toBe(false);
    expect(own("audit-out/latest/evil.py")).toBe(false);
    expect(own("audit-out/20260101T000000Z-aaaaaaaa/report.md", false)).toBe(false);
    expect(own("audit-out/20260101T000000Z-aaaaaaaa/report.md", true, null)).toBe(false);
    expect(own("audit-out/20260101T000000Z-aaaaaaaa/report.md", true, path.join(temp, "elsewhere"))).toBe(false);
    expect(own("app.py")).toBe(false);
  });

  it("keeps the changed-file count stable across runs with the default output", async () => {
    const repo = makeRepo("since-default");
    const counts: number[] = [];
    for (let round = 0; round < 3; round += 1) {
      const result = await scanProject({
        root: repo,
        offline: true,
        engines: ["builtin"],
        since: "HEAD",
        formats: ["json", "md", "sarif"],
        latestLink: true,
      });
      counts.push((result.run as { scope: { changedFiles: number } }).scope.changedFiles);
    }
    // .audit/ is not git-ignored in this repository and nothing else changed.
    expect(fs.existsSync(path.join(repo, ".audit", "index.json"))).toBe(true);
    expect(counts).toEqual([0, 0, 0]);
  });

  it("does the same for --out inside the root, a baseline and an ignore file", async () => {
    const repo = makeRepo("since-out");
    writeFile(repo, ".code-audit-ignore", 'version: 1\nignore:\n  - rule: "py-nothing"\n    reason: "none"\n');
    writeFile(repo, "new.py", 'import os\n\n\ndef go(c):\n    os.system("rm " + c)\n');
    const counts: number[] = [];
    let last: Awaited<ReturnType<typeof scanProject>> | undefined;
    for (let round = 0; round < 3; round += 1) {
      last = await scanProject({
        root: repo,
        out: path.join(repo, "audit-out"),
        offline: true,
        engines: ["builtin"],
        since: "HEAD",
        formats: ["json", "md", "sarif"],
        latestLink: true,
      });
      counts.push((last.run as { scope: { changedFiles: number } }).scope.changedFiles);
      if (round === 0) {
        fs.writeFileSync(path.join(repo, ".code-audit-baseline.json"), '{"schemaVersion":1,"createdAt":"x","tool":"t","entries":[]}\n');
      }
    }
    expect(counts).toEqual([1, 1, 1]);
    const reported = [...(last?.findings ?? []), ...(last?.hotspots ?? [])];
    expect([...new Set(reported.map((finding) => finding.file))]).toEqual(["new.py"]);
    const changed = await listChangedFiles(repo, "HEAD", { outputDir: path.join(repo, "audit-out") });
    expect(changed.files).toEqual(["new.py"]);
    // Without the hint the output directory is ordinary project content.
    const unhinted = await listChangedFiles(repo, "HEAD");
    expect(unhinted.files.some((file) => file.startsWith("audit-out/"))).toBe(true);
    expect(unhinted.files).not.toContain(".code-audit-ignore");
    expect(unhinted.files).not.toContain(".code-audit-baseline.json");
  });

  it("keeps repository files in the output directory in scope", async () => {
    // A hostile repository cannot use the output directory as a hiding place:
    // tracked files, unknown names and non-run directories still count.
    const repo = makeRepo("since-hostile");
    const out = path.join(repo, "audit-out");
    writeFile(repo, "audit-out/planted/run.json", "{}\n");
    writeFile(repo, "audit-out/planted/report.md", "tracked report\n");
    git(["add", "-A"], repo);
    git(["commit", "-qm", "plant"], repo);
    fs.appendFileSync(path.join(repo, "audit-out/planted/report.md"), "changed\n");
    writeFile(repo, "audit-out/planted/evil.py", 'import os\n\n\ndef go(c):\n    os.system("rm " + c)\n');
    writeFile(repo, "audit-out/latest/evil.py", 'import os\n\n\ndef go(c):\n    os.system("rm " + c)\n');
    const result = await scanProject({
      root: repo,
      out,
      offline: true,
      engines: ["builtin"],
      since: "HEAD",
      formats: ["json"],
    });
    const changed = await listChangedFiles(repo, "HEAD", { outputDir: out });
    expect(changed.files).toEqual([
      "audit-out/latest/evil.py",
      "audit-out/planted/evil.py",
      "audit-out/planted/report.md",
    ]);
    const reported = [...result.findings, ...result.hotspots];
    expect([...new Set(reported.map((finding) => finding.file))].sort()).toEqual([
      "audit-out/latest/evil.py",
      "audit-out/planted/evil.py",
    ]);
  });
});

// ---------------------------------------------------------------------------
// baseline <run> and the root recorded in run.json
// ---------------------------------------------------------------------------

describe("baseline target and the recorded root", () => {
  it("uses only the root derived from the run's location, or an explicit output", () => {
    const root = fs.realpathSync(fs.mkdtempSync(path.join(temp, "bt-root-")));
    const copy = path.join(temp, "bt-copy", "r3");
    fs.mkdirSync(copy, { recursive: true });

    // `<root>/.audit/<run>`: the caller passes the derived root.
    expect(resolveBaselineOutput({ runDir: path.join(root, ".audit", "r1"), root })).toBe(
      path.join(root, ".code-audit-baseline.json"),
    );
    // No derived root (an external --out, a copy): nothing recorded in the
    // run can stand in for it.
    expect(() => resolveBaselineOutput({ runDir: copy })).toThrow(BaselineError);
    expect(() => resolveBaselineOutput({ runDir: copy })).toThrow(/--output <file>/);
    // An explicit output is always honoured.
    const explicit = path.join(temp, "bt-explicit.json");
    expect(resolveBaselineOutput({ runDir: copy, output: explicit })).toBe(explicit);
  });

  it("CLI: refuses a copied run directory with exit 2 and writes nothing", () => {
    const project = path.join(temp, "baseline-project");
    fs.cpSync(VULNERABLE, project, { recursive: true });
    const other = path.join(temp, "baseline-other-project");
    fs.mkdirSync(other, { recursive: true });

    const scan = cli(["scan", project, "--offline", "--no-external", "--format", "json", "--out", path.join(temp, "baseline-out")]);
    expect(scan.status).toBe(1);
    const runDir = /^Report directory: (.+)$/m.exec(scan.stdout)?.[1]?.trim() ?? "";
    expect(runDir).not.toBe("");

    // Copy the run into another project and stand there.
    const copied = path.join(other, "audit-out", path.basename(runDir));
    fs.cpSync(runDir, copied, { recursive: true });
    const refused = cli(["baseline", copied], other);
    expect(refused.status).toBe(2);
    expect(refused.stderr).toContain("refusing to write a baseline");
    expect(refused.stderr).toContain("--output <file>");
    expect(refused.stderr).not.toContain("Usage:");
    expect(refused.stdout).not.toContain("baseline written");
    expect(fs.existsSync(path.join(project, ".code-audit-baseline.json"))).toBe(false);
    expect(fs.existsSync(path.join(other, ".code-audit-baseline.json"))).toBe(false);

    // With --output the user decides, relative to where they stand.
    const explicit = cli(["baseline", copied, "--output", "my-baseline.json"], other);
    expect(explicit.status).toBe(0);
    expect(fs.existsSync(path.join(other, "my-baseline.json"))).toBe(true);
    expect(fs.existsSync(path.join(project, ".code-audit-baseline.json"))).toBe(false);

    // The original run sits in an external --out directory: where it is does
    // not show which project it belongs to, so it needs --output as well.
    const external = cli(["baseline", runDir]);
    expect(external.status).toBe(2);
    expect(external.stderr).toContain("--output <file>");
    expect(fs.existsSync(path.join(project, ".code-audit-baseline.json"))).toBe(false);

    // ... and a run in the project's own .audit/, addressed by id.
    const local = cli(["scan", project, "--offline", "--no-external", "--format", "json", "--no-baseline"]);
    const localDir = /^Report directory: (.+)$/m.exec(local.stdout)?.[1]?.trim() ?? "";
    const byId = cli(["baseline", path.basename(localDir)], project);
    expect(byId.status).toBe(0);
    expect(fs.existsSync(path.join(project, ".code-audit-baseline.json"))).toBe(true);
  });
});

describe("run index and the run directory it names", () => {
  it("does not follow an index entry that points outside <root>/.audit", async () => {
    // A real run of project A ...
    const victim = path.join(temp, "index-victim");
    writeFile(victim, "app.py", 'import os\n\n\ndef run(c):\n    os.system("ls " + c)\n');
    const scanned = await scanProject({
      root: victim,
      out: path.join(temp, "index-victim-out"),
      offline: true,
      engines: ["builtin"],
      formats: ["json"],
    });
    // ... and a repository whose committed index names that directory.
    const hostile = path.join(temp, "index-hostile");
    writeFile(
      hostile,
      ".audit/index.json",
      JSON.stringify({
        schemaVersion: 1,
        runs: [
          {
            runId: "planted",
            runDir: scanned.runDir,
            root: victim,
            phase: "complete",
            startedAt: "2026-01-01T00:00:00.000Z",
            updatedAt: "2026-01-01T00:00:00.000Z",
          },
        ],
      }),
    );
    expect(() => resolveRunDir("planted", { cwd: hostile })).toThrow(RunStoreError);
    expect(() =>
      recordVerdict(
        "planted",
        [...scanned.findings, ...scanned.hotspots][0]?.id ?? "",
        { status: "false_positive", rationale: "planted" },
        { cwd: hostile },
      ),
    ).toThrow(/refusing to use it as a run directory/);
    expect(fs.existsSync(path.join(scanned.runDir, "verdicts.json"))).toBe(false);

    // The index of a project still resolves that project's own runs.
    const own = await scanProject({ root: victim, offline: true, engines: ["builtin"], formats: ["json"] });
    expect(resolveRunDir(own.runId, { cwd: path.join(temp, "elsewhere"), roots: [victim] })).toBe(own.runDir);
  });
});

// ---------------------------------------------------------------------------
// Suppressed findings carry what a SARIF `suppressions` entry needs
// ---------------------------------------------------------------------------

describe("suppression data", () => {
  it("gives every suppressed result a source and a reason, through every reader", async () => {
    const root = path.join(temp, "suppression");
    writeFile(
      root,
      "app.py",
      [
        "import os",
        "import subprocess",
        "",
        "",
        "def run(c):",
        '    os.system("ls " + c)  # code-audit:ignore py-command-injection py-os-system-api -- reviewed, c is a constant',
        "    subprocess.run(c, shell=True)  # code-audit:ignore *",
        "    c = c.strip()",
        '    os.system("rm " + c)',
        "",
      ].join("\n"),
    );
    writeFile(root, "legacy/old.py", 'import os\n\n\ndef run(c):\n    os.system("ls " + c)\n');
    writeFile(
      root,
      ".code-audit-ignore",
      ["version: 1", "ignore:", '  - paths: ["legacy/**"]', '    reason: "frozen code"', '    expires: "2099-01-01"', ""].join("\n"),
    );
    const result = await scanProject({
      root,
      out: path.join(temp, "suppression-out"),
      offline: true,
      engines: ["builtin"],
      noBaseline: true,
      formats: ["json", "sarif"],
    });

    const check = (items: Finding[]): Finding[] => {
      const suppressed = items.filter((item) => item.status === "suppressed" || item.suppression !== undefined);
      for (const item of suppressed) {
        expect(item.status).toBe("suppressed");
        expect(["inline", "ignore-file"]).toContain(item.suppression?.source);
        expect(typeof item.suppression?.reason).toBe("string");
        expect(typeof item.ruleId).toBe("string");
        expect(item.fingerprint).toMatch(/^[a-f0-9]{64}$/);
        if (item.suppression?.source === "ignore-file") {
          expect(item.suppression.reason).toBe("frozen code");
          expect(item.suppression.entry).toBe(0);
          expect(item.suppression.expires).toBe("2099-01-01");
        }
      }
      return suppressed;
    };
    const inMemory = check([...result.findings, ...result.hotspots]);
    const sources = inMemory.map((item) => item.suppression?.source);
    expect(sources).toContain("inline");
    expect(sources).toContain("ignore-file");
    const inlineReasons = inMemory
      .filter((item) => item.suppression?.source === "inline")
      .map((item) => item.suppression?.reason);
    expect(inlineReasons).toContain("reviewed, c is a constant");
    // An inline comment without a reason is still a suppression record.
    expect(inlineReasons).toContain("");
    // The unsuppressed line stays active.
    expect(
      [...result.findings, ...result.hotspots].some(
        (finding) => finding.file === "app.py" && finding.startLine === 9 && finding.status === "candidate",
      ),
    ).toBe(true);

    // findings.json on disk ...
    const envelope = JSON.parse(fs.readFileSync(path.join(result.runDir, "findings.json"), "utf8")) as {
      findings: Finding[];
      hotspots: Finding[];
    };
    expect(check([...envelope.findings, ...envelope.hotspots])).toHaveLength(inMemory.length);

    // ... and the run store, which the report commands render from. A verdict
    // changes the status, the suppression record stays.
    const target = inMemory[0] as Finding;
    recordVerdict(result.runDir, target.fingerprint, { status: "false_positive", rationale: "the value is a constant and never user input; see python/app.py:12 for the assignment" });
    const loaded = loadRun(result.runDir);
    const effective = [...effectiveFindings(loaded), ...effectiveHotspots(loaded)];
    const withRecord = effective.filter((item) => item.suppression !== undefined);
    expect(withRecord).toHaveLength(inMemory.length);
    const reviewed = effective.find((item) => item.fingerprint === target.fingerprint);
    expect(reviewed?.status).toBe("false_positive");
    expect(reviewed?.suppression).toEqual(target.suppression);
  });
});
