/**
 * Regression tests for the second adversarial review.
 *
 * Detection: the Python lexer fails open (it matches more text when unsure,
 * and warns about anything it does not match as usual).
 * Output: no secret literal reaches any output.
 */
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { afterAll, describe, expect, it } from "vitest";
import { disambiguateFingerprints } from "../src/finding.js";
import { inventory } from "../src/inventory.js";
import { maskSecret, redactLine, redactText, splitLines } from "../src/redact.js";
import {
  MAX_LOGICAL_LINE_SPAN,
  MAX_PATTERN_LINE_LENGTH,
  emptyLexDiagnostics,
  loadRules,
  pythonLogicalLines,
  scanRules,
} from "../src/rules.js";
import { addFinding, readSnippet, searchCode } from "../src/runstore.js";
import { scanProject } from "../src/scan.js";
import { scanSecrets } from "../src/secrets.js";
import { CLI, REPO_ROOT, RULES_DIR, cleanup, makeTempDir, readAllOutputFiles, writeFile } from "./helpers.js";

const temp = makeTempDir("review2");
afterAll(() => cleanup(temp));

const ruleSet = loadRules(RULES_DIR);

function scanSource(name: string, files: Record<string, string>) {
  const project = path.join(temp, name);
  for (const [rel, content] of Object.entries(files)) writeFile(project, rel, content);
  const result = scanRules(inventory(project).files, ruleSet);
  return {
    project,
    result,
    rows: result.hits.map((hit) => `${hit.file.relPath}:${hit.line}:${hit.rule.id}`).sort(),
  };
}

function cli(args: string[]) {
  return spawnSync(process.execPath, [CLI, ...args], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    timeout: 60_000,
  });
}

describe("review 2 / detection: the Python lexer fails open", () => {
  it("1. does not take a keyword for a string prefix (one line no longer blacks out the file)", () => {
    const source = [
      "import os, subprocess",
      'y = 1 if"""{""" else 2',
      "def f(cmd):",
      "    os.system(cmd)",
      "    subprocess.run(cmd, shell=True)",
      "    eval(cmd)",
      "",
    ].join("\n");
    const { rows, result } = scanSource("phantom-prefix", { "black.py": source });
    expect(rows).toEqual([
      "black.py:4:py-os-system-api",
      "black.py:5:py-subprocess-shell",
      "black.py:6:py-eval-api",
    ]);
    expect(result.warnings).toEqual([]);
    // Every statement is its own unit: nothing is swallowed by a phantom string.
    const units = pythonLogicalLines(splitLines(source));
    expect(units.every((unit) => unit.offsets.length === 1)).toBe(true);
    // Real prefixes are still prefixes, in any case and combination; anything
    // else before a quote is code.
    for (const prefix of ["r", "u", "b", "f", "t", "Rb", "bR", "fr", "RF", "tr"]) {
      const docstring = pythonLogicalLines([`${prefix}"""only a string"""`]);
      expect(docstring[0]?.text, prefix).toBe("");
    }
    for (const word of ["if", "in", "or", "x", "fb", "ur"]) {
      const code = pythonLogicalLines([`a = b ${word}"""{"""`, "os.system(cmd)"]);
      expect(code.map((unit) => unit.text), word).toEqual([`a = b ${word}"""{"""`, "os.system(cmd)"]);
    }
  });

  it("1. matches the region again as plain text when the file ends inside a string or a bracket", () => {
    const { rows, result } = scanSource("eof-fallback", {
      "open_string.py": ["import os", 'x = """', "os.system(cmd)", "eval(cmd)", ""].join("\n"),
      "open_bracket.py": ["import os", "def f(cmd): pass", "broken = (", "    os.system(cmd)", ""].join("\n"),
    });
    expect(rows).toEqual([
      "open_bracket.py:4:py-os-system-api",
      "open_string.py:3:py-os-system-api",
      "open_string.py:4:py-eval-api",
    ]);
    expect(result.warnings.filter((warning) => warning.includes("open_string.py"))).toEqual([
      "python lexer fallback in open_string.py from line 2 to line 5: the file ends inside a triple-quoted string; these lines were also matched as plain text",
    ]);
    expect(result.warnings.some((warning) =>
      warning.startsWith("python lexer fallback in open_bracket.py from line 3"),
    )).toBe(true);
  });

  it("1. falls back when two quote scans disagree and when a long 'string' keeps looking like code", () => {
    // A triple-quoted string inside a replacement field of a single-quoted
    // f-string: valid from Python 3.12 on, and exactly the kind of construct
    // the lexer could get wrong. The body is matched as plain text too.
    const nested = ["import os", "x = f\"{'''", "os.system(cmd)", "'''}\"", "y = 1", ""].join("\n");
    // 80 statements between triple quotes.
    const long = ["import os", 'HELP = """'];
    for (let index = 0; index < 80; index += 1) long.push(`value_${index} = os.system(cmd_${index})`);
    long.push('"""', "");
    // A long docstring of prose is left alone.
    const prose = ['"""Module docstring.', ""];
    for (let index = 0; index < 120; index += 1) prose.push(`Sentence number ${index} of the documentation.`);
    prose.push('"""', "x = 1", "");
    const { result } = scanSource("heuristic-fallback", {
      "nested.py": nested,
      "long.py": long.join("\n"),
      "prose.py": prose.join("\n"),
    });
    const lines = (file: string): number[] =>
      result.hits.filter((hit) => hit.file.relPath === file).map((hit) => hit.line);
    expect(lines("nested.py")).toEqual([3]);
    expect(lines("long.py")).toHaveLength(80);
    expect(lines("prose.py")).toEqual([]);
    expect(result.warnings.filter((warning) => warning.startsWith("python lexer fallback")).sort()).toEqual([
      "python lexer fallback in long.py from line 2 to line 83: a triple-quoted string of 81 lines contains 80 lines that look like statements; these lines were also matched as plain text",
      "python lexer fallback in nested.py from line 2 to line 6: two scans of the quotes disagree about a triple-quoted string; these lines were also matched as plain text",
    ]);
  });

  it("2. treats a lone carriage return as a line break everywhere", async () => {
    const project = path.join(temp, "lone-cr");
    writeFile(
      project,
      "app.py",
      'X = 1 # note\rimport subprocess; subprocess.run(input(), shell=True)\rAPI_TOKEN = "LEAKCRCR-zq81-kd93-pp02"\r\nY = 2\n',
    );
    expect(splitLines("a\rb\r\nc\nd")).toEqual(["a", "b", "c", "d"]);
    const inv = inventory(project);
    expect(inv.files[0]?.loc).toBe(5);
    const rules = scanRules(inv.files, ruleSet);
    expect(rules.hits.map((hit) => `${hit.line}:${hit.rule.id}`)).toContain("2:py-subprocess-shell");
    const secrets = scanSecrets(inv.files);
    expect(secrets.findings.map((finding) => finding.startLine)).toEqual([3]);

    const out = path.join(temp, "lone-cr-out");
    const scan = await scanProject({ root: project, out, offline: true, engines: ["builtin"] });
    const snippet = readSnippet(scan.runDir, "app.py");
    expect(snippet.totalLines).toBe(5);
    expect(snippet.lines[1]?.text).toBe("import subprocess; subprocess.run(input(), shell=True)");
    expect(snippet.lines[2]?.text).not.toContain("LEAKCRCR");
    const added = addFinding(scan.runDir, {
      file: "app.py",
      startLine: 4,
      title: "Marker",
      severity: "low",
      cwe: "CWE-1104",
      rationale: "line numbering check",
    });
    expect(added.finding.evidence).toBe("Y = 2");
  });

  it("3. does not count comment and blank lines toward the span of a statement", () => {
    const comments = Array.from({ length: 15 }, () => "        # note");
    const { rows, result } = scanSource("span-comments", {
      "indented.py": ["import subprocess", "def f(cmd):", "    subprocess.run(cmd,", ...comments, "", "        shell=True)", ""].join("\n"),
      // At indentation 0 the closing line looks like a new statement.
      "toplevel.py": ["import subprocess", "subprocess.run(cmd,", ...comments.map((line) => line.trim()), "shell=True)", ""].join("\n"),
    });
    expect(rows).toEqual(["indented.py:3:py-subprocess-shell", "toplevel.py:2:py-subprocess-shell"]);
    expect(result.warnings).toEqual([]);
  });

  it("3. keeps a long call whole and bridges a recovery restart", () => {
    const args = Array.from({ length: 170 }, (_, index) => `        env_${index}=1234567890123456789012345678901234567890,`);
    // Arguments at column 0: after 15 lines each one looks like a new
    // top-level statement to the recovery heuristic.
    const flush = Array.from({ length: 20 }, (_, index) => `arg_${index}=1,`);
    const { rows, result } = scanSource("span-long", {
      "cut.py": ["import subprocess", "def f(cmd):", "    subprocess.run(cmd,", ...args, "        shell=True)", ""].join("\n"),
      "restart.py": ["import subprocess", "subprocess.run(cmd,", ...flush, "shell=True)", ""].join("\n"),
    });
    expect(rows).toEqual(["cut.py:3:py-subprocess-shell", "restart.py:2:py-subprocess-shell"]);
    expect(result.warnings).toEqual([]);
  });

  it("3. matches overlapping windows when a statement has to be cut, and says so", () => {
    const lines = ["import subprocess", "data = ["];
    for (let index = 0; index < MAX_LOGICAL_LINE_SPAN - 5; index += 1) lines.push(`    ${index},`);
    // This call straddles the point where the statement is cut.
    const callLine = lines.length + 1;
    lines.push("    subprocess.run(cmd,");
    for (let index = 0; index < 10; index += 1) lines.push(`        option_${index}=${index},`);
    lines.push("        shell=True),");
    for (let index = 0; index < MAX_LOGICAL_LINE_SPAN; index += 1) lines.push(`    ${index},`);
    lines.push("]", "");
    const { rows, result } = scanSource("span-windows", { "big.py": lines.join("\n") });
    expect(rows).toEqual([`big.py:${callLine}:py-subprocess-shell`]);
    expect(result.warnings).toEqual([
      `1 statement(s) in big.py are longer than ${MAX_LOGICAL_LINE_SPAN} code lines or 16000 characters and were matched in overlapping windows (first at line 2); a call that spans more than one window can be missed`,
    ]);
    const diagnostics = emptyLexDiagnostics();
    pythonLogicalLines(lines, undefined, diagnostics);
    expect(diagnostics.cuts).toEqual([1]);
  });

  it("4. measures an over-long line after its comment is removed, and matches long code in windows", () => {
    const { rows, result } = scanSource("over-long", {
      "pad.py": ["import os", "def f(cmd):", `    os.system(cmd)  #${"x".repeat(3 * MAX_PATTERN_LINE_LENGTH)}`, ""].join("\n"),
      "far.py": ["import os", "x = 1", `y = 2;${" ".repeat(3 * MAX_PATTERN_LINE_LENGTH)}os.system(cmd)`, ""].join("\n"),
      "far.js": [`var a = 1;${" ".repeat(3 * MAX_PATTERN_LINE_LENGTH)}eval(input);`, ""].join("\n"),
    });
    expect(rows).toEqual(["far.js:1:js-eval", "far.py:3:py-os-system-api", "pad.py:3:py-os-system-api"]);
    expect(result.warnings.sort()).toEqual([
      `1 over-long line(s) (more than ${MAX_PATTERN_LINE_LENGTH} characters) in far.js at line(s) 1: matched in overlapping windows`,
      `1 over-long line(s) (more than ${MAX_PATTERN_LINE_LENGTH} characters) in far.py at line(s) 3: matched in overlapping windows`,
    ]);
    // Evidence of a hit on an over-long line is cut, not the whole line.
    for (const hit of result.hits) expect(hit.evidence.length).toBeLessThanOrEqual(400);
  });

  it("5. keeps the code of replacement fields in a multi-line f-string", () => {
    const { rows } = scanSource("ffield", {
      "ffield.py": [
        "import os",
        "def f(cmd):",
        '    x = f"""',
        "{os.system(cmd)}",
        "os.system(this_is_text)",
        '"""',
        '    f"""',
        "    {eval(cmd)}",
        '    """',
        "    return x",
        "",
      ].join("\n"),
    });
    expect(rows).toEqual(["ffield.py:4:py-os-system-api", "ffield.py:8:py-eval-api"]);
  });

  it("6. lists every inline-suppressed candidate and can ignore the comments", async () => {
    const project = path.join(temp, "inline-ignore");
    writeFile(
      project,
      "app.py",
      [
        "import os, subprocess",
        "def f(cmd):",
        "    subprocess.run(cmd, shell=True)  # code-audit:ignore py-subprocess-shell -- trust me",
        "    os.system(cmd)  # code-audit:ignore py-os-system-api",
        "    eval(cmd)",
        "",
      ].join("\n"),
    );
    const out = path.join(temp, "inline-ignore-out");
    const scan = await scanProject({ root: project, out, offline: true, engines: ["builtin"] });
    const suppressed = [...scan.findings, ...scan.hotspots].filter((f) => f.status === "suppressed");
    expect(suppressed.map((f) => `${f.ruleId}:${f.startLine}:${f.suppression?.source}:${f.suppression?.reason}`).sort()).toEqual([
      "py-os-system-api:4:inline:",
      "py-subprocess-shell:3:inline:trust me",
    ]);
    expect(scan.run.findingCounts).toMatchObject({ high: 0, medium: 0 });
    expect(scan.run.suppressedCount).toBe(2);
    expect(scan.warnings.some((warning) => warning.startsWith("2 candidate(s) suppressed by inline code-audit:ignore"))).toBe(true);

    const document = JSON.parse(fs.readFileSync(path.join(scan.runDir, "findings.json"), "utf8")) as {
      findings: Array<{ ruleId: string; status: string; suppression?: { source: string; reason: string } }>;
      hotspots: Array<{ ruleId: string; status: string; suppression?: { source: string } }>;
    };
    expect(document.findings.find((f) => f.ruleId === "py-subprocess-shell")).toMatchObject({
      status: "suppressed",
      suppression: { source: "inline", reason: "trust me" },
    });
    expect(document.hotspots.find((f) => f.ruleId === "py-os-system-api")?.status).toBe("suppressed");

    const report = fs.readFileSync(path.join(scan.runDir, "report.md"), "utf8");
    const section = report.slice(report.indexOf("5a. Suppressed findings"), report.indexOf("## 6."));
    expect(section).not.toContain("None.");
    expect(section).toMatch(/\| py-subprocess-shell \| app\.py \| 3 \| inline comment \| trust me \|/);
    expect(section).toMatch(/\| py-os-system-api \| app\.py \| 4 \| inline comment \| no reason given \|/);

    // --no-inline-ignore: the comments are not honoured.
    const strict = await scanProject({
      root: project,
      out: path.join(temp, "inline-ignore-strict"),
      offline: true,
      engines: ["builtin"],
      noInlineIgnore: true,
    });
    expect([...strict.findings, ...strict.hotspots].some((f) => f.status === "suppressed")).toBe(false);
    expect(strict.findings.map((f) => `${f.ruleId}:${f.startLine}`)).toEqual(["py-subprocess-shell:3"]);
    expect(strict.hotspots.map((f) => `${f.ruleId}:${f.startLine}`).sort()).toEqual([
      "py-eval-api:5",
      "py-os-system-api:4",
    ]);
    expect(strict.warnings.join("\n")).not.toContain("code-audit:ignore");

    const viaCli = cli(["scan", project, "--offline", "--no-external", "--no-inline-ignore", "--out", path.join(temp, "inline-ignore-cli")]);
    expect(viaCli.status).toBe(1);
    expect(viaCli.stdout).toContain("Findings: 1 ");
    const honoured = cli(["scan", project, "--offline", "--no-external", "--out", path.join(temp, "inline-ignore-cli2")]);
    expect(honoured.status).toBe(0);
    expect(honoured.stdout).toContain("Findings: 0 ");
    expect(honoured.stdout).toContain("Suppressed: 2 (ignore file 0, inline comments 2)");
  });

  it("11. ignores a sink name inside an ordinary string literal, for API-call rules only", () => {
    const { rows } = scanSource("in-literal", {
      "app.py": [
        "import os, subprocess, pickle",
        "def f(cmd, cursor, name):",
        '    s = "os.system(cmd)"',
        "    t = 'eval(cmd) and pickle.loads(data)'",
        '    u = f"subprocess.run(cmd, shell=True) {os.system(cmd)}"',
        '    cursor.execute("SELECT * FROM users WHERE name = \'" + name + "\'")',
        '    os.system("echo os.system(nested)")',
        "",
      ].join("\n"),
    });
    expect(rows).toEqual([
      // Code in a replacement field is code.
      "app.py:5:py-os-system-api",
      // Rules that read literals (SQL text) are not affected.
      "app.py:6:py-sql-injection",
      // The real call is reported once; the text inside its argument is not.
      "app.py:7:py-os-system-api",
    ]);
  });

  it("12. says so when a file named like requirements is treated as prose but holds pins", () => {
    const project = path.join(temp, "prose-requirements");
    writeFile(project, "requirements-dev.txt", "# notes\nsome words here\nmore words here\nflask==0.5\n");
    writeFile(project, "requirements/notes.txt", "Remember the deploy key.\nAsk ops first.\n");
    const inv = inventory(project);
    expect(inv.lockfiles).toEqual([]);
    expect(inv.warnings).toEqual([
      "requirements-dev.txt: named like a requirements file but most lines are not requirement specifiers; 1 pinned line(s) in it were not analysed as dependencies",
    ]);
  });
});

describe("review 2 / output: no secret literal reaches any output", () => {
  const SECRETS = {
    sameLine: "LEAKGGGG-zq81-kd93-pp02-GGGGKAEL",
    compound: "LEAKHHHH-Tr0ub4dor&3",
    jsonKey: "LEAKTTTT-zq81-kd93-pp02",
    signing: "LEAKMMMM-zq81-kd93-pp02-MMMM",
    tuple: "LEAKKKKK-zq81-kd93",
    header: "LEAKNNNN-zq81-kd93-pp02",
    k8s: "LEAKYYYY1234!@#LEAKZZZZtail99",
    short: "q7Xw2Lm9Z",
    plainArg: "LEAKQQQQ-zq81-kd93-plain",
    continued: "LEAKFFFF-zq81-kd93-pp02-FFFFKAEL",
    yamlBare: "LEAKWWWW-zq81-kd93-pp02",
    envBare: "LEAKllll-zq81-kd93-pp02",
  };

  function writeLeakProject(name: string): string {
    const project = path.join(temp, name);
    writeFile(
      project,
      "app.py",
      [
        "import os, requests, subprocess",
        `SECRET_KEY = "${SECRETS.sameLine}"; os.system(cmd)`,
        `db_password = "${SECRETS.compound}"`,
        `jwt_signing = "${SECRETS.signing}"`,
        `requests.get(url, auth=("admin", "${SECRETS.tuple}"), verify=False)`,
        `subprocess.run("curl -H 'X-Auth: ${SECRETS.header}' " + url, shell=True)`,
        `password = "${SECRETS.short}"`,
        `conn = connect("${SECRETS.plainArg}")`,
        "SECRET_KEY = (",
        `    "${SECRETS.continued}"`,
        ")",
        "",
      ].join("\n"),
    );
    writeFile(project, "conf.json", `{"password": "${SECRETS.jsonKey}", "name": "demo"}\n`);
    writeFile(project, "conf.yml", `db_password: ${SECRETS.yamlBare}\n`);
    writeFile(project, "Dockerfile", `FROM python:3.12\nUSER app\nENV API_TOKEN=${SECRETS.envBare}\n`);
    writeFile(project, "k8s/d.yml", `env:\n  - name: DB_PASSWORD\n    value: "${SECRETS.k8s}"\n`);
    return project;
  }

  function expectNoLeak(text: string, except: string[] = []): void {
    for (const [name, secret] of Object.entries(SECRETS)) {
      if (except.includes(name)) continue;
      expect(text.includes(secret), `${name} leaked`).toBe(false);
    }
  }

  it("7-10. keeps every literal out of the output files and out of read, search and findings", async () => {
    const project = writeLeakProject("leaks");
    const out = path.join(temp, "leaks-out");
    const scan = await scanProject({
      root: project,
      out,
      offline: true,
      engines: ["builtin"],
      formats: ["md", "json", "sarif"],
    });
    for (const file of ["findings.json", "report.md", "results.sarif", "coverage.json", "run.json"]) {
      expectNoLeak(fs.readFileSync(path.join(scan.runDir, file), "utf8"));
    }
    expectNoLeak(readAllOutputFiles(out));

    // 7. The hotspot of another rule on the line of a redactEvidence rule.
    const sameLine = [...scan.findings, ...scan.hotspots].filter(
      (finding) => finding.file === "app.py" && finding.startLine === 2,
    );
    expect(sameLine.map((finding) => finding.ruleId).sort()).toEqual([
      "py-hardcoded-secret",
      "py-os-system-api",
    ]);
    for (const finding of sameLine) {
      expect(finding.evidence).toBe('SECRET_KEY = "LE************************EL"; os.system(cmd)');
    }
    // 10. A short value is masked completely; the Kubernetes value is masked
    // as a whole, not only up to its first special character.
    const short = scan.findings.find((finding) => finding.file === "app.py" && finding.startLine === 7);
    expect(short?.evidence).toBe('password = "*********"');
    const k8s = scan.hotspots.find((finding) => finding.ruleId === "k8s-secret-in-env");
    expect(k8s?.evidence).toBe('value: "LE************************99"');

    // read / search / findings through the CLI, and through the library.
    for (const file of ["app.py", "conf.json", "conf.yml", "Dockerfile", "k8s/d.yml"]) {
      const read = cli(["read", scan.runDir, file]);
      expect(read.status, file).toBe(0);
      // (A literal that nothing marks as a secret is source text like any
      // other; it is masked once a finding says it is a credential, see 8.)
      expectNoLeak(read.stdout, ["plainArg"]);
      expectNoLeak(JSON.stringify(readSnippet(scan.runDir, file)), ["plainArg"]);
    }
    for (const pattern of ["LEAK", "q7Xw", "password", "os.system"]) {
      const search = cli(["search", scan.runDir, pattern]);
      expect(search.status, pattern).toBe(0);
      expect(search.stdout).toMatch(/match\(es\)/);
      expectNoLeak(search.stdout, ["plainArg"]);
      expectNoLeak(JSON.stringify(searchCode(scan.runDir, { pattern })), ["plainArg"]);
    }
    for (const kind of ["finding", "hotspot", "all"]) {
      const findings = cli(["findings", scan.runDir, "--kind", kind, "--min-confidence", "low", "--json"]);
      expect(findings.status).toBe(0);
      expectNoLeak(findings.stdout);
    }
    const report = cli(["report", scan.runDir, "--format", "md"]);
    expectNoLeak(report.stdout);
  });

  it("8. routes add-finding evidence through the line redaction", async () => {
    const project = writeLeakProject("add-finding");
    const out = path.join(temp, "add-finding-out");
    const scan = await scanProject({
      root: project,
      out,
      offline: true,
      engines: ["builtin"],
      formats: ["md", "json", "sarif"],
    });

    // A secret-like name on the line: masked whatever the CWE of the finding.
    const byName = cli([
      "add-finding", scan.runDir, "--file", "app.py", "--start", "3", "--title", "Odd default",
      "--severity", "medium", "--cwe", "CWE-1188", "--rationale", `the value ${SECRETS.compound} is a default`, "--json",
    ]);
    expect(byName.status).toBe(0);
    expectNoLeak(byName.stdout);
    expect((JSON.parse(byName.stdout) as { finding: { evidence: string } }).finding.evidence).toBe(
      'db_password = "LE****************&3"',
    );

    // No secret-like name on the line: a credential CWE masks every literal.
    const byCwe = addFinding(scan.runDir, {
      file: "app.py",
      startLine: 8,
      title: "Connection string in source",
      severity: "high",
      cwe: "CWE-798",
      rationale: "literal credential",
    });
    expect(byCwe.finding.evidence).toBe('conn = connect("LE********************in")');
    // ... and so does a title that says it is about a secret.
    const second = path.join(temp, "add-finding-out2");
    const scan2 = await scanProject({ root: project, out: second, offline: true, engines: ["builtin"] });
    const byTitle = addFinding(scan2.runDir, {
      file: "app.py",
      startLine: 8,
      title: "Hardcoded secret passed to connect()",
      severity: "high",
      cwe: "CWE-200",
      rationale: "literal credential",
    });
    expect(byTitle.finding.evidence).toBe('conn = connect("LE********************in")');
    // A multi-line value: the continuation line has no name on it.
    const continued = addFinding(scan2.runDir, {
      file: "app.py",
      startLine: 9,
      endLine: 11,
      title: "Config block",
      severity: "low",
      cwe: "CWE-1188",
      rationale: "multi-line value",
    });
    expectNoLeak(continued.finding.evidence);

    // The re-rendered report and every file of both runs stay clean.
    for (const dir of [scan.runDir, scan2.runDir]) {
      for (const format of ["md", "json", "sarif"]) {
        const rendered = cli(["report", dir, "--format", format]);
        expect(rendered.status).toBe(0);
        expectNoLeak(rendered.stdout);
      }
    }
    expectNoLeak(readAllOutputFiles(out));
    expectNoLeak(readAllOutputFiles(second));
  });

  it("9. masks the value of any secret-like name (redaction is generous)", () => {
    const value = "S3cr3t-Value-0001";
    const masked: string[] = [
      `db_password = "${value}"`,
      `DB_PASSWD: '${value}'`,
      `{"password": "${value}"}`,
      `jwt_signing = "${value}"`,
      `app.config["SECRET_KEY"] = '''${value}'''`,
      `self.api_key: str = "${value}"`,
      `client_secret => "${value}",`,
      `if password == "${value}":`,
      `os.environ.get("AUTH_TOKEN", "${value}")`,
      `auth=("admin", "${value}")`,
      `hmac.new(b"${value}", msg)`,
      `jwt.encode(payload, "${value}", algorithm="HS256")`,
      `set_password("${value}")`,
      `headers = {"Authorization": "Bearer ${value}"}`,
      `curl -H 'X-Api-Key: ${value}' https://example.invalid`,
      `conn = "Server=db;Password=${value};Database=x"`,
      `mysql --password ${value} -u root`,
      `salt = b"${value}"`,
      `PRIVATE_KEY = "${value}" + "${value}"`,
      `dsn = "${value}"`,
      `connection_string = "${value}"`,
      `credentials = ["${value}"]`,
    ];
    for (const line of masked) expect(redactLine(line), line).not.toContain(value);
    // Unquoted values in configuration files.
    expect(redactLine(`db_password: ${value}`, { file: "conf.yml" })).toBe("db_password: S3*************01");
    expect(redactLine(`API_TOKEN=${value}`, { file: ".env" })).toBe("API_TOKEN=S3*************01");
    expect(redactLine(`ENV API_TOKEN ${value}`, { file: "Dockerfile" })).not.toContain(value);
    // Code stays readable: references and expressions are not values.
    for (const line of [
      'password = request.form["password"]',
      "token = generate_token(user)",
      'password = os.environ["DB_PASSWORD"]',
      'api_key = "${API_KEY}"',
      "def check_password(self, password):",
      '@auth.route("/login")',
      'author = "Jane Doe"',
    ]) {
      expect(redactLine(line), line).toBe(line);
    }
    // Known formats keep their public prefix; a PEM header hides the rest.
    expect(redactLine("key AKIAIOSFODNN7EXAMPLE here")).toBe("key AKIA**************LE here");
    expect(redactLine('{"private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBg"}')).not.toContain("MIIEvQ");
    expect(redactLine("https://deploy:hunter2secret@host.example/simple")).toBe(
      "https://deploy:*************@host.example/simple",
    );
    // A value that continues on the next line.
    expect(redactText(`SECRET_KEY = (\n    "${value}"\n)`)).not.toContain(value);
    expect(redactText(`password: |\n  ${value}\nother: 1`, { file: "c.yml" })).not.toContain(value);
  });

  it("9. reports compound names and JSON keys, and none of the non-secrets", () => {
    const project = path.join(temp, "detector");
    writeFile(
      project,
      "settings.py",
      [
        'db_password = "Tr0ub4dor&3xyz"',
        'CONFIG = {"password": "Tr0ub4dor&3abc"}',
        'password = "Tr0ub4dor&3old"',
        // Not secrets: placeholder, environment, None, template, field name,
        // path, URL, prose, empty.
        'db_password = "changeme-please"',
        'db_password = os.environ["DB_PASSWORD"]',
        'admin_password = "None"',
        'reset_token = "{uid}-{token}"',
        'csrf_token = "csrf_middleware_token"',
        'password_field = "password_confirmation"',
        'auth_token = "%(token)s"',
        'cert_password = "/run/secrets/cert_password"',
        'token_url = "https://example.invalid/oauth/token"',
        'CONFIG = {"password": "Enter your password"}',
        'smtp_password = ""',
        "",
      ].join("\n"),
    );
    const found = scanSecrets(inventory(project).files).findings;
    expect(found.map((finding) => `${finding.startLine}:${finding.confidence}`)).toEqual([
      "1:medium",
      "2:medium",
      "3:high",
    ]);
    expect(JSON.stringify(found)).not.toContain("Tr0ub4dor");
  });

  it("10. masks short values completely and shows at most 2 + 2 characters of long ones", () => {
    expect(maskSecret("q7Xw2Lm9Z")).toBe("*********");
    expect(maskSecret("abc")).toBe("****");
    expect(maskSecret("0123456789abcde")).toBe("***************");
    expect(maskSecret("0123456789abcdef")).toBe("01************ef");
    expect(maskSecret("x".repeat(80))).toBe(`xx${"*".repeat(24)}xx`);
    expect(maskSecret("ghp_0123456789abcdefghijklmnopqrstuvwxyz", 4)).toBe(`ghp_${"*".repeat(24)}yz`);
    expect(redactLine('password = "q7Xw2Lm9Z"')).toBe('password = "*********"');
    expect(redactLine('api_key = "q7Xw2Lm9Zr4T"')).toBe('api_key = "************"');
  });

  it("10. gives two different secrets of the same length distinct findings", async () => {
    const project = path.join(temp, "same-length");
    writeFile(
      project,
      "settings.py",
      ['password = "Alpha-0001x"', "x = 1", 'password = "Bravo-0002y"', ""].join("\n"),
    );
    const found = scanSecrets(inventory(project).files).findings;
    // Fully masked values of one length give identical evidence, hence one
    // base fingerprint ...
    expect(found.map((finding) => finding.evidence)).toEqual([
      'password = "***********"',
      'password = "***********"',
    ]);
    expect(found[0]?.fingerprint).toBe(found[1]?.fingerprint);
    // ... and the occurrence number tells them apart.
    const distinct = disambiguateFingerprints(found);
    expect(new Set(distinct.map((finding) => finding.fingerprint)).size).toBe(2);
    const scan = await scanProject({
      root: project,
      out: path.join(temp, "same-length-out"),
      offline: true,
      engines: ["builtin"],
      formats: ["json"],
    });
    const secrets = scan.findings.filter((finding) => finding.category === "secrets");
    expect(secrets.map((finding) => finding.startLine).sort()).toEqual([1, 3]);
    expect(new Set(secrets.map((finding) => finding.fingerprint)).size).toBe(2);
  });
});
