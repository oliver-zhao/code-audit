import path from "node:path";
import fs from "node:fs";
import { afterAll, describe, expect, it } from "vitest";
import { inventory } from "../src/inventory.js";
import {
  MAX_LOGICAL_LINE_SPAN,
  MAX_PATTERN_LINE_LENGTH,
  loadRules,
  localizeRule,
  pythonLogicalLines,
  redactEvidenceLine,
  scanRules,
  stripPythonComment,
} from "../src/rules.js";
import { scanProject } from "../src/scan.js";
import {
  RULES_DIR,
  VULNERABLE,
  cleanup,
  loadExpected,
  makeTempDir,
  readAllOutputFiles,
  writeFile,
} from "./helpers.js";

const temp = makeTempDir("rules");

afterAll(() => cleanup(temp));

describe("rule loading", () => {
  it("loads every bundled rule with required metadata", () => {
    const ruleSet = loadRules(RULES_DIR);
    expect(ruleSet.rules.length).toBeGreaterThanOrEqual(50);
    for (const rule of ruleSet.rules) {
      expect(rule.id).toMatch(/^[a-z0-9-]+$/);
      expect(rule.cwe).toMatch(/^CWE-\d+$/);
      expect(rule.remediation.length).toBeGreaterThan(5);
      expect(["critical", "high", "medium", "low", "info"]).toContain(
        rule.severity,
      );
      expect(["high", "medium", "low"]).toContain(rule.confidence);
      expect(rule.title_zh).toBeTruthy();
      expect(rule.languages.length).toBeGreaterThan(0);
    }
  });

  it("localizes rule text to Chinese and falls back to English", () => {
    const rule = loadRules(RULES_DIR).rules.find(
      (candidate) => candidate.id === "cs-sql-injection",
    );
    expect(rule).toBeDefined();
    if (!rule) return;
    expect(localizeRule(rule, "en").title).toBe(rule.title);
    expect(localizeRule(rule, "zh").title).toBe(rule.title_zh);
    expect(localizeRule({ ...rule, title_zh: undefined }, "zh").title).toBe(
      rule.title,
    );
  });

  it("reports the file name for an invalid rule", () => {
    const rulesDir = path.join(temp, "bad-rules");
    writeFile(
      rulesDir,
      "bad.yml",
      [
        "rules:",
        "  - id: broken-rule",
        "    title: Broken",
        "    severity: high",
        "    languages: [python]",
        "    pattern: 'x'",
        "    message: missing cwe",
        "    remediation: fix it",
        "",
      ].join("\n"),
    );
    expect(() => loadRules(rulesDir)).toThrow(/bad\.yml/);
    expect(() => loadRules(rulesDir)).toThrow(/cwe/);
  });
});

describe("rule coverage of fixtures", () => {
  const ruleSet = loadRules(RULES_DIR);
  const expected = loadExpected();
  const inv = inventory(VULNERABLE);
  const result = scanRules(inv.files, ruleSet);
  const hits = new Set(
    result.hits.map((hit) => `${hit.file.relPath}:${hit.line}:${hit.rule.id}`),
  );

  it("has a matching fixture seed for every bundled rule", () => {
    const seedRuleIds = new Set(expected.seeds.map((seed) => seed.ruleId));
    const missing = ruleSet.rules
      .map((rule) => rule.id)
      .filter((id) => !seedRuleIds.has(id));
    expect(missing).toEqual([]);
  });

  it("matches every EXPECTED.json seed at the expected line", () => {
    // Seeds for scanner-emitted hotspots (for example dep-missing-lockfile,
    // which the rule engine no longer owns) are covered by scan.test.ts.
    const ruleIds = new Set(ruleSet.rules.map((rule) => rule.id));
    const missing = expected.seeds
      .filter((seed) => ruleIds.has(seed.ruleId))
      .map(
        (seed) => `${seed.file}:${seed.line}:${seed.ruleId}`,
      )
      .filter((key) => !hits.has(key));
    expect(missing).toEqual([]);
  });

  it("lists every finding and hotspot the engine reports in the Python rule fixtures", () => {
    // Bidirectional for python/*.py: a result that EXPECTED.json does not list
    // (or lists with another kind) is an unreviewed result. taint_*.py belong
    // to the external taint rules and keep the one-directional check above.
    const listed = new Set(
      expected.seeds.map(
        (seed) => `${seed.file}:${seed.line}:${seed.ruleId}:${seed.kind ?? "finding"}`,
      ),
    );
    const inScope = result.hits.filter(
      (hit) =>
        /^python\/[^/]+\.py$/.test(hit.file.relPath) &&
        !/^python\/taint_/.test(hit.file.relPath),
    );
    const unlisted = inScope
      .map((hit) => `${hit.file.relPath}:${hit.line}:${hit.rule.id}:${hit.rule.kind}`)
      .filter((key) => !listed.has(key));
    expect(unlisted).toEqual([]);
    // The scope is not empty: the check really looks at fixture results.
    expect(inScope.filter((hit) => hit.rule.kind === "finding").length).toBeGreaterThan(40);
    expect(inScope.filter((hit) => hit.rule.kind === "hotspot").length).toBeGreaterThan(20);
  });

  it("lists every finding and hotspot the engine reports in the C# rule fixtures", () => {
    // Bidirectional for csharp/**: C# sources, Razor views, web.config and
    // appsettings.json. A result that EXPECTED.json does not list (or lists
    // with another kind) is an unreviewed result.
    const listed = new Set(
      expected.seeds.map(
        (seed) => `${seed.file}:${seed.line}:${seed.ruleId}:${seed.kind ?? "finding"}`,
      ),
    );
    const inScope = result.hits.filter((hit) => hit.file.relPath.startsWith("csharp/"));
    const unlisted = inScope
      .map((hit) => `${hit.file.relPath}:${hit.line}:${hit.rule.id}:${hit.rule.kind}`)
      .filter((key) => !listed.has(key));
    expect(unlisted).toEqual([]);
    const languages = new Set(inScope.map((hit) => hit.file.language));
    expect([...languages].sort()).toEqual(["csharp", "json", "razor", "xml"]);
    expect(inScope.filter((hit) => hit.rule.kind === "finding").length).toBeGreaterThan(40);
    expect(inScope.filter((hit) => hit.rule.kind === "hotspot").length).toBeGreaterThan(15);
  });

  it("supports inline code-audit:ignore with a reason", () => {
    const project = path.join(temp, "suppressed");
    writeFile(
      project,
      "app.py",
      [
        "import os",
        'os.system("ls " + command)  # code-audit:ignore py-command-injection py-os-system-api -- test fixture',
        "",
      ].join("\n"),
    );
    const projectInv = inventory(project);
    const suppressionResult = scanRules(projectInv.files, ruleSet);
    expect(suppressionResult.hits).toHaveLength(0);
    expect(suppressionResult.suppressed).toHaveLength(2);
    expect(suppressionResult.suppressed[0]).toMatchObject({
      ruleId: "py-command-injection",
      file: "app.py",
      line: 2,
      reason: "test fixture",
    });
    expect(fs.existsSync(path.join(project, "app.py"))).toBe(true);
  });
});

describe("Python comment handling", () => {
  const ruleSet = loadRules(RULES_DIR);

  it("strips a # comment but keeps a # inside a string literal", () => {
    expect(stripPythonComment('value = "a#b"')).toBe('value = "a#b"');
    expect(stripPythonComment("value = 1  # note")).toBe("value = 1  ");
    expect(stripPythonComment("# whole line")).toBe("");
  });

  it("never matches a rule on a comment-only or trailing-comment line", () => {
    const project = path.join(temp, "pycomments");
    writeFile(project, "app.py", [
      "import os",
      'name = "a#b"',
      'os.system("ls " + name)',
      'safe = "a#b"  # os.system("ls " + name)',
      '# os.system("ls " + name)',
      "",
    ].join("\n"));
    const inv = inventory(project);
    const result = scanRules(inv.files, ruleSet);
    const lines = result.hits
      .filter((hit) => hit.rule.id === "py-command-injection")
      .map((hit) => hit.line);
    expect(lines).toEqual([3]);
  });
});

describe("Python logical lines", () => {
  it("joins a bracketed call into one unit and keeps line offsets", () => {
    const units = pythonLogicalLines([
      "jwt.decode(",
      "    token,  # the token",
      "    verify=False,",
      ")",
      "x = 1",
    ]);
    expect(units).toHaveLength(2);
    expect(units[0]).toMatchObject({ start: 0, declaration: false });
    expect(units[0]?.text).toBe("jwt.decode(\n    token,  \n    verify=False,\n)");
    expect(units[0]?.offsets).toEqual([0, 12, 25, 43]);
    expect(units[1]).toMatchObject({ start: 4, text: "x = 1" });
  });

  it("joins backslash continuations and unclosed triple-quoted strings", () => {
    const units = pythonLogicalLines([
      "total = first + \\",
      "    second",
      'sql = """SELECT *',
      "eval(user_input)",
      '""" + suffix',
    ]);
    expect(units.map((unit) => unit.start)).toEqual([0, 2]);
    // The body of the multi-line string is dropped on its continuation lines.
    expect(units[1]?.text).toBe('sql = """SELECT *\n\n""" + suffix');
  });

  it("blanks docstrings and other statements that are only a string", () => {
    const units = pythonLogicalLines([
      '"""Module docstring: eval(x)."""',
      "def run():",
      "    '''Call os.system(\"ls \" + name)",
      "    never.",
      "    '''",
      '    r"raw eval(x)"',
      '    return "eval(x) stays, it is not a bare string"',
    ]);
    expect(units.map((unit) => unit.text)).toEqual([
      "",
      "def run():",
      "",
      "",
      '    return "eval(x) stays, it is not a bare string"',
    ]);
  });

  it("marks def, class and import statements as declarations", () => {
    const units = pythonLogicalLines([
      "import os",
      "from flask import (",
      "    redirect,",
      ")",
      "class TagMarkup(JSONTag):",
      "    async def test_send_file(self):",
      "        @decorator",
      "        value = definition",
      "    def set_cookie_and_redirect(handler): pass",
    ]);
    expect(units.map((unit) => unit.declaration)).toEqual([
      true,
      true,
      true,
      true,
      false,
      false,
      true,
    ]);
  });

  it("splits a very long statement so matching stays bounded", () => {
    const lines = ["values = ["];
    for (let index = 0; index < 40; index += 1) lines.push(`    ${index},`);
    lines.push("]");
    const units = pythonLogicalLines(lines);
    expect(units.length).toBe(Math.ceil(lines.length / MAX_LOGICAL_LINE_SPAN));
    for (const unit of units) {
      expect(unit.offsets.length).toBeLessThanOrEqual(MAX_LOGICAL_LINE_SPAN);
    }
  });
});

function writeRules(name: string, body: string[]): string {
  const rulesDir = path.join(temp, name);
  writeFile(rulesDir, "rules.yml", [...body, ""].join("\n"));
  return rulesDir;
}

function scanSource(
  rulesDir: string,
  name: string,
  files: Record<string, string[]>,
): ReturnType<typeof scanRules> {
  const project = path.join(temp, name);
  for (const [file, lines] of Object.entries(files)) {
    writeFile(project, file, [...lines, ""].join("\n"));
  }
  return scanRules(inventory(project).files, loadRules(rulesDir));
}

const RULE_TAIL = [
  "    severity: high",
  "    confidence: medium",
  "    cwe: CWE-1",
  "    languages: [python]",
  "    message: test rule",
  "    remediation: fix the code",
];

describe("engine features used by the Python rules", () => {
  const rulesDir = writeRules("engine-rules", [
    "definitions:",
    "  SINK: 'danger\\('",
    "  CALL: '{{SINK}}[^)]*'",
    "rules:",
    "  - id: t-flag",
    "    title: flag",
    "    pattern: '{{CALL}}flag=True'",
    "    group: t-group",
    ...RULE_TAIL,
    "  - id: t-any",
    "    title: any",
    "    kind: hotspot",
    "    pattern: 'flag=True'",
    "    group: t-group",
    ...RULE_TAIL,
    "  - id: t-missing",
    "    title: missing",
    "    pattern: 'fetch\\('",
    "    notPattern: 'timeout='",
    ...RULE_TAIL,
    "  - id: t-name",
    "    title: name",
    "    pattern: 'send_file'",
    ...RULE_TAIL,
    "  - id: t-decl",
    "    title: decl",
    "    pattern: 'telnetlib'",
    "    matchDeclarations: true",
    ...RULE_TAIL,
  ]);

  it("expands {{NAME}} definitions, including nested ones", () => {
    const rule = loadRules(rulesDir).rules.find((item) => item.id === "t-flag");
    expect(rule?.pattern).toBe("danger\\([^)]*flag=True");
  });

  it("rejects unknown and malformed definitions with the file name", () => {
    const unknown = writeRules("unknown-definition", [
      "rules:",
      "  - id: t-unknown",
      "    title: unknown",
      "    pattern: '{{NOPE}}'",
      ...RULE_TAIL,
    ]);
    expect(() => loadRules(unknown)).toThrow(/rules\.yml.*unknown definition \{\{NOPE\}\}/);
    const malformed = writeRules("malformed-definition", [
      "definitions:",
      "  lower: 'x'",
      "rules: []",
    ]);
    expect(() => loadRules(malformed)).toThrow(/rules\.yml.*invalid definitions/);
  });

  it("matches a multi-line call once and reports the line where the match starts", () => {
    const result = scanSource(rulesDir, "engine-multiline", {
      "app.py": [
        "result = danger(",
        "    value,",
        "    flag=True,",
        ")",
        "fetch(",
        "    url,",
        "    timeout=5,",
        ")",
        "fetch(",
        "    url,",
        ")",
      ],
    });
    const hits = result.hits.map((hit) => `${hit.rule.id}:${hit.line}`);
    // t-any matches line 3 of the same statement and loses to t-flag (group).
    expect(hits).toEqual(["t-flag:1", "t-missing:9"]);
    expect(result.hits[0]?.evidence).toBe("result = danger(");
  });

  it("honours a suppression comment on the first line of a multi-line statement", () => {
    const result = scanSource(rulesDir, "engine-suppress", {
      "app.py": [
        "danger(  # code-audit:ignore t-flag t-any -- reviewed",
        "    flag=True,",
        ")",
      ],
    });
    expect(result.hits.map((hit) => hit.rule.id)).toEqual([]);
    expect(result.suppressed.map((item) => item.ruleId).sort()).toEqual([
      "t-any",
      "t-flag",
    ]);
  });

  it("skips def, class and import lines unless matchDeclarations is set", () => {
    const result = scanSource(rulesDir, "engine-declarations", {
      "app.py": [
        "import telnetlib",
        "from flask import send_file",
        "def test_send_file(client):",
        "    return send_file",
        "class send_file_view:",
        "    pass",
      ],
    });
    expect(result.hits.map((hit) => `${hit.rule.id}:${hit.line}`)).toEqual([
      "t-decl:1",
      "t-name:4",
    ]);
  });

  it("leaves other languages on physical lines", () => {
    const jsRules = writeRules("engine-js", [
      "rules:",
      "  - id: t-js",
      "    title: js",
      "    pattern: 'danger\\([^)]*flag'",
      ...RULE_TAIL.map((line) => line.replace("[python]", "[javascript]")),
    ]);
    const result = scanSource(jsRules, "engine-js-src", {
      "app.js": ["danger(", "  flag)", "danger(flag) // def x"],
    });
    expect(result.hits.map((hit) => hit.line)).toEqual([3]);
  });
});

describe("Python rule precision", () => {
  const ruleSet = loadRules(RULES_DIR);

  function findings(name: string, file: string, lines: string[]): string[] {
    const project = path.join(temp, name);
    writeFile(project, file, [...lines, ""].join("\n"));
    const result = scanRules(inventory(project).files, ruleSet);
    return result.hits
      .filter((hit) => hit.rule.kind === "finding")
      .map((hit) => `${hit.line}:${hit.rule.id}`);
  }

  it("does not report the false positives seen on real projects", () => {
    expect(
      findings("fp-real", "views.py", [
        "import os",
        "from flask import redirect, render_template, request, send_file, url_for",
        "from markupsafe import Markup",
        "",
        "class TagMarkup(JSONTag):",
        "    pass",
        "",
        "def test_send_file(client):",
        "    pass",
        "",
        "def set_cookie_and_redirect(handler):",
        '    render_template(f"{js}.html", js=js)',
        '    redirect(url_for("auth.login"))',
        '    redirect(url_for("profile", name=request.values["name"]))',
        '    redirect("/tags/" + request.args["tag"])',
        "    open(filename, 'rb')",
        '    open(os.path.join(os.path.dirname(__file__), "data.sql"))',
        "    db.executescript(f.read().decode('utf8'))",
        '    app.config.from_mapping(SECRET_KEY="dev")',
        '    cert_reqs = "CERT_NONE"',
        "    self.verify = True",
        "    return get_redirect_target(request.args)",
      ]),
    ).toEqual([]);
  });

  it("separates request data in the sink argument from request data elsewhere", () => {
    expect(
      findings("fp-args", "views.py", [
        "from flask import render_template_string, request",
        "import requests, sqlalchemy",
        "from sqlalchemy import text",
        'render_template_string(PAGE, name=request.args.get("name"))',
        'render_template_string(request.args.get("tpl"))',
        'cursor.execute("SELECT * FROM t WHERE id = ?", (request.args["id"],))',
        'cursor.execute("SELECT * FROM t WHERE id = " + request.args["id"])',
        "requests.post(API_URL, data=request.form, timeout=5)",
        'requests.get(request.args["url"], timeout=5)',
        'open(os.path.join(BASE, secure_filename(request.args["f"])))',
        'open(os.path.join(BASE, request.args["f"]))',
        "pickle.dumps(request.json)",
        'eval("1 + 1", {"x": request.args})',
      ]),
    ).toEqual([
      "5:py-render-template-string",
      "7:py-sql-injection",
      "9:py-ssrf",
      "11:py-path-traversal",
    ]);
  });

  it("reports SQL formatting only in value position", () => {
    expect(
      findings("sql-value", "db.py", [
        "from sqlalchemy import text",
        'cursor.execute(f"SELECT * FROM {table}")',
        'cursor.execute("SELECT * FROM t ORDER BY " + order)',
        'cursor.execute("SELECT * FROM t LIMIT %d" % limit)',
        'cursor.execute("SELECT * FROM t WHERE n = %s", (name,))',
        'cursor.execute(f"SELECT * FROM t WHERE n = {name}")',
        "cursor.execute(\"SELECT * FROM t WHERE n = '%s'\" % name)",
        "cursor.execute(\"INSERT INTO t VALUES (NULL, '{}')\".format(name))",
        "cursor.execute(",
        '    "SELECT * FROM t "',
        "    \"WHERE n LIKE '%\" + name + \"%'\"",
        ")",
        'text(f"SELECT * FROM t ORDER BY {order}")',
        "text(f\"SELECT * FROM t WHERE n = '{name}'\")",
        'self.execute(f"--flag={value}")',
        'message = "select one from %s" % name',
        "query = \"SELECT * FROM users WHERE name = '\" + name + \"'\"",
      ]),
    ).toEqual([
      "6:py-sql-injection",
      "7:py-sql-injection",
      "8:py-sql-injection",
      "9:py-sql-injection",
      "14:py-sqlalchemy-text",
      "17:py-sql-string-built",
    ]);
  });

  it("requires a formatted, request-derived or non-literal shell=True command for shell findings", () => {
    // Policy: a statement is a finding when it shows request data or a string
    // built at runtime reaching the sink, or when it is a well-known dangerous
    // form whatever the origin of the data. subprocess.*(<non-literal>,
    // shell=True) is such a form (line 5); a literal command with shell=True
    // (line 4) and os.system(variable) (line 3) stay hotspots.
    expect(
      findings("shell", "run.py", [
        "import os, subprocess",
        'os.system("ls -l")',
        "os.system(command)",
        'subprocess.run("make test", shell=True)',
        "subprocess.run(command, shell=True)",
        'subprocess.run(["git", "clone", url])',
        'subprocess.run(f"git clone {url}")',
        'subprocess.run(f"git clone {url}", shell=True)',
        "subprocess.check_output(",
        '    "ping " + host,',
        "    shell=True,",
        ")",
        'os.popen("ls %s" % name)',
      ]),
    ).toEqual([
      "5:py-subprocess-shell",
      "8:py-subprocess-shell",
      "9:py-subprocess-shell",
      "13:py-command-injection",
    ]);
  });

  it("reports a non-literal shell=True command at medium confidence and a literal one as a hotspot", () => {
    const project = path.join(temp, "shell-policy");
    writeFile(project, "run.py", [
      "import subprocess",
      "subprocess.run(name, shell=True)",
      "subprocess.Popen(self.command, shell=True)",
      'subprocess.call(" ".join(args), shell=True)',
      "subprocess.check_output(build_command(), shell=True)",
      'subprocess.run("make test", shell=True)',
      'subprocess.run(["ls", "-l"], shell=True)',
      "subprocess.run(name)",
      "subprocess.run(name, shell=False)",
      "",
    ].join("\n"));
    const result = scanRules(inventory(project).files, ruleSet);
    const rows = result.hits
      .filter((hit) => hit.rule.group === "py-subprocess")
      .map((hit) => `${hit.line}:${hit.rule.id}:${hit.rule.kind}:${hit.rule.confidence}`);
    expect(rows).toEqual([
      "2:py-subprocess-shell:finding:medium",
      "3:py-subprocess-shell:finding:medium",
      "4:py-subprocess-shell:finding:medium",
      "5:py-subprocess-shell:finding:medium",
      "6:py-subprocess-shell-api:hotspot:low",
      "7:py-subprocess-shell-api:hotspot:low",
    ]);
  });

  it("keeps open(variable) and requests.get(variable) out of the findings", () => {
    // The request value is read on another line; the regex engine cannot see
    // that, and open(<variable>) / requests.get(<variable>) are far too common
    // to be reported whatever the origin. These stay hotspots (the taint
    // rules report them when the flow exists).
    expect(
      findings("policy-hotspots", "views.py", [
        "import os, requests",
        "from flask import request",
        "def handler():",
        '    name = request.args.get("name")',
        '    open(os.path.join("/data", name))',
        "    requests.get(name)",
      ]),
    ).toEqual([]);
  });

  it("reports yaml.unsafe_load, an unsafe variable name and UnsafeLoader", () => {
    expect(
      findings("yaml-load", "load.py", [
        "import yaml",
        "yaml.unsafe_load(body)",
        "yaml.load(unsafe_body)",
        "yaml.load(body, Loader=yaml.UnsafeLoader)",
        "yaml.load(body, Loader=yaml.Loader)",
        "yaml.full_load(body)",
        "yaml.load(body)",
        "yaml.load(",
        "    unsafe_body,",
        "    Loader=yaml.FullLoader,",
        ")",
        // Safe forms.
        "yaml.safe_load(unsafe_body)",
        "yaml.load(unsafe_body, Loader=yaml.SafeLoader)",
        "yaml.load(unsafe_body, yaml.CSafeLoader)",
        "yaml.load(unsafe_body, Loader=yaml.BaseLoader)",
        "yaml.load(",
        "    unsafe_body,",
        "    Loader=SafeLoader,",
        ")",
      ]),
    ).toEqual([
      "2:py-yaml-load",
      "3:py-yaml-load",
      "4:py-yaml-load",
      "5:py-yaml-load",
      "6:py-yaml-load",
      "7:py-yaml-load",
      "8:py-yaml-load",
    ]);
  });

  it("does not match sink names inside longer identifiers", () => {
    expect(
      findings("names", "names.py", [
        "from jinja2 import Environment",
        'literal_eval(request.args["x"])',
        'model.eval(request.args["x"])',
        'conn.exec(request.args["x"])',
        'my_redirect(request.args["x"])',
        'reopen(request.args["x"])',
        "cursor.execute_later(\"SELECT * FROM t WHERE n = '%s'\" % name)",
        'TagMarkup(f"<b>{name}</b>")',
        "MyEnvironment(autoescape=False)",
        "asyncio.run(main(), debug=True)",
      ]),
    ).toEqual([]);
  });
});

describe("Python matcher: every match, robust lexing, declarations, notPattern scope", () => {
  const ruleSet = loadRules(RULES_DIR);

  function hitsOf(name: string, lines: string[], file = "app.py"): string[] {
    const project = path.join(temp, name);
    writeFile(project, file, [...lines, ""].join("\n"));
    const result = scanRules(inventory(project).files, ruleSet);
    return result.hits
      .filter((hit) => hit.rule.kind === "finding")
      .map((hit) => `${hit.line}:${hit.rule.id}`)
      .sort((left, right) => Number.parseInt(left, 10) - Number.parseInt(right, 10));
  }

  it("reports every match of a rule in one statement at the line where it starts", () => {
    expect(
      hitsOf("multi-hit", [
        "import os, pickle",
        "from flask import request",
        "handlers = [",
        "    pickle.loads(request.data),",
        '    pickle.loads(request.form["x"]),',
        '    pickle.loads(request.args["y"]),',
        "]",
        "result = run_all(",
        '    os.system("ls " + request.args["a"]),',
        '    os.system("rm " + request.args["b"]),',
        ")",
        // Two matches on one physical line are one result.
        "pair = (pickle.loads(request.data), pickle.loads(request.data))",
      ]),
    ).toEqual([
      "4:py-insecure-deserialization",
      "5:py-insecure-deserialization",
      "6:py-insecure-deserialization",
      "9:py-command-injection",
      "10:py-command-injection",
      "12:py-insecure-deserialization",
    ]);
  });

  it("keeps one result per call when rules of a group match different lines of it", () => {
    const project = path.join(temp, "group-span");
    writeFile(project, "app.py", [
      "import jwt, requests",
      "calls = [",
      "    jwt.decode(",
      "        token,",
      "        verify=False,",
      "    ),",
      "    requests.get(url, verify=False),",
      "]",
      "",
    ].join("\n"));
    const result = scanRules(inventory(project).files, ruleSet);
    const rows = result.hits
      .filter((hit) => hit.rule.group === "py-verify-false")
      .map((hit) => `${hit.line}:${hit.rule.id}`)
      .sort();
    // jwt.decode(...) wins over verify=False on line 5 of the same call; the
    // separate call on line 7 is its own result.
    expect(rows).toEqual(["3:py-jwt-verify-false", "7:py-tls-disabled"]);
  });

  it("does not lose the rest of a file after a string the lexer could misread", () => {
    const tail = [
      'os.system("ls " + request.args["a"])',
      "import json",
      'os.system("ls " + request.args["b"])',
      "def g():",
      ...Array.from({ length: 20 }, (_, index) => `    eval(request.args["k${index}"])`),
    ];
    const expectedTail = (offset: number): string[] => [
      `${offset + 1}:py-command-injection`,
      `${offset + 3}:py-command-injection`,
      ...Array.from({ length: 20 }, (_, index) => `${offset + 5 + index}:py-eval-dynamic`),
    ];
    const heads: Record<string, string[]> = {
      // Python 3.12 f-string with the same quote nested in a replacement field.
      "nested-fstring": ["from flask import request", 'x = f"{d["("]}"'],
      // A string continued with a backslash, with a bracket inside.
      "backslash-string": ["from flask import request", 'label = "open ( \\', '    still the string"'],
      // A format spec that contains a quote character and a bracket.
      "format-spec": ["from flask import request", "y = f\"{value:'>10}(\""],
      // An unbalanced bracket inside a plain string.
      "bracket-in-string": ["from flask import request", 'label = "unbalanced ("  # fine'],
    };
    for (const [name, head] of Object.entries(heads)) {
      expect(hitsOf(`lexer-${name}`, [...head, ...tail]), name).toEqual(
        expectedTail(head.length),
      );
      // No unit after the head spans more than one line.
      const units = pythonLogicalLines([...head, ...tail]);
      const multi = units.filter(
        (unit) => unit.start >= head.length && unit.offsets.length > 1,
      );
      expect(multi, name).toEqual([]);
    }
  });

  it("resets the bracket depth at a line that can only start a new statement", () => {
    // Line 2 never closes its bracket (invalid code, or a construct the lexer
    // does not know). Recovery happens at the next def / class / decorator /
    // import / block header instead of at the end of the file.
    const lines = [
      "from flask import request",
      "broken = call(",
      "def view1():",
      '    eval(request.args["a"])',
      "broken_again = [",
      "class View:",
      "    def get(self):",
      '        eval(request.args["b"])',
      "more = {",
      "@app.route('/x')",
      "def view2():",
      '    eval(request.args["c"])',
      "    other = (",
      "    if ready:",
      '        eval(request.args["d"])',
      "    last = (",
      "    return 1",
      'eval(request.args["e"])',
    ];
    expect(hitsOf("lexer-recovery", lines)).toEqual([
      "4:py-eval-dynamic",
      "8:py-eval-dynamic",
      "12:py-eval-dynamic",
      "15:py-eval-dynamic",
      "18:py-eval-dynamic",
    ]);
  });

  it("resets at a top-level assignment or call once a statement stays open past the span limit", () => {
    const lines = ["from flask import request", "broken = call("];
    for (let index = 0; index < MAX_LOGICAL_LINE_SPAN + 2; index += 1) {
      lines.push(`    item_${index},`);
    }
    const first = lines.length + 1;
    for (let index = 0; index < 40; index += 1) {
      lines.push(`value_${index} = eval(request.args["k${index}"])`);
    }
    const units = pythonLogicalLines(lines);
    const after = units.filter((unit) => unit.start >= first - 1);
    expect(after).toHaveLength(40);
    expect(after.every((unit) => unit.offsets.length === 1)).toBe(true);
    expect(hitsOf("lexer-soft-recovery", lines)).toEqual(
      Array.from({ length: 40 }, (_, index) => `${first + index}:py-eval-dynamic`),
    );
    // A legitimate long literal is still one statement cut into chunks: lines
    // inside it do not look like new statements.
    const literal = ["values = ["];
    for (let index = 0; index < 40; index += 1) literal.push(`    ${index},`);
    literal.push("]", "x = 1");
    const literalUnits = pythonLogicalLines(literal);
    expect(literalUnits.at(-1)).toMatchObject({ start: literal.length - 1, text: "x = 1" });
  });

  it("does not treat prose in a multi-line string as a new statement", () => {
    const units = pythonLogicalLines([
      'HELP = """',
      "def example():",
      "import os",
      "if x:",
      '"""',
      "x = 1",
    ]);
    expect(units.map((unit) => [unit.start, unit.offsets.length])).toEqual([
      [0, 5],
      [5, 1],
    ]);
  });

  it("matches the body that follows a def or class header and an import on the same line", () => {
    expect(
      hitsOf("decl-body", [
        "from flask import request",
        'def f(): return eval(request.args["q"])',
        'class A: x = eval(request.args["q"])',
        'import os; os.system("ls " + request.args["a"])',
        "async def g(",
        "    a,",
        '): return eval(request.args["z"])',
        // Headers and imports themselves are still not matched.
        "def eval(request_args): pass",
        "from request.args import eval",
      ]),
    ).toEqual([
      "2:py-eval-dynamic",
      "3:py-eval-dynamic",
      "4:py-command-injection",
      "7:py-eval-dynamic",
    ]);
    const units = pythonLogicalLines([
      "def f(a: int = 3) -> Dict[str, int]: return a",
      "class A(Base): x = 1",
      "import os; x = 1",
      "from a import (",
      "    b,",
      ")",
      "x = {1: 2}",
    ]);
    expect(units.map((unit) => unit.text.slice(unit.headerEnd))).toEqual([
      " return a",
      " x = 1",
      " x = 1",
      "",
      "x = {1: 2}",
    ]);
  });

  it("applies notPattern to the matched call, not to the whole statement", () => {
    expect(
      hitsOf("not-scope", [
        "import os, requests, yaml",
        "from flask import request",
        // The basename() call belongs to another statement on the same line.
        'safe_name = os.path.basename("x"); h = open(request.args["f"])',
        // The safe call is a sibling argument, not part of the first call.
        "docs = [",
        "    yaml.load(first),",
        "    yaml.load(second, Loader=yaml.SafeLoader),",
        "]",
        // Still suppressed: the sanitizer is inside the matched call, also
        // when the call spans lines.
        'open(os.path.join(BASE, os.path.basename(request.args["f"])))',
        "open(",
        "    os.path.join(BASE,",
        '                 secure_filename(request.args["f"])),',
        ")",
        "yaml.load(",
        "    third,",
        "    Loader=yaml.SafeLoader,",
        ")",
      ]),
    ).toEqual(["3:py-path-traversal", "5:py-yaml-load"]);

    const project = path.join(temp, "not-scope-hotspots");
    writeFile(project, "client.py", [
      "import requests",
      "responses = [",
      "    requests.get(first),",
      "    requests.get(second, timeout=3),",
      "]",
      "requests.get(third); session.get(other, timeout=3)",
      "requests.post(",
      "    url,",
      "    timeout=5,",
      ")",
      "",
    ].join("\n"));
    const result = scanRules(inventory(project).files, ruleSet);
    expect(
      result.hits
        .filter((hit) => hit.rule.id === "py-requests-timeout")
        .map((hit) => hit.line),
    ).toEqual([3, 6]);
  });
});

describe("engine guard against expensive input", () => {
  const ruleSet = loadRules(RULES_DIR);

  // Changed deliberately (fail open): an over-long line used to be skipped
  // completely; now it is matched in overlapping windows and reported.
  it("matches over-long lines in windows and says so, for every language", () => {
    const project = path.join(temp, "over-long");
    const filler = " ".repeat(MAX_PATTERN_LINE_LENGTH);
    writeFile(project, "app.py", [
      "import os",
      `os.system(${filler}"ls " + name)`,
      `values = [${filler}`,
      "]",
      'os.system("ls " + name)',
      "",
    ].join("\n"));
    writeFile(project, "app.js", [
      `eval(${filler}input);`,
      "eval(input);",
      "",
    ].join("\n"));
    const result = scanRules(inventory(project).files, ruleSet);
    const rows = result.hits.map((hit) => `${hit.file.relPath}:${hit.line}:${hit.rule.id}`);
    // The start of each long line is matched (the sink is there); the Python
    // lexer still tracks their brackets, so the statement after them is
    // matched normally.
    expect(rows).toEqual([
      "app.js:1:js-eval",
      "app.js:2:js-eval",
      "app.py:2:py-os-system-api",
      "app.py:5:py-command-injection",
    ]);
    expect(result.warnings.sort()).toEqual([
      `1 over-long line(s) (more than ${MAX_PATTERN_LINE_LENGTH} characters) in app.js at line(s) 1: matched in overlapping windows`,
      `2 over-long line(s) (more than ${MAX_PATTERN_LINE_LENGTH} characters) in app.py at line(s) 2, 3: matched in overlapping windows`,
    ]);
  });

  it("scans the review's ReDoS input quickly, below and above the line cap", () => {
    const project = path.join(temp, "redos-input");
    const lines: string[] = [];
    for (const size of [MAX_PATTERN_LINE_LENGTH - 20, 6000]) {
      for (const sink of ["os.system(", "cursor.execute(", "subprocess.run(", "eval(", "logging.info(", "x = "]) {
        lines.push(sink + " ".repeat(size - sink.length));
      }
    }
    writeFile(project, "app.py", [...lines, ""].join("\n"));
    const started = performance.now();
    const result = scanRules(inventory(project).files, ruleSet);
    const elapsed = performance.now() - started;
    expect(result.hits.filter((hit) => hit.rule.kind === "finding")).toEqual([]);
    // The former rules needed about 17 s for one such line.
    expect(elapsed).toBeLessThan(2000);
  });

  it("stops matching a file when a careless rule exhausts the time budget", () => {
    // Three quantifiers compete for the same blanks: cubic backtracking.
    const rulesDir = writeRules("slow-rules", [
      "rules:",
      "  - id: t-slow",
      "    title: slow",
      "    pattern: 'slow\\(\\s*\\s*\\s*done'",
      ...RULE_TAIL,
      "  - id: t-fast",
      "    title: fast",
      "    pattern: 'marker'",
      ...RULE_TAIL,
    ]);
    const lines = ["marker"];
    for (let index = 0; index < 200; index += 1) {
      lines.push(`slow(${" ".repeat(600)}`);
    }
    lines.push("marker");
    const project = path.join(temp, "slow-src");
    writeFile(project, "app.py", [...lines, ""].join("\n"));
    writeFile(project, "other.py", "marker\n");
    const started = performance.now();
    const result = scanRules(inventory(project).files, loadRules(rulesDir), {
      fileBudgetMs: 300,
    });
    const elapsed = performance.now() - started;
    // Unbounded, the 200 lines take well over ten seconds.
    expect(elapsed).toBeLessThan(5000);
    // On a fast machine the budget check between matches stops the file; on a
    // slow one a single match outlives the budget and the hard interrupt does.
    // Either way the file is named in a warning.
    expect(result.warnings.join("\n")).toMatch(
      /rule matching stopped at line \d+ of app\.py: time budget of 300 ms exceeded|rule matching of app\.py was interrupted after \d+ ms/,
    );
    // Results found before the budget ran out are kept, and other files are
    // still scanned.
    expect(result.hits.map((hit) => `${hit.file.relPath}:${hit.line}`).sort()).toEqual([
      "app.py:1",
      "other.py:1",
    ]);
  });
});

describe("evidence of credential rules", () => {
  const ruleSet = loadRules(RULES_DIR);
  const SECRETS = [
    "k9Zq7Lw2Xv4Tn8Rb6Yc1Mh3Jd5Gf0PsA",
    "Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0LzXcV",
    "Sup3rS3cr3tK3y!!0123456789abcdef",
    "1234567890abcdef",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY",
    "9f8e7d6c5b4a39281706f5e4d3c2b1a0",
    "Tf9SuperSecretValue123",
    "k8sPlainSecretValue9876",
    "mcpInlineSecret_0123456789",
    "shortpw1",
    "deploy:Tr0ub4dor3xyz",
  ];

  function writeSecretProject(name: string): string {
    const project = path.join(temp, name);
    // The review's proof of concept (poc4).
    writeFile(project, "settings.py", [
      "import os",
      `SECRET_KEY = "${SECRETS[0]}"`,
      `app.secret_key = "${SECRETS[1]}"`,
      `cipher = AES.new(b"${SECRETS[2]}", AES.MODE_CBC, b"${SECRETS[3]}")`,
      `AWS_SECRET_ACCESS_KEY = "${SECRETS[4]}"`,
      `API_SECRET_KEY = "${SECRETS[5]}"`,
      `config = {"SECRET_KEY": "${SECRETS[9]}"}`,
      "",
    ].join("\n"));
    writeFile(project, "infra/main.tf", [
      'provider "aws" {',
      `  secret_key = "${SECRETS[6]}"`,
      "}",
      "",
    ].join("\n"));
    writeFile(project, "k8s/pod.yml", [
      "apiVersion: v1",
      "kind: Pod",
      "spec:",
      "  containers:",
      "    - name: app",
      "      image: app:1.2.3",
      "      env:",
      "        - name: API_KEY",
      `          value: ${SECRETS[7]}`,
      "",
    ].join("\n"));
    writeFile(project, "Dockerfile", [
      "FROM python:3.12",
      "USER app",
      `RUN pip install --index-url http://${SECRETS[10]}@pypi.internal/simple pkg`,
      "RUN pip install --index-url http://pypi.internal/simple other",
      "",
    ].join("\n"));
    writeFile(project, "agents/mcp.json", [
      "{",
      `  "mcpServers": { "x": { "env": { "token": "${SECRETS[8]}" } } }`,
      "}",
      "",
    ].join("\n"));
    return project;
  }

  it("marks every rule that matches a credential literal with redactEvidence", () => {
    const flagged = ruleSet.rules
      .filter((rule) => rule.redactEvidence)
      .map((rule) => rule.id)
      .sort();
    expect(flagged).toEqual([
      "agent-mcp-inline-secret",
      "cs-config-machinekey-literal",
      "cs-hardcoded-crypto-key",
      "cs-jwt-hardcoded-key",
      "dep-http-install",
      "dep-pip-trusted-host",
      "k8s-secret-in-env",
      "py-hardcoded-secret",
      "py-secret-key-literal",
      "py-static-iv",
      "tf-hardcoded-credentials",
    ]);
  });

  it("rejects a redactEvidence value that is not a boolean", () => {
    const rulesDir = writeRules("bad-redact", [
      "rules:",
      "  - id: t-redact",
      "    title: redact",
      "    pattern: 'x'",
      "    redactEvidence: sometimes",
      ...RULE_TAIL,
    ]);
    expect(() => loadRules(rulesDir)).toThrow(/redactEvidence/);
  });

  it("masks literals from the match on, a named secret group, or the match itself", () => {
    // 16 characters or more: only the first 2 and last 2 stay visible.
    expect(redactEvidenceLine('cfg["SECRET_KEY"] = "0123456789abcdefghij"', 5, 42)).toBe(
      'cfg["SECRET_KEY"] = "01****************ij"',
    );
    // Short values are masked completely.
    expect(redactEvidenceLine('{"SECRET_KEY": "hunter2pass"}', 2, 28)).toBe(
      '{"SECRET_KEY": "***********"}',
    );
    expect(
      redactEvidenceLine("value: plainsecretvalue1234", 0, 27, { start: 7, end: 27 }),
    ).toBe("value: pl****************34");
    // A secret group that starts right after a quote covers the whole quoted
    // value, also the part after a character the pattern does not accept.
    expect(
      redactEvidenceLine('value: "LEAKYYYY1234!@#LEAKZZZZtail99"', 0, 20, { start: 8, end: 20 }),
    ).toBe('value: "LE************************99"');
    expect(redactEvidenceLine("token = abcdef", 0, 14)).toBe("[redacted]");
    // The pattern has a secret group that did not take part: nothing to mask.
    expect(redactEvidenceLine("pip install --index-url http://host/x", 0, 37, "absent")).toBe(
      "pip install --index-url http://host/x",
    );
  });

  it("keeps secret literals out of the rule hits", () => {
    const project = writeSecretProject("secret-hits");
    const result = scanRules(inventory(project).files, ruleSet);
    const redacted = result.hits.filter((hit) => hit.rule.redactEvidence);
    expect(redacted.map((hit) => `${hit.file.relPath}:${hit.line}:${hit.rule.id}`).sort()).toEqual([
      "Dockerfile:3:dep-http-install",
      "Dockerfile:3:dep-pip-trusted-host",
      "Dockerfile:4:dep-http-install",
      "Dockerfile:4:dep-pip-trusted-host",
      "agents/mcp.json:2:agent-mcp-inline-secret",
      "infra/main.tf:2:tf-hardcoded-credentials",
      "k8s/pod.yml:9:k8s-secret-in-env",
      "settings.py:2:py-hardcoded-secret",
      "settings.py:3:py-hardcoded-secret",
      "settings.py:4:py-static-iv",
      "settings.py:5:py-secret-key-literal",
      "settings.py:6:py-hardcoded-secret",
      "settings.py:7:py-secret-key-literal",
    ]);
    for (const hit of result.hits) {
      for (const secret of SECRETS) expect(hit.evidence).not.toContain(secret);
    }
    const byLine = new Map(
      redacted.filter((hit) => hit.file.relPath === "settings.py").map((hit) => [hit.line, hit.evidence]),
    );
    expect(byLine.get(2)).toBe('SECRET_KEY = "k9************************sA"');
    expect(byLine.get(4)).toBe(
      'cipher = AES.new(b"Su************************ef", AES.MODE_CBC, b"12************ef")',
    );
    expect(byLine.get(7)).toBe('config = {"SECRET_KEY": "********"}');
    const docker = redacted.filter((hit) => hit.file.relPath === "Dockerfile");
    expect(docker[0]?.evidence).toBe(
      "RUN pip install --index-url http://de****************yz@pypi.internal/simple pkg",
    );
    // No credentials in the URL: the evidence is the plain line.
    expect(docker.at(-1)?.evidence).toBe(
      "RUN pip install --index-url http://pypi.internal/simple other",
    );
  });

  it("writes no raw key to findings.json, report.md or results.sarif, and keeps fingerprints stable", async () => {
    const project = writeSecretProject("secret-scan");
    const out = path.join(temp, "secret-scan-out");
    const first = await scanProject({
      root: project,
      out,
      offline: true,
      engines: ["builtin"],
      formats: ["md", "json", "sarif"],
    });
    const output = readAllOutputFiles(out);
    for (const secret of SECRETS) expect(output).not.toContain(secret);
    const all = [...first.findings, ...first.hotspots];
    const key = all.find(
      (finding) => finding.ruleId === "py-hardcoded-secret" && finding.startLine === 2,
    );
    expect(key?.evidence).toBe('SECRET_KEY = "k9************************sA"');

    // The fingerprint is computed from the redacted evidence, as the secret
    // detector does: it does not depend on the full value of the secret.
    const source = fs.readFileSync(path.join(project, "settings.py"), "utf8");
    fs.writeFileSync(
      path.join(project, "settings.py"),
      source.replace(SECRETS[0] as string, "k9AAAAAAAAAAAAAAAAAAAAAAAAAAAAsA"),
    );
    const second = await scanProject({
      root: project,
      out: path.join(temp, "secret-scan-out2"),
      offline: true,
      engines: ["builtin"],
      formats: ["json"],
    });
    const again = [...second.findings, ...second.hotspots].find(
      (finding) => finding.ruleId === "py-hardcoded-secret" && finding.startLine === 2,
    );
    expect(again?.fingerprint).toBe(key?.fingerprint);
  });
});

// ---------------------------------------------------------------------------
// Regular-expression cost (ReDoS) guard for every built-in rule.
// ---------------------------------------------------------------------------

interface SampleToken {
  text: string;
  /** True when the token comes from a quantified atom or a character class. */
  open: boolean;
}

const CLASS_CANDIDATES = [
  "a", "A", "1", " ", "_", ".", "/", "-", '"', "'", "(", ")", "=", ":", ",",
  "{", "[", "<", "$", "%", "*", "+", "\\", "@", "#", "\n",
];

/**
 * Build example strings that a regular expression accepts (approximately), as
 * token lists. This is a small recursive-descent reader for the subset of the
 * JavaScript regex syntax that rule files use; it is only good enough to walk
 * a matcher into each part of a pattern so the pathological inputs below start
 * where the pattern's quantifiers are.
 */
function regexSamples(source: string, flags: string): SampleToken[][] {
  let pos = 0;
  const classFlags = flags.replace(/[gy]/g, "");

  const combine = (
    left: SampleToken[][],
    right: SampleToken[][],
    limit: number,
  ): SampleToken[][] => {
    if (left.length * right.length <= limit) {
      return left.flatMap((l) => right.map((r) => [...l, ...r]));
    }
    const size = Math.min(limit, Math.max(left.length, right.length));
    const result: SampleToken[][] = [];
    for (let index = 0; index < size; index += 1) {
      result.push([
        ...(left[index % left.length] as SampleToken[]),
        ...(right[index % right.length] as SampleToken[]),
      ]);
    }
    return result;
  };

  const parseAlternation = (limit: number): SampleToken[][] => {
    const result: SampleToken[][] = [];
    for (;;) {
      result.push(...parseSequence(limit));
      if (source[pos] === "|") {
        pos += 1;
        continue;
      }
      break;
    }
    return result.slice(0, limit);
  };

  const parseQuantifier = (): { min: number; max: number } | undefined => {
    const ch = source[pos];
    let quantifier: { min: number; max: number } | undefined;
    if (ch === "*") quantifier = { min: 0, max: Infinity };
    else if (ch === "+") quantifier = { min: 1, max: Infinity };
    else if (ch === "?") quantifier = { min: 0, max: 1 };
    else if (ch === "{") {
      const counted = /^\{(\d+)(,(\d*))?\}/.exec(source.slice(pos));
      if (!counted) return undefined;
      const min = Number(counted[1]);
      const max =
        counted[2] === undefined ? min : counted[3] ? Number(counted[3]) : Infinity;
      pos += counted[0].length - 1;
      quantifier = { min, max };
    }
    if (!quantifier) return undefined;
    pos += 1;
    if (source[pos] === "?") pos += 1;
    return quantifier;
  };

  const parseAtom = (limit: number): SampleToken[][] => {
    const ch = source[pos] as string;
    if (ch === "(") {
      pos += 1;
      let lookaround = false;
      if (source.startsWith("?:", pos)) pos += 2;
      else if (source.startsWith("?=", pos) || source.startsWith("?!", pos)) {
        lookaround = true;
        pos += 2;
      } else if (source.startsWith("?<=", pos) || source.startsWith("?<!", pos)) {
        lookaround = true;
        pos += 3;
      } else if (source.startsWith("?<", pos)) {
        pos = source.indexOf(">", pos) + 1;
      }
      const inner = parseAlternation(Math.max(2, Math.min(4, limit)));
      // Skip alternatives that did not fit in the limit.
      let depth = 0;
      while (pos < source.length) {
        const c = source[pos];
        if (c === "\\") pos += 1;
        else if (c === "[") {
          pos += 1;
          while (pos < source.length && source[pos] !== "]") {
            if (source[pos] === "\\") pos += 1;
            pos += 1;
          }
        } else if (c === "(") depth += 1;
        else if (c === ")") {
          if (depth === 0) break;
          depth -= 1;
        }
        pos += 1;
      }
      pos += 1;
      return lookaround ? [[]] : inner;
    }
    if (ch === "[") {
      const start = pos;
      pos += 1;
      while (pos < source.length && source[pos] !== "]") {
        if (source[pos] === "\\") pos += 1;
        pos += 1;
      }
      pos += 1;
      const matcher = new RegExp(source.slice(start, pos), classFlags);
      const pick = CLASS_CANDIDATES.find((candidate) => matcher.test(candidate)) ?? "";
      return [[{ text: pick, open: true }]];
    }
    if (ch === "\\") {
      const next = source[pos + 1] as string;
      pos += 2;
      const simple: Record<string, string> = {
        b: "", B: "", s: " ", S: "a", w: "a", W: " ", d: "1", D: "a",
        n: "\n", t: "\t", r: "\r",
      };
      if (next in simple) {
        return [[{ text: simple[next] as string, open: /[sSwWdD]/.test(next) }]];
      }
      if (next === "x") {
        const code = source.slice(pos, pos + 2);
        pos += 2;
        return [[{ text: String.fromCharCode(parseInt(code, 16)), open: false }]];
      }
      if (next === "u") {
        const code = source.slice(pos, pos + 4);
        pos += 4;
        return [[{ text: String.fromCharCode(parseInt(code, 16)), open: false }]];
      }
      if (/\d/.test(next)) return [[]];
      return [[{ text: next, open: false }]];
    }
    pos += 1;
    if (ch === "^" || ch === "$") return [[]];
    if (ch === ".") return [[{ text: "a", open: true }]];
    return [[{ text: ch, open: false }]];
  };

  const parseSequence = (limit: number): SampleToken[][] => {
    let variants: SampleToken[][] = [[]];
    while (pos < source.length && source[pos] !== "|" && source[pos] !== ")") {
      let atom = parseAtom(limit);
      const quantifier = parseQuantifier();
      if (quantifier) {
        const reps = quantifier.max === 0 ? 0 : Math.min(48, Math.max(1, quantifier.min));
        atom = atom.map((tokens) => {
          const repeated: SampleToken[] = [];
          for (let index = 0; index < reps; index += 1) {
            repeated.push(...tokens.map((token) => ({ ...token, open: true })));
          }
          return repeated;
        });
      }
      variants = combine(variants, atom, limit);
    }
    return variants;
  };

  return parseAlternation(16);
}

/** Prefixes of the samples that end right before or after an open token. */
function samplePrefixes(source: string, flags: string, cap: number): string[] {
  const prefixes = new Set<string>([""]);
  for (const tokens of regexSamples(source, flags)) {
    let text = "";
    for (const token of tokens) {
      if (token.open) prefixes.add(text);
      text += token.text;
      if (token.open) prefixes.add(text);
    }
    prefixes.add(text);
  }
  const all = [...prefixes]
    .filter((prefix) => prefix.length <= 200)
    .sort((left, right) => left.length - right.length);
  if (all.length <= cap) return all;
  // The shortest prefixes lead into the first quantifiers of every
  // alternative; the rest is sampled evenly.
  const head = Math.ceil(cap / 2);
  const picked = all.slice(0, head);
  const rest = all.slice(head);
  const step = rest.length / (cap - head);
  for (let index = 0; index < cap - head; index += 1) {
    picked.push(rest[Math.floor(index * step)] as string);
  }
  return picked;
}

const PUMPS = [
  " ", "(", "a", '"', "'", "=", "a ", "a(", "a.", "a, ", '"a" ', "\\", "{", "[", "a=", "\t",
];

function pathologicalInputs(prefix: string, size: number): string[] {
  const inputs: string[] = [];
  for (const pump of PUMPS) {
    inputs.push(prefix + pump.repeat(Math.ceil(size / pump.length)));
    if (prefix.length > 0) {
      const unit = prefix + pump;
      inputs.push(unit.repeat(Math.ceil(size / unit.length)));
    }
  }
  if (prefix.length > 0) inputs.push(prefix.repeat(Math.ceil(size / prefix.length)));
  return inputs;
}

/**
 * Worst time, in milliseconds, of one regex over the pathological inputs.
 * Sizes grow in stages so a cubic or exponential pattern is caught on a small
 * input instead of hanging the test.
 */
function worstRegexCost(
  regex: RegExp,
  prefixCap = 14,
): { ms: number; size: number; input: string } | undefined {
  const stages: Array<{ size: number; budget: number }> = [
    { size: 300, budget: 40 },
    { size: 1000, budget: 50 },
    { size: 3000, budget: 60 },
    { size: 30000, budget: 200 },
  ];
  const probe = new RegExp(regex.source, regex.flags.replace(/[gy]/g, ""));
  const prefixes = samplePrefixes(regex.source, regex.flags, prefixCap);
  for (const stage of stages) {
    for (const prefix of prefixes) {
      for (const input of pathologicalInputs(prefix, stage.size)) {
        let best = Infinity;
        // Two attempts: a slow first run can be noise, a slow second run is not.
        for (let attempt = 0; attempt < 2; attempt += 1) {
          const started = performance.now();
          probe.test(input);
          best = Math.min(best, performance.now() - started);
          if (best <= stage.budget) break;
        }
        if (best > stage.budget) {
          return { ms: Math.round(best), size: stage.size, input: input.slice(0, 60) };
        }
      }
    }
  }
  return undefined;
}

describe("regular-expression cost of the built-in rules", () => {
  const ruleSet = loadRules(RULES_DIR);
  const sourceFiles = [...new Set(ruleSet.rules.map((rule) => rule.sourceFile))].sort();

  it("covers every rule file: all languages, iac, agent and deps", () => {
    const folders = new Set(sourceFiles.map((file) => file.split(path.sep)[0]));
    expect([...folders].sort()).toEqual(["agent", "deps", "iac", "sast"]);
    expect(sourceFiles.length).toBeGreaterThanOrEqual(17);
  });

  // Every pattern, notPattern and filePattern of every built-in rule runs
  // against long runs of blanks, brackets, letters, quotes and "=" placed
  // after prefixes derived from the pattern itself. A pattern that needs more
  // than the budget on 30 000 characters backtracks quadratically or worse.
  it.each(sourceFiles)("runs every pattern of %s in near-linear time", (sourceFile) => {
    const slow: string[] = [];
    let checked = 0;
    for (const rule of ruleSet.rules) {
      if (rule.sourceFile !== sourceFile) continue;
      const compiled = rule.compiled;
      const entries: Array<[string, RegExp | undefined]> = [
        ["pattern", compiled.pattern],
        ...(compiled.patterns ?? []).map(
          (pattern, index): [string, RegExp] => [`patterns[${index}]`, pattern],
        ),
        ["notPattern", compiled.notPattern],
        ["filePattern", compiled.filePattern],
        ["fileAbsentPattern", compiled.fileAbsentPattern],
      ];
      for (const [field, regex] of entries) {
        if (!regex) continue;
        checked += 1;
        const cost = worstRegexCost(regex);
        if (cost) {
          slow.push(
            `${rule.id} ${field}: ${cost.ms} ms on ${cost.size} chars, input starts ${JSON.stringify(cost.input)}`,
          );
        }
      }
    }
    expect(checked).toBeGreaterThan(0);
    expect(slow).toEqual([]);
  }, 300_000);

  it("flags the patterns the review found (the guard itself works)", () => {
    // The former FIRSTREQ / DYN call site: three quantifiers compete for blanks.
    const cubic = /\bos\.system\s*\(\s*(?:\s*(?:[\w.]+\()*[^,()\n]*?\brequest\.args\b)/i;
    expect(worstRegexCost(cubic)).toBeDefined();
    // The former py-assert-auth: \s+ next to a class that matches blanks.
    const quadratic = /^\s*assert\s+[^,\n]*\bis_admin\b/i;
    expect(worstRegexCost(quadratic)).toBeDefined();
    expect(worstRegexCost(/\bos\.system\s*\(/i)).toBeUndefined();
  }, 120_000);
});
