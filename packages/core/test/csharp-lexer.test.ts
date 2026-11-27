import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { inventory } from "../src/inventory.js";
import {
  MAX_LOGICAL_LINE_SPAN,
  MAX_PATTERN_LINE_LENGTH,
  SKELETON_FIELD,
  csharpLogicalLines,
  emptyLexDiagnostics,
  loadRules,
  markupLogicalLines,
  scanRules,
  type LogicalLine,
} from "../src/rules.js";
import { RULES_DIR, cleanup, makeTempDir, writeFile } from "./helpers.js";

const temp = makeTempDir("csharp-lexer");

afterAll(() => cleanup(temp));

/** Units with code, in order; extra (fail-open) units are listed last by the lexer. */
function lex(lines: string[]): { units: LogicalLine[]; diagnostics: ReturnType<typeof emptyLexDiagnostics> } {
  const diagnostics = emptyLexDiagnostics();
  const units = csharpLogicalLines(lines, [], diagnostics);
  return { units, diagnostics };
}

function codeUnits(lines: string[]): LogicalLine[] {
  return lex(lines).units.filter((unit) => unit.text.trim().length > 0 && !unit.extra);
}

/** The skeleton with the hole filler shown as "#". */
function shownSkeleton(unit: LogicalLine): string {
  return (unit.skeleton ?? "").split(SKELETON_FIELD).join("#");
}

describe("C# lexer: comments", () => {
  it("blanks //, /// and /* */ comments and keeps columns", () => {
    const units = codeUnits([
      "// Process.Start(x + y)",
      "/// <summary>Process.Start(x)</summary>",
      "var a = 1; // trailing Process.Start(a)",
      "var b = /* inline */ 2;",
      "/* block",
      "   Process.Start(a + b) */ var c = 3;",
    ]);
    expect(units.map((unit) => [unit.start, unit.text.trimEnd()])).toEqual([
      [2, "var a = 1;"],
      [3, "var b =              2;"],
      [5, "                           var c = 3;"],
    ]);
    // Same columns as the physical line.
    expect(units[2]?.text.indexOf("var c")).toBe("   Process.Start(a + b) */ ".length);
  });

  it("never treats // inside a string as a comment", () => {
    const units = codeUnits([
      'var url = "http://example.com/a"; // real comment',
      'var path = @"C:\\temp\\// not a comment";',
      'var raw = """http://x // y""";',
    ]);
    expect(units[0]?.text.trimEnd()).toBe('var url = "http://example.com/a";');
    expect(units[1]?.text).toContain("// not a comment");
    expect(units[2]?.text).toContain("// y");
  });
});

describe("C# lexer: string literals", () => {
  it("handles escapes in regular strings and character literals", () => {
    const [unit] = codeUnits([
      "var s = \"a\\\"b // c\"; char q = '\\''; char d = '\"'; char p = '('; Foo(p);",
    ]);
    expect(unit?.text).toContain('"a\\"b // c"');
    // String and character contents are blank in the skeleton; brackets in
    // them do not count.
    expect(unit?.skeleton).toBe(
      "var s = \"         \"; char q = '  '; char d = ' '; char p = ' '; Foo(p);",
    );
  });

  it("handles verbatim strings with doubled quotes, also across lines", () => {
    const units = codeUnits([
      'var sql = @"SELECT ""Name""',
      "  FROM Users -- not code ) (",
      '  WHERE Id = 1";',
      "var next = 1;",
    ]);
    expect(units).toHaveLength(2);
    expect(units[0]?.offsets).toHaveLength(3);
    expect(units[0]?.text).toContain("FROM Users");
    // The line breaks inside the literal do not end anything.
    expect(units[0]?.skeleton).not.toContain("\n");
    expect(units[0]?.skeleton?.trimEnd().endsWith('";')).toBe(true);
    expect(units[1]?.text).toBe("var next = 1;");
  });

  it("treats the code in interpolation holes as code, with nested quotes and braces", () => {
    const [unit] = codeUnits([
      'var s = $"a {b + "x}"} c {{lit}} {d:N2} {(e ? "1" : "2")} {new { X = 1 }.X}";',
    ]);
    expect(unit).toBeDefined();
    const skeleton = shownSkeleton(unit as LogicalLine);
    expect(skeleton.startsWith('var s = $"')).toBe(true);
    expect(skeleton.endsWith('";')).toBe(true);
    // b + : code of a hole; "x}" : a nested string, blank; {{lit}} : text.
    expect(skeleton).toContain("# #");
    expect(skeleton).not.toContain("lit");
    // The format string N2 is literal text, (e ? ... ) is code.
    expect(skeleton).not.toContain("N2");
    expect(skeleton).toContain("## # ");
    // The braces of the anonymous object inside a hole do not end it.
    expect(skeleton).toContain("### # # # # ###");
    expect(unit?.text.length).toBe(unit?.skeleton?.length);
  });

  it("handles $@ and @$ prefixes and holes that span lines", () => {
    const units = codeUnits([
      'var a = $@"C:\\{dir}\\""x"" {Path(',
      '    "y")} end";',
      'var b = @$"{c}";',
    ]);
    expect(units).toHaveLength(2);
    expect(units[0]?.offsets).toHaveLength(2);
    expect(shownSkeleton(units[0] as LogicalLine)).toContain("###");
    expect(shownSkeleton(units[1] as LogicalLine)).toBe('var b = @$" # ";');
  });

  it("handles raw string literals with any number of quotes and $ / $$ prefixes", () => {
    const units = codeUnits([
      'var one = """He said "hi" and "" // ok""";',
      'var many = """"',
      '  A """ triple-quoted line inside ( [',
      '  """";',
      'var json = $$"""{"id": {{id}}, "set": {1, 2}}""";',
      'var mixed = $"""Total: {sum(1, 2)} done""";',
      "var after = 1;",
    ]);
    expect(units.map((unit) => unit.start)).toEqual([0, 1, 4, 5, 6]);
    expect(units[0]?.skeleton).toBe(`var one = """${" ".repeat('He said "hi" and "" // ok'.length)}""";`);
    expect(units[1]?.offsets).toHaveLength(3);
    const json = shownSkeleton(units[2] as LogicalLine);
    // Only {{id}} is a hole with $$; single braces are text.
    expect(json.match(/#/g)?.length).toBe(2);
    const mixed = shownSkeleton(units[3] as LogicalLine);
    // sum(1, 2) is a hole.
    expect(mixed).toContain("###### ##");
    expect(mixed.match(/#/g)?.length).toBe(8);
    expect(units[4]?.text).toBe("var after = 1;");
  });

  it("keeps literal text in `text` so rules can read SQL, and blanks it in the skeleton", () => {
    const [unit] = codeUnits(['var q = "SELECT * FROM T WHERE id = " + id;']);
    expect(unit?.text).toContain("SELECT * FROM T");
    expect(unit?.skeleton).toBe('var q = "                           " + id;');
  });
});

describe("C# lexer: statements", () => {
  it("joins a call that spans lines while ( or [ is open", () => {
    const units = codeUnits([
      "var cmd = new SqlCommand(",
      '    "SELECT * FROM T WHERE id = " +',
      "    id, conn);",
      "var list = new[] {",
      "    1,",
      "};",
    ]);
    expect(units.map((unit) => [unit.start, unit.offsets.length])).toEqual([
      [0, 3],
      [3, 1],
      [4, 1],
      [5, 1],
    ]);
  });

  it("does not join on { } and keeps attribute lines on their own", () => {
    const units = codeUnits([
      "[ValidateInput(false)]",
      "[HttpPost]",
      "public IActionResult Post(string id)",
      "{",
      "    Foo(x => {",
      "        Bar(id);",
      "    });",
      "}",
    ]);
    expect(units.map((unit) => unit.start)).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);
  });

  it("joins across a line break next to +, =, =>, . and ?:", () => {
    const units = codeUnits([
      'cmd.CommandText = "SELECT * FROM T WHERE id = " +',
      "    id;",
      "var q = db.Users",
      '    .FromSqlRaw("SELECT 1")',
      "    .ToList();",
      "var v = flag",
      "    ? a",
      "    : b;",
      "var x =",
      "    1;",
      "var done = 2;",
    ]);
    expect(units.map((unit) => [unit.start, unit.offsets.length])).toEqual([
      [0, 2],
      [2, 3],
      [5, 3],
      [8, 2],
      [10, 1],
    ]);
    // A continued expression is one expression: its line breaks are soft.
    expect(units[0]?.skeleton).not.toContain("\n");
  });

  it("starts every #if branch from the bracket state at the #if", () => {
    const units = codeUnits([
      "#if DEBUG",
      "    Foo(a,",
      "#else",
      "    Foo(b,",
      "#endif",
      "      c);",
      "var after = 1;",
      "#region Things with an ' apostrophe",
      "var more = 2;",
      "#endregion",
    ]);
    expect(units.map((unit) => unit.start)).toEqual([1, 3, 6, 8]);
    expect(units.find((unit) => unit.start === 6)?.text).toBe("var after = 1;");
  });
});

describe("C# lexer: fail open", () => {
  it("re-adds the region as plain lines when the file ends inside a block comment", () => {
    const { units, diagnostics } = lex(["var a = 1;", "/* never closed", "Process.Start(cmd + x);"]);
    expect(diagnostics.fallbacks).toEqual([
      { from: 1, to: 2, reason: "the file ends inside a block comment" },
    ]);
    expect(units.some((unit) => unit.extra && unit.text.includes("Process.Start"))).toBe(true);
  });

  it("re-adds the region when the file ends inside a verbatim or raw string", () => {
    for (const opening of ['var s = @"open', 'var s = """', 'var s = $"{Foo(']) {
      const { units, diagnostics } = lex([opening, "Process.Start(cmd + x);", "var y = 2;"]);
      expect(diagnostics.fallbacks, opening).toEqual([
        { from: 0, to: 2, reason: "the file ends inside a string literal" },
      ]);
      expect(units.some((unit) => unit.extra && unit.start === 1)).toBe(true);
    }
  });

  it("re-adds the region when the file ends inside an open ( or [", () => {
    const { diagnostics } = lex(["Foo(a,", "  b,", "  c"]);
    expect(diagnostics.fallbacks).toEqual([
      { from: 0, to: 2, reason: 'the file ends inside an open "(" or "["' },
    ]);
  });

  it("recovers at a member declaration inside an open (", () => {
    const { units, diagnostics } = lex([
      "class A {",
      "  void M() {",
      "    Foo(a,",
      "  }",
      "  public void N() {",
      "    Process.Start(cmd + x);",
      "  }",
      "}",
    ]);
    // The "}" closes the method body while "(" is open: the joined lines are
    // matched again as plain text, and the rest of the file is lexed normally.
    expect(diagnostics.fallbacks.length).toBeGreaterThan(0);
    const after = units.filter((unit) => !unit.extra && unit.text.includes("Process.Start"));
    expect(after).toHaveLength(1);
    expect(after[0]?.start).toBe(5);
    expect(after[0]?.offsets).toHaveLength(1);
  });

  it("closes a regular string at the end of its line and matches that line as plain text", () => {
    const { units, diagnostics } = lex(['var s = "never closed Process.Start(x + y);', "var t = 1;"]);
    expect(diagnostics.fallbacks).toEqual([
      { from: 0, to: 0, reason: "a string is not closed at the end of its line" },
    ]);
    expect(units.filter((unit) => !unit.extra).map((unit) => unit.start)).toContain(1);
    expect(units.some((unit) => unit.extra && unit.start === 0)).toBe(true);
  });

  it("re-adds a long multi-line string whose lines look like statements", () => {
    const lines = ['var s = @"'];
    for (let index = 0; index < 70; index += 1) lines.push(`var x${index} = Compute(${index});`);
    lines.push('";');
    const { diagnostics } = lex(lines);
    expect(diagnostics.fallbacks).toHaveLength(1);
    expect(diagnostics.fallbacks[0]?.reason).toMatch(/string literal of 71 lines contains 70 lines/);
  });

  it("names the language in the warning and still reports hits in the region", () => {
    const project = path.join(temp, "fallback");
    writeFile(project, "App.cs", ["class A {", "  void M() {", "    /* oops", '    Process.Start("sh", "-c " + cmd);', ""].join("\n"));
    const result = scanRules(inventory(project).files, loadRules(RULES_DIR));
    expect(result.warnings.some((warning) => warning.startsWith("csharp lexer fallback in App.cs from line 3 to line 5"))).toBe(true);
    expect(result.hits.map((hit) => `${hit.rule.id}:${hit.line}`)).toContain("cs-command-shell:4");
  });
});

describe("C# lexer: limits", () => {
  it("cuts a statement longer than the span limit into overlapping windows", () => {
    const lines = ["var values = Build("];
    for (let index = 0; index < MAX_LOGICAL_LINE_SPAN * 2; index += 1) lines.push(`    ${index},`);
    lines.push(");");
    const { units, diagnostics } = lex(lines);
    expect(diagnostics.cuts).toEqual([0]);
    // A window holds at most the span limit of new lines plus the half it
    // repeats from the window before.
    for (const unit of units) expect(unit.offsets.length).toBeLessThanOrEqual(MAX_LOGICAL_LINE_SPAN * 1.5);
    expect(units.filter((unit) => unit.offsets.length > 1).length).toBeGreaterThan(1);
    // Every line is in at least one unit.
    const covered = new Set<number>();
    for (const unit of units) unit.offsets.forEach((_, index) => covered.add(unit.start + index));
    expect(covered.size).toBe(lines.length);
  });

  it("matches an over-long line in windows", () => {
    const line = `var x = "${"a".repeat(MAX_PATTERN_LINE_LENGTH * 2)}"; Process.Start(cmd + y);`;
    const overLong: number[] = [];
    const units = csharpLogicalLines([line], overLong, emptyLexDiagnostics());
    expect(overLong).toEqual([0]);
    expect(units.some((unit) => unit.extra && unit.text.includes("Process.Start"))).toBe(true);
  });

  it("lexes large and hostile input in linear time", () => {
    const inputs: string[][] = [
      // 200 000 ordinary lines.
      Array.from({ length: 200_000 }, (_, index) => `    var v${index} = Foo("s", '${index % 10}', $"{index}") + 1; // c`),
      // One 1 MB line of quotes, braces and dollars.
      ['$"{' + '"$@{'.repeat(250_000)],
      // Deep nesting and many unclosed constructs.
      ["(".repeat(200_000)],
      Array.from({ length: 50_000 }, () => 'var s = "open'),
      Array.from({ length: 50_000 }, () => "/* a */ /* b"),
      Array.from({ length: 50_000 }, () => '$$"""{{ {'),
      // Long runs of $ and @ (string prefixes that never reach a quote).
      ["$".repeat(1_000_000)],
      ["@$".repeat(500_000)],
      // A deep bracket stack followed by closers that do not match, and #if
      // lines that save the bracket state.
      [...Array.from({ length: 50_000 }, () => "(((("), ...Array.from({ length: 50_000 }, () => "} #")],
      [...Array.from({ length: 2_000 }, () => "{ ( [ ("), ...Array.from({ length: 50_000 }, () => "#if A")],
      // Every closer ends a fallback region that overlaps the previous one.
      [...Array.from({ length: 25_000 }, () => "{ ("), ...Array.from({ length: 25_000 }, () => "}")],
      // A namespace declaration padded with blanks while a ( is open.
      ["Foo(", `namespace a${" ".repeat(900)}x`],
    ];
    for (const input of inputs) {
      const started = performance.now();
      csharpLogicalLines(input, [], emptyLexDiagnostics());
      expect(performance.now() - started, input[0]?.slice(0, 20)).toBeLessThan(5000);
    }
  }, 60_000);
});

describe("C# matching on logical lines", () => {
  const ruleSet = loadRules(RULES_DIR);

  function hits(name: string, lines: string[]): string[] {
    const project = path.join(temp, name);
    writeFile(project, "App.cs", [...lines, ""].join("\n"));
    return scanRules(inventory(project).files, ruleSet).hits.map((hit) => `${hit.rule.id}:${hit.line}`);
  }

  it("reports a multi-line call at the line where the match starts", () => {
    expect(
      hits("multiline", [
        "class A {",
        "  void M(string id) {",
        "    var cmd = new SqlCommand(",
        '        "SELECT * FROM T WHERE id = \'" +',
        "        id + \"'\", conn);",
        "  }",
        "}",
      ]),
    ).toEqual(["cs-sql-injection:3"]);
  });

  it("does not report code in comments or text in strings for codeOnly rules", () => {
    expect(
      hits("comments", [
        "class A {",
        '  // Process.Start("sh", "-c " + cmd);',
        "  /* var f = new BinaryFormatter();",
        "     MD5.Create(); */",
        '  const string Doc = "Call Process.Start(\\"sh\\", \\"-c \\" + cmd) or new BinaryFormatter()";',
        '  const string Raw = """',
        "     new BinaryFormatter();",
        '     """;',
        "}",
      ]),
    ).toEqual([]);
  });

  it("honours a suppression comment before a multi-line statement", () => {
    const project = path.join(temp, "suppressed");
    writeFile(
      project,
      "App.cs",
      [
        "class A {",
        "  void M(string id) {",
        "    // code-audit:ignore cs-sql-injection -- reviewed: id is an integer",
        "    var cmd = new SqlCommand(",
        '        "SELECT * FROM T WHERE id = " + id, conn);',
        "  }",
        "}",
        "",
      ].join("\n"),
    );
    const result = scanRules(inventory(project).files, ruleSet);
    expect(result.hits.filter((hit) => hit.rule.id === "cs-sql-injection")).toEqual([]);
    expect(result.suppressed.map((entry) => `${entry.ruleId}:${entry.line}`)).toEqual(["cs-sql-injection:4"]);
  });
});

describe("XML and Razor units", () => {
  it("blanks XML comments, keeps columns and joins a start tag up to its >", () => {
    const diagnostics = emptyLexDiagnostics();
    const units = markupLogicalLines(
      [
        '<a x="1"> <!-- <customErrors mode="Off" /> --> <b/>',
        "<!--",
        '  <compilation debug="true" />',
        "-->",
        '<compilation targetFramework="4.8"',
        '   note="a > b"',
        '   debug="true" />',
        "<![CDATA[ <not a tag ]]><c/>",
      ],
      "xml",
      [],
      diagnostics,
    ).filter((unit) => unit.text.trim().length > 0);
    expect(units.map((unit) => [unit.start, unit.offsets.length])).toEqual([
      [0, 1],
      [4, 3],
      [7, 1],
    ]);
    expect(units[0]?.text).toBe(`<a x="1"> ${" ".repeat(36)} <b/>`);
    expect(units[1]?.text).toContain('debug="true"');
    expect(diagnostics.fallbacks).toEqual([]);
  });

  it("blanks Razor @* *@ comments, also across lines, and keeps HTML comments", () => {
    const units = markupLogicalLines(
      ['<p>@* @Html.Raw(x) *@ ok</p>', "@*", "  @Html.Raw(y)", "*@", "<!-- @Html.Raw(z) -->"],
      "razor",
    ).filter((unit) => unit.text.trim().length > 0);
    expect(units.map((unit) => unit.text.trim())).toEqual([`<p>${" ".repeat(19)}ok</p>`, "<!-- @Html.Raw(z) -->"]);
  });

  it("fails open at the end of the file and for a start tag that never closes", () => {
    for (const [lines, language, reason] of [
      [["<a/>", "<!-- open", '<customErrors mode="Off" />'], "xml", "the file ends inside a comment"],
      [["@* open", "@Html.Raw(x)"], "razor", "the file ends inside a comment"],
      [['<compilation note="unclosed', 'debug="true" />'], "xml", "the file ends inside a start tag"],
    ] as const) {
      const diagnostics = emptyLexDiagnostics();
      const units = markupLogicalLines([...lines], language, [], diagnostics);
      expect(diagnostics.fallbacks[0]?.reason, lines[0]).toBe(reason);
      expect(units.some((unit) => unit.extra)).toBe(true);
    }
    const long = ["<a"];
    for (let index = 0; index < 120; index += 1) long.push(`  x${index}="1"`);
    long.push("/>");
    const diagnostics = emptyLexDiagnostics();
    const units = markupLogicalLines(long, "xml", [], diagnostics);
    expect(diagnostics.fallbacks[0]?.reason).toMatch(/start tag stays open/);
    for (const unit of units) expect(unit.offsets.length).toBeLessThanOrEqual(50);
  });

  it("lexes hostile markup in linear time", () => {
    for (const lines of [
      ["<!--".repeat(250_000)],
      Array.from({ length: 100_000 }, () => '<a b="'),
      Array.from({ length: 100_000 }, () => "@* x"),
    ]) {
      const started = performance.now();
      markupLogicalLines(lines, lines[0]?.startsWith("@") ? "razor" : "xml");
      expect(performance.now() - started).toBeLessThan(5000);
    }
  });

  it("classifies .config files as configuration and Razor views as source", () => {
    const project = path.join(temp, "kinds");
    writeFile(project, "Web.config", "<configuration />\n");
    writeFile(project, "Views/Index.cshtml", "<p>@Model.Name</p>\n");
    const kinds = Object.fromEntries(
      inventory(project).files.map((file) => [file.relPath, `${file.language}:${file.kind}`]),
    );
    expect(kinds).toEqual({ "Web.config": "xml:config", "Views/Index.cshtml": "razor:source" });
  });
});
