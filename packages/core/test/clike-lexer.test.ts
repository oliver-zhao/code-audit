import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { inventory } from "../src/inventory.js";
import { clikeLogicalLines, type ClikeLanguage, type LexExtras } from "../src/lexers/clike.js";
import { dockerfileLogicalLines } from "../src/lexers/dockerfile.js";
import {
  MAX_LOGICAL_LINE_SPAN,
  SKELETON_FIELD,
  emptyLexDiagnostics,
  loadRules,
  scanRules,
  type LogicalLine,
} from "../src/rules.js";
import { scanProject } from "../src/scan.js";
import { RULES_DIR, cleanup, makeTempDir, writeFile } from "./helpers.js";

const temp = makeTempDir("clike-lexer");

afterAll(() => cleanup(temp));

function lex(language: ClikeLanguage, lines: string[]) {
  const diagnostics = emptyLexDiagnostics();
  const extras: LexExtras = {};
  const units = clikeLogicalLines(lines, language, [], diagnostics, extras);
  return { units, diagnostics, extras };
}

/** Units with code, in order; extra (fail-open) units are listed last by the lexer. */
function codeUnits(language: ClikeLanguage, lines: string[]): LogicalLine[] {
  return lex(language, lines).units.filter((unit) => unit.text.trim().length > 0 && !unit.extra);
}

/** [first line, text with trailing blanks removed] of each code unit. */
function shown(language: ClikeLanguage, lines: string[]): Array<[number, string]> {
  return codeUnits(language, lines).map((unit) => [unit.start, unit.text.replace(/[ \t]+$/gm, "")]);
}

/** The skeleton with the hole filler shown as "#". */
function skeletonOf(unit: LogicalLine | undefined): string {
  return (unit?.skeleton ?? "").split(SKELETON_FIELD).join("#");
}

describe("C-family lexer: JavaScript and TypeScript", () => {
  it("blanks // and /* */ comments and the hashbang, keeping columns", () => {
    const units = codeUnits("javascript", [
      "#!/usr/bin/env node",
      "// eval(req.body.x)",
      "run(); // eval(req.body.x)",
      "var b = /* eval(x) */ 2;",
      "/* block",
      "   eval(x) */ var c = 3;",
    ]);
    expect(units.map((unit) => [unit.start, unit.text.trimEnd()])).toEqual([
      [2, "run();"],
      [3, `var b = ${" ".repeat(13)} 2;`],
      [5, "              var c = 3;"],
    ]);
    expect(units[2]?.text.indexOf("var c")).toBe("   eval(x) */ ".length);
  });

  it("keeps string text, blanks it in the skeleton, and never reads // or /* in a string", () => {
    const [unit] = codeUnits("javascript", [
      "const a = 'it\\'s // not' + \"/* nor \\\" this\" + f('(');",
    ]);
    expect(unit?.text).toBe("const a = 'it\\'s // not' + \"/* nor \\\" this\" + f('(');");
    expect(unit?.skeleton).toBe(`const a = '${" ".repeat(12)}' + "${" ".repeat(14)}" + f(' ');`);
  });

  it("treats template holes as code, with nested templates, and lets templates span lines", () => {
    const units = codeUnits("typescript", [
      "const q = `SELECT ${cols.join(`, ${sep}`)} FROM t",
      "  WHERE id = '${id}'`; run(q);",
    ]);
    expect(units).toHaveLength(1);
    expect(units[0]?.offsets).toEqual([0, 50]);
    // `SELECT ` and `${` blank, `cols.join(` code, the nested template's
    // text blank and its hole `sep` code, ... `${id}` code, `'` blank.
    expect(skeletonOf(units[0])).toBe(
      `const q = \`${" ".repeat(9)}##########${" ".repeat(5)}###  #${" ".repeat(25)}##  \`; run(q);`,
    );
  });

  it("continues a string after a backslash at the end of the line", () => {
    const { units, diagnostics } = lex("javascript", ["const s = 'a\\", "b'; run(s);"]);
    expect(diagnostics.fallbacks).toEqual([]);
    expect(units.filter((unit) => unit.text.trim()).map((unit) => skeletonOf(unit))).toEqual([
      `const s = '${" ".repeat(4)}'; run(s);`,
    ]);
  });

  it("tells regex literals from division", () => {
    const skeletons = codeUnits("javascript", [
      "const re = /[\"'`]\\/\\*/g;",
      "const half = a / b / c;",
      "if (x) return /=+/.test(y);",
      "const v = a++ / 2, w = (b) / 3, z = arr[0] / 4;",
      "f(x => /\\(/.test(x));",
      "const p = s.replace(/\"/g, '');",
    ]).map((unit) => skeletonOf(unit));
    expect(skeletons).toEqual([
      "const re = /         /g;",
      "const half = a / b / c;",
      "if (x) return /  /.test(y);",
      "const v = a++ / 2, w = (b) / 3, z = arr[0] / 4;",
      "f(x => /  /.test(x));",
      "const p = s.replace(/ /g, '');",
    ]);
  });

  it("treats an unclosed regex as division (fail open) and JSX text quotes as text", () => {
    const { units, diagnostics } = lex("javascript", [
      "const r = a /x;",
      "const el = <p>Don't do {x}/{y} it</p>;",
      "const img = <img src={a} />;",
      "run();",
    ]);
    expect(diagnostics.fallbacks).toEqual([]);
    expect(units.filter((unit) => unit.text.trim()).map((unit) => unit.start)).toEqual([0, 1, 2, 3]);
  });

  it("joins an options object passed as an argument, but not a callback body", () => {
    expect(
      shown("javascript", [
        "app.use(cors({ origin: true,",
        "  credentials: true }));",
        'app.get("/", (req, res) => {',
        "  a();",
        "  b(",
        "    c);",
        "});",
      ]),
    ).toEqual([
      [0, "app.use(cors({ origin: true,\n  credentials: true }));"],
      [2, 'app.get("/", (req, res) => {'],
      [3, "  a();"],
      [4, "  b(\n    c);"],
      [6, "});"],
    ]);
  });

  it("joins across a line break next to an operator or before a method call", () => {
    expect(
      shown("javascript", [
        'const q = "SELECT * FROM t WHERE id = " +',
        "  id;",
        "fetch(url)",
        "  .then(r => r.json());",
        "x = cond",
        "  ? a",
        "  : b;",
      ]),
    ).toEqual([
      [0, 'const q = "SELECT * FROM t WHERE id = " +\n  id;'],
      [2, "fetch(url)\n  .then(r => r.json());"],
      [4, "x = cond\n  ? a\n  : b;"],
    ]);
  });
});

describe("C-family lexer: Java", () => {
  it("handles text blocks, character literals and comments", () => {
    const units = codeUnits("java", [
      "class A {",
      "  // stmt.executeQuery(\"select\" + id);",
      '  String q = """',
      '      SELECT * FROM t WHERE a = "x" // not a comment',
      '      """;',
      "  char c = '\"'; char u = '\\u0041'; char q2 = '\\'';",
      "  /** Runtime.getRuntime().exec(cmd); */",
      "}",
    ]);
    expect(units.map((unit) => unit.start)).toEqual([0, 2, 5, 7]);
    expect(units[1]?.text).toContain("// not a comment");
    expect(skeletonOf(units[1])).toBe(`  String q = """${" ".repeat(60)}""";`);
    expect(skeletonOf(units[2])).toBe("  char c = ' '; char u = '      '; char q2 = '  ';");
  });

  it("joins a call whose arguments are on the next lines and a builder chain", () => {
    expect(
      shown("java", [
        "ResultSet rs = stmt.executeQuery(",
        '    "SELECT * FROM users WHERE id = " + id);',
        "Request r = builder",
        "    .url(u)",
        "    .build();",
      ]),
    ).toEqual([
      [0, 'ResultSet rs = stmt.executeQuery(\n    "SELECT * FROM users WHERE id = " + id);'],
      [2, "Request r = builder\n    .url(u)\n    .build();"],
    ]);
  });
});

describe("C-family lexer: Go", () => {
  it("handles raw strings over several lines, runes and comments", () => {
    const units = codeUnits("go", [
      "// exec.Command(\"sh\", \"-c\", x)",
      "q := `SELECT * FROM t",
      "WHERE id = ` + id",
      "c := '\"'; d := '`'",
      "/* exec.Command(x) */ run()",
    ]);
    expect(units.map((unit) => [unit.start, unit.offsets.length])).toEqual([
      [1, 2],
      [3, 1],
      [4, 1],
    ]);
    expect(skeletonOf(units[0])).toBe(`q := \`${" ".repeat(27)}\` + id`);
    expect(skeletonOf(units[1])).toBe("c := ' '; d := ' '");
  });

  it("joins after a trailing dot and a composite literal passed to a call", () => {
    expect(
      shown("go", [
        "rows, err := db.",
        "\tQuery(q)",
        "go run(Config{",
        "\tA: x,",
        "})",
        "srv := http.Server{",
        '\tAddr: ":80",',
        "}",
      ]),
    ).toEqual([
      [0, "rows, err := db.\n\tQuery(q)"],
      [2, "go run(Config{\n\tA: x,\n})"],
      [5, "srv := http.Server{"],
      [6, '\tAddr: ":80",'],
      [7, "}"],
    ]);
  });
});

describe("C-family lexer: C and C++", () => {
  it("handles raw strings, digit separators, character prefixes and multi-character constants", () => {
    const units = codeUnits("cpp", [
      'auto r = R"sql(SELECT "x" )" FROM t)sql"; system(r);',
      "int n = 1'000'000; char c = u8'a'; int m = 'ab'; char q = '\\'';",
    ]);
    expect(skeletonOf(units[0])).toBe(`auto r = R"${" ".repeat(28)}"; system(r);`);
    expect(skeletonOf(units[1])).toBe("int n = 1'000'000; char c = u8' '; int m = '  '; char q = '  ';");
  });

  it("continues a // comment and a string after a backslash at the end of the line", () => {
    const { units, diagnostics, extras } = lex("c", [
      "// comment continues \\",
      "   strcpy(dst, src); code-audit:ignore *",
      'const char *s = "abc\\',
      'def";',
    ]);
    expect(diagnostics.fallbacks).toEqual([]);
    const code = units.filter((unit) => unit.text.trim());
    expect(code.map((unit) => [unit.start, unit.text])).toEqual([[2, 'const char *s = "abc\\\ndef";']]);
    expect(extras.comments?.[1]).toBe("   strcpy(dst, src); code-audit:ignore *");
  });

  it("ends a directive whose last line is a // comment continued by a backslash", () => {
    expect(shown("c", ["#define A 1 // note \\", "   still the comment", "int x = f(1);"])).toEqual([
      [0, "#define A 1"],
      [2, "int x = f(1);"],
    ]);
  });

  it("makes each preprocessor directive its own unit, with its continuation lines", () => {
    expect(
      shown("c", [
        "#include <stdio.h> // system(x)",
        "#define RUN(x) system(x); \\",
        "    printf(x)",
        "void f(void) {",
        "  strcpy(dst,",
        "#ifdef WIN32",
        "    argv[1]);",
        "#else",
        "    argv[2]);",
        "#endif",
        "}",
      ]),
    ).toEqual([
      [0, "#include <stdio.h>"],
      [1, "#define RUN(x) system(x); \\\n    printf(x)"],
      [3, "void f(void) {"],
      [5, "#ifdef WIN32"],
      // Each branch starts from the bracket state at the #ifdef: the first
      // closes the call, the second is matched on its own.
      [4, "  strcpy(dst,\n\n    argv[1]);"],
      [7, "#else"],
      [7, "\n    argv[2]);"],
      [9, "#endif"],
      [10, "}"],
    ]);
  });

  it("starts every #if branch from the bracket state at the #if", () => {
    const { units, diagnostics } = lex("c", [
      "#ifdef A",
      "int f(int a) {",
      "#else",
      "int f(int a, int b) {",
      "#endif",
      "  return g(",
      "    a);",
      "}",
    ]);
    expect(diagnostics.fallbacks).toEqual([]);
    expect(units.find((unit) => unit.start === 5)?.offsets).toHaveLength(2);
  });
});

describe("C-family lexer: Rust", () => {
  it("tells character literals from lifetimes and labels", () => {
    const [unit] = codeUnits("rust", [
      "fn f<'a, 'b>(x: &'a str) -> char { let c = 'a'; let q = '\\''; let u = '\\u{41}'; 'outer: loop { break 'outer; } c }",
    ]);
    expect(skeletonOf(unit)).toBe(
      "fn f<'a, 'b>(x: &'a str) -> char { let c = ' '; let q = '  '; let u = '      '; 'outer: loop { break 'outer; } c }",
    );
  });

  it("handles raw, byte and multi-line strings", () => {
    const units = codeUnits("rust", [
      'let a = r#"raw " // "# + b"x\\"y" + br##"a "# b"##;',
      'let s = "multi // not a comment',
      'line";',
      'let r = r"C:\\path";',
    ]);
    expect(units.map((unit) => [unit.start, unit.offsets.length])).toEqual([
      [0, 1],
      [1, 2],
      [3, 1],
    ]);
    // Only the quotes of a closing delimiter stay in the skeleton.
    expect(skeletonOf(units[0])).toBe(`let a = r#"${" ".repeat(9)}"  + b"${" ".repeat(4)}" + br##"${" ".repeat(6)}"  ;`);
    expect(units[1]?.text).toContain("// not a comment");
    expect(skeletonOf(units[2])).toBe(`let r = r"${" ".repeat(7)}";`);
  });

  it("blanks nested block comments and doc comments", () => {
    expect(
      shown("rust", [
        "/* outer /* inner */ Command::new(x) */ let y = 1;",
        "/// Command::new(\"sh\").arg(\"-c\").arg(x)",
        "//! crate docs",
        "/* a /* b",
        "*/ still comment */ let z = 2;",
      ]),
    ).toEqual([
      [0, `${" ".repeat(40)}let y = 1;`],
      [4, `${" ".repeat(20)}let z = 2;`],
    ]);
  });

  it("joins a rustfmt method chain and a call split over lines", () => {
    expect(
      shown("rust", [
        'let out = Command::new("sh")',
        '    .arg("-c")',
        "    .arg(cmd)",
        "    .output()?;",
        "sqlx::query(&format!(",
        '    "SELECT * FROM t WHERE a = \'{}\'",',
        "    a",
        "))",
        ".fetch_all(pool)",
        ".await?;",
      ]),
    ).toEqual([
      [0, 'let out = Command::new("sh")\n    .arg("-c")\n    .arg(cmd)\n    .output()?;'],
      [4, "sqlx::query(&format!(\n    \"SELECT * FROM t WHERE a = '{}'\",\n    a\n))\n.fetch_all(pool)\n.await?;"],
    ]);
  });

  it("marks #[cfg(test)] modules as test regions", () => {
    const { extras } = lex("rust", [
      "fn real() {}",
      "#[cfg(test)]",
      "#[allow(unused)]",
      "mod tests {",
      '    const K: &str = "}";',
      "    fn t() { let c = '}'; }",
      "    /* } */",
      "}",
      "fn after() {}",
      "#[cfg(test)] mod inline { fn x() {} }",
      "#[cfg(test)]",
      "fn not_a_module() {}",
    ]);
    expect(extras.testRegions).toEqual([
      { from: 1, to: 7 },
      { from: 9, to: 9 },
    ]);
  });

  it("does not report a test region that is not closed", () => {
    const { extras } = lex("rust", ["#[cfg(test)]", "mod tests {", "fn t() {}"]);
    expect(extras.testRegions).toEqual([]);
  });

  it("recovers at an item inside an open (, but not inside macro arguments", () => {
    const { diagnostics } = lex("rust", [
      "let tts = quote!(",
      "    impl Foo for Bar {",
      "        fn decode(x: u8) {}",
      "    }",
      ");",
      "$(impl<DB> Type<DB> for $t {",
      "    fn info() {}",
      "})*",
    ]);
    expect(diagnostics.fallbacks).toEqual([]);
    const broken = lex("rust", ["let x = f(", "pub fn g() {", "}"]);
    expect(broken.diagnostics.fallbacks.map((region) => region.reason)).toEqual([
      'a declaration starts while a "(" or "[" is still open',
    ]);
  });
});

describe("C-family lexer: lines for inline suppression", () => {
  it("keeps comments and code, blanks string text, and is empty without a marker", () => {
    const { extras } = lex("javascript", [
      "run(); // code-audit:ignore js-eval",
      'const s = "code-audit:ignore *"; // other',
      "/* code-audit:ignore * */",
      "plain();",
    ]);
    expect(extras.comments).toEqual([
      "run(); // code-audit:ignore js-eval",
      `const s = "${" ".repeat(19)}"; // other`,
      "/* code-audit:ignore * */",
      "",
    ]);
  });
});

describe("C-family lexer: fail open", () => {
  it("closes a single-line string at the end of its line and re-adds the line", () => {
    for (const language of ["java", "go", "javascript", "c"] as const) {
      const { units, diagnostics } = lex(language, ['x = "open', "run(y);"]);
      expect(diagnostics.fallbacks.map((region) => region.reason), language).toEqual([
        "a string is not closed at the end of its line",
      ]);
      expect(units.some((unit) => unit.extra && unit.text === 'x = "open'), language).toBe(true);
      expect(units.some((unit) => !unit.extra && unit.text === "run(y);"), language).toBe(true);
    }
  });

  it("re-adds the region when the file ends inside a comment, a string or an open (", () => {
    for (const [language, lines, reason] of [
      ["java", ["a();", "/* open", "b();"], "the file ends inside a block comment"],
      ["rust", ["a();", "/* /* nested */", "b();"], "the file ends inside a block comment"],
      ["go", ["a := `raw", "b()"], "the file ends inside a string literal"],
      ["rust", ['let a = r#"raw', "b()"], "the file ends inside a string literal"],
      ["javascript", ["f(", "  a,"], 'the file ends inside an open "(" or "["'],
      ["cpp", ['auto r = R"x(', "b();"], "the file ends inside a string literal"],
    ] as const) {
      const { units, diagnostics } = lex(language, [...lines]);
      expect(diagnostics.fallbacks[0]?.reason, `${language} ${lines.join(" | ")}`).toBe(reason);
      expect(units.some((unit) => unit.extra)).toBe(true);
    }
  });

  it("re-adds the region when a closer does not match the open bracket", () => {
    const { diagnostics } = lex("java", ["void f() {", "  g(a,", "}", "int x;"]);
    expect(diagnostics.fallbacks[0]?.reason).toMatch(/closes a bracket while an inner/);
  });

  it("re-adds a long multi-line string whose lines look like statements", () => {
    const body = Array.from({ length: 80 }, (_, index) => `    let v${index} = run(x);`);
    const { diagnostics } = lex("rust", ['let s = "', ...body, '";']);
    expect(diagnostics.fallbacks[0]?.reason).toMatch(/string literal of \d+ lines/);
  });

  it("names the language in the warning and reports hits in the region", () => {
    const project = path.join(temp, "fallback");
    writeFile(project, "a.go", ['package a', 'var s = "open', 'func f() { exec.Command("sh", "-c", s) }', ""].join("\n"));
    const result = scanRules(inventory(project).files, loadRules(RULES_DIR));
    expect(result.warnings.some((warning) => /^go lexer fallback in a\.go from line 2 to line 2/.test(warning))).toBe(true);
  });
});

describe("C-family lexer: limits", () => {
  it("cuts a statement longer than the span limit into overlapping windows", () => {
    const lines = ["call(", ...Array.from({ length: 450 }, (_, index) => `  a${index},`), ");"];
    const diagnostics = emptyLexDiagnostics();
    const units = clikeLogicalLines(lines, "javascript", [], diagnostics);
    expect(diagnostics.cuts).toEqual([0]);
    // A window holds at most the span limit of new lines plus the half it
    // repeats from the window before.
    for (const unit of units) expect(unit.offsets.length).toBeLessThanOrEqual(MAX_LOGICAL_LINE_SPAN * 1.5);
  });

  it("matches an over-long line in windows", () => {
    const overLong: number[] = [];
    const units = clikeLogicalLines([`x = "${"a".repeat(5000)}"; eval(y);`], "javascript", overLong);
    expect(overLong).toEqual([0]);
    expect(units.some((unit) => unit.extra && unit.text.includes("eval(y)"))).toBe(true);
  });

  it("lexes large and hostile input in linear time", () => {
    const size = 400_000;
    const repeat = (unit: string): string => unit.repeat(Math.ceil(size / unit.length)).slice(0, size);
    const inputs: string[][] = [
      [repeat('"')], [repeat("'")], [repeat("`")], [repeat("\\")], [repeat("/ ")], [repeat("=/[")],
      [repeat("`${")], [repeat("'a ")], [repeat("r#")], [repeat('r###"')], [repeat("/*")], [repeat("(")],
      [repeat('R"(')], [repeat("1'")], [repeat("${f}")], [repeat("f({a")],
      repeat("'\n").split("\n"), repeat("f(\n").split("\n"), repeat("#define X \\\n").split("\n"),
      repeat("// \\\n").split("\n"), repeat("`${\n").split("\n"), repeat('r#"\n').split("\n"),
      repeat("f(\npub fn x(\n").split("\n"), repeat(".a\n").split("\n"),
    ];
    for (const language of ["csharp", "java", "javascript", "go", "cpp", "rust"] as const) {
      for (const lines of inputs) {
        const started = performance.now();
        clikeLogicalLines(lines, language, [], emptyLexDiagnostics(), {});
        expect(performance.now() - started, `${language} ${JSON.stringify(lines[0]?.slice(0, 6))}`).toBeLessThan(3000);
      }
    }
  });
});

/**
 * Differential fuzz: generated code with markers C (code), S (string text),
 * K (comment) and H (interpolation-hole code). Every marker must be where it
 * was written (same line and column) in the units, with the right skeleton,
 * and no comment marker may be visible. Valid generated code must not fall
 * back.
 */
describe("C-family lexer: fuzz", () => {
  type Generator = { str: () => string; cmt: () => string; extra: () => string };
  let seed = 1;
  const random = (): number => {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    return seed / 0x7fffffff;
  };
  const pick = <T,>(items: readonly T[]): T => items[Math.floor(random() * items.length)] as T;
  let counter = 0;
  const mark = (kind: string): string => `${kind}x${(counter++).toString(36)}q`;

  const generators: Record<string, Generator> = {
    javascript: {
      str: () => pick([
        () => `"${mark("S")} \\" // /* ' \` ${mark("S")}"`,
        () => `'${mark("S")} \\' " /* ${mark("S")}'`,
        () => `\`${mark("S")} \${${mark("H")} + \`${mark("S")} \${${mark("H")}}\`} \n${mark("S")} // \``,
        () => `/${mark("S")}[/"']\\/${mark("S")}/gi`,
        () => `"${mark("S")}\\\n${mark("S")}"`,
      ])(),
      cmt: () => pick([`// ${mark("K")} " ' \``, `/* ${mark("K")}\n ${mark("K")} " */`]),
      extra: () => pick([
        `${mark("C")} / ${mark("C")} / 2`,
        `x => /${mark("S")}/.test(${mark("C")})`,
        `${mark("C")}++ / 2`,
        `${mark("C")}({ ${mark("C")}: 1,\n ${mark("C")}: ${mark("C")} })`,
      ]),
    },
    java: {
      str: () => pick([
        () => `"${mark("S")} \\" // /* ${mark("S")}"`,
        () => pick([`'"'`, `'\\''`, `'('`, `'/'`, `'\\u0041'`]),
        () => `"""\n  ${mark("S")} " "" // ${mark("S")}\n  """`,
      ])(),
      cmt: () => pick([`// ${mark("K")} "`, `/* ${mark("K")}\n * ${mark("K")} " */`, `/** ${mark("K")} */`]),
      extra: () => `${mark("C")}.${mark("C")}()\n  .${mark("C")}(${mark("C")})`,
    },
    go: {
      str: () => pick([
        () => `"${mark("S")} \\" // ${mark("S")}"`,
        () => pick([`'"'`, `'\\''`, `'('`, "'`'", `'\\x41'`]),
        () => `\`${mark("S")} " // /* \n${mark("S")} \\\``,
      ])(),
      cmt: () => pick([`// ${mark("K")} " \``, `/* ${mark("K")}\n ${mark("K")} " */`]),
      extra: () => pick([`${mark("C")}.\n  ${mark("C")}(${mark("C")})`, `${mark("C")}(T{\n ${mark("C")}: ${mark("C")},\n})`]),
    },
    cpp: {
      str: () => pick([
        () => `"${mark("S")} \\" // /* ${mark("S")}"`,
        () => pick([`'"'`, `'\\''`, `'('`, `'/'`, `L'x'`, `'ab'`]),
        () => `R"d(${mark("S")} )" " \n${mark("S")} // )d"`,
        () => `"${mark("S")}\\\n${mark("S")}"`,
      ])(),
      cmt: () => pick([`// ${mark("K")} " '`, `/* ${mark("K")}\n ${mark("K")} " */`, `// ${mark("K")} \\\n ${mark("K")} "`]),
      extra: () => pick([
        `1'000'000 + ${mark("C")}`,
        `\n#define ${mark("C")}(a) ${mark("C")}(a) \\\n  + ${mark("C")}\n`,
        `\n#ifdef ${mark("C")}\n${mark("C")}(\n#else\n${mark("C")}(\n#endif\n ${mark("C")})`,
      ]),
    },
    rust: {
      str: () => pick([
        () => `"${mark("S")} \\" // /* ${mark("S")}\n${mark("S")}"`,
        () => `r#"${mark("S")} " // " # ${mark("S")}"#`,
        () => `br##"${mark("S")} "# ${mark("S")}"##`,
        () => `b"${mark("S")} \\" ${mark("S")}"`,
        () => pick([`'"'`, `'\\''`, `'('`, `'/'`, `'\\u{41}'`, `b'x'`]),
      ])(),
      cmt: () => pick([`// ${mark("K")} "`, `/* ${mark("K")} /* ${mark("K")} */\n ${mark("K")} " */`, `/// ${mark("K")} '`, `//! ${mark("K")}`]),
      extra: () => pick([
        `&'${mark("C")} ${mark("C")}`,
        `<'${mark("C")}, '${mark("C")}>`,
        `${mark("C")}::new(${mark("C")})\n    .${mark("C")}(${mark("C")})\n    .${mark("C")}()`,
        `'${mark("C")}: loop { break '${mark("C")}; }`,
      ]),
    },
  };

  function source(generator: Generator): string {
    const expression = (depth = 0): string => {
      const roll = random();
      if (roll < 0.25 || depth > 3) return mark("C");
      if (roll < 0.5) return generator.str();
      if (roll < 0.62) return `${mark("C")}(${expression(depth + 1)},\n  ${expression(depth + 1)})`;
      if (roll < 0.72) return `${expression(depth + 1)} +\n  ${expression(depth + 1)}`;
      if (roll < 0.82) {
        const comment = generator.cmt();
        const block = comment.startsWith("/*") ? comment : `/* ${mark("K")} */`;
        return `${expression(depth + 1)} ${block} + ${expression(depth + 1)}`;
      }
      if (roll < 0.9) return generator.extra();
      return `${mark("C")}[${expression(depth + 1)}]`;
    };
    const statement = (): string => {
      const roll = random();
      if (roll < 0.5) return `${mark("C")} = ${expression()};`;
      if (roll < 0.65) return `${mark("C")}(${expression()}); ${generator.cmt()}`;
      if (roll < 0.8) return `if (${expression()}) {\n${mark("C")} = ${expression()};\n}`;
      return generator.cmt();
    };
    return Array.from({ length: 1 + Math.floor(random() * 8) }, statement).join("\n");
  }

  for (const language of ["javascript", "java", "go", "cpp", "rust"] as const) {
    it(`keeps every code, string and hole marker in place and hides comments (${language})`, () => {
      seed = 7;
      const problems: string[] = [];
      for (let iteration = 0; iteration < 400 && problems.length < 5; iteration += 1) {
        counter = 0;
        const text = source(generators[language] as Generator);
        const lines = text.split("\n");
        const diagnostics = emptyLexDiagnostics();
        const units = clikeLogicalLines(lines, language, [], diagnostics, {});
        if (diagnostics.fallbacks.length > 0) problems.push(`fallback ${JSON.stringify(diagnostics.fallbacks)}\n${text}`);
        lines.forEach((line, lineIndex) => {
          for (const marker of line.matchAll(/([CSKH])x[0-9a-z]+q/g)) {
            const kind = marker[1] as string;
            const name = marker[0];
            let found: { unit: LogicalLine; offset: number } | undefined;
            for (const unit of units) {
              if (unit.extra) continue;
              const part = lineIndex - unit.start;
              if (part < 0 || part >= unit.offsets.length) continue;
              const offset = (unit.offsets[part] as number) + (marker.index as number);
              if (unit.text.slice(offset, offset + name.length) === name) {
                found = { unit, offset };
                break;
              }
            }
            if (kind === "K") {
              if (found) problems.push(`comment shown: ${name}\n${text}`);
              continue;
            }
            if (!found) {
              problems.push(`missing: ${name}\n${text}`);
              continue;
            }
            const skeleton = (found.unit.skeleton ?? "").slice(found.offset, found.offset + name.length);
            if (kind === "C" && skeleton !== name) problems.push(`code ${name}: ${skeleton}\n${text}`);
            if (kind === "S" && skeleton.trim() !== "") problems.push(`string ${name}: ${skeleton}\n${text}`);
            if (kind === "H" && skeleton !== SKELETON_FIELD.repeat(name.length)) problems.push(`hole ${name}\n${text}`);
          }
        });
      }
      expect(problems).toEqual([]);
    });
  }

  it("never throws on random character soup", () => {
    seed = 11;
    const alphabet = [
      '"', "'", "`", "@", "$", "{", "}", "(", ")", "[", "]", "/", "*", "\\", "\n", " ", "a", "r", "#", "R",
      "1", "<", ">", "=", "+", ".", "//", "/*", "*/", "${", 'r#"', '"#', 'R"x(', ')x"', "#if X\n", "#endif\n",
      "#[cfg(test)]\nmod t {\n", "'a", "pub fn x(\n",
    ];
    for (let iteration = 0; iteration < 3000; iteration += 1) {
      let text = "";
      const length = 1 + Math.floor(random() * 60);
      for (let index = 0; index < length; index += 1) text += pick(alphabet);
      const lines = text.split("\n");
      for (const language of ["csharp", "java", "javascript", "go", "c", "rust"] as const) {
        const units = clikeLogicalLines(lines, language, [], emptyLexDiagnostics(), {});
        for (const unit of units) {
          if (unit.skeleton !== undefined && unit.skeleton.length > 0) {
            expect(unit.skeleton.length, `${language} ${JSON.stringify(text)}`).toBe(unit.text.length);
          }
        }
      }
    }
  });
});

describe("C-family matching", () => {
  const ruleSet = loadRules(RULES_DIR);

  function hits(name: string, files: Record<string, string[]>) {
    const project = path.join(temp, name);
    for (const [file, lines] of Object.entries(files)) writeFile(project, file, [...lines, ""].join("\n"));
    return scanRules(inventory(project).files, ruleSet);
  }

  it("reports a multi-line call at the line where the match starts", () => {
    const result = hits("multiline", {
      "src/db.rs": [
        "pub async fn count(pool: &PgPool, status: &str) -> i64 {",
        "    sqlx::query_scalar::<_, i64>(&format!(",
        "        \"SELECT count(*) FROM jobs WHERE status = '{}'\",",
        "        status",
        "    ))",
        "    .fetch_one(pool)",
        "    .await",
        "}",
      ],
    });
    expect(result.hits.map((hit) => `${hit.line}:${hit.rule.id}`)).toEqual(["2:rs-sql-injection"]);
  });

  it("honours an ignore comment, but not ignore text inside a string literal", () => {
    const result = hits("ignore", {
      "src/Main.java": [
        "class Main {",
        "  void m(String id) throws Exception {",
        "    // code-audit:ignore * -- id is validated",
        '    stmt.executeQuery("SELECT * FROM t WHERE id = \'" + id + "\'");',
        '    String note = "code-audit:ignore *";',
        '    stmt.executeQuery("SELECT * FROM t WHERE id = \'" + id + "\'");',
        "  }",
        "}",
      ],
    });
    expect(result.suppressed.length).toBeGreaterThan(0);
    expect(new Set(result.suppressed.map((entry) => entry.line))).toEqual(new Set([4]));
    expect(result.hits.length).toBeGreaterThan(0);
    expect(new Set(result.hits.map((hit) => hit.line))).toEqual(new Set([6]));
  });

  it("does not report code in comments", () => {
    const result = hits("comments", {
      "app.js": [
        "// eval(req.body.code)",
        "/* child_process.exec(req.query.cmd)",
        "   eval(req.body.x) */",
        "run(); // eval(req.query.x)",
      ],
      "main.go": ["package main", "// exec.Command(\"sh\", \"-c\", r.URL.Query().Get(\"c\"))", "func main() {}"],
    });
    expect(result.hits.map((hit) => hit.rule.id)).toEqual([]);
  });

  it("treats findings in a Rust #[cfg(test)] module like findings in a test path", async () => {
    const project = path.join(temp, "rust-tests");
    writeFile(
      project,
      "src/net.rs",
      [
        "pub fn client() -> reqwest::Client {",
        "    reqwest::Client::builder().danger_accept_invalid_certs(true).build().unwrap()",
        "}",
        "",
        "#[cfg(test)]",
        "mod tests {",
        "    fn client() -> reqwest::Client {",
        "        reqwest::Client::builder().danger_accept_invalid_certs(true).build().unwrap()",
        "    }",
        "}",
        "",
      ].join("\n"),
    );
    const result = await scanProject({
      root: project,
      out: path.join(temp, "rust-tests-out"),
      offline: true,
      engines: ["builtin"],
      formats: ["json"],
    });
    const found = result.findings
      .filter((finding) => finding.ruleId === "rs-tls-accept-invalid")
      .map((finding) => `${finding.startLine}:${finding.pathContext ?? "-"}:${finding.confidence}`);
    expect(found).toEqual(["2:-:high", "8:test:medium"]);
  });
});

describe("Dockerfile units", () => {
  it("joins an instruction continued with a backslash and blanks comment lines", () => {
    const units = dockerfileLogicalLines([
      "FROM debian:12",
      "# RUN curl https://x | sh",
      "RUN apt-get update && \\",
      "    # a comment inside the instruction",
      "    curl -fsSL https://example.com/install.sh \\",
      "    | sh",
      "USER app",
    ]).filter((unit) => unit.text.trim().length > 0);
    expect(units.map((unit) => [unit.start, unit.offsets.length])).toEqual([
      [0, 1],
      [2, 4],
      [6, 1],
    ]);
    expect(units[1]?.text.split("\n")[1]).toBe("");
  });

  it("honours the escape parser directive", () => {
    const units = dockerfileLogicalLines(["# escape=`", "FROM x", "RUN a `", "  b"]).filter((unit) => unit.text.trim());
    expect(units.map((unit) => [unit.start, unit.offsets.length])).toEqual([
      [1, 1],
      [2, 2],
    ]);
  });
});
