/*
 * C-family lexer
 * --------------
 * One lexer for C#, Java, JavaScript/TypeScript, Go, C/C++ and Rust. It turns
 * the physical lines of a file into the units rules are matched against (see
 * `LogicalLine` in `rules.ts`), with per-language string and comment syntax:
 *
 * | Language | Comments | Strings and other literals |
 * |---|---|---|
 * | C# | `//`, `///`, `/* *\/` | `"..."`, `'c'`, `@"..."`, `$"...{hole}..."`, raw `"""..."""` with `$` prefixes |
 * | Java | `//`, `/* *\/` | `"..."`, `'c'`, text blocks `"""..."""` |
 * | JavaScript / TypeScript | `//`, `/* *\/`, hashbang | `'...'`, `"..."`, templates `` `...${hole}...` ``, regex literals `/.../flags` |
 * | Go | `//`, `/* *\/` | `"..."`, runes `'x'`, raw `` `...` `` |
 * | C / C++ | `//` (continued by `\`), `/* *\/` | `"..."`, `'c'`, raw `R"d(...)d"`; digit separators `1'000` |
 * | Rust | `//`, `///`, `//!`, nested `/* /* *\/ *\/` | `"..."` (multi-line), `b"..."`, raw `r#"..."#`, `'c'` vs lifetimes `'a` |
 *
 * Common behaviour:
 *
 * - comments are blanked (columns stay those of the physical line); their text
 *   is collected per line in `extras.comments` for inline suppression;
 * - string text is kept in `text` (rules read SQL and URLs) and blanked in
 *   `skeleton` (`codeOnly` rules ignore it); the code of interpolation holes
 *   is `SKELETON_FIELD` in the skeleton; a regex literal body is blanked like
 *   a string;
 * - a statement stays one unit while a `(` or `[` is open (not a `{`), while a
 *   string or hole spans lines, and across a line break next to a binary
 *   operator, `=`, `=>`, `.` or `?:` (a method chain `\n  .arg(x)` joins);
 * - preprocessor lines: C# directives are not code, and every `#if` branch
 *   starts from the bracket state at the `#if`; C/C++ directives are code and
 *   each directive (with its `\` continuation lines) is its own unit, with the
 *   same `#if` bracket handling;
 * - the lexer FAILS OPEN: when the file ends inside a string, a comment or an
 *   open `(` / `[`, a closer does not match the open bracket, a declaration
 *   turns up inside an open `(`, a single-line string is not closed at the end
 *   of its line, or a long multi-line string keeps looking like code, the
 *   region is added again as plain physical lines and recorded in
 *   `diagnostics.fallbacks`. When unsure whether `/` starts a regex literal it
 *   is division.
 *
 * Each character is visited a bounded number of times, so the lexer runs in
 * linear time on any input (see the hostile-input tests).
 */
import {
  MAX_LOGICAL_LINE_LENGTH,
  MAX_LOGICAL_LINE_SPAN,
  MAX_PATTERN_LINE_LENGTH,
  SKELETON_FIELD,
  windowUnits,
  type LexDiagnostics,
  type LogicalLine,
} from "../rules.js";

export const CLIKE_LANGUAGES = [
  "csharp",
  "java",
  "javascript",
  "typescript",
  "go",
  "c",
  "cpp",
  "rust",
] as const;

export type ClikeLanguage = (typeof CLIKE_LANGUAGES)[number];

export function isClikeLanguage(language: string): language is ClikeLanguage {
  return (CLIKE_LANGUAGES as readonly string[]).includes(language);
}

/** What a lexer reports besides the units. */
export interface LexExtras {
  /**
   * Per physical line, for inline suppression: the line with the text of
   * string (and regex) literals blanked, comments and code as written; ""
   * when the line holds no `code-audit:ignore`. A line in a fallback region
   * holds the whole physical line, since the lexer could not tell. A
   * `code-audit:ignore` inside a string literal therefore suppresses
   * nothing, and a trailing comment after code is still seen as one.
   */
  comments?: string[];
  /**
   * Rust: regions (zero-based, inclusive) of `#[cfg(test)] mod name { ... }`
   * modules. Findings there are treated like findings in a test path.
   */
  testRegions?: Array<{ from: number; to: number }>;
}

type Family = "csharp" | "java" | "js" | "go" | "c" | "rust";

/** An open string literal. */
interface StringContext {
  kind: "string";
  /**
   * regular: one quote character closes it, backslash escapes;
   * verbatim / raw: C# `@"..."` / `"""..."""`;
   * template: JavaScript template literal with `${...}` holes;
   * token: `close` closes it (text blocks, raw strings), escapes per `escapes`.
   */
  form: "regular" | "verbatim" | "raw" | "template" | "token";
  close: string;
  /** Regular string that may span lines (Rust). */
  multiline: boolean;
  escapes: boolean;
  /** C#: number of `$` in the prefix; 0 when the literal is not interpolated. */
  dollars: number;
  /** C# raw string literal: number of quotes in the delimiter. */
  quotes: number;
}

/** An interpolation hole: C# `{...}` or JavaScript `${...}`. */
interface HoleContext {
  kind: "hole";
  /** Brackets opened inside the hole and not closed yet. */
  depth: number;
  /** C#: true after the `:` that starts the format string. */
  spec: boolean;
  js: boolean;
}

/** An open block comment; `depth` counts nested Rust comments. */
interface CommentContext {
  kind: "comment";
  depth: number;
}

type Context = StringContext | HoleContext | CommentContext;

/** An open code bracket and the line it was opened on. */
interface Bracket {
  ch: "(" | "[" | "{";
  line: number;
  /**
   * A `{` opened inside an open `(` or `[` that starts a literal rather than
   * a block (an options object `f({ a: 1 })`, a Go composite literal
   * `f(T{...})`, a Rust struct literal): it keeps the statement open like
   * the bracket around it. Never set for C#.
   */
  literal?: boolean;
  /** Rust: the bracket of a macro invocation `name!(` or repetition `$(`. */
  macro?: boolean;
}

/** Words before a `{` that make it a block, not a literal. */
const BLOCK_KEYWORDS = new Set([
  "else", "try", "do", "finally", "async", "move", "unsafe", "loop", "static", "default", "const",
]);

const IDENTIFIER_CHAR = /[\p{L}\p{N}_]/u;
const JS_IDENTIFIER_CHAR = /[\p{L}\p{N}_$]/u;
const WHITESPACE = /\s/;
const ASCII_IDENTIFIER_CHAR = /[A-Za-z0-9_$]/;
/**
 * Code characters that never start a literal, comment or bracket: the lexer
 * copies a run of them at once. Quotes, `/`, brackets, `#`, `@`, `$` and
 * `\` are handled one at a time.
 */
const CODE_RUN = /[A-Za-z0-9_ \t.,;:=+\-*<>!&|%^~?]+/y;
const JS_CODE_RUN = /[A-Za-z0-9_$ \t.,;:=+\-*<>!&|%^~?]+/y;

/** Prefix and opening quotes of a C# string literal: `"`, `@"`, `$"`, `$@"`, `@$"`, `"""`, `$$"""`. */
const CS_STRING_START = /(\${0,16})(@?)(\${0,16})("+)/y;

/** A complete C# character literal. */
const CS_CHAR_LITERAL = /'(?:\\(?:u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|x[0-9A-Fa-f]{1,4}|[^\n])|[^'\\\n])'/y;
const JAVA_CHAR_LITERAL = /'(?:\\(?:u+[0-9A-Fa-f]{4}|[0-7]{1,3}|[^\n])|[^'\\\n])'/uy;
const GO_RUNE_LITERAL = /'(?:\\(?:x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|[0-7]{3}|[^\n])|[^'\\\n])'/uy;
/** C/C++ character constant, including multi-character constants like 'abcd'. */
const C_CHAR_LITERAL = /'(?:\\(?:x[0-9A-Fa-f]{1,8}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|[0-7]{1,3}|[^\n])|[^'\\\n]){1,4}'/uy;
const RUST_CHAR_LITERAL = /'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]{1,8}\}|[^\n])|[^'\\\n])'/uy;

/** Rust raw string opener: `r"`, `r#"`, `br##"`, `cr#"`. */
const RUST_RAW_START = /(?:br|cr|r)(#{0,255})"/y;
/** C++ raw string: the delimiter and `(` after the quote. */
const CPP_RAW_DELIMITER = /"([^()\\\s"]{0,16})\(/y;
/** Prefixes that make a C++ raw string. */
const CPP_RAW_PREFIXES = new Set(["R", "u8R", "uR", "UR", "LR"]);
/** C/C++ character-constant prefixes. */
const C_CHAR_PREFIXES = new Set(["L", "u", "U", "u8"]);

/** The end of a line whose expression goes on: a binary operator, `=`, `=>`, `.` or `?`. */
const CONTINUES_AT_END = /(?:(?<!\+)\+|=>?|&&|\|\||\?|(?<!\.)\.)\s*$/;

/** The start of a line that continues the expression before it. */
const CONTINUES_AT_START = /^\s*(?:\+(?!\+)|\.[A-Za-z_@$]|\?|:(?!:)|&&|\|\||=>)/;
const CS_CONTINUES_AT_START = /^\s*(?:\+(?!\+)|\.[A-Za-z_@]|\?|:(?!:)|&&|\|\||=>)/;

/** Words after which `/` starts a regex literal in JavaScript. */
const REGEX_KEYWORDS = new Set([
  "return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw",
  "case", "do", "else", "yield", "await", "extends",
]);

/** Words after which a quote starts a string even without a blank in between. */
const JS_QUOTE_KEYWORDS = new Set([
  ...REGEX_KEYWORDS, "export", "import", "from", "default",
]);

/**
 * A line that can only be the start of a member, type or function, never the
 * inside of an open `(` or `[`: when one turns up while a bracket is open,
 * the lexer (or the file) is wrong about that bracket.
 */
const HARD_RESTART: Record<Family, RegExp> = {
  csharp:
    /^\s*(?:(?:public|private|protected|internal)\s+[\w<\[]|namespace\s+[A-Za-z_][\w.]*(?:\s*[;{])?\s*$|(?:(?:sealed|static|abstract|partial)\s+){0,3}(?:class|interface|struct|enum)\s+[A-Za-z_]\w*\s*(?:[:<{(]|$))/,
  java:
    /^\s*(?:(?:public|private|protected)\s+[\w<\[@]|package\s+[\w.]+\s*;\s*$|import\s+(?:static\s+)?[\w.*]+\s*;\s*$|(?:(?:final|static|abstract|sealed)\s+){0,3}(?:class|interface|enum|record)\s+[A-Za-z_]\w*\s*(?:[<{(]|extends\b|implements\b|$))/,
  js:
    /^(?:export\s+(?:default\s+)?)?(?:(?:async\s+)?function\s*\*?\s*[A-Za-z_$][\w$]*\s*\(|class\s+[A-Za-z_$][\w$]*\s*(?:extends\b|\{|$)|import\s+[\w{*'"]|(?:const|let|var)\s+[\w${[]|interface\s+[A-Za-z_$]|type\s+[A-Za-z_$][\w$]*\s*(?:<[^>]{0,100}>)?\s*=)/,
  go: /^(?:func\s|type\s+[A-Za-z_]|package\s+[A-Za-z_]|import\s*[("]|var\s+[A-Za-z_(]|const\s+[A-Za-z_(])/,
  c: /^(?:typedef\s|namespace\s+[A-Za-z_]|template\s*<|(?:struct|union|enum|class)\s+[A-Za-z_]\w*\s*\{?\s*$)/,
  rust:
    /^\s*(?:pub(?:\([\w:\s]{0,40}\))?\s+)?(?:(?:async|const|unsafe|default)\s+|extern\s+"[^"\n]{0,20}"\s+)*(?:fn\s+[A-Za-z_]\w*\s*[<(]|struct\s+[A-Za-z_]|enum\s+[A-Za-z_]|trait\s+[A-Za-z_]|impl\b\s*[<A-Za-z_][^\n]{0,300}(?:\{\s*$|\sfor\s)|mod\s+[A-Za-z_]\w*\s*[;{]|use\s+[\w:{])/,
};

/** A line inside a multi-line string that looks like a statement. */
const STATEMENT_LIKE: Record<Family, RegExp> = {
  csharp:
    /^\s*(?:var\s+\w+\s*=|return\b|await\s|throw\s+new\b|(?:if|foreach|while|using)\s*\(|[A-Za-z_][\w.]{0,100}\s*(?:[-+*/|&]?=(?!=)|\())[^\n]{0,400};\s*$/,
  java:
    /^\s*(?:(?:final\s+)?[A-Z]\w{0,60}(?:<[^>\n]{0,80}>)?\s+\w+\s*=|var\s+\w+\s*=|return\b|throw\s+new\b|(?:if|for|while|try)\s*\(|[A-Za-z_][\w.]{0,100}\s*(?:[-+*/|&]?=(?!=)|\())[^\n]{0,400};\s*$/,
  js: /^\s*(?:(?:const|let|var)\s+[\w${[]|return\b|await\s|throw\s|(?:if|for|while|switch)\s*\(|[A-Za-z_$][\w$.]{0,100}\s*(?:[-+*/|&]?=(?![=>])|\())[^\n]{0,400};\s*$/,
  go: /^\s*(?:(?:if|for|switch)\s[^\n]{0,300}\{\s*$|return\b[^\n]{0,300}$|[A-Za-z_]\w{0,60}(?:\s*,\s*[A-Za-z_]\w{0,60}){0,4}\s*:=[^\n]{1,300}$|[A-Za-z_][\w.]{0,100}\([^\n]{0,300}\)\s*$)/,
  c: /^\s*(?:(?:const\s+)?(?:int|char|void|long|short|size_t|unsigned|struct\s+\w+|auto)\b[^\n]{0,200}=|return\b|(?:if|for|while|switch)\s*\(|[A-Za-z_][\w.>-]{0,100}\s*(?:[-+*/|&]?=(?!=)|\())[^\n]{0,400};\s*$/,
  rust: /^\s*(?:let\s+(?:mut\s+)?\w+|return\b|(?:if|while|for|match)\s[^\n]{0,200}\{\s*$|[A-Za-z_][\w.:]{0,100}\s*(?:[-+*/|&]?=(?![=>])|!?\())[^\n]{0,400}[;{]\s*$/,
};

/**
 * Open brackets that are tracked; deeper nesting (generated or hostile input)
 * is only counted, so every bracket costs constant time.
 */
const MAX_BRACKETS = 256;
/** Nested `#if` levels whose bracket state is saved. */
const MAX_CONDITIONALS = 64;

/** A multi-line string longer than this many lines is checked for code-like content. */
const STRING_FALLBACK_MIN_LINES = 60;
const STRING_FALLBACK_MIN_CODE_LINES = 20;

const MAX_UNIT_PARTS = 5000;

function familyOf(language: ClikeLanguage): Family {
  switch (language) {
    case "javascript":
    case "typescript":
      return "js";
    case "cpp":
      return "c";
    default:
      return language;
  }
}

/**
 * Skeleton of the delimiter that opens a literal: the prefix and quotes stay,
 * what follows the last quote (a C++ raw-string delimiter `d(`) is blank.
 */
function openingSkeleton(chunk: string): string {
  let last = chunk.length - 1;
  while (last >= 0 && !QUOTES.includes(chunk[last] as string)) last -= 1;
  return chunk.slice(0, last + 1) + " ".repeat(chunk.length - last - 1);
}

/** Skeleton of the delimiter that closes a literal: only the quotes stay. */
function closingSkeleton(chunk: string): string {
  let skeleton = "";
  for (let index = 0; index < chunk.length; index += 1) {
    const ch = chunk[index] as string;
    skeleton += QUOTES.includes(ch) ? ch : " ";
  }
  return skeleton;
}

const QUOTES = "\"'`";

/**
 * End (exclusive) of a JavaScript regex literal whose `/` is at `index`, or
 * -1 when the line ends first. Flags are included.
 */
function regexLiteralEnd(line: string, index: number): number {
  let cursor = index + 1;
  let inClass = false;
  while (cursor < line.length) {
    const ch = line[cursor] as string;
    if (ch === "\\") {
      cursor += 2;
      continue;
    }
    if (inClass) {
      if (ch === "]") inClass = false;
    } else if (ch === "[") {
      inClass = true;
    } else if (ch === "/") {
      cursor += 1;
      while (cursor < line.length && /[a-z]/.test(line[cursor] as string)) cursor += 1;
      return cursor;
    }
    cursor += 1;
  }
  return -1;
}

/**
 * Turn the physical lines of a C-family file into the units rules are matched
 * against; see the comment at the top of this file.
 */
export function clikeLogicalLines(
  lines: string[],
  language: ClikeLanguage,
  overLong?: number[],
  diagnostics?: LexDiagnostics,
  extras?: LexExtras,
): LogicalLine[] {
  const family = familyOf(language);
  const csharp = family === "csharp";
  const js = family === "js";
  const cfamily = family === "c";
  const rust = family === "rust";
  const hardRestart = HARD_RESTART[family];
  const statementLike = STATEMENT_LIKE[family];
  const continuesAtStart = csharp ? CS_CONTINUES_AT_START : CONTINUES_AT_START;
  const identifierChar = js ? JS_IDENTIFIER_CHAR : IDENTIFIER_CHAR;
  const charLiteral =
    family === "csharp"
      ? CS_CHAR_LITERAL
      : family === "java"
        ? JAVA_CHAR_LITERAL
        : family === "go"
          ? GO_RUNE_LITERAL
          : family === "c"
            ? C_CHAR_LITERAL
            : family === "rust"
              ? RUST_CHAR_LITERAL
              : null;

  const result: LogicalLine[] = [];
  const windows: LogicalLine[] = [];
  const stack: Context[] = [];
  let brackets: Bracket[] = [];
  // Openers beyond MAX_BRACKETS, counted but not tracked.
  let bracketOverflow = 0;
  // Bracket state at each open `#if`, restored at `#elif` / `#else`.
  const conditionals: Bracket[][] = [];
  let conditionalDepth = 0;
  // Line where the outermost open string or comment began.
  let contextStart = -1;
  // Long multi-line string: body lines and lines that look like statements.
  let stringBodyLines = 0;
  let stringCodeLike = 0;
  let continued = false;

  // JavaScript: the last code character and identifier, for regex literals
  // and quotes in JSX text.
  let prevSig = "";
  let prevSig2 = "";
  let prevWord = "";
  let prevIsIdentifier = false;

  // C/C++: a line comment or directive continued by a backslash.
  let commentSpliced = false;
  let directiveOpen = false;
  let directiveStart = 0;
  let directiveParts: string[] = [];
  let directiveSkeletons: string[] = [];

  const comments: string[] | undefined = extras ? new Array<string>(lines.length) : undefined;
  const lineSkeletons: string[] | undefined = rust && extras ? new Array<string>(lines.length) : undefined;

  let parts: string[] = [];
  let skeletonParts: string[] = [];
  let softBreaks: boolean[] = [];
  let start = 0;
  let sawCode = false;
  let unitCodeLines = 0;
  let unitNewLength = 0;
  let statementStart = 0;
  let statementCut = false;

  // Regions are merged and turned into plain-line units once, at the end, so
  // overlapping regions cost nothing extra.
  const fallbackRegions: Array<{ from: number; to: number; reason: string }> = [];
  const addFallback = (from: number, to: number, reason: string): void => {
    fallbackRegions.push({ from: Math.max(0, from), to: Math.min(to, lines.length - 1), reason });
  };

  const buildUnit = (
    unitStart: number,
    unitParts: string[],
    unitSkeletons: string[],
    soft: (index: number) => boolean,
    hasCode: boolean,
  ): LogicalLine => {
    const offsets: number[] = [];
    let offset = 0;
    for (const part of unitParts) {
      offsets.push(offset);
      offset += part.length + 1;
    }
    let skeleton = "";
    if (hasCode) {
      for (let index = 0; index < unitSkeletons.length; index += 1) {
        skeleton += unitSkeletons[index] as string;
        if (index < unitSkeletons.length - 1) skeleton += soft(index) ? " " : "\n";
      }
    }
    const unit: LogicalLine = {
      start: unitStart,
      text: hasCode ? unitParts.join("\n") : "",
      offsets,
      declaration: false,
      headerEnd: 0,
      skeleton,
    };
    // Rules of these languages were written for one physical line at a
    // time: `notPattern` sees the lines of the match.
    if (!csharp) unit.lineSpan = true;
    return unit;
  };

  const flush = (): void => {
    if (parts.length === 0) return;
    const breaks = softBreaks;
    result.push(buildUnit(start, parts, skeletonParts, (index) => breaks[index] === true, sawCode));
    parts = [];
    skeletonParts = [];
    softBreaks = [];
    sawCode = false;
    unitCodeLines = 0;
    unitNewLength = 0;
  };

  /** Flush a window of a statement that goes on, keeping half of it as overlap. */
  const cut = (lineIndex: number): void => {
    if (!statementCut) {
      statementCut = true;
      diagnostics?.cuts.push(statementStart);
    }
    let count = 0;
    let codeLines = 0;
    let length = 0;
    while (count < parts.length && count < MAX_UNIT_PARTS / 2) {
      const part = parts[parts.length - 1 - count] as string;
      if (part.length > 0) {
        if (codeLines >= MAX_LOGICAL_LINE_SPAN / 2) break;
        if (length + part.length + 1 > MAX_LOGICAL_LINE_LENGTH / 2) break;
        codeLines += 1;
        length += part.length + 1;
      }
      count += 1;
    }
    const from = parts.length - count;
    const tail = codeLines > 0
      ? { parts: parts.slice(from), skeletons: skeletonParts.slice(from), soft: softBreaks.slice(from) }
      : null;
    const hadCode = sawCode;
    flush();
    if (tail !== null) {
      parts = tail.parts;
      skeletonParts = tail.skeletons;
      softBreaks = tail.soft;
      start = lineIndex + 1 - tail.parts.length;
      sawCode = hadCode;
    }
  };

  /** Emit the C/C++ directive collected so far as its own unit. */
  const flushDirective = (): void => {
    if (directiveParts.length === 0) return;
    const hasCode = directiveParts.some((part) => part.trim().length > 0);
    result.push(buildUnit(directiveStart, directiveParts, directiveSkeletons, () => true, hasCode));
    directiveParts = [];
    directiveSkeletons = [];
  };

  const innermostIsParen = (): boolean => {
    const top = brackets[brackets.length - 1];
    return top !== undefined && (top.ch !== "{" || top.literal === true);
  };

  // Last code character and word of the lines before, for `literalBrace`.
  let lineEndSig = "";
  let lineEndWord = "";

  /**
   * Does the `{` about to be pushed start a literal? Only inside an open `(`
   * or `[` (or another literal), and only when what precedes it is not the
   * end of a function head, an arrow, a closure or a block keyword.
   */
  // Reads the physical line, not the skeleton being built: indexing a string
  // that grows by concatenation would copy it every time. A comment right
  // before the `{` makes it a block (the old behaviour, fail-safe).
  const literalBrace = (line: string, index: number): boolean => {
    if (csharp || !innermostIsParen()) return false;
    let at = index - 1;
    while (at >= 0 && WHITESPACE.test(line[at] as string)) at -= 1;
    let sig: string;
    let word = "";
    if (at < 0) {
      sig = lineEndSig;
      word = lineEndWord;
    } else {
      sig = line[at] as string;
      if (sig === "/" && line[at - 1] === "*") return false;
      let from = at;
      while (from >= 0 && at - from < 16 && identifierChar.test(line[from] as string)) from -= 1;
      word = line.slice(from + 1, at + 1);
    }
    if (sig === "" || sig === ")" || sig === ">") return false;
    if (rust && sig === "|") return false;
    return !BLOCK_KEYWORDS.has(word);
  };

  /** Close `ch`; an opener above the matching one was never closed. */
  const closeBracket = (ch: string, lineIndex: number): void => {
    if (bracketOverflow > 0) {
      bracketOverflow -= 1;
      return;
    }
    const want = ch === ")" ? "(" : ch === "]" ? "[" : "{";
    let index = brackets.length - 1;
    while (index >= 0 && (brackets[index] as Bracket).ch !== want) index -= 1;
    if (index < 0) return; // A stray closer changes nothing.
    let unbalancedFrom = -1;
    for (let above = index + 1; above < brackets.length; above += 1) {
      const entry = brackets[above] as Bracket;
      if (entry.ch !== "{" && (unbalancedFrom < 0 || entry.line < unbalancedFrom)) {
        unbalancedFrom = entry.line;
      }
    }
    brackets.length = index;
    if (unbalancedFrom >= 0 && unbalancedFrom < lineIndex) {
      addFallback(unbalancedFrom, lineIndex, `a "${ch}" closes a bracket while an inner "(" or "[" is still open`);
    }
  };

  /** Drop the `(` / `[` above the innermost `{`; returns the first line of them. */
  const dropOpenParens = (): number => {
    let first = -1;
    while (brackets.length > 0 && innermostIsParen()) {
      first = (brackets.pop() as Bracket).line;
    }
    return first;
  };

  /** `#if` / `#elif` / `#else` / `#endif`: save or restore the bracket state. */
  const conditional = (name: string): void => {
    if (name === "if" || (cfamily && (name === "ifdef" || name === "ifndef"))) {
      conditionalDepth += 1;
      if (conditionalDepth <= MAX_CONDITIONALS) conditionals.push(brackets.slice());
    } else if (name === "elif" || name === "else" || (cfamily && name.startsWith("elif"))) {
      const saved = conditionalDepth <= MAX_CONDITIONALS ? conditionals[conditionalDepth - 1] : undefined;
      if (saved) {
        brackets = saved.slice();
        bracketOverflow = 0;
      }
    } else if (name === "endif" && conditionalDepth > 0) {
      if (conditionalDepth <= MAX_CONDITIONALS) conditionals.pop();
      conditionalDepth -= 1;
    }
  };

  /** JavaScript: may a `/` here start a regex literal? */
  const regexAllowed = (): boolean => {
    if (prevSig === "") return true;
    if (JS_IDENTIFIER_CHAR.test(prevSig)) return REGEX_KEYWORDS.has(prevWord);
    switch (prevSig) {
      case ")":
      case "]":
      case '"':
      case ".":
      case "/":
      case "<":
        return false;
      case ">":
        return prevSig2 === "=";
      case "+":
      case "-":
        return prevSig2 !== prevSig;
      default:
        return true;
    }
  };

  const noteCode = (ch: string): void => {
    if (WHITESPACE.test(ch)) {
      prevIsIdentifier = false;
      return;
    }
    if (JS_IDENTIFIER_CHAR.test(ch)) {
      prevWord = prevIsIdentifier ? (prevWord.length < 16 ? prevWord + ch : prevWord) : ch;
      prevIsIdentifier = true;
    } else {
      prevIsIdentifier = false;
    }
    prevSig2 = prevSig;
    prevSig = ch;
  };
  const codeRun = js ? JS_CODE_RUN : CODE_RUN;
  /** `noteCode` for a run of `CODE_RUN` characters. */
  const noteRun = (text: string): void => {
    let last = text.length - 1;
    while (last >= 0 && WHITESPACE.test(text[last] as string)) last -= 1;
    if (last < 0) {
      prevIsIdentifier = false;
      return;
    }
    let before = last - 1;
    while (before >= 0 && WHITESPACE.test(text[before] as string)) before -= 1;
    prevSig2 = before >= 0 ? (text[before] as string) : prevSig;
    prevSig = text[last] as string;
    if (ASCII_IDENTIFIER_CHAR.test(prevSig)) {
      let from = last;
      while (from > 0 && last - from < 16 && ASCII_IDENTIFIER_CHAR.test(text[from - 1] as string)) from -= 1;
      const word = text.slice(from, last + 1);
      prevWord = from === 0 && prevIsIdentifier ? (prevWord + word).slice(0, 16) : word;
    }
    prevIsIdentifier = last === text.length - 1 && ASCII_IDENTIFIER_CHAR.test(prevSig);
  };
  /** A literal (string, template, regex) ended: what follows is an operator. */
  const noteLiteral = (): void => {
    prevSig2 = prevSig;
    prevSig = '"';
    prevIsIdentifier = false;
  };

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
    const line = lines[lineIndex] ?? "";
    const length = line.length;
    // Columns of the comments on this line, as [start, end) pairs.
    const commentRanges: number[] = [];
    let rawSuppression = false;
    prevIsIdentifier = false;

    if (stack.length > 0 && stack[0]?.kind === "string") {
      stringBodyLines += 1;
      if (line.length <= 500 && statementLike.test(line)) stringCodeLike += 1;
    }

    // C/C++: is this line a directive, or the continuation of one?
    const spliced = cfamily && line.endsWith("\\");
    const inDirective =
      cfamily && !commentSpliced && (directiveOpen || (stack.length === 0 && /^\s*#/.test(line)));
    if (inDirective && !directiveOpen) {
      directiveOpen = true;
      directiveStart = lineIndex;
      const name = /^\s*#\s*([a-z]+)/.exec(line);
      if (name) conditional(name[1] as string);
    }

    // Recovery: a member or type declaration cannot be inside an open ( or [
    // (except in the arguments of a Rust macro, which can hold any tokens).
    if (
      stack.length === 0 &&
      !inDirective &&
      !commentSpliced &&
      innermostIsParen() &&
      length <= 1000 &&
      hardRestart.test(line) &&
      !(rust && brackets.some((entry) => entry.macro === true))
    ) {
      flush();
      const first = dropOpenParens();
      continued = false;
      if (first >= 0 && first < lineIndex) {
        addFallback(first, lineIndex - 1, "a declaration starts while a \"(\" or \"[\" is still open");
      }
    }

    if (parts.length === 0) {
      start = lineIndex;
      if (!statementCut) statementStart = lineIndex;
    }

    let code = "";
    let skeleton = "";
    let regularOpenAtEnd = false;
    // A backslash at the very end of the line inside a string: C and
    // JavaScript continue the string on the next line.
    let escapedLineEnd = false;
    // JavaScript: a regex scan reached the end of the line; the rest of the
    // line treats `/` as division (keeps the lexer linear).
    let regexFailed = false;

    // C# preprocessor directive: not code, but it decides the bracket state.
    const csDirective = csharp && stack.length === 0 ? /^\s*#\s*([a-z]+)/.exec(line) : null;
    if (csDirective) {
      conditional(csDirective[1] as string);
    } else if (commentSpliced) {
      // C/C++: a // comment continued by a backslash on the line before.
      code = " ".repeat(length);
      skeleton = code;
      rawSuppression = true;
      commentSpliced = line.endsWith("\\");
      // A directive whose last line ended in that comment ends with it.
      if (directiveOpen && !commentSpliced) {
        flushDirective();
        directiveOpen = false;
      }
    } else if (lineIndex === 0 && (js || rust) && line.startsWith("#!") && !line.startsWith("#![")) {
      // Hashbang line.
      code = " ".repeat(length);
      skeleton = code;
      rawSuppression = true;
    } else {
      let index = 0;
      while (index < length) {
        const ch = line[index] as string;
        const top = stack[stack.length - 1];

        if (top?.kind === "comment") {
          if (rust) {
            // Nested block comments: look for the next /* or */.
            let cursor = index;
            let found = -1;
            while (cursor < length - 1) {
              const a = line[cursor];
              const b = line[cursor + 1];
              if ((a === "*" && b === "/") || (a === "/" && b === "*")) {
                found = cursor;
                break;
              }
              cursor += 1;
            }
            const end = found < 0 ? length : found + 2;
            code += " ".repeat(end - index);
            skeleton += " ".repeat(end - index);
            commentRanges.push(index, end);
            index = end;
            if (found >= 0) {
              if (line[found] === "*") {
                top.depth -= 1;
                if (top.depth === 0) stack.pop();
              } else {
                top.depth += 1;
              }
            }
            continue;
          }
          const close = line.indexOf("*/", index);
          const end = close < 0 ? length : close + 2;
          code += " ".repeat(end - index);
          skeleton += " ".repeat(end - index);
          commentRanges.push(index, end);
          index = end;
          if (close >= 0) stack.pop();
          continue;
        }

        if (top?.kind === "string") {
          const textRun = stringRun(top);
          if (textRun !== null) {
            textRun.lastIndex = index;
            const text = textRun.exec(line);
            if (text !== null) {
              code += text[0];
              skeleton += " ".repeat(text[0].length);
              index += text[0].length;
              continue;
            }
          }
          let taken = 1;
          let closes = false;
          let opensHole = false;
          if (top.form === "token") {
            if (top.escapes && ch === "\\") {
              taken = index + 1 < length ? 2 : 1;
            } else if (ch === top.close[0] && line.startsWith(top.close, index)) {
              closes = true;
              taken = top.close.length;
            } else if (!top.escapes) {
              // Jump to the next possible closer.
              const next = line.indexOf(top.close[0] as string, index + 1);
              taken = (next < 0 ? length : next) - index;
            }
          } else if (top.form === "template") {
            if (ch === "\\") {
              taken = index + 1 < length ? 2 : 1;
            } else if (ch === "`") {
              closes = true;
            } else if (ch === "$" && line[index + 1] === "{") {
              taken = 2;
              opensHole = true;
            }
          } else if (top.form === "raw") {
            if (ch === '"') {
              let run = 1;
              while (line[index + run] === '"') run += 1;
              if (run >= top.quotes) {
                // Extra quotes before the delimiter are content.
                const content = run - top.quotes;
                if (content > 0) {
                  code += line.slice(index, index + content);
                  skeleton += " ".repeat(content);
                  index += content;
                }
                closes = true;
                taken = top.quotes;
              } else {
                taken = run;
              }
            } else if (ch === "{" && top.dollars > 0) {
              let run = 1;
              while (line[index + run] === "{") run += 1;
              taken = run;
              opensHole = run >= top.dollars;
            }
          } else if (ch === "\\" && top.form === "regular") {
            if (index + 1 < length) taken = 2;
            else escapedLineEnd = true;
          } else if (ch === top.close) {
            if (top.form === "verbatim" && line[index + 1] === '"') taken = 2;
            else closes = true;
          } else if (top.dollars > 0 && ch === "{") {
            if (line[index + 1] === "{") taken = 2;
            else opensHole = true;
          } else if (top.dollars > 0 && ch === "}" && line[index + 1] === "}") {
            taken = 2;
          }
          const chunk = line.slice(index, index + taken);
          index += taken;
          if (closes) {
            stack.pop();
            code += chunk;
            skeleton += stack.length === 0 ? closingSkeleton(chunk) : " ".repeat(chunk.length);
            if (js) noteLiteral();
          } else {
            code += chunk;
            skeleton += " ".repeat(chunk.length);
            if (opensHole) {
              stack.push({ kind: "hole", depth: 0, spec: false, js: top.form === "template" });
              if (js) {
                prevSig = "{";
                prevSig2 = "";
              }
            }
          }
          continue;
        }

        // Code: top level or inside an interpolation hole.
        const hole = top?.kind === "hole" ? top : undefined;
        if (hole?.spec) {
          // C#: format string of a hole, literal text up to the closing brace.
          if (ch === "}") {
            stack.pop();
            const parent = stack[stack.length - 1];
            let taken = 1;
            if (parent?.kind === "string" && parent.form === "raw") {
              while (taken < parent.dollars && line[index + taken] === "}") taken += 1;
            }
            code += line.slice(index, index + taken);
            skeleton += " ".repeat(taken);
            index += taken;
          } else if (ch === '"' && stack[stack.length - 2]?.kind === "string" &&
            (stack[stack.length - 2] as StringContext).form !== "raw") {
            // A quote cannot be part of the format of a non-raw string: it ends it.
            stack.pop();
          } else {
            code += ch;
            skeleton += " ";
            index += 1;
          }
          continue;
        }

        // A run of characters that start nothing: copied as one piece.
        if (!hole) {
          codeRun.lastIndex = index;
          const run = codeRun.exec(line);
          if (run !== null) {
            const text = run[0];
            code += text;
            skeleton += text;
            index += text.length;
            if (js) noteRun(text);
            if (!sawCode && text.trim().length > 0) sawCode = true;
            continue;
          }
        }

        if (ch === "/" && line[index + 1] === "/" && (!hole || hole.js)) {
          code += " ".repeat(length - index);
          skeleton += " ".repeat(length - index);
          commentRanges.push(index, length);
          if (cfamily && line.endsWith("\\")) commentSpliced = true;
          index = length;
          continue;
        }
        if (ch === "/" && line[index + 1] === "*") {
          if (stack.length === 0) contextStart = lineIndex;
          stack.push({ kind: "comment", depth: 1 });
          code += "  ";
          skeleton += "  ";
          commentRanges.push(index, index + 2);
          index += 2;
          continue;
        }

        // String literals.
        let opened: { context: StringContext; taken: number } | null = null;
        if (csharp) {
          // A run of $ / @ is tried once, at its first character.
          const prefixRun = index > 0 && (line[index - 1] === "$" || line[index - 1] === "@");
          if (ch === '"' || ((ch === "@" || ch === "$") && !prefixRun)) {
            CS_STRING_START.lastIndex = index;
            const opening = CS_STRING_START.exec(line);
            const dollarsBefore = opening ? (opening[1] as string).length : 0;
            const dollarsAfter = opening ? (opening[3] as string).length : 0;
            if (
              opening &&
              (dollarsBefore === 0 || dollarsAfter === 0) &&
              !(ch !== '"' && index > 0 && IDENTIFIER_CHAR.test(line[index - 1] as string))
            ) {
              const verbatim = opening[2] === "@";
              const dollars = dollarsBefore + dollarsAfter;
              const quoteRun = (opening[4] as string).length;
              const prefix = opening[0].length - quoteRun;
              if (!verbatim && quoteRun >= 3) {
                opened = {
                  context: { kind: "string", form: "raw", close: '"', multiline: true, escapes: false, dollars, quotes: quoteRun },
                  taken: prefix + quoteRun,
                };
              } else {
                opened = {
                  context: {
                    kind: "string",
                    form: verbatim ? "verbatim" : "regular",
                    close: '"',
                    multiline: verbatim,
                    escapes: !verbatim,
                    dollars: Math.min(dollars, 1),
                    quotes: 1,
                  },
                  taken: prefix + 1,
                };
              }
            }
          }
        } else if (ch === '"') {
          if (rust && line[index - 1] === "r") {
            opened = rustRawString(line, index);
          } else if (family === "java" && line.startsWith('"""', index)) {
            opened = { context: tokenString('"""', true), taken: 3 };
          } else if (cfamily && index > 0 && line[index - 1] === "R") {
            let prefixStart = index - 1;
            while (prefixStart > 0 && index - prefixStart < 3 && /[uUL8]/.test(line[prefixStart - 1] as string)) {
              prefixStart -= 1;
            }
            const prefix = line.slice(prefixStart, index);
            CPP_RAW_DELIMITER.lastIndex = index;
            const raw = CPP_RAW_DELIMITER.exec(line);
            if (
              raw &&
              CPP_RAW_PREFIXES.has(prefix) &&
              !(prefixStart > 0 && IDENTIFIER_CHAR.test(line[prefixStart - 1] as string))
            ) {
              opened = { context: tokenString(`)${raw[1] as string}"`, false), taken: raw[0].length };
            }
          }
          if (
            opened === null &&
            !(js && prevIsIdentifier && !JS_QUOTE_KEYWORDS.has(prevWord))
          ) {
            opened = { context: regularString('"', rust), taken: 1 };
          }
        } else if (ch === "'" && js) {
          if (!(prevIsIdentifier && !JS_QUOTE_KEYWORDS.has(prevWord))) {
            opened = { context: regularString("'", false), taken: 1 };
          }
        } else if (ch === "`" && (js || family === "go")) {
          opened = js
            ? { context: { kind: "string", form: "template", close: "`", multiline: true, escapes: true, dollars: 0, quotes: 0 }, taken: 1 }
            : { context: tokenString("`", false), taken: 1 };
        } else if (rust && ch === "#" && line[index - 1] === "r") {
          opened = rustRawString(line, index);
        }
        if (opened !== null) {
          const chunk = line.slice(index, index + opened.taken);
          if (stack.length === 0) contextStart = lineIndex;
          const topLevel = stack.length === 0;
          stack.push(opened.context);
          code += chunk;
          skeleton += topLevel ? openingSkeleton(chunk) : " ".repeat(chunk.length);
          index += opened.taken;
          if (js) noteLiteral();
          continue;
        }

        if (ch === "'" && charLiteral !== null) {
          let separator = false;
          if (cfamily && index > 0 && /[0-9A-Za-z_]/.test(line[index - 1] as string)) {
            // 1'000'000 is a number with digit separators; u8'a' is a character.
            let runStart = index;
            while (runStart > 0 && index - runStart < 64 && /[0-9A-Za-z_']/.test(line[runStart - 1] as string)) {
              runStart -= 1;
            }
            const run = line.slice(runStart, index);
            separator = /^[0-9]/.test(run) && !C_CHAR_PREFIXES.has(run);
          }
          if (!separator) {
            charLiteral.lastIndex = index;
            const literal = charLiteral.exec(line);
            if (literal) {
              const text = literal[0];
              code += text;
              skeleton += hole
                ? " ".repeat(text.length)
                : `'${" ".repeat(text.length - 2)}'`;
              index += text.length;
              continue;
            }
            if (rust && index + 1 < length && IDENTIFIER_CHAR.test(line[index + 1] as string)) {
              // A lifetime or loop label: 'a, 'static, 'outer.
              let end = index + 1;
              while (end < length && IDENTIFIER_CHAR.test(line[end] as string)) end += 1;
              const text = line.slice(index, end);
              sawCode = true;
              code += text;
              skeleton += hole ? SKELETON_FIELD.repeat(text.length) : text;
              index = end;
              continue;
            }
          }
        }

        if (js && ch === "/" && !regexFailed && regexAllowed() && line[index + 1] !== ">") {
          const end = regexLiteralEnd(line, index);
          if (end < 0) {
            regexFailed = true;
          } else {
            const text = line.slice(index, end);
            const close = text.lastIndexOf("/");
            sawCode = true;
            code += text;
            skeleton += hole
              ? " ".repeat(text.length)
              : `/${" ".repeat(close - 1)}${text.slice(close)}`;
            index = end;
            noteLiteral();
            continue;
          }
        }

        if (hole) {
          if (ch === "(" || ch === "[" || ch === "{") hole.depth += 1;
          else if (ch === ")" || ch === "]") hole.depth = Math.max(0, hole.depth - 1);
          else if (ch === "}") {
            if (hole.depth > 0) hole.depth -= 1;
            else {
              stack.pop();
              const parent = stack[stack.length - 1];
              let taken = 1;
              if (parent?.kind === "string" && parent.form === "raw") {
                while (taken < parent.dollars && line[index + taken] === "}") taken += 1;
              }
              code += line.slice(index, index + taken);
              skeleton += " ".repeat(taken);
              index += taken;
              continue;
            }
          } else if (ch === ":" && hole.depth === 0 && !hole.js) {
            if (line[index + 1] === ":") {
              code += "::";
              skeleton += SKELETON_FIELD.repeat(2);
              index += 2;
              continue;
            }
            hole.spec = true;
            code += ch;
            skeleton += " ";
            index += 1;
            continue;
          }
          if (js) noteCode(ch);
          if (!WHITESPACE.test(ch)) sawCode = true;
          code += ch;
          skeleton += WHITESPACE.test(ch) ? ch : SKELETON_FIELD;
          index += 1;
          continue;
        }

        if (!inDirective) {
          if (ch === "(" || ch === "[" || ch === "{") {
            if (brackets.length < MAX_BRACKETS) {
              const entry: Bracket = { ch, line: lineIndex };
              if (ch === "{" && literalBrace(line, index)) entry.literal = true;
              if (rust && /[!$]\s*$/.test(line.slice(Math.max(0, index - 8), index))) entry.macro = true;
              brackets.push(entry);
            } else bracketOverflow += 1;
          } else if (ch === ")" || ch === "]" || ch === "}") closeBracket(ch, lineIndex);
        }
        if (js) noteCode(ch);
        if (!WHITESPACE.test(ch)) sawCode = true;
        code += ch;
        skeleton += ch;
        index += 1;
      }

      // A single-line string cannot span lines (only an interpolation hole
      // of an interpolated one can, in C#): one that is open here was
      // misread or the file is not valid. Close it and match the line as
      // plain text. C and JavaScript continue a string after a backslash at
      // the end of the line.
      const top = stack[stack.length - 1];
      if (top?.kind === "string" && top.form === "regular" && !top.multiline) {
        if (escapedLineEnd && (cfamily || js)) {
          // Continued on the next line.
        } else {
          stack.pop();
          regularOpenAtEnd = true;
        }
      }
      if (regularOpenAtEnd) {
        addFallback(lineIndex, lineIndex, "a string is not closed at the end of its line");
      }
    }

    if (comments) {
      if (!line.toLowerCase().includes("code-audit:ignore")) comments[lineIndex] = "";
      else if (rawSuppression || csDirective) comments[lineIndex] = line;
      else comments[lineIndex] = suppressionLine(line, skeleton, commentRanges);
    }

    const isCodeLine = code.trim().length > 0;
    if (!isCodeLine) {
      code = "";
      skeleton = "";
    } else {
      if (!inDirective) sawCode = true;
      if (code.length > MAX_PATTERN_LINE_LENGTH) {
        overLong?.push(lineIndex);
        diagnostics?.overLong.push(lineIndex);
        for (const unit of windowUnits(lineIndex, code)) windows.push(unit);
        code = code.slice(0, MAX_PATTERN_LINE_LENGTH);
        skeleton = skeleton.slice(0, MAX_PATTERN_LINE_LENGTH);
      }
    }
    if (lineSkeletons) lineSkeletons[lineIndex] = skeleton;
    if (isCodeLine && !inDirective && !csharp) {
      const trimmed = skeleton.trimEnd();
      lineEndSig = trimmed[trimmed.length - 1] ?? "";
      const word = /[\p{L}\p{N}_$]{1,16}$/u.exec(trimmed.slice(-16));
      lineEndWord = word ? word[0] : "";
    }

    // A comment never contains another context, so the bottom of the stack
    // says whether a string or hole is open.
    const inString = stack.length > 0 && (stack[0] as Context).kind !== "comment";

    if (inDirective) {
      // The directive is its own unit; the statement around it sees a blank line.
      directiveParts.push(code);
      directiveSkeletons.push(skeleton);
      code = "";
      skeleton = "";
      if (!spliced || directiveParts.length >= MAX_LOGICAL_LINE_SPAN) {
        flushDirective();
        directiveStart = lineIndex + 1;
      }
      if (!spliced) directiveOpen = false;
    } else if (isCodeLine && !inString) {
      continued =
        stack.length === 0 &&
        (CONTINUES_AT_END.test(skeleton.trimEnd().slice(-4)) ||
          (lineIndex + 1 < lines.length &&
            continuesAtStart.test((lines[lineIndex + 1] as string).slice(0, 200))));
    }
    const mainIsCode = isCodeLine && !inDirective;
    parts.push(code);
    skeletonParts.push(skeleton);
    softBreaks.push(inString || continued);
    if (mainIsCode) {
      unitCodeLines += 1;
      unitNewLength += code.length + 1;
    }

    // The outermost string or comment has ended: check a long string.
    if (stack.length === 0 && contextStart >= 0) {
      if (
        stringBodyLines > STRING_FALLBACK_MIN_LINES &&
        stringCodeLike >= STRING_FALLBACK_MIN_CODE_LINES
      ) {
        addFallback(
          contextStart,
          lineIndex,
          `a string literal of ${stringBodyLines} lines contains ${stringCodeLike} lines that look like statements`,
        );
      }
      contextStart = -1;
      stringBodyLines = 0;
      stringCodeLike = 0;
    }

    const open = inString || innermostIsParen() || continued;
    if (!open) {
      flush();
      statementCut = false;
    } else if (
      unitCodeLines >= MAX_LOGICAL_LINE_SPAN ||
      unitNewLength >= MAX_LOGICAL_LINE_LENGTH ||
      parts.length >= MAX_UNIT_PARTS
    ) {
      cut(lineIndex);
    }
  }

  const last = lines.length - 1;
  flush();
  flushDirective();
  if (stack.length > 0 && contextStart >= 0) {
    addFallback(
      contextStart,
      last,
      stack[0]?.kind === "comment"
        ? "the file ends inside a block comment"
        : "the file ends inside a string literal",
    );
  }
  let firstOpenParen = -1;
  for (const entry of brackets) {
    if (entry.ch !== "{") {
      firstOpenParen = entry.line;
      break;
    }
  }
  if (firstOpenParen >= 0) {
    addFallback(firstOpenParen, last, "the file ends inside an open \"(\" or \"[\"");
  }
  // Overlapping regions are reported once, from the earliest line, and their
  // lines are added once as plain-line units.
  fallbackRegions.sort((left, right) => left.from - right.from);
  const merged: Array<{ from: number; to: number; reason: string }> = [];
  for (const region of fallbackRegions) {
    const previous = merged[merged.length - 1];
    if (previous && region.from <= previous.to + 1) previous.to = Math.max(previous.to, region.to);
    else merged.push({ ...region });
  }
  for (const region of merged) {
    diagnostics?.fallbacks.push({ ...region });
    for (let index = region.from; index <= region.to; index += 1) {
      const text = lines[index] ?? "";
      if (comments) comments[index] = text;
      if (text.trim().length === 0) continue;
      windows.push({
        start: index,
        text: text.slice(0, MAX_PATTERN_LINE_LENGTH),
        offsets: [0],
        declaration: false,
        headerEnd: 0,
        extra: true,
      });
      if (text.length > MAX_PATTERN_LINE_LENGTH) {
        for (const unit of windowUnits(index, text)) windows.push(unit);
      }
    }
  }
  for (const unit of windows) result.push(unit);

  if (extras) {
    extras.comments = comments;
    if (lineSkeletons) {
      extras.testRegions = rustTestRegions(lineSkeletons, merged);
    }
  }
  return result;
}

/**
 * Rust raw string whose `r` (with an optional `b` / `c` before it) was
 * already emitted as code and whose `#` or `"` is at `index`.
 */
function rustRawString(line: string, index: number): { context: StringContext; taken: number } | null {
  let prefixStart = index - 1;
  if (prefixStart > 0 && (line[prefixStart - 1] === "b" || line[prefixStart - 1] === "c")) prefixStart -= 1;
  if (prefixStart > 0 && IDENTIFIER_CHAR.test(line[prefixStart - 1] as string)) return null;
  RUST_RAW_START.lastIndex = prefixStart;
  const raw = RUST_RAW_START.exec(line);
  if (!raw) return null;
  return { context: tokenString(`"${raw[1] as string}`, false), taken: prefixStart + raw[0].length - index };
}

/** Text of an open string up to the next character that may matter. */
const STRING_RUNS = new Map<string, RegExp>();
function stringRun(top: StringContext): RegExp | null {
  if (top.form === "raw" || (top.form === "token" && !top.escapes)) return null;
  let excluded = top.form === "template" ? "`$" : top.close[0] ?? "";
  if (top.escapes || top.form === "template") excluded += "\\\\";
  if (top.dollars > 0) excluded += "{}";
  let run = STRING_RUNS.get(excluded);
  if (run === undefined) {
    run = new RegExp(`[^${excluded.replace(/[\]\[^-]/g, "\\$&")}]+`, "y");
    STRING_RUNS.set(excluded, run);
  }
  return run;
}

/**
 * The line as inline suppression reads it: comments as written, code as in
 * the skeleton (string and regex text blank), so a `code-audit:ignore` inside
 * a string literal is not seen, and code before a comment still shows.
 */
function suppressionLine(line: string, skeleton: string, ranges: number[]): string {
  let result = "";
  let at = 0;
  for (let index = 0; index < ranges.length; index += 2) {
    const from = ranges[index] as number;
    const to = ranges[index + 1] as number;
    result += skeleton.slice(at, from).padEnd(from - at, " ") + line.slice(from, to);
    at = to;
  }
  return result + skeleton.slice(at, line.length);
}

function regularString(quote: string, multiline: boolean): StringContext {
  return { kind: "string", form: "regular", close: quote, multiline, escapes: true, dollars: 0, quotes: 1 };
}

function tokenString(close: string, escapes: boolean): StringContext {
  return { kind: "string", form: "token", close, multiline: true, escapes, dollars: 0, quotes: 0 };
}

const RUST_CFG_TEST = /^#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*/;
const RUST_ATTRIBUTE = /^#\s*\[[^\n]*\]\s*$/;
const RUST_MOD_OPEN = /^(?:pub(?:\([\w:\s]{0,40}\))?\s+)?mod\s+[A-Za-z_]\w*\s*\{/;

/**
 * Rust `#[cfg(test)]` modules: the attribute, optionally further attributes,
 * then `mod name {` up to its matching `}`. Read from the per-line skeletons
 * (strings and comments blanked). A module that is not closed, or one that
 * overlaps a fallback region, is not reported: the lexer could not vouch for
 * its braces, and a test region only ever lowers confidence.
 */
function rustTestRegions(
  skeletons: string[],
  fallbacks: Array<{ from: number; to: number }>,
): Array<{ from: number; to: number }> {
  const regions: Array<{ from: number; to: number }> = [];
  let attributeLine = -1;
  let depth = 0;
  let inModule = false;
  for (let index = 0; index < skeletons.length; index += 1) {
    const text = (skeletons[index] ?? "").trim();
    if (inModule) {
      for (let at = 0; at < text.length; at += 1) {
        const ch = text[at];
        if (ch === "{") depth += 1;
        else if (ch === "}") {
          depth -= 1;
          if (depth === 0) break;
        }
      }
      if (depth === 0) {
        regions.push({ from: attributeLine, to: index });
        inModule = false;
        attributeLine = -1;
      }
      continue;
    }
    let rest = text;
    if (attributeLine < 0) {
      const cfg = RUST_CFG_TEST.exec(text);
      if (!cfg) continue;
      attributeLine = index;
      rest = text.slice(cfg[0].length);
      if (rest.length === 0) continue;
    } else if (text.length === 0 || RUST_ATTRIBUTE.test(text)) {
      continue;
    }
    const opening = RUST_MOD_OPEN.exec(rest);
    if (!opening) {
      attributeLine = -1;
      continue;
    }
    depth = 0;
    let closed = false;
    for (let at = opening[0].length - 1; at < rest.length; at += 1) {
      const ch = rest[at];
      if (ch === "{") depth += 1;
      else if (ch === "}") {
        depth -= 1;
        if (depth === 0) {
          closed = true;
          break;
        }
      }
    }
    if (closed) {
      regions.push({ from: attributeLine, to: index });
      attributeLine = -1;
    } else {
      inModule = true;
    }
  }
  return regions.filter(
    (region) => !fallbacks.some((fallback) => fallback.from <= region.to && region.from <= fallback.to),
  );
}
