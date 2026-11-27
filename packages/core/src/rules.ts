import fs from "node:fs";
import path from "node:path";
import { parse as parseYaml } from "yaml";
import { canonicalExpressionLine, yamlKeyValues, type YamlKeyValue } from "./yamlValues.js";
import { z } from "zod";
import type { InventoryFile } from "./inventory.js";
import type { Confidence, Severity } from "./finding.js";
import { CONFIDENCE_ORDER } from "./finding.js";
import { InterruptedError, runInterruptible } from "./interrupt.js";
import {
  LINE_MASK_ALL,
  LINE_MASK_STRINGS,
  lexLiterals,
  redactEvidence,
  redactLine,
  sensitiveLines,
  splitLines,
  type RedactRange,
} from "./redact.js";
import { clikeLogicalLines, isClikeLanguage, type LexExtras } from "./lexers/clike.js";
import { dockerfileLogicalLines } from "./lexers/dockerfile.js";

export const RULE_LANGUAGES = [
  "csharp",
  "java",
  "javascript",
  "typescript",
  "python",
  "go",
  "c",
  "cpp",
  "rust",
  "dockerfile",
  "yaml",
  "json",
  "markdown",
  "razor",
  "xml",
] as const;

const RuleLanguageSchema = z.enum(RULE_LANGUAGES);

const RuleObjectSchema = z
  .object({
    id: z.string().regex(/^[a-z0-9][a-z0-9-]*$/, "rule id must be lowercase letters, digits, or dashes"),
    title: z.string().min(1),
    title_zh: z.string().min(1).optional(),
    severity: z.enum(["critical", "high", "medium", "low", "info"]),
    confidence: z.enum(["high", "medium", "low"]),
    kind: z.enum(["finding", "hotspot"]).default("finding"),
    cwe: z.string().regex(/^CWE-\d+$/, "cwe must look like CWE-89"),
    owasp: z.string().optional(),
    languages: z.array(RuleLanguageSchema).min(1),
    pattern: z.string().min(1).optional(),
    patterns: z.array(z.string().min(1)).min(1).optional(),
    notPattern: z.string().min(1).optional(),
    pathInclude: z.string().min(1).optional(),
    pathExclude: z.string().min(1).optional(),
    filePattern: z.string().min(1).optional(),
    fileAbsentPattern: z.string().min(1).optional(),
    flags: z.string().regex(/^[imsuy]*$/).optional(),
    group: z.string().regex(/^[a-z0-9][a-z0-9-]*$/).optional(),
    matchDeclarations: z.boolean().optional(),
    /**
     * The match is a credential, key, token or password literal: the engine
     * masks it in the evidence so it never reaches a report in clear text.
     */
    redactEvidence: z.boolean().optional(),
    /**
     * Python and the C-family languages (C#, Java, JavaScript/TypeScript, Go,
     * C/C++, Rust): ignore a match that starts inside the text of a string
     * literal (`s = "os.system(cmd)"`) or of a JavaScript regex literal. For
     * rules that look for an API call; not for rules that legitimately read
     * literals (SQL text, URLs, hosts).
     */
    codeOnly: z.boolean().optional(),
    /**
     * YAML only: match only inside the value of one of these mapping keys.
     * The file is parsed and the patterns see the value of each such key
     * (aliases resolved, `${{ }}` expressions in canonical form, `env` /
     * `matrix` indirection resolved one level); see `yamlValues.ts`. A file
     * that cannot be parsed is matched line by line in full, with a warning.
     */
    withinKeys: z
      .array(z.string().regex(/^[A-Za-z_][A-Za-z0-9_.-]*$/, "withinKeys entries must be plain YAML keys"))
      .min(1)
      .optional(),
    message: z.string().min(1),
    message_zh: z.string().min(1).optional(),
    remediation: z.string().min(1),
    remediation_zh: z.string().min(1).optional(),
    references: z.array(z.string()).optional(),
  });

/** Every field a rule may have, in schema order (documented in docs/rules.md). */
export const RULE_FIELDS: readonly string[] = Object.keys(RuleObjectSchema.shape);

const RuleSchema = RuleObjectSchema.superRefine((rule, ctx) => {
    if (!rule.pattern && !rule.patterns) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "either pattern or patterns is required",
        path: ["pattern"],
      });
    }
    if (rule.pattern && rule.patterns) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "pattern and patterns are mutually exclusive",
        path: ["patterns"],
      });
    }
    if (rule.withinKeys && rule.languages.some((language) => language !== "yaml")) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "withinKeys is only supported for rules whose languages are [yaml]",
        path: ["withinKeys"],
      });
    }
  });

export type RuleDefinition = z.infer<typeof RuleSchema>;

export interface CompiledRule {
  pattern?: RegExp;
  patterns?: RegExp[];
  /**
   * `pattern` (or the first of `patterns`) with the global flag, used to find
   * every match in a unit. Carries the `d` flag when evidence is redacted.
   */
  locator?: RegExp;
  /** True when the locator defines a capture group named `secret`. */
  hasSecretGroup?: boolean;
  notPattern?: RegExp;
  pathInclude?: RegExp;
  pathExclude?: RegExp;
  filePattern?: RegExp;
  fileAbsentPattern?: RegExp;
}

export interface LoadedRule extends RuleDefinition {
  sourceFile: string;
  compiled: CompiledRule;
}

export class RuleLoadError extends Error {
  readonly file: string;

  constructor(file: string, message: string) {
    super(`rule loading failed (${file}): ${message}`);
    this.name = "RuleLoadError";
    this.file = file;
  }
}

function compile(
  source: string | undefined,
  file: string,
  field: string,
  flags = "i",
): RegExp | undefined {
  if (source === undefined) return undefined;
  try {
    return new RegExp(source, flags);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new RuleLoadError(file, `${field} is not a valid regular expression: ${message}`);
  }
}

function compileRule(definition: RuleDefinition, sourceFile: string): LoadedRule {
  const flags = definition.flags ?? "i";
  const locatorSource = definition.pattern ?? definition.patterns?.[0];
  return {
    ...definition,
    sourceFile,
    compiled: {
      locator: compile(
        locatorSource,
        sourceFile,
        definition.pattern ? "pattern" : "patterns[0]",
        `${flags}g${definition.redactEvidence ? "d" : ""}`,
      ),
      hasSecretGroup: locatorSource !== undefined && /\(\?<secret>/.test(locatorSource),
      pattern: compile(definition.pattern, sourceFile, "pattern", definition.flags ?? "i"),
      patterns: definition.patterns?.map((p, index) =>
        compile(p, sourceFile, `patterns[${index}]`, definition.flags ?? "i"),
      ) as RegExp[] | undefined,
      notPattern: compile(
        definition.notPattern,
        sourceFile,
        "notPattern",
        definition.flags ?? "i",
      ),
      pathInclude: compile(definition.pathInclude, sourceFile, "pathInclude", ""),
      pathExclude: compile(definition.pathExclude, sourceFile, "pathExclude", ""),
      filePattern: compile(definition.filePattern, sourceFile, "filePattern", "im"),
      fileAbsentPattern: compile(
        definition.fileAbsentPattern,
        sourceFile,
        "fileAbsentPattern",
        "im",
      ),
    },
  };
}

function listYamlFiles(dir: string): string[] {
  const result: string[] = [];
  const walk = (current: string): void => {
    const entries = fs.readdirSync(current, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const abs = path.join(current, entry.name);
      if (entry.isDirectory()) {
        // Opengrep/Semgrep-syntax rules live under rules/opengrep and use a
        // different schema; they are loaded by the external adapter instead.
        if (entry.name === "opengrep") continue;
        walk(abs);
      } else if (
        entry.isFile() &&
        (entry.name.endsWith(".yml") || entry.name.endsWith(".yaml"))
      ) {
        result.push(abs);
      }
    }
  };
  if (!fs.existsSync(dir)) {
    throw new RuleLoadError(dir, "rules directory does not exist");
  }
  walk(dir);
  return result.sort();
}

const DefinitionsSchema = z.record(
  z.string().regex(/^[A-Z][A-Z0-9_]*$/, "definition names must look like REQUEST_VALUE"),
  z.string().min(1),
);

const DEFINITION_REFERENCE = /\{\{([A-Z][A-Z0-9_]*)\}\}/g;

/** Rule fields that hold a regular expression and may use `{{NAME}}`. */
const REGEX_FIELDS = [
  "pattern",
  "patterns",
  "notPattern",
  "pathInclude",
  "pathExclude",
  "filePattern",
  "fileAbsentPattern",
] as const;

function expandDefinition(
  source: string,
  definitions: Map<string, string>,
  file: string,
): string {
  return source.replace(DEFINITION_REFERENCE, (_match, name: string) => {
    const value = definitions.get(name);
    if (value === undefined) {
      throw new RuleLoadError(file, `unknown definition {{${name}}}`);
    }
    return value;
  });
}

/**
 * Read the optional top-level `definitions` map of a rule file: named regex
 * fragments that rules in the same file reference as `{{NAME}}`. A definition
 * may use definitions that appear before it.
 */
function loadDefinitions(raw: unknown, file: string): Map<string, string> {
  const definitions = new Map<string, string>();
  if (raw === undefined || raw === null) return definitions;
  const parsed = DefinitionsSchema.safeParse(raw);
  if (!parsed.success) {
    const details = parsed.error.issues
      .map((issue) => `${issue.path.join(".") || "<root>"}: ${issue.message}`)
      .join("; ");
    throw new RuleLoadError(file, `invalid definitions: ${details}`);
  }
  for (const [name, source] of Object.entries(parsed.data)) {
    definitions.set(name, expandDefinition(source, definitions, file));
  }
  return definitions;
}

function expandRuleDefinitions(
  rawRule: unknown,
  definitions: Map<string, string>,
  file: string,
): unknown {
  if (typeof rawRule !== "object" || rawRule === null) return rawRule;
  const rule: Record<string, unknown> = { ...(rawRule as Record<string, unknown>) };
  for (const field of REGEX_FIELDS) {
    const value = rule[field];
    if (typeof value === "string") {
      rule[field] = expandDefinition(value, definitions, file);
    } else if (Array.isArray(value)) {
      rule[field] = value.map((item: unknown) =>
        typeof item === "string" ? expandDefinition(item, definitions, file) : item,
      );
    }
  }
  return rule;
}

export interface RuleSet {
  rules: LoadedRule[];
  rulesDir: string;
  files: string[];
}

export function loadRules(rulesDir: string): RuleSet {
  const absoluteDir = path.resolve(rulesDir);
  const files = listYamlFiles(absoluteDir);
  const rules: LoadedRule[] = [];
  const byId = new Map<string, string>();

  for (const file of files) {
    const relative = path.relative(absoluteDir, file);
    let document: unknown;
    try {
      document = parseYaml(fs.readFileSync(file, "utf8"));
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new RuleLoadError(relative, `YAML parse failed: ${message}`);
    }

    const rawRules: unknown = Array.isArray(document)
      ? document
      : (document as { rules?: unknown } | null)?.rules;
    const definitions = loadDefinitions(
      Array.isArray(document)
        ? undefined
        : (document as { definitions?: unknown } | null)?.definitions,
      relative,
    );
    if (rawRules === undefined) {
      throw new RuleLoadError(relative, "missing top-level rules array");
    }
    if (!Array.isArray(rawRules)) {
      throw new RuleLoadError(relative, "rules must be an array");
    }

    for (const [index, rawRule] of rawRules.entries()) {
      const parsed = RuleSchema.safeParse(
        expandRuleDefinitions(rawRule, definitions, relative),
      );
      if (!parsed.success) {
        const details = parsed.error.issues
          .map((issue) => `${issue.path.join(".") || "<root>"}: ${issue.message}`)
          .join("; ");
        throw new RuleLoadError(relative, `invalid rule at index ${index + 1}: ${details}`);
      }
      const rule = compileRule(parsed.data, relative);
      const previous = byId.get(rule.id);
      if (previous) {
        throw new RuleLoadError(
          relative,
          `duplicate rule id: ${rule.id} (already defined in ${previous})`,
        );
      }
      byId.set(rule.id, relative);
      rules.push(rule);
    }
  }

  return { rules, rulesDir: absoluteDir, files };
}

export function ruleMatchesFile(
  rule: LoadedRule,
  file: Pick<InventoryFile, "relPath" | "language">,
): boolean {
  if (!rule.languages.includes(file.language as never)) return false;
  if (rule.compiled.pathInclude && !rule.compiled.pathInclude.test(file.relPath)) {
    return false;
  }
  if (rule.compiled.pathExclude && rule.compiled.pathExclude.test(file.relPath)) {
    return false;
  }
  return true;
}

function parseSuppression(
  line: string,
): { ruleIds: string[]; reason: string } | undefined {
  const marker = "code-audit:ignore";
  const index = line.toLowerCase().indexOf(marker);
  if (index < 0) return undefined;
  const rest = line.slice(index + marker.length).trim();
  if (!rest) return undefined;
  const divider = rest.indexOf("--");
  const idPart = divider >= 0 ? rest.slice(0, divider) : rest;
  const reason = divider >= 0 ? rest.slice(divider + 2).trim() : "";
  const ruleIds = idPart
    .split(/[\s,]+/)
    .map((value) => value.trim())
    .filter((value) => /^[a-z0-9*][a-z0-9-]*$/.test(value));
  if (ruleIds.length === 0) return undefined;
  return { ruleIds, reason };
}

export function isSuppressed(
  currentLine: string,
  previousLine: string | undefined,
  ruleId: string,
): { suppressed: boolean; reason: string } {
  for (const line of [currentLine, previousLine ?? ""]) {
    const parsed = parseSuppression(line);
    if (!parsed) continue;
    if (parsed.ruleIds.includes("*") || parsed.ruleIds.includes(ruleId)) {
      return { suppressed: true, reason: parsed.reason };
    }
  }
  return { suppressed: false, reason: "" };
}

export interface RuleHit {
  rule: LoadedRule;
  file: InventoryFile;
  line: number;
  evidence: string;
  /** Reason given by the inline `code-audit:ignore` comment that suppressed the hit. */
  suppressedBy?: string;
}

/**
 * Return the code part of a Python line, dropping a `#` comment.
 *
 * A `#` inside a string literal is kept (`"a#b"` is not a comment). The
 * function is line-based, so a triple-quoted string that spans lines is not
 * tracked across lines; that is acceptable for a pattern engine.
 */
export function stripPythonComment(line: string): string {
  let quote: string | null = null;
  let triple = false;
  for (let index = 0; index < line.length; index += 1) {
    const ch = line[index];
    if (quote) {
      if (ch === "\\") {
        index += 1;
        continue;
      }
      if (triple) {
        if (line.startsWith(quote.repeat(3), index)) {
          index += 2;
          quote = null;
          triple = false;
        }
      } else if (ch === quote) {
        quote = null;
      }
      continue;
    }
    if (ch === "#") return line.slice(0, index);
    if (ch === '"' || ch === "'") {
      if (line.startsWith(ch.repeat(3), index)) {
        quote = ch;
        triple = true;
        index += 2;
      } else {
        quote = ch;
        triple = false;
      }
    }
  }
  return line;
}

/** One unit of text that rule patterns are matched against. */
export interface LogicalLine {
  /** Zero-based index of the first physical line of the unit. */
  start: number;
  /** Text the patterns see; physical lines are joined with "\n". */
  text: string;
  /** Offset in `text` at which each physical line of the unit begins. */
  offsets: number[];
  /** True for a Python `def`, `class`, `import` or `from ... import` statement. */
  declaration: boolean;
  /**
   * Offset in `text` where the declaration header ends: the `:` that closes a
   * `def` / `class` signature, or the end of an `import` statement. Rules
   * without `matchDeclarations` do not see the text before it. 0 when the unit
   * has no header.
   */
  headerEnd: number;
  /**
   * Python and the C-family languages: `text` with the contents of string
   * (and JavaScript regex) literals replaced by spaces, the code of f-string
   * replacement fields (C#, JavaScript: interpolation holes) replaced by
   * `SKELETON_FIELD`, and the line breaks that do not end anything (inside a
   * string, after a backslash) replaced by a space. Brackets, commas and
   * semicolons that remain are code. Same length as `text`.
   */
  skeleton?: string;
  /**
   * Column of the physical line at which `text` starts. Set on the extra
   * windows of an over-long line; otherwise every part of a unit starts at
   * column 0 of its line.
   */
  column?: number;
  /**
   * True for a unit added by the fail-open paths (lexer fallback, window of an
   * over-long line, bridge across a recovery restart). Such a unit repeats
   * text that other units already cover.
   */
  extra?: boolean;
  /** An `extra` unit that joins the lines around a recovery restart. */
  bridge?: boolean;
  /**
   * The span of a match (what `notPattern` sees, and what group
   * deduplication compares) is the physical lines the match covers, widened
   * to the expression around the match, instead of only that expression. Set
   * by the C-family lexer for the languages whose rules were written for one
   * physical line at a time (all but C#): on a single-line statement the span
   * stays the whole line.
   */
  lineSpan?: boolean;
}

/** Filler in a skeleton for the code of an f-string replacement field. */
export const SKELETON_FIELD = "\u0001";

/**
 * A bracketed statement with more code lines than this is matched in
 * overlapping windows. Comment-only and blank lines do not count.
 */
export const MAX_LOGICAL_LINE_SPAN = 200;

/**
 * At most this many characters of one line (for Python: of its code, after the
 * comment is removed) are matched as one piece. A longer line is matched in
 * overlapping windows of this size, up to `MAX_LONG_LINE_MATCHED` characters,
 * and reported in a warning. The cap bounds the work any single pattern can do
 * on generated, minified or hostile input.
 */
export const MAX_PATTERN_LINE_LENGTH = 2000;

/** Characters of an over-long line that are matched (in windows). */
export const MAX_LONG_LINE_MATCHED = 20_000;

/** A logical line is cut when its text grows beyond this many characters. */
export const MAX_LOGICAL_LINE_LENGTH = 16_000;

/**
 * A statement that has stayed open for this many code lines is ended by a line
 * at indentation 0 that looks like a new statement (lexer recovery).
 */
const SOFT_RESTART_AFTER_LINES = 15;

/**
 * Safety net for a triple-quoted string the lexer may have invented: when the
 * dropped body is longer than `TRIPLE_FALLBACK_MIN_LINES` lines and at least
 * `TRIPLE_FALLBACK_MIN_CODE_LINES` of them look like statements, the region is
 * matched again as plain text.
 */
const TRIPLE_FALLBACK_MIN_LINES = 60;
const TRIPLE_FALLBACK_MIN_CODE_LINES = 20;

/** Wall-clock budget for matching all rules against one file. */
export const FILE_MATCH_BUDGET_MS = 5000;

/**
 * How long after the budget a match that has not returned is interrupted (see
 * `interrupt.ts`). The budget itself is checked between matches.
 */
export const HARD_INTERRUPT_GRACE_MS = 1000;

/** Budget per file once several files have already exhausted the full budget. */
const REDUCED_FILE_MATCH_BUDGET_MS = 500;
const SLOW_FILES_BEFORE_REDUCED_BUDGET = 5;

/**
 * Upper bound on the matches of one rule in one logical line, per physical
 * line of it. Reaching it is reported in a warning.
 */
const MAX_MATCHES_PER_LINE = 100;

/**
 * A statement with more code lines than this has the secondary `patterns` of
 * a rule tested on the expression around each match instead of on the whole
 * statement: in a list of a hundred calls, `shell=True` in the last one says
 * nothing about the first.
 */
const WHOLE_UNIT_PATTERNS_MAX_LINES = 15;

const PYTHON_DECLARATION = /^\s*(?:async\s+def|def|class|import|from)\s/;
const PYTHON_BLOCK_DECLARATION = /^\s*(?:async\s+def|def|class)\s/;

/**
 * A line that can only be the start of a new statement, whatever the lexer
 * believes about open brackets: `def`, `class`, a decorator, `import`,
 * `from ... import`, `return`, `raise`.
 */
const PYTHON_HARD_RESTART =
  /^\s*(?:(?:async\s+)?def\s+\w+\s*\(|class\s+\w+\s*[:(]|@[A-Za-z_][\w.]*\s*(?:\(|#|$)|import\s+[A-Za-z_]|from\s+[\w.]+\s+import\b|(?:return|raise)\b)/;

/** A compound-statement header; it restarts when the line also ends with `:`. */
const PYTHON_BLOCK_RESTART =
  /^\s*(?:if|elif|for|while|with|try|else|except|finally|async\s+(?:for|with))\b/;

/**
 * A line at indentation 0 that looks like a new top-level statement (an
 * assignment or a call). Used only after a statement has stayed open for
 * `SOFT_RESTART_AFTER_LINES` code lines.
 */
const PYTHON_SOFT_RESTART =
  /^[A-Za-z_][\w.]*(?:\[[^\]\n]{0,80}\])?\s*(?:[-+*/|&^%@]?=(?!=)|:\s*[A-Za-z_\[]|\()/;

/** An assignment or a call statement at any indentation. */
const PYTHON_STATEMENT_LIKE =
  /^\s*[A-Za-z_][\w.]*(?:\[[^\]\n]{0,80}\])?\s*(?:[-+*/|&^%@]?=(?!=)\s*\S|\(.*\)\s*$)/;

function looksLikePythonStatement(line: string): boolean {
  if (line.length > 400) return false;
  return (
    PYTHON_HARD_RESTART.test(line) ||
    (PYTHON_BLOCK_RESTART.test(line) && /:\s*$/.test(stripPythonComment(line))) ||
    PYTHON_STATEMENT_LIKE.test(line)
  );
}

interface StringContext {
  kind: "string";
  quote: string;
  triple: boolean;
  fstring: boolean;
  /** Open since an earlier line: its literal text on this line is dropped. */
  carried: boolean;
}

/** A `{...}` replacement field of an f-string. */
interface FieldContext {
  kind: "field";
  depth: number;
  /** True after the `:` that starts the format spec. */
  spec: boolean;
}

type LexContext = StringContext | FieldContext;

/** Every valid Python string prefix, lower case. */
const STRING_PREFIXES = new Set(["r", "u", "b", "f", "t", "br", "rb", "fr", "rf", "tr", "rt"]);

const IDENTIFIER_CHAR = /[\p{L}\p{N}_]/u;

/**
 * The string prefix that ends right before the quote at `quoteIndex`: its
 * length (0 when there is none) and whether it makes an f-string or t-string.
 *
 * Only real prefixes count (`r`, `u`, `b`, `f`, `t` and their two-letter
 * combinations, any case), and only when no identifier character precedes
 * them: in `x if"""a""" else y` the `if` is a keyword, not a prefix.
 */
function stringPrefixBefore(line: string, quoteIndex: number): { length: number; fstring: boolean } {
  let start = quoteIndex;
  while (start > 0 && quoteIndex - start < 3 && IDENTIFIER_CHAR.test(line[start - 1] as string)) {
    start -= 1;
  }
  const run = line.slice(start, quoteIndex).toLowerCase();
  if (run.length === 0 || run.length > 2 || !STRING_PREFIXES.has(run)) {
    return { length: 0, fstring: false };
  }
  return { length: run.length, fstring: run.includes("f") || run.includes("t") };
}

/** Length of a string prefix that starts at `index` in code, or 0. */
function stringPrefixAt(line: string, index: number): number {
  const ahead = /^[A-Za-z]{1,2}(?=["'])/.exec(line.slice(index, index + 3));
  if (!ahead || !STRING_PREFIXES.has(ahead[0].toLowerCase())) return 0;
  if (index > 0 && IDENTIFIER_CHAR.test(line[index - 1] as string)) return 0;
  return ahead[0].length;
}

/** Why and where a lexer (Python, C-family, markup) could not vouch for its own result. */
export interface LexDiagnostics {
  /** Zero-based indexes of lines whose code is longer than the line cap. */
  overLong: number[];
  /** Regions matched again as plain physical lines (zero-based, inclusive). */
  fallbacks: Array<{ from: number; to: number; reason: string }>;
  /** Zero-based first line of each statement that was cut into windows. */
  cuts: number[];
}

export function emptyLexDiagnostics(): LexDiagnostics {
  return { overLong: [], fallbacks: [], cuts: [] };
}

/** Extra units for the part of an over-long line beyond the first window. */
export function windowUnits(lineIndex: number, text: string): LogicalLine[] {
  const units: LogicalLine[] = [];
  const limit = Math.min(text.length, MAX_LONG_LINE_MATCHED);
  const step = MAX_PATTERN_LINE_LENGTH / 2;
  for (let column = step; column < limit; column += step) {
    units.push({
      start: lineIndex,
      text: text.slice(column, Math.min(limit, column + MAX_PATTERN_LINE_LENGTH)),
      offsets: [0],
      declaration: false,
      headerEnd: 0,
      column,
      extra: true,
    });
  }
  return units;
}

/**
 * Turn the physical lines of a Python file into the text rules are matched
 * against:
 *
 * - `#` comments are removed (a `#` inside a string literal is kept);
 * - a statement that is only a string literal (a docstring) is blanked, and so
 *   is the literal text of any triple-quoted string on its continuation lines;
 *   the code of f-string replacement fields is always kept;
 * - a statement that spans several physical lines because of open brackets,
 *   an open triple-quoted string, a trailing backslash or a string continued
 *   with a backslash becomes one logical line, so `notPattern` and `[^)]*`
 *   see the whole call.
 *
 * This is a small lexer, not a parser, and it FAILS OPEN: whenever it is not
 * sure, it produces more text to match, never less.
 *
 * - It follows f-string replacement fields (including quotes nested in them,
 *   as Python 3.12 allows) so brackets inside strings never count.
 * - A string that is not closed at the end of its line is closed there, and a
 *   line that can only start a new statement (`def`, `class`, a decorator,
 *   `import`, `if ...:` and so on) resets the bracket depth, as does an
 *   assignment or call at indentation 0 once a statement has stayed open for
 *   `SOFT_RESTART_AFTER_LINES` code lines. Because such a line could also be a
 *   legitimate continuation, an extra unit bridges the restart so a call that
 *   spans it is still seen whole.
 * - A statement with more than `MAX_LOGICAL_LINE_SPAN` code lines (comment and
 *   blank lines do not count) or `MAX_LOGICAL_LINE_LENGTH` characters is
 *   matched in windows that overlap by half, and recorded in
 *   `diagnostics.cuts`.
 * - A line whose code is longer than `MAX_PATTERN_LINE_LENGTH` is matched in
 *   overlapping windows up to `MAX_LONG_LINE_MATCHED` characters and recorded
 *   in `overLong` / `diagnostics.overLong`.
 * - When the file ends inside a string, a bracket or a continuation, or a
 *   triple-quoted string runs long while its body keeps looking like code, the
 *   region is added again as plain physical lines with only the comment
 *   removed, and recorded in `diagnostics.fallbacks`.
 */
export function pythonLogicalLines(
  lines: string[],
  overLong?: number[],
  diagnostics?: LexDiagnostics,
): LogicalLine[] {
  const result: LogicalLine[] = [];
  const windows: LogicalLine[] = [];
  const stack: LexContext[] = [];
  let depth = 0;
  let continued = false;
  // Code lines the current statement has been open for.
  let statementLines = 0;
  let statementStart = 0;
  let statementCut = false;
  let declKind: "block" | "import" | null = null;
  let headerDone = false;
  // Where the declaration header ended: physical line and column after it.
  let headerLine = -1;
  let headerColumn = 0;

  let parts: string[] = [];
  let skeletonParts: string[] = [];
  // softBreak[i]: the line break after part i does not end anything.
  let softBreaks: boolean[] = [];
  let start = 0;
  let sawCode = false;
  // Code lines and characters added to the unit since it was started or seeded.
  let unitCodeLines = 0;
  let unitNewLength = 0;

  interface Tail {
    start: number;
    parts: string[];
    skeletonParts: string[];
    softBreaks: boolean[];
  }
  // After a recovery restart: the tail of the statement it ended, followed by
  // the lines after it. If the restart line was a continuation after all, this
  // extra unit still shows the call whole.
  let bridge: (Tail & { added: number }) | null = null;

  const emitBridge = (): void => {
    if (bridge !== null && bridge.added > 0) {
      const joined = build(bridge.parts, bridge.skeletonParts, bridge.softBreaks, true);
      result.push({
        start: bridge.start,
        text: joined.text,
        offsets: joined.offsets,
        declaration: false,
        headerEnd: 0,
        skeleton: joined.skeleton,
        extra: true,
        bridge: true,
      });
    }
    bridge = null;
  };

  // Triple-quoted string that is open across lines.
  let tripleStart = -1;
  let tripleBodyLines = 0;
  let tripleCodeLike = 0;

  const isOpen = (): boolean => depth > 0 || continued || stack.length > 0;
  const inTriple = (): boolean =>
    stack.some((context) => context.kind === "string" && context.triple);

  // Blank parts (comment-only lines, dropped string text) are free: they do
  // not count toward the size of a unit or of the overlap, up to this many
  // parts in one unit.
  const MAX_UNIT_PARTS = 5000;

  const takeTail = (): Tail | null => {
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
    if (codeLines === 0) return null;
    const from = parts.length - count;
    return {
      start: start + from,
      parts: parts.slice(from),
      skeletonParts: skeletonParts.slice(from),
      softBreaks: softBreaks.slice(from),
    };
  };

  const build = (
    unitParts: string[],
    unitSkeletons: string[],
    unitSoftBreaks: boolean[],
    hasCode: boolean,
  ): { text: string; skeleton: string; offsets: number[] } => {
    const offsets: number[] = [];
    let offset = 0;
    for (const part of unitParts) {
      offsets.push(offset);
      offset += part.length + 1;
    }
    const text = hasCode ? unitParts.join("\n") : "";
    let skeleton = "";
    if (hasCode) {
      for (let index = 0; index < unitSkeletons.length; index += 1) {
        skeleton += unitSkeletons[index] as string;
        if (index < unitSkeletons.length - 1) skeleton += unitSoftBreaks[index] ? " " : "\n";
      }
    }
    return { text, skeleton, offsets };
  };

  const flush = (): void => {
    if (parts.length === 0) return;
    const { text, skeleton, offsets } = build(parts, skeletonParts, softBreaks, sawCode);
    let unitHeaderEnd = 0;
    if (sawCode && declKind !== null) {
      if (!headerDone) unitHeaderEnd = text.length;
      else if (headerLine >= start && headerLine < start + parts.length) {
        unitHeaderEnd = Math.min(
          text.length,
          (offsets[headerLine - start] as number) + headerColumn,
        );
      }
    }
    result.push({
      start,
      text,
      offsets,
      declaration: PYTHON_DECLARATION.test(text),
      headerEnd: unitHeaderEnd,
      skeleton,
    });
    if (bridge !== null) {
      const contiguous = bridge.start + bridge.parts.length === start;
      if (!contiguous || declKind === "block") {
        emitBridge();
      } else {
        // Hypothesis: these lines continue the statement before the restart.
        bridge.softBreaks[bridge.softBreaks.length - 1] = true;
        for (let index = 0; index < parts.length; index += 1) {
          const part = sawCode ? (parts[index] as string) : "";
          bridge.parts.push(part);
          bridge.skeletonParts.push(sawCode ? (skeletonParts[index] as string) : "");
          bridge.softBreaks.push(true);
          if (part.length > 0) bridge.added += 1;
        }
        if (bridge.added >= MAX_LOGICAL_LINE_SPAN / 2) emitBridge();
      }
    }
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
    const tail = takeTail();
    const hadCode = sawCode;
    flush();
    if (tail !== null) {
      parts = tail.parts;
      skeletonParts = tail.skeletonParts;
      softBreaks = tail.softBreaks;
      start = lineIndex + 1 - tail.parts.length;
      sawCode = hadCode;
    }
  };

  const resetStatement = (): void => {
    depth = 0;
    continued = false;
    stack.length = 0;
    statementLines = 0;
    statementCut = false;
    declKind = null;
    headerDone = false;
    headerLine = -1;
  };

  const fallbackRegions: Array<{ from: number; to: number; reason: string }> = [];
  const fallbackLines = new Set<number>();
  const addFallback = (from: number, to: number, reason: string): void => {
    fallbackRegions.push({ from, to, reason });
    for (let index = from; index <= to; index += 1) {
      if (fallbackLines.has(index)) continue;
      fallbackLines.add(index);
      const code = stripPythonComment(lines[index] ?? "");
      if (code.trim().length === 0) continue;
      windows.push({
        start: index,
        text: code.slice(0, MAX_PATTERN_LINE_LENGTH),
        offsets: [0],
        declaration: false,
        headerEnd: 0,
        extra: true,
      });
      if (code.length > MAX_PATTERN_LINE_LENGTH) {
        for (const unit of windowUnits(index, code)) windows.push(unit);
      }
    }
  };

  // Independent check: a second scanner that knows nothing about string
  // prefixes or f-string replacement fields, only quotes, backslashes and
  // comments. When the two disagree at the end of a line about being inside a
  // triple-quoted string, one of them is wrong; the lines are then matched as
  // plain text as well, until they agree again.
  let plainQuote: string | null = null;
  let plainTriple = false;
  let disagreeStart = -1;
  const advancePlainScanner = (line: string): void => {
    let index = 0;
    let continuedString = false;
    while (index < line.length) {
      const ch = line[index] as string;
      if (plainQuote !== null) {
        if (ch === "\\") {
          if (index === line.length - 1) continuedString = true;
          index += 2;
        } else if (plainTriple ? line.startsWith(plainQuote.repeat(3), index) : ch === plainQuote) {
          index += plainTriple ? 3 : 1;
          plainQuote = null;
        } else {
          index += 1;
        }
        continue;
      }
      if (ch === "#") break;
      if (ch === '"' || ch === "'") {
        plainTriple = line.startsWith(ch.repeat(3), index);
        plainQuote = ch;
        index += plainTriple ? 3 : 1;
        continue;
      }
      index += 1;
    }
    if (plainQuote !== null && !plainTriple && !continuedString) plainQuote = null;
  };

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
    const line = lines[lineIndex] ?? "";
    advancePlainScanner(line);

    if (inTriple()) {
      tripleBodyLines += 1;
      if (looksLikePythonStatement(line)) tripleCodeLike += 1;
    } else if (isOpen()) {
      // Recovery: never let one mis-lexed line degrade the rest of the file.
      const restart =
        PYTHON_HARD_RESTART.test(line) ||
        (PYTHON_BLOCK_RESTART.test(line) &&
          /:\s*$/.test(stripPythonComment(line))) ||
        (statementLines >= SOFT_RESTART_AFTER_LINES && PYTHON_SOFT_RESTART.test(line));
      if (restart) {
        const tail = PYTHON_DECLARATION.test(line) ? null : takeTail();
        const bridging = bridge !== null;
        flush();
        resetStatement();
        if (!bridging && bridge === null && tail !== null) bridge = { ...tail, added: 0 };
      }
    }

    if (!isOpen()) {
      // A new statement starts on this line.
      statementLines = 0;
      statementStart = lineIndex;
      statementCut = false;
      headerDone = false;
      headerLine = -1;
      declKind = PYTHON_BLOCK_DECLARATION.test(line)
        ? "block"
        : PYTHON_DECLARATION.test(line)
          ? "import"
          : null;
    }
    if (parts.length === 0) start = lineIndex;

    for (const context of stack) {
      if (context.kind === "string") context.carried = true;
    }

    let code = "";
    let skeleton = "";
    let index = 0;
    continued = false;
    let stringContinued = false;
    const length = line.length;

    while (index < length) {
      const ch = line[index] as string;
      const top = stack[stack.length - 1];

      if (top?.kind === "string") {
        let taken = 1;
        let closes = false;
        if (ch === "\\") {
          if (index === length - 1) stringContinued = true;
          else taken = 2;
        } else if (top.triple ? line.startsWith(top.quote.repeat(3), index) : ch === top.quote) {
          closes = true;
          taken = top.triple ? 3 : 1;
        } else if (top.fstring && ch === "{") {
          if (line[index + 1] === "{") taken = 2;
          else stack.push({ kind: "field", depth: 0, spec: false });
        } else if (top.fstring && ch === "}" && line[index + 1] === "}") {
          taken = 2;
        }
        const chunk = line.slice(index, index + taken);
        index += taken;
        // The literal text of a triple-quoted string that was already open
        // when the line started is dropped (kept as blanks, so columns of the
        // rest of the line stay those of the physical line).
        const dropped = top.triple && top.carried;
        if (closes) {
          stack.pop();
          code += chunk;
          skeleton += stack.length === 0 ? chunk : " ".repeat(chunk.length);
        } else if (dropped) {
          code += " ".repeat(chunk.length);
          skeleton += " ".repeat(chunk.length);
        } else {
          code += chunk;
          skeleton += " ".repeat(chunk.length);
        }
        continue;
      }

      if (top?.kind === "field") {
        if (!top.spec && (ch === '"' || ch === "'")) {
          const triple = line.startsWith(ch.repeat(3), index);
          stack.push({
            kind: "string",
            quote: ch,
            triple,
            fstring: stringPrefixBefore(line, index).fstring,
            carried: false,
          });
          const taken = triple ? 3 : 1;
          code += line.slice(index, index + taken);
          skeleton += " ".repeat(taken);
          index += taken;
          continue;
        }
        if (ch === "(" || ch === "[" || ch === "{") {
          top.depth += 1;
        } else if (ch === ")" || ch === "]") {
          top.depth = Math.max(0, top.depth - 1);
        } else if (ch === "}") {
          if (top.depth > 0) top.depth -= 1;
          else stack.pop();
        } else if (ch === ":" && top.depth === 0) {
          top.spec = true;
        } else if (top.spec && (ch === '"' || ch === "'")) {
          // A quote in a format spec can only be the end of the string.
          const parent = stack[stack.length - 2];
          if (parent?.kind === "string" && !parent.triple && parent.quote === ch) {
            stack.pop();
            continue;
          }
        }
        // The code of a replacement field is code: it is always kept, also
        // inside a triple-quoted string whose text is dropped.
        if (!/\s/.test(ch)) sawCode = true;
        code += ch;
        skeleton += /\s/.test(ch) ? ch : SKELETON_FIELD;
        index += 1;
        continue;
      }

      // Plain code.
      if (ch === "#") break;
      if (ch === '"' || ch === "'") {
        const triple = line.startsWith(ch.repeat(3), index);
        stack.push({
          kind: "string",
          quote: ch,
          triple,
          fstring: stringPrefixBefore(line, index).fstring,
          carried: false,
        });
        const taken = triple ? 3 : 1;
        code += line.slice(index, index + taken);
        skeleton += line.slice(index, index + taken);
        index += taken;
        continue;
      }
      // String prefixes (r, b, f, u, t) directly before a quote are not code.
      const prefixLength = stringPrefixAt(line, index);
      if (prefixLength > 0) {
        code += line.slice(index, index + prefixLength);
        skeleton += line.slice(index, index + prefixLength);
        index += prefixLength;
        continue;
      }
      if (ch === "(" || ch === "[" || ch === "{") depth += 1;
      else if (ch === ")" || ch === "]" || ch === "}") depth = Math.max(0, depth - 1);
      else if (ch === "\\" && index === length - 1) continued = true;
      else if (depth === 0 && declKind !== null && !headerDone) {
        if ((declKind === "block" && ch === ":") || (declKind === "import" && ch === ";")) {
          headerDone = true;
          headerLine = lineIndex;
          headerColumn = code.length + 1;
        }
      }
      if (!/\s/.test(ch)) sawCode = true;
      code += ch;
      skeleton += ch;
      index += 1;
    }

    // A string that is not triple-quoted ends with its line unless the line
    // ends with a backslash inside it. Close whatever is left open, so a
    // construct this lexer does not understand costs one line at most.
    if (!stringContinued) {
      while (stack.length > 0) {
        const top = stack[stack.length - 1] as LexContext;
        if (top.kind === "string") {
          if (top.triple) break;
          stack.pop();
        } else {
          const parent = stack[stack.length - 2];
          if (parent && parent.kind === "string" && parent.triple) break;
          stack.pop();
        }
      }
    }

    // A line with no code left (blank, comment only, or all of it the text of
    // a carried string) contributes an empty part and does not count toward
    // the span of the statement.
    const isCodeLine = code.trim().length > 0;
    if (!isCodeLine) {
      code = "";
      skeleton = "";
    } else if (code.length > MAX_PATTERN_LINE_LENGTH) {
      // Measured after the comment is removed, so padding a comment does not
      // hide the code in front of it.
      overLong?.push(lineIndex);
      diagnostics?.overLong.push(lineIndex);
      for (const unit of windowUnits(lineIndex, code)) windows.push(unit);
      code = code.slice(0, MAX_PATTERN_LINE_LENGTH);
      skeleton = skeleton.slice(0, MAX_PATTERN_LINE_LENGTH);
      if (headerLine === lineIndex) headerColumn = Math.min(headerColumn, code.length);
    }
    parts.push(code);
    skeletonParts.push(skeleton);
    softBreaks.push(continued || stack.length > 0);
    if (isCodeLine) {
      statementLines += 1;
      unitCodeLines += 1;
      unitNewLength += code.length + 1;
    }

    // Track a triple-quoted string that stays open across lines.
    if (inTriple()) {
      if (tripleStart < 0) {
        tripleStart = lineIndex;
        tripleBodyLines = 0;
        tripleCodeLike = 0;
      }
    } else if (tripleStart >= 0) {
      if (
        tripleBodyLines > TRIPLE_FALLBACK_MIN_LINES &&
        tripleCodeLike >= TRIPLE_FALLBACK_MIN_CODE_LINES
      ) {
        addFallback(
          tripleStart,
          lineIndex,
          `a triple-quoted string of ${tripleBodyLines} lines contains ${tripleCodeLike} lines that look like statements`,
        );
      }
      tripleStart = -1;
    }

    const plainInTriple = plainQuote !== null && plainTriple;
    if (plainInTriple !== inTriple()) {
      if (disagreeStart < 0) disagreeStart = lineIndex;
    } else if (disagreeStart >= 0) {
      addFallback(
        disagreeStart,
        lineIndex,
        "two scans of the quotes disagree about a triple-quoted string",
      );
      disagreeStart = -1;
    }

    if (!isOpen()) {
      flush();
      declKind = null;
      headerDone = false;
      headerLine = -1;
      statementLines = 0;
    } else if (
      unitCodeLines >= MAX_LOGICAL_LINE_SPAN ||
      unitNewLength >= MAX_LOGICAL_LINE_LENGTH ||
      parts.length >= MAX_UNIT_PARTS
    ) {
      cut(lineIndex);
    }
  }

  // End of file in an inconsistent state: the lexer was wrong somewhere, or
  // the file is not valid Python. Either way, match the open region as plain
  // text as well.
  const endsOpen = isOpen();
  const last = lines.length - 1;
  flush();
  emitBridge();
  if (disagreeStart >= 0) {
    addFallback(
      disagreeStart,
      last,
      "two scans of the quotes disagree about a triple-quoted string",
    );
  }
  if (tripleStart >= 0) {
    addFallback(tripleStart, last, "the file ends inside a triple-quoted string");
  } else if (endsOpen && statementStart <= last) {
    addFallback(
      statementStart,
      last,
      "the file ends inside an open bracket, string or line continuation",
    );
  }
  if (diagnostics && fallbackRegions.length > 0) {
    // Overlapping regions are reported once, from the earliest line.
    fallbackRegions.sort((left, right) => left.from - right.from);
    for (const region of fallbackRegions) {
      const previous = diagnostics.fallbacks[diagnostics.fallbacks.length - 1];
      if (previous && region.from <= previous.to + 1) {
        previous.to = Math.max(previous.to, region.to);
      } else {
        diagnostics.fallbacks.push({ ...region });
      }
    }
  }
  for (const unit of windows) result.push(unit);
  return result;
}

/**
 * Turn the physical lines of a C# file into the text rules are matched
 * against. The units have the same shape as the Python ones
 * (`pythonLogicalLines`):
 *
 * - `//`, `///` and `/* ... *\/` comments (also across lines) are replaced by
 *   blanks, so columns stay those of the physical line; `//` inside a string
 *   is not a comment;
 * - string literals of every form (regular with escapes, character literals,
 *   verbatim `@"..."` with `""`, interpolated `$"..."`, `$@"..."` / `@$"..."`,
 *   raw `"""..."""` with any number of quotes and `$` / `$$` prefixes) are
 *   kept in `text`, so rules can read SQL text or connection strings, and
 *   blanked in `skeleton`, so `codeOnly` rules ignore them; the code in an
 *   interpolation hole is code (`SKELETON_FIELD` in the skeleton);
 * - a statement stays one unit while a `(` or `[` is open (not a `{`: a block
 *   body is a list of statements), while a string or interpolation hole spans
 *   lines, and across a line break next to a binary operator, `=`, `=>`, `.`
 *   or `?:` (`"..." +` at the end of a line, `.Where(...)` at the start of the
 *   next);
 * - preprocessor lines (`#if`, `#region`, ...) are not code; every branch of
 *   an `#if` starts from the bracket state at the `#if`.
 *
 * Like the Python lexer it FAILS OPEN: when the file ends inside a string, a
 * comment or an open `(` / `[`, when a closing bracket does not match the open
 * one, when a member declaration turns up inside an open `(`, when a regular
 * string is not closed at the end of its line, or when a long multi-line
 * string keeps looking like code, the region is added again as plain physical
 * lines and recorded in `diagnostics.fallbacks`. Statements longer than
 * `MAX_LOGICAL_LINE_SPAN` code lines or `MAX_LOGICAL_LINE_LENGTH` characters
 * are matched in overlapping windows (`diagnostics.cuts`), and lines longer
 * than `MAX_PATTERN_LINE_LENGTH` in windows (`overLong`). The lexer is one
 * pass over the characters.
 *
 * The lexer is the shared C-family lexer (`lexers/clike.ts`) with the C#
 * syntax; this wrapper keeps the original entry point.
 */
export function csharpLogicalLines(
  lines: string[],
  overLong?: number[],
  diagnostics?: LexDiagnostics,
): LogicalLine[] {
  return clikeLogicalLines(lines, "csharp", overLong, diagnostics);
}

/** A start tag that stays open longer than this many lines is treated as a lexer error. */
const MARKUP_MAX_TAG_LINES = 50;

/**
 * Units for XML configuration (`xml`) and Razor views (`razor`), which are
 * otherwise matched line by line:
 *
 * - XML: `<!-- ... -->` comments (also across lines) are blanked, and an
 *   element whose start tag spans several lines (`<compilation` on one line,
 *   `debug="true" />` on the next) is one unit, up to the `>` that closes the
 *   tag outside attribute quotes. `<![CDATA[ ... ]]>` content is text.
 * - Razor: `@* ... *@` comments (also across lines) are blanked; every
 *   physical line stays its own unit. HTML comments are not blanked: Razor
 *   code inside them still runs.
 *
 * Blanked text keeps its length, so columns are those of the physical line.
 * The lexer FAILS OPEN: when the file ends inside a comment or a start tag,
 * or a start tag stays open for more than `MARKUP_MAX_TAG_LINES` lines, the
 * region is added again as plain physical lines and recorded in
 * `diagnostics.fallbacks`.
 */
export function markupLogicalLines(
  lines: string[],
  language: "xml" | "razor",
  overLong?: number[],
  diagnostics?: LexDiagnostics,
): LogicalLine[] {
  const xml = language === "xml";
  const open = xml ? "<!--" : "@*";
  const close = xml ? "-->" : "*@";
  const result: LogicalLine[] = [];
  const windows: LogicalLine[] = [];
  const regions: Array<{ from: number; to: number; reason: string }> = [];
  let inComment = false;
  let commentStart = -1;
  let inCdata = false;
  let inTag = false;
  let tagQuote: string | null = null;
  let tagStart = -1;
  let parts: string[] = [];
  let start = 0;

  const flush = (): void => {
    if (parts.length === 0) return;
    const offsets: number[] = [];
    let offset = 0;
    for (const part of parts) {
      offsets.push(offset);
      offset += part.length + 1;
    }
    result.push({ start, text: parts.join("\n"), offsets, declaration: false, headerEnd: 0 });
    parts = [];
  };

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
    const line = lines[lineIndex] ?? "";
    if (parts.length === 0) start = lineIndex;
    let code = "";
    let index = 0;
    while (index < line.length) {
      if (inComment) {
        const end = line.indexOf(close, index);
        const stop = end < 0 ? line.length : end + close.length;
        code += " ".repeat(stop - index);
        index = stop;
        if (end >= 0) inComment = false;
        continue;
      }
      if (inCdata) {
        const end = line.indexOf("]]>", index);
        const stop = end < 0 ? line.length : end + 3;
        code += line.slice(index, stop);
        index = stop;
        if (end >= 0) inCdata = false;
        continue;
      }
      const ch = line[index] as string;
      if (inTag) {
        if (tagQuote !== null) {
          if (ch === tagQuote) tagQuote = null;
        } else if (ch === '"' || ch === "'") {
          tagQuote = ch;
        } else if (ch === ">") {
          inTag = false;
        }
        code += ch;
        index += 1;
        continue;
      }
      if (line.startsWith(open, index)) {
        inComment = true;
        commentStart = lineIndex;
        code += " ".repeat(open.length);
        index += open.length;
        continue;
      }
      if (xml && line.startsWith("<![CDATA[", index)) {
        inCdata = true;
        code += "<![CDATA[";
        index += 9;
        continue;
      }
      if (xml && ch === "<") {
        inTag = true;
        tagQuote = null;
        tagStart = lineIndex;
      }
      code += ch;
      index += 1;
    }
    if (code.length > MAX_PATTERN_LINE_LENGTH) {
      overLong?.push(lineIndex);
      diagnostics?.overLong.push(lineIndex);
      for (const unit of windowUnits(lineIndex, code)) windows.push(unit);
      code = code.slice(0, MAX_PATTERN_LINE_LENGTH);
    }
    parts.push(code);
    if (inTag && lineIndex - tagStart + 1 >= MARKUP_MAX_TAG_LINES) {
      // A quote or "<" was probably not what it seemed: recover.
      regions.push({ from: tagStart, to: lineIndex, reason: `a start tag stays open for ${MARKUP_MAX_TAG_LINES} lines` });
      inTag = false;
      tagQuote = null;
    }
    if (!inTag) flush();
  }
  flush();
  const last = lines.length - 1;
  if (inComment && commentStart >= 0) {
    regions.push({ from: commentStart, to: last, reason: "the file ends inside a comment" });
  }
  if (inTag && tagStart >= 0) {
    regions.push({ from: tagStart, to: last, reason: "the file ends inside a start tag" });
  }
  regions.sort((left, right) => left.from - right.from);
  const merged: Array<{ from: number; to: number; reason: string }> = [];
  for (const region of regions) {
    const previous = merged[merged.length - 1];
    if (previous && region.from <= previous.to + 1) previous.to = Math.max(previous.to, region.to);
    else merged.push({ ...region });
  }
  for (const region of merged) {
    diagnostics?.fallbacks.push({ ...region });
    for (let index = region.from; index <= region.to; index += 1) {
      const text = lines[index] ?? "";
      if (text.trim().length === 0) continue;
      windows.push({ start: index, text: text.slice(0, MAX_PATTERN_LINE_LENGTH), offsets: [0], declaration: false, headerEnd: 0, extra: true });
      if (text.length > MAX_PATTERN_LINE_LENGTH) {
        for (const unit of windowUnits(index, text)) windows.push(unit);
      }
    }
  }
  for (const unit of windows) result.push(unit);
  return result;
}

function plainLogicalLines(lines: string[], overLong: number[]): LogicalLine[] {
  const result: LogicalLine[] = [];
  const windows: LogicalLine[] = [];
  for (let index = 0; index < lines.length; index += 1) {
    const text = lines[index] as string;
    const tooLong = text.length > MAX_PATTERN_LINE_LENGTH;
    if (tooLong) {
      overLong.push(index);
      for (const unit of windowUnits(index, text)) windows.push(unit);
    }
    result.push({
      start: index,
      text: tooLong ? text.slice(0, MAX_PATTERN_LINE_LENGTH) : text,
      offsets: [0],
      declaration: false,
      headerEnd: 0,
    });
  }
  for (const unit of windows) result.push(unit);
  return result;
}

function physicalLineIndex(unit: LogicalLine, offset: number): number {
  let line = 0;
  for (let index = 0; index < unit.offsets.length; index += 1) {
    if ((unit.offsets[index] as number) <= offset) line = index;
  }
  return line;
}

/** Bracket depth before each character of a skeleton. */
function bracketDepths(skeleton: string): Int32Array {
  const depths = new Int32Array(skeleton.length + 1);
  let depth = 0;
  for (let index = 0; index < skeleton.length; index += 1) {
    depths[index] = depth;
    const ch = skeleton.charCodeAt(index);
    // ( [ {  and  ) ] }
    if (ch === 40 || ch === 91 || ch === 123) depth += 1;
    else if (ch === 41 || ch === 93 || ch === 125) depth -= 1;
  }
  depths[skeleton.length] = depth;
  return depths;
}

/**
 * The part of a logical line a match belongs to: the expression around the
 * match, from the previous line break, `;`, `,` or enclosing open bracket up
 * to the end of the call the match opens and then to the next line break, `;`,
 * `,` or enclosing close bracket. `notPattern` is tested against this span, and
 * hits of one rule group are merged when their spans overlap.
 *
 * Without a skeleton (languages without a lexer) the span is the whole unit,
 * which is one physical line. For a unit marked `lineSpan` (C-family
 * languages other than C#) it is the physical lines the match covers and the
 * expression around it.
 */
function matchSpan(
  unit: LogicalLine,
  depths: Int32Array | undefined,
  matchStart: number,
  matchEnd: number,
): { start: number; end: number } {
  const skeleton = unit.skeleton;
  if (skeleton === undefined || depths === undefined) {
    return { start: 0, end: unit.text.length };
  }
  const expression = expressionSpan(skeleton, depths, matchStart, matchEnd);
  if (unit.lineSpan === true) {
    // The physical lines of the match, widened to the expression around it
    // (a method chain on the following lines).
    const first = physicalLineIndex(unit, matchStart);
    const last = physicalLineIndex(unit, Math.max(matchStart, matchEnd - 1));
    const next = unit.offsets[last + 1];
    return {
      start: Math.min(unit.offsets[first] as number, expression.start),
      end: Math.max(next === undefined ? unit.text.length : next - 1, expression.end),
    };
  }
  return expression;
}

function expressionSpan(
  skeleton: string,
  depths: Int32Array,
  matchStart: number,
  matchEnd: number,
): { start: number; end: number } {
  const base = depths[matchStart] as number;
  let start = matchStart;
  while (start > 0) {
    const ch = skeleton[start - 1] as string;
    const depth = depths[start - 1] as number;
    if (ch === "\n" || ch === ";") break;
    if (depth === base && ch === ",") break;
    if (depth < base && (ch === "(" || ch === "[" || ch === "{")) break;
    start -= 1;
  }
  let end = Math.max(matchEnd, matchStart);
  while (end < skeleton.length) {
    const ch = skeleton[end] as string;
    const depth = depths[end] as number;
    if (depth < base) break;
    if (depth === base) {
      if (ch === "\n" || ch === ";" || ch === ",") break;
      if (ch === ")" || ch === "]" || ch === "}") break;
    }
    end += 1;
  }
  return { start, end };
}

/** Replace `[0, headerEnd)` with spaces, keeping line breaks and offsets. */
function maskHeader(text: string, headerEnd: number): string {
  return text.slice(0, headerEnd).replace(/[^\n]/g, " ") + text.slice(headerEnd);
}

/**
 * Column ranges of `line` that a `redactEvidence` rule match covers:
 *
 * - When the pattern defines a capture group named `secret`, that group (and
 *   nothing else; a group that did not take part masks nothing).
 * - Otherwise the contents of every string literal that opens at or after the
 *   column where the match starts.
 * - Otherwise the matched text itself, so a credential never reaches a report
 *   in clear text.
 */
export function secretRangesOfMatch(
  line: string,
  matchStart: number,
  matchEnd: number,
  secret?: { start: number; end: number } | "absent",
): RedactRange[] {
  if (secret === "absent") return [];
  if (secret) {
    if (secret.end <= secret.start) return [];
    // A group that starts right after an opening quote covers the whole
    // quoted value, even when the pattern stops at a special character.
    const quote = line[secret.start - 1];
    let end = secret.end;
    if (quote === '"' || quote === "'" || quote === "`") {
      let close = secret.start;
      while (close < line.length && line[close] !== quote) {
        if (line[close] === "\\") close += 1;
        close += 1;
      }
      if (close < line.length && close > end) end = close;
    }
    return [{ start: secret.start, end }];
  }
  const ranges: RedactRange[] = [];
  for (const literal of lexLiterals(line)) {
    if (literal.open >= matchStart && literal.contentEnd > literal.contentStart) {
      ranges.push({ start: literal.contentStart, end: literal.contentEnd });
    }
  }
  if (ranges.length === 0) {
    const end = Math.min(Math.max(matchEnd, matchStart), line.length);
    ranges.push({ start: matchStart, end, replacement: "[redacted]" });
  }
  return ranges;
}

/**
 * Evidence for a rule with `redactEvidence`: the line with the secret masked
 * (see `secretRangesOfMatch` for what is masked and `maskSecret` for how).
 */
export function redactEvidenceLine(
  line: string,
  matchStart: number,
  matchEnd: number,
  secret?: { start: number; end: number } | "absent",
): string {
  return redactLine(line, { ranges: secretRangesOfMatch(line, matchStart, matchEnd, secret) });
}

export interface SuppressedHit {
  ruleId: string;
  file: string;
  line: number;
  reason: string;
}

export interface RuleScanResult {
  hits: RuleHit[];
  /**
   * Hits that an inline `code-audit:ignore` comment suppressed. They are not
   * in `hits`; the scan reports them as suppressed findings.
   */
  suppressedHits: RuleHit[];
  suppressed: SuppressedHit[];
  warnings: string[];
  scannedFiles: number;
  /**
   * What `redactEvidence` rules matched: file -> 1-based line -> column ranges
   * of the physical line. Other engines mask the same ranges in their
   * evidence for that line.
   */
  redactions: Map<string, Map<number, RedactRange[]>>;
  /**
   * Rust `#[cfg(test)]` modules: file -> 1-based inclusive line ranges. The
   * scan treats a finding in one like a finding in a test path.
   */
  testRegions?: Map<string, Array<{ from: number; to: number }>>;
}

export interface RuleScanOptions {
  /** Wall-clock budget for one file, in milliseconds. */
  fileBudgetMs?: number;
  /**
   * Honour inline `code-audit:ignore` comments (default true). The comments
   * come from the audited repository; an audit that must see everything turns
   * this off.
   */
  inlineIgnore?: boolean;
}

interface HitPlacement {
  /** First physical line of the logical line the hit belongs to. */
  unitStart: number;
  spanStart: number;
  spanEnd: number;
}

function listLines(indexes: number[]): string {
  const unique = [...new Set(indexes)].sort((left, right) => left - right);
  const shown = unique.slice(0, 5).map((index) => String(index + 1));
  return `${shown.join(", ")}${unique.length > shown.length ? ", ..." : ""}`;
}

/**
 * True when the match at `offset` starts inside the text of a string literal
 * (not in the code of an f-string replacement field or interpolation hole).
 * Only a unit the Python or C-family lexer produced with a skeleton can say
 * so; for any other unit the answer is false, so nothing is ignored.
 */
function startsInStringLiteral(unit: LogicalLine, offset: number): boolean {
  const skeleton = unit.skeleton;
  if (skeleton === undefined || unit.extra) return false;
  const inText = unit.text[offset];
  if (inText === undefined || /\s/.test(inText)) return false;
  return skeleton[offset] === " ";
}

export function scanRules(
  files: InventoryFile[],
  ruleSet: RuleSet,
  options: RuleScanOptions = {},
): RuleScanResult {
  const hits: RuleHit[] = [];
  const suppressedHits: RuleHit[] = [];
  const placementOf = new Map<RuleHit, HitPlacement>();
  const suppressed: SuppressedHit[] = [];
  const warnings: string[] = [];
  const redactions = new Map<string, Map<number, RedactRange[]>>();
  const testRegions = new Map<string, Array<{ from: number; to: number }>>();
  let scannedFiles = 0;
  let slowFiles = 0;
  const fullBudget = options.fileBudgetMs ?? FILE_MATCH_BUDGET_MS;
  const inlineIgnore = options.inlineIgnore !== false;

  for (const file of files) {
    if (!file.scannable || file.language === "unknown") continue;

    const applicable = ruleSet.rules.filter((rule) => ruleMatchesFile(rule, file));
    if (applicable.length === 0) continue;

    let content: string;
    try {
      content = fs.readFileSync(file.absPath, "utf8");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      warnings.push(`cannot read ${file.relPath}: ${message}`);
      continue;
    }
    scannedFiles += 1;

    const lines = splitLines(content);
    const budget =
      slowFiles >= SLOW_FILES_BEFORE_REDUCED_BUDGET
        ? Math.min(fullBudget, REDUCED_FILE_MATCH_BUDGET_MS)
        : fullBudget;
    const deadline = performance.now() + budget;
    let outOfTime = false as boolean;
    let stoppedAt = 0;
    // The deadline above is checked between matches. A single match that does
    // not return (a custom rule with an exponential pattern) never reaches the
    // check, so the matching loops also run under a limit that interrupts
    // them. What was found before the interruption is kept.
    const hardDeadline = deadline + HARD_INTERRUPT_GRACE_MS;
    let interrupted = false as boolean;
    const guarded = <T>(work: () => T, whenInterrupted: T): T => {
      if (interrupted) return whenInterrupted;
      try {
        return runInterruptible(work, Math.max(1, hardDeadline - performance.now()));
      } catch (error) {
        if (!(error instanceof InterruptedError)) throw error;
        interrupted = true;
        return whenInterrupted;
      }
    };

    // File-level conditions are tested line by line. An over-long line is
    // tested in the same overlapping windows that rule matching uses (up to
    // MAX_LONG_LINE_MATCHED characters), so no single test scans more than
    // MAX_PATTERN_LINE_LENGTH characters. A window that starts inside the
    // line is prefixed with a character that is neither a line break nor a
    // blank, so `^` (and `^\s*key:`) cannot match in the middle of a line.
    // Only a line longer than MAX_LONG_LINE_MATCHED leaves text untested; a
    // filePattern then fails open, as before.
    let hasUntestedText = false;
    const anyLine = (pattern: RegExp): boolean => {
      for (const line of lines) {
        if (line.length > MAX_PATTERN_LINE_LENGTH) {
          if (pattern.test(line.slice(0, MAX_PATTERN_LINE_LENGTH))) return true;
          if (line.length > MAX_LONG_LINE_MATCHED) hasUntestedText = true;
          const limit = Math.min(line.length, MAX_LONG_LINE_MATCHED);
          const step = MAX_PATTERN_LINE_LENGTH / 2;
          for (let column = step; column < limit; column += step) {
            const window = line.slice(column, Math.min(limit, column + MAX_PATTERN_LINE_LENGTH));
            if (pattern.test(`\u0001${window}`)) return true;
          }
        } else if (pattern.test(line)) return true;
      }
      return false;
    };
    // Interrupted: fail open, every applicable rule stays.
    const fileRules = guarded(
      () =>
        applicable.filter((rule) => {
          if (rule.compiled.filePattern && !anyLine(rule.compiled.filePattern)) {
            // Fail open: the part of an over-long line beyond the matched
            // windows may hold what the rule requires.
            if (!hasUntestedText) return false;
          }
          if (rule.compiled.fileAbsentPattern && anyLine(rule.compiled.fileAbsentPattern)) {
            return false;
          }
          return true;
        }),
      applicable,
    );

    // Python and the C-family languages are matched on logical lines with
    // comments removed (see pythonLogicalLines and lexers/clike.ts).
    // Inline suppression reads the original physical line, or for the
    // C-family languages the comments on it (`extras.comments`).
    const overLong: number[] = [];
    const diagnostics = emptyLexDiagnostics();
    const extras: LexExtras = {};
    const units =
      file.language === "python"
        ? pythonLogicalLines(lines, overLong, diagnostics)
        : isClikeLanguage(file.language)
          ? clikeLogicalLines(lines, file.language, overLong, diagnostics, extras)
          : file.language === "xml" || file.language === "razor"
            ? markupLogicalLines(lines, file.language, overLong, diagnostics)
            : file.language === "dockerfile"
              ? dockerfileLogicalLines(lines, overLong, diagnostics)
              : plainLogicalLines(lines, overLong);
    const suppressionText = extras.comments;
    if (extras.testRegions && extras.testRegions.length > 0) {
      testRegions.set(
        file.relPath,
        extras.testRegions.map((region) => ({ from: region.from + 1, to: region.to + 1 })),
      );
    }
    if (overLong.length > 0) {
      const beyond = overLong.some(
        (index) => (lines[index] as string).length > MAX_LONG_LINE_MATCHED,
      );
      warnings.push(
        `${overLong.length} over-long line(s) (more than ${MAX_PATTERN_LINE_LENGTH} characters) in ${file.relPath} at line(s) ${listLines(overLong)}: matched in overlapping windows` +
          (beyond
            ? `; only the first ${MAX_LONG_LINE_MATCHED} characters of a line are matched`
            : ""),
      );
    }
    for (const fallback of diagnostics.fallbacks) {
      warnings.push(
        `${file.language} lexer fallback in ${file.relPath} from line ${fallback.from + 1} to line ${fallback.to + 1}: ${fallback.reason}; these lines were also matched as plain text`,
      );
    }
    if (diagnostics.cuts.length > 0) {
      warnings.push(
        `${diagnostics.cuts.length} statement(s) in ${file.relPath} are longer than ${MAX_LOGICAL_LINE_SPAN} code lines or ${MAX_LOGICAL_LINE_LENGTH} characters and were matched in overlapping windows (first at line ${(diagnostics.cuts[0] as number) + 1}); a call that spans more than one window can be missed`,
      );
    }
    if (fileRules.length === 0) continue;

    interface PendingHit {
      rule: LoadedRule;
      index: number;
      column: number;
      placement: HitPlacement;
      suppressedBy?: string;
    }
    const pending: PendingHit[] = [];
    // Zero-based line -> ranges matched by redactEvidence rules.
    const fileRedactions = new Map<number, RedactRange[]>();
    const addRedaction = (index: number, range: RedactRange): void => {
      const list = fileRedactions.get(index);
      if (list) list.push(range);
      else fileRedactions.set(index, [range]);
    };

    const cappedRules = new Set<string>();
    let cappedAt = -1;

    // Rules with `withinKeys` are matched against the parsed values of
    // those YAML keys, after the line loop. When the file cannot be parsed
    // the rules fail open: they are matched against every line instead.
    const keyValues = new Map<string, YamlKeyValue[] | undefined>();
    const keyValuesOf = (keys: readonly string[]): YamlKeyValue[] | undefined => {
      const cacheKey = keys.join("\u0000");
      if (keyValues.has(cacheKey)) return keyValues.get(cacheKey);
      const parsed = yamlKeyValues(content, keys);
      if (!parsed.ok) {
        warnings.push(
          `${file.relPath}: ${parsed.reason}; rules limited to the value of ${keys.map((key) => `${key}:`).join(" / ")} were matched against every line of the file instead`,
        );
      }
      const result = parsed.ok ? parsed.values : undefined;
      keyValues.set(cacheKey, result);
      return result;
    };
    const structuredRules = fileRules.filter(
      (rule) => rule.withinKeys !== undefined && keyValuesOf(rule.withinKeys) !== undefined,
    );
    const structured = new Set(structuredRules);

    // One hit per rule and physical line.
    const reported = new Set<string>();
    guarded(() => {
    for (const unit of units) {
      if (unit.text.trim().length === 0) continue;
      if (outOfTime || performance.now() > deadline) {
        outOfTime = true;
        stoppedAt = unit.start + 1;
        break;
      }
      const masked =
        unit.headerEnd > 0 ? maskHeader(unit.text, unit.headerEnd) : unit.text;
      const maskedIsBlank = unit.headerEnd > 0 && masked.trim().length === 0;
      let depths: Int32Array | undefined;
      const matchCap = MAX_MATCHES_PER_LINE * unit.offsets.length;
      let codeLines = 0;
      if (unit.skeleton !== undefined && !unit.extra && unit.offsets.length > WHOLE_UNIT_PATTERNS_MAX_LINES) {
        for (let part = 0; part < unit.offsets.length; part += 1) {
          const next = unit.offsets[part + 1] ?? unit.text.length + 1;
          if (next - (unit.offsets[part] as number) > 1) codeLines += 1;
        }
      }
      // A bridge joins statements on the guess that they are one: there, too,
      // secondary patterns must hold for the expression, not for the guess.
      const patternsPerSpan =
        codeLines > WHOLE_UNIT_PATTERNS_MAX_LINES || unit.bridge === true;

      for (const rule of fileRules) {
        if (maskedIsBlank && !rule.matchDeclarations) continue;
        if (structured.has(rule)) continue;
        let text = rule.matchDeclarations ? unit.text : masked;
        // Fail-open path of a `withinKeys` rule (the file could not be
        // parsed): every line is matched, with its expressions in the same
        // canonical form the structured path uses.
        if (rule.withinKeys && unit.column === undefined && unit.offsets.length === 1) {
          text = canonicalExpressionLine(lines, unit.start);
        }
        // Long units are where a careless pattern could be slow.
        if (text.length > 200 && performance.now() > deadline) {
          outOfTime = true;
          break;
        }

        const compiled = rule.compiled;
        const rest = compiled.patterns?.slice(1);
        if (rest && !rest.every((pattern) => pattern.test(text))) continue;
        const locator = compiled.locator;
        if (!locator) continue;
        locator.lastIndex = 0;
        let found = 0;
        let match: RegExpExecArray | null;
        while ((match = locator.exec(text)) !== null) {
          if (match[0].length === 0) locator.lastIndex += 1;
          found += 1;
          if (found > matchCap) {
            cappedRules.add(rule.id);
            if (cappedAt < 0) cappedAt = unit.start;
            break;
          }

          const matchStart = match.index;
          const matchEnd = match.index + match[0].length;
          if (rule.codeOnly && startsInStringLiteral(unit, matchStart)) continue;
          if (unit.skeleton !== undefined && depths === undefined) {
            depths = bracketDepths(unit.skeleton);
          }
          const span = matchSpan(unit, depths, matchStart, matchEnd);
          if (rest && patternsPerSpan) {
            const spanText = text.slice(span.start, span.end);
            if (!rest.every((pattern) => pattern.test(spanText))) continue;
          }
          if (
            compiled.notPattern !== undefined &&
            compiled.notPattern.test(text.slice(span.start, span.end))
          ) {
            continue;
          }

          const lineInUnit = physicalLineIndex(unit, matchStart);
          const index = unit.start + lineInUnit;
          const lineStart = unit.offsets[lineInUnit] as number;
          const columnBase = unit.column ?? 0;

          if (rule.redactEvidence) {
            // What the rule matched is masked on its line for every finding,
            // whichever rule or engine reports it. Unit text is aligned with
            // the physical line, so offsets are columns.
            let secretRange: [number, number] | undefined;
            if (compiled.hasSecretGroup) {
              secretRange = (
                match as RegExpExecArray & {
                  indices?: { groups?: Record<string, [number, number] | undefined> };
                }
              ).indices?.groups?.secret;
            }
            const lastLine = physicalLineIndex(unit, Math.max(matchStart, matchEnd - 1));
            for (let part = lineInUnit; part <= lastLine; part += 1) {
              const partStart = unit.offsets[part] as number;
              const nextStart = unit.offsets[part + 1];
              const partEnd = nextStart === undefined ? unit.text.length : nextStart - 1;
              const partText = unit.text.slice(partStart, partEnd);
              let secret: { start: number; end: number } | "absent" | undefined;
              if (compiled.hasSecretGroup) {
                secret =
                  secretRange && secretRange[1] > partStart && secretRange[0] <= partEnd
                    ? {
                        start: Math.max(secretRange[0], partStart) - partStart,
                        end: Math.min(secretRange[1], partEnd) - partStart,
                      }
                    : "absent";
              }
              const ranges = secretRangesOfMatch(
                partText,
                Math.max(matchStart, partStart) - partStart,
                Math.min(matchEnd, partEnd) - partStart,
                secret,
              );
              for (const range of ranges) {
                addRedaction(unit.start + part, {
                  ...range,
                  start: range.start + columnBase,
                  end: range.end + columnBase,
                });
              }
            }
          }

          const key = `${rule.id}\u0000${index}`;
          if (reported.has(key)) continue;
          reported.add(key);

          const hit: PendingHit = {
            rule,
            index,
            column: matchStart - lineStart + columnBase,
            placement: {
              unitStart: unit.start,
              spanStart: span.start,
              spanEnd: span.end,
            },
          };
          if (inlineIgnore) {
            const source = suppressionText ?? lines;
            const line = source[index] ?? "";
            let suppression = isSuppressed(line, source[index - 1], rule.id);
            if (!suppression.suppressed && unit.start !== index) {
              suppression = isSuppressed(
                source[unit.start] ?? "",
                source[unit.start - 1],
                rule.id,
              );
            }
            if (suppression.suppressed) hit.suppressedBy = suppression.reason;
          }
          pending.push(hit);
        }
      }
    }
    // Structured matching of `withinKeys` rules; see `yamlValues.ts`.
    for (const rule of structuredRules) {
      if (outOfTime) break;
      const values = keyValuesOf(rule.withinKeys as string[]) ?? [];
      const compiled = rule.compiled;
      const locator = compiled.locator;
      if (!locator) continue;
      const rest = compiled.patterns?.slice(1);
      for (let valueIndex = 0; valueIndex < values.length; valueIndex += 1) {
        const value = values[valueIndex] as YamlKeyValue;
        if (!(rule.withinKeys as string[]).includes(value.key)) continue;
        if (performance.now() > deadline) {
          outOfTime = true;
          break;
        }
        const text = value.text;
        if (rest && !rest.every((pattern) => pattern.test(text))) continue;
        locator.lastIndex = 0;
        let found = 0;
        let match: RegExpExecArray | null;
        while ((match = locator.exec(text)) !== null) {
          if (match[0].length === 0) locator.lastIndex += 1;
          found += 1;
          if (found > MAX_MATCHES_PER_LINE * 100) {
            cappedRules.add(rule.id);
            if (cappedAt < 0) cappedAt = value.lineAt(match.index);
            break;
          }
          const matchStart = match.index;
          const matchEnd = match.index + match[0].length;
          if (compiled.notPattern !== undefined) {
            const lineStart = text.lastIndexOf("\n", matchStart) + 1;
            const lineEnd = text.indexOf("\n", matchEnd);
            if (compiled.notPattern.test(text.slice(lineStart, lineEnd < 0 ? text.length : lineEnd))) {
              continue;
            }
          }
          const index = Math.min(value.lineAt(matchStart), Math.max(0, lines.length - 1));
          const key = `${rule.id}\u0000${index}`;
          if (reported.has(key)) continue;
          reported.add(key);
          const line = lines[index] ?? "";
          // Spans of different values never overlap; rules of one group that
          // match the same expression of one value do.
          const base = valueIndex * 0x1000000;
          const hit: PendingHit = {
            rule,
            index,
            column: Math.max(0, line.indexOf("${{")),
            placement: { unitStart: index, spanStart: base + matchStart, spanEnd: base + matchEnd },
          };
          if (inlineIgnore) {
            const suppression = isSuppressed(line, lines[index - 1], rule.id);
            if (suppression.suppressed) hit.suppressedBy = suppression.reason;
          }
          pending.push(hit);
        }
      }
    }
    }, undefined);
    if (interrupted) {
      slowFiles += 1;
      warnings.push(
        `rule matching of ${file.relPath} was interrupted after ${Math.round(budget + HARD_INTERRUPT_GRACE_MS)} ms: a pattern did not return (catastrophic backtracking); findings in the rest of the file are missing`,
      );
      outOfTime = false;
    }
    if (cappedRules.size > 0) {
      warnings.push(
        `${cappedRules.size} rule(s) matched more than ${MAX_MATCHES_PER_LINE} times per line in one statement of ${file.relPath} (first at line ${cappedAt + 1}); further matches in that statement were not recorded`,
      );
    }
    if (outOfTime) {
      slowFiles += 1;
      warnings.push(
        stoppedAt > 0
          ? `rule matching stopped at line ${stoppedAt} of ${file.relPath}: time budget of ${budget} ms exceeded`
          : `rule matching of ${file.relPath} exceeded the time budget of ${budget} ms; the last statement may be incomplete`,
      );
    }

    if (fileRedactions.size > 0) {
      const byLine = new Map<number, RedactRange[]>();
      for (const [index, ranges] of fileRedactions) byLine.set(index + 1, ranges);
      redactions.set(file.relPath, byLine);
    }
    if (pending.length === 0) continue;

    // Evidence is the physical line, redacted as a line: the secret that one
    // rule found is masked in the evidence of every other rule's hit too.
    const flags = sensitiveLines(lines);
    for (const item of pending) {
      const evidence =
        flags[item.index] === LINE_MASK_ALL
          ? "[private key content redacted]"
          : redactEvidence(lines[item.index] ?? "", {
              file: file.relPath,
              column: item.column,
              ranges: fileRedactions.get(item.index),
              maskAllStrings: flags[item.index] === LINE_MASK_STRINGS,
            });
      const hit: RuleHit = { rule: item.rule, file, line: item.index + 1, evidence };
      if (item.suppressedBy !== undefined) {
        const reason = redactLine(item.suppressedBy).slice(0, 200);
        hit.suppressedBy = reason;
        suppressedHits.push(hit);
        suppressed.push({
          ruleId: item.rule.id,
          file: file.relPath,
          line: item.index + 1,
          reason,
        });
        continue;
      }
      hits.push(hit);
      placementOf.set(hit, item.placement);
    }
  }

  // Rules of one group are deduplicated per expression: hits whose spans
  // overlap (for example a specific rule and its API-only fallback on the same
  // call, even when they match different lines of it) produce one result, the
  // one with the highest confidence and severity.
  interface Cluster {
    start: number;
    end: number;
    best: RuleHit;
  }
  const score = (hit: RuleHit): number =>
    CONFIDENCE_ORDER[hit.rule.confidence] * 10 + severityRank(hit.rule.severity);
  const clusters = new Map<string, Cluster[]>();
  for (const hit of hits) {
    if (!hit.rule.group) continue;
    const placement = placementOf.get(hit) as HitPlacement;
    const key = `${hit.file.relPath}\u0000${placement.unitStart}\u0000${hit.rule.group}`;
    let list = clusters.get(key);
    if (!list) {
      list = [];
      clusters.set(key, list);
    }
    let merged: Cluster = { start: placement.spanStart, end: placement.spanEnd, best: hit };
    const remaining: Cluster[] = [];
    for (const cluster of list) {
      // Empty spans cannot overlap by the strict test; treat touching as overlap.
      if (merged.start <= cluster.end && cluster.start <= merged.end) {
        merged = {
          start: Math.min(merged.start, cluster.start),
          end: Math.max(merged.end, cluster.end),
          best: score(merged.best) > score(cluster.best) ? merged.best : cluster.best,
        };
      } else {
        remaining.push(cluster);
      }
    }
    remaining.push(merged);
    clusters.set(key, remaining);
  }

  const winners = new Set<RuleHit>();
  for (const list of clusters.values()) {
    for (const cluster of list) winners.add(cluster.best);
  }
  const dedupedHits = hits.filter((hit) => !hit.rule.group || winners.has(hit));

  return { hits: dedupedHits, suppressedHits, suppressed, warnings, scannedFiles, redactions, testRegions };
}

/**
 * Column ranges that `redactEvidence` rules match in one file, by 1-based
 * line. Used by the tools that show source lines outside a scan (read, search,
 * agent-added findings) so they mask what the scan would mask.
 */
export function redactionsForFile(
  file: InventoryFile,
  ruleSet: RuleSet,
): Map<number, RedactRange[]> {
  const rules = ruleSet.rules.filter((rule) => rule.redactEvidence);
  if (rules.length === 0) return new Map();
  const result = scanRules([file], { ...ruleSet, rules }, { inlineIgnore: false, fileBudgetMs: 2000 });
  return result.redactions.get(file.relPath) ?? new Map();
}

function severityRank(severity: Severity): number {
  switch (severity) {
    case "critical":
      return 5;
    case "high":
      return 4;
    case "medium":
      return 3;
    case "low":
      return 2;
    default:
      return 1;
  }
}

export interface LocalizedRuleText {
  title: string;
  message: string;
  remediation: string;
}

/**
 * Pick the requested language for rule text, falling back to English when a
 * translation is missing.
 */
export function localizeRule(
  rule: Pick<
    LoadedRule,
    "title" | "title_zh" | "message" | "message_zh" | "remediation" | "remediation_zh"
  >,
  lang: "en" | "zh",
): LocalizedRuleText {
  if (lang === "zh") {
    return {
      title: rule.title_zh ?? rule.title,
      message: rule.message_zh ?? rule.message,
      remediation: rule.remediation_zh ?? rule.remediation,
    };
  }
  return {
    title: rule.title,
    message: rule.message,
    remediation: rule.remediation,
  };
}
