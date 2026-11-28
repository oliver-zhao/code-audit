/**
 * Tool and parameter descriptions of MCP servers, for rules with
 * `withinMcpDescriptions` (JavaScript, TypeScript, Python).
 *
 * A description is text the model reads and the user rarely sees:
 *
 * - JavaScript / TypeScript: every string argument of a `.tool(`,
 *   `registerTool(` or `.describe(` call (zod parameter descriptions), and
 *   the value of a `description` property (`description: "..."`), which
 *   also covers tools defined in their own module (`{ description,
 *   inputSchema }`);
 * - Python: the docstring of a function decorated with `@<name>.tool` or
 *   `@tool`, and the value of a `description=` keyword argument or a
 *   `"description":` key.
 *
 * Comments and other strings are never descriptions. Escape sequences are
 * decoded (`\u200b`, `\u{202e}`, `\x20`, `\N` is left as written), because
 * the model receives the decoded text, and string literals joined with `+`
 * (or written next to each other in Python) are one description. Each
 * character keeps the source offset it came from, so a hit is reported at the
 * line where that part of the description is written.
 *
 * The reader is a small tokenizer, not a parser: it fails soft (an
 * unterminated string ends at the line break) and never throws.
 */
import type { YamlKeyValue } from "./yamlValues.js";

/** The file is an MCP server or tool module: an SDK import or a registration form (case-sensitive). */
const APPLICABLE =
  /@modelcontextprotocol\/sdk|\bfrom\s+mcp(?:\.server(?:\.\w+)*)?\s+import\b|\bimport\s+mcp\b|\bFastMCP\b|\.tool\s*\(|\bregisterTool\s*\(|\.describe\s*\(|@\w+(?:\.\w+)*\.tool\b|@tool\b/;

/** Upper bound of the text examined (descriptions are short; a hostile file is not). */
const MAX_FILE = 2 * 1024 * 1024;

interface StringToken {
  kind: "string";
  value: string;
  /** Source offset of each character of `value`. */
  source: number[];
  start: number;
}
interface OtherToken {
  kind: "id" | "punct";
  text: string;
  start: number;
}
type Token = StringToken | OtherToken;

function hexValue(text: string): number | undefined {
  if (!/^[0-9A-Fa-f]+$/.test(text)) return undefined;
  const value = Number.parseInt(text, 16);
  return value <= 0x10ffff ? value : undefined;
}

/**
 * Decode one escape at `content[at] === "\\"`. Returns the text and the index
 * after the escape.
 */
function decodeEscape(content: string, at: number, python: boolean): { text: string; next: number } {
  const c = content[at + 1] ?? "";
  const simple: Record<string, string> = { n: "\n", t: "\t", r: "\r", b: "\b", f: "\f", v: "\v", "0": "\0" };
  if (c === "\n") return { text: "", next: at + 2 };
  if (c === "\r") return { text: "", next: content[at + 2] === "\n" ? at + 3 : at + 2 };
  if (c === "x") {
    const value = hexValue(content.slice(at + 2, at + 4));
    if (value !== undefined) return { text: String.fromCodePoint(value), next: at + 4 };
  }
  if (c === "u") {
    if (!python && content[at + 2] === "{") {
      const close = content.indexOf("}", at + 3);
      if (close > at && close - at < 12) {
        const value = hexValue(content.slice(at + 3, close));
        if (value !== undefined) return { text: String.fromCodePoint(value), next: close + 1 };
      }
    }
    const value = hexValue(content.slice(at + 2, at + 6));
    if (value !== undefined && content.slice(at + 2, at + 6).length === 4) {
      return { text: String.fromCharCode(value), next: at + 6 };
    }
  }
  if (python && c === "U") {
    const value = hexValue(content.slice(at + 2, at + 10));
    if (value !== undefined && content.slice(at + 2, at + 10).length === 8) {
      return { text: String.fromCodePoint(value), next: at + 10 };
    }
  }
  if (c === "0" && python && /[0-7]/.test(content[at + 2] ?? "")) {
    const digits = /^[0-7]{1,3}/.exec(content.slice(at + 1)) as RegExpExecArray;
    return { text: String.fromCharCode(Number.parseInt(digits[0], 8)), next: at + 1 + digits[0].length };
  }
  if (c in simple) return { text: simple[c] as string, next: at + 2 };
  if (python && !"\\'\"abfnrtv".includes(c)) return { text: `\\${c}`, next: at + 2 };
  return { text: c, next: at + 2 };
}

/** Read a quoted string starting at `at` (the opening quote). */
function readString(
  content: string,
  at: number,
  quote: string,
  options: { python: boolean; raw: boolean; triple: boolean },
): { token: StringToken; next: number } {
  const token: StringToken = { kind: "string", value: "", source: [], start: at };
  let index = at + (options.triple ? 3 : 1);
  const push = (text: string, offset: number): void => {
    for (const ch of text) {
      token.value += ch;
      for (let unit = 0; unit < ch.length; unit += 1) token.source.push(offset);
    }
  };
  while (index < content.length) {
    const ch = content[index] as string;
    if (options.triple ? content.startsWith(quote.repeat(3), index) : ch === quote) {
      return { token, next: index + (options.triple ? 3 : 1) };
    }
    if (!options.triple && quote !== "`" && (ch === "\n" || ch === "\r")) return { token, next: index };
    if (ch === "\\" && !options.raw) {
      const escape = decodeEscape(content, index, options.python);
      push(escape.text, index);
      index = escape.next;
      continue;
    }
    if (quote === "`" && ch === "$" && content[index + 1] === "{") {
      // Skip the expression; nested braces and simple strings are balanced.
      let depth = 1;
      index += 2;
      while (index < content.length && depth > 0) {
        const inner = content[index] as string;
        if (inner === "{") depth += 1;
        else if (inner === "}") depth -= 1;
        else if (inner === '"' || inner === "'") {
          const close = content.indexOf(inner, index + 1);
          if (close > 0) index = close;
        }
        index += 1;
      }
      push(" ", index - 1);
      continue;
    }
    push(ch, index);
    index += ch.length;
  }
  return { token, next: index };
}

const REGEX_BEFORE = new Set([
  "(", ",", "=", ":", "[", "!", "&", "|", "?", "{", "}", ";", "+", "-", "*", "%", "<", ">", "~", "^",
]);
const REGEX_AFTER_WORD = new Set(["return", "typeof", "case", "do", "else", "in", "of", "new", "delete", "void", "throw", "yield", "await"]);

function tokenizeJs(content: string): Token[] {
  const tokens: Token[] = [];
  let index = 0;
  const last = (): Token | undefined => tokens[tokens.length - 1];
  while (index < content.length) {
    const ch = content[index] as string;
    if (/\s/.test(ch)) {
      index += 1;
      continue;
    }
    if (ch === "/" && content[index + 1] === "/") {
      const end = content.indexOf("\n", index);
      index = end < 0 ? content.length : end;
      continue;
    }
    if (ch === "/" && content[index + 1] === "*") {
      const end = content.indexOf("*/", index + 2);
      index = end < 0 ? content.length : end + 2;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      const read = readString(content, index, ch, { python: false, raw: false, triple: false });
      tokens.push(read.token);
      index = read.next;
      continue;
    }
    if (ch === "/") {
      const previous = last();
      const regex =
        previous === undefined ||
        (previous.kind === "punct" && REGEX_BEFORE.has(previous.text)) ||
        (previous.kind === "id" && REGEX_AFTER_WORD.has(previous.text));
      if (regex) {
        let inClass = false;
        index += 1;
        while (index < content.length && content[index] !== "\n") {
          const inner = content[index] as string;
          if (inner === "\\") index += 1;
          else if (inner === "[") inClass = true;
          else if (inner === "]") inClass = false;
          else if (inner === "/" && !inClass) break;
          index += 1;
        }
        index += 1;
        continue;
      }
    }
    const word = /^[A-Za-z_$][\w$]*/.exec(content.slice(index, index + 200));
    if (word) {
      tokens.push({ kind: "id", text: word[0], start: index });
      index += word[0].length;
      continue;
    }
    const number = /^[0-9][\w.]*/.exec(content.slice(index, index + 100));
    if (number) {
      index += number[0].length;
      continue;
    }
    tokens.push({ kind: "punct", text: ch, start: index });
    index += 1;
  }
  return tokens;
}

function tokenizePython(content: string): Token[] {
  const tokens: Token[] = [];
  let index = 0;
  while (index < content.length) {
    const ch = content[index] as string;
    if (/\s/.test(ch)) {
      index += 1;
      continue;
    }
    if (ch === "#") {
      const end = content.indexOf("\n", index);
      index = end < 0 ? content.length : end;
      continue;
    }
    const prefix = /^([rRbBuUfF]{0,2})(['"])/.exec(content.slice(index, index + 4));
    if (prefix && (prefix[1] === "" || !/[\w]/.test(content[index - 1] ?? ""))) {
      const quote = prefix[2] as string;
      const quoteAt = index + (prefix[1] as string).length;
      const triple = content.startsWith(quote.repeat(3), quoteAt);
      const read = readString(content, quoteAt, quote, {
        python: true,
        raw: /[rR]/.test(prefix[1] as string),
        triple,
      });
      read.token.start = index;
      tokens.push(read.token);
      index = read.next;
      continue;
    }
    const word = /^[A-Za-z_]\w*/.exec(content.slice(index, index + 200));
    if (word) {
      tokens.push({ kind: "id", text: word[0], start: index });
      index += word[0].length;
      continue;
    }
    const number = /^[0-9][\w.]*/.exec(content.slice(index, index + 100));
    if (number) {
      index += number[0].length;
      continue;
    }
    tokens.push({ kind: "punct", text: ch, start: index });
    index += 1;
  }
  return tokens;
}

/** The string expression starting at token `at`: strings joined by `+` (and, in Python, by juxtaposition). */
function stringExpression(tokens: Token[], at: number, python: boolean): { parts: StringToken[]; next: number } {
  const parts: StringToken[] = [];
  let index = at;
  while (index < tokens.length) {
    const token = tokens[index] as Token;
    if (token.kind !== "string") break;
    parts.push(token);
    index += 1;
    const next = tokens[index];
    if (next?.kind === "punct" && next.text === "+" && tokens[index + 1]?.kind === "string") {
      index += 1;
      continue;
    }
    if (python && next?.kind === "string") continue;
    break;
  }
  return { parts, next: index };
}

function lineStarts(content: string): number[] {
  const starts = [0];
  for (let index = 0; index < content.length; index += 1) {
    const ch = content.charCodeAt(index);
    if (ch === 10) starts.push(index + 1);
    else if (ch === 13 && content.charCodeAt(index + 1) !== 10) starts.push(index + 1);
  }
  return starts;
}

function lineOf(starts: number[], offset: number): number {
  let low = 0;
  let high = starts.length - 1;
  while (low < high) {
    const middle = (low + high + 1) >> 1;
    if ((starts[middle] as number) <= offset) low = middle;
    else high = middle - 1;
  }
  return low;
}

export interface McpDescriptionsResult {
  /** The file has an SDK import or a registration form. */
  applicable: boolean;
  values: YamlKeyValue[];
}

/** Descriptions of an MCP server or tool module (see the file comment). */
export function mcpDescriptionValues(content: string, language: string): McpDescriptionsResult {
  const text = content.length > MAX_FILE ? content.slice(0, MAX_FILE) : content;
  if (!APPLICABLE.test(text)) return { applicable: false, values: [] };
  const python = language === "python";
  const tokens = python ? tokenizePython(text) : tokenizeJs(text);
  const starts = lineStarts(text);
  const values: YamlKeyValue[] = [];
  const seen = new Set<number>();
  const emit = (parts: StringToken[]): void => {
    if (parts.length === 0 || seen.has(parts[0]?.start as number)) return;
    seen.add(parts[0]?.start as number);
    let value = "";
    const source: number[] = [];
    for (const part of parts) {
      value += part.value;
      source.push(...part.source);
    }
    if (value.length === 0) return;
    const fallbackLine = lineOf(starts, parts[0]?.start as number);
    values.push({
      key: "description",
      text: value,
      lineAt: (offset) => {
        const at = source[Math.min(offset, source.length - 1)];
        return at === undefined ? fallbackLine : lineOf(starts, at);
      },
    });
  };
  const isPunct = (token: Token | undefined, punct: string): boolean => token?.kind === "punct" && token.text === punct;
  const isId = (token: Token | undefined, id: string): boolean => token?.kind === "id" && token.text === id;

  // `description: "..."`, `description = "..."`, `"description": "..."`.
  for (let index = 0; index + 2 < tokens.length; index += 1) {
    const token = tokens[index] as Token;
    const named =
      (token.kind === "id" && token.text === "description") ||
      (token.kind === "string" && token.value === "description");
    if (!named) continue;
    const separator = tokens[index + 1];
    if (!isPunct(separator, ":") && !isPunct(separator, "=")) continue;
    if (isPunct(separator, "=") && isPunct(tokens[index + 2], "=")) continue;
    emit(stringExpression(tokens, index + 2, python).parts);
  }

  {
    // String arguments of .tool( / registerTool( / .describe( calls (in
    // Python also add_tool( and the arguments of a @x.tool(...) decorator,
    // such as name= and description=).
    const stack: Array<{ open: string; description: boolean }> = [];
    for (let index = 0; index < tokens.length; index += 1) {
      const token = tokens[index] as Token;
      if (token.kind === "punct" && "([{".includes(token.text)) {
        const callee = tokens[index - 1];
        const description =
          token.text === "(" &&
          callee?.kind === "id" &&
          (callee.text === "registerTool" ||
            (python && callee.text === "add_tool") ||
            ((callee.text === "tool" || callee.text === "describe") && isPunct(tokens[index - 2], ".")));
        stack.push({ open: token.text, description });
        continue;
      }
      if (token.kind === "punct" && ")]}".includes(token.text)) {
        stack.pop();
        continue;
      }
      if (token.kind === "string" && stack[stack.length - 1]?.description) {
        const expression = stringExpression(tokens, index, python);
        emit(expression.parts);
        index = expression.next - 1;
      }
    }
  }
  if (python) {
    // Docstrings of functions decorated with @<x>.tool / @tool.
    let toolDecorator = false;
    for (let index = 0; index < tokens.length; index += 1) {
      const token = tokens[index] as Token;
      if (isPunct(token, "@")) {
        let at = index + 1;
        let lastName = "";
        while (tokens[at]?.kind === "id") {
          lastName = (tokens[at] as OtherToken).text;
          if (isPunct(tokens[at + 1], ".")) at += 2;
          else break;
        }
        if (lastName === "tool") toolDecorator = true;
        continue;
      }
      if (isId(token, "def") && toolDecorator) {
        toolDecorator = false;
        let depth = 0;
        let at = index + 1;
        for (; at < tokens.length; at += 1) {
          const inner = tokens[at] as Token;
          if (inner.kind !== "punct") continue;
          if ("([{".includes(inner.text)) depth += 1;
          else if (")]}".includes(inner.text)) depth -= 1;
          else if (inner.text === ":" && depth === 0) break;
        }
        if (tokens[at + 1]?.kind === "string") emit(stringExpression(tokens, at + 1, true).parts);
        continue;
      }
      if (isId(token, "class")) toolDecorator = false;
    }
  }
  return { applicable: true, values };
}
