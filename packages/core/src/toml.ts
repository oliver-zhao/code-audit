/**
 * A deliberately small TOML reader.
 *
 * It is not a complete TOML implementation. It understands the subset used by
 * the Python lockfiles this project parses: tables (`[a.b]`), arrays of tables
 * (`[[package]]`), bare and quoted keys, basic and literal strings (including
 * multi-line strings), integers, floats, booleans, arrays (which may span
 * several lines) and inline tables (`source = { registry = "..." }`).
 *
 * Anything it cannot read throws; callers turn that into a warning instead of
 * failing the scan. Dates, times and exotic number formats are returned as
 * strings rather than rejected.
 */

export interface TomlTable {
  [key: string]: TomlValue;
}

export type TomlValue = string | number | boolean | TomlValue[] | TomlTable;

export interface TomlParseResult {
  data: TomlTable;
  error?: string;
  /**
   * 1-based line of the `[table]` / `[[array-of-tables]]` header that opened
   * the given table, when the table came from a header.
   */
  lineOf(table: TomlTable): number | undefined;
}

/** Nesting limit for arrays and inline tables; deeper input is rejected. */
const MAX_DEPTH = 64;

/**
 * Tables have no prototype, so keys such as `__proto__`, `constructor` or
 * `toString` are ordinary data and can never reach `Object.prototype`.
 */
function newTable(): TomlTable {
  return Object.create(null) as TomlTable;
}

const NUMBER_PATTERN = /^[+-]?(?:\d[\d_]*)(?:\.\d[\d_]*)?(?:[eE][+-]?\d[\d_]*)?$/;

class TomlError extends Error {}

class Parser {
  private pos = 0;
  private depth = 0;
  private lineStarts: number[] | undefined;
  readonly headerLines = new Map<TomlTable, number>();

  constructor(private readonly input: string) {}

  /** 1-based line number of an offset (binary search over line starts). */
  private lineAtOffset(offset: number): number {
    if (!this.lineStarts) {
      const starts = [0];
      for (let i = this.input.indexOf("\n"); i >= 0; i = this.input.indexOf("\n", i + 1)) {
        starts.push(i + 1);
      }
      this.lineStarts = starts;
    }
    const starts = this.lineStarts;
    let low = 0;
    let high = starts.length - 1;
    while (low < high) {
      const mid = (low + high + 1) >> 1;
      if ((starts[mid] as number) <= offset) low = mid;
      else high = mid - 1;
    }
    return low + 1;
  }

  parse(): TomlTable {
    const root: TomlTable = newTable();
    let current = root;
    for (;;) {
      this.skipDocumentSpace();
      if (this.pos >= this.input.length) break;
      if (this.input.startsWith("[[", this.pos)) {
        current = this.parseArrayHeader(root);
      } else if (this.input[this.pos] === "[") {
        current = this.parseTableHeader(root);
      } else {
        this.parseKeyValue(current);
      }
    }
    return root;
  }

  private fail(message: string): never {
    throw new TomlError(`${message} at line ${this.lineAtOffset(this.pos)}`);
  }

  private peek(offset = 0): string {
    return this.input[this.pos + offset] ?? "";
  }

  private skipInlineSpace(): void {
    while (this.pos < this.input.length) {
      const ch = this.input[this.pos];
      if (ch === " " || ch === "\t" || ch === "\r") this.pos += 1;
      else break;
    }
  }

  private skipComment(): void {
    if (this.input[this.pos] === "#") {
      while (this.pos < this.input.length && this.input[this.pos] !== "\n") {
        this.pos += 1;
      }
    }
  }

  /** Whitespace, newlines and comments allowed between statements. */
  private skipDocumentSpace(): void {
    for (;;) {
      const ch = this.input[this.pos];
      if (ch === " " || ch === "\t" || ch === "\r" || ch === "\n") {
        this.pos += 1;
        continue;
      }
      if (ch === "#") {
        this.skipComment();
        continue;
      }
      break;
    }
  }

  /** Whitespace, newlines and comments allowed inside arrays. */
  private skipArraySpace(): void {
    this.skipDocumentSpace();
  }

  private parseKeyPart(): string {
    const ch = this.peek();
    if (ch === '"') return this.parseBasicString();
    if (ch === "'") return this.parseLiteralString();
    const start = this.pos;
    while (this.pos < this.input.length && /[A-Za-z0-9_-]/.test(this.input[this.pos] ?? "")) {
      this.pos += 1;
    }
    if (start === this.pos) this.fail("expected a key");
    return this.input.slice(start, this.pos);
  }

  private parseKeyPath(): string[] {
    const parts: string[] = [];
    for (;;) {
      this.skipInlineSpace();
      parts.push(this.parseKeyPart());
      this.skipInlineSpace();
      if (this.peek() === ".") {
        this.pos += 1;
        continue;
      }
      break;
    }
    return parts;
  }

  private parseBasicString(): string {
    if (this.input.startsWith('"""', this.pos)) {
      this.pos += 3;
      // A newline directly after the opening delimiter is trimmed.
      if (this.input[this.pos] === "\r") this.pos += 1;
      if (this.input[this.pos] === "\n") this.pos += 1;
      let text = "";
      for (;;) {
        const ch = this.input[this.pos];
        if (ch === undefined) this.fail("unterminated multi-line string");
        if (ch === '"' && this.input.startsWith('"""', this.pos)) {
          this.pos += 3;
          // Up to two extra quotes may sit directly before the delimiter.
          while (this.input[this.pos] === '"') {
            text += '"';
            this.pos += 1;
          }
          return text;
        }
        if (ch === "\\") {
          const next = this.input[this.pos + 1];
          if (next === "\n" || next === "\r" || next === " " || next === "\t") {
            // Line-ending backslash: skip it and all following whitespace.
            let probe = this.pos + 1;
            while (/[ \t]/.test(this.input[probe] ?? "")) probe += 1;
            if (this.input[probe] === "\r") probe += 1;
            if (this.input[probe] === "\n") {
              while (/[ \t\r\n]/.test(this.input[probe] ?? "")) probe += 1;
              this.pos = probe;
              continue;
            }
          }
          text += this.parseEscape();
          continue;
        }
        text += ch;
        this.pos += 1;
      }
    }
    this.pos += 1; // opening quote
    let result = "";
    for (;;) {
      const ch = this.input[this.pos];
      if (ch === undefined || ch === "\n") this.fail("unterminated string");
      if (ch === '"') {
        this.pos += 1;
        return result;
      }
      if (ch === "\\") {
        result += this.parseEscape();
        continue;
      }
      result += ch;
      this.pos += 1;
    }
  }

  /** Parse one backslash escape starting at the backslash. */
  private parseEscape(): string {
    this.pos += 1;
    const esc = this.input[this.pos];
    if (esc === undefined) this.fail("unterminated escape");
    const escapes: Record<string, string> = {
      n: "\n",
      t: "\t",
      r: "\r",
      '"': '"',
      "\\": "\\",
      b: "\b",
      f: "\f",
      e: "\u001b",
    };
    if (esc === "u" || esc === "U" || esc === "x") {
      const width = esc === "u" ? 4 : esc === "U" ? 8 : 2;
      const hex = this.input.slice(this.pos + 1, this.pos + 1 + width);
      const code = hex.length === width && /^[0-9A-Fa-f]+$/.test(hex) ? parseInt(hex, 16) : -1;
      if (code < 0 || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) {
        this.fail(`invalid \\${esc} escape`);
      }
      this.pos += 1 + width;
      return String.fromCodePoint(code);
    }
    this.pos += 1;
    return escapes[esc] ?? esc;
  }

  private parseLiteralString(): string {
    if (this.input.startsWith("'''", this.pos)) {
      this.pos += 3;
      const end = this.input.indexOf("'''", this.pos);
      if (end < 0) this.fail("unterminated multi-line literal string");
      let raw = this.input.slice(this.pos, end);
      if (raw.startsWith("\r\n")) raw = raw.slice(2);
      else if (raw.startsWith("\n")) raw = raw.slice(1);
      this.pos = end + 3;
      return raw;
    }
    this.pos += 1;
    const end = this.input.indexOf("'", this.pos);
    if (end < 0 || this.input.slice(this.pos, end).includes("\n")) {
      this.fail("unterminated literal string");
    }
    const raw = this.input.slice(this.pos, end);
    this.pos = end + 1;
    return raw;
  }

  private parseValue(): TomlValue {
    this.skipArraySpace();
    const ch = this.peek();
    if (ch === '"') return this.parseBasicString();
    if (ch === "'") return this.parseLiteralString();
    if (ch === "[" || ch === "{") {
      if (this.depth >= MAX_DEPTH) this.fail("value is nested too deeply");
      this.depth += 1;
      const nested = ch === "[" ? this.parseArray() : this.parseInlineTable();
      this.depth -= 1;
      return nested;
    }
    const start = this.pos;
    while (this.pos < this.input.length && !/[\s,\]}\n#]/.test(this.input[this.pos] ?? "")) {
      this.pos += 1;
    }
    let token = this.input.slice(start, this.pos);
    if (token.length === 0) this.fail("expected a value");
    if (token === "true") return true;
    if (token === "false") return false;
    // RFC 3339 allows a space between date and time: `1979-05-27 07:32:00Z`.
    if (
      /^\d{4}-\d{2}-\d{2}$/.test(token) &&
      this.input[this.pos] === " " &&
      /^\d{2}:\d{2}/.test(this.input.slice(this.pos + 1, this.pos + 6))
    ) {
      this.pos += 1;
      const timeStart = this.pos;
      while (this.pos < this.input.length && !/[\s,\]}\n#]/.test(this.input[this.pos] ?? "")) {
        this.pos += 1;
      }
      token = `${token} ${this.input.slice(timeStart, this.pos)}`;
    }
    if (NUMBER_PATTERN.test(token)) return Number(token.replace(/_/g, ""));
    return token;
  }

  private parseArray(): TomlValue[] {
    this.pos += 1; // [
    const result: TomlValue[] = [];
    for (;;) {
      this.skipArraySpace();
      if (this.pos >= this.input.length) this.fail("unterminated array");
      if (this.peek() === "]") {
        this.pos += 1;
        return result;
      }
      result.push(this.parseValue());
      this.skipArraySpace();
      const ch = this.peek();
      if (ch === ",") {
        this.pos += 1;
        continue;
      }
      if (ch === "]") {
        this.pos += 1;
        return result;
      }
      this.fail("expected ',' or ']' in array");
    }
  }

  private parseInlineTable(): TomlTable {
    this.pos += 1; // {
    const result: TomlTable = newTable();
    // TOML 1.1 allows newlines, comments and a trailing comma in inline tables.
    for (;;) {
      this.skipDocumentSpace();
      if (this.pos >= this.input.length) this.fail("unterminated inline table");
      if (this.peek() === "}") {
        this.pos += 1;
        return result;
      }
      const path = this.parseKeyPath();
      this.skipInlineSpace();
      if (this.peek() !== "=") this.fail("expected '=' in inline table");
      this.pos += 1;
      assignPath(result, path, this.parseValue());
      this.skipDocumentSpace();
      const ch = this.peek();
      if (ch === ",") {
        this.pos += 1;
        continue;
      }
      if (ch === "}") {
        this.pos += 1;
        return result;
      }
      this.fail("expected ',' or '}' in inline table");
    }
  }

  private parseKeyValue(table: TomlTable): void {
    const path = this.parseKeyPath();
    this.skipInlineSpace();
    if (this.peek() !== "=") this.fail("expected '=' after key");
    this.pos += 1;
    const value = this.parseValue();
    assignPath(table, path, value);
    this.skipInlineSpace();
    this.skipComment();
    const ch = this.peek();
    if (ch === "\n" || ch === "\r" || ch === "") return;
    this.fail("unexpected trailing content after value");
  }

  private endOfHeader(): void {
    this.skipInlineSpace();
    this.skipComment();
    const ch = this.peek();
    if (ch === "\n" || ch === "") return;
    this.fail("unexpected content after table header");
  }

  private parseTableHeader(root: TomlTable): TomlTable {
    const line = this.lineAtOffset(this.pos);
    this.pos += 1; // [
    const path = this.parseKeyPath();
    this.skipInlineSpace();
    if (this.peek() !== "]" || this.input.startsWith("]]", this.pos)) {
      this.fail("expected ']'");
    }
    this.pos += 1;
    this.endOfHeader();
    const table = descend(root, path, false);
    if (!this.headerLines.has(table)) this.headerLines.set(table, line);
    return table;
  }

  private parseArrayHeader(root: TomlTable): TomlTable {
    const line = this.lineAtOffset(this.pos);
    this.pos += 2; // [[
    const path = this.parseKeyPath();
    this.skipInlineSpace();
    if (!this.input.startsWith("]]", this.pos)) this.fail("expected ']]'");
    this.pos += 2;
    this.endOfHeader();
    const table = descend(root, path, true);
    this.headerLines.set(table, line);
    return table;
  }
}

function lastElement(value: TomlValue | undefined): TomlTable | undefined {
  if (Array.isArray(value)) {
    const last = value[value.length - 1];
    if (last && typeof last === "object" && !Array.isArray(last)) {
      return last as TomlTable;
    }
    return undefined;
  }
  if (value && typeof value === "object") return value as TomlTable;
  return undefined;
}

function descend(root: TomlTable, path: string[], array: boolean): TomlTable {
  let current = root;
  for (let index = 0; index < path.length - 1; index += 1) {
    const part = path[index] as string;
    let next = current[part];
    if (next === undefined) {
      next = newTable();
      current[part] = next;
    }
    const table = lastElement(next);
    if (!table) throw new TomlError(`key '${part}' is not a table`);
    current = table;
  }
  const leaf = path[path.length - 1] as string;
  if (array) {
    let list = current[leaf];
    if (list === undefined) {
      list = [];
      current[leaf] = list;
    }
    if (!Array.isArray(list)) throw new TomlError(`key '${leaf}' is not an array of tables`);
    const table: TomlTable = newTable();
    list.push(table);
    return table;
  }
  const existing = current[leaf];
  const table = lastElement(existing);
  if (table) return table;
  if (existing !== undefined) throw new TomlError(`key '${leaf}' is not a table`);
  const created: TomlTable = newTable();
  current[leaf] = created;
  return created;
}

function assignPath(table: TomlTable, path: string[], value: TomlValue): void {
  let current = table;
  for (let index = 0; index < path.length - 1; index += 1) {
    const part = path[index] as string;
    let next = current[part];
    if (next === undefined) {
      next = newTable();
      current[part] = next;
    }
    const child = lastElement(next);
    if (!child) throw new TomlError(`key '${part}' is not a table`);
    current = child;
  }
  current[path[path.length - 1] as string] = value;
}

/**
 * Parse a TOML document, returning a warning string instead of throwing on
 * input the subset reader cannot handle.
 */
export function parseTomlSubset(content: string, file: string): TomlParseResult {
  // A UTF-8 byte order mark is not part of the document.
  const input = content.charCodeAt(0) === 0xfeff ? content.slice(1) : content;
  const parser = new Parser(input);
  try {
    const data = parser.parse();
    return { data, lineOf: (table) => parser.headerLines.get(table) };
  } catch (error) {
    // RangeError (stack exhaustion) and any other failure become a warning.
    return {
      data: newTable(),
      error: `${file}: TOML parse failed (${
        error instanceof Error ? error.message : String(error)
      })`,
      lineOf: () => undefined,
    };
  }
}