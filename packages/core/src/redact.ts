/**
 * Line splitting and secret redaction shared by every engine and every output
 * path (rule evidence, secret findings, external adapters, agent-added
 * findings, the read / search tools).
 *
 * Redaction is a property of the LINE, not of the rule that happened to match
 * it: `redactLine` masks everything on a line that looks like a credential,
 * plus any extra column ranges the caller knows about (what a `redactEvidence`
 * rule matched on that line). Over-redaction is harmless; a secret that reaches
 * a report is not.
 */

/**
 * Split text into physical lines the way Python does: `\r\n`, a lone `\r` and
 * `\n` all end a line. Every place that computes a line number uses this, so
 * numbers agree between the rule engine, the secret detector, the read tool and
 * the reports. (A lone `\r` is a line break for the Python tokenizer, so text
 * after `# comment\r` is code.)
 */
export function splitLines(text: string): string[] {
  return text.split(/\r\n|\r|\n/);
}

/** Number of physical lines, consistent with `splitLines`; 0 for empty text. */
export function countLines(text: string): number {
  if (text.length === 0) return 0;
  let count = 1;
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    if (code === 10) count += 1;
    else if (code === 13 && text.charCodeAt(index + 1) !== 10) count += 1;
  }
  return count;
}

export interface RedactRange {
  start: number;
  end: number;
  /** Leading characters that are a public, recognisable prefix (`AKIA`, `ghp_`). */
  keep?: number;
  /** Fixed text to show instead of a mask. */
  replacement?: string;
}

/**
 * Mask a secret value.
 *
 * - Fewer than 16 characters: fully masked.
 * - Otherwise at most the first 2 and the last 2 characters stay visible.
 * - `keepPrefix` characters of a vendor token prefix (`AKIA`, `ghp_`, `xoxb-`)
 *   stay visible; then only the last 2 characters of a long remainder do.
 *
 * The mask length follows the value length (capped), so a rotated secret of
 * the same length produces the same masked text.
 */
export function maskSecret(value: string, keepPrefix = 0): string {
  const keep = Math.max(0, Math.min(keepPrefix, value.length));
  const prefix = value.slice(0, keep);
  const body = value.slice(keep);
  if (body.length < 16) {
    return `${prefix}${"*".repeat(Math.min(24, Math.max(4, body.length)))}`;
  }
  if (keep > 0) {
    return `${prefix}${"*".repeat(Math.min(24, body.length - 2))}${body.slice(-2)}`;
  }
  return `${body.slice(0, 2)}${"*".repeat(Math.min(24, body.length - 4))}${body.slice(-2)}`;
}

interface TokenFormat {
  pattern: RegExp;
  /** Length of the public prefix, from the match. */
  keep: (match: string) => number;
}

/** Vendor token formats that are masked wherever they appear. */
const TOKEN_FORMATS: TokenFormat[] = [
  { pattern: /\bA(?:KIA|SIA)[0-9A-Z]{16}\b/g, keep: () => 4 },
  {
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b/g,
    keep: (match) => (match.startsWith("github_pat_") ? 11 : 4),
  },
  { pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}/g, keep: () => 5 },
  { pattern: /\bglpat-[A-Za-z0-9_-]{20,}/g, keep: () => 6 },
  { pattern: /\bsk-[A-Za-z0-9_-]{20,}/g, keep: () => 3 },
  { pattern: /\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}/g, keep: () => 8 },
  { pattern: /\bAIza[0-9A-Za-z_-]{35}/g, keep: () => 4 },
  // JSON Web Token: three base64url parts.
  { pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, keep: () => 3 },
];

const PRIVATE_KEY_MARKER = /-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----/;

/**
 * Credentials embedded in a URL: `scheme://user:password@host`. Group 1 is the
 * part before the password, group 2 the password. Lengths are bounded so the
 * pattern stays linear on hostile input.
 */
export const URL_CREDENTIALS =
  /(\b[A-Za-z][A-Za-z0-9+.-]{0,30}:\/\/[^\s:@\/?#"'<>]{0,128}:)([^\s@\/?#"'<>]{1,512})@(?=[A-Za-z0-9[])/g;

/** `scheme://userinfo@host` with no password part: the userinfo may be a token. */
const URL_USERINFO =
  /(\b[A-Za-z][A-Za-z0-9+.-]{0,30}:\/\/)([^\s:@\/?#"'<>${}]{8,512})@(?=[A-Za-z0-9[])/g;

/** A URL password that is a variable reference or an obvious dummy. */
export function isUrlPasswordReference(value: string): boolean {
  if (/^[$%]/.test(value) || /^\*+$/.test(value) || /[{}]/.test(value)) return true;
  if (/^<[^>]*>$/.test(value)) return true;
  return false;
}

/**
 * Words that make an identifier, a JSON / YAML key, a header name or a
 * function name "secret-like". Deliberately generous: this list decides what is
 * masked, not what is reported.
 */
const SECRET_WORD_SOURCE =
  "pass(?:word|wd|phrase|code)|pass(?![A-Za-z])|pwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|encryption[_-]?key|master[_-]?key|credential|signing|signature|auth(?!ors?(?![A-Za-z]))|bearer|salt|hmac|jwt|dsn|conn(?:ection)?[_-]?str(?:ing)?|session[_-]?key|(?<![A-Za-z])(?:key|iv|nonce|pin|otp)(?![A-Za-z])|[_-]key(?![A-Za-z])";
const SECRET_WORD = new RegExp(SECRET_WORD_SOURCE, "gi");
const SECRET_WORD_TEST = new RegExp(SECRET_WORD_SOURCE, "i");

/** A secret-like name whose value starts on a following line. */
const SECRET_CONTINUES = new RegExp(
  `(?:${SECRET_WORD_SOURCE})[A-Za-z0-9_$.-]{0,80}["'\`\\])\\s]{0,8}(?::[^="'\`]{0,50})?(?:=|:|\\()(?:\\s*[(\\[{]){0,4}\\s*\\\\?$`,
  "i",
);
/** A YAML block scalar under a secret-like key: `password: |`. */
const SECRET_BLOCK_SCALAR = new RegExp(
  `(?:${SECRET_WORD_SOURCE})[A-Za-z0-9_$.-]{0,80}["']?\\s*:\\s*[|>][-+0-9]{0,2}$`,
  "i",
);

const IDENT_CHAR = /[A-Za-z0-9_$.-]/;

export interface Literal {
  /** Index of the opening quote. */
  open: number;
  contentStart: number;
  contentEnd: number;
  /** Index just after the closing quote (or the end of the line). */
  close: number;
}

/**
 * String literals of one line, by a simple quote scan (`"`, `'`, backtick,
 * triple quotes, backslash escapes). An unterminated literal runs to the end
 * of the line. This is not a parser: on prose (an apostrophe) it produces
 * spurious literals, which only makes redaction more generous.
 */
export function lexLiterals(line: string): Literal[] {
  const literals: Literal[] = [];
  let index = 0;
  const length = line.length;
  while (index < length) {
    const ch = line.charCodeAt(index);
    // " ' `
    if (ch !== 34 && ch !== 39 && ch !== 96) {
      index += 1;
      continue;
    }
    const quote = line[index] as string;
    const triple = quote !== "`" && line.startsWith(quote.repeat(3), index);
    const width = triple ? 3 : 1;
    const contentStart = index + width;
    let end = contentStart;
    let closed = false;
    while (end < length) {
      const current = line.charCodeAt(end);
      if (current === 92) {
        end += 2;
        continue;
      }
      if (current === ch && (!triple || line.startsWith(quote.repeat(3), end))) {
        closed = true;
        break;
      }
      end += 1;
    }
    end = Math.min(end, length);
    literals.push({
      open: index,
      contentStart,
      contentEnd: end,
      close: closed ? end + width : length,
    });
    index = closed ? end + width : length;
  }
  return literals;
}

/** A value that is a reference to configuration, not a secret itself. */
function isReferenceValue(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length === 0) return true;
  if (/^(?:Bearer|Basic|Token|Digest)$/i.test(trimmed)) return true;
  return /^(?:\$\{[^}]*\}|\$\([^)]*\)|\$[A-Za-z_][A-Za-z0-9_]*|\{\{[^}]*\}\}|<[^<>]*>|\{[\w.]*\}|%\(\w+\)s|%[sd]|%[A-Za-z_][A-Za-z0-9_]*%)$/.test(
    trimmed,
  );
}

const CONFIG_EXTENSIONS = new Set([
  "yml",
  "yaml",
  "json",
  "jsonc",
  "toml",
  "ini",
  "cfg",
  "conf",
  "env",
  "properties",
  "tf",
  "tfvars",
  "envrc",
]);

/** Files in which `name: value` / `NAME=value` without quotes is the norm. */
export function isConfigLikeFile(file: string | undefined): boolean {
  if (!file) return false;
  const base = (file.split(/[\\/]/).pop() ?? "").toLowerCase();
  if (base.startsWith(".env") || base.startsWith("dockerfile") || base.endsWith(".dockerfile")) {
    return true;
  }
  const dot = base.lastIndexOf(".");
  return dot >= 0 && CONFIG_EXTENSIONS.has(base.slice(dot + 1));
}

const UNQUOTED_KEYWORDS = /^(?:none|null|nil|true|false|undefined|yes|no|on|off|self|this)$/i;

function skipSpaces(line: string, from: number, limit: number): number {
  let index = from;
  while (index < limit && (line[index] === " " || line[index] === "\t")) index += 1;
  return index;
}

/**
 * Column ranges of one line that hold the value of a secret-like name:
 *
 * - `db_password = "..."`, `"password": "..."`, `cfg["SECRET_KEY"] = '...'`,
 *   `token: str = "..."`, `if password == "..."`;
 * - every literal of a bracketed value or of a concatenation:
 *   `auth=("user", "pw")`, `"a" + "b"`;
 * - the default of a lookup by a secret-like key:
 *   `os.environ.get("SECRET_KEY", "default")`;
 * - every literal argument of a call to a secret-like function:
 *   `set_password("...")`, `hmac.new(b"...", ...)`, `jwt.encode(p, "...")`;
 * - `name: value` / `NAME=value` without quotes, in configuration files
 *   always and in other files when the value looks like a token;
 * - `'X-Auth: value'`, `"password=value;..."`, `Authorization: Bearer value`
 *   inside a string literal;
 * - `--password value`.
 */
function secretValueRanges(line: string, configLike: boolean): RedactRange[] {
  const ranges: RedactRange[] = [];
  if (!SECRET_WORD_TEST.test(line)) return ranges;
  const literals = lexLiterals(line);
  // Literals are sorted by position: the last one that opens at or before
  // `position`, by binary search (a minified line can hold thousands).
  const lastOpeningAtOrBefore = (position: number): Literal | undefined => {
    let low = 0;
    let high = literals.length - 1;
    let found: Literal | undefined;
    while (low <= high) {
      const middle = (low + high) >> 1;
      const literal = literals[middle] as Literal;
      if (literal.open <= position) {
        found = literal;
        low = middle + 1;
      } else {
        high = middle - 1;
      }
    }
    return found;
  };
  const literalAt = (position: number): Literal | undefined => {
    const literal = lastOpeningAtOrBefore(position);
    return literal && position >= literal.contentStart && position < literal.contentEnd
      ? literal
      : undefined;
  };
  const literalOpeningAt = (position: number): Literal | undefined => {
    const literal = lastOpeningAtOrBefore(position);
    return literal && literal.open === position ? literal : undefined;
  };
  const addLiteral = (literal: Literal): void => {
    if (literal.contentEnd <= literal.contentStart) return;
    if (isReferenceValue(line.slice(literal.contentStart, literal.contentEnd))) return;
    ranges.push({ start: literal.contentStart, end: literal.contentEnd });
  };

  /** Mask every literal between the bracket at `open` and its closing bracket. */
  const maskGroup = (open: number): void => {
    let depth = 0;
    let index = open;
    // Bounded, so many groups on one huge line stay linear overall.
    const limit = Math.min(line.length, open + 4000);
    while (index < limit) {
      const literal = literalOpeningAt(index);
      if (literal) {
        addLiteral(literal);
        index = literal.close;
        continue;
      }
      const ch = line[index];
      if (ch === "(" || ch === "[" || ch === "{") depth += 1;
      else if (ch === ")" || ch === "]" || ch === "}") {
        depth -= 1;
        if (depth <= 0) return;
      }
      index += 1;
    }
  };

  /** Mask an unquoted value that starts at `from`. */
  const maskUnquoted = (from: number, limit: number, insideString: boolean): void => {
    let start = from;
    const scheme = /^(?:Bearer|Basic|Token|Digest)\s+/i.exec(line.slice(start, start + 12));
    if (scheme) start += scheme[0].length;
    if (start >= limit) return;
    const first = line[start] as string;
    if (insideString && (first === '"' || first === "'" || first === "`")) {
      // A quoted value nested in the literal: password='...'
      let end = start + 1;
      while (end < limit && line[end] !== first) end += 1;
      if (end > start + 1 && !isReferenceValue(line.slice(start + 1, end))) {
        ranges.push({ start: start + 1, end });
      }
      return;
    }
    let end = start;
    while (end < limit && !/[\s"'`,;&]/.test(line[end] as string)) end += 1;
    const value = line.slice(start, end);
    if (value.length === 0 || isReferenceValue(value) || UNQUOTED_KEYWORDS.test(value)) return;
    if (insideString || configLike) {
      if (value.length < (insideString ? 4 : 1)) return;
      // A format placeholder or a concatenation point, not a value.
      if (/^[%{]/.test(value)) return;
    } else {
      // Source code: only a value that looks like a token, never an expression.
      if (value.length < 8) return;
      if (!/[0-9]/.test(value) || !/[A-Za-z]/.test(value)) return;
      if (/[()[\]{}<>$|\\]/.test(value)) return;
    }
    ranges.push({ start, end });
  };

  /** Mask the value expression that starts at `from` (code level). */
  const maskValueExpression = (from: number, allowUnquoted: boolean): void => {
    let position = skipSpaces(line, from, line.length);
    const opener = line[position];
    if (opener === "(" || opener === "[" || opener === "{") {
      maskGroup(position);
      return;
    }
    for (let count = 0; count < 12; count += 1) {
      const scan = skipSpaces(line, position, line.length);
      let literal = literalOpeningAt(scan);
      if (!literal) {
        const prefix = /^[A-Za-z]{1,2}(?=["'])/.exec(line.slice(scan, scan + 3));
        if (prefix) literal = literalOpeningAt(scan + prefix[0].length);
      }
      if (!literal) {
        if (count === 0 && allowUnquoted) maskUnquoted(scan, line.length, false);
        return;
      }
      addLiteral(literal);
      position = skipSpaces(line, literal.close, line.length);
      const next = line[position];
      if (next === "+" || next === "%") {
        position += 1;
        continue;
      }
      // Adjacent literals ("a" "b") continue the value.
      if (literalOpeningAt(position)) continue;
      return;
    }
  };

  const envStyle = configLike && /^\s*(?:ENV|ARG|export|set)\s/i.test(line);

  SECRET_WORD.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = SECRET_WORD.exec(line)) !== null) {
    if (match[0].length === 0) {
      SECRET_WORD.lastIndex += 1;
      continue;
    }
    let nameEnd = match.index + match[0].length;
    const nameLimit = Math.min(line.length, nameEnd + 80);
    while (nameEnd < nameLimit && IDENT_CHAR.test(line[nameEnd] as string)) nameEnd += 1;
    let nameStart = match.index;
    const startLimit = Math.max(0, nameStart - 80);
    while (nameStart > startLimit && IDENT_CHAR.test(line[nameStart - 1] as string)) nameStart -= 1;
    // Trailing dots and dashes are punctuation, not part of the name.
    while (nameEnd > match.index + match[0].length && /[.-]/.test(line[nameEnd - 1] as string)) {
      nameEnd -= 1;
    }
    // Do not look at the same identifier twice.
    SECRET_WORD.lastIndex = Math.max(SECRET_WORD.lastIndex, nameEnd);
    const name = line.slice(nameStart, nameEnd);
    const isFlag = /^--?[A-Za-z]/.test(name);

    const inside = literalAt(match.index);
    let position = nameEnd;
    let keyLiteral: Literal | undefined;
    if (inside) {
      if (nameEnd < inside.contentEnd) {
        // `name: value`, `name=value`, `name='value'` inside a string literal.
        let scan = skipSpaces(line, nameEnd, inside.contentEnd);
        const sep = line[scan];
        if (sep === ":" || sep === "=") {
          scan = skipSpaces(line, scan + 1, inside.contentEnd);
          if (scan < inside.contentEnd) {
            maskUnquoted(scan, inside.contentEnd, true);
            continue;
          }
        } else if (isFlag && scan > nameEnd) {
          maskUnquoted(scan, inside.contentEnd, true);
          continue;
        } else if (scan < inside.contentEnd) {
          continue;
        }
      }
      // The literal is the key itself: continue after its closing quote.
      keyLiteral = inside;
      position = inside.close;
    }

    // Closing brackets of a subscript, whitespace.
    const afterName = position;
    while (position < line.length && /[\s\])]/.test(line[position] as string)) position += 1;
    let sep = line[position];
    if (sep === undefined) continue;
    if (sep === ":" && !configLike) {
      // A type annotation: `token: str = "..."`.
      const rest = line.slice(position + 1, position + 60);
      const annotation = /^[^="'`:,(){}]{0,50}=(?!=)/.exec(rest);
      if (annotation && line[position + 1] !== ":") {
        position += annotation[0].length;
        sep = "=";
      }
    }
    if (sep === "=" || sep === "!") {
      // =, ==, ===, !=, =>
      let scan = position + 1;
      while (scan < line.length && (line[scan] === "=" || line[scan] === ">")) scan += 1;
      if (sep === "!" && scan === position + 1) continue;
      maskValueExpression(scan, sep === "=" && scan === position + 1);
    } else if (sep === ":") {
      if (line[position + 1] === "=") maskValueExpression(position + 2, true);
      else maskValueExpression(position + 1, true);
    } else if (sep === ",") {
      // `get("SECRET_KEY", "default")`: the key is the first argument of a call.
      if (keyLiteral) {
        let before = keyLiteral.open - 1;
        while (before >= 0 && /[\sA-Za-z]/.test(line[before] as string) && keyLiteral.open - before < 4) {
          before -= 1;
        }
        if (line[before] === "(") maskValueExpression(position + 1, false);
      }
    } else if (sep === "(" && !keyLiteral && position === afterName) {
      // A call: only when the function itself is secret-like (`set_password(`),
      // not when an object on the way to it is (`auth.route(`).
      const lastSegment = name.slice(name.lastIndexOf(".") + 1);
      if (SECRET_WORD_TEST.test(lastSegment) || /(?:^|\.)(?:hmac|jwt)\.\w+$/i.test(name)) {
        maskGroup(position);
      }
    } else if (!keyLiteral && position > afterName && (isFlag || envStyle)) {
      // `--password value`, `ENV API_TOKEN value`
      const literal = literalOpeningAt(position);
      if (literal) addLiteral(literal);
      else maskUnquoted(position, line.length, true);
    }
  }
  return ranges;
}

/** What `sensitiveLines` says about a line. */
export const LINE_PLAIN = 0;
/** The value of a secret-like name continues here: mask every string literal. */
export const LINE_MASK_STRINGS = 1;
/** Body of a PEM private-key block or of a secret block scalar: mask the line. */
export const LINE_MASK_ALL = 2;

const PRIVATE_KEY_END = /-----END [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----/;

/**
 * Per-line redaction state that needs more than one line to decide:
 *
 * - lines inside a `-----BEGIN ... PRIVATE KEY-----` block;
 * - lines that continue the value of a secret-like name that ended its line
 *   with `=`, `:`, `(` or an open bracket (`SECRET_KEY = (` + `"..."`);
 * - the body of a YAML block scalar under a secret-like key.
 */
export function sensitiveLines(lines: string[]): Uint8Array {
  const flags = new Uint8Array(lines.length);
  let inPrivateKey = false;
  let continuation = 0;
  let blockIndent = -1;
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] as string;
    if (line.length > 20_000) {
      continuation = 0;
      blockIndent = -1;
      continue;
    }
    const ends = PRIVATE_KEY_END.test(line);
    if (inPrivateKey) {
      flags[index] = LINE_MASK_ALL;
      if (ends) inPrivateKey = false;
      continue;
    }
    if (PRIVATE_KEY_MARKER.test(line)) {
      if (!ends) inPrivateKey = true;
      continue;
    }
    const indent = line.length - line.trimStart().length;
    if (blockIndent >= 0) {
      if (line.trim().length === 0 || indent > blockIndent) {
        if (line.trim().length > 0) flags[index] = LINE_MASK_ALL;
        continue;
      }
      blockIndent = -1;
    }
    if (continuation > 0) {
      flags[index] = LINE_MASK_STRINGS;
      continuation -= 1;
      const trimmed = line.trim();
      // The value ends at a blank line or at a line that closes the bracket
      // without continuing.
      if (trimmed.length === 0 || (/[)\]}]/.test(trimmed) && !/[,+\\([{]$/.test(trimmed))) {
        continuation = 0;
      }
    }
    // Tested without trailing blanks, so the patterns need no trailing \s*.
    const body = line.trimEnd();
    if (SECRET_BLOCK_SCALAR.test(body)) blockIndent = indent;
    else if (SECRET_CONTINUES.test(body)) continuation = 20;
  }
  return flags;
}

export interface RedactOptions {
  /** Path of the file the line comes from; selects configuration-file rules. */
  file?: string;
  /** Extra column ranges to mask (what a `redactEvidence` rule matched). */
  ranges?: RedactRange[];
  /** Mask the contents of every string literal on the line. */
  maskAllStrings?: boolean;
}

const PRIVATE_KEY_REPLACEMENT = "[private key content redacted]";
const PRIVATE_KEY_REPLACEMENT_FOR_BODY = PRIVATE_KEY_REPLACEMENT;

/**
 * Return `line` with every secret masked:
 *
 * - string literals (and unquoted values) assigned to, compared with or passed
 *   as a secret-like name, see `secretValueRanges`;
 * - known vendor token formats (a recognisable prefix stays);
 * - everything from a `-----BEGIN ... PRIVATE KEY-----` marker to the end;
 * - the password of `scheme://user:password@host`;
 * - `options.ranges`, and with `options.maskAllStrings` every string literal.
 *
 * The same function is used for the evidence of every finding from every
 * engine and for the read / search tools.
 */
export function redactLine(line: string, options: RedactOptions = {}): string {
  return redactLineDetailed(line, options).text;
}

/**
 * `redactLine` that also returns the raw values it masked, so text written
 * about the line (an agent's rationale) can be scrubbed of the same values.
 */
export function redactLineDetailed(
  line: string,
  options: RedactOptions = {},
): { text: string; masked: string[] } {
  const masked: string[] = [];
  if (line.length === 0) return { text: line, masked };
  const ranges: RedactRange[] = [];
  for (const range of options.ranges ?? []) {
    const start = Math.max(0, Math.min(range.start, line.length));
    const end = Math.max(start, Math.min(range.end, line.length));
    if (end > start) ranges.push({ ...range, start, end });
  }

  const marker = PRIVATE_KEY_MARKER.exec(line);
  if (marker) {
    ranges.push({
      start: marker.index,
      end: line.length,
      replacement: PRIVATE_KEY_REPLACEMENT,
    });
  }

  for (const format of TOKEN_FORMATS) {
    format.pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = format.pattern.exec(line)) !== null) {
      ranges.push({
        start: match.index,
        end: match.index + match[0].length,
        keep: format.keep(match[0]),
      });
    }
  }

  for (const url of line.matchAll(URL_CREDENTIALS)) {
    const head = url[1] ?? "";
    const password = url[2] ?? "";
    if (isUrlPasswordReference(password)) continue;
    const start = (url.index ?? 0) + head.length;
    ranges.push({ start, end: start + password.length });
  }

  // A token as the whole userinfo: https://TOKEN@host
  for (const url of line.matchAll(URL_USERINFO)) {
    const start = (url.index ?? 0) + (url[1] ?? "").length;
    ranges.push({ start, end: start + (url[2] ?? "").length });
  }

  for (const range of secretValueRanges(line, isConfigLikeFile(options.file))) {
    ranges.push(range);
  }

  if (options.maskAllStrings) {
    for (const literal of lexLiterals(line)) {
      if (literal.contentEnd > literal.contentStart) {
        ranges.push({ start: literal.contentStart, end: literal.contentEnd });
      }
    }
  }

  if (ranges.length === 0) return { text: line, masked };
  ranges.sort((left, right) => left.start - right.start || right.end - left.end);
  let output = "";
  let cursor = 0;
  let index = 0;
  while (index < ranges.length) {
    const first = ranges[index] as RedactRange;
    let start = first.start;
    let end = first.end;
    let keep = first.keep ?? 0;
    let replacement = first.replacement;
    index += 1;
    while (index < ranges.length && (ranges[index] as RedactRange).start < end) {
      const next = ranges[index] as RedactRange;
      end = Math.max(end, next.end);
      replacement = replacement ?? next.replacement;
      // A public token prefix stays visible when the token starts the range.
      if (next.start === start) keep = Math.max(keep, next.keep ?? 0);
      index += 1;
    }
    if (start < cursor) start = cursor;
    if (end <= start) continue;
    output += line.slice(cursor, start);
    output += replacement ?? maskSecret(line.slice(start, end), keep);
    masked.push(line.slice(start, end));
    cursor = end;
  }
  return { text: output + line.slice(cursor), masked };
}

/** Replace every occurrence of the given raw values in `text` by a mask. */
export function scrubValues(text: string, values: Iterable<string>): string {
  let output = text;
  const sorted = [...new Set(values)]
    .filter((value) => value.trim().length >= 4)
    .sort((left, right) => right.length - left.length);
  for (const value of sorted) {
    if (output.includes(value)) output = output.split(value).join(maskSecret(value));
  }
  return output;
}

/** A source line up to this length is evidence as a whole (trimmed). */
export const MAX_EVIDENCE_LINE = 2000;
/** Length of the evidence cut from a longer line. */
export const MAX_EVIDENCE_LENGTH = 400;

/**
 * Evidence text for one source line: trimmed and redacted. A line longer than
 * `MAX_EVIDENCE_LINE` is cut to `MAX_EVIDENCE_LENGTH` characters starting at
 * `column`; every string literal in the cut is masked, because the cut may
 * separate a secret from the name that would have identified it. Literals are
 * located on the whole line, so a cut that starts inside one still masks it.
 */
export function redactEvidence(
  line: string,
  options: RedactOptions & { column?: number } = {},
): string {
  const lead = line.length - line.trimStart().length;
  let start = lead;
  let end = line.trimEnd().length;
  const ranges: RedactRange[] = [...(options.ranges ?? [])];
  let maskAllStrings = options.maskAllStrings ?? false;
  if (end - start > MAX_EVIDENCE_LINE) {
    const column = Math.max(lead, Math.min(options.column ?? lead, end));
    start = column;
    end = Math.min(end, start + MAX_EVIDENCE_LENGTH);
    if (line.length <= 400_000) {
      for (const literal of lexLiterals(line)) {
        if (literal.contentEnd > start && literal.contentStart < end) {
          ranges.push({ start: literal.contentStart, end: literal.contentEnd });
        }
        if (literal.open >= end) break;
      }
    } else {
      maskAllStrings = true;
    }
  }
  const shifted = ranges
    .filter((range) => range.end > start && range.start < end)
    .map((range) => ({
      ...range,
      // A range that begins before the cut has no visible prefix to keep.
      keep: range.start < start ? 0 : range.keep,
      start: Math.max(0, range.start - start),
      end: Math.min(end, range.end) - start,
    }));
  return redactLine(line.slice(start, end), {
    file: options.file,
    ranges: shifted,
    maskAllStrings,
  });
}

/** CWE ids whose findings are about a credential stored or sent in clear. */
const CREDENTIAL_CWES = new Set([
  "CWE-798",
  "CWE-259",
  "CWE-321",
  "CWE-522",
  "CWE-256",
  "CWE-312",
]);

/**
 * True when a finding described by these fields is about a secret, so every
 * string literal in its evidence is masked.
 */
export function isCredentialFinding(fields: {
  cwe?: string;
  title?: string;
  ruleId?: string;
  category?: string;
}): boolean {
  if (fields.cwe && CREDENTIAL_CWES.has(fields.cwe.trim().toUpperCase())) return true;
  if (fields.category === "secrets") return true;
  const text = `${fields.title ?? ""} ${fields.ruleId ?? ""}`;
  return /secret|passw|passphrase|credential|token|api[\s_-]?key|private[\s_-]?key|hard[\s_-]?coded|signing[\s_-]?key|encryption[\s_-]?key/i.test(
    text,
  );
}

/**
 * Redact line `index` of `lines` using the multi-line state from
 * `sensitiveLines(lines)`.
 */
export function redactLineAt(
  lines: string[],
  flags: Uint8Array,
  index: number,
  options: RedactOptions = {},
): string {
  const flag = flags[index] ?? LINE_PLAIN;
  if (flag === LINE_MASK_ALL) return PRIVATE_KEY_REPLACEMENT_FOR_BODY;
  return redactLine(lines[index] ?? "", {
    ...options,
    maskAllStrings: options.maskAllStrings || flag === LINE_MASK_STRINGS,
  });
}

/** Redact a multi-line text line by line (see `sensitiveLines`). */
export function redactText(text: string, options: RedactOptions = {}): string {
  const lines = splitLines(text);
  const flags = sensitiveLines(lines);
  return lines.map((_line, index) => redactLineAt(lines, flags, index, options)).join("\n");
}
