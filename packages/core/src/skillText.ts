/**
 * Helpers of the skill scan that do not trust file classification:
 *
 * - `extractPrintableText`: the printable text of any file (binary, NUL
 *   bytes, invalid UTF-8), so that rules and secret detectors can run over
 *   it. A polyglot (`%PDF-1.4\necho ...\n\0...` as `manual.pdf`) is an image
 *   to a viewer and a script to `bash`; its text is what matters for an agent.
 * - `gitDirProblems`: whether a `.git` directory looks created by git, so
 *   that the root `.git` of a local checkout may be left out of the scan.
 */
import fs from "node:fs";
import path from "node:path";

export interface ExtractedText {
  /** One extracted run per line. */
  text: string;
  /** One-based line of the original file where each extracted line starts. */
  lines: number[];
}

/** Shortest run of printable characters that is kept when not ended by a newline. */
export const MIN_PRINTABLE_RUN = 4;

/** Length of the UTF-8 sequence starting with `byte`, 0 when it cannot start one. */
function utf8Length(byte: number): number {
  if (byte >= 0xc2 && byte <= 0xdf) return 2;
  if (byte >= 0xe0 && byte <= 0xef) return 3;
  if (byte >= 0xf0 && byte <= 0xf4) return 4;
  return 0;
}

/**
 * Printable runs of `buffer`: ASCII 0x20-0x7E, tab, and well-formed UTF-8
 * sequences. A newline ends a run and the line it belongs to is recorded; a
 * run ended by any other byte (NUL, control, invalid UTF-8) is kept when it
 * has at least `MIN_PRINTABLE_RUN` characters.
 */
export function extractPrintableText(buffer: Uint8Array): ExtractedText {
  const out: string[] = [];
  const lines: number[] = [];
  let line = 1;
  let run = "";
  let runChars = 0;
  let runLine = 1;
  const flush = (force: boolean): void => {
    if (runChars > 0 && (force || runChars >= MIN_PRINTABLE_RUN)) {
      out.push(run);
      lines.push(runLine);
    }
    run = "";
    runChars = 0;
  };
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let index = 0;
  while (index < buffer.length) {
    const byte = buffer[index] as number;
    if (byte === 0x0a) {
      flush(true);
      line += 1;
      index += 1;
      continue;
    }
    if ((byte >= 0x20 && byte <= 0x7e) || byte === 0x09) {
      if (runChars === 0) runLine = line;
      run += String.fromCharCode(byte);
      runChars += 1;
      index += 1;
      continue;
    }
    const length = utf8Length(byte);
    if (length > 0 && index + length <= buffer.length) {
      try {
        const char = decoder.decode(buffer.subarray(index, index + length));
        if (runChars === 0) runLine = line;
        run += char;
        runChars += 1;
        index += length;
        continue;
      } catch {
        // not a well-formed sequence: a separator like any other byte
      }
    }
    flush(false);
    index += 1;
  }
  flush(false);
  return { text: out.join("\n"), lines };
}

const GIT_TOP_LEVEL: Record<string, "file" | "dir"> = {
  HEAD: "file",
  config: "file",
  description: "file",
  hooks: "dir",
  info: "dir",
  objects: "dir",
  refs: "dir",
  logs: "dir",
  index: "file",
  "packed-refs": "file",
  FETCH_HEAD: "file",
  ORIG_HEAD: "file",
  COMMIT_EDITMSG: "file",
  shallow: "file",
};

const CONFIG_KEYS: ReadonlyArray<RegExp> = [
  /^core\.(?:repositoryformatversion|filemode|bare|logallrefupdates|ignorecase|precomposeunicode|symlinks)$/,
  /^remote\..+\.(?:url|fetch)$/,
  // Written by `git clone --no-tags`; its value is checked below.
  /^remote\..+\.tagopt$/,
  /^branch\..+\.(?:remote|merge)$/,
  /^extensions\.objectformat$/,
];

/** Config keys of `text` (`section.sub.key`, lower-cased except the subsection), or a parse problem. */
function configKeys(text: string): { keys: string[]; values: Map<string, string[]>; problem?: string } {
  const keys: string[] = [];
  const values = new Map<string, string[]>();
  let section: string | undefined;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#") || line.startsWith(";")) continue;
    const header = /^\[\s*([A-Za-z0-9.-]+)(?:\s+"((?:[^"\\]|\\.)*)")?\s*\]$/.exec(line);
    if (header) {
      const name = (header[1] as string).toLowerCase();
      section = header[2] !== undefined ? `${name}.${header[2]}` : name;
      continue;
    }
    const entry = /^([A-Za-z][A-Za-z0-9-]*)\s*(?:=(.*))?$/.exec(line);
    if (!entry || section === undefined) return { keys, values, problem: `unparsed config line ${JSON.stringify(line.slice(0, 80))}` };
    const key = `${section}.${(entry[1] as string).toLowerCase()}`;
    keys.push(key);
    let value = (entry[2] ?? "").trim();
    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
    values.set(key, [...(values.get(key) ?? []), value]);
  }
  return { keys, values };
}

/** https://, ssh://, git:// or scp-like user@host:path, with no whitespace or `::`. */
export function isPlainRemoteUrl(url: string): boolean {
  if (/[\s\u0000-\u001f]/.test(url) || url.includes("::") || url.startsWith("-")) return false;
  if (/^(?:https|ssh|git):\/\/[A-Za-z0-9[]/i.test(url)) return true;
  return /^[A-Za-z0-9._][A-Za-z0-9._-]*@[A-Za-z0-9][A-Za-z0-9.-]*:[^-]/.test(url);
}

/**
 * Why a `.git` directory does not look like one git created (empty when it
 * does): only git's standard top-level entries, only `*.sample` hooks, only
 * `info/exclude`, an `objects/` of loose-object and pack files, no symbolic
 * links, and a `config` with no key outside a short allowlist (no fsmonitor,
 * hooksPath, sshCommand, pager, editor, alias, filter, diff or merge driver,
 * credential helper or include).
 */
export function gitDirProblems(gitDir: string): Array<{ path: string; reason: string }> {
  const problems: Array<{ path: string; reason: string }> = [];
  const add = (rel: string, reason: string): void => {
    problems.push({ path: `.git/${rel}`, reason });
  };
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(gitDir, { withFileTypes: true });
  } catch {
    return [{ path: ".git", reason: "git metadata could not be read" }];
  }
  for (const entry of entries) {
    const expected = GIT_TOP_LEVEL[entry.name];
    if (entry.isSymbolicLink()) add(entry.name, "symbolic link inside .git");
    else if (expected === undefined) add(entry.name, "not part of git's standard layout");
    else if (expected === "dir" && !entry.isDirectory()) add(entry.name, "expected a directory");
    else if (expected === "file" && !entry.isFile()) add(entry.name, "expected a file");
  }
  const list = (rel: string): fs.Dirent[] => {
    try {
      return fs.readdirSync(path.join(gitDir, rel), { withFileTypes: true });
    } catch {
      return [];
    }
  };
  for (const hook of list("hooks")) {
    if (!hook.isFile() || !hook.name.endsWith(".sample")) add(`hooks/${hook.name}`, "hook that git does not install (only *.sample hooks are expected)");
  }
  for (const info of list("info")) {
    if (!info.isFile() || info.name !== "exclude") add(`info/${info.name}`, "not part of git's standard layout");
  }
  for (const object of list("objects")) {
    const rel = `objects/${object.name}`;
    if (/^[0-9a-f]{2}$/.test(object.name) && object.isDirectory()) {
      for (const loose of list(rel)) {
        if (!loose.isFile() || !/^[0-9a-f]{38,62}$/.test(loose.name)) add(`${rel}/${loose.name}`, "not a git object");
      }
    } else if (object.name === "pack" && object.isDirectory()) {
      for (const pack of list(rel)) {
        if (!pack.isFile() || !/^pack-[0-9a-f]{40,64}\.(?:pack|idx|rev|keep|promisor|mtimes)$/.test(pack.name)) {
          add(`${rel}/${pack.name}`, "not a git pack file");
        }
      }
    } else if (object.name === "info" && object.isDirectory()) {
      for (const item of list(rel)) {
        if (!item.isFile() || !["packs", "alternates", "commit-graph"].includes(item.name)) add(`${rel}/${item.name}`, "not part of git's standard layout");
        else if (item.name === "alternates") add(`${rel}/${item.name}`, "points git at objects outside the package");
      }
    } else {
      add(rel, "not part of git's standard layout");
    }
  }
  // Links below refs/ and logs/ are refused; their files are ref names.
  const walk = (rel: string, depth: number): void => {
    for (const item of list(rel)) {
      const child = `${rel}/${item.name}`;
      if (item.isSymbolicLink()) add(child, "symbolic link inside .git");
      else if (item.isDirectory() && depth < 20) walk(child, depth + 1);
    }
  };
  walk("refs", 0);
  walk("logs", 0);
  try {
    const stat = fs.lstatSync(path.join(gitDir, "config"));
    if (stat.isFile()) {
      if (stat.size > 64 * 1024) add("config", "config is larger than 64 KiB");
      else {
        const { keys, values, problem } = configKeys(fs.readFileSync(path.join(gitDir, "config"), "utf8"));
        if (problem) add("config", problem);
        for (const key of keys) {
          if (!CONFIG_KEYS.some((pattern) => pattern.test(key))) add("config", `config key ${key} is not one git writes for a plain clone (it can run commands or change what git does)`);
        }
        // A remote is a network address: not a helper transport (`ext::`),
        // not a local path, not an option.
        for (const [key, list] of values) {
          if (/^remote\..+\.tagopt$/.test(key)) {
            for (const value of list) if (value !== "--no-tags" && value !== "--tags") add("config", `config ${key} = ${JSON.stringify(value.slice(0, 80))} is not --no-tags or --tags`);
            continue;
          }
          if (!/^remote\..+\.url$/.test(key)) continue;
          for (const url of list) {
            if (!isPlainRemoteUrl(url)) add("config", `config ${key} = ${JSON.stringify(url.slice(0, 80))} is not an https://, ssh://, git:// or user@host:path address`);
          }
        }
      }
    }
  } catch {
    // no config file: nothing to check
  }
  return problems;
}

// ---------------------------------------------------------------------------
// Wide encodings
// ---------------------------------------------------------------------------

export type WideEncoding = "utf-16le" | "utf-16be" | "utf-32le" | "utf-32be";

/**
 * UTF-32 with a BOM, UTF-16 with a BOM, or UTF-16 without one: over the
 * first 512 bytes, mostly ASCII with a NUL in every other byte.
 */
export function detectWideEncoding(buffer: Uint8Array): WideEncoding | undefined {
  const b = (index: number): number => buffer[index] ?? -1;
  if (b(0) === 0xff && b(1) === 0xfe && b(2) === 0 && b(3) === 0) return "utf-32le";
  if (b(0) === 0 && b(1) === 0 && b(2) === 0xfe && b(3) === 0xff) return "utf-32be";
  if (b(0) === 0xff && b(1) === 0xfe) return "utf-16le";
  if (b(0) === 0xfe && b(1) === 0xff) return "utf-16be";
  const limit = Math.min(buffer.length, 512) & ~1;
  if (limit < 8) return undefined;
  let le = 0;
  let be = 0;
  const printable = (byte: number): boolean => (byte >= 0x20 && byte <= 0x7e) || byte === 0x09 || byte === 0x0a || byte === 0x0d;
  for (let index = 0; index < limit; index += 2) {
    const first = buffer[index] as number;
    const second = buffer[index + 1] as number;
    if (printable(first) && second === 0) le += 1;
    if (first === 0 && printable(second)) be += 1;
  }
  const pairs = limit / 2;
  if (le >= pairs * 0.9) return "utf-16le";
  if (be >= pairs * 0.9) return "utf-16be";
  return undefined;
}

/** Decode wide text strictly; undefined when it does not decode. */
export function decodeWideText(buffer: Uint8Array, encoding: WideEncoding): string | undefined {
  try {
    if (encoding === "utf-16le" || encoding === "utf-16be") {
      const text = new TextDecoder(encoding, { fatal: true }).decode(buffer);
      return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
    }
    if (buffer.length % 4 !== 0) return undefined;
    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    const chars: string[] = [];
    for (let at = 0; at < buffer.length; at += 4) {
      const code = view.getUint32(at, encoding === "utf-32le");
      if (code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return undefined;
      if (at === 0 && code === 0xfeff) continue;
      chars.push(String.fromCodePoint(code));
    }
    return chars.join("");
  } catch {
    return undefined;
  }
}

/** `buffer` with every NUL byte removed (bash drops them when it runs a script). */
export function stripNul(buffer: Uint8Array): Buffer {
  return Buffer.from(Buffer.from(buffer).filter((byte) => byte !== 0));
}

// ---------------------------------------------------------------------------
// PDF streams
// ---------------------------------------------------------------------------

export interface PdfText {
  /** Text recovered from FlateDecode streams, with the line their stream starts on. */
  parts: Array<{ text: string; line: number }>;
  /** Filters seen that can hold text but were not decoded. */
  undecoded: string[];
  /** Streams over the limits (not analysed). */
  overLimit: number;
  /** Inflated bytes in all. */
  inflatedBytes: number;
}

const TEXT_CAPABLE_FILTERS = ["LZWDecode", "ASCII85Decode", "ASCIIHexDecode", "RunLengthDecode", "LZW", "A85", "AHx", "RL"];
const MAX_PDF_STREAMS = 10_000;

/** A literal `(...)` string of PDF syntax at `start`, with escapes resolved. */
function pdfLiteral(text: string, start: number): { value: string; end: number } {
  let depth = 1;
  let value = "";
  let at = start + 1;
  while (at < text.length && depth > 0) {
    const char = text[at] as string;
    if (char === "\\") {
      const next = text[at + 1] ?? "";
      const octal = /^[0-7]{1,3}/.exec(text.slice(at + 1, at + 4));
      if (octal) {
        value += String.fromCharCode(parseInt(octal[0], 8) & 0xff);
        at += 1 + octal[0].length;
        continue;
      }
      value += ({ n: "\n", r: "\r", t: "\t", b: "\b", f: "\f" } as Record<string, string>)[next] ?? (next === "\n" ? "" : next);
      at += 2;
      continue;
    }
    if (char === "(") depth += 1;
    if (char === ")") {
      depth -= 1;
      if (depth === 0) break;
    }
    value += char;
    at += 1;
  }
  return { value, end: at + 1 };
}

/**
 * The strings shown by the text operators of a content stream: `(..) Tj`,
 * `(..) '`, `(..) "`, `[(..) -120 (..)] TJ` and `<hex> Tj`. One line per
 * operator, and one line per text object (`BT` ... `ET`) with its strings
 * joined, so that text split across operators is matched as a whole.
 */
export function pdfTextOperators(content: string): string[] {
  const lines: string[] = [];
  let block: string[] = [];
  let pending: string[] = [];
  let at = 0;
  const limit = Math.min(content.length, 8 * 1024 * 1024);
  while (at < limit) {
    const char = content[at] as string;
    if (char === "(") {
      const literal = pdfLiteral(content, at);
      pending.push(literal.value);
      at = literal.end;
      continue;
    }
    if (char === "<" && content[at + 1] !== "<") {
      const close = content.indexOf(">", at);
      if (close < 0) break;
      const hex = content.slice(at + 1, close).replace(/\s+/g, "");
      if (/^[0-9A-Fa-f]*$/.test(hex)) pending.push(Buffer.from(hex.length % 2 ? `${hex}0` : hex, "hex").toString("latin1"));
      at = close + 1;
      continue;
    }
    const operator = /^(?:TJ|Tj|BT|ET|'|")(?![A-Za-z])/.exec(content.slice(at, at + 3));
    if (operator) {
      const name = operator[0];
      if (name === "BT") {
        block = [];
        pending = [];
      } else if (name === "ET") {
        if (block.length > 1) lines.push(block.join(" "));
        block = [];
        pending = [];
      } else {
        const joined = pending.join("");
        if (joined) {
          lines.push(joined);
          block.push(joined);
        }
        pending = [];
      }
      at += name.length;
      continue;
    }
    // Any other operator ends the operands collected so far.
    if (/[A-Za-z*]/.test(char)) {
      const word = /^[A-Za-z*]+/.exec(content.slice(at, at + 16))?.[0] ?? char;
      pending = [];
      at += word.length;
      continue;
    }
    at += 1;
  }
  return lines;
}

/**
 * Inflate the FlateDecode streams of a PDF (each at most `maxStreamBytes`,
 * ratio at most `maxRatio`, all of them together at most `budget` bytes) and
 * return their printable text and the strings of their text operators.
 */
export function pdfStreamText(
  buffer: Buffer,
  limits: { maxStreamBytes: number; maxRatio: number; budget: number },
  inflate: (data: Buffer, maxOutputLength: number) => Buffer,
): PdfText {
  const result: PdfText = { parts: [], undecoded: [], overLimit: 0, inflatedBytes: 0 };
  const source = buffer.toString("latin1");
  const streamWord = /stream\r?\n/g;
  let match: RegExpExecArray | null;
  let streams = 0;
  while ((match = streamWord.exec(source)) !== null) {
    // "endstream" is not the start of a stream.
    if (match.index > 0 && /[A-Za-z]/.test(source[match.index - 1] as string)) continue;
    streams += 1;
    if (streams > MAX_PDF_STREAMS) break;
    const dataStart = match.index + match[0].length;
    const dataEnd = source.indexOf("endstream", dataStart);
    if (dataEnd < 0) break;
    streamWord.lastIndex = dataEnd + 9;
    const dictStart = source.lastIndexOf("<<", match.index);
    const dictionary = dictStart >= 0 ? source.slice(dictStart, match.index) : "";
    const filterIndex = dictionary.indexOf("/Filter");
    const used =
      filterIndex >= 0
        ? [...dictionary.slice(filterIndex + 7).matchAll(/\/([A-Za-z0-9]+)/g)].map((m) => m[1] as string).slice(0, 4)
        : [];
    const line = (source.slice(0, dataStart).match(/\n/g)?.length ?? 0) + 1;
    const textCapable = used.filter((name) => TEXT_CAPABLE_FILTERS.includes(name));
    if (textCapable.length > 0) {
      for (const name of textCapable) if (!result.undecoded.includes(name)) result.undecoded.push(name);
      continue;
    }
    if (!(used[0] === "FlateDecode" || used[0] === "Fl")) continue;
    let data = buffer.subarray(dataStart, dataEnd);
    if (data.length > 0 && data[data.length - 1] === 0x0a) data = data.subarray(0, data[data.length - 2] === 0x0d ? -2 : -1);
    let inflated: Buffer;
    try {
      inflated = inflate(Buffer.from(data), limits.maxStreamBytes);
    } catch {
      result.overLimit += 1;
      continue;
    }
    if (inflated.length > limits.maxRatio * Math.max(data.length, 1) || result.inflatedBytes + inflated.length > limits.budget) {
      result.overLimit += 1;
      continue;
    }
    result.inflatedBytes += inflated.length;
    result.parts.push({ text: extractPrintableText(inflated).text, line });
    const operators = pdfTextOperators(inflated.toString("latin1"));
    if (operators.length > 0) result.parts.push({ text: operators.join("\n"), line });
  }
  return result;
}
