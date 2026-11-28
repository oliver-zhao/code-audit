/**
 * Binary files inside skill and plugin directories, and the rules that match
 * them (`languages: [binary]`).
 *
 * The inventory does not read binary files as text (binary extension, NUL
 * byte, over the size limit). A skill or plugin that ships compiled code
 * (`.pyc`, native libraries, executables) or hides one behind a text or image
 * extension is worth reporting, so for files in such directories the
 * inventory keeps a list with the path, the size and the first 8 bytes. Only
 * those 8 bytes are ever read from a file that was not read as text.
 */
import fs from "node:fs";
import { CONFIDENCE_ORDER, type Severity } from "./finding.js";
import type { InventoryFile } from "./inventory.js";
import type { LoadedRule, RuleHit, RuleSet } from "./rules.js";

/** Bytes of the file header that are kept. */
export const BINARY_MAGIC_BYTES = 8;
/** Entries of the binary list; beyond this the list is truncated with a warning. */
export const MAX_BINARY_FILES = 10_000;

export const BINARY_TYPES = [
  "elf",
  "mach-o",
  "mach-o-universal",
  "java-class",
  "pe",
  "wasm",
  "python-bytecode",
  "zip",
  "gzip",
  "bzip2",
  "xz",
  "7z",
  "rar",
  "png",
  "jpeg",
  "gif",
  "webp",
  "bmp",
  "ico",
  "pdf",
  "woff",
  "woff2",
  "font",
  "sqlite",
  "empty",
  "text",
  "unknown",
] as const;

export type BinaryType = (typeof BINARY_TYPES)[number];

/** Executable code: native programs and libraries, bytecode. */
export const EXECUTABLE_BINARY_TYPES: readonly BinaryType[] = [
  "elf",
  "mach-o",
  "mach-o-universal",
  "java-class",
  "pe",
  "wasm",
  "python-bytecode",
];

export interface BinaryFile {
  /** Relative, `/`-separated path. */
  relPath: string;
  absPath: string;
  size: number;
  /** The first (up to) 8 bytes, upper-case hexadecimal. */
  magic: string;
  /** What the header says the file is. */
  type: BinaryType;
  /** Why the inventory did not read it as text (or "text" for a text file with an executable header). */
  reason: string;
  /**
   * For a `.pyc` / `.pyo` in `__pycache__/`: whether the source module
   * (`<name>.py` next to the `__pycache__` directory) exists. Undefined for
   * other files.
   */
  sourcePresent?: boolean;
}

/**
 * Paths of agent packages by name: a `skills/` directory, a plugin below
 * `plugins/<name>/`, and the project directories of Claude Code, Codex,
 * OpenCode and the shared `.agents/`. (A directory tree that holds a
 * `SKILL.md` or `.claude-plugin/` is recognised by the inventory itself.)
 */
const AGENT_PACKAGE_PATH = /(?:^|\/)(?:skills|\.claude|\.codex|\.agents|\.opencode|\.claude-plugin)\/|(?:^|\/)plugins\/[^/]+\//;

export function isAgentPackagePath(relPath: string): boolean {
  return AGENT_PACKAGE_PATH.test(relPath);
}

function hex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).toUpperCase().padStart(2, "0");
  return out;
}

/** The first 8 bytes of a file, or undefined when it cannot be read. */
export function readMagic(absPath: string): Buffer | undefined {
  let fd: number | undefined;
  try {
    fd = fs.openSync(absPath, "r");
    const buffer = Buffer.alloc(BINARY_MAGIC_BYTES);
    const read = fs.readSync(fd, buffer, 0, BINARY_MAGIC_BYTES, 0);
    return buffer.subarray(0, read);
  } catch {
    return undefined;
  } finally {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch {
        // Nothing to do: the descriptor is gone either way.
      }
    }
  }
}

const startsWith = (bytes: Uint8Array, prefix: readonly number[]): boolean =>
  prefix.every((value, index) => bytes[index] === value);

/** What a file header says the file is. */
export function classifyMagic(bytes: Uint8Array): BinaryType {
  if (bytes.length === 0) return "empty";
  if (startsWith(bytes, [0x7f, 0x45, 0x4c, 0x46])) return "elf";
  if (
    startsWith(bytes, [0xfe, 0xed, 0xfa, 0xce]) ||
    startsWith(bytes, [0xfe, 0xed, 0xfa, 0xcf]) ||
    startsWith(bytes, [0xce, 0xfa, 0xed, 0xfe]) ||
    startsWith(bytes, [0xcf, 0xfa, 0xed, 0xfe])
  ) {
    return "mach-o";
  }
  if (startsWith(bytes, [0xca, 0xfe, 0xba, 0xbe])) {
    // A universal binary counts its architectures (a small number) where a
    // Java class file has its version (45 and up).
    if (bytes.length >= 8) {
      const second = ((bytes[4] as number) << 24) | ((bytes[5] as number) << 16) | ((bytes[6] as number) << 8) | (bytes[7] as number);
      return second > 0 && second < 0x2d ? "mach-o-universal" : "java-class";
    }
    return "mach-o-universal";
  }
  if (startsWith(bytes, [0xca, 0xfe, 0xba, 0xbf]) || startsWith(bytes, [0xbe, 0xba, 0xfe, 0xca])) return "mach-o-universal";
  // Two-letter magics ("MZ", "BM") count only when the header is not text.
  const text = looksLikeText(bytes);
  if (startsWith(bytes, [0x4d, 0x5a]) && !text) return "pe";
  if (startsWith(bytes, [0x00, 0x61, 0x73, 0x6d])) return "wasm";
  if (startsWith(bytes, [0x50, 0x4b, 0x03, 0x04]) || startsWith(bytes, [0x50, 0x4b, 0x05, 0x06]) || startsWith(bytes, [0x50, 0x4b, 0x07, 0x08])) {
    return "zip";
  }
  if (startsWith(bytes, [0x1f, 0x8b])) return "gzip";
  if (startsWith(bytes, [0x42, 0x5a, 0x68])) return "bzip2";
  if (startsWith(bytes, [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])) return "xz";
  if (startsWith(bytes, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return "7z";
  if (startsWith(bytes, [0x52, 0x61, 0x72, 0x21])) return "rar";
  if (startsWith(bytes, [0x89, 0x50, 0x4e, 0x47])) return "png";
  if (startsWith(bytes, [0xff, 0xd8, 0xff])) return "jpeg";
  if (startsWith(bytes, [0x47, 0x49, 0x46, 0x38])) return "gif";
  if (startsWith(bytes, [0x52, 0x49, 0x46, 0x46])) return "webp";
  if (startsWith(bytes, [0x42, 0x4d]) && !text) return "bmp";
  if (startsWith(bytes, [0x00, 0x00, 0x01, 0x00])) return "ico";
  if (startsWith(bytes, [0x25, 0x50, 0x44, 0x46])) return "pdf";
  if (startsWith(bytes, [0x77, 0x4f, 0x46, 0x46])) return "woff";
  if (startsWith(bytes, [0x77, 0x4f, 0x46, 0x32])) return "woff2";
  if (startsWith(bytes, [0x00, 0x01, 0x00, 0x00]) || startsWith(bytes, [0x4f, 0x54, 0x54, 0x4f])) return "font";
  if (startsWith(bytes, [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66])) return "sqlite";
  // Printable UTF-8 (an over-long text file): before the bytecode test, whose
  // first two bytes are never valid UTF-8 followed by a line break.
  if (text) return "text";
  // CPython bytecode: a two-byte version number followed by \r\n.
  if (bytes.length >= 4 && bytes[2] === 0x0d && bytes[3] === 0x0a) return "python-bytecode";
  return "unknown";
}

const utf8 = new TextDecoder("utf-8", { fatal: true });

/** Printable UTF-8 (tabs and line breaks allowed); a sequence cut off at the end is accepted. */
function looksLikeText(bytes: Uint8Array): boolean {
  for (const byte of bytes) {
    if (byte < 0x20 && byte !== 0x09 && byte !== 0x0a && byte !== 0x0d) return false;
    if (byte === 0x7f) return false;
  }
  for (let cut = 0; cut <= Math.min(3, bytes.length - 1); cut += 1) {
    try {
      utf8.decode(bytes.subarray(0, bytes.length - cut));
      return true;
    } catch {
      // Try without a possibly truncated last sequence.
    }
  }
  return false;
}

/**
 * Headers that are checked on files that were read as text too: an
 * executable or archive with a text name and no NUL byte in its first 8 KiB
 * is still not text. (`MZ` alone is two letters and is not used here.)
 */
export function isStrongBinaryHeader(type: BinaryType): boolean {
  return type === "elf" || type === "mach-o" || type === "mach-o-universal" || type === "zip" || type === "wasm";
}

/**
 * True for a header that is executable code or an archive whatever the file
 * name: a strong header, or a PE / Java class / CPython bytecode header whose
 * first 8 bytes also hold a NUL byte (which text never has).
 */
export function looksExecutableHeader(header: Uint8Array): boolean {
  const bytes = header.subarray(0, BINARY_MAGIC_BYTES);
  const type = classifyMagic(bytes);
  if (isStrongBinaryHeader(type)) return true;
  return (type === "pe" || type === "java-class" || type === "python-bytecode") && bytes.includes(0);
}

export function binaryFileOf(
  relPath: string,
  absPath: string,
  size: number,
  header: Uint8Array | undefined,
  reason: string,
): BinaryFile {
  const bytes = header ? header.subarray(0, BINARY_MAGIC_BYTES) : new Uint8Array();
  return {
    relPath,
    absPath,
    size,
    magic: hex(bytes),
    type: header ? classifyMagic(bytes) : "unknown",
    reason: header ? reason : `${reason}; header not readable`,
  };
}

function severityRank(severity: Severity): number {
  return { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[severity];
}

/** The pseudo inventory entry a binary hit refers to. */
function inventoryEntry(binary: BinaryFile): InventoryFile {
  return {
    relPath: binary.relPath,
    absPath: binary.absPath,
    language: "unknown",
    size: binary.size,
    loc: 0,
    kind: "other",
    scannable: false,
    isLockfile: false,
  };
}

function binaryRuleMatches(rule: LoadedRule, binary: BinaryFile): boolean {
  const compiled = rule.compiled;
  if (compiled.pathInclude && !compiled.pathInclude.test(binary.relPath)) return false;
  if (compiled.pathExclude && compiled.pathExclude.test(binary.relPath)) return false;
  if (compiled.pattern && !compiled.pattern.test(binary.relPath)) return false;
  if (compiled.notPattern && compiled.notPattern.test(binary.relPath)) return false;
  if (rule.fileMagic && !rule.fileMagic.some((prefix) => binary.magic.startsWith(prefix))) return false;
  if (rule.fileType && !rule.fileType.includes(binary.type)) return false;
  // sourcePresent: true = only a cached .pyc whose source exists; false =
  // anything but such a file.
  if (rule.sourcePresent === true && binary.sourcePresent !== true) return false;
  if (rule.sourcePresent === false && binary.sourcePresent === true) return false;
  return true;
}

/**
 * Match the rules with `languages: [binary]` against the binary list. A hit
 * is at line 1 with the evidence `binary file (<type>, <size> bytes)`. Hits
 * of one group on one file collapse into the one with the highest
 * confidence, then severity.
 */
export function scanBinaryRules(binaries: readonly BinaryFile[], ruleSet: RuleSet): RuleHit[] {
  const rules = ruleSet.rules.filter((rule) => rule.languages.includes("binary"));
  if (rules.length === 0) return [];
  const hits: RuleHit[] = [];
  for (const binary of binaries) {
    const matched = rules.filter((rule) => binaryRuleMatches(rule, binary));
    if (matched.length === 0) continue;
    const best = new Map<string, LoadedRule>();
    const ungrouped: LoadedRule[] = [];
    const score = (rule: LoadedRule): number =>
      (CONFIDENCE_ORDER[rule.confidence] * 10 + severityRank(rule.severity)) * 100 + (rule.groupPriority ?? 0);
    for (const rule of matched) {
      if (!rule.group) {
        ungrouped.push(rule);
        continue;
      }
      const current = best.get(rule.group);
      if (!current || score(rule) > score(current)) best.set(rule.group, rule);
    }
    const file = inventoryEntry(binary);
    for (const rule of [...ungrouped, ...best.values()]) {
      hits.push({ rule, file, line: 1, evidence: `binary file (${binary.type}, ${binary.size} bytes)` });
    }
  }
  return hits;
}
