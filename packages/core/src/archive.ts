/**
 * Readers for the archive formats a skill or plugin is distributed in (zip,
 * tar, gzip-compressed tar), written on top of `node:zlib` only.
 *
 * The archive comes from someone else and is never trusted. Everything is
 * checked BEFORE a single byte is written:
 *
 * - at most `ARCHIVE_MAX_ENTRIES` entries and `ARCHIVE_MAX_TOTAL_BYTES`
 *   declared uncompressed bytes in all;
 * - no absolute path, no drive letter, no `..` segment, no backslash, no
 *   control character, no name that is not valid UTF-8;
 * - no symbolic link, hard link, device, FIFO or socket entry;
 * - no two entries that land on the same path (compared after Unicode NFC
 *   normalisation and case folding, as a case-insensitive file system sees
 *   them), and no file that is also used as a directory;
 * - zip: the central directory and every local header agree on the name and
 *   the method, entries do not overlap (overlapping entries are how
 *   "non-recursive" zip bombs work), and the Info-ZIP Unicode path field, when
 *   present, names the same file.
 *
 * Any of these is an `ArchiveError`: the archive is refused as a whole.
 * Problems confined to one entry do not refuse the archive; the entry is not
 * unpacked and is reported in `skipped` (the caller must treat the result as
 * incomplete): a file larger than `ARCHIVE_MAX_FILE_BYTES`, a compression
 * ratio above `ARCHIVE_MAX_RATIO`, an unsupported compression method, an
 * encrypted entry, an unsupported tar entry type.
 *
 * While unpacking, an entry that inflates to more than it declared, or whose
 * CRC-32 does not match, refuses the archive. Files are created with
 * `O_EXCL | O_NOFOLLOW` and mode 0644 below a directory the caller created;
 * every written path is checked with `resolveInside` afterwards.
 */
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import { resolveInside } from "./pathJail.js";
import { ensureDirInside } from "./safeFs.js";

export const ARCHIVE_MAX_ENTRIES = 10_000;
export const ARCHIVE_MAX_TOTAL_BYTES = 100 * 1024 * 1024;
export const ARCHIVE_MAX_FILE_BYTES = 1024 * 1024;
export const ARCHIVE_MAX_RATIO = 100;
/** Largest archive file that is read at all. */
export const ARCHIVE_MAX_INPUT_BYTES = 100 * 1024 * 1024;
const MAX_PATH_LENGTH = 1024;
const MAX_SEGMENT_BYTES = 255;
const MAX_DEPTH = 64;

export type ArchiveFormat = "zip" | "tar" | "tar.gz";

export class ArchiveError extends Error {
  readonly code: string;

  constructor(message: string, code = "ARCHIVE_REJECTED") {
    super(message);
    this.name = "ArchiveError";
    this.code = code;
  }
}

export interface ArchiveSkip {
  path: string;
  reason: string;
}

interface PlannedEntry {
  path: string;
  type: "file" | "directory";
  size: number;
  /** Returns the content; throws an ArchiveError when it is inconsistent. */
  read?: () => Buffer;
}

export interface ArchivePlan {
  format: ArchiveFormat;
  entries: PlannedEntry[];
  skipped: ArchiveSkip[];
}

export interface ExtractResult {
  format: ArchiveFormat;
  files: number;
  directories: number;
  bytes: number;
  skipped: ArchiveSkip[];
}

/** Archive format by file name, or undefined when the name is not one. */
export function archiveFormatOf(file: string): ArchiveFormat | undefined {
  const lower = file.toLowerCase();
  if (lower.endsWith(".zip")) return "zip";
  if (lower.endsWith(".tar.gz") || lower.endsWith(".tgz")) return "tar.gz";
  if (lower.endsWith(".tar")) return "tar";
  return undefined;
}

// ---------------------------------------------------------------------------
// CRC-32 (IEEE 802.3), table driven. zlib.crc32 needs Node 22.2.
// ---------------------------------------------------------------------------

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

export function crc32(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i += 1) {
    crc = (CRC_TABLE[(crc ^ (data[i] as number)) & 0xff] as number) ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

const UTF8 = new TextDecoder("utf-8", { fatal: true });

function decodeName(bytes: Uint8Array, what: string): string {
  try {
    return UTF8.decode(bytes);
  } catch {
    throw new ArchiveError(`${what}: entry name is not valid UTF-8`, "ARCHIVE_BAD_NAME");
  }
}

/** Printable form of an entry name for messages. */
function shown(name: string): string {
  return JSON.stringify(name.length > 200 ? `${name.slice(0, 200)}...` : name);
}

/**
 * The normalised relative POSIX path of an entry, or "" for an entry that
 * names the archive root itself (`./`). Throws for every unsafe form.
 */
export function normalizeArchivePath(raw: string): string {
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(raw)) {
    throw new ArchiveError(`entry ${shown(raw)} has a control character in its name`, "ARCHIVE_BAD_NAME");
  }
  if (raw.includes("\\")) {
    throw new ArchiveError(`entry ${shown(raw)} uses a backslash (Windows) path`, "ARCHIVE_BAD_PATH");
  }
  if (raw.startsWith("/") || /^[A-Za-z]:/.test(raw)) {
    throw new ArchiveError(`entry ${shown(raw)} has an absolute path`, "ARCHIVE_BAD_PATH");
  }
  const segments = raw.split("/").filter((segment) => segment !== "" && segment !== ".");
  if (segments.includes("..")) {
    throw new ArchiveError(`entry ${shown(raw)} has a '..' segment (path traversal)`, "ARCHIVE_BAD_PATH");
  }
  if (segments.length > MAX_DEPTH) {
    throw new ArchiveError(`entry ${shown(raw)} is nested more than ${MAX_DEPTH} levels`, "ARCHIVE_BAD_PATH");
  }
  for (const segment of segments) {
    // Windows drops a trailing dot or space (`SKILL.md.` is `SKILL.md`) and
    // some tools fold full-width dots (`．．`) to `..`.
    if (/[. ]$/.test(segment) || segment.normalize("NFKC").split("/").includes("..")) {
      throw new ArchiveError(`entry ${shown(raw)} has a name component that Windows would rewrite`, "ARCHIVE_BAD_PATH");
    }
    if (Buffer.byteLength(segment, "utf8") > MAX_SEGMENT_BYTES) {
      throw new ArchiveError(`entry ${shown(raw)} has a name component over ${MAX_SEGMENT_BYTES} bytes`, "ARCHIVE_BAD_PATH");
    }
  }
  const joined = segments.join("/");
  if (joined.length > MAX_PATH_LENGTH) {
    throw new ArchiveError(`entry ${shown(raw)} has a path over ${MAX_PATH_LENGTH} characters`, "ARCHIVE_BAD_PATH");
  }
  return joined;
}

/** Key under which two names land on the same file of a case-insensitive file system. */
function collisionKey(relPath: string): string {
  return relPath.normalize("NFC").toLowerCase();
}

/**
 * Check the plan as a whole: entry count, total size, duplicates and
 * file/directory conflicts. Throws on the first problem.
 */
function checkPlan(plan: ArchivePlan): void {
  const total = plan.entries.length + plan.skipped.length;
  if (total > ARCHIVE_MAX_ENTRIES) {
    throw new ArchiveError(`archive has more than ${ARCHIVE_MAX_ENTRIES} entries`, "ARCHIVE_TOO_MANY_ENTRIES");
  }
  const kinds = new Map<string, "file" | "directory">();
  const see = (relPath: string, type: "file" | "directory"): void => {
    const key = collisionKey(relPath);
    const existing = kinds.get(key);
    if (existing !== undefined && (existing === "file" || type === "file")) {
      throw new ArchiveError(`archive has more than one entry for ${shown(relPath)}`, "ARCHIVE_DUPLICATE_PATH");
    }
    kinds.set(key, type);
  };
  for (const entry of plan.entries) see(entry.path, entry.type);
  // A skipped file still occupies its name: a second entry with that name
  // could otherwise be unpacked in its place.
  for (const skip of plan.skipped) if (skip.path) see(skip.path, "file");
  for (const relPath of [...plan.entries.map((entry) => entry.path), ...plan.skipped.map((skip) => skip.path)]) {
    const parts = relPath.split("/");
    for (let index = 1; index < parts.length; index += 1) {
      const ancestor = collisionKey(parts.slice(0, index).join("/"));
      if (kinds.get(ancestor) === "file") {
        throw new ArchiveError(`archive entry ${shown(relPath)} is below an entry that is a file`, "ARCHIVE_DUPLICATE_PATH");
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Zip
// ---------------------------------------------------------------------------

const EOCD_SIGNATURE = 0x06054b50;
const ZIP64_LOCATOR_SIGNATURE = 0x07064b50;
const CENTRAL_SIGNATURE = 0x02014b50;
const LOCAL_SIGNATURE = 0x04034b50;
const S_IFMT = 0o170000;
const S_IFREG = 0o100000;
const S_IFDIR = 0o040000;
const S_IFLNK = 0o120000;

/** Central header, local header, end record, ZIP64 end record and locator, data descriptor. */
const ZIP_SIGNATURES: readonly Buffer[] = [
  [1, 2],
  [3, 4],
  [5, 6],
  [6, 6],
  [6, 7],
  [7, 8],
].map(([a, b]) => Buffer.from([0x50, 0x4b, a as number, b as number]));

function findEndOfCentralDirectory(buffer: Buffer): number {
  const last = buffer.length - 22;
  const first = Math.max(0, last - 0xffff);
  for (let offset = last; offset >= first; offset -= 1) {
    if (buffer.readUInt32LE(offset) !== EOCD_SIGNATURE) continue;
    const commentLength = buffer.readUInt16LE(offset + 20);
    if (offset + 22 + commentLength !== buffer.length) continue;
    // The end record sits exactly at end-of-file minus its comment. A
    // comment that holds zip structures is a second archive that other
    // extractors (unzip, bsdtar) pick instead of this one.
    const comment = buffer.subarray(offset + 22);
    for (const signature of ZIP_SIGNATURES) {
      if (comment.indexOf(signature) >= 0) {
        throw new ArchiveError(
          `zip archive comment contains a zip record signature (PK\\x${signature[2]?.toString(16).padStart(2, "0")}\\x${signature[3]?.toString(16).padStart(2, "0")}): a hidden second archive`,
          "ARCHIVE_COMMENT",
        );
      }
    }
    return offset;
  }
  throw new ArchiveError("not a zip archive (no end of central directory record)", "ARCHIVE_MALFORMED");
}

/**
 * Walk an extra field. It must be well formed, and a field that renames the
 * entry (Info-ZIP Unicode Path, 0x7075; some extractors use it instead of the
 * name) must name the same file, in the local header as in the central
 * directory.
 */
function checkExtraField(extra: Buffer, rawName: string, where: string): void {
  let at = 0;
  while (at < extra.length) {
    if (at + 4 > extra.length) {
      throw new ArchiveError(`zip entry ${shown(rawName)}: malformed extra field in the ${where}`, "ARCHIVE_MALFORMED");
    }
    const id = extra.readUInt16LE(at);
    const length = extra.readUInt16LE(at + 2);
    if (at + 4 + length > extra.length) {
      throw new ArchiveError(`zip entry ${shown(rawName)}: malformed extra field in the ${where}`, "ARCHIVE_MALFORMED");
    }
    if (id === 0x7075) {
      const unicodeName = length >= 5 ? decodeName(extra.subarray(at + 9, at + 4 + length), "zip") : "";
      if (unicodeName !== rawName) {
        throw new ArchiveError(
          `zip entry ${shown(rawName)} carries a different Unicode path ${shown(unicodeName)} in the ${where}`,
          "ARCHIVE_BAD_NAME",
        );
      }
    }
    at += 4 + length;
  }
}

/** Plan the extraction of a zip archive held in `buffer`. */
export function planZip(buffer: Buffer): ArchivePlan {
  if (buffer.length < 22) throw new ArchiveError("not a zip archive (too short)", "ARCHIVE_MALFORMED");
  const eocd = findEndOfCentralDirectory(buffer);
  if (eocd >= 20 && buffer.readUInt32LE(eocd - 20) === ZIP64_LOCATOR_SIGNATURE) {
    throw new ArchiveError("ZIP64 archives are not supported", "ARCHIVE_UNSUPPORTED");
  }
  const disk = buffer.readUInt16LE(eocd + 4);
  const cdDisk = buffer.readUInt16LE(eocd + 6);
  const entriesOnDisk = buffer.readUInt16LE(eocd + 8);
  const totalEntries = buffer.readUInt16LE(eocd + 10);
  const cdSize = buffer.readUInt32LE(eocd + 12);
  const cdOffset = buffer.readUInt32LE(eocd + 16);
  if (totalEntries === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
    throw new ArchiveError("ZIP64 archives are not supported", "ARCHIVE_UNSUPPORTED");
  }
  if (disk !== 0 || cdDisk !== 0 || entriesOnDisk !== totalEntries) {
    throw new ArchiveError("multi-volume zip archives are not supported", "ARCHIVE_UNSUPPORTED");
  }
  if (totalEntries > ARCHIVE_MAX_ENTRIES) {
    throw new ArchiveError(`archive has more than ${ARCHIVE_MAX_ENTRIES} entries`, "ARCHIVE_TOO_MANY_ENTRIES");
  }
  if (cdOffset + cdSize > eocd) {
    throw new ArchiveError("zip central directory lies outside the archive", "ARCHIVE_MALFORMED");
  }

  const entries: PlannedEntry[] = [];
  const skipped: ArchiveSkip[] = [];
  const spans: Array<{ start: number; end: number; name: string }> = [];
  let declaredTotal = 0;
  let offset = cdOffset;
  for (let index = 0; index < totalEntries; index += 1) {
    if (offset + 46 > cdOffset + cdSize || buffer.readUInt32LE(offset) !== CENTRAL_SIGNATURE) {
      throw new ArchiveError("zip central directory is malformed", "ARCHIVE_MALFORMED");
    }
    const madeBy = buffer.readUInt16LE(offset + 4);
    const flags = buffer.readUInt16LE(offset + 8);
    const method = buffer.readUInt16LE(offset + 10);
    const crc = buffer.readUInt32LE(offset + 16);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const size = buffer.readUInt32LE(offset + 24);
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const externalAttributes = buffer.readUInt32LE(offset + 38);
    const localOffset = buffer.readUInt32LE(offset + 42);
    const next = offset + 46 + nameLength + extraLength + commentLength;
    if (next > cdOffset + cdSize) {
      throw new ArchiveError("zip central directory is malformed", "ARCHIVE_MALFORMED");
    }
    if (compressedSize === 0xffffffff || size === 0xffffffff || localOffset === 0xffffffff) {
      throw new ArchiveError("ZIP64 archives are not supported", "ARCHIVE_UNSUPPORTED");
    }
    const nameBytes = buffer.subarray(offset + 46, offset + 46 + nameLength);
    const rawName = decodeName(nameBytes, "zip");
    checkExtraField(buffer.subarray(offset + 46 + nameLength, offset + 46 + nameLength + extraLength), rawName, "central directory");
    offset = next;

    const hostSystem = madeBy >>> 8;
    const unixMode = hostSystem === 3 ? externalAttributes >>> 16 : 0;
    const fileType = unixMode & S_IFMT;
    if (fileType === S_IFLNK) {
      throw new ArchiveError(`zip entry ${shown(rawName)} is a symbolic link`, "ARCHIVE_LINK");
    }
    if (fileType !== 0 && fileType !== S_IFREG && fileType !== S_IFDIR) {
      throw new ArchiveError(`zip entry ${shown(rawName)} is a device, FIFO or socket`, "ARCHIVE_SPECIAL_FILE");
    }
    const relPath = normalizeArchivePath(rawName);
    const isDirectory =
      rawName.endsWith("/") || fileType === S_IFDIR || (hostSystem === 0 && (externalAttributes & 0x10) !== 0);

    // The local header must agree with the central directory.
    if (localOffset + 30 > cdOffset || buffer.readUInt32LE(localOffset) !== LOCAL_SIGNATURE) {
      throw new ArchiveError(`zip entry ${shown(rawName)}: local header missing`, "ARCHIVE_MALFORMED");
    }
    // Extractors read the local header (streaming ones read nothing else):
    // every field that names or sizes the entry must agree with the central
    // directory, or the scan and the install see different files.
    const disagree = (field: string): never => {
      throw new ArchiveError(
        `zip entry ${shown(rawName)}: local header and central directory disagree (${field})`,
        "ARCHIVE_MALFORMED",
      );
    };
    const localFlags = buffer.readUInt16LE(localOffset + 6);
    const localMethod = buffer.readUInt16LE(localOffset + 8);
    const localCrc = buffer.readUInt32LE(localOffset + 14);
    const localCompressed = buffer.readUInt32LE(localOffset + 18);
    const localSize = buffer.readUInt32LE(localOffset + 22);
    const localNameLength = buffer.readUInt16LE(localOffset + 26);
    const localExtraLength = buffer.readUInt16LE(localOffset + 28);
    const localName = buffer.subarray(localOffset + 30, localOffset + 30 + localNameLength);
    if (!localName.equals(nameBytes)) disagree("name");
    if (localMethod !== method) disagree("method");
    if (localFlags !== flags) disagree("flags");
    if (localOffset + 30 + localNameLength + localExtraLength > cdOffset) {
      throw new ArchiveError(`zip entry ${shown(rawName)}: local header lies outside the archive`, "ARCHIVE_MALFORMED");
    }
    checkExtraField(
      buffer.subarray(localOffset + 30 + localNameLength, localOffset + 30 + localNameLength + localExtraLength),
      rawName,
      "local header",
    );
    const dataStart = localOffset + 30 + localNameLength + localExtraLength;
    let dataEnd = dataStart + compressedSize;
    if (dataEnd > cdOffset) {
      throw new ArchiveError(`zip entry ${shown(rawName)}: data lies outside the archive`, "ARCHIVE_MALFORMED");
    }
    const usesDescriptor = (flags & 0x8) !== 0;
    if (!usesDescriptor || localCrc !== 0 || localCompressed !== 0 || localSize !== 0) {
      // Without a data descriptor (or when the local header fills them in
      // anyway) the local values are what extractors use.
      if (localCrc !== crc) disagree("CRC-32");
      if (localCompressed !== compressedSize) disagree("compressed size");
      if (localSize !== size) disagree("uncompressed size");
    }
    if (usesDescriptor) {
      // Data descriptor: optional signature, then CRC-32 and both sizes.
      const signed = dataEnd + 4 <= cdOffset && buffer.readUInt32LE(dataEnd) === 0x08074b50;
      const at = signed ? dataEnd + 4 : dataEnd;
      if (at + 12 > cdOffset) {
        throw new ArchiveError(`zip entry ${shown(rawName)}: data descriptor missing`, "ARCHIVE_MALFORMED");
      }
      if (buffer.readUInt32LE(at) !== crc) disagree("data descriptor CRC-32");
      if (buffer.readUInt32LE(at + 4) !== compressedSize) disagree("data descriptor compressed size");
      if (buffer.readUInt32LE(at + 8) !== size) disagree("data descriptor uncompressed size");
      dataEnd = at + 12;
    }
    spans.push({ start: localOffset, end: dataEnd, name: rawName });

    if (isDirectory) {
      if (size !== 0) {
        throw new ArchiveError(`zip directory entry ${shown(rawName)} has content`, "ARCHIVE_MALFORMED");
      }
      if (relPath !== "") entries.push({ path: relPath, type: "directory", size: 0 });
      continue;
    }
    if (relPath === "") {
      throw new ArchiveError(`zip entry ${shown(rawName)} has an empty path`, "ARCHIVE_BAD_PATH");
    }
    declaredTotal += size;
    if (declaredTotal > ARCHIVE_MAX_TOTAL_BYTES) {
      throw new ArchiveError(
        `archive unpacks to more than ${ARCHIVE_MAX_TOTAL_BYTES / 1024 / 1024} MiB`,
        "ARCHIVE_TOO_LARGE",
      );
    }
    if ((flags & 0x1) !== 0) {
      skipped.push({ path: relPath, reason: "encrypted archive entry (not unpacked)" });
      continue;
    }
    if (method !== 0 && method !== 8) {
      skipped.push({ path: relPath, reason: `unsupported compression method ${method} (not unpacked)` });
      continue;
    }
    if (size > ARCHIVE_MAX_FILE_BYTES) {
      skipped.push({ path: relPath, reason: `file exceeds the ${ARCHIVE_MAX_FILE_BYTES / 1024 / 1024} MiB limit (not unpacked)` });
      continue;
    }
    if (size > 0 && size > ARCHIVE_MAX_RATIO * Math.max(compressedSize, 1)) {
      skipped.push({ path: relPath, reason: `compression ratio exceeds ${ARCHIVE_MAX_RATIO}:1 (not unpacked)` });
      continue;
    }
    if (method === 0 && compressedSize !== size) {
      throw new ArchiveError(`zip entry ${shown(rawName)}: stored entry with mismatching sizes`, "ARCHIVE_MALFORMED");
    }
    const read = (): Buffer => {
      const raw = buffer.subarray(dataStart, dataStart + compressedSize);
      let data: Buffer;
      if (method === 0) {
        data = Buffer.from(raw);
      } else {
        try {
          data = zlib.inflateRawSync(raw, { maxOutputLength: Math.max(size, 1) });
        } catch {
          throw new ArchiveError(
            `zip entry ${shown(rawName)} does not inflate to its declared size of ${size} bytes`,
            "ARCHIVE_MALFORMED",
          );
        }
      }
      if (data.length !== size) {
        throw new ArchiveError(
          `zip entry ${shown(rawName)} does not inflate to its declared size of ${size} bytes`,
          "ARCHIVE_MALFORMED",
        );
      }
      if (crc32(data) !== crc) {
        throw new ArchiveError(`zip entry ${shown(rawName)}: CRC-32 mismatch`, "ARCHIVE_MALFORMED");
      }
      return data;
    };
    entries.push({ path: relPath, type: "file", size, read });
  }
  spans.sort((a, b) => a.start - b.start);
  // The entries must tile the archive from offset 0 to the central directory:
  // no prefix, no gap, no unreferenced local entry (a streaming extractor
  // unpacks every local header it meets), no overlap. Only the archive
  // comment may follow the end record.
  let expected = 0;
  for (const span of spans) {
    if (span.start < expected) {
      throw new ArchiveError(`zip entry ${shown(span.name)} overlaps the entry before it (zip bomb construction)`, "ARCHIVE_OVERLAP");
    }
    if (span.start > expected) {
      throw new ArchiveError(
        `zip archive has ${span.start - expected} unreferenced byte(s) before entry ${shown(span.name)}`,
        "ARCHIVE_UNREFERENCED",
      );
    }
    expected = span.end;
  }
  if (expected !== cdOffset) {
    throw new ArchiveError(`zip archive has ${cdOffset - expected} unreferenced byte(s) before its central directory`, "ARCHIVE_UNREFERENCED");
  }
  if (cdOffset + cdSize !== eocd) {
    throw new ArchiveError("zip archive has data between its central directory and its end record", "ARCHIVE_UNREFERENCED");
  }
  const plan: ArchivePlan = { format: "zip", entries, skipped };
  checkPlan(plan);
  return plan;
}

// ---------------------------------------------------------------------------
// Tar (POSIX ustar, pax extended headers, GNU long names)
// ---------------------------------------------------------------------------

function cString(block: Buffer, start: number, length: number): Buffer {
  const field = block.subarray(start, start + length);
  const nul = field.indexOf(0);
  return nul < 0 ? field : field.subarray(0, nul);
}

function parseOctal(block: Buffer, start: number, length: number, what: string): number {
  const field = block.subarray(start, start + length);
  if (((field[0] as number) & 0x80) !== 0) {
    // GNU base-256: only small positive values are accepted.
    if ((field[0] as number) !== 0x80) throw new ArchiveError(`tar ${what} field out of range`, "ARCHIVE_MALFORMED");
    let value = 0;
    for (let i = 1; i < field.length; i += 1) {
      value = value * 256 + (field[i] as number);
      if (value > Number.MAX_SAFE_INTEGER / 256) throw new ArchiveError(`tar ${what} field out of range`, "ARCHIVE_MALFORMED");
    }
    return value;
  }
  const text = field.toString("latin1").replace(/\0.*$/s, "").trim();
  if (text === "") return 0;
  if (!/^[0-7]{1,12}$/.test(text)) throw new ArchiveError(`tar ${what} field is not octal`, "ARCHIVE_MALFORMED");
  return parseInt(text, 8);
}

function checksumOk(block: Buffer): boolean {
  const stored = parseOctal(block, 148, 8, "checksum");
  let unsigned = 0;
  let signed = 0;
  for (let i = 0; i < 512; i += 1) {
    const byte = i >= 148 && i < 156 ? 0x20 : (block[i] as number);
    unsigned += byte;
    signed += byte > 127 ? byte - 256 : byte;
  }
  return stored === unsigned || stored === signed;
}

function parsePax(data: Buffer): Map<string, string> {
  const records = new Map<string, string>();
  let at = 0;
  while (at < data.length) {
    const space = data.indexOf(0x20, at);
    if (space < 0) break;
    const length = Number(data.subarray(at, space).toString("latin1"));
    if (!Number.isSafeInteger(length) || length <= 0 || at + length > data.length) {
      throw new ArchiveError("tar pax header is malformed", "ARCHIVE_MALFORMED");
    }
    const record = data.subarray(space + 1, at + length - 1);
    const equals = record.indexOf(0x3d);
    if (equals > 0) {
      const key = decodeName(record.subarray(0, equals), "tar pax key");
      records.set(key, decodeName(record.subarray(equals + 1), "tar"));
    }
    at += length;
  }
  return records;
}

/** Plan the extraction of an uncompressed tar archive held in `buffer`. */
export function planTar(buffer: Buffer, format: ArchiveFormat = "tar"): ArchivePlan {
  const entries: PlannedEntry[] = [];
  const skipped: ArchiveSkip[] = [];
  let declaredTotal = 0;
  let offset = 0;
  let pax: Map<string, string> | undefined;
  let longName: string | undefined;
  let count = 0;
  let ended = false;
  while (offset + 512 <= buffer.length) {
    const block = buffer.subarray(offset, offset + 512);
    if (block.every((byte) => byte === 0)) {
      ended = true;
      break;
    }
    if (!checksumOk(block)) throw new ArchiveError("tar header checksum mismatch", "ARCHIVE_MALFORMED");
    const typeflag = String.fromCharCode(block[156] as number);
    const magic = block.subarray(257, 263).toString("latin1");
    let size = parseOctal(block, 124, 12, "size");
    if (pax?.has("size")) {
      const text = pax.get("size") as string;
      const paxSize = /^[0-9]{1,15}$/.test(text) ? Number(text) : Number.NaN;
      if (!Number.isSafeInteger(paxSize) || paxSize < 0) throw new ArchiveError("tar pax size is invalid", "ARCHIVE_MALFORMED");
      size = paxSize;
    }
    const dataStart = offset + 512;
    const dataEnd = dataStart + size;
    if (dataEnd > buffer.length) throw new ArchiveError("tar archive is truncated", "ARCHIVE_MALFORMED");
    offset = dataStart + Math.ceil(size / 512) * 512;

    if (typeflag === "x" || typeflag === "L" || typeflag === "K" || typeflag === "g") {
      if (size > 1024 * 1024) throw new ArchiveError("tar metadata header is too large", "ARCHIVE_MALFORMED");
      const data = buffer.subarray(dataStart, dataEnd);
      if (typeflag === "x") pax = parsePax(data);
      else if (typeflag === "L") longName = decodeName(cString(data, 0, data.length), "tar");
      // `K` (GNU long link name) only matters for links, which are refused;
      // `g` (pax global header) is not applied to entry names.
      continue;
    }

    count += 1;
    if (count > ARCHIVE_MAX_ENTRIES) {
      throw new ArchiveError(`archive has more than ${ARCHIVE_MAX_ENTRIES} entries`, "ARCHIVE_TOO_MANY_ENTRIES");
    }
    let rawName = decodeName(cString(block, 0, 100), "tar");
    if (magic === "ustar\0") {
      const prefix = decodeName(cString(block, 345, 155), "tar");
      if (prefix) rawName = `${prefix}/${rawName}`;
    }
    if (longName !== undefined) rawName = longName;
    if (pax?.has("path")) rawName = pax.get("path") as string;
    pax = undefined;
    longName = undefined;

    if (typeflag === "1") throw new ArchiveError(`tar entry ${shown(rawName)} is a hard link`, "ARCHIVE_LINK");
    if (typeflag === "2") throw new ArchiveError(`tar entry ${shown(rawName)} is a symbolic link`, "ARCHIVE_LINK");
    if (typeflag === "3" || typeflag === "4" || typeflag === "6") {
      throw new ArchiveError(`tar entry ${shown(rawName)} is a device or FIFO`, "ARCHIVE_SPECIAL_FILE");
    }
    const relPath = normalizeArchivePath(rawName);
    // Old (pre-POSIX) tar writes a directory as a regular entry whose name ends in '/'.
    if (typeflag === "5" || (rawName.endsWith("/") && size === 0 && (typeflag === "0" || typeflag === "\0"))) {
      if (relPath !== "") entries.push({ path: relPath, type: "directory", size: 0 });
      continue;
    }
    if (relPath === "") throw new ArchiveError(`tar entry ${shown(rawName)} has an empty path`, "ARCHIVE_BAD_PATH");
    if (typeflag !== "0" && typeflag !== "\0" && typeflag !== "7") {
      skipped.push({ path: relPath, reason: `unsupported tar entry type ${JSON.stringify(typeflag)} (not unpacked)` });
      continue;
    }
    declaredTotal += size;
    if (declaredTotal > ARCHIVE_MAX_TOTAL_BYTES) {
      throw new ArchiveError(
        `archive unpacks to more than ${ARCHIVE_MAX_TOTAL_BYTES / 1024 / 1024} MiB`,
        "ARCHIVE_TOO_LARGE",
      );
    }
    if (size > ARCHIVE_MAX_FILE_BYTES) {
      skipped.push({ path: relPath, reason: `file exceeds the ${ARCHIVE_MAX_FILE_BYTES / 1024 / 1024} MiB limit (not unpacked)` });
      continue;
    }
    const start = dataStart;
    const end = dataEnd;
    entries.push({ path: relPath, type: "file", size, read: () => Buffer.from(buffer.subarray(start, end)) });
  }
  if (!ended && entries.length === 0 && skipped.length === 0) {
    throw new ArchiveError("not a tar archive", "ARCHIVE_MALFORMED");
  }
  const plan: ArchivePlan = { format, entries, skipped };
  checkPlan(plan);
  return plan;
}

/** Gunzip `buffer` with an output cap, then plan it as a tar archive. */
export function planTarGz(buffer: Buffer): ArchivePlan {
  // Room for the contents plus one header and padding block per entry.
  const cap = ARCHIVE_MAX_TOTAL_BYTES + (ARCHIVE_MAX_ENTRIES + 16) * 1024;
  let tar: Buffer;
  try {
    tar = zlib.gunzipSync(buffer, { maxOutputLength: cap });
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ERR_BUFFER_TOO_LARGE" || (error instanceof RangeError)) {
      throw new ArchiveError(
        `archive unpacks to more than ${ARCHIVE_MAX_TOTAL_BYTES / 1024 / 1024} MiB`,
        "ARCHIVE_TOO_LARGE",
      );
    }
    throw new ArchiveError("not a gzip-compressed archive", "ARCHIVE_MALFORMED");
  }
  // The gzip stream as a whole: a tarball of text compresses about 3-10:1,
  // padding included. More than 100:1 over a megabyte is a bomb.
  if (tar.length > ARCHIVE_MAX_FILE_BYTES && tar.length > ARCHIVE_MAX_RATIO * buffer.length) {
    throw new ArchiveError(`archive compression ratio exceeds ${ARCHIVE_MAX_RATIO}:1`, "ARCHIVE_RATIO");
  }
  return planTar(tar, "tar.gz");
}

export function planArchive(buffer: Buffer, format: ArchiveFormat): ArchivePlan {
  if (format === "zip") return planZip(buffer);
  if (format === "tar.gz") return planTarGz(buffer);
  return planTar(buffer, "tar");
}

const O_NOFOLLOW: number =
  typeof fs.constants.O_NOFOLLOW === "number" ? fs.constants.O_NOFOLLOW : 0;

/**
 * Unpack a planned archive into `destination`, an empty directory the caller
 * created. Nothing is written when the plan was refused; an inconsistent
 * entry found while unpacking throws (the caller removes the directory).
 */
export function extractPlan(plan: ArchivePlan, destination: string): ExtractResult {
  const root = fs.realpathSync.native(destination);
  if (fs.readdirSync(root).length > 0) {
    throw new ArchiveError(`destination ${root} is not empty`, "ARCHIVE_DESTINATION");
  }
  let files = 0;
  let directories = 0;
  let bytes = 0;
  const written: string[] = [];
  for (const entry of plan.entries) {
    const target = path.join(root, entry.path.split("/").join(path.sep));
    if (entry.type === "directory") {
      ensureDirInside(root, target);
      directories += 1;
      continue;
    }
    const data = (entry.read as () => Buffer)();
    bytes += data.length;
    if (bytes > ARCHIVE_MAX_TOTAL_BYTES) {
      throw new ArchiveError(`archive unpacks to more than ${ARCHIVE_MAX_TOTAL_BYTES / 1024 / 1024} MiB`, "ARCHIVE_TOO_LARGE");
    }
    const parent = ensureDirInside(root, path.dirname(target));
    const file = path.join(parent, path.basename(target));
    let fd: number;
    try {
      fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | O_NOFOLLOW, 0o644);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      throw new ArchiveError(`cannot create ${shown(entry.path)}: ${code ?? "error"}`, code === "EEXIST" ? "ARCHIVE_DUPLICATE_PATH" : "ARCHIVE_WRITE");
    }
    try {
      fs.writeFileSync(fd, data);
    } finally {
      fs.closeSync(fd);
    }
    files += 1;
    written.push(entry.path);
  }
  // Every file is where its name says, inside the destination.
  for (const relPath of written) {
    resolveInside(root, relPath);
  }
  return { format: plan.format, files, directories, bytes, skipped: plan.skipped };
}

/**
 * Read `archive` (a regular file, not followed through a symbolic link) and
 * unpack it into `destination`.
 */
export function extractArchive(archive: string, destination: string, format?: ArchiveFormat): ExtractResult {
  const kind = format ?? archiveFormatOf(archive);
  if (!kind) throw new ArchiveError(`not a supported archive name: ${archive}`, "ARCHIVE_UNSUPPORTED");
  let fd: number;
  try {
    fd = fs.openSync(archive, fs.constants.O_RDONLY | O_NOFOLLOW);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    throw new ArchiveError(
      code === "ELOOP" ? `refusing to read the archive through a symbolic link: ${archive}` : `cannot read ${archive}: ${code ?? "error"}`,
      "ARCHIVE_READ",
    );
  }
  let buffer: Buffer;
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile()) throw new ArchiveError(`not a regular file: ${archive}`, "ARCHIVE_READ");
    if (stat.size > ARCHIVE_MAX_INPUT_BYTES) {
      throw new ArchiveError(`archive is larger than ${ARCHIVE_MAX_INPUT_BYTES / 1024 / 1024} MiB`, "ARCHIVE_TOO_LARGE");
    }
    buffer = Buffer.alloc(stat.size);
    let offset = 0;
    while (offset < buffer.length) {
      const read = fs.readSync(fd, buffer, offset, buffer.length - offset, offset);
      if (read === 0) break;
      offset += read;
    }
    buffer = buffer.subarray(0, offset);
  } finally {
    fs.closeSync(fd);
  }
  return extractPlan(planArchive(buffer, kind), destination);
}
