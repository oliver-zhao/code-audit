/**
 * In-memory builders for zip and tar archives used by the tests. Malicious
 * archives are built here, at test time; no archive is committed.
 */
import zlib from "node:zlib";
import { crc32 } from "../src/archive.js";

export interface ZipEntrySpec {
  name: string;
  data?: Buffer | string;
  /** 0 store, 8 deflate (default), anything else is written as given. */
  method?: number;
  /** Unix mode (file type bits included); sets "made by" to Unix. */
  mode?: number;
  /** Declared uncompressed size instead of the real one. */
  declaredSize?: number;
  /** CRC-32 to write instead of the real one. */
  crc?: number;
  flags?: number;
  /** Extra field bytes for the central directory record. */
  extra?: Buffer;
  /** Name written into the local header instead of `name`. */
  localName?: string;
  /** Write the data region as given instead of compressing `data`. */
  rawData?: Buffer;
}

export function infoZipUnicodePath(name: string): Buffer {
  const nameBytes = Buffer.from(name, "utf8");
  const field = Buffer.alloc(4 + 5 + nameBytes.length);
  field.writeUInt16LE(0x7075, 0);
  field.writeUInt16LE(5 + nameBytes.length, 2);
  field.writeUInt8(1, 4);
  field.writeUInt32LE(crc32(nameBytes), 5);
  nameBytes.copy(field, 9);
  return field;
}

function localHeader(name: Buffer, method: number, crc: number, compressed: number, size: number, flags: number): Buffer {
  const header = Buffer.alloc(30);
  header.writeUInt32LE(0x04034b50, 0);
  header.writeUInt16LE(20, 4);
  header.writeUInt16LE(flags | 0x0800, 6);
  header.writeUInt16LE(method, 8);
  header.writeUInt32LE(crc, 14);
  header.writeUInt32LE(compressed, 18);
  header.writeUInt32LE(size, 22);
  header.writeUInt16LE(name.length, 26);
  header.writeUInt16LE(0, 28);
  return Buffer.concat([header, name]);
}

interface CentralSpec {
  name: Buffer;
  method: number;
  crc: number;
  compressed: number;
  size: number;
  flags: number;
  mode?: number;
  extra?: Buffer;
  offset: number;
}

function centralRecord(spec: CentralSpec): Buffer {
  const extra = spec.extra ?? Buffer.alloc(0);
  const record = Buffer.alloc(46);
  record.writeUInt32LE(0x02014b50, 0);
  record.writeUInt16LE(spec.mode !== undefined ? (3 << 8) | 20 : 20, 4);
  record.writeUInt16LE(20, 6);
  record.writeUInt16LE(spec.flags | 0x0800, 8);
  record.writeUInt16LE(spec.method, 10);
  record.writeUInt32LE(spec.crc, 16);
  record.writeUInt32LE(spec.compressed, 20);
  record.writeUInt32LE(spec.size, 24);
  record.writeUInt16LE(spec.name.length, 28);
  record.writeUInt16LE(extra.length, 30);
  record.writeUInt32LE(spec.mode !== undefined ? (spec.mode << 16) >>> 0 : 0, 38);
  record.writeUInt32LE(spec.offset, 42);
  return Buffer.concat([record, spec.name, extra]);
}

function endRecord(count: number, cdSize: number, cdOffset: number): Buffer {
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(count, 8);
  end.writeUInt16LE(count, 10);
  end.writeUInt32LE(cdSize, 12);
  end.writeUInt32LE(cdOffset, 16);
  return end;
}

export function buildZip(entries: ZipEntrySpec[]): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const entry of entries) {
    const data = typeof entry.data === "string" ? Buffer.from(entry.data, "utf8") : (entry.data ?? Buffer.alloc(0));
    const method = entry.method ?? (entry.name.endsWith("/") ? 0 : 8);
    const compressed = entry.rawData ?? (method === 8 ? zlib.deflateRawSync(data) : data);
    const name = Buffer.from(entry.name, "utf8");
    const crc = entry.crc ?? crc32(data);
    const size = entry.declaredSize ?? data.length;
    const flags = entry.flags ?? 0;
    const local = localHeader(Buffer.from(entry.localName ?? entry.name, "utf8"), method, crc, compressed.length, size, flags);
    locals.push(local, compressed);
    centrals.push(
      centralRecord({ name, method, crc, compressed: compressed.length, size, flags, mode: entry.mode, extra: entry.extra, offset }),
    );
    offset += local.length + compressed.length;
  }
  const cd = Buffer.concat(centrals);
  return Buffer.concat([...locals, cd, endRecord(entries.length, cd.length, offset)]);
}

/** Two entries whose data overlap: b.txt's local header lies inside a.txt's data. */
export function buildOverlappingZip(): Buffer {
  const bData = Buffer.from("inner", "utf8");
  const bName = Buffer.from("b.txt", "utf8");
  const bLocal = localHeader(bName, 0, crc32(bData), bData.length, bData.length, 0);
  const aData = Buffer.concat([bLocal, bData]);
  const aName = Buffer.from("a.txt", "utf8");
  const aLocal = localHeader(aName, 0, crc32(aData), aData.length, aData.length, 0);
  const archive = Buffer.concat([aLocal, aData]);
  const cd = Buffer.concat([
    centralRecord({ name: aName, method: 0, crc: crc32(aData), compressed: aData.length, size: aData.length, flags: 0, offset: 0 }),
    centralRecord({
      name: bName,
      method: 0,
      crc: crc32(bData),
      compressed: bData.length,
      size: bData.length,
      flags: 0,
      offset: aLocal.length,
    }),
  ]);
  return Buffer.concat([archive, cd, endRecord(2, cd.length, archive.length)]);
}

export interface TarEntrySpec {
  name: string;
  data?: Buffer | string;
  /** Tar type flag, default "0" (or "5" for a name ending in /). */
  type?: string;
  linkname?: string;
  /** Size to write in the header instead of the real one. */
  size?: number;
  /** Break the header checksum. */
  badChecksum?: boolean;
}

function octal(value: number, length: number): string {
  return `${value.toString(8).padStart(length - 1, "0")}\0`;
}

function tarHeader(name: string, size: number, type: string, linkname = "", badChecksum = false): Buffer {
  const header = Buffer.alloc(512);
  header.write(name, 0, 100, "utf8");
  header.write(octal(0o644, 8), 100, "latin1");
  header.write(octal(0, 8), 108, "latin1");
  header.write(octal(0, 8), 116, "latin1");
  header.write(octal(size, 12), 124, "latin1");
  header.write(octal(0, 12), 136, "latin1");
  header.write("        ", 148, "latin1");
  header.write(type, 156, "latin1");
  header.write(linkname, 157, 100, "utf8");
  header.write("ustar\0", 257, "latin1");
  header.write("00", 263, "latin1");
  let sum = 0;
  for (const byte of header) sum += byte;
  header.write(`${(badChecksum ? sum + 1 : sum).toString(8).padStart(6, "0")}\0 `, 148, "latin1");
  return header;
}

function padded(data: Buffer): Buffer {
  const remainder = data.length % 512;
  return remainder === 0 ? data : Buffer.concat([data, Buffer.alloc(512 - remainder)]);
}

export function paxRecord(key: string, value: string): string {
  const body = ` ${key}=${value}\n`;
  let length = body.length + 1;
  while (`${length}${body}`.length !== length) length += 1;
  return `${length}${body}`;
}

export function buildTar(entries: TarEntrySpec[]): Buffer {
  const parts: Buffer[] = [];
  for (const entry of entries) {
    const data = typeof entry.data === "string" ? Buffer.from(entry.data, "utf8") : (entry.data ?? Buffer.alloc(0));
    const type = entry.type ?? (entry.name.endsWith("/") ? "5" : "0");
    parts.push(tarHeader(entry.name, entry.size ?? data.length, type, entry.linkname, entry.badChecksum));
    if (data.length > 0) parts.push(padded(data));
  }
  parts.push(Buffer.alloc(1024));
  return Buffer.concat(parts);
}

export function buildTarGz(entries: TarEntrySpec[]): Buffer {
  return zlib.gzipSync(buildTar(entries));
}
