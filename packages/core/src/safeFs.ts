/**
 * File-system writes and reads that do not follow symbolic links planted in
 * an audited repository.
 *
 * Everything below `.audit/`, a run directory or the audit root may have been
 * prepared by someone else. A plain `writeFileSync(path)` follows a symbolic
 * link at `path` and overwrites its target, and `mkdirSync(..., { recursive })`
 * walks through symlinked directories. Every file the tool writes goes through
 * the helpers here instead.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export class SafeFsError extends Error {
  readonly code: string;

  constructor(message: string, code = "UNSAFE_PATH") {
    super(message);
    this.name = "SafeFsError";
    this.code = code;
  }
}

/** `O_NOFOLLOW` where the platform has it (not on Windows). */
const O_NOFOLLOW: number =
  typeof fs.constants.O_NOFOLLOW === "number" ? fs.constants.O_NOFOLLOW : 0;

function lstatOrUndefined(target: string): fs.Stats | undefined {
  try {
    return fs.lstatSync(target);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "ENOTDIR") return undefined;
    throw error;
  }
}

/** Canonical path with the on-disk spelling of every component. */
export function canonicalPath(target: string): string {
  return fs.realpathSync.native(target);
}

/** True when `child` is `parent` or below it. Both must be canonical. */
export function isPathInside(parent: string, child: string): boolean {
  const relative = path.relative(parent, child);
  return (
    relative === "" ||
    (relative !== ".." &&
      !relative.startsWith(`..${path.sep}`) &&
      !path.isAbsolute(relative))
  );
}

/** Text from a file inside an audited repository, safe to print in a message. */
export function printable(value: unknown, max = 200): string {
  const text = (typeof value === "string" ? value : String(value)).slice(0, max * 2 + 8);
  // Control characters (terminal escapes, newlines) never reach the terminal.
  const clean = Array.from(text, (char) => {
    const code = char.codePointAt(0) ?? 0;
    const control =
      code < 0x20 || (code >= 0x7f && code <= 0x9f) || code === 0x2028 || code === 0x2029;
    return control ? "?" : char;
  }).join("");
  return clean.length > max ? `${clean.slice(0, max)}...` : clean;
}

export interface AtomicWriteOptions {
  /**
   * The directory the file is meant to be written to, as a canonical path.
   * The write is refused when the real path of the destination's parent is
   * any other directory, that is when a component of the path is a symbolic
   * link. Without it the parent is a path the user named and is followed.
   */
  expectedDir?: string;
  /** Mode of a newly created file; defaults to 0o644 (before umask). */
  mode?: number;
}

/**
 * Write `data` to `file` without following a symbolic link at `file`.
 *
 * The data goes to a new temporary file in the same directory, created with
 * `O_EXCL` (and `O_NOFOLLOW`), which is then renamed over the destination.
 * `rename` replaces a symbolic link at the destination instead of writing
 * through it. Returns the path that was written.
 */
export function writeFileAtomicNoFollow(
  file: string,
  data: string | Uint8Array,
  options: AtomicWriteOptions = {},
): string {
  const target = path.resolve(file);
  const name = path.basename(target);
  if (!name || name === "." || name === "..") {
    throw new SafeFsError(`not a file path: ${file}`, "INVALID_PATH");
  }
  let parent: string;
  try {
    parent = canonicalPath(path.dirname(target));
  } catch (error) {
    throw new SafeFsError(
      `cannot write ${file}: its directory does not exist or cannot be resolved (${
        (error as NodeJS.ErrnoException).code ?? "error"
      })`,
      "PARENT_MISSING",
    );
  }
  if (options.expectedDir !== undefined && parent !== path.resolve(options.expectedDir)) {
    throw new SafeFsError(
      `refusing to write ${name}: ${path.dirname(target)} resolves to ${parent}, not to ${options.expectedDir} (a symbolic link is in the way)`,
      "PARENT_REDIRECTED",
    );
  }
  const destination = path.join(parent, name);
  const existing = lstatOrUndefined(destination);
  if (existing?.isDirectory()) {
    throw new SafeFsError(`refusing to replace a directory with a file: ${destination}`, "IS_DIRECTORY");
  }
  const temp = path.join(
    parent,
    `${name}.tmp-${process.pid}-${crypto.randomBytes(6).toString("hex")}`,
  );
  let fd: number | undefined;
  try {
    fd = fs.openSync(
      temp,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | O_NOFOLLOW,
      options.mode ?? 0o644,
    );
    fs.writeFileSync(fd, data);
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(temp, destination);
  } catch (error) {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch {
        // already closed
      }
    }
    try {
      fs.unlinkSync(temp);
    } catch {
      // nothing to remove
    }
    throw error;
  }
  return destination;
}

/**
 * Append to a file without following a symbolic link at its path. The file is
 * created when it does not exist.
 */
export function appendFileNoFollow(file: string, data: string | Uint8Array): void {
  const target = path.resolve(file);
  if (O_NOFOLLOW === 0 && lstatOrUndefined(target)?.isSymbolicLink()) {
    throw new SafeFsError(`refusing to append through a symbolic link: ${file}`, "SYMLINK");
  }
  let fd: number;
  try {
    fd = fs.openSync(
      target,
      fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_CREAT | O_NOFOLLOW,
      0o644,
    );
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ELOOP" || code === "EMLINK") {
      throw new SafeFsError(`refusing to append through a symbolic link: ${file}`, "SYMLINK");
    }
    throw error;
  }
  try {
    if (!fs.fstatSync(fd).isFile()) {
      throw new SafeFsError(`refusing to append to something that is not a regular file: ${file}`, "NOT_A_FILE");
    }
    fs.writeFileSync(fd, data);
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Read a regular file without following a symbolic link at its path. Returns
 * undefined when the file does not exist.
 */
export function readFileNoFollow(file: string, maxBytes: number): Buffer | undefined {
  const target = path.resolve(file);
  if (O_NOFOLLOW === 0 && lstatOrUndefined(target)?.isSymbolicLink()) {
    throw new SafeFsError(`refusing to read through a symbolic link: ${file}`, "SYMLINK");
  }
  let fd: number;
  try {
    fd = fs.openSync(target, fs.constants.O_RDONLY | O_NOFOLLOW);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "ENOTDIR") return undefined;
    if (code === "ELOOP" || code === "EMLINK") {
      throw new SafeFsError(`refusing to read through a symbolic link: ${file}`, "SYMLINK");
    }
    throw new SafeFsError(`cannot read ${file}: ${code ?? "error"}`, "READ_FAILED");
  }
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile()) {
      throw new SafeFsError(`not a regular file: ${file}`, "NOT_A_FILE");
    }
    if (stat.size > maxBytes) {
      throw new SafeFsError(
        `${file} is larger than the ${maxBytes} byte limit (${stat.size} bytes)`,
        "TOO_LARGE",
      );
    }
    const buffer = Buffer.alloc(stat.size);
    let offset = 0;
    while (offset < buffer.length) {
      const read = fs.readSync(fd, buffer, offset, buffer.length - offset, offset);
      if (read === 0) break;
      offset += read;
    }
    return offset === buffer.length ? buffer : buffer.subarray(0, offset);
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Create `target` below `base` one component at a time and return its
 * canonical path. `base` must exist. A component that already exists as a
 * symbolic link is followed only when it stays inside `base`; one that leaves
 * it is refused, so the tool never creates or writes files outside `base`
 * through a link planted below it.
 */
export function ensureDirInside(base: string, target: string): string {
  let baseReal: string;
  try {
    baseReal = canonicalPath(base);
  } catch {
    throw new SafeFsError(`directory does not exist: ${base}`, "PARENT_MISSING");
  }
  const lexicalBases = [path.resolve(base), baseReal];
  const absolute = path.resolve(target);
  let relative: string | undefined;
  for (const candidate of lexicalBases) {
    const rel = path.relative(candidate, absolute);
    if (rel === "" || (rel !== ".." && !rel.startsWith(`..${path.sep}`) && !path.isAbsolute(rel))) {
      relative = rel;
      break;
    }
  }
  if (relative === undefined) {
    throw new SafeFsError(`${target} is not inside ${base}`, "PATH_OUTSIDE");
  }
  let current = baseReal;
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    const next = path.join(current, segment);
    let stat = lstatOrUndefined(next);
    if (!stat) {
      try {
        fs.mkdirSync(next);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      }
      stat = lstatOrUndefined(next);
      if (!stat) throw new SafeFsError(`cannot create directory ${next}`, "MKDIR_FAILED");
    }
    if (stat.isSymbolicLink()) {
      let real: string;
      try {
        real = canonicalPath(next);
      } catch {
        throw new SafeFsError(
          `refusing to write through ${next}: it is a broken symbolic link`,
          "SYMLINK_ESCAPE",
        );
      }
      if (!isPathInside(baseReal, real)) {
        throw new SafeFsError(
          `refusing to write through ${next}: it is a symbolic link that leaves ${baseReal} (-> ${real})`,
          "SYMLINK_ESCAPE",
        );
      }
      if (!fs.statSync(real).isDirectory()) {
        throw new SafeFsError(`not a directory: ${next}`, "NOT_A_DIRECTORY");
      }
      current = real;
    } else if (stat.isDirectory()) {
      current = next;
    } else {
      throw new SafeFsError(`not a directory: ${next}`, "NOT_A_DIRECTORY");
    }
  }
  return current;
}
