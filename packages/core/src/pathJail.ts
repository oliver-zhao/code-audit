import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export class PathJailError extends Error {
  readonly code: string;

  constructor(message: string, code = "PATH_JAIL") {
    super(message);
    this.name = "PathJailError";
    this.code = code;
  }
}

function safeLstat(target: string): fs.Stats | undefined {
  try {
    return fs.lstatSync(target);
  } catch (error) {
    const err = error as NodeJS.ErrnoException;
    if (err.code === "ENOENT" || err.code === "ENOTDIR") return undefined;
    throw error;
  }
}

/**
 * Canonical real path. The native implementation is used on purpose: unlike
 * the JavaScript `fs.realpathSync`, it also returns the on-disk spelling of
 * every component on case-insensitive (macOS, Windows) and
 * normalization-insensitive filesystems, so two spellings of one directory
 * compare equal as strings after this call.
 */
function realpathCanonical(target: string): string {
  return fs.realpathSync.native(target);
}

/** True when both paths exist and refer to the same filesystem object. */
function sameFile(a: string, b: string): boolean {
  try {
    const left = fs.statSync(a, { bigint: true });
    const right = fs.statSync(b, { bigint: true });
    return left.dev === right.dev && left.ino === right.ino && left.ino !== 0n;
  } catch {
    return false;
  }
}

/**
 * Resolve a path even when the leaf does not exist yet. Every existing
 * component is passed through realpath(), so symlinked parents cannot escape.
 */
function realpathLoose(target: string): string {
  try {
    return realpathCanonical(target);
  } catch (error) {
    const err = error as NodeJS.ErrnoException;
    if (err.code !== "ENOENT" && err.code !== "ENOTDIR") throw error;

    const stat = safeLstat(target);
    if (stat?.isSymbolicLink()) {
      throw new PathJailError(
        `refusing a broken or out-of-root symbolic link: ${target}`,
        "BROKEN_SYMLINK",
      );
    }

    const parent = path.dirname(target);
    if (parent === target) throw error;
    return path.join(realpathLoose(parent), path.basename(target));
  }
}

function homeRealpath(): string {
  const home = os.homedir();
  try {
    return realpathCanonical(home);
  } catch {
    return path.resolve(home);
  }
}

function isInside(root: string, target: string): boolean {
  const rel = path.relative(root, target);
  return (
    rel === "" ||
    (rel !== ".." && !rel.startsWith(`..${path.sep}`) && !path.isAbsolute(rel))
  );
}

export interface ValidatedRoot {
  /** Absolute, real path of the audit root. */
  root: string;
  /** Original path passed by the caller. */
  input: string;
}

/**
 * Validate that a directory is safe to use as an audit root. Filesystem root
 * and the current user's home directory are refused.
 *
 * The root is chosen by the user and may be a symbolic link or live below one
 * (macOS: `/tmp` -> `/private/tmp`, `/var` -> `/private/var`). It is followed
 * and the returned `root` is always the canonical real path; every later
 * comparison must be made against that value, never against `input`.
 */
export function validateAuditRoot(root: string): ValidatedRoot {
  const input = path.resolve(root);
  let stat: fs.Stats;
  try {
    // stat(), not lstat(): a root that is itself a symlink to a directory is
    // legitimate. A dangling symlink fails here like a missing directory.
    stat = fs.statSync(input);
  } catch (error) {
    const err = error as NodeJS.ErrnoException;
    if (err.code === "ENOENT" || err.code === "ENOTDIR" || err.code === "ELOOP") {
      throw new PathJailError(`audit root does not exist: ${root}`, "ROOT_MISSING");
    }
    throw error;
  }
  if (!stat.isDirectory()) {
    throw new PathJailError(`audit root is not a directory: ${root}`, "ROOT_NOT_DIRECTORY");
  }

  const real = realpathCanonical(input);
  const fsRoot = path.parse(real).root;
  if (real === fsRoot) {
    throw new PathJailError("refusing the filesystem root as the audit root", "ROOT_FORBIDDEN");
  }
  // Compare by identity as well as by name so that a differently-cased or
  // differently-normalized spelling of the home directory is still refused.
  const home = homeRealpath();
  if (real === home || sameFile(real, home)) {
    throw new PathJailError("refusing the user home directory as the audit root", "ROOT_FORBIDDEN");
  }
  return { root: real, input };
}

/**
 * Resolve `p` against `root` and verify the real path stays inside the root.
 * Absolute paths, `../` traversal, and symlinks pointing outside are rejected.
 */
export function resolveInside(root: string, p: string): string {
  const validated = validateAuditRoot(root);
  const rootReal = validated.root;

  const candidate = path.isAbsolute(p)
    ? path.resolve(p)
    : path.resolve(rootReal, p);
  const resolved = realpathLoose(candidate);

  if (!isInside(rootReal, resolved)) {
    throw new PathJailError(
      `path escapes the audit root: ${p} -> ${resolved}`,
      "PATH_OUTSIDE_ROOT",
    );
  }
  return resolved;
}

/** Relative POSIX-style path, used in findings and reports. */
export function toPosixRelative(root: string, target: string): string {
  return path.relative(root, target).split(path.sep).join("/");
}
