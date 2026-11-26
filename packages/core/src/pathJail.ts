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
 * Directories that hold credentials and machine configuration, relative to
 * the user's home directory. A directory at or below one of them is not an
 * audit root unless the user says so (`--allow-sensitive-root`): an audit
 * makes every text file below the root readable through `read` / `search`,
 * and writes `.audit/` into it.
 */
export const SENSITIVE_HOME_DIRECTORIES = [
  ".ssh",
  ".aws",
  ".gnupg",
  ".config",
  ".kube",
  ".docker",
  ".azure",
  ".oci",
  ".password-store",
  ".terraform.d",
  ".local/share/keyrings",
  ".claude",
  ".codex",
  "Library",
  "AppData",
] as const;

/** The same, as absolute paths. */
export const SENSITIVE_SYSTEM_DIRECTORIES = [
  "/etc",
  "/private/etc",
  "/root",
  "/var/root",
  "/proc",
  "/sys",
  "/dev",
  "/boot",
  "/run/secrets",
  "/var/run/secrets",
] as const;

function canonicalOrResolved(target: string): string {
  try {
    return realpathCanonical(target);
  } catch {
    return path.resolve(target);
  }
}

/**
 * The credential directory that `real` (a canonical path) is, or is inside
 * of; undefined when there is none.
 */
export function sensitiveDirectoryOf(real: string): string | undefined {
  const home = homeRealpath();
  const candidates = [
    ...SENSITIVE_HOME_DIRECTORIES.map((name) => path.join(home, ...name.split("/"))),
    // A system directory that contains the home directory (HOME=/root for
    // root) says nothing about a project below that home.
    ...(process.platform === "win32" ? [] : SENSITIVE_SYSTEM_DIRECTORIES).filter(
      (dir) => !isInside(canonicalOrResolved(dir), home),
    ),
  ];
  for (const candidate of candidates) {
    const canonical = canonicalOrResolved(candidate);
    if (isInside(canonical, real) || sameFile(canonical, real)) return candidate;
  }
  return undefined;
}

/**
 * Sensitive roots a human allowed in this process (`--allow-sensitive-root`),
 * as canonical paths. Only these exact directories are exempt.
 */
const allowedSensitiveRoots = new Set<string>();

/**
 * Record that the user explicitly allowed `root` although it is, or is inside,
 * a credential directory. For the command line only: the MCP server never
 * calls this, because its arguments are chosen by a model.
 */
export function allowSensitiveRoot(root: string): void {
  allowedSensitiveRoots.add(canonicalOrResolved(path.resolve(root)));
}

/** Forget every exemption (tests). */
export function resetAllowedSensitiveRoots(): void {
  allowedSensitiveRoots.clear();
}

export interface ValidateRootOptions {
  /**
   * Accept a root at or below a credential directory without it having been
   * allowed with `allowSensitiveRoot`. For code that does not read the tree.
   */
  allowSensitive?: boolean;
}

/**
 * Validate that a directory is safe to use as an audit root. Refused: the
 * filesystem root, the current user's home directory and every directory
 * that contains it, and - unless allowed - well-known credential and
 * configuration directories (`~/.ssh`, `~/.aws`, `~/.config`, `/etc`, ...;
 * see `SENSITIVE_HOME_DIRECTORIES`) and everything below them.
 *
 * The root is chosen by the user and may be a symbolic link or live below one
 * (macOS: `/tmp` -> `/private/tmp`, `/var` -> `/private/var`). It is followed
 * and the returned `root` is always the canonical real path; every check here
 * and every later comparison is made against that value, never against
 * `input`.
 */
export function validateAuditRoot(root: string, options: ValidateRootOptions = {}): ValidatedRoot {
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
  if (isInside(real, home)) {
    throw new PathJailError(
      `refusing a directory that contains the user home directory as the audit root: ${real}`,
      "ROOT_FORBIDDEN",
    );
  }
  if (!options.allowSensitive && !allowedSensitiveRoots.has(real)) {
    const sensitive = sensitiveDirectoryOf(real);
    if (sensitive !== undefined) {
      throw new PathJailError(
        `refusing ${real} as the audit root: it is ${
          canonicalOrResolved(sensitive) === real ? "" : "inside "
        }${sensitive}, a directory that usually holds credentials or machine configuration. ` +
          "On the command line, pass --allow-sensitive-root to audit it anyway; the MCP server never does",
        "ROOT_SENSITIVE",
      );
    }
  }
  return { root: real, input };
}

/**
 * Canonical path of `target` (resolved against `base` when relative; the
 * leaf may not exist yet), verified to be `base` itself or inside it with
 * every symbolic link followed. `base` must be a canonical path. Used by the
 * MCP server to contain every path argument in its base directory.
 */
export function resolveWithinBase(base: string, target: string, what = "path"): string {
  const candidate = path.isAbsolute(target) ? path.resolve(target) : path.resolve(base, target);
  const resolved = realpathLoose(candidate);
  if (!isInside(base, resolved)) {
    throw new PathJailError(
      `${what} is outside the base directory of this server: ${target}${
        resolved === target ? "" : ` (-> ${resolved})`
      } is not inside ${base}`,
      "OUTSIDE_BASE",
    );
  }
  return resolved;
}

/** True when `target` is `base` or below it (both canonical paths). */
export function isInsideCanonical(base: string, target: string): boolean {
  return isInside(base, target);
}

/** Canonical real path of the current user's home directory. */
export function homeDirectoryCanonical(): string {
  return homeRealpath();
}

/**
 * Resolve `p` against `root` and verify the real path stays inside the root.
 * Absolute paths, `../` traversal, and symlinks pointing outside are rejected.
 */
export function resolveInside(root: string, p: string): string {
  // The jail of a root that an entry point has already accepted: whether a
  // credential directory may be a root is decided there, not per path.
  const validated = validateAuditRoot(root, { allowSensitive: true });
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
