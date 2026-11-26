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
 * Resolve a path even when the leaf does not exist yet. Every existing
 * component is passed through realpath(), so symlinked parents cannot escape.
 */
function realpathLoose(target: string): string {
  try {
    return fs.realpathSync(target);
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
    return fs.realpathSync(home);
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
 */
export function validateAuditRoot(root: string): ValidatedRoot {
  const input = path.resolve(root);
  const stat = safeLstat(input);
  if (!stat) {
    throw new PathJailError(`audit root does not exist: ${root}`, "ROOT_MISSING");
  }
  if (!stat.isDirectory()) {
    throw new PathJailError(`audit root is not a directory: ${root}`, "ROOT_NOT_DIRECTORY");
  }

  const real = fs.realpathSync(input);
  const fsRoot = path.parse(real).root;
  if (real === fsRoot) {
    throw new PathJailError("refusing the filesystem root as the audit root", "ROOT_FORBIDDEN");
  }
  if (real === homeRealpath()) {
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
