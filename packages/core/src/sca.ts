import { splitLines } from "./redact.js";
import fs from "node:fs";
import path from "node:path";
import { parse as parseYaml } from "yaml";
import {
  createFinding,
  SEVERITY_ORDER,
  type Finding,
  type FindingInit,
  type Severity,
} from "./finding.js";
import type { InventoryResult, ManifestRef } from "./inventory.js";
import { isRequirementsLockfilePath } from "./inventory.js";
import { comparePypiVersions } from "./pypi.js";
import {
  PathJailError,
  resolveInside,
  toPosixRelative,
  validateAuditRoot,
} from "./pathJail.js";
import { parseTomlSubset, type TomlTable, type TomlValue } from "./toml.js";
import { compileGlob } from "./glob.js";

export type OsvEcosystem = "npm" | "PyPI" | "Go" | "Maven" | "NuGet" | "crates.io";

/**
 * How a package is used by the project, when the lockfile or manifest makes
 * that knowable: a runtime dependency, an optional extra, a development /
 * dependency-group dependency, or unknown.
 */
export type DependencyScope = "runtime" | "optional" | "dev" | "unknown";

export interface ScaPackage {
  name: string;
  version: string;
  ecosystem: OsvEcosystem;
  file: string;
  line: number;
  manager: string;
  direct: boolean;
  /** Dependency scope; absent means the parser does not determine it. */
  scope?: DependencyScope;
  /** True for development-only dependencies (same as `scope === "dev"`). */
  dev?: boolean;
}

export interface ParsedDependencies {
  packages: ScaPackage[];
  warnings: string[];
}

export interface HttpClient {
  postJson(
    url: string,
    body: unknown,
    options?: { timeoutMs?: number },
  ): Promise<unknown>;
  getJson(url: string, options?: { timeoutMs?: number }): Promise<unknown>;
}

export const fetchHttpClient: HttpClient = {
  async postJson(url, body, options = {}) {
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(options.timeoutMs ?? 10_000),
    });
    if (!response.ok) {
      throw new HttpError(response.status, response.statusText);
    }
    return response.json();
  },
  async getJson(url, options = {}) {
    const response = await fetch(url, {
      method: "GET",
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(options.timeoutMs ?? 10_000),
    });
    if (!response.ok) {
      throw new HttpError(response.status, response.statusText);
    }
    return response.json();
  },
};

export class HttpError extends Error {
  readonly status: number;

  constructor(status: number, statusText = "") {
    super(`HTTP ${status}${statusText ? ` ${statusText}` : ""}`);
    this.name = "HttpError";
    this.status = status;
  }
}

/**
 * Upper bounds on what one (untrusted) repository can make the SCA engine
 * hold in memory. A dependency file with more pins than this is not a real
 * project; the extra entries are dropped with a warning instead of being
 * queried.
 */
export const MAX_DEPENDENCIES_PER_FILE = 50_000;
export const MAX_DEPENDENCIES_PER_SCAN = 200_000;

/**
 * Append `items` to `target` one by one. `target.push(...items)` passes every
 * element as a call argument and throws "Maximum call stack size exceeded"
 * once `items` has roughly 100k entries, which an untrusted input can reach.
 */
function appendAll<T>(target: T[], items: readonly T[]): void {
  for (const item of items) target.push(item);
}

function findLine(content: string, needle: string, fallback = 1): number {
  const index = content.indexOf(needle);
  if (index < 0) return fallback;
  let line = 1;
  for (let i = 0; i < index; i += 1) {
    if (content.charCodeAt(i) === 10) line += 1;
  }
  return line;
}

function lineAt(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i += 1) {
    if (content.charCodeAt(i) === 10) line += 1;
  }
  return line;
}

/**
 * Normalize a package name for matching against OSV advisories.
 *
 * PyPI follows PEP 503: compare case-insensitively and treat any run of
 * `-`, `_`, and `.` as a single `-`. NuGet is case-insensitive. npm, Go and
 * Maven names are case-sensitive and are returned unchanged.
 */
export function normalizePackageName(name: string, ecosystem?: string): string {
  const eco = ecosystem?.toLowerCase();
  if (eco === "pypi") return name.toLowerCase().replace(/[-_.]+/g, "-");
  if (eco === "nuget") return name.toLowerCase();
  return name;
}

function packageKey(pkg: { name: string; version: string; ecosystem: string }): string {
  return `${pkg.ecosystem}\u0000${normalizePackageName(pkg.name, pkg.ecosystem)}\u0000${pkg.version}`;
}

/** One entry per (file, ecosystem, name, version). */
function uniqueOccurrences(packages: ScaPackage[]): ScaPackage[] {
  const seen = new Set<string>();
  const result: ScaPackage[] = [];
  for (const pkg of packages) {
    const key = `${pkg.file}\u0000${packageKey(pkg)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(pkg);
  }
  return result;
}

function pushUnique(packages: ScaPackage[]): ScaPackage[] {
  const seen = new Set<string>();
  const result: ScaPackage[] = [];
  for (const pkg of packages) {
    const key = packageKey(pkg);
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(pkg);
  }
  return result;
}

export function parsePackageLock(
  content: string,
  file: string,
): ParsedDependencies {
  const warnings: string[] = [];
  let document: Record<string, unknown>;
  try {
    document = JSON.parse(content) as Record<string, unknown>;
  } catch (error) {
    return {
      packages: [],
      warnings: [
        `package-lock.json parse failed (${file}): ${error instanceof Error ? error.message : String(error)}`,
      ],
    };
  }

  const packages: ScaPackage[] = [];
  const packagesSection = document.packages;
  if (packagesSection && typeof packagesSection === "object") {
    for (const [key, value] of Object.entries(
      packagesSection as Record<string, unknown>,
    )) {
      if (!key) continue;
      if (!value || typeof value !== "object") continue;
      const entry = value as Record<string, unknown>;
      const version = entry.version;
      if (typeof version !== "string") continue;
      const marker = "node_modules/";
      const markerIndex = key.lastIndexOf(marker);
      const name = markerIndex >= 0 ? key.slice(markerIndex + marker.length) : key;
      if (!name) continue;
      const direct = key === `node_modules/${name}`;
      packages.push({
        name,
        version,
        ecosystem: "npm",
        file,
        line: findLine(content, `"${key}"`),
        manager: "npm",
        direct,
      });
    }
  }

  if (packages.length === 0 && document.dependencies && typeof document.dependencies === "object") {
    const walk = (deps: Record<string, unknown>, direct: boolean): void => {
      for (const [name, value] of Object.entries(deps)) {
        if (!value || typeof value !== "object") continue;
        const entry = value as Record<string, unknown>;
        if (typeof entry.version === "string") {
          packages.push({
            name,
            version: entry.version,
            ecosystem: "npm",
            file,
            line: findLine(content, `"${name}"`),
            manager: "npm",
            direct,
          });
        }
        if (entry.dependencies && typeof entry.dependencies === "object") {
          walk(entry.dependencies as Record<string, unknown>, false);
        }
      }
    };
    walk(document.dependencies as Record<string, unknown>, true);
  }

  if (packages.length === 0) {
    warnings.push(`${file}: no parseable package-lock dependencies found`);
  }
  return { packages: pushUnique(packages), warnings };
}

export function parsePnpmLock(content: string, file: string): ParsedDependencies {
  const warnings: string[] = [];
  let document: Record<string, unknown>;
  try {
    document = (parseYaml(content) ?? {}) as Record<string, unknown>;
  } catch (error) {
    return {
      packages: [],
      warnings: [
        `pnpm-lock.yaml parse failed (${file}): ${error instanceof Error ? error.message : String(error)}`,
      ],
    };
  }

  const packages: ScaPackage[] = [];
  for (const sectionName of ["packages", "snapshots"]) {
    const section = document[sectionName];
    if (!section || typeof section !== "object") continue;
    for (const rawKey of Object.keys(section as Record<string, unknown>)) {
      let key = rawKey.startsWith("/") ? rawKey.slice(1) : rawKey;
      const peerIndex = key.indexOf("(");
      if (peerIndex >= 0) key = key.slice(0, peerIndex);
      let name = "";
      let version = "";
      const atIndex = key.lastIndexOf("@");
      if (atIndex > 0) {
        name = key.slice(0, atIndex);
        version = key.slice(atIndex + 1);
      } else {
        // Older pnpm lockfiles use /name/version keys.
        const slashIndex = key.lastIndexOf("/");
        if (slashIndex <= 0) continue;
        name = key.slice(0, slashIndex);
        version = key.slice(slashIndex + 1);
      }
      if (!name || !/^[0-9]/.test(version)) continue;
      packages.push({
        name,
        version,
        ecosystem: "npm",
        file,
        line: findLine(content, rawKey),
        manager: "pnpm",
        direct: true,
      });
    }
  }

  if (packages.length === 0) {
    warnings.push(`${file}: no parseable pnpm dependencies found`);
  }
  return { packages: pushUnique(packages), warnings };
}

/** Remove a UTF-8 byte order mark. */
function stripBom(content: string): string {
  return content.charCodeAt(0) === 0xfeff ? content.slice(1) : content;
}

const SCOPE_RANK: Record<DependencyScope, number> = {
  runtime: 3,
  optional: 2,
  dev: 1,
  unknown: 0,
};

function betterScope(
  a: DependencyScope | undefined,
  b: DependencyScope,
): DependencyScope {
  return a !== undefined && SCOPE_RANK[a] >= SCOPE_RANK[b] ? a : b;
}

function pypiKey(name: string): string {
  return normalizePackageName(name, "PyPI");
}

/** Leading distribution name of a PEP 508 requirement string. */
function requirementName(line: string): string | undefined {
  return /^\s*([A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?)/.exec(line)?.[1];
}

/** Extras of a PEP 508 requirement string (`name[a,b]>=1` -> `["a", "b"]`). */
function requirementExtras(line: string): string[] {
  const match = /^\s*[A-Za-z0-9][A-Za-z0-9_.-]*\s*\[([^\]]*)\]/.exec(line);
  if (!match?.[1]) return [];
  return match[1]
    .split(",")
    .map((part) => part.trim().toLowerCase())
    .filter((part) => part.length > 0);
}

/** Files larger than this are not followed as `-r` includes or manifests. */
const MAX_SIDE_FILE_BYTES = 8 * 1024 * 1024;
const MAX_INCLUDE_DEPTH = 32;

/**
 * Read a text file that is referenced from inside the audit root (an `-r`
 * include or a sibling manifest). The target must resolve, after following
 * symbolic links, to a regular file inside the root.
 */
function readJailedFile(
  root: string,
  relPath: string,
): { rel: string; content: string } | { error: string } {
  let abs: string;
  let realRoot: string;
  try {
    realRoot = validateAuditRoot(root).root;
    abs = resolveInside(realRoot, relPath);
  } catch (error) {
    return {
      error:
        error instanceof PathJailError
          ? "outside the audit root"
          : error instanceof Error
            ? error.message
            : String(error),
    };
  }
  try {
    const stat = fs.statSync(abs);
    if (!stat.isFile()) return { error: "not a regular file" };
    if (stat.size > MAX_SIDE_FILE_BYTES) return { error: "file is too large" };
    return {
      rel: toPosixRelative(realRoot, abs),
      content: fs.readFileSync(abs, "utf8"),
    };
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    return { error: code ?? (error instanceof Error ? error.message : String(error)) };
  }
}

/**
 * Resolve the target of a `-r` include relative to the including file.
 * Absolute paths, drive letters, URLs and anything that leaves the audit root
 * are refused without touching the filesystem outside the root.
 */
function includeTargetPath(file: string, target: string): string | undefined {
  if (!target || target.includes("\u0000")) return undefined;
  if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(target)) return undefined; // URL or C:\
  const posixTarget = target.split("\\").join("/");
  if (posixTarget.startsWith("/") || posixTarget.startsWith("~")) return undefined;
  const baseDir = path.posix.dirname(file.split(path.sep).join("/"));
  const joined = path.posix.normalize(path.posix.join(baseDir, posixTarget));
  if (joined === ".." || joined.startsWith("../") || path.posix.isAbsolute(joined)) {
    return undefined;
  }
  return joined;
}

export interface RequirementsOptions {
  /** Audit root, required to resolve `-r` includes through the path jail. */
  root?: string;
  /** Already-visited files, used to break include cycles and double counts. */
  visited?: Set<string>;
  /** Include nesting depth (internal). */
  depth?: number;
}

/** Strip a pip inline comment: `#` at the start or preceded by whitespace. */
function stripRequirementComment(line: string): string {
  for (let index = line.indexOf("#"); index >= 0; index = line.indexOf("#", index + 1)) {
    if (index === 0 || /\s/.test(line[index - 1] ?? "")) {
      return line.slice(0, index);
    }
  }
  return line;
}

/** Value of a pip option written as `-r x`, `-rx`, `--requirement x` or `--requirement=x`. */
function pipOptionValue(
  line: string,
  short: string,
  long: string,
): string | undefined {
  let rest: string | undefined;
  if (line === long || line.startsWith(`${long} `) || line.startsWith(`${long}\t`)) {
    rest = line.slice(long.length);
  } else if (line.startsWith(`${long}=`)) {
    rest = line.slice(long.length + 1);
  } else if (line.startsWith(short) && !line.startsWith("--")) {
    rest = line.slice(short.length);
  }
  if (rest === undefined) return undefined;
  let value = rest.trim();
  const quoted = /^(["'])(.*)\1$/.exec(value);
  if (quoted) value = quoted[2] ?? "";
  return value;
}

type RequirementLine =
  | { kind: "pinned"; name: string; version: string }
  | { kind: "unpinned" }
  | { kind: "url" }
  | { kind: "other" };

const REQUIREMENT_HEAD =
  /^([A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?\s*/;

function classifyRequirement(line: string): RequirementLine {
  if (/^(?:[A-Za-z][A-Za-z0-9+.-]*:|\.{0,2}[\\/]|~)/.test(line)) return { kind: "url" };
  const head = REQUIREMENT_HEAD.exec(line);
  if (!head) return { kind: "other" };
  const name = head[1] ?? "";
  let rest = line.slice(head[0].length);
  if (rest.startsWith("@")) return { kind: "url" };
  // A bare local archive such as `./pkg.whl` was handled above; `pkg.whl`
  // and `dir/pkg` are paths too.
  if (/^[\\/]/.test(rest) || /\.(?:whl|tar\.gz|zip|tgz)$/i.test(name)) return { kind: "url" };
  const markerIndex = rest.indexOf(";");
  if (markerIndex >= 0) rest = rest.slice(0, markerIndex);
  const optionIndex = rest.search(/\s--?[A-Za-z]/);
  if (optionIndex >= 0) rest = rest.slice(0, optionIndex);
  rest = rest.trim();
  if (rest.startsWith("(") && rest.endsWith(")")) rest = rest.slice(1, -1).trim();
  if (rest === "") return { kind: "unpinned" };
  if (!/^(?:===|==|~=|!=|<=|>=|<|>)/.test(rest)) return { kind: "other" };
  for (const clause of rest.split(",")) {
    const pinned = /^\s*(===|==)\s*([^\s,;]+)\s*$/.exec(clause);
    if (!pinned) continue;
    const version = pinned[2] ?? "";
    if (!version || version.includes("*") || version.length > 128) continue;
    return { kind: "pinned", name, version };
  }
  return { kind: "unpinned" };
}

export function parseRequirements(
  content: string,
  file: string,
  options: RequirementsOptions = {},
): ParsedDependencies {
  const warnings: string[] = [];
  const packages: ScaPackage[] = [];
  let unpinned = 0;
  let urlEntries = 0;
  const root = options.root;
  const visited = options.visited ?? new Set<string>();
  const depth = options.depth ?? 0;

  if (root && visited.has(file)) return { packages: [], warnings };
  if (root) visited.add(file);

  // Join backslash line continuations, remembering the first physical line.
  // A comment line never continues (pip behaves the same way).
  const logical: Array<{ text: string; line: number }> = [];
  let acc = "";
  let accLine = 1;
  const physical = splitLines(stripBom(content));
  for (let index = 0; index < physical.length; index += 1) {
    const raw = (physical[index] ?? "").trimEnd();
    const isComment = raw.trimStart().startsWith("#");
    if (raw.endsWith("\\") && !isComment) {
      if (acc.length === 0) accLine = index + 1;
      acc += `${raw.slice(0, -1)} `;
      continue;
    }
    if (acc.length > 0) {
      logical.push({ text: isComment ? acc : acc + raw, line: accLine });
      acc = "";
    } else {
      logical.push({ text: raw, line: index + 1 });
    }
  }
  if (acc.length > 0) logical.push({ text: acc, line: accLine });

  for (const entry of logical) {
    const line = stripRequirementComment(entry.text).trim();
    if (!line) continue;

    if (line.startsWith("-")) {
      const target = pipOptionValue(line, "-r", "--requirement");
      if (target !== undefined) {
        if (!target || !root) continue;
        const candidate = includeTargetPath(file, target);
        if (!candidate) {
          warnings.push(
            `${file}: include ${target} is outside the audit root and was not read`,
          );
          continue;
        }
        if (visited.has(candidate)) continue;
        if (depth >= MAX_INCLUDE_DEPTH) {
          warnings.push(`${file}: include ${target} is nested too deeply and was not read`);
          continue;
        }
        const included = readJailedFile(root, candidate);
        if ("error" in included) {
          warnings.push(
            included.error === "outside the audit root"
              ? `${file}: include ${target} is outside the audit root and was not read`
              : `${file}: cannot read include ${target} (${included.error})`,
          );
          continue;
        }
        if (visited.has(included.rel)) continue;
        if (included.rel !== candidate) visited.add(candidate);
        const nested = parseRequirements(included.content, included.rel, {
          root,
          visited,
          depth: depth + 1,
        });
        appendAll(packages, nested.packages);
        appendAll(warnings, nested.warnings);
        continue;
      }
      // Editable installs point at a path or VCS URL and carry no version.
      if (pipOptionValue(line, "-e", "--editable") !== undefined) {
        urlEntries += 1;
        continue;
      }
      // Constraints only restrict versions; other pip options (--hash,
      // --index-url, --find-links, ...) carry no package at all.
      continue;
    }

    const classified = classifyRequirement(line);
    if (classified.kind === "url") {
      urlEntries += 1;
    } else if (classified.kind === "unpinned") {
      unpinned += 1;
    } else if (classified.kind === "pinned") {
      packages.push({
        name: classified.name,
        version: classified.version,
        ecosystem: "PyPI",
        file,
        line: entry.line,
        manager: "requirements",
        direct: true,
        scope: "unknown",
      });
    }
  }

  if (urlEntries > 0) {
    warnings.push(
      `${file}: ${urlEntries} direct URL/VCS entries cannot be checked against OSV`,
    );
  }
  if (unpinned > 0) {
    warnings.push(
      `${file}: ${unpinned} unpinned entries not parsed (unresolved transitive dependencies)`,
    );
  }
  return { packages: pushUnique(packages), warnings };
}

/** Dependencies declared by a project manifest (pyproject.toml or Pipfile). */
export interface ManifestDependencies {
  /** Normalized names of every declared dependency, in any group. */
  names: Set<string>;
  /** Normalized name -> strongest scope it is declared with. */
  scopes: Map<string, DependencyScope>;
  /** Names of optional-dependency (extras) groups. */
  optionalGroups: Set<string>;
  /**
   * Cargo only: keys of the local crates whose own Cargo.toml was read, so
   * their declared dependencies (with scope) are already in `names`.
   */
  localCrates?: Set<string>;
  warning?: string;
}

/** Either plain direct names (legacy) or full manifest information. */
export type DirectInfo = Set<string> | ManifestDependencies;

function manifestOf(info: DirectInfo | undefined): ManifestDependencies | undefined {
  if (!info) return undefined;
  if (info instanceof Set) {
    return { names: info, scopes: new Map(), optionalGroups: new Set() };
  }
  return info;
}

function asTable(value: TomlValue | undefined): TomlTable | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as TomlTable)
    : undefined;
}

function asString(value: TomlValue | undefined): string | undefined {
  return typeof value === "string" ? value : undefined;
}

type TomlLockManager = "poetry" | "uv" | "pdm" | "pylock";

interface PackageBlockOptions {
  manager: TomlLockManager;
  manifest?: ManifestDependencies;
  /** Table name inside `[[...]]`; defaults to `package`. */
  header?: string;
}

interface DependencyRef {
  key: string;
  extras: string[];
}

/** Dependency references of a lock entry, for every supported lock shape. */
function dependencyRefs(value: TomlValue | undefined): DependencyRef[] {
  const refs: DependencyRef[] = [];
  if (Array.isArray(value)) {
    for (const item of value) {
      if (typeof item === "string") {
        // pdm: PEP 508 strings.
        const name = requirementName(item);
        if (name) refs.push({ key: pypiKey(name), extras: requirementExtras(item) });
        continue;
      }
      const table = asTable(item);
      const name = asString(table?.name);
      if (!name) continue;
      const extra = table?.extra;
      refs.push({
        key: pypiKey(name),
        extras: Array.isArray(extra)
          ? extra.filter((x): x is string => typeof x === "string").map((x) => x.toLowerCase())
          : [],
      });
    }
    return refs;
  }
  // poetry: a table keyed by dependency name.
  const table = asTable(value);
  if (table) for (const key of Object.keys(table)) refs.push({ key: pypiKey(key), extras: [] });
  return refs;
}

/** True for the project itself or a local workspace member: not a PyPI release. */
function isLocalProject(table: TomlTable, manager: TomlLockManager): boolean {
  const source = asTable(table.source);
  if (source) {
    if (
      typeof source.virtual === "string" ||
      typeof source.editable === "string" ||
      typeof source.directory === "string"
    ) {
      return true;
    }
    // poetry: [package.source] type = "directory"
    if (source.type === "directory") return true;
  }
  if (manager === "pylock" && asTable(table.directory)) return true;
  if (manager === "pdm") {
    if (table.editable === true) return true;
    const localPath = asString(table.path);
    if (localPath !== undefined && !/\.(?:whl|tar\.gz|zip|tgz)$/i.test(localPath)) return true;
  }
  return false;
}

/** Scope stated by the lock entry itself, when the format records one. */
function explicitScope(
  table: TomlTable,
  manager: TomlLockManager,
  manifest: ManifestDependencies | undefined,
): DependencyScope | undefined {
  if (manager === "poetry") {
    const optional = table.optional === true;
    const category = asString(table.category);
    if (category === "dev") return "dev";
    if (category === "main") return optional ? "optional" : "runtime";
    if (Array.isArray(table.groups)) {
      const groups = table.groups.filter((g): g is string => typeof g === "string");
      if (groups.includes("main")) return optional ? "optional" : "runtime";
      if (groups.length > 0) return "dev";
    }
    return optional ? "optional" : undefined;
  }
  if (manager === "pdm" && Array.isArray(table.groups)) {
    const groups = table.groups.filter((g): g is string => typeof g === "string");
    if (groups.includes("default")) return "runtime";
    if (groups.length === 0 || !manifest) return undefined;
    return groups.some((group) => manifest.optionalGroups.has(group.toLowerCase()))
      ? "optional"
      : "dev";
  }
  return undefined;
}

/**
 * Line-based scan used only when the TOML reader rejects a lockfile. It finds
 * `name` / `version` directly below each `[[package]]` header so a file with
 * one unreadable construct still yields its packages.
 */
function scanPackageBlocks(
  content: string,
  file: string,
  options: PackageBlockOptions,
): ScaPackage[] {
  const header = `[[${options.header ?? "package"}]]`;
  const packages: ScaPackage[] = [];
  const lines = splitLines(stripBom(content));
  let current: { line: number; name?: string; version?: string; local: boolean } | undefined;
  let inHead = false;
  const flush = (): void => {
    if (current?.name && current.version && !current.local) {
      packages.push({
        name: current.name,
        version: current.version,
        ecosystem: "PyPI",
        file,
        line: current.line,
        manager: options.manager,
        direct: options.manifest
          ? options.manifest.names.has(pypiKey(current.name))
          : true,
        scope: "unknown",
      });
    }
    current = undefined;
  };
  for (let index = 0; index < lines.length; index += 1) {
    const text = (lines[index] ?? "").trim();
    if (text.startsWith("[")) {
      if (text.startsWith(header)) {
        flush();
        current = { line: index + 1, local: false };
        inHead = true;
      } else if (/^\[{1,2}[A-Za-z0-9_."'-]+\]{1,2}/.test(text)) {
        inHead = false;
      }
      continue;
    }
    if (!current || !inHead || text.length > 4096) continue;
    const pair = /^(name|version)\s*=\s*(?:"([^"\\]*)"|'([^']*)')/.exec(text);
    if (pair) {
      const value = pair[2] ?? pair[3] ?? "";
      if (pair[1] === "name") current.name ??= value;
      else current.version ??= value;
    } else if (/^source\s*=\s*\{\s*(?:virtual|editable|directory)\s*=/.test(text)) {
      current.local = true;
    }
  }
  flush();
  return packages;
}

const NO_MANIFEST_WARNING =
  "no pyproject.toml found; all dependencies are treated as direct (unresolved transitive dependencies)";

function parsePackageBlocks(
  content: string,
  file: string,
  options: PackageBlockOptions,
): ParsedDependencies {
  const warnings: string[] = [];
  const manager = options.manager;
  const manifest = options.manifest;
  const parsed = parseTomlSubset(content, file);

  if (parsed.error) {
    const scanned = pushUnique(scanPackageBlocks(content, file, options));
    warnings.push(
      `${parsed.error}; used a line-based fallback (${scanned.length} packages, dependency scope unknown)`,
    );
    if (scanned.length === 0) {
      warnings.push(`${file}: no parseable ${manager} dependencies found`);
    }
    return { packages: scanned, warnings };
  }

  interface Entry {
    table: TomlTable;
    name: string;
    key: string;
    version?: string;
    line: number;
    local: boolean;
  }
  const entries: Entry[] = [];
  const rawEntries = parsed.data[options.header ?? "package"];
  if (Array.isArray(rawEntries)) {
    for (const raw of rawEntries) {
      const table = asTable(raw);
      const name = asString(table?.name);
      if (!table || !name) continue;
      entries.push({
        table,
        name,
        key: pypiKey(name),
        version: asString(table.version),
        line: parsed.lineOf(table) ?? 1,
        local: isLocalProject(table, manager),
      });
    }
  }

  // Seeds: what the project itself declares, from the lockfile's own root
  // entries (uv) and from the sibling manifest.
  const seeds = new Map<string, DependencyScope>();
  const seedExtras = new Map<string, Set<string>>();
  const addSeed = (ref: DependencyRef, scope: DependencyScope): void => {
    seeds.set(ref.key, betterScope(seeds.get(ref.key), scope));
    if (ref.extras.length > 0) {
      const set = seedExtras.get(ref.key) ?? new Set<string>();
      for (const extra of ref.extras) set.add(extra);
      seedExtras.set(ref.key, set);
    }
  };
  const groupRefs = (value: TomlValue | undefined): DependencyRef[] => {
    const table = asTable(value);
    if (!table) return [];
    return Object.keys(table).flatMap((group) => dependencyRefs(table[group]));
  };
  for (const entry of entries) {
    if (!entry.local) continue;
    for (const ref of dependencyRefs(entry.table.dependencies)) addSeed(ref, "runtime");
    for (const ref of groupRefs(entry.table["optional-dependencies"])) addSeed(ref, "optional");
    for (const ref of groupRefs(entry.table["dev-dependencies"])) addSeed(ref, "dev");
  }
  if (manifest) {
    for (const key of manifest.names) {
      addSeed({ key, extras: [] }, manifest.scopes.get(key) ?? "unknown");
    }
  }
  const localKeys = new Set(entries.filter((e) => e.local).map((e) => e.key));
  for (const key of localKeys) seeds.delete(key);

  // Propagate scopes through the dependency graph: runtime first, so a
  // package reachable from a runtime dependency is never labelled dev.
  const byKey = new Map<string, Entry[]>();
  for (const entry of entries) {
    const list = byKey.get(entry.key) ?? [];
    list.push(entry);
    byKey.set(entry.key, list);
  }
  const reached = new Map<string, DependencyScope>();
  const expandedExtras = new Set<string>();
  for (const scope of ["runtime", "optional", "dev"] as const) {
    const queue: DependencyRef[] = [];
    for (const [key, seedScope] of seeds) {
      if (seedScope === scope) {
        queue.push({ key, extras: [...(seedExtras.get(key) ?? [])] });
      }
    }
    while (queue.length > 0) {
      const ref = queue.pop() as DependencyRef;
      const first = !reached.has(ref.key);
      if (first) reached.set(ref.key, scope);
      for (const entry of byKey.get(ref.key) ?? []) {
        if (first) appendAll(queue, dependencyRefs(entry.table.dependencies));
        const optional = asTable(entry.table["optional-dependencies"]);
        for (const extra of ref.extras) {
          const marker = `${ref.key}\u0000${extra}`;
          if (expandedExtras.has(marker)) continue;
          expandedExtras.add(marker);
          if (!optional) continue;
          for (const group of Object.keys(optional)) {
            if (group.toLowerCase() === extra) appendAll(queue, dependencyRefs(optional[group]));
          }
        }
      }
    }
  }

  const packages: ScaPackage[] = [];
  let noVersion = 0;
  for (const entry of entries) {
    if (entry.local) continue;
    if (!entry.version) {
      noVersion += 1;
      continue;
    }
    const scope =
      explicitScope(entry.table, manager, manifest) ?? reached.get(entry.key) ?? "unknown";
    const pkg: ScaPackage = {
      name: entry.name,
      version: entry.version,
      ecosystem: "PyPI",
      file,
      line: entry.line,
      manager,
      direct: seeds.size > 0 ? seeds.has(entry.key) : true,
      scope,
    };
    if (scope === "dev") pkg.dev = true;
    packages.push(pkg);
  }

  if (noVersion > 0) {
    warnings.push(
      `${file}: ${noVersion} entries without a version (VCS, URL or directory sources) cannot be checked against OSV`,
    );
  }
  if (packages.length > 0 && seeds.size === 0) {
    warnings.push(
      manifest
        ? `${file}: no dependencies could be read from the project manifest; all dependencies are treated as direct`
        : `${file}: ${NO_MANIFEST_WARNING}`,
    );
  }
  if (packages.length === 0) {
    warnings.push(`${file}: no parseable ${manager} dependencies found`);
  }
  return { packages: pushUnique(packages), warnings };
}

export function parsePoetryLock(
  content: string,
  file: string,
  direct?: DirectInfo,
): ParsedDependencies {
  return parsePackageBlocks(content, file, {
    manager: "poetry",
    manifest: manifestOf(direct),
  });
}

export function parseUvLock(
  content: string,
  file: string,
  direct?: DirectInfo,
): ParsedDependencies {
  return parsePackageBlocks(content, file, { manager: "uv", manifest: manifestOf(direct) });
}

export function parsePdmLock(
  content: string,
  file: string,
  direct?: DirectInfo,
): ParsedDependencies {
  return parsePackageBlocks(content, file, { manager: "pdm", manifest: manifestOf(direct) });
}

export function parsePylock(
  content: string,
  file: string,
  direct?: DirectInfo,
): ParsedDependencies {
  return parsePackageBlocks(content, file, {
    manager: "pylock",
    manifest: manifestOf(direct),
    header: "packages",
  });
}

/** First line of every `"name": {` entry per top-level Pipfile.lock section. */
function pipfileLockLines(content: string): Map<string, number> {
  const lines = new Map<string, number>();
  const physical = splitLines(content);
  let section = "";
  let sectionIndent = -1;
  for (let index = 0; index < physical.length; index += 1) {
    const text = physical[index] ?? "";
    if (text.length > 4096) continue;
    const match = /^(\s*)"((?:[^"\\]|\\.)*)"\s*:\s*\{/.exec(text);
    if (!match) continue;
    const indent = (match[1] ?? "").length;
    const key = match[2] ?? "";
    if (sectionIndent < 0 || indent <= sectionIndent) {
      section = key;
      sectionIndent = indent;
      continue;
    }
    const id = `${section}\u0000${key}`;
    if (!lines.has(id)) lines.set(id, index + 1);
  }
  return lines;
}

export function parsePipfileLock(
  content: string,
  file: string,
  direct?: DirectInfo,
): ParsedDependencies {
  const warnings: string[] = [];
  const packages: ScaPackage[] = [];
  const text = stripBom(content);
  let document: unknown;
  try {
    document = JSON.parse(text);
  } catch (error) {
    return {
      packages: [],
      warnings: [
        `Pipfile.lock parse failed (${file}): ${error instanceof Error ? error.message : String(error)}`,
      ],
    };
  }
  if (!document || typeof document !== "object" || Array.isArray(document)) {
    return { packages: [], warnings: [`${file}: no parseable Pipfile.lock dependencies found`] };
  }

  const manifest = manifestOf(direct);
  const lineIndex = pipfileLockLines(text);
  const sections = Object.keys(document).filter((key) => key !== "_meta");
  // `default` first so a package present in several categories is runtime.
  sections.sort((a, b) => Number(b === "default") - Number(a === "default"));

  let unpinned = 0;
  let unversioned = 0;
  for (const section of sections) {
    const group = (document as Record<string, unknown>)[section];
    if (!group || typeof group !== "object" || Array.isArray(group)) continue;
    const scope: DependencyScope = section === "default" ? "runtime" : "dev";
    for (const [name, value] of Object.entries(group as Record<string, unknown>)) {
      if (!value || typeof value !== "object") continue;
      const entry = value as Record<string, unknown>;
      if (typeof entry.version !== "string") {
        // git / file / path / editable entries have no version.
        unversioned += 1;
        continue;
      }
      const pinned = /^\s*={2,3}\s*([^\s,;*]+)\s*$/.exec(entry.version);
      if (!pinned?.[1]) {
        unpinned += 1;
        continue;
      }
      packages.push({
        name,
        version: pinned[1],
        ecosystem: "PyPI",
        file,
        line: lineIndex.get(`${section}\u0000${name}`) ?? 1,
        manager: "pipfile",
        direct: manifest && manifest.names.size > 0 ? manifest.names.has(pypiKey(name)) : true,
        scope,
        dev: scope === "dev",
      });
    }
  }

  if (unversioned > 0) {
    warnings.push(
      `${file}: ${unversioned} direct URL/VCS entries cannot be checked against OSV`,
    );
  }
  if (unpinned > 0) {
    warnings.push(
      `${file}: ${unpinned} unpinned entries not parsed (unresolved transitive dependencies)`,
    );
  }
  if (packages.length === 0) {
    warnings.push(`${file}: no parseable Pipfile.lock dependencies found`);
  }
  return { packages: pushUnique(packages), warnings };
}

function emptyManifest(warning?: string): ManifestDependencies {
  return {
    names: new Set<string>(),
    scopes: new Map<string, DependencyScope>(),
    optionalGroups: new Set<string>(),
    ...(warning ? { warning } : {}),
  };
}

/**
 * Extract the dependencies a pyproject.toml declares, with the scope each one
 * is declared in: PEP 621 `[project]`, `[project.optional-dependencies]`,
 * PEP 735 `[dependency-groups]`, Poetry tables and groups (including the
 * legacy `dev-dependencies`), PDM and uv development dependencies.
 */
export function parsePyprojectDependencies(
  content: string,
  file: string,
): ManifestDependencies {
  const parsed = parseTomlSubset(content, file);
  if (parsed.error) return emptyManifest(parsed.error);

  const result = emptyManifest();
  const add = (name: string | undefined, scope: DependencyScope): void => {
    if (!name) return;
    const key = pypiKey(name);
    result.names.add(key);
    result.scopes.set(key, betterScope(result.scopes.get(key), scope));
  };
  const addArray = (value: TomlValue | undefined, scope: DependencyScope): void => {
    if (!Array.isArray(value)) return;
    for (const item of value) {
      // Tables such as `{ include-group = "x" }` are not requirements.
      if (typeof item === "string") add(requirementName(item), scope);
    }
  };
  const addGroups = (value: TomlValue | undefined, scope: DependencyScope): void => {
    const table = asTable(value);
    if (!table) return;
    for (const group of Object.keys(table)) {
      if (scope === "optional") result.optionalGroups.add(group.toLowerCase());
      addArray(table[group], scope);
    }
  };
  const addPoetryTable = (value: TomlValue | undefined, scope: DependencyScope): void => {
    const table = asTable(value);
    if (!table) return;
    for (const key of Object.keys(table)) {
      // `python` is a constraint key in Poetry, not a package.
      if (key.toLowerCase() === "python") continue;
      const spec = asTable(table[key]);
      add(key, scope === "runtime" && spec?.optional === true ? "optional" : scope);
    }
  };

  const project = asTable(parsed.data.project);
  addArray(project?.dependencies, "runtime");
  addGroups(project?.["optional-dependencies"], "optional");
  addGroups(parsed.data["dependency-groups"], "dev");

  const tool = asTable(parsed.data.tool);
  const poetry = asTable(tool?.poetry);
  addPoetryTable(poetry?.dependencies, "runtime");
  addPoetryTable(poetry?.["dev-dependencies"], "dev");
  const groups = asTable(poetry?.group);
  if (groups) {
    for (const key of Object.keys(groups)) {
      addPoetryTable(asTable(groups[key])?.dependencies, "dev");
    }
  }
  const extras = asTable(poetry?.extras);
  if (extras) for (const key of Object.keys(extras)) result.optionalGroups.add(key.toLowerCase());

  addGroups(asTable(tool?.pdm)?.["dev-dependencies"], "dev");
  addArray(asTable(tool?.uv)?.["dev-dependencies"], "dev");

  return result;
}

/** Extract the dependencies a Pipfile declares (`[packages]`, `[dev-packages]`, custom categories). */
export function parsePipfileDependencies(
  content: string,
  file: string,
): ManifestDependencies {
  const parsed = parseTomlSubset(content, file);
  if (parsed.error) return emptyManifest(parsed.error);
  const result = emptyManifest();
  const reserved = new Set(["source", "requires", "scripts", "pipenv", "pipfile"]);
  for (const section of Object.keys(parsed.data)) {
    if (reserved.has(section)) continue;
    const table = asTable(parsed.data[section]);
    if (!table) continue;
    const scope: DependencyScope = section === "packages" ? "runtime" : "dev";
    for (const name of Object.keys(table)) {
      const key = pypiKey(name);
      result.names.add(key);
      result.scopes.set(key, betterScope(result.scopes.get(key), scope));
    }
  }
  return result;
}

export function parseGoMod(content: string, file: string): ParsedDependencies {
  const warnings: string[] = [];
  const packages: ScaPackage[] = [];
  const lines = splitLines(content);
  let inRequireBlock = false;

  for (let index = 0; index < lines.length; index += 1) {
    const raw = lines[index] ?? "";
    const line = raw.replace(/\/\/.*$/, "").trim();
    if (!line) continue;

    if (/^require\s*\($/.test(line)) {
      inRequireBlock = true;
      continue;
    }
    if (inRequireBlock && line === ")") {
      inRequireBlock = false;
      continue;
    }

    const match = inRequireBlock
      ? /^(\S+)\s+(v\S+)/.exec(line)
      : /^require\s+(\S+)\s+(v\S+)/.exec(line);
    if (!match) continue;
    const name = match[1] ?? "";
    const version = match[2] ?? "";
    if (!name || !version) continue;
    packages.push({
      name,
      version,
      ecosystem: "Go",
      file,
      line: index + 1,
      manager: "go",
      direct: !/\/\/\s*indirect/.test(raw),
    });
  }

  if (packages.length === 0) {
    warnings.push(`${file}: no require dependencies found`);
  }
  return { packages: pushUnique(packages), warnings };
}

export function parsePomXml(content: string, file: string): ParsedDependencies {
  const warnings: string[] = [
    `${file}: pom.xml parsing is limited to direct dependencies with literal versions; unresolved transitive dependencies`,
  ];
  const packages: ScaPackage[] = [];

  const withoutManagement = content.replace(
    /<dependencyManagement>[\s\S]*?<\/dependencyManagement>/g,
    (match) => "\n".repeat((match.match(/\n/g) ?? []).length),
  );

  const dependencyPattern = /<dependency\b[^>]*>([\s\S]*?)<\/dependency>/g;
  let match: RegExpExecArray | null;
  while ((match = dependencyPattern.exec(withoutManagement)) !== null) {
    const body = match[1] ?? "";
    const groupId = /<groupId>([^<]+)<\/groupId>/.exec(body)?.[1]?.trim();
    const artifactId = /<artifactId>([^<]+)<\/artifactId>/.exec(body)?.[1]?.trim();
    const version = /<version>([^<]+)<\/version>/.exec(body)?.[1]?.trim();
    if (!groupId || !artifactId) continue;
    if (!version || version.includes("${")) continue;
    packages.push({
      name: `${groupId}:${artifactId}`,
      version,
      ecosystem: "Maven",
      file,
      line: lineAt(withoutManagement, match.index),
      manager: "maven",
      direct: true,
    });
  }

  return { packages: pushUnique(packages), warnings };
}

export function parsePackagesLock(
  content: string,
  file: string,
): ParsedDependencies {
  const warnings: string[] = [];
  const packages: ScaPackage[] = [];
  let document: Record<string, unknown>;
  try {
    document = JSON.parse(content) as Record<string, unknown>;
  } catch (error) {
    return {
      packages: [],
      warnings: [
        `packages.lock.json parse failed (${file}): ${error instanceof Error ? error.message : String(error)}`,
      ],
    };
  }

  const dependencies = document.dependencies;
  if (dependencies && typeof dependencies === "object") {
    for (const framework of Object.values(dependencies as Record<string, unknown>)) {
      if (!framework || typeof framework !== "object") continue;
      for (const [name, value] of Object.entries(
        framework as Record<string, unknown>,
      )) {
        if (!value || typeof value !== "object") continue;
        const entry = value as Record<string, unknown>;
        if (entry.type === "Project") continue;
        const version = entry.resolved;
        if (typeof version !== "string") continue;
        packages.push({
          name,
          version,
          ecosystem: "NuGet",
          file,
          line: findLine(content, `"${name}"`),
          manager: "nuget",
          direct: true,
        });
      }
    }
  }

  if (packages.length === 0) {
    warnings.push(`${file}: no parseable NuGet dependencies found`);
  }
  return { packages: pushUnique(packages), warnings };
}

// ---------------------------------------------------------------------------
// Rust: Cargo.lock with the sibling Cargo.toml (and workspace members).

/** Crate names compare case-insensitively with `-` and `_` treated as equal. */
function cargoKey(name: string): string {
  return name.toLowerCase().replace(/_/g, "-");
}

/** Index URLs of crates.io: the git index and the sparse index. */
const CRATES_IO_SOURCES = new Set([
  "registry+https://github.com/rust-lang/crates.io-index",
  "sparse+https://index.crates.io/",
]);

type CargoSourceKind = "crates.io" | "local" | "git" | "other-registry";

function cargoSourceKind(source: string | undefined): CargoSourceKind {
  if (source === undefined) return "local";
  if (CRATES_IO_SOURCES.has(source)) return "crates.io";
  if (source.startsWith("git+")) return "git";
  return "other-registry";
}

/** `name`, `name version` or `name version (source)` -> key of `name`. */
function cargoDependencyKey(entry: string): string | undefined {
  const name = /^\s*([A-Za-z0-9_-]+)/.exec(entry)?.[1];
  return name ? cargoKey(name) : undefined;
}

interface CargoManifest {
  manifest: ManifestDependencies;
  /** `[package] name`, when the manifest is a crate (not a virtual workspace). */
  crate?: string;
  /** `[workspace] members` / `exclude` globs, relative to the manifest. */
  members: string[];
  exclude: string[];
  /** Workspace dependency key -> real crate name (`package = "..."`). */
  workspaceRenames: Map<string, string>;
}

function stringArray(value: TomlValue | undefined): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
}

function readCargoManifest(
  content: string,
  file: string,
  inheritedRenames: Map<string, string> = new Map(),
): CargoManifest {
  const parsed = parseTomlSubset(stripBom(content), file);
  const empty: CargoManifest = {
    manifest: emptyManifest(parsed.error),
    members: [],
    exclude: [],
    workspaceRenames: new Map(),
  };
  if (parsed.error) return empty;

  const result = emptyManifest();
  const add = (name: string, scope: DependencyScope): void => {
    const key = cargoKey(name);
    result.names.add(key);
    result.scopes.set(key, betterScope(result.scopes.get(key), scope));
  };
  const workspace = asTable(parsed.data.workspace);
  const workspaceDeps = asTable(workspace?.dependencies);
  const workspaceRenames = new Map(inheritedRenames);
  if (workspaceDeps) {
    for (const key of Object.keys(workspaceDeps)) {
      const renamed = asString(asTable(workspaceDeps[key])?.package);
      if (renamed) workspaceRenames.set(key, renamed);
    }
  }
  // The crate a dependency key names: `package = "..."` renames it, and
  // `{ workspace = true }` takes the rename from `[workspace.dependencies]`.
  const crateName = (key: string, spec: TomlValue | undefined): string => {
    const table = asTable(spec);
    const renamed = asString(table?.package);
    if (renamed) return renamed;
    if (table?.workspace === true) return workspaceRenames.get(key) ?? key;
    return key;
  };
  const addTable = (value: TomlValue | undefined, scope: DependencyScope): void => {
    const table = asTable(value);
    if (!table) return;
    for (const key of Object.keys(table)) add(crateName(key, table[key]), scope);
  };
  // Cargo also accepts the legacy spellings with an underscore.
  const addSections = (container: TomlTable | undefined): void => {
    if (!container) return;
    addTable(container.dependencies, "runtime");
    addTable(container["build-dependencies"], "runtime");
    addTable(container.build_dependencies, "runtime");
    addTable(container["dev-dependencies"], "dev");
    addTable(container.dev_dependencies, "dev");
  };

  addSections(parsed.data);
  const target = asTable(parsed.data.target);
  if (target) for (const cfg of Object.keys(target)) addSections(asTable(target[cfg]));
  // Workspace dependencies are declared for the members; how a member uses
  // one is not known here.
  if (workspaceDeps) {
    for (const key of Object.keys(workspaceDeps)) add(crateName(key, workspaceDeps[key]), "unknown");
  }

  return {
    manifest: result,
    crate: asString(asTable(parsed.data.package)?.name),
    members: stringArray(workspace?.members),
    exclude: stringArray(workspace?.exclude),
    workspaceRenames,
  };
}

/** Dependencies a single Cargo.toml declares, with their scope. */
export function parseCargoManifestDependencies(
  content: string,
  file: string,
): ManifestDependencies {
  const parsed = readCargoManifest(content, file);
  parsed.manifest.localCrates = new Set(parsed.crate ? [cargoKey(parsed.crate)] : []);
  return parsed.manifest;
}

function mergeManifest(target: ManifestDependencies, source: ManifestDependencies): void {
  for (const key of source.names) {
    target.names.add(key);
    const scope = source.scopes.get(key);
    if (scope) target.scopes.set(key, betterScope(target.scopes.get(key), scope));
  }
}

/** Upper bound on workspace member manifests read for one Cargo.lock. */
const MAX_CARGO_MEMBERS = 1000;
/** Upper bound on `members` / `exclude` patterns taken from one Cargo.toml. */
const MAX_CARGO_MEMBER_PATTERNS = 1000;

/** `./crates/x/` -> `crates/x`, the way Cargo joins it onto the workspace root. */
function normalizeMemberPath(value: string): string {
  let result = value.trim().replace(/\\/g, "/");
  while (result.startsWith("./")) result = result.slice(2);
  return result.replace(/\/+$/, "");
}

function isGlobPattern(value: string): boolean {
  return /[*?[\]{}]/.test(value);
}

interface WorkspaceMembers {
  /** True when a directory (relative to the workspace root) is a member. */
  matches(dir: string): boolean;
  /** Members written as plain paths (no glob characters). */
  literal: string[];
}

/**
 * Member matching as Cargo does it: `members` are globs, `exclude` entries
 * are path prefixes. Patterns are compiled once and capped in number.
 */
function workspaceMembers(members: string[], exclude: string[]): WorkspaceMembers {
  const include = members
    .slice(0, MAX_CARGO_MEMBER_PATTERNS)
    .map(normalizeMemberPath)
    .filter((member) => member.length > 0 && !member.startsWith("../") && member !== "..");
  const excluded = exclude
    .slice(0, MAX_CARGO_MEMBER_PATTERNS)
    .map(normalizeMemberPath)
    .filter((member) => member.length > 0);
  const compiled = include.map((pattern) => {
    try {
      return compileGlob(pattern);
    } catch {
      return () => false;
    }
  });
  return {
    matches: (dir) =>
      !excluded.some((prefix) => dir === prefix || dir.startsWith(`${prefix}/`)) &&
      compiled.some((match) => match(dir)),
    literal: include.filter((member) => !isGlobPattern(member)),
  };
}

/**
 * Read the Cargo.toml next to a Cargo.lock through the path jail, plus the
 * manifests of the workspace members it lists: members written as plain
 * paths are read directly, glob members are matched against `manifestPaths`
 * (the Cargo.toml files the inventory found). Returns undefined when there is
 * no Cargo.toml.
 */
function readCargoManifests(
  root: string,
  lockfileRel: string,
  manifestPaths: readonly string[],
): ManifestDependencies | undefined {
  const dir = dirOf(lockfileRel);
  const rel = dir === "." ? "Cargo.toml" : `${dir}/Cargo.toml`;
  const read = readJailedFile(root, rel);
  if ("error" in read) {
    if (read.error === "ENOENT" || read.error === "ENOTDIR") return undefined;
    return emptyManifest(`${rel}: manifest was not read (${read.error})`);
  }
  const top = readCargoManifest(read.content, rel);
  const combined = emptyManifest(top.manifest.warning);
  combined.localCrates = new Set<string>();
  mergeManifest(combined, top.manifest);
  if (top.crate) combined.localCrates.add(cargoKey(top.crate));
  if (top.members.length === 0) return combined;

  const prefix = dir === "." ? "" : `${dir}/`;
  const members = workspaceMembers(top.members, top.exclude);
  const candidates = new Set<string>();
  for (const member of members.literal) {
    if (members.matches(member)) candidates.add(`${prefix}${member}/Cargo.toml`);
  }
  for (const manifestPath of manifestPaths) {
    if (path.posix.basename(manifestPath) !== "Cargo.toml") continue;
    if (!manifestPath.startsWith(prefix)) continue;
    const memberDir = dirOf(manifestPath.slice(prefix.length));
    if (memberDir === "." || memberDir.startsWith("../")) continue;
    if (members.matches(memberDir)) candidates.add(manifestPath);
  }

  let count = 0;
  for (const manifestPath of candidates) {
    if (count >= MAX_CARGO_MEMBERS) {
      combined.warning ??= `${rel}: more than ${MAX_CARGO_MEMBERS} workspace members; the rest were not read`;
      break;
    }
    count += 1;
    const member = readJailedFile(root, manifestPath);
    if ("error" in member) {
      if (member.error !== "ENOENT" && member.error !== "ENOTDIR") {
        combined.warning ??= `${manifestPath}: manifest was not read (${member.error})`;
      }
      continue;
    }
    const parsed = readCargoManifest(member.content, manifestPath, top.workspaceRenames);
    if (parsed.manifest.warning) {
      combined.warning ??= parsed.manifest.warning;
      continue;
    }
    mergeManifest(combined, parsed.manifest);
    if (parsed.crate) combined.localCrates.add(cargoKey(parsed.crate));
  }
  return combined;
}

interface CargoWorkspaceInfo {
  members: WorkspaceMembers;
  /** Keys of the local crates the workspace Cargo.lock lists. */
  localCrates: Set<string>;
}

/** Parsed workspace information per directory, shared by one caller. */
type CargoWorkspaceCache = Map<string, CargoWorkspaceInfo | undefined>;

function cargoWorkspaceInfo(
  root: string,
  dir: string,
  cache: CargoWorkspaceCache,
): CargoWorkspaceInfo | undefined {
  if (cache.has(dir)) return cache.get(dir);
  const prefix = dir === "." ? "" : `${dir}/`;
  let info: CargoWorkspaceInfo | undefined;
  const manifest = readJailedFile(root, `${prefix}Cargo.toml`);
  const lock = readJailedFile(root, `${prefix}Cargo.lock`);
  if (!("error" in manifest) || !("error" in lock)) {
    const top = "error" in manifest ? undefined : readCargoManifest(manifest.content, `${prefix}Cargo.toml`);
    const localCrates = new Set<string>();
    if (!("error" in lock)) {
      const parsed = parseTomlSubset(stripBom(lock.content), `${prefix}Cargo.lock`);
      const packages = parsed.error ? [] : parsed.data.package;
      if (Array.isArray(packages)) {
        for (const item of packages) {
          const table = asTable(item);
          const name = asString(table?.name);
          if (table && name && table.source === undefined) localCrates.add(cargoKey(name));
        }
      }
    }
    info = { members: workspaceMembers(top?.members ?? [], top?.exclude ?? []), localCrates };
  }
  cache.set(dir, info);
  return info;
}

/**
 * True when the Cargo.toml at `manifestRel` belongs to the workspace of the
 * nearest enclosing directory that has a Cargo.lock, so it shares that
 * lockfile: either `[workspace] members` lists it, or the lockfile records
 * its crate as a local package (Cargo also makes path dependencies inside
 * the workspace members).
 */
function isCargoWorkspaceMember(
  root: string,
  manifestRel: string,
  byDir: Map<string, Set<string>>,
  cache: CargoWorkspaceCache,
): boolean {
  const dir = dirOf(manifestRel);
  let current = dir;
  while (current !== "." && current !== "" && current !== "/") {
    current = path.posix.dirname(current);
    const files = [...(byDir.get(current) ?? [])].map((rel) => path.posix.basename(rel));
    if (!files.includes("Cargo.lock")) continue;
    const info = cargoWorkspaceInfo(root, current, cache);
    if (!info) return false;
    const memberDir = current === "." ? dir : dir.slice(current.length + 1);
    if (info.members.matches(memberDir)) return true;
    const own = readJailedFile(root, manifestRel);
    if ("error" in own) return false;
    const crate = readCargoManifest(own.content, manifestRel).crate;
    return crate !== undefined && info.localCrates.has(cargoKey(crate));
  }
  return false;
}

const NO_CARGO_MANIFEST_WARNING =
  "no Cargo.toml found; all dependencies are treated as direct (unresolved transitive dependencies)";

/**
 * Line-based scan used only when the TOML reader rejects a Cargo.lock: the
 * `name`, `version` and `source` lines of each `[[package]]` block.
 */
function scanCargoBlocks(content: string): Array<{
  name: string;
  version?: string;
  source?: string;
  line: number;
}> {
  const blocks: Array<{ name?: string; version?: string; source?: string; line: number }> = [];
  let current: (typeof blocks)[number] | undefined;
  const lines = splitLines(stripBom(content));
  for (let index = 0; index < lines.length; index += 1) {
    const text = (lines[index] ?? "").trim();
    if (text.startsWith("[")) {
      current = text.startsWith("[[package]]") ? { line: index + 1 } : undefined;
      if (current) blocks.push(current);
      continue;
    }
    if (!current || text.length > 4096) continue;
    const pair = /^(name|version|source)\s*=\s*(?:"([^"\\]*)"|'([^']*)')/.exec(text);
    if (!pair) continue;
    const key = pair[1] as "name" | "version" | "source";
    current[key] ??= pair[2] ?? pair[3] ?? "";
  }
  return blocks.filter(
    (block): block is { name: string; version?: string; source?: string; line: number } =>
      typeof block.name === "string" && block.name.length > 0,
  );
}

/**
 * Parse a Cargo.lock. crates.io packages are returned with ecosystem
 * `crates.io`; local workspace and path crates are skipped; git and
 * alternative-registry crates cannot be checked against OSV and are counted in
 * one warning each. With the sibling manifest, a crate is direct when the
 * manifest names it, and scopes propagate through the lockfile's dependency
 * lists (runtime first, so nothing reachable at run time is labelled dev).
 */
export function parseCargoLock(
  content: string,
  file: string,
  direct?: DirectInfo,
): ParsedDependencies {
  const warnings: string[] = [];
  const manifest = manifestOf(direct);
  const parsed = parseTomlSubset(stripBom(content), file);

  interface Entry {
    name: string;
    key: string;
    version?: string;
    line: number;
    kind: CargoSourceKind;
    dependencies: string[];
  }
  const entries: Entry[] = [];
  if (parsed.error) {
    for (const block of scanCargoBlocks(content)) {
      entries.push({
        name: block.name,
        key: cargoKey(block.name),
        version: block.version,
        line: block.line,
        kind: cargoSourceKind(block.source),
        dependencies: [],
      });
    }
    warnings.push(
      `${parsed.error}; used a line-based fallback (${entries.length} packages, dependency scope unknown)`,
    );
  } else {
    const raw = parsed.data.package;
    if (Array.isArray(raw)) {
      for (const item of raw) {
        const table = asTable(item);
        const name = asString(table?.name);
        if (!table || !name) continue;
        entries.push({
          name,
          key: cargoKey(name),
          version: asString(table.version),
          line: parsed.lineOf(table) ?? 1,
          kind: cargoSourceKind(asString(table.source)),
          dependencies: stringArray(table.dependencies),
        });
      }
    }
  }

  // Seeds: what the manifests declare. A local (path) crate is part of the
  // project, so it is never a direct dependency itself, but what it depends
  // on is still reached through it.
  const seeds = new Map<string, DependencyScope>();
  if (manifest) {
    for (const key of manifest.names) seeds.set(key, manifest.scopes.get(key) ?? "unknown");
  }
  const directKeys = new Set(seeds.keys());
  const manifestKnown = seeds.size > 0;
  for (const entry of entries) if (entry.kind === "local") directKeys.delete(entry.key);
  // A local crate whose Cargo.toml was read is covered by its manifest seeds;
  // its lockfile list also holds its dev-dependencies, so it is not followed.
  // A local crate whose manifest was not read (a path dependency outside the
  // workspace, an unmatched member) contributes its lockfile list as runtime:
  // without the manifest nothing it uses may be labelled dev.
  const readCrates = manifest?.localCrates ?? new Set<string>();
  const followed = (entry: Entry): boolean =>
    entry.kind !== "local" || !readCrates.has(entry.key);
  if (manifest) {
    for (const entry of entries) {
      if (entry.kind !== "local" || readCrates.has(entry.key)) continue;
      for (const dependency of entry.dependencies) {
        const key = cargoDependencyKey(dependency);
        if (key) seeds.set(key, betterScope(seeds.get(key), "runtime"));
      }
    }
  }

  const byKey = new Map<string, Entry[]>();
  for (const entry of entries) {
    const list = byKey.get(entry.key) ?? [];
    list.push(entry);
    byKey.set(entry.key, list);
  }
  const reached = new Map<string, DependencyScope>();
  for (const scope of ["runtime", "dev"] as const) {
    const queue: string[] = [];
    for (const [key, seedScope] of seeds) if (seedScope === scope) queue.push(key);
    while (queue.length > 0) {
      const key = queue.pop() as string;
      if (reached.has(key)) continue;
      reached.set(key, scope);
      for (const entry of byKey.get(key) ?? []) {
        if (!followed(entry)) continue;
        for (const dependency of entry.dependencies) {
          const next = cargoDependencyKey(dependency);
          if (next && !reached.has(next)) queue.push(next);
        }
      }
    }
  }

  const packages: ScaPackage[] = [];
  let git = 0;
  let otherRegistry = 0;
  let noVersion = 0;
  for (const entry of entries) {
    if (entry.kind === "local") continue;
    if (entry.kind === "git") {
      git += 1;
      continue;
    }
    if (entry.kind === "other-registry") {
      otherRegistry += 1;
      continue;
    }
    if (!entry.version) {
      noVersion += 1;
      continue;
    }
    // Without the dependency graph (line-based fallback) a crate declared as
    // a dev-dependency may still be reached at run time: never label it dev.
    let scope = reached.get(entry.key) ?? seeds.get(entry.key) ?? "unknown";
    if (parsed.error && scope === "dev") scope = "unknown";
    const pkg: ScaPackage = {
      name: entry.name,
      version: entry.version,
      ecosystem: "crates.io",
      file,
      line: entry.line,
      manager: "cargo",
      direct: manifestKnown ? directKeys.has(entry.key) : true,
      scope,
    };
    if (scope === "dev") pkg.dev = true;
    packages.push(pkg);
  }

  if (git > 0) {
    warnings.push(
      `${file}: ${git} crate(s) from git repositories cannot be checked against OSV`,
    );
  }
  if (otherRegistry > 0) {
    warnings.push(
      `${file}: ${otherRegistry} crate(s) from registries other than crates.io were not checked against OSV`,
    );
  }
  if (noVersion > 0) {
    warnings.push(`${file}: ${noVersion} crates.io entries without a version were skipped`);
  }
  if (packages.length > 0 && !manifestKnown) {
    warnings.push(
      manifest
        ? `${file}: no dependencies could be read from Cargo.toml; all dependencies are treated as direct`
        : `${file}: ${NO_CARGO_MANIFEST_WARNING}`,
    );
  }
  if (entries.length === 0) {
    warnings.push(`${file}: no parseable cargo dependencies found`);
  }
  return { packages: pushUnique(packages), warnings };
}

export interface ParseLockfileOptions {
  /** Audit root, used to resolve `-r` includes in requirements files. */
  root?: string;
  /**
   * Dependencies declared by the sibling manifest (pyproject.toml, Pipfile
   * or Cargo.toml), if present: plain direct names or full manifest
   * information.
   */
  directNames?: DirectInfo;
  /**
   * Requirements files already parsed in this scan. Sharing one set across
   * lockfiles keeps a file that is both scanned and `-r`-included from being
   * parsed (and warned about) twice.
   */
  visitedRequirements?: Set<string>;
}

export function parseLockfile(
  relPath: string,
  content: string,
  options: ParseLockfileOptions = {},
): ParsedDependencies {
  const base = path.basename(relPath);
  const requirements = (): ParsedDependencies =>
    parseRequirements(content, relPath, {
      root: options.root,
      visited: options.visitedRequirements ?? new Set<string>(),
    });
  switch (base) {
    case "package-lock.json":
      return parsePackageLock(content, relPath);
    case "pnpm-lock.yaml":
      return parsePnpmLock(content, relPath);
    case "requirements.txt":
      return requirements();
    case "poetry.lock":
      return parsePoetryLock(content, relPath, options.directNames);
    case "uv.lock":
      return parseUvLock(content, relPath, options.directNames);
    case "pdm.lock":
      return parsePdmLock(content, relPath, options.directNames);
    case "Pipfile.lock":
      return parsePipfileLock(content, relPath, options.directNames);
    case "go.mod":
      return parseGoMod(content, relPath);
    case "pom.xml":
      return parsePomXml(content, relPath);
    case "packages.lock.json":
      return parsePackagesLock(content, relPath);
    case "Cargo.lock":
      return parseCargoLock(content, relPath, options.directNames);
    case "go.sum":
    case "yarn.lock":
      return { packages: [], warnings: [] };
    default:
      if (base === "pylock.toml" || /^pylock\..+\.toml$/.test(base)) {
        return parsePylock(content, relPath, options.directNames);
      }
      if (isRequirementsLockfilePath(relPath)) return requirements();
      return { packages: [], warnings: [`${relPath}: unsupported lockfile type`] };
  }
}

function dirOf(relPath: string): string {
  return path.posix.dirname(relPath.split(path.sep).join("/"));
}

const EXPECTED_LOCKFILES: Record<string, string[]> = {
  "package.json": ["package-lock.json", "pnpm-lock.yaml", "yarn.lock"],
  "pyproject.toml": [
    "poetry.lock",
    "uv.lock",
    "pdm.lock",
    "pylock.toml",
    "requirements.txt",
  ],
  "Pipfile": ["Pipfile.lock"],
  "Cargo.toml": ["Cargo.lock"],
  "composer.json": ["composer.lock"],
};

function hasRequiredLockfile(
  base: string,
  present: Set<string>,
  nested?: Set<string>,
  workspaceMember?: () => boolean,
): boolean {
  const names = new Set(
    [...present].map((relPath) => path.posix.basename(relPath)),
  );
  const required = EXPECTED_LOCKFILES[base];
  if (required?.some((candidate) => names.has(candidate))) return true;
  // A workspace member's Cargo.toml shares the Cargo.lock of its workspace.
  if (base === "Cargo.toml" && workspaceMember?.()) return true;
  if (base === "pyproject.toml") {
    if ([...names].some((name) => /^pylock\..+\.toml$/.test(name))) return true;
    if ([...present].some(isRequirementsLockfilePath)) return true;
    // `requirements/*.txt` next to the manifest also counts.
    if (nested && [...nested].some(isRequirementsLockfilePath)) return true;
  }
  return false;
}

function requirementsDirOf(dir: string): string {
  return dir === "." || dir === "" ? "requirements" : `${dir}/requirements`;
}

function manifestHygieneWarnings(inventory: InventoryResult): string[] {
  const cargoCache: CargoWorkspaceCache = new Map();
  const warnings: string[] = [];
  const byDir = new Map<string, Set<string>>();
  for (const manifest of inventory.manifests) {
    const dir = dirOf(manifest.relPath);
    const set = byDir.get(dir) ?? new Set<string>();
    set.add(manifest.relPath);
    byDir.set(dir, set);
  }

  for (const manifest of inventory.manifests) {
    if (manifest.isLockfile) continue;
    const base = path.basename(manifest.relPath);
    const dir = dirOf(manifest.relPath);
    const present = byDir.get(dir) ?? new Set<string>();
    if (
      !hasRequiredLockfile(
        base,
        present,
        byDir.get(requirementsDirOf(dir)),
        () => isCargoWorkspaceMember(inventory.root, manifest.relPath, byDir, cargoCache),
      )
    ) {
      warnings.push(
        `${manifest.relPath}: no matching lockfile found; direct dependencies only (unresolved transitive dependencies)`,
      );
    }
    if (base.endsWith(".csproj") && !present.has("packages.lock.json")) {
      warnings.push(
        `${manifest.relPath}: packages.lock.json not found (unresolved transitive dependencies)`,
      );
    }
  }
  return warnings;
}

export interface ManifestLockfileIssue {
  /** Project-relative manifest path. */
  file: string;
  /** Line of the dependency declaration, or 1 when it cannot be found. */
  line: number;
  /** Manifest base name, e.g. package.json. */
  manifest: string;
}

function dependencyDeclarationLine(absPath: string, base: string): number {
  let content: string;
  try {
    content = fs.readFileSync(absPath, "utf8");
  } catch {
    return 1;
  }
  const patterns: RegExp[] =
    base === "package.json"
      ? [/"dependencies"\s*:/, /"devDependencies"\s*:/]
      : base === "pyproject.toml"
        ? [/^\s*dependencies\s*=/, /\[tool\.poetry\.dependencies\]/, /\[project\]/]
        : base === "Cargo.toml"
          ? [/^\s*\[(?:workspace\.)?dependencies\]/]
          : [];
  const lines = splitLines(content);
  for (let index = 0; index < lines.length; index += 1) {
    if (patterns.some((pattern) => pattern.test(lines[index] ?? ""))) {
      return index + 1;
    }
  }
  return 1;
}

/**
 * The same detection that produces the "no matching lockfile found" warning,
 * exposed as structured issues so the scanner can emit one low-confidence
 * hotspot per manifest that has no lockfile next to it.
 */
export function manifestLockfileIssues(
  inventory: InventoryResult,
): ManifestLockfileIssue[] {
  const cargoCache: CargoWorkspaceCache = new Map();
  const byDir = new Map<string, Set<string>>();
  for (const manifest of inventory.manifests) {
    const dir = dirOf(manifest.relPath);
    const set = byDir.get(dir) ?? new Set<string>();
    set.add(manifest.relPath);
    byDir.set(dir, set);
  }

  const issues: ManifestLockfileIssue[] = [];
  for (const manifest of inventory.manifests) {
    if (manifest.isLockfile) continue;
    const base = path.basename(manifest.relPath);
    const dir = dirOf(manifest.relPath);
    const present = byDir.get(dir) ?? new Set<string>();
    const required = EXPECTED_LOCKFILES[base];
    const missing = required
      ? !hasRequiredLockfile(
          base,
          present,
          byDir.get(requirementsDirOf(dir)),
          () => isCargoWorkspaceMember(inventory.root, manifest.relPath, byDir, cargoCache),
        )
      : base.endsWith(".csproj") &&
        ![...present].some((relPath) => path.posix.basename(relPath) === "packages.lock.json");
    if (!missing) continue;
    issues.push({
      file: manifest.relPath,
      line: dependencyDeclarationLine(
        path.join(inventory.root, manifest.relPath),
        base,
      ),
      manifest: base,
    });
  }
  return issues;
}

export function parseCvssV3(vector: string): number | undefined {
  const metrics = new Map<string, string>();
  for (const part of vector.split("/")) {
    const [key, value] = part.split(":");
    if (key && value) metrics.set(key, value);
  }
  const av = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[metrics.get("AV") ?? ""];
  const ac = { L: 0.77, H: 0.44 }[metrics.get("AC") ?? ""];
  const ui = { N: 0.85, R: 0.62 }[metrics.get("UI") ?? ""];
  const scopeChanged = metrics.get("S") === "C";
  const pr = scopeChanged
    ? { N: 0.85, L: 0.68, H: 0.5 }[metrics.get("PR") ?? ""]
    : { N: 0.85, L: 0.62, H: 0.27 }[metrics.get("PR") ?? ""];
  const impactMetric = { H: 0.56, L: 0.22, N: 0 } as Record<string, number>;
  const c = impactMetric[metrics.get("C") ?? ""];
  const i = impactMetric[metrics.get("I") ?? ""];
  const a = impactMetric[metrics.get("A") ?? ""];
  if (
    av === undefined ||
    ac === undefined ||
    ui === undefined ||
    pr === undefined ||
    c === undefined ||
    i === undefined ||
    a === undefined
  ) {
    return undefined;
  }

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  const exploitability = 8.22 * av * ac * pr * ui;
  if (impact <= 0) return 0;
  const base = scopeChanged
    ? Math.min(1.08 * (impact + exploitability), 10)
    : Math.min(impact + exploitability, 10);
  return Math.ceil(base * 10) / 10;
}

export function severityFromScore(score: number): Severity {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "info";
}

function severityFromText(value: string | undefined): Severity | undefined {
  if (!value) return undefined;
  const normalized = value.toUpperCase();
  if (normalized === "CRITICAL") return "critical";
  if (normalized === "HIGH") return "high";
  if (normalized === "MODERATE" || normalized === "MEDIUM") return "medium";
  if (normalized === "LOW") return "low";
  return undefined;
}

export interface OsvDetail {
  id?: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: Array<{ type?: string; score?: string }>;
  affected?: Array<{
    package?: { name?: string; ecosystem?: string };
    ranges?: Array<{
      type?: string;
      events?: Array<{ introduced?: string; fixed?: string; last_affected?: string }>;
    }>;
  }>;
  database_specific?: {
    severity?: string;
    cwe_ids?: string[];
  };
  references?: Array<{ url?: string }>;
}

export function extractSeverity(detail: OsvDetail | undefined): {
  severity: Severity;
  cvss?: number;
} {
  if (!detail) return { severity: "medium" };
  const textSeverity = severityFromText(detail.database_specific?.severity);
  for (const item of detail.severity ?? []) {
    if (item.type?.startsWith("CVSS_V3") && item.score) {
      const score = parseCvssV3(item.score);
      if (score !== undefined) {
        return { severity: severityFromScore(score), cvss: score };
      }
    }
  }
  if (textSeverity) return { severity: textSeverity };
  return { severity: "medium" };
}

function versionTokens(value: string): Array<number | string> {
  return value
    .trim()
    .replace(/^v/i, "")
    .split(/[.+-]/)
    .filter((part) => part.length > 0)
    .map((part) => (/^\d+$/.test(part) ? Number(part) : part.toLowerCase()));
}

/** Compare dotted versions, treating numeric segments numerically. */
export function compareVersions(a: string, b: string): number {
  const left = versionTokens(a);
  const right = versionTokens(b);
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const l = left[index];
    const r = right[index];
    if (l === undefined) return r === undefined ? 0 : -1;
    if (r === undefined) return 1;
    if (typeof l === "number" && typeof r === "number") {
      if (l !== r) return l < r ? -1 : 1;
      continue;
    }
    if (typeof l === "number") return 1;
    if (typeof r === "number") return -1;
    const compared = l.localeCompare(r);
    if (compared !== 0) return compared < 0 ? -1 : 1;
  }
  return 0;
}

/**
 * Compare Semantic Versioning 2.0 versions: build metadata is ignored and a
 * pre-release sorts before its release. Falls back to `compareVersions` when
 * either side is not `MAJOR.MINOR.PATCH`.
 */
export function compareSemver(a: string, b: string): number {
  const split = (value: string): { core: number[]; pre: string[] } | undefined => {
    const match = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(
      value.trim(),
    );
    if (!match) return undefined;
    return {
      core: [Number(match[1]), Number(match[2]), Number(match[3])],
      pre: match[4] ? match[4].split(".") : [],
    };
  };
  const left = split(a);
  const right = split(b);
  if (!left || !right) return compareVersions(a, b);
  for (let index = 0; index < 3; index += 1) {
    const l = left.core[index] as number;
    const r = right.core[index] as number;
    if (l !== r) return l < r ? -1 : 1;
  }
  if (left.pre.length === 0 || right.pre.length === 0) {
    if (left.pre.length === right.pre.length) return 0;
    return left.pre.length === 0 ? 1 : -1;
  }
  const length = Math.max(left.pre.length, right.pre.length);
  for (let index = 0; index < length; index += 1) {
    const l = left.pre[index];
    const r = right.pre[index];
    if (l === undefined) return -1;
    if (r === undefined) return 1;
    const ln = /^\d+$/.test(l);
    const rn = /^\d+$/.test(r);
    if (ln && rn) {
      const diff = Number(l) - Number(r);
      if (diff !== 0) return diff < 0 ? -1 : 1;
      continue;
    }
    if (ln !== rn) return ln ? -1 : 1;
    if (l !== r) return l < r ? -1 : 1;
  }
  return 0;
}

/**
 * Version comparator for an ecosystem: PEP 440 for PyPI, SemVer for
 * crates.io, generic otherwise.
 */
export function versionComparator(
  ecosystem: string | undefined,
): (a: string, b: string) => number {
  const eco = ecosystem?.toLowerCase();
  if (eco === "pypi") return comparePypiVersions;
  if (eco === "crates.io") return compareSemver;
  return compareVersions;
}

/**
 * Pick the smallest fixed version that is greater than the installed version.
 * OSV may return multiple ranges and affected entries; entries for another
 * package are ignored, and advisories with only `last_affected` have no fix.
 */
export function extractFixedVersion(
  detail: OsvDetail | undefined,
  pkg: { name: string; version: string; ecosystem?: string },
): string | undefined {
  if (!detail) return undefined;
  const candidates: string[] = [];
  const packageKey = normalizePackageName(pkg.name, pkg.ecosystem);
  for (const affected of detail.affected ?? []) {
    if (
      affected.package?.name &&
      normalizePackageName(affected.package.name, pkg.ecosystem) !== packageKey
    ) {
      continue;
    }
    if (
      affected.package?.ecosystem &&
      pkg.ecosystem &&
      affected.package.ecosystem.toLowerCase() !== pkg.ecosystem.toLowerCase()
    ) {
      continue;
    }
    for (const range of affected.ranges ?? []) {
      // GIT ranges carry commit hashes, not release versions.
      if (range.type?.toUpperCase() === "GIT") continue;
      for (const event of range.events ?? []) {
        if (event.fixed) candidates.push(event.fixed);
      }
    }
  }
  const compare = versionComparator(pkg.ecosystem);
  const applicable = candidates
    .filter((candidate) => compare(candidate, pkg.version) > 0)
    .sort(compare);
  return applicable[0];
}

const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL = "https://api.osv.dev/v1/vulns/";

export interface ScaOptions {
  root: string;
  inventory: InventoryResult;
  offline?: boolean;
  http?: HttpClient;
  batchSize?: number;
  timeoutMs?: number;
  detailConcurrency?: number;
  maxRetries?: number;
  retryBaseMs?: number;
  /** Lockfile relative paths already covered by an external scanner. */
  skipLockfiles?: string[];
  /** Injectable delay so tests do not wait for real backoff. */
  sleep?: (ms: number) => Promise<void>;
  /** Injectable dependency-file parser (tests); defaults to `parseLockfile`. */
  parseLockfile?: typeof parseLockfile;
}

function isRetryable(error: unknown): boolean {
  if (error instanceof HttpError) {
    return error.status === 429 || error.status >= 500;
  }
  const message = error instanceof Error ? error.message : String(error);
  return /HTTP (?:429|5\d\d)\b/.test(message);
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function requestWithRetry(
  request: () => Promise<unknown>,
  options: { maxRetries: number; retryBaseMs: number; sleep: (ms: number) => Promise<void> },
): Promise<unknown> {
  let attempt = 0;
  for (;;) {
    try {
      return await request();
    } catch (error) {
      if (attempt >= options.maxRetries || !isRetryable(error)) throw error;
      const delay = options.retryBaseMs * 2 ** attempt;
      attempt += 1;
      await options.sleep(delay);
    }
  }
}

/** Run tasks with a fixed concurrency limit, preserving input order. */
async function mapWithConcurrency<T, R>(
  items: T[],
  limit: number,
  worker: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const lanes = Array.from(
    { length: Math.max(1, Math.min(limit, items.length)) },
    async () => {
      for (;;) {
        const index = next;
        next += 1;
        if (index >= items.length) return;
        results[index] = await worker(items[index] as T, index);
      }
    },
  );
  await Promise.all(lanes);
  return results;
}

export interface ScaResult {
  findings: Finding[];
  warnings: string[];
  packages: ScaPackage[];
  queriedPackages: number;
  vulnIds: string[];
  unresolvedManifests: string[];
  /** True only when an OSV query or detail request failed (partial failure). */
  degraded: boolean;
}

function truncate(value: string, max = 300): string {
  const singleLine = value.replace(/\s+/g, " ").trim();
  return singleLine.length > max ? `${singleLine.slice(0, max)}…` : singleLine;
}

/**
 * Read the manifest next to a lockfile through the path jail: pyproject.toml
 * for the Python TOML lockfiles, Pipfile for Pipfile.lock, Cargo.toml (and the
 * workspace members among `manifestPaths`) for Cargo.lock. Returns undefined
 * when there is no sibling manifest so the caller keeps every package marked
 * direct.
 */
export function readSiblingManifest(
  root: string,
  lockfileRel: string,
  manifestPaths: readonly string[] = [],
): ManifestDependencies | undefined {
  const base = path.posix.basename(lockfileRel);
  if (base === "Cargo.lock") return readCargoManifests(root, lockfileRel, manifestPaths);
  const manifestName = base === "Pipfile.lock" ? "Pipfile" : "pyproject.toml";
  const isTomlLock =
    base === "poetry.lock" ||
    base === "uv.lock" ||
    base === "pdm.lock" ||
    base === "pylock.toml" ||
    /^pylock\..+\.toml$/.test(base);
  if (!isTomlLock && base !== "Pipfile.lock") return undefined;
  const dir = dirOf(lockfileRel);
  const rel = dir === "." ? manifestName : `${dir}/${manifestName}`;
  const read = readJailedFile(root, rel);
  if ("error" in read) {
    if (read.error === "ENOENT" || read.error === "ENOTDIR") return undefined;
    return emptyManifest(`${rel}: manifest was not read (${read.error})`);
  }
  return manifestName === "Pipfile"
    ? parsePipfileDependencies(read.content, rel)
    : parsePyprojectDependencies(read.content, rel);
}

const ADVISORY_ID_PREFERENCE = [/^GHSA-/i, /^CVE-/i];

/** Prefer a GHSA id, then a CVE id, then the first id. */
export function pickAdvisoryId(ids: string[]): string {
  for (const pattern of ADVISORY_ID_PREFERENCE) {
    const match = ids.find((id) => pattern.test(id));
    if (match) return match;
  }
  return ids[0] ?? "";
}

export interface AdvisoryEntry {
  id: string;
  detail?: OsvDetail;
}

/**
 * Group advisories that are the same vulnerability under different names
 * (PYSEC / GHSA / CVE). Two entries belong together when their id-plus-alias
 * sets intersect, or when an explicit group (OSV-Scanner `groups[].ids`)
 * lists both. Groups and their members keep first-seen order.
 */
export function groupAdvisories(
  entries: AdvisoryEntry[],
  explicitGroups: string[][] = [],
): AdvisoryEntry[][] {
  const unique: AdvisoryEntry[] = [];
  const indexById = new Map<string, number>();
  for (const entry of entries) {
    if (!entry.id || indexById.has(entry.id)) continue;
    indexById.set(entry.id, unique.length);
    unique.push(entry);
  }
  const parent = unique.map((_, index) => index);
  const find = (index: number): number => {
    let root = index;
    while (parent[root] !== root) root = parent[root] as number;
    while (parent[index] !== root) {
      const next = parent[index] as number;
      parent[index] = root;
      index = next;
    }
    return root;
  };
  const union = (a: number, b: number): void => {
    const ra = find(a);
    const rb = find(b);
    if (ra === rb) return;
    // Keep the earlier entry as the root so group order is stable.
    if (ra < rb) parent[rb] = ra;
    else parent[ra] = rb;
  };
  const owner = new Map<string, number>();
  const claim = (name: string, index: number): void => {
    const key = name.toUpperCase();
    const existing = owner.get(key);
    if (existing === undefined) owner.set(key, index);
    else union(existing, index);
  };
  unique.forEach((entry, index) => {
    claim(entry.id, index);
    for (const alias of entry.detail?.aliases ?? []) {
      if (typeof alias === "string" && alias) claim(alias, index);
    }
  });
  for (const ids of explicitGroups) {
    let first: number | undefined;
    for (const id of ids) {
      const index = indexById.get(id);
      if (index === undefined) continue;
      if (first === undefined) first = index;
      else union(first, index);
    }
  }
  const groups = new Map<number, AdvisoryEntry[]>();
  unique.forEach((entry, index) => {
    const root = find(index);
    const list = groups.get(root) ?? [];
    list.push(entry);
    groups.set(root, list);
  });
  return [...groups.values()];
}

export interface AdvisorySummary {
  advisoryId: string;
  /** Every other id and alias of the same vulnerability. */
  aliases: string[];
  severity: Severity;
  cvss?: number;
  fixedVersion?: string;
  summary: string;
  details: string;
  cwe: string;
  references: string[];
}

/**
 * Collapse one advisory group into a single description: the preferred id,
 * the highest severity, and the fixed version that satisfies every entry of
 * the group (the highest of the per-entry minimum fixes).
 */
export function summarizeAdvisoryGroup(
  entries: AdvisoryEntry[],
  pkg: { name: string; version: string; ecosystem?: string },
  extra: { aliases?: string[]; maxSeverityScore?: number } = {},
): AdvisorySummary {
  const advisoryId = pickAdvisoryId(entries.map((entry) => entry.id));
  const primary = entries.find((entry) => entry.id === advisoryId);
  const ordered = primary ? [primary, ...entries.filter((e) => e !== primary)] : entries;

  let severity: Severity | undefined;
  let cvss: number | undefined;
  const raise = (candidate: Severity): void => {
    if (!severity || SEVERITY_ORDER[candidate] > SEVERITY_ORDER[severity]) {
      severity = candidate;
    }
  };
  for (const entry of ordered) {
    const detail = entry.detail;
    if (!detail) continue;
    const extracted = extractSeverity(detail);
    const informative =
      extracted.cvss !== undefined ||
      severityFromText(detail.database_specific?.severity) !== undefined;
    if (!informative) continue;
    raise(extracted.severity);
    if (extracted.cvss !== undefined && (cvss === undefined || extracted.cvss > cvss)) {
      cvss = extracted.cvss;
    }
  }
  const score = extra.maxSeverityScore;
  if (score !== undefined && Number.isFinite(score) && score > 0 && score <= 10) {
    raise(severityFromScore(score));
    if (cvss === undefined || score > cvss) cvss = score;
  }

  const compare = versionComparator(pkg.ecosystem);
  let fixedVersion: string | undefined;
  for (const entry of ordered) {
    const fixed = extractFixedVersion(entry.detail, pkg);
    if (fixed && (!fixedVersion || compare(fixed, fixedVersion) > 0)) fixedVersion = fixed;
  }

  const seen = new Set<string>([advisoryId.toUpperCase()]);
  const aliases: string[] = [];
  const addAlias = (value: unknown): void => {
    if (typeof value !== "string" || !value) return;
    const key = value.toUpperCase();
    if (seen.has(key)) return;
    seen.add(key);
    aliases.push(value);
  };
  for (const entry of ordered) addAlias(entry.id);
  for (const entry of ordered) for (const alias of entry.detail?.aliases ?? []) addAlias(alias);
  for (const alias of extra.aliases ?? []) addAlias(alias);

  const summary =
    ordered.map((entry) => entry.detail?.summary).find((text) => Boolean(text)) ??
    `OSV advisory ${advisoryId}`;
  const details =
    ordered.map((entry) => entry.detail?.details).find((text) => Boolean(text)) ?? summary;
  const cwe =
    ordered
      .map((entry) => entry.detail?.database_specific?.cwe_ids?.[0])
      .find((value) => Boolean(value)) ?? "CWE-1104";
  const references = [
    ...new Set([
      `https://osv.dev/vulnerability/${advisoryId}`,
      ...ordered.flatMap((entry) =>
        (entry.detail?.references ?? [])
          .map((reference) => reference.url)
          .filter((url): url is string => Boolean(url)),
      ),
    ]),
  ].slice(0, 5);

  return {
    advisoryId,
    aliases,
    severity: severity ?? "medium",
    ...(cvss !== undefined ? { cvss } : {}),
    ...(fixedVersion ? { fixedVersion } : {}),
    summary,
    details,
    cwe,
    references,
  };
}

/** Human-readable dependency path used in SCA findings. */
export function describeDependencyPath(pkg: {
  manager: string;
  direct: boolean;
  scope?: DependencyScope;
  dev?: boolean;
}): string {
  if (pkg.dev || pkg.scope === "dev") return `${pkg.manager} dev dependency`;
  return pkg.direct
    ? `${pkg.manager} direct dependency`
    : `${pkg.manager} transitive dependency (from lockfile)`;
}

/** Remediation text of an SCA finding; always names `fixedVersion` when given. */
export function scaRemediation(name: string, fixedVersion: string | undefined): string {
  return fixedVersion
    ? `Upgrade ${name} to ${fixedVersion} or later; rerun the dependency audit and regression tests.`
    : `Upgrade ${name} to the latest stable or vendor-recommended version; confirm the impact before choosing mitigations.`;
}

/** Build the SCA finding for one advisory group of one package. */
export function buildScaFinding(input: {
  advisory: AdvisorySummary;
  name: string;
  version: string;
  ecosystem: string;
  file: string;
  line: number;
  dependencyPath: string;
  scope?: DependencyScope;
  provenance: { engine: string; rule?: string; version?: string };
}): Finding {
  const { advisory, name, version } = input;
  // `dependencyScope` is an additive SCA field; the finding schema passes
  // unknown keys through, so it reaches the JSON report unchanged.
  const init: FindingInit & { dependencyScope: DependencyScope } = {
    ruleId: `sca-${advisory.advisoryId.toLowerCase()}`,
    title: truncate(`${name}@${version}: ${advisory.summary}`, 160),
    category: "sca",
    severity: advisory.severity,
    confidence: "high",
    cvss: advisory.cvss,
    cwe: advisory.cwe,
    owasp: "A06:2021",
    file: input.file,
    startLine: input.line,
    evidence: `${name}@${version}`,
    message: truncate(advisory.details, 500),
    remediation: scaRemediation(name, advisory.fixedVersion),
    references: advisory.references,
    package: name,
    ecosystem: input.ecosystem,
    installedVersion: version,
    fixedVersion: advisory.fixedVersion,
    advisoryId: advisory.advisoryId,
    aliases: advisory.aliases,
    dependencyPath: input.dependencyPath,
    dependencyScope: input.scope ?? "unknown",
    reachable: "unknown",
    provenance: input.provenance,
  };
  return createFinding(init);
}

export async function runSca(options: ScaOptions): Promise<ScaResult> {
  const warnings = manifestHygieneWarnings(options.inventory);
  const findings: Finding[] = [];
  const packages: ScaPackage[] = [];
  const skipLockfiles = new Set(options.skipLockfiles ?? []);
  const visitedRequirements = new Set<string>();
  const manifestPaths = options.inventory.manifests.map((manifest) => manifest.relPath);
  const seenWarnings = new Set<string>(warnings);
  const perFileCount = new Map<string, number>();
  const overCap = new Map<string, number>();
  let scanCapExceeded = false;

  for (const lockfile of options.inventory.lockfiles) {
    if (skipLockfiles.has(lockfile.relPath)) continue;
    const base = path.basename(lockfile.relPath);
    if (base === "go.sum" || base === "yarn.lock") continue;
    const abs = path.join(options.root, lockfile.relPath);
    let content: string;
    try {
      content = fs.readFileSync(abs, "utf8");
    } catch (error) {
      warnings.push(
        `${lockfile.relPath}: cannot read lockfile (${error instanceof Error ? error.message : String(error)})`,
      );
      continue;
    }
    // One hostile or broken dependency file must never abort the scan: any
    // exception while parsing it becomes a warning and the next file is read.
    let parsed: ParsedDependencies;
    try {
      const manifest = readSiblingManifest(options.root, lockfile.relPath, manifestPaths);
      if (manifest?.warning && !seenWarnings.has(manifest.warning)) {
        seenWarnings.add(manifest.warning);
        warnings.push(manifest.warning);
      }
      parsed = (options.parseLockfile ?? parseLockfile)(lockfile.relPath, content, {
        root: options.root,
        directNames: manifest,
        visitedRequirements,
      });
    } catch (error) {
      warnings.push(
        `${lockfile.relPath}: dependency file could not be parsed and was skipped (${
          error instanceof Error ? error.message : String(error)
        })`,
      );
      continue;
    }
    // Caps are counted per declaring file (an `-r` include is its own file).
    for (const pkg of parsed.packages) {
      if (packages.length >= MAX_DEPENDENCIES_PER_SCAN) {
        scanCapExceeded = true;
        break;
      }
      const count = perFileCount.get(pkg.file) ?? 0;
      if (count >= MAX_DEPENDENCIES_PER_FILE) {
        overCap.set(pkg.file, (overCap.get(pkg.file) ?? 0) + 1);
        continue;
      }
      perFileCount.set(pkg.file, count + 1);
      packages.push(pkg);
    }
    for (const warning of parsed.warnings) {
      if (!seenWarnings.has(warning)) {
        seenWarnings.add(warning);
        warnings.push(warning);
      }
    }
    if (scanCapExceeded) break;
  }
  for (const [file, dropped] of overCap) {
    warnings.push(
      `${file}: more than ${MAX_DEPENDENCIES_PER_FILE} dependencies; ${dropped} further entries were not checked`,
    );
  }
  if (scanCapExceeded) {
    warnings.push(
      `more than ${MAX_DEPENDENCIES_PER_SCAN} dependencies in this scan; the remaining dependency files were not checked`,
    );
  }

  // Every (file, package, version) occurrence is kept so that each lockfile
  // pinning a vulnerable release gets its own finding; OSV is queried once
  // per distinct (ecosystem, name, version).
  const uniquePackages = uniqueOccurrences(packages);
  const queryPackages = pushUnique(uniquePackages);
  const unresolvedManifests = warnings.filter((warning) =>
    warning.includes("unresolved transitive dependencies"),
  );

  if (uniquePackages.length === 0) {
    return {
      findings,
      warnings,
      packages: [],
      queriedPackages: 0,
      vulnIds: [],
      unresolvedManifests,
      degraded: false,
    };
  }

  if (options.offline) {
    warnings.push(
      `offline mode: skipped OSV.dev queries (${queryPackages.length} dependencies were not checked for vulnerabilities)`,
    );
    return {
      findings,
      warnings,
      packages: uniquePackages,
      queriedPackages: 0,
      vulnIds: [],
      unresolvedManifests,
      degraded: false,
    };
  }

  const http = options.http ?? fetchHttpClient;
  const batchSize = options.batchSize ?? 100;
  const timeoutMs = options.timeoutMs ?? 10_000;
  const detailConcurrency = Math.max(1, options.detailConcurrency ?? 8);
  const maxRetries = Math.max(0, options.maxRetries ?? 3);
  const retryBaseMs = options.retryBaseMs ?? 250;
  const sleep = options.sleep ?? defaultSleep;
  const retry = { maxRetries, retryBaseMs, sleep };
  const associations: Array<{ pkg: ScaPackage; vulnId: string }> = [];
  const idsByQuery = new Map<string, string[]>();
  let degraded = false;

  for (let offset = 0; offset < queryPackages.length; offset += batchSize) {
    const batch = queryPackages.slice(offset, offset + batchSize);
    let response: unknown;
    try {
      response = await requestWithRetry(
        () =>
          http.postJson(
            OSV_BATCH_URL,
            {
              queries: batch.map((pkg) => ({
                package: {
                  name: normalizePackageName(pkg.name, pkg.ecosystem),
                  ecosystem: pkg.ecosystem,
                },
                version: pkg.version,
              })),
            },
            { timeoutMs },
          ),
        retry,
      );
    } catch (error) {
      degraded = true;
      warnings.push(
        `OSV batch query failed (batch ${Math.floor(offset / batchSize) + 1}): ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
      continue;
    }

    const results = (response as { results?: unknown } | null)?.results;
    if (!Array.isArray(results)) {
      degraded = true;
      warnings.push("OSV batch response had an unexpected shape; the batch was skipped");
      continue;
    }
    for (let index = 0; index < batch.length; index += 1) {
      const pkg = batch[index];
      if (!pkg) continue;
      const result = results[index] as
        | { vulns?: Array<{ id?: string }> }
        | undefined;
      for (const vuln of result?.vulns ?? []) {
        if (typeof vuln.id !== "string" || !vuln.id) continue;
        const ids = idsByQuery.get(packageKey(pkg)) ?? [];
        if (ids.includes(vuln.id)) continue;
        ids.push(vuln.id);
        idsByQuery.set(packageKey(pkg), ids);
        associations.push({ pkg, vulnId: vuln.id });
      }
    }
  }

  const vulnIds = [...new Set(associations.map((item) => item.vulnId))];
  const details = new Map<string, OsvDetail>();
  const detailWarnings = new Array<string | undefined>(vulnIds.length);

  await mapWithConcurrency(vulnIds, detailConcurrency, async (vulnId, index) => {
    try {
      const detail = (await requestWithRetry(
        () =>
          http.getJson(`${OSV_VULN_URL}${encodeURIComponent(vulnId)}`, {
            timeoutMs,
          }),
        retry,
      )) as OsvDetail;
      details.set(vulnId, detail);
    } catch (error) {
      degraded = true;
      detailWarnings[index] =
        `OSV vulnerability detail fetch failed ${vulnId}: ${
          error instanceof Error ? error.message : String(error)
        }`;
    }
  });
  for (const warning of detailWarnings) {
    if (warning) warnings.push(warning);
  }

  // One finding per vulnerability: the same advisory published as PYSEC-x and
  // GHSA-y (linked through a shared alias) is reported once.
  const advisoriesByQuery = new Map<string, AdvisorySummary[]>();
  for (const pkg of queryPackages) {
    const ids = idsByQuery.get(packageKey(pkg));
    if (!ids) continue;
    advisoriesByQuery.set(
      packageKey(pkg),
      groupAdvisories(ids.map((id) => ({ id, detail: details.get(id) }))).map((group) =>
        summarizeAdvisoryGroup(group, pkg),
      ),
    );
  }
  for (const pkg of uniquePackages) {
    for (const advisory of advisoriesByQuery.get(packageKey(pkg)) ?? []) {
      findings.push(
        buildScaFinding({
          advisory,
          name: pkg.name,
          version: pkg.version,
          ecosystem: pkg.ecosystem,
          file: pkg.file,
          line: pkg.line,
          dependencyPath: describeDependencyPath(pkg),
          scope: pkg.scope,
          provenance: { engine: "osv", rule: advisory.advisoryId },
        }),
      );
    }
  }

  return {
    findings,
    warnings,
    packages: uniquePackages,
    queriedPackages: queryPackages.length,
    vulnIds,
    unresolvedManifests,
    degraded,
  };
}
