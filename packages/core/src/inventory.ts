import { countLines as countPhysicalLines, splitLines } from "./redact.js";
import fs from "node:fs";
import path from "node:path";
import { detectLanguage, type Language } from "./language.js";
import { toPosixRelative, validateAuditRoot } from "./pathJail.js";
import { BASELINE_FILE_NAME, IGNORE_FILE_NAME } from "./ignore.js";

export const DEFAULT_EXCLUDED_DIRS = [
  "node_modules",
  "vendor",
  "dist",
  "build",
  "target",
  "bin",
  "obj",
  ".git",
  ".audit",
  ".code-audit",
  ".next",
  "coverage",
  "__pycache__",
  ".venv",
  "venv",
  ".gradle",
  ".cache",
  "Pods",
];

const BINARY_EXTENSIONS = new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".bmp",
  ".ico",
  ".webp",
  ".pdf",
  ".zip",
  ".gz",
  ".tgz",
  ".tar",
  ".bz2",
  ".xz",
  ".7z",
  ".rar",
  ".exe",
  ".dll",
  ".so",
  ".dylib",
  ".class",
  ".jar",
  ".war",
  ".ear",
  ".o",
  ".a",
  ".obj",
  ".lib",
  ".pyc",
  ".pyo",
  ".woff",
  ".woff2",
  ".ttf",
  ".eot",
  ".mp3",
  ".mp4",
  ".mov",
  ".avi",
  ".sqlite",
  ".db",
]);

export const MAX_TEXT_FILE_BYTES = 1024 * 1024;

export type ManifestType =
  | "npm"
  | "pnpm"
  | "yarn"
  | "requirements"
  | "poetry"
  | "uv"
  | "pdm"
  | "pipfile"
  | "pylock"
  | "go"
  | "maven"
  | "nuget"
  | "cargo"
  | "composer"
  | "unknown";

export interface InventoryFile {
  relPath: string;
  absPath: string;
  language: Language;
  size: number;
  loc: number;
  kind: "source" | "config" | "doc" | "lockfile" | "manifest" | "other";
  /**
   * True when the file gets the full analysis: source rules (when its
   * language is known) and every secret detector. Only machine-generated
   * lockfiles are not scannable; see the policy above `LOCKFILE_MARKERS`.
   */
  scannable: boolean;
  /** True when the file is a dependency source for the SCA engine. */
  isLockfile: boolean;
  manifestType?: ManifestType;
}

export interface SkippedFile {
  relPath: string;
  reason: string;
}

export interface ManifestRef {
  relPath: string;
  type: ManifestType;
  isLockfile: boolean;
}

export interface InventoryResult {
  root: string;
  files: InventoryFile[];
  skipped: SkippedFile[];
  stats: {
    files: number;
    /** Files that were read and analysed, fully or partially. */
    scannedFiles: number;
    /**
     * Subset of `scannedFiles` that was only partially analysed: generated
     * lockfiles, which are read for dependencies and high-confidence secrets
     * but not matched against source rules or the generic secret heuristic.
     */
    partialFiles: number;
    skippedFiles: number;
    totalBytes: number;
    loc: number;
  };
  languages: Record<string, { files: number; loc: number }>;
  manifests: ManifestRef[];
  lockfiles: ManifestRef[];
  warnings: string[];
}

interface Marker {
  /** `text` is the file content, for markers that need to look inside. */
  match: (baseName: string, relPath: string, text: string) => boolean;
  type: ManifestType;
  lockfile: boolean;
  /**
   * True for lockfiles written by a tool (hash-heavy, never edited by hand).
   * Dependency files people write by hand (requirements files, go.mod) are
   * lockfiles for SCA but are still fully scanned.
   */
  generated?: boolean;
}

/**
 * True for `requirements.txt`, `requirements*.txt`, `*requirements.txt` and any
 * `*.txt` directly inside a `requirements/` directory. This is a name check
 * only; the inventory additionally requires the content of every such file
 * other than a plain `requirements.txt` to look like a requirements file
 * (`looksLikeRequirements`).
 */
export function isRequirementsLockfilePath(relPath: string): boolean {
  const normalized = relPath.split(path.sep).join("/");
  const parts = normalized.split("/");
  const base = parts.pop() ?? "";
  // The directory that directly contains the file, at any depth.
  const parent = parts[parts.length - 1] ?? "";
  if (base === "requirements.txt") return true;
  if (/^requirements.*\.txt$/.test(base)) return true;
  if (/requirements\.txt$/.test(base)) return true;
  if (parent === "requirements" && base.endsWith(".txt")) return true;
  return false;
}

const REQUIREMENT_SPECIFIER_LINE =
  /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,200}[A-Za-z0-9])?\s*(?:\[[^\]]{0,500}\])?\s*(?:\(?\s*(?:===|==|~=|!=|<=|>=|<|>)\s*[^\s=].*|@\s*\S.*|;.*)?$/;
const PIP_OPTION_LINE = /^--?[A-Za-z]/;
const REQUIREMENT_URL_LINE = /^(?:[A-Za-z][A-Za-z0-9+.-]*:\/\/|\.{0,2}\/)\S/;

/**
 * True when more than half of the non-blank, non-comment lines are pip
 * requirement specifiers (`name`, `name==1.0`, `name[extra]>=1 ; marker`,
 * `name @ url`), pip options (`-r x`, `--hash=...`) or URL/path requirements.
 * A file with no such lines at all (empty or comments only) counts as a
 * requirements file. Used to tell `requirements/notes.txt` (prose) apart from
 * `requirements/dev.txt`.
 */
export function looksLikeRequirements(text: string): boolean {
  let total = 0;
  let matching = 0;
  for (const raw of splitLines(text)) {
    let line = raw.trim();
    if (line.charCodeAt(0) === 0xfeff) line = line.slice(1).trim();
    if (!line || line.startsWith("#")) continue;
    const comment = line.search(/\s#/);
    if (comment >= 0) line = line.slice(0, comment).trim();
    if (line.endsWith("\\")) line = line.slice(0, -1).trim();
    if (!line) continue;
    total += 1;
    if (
      PIP_OPTION_LINE.test(line) ||
      REQUIREMENT_URL_LINE.test(line) ||
      REQUIREMENT_SPECIFIER_LINE.test(line)
    ) {
      matching += 1;
    }
  }
  return total === 0 || matching * 2 > total;
}

/** Lines of the form `name==1.2.3` (a pin) in a text. */
export function countPinnedRequirements(text: string): number {
  let count = 0;
  for (const raw of splitLines(text)) {
    if (raw.length > 500) continue;
    if (/^\s*[A-Za-z0-9][A-Za-z0-9._-]{0,200}\s*(?:\[[^\]]{0,200}\])?\s*===?\s*[0-9][^\s;#]{0,100}/.test(raw)) {
      count += 1;
    }
  }
  return count;
}

/** A named `pylock.<name>.toml` is a PEP 751 lockfile only with a `lock-version` key. */
function looksLikePylock(text: string): boolean {
  return /^[ \t]*lock-version[ \t]*=/m.test(text);
}

/*
 * Analysis policy for dependency files
 * ------------------------------------
 * 1. Hand-written dependency files -- requirements-style `.txt` files, go.mod
 *    and every manifest (package.json, pyproject.toml, Pipfile, ...) -- are
 *    `scannable`: all secret detectors run on them (an `--index-url` with
 *    embedded credentials is a finding) and source rules apply when the
 *    language is known. They are additionally parsed for dependencies.
 * 2. Generated lockfiles (`generated: true` below) are not `scannable`: they
 *    are thousands of lines of hashes that no source rule is written for,
 *    and the generic `password = "..."` entropy heuristic is not run on them.
 *    They are NOT exempt from secret detection: the high-confidence detectors
 *    (private-key blocks, AWS / GitHub / Slack token formats, credentials
 *    embedded in a URL) still run, see `scanSecrets`. Those formats cannot be
 *    produced by a hex digest or a base64 integrity hash. Such files are
 *    counted in `stats.partialFiles`.
 * 3. A file is only classified by its name when the name is unambiguous. A
 *    `.txt` that merely sits in `requirements/` or has "requirements" in its
 *    name, and a `pylock.<name>.toml`, must also look like what the name
 *    claims; otherwise it is an ordinary, fully scanned text file and is not
 *    parsed for dependencies.
 */
const LOCKFILE_MARKERS: Marker[] = [
  { match: (b) => b === "package-lock.json", type: "npm", lockfile: true, generated: true },
  { match: (b) => b === "pnpm-lock.yaml", type: "pnpm", lockfile: true, generated: true },
  { match: (b) => b === "yarn.lock", type: "yarn", lockfile: true, generated: true },
  { match: (b) => b === "requirements.txt", type: "requirements", lockfile: true },
  {
    match: (_b, rel, text) => isRequirementsLockfilePath(rel) && looksLikeRequirements(text),
    type: "requirements",
    lockfile: true,
  },
  { match: (b) => b === "poetry.lock", type: "poetry", lockfile: true, generated: true },
  { match: (b) => b === "uv.lock", type: "uv", lockfile: true, generated: true },
  { match: (b) => b === "pdm.lock", type: "pdm", lockfile: true, generated: true },
  { match: (b) => b === "Pipfile.lock", type: "pipfile", lockfile: true, generated: true },
  {
    match: (b, _rel, text) =>
      b === "pylock.toml" || (/^pylock\..+\.toml$/.test(b) && looksLikePylock(text)),
    type: "pylock",
    lockfile: true,
    generated: true,
  },
  { match: (b) => b === "go.mod", type: "go", lockfile: true },
  { match: (b) => b === "go.sum", type: "go", lockfile: true, generated: true },
  { match: (b) => b === "packages.lock.json", type: "nuget", lockfile: true, generated: true },
  { match: (b) => b === "Cargo.lock", type: "cargo", lockfile: true, generated: true },
  { match: (b) => b === "composer.lock", type: "composer", lockfile: true, generated: true },
];

const MANIFEST_MARKERS: Marker[] = [
  { match: (b) => b === "package.json", type: "npm", lockfile: false },
  { match: (b) => b === "pyproject.toml", type: "requirements", lockfile: false },
  { match: (b) => b === "Pipfile", type: "requirements", lockfile: false },
  { match: (b) => b === "pom.xml", type: "maven", lockfile: false },
  { match: (b) => b.endsWith(".csproj"), type: "nuget", lockfile: false },
  { match: (b) => b === "Cargo.toml", type: "cargo", lockfile: false },
  { match: (b) => b === "composer.json", type: "composer", lockfile: false },
  { match: (b) => b === "vcpkg.json", type: "unknown", lockfile: false },
];

function classifyManifest(
  baseName: string,
  relPath: string,
  text: string,
): Marker | undefined {
  return (
    LOCKFILE_MARKERS.find((marker) => marker.match(baseName, relPath, text)) ??
    MANIFEST_MARKERS.find((marker) => marker.match(baseName, relPath, text))
  );
}

function kindFor(language: Language, isLockfile: boolean, manifest: boolean): InventoryFile["kind"] {
  if (isLockfile) return "lockfile";
  if (manifest) return "manifest";
  if (language === "markdown") return "doc";
  if (
    language === "json" ||
    language === "yaml" ||
    language === "dockerfile"
  ) {
    return "config";
  }
  if (language !== "unknown") return "source";
  return "other";
}

function countLines(text: string): number {
  // Same line breaks as splitLines: \r\n, a lone \r and \n.
  return countPhysicalLines(text);
}

function looksBinary(buffer: Buffer): boolean {
  const limit = Math.min(buffer.length, 8192);
  for (let i = 0; i < limit; i += 1) {
    if (buffer[i] === 0) return true;
  }
  return false;
}

export interface InventoryOptions {
  excludes?: string[];
  maxFileSize?: number;
}

/**
 * Read the manifest written by `code-audit install` and return the set of
 * project-relative files that the installer created or owns. Those files are
 * adapter plumbing, not user code, so the inventory skips them. A user's own
 * `opencode.json` or `SKILL.md` that predates the install is not listed.
 */
function readAdapterFileManifest(root: string): Set<string> {
  const file = path.join(root, ".code-audit", "installed.json");
  let document: unknown;
  try {
    document = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return new Set<string>();
  }
  const files = (document as { files?: unknown } | null)?.files;
  const skip = new Set<string>();
  if (!Array.isArray(files)) return skip;
  for (const entry of files) {
    const record = entry as { path?: unknown; skip?: unknown };
    if (typeof record.path !== "string" || record.skip !== true) continue;
    skip.add(record.path.split("\\").join("/").replace(/^\.\//, ""));
  }
  return skip;
}

export function inventory(
  rootInput: string,
  options: InventoryOptions = {},
): InventoryResult {
  const { root } = validateAuditRoot(rootInput);
  const excludedDirs = new Set(
    (options.excludes ?? DEFAULT_EXCLUDED_DIRS).map((name) => name.toLowerCase()),
  );
  const maxFileSize = options.maxFileSize ?? MAX_TEXT_FILE_BYTES;
  const adapterFiles = readAdapterFileManifest(root);

  const files: InventoryFile[] = [];
  const skipped: SkippedFile[] = [];
  const warnings: string[] = [];
  const languages: Record<string, { files: number; loc: number }> = {};
  const manifests: ManifestRef[] = [];

  let totalBytes = 0;
  let totalLoc = 0;
  let partialFiles = 0;

  const walk = (dir: string): void => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (error) {
      const err = error as NodeJS.ErrnoException;
      skipped.push({
        relPath: toPosixRelative(root, dir),
        reason: `cannot read directory: ${err.code ?? err.message}`,
      });
      return;
    }

    entries.sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      const abs = path.join(dir, entry.name);
      const rel = toPosixRelative(root, abs);

      if (entry.isSymbolicLink()) {
        skipped.push({
          relPath: rel,
          reason: "symbolic link (skipped to avoid escape or loops)",
        });
        continue;
      }

      if (entry.isDirectory()) {
        if (excludedDirs.has(entry.name.toLowerCase())) {
          skipped.push({ relPath: `${rel}/`, reason: "default-excluded directory" });
          continue;
        }
        walk(abs);
        continue;
      }

      if (!entry.isFile()) {
        skipped.push({ relPath: rel, reason: "not a regular file" });
        continue;
      }

      if (adapterFiles.has(rel)) {
        skipped.push({ relPath: rel, reason: "code-audit adapter file" });
        continue;
      }

      if (rel === IGNORE_FILE_NAME || rel === BASELINE_FILE_NAME) {
        skipped.push({ relPath: rel, reason: "code-audit control file" });
        continue;
      }

      let stat: fs.Stats;
      try {
        stat = fs.statSync(abs);
      } catch (error) {
        const err = error as NodeJS.ErrnoException;
        skipped.push({ relPath: rel, reason: `cannot stat file: ${err.code}` });
        continue;
      }

      const ext = path.extname(entry.name).toLowerCase();
      if (BINARY_EXTENSIONS.has(ext)) {
        skipped.push({ relPath: rel, reason: "binary extension" });
        continue;
      }
      if (stat.size > maxFileSize) {
        skipped.push({
          relPath: rel,
          reason: `file exceeds the ${Math.floor(maxFileSize / 1024 / 1024)} MB limit`,
        });
        continue;
      }

      let buffer: Buffer;
      try {
        buffer = fs.readFileSync(abs);
      } catch (error) {
        const err = error as NodeJS.ErrnoException;
        skipped.push({ relPath: rel, reason: `cannot read file: ${err.code}` });
        continue;
      }
      if (looksBinary(buffer)) {
        skipped.push({ relPath: rel, reason: "binary content detected (NUL byte)" });
        continue;
      }

      const text = buffer.toString("utf8");
      const loc = countLines(text);
      const language = detectLanguage(rel);
      const marker = classifyManifest(entry.name, rel, text);
      const isLockfile = marker?.lockfile ?? false;
      const isManifest = Boolean(marker);
      const kind = kindFor(language, isLockfile, isManifest);
      const scannable = !(marker?.generated ?? false);
      if (!scannable) partialFiles += 1;
      if (!marker && isRequirementsLockfilePath(rel)) {
        // The name says requirements, the content mostly does not (pip would
        // reject such a file). It is scanned as text; pins in it are not
        // dependencies, and that is said out loud.
        const pinned = countPinnedRequirements(text);
        if (pinned > 0) {
          warnings.push(
            `${rel}: named like a requirements file but most lines are not requirement specifiers; ${pinned} pinned line(s) in it were not analysed as dependencies`,
          );
        }
      }

      files.push({
        relPath: rel,
        absPath: abs,
        language,
        size: stat.size,
        loc,
        kind,
        scannable,
        isLockfile,
        manifestType: marker?.type,
      });

      totalBytes += stat.size;
      totalLoc += loc;
      if (language !== "unknown") {
        const entryStats = languages[language] ?? { files: 0, loc: 0 };
        entryStats.files += 1;
        entryStats.loc += loc;
        languages[language] = entryStats;
      }
      if (marker) {
        manifests.push({
          relPath: rel,
          type: marker.type,
          isLockfile: marker.lockfile,
        });
      }
    }
  };

  walk(root);

  const lockfiles = manifests.filter((manifest) => manifest.isLockfile);

  return {
    root,
    files,
    skipped,
    stats: {
      files: files.length + skipped.length,
      scannedFiles: files.length,
      partialFiles,
      skippedFiles: skipped.length,
      totalBytes,
      loc: totalLoc,
    },
    languages,
    manifests,
    lockfiles,
    warnings,
  };
}
