import fs from "node:fs";
import path from "node:path";
import { detectLanguage, type Language } from "./language.js";
import { toPosixRelative, validateAuditRoot } from "./pathJail.js";

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
  scannable: boolean;
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
    scannedFiles: number;
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
  match: (baseName: string) => boolean;
  type: ManifestType;
  lockfile: boolean;
}

const LOCKFILE_MARKERS: Marker[] = [
  { match: (b) => b === "package-lock.json", type: "npm", lockfile: true },
  { match: (b) => b === "pnpm-lock.yaml", type: "pnpm", lockfile: true },
  { match: (b) => b === "yarn.lock", type: "yarn", lockfile: true },
  { match: (b) => b === "requirements.txt", type: "requirements", lockfile: true },
  { match: (b) => b === "poetry.lock", type: "poetry", lockfile: true },
  { match: (b) => b === "go.mod", type: "go", lockfile: true },
  { match: (b) => b === "go.sum", type: "go", lockfile: true },
  { match: (b) => b === "packages.lock.json", type: "nuget", lockfile: true },
  { match: (b) => b === "Cargo.lock", type: "cargo", lockfile: true },
  { match: (b) => b === "composer.lock", type: "composer", lockfile: true },
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

function classifyManifest(baseName: string): Marker | undefined {
  return (
    LOCKFILE_MARKERS.find((marker) => marker.match(baseName)) ??
    MANIFEST_MARKERS.find((marker) => marker.match(baseName))
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
  if (text.length === 0) return 0;
  let count = 1;
  for (let i = 0; i < text.length; i += 1) {
    if (text.charCodeAt(i) === 10) count += 1;
  }
  return count;
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
      const marker = classifyManifest(entry.name);
      const isLockfile = marker?.lockfile ?? false;
      const isManifest = Boolean(marker);
      const kind = kindFor(language, isLockfile, isManifest);
      const scannable = !isLockfile;

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
