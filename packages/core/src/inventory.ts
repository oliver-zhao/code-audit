import { countLines as countPhysicalLines, splitLines } from "./redact.js";
import fs from "node:fs";
import path from "node:path";
import { CONFIG_LANGUAGES, SOURCE_LANGUAGES, detectLanguage, type Language } from "./language.js";
import { toPosixRelative, validateAuditRoot } from "./pathJail.js";
import { BASELINE_FILE_NAME, IGNORE_FILE_NAME } from "./ignore.js";
import type { PathContext } from "./finding.js";
import { classifyFileDetailed, type PathContextSource } from "./pathContext.js";
import { LATEST_OUTPUT_FILES, RUN_OUTPUT_FILES, TOOL_NAME, toolRootDir } from "./meta.js";
import {
  MAX_BINARY_FILES,
  binaryFileOf,
  isAgentPackagePath,
  looksExecutableHeader,
  readMagic,
  type BinaryFile,
} from "./binaryRules.js";
import {
  NUGET_PROJECT_FILE,
  isNuGetImportedFile,
  isNuGetLockfileName,
  isPackagesConfigName,
} from "./nuget.js";

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

/** Directory entries looked at, per skill or plugin tree, while listing binaries in its excluded directories. */
export const BINARY_LIST_MAX_ENTRIES = 20_000;
/**
 * Excluded directories that are not listed for binaries when they sit
 * directly in the audit root (dependencies and tool output of the audited
 * project itself). Inside a skill or plugin tree below the root they are
 * listed like any other directory.
 */
const BINARY_LIST_ROOT_SKIPPED_DIRS = new Set([".git", "node_modules", ".venv", "venv", ".audit", ".code-audit"]);

/**
 * Instruction files that agent hosts load (the `{{INSTR}}` paths of
 * rules/agent plus `commands/*.md`), matched case-insensitively. A symbolic
 * link at such a path is read through the link (see `inventory`).
 */
const INSTRUCTION_PATH =
  /(?:^|\/)(?:CLAUDE(?:\.local)?|AGENTS(?:\.override)?|AGENT|GEMINI|SKILL|QWEN|CRUSH|WARP)\.md$|(?:^|\/)(?:\.cursorrules|\.windsurfrules|\.clinerules|\.rules)$|(?:^|\/)\.github\/(?:copilot-instructions\.md|(?:instructions|prompts|agents|chatmodes)\/.+\.md)$|(?:^|\/)\.(?:claude|opencode|codex|agents|cursor|windsurf|clinerules|roo|kilocode|continue|kiro|junie|gemini|qwen|dsh|amazonq|augment|trae)\/.+\.mdc?$|(?:^|\/)plugins\/[^/]+\/(?:agents|commands|skills)\/.+\.md$|(?:^|\/)commands\/[^/]+\.md$/i;
/** Instruction files of a skill or plugin tree, relative to the tree root. */
const TREE_INSTRUCTION_PATH = /(?:^|\/)SKILL\.md$|(?:^|\/)(?:agents|commands)\/[^/]+\.md$|(?:^|\/)skills\/.+\.md$/i;

function isInstructionPath(rel: string, treeRoot: string | undefined): boolean {
  if (INSTRUCTION_PATH.test(rel)) return true;
  if (treeRoot === undefined) return false;
  return TREE_INSTRUCTION_PATH.test(treeRoot === "" ? rel : rel.slice(treeRoot.length + 1));
}

/** Interpreter named on a `#!` line, for extensionless scripts in skill trees. */
const SHEBANG = /^#![ \t]*(?:\/usr\/bin\/env[ \t]+(?:-S[ \t]+)?)?(?:\S*\/)?(bash|sh|zsh|ksh|dash|fish|python[0-9.]*|pypy[0-9.]*|node|nodejs|deno|bun|tsx|ts-node)\b/;

function shebangLanguage(text: string): Language | undefined {
  const match = SHEBANG.exec(text.slice(0, 200));
  if (!match) return undefined;
  const name = match[1] as string;
  if (/^(?:python|pypy)/.test(name)) return "python";
  if (/^(?:tsx|ts-node)$/.test(name)) return "typescript";
  if (/^(?:node|nodejs|deno|bun)$/.test(name)) return "javascript";
  return "shell";
}

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
  /**
   * Test, docs, example, vendored or generated file, by path (and, for
   * generated, a header comment). Absent for ordinary source. See
   * `pathContext.ts`.
   */
  pathContext?: PathContext;
  /**
   * What decided `pathContext`: the path, or a generated-file header comment.
   * Only a path classification lowers confidence.
   */
  pathContextSource?: PathContextSource;
  /**
   * True for an entry of `InventoryResult.toolOutput`: a file that carries
   * the tool's own output name inside a directory recognised as one of its
   * run directories. Secret detectors run on it; rules do not.
   */
  toolOutput?: boolean;
  /**
   * Set when the file is inside a skill or plugin tree: the relative path of
   * the nearest directory (the file's own or a parent, the root included,
   * as "") that holds `SKILL.md`, `plugin.json` or `.claude-plugin/plugin.json`.
   * Rules with `inSkillTree` use it.
   */
  skillTreeRoot?: string;
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
  /**
   * Files recognised as the tool's own output (reports of earlier runs in an
   * `--out` directory inside the audit root). They are listed in `skipped`
   * and are exempt from rule matching (a report quotes vulnerable code), but
   * the scan still runs every secret detector on them: genuine output never
   * holds a secret in clear text, and the marker that makes a directory a run
   * directory is data of the audited repository. Files of the run being
   * written, and files over the size limit (`toolOutputUnread`), are not here.
   */
  toolOutput: InventoryFile[];
  /** Recognised tool-output files that were too large or unreadable. */
  toolOutputUnread: number;
  /**
   * Source files (by extension) inside default-excluded directories, which
   * were not read. Counted per excluded directory name; `truncated` when the
   * count stopped at `EXCLUDED_COUNT_MAX_ENTRIES` directory entries.
   */
  excludedSource: { total: number; truncated: boolean; byDirectory: Record<string, number> };
  /**
   * Files inside skill and plugin directories that were not read as text
   * (binary extension or content, over the size limit, in a default-excluded
   * directory), and text files there whose header is an executable or archive
   * header: path, size and the first 8 bytes. Matched by binary rules; see
   * `binaryRules.ts`.
   */
  binaries: BinaryFile[];
  /**
   * Skill or plugin trees (relative path of the tree root, "" for the audit
   * root; or of the excluded directory when no tree root is known) whose
   * binary list is incomplete: the entry budget of the tree, the depth limit
   * or the list cap was reached. A consumer that gives a verdict on a
   * package must treat such a tree as not fully scanned.
   */
  binaryListIncomplete: string[];
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
  { match: isNuGetLockfileName, type: "nuget", lockfile: true, generated: true },
  // NuGet project files, packages.config and the Directory.* MSBuild files
  // are written by hand: read for dependencies and fully scanned.
  { match: (b) => NUGET_PROJECT_FILE.test(b), type: "nuget", lockfile: true },
  { match: isPackagesConfigName, type: "nuget", lockfile: true },
  { match: isNuGetImportedFile, type: "nuget", lockfile: true },
  { match: (b) => b === "Cargo.lock", type: "cargo", lockfile: true, generated: true },
  { match: (b) => b === "composer.lock", type: "composer", lockfile: true, generated: true },
];

const MANIFEST_MARKERS: Marker[] = [
  { match: (b) => b === "package.json", type: "npm", lockfile: false },
  { match: (b) => b === "pyproject.toml", type: "requirements", lockfile: false },
  { match: (b) => b === "Pipfile", type: "requirements", lockfile: false },
  { match: (b) => b === "pom.xml", type: "maven", lockfile: false },
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
  if (CONFIG_LANGUAGES.includes(language)) return "config";
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
  /**
   * Run directories the caller itself is writing to (absolute paths), for a
   * scan whose `--out` is inside the audit root: the run has no `run.json`
   * yet, so it cannot be recognised by its content.
   */
  ownRunDirs?: string[];
  /**
   * Audit of a repository that is not trusted: default-excluded directories
   * (all but `.git`) are scanned like any other, and files that are
   * byte-identical to the tool's shipped adapter files are scanned too.
   */
  untrusted?: boolean;
}

/**
 * Adapter files that `code-audit install` writes verbatim, by project-relative
 * path, and the shipped file each one is a copy of (relative to the tool
 * root). `packages/cli/src/install.ts` writes exactly these (a test compares
 * the two); the plugin layout of releases up to 0.1.0 is included.
 *
 * The inventory skips such a file ONLY when its content is identical to the
 * shipped file (after newline normalisation). Nothing inside the audited
 * repository -- not `.code-audit/installed.json`, not the path -- can make
 * the scanner skip a file: a `SKILL.md` with one changed byte is audited.
 *
 * Files the installer merges into (`.mcp.json`, `AGENTS.md`, `opencode.json`,
 * `.codex/config.toml`, `dsh/cordis.patch.yml`) hold user content and are
 * always scanned in full.
 */
export const ADAPTER_OWNED_FILES: Readonly<Record<string, string>> = {
  ".opencode/skills/code-audit/SKILL.md": "skills/code-audit/SKILL.md",
  ".dsh/skills/code-audit/SKILL.md": "skills/code-audit/SKILL.md",
  ".claude/skills/code-audit/SKILL.md": "skills/code-audit/SKILL.md",
  ".agents/skills/code-audit/SKILL.md": "skills/code-audit/SKILL.md",
  ".opencode/commands/audit.md": "adapters/opencode/commands/audit.md",
  ".claude/commands/audit.md": "adapters/claude-code/commands/audit.md",
  // Plugin layout written into the project root by releases up to 0.1.0.
  "skills/code-audit/SKILL.md": "skills/code-audit/SKILL.md",
  "commands/audit.md": "adapters/claude-code/commands/audit.md",
  ".claude-plugin/plugin.json": "adapters/claude-code/.claude-plugin/plugin.json",
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const normalizeNewlines = (text: string): string => text.replace(/\r\n?/g, "\n");

const shippedAdapterCache = new Map<string, string | undefined>();

function shippedAdapterText(source: string): string | undefined {
  if (shippedAdapterCache.has(source)) return shippedAdapterCache.get(source);
  let text: string | undefined;
  try {
    text = normalizeNewlines(fs.readFileSync(path.join(toolRootDir(), source), "utf8"));
  } catch {
    // Packaged without the adapter sources: nothing can be recognised, so
    // nothing is skipped.
    text = undefined;
  }
  shippedAdapterCache.set(source, text);
  return text;
}

/**
 * True when `relPath` is one of the fixed adapter paths and `text` is exactly
 * what this version of the tool installs there.
 */
export function isShippedAdapterFile(relPath: string, text: string): boolean {
  if (!Object.prototype.hasOwnProperty.call(ADAPTER_OWNED_FILES, relPath)) return false;
  const shipped = shippedAdapterText(ADAPTER_OWNED_FILES[relPath] as string);
  return shipped !== undefined && shipped.length > 0 && normalizeNewlines(text) === shipped;
}

/** Directory entries looked at while counting source files in excluded directories. */
export const EXCLUDED_COUNT_MAX_ENTRIES = 50_000;

/** Excluded directories that are never scanned or counted, even for `untrusted`. */
const NEVER_SCANNED_DIRS = new Set([".git"]);

const MARKER_FILE_LIMIT = 64 * 1024 * 1024;

function readMarkerJson(file: string): unknown {
  try {
    const stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.size > MARKER_FILE_LIMIT) return undefined;
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return undefined;
  }
}

/**
 * The output file names of this tool in `dir`, when `dir` is one of its run
 * directories; otherwise undefined. A run directory is recognised by content,
 * not by name:
 *
 * - `run.json` whose `tool.name` is this tool, next to a `findings.json`
 *   (a finished run, wherever `--out` put it);
 * - a `latest/` directory whose `findings.json` carries the same marker
 *   (`--latest-link` copies);
 * - `state.json` of this tool whose `runId` is the directory name (a run that
 *   failed or is still running).
 *
 * The marker is data in the audited repository, so it decides little: only
 * files with the tool's own fixed output names are skipped, each one is listed
 * in coverage, and anything else in the directory (a `.py` next to a planted
 * `run.json`) is inventoried as usual.
 */
export function ownOutputFileNames(
  dir: string,
  fileNames: ReadonlySet<string>,
): ReadonlySet<string> | undefined {
  if (fileNames.has("run.json") && fileNames.has("findings.json")) {
    const run = readMarkerJson(path.join(dir, "run.json"));
    if (
      isRecord(run) &&
      isRecord(run.tool) &&
      run.tool.name === TOOL_NAME &&
      typeof run.runId === "string"
    ) {
      return RUN_OUTPUT_FILES;
    }
  }
  if (path.basename(dir) === "latest" && fileNames.has("findings.json")) {
    const document = readMarkerJson(path.join(dir, "findings.json"));
    if (
      isRecord(document) &&
      isRecord(document.run) &&
      isRecord(document.run.tool) &&
      document.run.tool.name === TOOL_NAME &&
      Array.isArray(document.findings)
    ) {
      return LATEST_OUTPUT_FILES;
    }
  }
  if (fileNames.has("state.json")) {
    const state = readMarkerJson(path.join(dir, "state.json"));
    if (
      isRecord(state) &&
      state.schemaVersion === 1 &&
      state.runId === path.basename(dir) &&
      typeof state.phase === "string" &&
      typeof state.runDir === "string"
    ) {
      return new Set(["state.json"]);
    }
  }
  return undefined;
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
  const untrusted = options.untrusted === true;
  const ownRunDirs = new Set(
    (options.ownRunDirs ?? []).map((dir) => {
      try {
        return fs.realpathSync(dir);
      } catch {
        return path.resolve(dir);
      }
    }),
  );

  const files: InventoryFile[] = [];
  const skipped: SkippedFile[] = [];
  const warnings: string[] = [];
  const languages: Record<string, { files: number; loc: number }> = {};
  const manifests: ManifestRef[] = [];

  let totalBytes = 0;
  let totalLoc = 0;
  let partialFiles = 0;
  const toolOutput: InventoryFile[] = [];
  let toolOutputUnread = 0;
  const excludedSource = { total: 0, truncated: false, byDirectory: {} as Record<string, number> };
  let excludedEntries = 0;
  const binaries: BinaryFile[] = [];
  let binariesTruncated = false;
  const incompleteTrees = new Set<string>();
  /** .py files by relative path, with their size (for the .pyc source check). */
  const sourceFiles = new Map<string, number>();
  const addBinary = (binary: BinaryFile, treeKey: string): void => {
    if (binaries.length >= MAX_BINARY_FILES) {
      binariesTruncated = true;
      incompleteTrees.add(treeKey);
      return;
    }
    binaries.push(binary);
  };
  const recordBinary = (
    rel: string,
    abs: string,
    size: number,
    reason: string,
    treeKey: string,
    header?: Uint8Array,
  ): void => {
    addBinary(binaryFileOf(rel, abs, size, header ?? readMagic(abs), reason), treeKey);
  };
  // Default-excluded directories inside a skill or plugin (`__pycache__/`,
  // `bin/`, `build/`) are not read, but a package that ships compiled code
  // there is reported: their files are listed by header (8 bytes each),
  // within a budget of directory entries.
  // Every tree has its own budget, so a tree cannot hide a binary behind
  // the files of another one; a tree whose budget runs out is marked
  // incomplete (`binaryListIncomplete`), not only warned about.
  const binaryListEntries = new Map<string, number>();
  const listExcludedBinaries = (dir: string, depth: number, treeKey: string): void => {
    if ((binaryListEntries.get(treeKey) ?? 0) > BINARY_LIST_MAX_ENTRIES) return;
    if (depth > 20) {
      incompleteTrees.add(treeKey);
      return;
    }
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      incompleteTrees.add(treeKey);
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const count = (binaryListEntries.get(treeKey) ?? 0) + 1;
      binaryListEntries.set(treeKey, count);
      if (count > BINARY_LIST_MAX_ENTRIES) {
        incompleteTrees.add(treeKey);
        // Once per tree: the enclosing directories stop at the check above.
        if (count === BINARY_LIST_MAX_ENTRIES + 1) {
          warnings.push(
            `more than ${BINARY_LIST_MAX_ENTRIES} entries in default-excluded directories of the skill or plugin tree ${treeKey === "" ? "at the root" : treeKey}; binary files beyond that were not listed (the tree is marked incomplete)`,
          );
        }
        return;
      }
      const abs = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        listExcludedBinaries(abs, depth + 1, treeKey);
        continue;
      }
      if (!entry.isFile()) continue;
      const rel = toPosixRelative(root, abs);
      let size = 0;
      try {
        size = fs.statSync(abs).size;
      } catch {
        size = 0;
      }
      if (rel.endsWith(".py")) sourceFiles.set(rel, size);
      const header = readMagic(abs);
      const binaryName = BINARY_EXTENSIONS.has(path.extname(entry.name).toLowerCase());
      if (binaryName || /(?:^|\/)__pycache__\//.test(rel) || (header && looksExecutableHeader(header))) {
        recordBinary(rel, abs, size, "in a default-excluded directory", treeKey, header);
      }
    }
  };

  // Excluded directories are not read. Their source files are counted (names
  // only, bounded) so the report can say how much code was left out.
  const countExcluded = (dir: string, name: string, depth: number): void => {
    if (excludedSource.truncated || depth > 40) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      excludedEntries += 1;
      if (excludedEntries > EXCLUDED_COUNT_MAX_ENTRIES) {
        excludedSource.truncated = true;
        return;
      }
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (!NEVER_SCANNED_DIRS.has(entry.name.toLowerCase())) {
          countExcluded(path.join(dir, entry.name), name, depth + 1);
        }
      } else if (entry.isFile() && SOURCE_LANGUAGES.includes(detectLanguage(entry.name))) {
        excludedSource.total += 1;
        excludedSource.byDirectory[name] = (excludedSource.byDirectory[name] ?? 0) + 1;
      }
    }
  };

  let realRoot = root;
  try {
    realRoot = fs.realpathSync(root);
  } catch {
    realRoot = root;
  }
  /** The target of a symbolic link, when it is a readable text file inside the audit root. */
  const readLinkedInstructionFile = (link: string): { target: string; size: number; loc: number } | undefined => {
    try {
      const target = fs.realpathSync(link);
      if (target !== realRoot && !target.startsWith(`${realRoot}${path.sep}`)) return undefined;
      const stat = fs.statSync(target);
      if (!stat.isFile() || stat.size > maxFileSize) return undefined;
      const buffer = fs.readFileSync(target);
      if (looksBinary(buffer)) return undefined;
      return { target, size: stat.size, loc: countLines(buffer.toString("utf8")) };
    } catch {
      return undefined;
    }
  };

  const walk = (dir: string, parentInPackage: boolean, parentTreeRoot: string | undefined): void => {
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
    // A skill (a directory with SKILL.md) or a plugin (with .claude-plugin/)
    // makes its whole tree a package for the binary list.
    const inPackage =
      parentInPackage ||
      entries.some(
        (entry) =>
          ((entry.isFile() || entry.isSymbolicLink()) && entry.name.toLowerCase() === "skill.md") ||
          (entry.isDirectory() && entry.name === ".claude-plugin"),
      );
    // The nearest skill or plugin tree root (rules with `inSkillTree`).
    const isTreeRoot = entries.some(
      (entry) =>
        // SKILL.md in any case, and also as a symbolic link: hosts open it
        // with a plain read, which follows the link.
        ((entry.isFile() || entry.isSymbolicLink()) &&
          (entry.name.toLowerCase() === "skill.md" || entry.name === "plugin.json")) ||
        (entry.isDirectory() &&
          entry.name === ".claude-plugin" &&
          fs.existsSync(path.join(dir, entry.name, "plugin.json"))),
    );
    const treeRoot = isTreeRoot ? toPosixRelative(root, dir) : parentTreeRoot;
    const atRoot = dir === root;

    // Reports of earlier runs (an `--out` directory inside the audit root)
    // are not part of the audited project.
    const ownRun = ownRunDirs.has(dir);
    // For an untrusted repository a run directory is recognised only below
    // `<root>/.audit/`, where the tool itself writes; a marker anywhere else
    // changes nothing and the files are scanned in full.
    const recognise =
      !ownRun && (!untrusted || `${toPosixRelative(root, dir)}/`.startsWith(".audit/"));
    const ownOutput = !recognise
      ? undefined
      : ownOutputFileNames(
          dir,
          new Set(entries.filter((entry) => entry.isFile()).map((entry) => entry.name)),
        );

    for (const entry of entries) {
      const abs = path.join(dir, entry.name);
      const rel = toPosixRelative(root, abs);

      if (entry.isSymbolicLink()) {
        // An instruction file (SKILL.md, CLAUDE.md, AGENTS.md, a subagent, a
        // command, .cursorrules, ...) that is a link is read through the link
        // when its target is a text file inside the audit root: hosts open it
        // with a plain read. A link that leaves the root is not read and is
        // reported.
        if (isInstructionPath(rel, treeRoot)) {
          const linked = readLinkedInstructionFile(abs);
          if (linked) {
            files.push({
              relPath: rel,
              absPath: linked.target,
              language: detectLanguage(rel),
              size: linked.size,
              loc: linked.loc,
              kind: "doc",
              scannable: true,
              isLockfile: false,
              ...(treeRoot !== undefined ? { skillTreeRoot: treeRoot } : {}),
            });
            totalLoc += linked.loc;
            warnings.push(
              `${rel} is a symbolic link to ${toPosixRelative(root, linked.target)}; it was read through the link as an instruction file`,
            );
            continue;
          }
          warnings.push(
            `${rel} is a symbolic link to a file outside the audit root or to something that is not a text file; it was not read${entry.name.toLowerCase() === "skill.md" ? ", but its directory is treated as a skill tree" : ""}`,
          );
        }
        skipped.push({
          relPath: rel,
          reason: "symbolic link (skipped to avoid escape or loops)",
        });
        continue;
      }

      if (entry.isDirectory()) {
        const lowerName = entry.name.toLowerCase();
        // `src/bin/` holds Cargo binary targets (source code), not build output.
        const cargoBin = lowerName === "bin" && path.basename(dir).toLowerCase() === "src";
        // The `bin/` of a skill or plugin holds its scripts (the commands
        // and hooks call them), not build output: it is read like source.
        const skillBin = lowerName === "bin" && treeRoot !== undefined;
        if (
          excludedDirs.has(lowerName) &&
          !cargoBin &&
          !skillBin &&
          (!untrusted || NEVER_SCANNED_DIRS.has(lowerName))
        ) {
          skipped.push({ relPath: `${rel}/`, reason: "default-excluded directory" });
          if (!NEVER_SCANNED_DIRS.has(lowerName)) countExcluded(abs, lowerName, 0);
          if (
            (inPackage || isAgentPackagePath(`${rel}/`)) &&
            !(atRoot && BINARY_LIST_ROOT_SKIPPED_DIRS.has(lowerName))
          ) {
            listExcludedBinaries(abs, 0, treeRoot ?? rel);
          }
          continue;
        }
        walk(abs, inPackage, treeRoot);
        continue;
      }

      if (!entry.isFile()) {
        skipped.push({ relPath: rel, reason: "not a regular file" });
        continue;
      }

      // The run this scan is writing right now is not input.
      if (ownRun && RUN_OUTPUT_FILES.has(entry.name)) {
        skipped.push({ relPath: rel, reason: "code-audit output" });
        continue;
      }
      if (ownOutput?.has(entry.name)) {
        skipped.push({ relPath: rel, reason: "code-audit output" });
        let size = -1;
        try {
          size = fs.statSync(abs).size;
        } catch {
          size = -1;
        }
        if (size < 0 || size > maxFileSize) toolOutputUnread += 1;
        else {
          toolOutput.push({
            relPath: rel,
            absPath: abs,
            language: detectLanguage(rel),
            size,
            loc: 0,
            kind: "other",
            scannable: true,
            isLockfile: false,
            toolOutput: true,
          });
        }
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

      const packaged = inPackage || isAgentPackagePath(rel);
      const treeKey = treeRoot ?? path.posix.dirname(rel);
      if (rel.endsWith(".py")) sourceFiles.set(rel, stat.size);
      const ext = path.extname(entry.name).toLowerCase();
      if (BINARY_EXTENSIONS.has(ext)) {
        skipped.push({ relPath: rel, reason: "binary extension" });
        if (packaged) recordBinary(rel, abs, stat.size, "binary extension", treeKey);
        continue;
      }
      if (stat.size > maxFileSize) {
        skipped.push({
          relPath: rel,
          reason: `file exceeds the ${Math.floor(maxFileSize / 1024 / 1024)} MB limit`,
        });
        if (packaged) recordBinary(rel, abs, stat.size, "over the size limit", treeKey);
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
      if (looksBinary(buffer) && detectLanguage(rel) !== "unknown") {
        // A file named as source or configuration with a NUL byte: an
        // interpreter still runs it (Node, bash and Python ignore or tolerate
        // a NUL in a comment), so skipping it as binary would let a single
        // byte hide the file. It is scanned with the NUL bytes removed.
        const kept = Buffer.allocUnsafe(buffer.length);
        let length = 0;
        for (let i = 0; i < buffer.length; i += 1) {
          const byte = buffer[i] as number;
          if (byte !== 0) kept[length++] = byte;
        }
        buffer = kept.subarray(0, length);
        warnings.push(`${rel}: contains NUL bytes; scanned with them removed`);
      }
      if (looksBinary(buffer)) {
        skipped.push({ relPath: rel, reason: "binary content detected (NUL byte)" });
        if (packaged) recordBinary(rel, abs, stat.size, "binary content (NUL byte)", treeKey, buffer);
        continue;
      }
      // A text file (no NUL byte) with an executable or archive header.
      if (packaged && buffer.length >= 4 && looksExecutableHeader(buffer.subarray(0, 8))) {
        recordBinary(rel, abs, stat.size, "text file with a binary header", treeKey, buffer);
      }

      const text = buffer.toString("utf8");
      if (!untrusted && isShippedAdapterFile(rel, text)) {
        skipped.push({ relPath: rel, reason: "code-audit adapter file" });
        continue;
      }
      const loc = countLines(text);
      let language = detectLanguage(rel);
      // Inside a skill or plugin tree, an extensionless script is classified
      // by its #! line and a fish script is read as shell.
      if (treeRoot !== undefined && language === "unknown") {
        if (!entry.name.includes(".")) language = shebangLanguage(text) ?? language;
        else if (ext === ".fish") language = "shell";
      }
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

      const classification = classifyFileDetailed(rel, text, language);
      const pathContext = classification.context;
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
        ...(pathContext ? { pathContext, pathContextSource: classification.source } : {}),
        ...(treeRoot !== undefined ? { skillTreeRoot: treeRoot } : {}),
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

  walk(root, false, undefined);
  // A .pyc in __pycache__/ whose source module sits next to the directory.
  for (const binary of binaries) {
    const at = binary.relPath.lastIndexOf("__pycache__/");
    if (at < 0 || !/\.py[co]$/.test(binary.relPath)) continue;
    const parent = binary.relPath.slice(0, at);
    const module = binary.relPath.slice(at + "__pycache__/".length).split(".")[0] as string;
    if (module.includes("/")) continue;
    // The cache stands for its source only when it is a timestamp-based
    // .pyc (flags word 0, PEP 552) that records the size of that very
    // source. A hash-based .pyc (flags 1 or 3) may be loaded without any
    // check against the source, and a size mismatch means it was not
    // compiled from it: both stay bundled bytecode.
    const sourceSize = sourceFiles.get(`${parent}${module}.py`);
    const header = readMagic(binary.absPath, 16);
    const flags = header && header.length >= 16 ? header.readUInt32LE(4) : undefined;
    const recordedSize = header && header.length >= 16 ? header.readUInt32LE(12) : undefined;
    binary.sourcePresent = sourceSize !== undefined && flags === 0 && recordedSize === sourceSize >>> 0;
  }
  if (binariesTruncated) {
    warnings.push(
      `more than ${MAX_BINARY_FILES} binary files in skill or plugin directories; only the first ${MAX_BINARY_FILES} were listed for the binary rules`,
    );
  }

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
    toolOutput,
    toolOutputUnread,
    excludedSource,
    binaries,
    binaryListIncomplete: [...incompleteTrees].sort(),
  };
}
