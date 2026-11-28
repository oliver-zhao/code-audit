/**
 * Skill / plugin package scan: `code-audit skill <target>`.
 *
 * A skill or plugin is code and instructions an agent will follow. Before it
 * is installed, the package is scanned like an untrusted repository (the
 * `untrusted` policy is forced on and cannot be turned off) and every package
 * gets one deterministic install verdict:
 *
 *   DO_NOT_INSTALL   a match of a rule tagged `malicious-intent` (confidence
 *                    medium or high), or a critical finding at high confidence
 *   REVIEW           otherwise: a high or critical finding, a medium finding
 *                    at confidence medium or high, any hotspot, or a
 *                    `malicious-intent` match at low confidence
 *   INCOMPLETE       otherwise: anything was not analysed (skipped files,
 *                    unrecognised binaries, archive entries not unpacked,
 *                    partial rule matching, a failed external engine, the
 *                    built-in engine not selected, dependencies not checked)
 *   SAFE_TO_INSTALL  none of the above; worded "no known risk patterns found
 *                    (not a guarantee of safety)"
 *
 * The verdict never depends on the risk score, which only orders packages.
 *
 * Targets: a directory, a single SKILL.md, a .zip / .tar / .tar.gz / .tgz
 * archive (unpacked with the checks of `archive.ts` into a temporary
 * directory) or a git URL (https or ssh only; cloned shallowly with hooks,
 * submodules, tags and local transports disabled). Nothing from the package
 * is ever executed. Temporary directories are removed when the scan ends,
 * also when it fails.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import {
  ARCHIVE_MAX_FILE_BYTES,
  ARCHIVE_MAX_RATIO,
  archiveFormatOf,
  extractArchive,
  type ArchiveSkip,
} from "./archive.js";
import {
  CONFIDENCE_ORDER,
  createFinding,
  type Confidence,
  type Finding,
  type Severity,
} from "./finding.js";
import type { InventoryFile, InventoryResult } from "./inventory.js";
import { detectLanguage } from "./language.js";
import { TOOL_NAME, TOOL_VERSION, defaultRulesDir } from "./meta.js";
import { validateAuditRoot } from "./pathJail.js";
import { redactText, splitLines } from "./redact.js";
import { singleLineText } from "./report.js";
import { loadRules, type RuleSet } from "./rules.js";
import { writeRunFile } from "./runstore.js";
import { printable, readFileNoFollow } from "./safeFs.js";
import type { HttpClient } from "./sca.js";
import { scanProject, type EngineName, type ReportFormat, type ScanResult } from "./scan.js";
import { runTool } from "./external/run.js";
import { scanRules, type RuleHit } from "./rules.js";
import { scanSecrets } from "./secrets.js";
import zlib from "node:zlib";
import {
  decodeWideText,
  detectWideEncoding,
  extractPrintableText,
  gitDirProblems,
  pdfStreamText,
  stripNul,
} from "./skillText.js";

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

export const SKILL_VERDICTS = ["DO_NOT_INSTALL", "REVIEW", "INCOMPLETE", "SAFE_TO_INSTALL"] as const;
export const SkillVerdictSchema = z.enum(SKILL_VERDICTS);
export type SkillVerdict = z.infer<typeof SkillVerdictSchema>;

/** Worst first. */
const VERDICT_RANK: Record<SkillVerdict, number> = {
  DO_NOT_INSTALL: 3,
  REVIEW: 2,
  INCOMPLETE: 1,
  SAFE_TO_INSTALL: 0,
};

export const SAFE_TO_INSTALL_TEXT = "No known risk patterns found (not a guarantee of safety).";

export const VERDICT_TEXT: Record<SkillVerdict, string> = {
  DO_NOT_INSTALL: "Do not install: the package matches patterns of hostile intent or a critical, high-confidence finding.",
  REVIEW: "Review before installing: the package has high-risk findings or hotspots a person must look at.",
  INCOMPLETE: "Incomplete: part of the package could not be analysed; the result is not a clean bill of health.",
  SAFE_TO_INSTALL: SAFE_TO_INSTALL_TEXT,
};

export const MALICIOUS_INTENT_TAG = "malicious-intent";
export const UNDECLARED_CAPABILITY_RULE_ID = "skill-undeclared-capability";

export const SkillReasonSchema = z.object({
  code: z.enum([
    "malicious-intent",
    "critical-high-confidence",
    "high-severity",
    "medium-severity",
    "hotspot",
    "malicious-intent-low-confidence",
  ]),
  message: z.string(),
  findingId: z.string().optional(),
  ruleId: z.string().optional(),
  file: z.string().optional(),
  line: z.number().int().optional(),
});
export type SkillReason = z.infer<typeof SkillReasonSchema>;

export const SkillIncompleteSchema = z.object({
  /** Package-relative POSIX path, absent for package-wide reasons. */
  path: z.string().optional(),
  reason: z.string(),
});
export type SkillIncomplete = z.infer<typeof SkillIncompleteSchema>;

export const SkillFindingSchema = z.object({
  id: z.string(),
  ruleId: z.string(),
  kind: z.enum(["finding", "hotspot"]),
  severity: z.string(),
  confidence: z.string(),
  title: z.string(),
  /** Relative to the scanned root (not to the package). */
  file: z.string(),
  startLine: z.number().int(),
  tags: z.array(z.string()),
  evidence: z.string(),
});
export type SkillFinding = z.infer<typeof SkillFindingSchema>;

export const CAPABILITIES = ["network", "subprocess", "fileWrite"] as const;
export type Capability = (typeof CAPABILITIES)[number];

export const SkillCapabilitiesSchema = z.object({
  /** Tool names from SKILL.md `allowed-tools`; null when the key is absent. */
  allowedTools: z.array(z.string()).nullable(),
  /** Scripts of the package that use each capability (scanned-root-relative paths). */
  detected: z.object({
    network: z.array(z.string()),
    subprocess: z.array(z.string()),
    fileWrite: z.array(z.string()),
  }),
  /** Capabilities a script needs that `allowed-tools` does not grant. */
  undeclared: z.array(z.enum(CAPABILITIES)),
});
export type SkillCapabilities = z.infer<typeof SkillCapabilitiesSchema>;

export const SkillPackageSchema = z.object({
  /** Package directory relative to the scanned root; "." for the root. */
  path: z.string(),
  name: z.string(),
  /** `outside`: the group of files that belong to no package (recursive scans). */
  kind: z.enum(["skill", "plugin", "directory", "outside"]),
  verdict: SkillVerdictSchema,
  verdictText: z.string(),
  riskScore: z.number().min(0).max(100),
  reasons: z.array(SkillReasonSchema),
  incomplete: z.array(SkillIncompleteSchema),
  findings: z.array(SkillFindingSchema),
  capabilities: SkillCapabilitiesSchema,
  notes: z.array(z.string()),
});
export type SkillPackage = z.infer<typeof SkillPackageSchema>;

export const SkillScanDocumentSchema = z.object({
  schemaVersion: z.literal(1),
  tool: z.object({ name: z.string(), version: z.string() }),
  target: z.object({
    input: z.string(),
    kind: z.enum(["directory", "skill-file", "archive", "git"]),
  }),
  recursive: z.boolean(),
  runId: z.string(),
  runDir: z.string(),
  packages: z.array(SkillPackageSchema),
  summary: z.object({
    packages: z.number().int(),
    verdicts: z.object({
      DO_NOT_INSTALL: z.number().int(),
      REVIEW: z.number().int(),
      INCOMPLETE: z.number().int(),
      SAFE_TO_INSTALL: z.number().int(),
    }),
    /** The worst verdict of all packages. */
    verdict: SkillVerdictSchema,
    /** 0 when every package is SAFE_TO_INSTALL, else 1. */
    exitCode: z.union([z.literal(0), z.literal(1)]),
    /** Results in files that belong to no package (recursive scans). */
    outside: z.object({ findings: z.number().int(), hotspots: z.number().int() }),
  }),
});
export type SkillScanDocument = z.infer<typeof SkillScanDocumentSchema>;

// ---------------------------------------------------------------------------
// Targets
// ---------------------------------------------------------------------------

export class SkillTargetError extends Error {
  readonly code: string;

  constructor(message: string, code = "SKILL_TARGET") {
    super(message);
    this.name = "SkillTargetError";
    this.code = code;
  }
}

export type GitTargetCheck =
  | { remote: false }
  | { remote: true; ok: true; url: string; protocol: "https" | "ssh" }
  | { remote: true; ok: false; reason: string };

const SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*:\/\//;
/** `user@host:path` (scp-like); deliberately loose, the strict form is checked below. */
const SCP_LIKE = /^[^/:@\s]+@[^/:]+:/;
const HOST = /^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/;

/**
 * Whether `input` names a git remote and, if so, whether it is accepted. Only
 * `https://host/path`, `ssh://[user@]host[:port]/path` and `user@host:path`
 * are; `file://`, `git://`, `http://`, `ext::`, `fd::` and every other
 * transport, user info with a password, and anything that could reach git as
 * an option are refused. `localExists` lets a local file whose name merely
 * looks like `user@host:path` or contains `::` be scanned as a file.
 */
export function checkGitTarget(input: string, localExists = false): GitTargetCheck {
  const looksRemote =
    SCHEME.test(input) || (!localExists && (input.includes("::") || SCP_LIKE.test(input)));
  if (!looksRemote) return { remote: false };
  const refuse = (reason: string): GitTargetCheck => ({ remote: true, ok: false, reason });
  // eslint-disable-next-line no-control-regex
  if (/[\s\u0000-\u001f\u007f]/.test(input)) return refuse("git URL contains whitespace or control characters");
  if (input.startsWith("-")) return refuse("git URL starts with '-'");
  if (input.includes("::")) return refuse("git remote helper syntax (<transport>::<address>) is not accepted");
  if (SCHEME.test(input)) {
    let url: URL;
    try {
      url = new URL(input);
    } catch {
      return refuse("git URL cannot be parsed");
    }
    const protocol = url.protocol.toLowerCase();
    if (protocol !== "https:" && protocol !== "ssh:") {
      return refuse(`only https:// and ssh:// git URLs are accepted, not ${protocol}//`);
    }
    if (!HOST.test(url.hostname)) return refuse("git URL has an invalid host name");
    if (url.password !== "") return refuse("git URL must not carry a password");
    if (protocol === "https:" && url.username !== "") return refuse("https git URL must not carry user info");
    if (url.username !== "" && !/^[A-Za-z0-9._][A-Za-z0-9._-]*$/.test(url.username)) return refuse("git URL has an invalid user name");
    if (url.pathname === "" || url.pathname === "/") return refuse("git URL has no repository path");
    return { remote: true, ok: true, url: input, protocol: protocol === "https:" ? "https" : "ssh" };
  }
  const match = /^([A-Za-z0-9._-]+)@([A-Za-z0-9.-]+):(.+)$/.exec(input);
  if (!match) return refuse("not an accepted git URL");
  const [, user, host, repoPath] = match as unknown as [string, string, string, string];
  if (user.startsWith("-")) return refuse("git URL user name starts with '-'");
  if (!HOST.test(host)) return refuse("git URL has an invalid host name");
  if (repoPath.startsWith("-")) return refuse("git repository path starts with '-'");
  return { remote: true, ok: true, url: input, protocol: "ssh" };
}

/** Environment for git: the same hardening as `git.ts` (`GIT_ENV`), plus transport limits. */
const GIT_CLONE_ENV: Record<string, string> = {
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: os.devNull,
  GIT_ATTR_NOSYSTEM: "1",
  GIT_TERMINAL_PROMPT: "0",
  GIT_OPTIONAL_LOCKS: "0",
  GIT_ALLOW_PROTOCOL: "https:ssh",
  GIT_PROTOCOL_FROM_USER: "0",
  GIT_LFS_SKIP_SMUDGE: "1",
  GIT_SSH_COMMAND: "ssh -o BatchMode=yes",
};

/** Arguments of the shallow clone (exported for tests). */
export function gitCloneArgs(url: string, destination: string): string[] {
  return [
    "-c", "protocol.allow=never",
    "-c", "protocol.https.allow=always",
    "-c", "protocol.ssh.allow=always",
    "-c", "protocol.file.allow=never",
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.fsmonitor=false",
    "-c", "submodule.recurse=false",
    "-c", "credential.helper=",
    "clone",
    "--depth", "1",
    "--no-recurse-submodules",
    "--no-tags",
    "-c", "core.hooksPath=/dev/null",
    "-c", "protocol.file.allow=never",
    "--",
    url,
    destination,
  ];
}

const GIT_CLONE_TIMEOUT_MS = 180_000;

async function cloneRepository(
  url: string,
  destination: string,
  options: { pathEnv?: string; timeoutMs?: number },
): Promise<void> {
  const result = await runTool("git", gitCloneArgs(url, destination), {
    timeoutMs: options.timeoutMs ?? GIT_CLONE_TIMEOUT_MS,
    env: {
      ...GIT_CLONE_ENV,
      ...(process.env.SSH_AUTH_SOCK ? { SSH_AUTH_SOCK: process.env.SSH_AUTH_SOCK } : {}),
      ...(options.pathEnv ? { PATH: options.pathEnv } : {}),
    },
  });
  if (result.timedOut) throw new SkillTargetError("git clone timed out", "GIT_CLONE_FAILED");
  if (result.exitCode !== 0) {
    const detail = printable(result.stderr.trim().split("\n").slice(-2).join(" ") || `exit code ${result.exitCode}`, 300);
    throw new SkillTargetError(`git clone failed: ${detail}`, "GIT_CLONE_FAILED");
  }
  if (!fs.existsSync(destination) || !fs.statSync(destination).isDirectory()) {
    throw new SkillTargetError("git clone produced no directory", "GIT_CLONE_FAILED");
  }
}

// Temporary directories of scans in progress; removed by `cleanupSkillTempDirs`
// as well (a signal handler of the command line).
const activeTempDirs = new Set<string>();

function makeTempDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "code-audit-skill-"));
  activeTempDirs.add(dir);
  return dir;
}

function removeTempDir(dir: string): void {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } finally {
    activeTempDirs.delete(dir);
  }
}

/** Remove every temporary directory of a scan still running (signal handlers). */
export function cleanupSkillTempDirs(): void {
  for (const dir of [...activeTempDirs]) {
    try {
      removeTempDir(dir);
    } catch {
      // best effort
    }
  }
}

// ---------------------------------------------------------------------------
// Package discovery
// ---------------------------------------------------------------------------

interface PackageDir {
  /** Root-relative POSIX path, "" for the root. */
  rel: string;
  kind: "skill" | "plugin" | "directory";
  name: string;
  /** Root-relative path of SKILL.md, when there is one. */
  skillFile?: string;
  notes: string[];
}

const DISCOVERY_SKIP = new Set([".git", ".audit", "node_modules"]);
const DISCOVERY_MAX_DEPTH = 30;
const DISCOVERY_MAX_ENTRIES = 200_000;

function isFileNoFollow(file: string): boolean {
  try {
    return fs.lstatSync(file).isFile();
  } catch {
    return false;
  }
}

/** A regular file or a symbolic link at `file` (a link is not followed). */
function presentNoFollow(file: string): boolean {
  try {
    const stat = fs.lstatSync(file);
    return stat.isFile() || stat.isSymbolicLink();
  } catch {
    return false;
  }
}

function packageKindAt(dir: string): "skill" | "plugin" | undefined {
  // `.claude-plugin/plugin.json` makes the directory above it the plugin.
  if (path.basename(dir) === ".claude-plugin") return undefined;
  // A manifest that is a symbolic link still makes a package (an install
  // follows the link); it is reported as not analysed.
  if (presentNoFollow(path.join(dir, ".claude-plugin", "plugin.json")) || presentNoFollow(path.join(dir, "plugin.json"))) {
    return "plugin";
  }
  if (presentNoFollow(path.join(dir, "SKILL.md"))) return "skill";
  return undefined;
}

function joinRel(base: string, name: string): string {
  return base === "" ? name : `${base}/${name}`;
}

/** Directories below `root` that are skills or plugins, in path order. */
function discoverPackages(root: string): { packages: Array<{ rel: string; kind: "skill" | "plugin" }>; truncated: boolean } {
  const packages: Array<{ rel: string; kind: "skill" | "plugin" }> = [];
  let entriesSeen = 0;
  let truncated = false;
  const walk = (dir: string, rel: string, depth: number): void => {
    if (truncated) return;
    const kind = packageKindAt(dir);
    if (kind) packages.push({ rel, kind });
    if (depth >= DISCOVERY_MAX_DEPTH) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      entriesSeen += 1;
      if (entriesSeen > DISCOVERY_MAX_ENTRIES) {
        truncated = true;
        return;
      }
      if (!entry.isDirectory() || entry.isSymbolicLink()) continue;
      if (DISCOVERY_SKIP.has(entry.name)) continue;
      walk(path.join(dir, entry.name), joinRel(rel, entry.name), depth + 1);
    }
  };
  walk(root, "", 0);
  return { packages, truncated };
}

// ---------------------------------------------------------------------------
// SKILL.md front matter
// ---------------------------------------------------------------------------

const FRONTMATTER_MAX_BYTES = 64 * 1024;

export interface SkillFrontmatter {
  ok: boolean;
  /** Present when the file has front matter that parsed to a mapping. */
  data?: Record<string, unknown>;
  error?: string;
}

/** Parse the YAML front matter of a SKILL.md text (bounded; never throws). */
export function parseFrontmatter(text: string): SkillFrontmatter {
  const body = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  if (!/^---\r?\n/.test(body)) return { ok: true };
  const end = /\r?\n---[ \t]*(?:\r?\n|$)/.exec(body.slice(3));
  if (!end) return { ok: false, error: "front matter is not closed by a '---' line" };
  const yamlText = body.slice(3, 3 + end.index);
  if (yamlText.length > FRONTMATTER_MAX_BYTES) return { ok: false, error: "front matter is larger than 64 KiB" };
  try {
    const data: unknown = parseYaml(yamlText, { maxAliasCount: 20 });
    if (data === null || data === undefined) return { ok: true };
    if (typeof data !== "object" || Array.isArray(data)) return { ok: false, error: "front matter is not a mapping" };
    return { ok: true, data: data as Record<string, unknown> };
  } catch (error) {
    return { ok: false, error: `front matter does not parse: ${printable(error instanceof Error ? error.message : String(error), 120)}` };
  }
}

const TOOL_TOKEN = /[A-Za-z_*][\w.*-]*/;

/** Tool names of an `allowed-tools` value (string or list); undefined when it is neither. */
export function parseAllowedTools(value: unknown): string[] | undefined {
  const items: string[] = [];
  if (typeof value === "string") {
    // `Read, Grep, Bash(git status:*)` or space separated: drop the
    // parenthesised argument patterns, then split.
    const stripped = value.replace(/\([^()]*\)/g, "");
    for (const part of stripped.split(/[\s,]+/)) if (part) items.push(part);
  } else if (Array.isArray(value)) {
    for (const item of value) if (typeof item === "string") items.push(item.trim());
  } else {
    return undefined;
  }
  const names: string[] = [];
  for (const item of items) {
    const match = TOOL_TOKEN.exec(item);
    if (match && !names.includes(match[0])) names.push(match[0]);
  }
  return names;
}

/** Tools that grant each capability to a skill's scripts. */
const CAPABILITY_TOOLS: Record<Capability, readonly string[]> = {
  network: ["Bash", "WebFetch"],
  subprocess: ["Bash"],
  fileWrite: ["Bash", "Write", "Edit", "MultiEdit", "NotebookEdit"],
};

const CAPABILITY_WORDS: Record<Capability, string> = {
  network: "network access",
  subprocess: "running other programs",
  fileWrite: "writing files",
};

function grants(allowed: readonly string[], capability: Capability): boolean {
  return allowed.some((tool) => tool === "*" || CAPABILITY_TOOLS[capability].includes(tool));
}

// ---------------------------------------------------------------------------
// Script capability detection (F2.3)
// ---------------------------------------------------------------------------

type ScriptKind = "shell" | "python" | "javascript" | "ruby" | "perl" | "powershell";

const SCRIPT_EXTENSIONS: Record<string, ScriptKind> = {
  ".sh": "shell",
  ".bash": "shell",
  ".zsh": "shell",
  ".py": "python",
  ".js": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".ts": "javascript",
  ".mts": "javascript",
  ".cts": "javascript",
  ".rb": "ruby",
  ".pl": "perl",
  ".ps1": "powershell",
};

function scriptKindOf(relPath: string, firstLine: string): ScriptKind | undefined {
  const byExtension = SCRIPT_EXTENSIONS[path.extname(relPath).toLowerCase()];
  if (byExtension) return byExtension;
  if (!firstLine.startsWith("#!")) return undefined;
  if (/\b(?:ba|z|da|k)?sh\b/.test(firstLine)) return "shell";
  if (/\bpython[0-9.]*\b/.test(firstLine)) return "python";
  if (/\b(?:node|deno|bun|tsx|ts-node)\b/.test(firstLine)) return "javascript";
  if (/\bruby\b/.test(firstLine)) return "ruby";
  if (/\bperl\b/.test(firstLine)) return "perl";
  return undefined;
}

const NETWORK_PATTERN =
  /\b(?:curl|wget)\b|\bfetch\s*\(|\brequests\.[a-z]|\bhttpx?\.[a-z]|\bhttps\.(?:get|request)\b|\burllib\b|\baxios\b|\bsocket\.(?:socket|connect|create_connection)\b|\bnet\.(?:connect|createConnection)\b|\bInvoke-(?:WebRequest|RestMethod)\b|\bNet::HTTP\b|\bopen-uri\b|\bLWP::/;
const SUBPROCESS_PATTERN =
  /\bsubprocess\b|\bchild_process\b|\bos\.(?:system|popen|exec[lv]p?e?|spawn[lv]p?e?)\b|(?<![\w.$])exec(?:Sync|File|FileSync)?\s*\(|\bspawn(?:Sync)?\s*\(|\bpty\.spawn\b|\bStart-Process\b|\bDeno\.(?:run|Command)\b|\bBun\.spawn\b|\bsystem\s*\(/;
/** Ruby and Perl run a command between backticks (`ls`), and with %x(...) / qx(...). */
const BACKTICK_PATTERN = /`[^`]+`|%x[({[]|\bqx[({[/]/;
const WRITE_PATTERN =
  /\bwrite(?:File|FileSync)\b|\bappendFile(?:Sync)?\b|\bcreateWriteStream\b|\.write_(?:text|bytes)\s*\(|\bshutil\.(?:copy|copyfile|copy2|copytree|move)\b|\bos\.(?:rename|replace|remove|unlink|makedirs|mkdir)\b|\bfs\.(?:rm|rmSync|unlink|unlinkSync|mkdir|mkdirSync|rename|renameSync|copyFile|copyFileSync|cp|cpSync)\b|\bFile\.(?:write|open)\b|\bSet-Content\b|\bOut-File\b|\bAdd-Content\b/;
const SHELL_WRITE_PATTERN =
  /(?:^|[^<>&|0-9-])[0-9]?>>?[ \t]*(?![&>]|\/dev\/null\b)[^\s&|;<>()]|\b(?:tee|cp|mv|rm|mkdir|touch|ln|dd|install)[ \t]|\bsed[ \t]+-i|\b(?:curl|wget)\b[^\n|;&]{0,300}[ \t](?:-o|-O|--output|--output-document)\b/;
const SHELL_NETWORK_PATTERN = /\b(?:curl|wget|nc|ncat|scp|rsync|ssh|ftp|sftp)[ \t]|\/dev\/tcp\//;

/** True for an `open(...)` call on the line whose mode writes (w, a, x, +). */
function opensForWriting(line: string): boolean {
  let at = line.search(/\bopen\s*\(/);
  while (at >= 0) {
    const close = line.indexOf(")", at);
    const args = line.slice(at, close < 0 ? at + 300 : close);
    if (/["'][rbtU]*[wax+][rbtwax+U]*["']/.test(args) && /,/.test(args)) return true;
    const next = line.slice(at + 4).search(/\bopen\s*\(/);
    at = next < 0 ? -1 : at + 4 + next;
  }
  return false;
}

function isCommentLine(line: string, kind: ScriptKind): boolean {
  const trimmed = line.trimStart();
  if (trimmed === "") return true;
  if (kind === "javascript") return trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*");
  return trimmed.startsWith("#");
}

const MAX_SCANNED_LINE = 4000;

export interface ScriptCapabilityHit {
  capability: Capability;
  /** One-based line. */
  line: number;
  text: string;
}

/** First line of each capability a script uses (comments skipped). */
export function detectCapabilities(text: string, kind: ScriptKind): ScriptCapabilityHit[] {
  const hits = new Map<Capability, ScriptCapabilityHit>();
  const lines = splitLines(text);
  for (let index = 0; index < lines.length && hits.size < CAPABILITIES.length; index += 1) {
    const raw = lines[index] as string;
    if (isCommentLine(raw, kind)) continue;
    const line = raw.length > MAX_SCANNED_LINE ? raw.slice(0, MAX_SCANNED_LINE) : raw;
    const record = (capability: Capability): void => {
      if (!hits.has(capability)) hits.set(capability, { capability, line: index + 1, text: line });
    };
    if (kind === "shell") {
      // A shell script runs other programs by nature.
      record("subprocess");
      if (SHELL_NETWORK_PATTERN.test(line) || NETWORK_PATTERN.test(line)) record("network");
      if (SHELL_WRITE_PATTERN.test(line)) record("fileWrite");
      continue;
    }
    if (NETWORK_PATTERN.test(line)) record("network");
    if (SUBPROCESS_PATTERN.test(line) || ((kind === "ruby" || kind === "perl") && BACKTICK_PATTERN.test(line))) {
      record("subprocess");
    }
    if (WRITE_PATTERN.test(line) || opensForWriting(line)) record("fileWrite");
  }
  return [...hits.values()].sort((a, b) => a.line - b.line);
}

function isInside(packageRel: string, fileRel: string): boolean {
  return packageRel === "" || fileRel === packageRel || fileRel.startsWith(`${packageRel}/`);
}

/** The deepest package that contains `fileRel`. */
function owningPackage<T extends { rel: string }>(packages: T[], fileRel: string): T | undefined {
  let best: T | undefined;
  for (const pkg of packages) {
    if (isInside(pkg.rel, fileRel) && (!best || pkg.rel.length > best.rel.length)) best = pkg;
  }
  return best;
}

interface CapabilityState {
  allowedTools: string[] | null;
  detected: Record<Capability, string[]>;
  undeclared: Set<Capability>;
}

function emptyCapabilities(allowedTools: string[] | null): CapabilityState {
  return { allowedTools, detected: { network: [], subprocess: [], fileWrite: [] }, undeclared: new Set() };
}

/**
 * The capability check over an inventory: for every script of a package, the
 * capabilities it uses; a hotspot `skill-undeclared-capability` per script and
 * capability when the package's SKILL.md declares `allowed-tools` without a
 * tool that grants it.
 */
function capabilityCheck(
  packages: PackageDir[],
  allowedByPackage: Map<string, string[] | null>,
  states: Map<string, CapabilityState>,
  notAnalysed: Array<{ path: string; reason: string }>,
  invalidUtf8: string[],
  withNul: string[],
): (inv: InventoryResult) => Finding[] {
  return (inv) => {
    const findings: Finding[] = [];
    for (const file of inv.files) {
      const buffer = readScript(file);
      if (buffer === undefined) continue;
      // A Git LFS pointer stands in for content that was never fetched; an
      // install with LFS gets the real file.
      if (buffer.subarray(0, LFS_POINTER.length).equals(LFS_POINTER)) {
        notAnalysed.push({ path: file.relPath, reason: "content not present: Git LFS object (only the pointer was analysed)" });
        continue;
      }
      // A NUL after the first 8 KiB: read as text by the inventory, but bash
      // drops NUL bytes and runs what is left; the text pass matches that.
      if (buffer.includes(0)) withNul.push(file.relPath);
      let content: string;
      try {
        content = STRICT_UTF8.decode(buffer);
      } catch {
        // Also matched as decoded with replacement characters; its
        // printable text goes through the text pass as well.
        invalidUtf8.push(file.relPath);
        content = buffer.toString("utf8");
      }
      const owner = owningPackage(packages, file.relPath);
      if (!owner) continue;
      if (owner.skillFile === file.relPath) continue;
      const firstLine = content.slice(0, Math.min(content.length, 200)).split(/\r?\n/, 1)[0] ?? "";
      const kind = scriptKindOf(file.relPath, firstLine);
      if (!kind) continue;
      const state = states.get(owner.rel) as CapabilityState;
      const allowed = allowedByPackage.get(owner.rel) ?? null;
      for (const hit of detectCapabilities(content, kind)) {
        state.detected[hit.capability].push(file.relPath);
        if (allowed === null || grants(allowed, hit.capability)) continue;
        state.undeclared.add(hit.capability);
        const evidence = redactText(singleLineText(hit.text.trim(), 200), { file: file.relPath });
        const skillFile = owner.skillFile ?? "SKILL.md";
        findings.push(
          createFinding({
            ruleId: UNDECLARED_CAPABILITY_RULE_ID,
            title: `Skill script needs ${CAPABILITY_WORDS[hit.capability]} that allowed-tools does not declare`,
            category: "config",
            severity: "medium",
            confidence: "medium",
            kind: "hotspot",
            cwe: "CWE-912",
            language: file.language,
            file: file.relPath,
            startLine: hit.line,
            evidence,
            message: `${skillFile} limits the skill to allowed-tools [${allowed.join(", ")}], which has none of ${CAPABILITY_TOOLS[hit.capability].join(" / ")}, but this script uses ${CAPABILITY_WORDS[hit.capability]}. The skill does more than it declares.`,
            remediation:
              "Read the script before installing. If the capability is needed, the skill should declare the tool in allowed-tools; if it is not, the script should not use it.",
            references: ["CWE-912"],
            provenance: { engine: "builtin-skill", rule: UNDECLARED_CAPABILITY_RULE_ID, version: TOOL_VERSION },
          }),
        );
      }
    }
    return findings;
  };
}

const LFS_POINTER = Buffer.from("version https://git-lfs.github.com/spec/", "latin1");
const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true });

function readScript(file: InventoryFile): Buffer | undefined {
  if (!file.scannable || file.size > ARCHIVE_MAX_FILE_BYTES) return undefined;
  try {
    return readFileNoFollow(file.absPath, ARCHIVE_MAX_FILE_BYTES);
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Binary files the inventory skipped
// ---------------------------------------------------------------------------

interface Magic {
  name: string;
  extensions: readonly string[];
  test: (head: Buffer) => boolean;
}

const startsWith = (head: Buffer, hex: string, at = 0): boolean => {
  const bytes = Buffer.from(hex, "hex");
  return head.length >= at + bytes.length && head.subarray(at, at + bytes.length).equals(bytes);
};

/** Media formats a skill may carry as data: images, fonts, audio, video, PDF. */
const KNOWN_DATA_FORMATS: Magic[] = [
  { name: "PNG image", extensions: [".png"], test: (h) => startsWith(h, "89504e470d0a1a0a") },
  { name: "JPEG image", extensions: [".jpg", ".jpeg"], test: (h) => startsWith(h, "ffd8ff") },
  { name: "GIF image", extensions: [".gif"], test: (h) => startsWith(h, "474946383761") || startsWith(h, "474946383961") },
  { name: "WebP image", extensions: [".webp"], test: (h) => startsWith(h, "52494646") && startsWith(h, "57454250", 8) },
  { name: "BMP image", extensions: [".bmp"], test: (h) => startsWith(h, "424d") },
  { name: "ICO image", extensions: [".ico"], test: (h) => startsWith(h, "00000100") },
  { name: "PDF document", extensions: [".pdf"], test: (h) => startsWith(h, "255044462d") },
  { name: "WOFF font", extensions: [".woff"], test: (h) => startsWith(h, "774f4646") },
  { name: "WOFF2 font", extensions: [".woff2"], test: (h) => startsWith(h, "774f4632") },
  { name: "TrueType font", extensions: [".ttf"], test: (h) => startsWith(h, "00010000") || startsWith(h, "74727565") },
  { name: "OpenType font", extensions: [".otf", ".ttf"], test: (h) => startsWith(h, "4f54544f") },
  { name: "MP3 audio", extensions: [".mp3"], test: (h) => startsWith(h, "494433") || startsWith(h, "fffb") || startsWith(h, "fff3") },
  { name: "MP4 video", extensions: [".mp4", ".mov"], test: (h) => startsWith(h, "66747970", 4) },
];

const EXECUTABLE_FORMATS: Magic[] = [
  { name: "ELF executable", extensions: [], test: (h) => startsWith(h, "7f454c46") },
  {
    name: "Mach-O executable",
    extensions: [],
    test: (h) => ["feedface", "feedfacf", "cefaedfe", "cffaedfe", "cafebabe", "bebafeca"].some((hex) => startsWith(h, hex)),
  },
  { name: "PE executable", extensions: [], test: (h) => startsWith(h, "4d5a") },
];

const ARCHIVE_FORMATS: Magic[] = [
  { name: "zip archive", extensions: [], test: (h) => startsWith(h, "504b0304") || startsWith(h, "504b0506") },
  { name: "gzip data", extensions: [], test: (h) => startsWith(h, "1f8b") },
];

/** How much of a skipped file is read to decide whether it really is binary. */
const BINARY_PROBE_BYTES = 8192;

function readHead(file: string): Buffer | undefined {
  const flags = fs.constants.O_RDONLY | (typeof fs.constants.O_NOFOLLOW === "number" ? fs.constants.O_NOFOLLOW : 0);
  let fd: number;
  try {
    fd = fs.openSync(file, flags);
  } catch {
    return undefined;
  }
  try {
    const head = Buffer.alloc(BINARY_PROBE_BYTES);
    const read = fs.readSync(fd, head, 0, BINARY_PROBE_BYTES, 0);
    return head.subarray(0, read);
  } catch {
    return undefined;
  } finally {
    fs.closeSync(fd);
  }
}

// ---------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------

const SEVERITY_WEIGHT: Record<Severity, number> = { critical: 40, high: 20, medium: 8, low: 3, info: 0 };
const CONFIDENCE_FACTOR: Record<Confidence, number> = { high: 1, medium: 0.6, low: 0.3 };

/** Ordering aid only; the verdict never looks at it. */
export function riskScore(findings: ReadonlyArray<Pick<Finding, "severity" | "confidence" | "kind">>): number {
  let score = 0;
  for (const finding of findings) {
    const weight = SEVERITY_WEIGHT[finding.severity] * CONFIDENCE_FACTOR[finding.confidence];
    score += finding.kind === "hotspot" ? weight / 4 : weight;
  }
  return Math.min(100, Math.round(score * 10) / 10);
}

const atLeast = (confidence: Confidence, minimum: Confidence): boolean =>
  CONFIDENCE_ORDER[confidence] >= CONFIDENCE_ORDER[minimum];

/** Reasons that decide the verdict, worst first. */
export function verdictReasons(
  findings: ReadonlyArray<Finding>,
  tagsOf: (ruleId: string) => readonly string[],
): SkillReason[] {
  const reasons: SkillReason[] = [];
  const where = (finding: Finding): Pick<SkillReason, "findingId" | "ruleId" | "file" | "line"> => ({
    findingId: finding.id,
    ruleId: finding.ruleId,
    file: finding.file,
    line: finding.startLine,
  });
  const label = (finding: Finding): string =>
    `${finding.ruleId} at ${finding.file}:${finding.startLine} (${finding.kind}, ${finding.severity}, confidence ${finding.confidence})`;
  for (const finding of findings) {
    // Rule tags, plus the tags a finding carries from every rule that matched
    // in its group (a group keeps the released rule's id; see merge/rules).
    const malicious =
      tagsOf(finding.ruleId).includes(MALICIOUS_INTENT_TAG) || (finding.tags ?? []).includes(MALICIOUS_INTENT_TAG);
    if (malicious && atLeast(finding.confidence, "medium")) {
      reasons.push({ code: "malicious-intent", message: `rule tagged malicious-intent matched: ${label(finding)}`, ...where(finding) });
    } else if (finding.kind === "finding" && finding.severity === "critical" && finding.confidence === "high") {
      reasons.push({ code: "critical-high-confidence", message: `critical finding at high confidence: ${label(finding)}`, ...where(finding) });
    } else if (malicious) {
      reasons.push({ code: "malicious-intent-low-confidence", message: `rule tagged malicious-intent matched at low confidence: ${label(finding)}`, ...where(finding) });
    } else if (finding.kind === "hotspot") {
      reasons.push({ code: "hotspot", message: `hotspot: ${label(finding)}`, ...where(finding) });
    } else if (finding.severity === "critical" || finding.severity === "high") {
      reasons.push({ code: "high-severity", message: `${finding.severity} finding: ${label(finding)}`, ...where(finding) });
    } else if (finding.severity === "medium" && atLeast(finding.confidence, "medium")) {
      reasons.push({ code: "medium-severity", message: `medium finding: ${label(finding)}`, ...where(finding) });
    }
  }
  const order: SkillReason["code"][] = [
    "malicious-intent",
    "critical-high-confidence",
    "high-severity",
    "malicious-intent-low-confidence",
    "medium-severity",
    "hotspot",
  ];
  return reasons.sort((a, b) => order.indexOf(a.code) - order.indexOf(b.code));
}

export function decideVerdict(reasons: readonly SkillReason[], incomplete: readonly SkillIncomplete[]): SkillVerdict {
  if (reasons.some((reason) => reason.code === "malicious-intent" || reason.code === "critical-high-confidence")) {
    return "DO_NOT_INSTALL";
  }
  if (reasons.length > 0) return "REVIEW";
  if (incomplete.length > 0) return "INCOMPLETE";
  return "SAFE_TO_INSTALL";
}

export function worstVerdict(verdicts: readonly SkillVerdict[]): SkillVerdict {
  let worst: SkillVerdict = "SAFE_TO_INSTALL";
  for (const verdict of verdicts) if (VERDICT_RANK[verdict] > VERDICT_RANK[worst]) worst = verdict;
  return worst;
}

// Warnings of the rule engine that mean part of a file was not analysed.
const PARTIAL_WARNINGS: RegExp[] = [
  /^cannot read (.+?): /,
  /^rule matching of (.+?) was interrupted/,
  /^rule matching stopped at line \d+ of (.+?): /,
  /^rule matching of (.+?) exceeded the time budget/,
  /^\d+ over-long line\(s\) .* in (.+?) at line\(s\) .*; only the first \d+ characters of a line are matched/,
];

/** Skipped entries of the inventory that are not part of the package's content. */
/**
 * The only skipped files that are not package content: those of the run this
 * scan is writing, when its output directory lies inside the scanned root.
 * Everything else the inventory skipped - `.git/` content, control files,
 * planted `.audit/` look-alikes, earlier runs - is listed as not analysed.
 */
function ownRunFile(relPath: string, ownRunRel: string | undefined): boolean {
  return ownRunRel !== undefined && relPath.startsWith(`${ownRunRel}/`);
}

function isRealDirectory(dir: string): boolean {
  try {
    return fs.lstatSync(dir).isDirectory();
  } catch {
    return false;
  }
}

/** Files below a directory the inventory did not enter (bounded). */
function filesBelow(root: string, relDir: string, limit: number): { files: string[]; more: number } {
  const files: string[] = [];
  let more = 0;
  const walk = (rel: string, depth: number): void => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(fromRoot(root, rel), { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const child = `${rel}/${entry.name}`;
      if (entry.isDirectory() && !entry.isSymbolicLink()) {
        if (depth < 40) walk(child, depth + 1);
        else more += 1;
      } else if (files.length < limit) files.push(child);
      else more += 1;
    }
  };
  walk(relDir, 0);
  return { files, more };
}

const BINARY_SKIP_REASONS = new Set(["binary extension", "binary content detected (NUL byte)"]);

function packageRelative(pkgRel: string, fileRel: string): string {
  if (pkgRel === "") return fileRel;
  return fileRel === pkgRel ? "." : fileRel.slice(pkgRel.length + 1);
}

// ---------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Text pass: rules over the printable text of every file
// ---------------------------------------------------------------------------


interface TextPassState {
  /** Files whose text went through the rules and secret detectors. */
  passed: Set<string>;
  /** Files the text pass could not cover (too large, unreadable, undecodable). */
  notAnalysed: Array<{ path: string; reason: string }>;
  /** Notes about content the pass could not decode but that does not make the result incomplete. */
  notes: Array<{ path: string; note: string }>;
}

/** Absolute path of a root-relative POSIX path (no spread over its segments). */
function fromRoot(root: string, rel: string): string {
  return path.join(root, rel.split("/").join(path.sep));
}

function syntheticFile(relPath: string, absPath: string, language: InventoryFile["language"], size: number): InventoryFile {
  return { relPath, absPath, language, size, loc: 0, kind: language === "markdown" ? "doc" : "source", scannable: true, isLockfile: false };
}

/** Inflated bytes allowed for the PDF streams of one scan; beyond it a PDF is not analysed. */
const PDF_INFLATE_BUDGET = 32 * 1024 * 1024;

/** One text derived from a file, and the rules it is matched with. */
interface TextSource {
  rel: string;
  text: string;
  /** Original line of each line of `text`; a number maps every line there. */
  lines: number[] | number;
  /** `full`: the rules of the file's own language as well. */
  full: boolean;
  secrets: boolean;
  label: string;
}

/**
 * Skill mode does not trust file classification. Every file the inventory
 * skipped as binary, and every file that is not valid UTF-8, goes through a
 * text pass whose results point at the original file:
 *
 * - UTF-16 / UTF-32 text is decoded and matched like a UTF-8 file (the
 *   rules of its language, the instruction and shell rules, secrets); one
 *   that does not decode is not analysed;
 * - otherwise its printable runs, and the printable runs of the file with
 *   every NUL removed (bash drops NULs and runs what is left), are matched
 *   with the Markdown (instruction) and shell rules, the former also with
 *   the secret detectors;
 * - a PDF's FlateDecode streams are inflated (bounded) and their printable
 *   text and the strings of their text operators are matched the same way.
 *
 * Every other text file is also matched with the instruction rules, as
 * Markdown, whatever its extension. Results already reported by the normal
 * pass (same rule, file and line) are not repeated.
 */
function textPass(
  root: string,
  ruleSet: RuleSet,
  instructionIds: ReadonlySet<string>,
  scratch: string,
  invalidUtf8: readonly string[],
  withNul: readonly string[],
  state: TextPassState,
): (inv: InventoryResult, existing: readonly Finding[]) => Finding[] {
  return (inv, existing) => {
    const invalid = new Set(invalidUtf8);
    const textWithNul = new Set(withNul);
    const candidates = new Set<string>([...invalidUtf8, ...withNul]);
    for (const skip of inv.skipped) if (BINARY_SKIP_REASONS.has(skip.reason)) candidates.add(skip.relPath);
    const sources: TextSource[] = [];
    let pdfBudget = PDF_INFLATE_BUDGET;
    for (const rel of [...candidates].sort()) {
      const sourcesBefore = sources.length;
      try {
      const abs = fromRoot(root, rel);
      let buffer: Buffer | undefined;
      try {
        const stat = fs.lstatSync(abs);
        if (!stat.isFile()) continue;
        if (stat.size > ARCHIVE_MAX_FILE_BYTES) {
          state.notAnalysed.push({ path: rel, reason: `file exceeds the ${ARCHIVE_MAX_FILE_BYTES / 1024 / 1024} MiB limit of the text pass (not analysed)` });
          continue;
        }
        buffer = readFileNoFollow(abs, ARCHIVE_MAX_FILE_BYTES);
      } catch {
        buffer = undefined;
      }
      if (buffer === undefined) {
        state.notAnalysed.push({ path: rel, reason: "file could not be read for the text pass (not analysed)" });
        continue;
      }
      const wide = detectWideEncoding(buffer);
      if (wide) {
        const decoded = decodeWideText(buffer, wide);
        if (decoded === undefined) {
          state.notAnalysed.push({ path: rel, reason: `${wide.toUpperCase()} text that does not decode (not analysed)` });
          continue;
        }
        sources.push({ rel, text: decoded, lines: [...decoded.split(/\r\n|\r|\n/).keys()].map((index) => index + 1), full: true, secrets: true, label: `${wide.toUpperCase()} text` });
        state.passed.add(rel);
        continue;
      }
      if (textWithNul.has(rel)) {
        // Read as text by the normal pass; only the NUL-stripped view is new.
        // Newlines are kept, so its lines are the file's lines.
        const joined = stripNul(buffer).toString("utf8");
        sources.push({ rel, text: joined, lines: [...joined.split(/\r\n|\r|\n/).keys()].map((index) => index + 1), full: true, secrets: true, label: "text with NUL bytes removed" });
        continue;
      }
      const printable = extractPrintableText(buffer);
      sources.push({ rel, text: printable.text, lines: printable.lines, full: false, secrets: !invalid.has(rel), label: "text extracted from a non-text file" });
      if (buffer.includes(0)) {
        const joined = extractPrintableText(stripNul(buffer));
        sources.push({ rel, text: joined.text, lines: joined.lines, full: false, secrets: true, label: "text of a non-text file with NUL bytes removed" });
      }
      if (buffer.subarray(0, 1024).includes(Buffer.from("%PDF-"))) {
        const pdf = pdfStreamText(
          buffer,
          { maxStreamBytes: ARCHIVE_MAX_FILE_BYTES, maxRatio: ARCHIVE_MAX_RATIO, budget: pdfBudget },
          (data, maxOutputLength) => zlib.inflateSync(data, { maxOutputLength }),
        );
        pdfBudget -= pdf.inflatedBytes;
        // All streams of the file as one text (one scratch file), each line
        // mapped to the line its stream starts on.
        if (pdf.parts.length > 0) {
          const texts: string[] = [];
          const lines: number[] = [];
          for (const part of pdf.parts) {
            const partLines = part.text.split("\n");
            for (const partLine of partLines) {
              texts.push(partLine);
              lines.push(part.line);
            }
          }
          sources.push({ rel, text: texts.join("\n"), lines, full: false, secrets: true, label: "text of a compressed PDF stream" });
        }
        if (pdf.problems.length > 0) {
          state.notAnalysed.push({ path: rel, reason: `PDF content not analysed: ${pdf.problems.join("; ")} (limits: 1 MiB and ${ARCHIVE_MAX_RATIO}:1 per stream, ${PDF_INFLATE_BUDGET / 1024 / 1024} MiB inflated per scan, 4 MiB of text per PDF)` });
          continue;
        }
        if (pdf.undecoded.length > 0) {
          state.notes.push({ path: rel, note: `${rel}: PDF streams with ${pdf.undecoded.join(", ")} were not decoded; text in them was not analysed` });
        }
      }
      state.passed.add(rel);
      } catch (error) {
        // A failure on one file never fails the run: that file is not analysed.
        sources.length = sourcesBefore;
        state.passed.delete(rel);
        state.notAnalysed.push({ path: rel, reason: `text pass failed on this file: ${printable(error instanceof Error ? error.message : String(error), 200)} (not analysed)` });
      }
    }

    // Synthetic files: the text of each source as Markdown and as shell
    // (and under its own name for a decoded wide-text file).
    const originalOf = new Map<string, TextSource>();
    const textFiles: InventoryFile[] = [];
    const fullFiles: InventoryFile[] = [];
    const secretFiles: InventoryFile[] = [];
    sources.forEach((source, index) => {
      const file = path.join(scratch, `${index}.txt`);
      fs.writeFileSync(file, source.text, { mode: 0o600 });
      const md = syntheticFile(`${source.rel}.${index}.strings.md`, file, "markdown", source.text.length);
      const sh = syntheticFile(`${source.rel}.${index}.strings.sh`, file, "shell", source.text.length);
      textFiles.push(md, sh);
      originalOf.set(md.relPath, source);
      originalOf.set(sh.relPath, source);
      if (source.full) {
        const own = syntheticFile(source.rel, file, detectLanguage(source.rel), source.text.length);
        fullFiles.push(own);
        originalOf.set(`full:${source.rel}`, source);
      }
      if (source.secrets) {
        const secret = syntheticFile(`${source.rel}#${index}`, file, "unknown", source.text.length);
        secretFiles.push(secret);
        originalOf.set(secret.relPath, source);
      }
    });
    // Instructions can be in any text file a skill tells the agent to read.
    const instructionFiles: InventoryFile[] = inv.files
      .filter((file) => file.language !== "markdown" && file.scannable && !file.isLockfile)
      .map((file) => syntheticFile(`${file.relPath}.instr.md`, file.absPath, "markdown", file.size));
    for (const file of instructionFiles) {
      originalOf.set(file.relPath, { rel: file.relPath.slice(0, -".instr.md".length), text: "", lines: [], full: false, secrets: false, label: "" });
    }

    const lineOf = (source: TextSource, line: number): number =>
      typeof source.lines === "number" ? source.lines : (source.lines[line - 1] ?? 1);
    const instructionOnly: RuleSet = { ...ruleSet, rules: ruleSet.rules.filter((rule) => instructionIds.has(rule.id)) };
    const seen = new Set<string>(existing.map((finding) => `${finding.ruleId}\u0000${finding.file}\u0000${finding.startLine}`));
    const findings: Finding[] = [];
    const add = (hit: RuleHit, source: TextSource, line: number): void => {
      const key = `${hit.rule.id}\u0000${source.rel}\u0000${line}`;
      if (seen.has(key)) return;
      seen.add(key);
      findings.push(
        createFinding({
          ruleId: hit.rule.id,
          title: hit.rule.title,
          category: "config",
          severity: hit.rule.severity,
          confidence: hit.rule.confidence,
          kind: hit.rule.kind,
          cwe: hit.rule.cwe,
          owasp: hit.rule.owasp,
          language: detectLanguage(source.rel),
          file: source.rel,
          startLine: line,
          evidence: source.label ? `[${source.label}] ${hit.evidence}` : hit.evidence,
          message: `${hit.rule.message}${source.label ? ` (matched in the ${source.label})` : " (matched as an instruction file in skill mode)"}`,
          remediation: hit.rule.remediation,
          references: hit.rule.references ?? [hit.rule.cwe],
          provenance: { engine: "builtin-rules", rule: hit.rule.id, version: TOOL_VERSION },
        }),
      );
    };
    // A pass that throws is retried file by file; a file that still fails is
    // not analysed, and the run goes on.
    const failed = new Set<string>();
    const guarded = <T>(files: InventoryFile[], run: (batch: InventoryFile[]) => T[], originalRel: (file: InventoryFile) => string): T[] => {
      try {
        return run(files);
      } catch {
        const results: T[] = [];
        for (const file of files) {
          try {
            for (const item of run([file])) results.push(item);
          } catch (error) {
            const rel = originalRel(file);
            if (!failed.has(rel)) {
              failed.add(rel);
              state.passed.delete(rel);
              state.notAnalysed.push({ path: rel, reason: `rule matching failed on this file: ${printable(error instanceof Error ? error.message : String(error), 200)} (not analysed)` });
            }
          }
        }
        return results;
      }
    };
    const relOf = (file: InventoryFile): string => (originalOf.get(file.relPath) ?? originalOf.get(`full:${file.relPath}`))?.rel ?? file.relPath;
    for (const hit of guarded(textFiles, (batch) => scanRules(batch, ruleSet, { inlineIgnore: false }).hits, relOf)) {
      const source = originalOf.get(hit.file.relPath) as TextSource;
      add(hit, source, lineOf(source, hit.line));
    }
    for (const hit of guarded(fullFiles, (batch) => scanRules(batch, ruleSet, { inlineIgnore: false }).hits, relOf)) {
      const source = originalOf.get(`full:${hit.file.relPath}`) as TextSource;
      add(hit, source, lineOf(source, hit.line));
    }
    for (const hit of guarded(instructionFiles, (batch) => scanRules(batch, instructionOnly, { inlineIgnore: false }).hits, relOf)) {
      const source = originalOf.get(hit.file.relPath) as TextSource;
      add(hit, source, hit.line);
    }
    for (const secret of guarded(secretFiles, (batch) => scanSecrets(batch).findings, relOf)) {
      const source = originalOf.get(secret.file) as TextSource;
      const line = lineOf(source, secret.startLine);
      const key = `${secret.ruleId}\u0000${source.rel}\u0000${line}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const { id: _id, fingerprint: _fingerprint, ...rest } = secret;
      findings.push(
        createFinding({
          ...(rest as Parameters<typeof createFinding>[0]),
          file: source.rel,
          startLine: line,
          endLine: line,
          evidence: `[${source.label}] ${secret.evidence}`,
        }),
      );
    }
    return findings;
  };
}

/**
 * After the text pass: a file that is still not analysed. Executables and
 * nested archives are code or containers whose behaviour or content the text
 * pass does not cover.
 */
export function classifySkippedBinary(_relPath: string, head: Buffer | undefined): string | undefined {
  if (!head) return "binary file could not be read";
  const executable = EXECUTABLE_FORMATS.find((magic) => magic.test(head));
  if (executable) return `${executable.name} (only its printable text was analysed)`;
  const archive = ARCHIVE_FORMATS.find((magic) => magic.test(head));
  if (archive) return `nested ${archive.name} (contents not analysed)`;
  return undefined;
}

// ---------------------------------------------------------------------------
// Instruction-file rules in skill mode
// ---------------------------------------------------------------------------

function listRuleFiles(dir: string, depth = 0): string[] {
  if (depth > 10) return [];
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  const files: string[] = [];
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      for (const file of listRuleFiles(full, depth + 1)) files.push(file);
    }
    else if (entry.isFile() && /\.ya?ml$/i.test(entry.name)) files.push(full);
  }
  return files;
}

/**
 * Ids of the rules whose `pathInclude` uses the `{{INSTR}}` macro (the
 * instruction files agent hosts load: SKILL.md, CLAUDE.md, ...), read from
 * the rule files as written, before the macro is expanded.
 */
export function instructionRuleIds(rulesDir: string): Set<string> {
  const ids = new Set<string>();
  for (const file of listRuleFiles(path.resolve(rulesDir))) {
    let document: unknown;
    try {
      document = parseYaml(fs.readFileSync(file, "utf8"));
    } catch {
      continue;
    }
    const rules = Array.isArray(document) ? document : (document as { rules?: unknown } | null)?.rules;
    if (!Array.isArray(rules)) continue;
    for (const rule of rules) {
      if (!rule || typeof rule !== "object") continue;
      const { id, pathInclude } = rule as { id?: unknown; pathInclude?: unknown };
      if (typeof id === "string" && typeof pathInclude === "string" && pathInclude.includes("{{INSTR}}")) ids.add(id);
    }
  }
  return ids;
}

const escapeRegex = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * Skill mode: a skill loads the files its SKILL.md points at (`reference.md`,
 * `FORMS.md`, ...), so every Markdown file inside a package is an
 * instruction file. The instruction-file rules additionally match `*.md` /
 * `*.mdc` below every package directory.
 */
export function extendInstructionRules(ruleSet: RuleSet, ids: ReadonlySet<string>, packageRels: readonly string[]): RuleSet {
  if (ids.size === 0 || packageRels.length === 0) return ruleSet;
  const extensions = "\\.(?:mdc?|mdx)$";
  const markdown = packageRels.includes("")
    ? extensions
    : `^(?:${packageRels.map((rel) => `${escapeRegex(rel)}/`).join("|")}).*${extensions}`;
  return {
    ...ruleSet,
    rules: ruleSet.rules.map((rule) => {
      const include = rule.compiled.pathInclude;
      if (!ids.has(rule.id) || !include) return rule;
      return {
        ...rule,
        compiled: { ...rule.compiled, pathInclude: new RegExp(`(?:${include.source})|${markdown}`, include.flags) },
      };
    }),
  };
}

/** `path` of the group of files outside every package. */
export const OUTSIDE_PACKAGES_PATH = "<outside packages>";

/** How a package is shown to a person: `./relative/path`, or the outside group's fixed label. */
export function displayPackagePath(pkg: Pick<SkillPackage, "path" | "kind">): string {
  if (pkg.kind === "outside") return OUTSIDE_PACKAGES_PATH;
  return pkg.path === "." ? "./" : `./${pkg.path}`;
}

export const SKILL_DEFAULT_ENGINES: EngineName[] = ["builtin", "opengrep", "gitleaks"];

export interface SkillScanOptions {
  target: string;
  recursive?: boolean;
  formats?: ReportFormat[];
  /** Directory that receives `<run-id>/`. Default: `<target>/.audit` for a directory, `<cwd>/.audit` otherwise. */
  out?: string;
  offline?: boolean;
  /** Explicit engine list; default builtin plus installed opengrep and gitleaks. */
  engines?: EngineName[];
  rulesDir?: string;
  lang?: "en" | "zh";
  /** False refuses git URLs (the MCP server). Default true. */
  allowGit?: boolean;
  /** Working directory for the default output of unpacked or cloned targets. */
  cwd?: string;
  pathEnv?: string;
  http?: HttpClient;
  gitTimeoutMs?: number;
  now?: () => Date;
}

export interface SkillScanResult {
  document: SkillScanDocument;
  scan: ScanResult;
  /** Path of skill.json in the run directory. */
  jsonPath: string;
}

interface ResolvedTarget {
  kind: SkillScanDocument["target"]["kind"];
  root: string;
  /** Set when root is a temporary directory to remove afterwards. */
  tempDir?: string;
  archiveSkipped: ArchiveSkip[];
}

async function resolveTarget(options: SkillScanOptions): Promise<ResolvedTarget> {
  const input = options.target;
  if (!input) throw new SkillTargetError("skill requires a target", "SKILL_TARGET");
  const localExists = fs.existsSync(input);
  const git = checkGitTarget(input, localExists);
  if (git.remote) {
    if (options.allowGit === false) {
      throw new SkillTargetError("git URLs are not accepted here; clone the repository yourself and pass the directory", "GIT_URL_REFUSED");
    }
    if (!git.ok) throw new SkillTargetError(`refusing git target: ${git.reason}`, "GIT_URL_REFUSED");
    if (options.offline) throw new SkillTargetError("a git target needs the network; refused with --offline", "GIT_URL_REFUSED");
    const tempDir = makeTempDir();
    try {
      const destination = path.join(tempDir, "repo");
      await cloneRepository(git.url, destination, { pathEnv: options.pathEnv, timeoutMs: options.gitTimeoutMs });
      // Our own fresh clone's repository data is not package content; any
      // other `.git` (nested, or in a directory or archive) is reported.
      fs.rmSync(path.join(destination, ".git"), { recursive: true, force: true });
      return { kind: "git", root: destination, tempDir, archiveSkipped: [] };
    } catch (error) {
      removeTempDir(tempDir);
      throw error;
    }
  }
  let stat: fs.Stats;
  try {
    stat = fs.statSync(input);
  } catch {
    throw new SkillTargetError(`target does not exist: ${input}`, "SKILL_TARGET_MISSING");
  }
  if (stat.isDirectory()) return { kind: "directory", root: input, archiveSkipped: [] };
  if (!stat.isFile()) throw new SkillTargetError(`target is not a file or directory: ${input}`, "SKILL_TARGET");
  const format = archiveFormatOf(input);
  if (format) {
    const tempDir = makeTempDir();
    try {
      const destination = path.join(tempDir, "package");
      fs.mkdirSync(destination);
      const result = extractArchive(input, destination, format);
      return { kind: "archive", root: destination, tempDir, archiveSkipped: result.skipped };
    } catch (error) {
      removeTempDir(tempDir);
      throw error;
    }
  }
  if (path.extname(input).toLowerCase() === ".md") {
    // A skill is its directory: the scripts and references next to SKILL.md
    // are part of what gets installed, so the containing directory is the
    // package.
    return { kind: "skill-file", root: path.dirname(path.resolve(input)), archiveSkipped: [] };
  }
  throw new SkillTargetError(
    `unsupported target ${input}: expected a directory, a SKILL.md, a .zip, .tar, .tar.gz or .tgz archive, or an https/ssh git URL`,
    "SKILL_TARGET",
  );
}

function readManifestName(file: string): string | undefined {
  try {
    const data: unknown = JSON.parse(readFileNoFollow(file, 256 * 1024)?.toString("utf8") ?? "null");
    if (data && typeof data === "object" && typeof (data as { name?: unknown }).name === "string") {
      return (data as { name: string }).name;
    }
  } catch {
    // no name
  }
  return undefined;
}

/** Free text taken from the package (names, parser messages): one printable line, secrets masked. */
function cleanText(value: string, max: number): string {
  return redactText(singleLineText(printable(value, max), max));
}

function cleanName(value: string): string {
  return cleanText(value, 100);
}

function describePackage(root: string, rel: string, kind: PackageDir["kind"]): { pkg: PackageDir; allowed: string[] | null } {
  const dir = rel === "" ? root : fromRoot(root, rel);
  const notes: string[] = [];
  let name: string | undefined;
  let allowed: string[] | null = null;
  let skillFile: string | undefined;
  const skillPath = path.join(dir, "SKILL.md");
  let skillIsLink = false;
  try {
    skillIsLink = fs.lstatSync(skillPath).isSymbolicLink();
  } catch {
    skillIsLink = false;
  }
  if (skillIsLink) notes.push("SKILL.md is a symbolic link; it was not followed or analysed");
  if (isFileNoFollow(skillPath)) {
    skillFile = joinRel(rel, "SKILL.md");
    let text: string | undefined;
    try {
      text = readFileNoFollow(skillPath, ARCHIVE_MAX_FILE_BYTES)?.toString("utf8");
    } catch {
      notes.push("SKILL.md could not be read for its front matter");
    }
    if (text !== undefined) {
      const frontmatter = parseFrontmatter(text);
      if (!frontmatter.ok) notes.push(`SKILL.md ${frontmatter.error ?? "front matter could not be read"}; allowed-tools not compared`);
      const data = frontmatter.data ?? {};
      if (typeof data.name === "string" && data.name.trim()) name = data.name.trim();
      if ("allowed-tools" in data) {
        const tools = parseAllowedTools(data["allowed-tools"]);
        if (tools === undefined) notes.push("SKILL.md allowed-tools is neither a string nor a list; not compared");
        else allowed = tools;
      }
    }
  }
  if (kind === "plugin" && name === undefined) {
    name =
      readManifestName(path.join(dir, ".claude-plugin", "plugin.json")) ?? readManifestName(path.join(dir, "plugin.json"));
  }
  if (kind === "directory") notes.push("no SKILL.md or plugin manifest found; scanned as a plain directory");
  const fallback = rel === "" ? path.basename(root) : (rel.split("/").pop() as string);
  return {
    pkg: {
      rel,
      kind,
      name: cleanName(name ?? fallback),
      ...(skillFile ? { skillFile } : {}),
      notes: notes.map((note) => cleanText(note, 300)),
    },
    allowed,
  };
}

/**
 * Scan a skill or plugin package (or, with `recursive`, every package below a
 * directory) and decide an install verdict for each.
 */
export async function scanSkill(options: SkillScanOptions): Promise<SkillScanResult> {
  const target = await resolveTarget(options);
  try {
    return await scanResolved(options, target);
  } finally {
    if (target.tempDir) removeTempDir(target.tempDir);
  }
}

async function scanResolved(options: SkillScanOptions, target: ResolvedTarget): Promise<SkillScanResult> {
  const validated = validateAuditRoot(target.root);
  const root = validated.root;
  const recursive = options.recursive === true;

  // ---- Packages ----
  const packageDirs: PackageDir[] = [];
  const allowedByPackage = new Map<string, string[] | null>();
  const discovery = recursive ? discoverPackages(root) : undefined;
  const found = recursive
    ? (discovery?.packages ?? [])
    : [{ rel: "", kind: packageKindAt(root) ?? ("directory" as const) }];
  if (found.length === 0) {
    found.push({ rel: "", kind: "directory" });
  }
  for (const entry of found) {
    const { pkg, allowed } = describePackage(root, entry.rel, entry.kind);
    if (recursive && entry.kind === "directory") {
      pkg.notes.splice(0, pkg.notes.length, "no SKILL.md or plugin manifest found below the target; scanned as one plain directory");
    }
    packageDirs.push(pkg);
    allowedByPackage.set(pkg.rel, allowed);
  }
  const capabilityStates = new Map<string, CapabilityState>();
  for (const pkg of packageDirs) capabilityStates.set(pkg.rel, emptyCapabilities(allowedByPackage.get(pkg.rel) ?? null));

  // ---- Scan (untrusted, always) ----
  const explicitEngines = options.engines !== undefined;
  const engines = options.engines ?? SKILL_DEFAULT_ENGINES;
  // Never into the package by default: a vetted directory is often copied
  // as it is into the host's skills directory.
  const out = options.out ?? path.join(options.cwd ?? process.cwd(), ".audit");
  const contentNotAnalysed: Array<{ path: string; reason: string }> = [];
  const invalidUtf8: string[] = [];
  const withNul: string[] = [];
  const hookFailures: string[] = [];
  const instructionRules = instructionRuleIds(options.rulesDir ?? defaultRulesDir());
  // Instruction matching covers the whole target: in a recursive scan a file
  // outside every package (`../../shared.md`) feeds the outside group.
  const skillRules = extendInstructionRules(loadRules(options.rulesDir ?? defaultRulesDir()), instructionRules, [""]);
  const textState: TextPassState = { passed: new Set(), notAnalysed: [], notes: [] };
  const scratch = makeTempDir();
  const capability = capabilityCheck(packageDirs, allowedByPackage, capabilityStates, contentNotAnalysed, invalidUtf8, withNul);
  const strings = textPass(root, skillRules, instructionRules, scratch, invalidUtf8, withNul, textState);
  let scan: ScanResult;
  try {
    scan = await scanProject({
    root,
    untrusted: true,
    engines,
    offline: options.offline === true,
    formats: options.formats,
    ...(out !== undefined ? { out } : {}),
    ...(options.rulesDir ? { rulesDir: options.rulesDir } : {}),
    ...(options.lang ? { lang: options.lang } : {}),
    ...(options.pathEnv ? { pathEnv: options.pathEnv } : {}),
    ...(options.http ? { http: options.http } : {}),
    ...(options.now ? { now: options.now } : {}),
    extraFindings: (inv, existing) => {
      const results: Finding[] = [];
      for (const [name, run] of [
        ["capability check", () => capability(inv)],
        ["text pass", () => strings(inv, existing)],
      ] as const) {
        try {
          for (const finding of run()) results.push(finding);
        } catch (error) {
          hookFailures.push(`the skill ${name} failed: ${printable(error instanceof Error ? error.message : String(error), 200)}`);
        }
      }
      return results;
    },
    transformRules: () => skillRules,
  });
  } finally {
    removeTempDir(scratch);
  }

  // Tags come from the rule set the scan used, by rule id.
  const ruleSet = loadRules(options.rulesDir ?? defaultRulesDir());
  const tagsById = new Map<string, readonly string[]>();
  for (const rule of ruleSet.rules) tagsById.set(rule.id, rule.tags ?? []);
  const tagsOf = (ruleId: string): readonly string[] => tagsById.get(ruleId) ?? [];

  // ---- What was not analysed ----
  const globalIncomplete: SkillIncomplete[] = [];
  const selected = new Set(engines);
  if (!selected.has("builtin")) {
    globalIncomplete.push({ reason: "the built-in rules and secret detectors were not run (--engines without builtin)" });
  }
  for (const engine of scan.coverage.engines) {
    if (engine.status === "failed" || engine.status === "timeout") {
      globalIncomplete.push({ reason: `external engine ${engine.name} ${engine.status === "timeout" ? "timed out" : "failed"}: ${engine.detail ?? ""}`.trim() });
    } else if (engine.status === "missing" && explicitEngines) {
      globalIncomplete.push({ reason: `requested engine ${engine.name} is not installed` });
    }
  }
  for (const failure of hookFailures) globalIncomplete.push({ reason: `${failure} (not analysed)` });
  if (discovery?.truncated) {
    globalIncomplete.push({ reason: `package discovery stopped after ${DISCOVERY_MAX_ENTRIES} directory entries` });
  }
  const osv = scan.coverage.engines.find((engine) => engine.name === "osv");
  const dependencyGap =
    osv?.status === "offline"
      ? "dependency advisories were not checked (offline)"
      : osv?.status === "degraded"
        ? "dependency advisories could not be checked for every package (OSV.dev unavailable)"
        : undefined;

  const fileIncomplete: Array<{ path: string; reason: string }> = [...contentNotAnalysed, ...textState.notAnalysed];
  const ownRunRel = (() => {
    const rel = path.relative(root, scan.runDir);
    return rel && !rel.startsWith("..") && !path.isAbsolute(rel) ? rel.split(path.sep).join("/") : undefined;
  })();
  const localDirectoryTarget = target.kind === "directory" || target.kind === "skill-file";
  let rootGitNote: string | undefined;
  // A `.git` FILE (a gitdir pointer of a worktree or submodule) is read as
  // text, but the repository it points at is not part of the scan.
  for (const scanned of scan.coverage.scannedFiles) {
    if (scanned.path === ".git" || scanned.path.endsWith("/.git")) {
      fileIncomplete.push({ path: scanned.path, reason: "a .git file (gitdir pointer); the repository data it points at is not analysed" });
    }
  }
  for (const skip of scan.coverage.skipped) {
    if (ownRunFile(skip.path, ownRunRel)) continue;
    if (skip.path.endsWith("/") && skip.reason === "default-excluded directory") {
      // A directory the inventory never enters (`.git`): every file in it.
      const dir = skip.path.slice(0, -1);
      // Except the repository metadata at the root of a local directory
      // target (a skill the user just cloned): a real directory there is
      // not part of what gets installed. A `.git` in an archive, a nested
      // one, or a `.git` file or link is still reported.
      if (dir === ".git" && localDirectoryTarget && isRealDirectory(path.join(root, ".git"))) {
        let problems: Array<{ path: string; reason: string }>;
        try {
          problems = gitDirProblems(path.join(root, ".git"));
        } catch (error) {
          problems = [{ path: ".git", reason: `git metadata could not be checked: ${printable(error instanceof Error ? error.message : String(error), 200)}` }];
        }
        if (problems.length === 0) {
          rootGitNote = "git metadata at .git/ not analysed: not part of an installed skill";
          continue;
        }
        // Not what git creates for a checkout: every unusual entry with its
        // reason, then every file as before.
        for (const entry of problems) fileIncomplete.push(entry);
      }
      const below = filesBelow(root, dir, 200);
      for (const file of below.files) fileIncomplete.push({ path: file, reason: `inside ${dir}/, which is never scanned (not analysed)` });
      if (below.more > 0) fileIncomplete.push({ path: dir, reason: `${below.more} more file(s) inside ${dir}/ not analysed` });
      continue;
    }
    if (BINARY_SKIP_REASONS.has(skip.reason)) {
      // Analysed only once the text pass ran on it (its own reason is listed
      // when it could not); executables and nested archives stay listed.
      if (!textState.passed.has(skip.path)) continue;
      const reason = classifySkippedBinary(skip.path, readHead(fromRoot(root, skip.path)));
      if (reason) fileIncomplete.push({ path: skip.path, reason });
      continue;
    }
    if (skip.reason.startsWith("symbolic link")) {
      fileIncomplete.push({ path: skip.path, reason: "symbolic link (not followed, not analysed)" });
      continue;
    }
    fileIncomplete.push({
      path: skip.path.replace(/\/$/, ""),
      reason: skip.reason === "code-audit output" ? "named like code-audit output but not written by this run (not rule-matched)" : skip.reason,
    });
  }
  for (const skip of target.archiveSkipped) fileIncomplete.push({ path: skip.path, reason: `archive entry ${skip.reason}` });
  // A skill tree whose list of binary files hit its budget: the binaries in
  // it were not all checked (inventory.ts). "" is the audit root.
  for (const tree of scan.coverage.binaryListIncomplete ?? []) {
    fileIncomplete.push({
      path: tree === "" ? "." : tree,
      reason: "the list of binary files in this skill tree is incomplete (entry budget reached); not every file was checked",
    });
  }
  // Every partial-analysis warning names its file; it counts for the packages
  // that contain the file (none, for a file outside every package).
  for (const warning of scan.warnings) {
    for (const pattern of PARTIAL_WARNINGS) {
      const match = pattern.exec(warning);
      if (!match) continue;
      fileIncomplete.push({ path: match[1] as string, reason: `only partly analysed: ${singleLineText(warning, 300)}` });
      break;
    }
  }

  // ---- Per package ----
  const all = [...scan.findings, ...scan.hotspots];
  const toPackage = (
    entry: { path: string; name: string; kind: SkillPackage["kind"]; notes: string[] },
    own: Finding[],
    incomplete: SkillIncomplete[],
    state: CapabilityState,
  ): SkillPackage => {
    const reasons = verdictReasons(own, tagsOf);
    const verdict = decideVerdict(reasons, incomplete);
    return {
      path: entry.path,
      name: entry.name,
      kind: entry.kind,
      verdict,
      verdictText: VERDICT_TEXT[verdict],
      riskScore: riskScore(own),
      reasons,
      incomplete,
      findings: own.map((finding) => ({
        id: finding.id,
        ruleId: finding.ruleId,
        kind: finding.kind,
        severity: finding.severity,
        confidence: finding.confidence,
        title: singleLineText(finding.title, 200),
        file: finding.file,
        startLine: finding.startLine,
        tags: [...new Set([...tagsOf(finding.ruleId), ...(finding.tags ?? [])])].sort(),
        evidence: singleLineText(finding.evidence, 240),
      })),
      capabilities: {
        allowedTools: state.allowedTools,
        detected: {
          network: [...new Set(state.detected.network)],
          subprocess: [...new Set(state.detected.subprocess)],
          fileWrite: [...new Set(state.detected.fileWrite)],
        },
        undeclared: CAPABILITIES.filter((capability) => state.undeclared.has(capability)),
      },
      notes: entry.notes,
    };
  };
  const packages: SkillPackage[] = packageDirs.map((pkg) => {
    const own = all.filter((finding) => isInside(pkg.rel, finding.file));
    const incomplete: SkillIncomplete[] = [...globalIncomplete];
    for (const entry of fileIncomplete) {
      if (isInside(pkg.rel, entry.path)) incomplete.push({ path: packageRelative(pkg.rel, entry.path), reason: entry.reason });
    }
    if (dependencyGap && scan.coverage.manifests.some((manifest) => isInside(pkg.rel, manifest.relPath))) {
      incomplete.push({ reason: dependencyGap });
    }
    return toPackage(
      {
        path: pkg.rel === "" ? "." : pkg.rel,
        name: pkg.name,
        kind: pkg.kind,
        notes: [
          ...pkg.notes,
          ...(rootGitNote && pkg.rel === "" ? [rootGitNote] : []),
          ...textState.notes.filter((entry) => isInside(pkg.rel, entry.path)).map((entry) => cleanText(entry.note, 300)),
        ],
      },
      own,
      incomplete,
      capabilityStates.get(pkg.rel) as CapabilityState,
    );
  });
  // Results and unanalysed files outside every package (recursive scans of a
  // directory that is not itself a package) form a group of their own, which
  // counts toward the overall verdict and the exit code like a package.
  const insideSome = (file: string): boolean => packageDirs.some((pkg) => isInside(pkg.rel, file));
  const outside = all.filter((finding) => !insideSome(finding.file));
  const outsideIncomplete = fileIncomplete.filter((entry) => !insideSome(entry.path));
  if (outside.length > 0 || outsideIncomplete.length > 0) {
    packages.push(
      toPackage(
        {
          path: OUTSIDE_PACKAGES_PATH,
          name: "outside any package",
          kind: "outside",
          notes: ["files below the target that belong to no discovered skill or plugin"],
        },
        outside,
        outsideIncomplete,
        emptyCapabilities(null),
      ),
    );
  }
  packages.sort((a, b) => VERDICT_RANK[b.verdict] - VERDICT_RANK[a.verdict] || b.riskScore - a.riskScore || a.path.localeCompare(b.path));

  const counts = { DO_NOT_INSTALL: 0, REVIEW: 0, INCOMPLETE: 0, SAFE_TO_INSTALL: 0 };
  for (const pkg of packages) counts[pkg.verdict] += 1;
  const verdict = worstVerdict(packages.map((pkg) => pkg.verdict));
  const document: SkillScanDocument = SkillScanDocumentSchema.parse({
    schemaVersion: 1,
    tool: { name: TOOL_NAME, version: TOOL_VERSION },
    target: { input: options.target, kind: target.kind },
    recursive,
    runId: scan.runId,
    runDir: scan.runDir,
    packages,
    summary: {
      packages: packages.length,
      verdicts: counts,
      verdict,
      exitCode: verdict === "SAFE_TO_INSTALL" ? 0 : 1,
      outside: {
        findings: outside.filter((finding) => finding.kind === "finding").length,
        hotspots: outside.filter((finding) => finding.kind === "hotspot").length,
      },
    },
  });
  const jsonPath = writeRunFile(scan.runDir, "skill.json", `${JSON.stringify(document, null, 2)}\n`);
  if ((options.formats ?? ["md"]).includes("md")) {
    writeRunFile(scan.runDir, "skill.md", renderSkillMarkdown(document));
  }
  return { document, scan, jsonPath };
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function mdText(value: string): string {
  return singleLineText(value, 400).replace(/[|`*_<>[\]]/g, (char) => `\\${char}`);
}

export function renderSkillMarkdown(document: SkillScanDocument): string {
  const lines: string[] = [
    "# code-audit skill verdict",
    "",
    `- Target: ${mdText(document.target.input)} (${document.target.kind})`,
    `- Packages: ${document.summary.packages}; overall verdict **${document.summary.verdict}**`,
    `- Run: ${mdText(document.runId)}`,
    "",
    "Content quoted below comes from the scanned package and is untrusted.",
    "",
    "| Verdict | Package | Path | Risk |",
    "| --- | --- | --- | --- |",
  ];
  for (const pkg of document.packages) {
    lines.push(`| ${pkg.verdict} | ${pkg.kind === "outside" ? "-" : mdText(pkg.name)} | ${mdText(displayPackagePath(pkg))} | ${pkg.riskScore} |`);
  }
  for (const pkg of document.packages) {
    lines.push("", `## ${pkg.verdict}: ${mdText(displayPackagePath(pkg))}${pkg.kind === "outside" ? "" : ` (name: ${mdText(pkg.name)})`}`, "", pkg.verdictText);
    if (pkg.reasons.length > 0) {
      lines.push("", "Reasons:", "");
      for (const reason of pkg.reasons) lines.push(`- ${mdText(reason.message)}`);
    }
    if (pkg.incomplete.length > 0) {
      lines.push("", "Not analysed:", "");
      for (const entry of pkg.incomplete) lines.push(`- ${entry.path ? `${mdText(entry.path)}: ` : ""}${mdText(entry.reason)}`);
    }
    if (pkg.capabilities.allowedTools !== null || pkg.capabilities.undeclared.length > 0) {
      lines.push(
        "",
        `allowed-tools: ${pkg.capabilities.allowedTools === null ? "(not declared)" : mdText(pkg.capabilities.allowedTools.join(", ") || "(empty)")}` +
          (pkg.capabilities.undeclared.length > 0 ? `; undeclared: ${pkg.capabilities.undeclared.join(", ")}` : ""),
      );
    }
    for (const note of pkg.notes) lines.push("", `Note: ${mdText(note)}`);
  }
  lines.push("");
  return `${lines.join("\n")}\n`;
}

/** Plain text for a terminal. Repository-derived text is reduced to one printable line. */
export function renderSkillText(document: SkillScanDocument, maxReasons = 5): string {
  const lines: string[] = [`code-audit skill: ${printable(document.target.input, 300)} (${document.target.kind})`];
  for (const pkg of document.packages) {
    lines.push(
      pkg.kind === "outside"
        ? `${pkg.verdict.padEnd(15)} ${OUTSIDE_PACKAGES_PATH}  risk ${pkg.riskScore}/100`
        : `${pkg.verdict.padEnd(15)} ${printable(displayPackagePath(pkg), 200)}  (name: ${printable(pkg.name, 100)})  risk ${pkg.riskScore}/100`,
    );
    if (pkg.verdict === "SAFE_TO_INSTALL") lines.push(`  ${SAFE_TO_INSTALL_TEXT}`);
    for (const reason of pkg.reasons.slice(0, maxReasons)) lines.push(`  - ${printable(reason.message, 300)}`);
    if (pkg.reasons.length > maxReasons) lines.push(`  - ... ${pkg.reasons.length - maxReasons} more (see skill.json)`);
    for (const entry of pkg.incomplete.slice(0, maxReasons)) {
      lines.push(`  not analysed: ${entry.path ? `${printable(entry.path, 200)}: ` : ""}${printable(entry.reason, 300)}`);
    }
    if (pkg.incomplete.length > maxReasons) lines.push(`  not analysed: ... ${pkg.incomplete.length - maxReasons} more (see skill.json)`);
  }
  const counts = document.summary.verdicts;
  lines.push(
    `Summary: ${document.summary.packages} package(s): ${SKILL_VERDICTS.filter((verdict) => counts[verdict] > 0)
      .map((verdict) => `${counts[verdict]} ${verdict}`)
      .join(", ")}`,
  );
  if (document.summary.outside.findings + document.summary.outside.hotspots > 0) {
    lines.push(
      `Outside any package: ${document.summary.outside.findings} finding(s), ${document.summary.outside.hotspots} hotspot(s)`,
    );
  }
  lines.push(`Run directory: ${document.runDir}`, "");
  return lines.join("\n");
}
