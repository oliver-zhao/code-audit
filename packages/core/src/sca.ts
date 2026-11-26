import fs from "node:fs";
import path from "node:path";
import { parse as parseYaml } from "yaml";
import {
  createFinding,
  type Finding,
  type Severity,
} from "./finding.js";
import type { InventoryResult, ManifestRef } from "./inventory.js";

export type OsvEcosystem = "npm" | "PyPI" | "Go" | "Maven" | "NuGet";

export interface ScaPackage {
  name: string;
  version: string;
  ecosystem: OsvEcosystem;
  file: string;
  line: number;
  manager: string;
  direct: boolean;
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

const ECOSYSTEM_BY_MANAGER: Record<string, OsvEcosystem> = {
  npm: "npm",
  pnpm: "npm",
  yarn: "npm",
  requirements: "PyPI",
  poetry: "PyPI",
  go: "Go",
  maven: "Maven",
  nuget: "NuGet",
};

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

function pushUnique(packages: ScaPackage[]): ScaPackage[] {
  const seen = new Set<string>();
  const result: ScaPackage[] = [];
  for (const pkg of packages) {
    const key = `${pkg.ecosystem}\u0000${normalizePackageName(pkg.name, pkg.ecosystem)}\u0000${pkg.version}`;
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

export function parseRequirements(
  content: string,
  file: string,
): ParsedDependencies {
  const warnings: string[] = [];
  const packages: ScaPackage[] = [];
  let unpinned = 0;

  const lines = content.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const raw = lines[index] ?? "";
    const line = raw.replace(/#.*$/, "").trim();
    if (!line || line.startsWith("-")) continue;
    const match = /^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*==\s*([^;\s]+)/.exec(line);
    if (!match) {
      if (/^[A-Za-z0-9_.-]+\s*(?:[<>=!~]|$)/.test(line)) unpinned += 1;
      continue;
    }
    const name = match[1] ?? "";
    const version = match[2] ?? "";
    if (!name || !version || version.includes("*")) {
      unpinned += 1;
      continue;
    }
    packages.push({
      name,
      version,
      ecosystem: "PyPI",
      file,
      line: index + 1,
      manager: "requirements",
      direct: true,
    });
  }

  if (unpinned > 0) {
    warnings.push(
      `${file}: ${unpinned} unpinned entries not parsed (unresolved transitive dependencies)`,
    );
  }
  return { packages: pushUnique(packages), warnings };
}

export function parsePoetryLock(
  content: string,
  file: string,
): ParsedDependencies {
  const warnings: string[] = [];
  const packages: ScaPackage[] = [];
  const blocks = content.split(/^\[\[package\]\]\s*$/m);
  let offset = content.indexOf("[[package]]");

  for (let index = 1; index < blocks.length; index += 1) {
    const block = blocks[index] ?? "";
    const start = content.indexOf(block, Math.max(0, offset));
    const name = /^name\s*=\s*"([^"]+)"/m.exec(block)?.[1];
    const version = /^version\s*=\s*"([^"]+)"/m.exec(block)?.[1];
    if (name && version) {
      packages.push({
        name,
        version,
        ecosystem: "PyPI",
        file,
        line: start >= 0 ? lineAt(content, start) : 1,
        manager: "poetry",
        direct: true,
      });
    }
    offset = start + block.length;
  }

  if (packages.length === 0) {
    warnings.push(`${file}: no parseable poetry dependencies found`);
  }
  return { packages: pushUnique(packages), warnings };
}

export function parseGoMod(content: string, file: string): ParsedDependencies {
  const warnings: string[] = [];
  const packages: ScaPackage[] = [];
  const lines = content.split(/\r?\n/);
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

export function parseLockfile(
  relPath: string,
  content: string,
): ParsedDependencies {
  const base = path.basename(relPath);
  switch (base) {
    case "package-lock.json":
      return parsePackageLock(content, relPath);
    case "pnpm-lock.yaml":
      return parsePnpmLock(content, relPath);
    case "requirements.txt":
      return parseRequirements(content, relPath);
    case "poetry.lock":
      return parsePoetryLock(content, relPath);
    case "go.mod":
      return parseGoMod(content, relPath);
    case "pom.xml":
      return parsePomXml(content, relPath);
    case "packages.lock.json":
      return parsePackagesLock(content, relPath);
    case "go.sum":
    case "yarn.lock":
      return { packages: [], warnings: [] };
    default:
      return { packages: [], warnings: [`${relPath}: unsupported lockfile type`] };
  }
}

function dirOf(relPath: string): string {
  return path.posix.dirname(relPath.split(path.sep).join("/"));
}

const EXPECTED_LOCKFILES: Record<string, string[]> = {
  "package.json": ["package-lock.json", "pnpm-lock.yaml", "yarn.lock"],
  "pyproject.toml": ["poetry.lock", "requirements.txt"],
  "Pipfile": ["Pipfile.lock"],
  "Cargo.toml": ["Cargo.lock"],
  "composer.json": ["composer.lock"],
};

function manifestHygieneWarnings(inventory: InventoryResult): string[] {
  const warnings: string[] = [];
  const byDir = new Map<string, Set<string>>();
  for (const manifest of inventory.manifests) {
    const dir = dirOf(manifest.relPath);
    const set = byDir.get(dir) ?? new Set<string>();
    set.add(path.basename(manifest.relPath));
    byDir.set(dir, set);
  }

  for (const manifest of inventory.manifests) {
    if (manifest.isLockfile) continue;
    const base = path.basename(manifest.relPath);
    const dir = dirOf(manifest.relPath);
    const present = byDir.get(dir) ?? new Set<string>();
    const required = EXPECTED_LOCKFILES[base];
    if (required && !required.some((candidate) => present.has(candidate))) {
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

function severityFromScore(score: number): Severity {
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
    ranges?: Array<{ events?: Array<{ fixed?: string; last_affected?: string }> }>;
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
      affected.package.ecosystem !== pkg.ecosystem
    ) {
      continue;
    }
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) candidates.push(event.fixed);
      }
    }
  }
  const applicable = candidates
    .filter((candidate) => compareVersions(candidate, pkg.version) > 0)
    .sort(compareVersions);
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

export async function runSca(options: ScaOptions): Promise<ScaResult> {
  const warnings = manifestHygieneWarnings(options.inventory);
  const findings: Finding[] = [];
  const packages: ScaPackage[] = [];
  const skipLockfiles = new Set(options.skipLockfiles ?? []);

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
    const parsed = parseLockfile(lockfile.relPath, content);
    packages.push(...parsed.packages);
    warnings.push(...parsed.warnings);
  }

  const uniquePackages = pushUnique(packages);
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
      `offline mode: skipped OSV.dev queries (${uniquePackages.length} dependencies were not checked for vulnerabilities)`,
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
  let degraded = false;

  for (let offset = 0; offset < uniquePackages.length; offset += batchSize) {
    const batch = uniquePackages.slice(offset, offset + batchSize);
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
        if (vuln.id) associations.push({ pkg, vulnId: vuln.id });
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

  for (const { pkg, vulnId } of associations) {
    const detail = details.get(vulnId);
    const { severity, cvss } = extractSeverity(detail);
    const fixedVersion = extractFixedVersion(detail, pkg);
    const aliases = detail?.aliases ?? [];
    const summary = detail?.summary ?? `OSV advisory ${vulnId}`;
    const cwe = detail?.database_specific?.cwe_ids?.[0] ?? "CWE-1104";
    const references = [
      `https://osv.dev/vulnerability/${vulnId}`,
      ...(detail?.references ?? [])
        .map((reference) => reference.url)
        .filter((url): url is string => Boolean(url)),
    ].slice(0, 5);

    findings.push(
      createFinding({
        ruleId: `sca-${vulnId.toLowerCase()}`,
        title: truncate(`${pkg.name}@${pkg.version}: ${summary}`, 160),
        category: "sca",
        severity,
        confidence: "high",
        cvss,
        cwe,
        owasp: "A06:2021",
        file: pkg.file,
        startLine: pkg.line,
        evidence: `${pkg.name}@${pkg.version}`,
        message: truncate(detail?.details ?? summary, 500),
        remediation: fixedVersion
          ? `Upgrade ${pkg.name} to ${fixedVersion} or later; rerun the dependency audit and regression tests.`
          : `Upgrade ${pkg.name} to the latest stable or vendor-recommended version; confirm the impact before choosing mitigations.`,
        references,
        package: pkg.name,
        ecosystem: pkg.ecosystem,
        installedVersion: pkg.version,
        fixedVersion,
        advisoryId: vulnId,
        aliases: [...new Set([vulnId, ...aliases])],
        dependencyPath: pkg.direct
          ? `${pkg.manager} direct dependency`
          : `${pkg.manager} transitive dependency (from lockfile)`,
        reachable: "unknown",
        provenance: { engine: "osv", rule: vulnId },
      }),
    );
  }

  return {
    findings,
    warnings,
    packages: uniquePackages,
    queriedPackages: uniquePackages.length,
    vulnIds,
    unresolvedManifests,
    degraded,
  };
}
