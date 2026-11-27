import path from "node:path";
import type {
  DependencyScope,
  ManifestDependencies,
  ParsedDependencies,
  ScaPackage,
} from "./sca.js";
import { lineLookup, parseXml, type XmlElement } from "./xmlScan.js";

/*
 * NuGet dependencies declared in MSBuild files and packages.config.
 *
 * What is read, per project file (`*.csproj`, `*.fsproj`, `*.vbproj`):
 * - `PackageReference` items (Include / Update / Remove; `Version`,
 *   `VersionOverride`, `PrivateAssets`, `IncludeAssets` as attributes or
 *   child elements) from the project and from the nearest
 *   `Directory.Build.props` / `Directory.Build.targets` above it;
 * - Central Package Management: `PackageVersion` items and
 *   `GlobalPackageReference` items of the nearest `Directory.Packages.props`;
 * - `$(Property)` references, resolved from literal `PropertyGroup`
 *   definitions of those files (bounded; anything else stays unresolved).
 *
 * MSBuild conditions are not evaluated: every item and property is taken as
 * present. Only exact versions are queried; ranges, floating versions and
 * unresolved properties are counted in one warning per file.
 */

/** Read a file relative to the audit root through the path jail. */
export type JailedRead = (rel: string) => { rel: string; content: string } | { error: string };

export const NUGET_PROJECT_FILE = /\.(?:cs|fs|vb)proj$/i;
export const NUGET_IMPORTED_FILES = new Set([
  "directory.build.props",
  "directory.build.targets",
  "directory.packages.props",
]);

/** True for `packages.lock.json` and `packages.<project>.lock.json`. */
export function isNuGetLockfileName(base: string): boolean {
  return base === "packages.lock.json" || /^packages\.[^/\\]+\.lock\.json$/.test(base);
}

/** True for `packages.config` and `packages.<project>.config`. */
export function isPackagesConfigName(base: string): boolean {
  return /^packages(?:\.[^/\\]+)?\.config$/i.test(base);
}

export function isNuGetImportedFile(base: string): boolean {
  return NUGET_IMPORTED_FILES.has(base.toLowerCase());
}

// ---------------------------------------------------------------------------
// Versions

const NUGET_VERSION =
  /^(\d{1,9})(?:\.(\d{1,9}))?(?:\.(\d{1,9}))?(?:\.(\d{1,9}))?(-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z.-]+)?$/;

/**
 * The exact version a NuGet version string pins, normalized the way NuGet
 * normalizes it (three parts at least, a zero fourth part dropped, build
 * metadata dropped), or undefined for ranges, floating versions and anything
 * unparseable. A plain `1.2.3` is a minimum in NuGet, but restore picks
 * exactly that version when it exists, so it is queried as 1.2.3; the
 * equivalent `[1.2.3, )` and the exact `[1.2.3]` are treated the same way.
 */
export function exactNuGetVersion(raw: string): string | undefined {
  let value = raw.trim();
  if (value.length === 0 || value.length > 128) return undefined;
  const bracket = /^\[\s*([^,\]\s]+)\s*(?:\]|,\s*\))$/.exec(value);
  if (bracket?.[1]) value = bracket[1];
  const match = NUGET_VERSION.exec(value);
  if (!match) return undefined;
  const parts = [match[1], match[2] ?? "0", match[3] ?? "0"].map((part) =>
    String(Number.parseInt(part as string, 10)),
  );
  const fourth = match[4];
  if (fourth !== undefined && Number.parseInt(fourth, 10) !== 0) {
    parts.push(String(Number.parseInt(fourth, 10)));
  }
  return `${parts.join(".")}${match[5] ?? ""}`;
}

// ---------------------------------------------------------------------------
// MSBuild files

interface ItemDecl {
  kind: "packagereference" | "packageversion" | "globalpackagereference";
  op: "include" | "update" | "remove";
  spec: string;
  /** Lower-cased metadata name -> raw value; child elements override attributes. */
  metadata: Map<string, string>;
  conditional: boolean;
  file: string;
  line: number;
}

interface MsbuildFile {
  rel: string;
  properties: Array<{ name: string; value: string }>;
  items: ItemDecl[];
  /** True when the file imports the same-named file of a parent directory. */
  importsAbove: boolean;
  /** `Project` values of other `<Import>` elements (SDK imports excluded). */
  imports: string[];
  error?: string;
}

const MAX_IMPORTS_PER_FILE = 64;

const ITEM_KINDS = new Set(["packagereference", "packageversion", "globalpackagereference"]);
const METADATA = new Set([
  "version",
  "versionoverride",
  "privateassets",
  "includeassets",
  "excludeassets",
]);

/** Scan one MSBuild file for properties, package items and parent imports. */
export function readMsbuildFile(content: string, rel: string): MsbuildFile {
  const parsed = parseXml(content);
  const lineOf = lineLookup(content);
  const file: MsbuildFile = { rel, properties: [], items: [], importsAbove: false, imports: [] };
  if (parsed.error) file.error = parsed.error;
  const base = path.posix.basename(rel).toLowerCase();

  // Iterative walk in document order; ProjectExtensions holds arbitrary XML.
  const queue: Array<{ element: XmlElement; parent: string }> = [];
  for (let k = parsed.root.children.length - 1; k >= 0; k -= 1) {
    queue.push({ element: parsed.root.children[k] as XmlElement, parent: "#document" });
  }
  while (queue.length > 0) {
    const { element, parent } = queue.pop() as { element: XmlElement; parent: string };
    const name = element.name.toLowerCase();
    if (name === "projectextensions") continue;
    if (parent === "propertygroup") {
      file.properties.push({ name: name, value: element.text.trim() });
      continue;
    }
    if (name === "import") {
      const project = element.attrs.get("project") ?? "";
      if (/GetPathOfFileAbove/i.test(project)) {
        if (project.toLowerCase().includes(base)) file.importsAbove = true;
      } else if (!element.attrs.has("sdk") && project && file.imports.length < MAX_IMPORTS_PER_FILE) {
        file.imports.push(project.trim());
      }
      continue;
    }
    if (ITEM_KINDS.has(name) && parent === "itemgroup") {
      const include = element.attrs.get("include");
      const update = element.attrs.get("update");
      const remove = element.attrs.get("remove");
      const op = include !== undefined ? "include" : update !== undefined ? "update" : remove !== undefined ? "remove" : undefined;
      if (!op) continue;
      const metadata = new Map<string, string>();
      for (const [key, value] of element.attrs) if (METADATA.has(key)) metadata.set(key, value);
      for (const child of element.children) {
        const key = child.name.toLowerCase();
        if (METADATA.has(key)) metadata.set(key, child.text.trim());
      }
      file.items.push({
        kind: name as ItemDecl["kind"],
        op,
        spec: (include ?? update ?? remove ?? "").trim(),
        metadata,
        conditional: element.attrs.has("condition"),
        file: rel,
        line: lineOf(element.offset),
      });
      continue;
    }
    for (let k = element.children.length - 1; k >= 0; k -= 1) {
      queue.push({ element: element.children[k] as XmlElement, parent: name });
    }
  }
  return file;
}

// ---------------------------------------------------------------------------
// Property expansion

const MAX_EXPANSION_DEPTH = 8;
const MAX_EXPANDED_LENGTH = 1024;
const MAX_EXPANSION_STEPS = 256;

/**
 * Expand `$(Name)` references from `properties`. Returns undefined when a
 * reference cannot be resolved (unknown property, property function, item
 * transform), when expansion nests too deep (a cycle) or grows too long.
 */
export function expandProperties(
  value: string,
  properties: ReadonlyMap<string, string>,
): string | undefined {
  let steps = 0;
  const expand = (text: string, depth: number): string | undefined => {
    if (!text.includes("$(") && !text.includes("@(") && !text.includes("%(")) return text;
    if (text.includes("@(") || text.includes("%(")) return undefined;
    if (depth > MAX_EXPANSION_DEPTH) return undefined;
    let out = "";
    let i = 0;
    for (;;) {
      const start = text.indexOf("$(", i);
      if (start < 0) {
        out += text.slice(i);
        break;
      }
      out += text.slice(i, start);
      const end = text.indexOf(")", start + 2);
      if (end < 0) return undefined;
      const name = text.slice(start + 2, end).trim();
      if (!/^[A-Za-z_][A-Za-z0-9_.-]*$/.test(name)) return undefined;
      steps += 1;
      if (steps > MAX_EXPANSION_STEPS) return undefined;
      const raw = properties.get(name.toLowerCase());
      if (raw === undefined) return undefined;
      const inner = expand(raw, depth + 1);
      if (inner === undefined) return undefined;
      out += inner;
      if (out.length > MAX_EXPANDED_LENGTH) return undefined;
      i = end + 1;
    }
    return out.length > MAX_EXPANDED_LENGTH ? undefined : out;
  };
  return expand(value, 0);
}

// ---------------------------------------------------------------------------
// Project evaluation

/** Parsed `Directory.*` files by path; shared across the projects of a scan. */
export type NuGetCache = Map<string, MsbuildFile | { error: string } | null>;

export interface NuGetContext {
  read?: JailedRead;
  cache?: NuGetCache;
}

const MAX_IMPORT_CHAIN = 16;
/** Package references kept per project; a real project has a few hundred. */
const MAX_REFERENCES_PER_PROJECT = 50_000;
/** Item updates applied per project (Update items x matching items). */
const MAX_UPDATE_STEPS = 1_000_000;
/** Conditional central versions kept per package. */
const MAX_CENTRAL_CANDIDATES = 64;

function dirOf(rel: string): string {
  return path.posix.dirname(rel.split(path.sep).join("/"));
}

function loadFile(rel: string, context: NuGetContext): MsbuildFile | { error: string } | null {
  const cache = context.cache;
  if (cache?.has(rel)) return cache.get(rel) ?? null;
  let result: MsbuildFile | { error: string } | null = null;
  const read = context.read?.(rel);
  if (read) {
    if ("error" in read) {
      result = read.error === "ENOENT" || read.error === "ENOTDIR" ? null : { error: read.error };
    } else {
      result = readMsbuildFile(read.content, read.rel);
    }
  }
  cache?.set(rel, result);
  return result;
}

/**
 * The nearest `name` in `dir` or an ancestor inside the root, followed by the
 * further ancestors it imports with GetPathOfFileAbove. Outermost first.
 */
function importChain(
  dir: string,
  name: string,
  context: NuGetContext,
  warnings: string[],
): MsbuildFile[] {
  const chain: MsbuildFile[] = [];
  let current = dir;
  let wantMore = true;
  for (let guard = 0; guard < 64 && wantMore; guard += 1) {
    const rel = current === "." ? name : `${current}/${name}`;
    const loaded = loadFile(rel, context);
    if (loaded && "error" in loaded) {
      warnings.push(`${rel}: not read (${loaded.error}); versions and properties it declares are unknown`);
      break;
    }
    if (loaded) {
      if (loaded.error) warnings.push(`${rel}: malformed XML (${loaded.error}); read up to the error`);
      chain.unshift(loaded);
      wantMore = loaded.importsAbove && chain.length < MAX_IMPORT_CHAIN;
    }
    if (current === "." || current === "" || current === "/") break;
    current = dirOf(current);
  }
  return chain;
}

const MAX_IMPORTED_FILES = 64;
const MAX_IMPORT_DEPTH = 8;

/**
 * The audit-root-relative path an `<Import Project="...">` names, or
 * undefined when it cannot be resolved statically (other properties, globs,
 * absolute paths, anything outside the root).
 */
export function importTargetPath(raw: string, fileRel: string, projectRel: string): string | undefined {
  const fileDir = dirOf(fileRel);
  const projectDir = dirOf(projectRel);
  let rootRelative = false;
  let value = raw.trim().replace(/\$\((MSBuildThisFileDirectory|MSBuildProjectDirectory)\)/gi, (_match, name: string) => {
    rootRelative = true;
    if (name.toLowerCase() === "msbuildthisfiledirectory") return fileDir === "." ? "" : `${fileDir}/`;
    return projectDir;
  });
  if (/[$@%]\(|[*?]/.test(value) || value.includes("\u0000") || value.length > 1024) return undefined;
  value = value.split("\\").join("/");
  if (value.startsWith("/") || /^[A-Za-z]:/.test(value)) return undefined;
  const joined = path.posix.normalize(rootRelative ? value : path.posix.join(fileDir, value));
  if (joined === ".." || joined.startsWith("../") || path.posix.isAbsolute(joined)) return undefined;
  return joined;
}

function expandImports(
  files: MsbuildFile[],
  projectRel: string,
  context: NuGetContext,
  warnings: string[],
  visited: Set<string>,
  budget: { left: number },
): MsbuildFile[] {
  const out: MsbuildFile[] = [];
  const visit = (file: MsbuildFile, depth: number): void => {
    if (depth < MAX_IMPORT_DEPTH) {
      for (const raw of file.imports) {
        const target = importTargetPath(raw, file.rel, projectRel);
        if (!target || visited.has(target)) continue;
        if (budget.left <= 0) break;
        budget.left -= 1;
        visited.add(target);
        const loaded = loadFile(target, context);
        if (!loaded) continue;
        if ("error" in loaded) {
          warnings.push(`${target}: imported by ${file.rel} but not read (${loaded.error})`);
          continue;
        }
        if (loaded.error) warnings.push(`${target}: malformed XML (${loaded.error}); read up to the error`);
        visit(loaded, depth + 1);
      }
    }
    out.push(file);
  };
  for (const file of files) {
    visited.add(file.rel);
    visit(file, 0);
  }
  return out;
}

interface CentralIndex {
  /** Package key -> PackageVersion items naming it literally, in file order. */
  literal: Map<string, ItemDecl[]>;
  /** PackageVersion items whose Include uses MSBuild expressions (capped). */
  dynamic: ItemDecl[];
}

const MAX_DYNAMIC_CENTRAL = 1000;
const centralIndexCache = new WeakMap<MsbuildFile, CentralIndex>();

function centralIndex(file: MsbuildFile): CentralIndex {
  const cached = centralIndexCache.get(file);
  if (cached) return cached;
  const index: CentralIndex = { literal: new Map(), dynamic: [] };
  for (const decl of file.items) {
    if (decl.kind !== "packageversion") continue;
    if (/[$@%]\(/.test(decl.spec)) {
      if (index.dynamic.length < MAX_DYNAMIC_CENTRAL) index.dynamic.push(decl);
      continue;
    }
    for (const name of splitSpec(decl.spec)) {
      const key = nugetKey(name);
      const list = index.literal.get(key);
      if (list) list.push(decl);
      else index.literal.set(key, [decl]);
    }
  }
  centralIndexCache.set(file, index);
  return index;
}

interface PackageItem {
  name: string;
  metadata: Map<string, string>;
  file: string;
  line: number;
  /** Where the version metadata was last set (an Update item may set it). */
  versionFile: string;
  versionLine: number;
  global: boolean;
  removed: boolean;
}

function splitSpec(spec: string): string[] {
  return spec
    .split(";")
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
}

function assetList(value: string | undefined, properties: ReadonlyMap<string, string>): string[] | undefined {
  if (value === undefined) return undefined;
  const expanded = expandProperties(value, properties);
  if (expanded === undefined) return undefined;
  return expanded
    .split(";")
    .map((part) => part.trim().toLowerCase())
    .filter((part) => part.length > 0);
}

/**
 * Dev scope for build-only references: `PrivateAssets="all"` (analyzers,
 * source generators, SourceLink), or `IncludeAssets` / `ExcludeAssets` that
 * leave neither the compile nor the runtime assets.
 */
function referenceScope(item: PackageItem, properties: ReadonlyMap<string, string>): DependencyScope {
  const privateAssets = assetList(item.metadata.get("privateassets"), properties);
  if (privateAssets?.includes("all")) return "dev";
  if (item.global && item.metadata.get("privateassets") === undefined) return "dev";
  const include = assetList(item.metadata.get("includeassets"), properties);
  if (include && !include.some((asset) => asset === "all" || asset === "compile" || asset === "runtime")) {
    return "dev";
  }
  const exclude = assetList(item.metadata.get("excludeassets"), properties);
  if (exclude && (exclude.includes("all") || (exclude.includes("compile") && exclude.includes("runtime")))) {
    return "dev";
  }
  return "runtime";
}

export interface NuGetProjectResult extends ParsedDependencies {
  /** Normalized names with their scope, for marking lockfile entries. */
  manifest: ManifestDependencies;
  /** Number of package references (resolved or not). */
  references: number;
}

function nugetKey(name: string): string {
  return name.toLowerCase();
}

export const NO_NUGET_LOCKFILE_WARNING =
  "packages.lock.json not found; direct dependencies only (unresolved transitive dependencies)";

/**
 * Evaluate the NuGet package references of one project file. `context.read`
 * reads the `Directory.*` files above it through the path jail; without it
 * only the project file itself is used.
 */
export function evaluateNuGetProject(
  content: string,
  rel: string,
  context: NuGetContext = {},
): NuGetProjectResult {
  const warnings: string[] = [];
  const project = readMsbuildFile(content, rel);
  if (project.error) warnings.push(`${rel}: malformed XML (${project.error}); read up to the error`);
  const dir = dirOf(rel);
  // Each file is preceded by the files it imports (resolved relative paths
  // only); a file is used once per project, as MSBuild skips repeated imports.
  const visited = new Set<string>([rel]);
  const budget = { left: MAX_IMPORTED_FILES };
  const withImports = (files: MsbuildFile[]): MsbuildFile[] =>
    context.read ? expandImports(files, rel, context, warnings, visited, budget) : files;
  const chain = (name: string): MsbuildFile[] =>
    context.read ? withImports(importChain(dir, name, context, warnings)) : [];
  const buildProps = chain("Directory.Build.props");
  const packagesProps = chain("Directory.Packages.props");
  const projectFiles = withImports([project]);
  const buildTargets = chain("Directory.Build.targets");

  // MSBuild evaluates all properties before any item, in import order:
  // Directory.Build.props, Directory.Packages.props, the project, then
  // Directory.Build.targets. Later definitions win; conditions are ignored.
  const properties = new Map<string, string>();
  for (const file of [...buildProps, ...packagesProps, ...projectFiles, ...buildTargets]) {
    for (const property of file.properties) properties.set(property.name, property.value);
  }
  const expand = (value: string): string | undefined => expandProperties(value, properties);

  // Package references, in evaluation order. `byKey` indexes the live items
  // so Update and Remove cost the number of matching items, not all items.
  const items: PackageItem[] = [];
  const byKey = new Map<string, PackageItem[]>();
  let dropped = 0;
  let updateSteps = 0;
  let updatesStopped = false;
  const unresolvedByFile = new Map<string, number>();
  const unresolved = (file: string): void => {
    unresolvedByFile.set(file, (unresolvedByFile.get(file) ?? 0) + 1);
  };
  const applyReference = (decl: ItemDecl, global: boolean): void => {
    const spec = expand(decl.spec);
    if (spec === undefined) {
      if (decl.op === "include") unresolved(decl.file);
      return;
    }
    for (const name of splitSpec(spec)) {
      const key = nugetKey(name);
      if (decl.op === "include") {
        if (items.length >= MAX_REFERENCES_PER_PROJECT) {
          dropped += 1;
          continue;
        }
        const item: PackageItem = {
          name,
          metadata: new Map(decl.metadata),
          file: decl.file,
          line: decl.line,
          versionFile: decl.file,
          versionLine: decl.line,
          global,
          removed: false,
        };
        items.push(item);
        const list = byKey.get(key);
        if (list) list.push(item);
        else byKey.set(key, [item]);
      } else if (decl.op === "update") {
        for (const item of byKey.get(key) ?? []) {
          updateSteps += 1;
          if (updateSteps > MAX_UPDATE_STEPS) {
            updatesStopped = true;
            return;
          }
          for (const [meta, value] of decl.metadata) item.metadata.set(meta, value);
          if (decl.metadata.has("version") || decl.metadata.has("versionoverride")) {
            item.versionFile = decl.file;
            item.versionLine = decl.line;
          }
        }
      } else {
        for (const item of byKey.get(key) ?? []) item.removed = true;
        byKey.delete(key);
      }
    }
  };
  for (const file of [...buildProps, ...projectFiles, ...buildTargets]) {
    for (const decl of file.items) if (decl.kind === "packagereference") applyReference(decl, false);
  }
  for (const file of packagesProps) {
    for (const decl of file.items) if (decl.kind === "globalpackagereference") applyReference(decl, true);
  }

  // Central versions: name -> candidate declarations. An unconditional
  // declaration replaces earlier ones; conditional ones are added, since the
  // condition is not evaluated and each may apply to some build.
  // Only the referenced packages are looked up, through a per-file index, so
  // a large Directory.Packages.props shared by many projects is cheap.
  const centralFiles = [...packagesProps, ...projectFiles, ...buildTargets].map((file) => {
    const index = centralIndex(file);
    const dynamic = new Map<string, ItemDecl[]>();
    for (const decl of index.dynamic) {
      const spec = expand(decl.spec);
      if (spec === undefined) continue;
      for (const name of splitSpec(spec)) {
        const key = nugetKey(name);
        const list = dynamic.get(key);
        if (list) list.push(decl);
        else dynamic.set(key, [decl]);
      }
    }
    return { index, dynamic };
  });
  const central = new Map<string, Array<{ version: string; file: string; line: number }>>();
  const centralFor = (key: string): Array<{ version: string; file: string; line: number }> => {
    const cached = central.get(key);
    if (cached) return cached;
    let entries: Array<{ version: string; file: string; line: number }> = [];
    for (const { index, dynamic } of centralFiles) {
      const decls = [...(index.literal.get(key) ?? []), ...(dynamic.get(key) ?? [])].sort(
        (a, b) => a.line - b.line,
      );
      for (const decl of decls) {
        if (decl.op === "remove") {
          entries = [];
          continue;
        }
        const version = decl.metadata.get("version");
        if (version === undefined) continue;
        const entry = { version, file: decl.file, line: decl.line };
        if (decl.op === "update") {
          if (entries.length > 0) entries = [entry];
        } else if (!decl.conditional) {
          entries = [entry];
        } else if (entries.length < MAX_CENTRAL_CANDIDATES) {
          entries.push(entry);
        }
      }
    }
    central.set(key, entries);
    return entries;
  };
  const cpmSetting = expand(properties.get("managepackageversionscentrally") ?? "")?.trim().toLowerCase();
  const cpmEnabled = cpmSetting === "true" || (packagesProps.length > 0 && cpmSetting !== "false");

  const packages: ScaPackage[] = [];
  const manifest: ManifestDependencies = {
    names: new Set(),
    scopes: new Map(),
    optionalGroups: new Set(),
  };
  for (const item of items) {
    if (item.removed) continue;
    if (packages.length >= MAX_REFERENCES_PER_PROJECT) {
      dropped += 1;
      continue;
    }
    const scope = referenceScope(item, properties);
    const key = nugetKey(item.name);
    manifest.names.add(key);
    const previous = manifest.scopes.get(key);
    manifest.scopes.set(key, previous === "runtime" || scope === "runtime" ? "runtime" : scope);

    const own = item.metadata.get("versionoverride") ?? item.metadata.get("version");
    const candidates =
      own !== undefined
        ? [{ version: own, file: item.versionFile, line: item.versionLine }]
        : cpmEnabled
          ? centralFor(key)
          : [];
    if (candidates.length === 0) {
      unresolved(item.file);
      continue;
    }
    for (const candidate of candidates) {
      const expanded = expand(candidate.version);
      const version = expanded === undefined ? undefined : exactNuGetVersion(expanded);
      if (version === undefined) {
        unresolved(candidate.file);
        continue;
      }
      const pkg: ScaPackage = {
        name: item.name,
        version,
        ecosystem: "NuGet",
        file: candidate.file,
        line: candidate.line,
        manager: "nuget",
        direct: true,
        scope,
      };
      if (scope === "dev") pkg.dev = true;
      if (candidate.file !== rel) pkg.via = rel;
      packages.push(pkg);
    }
  }

  for (const [file, count] of unresolvedByFile) {
    warnings.push(
      `${file}: ${count} NuGet package reference(s) not checked (version range, floating version, unresolved MSBuild property or no version)`,
    );
  }
  if (dropped > 0) {
    warnings.push(
      `${rel}: more than ${MAX_REFERENCES_PER_PROJECT} NuGet package references; ${dropped} further entries were not checked`,
    );
  }
  if (updatesStopped) {
    warnings.push(`${rel}: too many PackageReference Update items; the rest were not applied`);
  }
  const references = items.reduce((count, item) => count + (item.removed ? 0 : 1), 0);
  return { packages, warnings, manifest, references };
}

// ---------------------------------------------------------------------------
// packages.config

export function parsePackagesConfig(content: string, file: string): ParsedDependencies {
  const warnings: string[] = [];
  const parsed = parseXml(content);
  if (parsed.error) warnings.push(`${file}: malformed XML (${parsed.error}); read up to the error`);
  const lineOf = lineLookup(content);
  const packages: ScaPackage[] = [];
  let unchecked = 0;
  const queue: XmlElement[] = [...parsed.root.children];
  while (queue.length > 0) {
    const element = queue.pop() as XmlElement;
    const name = element.name.toLowerCase();
    if (name !== "package") {
      for (const child of element.children) queue.push(child);
      continue;
    }
    const id = element.attrs.get("id")?.trim();
    const raw = element.attrs.get("version");
    if (!id) continue;
    const version = raw === undefined ? undefined : exactNuGetVersion(raw);
    if (!version) {
      unchecked += 1;
      continue;
    }
    const dev = element.attrs.get("developmentdependency")?.trim().toLowerCase() === "true";
    const pkg: ScaPackage = {
      name: id,
      version,
      ecosystem: "NuGet",
      file,
      line: lineOf(element.offset),
      manager: "nuget",
      // packages.config lists every installed package, transitive ones included.
      direct: true,
      scope: dev ? "dev" : "runtime",
    };
    if (dev) pkg.dev = true;
    packages.push(pkg);
  }
  packages.sort((a, b) => a.line - b.line);
  if (unchecked > 0) {
    warnings.push(`${file}: ${unchecked} package(s) without an exact version were not checked`);
  }
  if (packages.length === 0 && unchecked === 0) {
    warnings.push(`${file}: no parseable NuGet packages found`);
  }
  return { packages, warnings };
}

// ---------------------------------------------------------------------------
// packages.lock.json

/**
 * Parse a NuGet `packages.lock.json`. Each target framework (and runtime)
 * section lists the full resolved graph: `Direct` entries are the project's
 * own references, `Transitive` and `CentralTransitive` entries are not,
 * `Project` entries are other projects and are skipped. The same package and
 * version under several frameworks is one package, direct when it is direct
 * anywhere. With the project's references (`manifest`), direct entries get
 * the scope the project declares them with.
 */
export function parseNuGetLock(
  content: string,
  file: string,
  manifest?: ManifestDependencies,
): ParsedDependencies {
  let document: unknown;
  try {
    document = JSON.parse(content.charCodeAt(0) === 0xfeff ? content.slice(1) : content);
  } catch (error) {
    return {
      packages: [],
      warnings: [
        `packages.lock.json parse failed (${file}): ${error instanceof Error ? error.message : String(error)}`,
      ],
    };
  }
  // Line of each framework-level entry (`"Name": {`), found in one pass;
  // nested dependency lists use `"Name": "version"` and do not match.
  const lineOf = lineLookup(content);
  const entryLines = new Map<string, number>();
  const entryPattern = /"([^"\\\n]{1,512})"[ \t]*:[ \t]*\{/g;
  let match: RegExpExecArray | null;
  while ((match = entryPattern.exec(content)) !== null) {
    const key = nugetKey(match[1] as string);
    if (!entryLines.has(key)) entryLines.set(key, lineOf(match.index));
  }

  const byKey = new Map<string, ScaPackage>();
  const dependencies = (document as { dependencies?: unknown } | null)?.dependencies;
  if (dependencies && typeof dependencies === "object" && !Array.isArray(dependencies)) {
    for (const framework of Object.values(dependencies as Record<string, unknown>)) {
      if (!framework || typeof framework !== "object" || Array.isArray(framework)) continue;
      for (const [name, value] of Object.entries(framework as Record<string, unknown>)) {
        if (!value || typeof value !== "object") continue;
        const entry = value as Record<string, unknown>;
        if (entry.type === "Project") continue;
        if (typeof entry.resolved !== "string" || !entry.resolved) continue;
        const direct =
          entry.type === "Direct"
            ? true
            : typeof entry.type === "string"
              ? false
              : manifest
                ? manifest.names.has(nugetKey(name))
                : true;
        const key = `${nugetKey(name)}\u0000${entry.resolved}`;
        const existing = byKey.get(key);
        if (existing) {
          if (direct && !existing.direct) existing.direct = true;
          continue;
        }
        byKey.set(key, {
          name,
          version: entry.resolved,
          ecosystem: "NuGet",
          file,
          line: entryLines.get(nugetKey(name)) ?? 1,
          manager: "nuget",
          direct,
        });
      }
    }
  }
  const packages = [...byKey.values()];
  if (manifest) {
    for (const pkg of packages) {
      if (!pkg.direct) continue;
      const scope = manifest.scopes.get(nugetKey(pkg.name));
      if (!scope) continue;
      pkg.scope = scope;
      if (scope === "dev") pkg.dev = true;
    }
  }
  const warnings: string[] = [];
  if (packages.length === 0) warnings.push(`${file}: no parseable NuGet dependencies found`);
  return { packages, warnings };
}

/**
 * The project file(s) a NuGet lockfile belongs to: `packages.lock.json` goes
 * with the project files in its directory, `packages.<name>.lock.json` with
 * `<name>.*proj`.
 */
export function lockfileProjects(lockfileRel: string, projectPaths: readonly string[]): string[] {
  const dir = dirOf(lockfileRel);
  const base = path.posix.basename(lockfileRel);
  const named = /^packages\.(.+)\.lock\.json$/.exec(base)?.[1];
  return projectPaths.filter((rel) => {
    if (dirOf(rel) !== dir || !NUGET_PROJECT_FILE.test(rel)) return false;
    if (!named) return true;
    return path.posix.basename(rel).replace(NUGET_PROJECT_FILE, "") === named;
  });
}

/** NuGet lockfile names that would cover the project file `rel`. */
export function projectLockfileNames(rel: string): string[] {
  const dir = dirOf(rel);
  const prefix = dir === "." ? "" : `${dir}/`;
  const stem = path.posix.basename(rel).replace(NUGET_PROJECT_FILE, "");
  return [`${prefix}packages.lock.json`, `${prefix}packages.${stem}.lock.json`];
}
