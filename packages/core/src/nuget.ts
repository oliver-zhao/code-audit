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
 * MSBuild conditions are not evaluated. Where one decides between values
 * (conditional properties, item groups, Update items, central versions),
 * every possible value is kept as a candidate and reported; a conditional
 * Remove removes nothing. Only exact versions are queried; ranges, floating
 * versions and unresolved properties are counted in one warning per file.
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

/** One metadata value of an item; conditional when its element has a Condition. */
interface MetaValue {
  value: string;
  conditional: boolean;
  /** Set on the last kept value when further conditional values were dropped. */
  overflow?: boolean;
}

interface ItemDecl {
  kind: "packagereference" | "packageversion" | "globalpackagereference";
  op: "include" | "update" | "remove";
  spec: string;
  /** Lower-cased metadata name -> values in document order (attribute first). */
  metadata: Map<string, MetaValue[]>;
  /** The item or an enclosing ItemGroup / When / Otherwise / Target has a condition. */
  conditional: boolean;
  file: string;
  line: number;
}

interface PropertyDecl {
  name: string;
  value: string;
  /** The property or an enclosing PropertyGroup / When / Otherwise / Target has a condition. */
  conditional: boolean;
  /** Condition attributes of the property and its enclosing elements. */
  conditions: string[];
  /** Inside When / Otherwise / Target, whose applicability is not known. */
  opaque: boolean;
}

interface MsbuildFile {
  rel: string;
  properties: PropertyDecl[];
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

/** `<Import>` of the same-named file in a parent directory (GetPathOfFileAbove). */
function importsSameFileAbove(project: string, base: string): boolean {
  if (!/GetPathOfFileAbove/i.test(project)) return false;
  const lower = project.toLowerCase();
  return (
    lower.includes(base) ||
    lower.includes("$(msbuildthisfile)") ||
    lower.includes("$(msbuildthisfilename)$(msbuildthisfileextension)")
  );
}

/** Scan one MSBuild file for properties, package items and imports. */
export function readMsbuildFile(content: string, rel: string): MsbuildFile {
  const parsed = parseXml(content);
  const lineOf = lineLookup(content);
  const file: MsbuildFile = { rel, properties: [], items: [], importsAbove: false, imports: [] };
  if (parsed.error) file.error = parsed.error;
  const base = path.posix.basename(rel).toLowerCase();

  // Iterative walk in document order; ProjectExtensions holds arbitrary XML.
  // `conditional` is inherited: an element inside a conditional ItemGroup,
  // PropertyGroup, When, Otherwise or Target only applies to some builds.
  interface Frame {
    element: XmlElement;
    parent: string;
    conditional: boolean;
    conditions: string[];
    opaque: boolean;
  }
  const queue: Frame[] = [];
  for (let k = parsed.root.children.length - 1; k >= 0; k -= 1) {
    queue.push({
      element: parsed.root.children[k] as XmlElement,
      parent: "#document",
      conditional: false,
      conditions: [],
      opaque: false,
    });
  }
  while (queue.length > 0) {
    const frame = queue.pop() as Frame;
    const { element, parent } = frame;
    const name = element.name.toLowerCase();
    if (name === "projectextensions") continue;
    const conditional =
      frame.conditional ||
      element.attrs.has("condition") ||
      name === "when" ||
      name === "otherwise" ||
      name === "target";
    const own = element.attrs.get("condition");
    const conditions = own !== undefined && frame.conditions.length < 8 ? [...frame.conditions, own] : frame.conditions;
    const opaque = frame.opaque || name === "when" || name === "otherwise" || name === "target";
    if (parent === "propertygroup") {
      file.properties.push({ name, value: element.text.trim(), conditional, conditions, opaque });
      continue;
    }
    if (name === "import") {
      const project = element.attrs.get("project") ?? "";
      if (/GetPathOfFileAbove/i.test(project)) {
        if (importsSameFileAbove(project, base)) file.importsAbove = true;
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
      const metadata = new Map<string, MetaValue[]>();
      const add = (key: string, value: string, valueConditional: boolean): void => {
        const list = metadata.get(key) ?? [];
        // An unconditional value replaces earlier ones; a conditional one is
        // another candidate.
        if (!valueConditional) list.length = 0;
        if (list.length < MAX_CANDIDATES) list.push({ value, conditional: valueConditional });
        else (list[list.length - 1] as MetaValue).overflow = true;
        metadata.set(key, list);
      };
      for (const [key, value] of element.attrs) if (METADATA.has(key)) add(key, value, false);
      for (const child of element.children) {
        const key = child.name.toLowerCase();
        if (METADATA.has(key)) add(key, child.text.trim(), child.attrs.has("condition"));
      }
      file.items.push({
        kind: name as ItemDecl["kind"],
        op,
        spec: (include ?? update ?? remove ?? "").trim(),
        metadata,
        conditional,
        file: rel,
        line: lineOf(element.offset),
      });
      continue;
    }
    for (let k = element.children.length - 1; k >= 0; k -= 1) {
      queue.push({ element: element.children[k] as XmlElement, parent: name, conditional, conditions, opaque });
    }
  }
  return file;
}

// ---------------------------------------------------------------------------
// Property evaluation

/** Possible values per property or expression; bounded. */
const MAX_CANDIDATES = 16;
const MAX_EXPANDED_LENGTH = 1024;
const MAX_REFERENCES_PER_VALUE = 64;

/**
 * Possible values of a property: every value a conditional definition may
 * have given it. `null` stands for a value that cannot be known statically.
 */
type Values = ReadonlyArray<string | null>;

/**
 * Characters one expansion may build, and one project's evaluation in total.
 * The first keeps a single hostile property from making everything after it
 * unknown; the second bounds the time of a file full of them.
 */
const MAX_EXPANSION_CHARS_PER_VALUE = 65_536;
const MAX_EXPANSION_CHARS = 32_000_000;

/**
 * Evaluated properties of one project, with the expansion budget they share:
 * once spent, every further expansion is unknown (and reported as such).
 */
class PropertyMap extends Map<string, Values> {
  budget = MAX_EXPANSION_CHARS;
}

function uniqueValues(values: Array<string | null>): Array<string | null> {
  const out: Array<string | null> = [];
  const seen = new Set<string | null>();
  for (const value of values) {
    if (seen.has(value)) continue;
    seen.add(value);
    out.push(value);
  }
  return out;
}

/**
 * Expand `$(Name)` references against already-evaluated properties. Every
 * combination of the referenced properties' possible values is a result
 * (bounded). An unknown property, a property function, an item reference
 * (`@(...)`, `%(...)`) or an over-long result yields `null`; when the
 * combinations exceed the bound, `null` is added so the caller reports
 * that something was not checked.
 */
export function expandValues(text: string, properties: ReadonlyMap<string, Values>): Array<string | null> {
  if (!text.includes("$(") && !text.includes("@(") && !text.includes("%(")) return [text];
  if (text.includes("@(") || text.includes("%(")) return [null];
  const budgeted = properties instanceof PropertyMap ? properties : undefined;
  if (budgeted && budgeted.budget <= 0) return [null];
  let results: Array<string | null> = [""];
  let truncated = false;
  let i = 0;
  let references = 0;
  let spent = 0;
  const append = (options: Values): void => {
    const next: Array<string | null> = [];
    for (const prefix of results) {
      for (const option of options) {
        if (prefix === null || option === null) next.push(null);
        else {
          const joined = prefix + option;
          spent += joined.length;
          if (budgeted) budgeted.budget -= joined.length;
          next.push(joined.length > MAX_EXPANDED_LENGTH ? null : joined);
        }
        if (next.length >= MAX_CANDIDATES * MAX_CANDIDATES) break;
      }
    }
    results = uniqueValues(next);
    if (results.length > MAX_CANDIDATES) {
      results = results.slice(0, MAX_CANDIDATES);
      truncated = true;
    }
  };
  for (;;) {
    const start = text.indexOf("$(", i);
    if (start < 0) {
      append([text.slice(i)]);
      break;
    }
    append([text.slice(i, start)]);
    const end = text.indexOf(")", start + 2);
    if (end < 0) return [null];
    references += 1;
    if (references > MAX_REFERENCES_PER_VALUE) return [null];
    const name = text.slice(start + 2, end).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_.-]*$/.test(name)) return [null];
    append(properties.get(name.toLowerCase()) ?? [null]);
    if (spent > MAX_EXPANSION_CHARS_PER_VALUE) return [null];
    if (budgeted && budgeted.budget <= 0) return [null];
    i = end + 1;
  }
  if (truncated && !results.includes(null)) results.push(null);
  return results;
}

/**
 * Evaluate property definitions in order, as MSBuild does: each value is
 * expanded when it is defined (so `<V>$(V).5</V>` extends the earlier V).
 * An unconditional definition replaces the property; a conditional one adds
 * its values to the possible ones, since the condition is not evaluated.
 */
const EMPTY_CHECK =
  /^\s*(?:(['"]?)\$\(\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*\)\1\s*(==|!=)\s*(['"])\4|(['"])\5\s*(==|!=)\s*(['"]?)\$\(\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*\)\7)\s*$/;

/**
 * The value of a condition that only compares a property with the empty
 * string (`'$(X)' == ''`, `'$(X)' != ''`, either order), when the possible
 * values of X decide it; undefined for any other condition.
 */
function parseEmptyCheck(condition: string): { name: string; equals: boolean } | undefined {
  if (condition.length > 256) return undefined;
  const match = EMPTY_CHECK.exec(condition);
  if (!match) return undefined;
  return { name: (match[2] ?? match[8] ?? "").toLowerCase(), equals: (match[3] ?? match[6]) === "==" };
}

export function staticEmptyCheck(condition: string, properties: ReadonlyMap<string, Values>): boolean | undefined {
  const check = parseEmptyCheck(condition);
  if (!check) return undefined;
  const operator = check.equals ? "==" : "!=";
  const values = properties.get(check.name) ?? [""];
  let empty: boolean;
  if (values.every((value) => value === "")) empty = true;
  else if (values.every((value) => value !== null && value.trim() !== "")) empty = false;
  else return undefined;
  return operator === "==" ? empty : !empty;
}

/**
 * Evaluate property definitions in order, as MSBuild does: each value is
 * expanded when it is defined (so `<V>$(V).5</V>` extends the earlier V).
 * An unconditional definition replaces the property; a conditional one adds
 * its values to the possible ones, since the condition is not evaluated,
 * except for empty checks the known values decide (`'$(V)' == ''` is false
 * once V has a value: the "default if empty" idiom).
 */
function evaluateProperties(files: readonly MsbuildFile[], start?: PropertyMap): PropertyMap {
  const properties = new PropertyMap(start ?? []);
  if (start) properties.budget = start.budget;
  for (const file of files) {
    for (const property of file.properties) {
      let conditional = property.conditional;
      if (conditional) {
        const results = property.conditions.map((condition) => staticEmptyCheck(condition, properties));
        if (results.includes(false)) continue;
        if (!property.opaque && results.every((result) => result === true)) conditional = false;
      }
      const values = expandValues(property.value, properties);
      const previous = properties.get(property.name);
      if (!conditional) {
        properties.set(property.name, values);
      } else if (previous === undefined) {
        // Defined in some builds only: elsewhere it stays empty.
        properties.set(property.name, uniqueValues(["", ...values]));
      } else {
        // `<V Condition="'$(V)' == ''">default</V>` replaces exactly the
        // builds where V is empty.
        const check = property.conditions.length === 1 && !property.opaque ? parseEmptyCheck(property.conditions[0] as string) : undefined;
        const kept =
          check && check.equals && check.name === property.name ? previous.filter((value) => value !== "") : previous;
        let merged = uniqueValues([...kept, ...values]);
        if (merged.length > MAX_CANDIDATES) {
          merged = merged.slice(0, MAX_CANDIDATES);
          if (!merged.includes(null)) merged.push(null);
        }
        properties.set(property.name, merged);
      }
    }
  }
  return properties;
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
/** Evaluated Directory.*.props properties per scan cache, by file list. */
const prefixCaches = new WeakMap<NuGetCache, Map<string, PropertyMap>>();
/** Package references kept per project; a real project has a few hundred. */
const MAX_REFERENCES_PER_PROJECT = 50_000;
/** Item updates applied per project (Update items x matching items). */
const MAX_UPDATE_STEPS = 1_000_000;

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

/** A value an item metadata or a central version may have, and where it was set. */
interface Candidate {
  value: string;
  file: string;
  line: number;
}

/**
 * Possible values of one item metadata (or central version). `definite` is
 * true when an unconditional declaration set it, so it has a value in every
 * build; otherwise builds where no candidate applies also exist.
 */
interface CandidateList {
  entries: readonly Candidate[];
  definite: boolean;
  /** File of a candidate dropped at the bound; reported as not checked. */
  overflow?: string;
}

/** Apply a set of the value: unconditional replaces, conditional adds. */
function setCandidate(
  list: CandidateList | undefined,
  entry: Candidate,
  conditional: boolean,
  overflow = false,
): CandidateList {
  if (!conditional) return { entries: [entry], definite: true, ...(overflow ? { overflow: entry.file } : {}) };
  const entries = list ? [...list.entries] : [];
  let dropped = list?.overflow ?? (overflow ? entry.file : undefined);
  if (entries.length < MAX_CANDIDATES) entries.push(entry);
  else dropped ??= entry.file;
  return { entries, definite: list?.definite ?? false, ...(dropped ? { overflow: dropped } : {}) };
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
  file: string;
  line: number;
  /** Lower-cased metadata name -> possible values. */
  metadata: Map<string, CandidateList>;
  removed: boolean;
}

function splitSpec(spec: string): string[] {
  return spec
    .split(";")
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
}

/** Names an Include / Update / Remove may stand for; null entries are unknown. */
function specNames(spec: string, properties: PropertyMap): { names: string[]; unknown: boolean } {
  const names: string[] = [];
  let unknown = false;
  for (const value of expandValues(spec, properties)) {
    if (value === null) unknown = true;
    else for (const name of splitSpec(value)) names.push(name);
  }
  return { names: [...new Set(names)], unknown };
}

/** Apply one item's metadata values to a candidate map. */
function applyMetadata(
  target: Map<string, CandidateList>,
  decl: ItemDecl,
  forceConditional: boolean,
): void {
  for (const [key, values] of decl.metadata) {
    let list = target.get(key);
    for (const value of values) {
      list = setCandidate(
        list,
        { value: value.value, file: decl.file, line: decl.line },
        forceConditional || value.conditional,
        value.overflow === true,
      );
    }
    if (list) target.set(key, list);
  }
}

function assetSets(list: CandidateList | undefined, properties: PropertyMap): string[][] | undefined {
  if (!list) return undefined;
  const sets: string[][] = [];
  for (const entry of list.entries) {
    for (const value of expandValues(entry.value, properties)) {
      if (value === null) return undefined; // unknown: may include everything
      sets.push(
        value
          .split(";")
          .map((part) => part.trim().toLowerCase())
          .filter((part) => part.length > 0),
      );
    }
  }
  return sets;
}

/**
 * Dev scope only for references that bring neither compile nor runtime
 * assets in any build: every possible `IncludeAssets` lacks `compile`,
 * `runtime` and `all`, or every possible `ExcludeAssets` removes both.
 * `PrivateAssets` alone does not make a package dev: it only keeps the
 * package from flowing to consumers, the project itself still ships it.
 */
function referenceScope(item: PackageItem, properties: PropertyMap): DependencyScope {
  const includeList = item.metadata.get("includeassets");
  if (includeList?.definite) {
    const sets = assetSets(includeList, properties);
    if (sets && sets.length > 0 && sets.every((set) => !set.some((a) => a === "all" || a === "compile" || a === "runtime"))) {
      return "dev";
    }
  }
  const excludeList = item.metadata.get("excludeassets");
  if (excludeList?.definite) {
    const sets = assetSets(excludeList, properties);
    if (
      sets &&
      sets.length > 0 &&
      sets.every((set) => set.includes("all") || (set.includes("compile") && set.includes("runtime")))
    ) {
      return "dev";
    }
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
 * reads the `Directory.*` files above it (and plain imports) through the path
 * jail; without it only the project file itself is used.
 *
 * Conditions are not evaluated. Where a condition decides between values
 * (conditional properties, item groups, Update items, central versions),
 * every possible value is a candidate and reported; a conditional Remove
 * removes nothing. When unsure, more is reported, never less.
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

  // MSBuild evaluates all properties (in import order: Directory.Build.props,
  // Directory.Packages.props, the project, Directory.Build.targets) before
  // any item.
  // The Directory.*.props part is the same for every project that shares
  // those files, so it is evaluated once per scan.
  const prefixFiles = [...buildProps, ...packagesProps];
  let prefix: PropertyMap | undefined;
  const prefixCache = context.cache ? prefixCaches.get(context.cache) ?? new Map<string, PropertyMap>() : undefined;
  if (context.cache && prefixCache) prefixCaches.set(context.cache, prefixCache);
  const prefixKey = prefixFiles.map((file) => file.rel).join("\u0000");
  prefix = prefixCache?.get(prefixKey);
  if (!prefix) {
    prefix = evaluateProperties(prefixFiles);
    prefixCache?.set(prefixKey, prefix);
  }
  const properties = evaluateProperties([...projectFiles, ...buildTargets], prefix);

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
  const applyReference = (decl: ItemDecl): void => {
    const { names, unknown } = specNames(decl.spec, properties);
    if (unknown && decl.op === "include") unresolved(decl.file);
    for (const name of names) {
      const key = nugetKey(name);
      if (decl.op === "include") {
        if (items.length >= MAX_REFERENCES_PER_PROJECT) {
          dropped += 1;
          continue;
        }
        const item: PackageItem = { name, file: decl.file, line: decl.line, metadata: new Map(), removed: false };
        applyMetadata(item.metadata, decl, false);
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
          // A conditional Update adds candidates instead of replacing.
          applyMetadata(item.metadata, decl, decl.conditional);
        }
      } else if (!decl.conditional) {
        // A conditional Remove may not apply: the item stays.
        for (const item of byKey.get(key) ?? []) item.removed = true;
        byKey.delete(key);
      }
    }
  };
  for (const file of [...buildProps, ...projectFiles, ...buildTargets]) {
    for (const decl of file.items) if (decl.kind === "packagereference") applyReference(decl);
  }
  for (const file of packagesProps) {
    for (const decl of file.items) if (decl.kind === "globalpackagereference") applyReference(decl);
  }

  // Central versions of the referenced packages, through a per-file index so
  // a large Directory.Packages.props shared by many projects is cheap.
  const centralFiles = [...packagesProps, ...projectFiles, ...buildTargets].map((file) => {
    const index = centralIndex(file);
    const dynamic = new Map<string, ItemDecl[]>();
    for (const decl of index.dynamic) {
      for (const name of specNames(decl.spec, properties).names) {
        const key = nugetKey(name);
        const list = dynamic.get(key);
        if (list) list.push(decl);
        else dynamic.set(key, [decl]);
      }
    }
    return { index, dynamic };
  });
  const central = new Map<string, CandidateList | undefined>();
  const centralFor = (key: string): CandidateList | undefined => {
    if (central.has(key)) return central.get(key);
    let list: CandidateList | undefined;
    for (const { index, dynamic } of centralFiles) {
      const decls = [...(index.literal.get(key) ?? []), ...(dynamic.get(key) ?? [])].sort(
        (a, b) => a.line - b.line,
      );
      for (const decl of decls) {
        if (decl.op === "remove") {
          if (!decl.conditional) list = undefined;
          continue;
        }
        if (decl.op === "update" && !list) continue;
        const versions = new Map<string, CandidateList>(list ? [["version", list]] : []);
        const only = new Map([["version", decl.metadata.get("version") ?? []]]);
        applyMetadata(versions, { ...decl, metadata: only }, decl.conditional);
        list = versions.get("version") ?? list;
      }
    }
    central.set(key, list);
    return list;
  };
  const cpmValues = properties.get("managepackageversionscentrally") ?? [];
  const cpmEnabled =
    cpmValues.some((value) => value?.trim().toLowerCase() === "true") ||
    (packagesProps.length > 0 && !(cpmValues.length > 0 && cpmValues.every((value) => value?.trim().toLowerCase() === "false")));

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

    // VersionOverride only counts with Central Package Management; where it
    // may not apply, the regular version is a candidate too.
    const candidates: Candidate[] = [];
    let definite = false;
    const override = cpmEnabled ? item.metadata.get("versionoverride") : undefined;
    if (override) {
      candidates.push(...override.entries);
      definite = override.definite;
      if (override.overflow) unresolved(override.overflow);
    }
    if (!definite) {
      const own = item.metadata.get("version");
      const fallback = own ?? (cpmEnabled ? centralFor(key) : undefined);
      if (fallback) candidates.push(...fallback.entries);
      if (fallback?.overflow) unresolved(fallback.overflow);
    }
    if (candidates.length === 0) {
      unresolved(item.file);
      continue;
    }
    for (const candidate of candidates) {
      const expansions = expandValues(candidate.value, properties);
      // A property defined only in some builds is empty in the others; an
      // empty version is no version to check, so it is not counted when the
      // property has a value elsewhere.
      const hasValue = expansions.some((value) => value !== null && value.trim() !== "");
      for (const expanded of expansions) {
        if (hasValue && expanded !== null && expanded.trim() === "") continue;
        const version = expanded === null ? undefined : exactNuGetVersion(expanded);
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
  if (properties.budget <= 0) {
    warnings.push(`${rel}: MSBuild property expansion stopped at its size limit; later values were treated as unknown`);
  }
  if (updatesStopped) {
    warnings.push(`${rel}: too many PackageReference Update items; the rest were not applied`);
  }
  const references = items.reduce((count, item) => count + (item.removed ? 0 : 1), 0);
  return { packages: dedupeOccurrences(packages), warnings, manifest, references };
}

/** One entry per (file, line, name, version) within a project. */
function dedupeOccurrences(packages: ScaPackage[]): ScaPackage[] {
  const seen = new Set<string>();
  return packages.filter((pkg) => {
    const key = `${pkg.file}\u0000${pkg.line}\u0000${nugetKey(pkg.name)}\u0000${pkg.version}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
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

function projectStem(rel: string): string {
  return path.posix.basename(rel).replace(NUGET_PROJECT_FILE, "");
}

/**
 * The project a NuGet lockfile belongs to: `packages.<Name>.lock.json` to
 * `<Name>.*proj` in its directory, `packages.lock.json` to the project file
 * in its directory when it is the only one there (with several, NuGet would
 * need per-project names, so the shared file is not attributed to any).
 */
export function lockfileOwner(lockfileRel: string, projectPaths: readonly string[]): string | undefined {
  const dir = dirOf(lockfileRel);
  const named = /^packages\.(.+)\.lock\.json$/.exec(path.posix.basename(lockfileRel))?.[1];
  const inDir = projectPaths.filter((rel) => dirOf(rel) === dir && NUGET_PROJECT_FILE.test(rel));
  if (named) return inDir.find((rel) => projectStem(rel).toLowerCase() === named.toLowerCase());
  return inDir.length === 1 ? inDir[0] : undefined;
}

/** Lockfile paths that would belong to the project `rel` (see `lockfileOwner`). */
export function projectLockfileCandidates(rel: string, projectPaths: readonly string[]): string[] {
  const dir = dirOf(rel);
  const prefix = dir === "." ? "" : `${dir}/`;
  const candidates = [`${prefix}packages.${projectStem(rel)}.lock.json`];
  const inDir = projectPaths.filter((other) => dirOf(other) === dir && NUGET_PROJECT_FILE.test(other));
  if (inDir.length <= 1) candidates.push(`${prefix}packages.lock.json`);
  return candidates;
}
