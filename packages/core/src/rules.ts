import fs from "node:fs";
import path from "node:path";
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import type { InventoryFile } from "./inventory.js";
import type { Confidence, Severity } from "./finding.js";
import { CONFIDENCE_ORDER } from "./finding.js";

export const RULE_LANGUAGES = [
  "csharp",
  "java",
  "javascript",
  "typescript",
  "python",
  "go",
  "c",
  "cpp",
  "dockerfile",
  "yaml",
  "json",
  "markdown",
] as const;

const RuleLanguageSchema = z.enum(RULE_LANGUAGES);

const RuleSchema = z
  .object({
    id: z.string().regex(/^[a-z0-9][a-z0-9-]*$/, "rule id must be lowercase letters, digits, or dashes"),
    title: z.string().min(1),
    title_zh: z.string().min(1).optional(),
    severity: z.enum(["critical", "high", "medium", "low", "info"]),
    confidence: z.enum(["high", "medium", "low"]),
    kind: z.enum(["finding", "hotspot"]).default("finding"),
    cwe: z.string().regex(/^CWE-\d+$/, "cwe must look like CWE-89"),
    owasp: z.string().optional(),
    languages: z.array(RuleLanguageSchema).min(1),
    pattern: z.string().min(1).optional(),
    patterns: z.array(z.string().min(1)).min(1).optional(),
    notPattern: z.string().min(1).optional(),
    pathInclude: z.string().min(1).optional(),
    pathExclude: z.string().min(1).optional(),
    filePattern: z.string().min(1).optional(),
    fileAbsentPattern: z.string().min(1).optional(),
    flags: z.string().regex(/^[imsuy]*$/).optional(),
    group: z.string().regex(/^[a-z0-9][a-z0-9-]*$/).optional(),
    message: z.string().min(1),
    message_zh: z.string().min(1).optional(),
    remediation: z.string().min(1),
    remediation_zh: z.string().min(1).optional(),
    references: z.array(z.string()).optional(),
  })
  .superRefine((rule, ctx) => {
    if (!rule.pattern && !rule.patterns) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "either pattern or patterns is required",
        path: ["pattern"],
      });
    }
    if (rule.pattern && rule.patterns) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "pattern and patterns are mutually exclusive",
        path: ["patterns"],
      });
    }
  });

export type RuleDefinition = z.infer<typeof RuleSchema>;

export interface CompiledRule {
  pattern?: RegExp;
  patterns?: RegExp[];
  notPattern?: RegExp;
  pathInclude?: RegExp;
  pathExclude?: RegExp;
  filePattern?: RegExp;
  fileAbsentPattern?: RegExp;
}

export interface LoadedRule extends RuleDefinition {
  sourceFile: string;
  compiled: CompiledRule;
}

export class RuleLoadError extends Error {
  readonly file: string;

  constructor(file: string, message: string) {
    super(`rule loading failed (${file}): ${message}`);
    this.name = "RuleLoadError";
    this.file = file;
  }
}

function compile(
  source: string | undefined,
  file: string,
  field: string,
  flags = "i",
): RegExp | undefined {
  if (source === undefined) return undefined;
  try {
    return new RegExp(source, flags);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new RuleLoadError(file, `${field} is not a valid regular expression: ${message}`);
  }
}

function compileRule(definition: RuleDefinition, sourceFile: string): LoadedRule {
  return {
    ...definition,
    sourceFile,
    compiled: {
      pattern: compile(definition.pattern, sourceFile, "pattern", definition.flags ?? "i"),
      patterns: definition.patterns?.map((p, index) =>
        compile(p, sourceFile, `patterns[${index}]`, definition.flags ?? "i"),
      ) as RegExp[] | undefined,
      notPattern: compile(
        definition.notPattern,
        sourceFile,
        "notPattern",
        definition.flags ?? "i",
      ),
      pathInclude: compile(definition.pathInclude, sourceFile, "pathInclude", ""),
      pathExclude: compile(definition.pathExclude, sourceFile, "pathExclude", ""),
      filePattern: compile(definition.filePattern, sourceFile, "filePattern", "im"),
      fileAbsentPattern: compile(
        definition.fileAbsentPattern,
        sourceFile,
        "fileAbsentPattern",
        "im",
      ),
    },
  };
}

function listYamlFiles(dir: string): string[] {
  const result: string[] = [];
  const walk = (current: string): void => {
    const entries = fs.readdirSync(current, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const abs = path.join(current, entry.name);
      if (entry.isDirectory()) {
        // Opengrep/Semgrep-syntax rules live under rules/opengrep and use a
        // different schema; they are loaded by the external adapter instead.
        if (entry.name === "opengrep") continue;
        walk(abs);
      } else if (
        entry.isFile() &&
        (entry.name.endsWith(".yml") || entry.name.endsWith(".yaml"))
      ) {
        result.push(abs);
      }
    }
  };
  if (!fs.existsSync(dir)) {
    throw new RuleLoadError(dir, "rules directory does not exist");
  }
  walk(dir);
  return result.sort();
}

export interface RuleSet {
  rules: LoadedRule[];
  rulesDir: string;
  files: string[];
}

export function loadRules(rulesDir: string): RuleSet {
  const absoluteDir = path.resolve(rulesDir);
  const files = listYamlFiles(absoluteDir);
  const rules: LoadedRule[] = [];
  const byId = new Map<string, string>();

  for (const file of files) {
    const relative = path.relative(absoluteDir, file);
    let document: unknown;
    try {
      document = parseYaml(fs.readFileSync(file, "utf8"));
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new RuleLoadError(relative, `YAML parse failed: ${message}`);
    }

    const rawRules: unknown = Array.isArray(document)
      ? document
      : (document as { rules?: unknown } | null)?.rules;
    if (rawRules === undefined) {
      throw new RuleLoadError(relative, "missing top-level rules array");
    }
    if (!Array.isArray(rawRules)) {
      throw new RuleLoadError(relative, "rules must be an array");
    }

    for (const [index, rawRule] of rawRules.entries()) {
      const parsed = RuleSchema.safeParse(rawRule);
      if (!parsed.success) {
        const details = parsed.error.issues
          .map((issue) => `${issue.path.join(".") || "<root>"}: ${issue.message}`)
          .join("; ");
        throw new RuleLoadError(relative, `invalid rule at index ${index + 1}: ${details}`);
      }
      const rule = compileRule(parsed.data, relative);
      const previous = byId.get(rule.id);
      if (previous) {
        throw new RuleLoadError(
          relative,
          `duplicate rule id: ${rule.id} (already defined in ${previous})`,
        );
      }
      byId.set(rule.id, relative);
      rules.push(rule);
    }
  }

  return { rules, rulesDir: absoluteDir, files };
}

export function ruleMatchesFile(
  rule: LoadedRule,
  file: Pick<InventoryFile, "relPath" | "language">,
): boolean {
  if (!rule.languages.includes(file.language as never)) return false;
  if (rule.compiled.pathInclude && !rule.compiled.pathInclude.test(file.relPath)) {
    return false;
  }
  if (rule.compiled.pathExclude && rule.compiled.pathExclude.test(file.relPath)) {
    return false;
  }
  return true;
}

function parseSuppression(
  line: string,
): { ruleIds: string[]; reason: string } | undefined {
  const marker = "code-audit:ignore";
  const index = line.toLowerCase().indexOf(marker);
  if (index < 0) return undefined;
  const rest = line.slice(index + marker.length).trim();
  if (!rest) return undefined;
  const divider = rest.indexOf("--");
  const idPart = divider >= 0 ? rest.slice(0, divider) : rest;
  const reason = divider >= 0 ? rest.slice(divider + 2).trim() : "";
  const ruleIds = idPart
    .split(/[\s,]+/)
    .map((value) => value.trim())
    .filter((value) => /^[a-z0-9*][a-z0-9-]*$/.test(value));
  if (ruleIds.length === 0) return undefined;
  return { ruleIds, reason };
}

export function isSuppressed(
  currentLine: string,
  previousLine: string | undefined,
  ruleId: string,
): { suppressed: boolean; reason: string } {
  for (const line of [currentLine, previousLine ?? ""]) {
    const parsed = parseSuppression(line);
    if (!parsed) continue;
    if (parsed.ruleIds.includes("*") || parsed.ruleIds.includes(ruleId)) {
      return { suppressed: true, reason: parsed.reason };
    }
  }
  return { suppressed: false, reason: "" };
}

export interface RuleHit {
  rule: LoadedRule;
  file: InventoryFile;
  line: number;
  evidence: string;
}

export interface SuppressedHit {
  ruleId: string;
  file: string;
  line: number;
  reason: string;
}

export interface RuleScanResult {
  hits: RuleHit[];
  suppressed: SuppressedHit[];
  warnings: string[];
  scannedFiles: number;
}

export function scanRules(files: InventoryFile[], ruleSet: RuleSet): RuleScanResult {
  const hits: RuleHit[] = [];
  const suppressed: SuppressedHit[] = [];
  const warnings: string[] = [];
  let scannedFiles = 0;

  for (const file of files) {
    if (!file.scannable || file.language === "unknown") continue;

    const applicable = ruleSet.rules.filter((rule) => ruleMatchesFile(rule, file));
    if (applicable.length === 0) continue;

    let content: string;
    try {
      content = fs.readFileSync(file.absPath, "utf8");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      warnings.push(`cannot read ${file.relPath}: ${message}`);
      continue;
    }
    scannedFiles += 1;

    const fileRules = applicable.filter((rule) => {
      if (rule.compiled.filePattern && !rule.compiled.filePattern.test(content)) {
        return false;
      }
      if (
        rule.compiled.fileAbsentPattern &&
        rule.compiled.fileAbsentPattern.test(content)
      ) {
        return false;
      }
      return true;
    });
    if (fileRules.length === 0) continue;

    const lines = content.split(/\r?\n/);
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index] ?? "";
      if (line.trim().length === 0) continue;
      for (const rule of fileRules) {
        const notMatch =
          rule.compiled.notPattern !== undefined && rule.compiled.notPattern.test(line);
        if (notMatch) continue;

        let matched = false;
        if (rule.compiled.pattern) {
          matched = rule.compiled.pattern.test(line);
        } else if (rule.compiled.patterns) {
          matched = rule.compiled.patterns.every((pattern) => pattern.test(line));
        }
        if (!matched) continue;

        const suppression = isSuppressed(line, lines[index - 1], rule.id);
        if (suppression.suppressed) {
          suppressed.push({
            ruleId: rule.id,
            file: file.relPath,
            line: index + 1,
            reason: suppression.reason,
          });
          continue;
        }

        hits.push({
          rule,
          file,
          line: index + 1,
          evidence: line.trim(),
        });
      }
    }
  }

  const bestGroupHit = new Map<string, RuleHit>();
  for (const hit of hits) {
    if (!hit.rule.group) continue;
    const key = `${hit.file.relPath}\u0000${hit.line}\u0000${hit.rule.group}`;
    const current = bestGroupHit.get(key);
    if (!current) {
      bestGroupHit.set(key, hit);
      continue;
    }
    const hitScore =
      CONFIDENCE_ORDER[hit.rule.confidence] * 10 +
      severityRank(hit.rule.severity);
    const currentScore =
      CONFIDENCE_ORDER[current.rule.confidence] * 10 +
      severityRank(current.rule.severity);
    if (hitScore > currentScore) bestGroupHit.set(key, hit);
  }

  const winners = new Set(bestGroupHit.values());
  const dedupedHits = hits.filter(
    (hit) => !hit.rule.group || winners.has(hit),
  );

  return { hits: dedupedHits, suppressed, warnings, scannedFiles };
}

function severityRank(severity: Severity): number {
  switch (severity) {
    case "critical":
      return 5;
    case "high":
      return 4;
    case "medium":
      return 3;
    case "low":
      return 2;
    default:
      return 1;
  }
}

export interface LocalizedRuleText {
  title: string;
  message: string;
  remediation: string;
}

/**
 * Pick the requested language for rule text, falling back to English when a
 * translation is missing.
 */
export function localizeRule(
  rule: Pick<
    LoadedRule,
    "title" | "title_zh" | "message" | "message_zh" | "remediation" | "remediation_zh"
  >,
  lang: "en" | "zh",
): LocalizedRuleText {
  if (lang === "zh") {
    return {
      title: rule.title_zh ?? rule.title,
      message: rule.message_zh ?? rule.message,
      remediation: rule.remediation_zh ?? rule.remediation,
    };
  }
  return {
    title: rule.title,
    message: rule.message,
    remediation: rule.remediation,
  };
}
