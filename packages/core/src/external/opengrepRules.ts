import fs from "node:fs";
import path from "node:path";
import { parse as parseYaml } from "yaml";
import { toolRootDir } from "../meta.js";

/** Directory that ships the bundled Opengrep/Semgrep-syntax rules. */
export function defaultOpengrepRulesDir(): string {
  // The misspelt name is the one earlier builds read; it keeps working.
  const override =
    process.env.CODE_AUDIT_OPENGREP_RULES_DIR ?? process.env.CODE_AUDIT_OPENREP_RULES_DIR;
  if (override) return path.resolve(override);
  return path.join(toolRootDir(), "rules", "opengrep");
}

export interface OpengrepRuleSummary {
  id: string;
  languages: string[];
  severity: string;
  cwe?: string;
}

export interface OpengrepRuleSet {
  rulesDir: string;
  files: string[];
  rules: OpengrepRuleSummary[];
  errors: string[];
}

function listYamlFiles(dir: string): string[] {
  const result: string[] = [];
  const walk = (current: string): void => {
    const entries = fs.readdirSync(current, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const abs = path.join(current, entry.name);
      if (entry.isDirectory()) walk(abs);
      else if (entry.isFile() && (entry.name.endsWith(".yml") || entry.name.endsWith(".yaml"))) {
        result.push(abs);
      }
    }
  };
  walk(dir);
  return result.sort();
}

/**
 * Load Opengrep/Semgrep-syntax rules for counting and validation. Unlike the
 * built-in rule loader this does not require title/remediation fields, because
 * the external tool supplies its own messages.
 */
export function loadOpengrepRules(rulesDir: string): OpengrepRuleSet {
  const absoluteDir = path.resolve(rulesDir);
  const files = listYamlFiles(absoluteDir);
  const rules: OpengrepRuleSummary[] = [];
  const errors: string[] = [];
  for (const file of files) {
    const relative = path.relative(absoluteDir, file);
    let document: unknown;
    try {
      document = parseYaml(fs.readFileSync(file, "utf8"));
    } catch (error) {
      errors.push(`${relative}: ${error instanceof Error ? error.message : String(error)}`);
      continue;
    }
    const rawRules = (document as { rules?: unknown } | null)?.rules;
    if (!Array.isArray(rawRules)) {
      errors.push(`${relative}: missing top-level rules array`);
      continue;
    }
    for (const raw of rawRules) {
      const record = raw as {
        id?: unknown;
        languages?: unknown;
        severity?: unknown;
        metadata?: { cwe?: unknown };
      };
      if (typeof record.id !== "string") {
        errors.push(`${relative}: rule without an id`);
        continue;
      }
      const languages = Array.isArray(record.languages)
        ? record.languages.filter((item): item is string => typeof item === "string")
        : [];
      const cwe = record.metadata?.cwe;
      rules.push({
        id: record.id,
        languages,
        severity: typeof record.severity === "string" ? record.severity : "UNKNOWN",
        ...(typeof cwe === "string" ? { cwe } : {}),
      });
    }
  }
  return { rulesDir: absoluteDir, files, rules, errors };
}