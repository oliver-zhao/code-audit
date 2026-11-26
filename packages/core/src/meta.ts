import path from "node:path";
import { fileURLToPath } from "node:url";

export const TOOL_VERSION = "0.1.0";
export const TOOL_NAME = "code-audit";

/** Directory that ships the bundled YAML rules. */
export function defaultRulesDir(): string {
  const override = process.env.CODE_AUDIT_RULES_DIR;
  if (override) return path.resolve(override);
  const here = path.dirname(fileURLToPath(import.meta.url));
  return path.resolve(here, "../../..", "rules");
}

/** Root of the tool's own checkout or package (holds `rules/`, `skills/`, `adapters/`, `bin/`). */
export function toolRootDir(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  return path.resolve(here, "../../..");
}

/** Files the tool writes into a run directory (`<out>/<run-id>/`). */
export const RUN_OUTPUT_FILES: ReadonlySet<string> = new Set([
  "run.json",
  "state.json",
  "coverage.json",
  "findings.json",
  "report.md",
  "results.sarif",
  "verdicts.json",
  "agent-findings.json",
]);

/** Files `--latest-link` copies into `<out>/latest/`. */
export const LATEST_OUTPUT_FILES: ReadonlySet<string> = new Set([
  "findings.json",
  "report.md",
  "results.sarif",
]);
