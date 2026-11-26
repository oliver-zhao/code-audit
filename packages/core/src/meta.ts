import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

/** Version of the tool. Must equal `version` in every package.json (tested). */
export const TOOL_VERSION = "0.2.0";
export const TOOL_NAME = "code-audit";

/** Directory of the `@code-audit/core` package (the parent of `dist/`). */
function corePackageDir(): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
}

function isFile(file: string): boolean {
  try {
    return fs.statSync(file).isFile();
  } catch {
    return false;
  }
}

/**
 * The repository root when this code runs from a checkout of the code-audit
 * monorepo (`<root>/packages/core/dist`), else undefined. The checkout is
 * recognised by its own workspace file and rule directory, so a directory
 * that merely sits two levels above an installed package (`node_modules`)
 * is never taken for it.
 */
export function monorepoRootDir(): string | undefined {
  const packageDir = corePackageDir();
  const candidate = path.resolve(packageDir, "../..");
  if (path.basename(path.dirname(packageDir)) !== "packages") return undefined;
  if (!isFile(path.join(candidate, "pnpm-workspace.yaml"))) return undefined;
  if (!isFile(path.join(candidate, "skills/code-audit/SKILL.md"))) return undefined;
  return candidate;
}

let cachedToolRoot: string | undefined;

/**
 * Directory that holds the files the tool ships besides its code: `rules/`,
 * `skills/` and the adapter sources under `adapters/`.
 *
 * - In a checkout of the repository this is the repository root.
 * - In an installed package it is `<@code-audit/core>/assets`, a copy of those
 *   directories made when the package is packed (`scripts/pack-assets.mjs`).
 */
export function toolRootDir(): string {
  if (cachedToolRoot === undefined) {
    cachedToolRoot = monorepoRootDir() ?? path.join(corePackageDir(), "assets");
  }
  return cachedToolRoot;
}

/** Directory that ships the bundled YAML rules. */
export function defaultRulesDir(): string {
  const override = process.env.CODE_AUDIT_RULES_DIR;
  if (override) return path.resolve(override);
  return path.join(toolRootDir(), "rules");
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
