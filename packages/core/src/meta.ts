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
