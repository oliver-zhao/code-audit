/**
 * YAML front matter of Markdown files (skills, commands, subagents), for rules
 * with `withinFrontmatter`. The block is the text between a first line that is
 * exactly `---` and the next line that is exactly `---`; it is parsed with the
 * same bounded YAML reader as `withinKeys` (`yamlValues.ts`), and the line of
 * each value is mapped back to the line of the Markdown file.
 */
import { yamlKeyValues, type YamlKeyValue } from "./yamlValues.js";

export type FrontmatterValuesResult =
  | { ok: true; values: YamlKeyValue[] }
  | { ok: false; reason: string };

/** Front matter longer than this many lines is not read. */
export const FRONTMATTER_MAX_LINES = 2000;

/**
 * The values of `keys` in the front matter of `lines` (a file split into
 * physical lines). A file without front matter has no values; a block that is
 * not closed or does not parse is `ok: false`.
 */
export function frontmatterKeyValues(lines: readonly string[], keys: readonly string[]): FrontmatterValuesResult {
  const first = (lines[0] ?? "").replace(/^﻿/, "");
  if (first.trimEnd() !== "---") return { ok: true, values: [] };
  let end = -1;
  const limit = Math.min(lines.length, FRONTMATTER_MAX_LINES + 1);
  for (let index = 1; index < limit; index += 1) {
    if ((lines[index] as string).trimEnd() === "---") {
      end = index;
      break;
    }
  }
  if (end < 0) {
    return {
      ok: false,
      reason:
        lines.length > FRONTMATTER_MAX_LINES + 1
          ? `front matter not closed within ${FRONTMATTER_MAX_LINES} lines`
          : "front matter is not closed by a --- line",
    };
  }
  const block = lines.slice(1, end).join("\n");
  const parsed = yamlKeyValues(block, keys);
  if (!parsed.ok) return { ok: false, reason: `front matter ${parsed.reason}` };
  return {
    ok: true,
    values: parsed.values.map((value) => ({
      ...value,
      // Line 0 of the block is line 1 of the file.
      lineAt: (offset: number) => value.lineAt(offset) + 1,
    })),
  };
}
