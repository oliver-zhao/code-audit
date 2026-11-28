/**
 * YAML front matter of Markdown files (skills, commands, subagents, Cursor
 * rules), for rules with `withinFrontmatter`. The block is the text between a
 * first line that is exactly `---` and the next line that is exactly `---`;
 * it is parsed with the same bounded YAML reader as `withinKeys`
 * (`yamlValues.ts`), and the line of each value is mapped back to the line of
 * the Markdown file.
 *
 * Hosts read front matter more leniently than a YAML parser (an unquoted
 * `: ` in a description, `globs: **` in a Cursor rule). When the block does
 * not parse, the requested keys are read line by line instead: a `key: value`
 * line at column 0, followed by its indented continuation lines.
 */
import { yamlKeyValues, type YamlKeyValue } from "./yamlValues.js";

export type FrontmatterValuesResult =
  | { ok: true; values: YamlKeyValue[]; fallback?: string }
  | { ok: false; reason: string };

/** Front matter longer than this many lines is not read. */
export const FRONTMATTER_MAX_LINES = 2000;

const KEY_LINE = /^([A-Za-z_][A-Za-z0-9_.-]*)[ \t]*:(?:[ \t]+(.*))?$/;

/** Line-based reading of `keys` in the block (`blockLines`, file line of the first = `firstLine`). */
function lineValues(blockLines: readonly string[], firstLine: number, keys: readonly string[]): YamlKeyValue[] {
  const values: YamlKeyValue[] = [];
  for (let index = 0; index < blockLines.length; index += 1) {
    const match = KEY_LINE.exec(blockLines[index] as string);
    if (!match || !keys.includes(match[1] as string)) continue;
    const parts: string[] = [];
    const lineOfPart: number[] = [];
    let first = (match[2] ?? "").trim();
    // Block scalar indicators and surrounding quotes are not part of the text.
    if (/^[|>][+-]?\d?$/.test(first)) first = "";
    first = first.replace(/^(["'])(.*)\1$/, "$2");
    if (first) {
      parts.push(first);
      lineOfPart.push(firstLine + index);
    }
    let next = index + 1;
    while (next < blockLines.length && /^(?:[ \t]|$)/.test(blockLines[next] as string)) {
      const text = (blockLines[next] as string).trim();
      if (text) {
        parts.push(text);
        lineOfPart.push(firstLine + next);
      }
      next += 1;
    }
    if (parts.length === 0) continue;
    const starts: number[] = [];
    let text = "";
    for (const part of parts) {
      if (text) text += "\n";
      starts.push(text.length);
      text += part;
    }
    values.push({
      key: match[1] as string,
      text,
      lineAt: (offset) => {
        let at = 0;
        for (let part = 0; part < starts.length; part += 1) if ((starts[part] as number) <= offset) at = part;
        return lineOfPart[at] as number;
      },
    });
  }
  return values;
}

/**
 * The values of `keys` in the front matter of `lines` (a file split into
 * physical lines). A file without front matter has no values; a block that is
 * not closed is `ok: false`; a block that does not parse as YAML is read line
 * by line, and `fallback` says why.
 */
export function frontmatterKeyValues(lines: readonly string[], keys: readonly string[]): FrontmatterValuesResult {
  const first = (lines[0] ?? "").replace(/^\uFEFF/, "");
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
  const blockLines = lines.slice(1, end);
  const parsed = yamlKeyValues(blockLines.join("\n"), keys);
  if (!parsed.ok) return { ok: true, values: lineValues(blockLines, 1, keys), fallback: parsed.reason };
  return {
    ok: true,
    values: parsed.values.map((value) => ({
      ...value,
      // Line 0 of the block is line 1 of the file.
      lineAt: (offset: number) => value.lineAt(offset) + 1,
    })),
  };
}
