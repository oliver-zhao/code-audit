/*
 * Dockerfile units
 * ----------------
 * An instruction continued with the escape character (`\`, or the one set by
 * an `# escape=` parser directive) at the end of a line is one unit, so
 * `RUN curl ... \` followed by `  | sh` is seen whole; the hit is still
 * reported on the physical line where the match starts. Comment lines (`#`
 * as the first non-blank character) are blank, also inside a continued
 * instruction, where Docker drops them too. A `#` later in a line is kept:
 * inside a RUN it may be shell text or a shell comment, and the lexer does
 * not guess (fail open). Heredoc bodies are matched line by line as written.
 */
import {
  MAX_LOGICAL_LINE_LENGTH,
  MAX_LOGICAL_LINE_SPAN,
  MAX_PATTERN_LINE_LENGTH,
  windowUnits,
  type LexDiagnostics,
  type LogicalLine,
} from "../rules.js";

/** A parser directive Docker knows: `# syntax=`, `# escape=`, `# check=`. */
const PARSER_DIRECTIVE = /^\s*#\s*(syntax|escape|check)\s*=\s*(\S*)\s*$/i;

export function dockerfileLogicalLines(
  lines: string[],
  overLong?: number[],
  diagnostics?: LexDiagnostics,
): LogicalLine[] {
  // Parser directives are read only at the very start of the file: the first
  // blank line, comment, unknown directive or instruction ends them, as in
  // Docker. `# escape=` sets the continuation character.
  let escape = "\\";
  for (const line of lines) {
    const directive = PARSER_DIRECTIVE.exec(line);
    if (!directive) break;
    if ((directive[1] as string).toLowerCase() === "escape" && (directive[2] === "`" || directive[2] === "\\")) {
      escape = directive[2] as string;
    }
  }

  const result: LogicalLine[] = [];
  const windows: LogicalLine[] = [];
  let parts: string[] = [];
  let start = 0;
  let codeLines = 0;
  let length = 0;
  let cutReported = false;

  const flush = (): void => {
    if (parts.length === 0) return;
    const offsets: number[] = [];
    let offset = 0;
    for (const part of parts) {
      offsets.push(offset);
      offset += part.length + 1;
    }
    result.push({ start, text: parts.join("\n"), offsets, declaration: false, headerEnd: 0 });
    parts = [];
    codeLines = 0;
    length = 0;
  };

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    if (parts.length === 0) start = index;
    const comment = /^\s*#/.test(line);
    let text = comment ? "" : line;
    if (text.length > MAX_PATTERN_LINE_LENGTH) {
      overLong?.push(index);
      diagnostics?.overLong.push(index);
      for (const unit of windowUnits(index, text)) windows.push(unit);
      text = text.slice(0, MAX_PATTERN_LINE_LENGTH);
    }
    parts.push(text);
    if (text.trim().length > 0) {
      codeLines += 1;
      length += text.length + 1;
    }
    // A comment or blank line inside a continued instruction keeps it open.
    const continues =
      codeLines > 0 && (comment || line.trim().length === 0 || line.trimEnd().endsWith(escape));
    if (!continues || index === lines.length - 1) {
      flush();
      cutReported = false;
    } else if (codeLines >= MAX_LOGICAL_LINE_SPAN || length >= MAX_LOGICAL_LINE_LENGTH) {
      if (!cutReported) {
        diagnostics?.cuts.push(start);
        cutReported = true;
      }
      // Keep the last half as overlap with the next window.
      const keep = Math.floor(parts.length / 2);
      const tail = parts.slice(parts.length - keep);
      flush();
      parts = tail;
      start = index + 1 - tail.length;
      for (const part of tail) {
        if (part.trim().length > 0) {
          codeLines += 1;
          length += part.length + 1;
        }
      }
    }
  }
  flush();
  for (const unit of windows) result.push(unit);
  return result;
}
