/**
 * Line numbers read from external engine output. A tool result is data: JSON
 * `1e309` parses to Infinity and a corrupted or hostile result can hold any
 * number, so only a positive safe integer is taken as a line.
 */
export function safeLine(value: unknown): number | undefined {
  if (typeof value !== "number" || !Number.isFinite(value)) return undefined;
  const line = Math.trunc(value);
  return line >= 1 && Number.isSafeInteger(line) ? line : undefined;
}

/**
 * Start and end line of an external result. A start that is not a positive
 * safe integer becomes 1 with a warning; an end that is not one (or is before
 * the start) becomes the start.
 */
export function safeLineRange(
  start: unknown,
  end: unknown,
  onInvalid: (field: string, value: unknown) => void,
): { startLine: number; endLine: number } {
  let startLine = safeLine(start);
  if (startLine === undefined) {
    if (start !== undefined && start !== null) onInvalid("start line", start);
    startLine = 1;
  }
  let endLine = safeLine(end);
  if (endLine === undefined || endLine < startLine) {
    if (end !== undefined && end !== null && endLine === undefined) onInvalid("end line", end);
    endLine = startLine;
  }
  return { startLine, endLine };
}
