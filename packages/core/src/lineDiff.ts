/**
 * Line-level diff for `scan --since <ref> --diff-lines`.
 *
 * An implementation of Myers' O((N+M)D) difference algorithm ("An O(ND)
 * Difference Algorithm and Its Variations", 1986) in its linear-space form:
 * the edit distance D is measured first with the greedy forward pass (one
 * V array, no trace), then the middle-snake bisection finds the matched
 * lines. The result is the set of lines of the NEW text that are not part of
 * the longest common subsequence - inserted or replaced lines - plus, by
 * default, the new lines adjacent to each deletion.
 *
 * Inputs from the audited repository can be large or adversarial. Above
 * `maxLines` lines on either side, or an edit distance above `maxEditDistance`,
 * the diff is not computed and every line of the new text counts as changed
 * (fail open: more lines in scope, never fewer).
 */

import { splitLines } from "./redact.js";

export const DEFAULT_DIFF_MAX_LINES = 20_000;
export const DEFAULT_DIFF_MAX_EDIT_DISTANCE = 5_000;

export interface LineDiffOptions {
  /** More lines than this on either side: every new line counts as changed. */
  maxLines?: number;
  /** An edit distance above this: every new line counts as changed. */
  maxEditDistance?: number;
  /**
   * Also count the new lines directly before and after a deletion as changed
   * (default true): removing a guard or sanitizer line changes what its
   * neighbour does, though the neighbour's text is the same.
   */
  markDeletions?: boolean;
}

export type LineDiffResult =
  | {
      /** The diff was computed. */
      whole: false;
      /** 1-based line numbers of the new text that were inserted or changed. */
      changed: Set<number>;
      /** Edit distance (inserted + deleted lines). */
      editDistance: number;
      newLineCount: number;
    }
  | {
      /** Not computed: every line of the new text counts as changed. */
      whole: true;
      reason: "too-many-lines" | "edit-distance";
      newLineCount: number;
    };

/**
 * Split a text into lines exactly the way the scanner numbers them
 * (`splitLines` in redact.ts): `\r\n`, a lone `\r` and `\n` each end a line.
 * Line N here is line N of every finding, so a lone CR cannot shift a finding
 * onto a line the diff considers unchanged. The terminator is not part of a
 * line's content, so a change of line endings alone (CRLF <-> LF) does not
 * make a line "changed", and a final line break is not an extra empty line
 * ("a\nb" and "a\nb\n" both have two lines).
 */
export function splitDiffLines(text: string): string[] {
  if (text === "") return [];
  const lines = splitLines(text);
  if (lines[lines.length - 1] === "") lines.pop();
  return lines;
}

/** Map each distinct line to a small integer so comparisons are cheap. */
function intern(oldLines: readonly string[], newLines: readonly string[]): [Int32Array, Int32Array] {
  const ids = new Map<string, number>();
  const encode = (lines: readonly string[]): Int32Array => {
    const out = new Int32Array(lines.length);
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index] as string;
      let id = ids.get(line);
      if (id === undefined) {
        id = ids.size;
        ids.set(line, id);
      }
      out[index] = id;
    }
    return out;
  };
  return [encode(oldLines), encode(newLines)];
}

/**
 * Edit distance between a[aLo, aHi) and b[bLo, bHi) with the greedy forward
 * pass, or `undefined` when it exceeds `limit`. O((N+M)D) time, O(N+M) space.
 */
function editDistance(
  a: Int32Array,
  b: Int32Array,
  aLo: number,
  aHi: number,
  bLo: number,
  bHi: number,
  limit: number,
): number | undefined {
  const n = aHi - aLo;
  const m = bHi - bLo;
  const max = n + m;
  if (max === 0) return 0;
  const offset = max + 1;
  const v = new Int32Array(2 * max + 3);
  const bound = Math.min(max, limit);
  // Diagonals whose path has left the grid are skipped from then on.
  let kStart = 0;
  let kEnd = 0;
  for (let d = 0; d <= bound; d += 1) {
    for (let k = -d + kStart; k <= d - kEnd; k += 2) {
      let x: number;
      if (k === -d || (k !== d && (v[offset + k - 1] as number) < (v[offset + k + 1] as number))) {
        x = v[offset + k + 1] as number;
      } else {
        x = (v[offset + k - 1] as number) + 1;
      }
      let y = x - k;
      while (x < n && y < m && a[aLo + x] === b[bLo + y]) {
        x += 1;
        y += 1;
      }
      v[offset + k] = x;
      if (x > n) kEnd += 2;
      else if (y > m) kStart += 2;
      else if (x === n && y === m) return d;
    }
  }
  return undefined;
}

/**
 * Mark the lines of b[bLo, bHi) that are not matched with a line of
 * a[aLo, aHi), with the linear-space divide and conquer of Myers section 4b.
 */
function markInserted(
  a: Int32Array,
  b: Int32Array,
  aLo: number,
  aHi: number,
  bLo: number,
  bHi: number,
  out: Set<number>,
  deletions?: Set<number>,
): void {
  // An explicit stack instead of recursion: depth is bounded by log(N+M)
  // for balanced splits, but never trust that with adversarial input.
  const stack: Array<[number, number, number, number]> = [[aLo, aHi, bLo, bHi]];
  while (stack.length > 0) {
    let [x0, x1, y0, y1] = stack.pop() as [number, number, number, number];
    // Common prefix and suffix are matched.
    while (x0 < x1 && y0 < y1 && a[x0] === b[y0]) {
      x0 += 1;
      y0 += 1;
    }
    while (x0 < x1 && y0 < y1 && a[x1 - 1] === b[y1 - 1]) {
      x1 -= 1;
      y1 -= 1;
    }
    if (y0 === y1) {
      // Only deletions remain: lines a[x0, x1) were removed between new
      // lines y0 - 1 and y0 (0-based).
      if (x0 < x1) deletions?.add(y0);
      continue;
    }
    if (x0 === x1) {
      for (let y = y0; y < y1; y += 1) out.add(y + 1);
      continue;
    }
    const split = middleSnake(a, b, x0, x1, y0, y1);
    if (!split) {
      for (let y = y0; y < y1; y += 1) out.add(y + 1);
      continue;
    }
    const [splitX, splitY] = split;
    if ((splitX === x0 && splitY === y0) || (splitX === x1 && splitY === y1)) {
      // No progress (not expected): count the range as changed, never loop.
      for (let y = y0; y < y1; y += 1) out.add(y + 1);
      continue;
    }
    stack.push([x0, splitX, y0, splitY], [splitX, x1, splitY, y1]);
  }
}

/**
 * The point where the forward and the reverse furthest-reaching D-paths
 * meet (Myers 4b). Both sub-problems it splits into are strictly smaller.
 * `undefined` when the ranges have no line in common.
 * Requires a non-empty range on both sides whose first and last elements
 * differ (the caller strips the common prefix and suffix).
 */
function middleSnake(
  a: Int32Array,
  b: Int32Array,
  aLo: number,
  aHi: number,
  bLo: number,
  bHi: number,
): [number, number] | undefined {
  const n = aHi - aLo;
  const m = bHi - bLo;
  const maxD = Math.ceil((n + m) / 2);
  const offset = maxD;
  const size = 2 * maxD + 2;
  const vf = new Int32Array(size).fill(-1);
  const vr = new Int32Array(size).fill(-1);
  vf[offset + 1] = 0;
  vr[offset + 1] = 0;
  const delta = n - m;
  const front = delta % 2 !== 0;
  // Diagonals whose path has left the grid are skipped from then on.
  let kfStart = 0;
  let kfEnd = 0;
  let krStart = 0;
  let krEnd = 0;
  for (let d = 0; d < maxD; d += 1) {
    for (let k = -d + kfStart; k <= d - kfEnd; k += 2) {
      const index = offset + k;
      let x: number;
      if (k === -d || (k !== d && (vf[index - 1] as number) < (vf[index + 1] as number))) {
        x = vf[index + 1] as number;
      } else {
        x = (vf[index - 1] as number) + 1;
      }
      let y = x - k;
      while (x < n && y < m && a[aLo + x] === b[bLo + y]) {
        x += 1;
        y += 1;
      }
      vf[index] = x;
      if (x > n) {
        kfEnd += 2;
      } else if (y > m) {
        kfStart += 2;
      } else if (front) {
        const indexR = offset + delta - k;
        if (indexR >= 0 && indexR < size && (vr[indexR] as number) !== -1) {
          if (x >= n - (vr[indexR] as number)) return [aLo + x, bLo + y];
        }
      }
    }
    for (let k = -d + krStart; k <= d - krEnd; k += 2) {
      const index = offset + k;
      let x: number;
      if (k === -d || (k !== d && (vr[index - 1] as number) < (vr[index + 1] as number))) {
        x = vr[index + 1] as number;
      } else {
        x = (vr[index - 1] as number) + 1;
      }
      let y = x - k;
      while (x < n && y < m && a[aHi - 1 - x] === b[bHi - 1 - y]) {
        x += 1;
        y += 1;
      }
      vr[index] = x;
      if (x > n) {
        krEnd += 2;
      } else if (y > m) {
        krStart += 2;
      } else if (!front) {
        const kf = delta - k;
        const indexF = offset + kf;
        if (indexF >= 0 && indexF < size && (vf[indexF] as number) !== -1) {
          const xf = vf[indexF] as number;
          if (xf >= n - x) return [aLo + xf, bLo + xf - kf];
        }
      }
    }
  }
  // No overlap within ceil((N+M)/2) steps: D = N + M, the ranges have no
  // line in common.
  return undefined;
}

/**
 * Lines of `newText` that are inserted or changed compared with `oldText`.
 * `oldText` undefined means the file is new: every line is changed.
 */
export function changedLines(
  oldText: string | undefined,
  newText: string,
  options: LineDiffOptions = {},
): LineDiffResult {
  const maxLines = options.maxLines ?? DEFAULT_DIFF_MAX_LINES;
  const maxEditDistance = options.maxEditDistance ?? DEFAULT_DIFF_MAX_EDIT_DISTANCE;
  const newLines = splitDiffLines(newText);
  if (oldText === undefined) {
    const changed = new Set<number>();
    for (let line = 1; line <= newLines.length; line += 1) changed.add(line);
    return { whole: false, changed, editDistance: newLines.length, newLineCount: newLines.length };
  }
  const oldLines = splitDiffLines(oldText);
  if (oldLines.length > maxLines || newLines.length > maxLines) {
    return { whole: true, reason: "too-many-lines", newLineCount: newLines.length };
  }
  const [a, b] = intern(oldLines, newLines);
  // The common prefix and suffix do not count toward the edit distance.
  let aLo = 0;
  let bLo = 0;
  let aHi = a.length;
  let bHi = b.length;
  while (aLo < aHi && bLo < bHi && a[aLo] === b[bLo]) {
    aLo += 1;
    bLo += 1;
  }
  while (aLo < aHi && bLo < bHi && a[aHi - 1] === b[bHi - 1]) {
    aHi -= 1;
    bHi -= 1;
  }
  const distance = editDistance(a, b, aLo, aHi, bLo, bHi, maxEditDistance);
  if (distance === undefined) {
    return { whole: true, reason: "edit-distance", newLineCount: newLines.length };
  }
  const changed = new Set<number>();
  const deletions = new Set<number>();
  markInserted(a, b, aLo, aHi, bLo, bHi, changed, deletions);
  if (options.markDeletions !== false) {
    const inserted = new Set(changed);
    for (const at of deletions) {
      // The deleted lines sit between new lines at - 1 and at (0-based),
      // that is 1-based `at` and `at + 1`. A deletion next to an inserted
      // line is a replacement, already marked; a pure deletion marks both
      // neighbours.
      if (inserted.has(at) || inserted.has(at + 1)) continue;
      if (at >= 1) changed.add(at);
      if (at < newLines.length) changed.add(at + 1);
    }
  }
  return { whole: false, changed, editDistance: distance, newLineCount: newLines.length };
}
