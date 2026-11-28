import { describe, expect, it } from "vitest";
import { changedLines, splitDiffLines } from "../src/lineDiff.js";

function text(lines: string[]): string {
  return lines.map((line) => `${line}\n`).join("");
}

function changed(oldLines: string[], newLines: string[]): number[] {
  const result = changedLines(text(oldLines), text(newLines));
  if (result.whole) throw new Error(`unexpected whole-file result: ${result.reason}`);
  return [...result.changed].sort((a, b) => a - b);
}

/** Length of the longest common subsequence, by dynamic programming. */
function lcsLength(a: string[], b: string[]): number {
  const table = Array.from({ length: a.length + 1 }, () => new Int32Array(b.length + 1));
  for (let i = a.length - 1; i >= 0; i -= 1) {
    for (let j = b.length - 1; j >= 0; j -= 1) {
      const row = table[i] as Int32Array;
      row[j] =
        a[i] === b[j]
          ? ((table[i + 1] as Int32Array)[j + 1] as number) + 1
          : Math.max((table[i + 1] as Int32Array)[j] as number, row[j + 1] as number);
    }
  }
  return (table[0] as Int32Array)[0] as number;
}

describe("splitDiffLines", () => {
  it("splits on LF, drops the final line break and a trailing CR", () => {
    expect(splitDiffLines("")).toEqual([]);
    expect(splitDiffLines("a")).toEqual(["a"]);
    expect(splitDiffLines("a\n")).toEqual(["a"]);
    expect(splitDiffLines("a\nb")).toEqual(["a", "b"]);
    expect(splitDiffLines("a\r\nb\r\n")).toEqual(["a", "b"]);
    expect(splitDiffLines("a\n\n")).toEqual(["a", ""]);
  });
});

describe("Myers line diff", () => {
  it("reports nothing for identical texts", () => {
    expect(changed(["a", "b", "c"], ["a", "b", "c"])).toEqual([]);
  });

  it("reports inserted lines", () => {
    expect(changed(["a", "b", "c"], ["a", "x", "b", "c"])).toEqual([2]);
    expect(changed(["a", "b"], ["x", "a", "b", "y"])).toEqual([1, 4]);
    expect(changed(["a"], ["a", "b", "c"])).toEqual([2, 3]);
  });

  it("reports no new line for a pure deletion", () => {
    expect(changed(["a", "b", "c", "d"], ["a", "d"])).toEqual([]);
    expect(changed(["a", "b"], [])).toEqual([]);
  });

  it("reports replaced lines", () => {
    expect(changed(["a", "b", "c"], ["a", "B", "c"])).toEqual([2]);
    expect(changed(["a", "b", "c", "d"], ["a", "X", "Y", "Z", "d"])).toEqual([2, 3, 4]);
  });

  it("handles empty texts", () => {
    const fromEmpty = changedLines("", "a\nb\n");
    expect(fromEmpty.whole).toBe(false);
    if (!fromEmpty.whole) expect([...fromEmpty.changed]).toEqual([1, 2]);
    const toEmpty = changedLines("a\nb\n", "");
    expect(toEmpty.whole).toBe(false);
    if (!toEmpty.whole) expect(toEmpty.changed.size).toBe(0);
    const both = changedLines("", "");
    expect(both.whole).toBe(false);
    if (!both.whole) expect(both.changed.size).toBe(0);
  });

  it("treats a new file (no old text) as changed in full", () => {
    const result = changedLines(undefined, "a\nb\nc");
    expect(result.whole).toBe(false);
    if (!result.whole) expect([...result.changed]).toEqual([1, 2, 3]);
  });

  it("ignores a change of line endings alone (CRLF <-> LF)", () => {
    const result = changedLines("a\nb\nc\n", "a\r\nb\r\nX\r\n");
    expect(result.whole).toBe(false);
    if (!result.whole) expect([...result.changed]).toEqual([3]);
  });

  it("ignores a missing or added final line break", () => {
    const added = changedLines("a\nb", "a\nb\n");
    expect(added.whole).toBe(false);
    if (!added.whole) expect(added.changed.size).toBe(0);
    const appended = changedLines("a\nb", "a\nb\nc");
    expect(appended.whole).toBe(false);
    if (!appended.whole) expect([...appended.changed]).toEqual([3]);
  });

  it("finds a longest common subsequence on random inputs", () => {
    let seed = 12345;
    const random = (): number => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed / 0x7fffffff;
    };
    for (let iteration = 0; iteration < 3000; iteration += 1) {
      const alphabet = 1 + Math.floor(random() * 5);
      const a = Array.from({ length: Math.floor(random() * 30) }, () =>
        String.fromCharCode(97 + Math.floor(random() * alphabet)),
      );
      const b = Array.from({ length: Math.floor(random() * 30) }, () =>
        String.fromCharCode(97 + Math.floor(random() * alphabet)),
      );
      const result = changedLines(text(a), text(b));
      expect(result.whole).toBe(false);
      if (result.whole) continue;
      // The unchanged new lines form a common subsequence of maximal length.
      const kept = b.filter((_, index) => !result.changed.has(index + 1));
      let position = 0;
      for (const line of kept) {
        while (position < a.length && a[position] !== line) position += 1;
        expect(position).toBeLessThan(a.length);
        position += 1;
      }
      const lcs = lcsLength(a, b);
      expect(kept.length).toBe(lcs);
      expect(result.editDistance).toBe(a.length + b.length - 2 * lcs);
    }
  });

  it("diffs a 20,000-line file with 2,000 changed lines quickly", () => {
    const old = Array.from({ length: 20_000 }, (_, index) => `line ${index}`);
    const edited = old.slice();
    for (let index = 0; index < 2_000; index += 1) edited[index * 10] = `changed ${index}`;
    const started = performance.now();
    const result = changedLines(old.join("\n"), edited.join("\n"));
    const elapsed = performance.now() - started;
    expect(result.whole).toBe(false);
    if (!result.whole) {
      expect(result.changed.size).toBe(2_000);
      expect(result.editDistance).toBe(4_000);
      expect(result.changed.has(1)).toBe(true);
      expect(result.changed.has(2)).toBe(false);
    }
    expect(elapsed).toBeLessThan(10_000);
  });

  it("falls back to the whole file above the line limit", () => {
    const old = Array.from({ length: 20_001 }, (_, index) => `line ${index}`).join("\n");
    const result = changedLines(old, `${old}\nmore`);
    expect(result).toMatchObject({ whole: true, reason: "too-many-lines" });
    // The limit is configurable.
    expect(changedLines("a\nb\nc", "a\nx\nc", { maxLines: 2 })).toMatchObject({
      whole: true,
      reason: "too-many-lines",
    });
  });

  it("falls back to the whole file above the edit-distance limit, without the full cost", () => {
    const old = Array.from({ length: 20_000 }, (_, index) => `old ${index}`).join("\n");
    const replaced = Array.from({ length: 20_000 }, (_, index) => `new ${index}`).join("\n");
    const started = performance.now();
    const result = changedLines(old, replaced);
    const elapsed = performance.now() - started;
    expect(result).toMatchObject({ whole: true, reason: "edit-distance" });
    expect(elapsed).toBeLessThan(10_000);
    expect(changedLines("a\nb\nc\n", "x\ny\nz\n", { maxEditDistance: 5 })).toMatchObject({
      whole: true,
      reason: "edit-distance",
    });
    const exact = changedLines("a\nb\nc\n", "x\ny\nz\n", { maxEditDistance: 6 });
    expect(exact.whole).toBe(false);
  });
});
