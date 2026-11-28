/**
 * crossEngineDedupe is indexed by file, CWE and line bucket; it must give
 * exactly the result of the pairwise definition (crossEngineDedupeReference)
 * and stay fast on large scans.
 */
import { describe, expect, it } from "vitest";
import { createFinding, type Finding } from "../src/finding.js";
import { crossEngineDedupe, crossEngineDedupeReference } from "../src/external/merge.js";
import { safeLine, safeLineRange } from "../src/external/lines.js";

/** Small deterministic generator (mulberry32). */
function random(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const ENGINES = ["builtin-rules", "builtin-secrets", "opengrep", "semgrep", "gitleaks"] as const;
const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const CONFIDENCES = ["high", "medium", "low"] as const;

function finding(
  next: () => number,
  options: { files: number; lines: number; wide: number },
  index: number,
): Finding {
  const pick = <T>(items: readonly T[]): T => items[Math.floor(next() * items.length)] as T;
  const engine = pick(ENGINES);
  const startLine = 1 + Math.floor(next() * options.lines);
  // Mostly short ranges, some long ones that cross many line buckets.
  const length = next() < options.wide ? Math.floor(next() * 5000) : Math.floor(next() * 4);
  const cwe = next() < 0.05 ? undefined : pick(["CWE-79", "cwe-79", "CWE-89", "CWE-798", "CWE-95"]);
  const secrets = engine === "builtin-secrets" || engine === "gitleaks";
  const extraEngines = next() < 0.2 ? [pick(ENGINES)] : undefined;
  const ruleId = `r${Math.floor(next() * 6)}`;
  return createFinding({
    ruleId,
    title: "t",
    category: secrets ? "secrets" : next() < 0.9 ? "sast" : "config",
    severity: pick(SEVERITIES),
    confidence: pick(CONFIDENCES),
    ...(cwe ? { cwe } : {}),
    file: `src/f${Math.floor(next() * options.files)}.py`,
    startLine,
    endLine: startLine + length,
    evidence: `line ${index}`,
    message: "m",
    remediation: "r",
    provenance: { engine, rule: ruleId, ...(extraEngines ? { engines: extraEngines } : {}) },
  } as Parameters<typeof createFinding>[0]);
}

describe("crossEngineDedupe (indexed)", () => {
  it("gives exactly the result of the pairwise definition on randomized inputs", () => {
    let merges = 0;
    for (let seed = 1; seed <= 300; seed += 1) {
      const next = random(seed);
      const options = {
        files: 1 + Math.floor(next() * 4),
        lines: [5, 60, 300, 3000][seed % 4] as number,
        wide: [0, 0.05, 0.3][seed % 3] as number,
      };
      const count = 1 + Math.floor(next() * 120);
      const input = Array.from({ length: count }, (_value, index) => finding(next, options, index));
      const indexed = crossEngineDedupe(input);
      expect(indexed, `seed ${seed}`).toEqual(crossEngineDedupeReference(input));
      merges += input.length - indexed.length;
    }
    // The inputs exercise merging, not only distinct findings.
    expect(merges).toBeGreaterThan(500);
  });

  it("handles ranges at the bucket edges, huge ranges and missing CWEs like the definition", () => {
    const base = {
      title: "t",
      category: "sast",
      severity: "high",
      confidence: "medium",
      cwe: "CWE-95",
      file: "a.py",
      evidence: "e",
      message: "m",
      remediation: "r",
    } as const;
    const make = (engine: string, startLine: number, endLine: number, cwe?: string): Finding =>
      createFinding({
        ...base,
        ...(cwe === undefined ? {} : { cwe }),
        ruleId: `${engine}-r`,
        startLine,
        endLine,
        provenance: { engine, rule: `${engine}-r` },
      } as Parameters<typeof createFinding>[0]);
    const input = [
      make("builtin-rules", 63, 64),
      make("opengrep", 64, 64),
      make("semgrep", 1, 1_000_000),
      make("builtin-rules", 500_000, 500_000),
      make("opengrep", 127, 128),
      make("semgrep", 128, 128, "cwe-95"),
      make("opengrep", 10, 10, ""),
    ];
    expect(crossEngineDedupe(input)).toEqual(crossEngineDedupeReference(input));
  });

  it("dedupes 50,000 findings across 50 files in under 2 s", () => {
    const next = random(42);
    const input = Array.from({ length: 50_000 }, (_value, index) =>
      finding(next, { files: 50, lines: 20_000, wide: 0.001 }, index),
    );
    const started = performance.now();
    const result = crossEngineDedupe(input);
    const elapsed = performance.now() - started;
    expect(result.length).toBeGreaterThan(0);
    expect(elapsed).toBeLessThan(2000);
  });
});

describe("crossEngineDedupe with non-finite or unsafe line numbers", () => {
  it("returns, and matches the definition, for Infinity, NaN, 2^53 and 2^60", () => {
    const base = {
      ruleId: "r",
      title: "t",
      category: "sast",
      severity: "high",
      confidence: "medium",
      cwe: "CWE-95",
      file: "a.py",
      evidence: "e",
      message: "m",
      remediation: "r",
    } as const;
    const make = (engine: string, startLine: number, endLine: number): Finding => ({
      ...createFinding({ ...base, startLine: 1, endLine: 1, provenance: { engine, rule: "r" } } as Parameters<typeof createFinding>[0]),
      startLine,
      endLine,
    });
    const input = [
      make("opengrep", Infinity, Infinity),
      make("semgrep", Infinity, Infinity),
      make("opengrep", Number.NaN, Number.NaN),
      make("builtin-rules", 2 ** 60, 2 ** 60),
      make("semgrep", 2 ** 60, 2 ** 60 + 5),
      make("opengrep", 2 ** 53, 2 ** 53),
      make("builtin-rules", 1, Infinity),
      make("semgrep", 5, 5),
      make("opengrep", -Infinity, 3),
    ];
    const started = performance.now();
    const result = crossEngineDedupe(input);
    expect(performance.now() - started).toBeLessThan(1000);
    expect(result).toEqual(crossEngineDedupeReference(input));
  });

  it("parses only positive safe integers as external line numbers", () => {
    expect([1, 7.9, 0, -3, Infinity, Number.NaN, 2 ** 60, "5", undefined].map(safeLine)).toEqual([
      1, 7, undefined, undefined, undefined, undefined, undefined, undefined, undefined,
    ]);
    const warnings: string[] = [];
    const note = (field: string): void => {
      warnings.push(field);
    };
    expect(safeLineRange(JSON.parse("1e309"), 4, note)).toEqual({ startLine: 1, endLine: 4 });
    expect(safeLineRange(10, 2 ** 60, note)).toEqual({ startLine: 10, endLine: 10 });
    expect(safeLineRange(10, 3, note)).toEqual({ startLine: 10, endLine: 10 });
    expect(warnings).toEqual(["start line", "end line"]);
  });
});
