import type { ManifestRef } from "./inventory.js";

export interface CoverageFile {
  path: string;
  language: string;
  loc: number;
  engines: string[];
  /** Path classification of the file; absent for ordinary source. */
  pathContext?: "test" | "docs" | "example" | "vendored" | "generated";
}

export interface CoverageSkip {
  path: string;
  reason: string;
}

export interface CoverageEngine {
  name: string;
  enabled: boolean;
  status: string;
  detail?: string;
  /** Wall-clock duration of the engine run in milliseconds (external engines). */
  durationMs?: number;
}

export interface CoverageReport {
  root: string;
  stats: {
    files: number;
    scannedFiles: number;
    /** Subset of scannedFiles analysed only partially (generated lockfiles). */
    partialFiles?: number;
    skippedFiles: number;
    loc: number;
  };
  languages: Record<string, { files: number; loc: number }>;
  scannedFiles: CoverageFile[];
  skipped: CoverageSkip[];
  manifests: ManifestRef[];
  engines: CoverageEngine[];
  rulesCount: number;
  warnings: string[];
  suppressed: Array<{
    ruleId: string;
    file: string;
    line: number;
    reason: string;
  }>;
  /**
   * Files per path context, and whether findings in them had their
   * confidence lowered (`--include-tests` turns that off).
   */
  pathContext?: {
    lowering: boolean;
    files: Record<"test" | "docs" | "example" | "vendored" | "generated", number>;
  };
  /** Present when --since limited the report to changed files. */
  scope?: {
    since: string | null;
    changedFiles: number;
    outOfScope: number;
  };
}
