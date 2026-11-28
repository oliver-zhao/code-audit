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
  /** Present when --history asked for a secret scan of the git history. */
  history?: {
    /** `skipped`: gitleaks is not installed; `partial`: a limit was hit. */
    status: "ok" | "partial" | "skipped" | "failed";
    /** The revision range; null for every commit reachable from any ref. */
    range: string | null;
    detail: string;
    /** Commits in the range. */
    commits: number;
    /** Commits Gitleaks was asked to scan at most. */
    maxCommits: number;
    /** Gitleaks results before deduplication. */
    results: number;
    /** History findings reported on their own (the secret is gone or changed place). */
    findings: number;
    /** Current findings that the history scan found in older commits too. */
    annotated: number;
  };
  /** Present when --since limited the report to changed files. */
  scope?: {
    since: string | null;
    changedFiles: number;
    outOfScope: number;
    /** `--diff-lines`: findings were kept only when they touch a changed line. */
    diffLines?: boolean;
    /** Findings and hotspots in changed files left out by `--diff-lines`. */
    diffLinesFiltered?: number;
    /** Changed files that were not diffed line by line (counted in full). */
    diffLinesWholeFiles?: number;
  };
}
