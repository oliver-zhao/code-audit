import type { ManifestRef } from "./inventory.js";

export interface CoverageFile {
  path: string;
  language: string;
  loc: number;
  engines: string[];
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
}
