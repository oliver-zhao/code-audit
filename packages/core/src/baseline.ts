import fs from "node:fs";
import path from "node:path";
import { z } from "zod";
import type { Finding } from "./finding.js";
import { BASELINE_FILE_NAME } from "./ignore.js";

export const BASELINE_SCHEMA_VERSION = 1;

const BaselineEntrySchema = z.object({
  fingerprint: z.string().regex(/^[a-f0-9]{64}$/),
  ruleId: z.string().min(1),
  file: z.string().min(1),
  severity: z.enum(["critical", "high", "medium", "low", "info"]),
  title: z.string(),
});

const BaselineDocumentSchema = z.object({
  schemaVersion: z.number(),
  createdAt: z.string(),
  tool: z.string(),
  entries: z.array(BaselineEntrySchema),
});

export type BaselineEntry = z.infer<typeof BaselineEntrySchema>;

export interface BaselineDocument {
  schemaVersion: number;
  createdAt: string;
  tool: string;
  entries: BaselineEntry[];
}

export class BaselineError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BaselineError";
  }
}

/** Parse and validate baseline JSON text, rejecting unknown schema versions. */
export function parseBaseline(text: string, source: string): BaselineDocument {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (error) {
    throw new BaselineError(
      `baseline ${source} is not valid JSON: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  const parsed = BaselineDocumentSchema.safeParse(raw);
  if (!parsed.success) {
    const details = parsed.error.issues
      .map((issue) => `${issue.path.join(".") || "<root>"}: ${issue.message}`)
      .join("; ");
    throw new BaselineError(`invalid baseline ${source}: ${details}`);
  }
  if (parsed.data.schemaVersion !== BASELINE_SCHEMA_VERSION) {
    throw new BaselineError(
      `baseline ${source} has unsupported schemaVersion ${parsed.data.schemaVersion} (expected ${BASELINE_SCHEMA_VERSION})`,
    );
  }
  return parsed.data;
}

/** Read a baseline from disk, validating schema version and JSON. */
export function readBaseline(file: string): BaselineDocument {
  let text: string;
  try {
    text = fs.readFileSync(file, "utf8");
  } catch (error) {
    const err = error as NodeJS.ErrnoException;
    if (err.code === "ENOENT") {
      throw new BaselineError(`baseline file not found: ${file}`);
    }
    throw new BaselineError(
      `cannot read baseline ${file}: ${err.code ?? err.message}`,
    );
  }
  return parseBaseline(text, file);
}

/**
 * Build a baseline document from a run's active findings. Hotspots, suppressed
 * findings and false positives are excluded. Entries are sorted by fingerprint
 * so the file is diff-friendly and never contain evidence or secret values.
 */
export function buildBaseline(
  findings: readonly Finding[],
  createdAt: string,
  tool: string,
): BaselineDocument {
  const entries: BaselineEntry[] = findings
    .filter(
      (finding) =>
        finding.status !== "suppressed" &&
        finding.status !== "false_positive" &&
        finding.kind !== "hotspot",
    )
    .map((finding) => ({
      fingerprint: finding.fingerprint,
      ruleId: finding.ruleId,
      file: finding.file,
      severity: finding.severity,
      title: finding.title,
    }))
    .sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));
  return {
    schemaVersion: BASELINE_SCHEMA_VERSION,
    createdAt,
    tool,
    entries,
  };
}

/** Serialize a baseline document as stable, human-diffable JSON. */
export function serializeBaseline(document: BaselineDocument): string {
  return `${JSON.stringify(document, null, 2)}\n`;
}

export interface BaselineComparison {
  new: number;
  existing: number;
  fixed: number;
}

/**
 * Compare a run's active findings against the baseline.
 *
 * - A finding whose fingerprint is in the baseline is `existing`.
 * - A finding whose fingerprint is not in the baseline is `new`.
 * - A baseline fingerprint with no matching finding is `fixed`.
 */
export function compareBaseline(
  baseline: BaselineDocument,
  findings: readonly Finding[],
): { states: Map<string, "new" | "existing">; counts: BaselineComparison; fixed: BaselineEntry[] } {
  const baselineFingerprints = new Set(
    baseline.entries.map((entry) => entry.fingerprint),
  );
  const active = findings.filter(
    (finding) =>
      finding.status !== "suppressed" &&
      finding.status !== "false_positive" &&
      finding.kind !== "hotspot",
  );
  const states = new Map<string, "new" | "existing">();
  const seen = new Set<string>();
  let existing = 0;
  let fresh = 0;
  for (const finding of active) {
    const isExisting = baselineFingerprints.has(finding.fingerprint);
    states.set(finding.fingerprint, isExisting ? "existing" : "new");
    if (isExisting) existing += 1;
    else fresh += 1;
    seen.add(finding.fingerprint);
  }
  const fixed = baseline.entries.filter(
    (entry) => !seen.has(entry.fingerprint),
  );
  return {
    states,
    counts: { new: fresh, existing, fixed: fixed.length },
    fixed,
  };
}