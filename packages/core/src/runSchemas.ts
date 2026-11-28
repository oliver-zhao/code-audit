/**
 * Schemas of the JSON files in a run directory and of `.audit/index.json`.
 *
 * These files sit inside the audited repository, so their content is not
 * trusted: every one is parsed with a size limit, a nesting limit and a zod
 * schema before anything else looks at it.
 */
import { z } from "zod";
import { FindingSchema, SEVERITIES } from "./finding.js";
import { printable } from "./safeFs.js";

/** Largest JSON file read from a run directory. */
export const MAX_RUN_FILE_BYTES = 128 * 1024 * 1024;
/** Deepest nesting accepted in a JSON file of a run directory. */
export const MAX_JSON_DEPTH = 64;

const RUN_PHASES = ["running", "complete", "failed"] as const;
const VERDICT_STATUS_VALUES = [
  "confirmed",
  "likely",
  "needs_review",
  "false_positive",
  "proof_gap",
] as const;
const FINGERPRINT = /^[a-f0-9]{64}$/;

export const RunStateSchema = z.object({
  schemaVersion: z.literal(1),
  runId: z.string().min(1).max(200),
  root: z.string(),
  runDir: z.string(),
  phase: z.enum(RUN_PHASES),
  startedAt: z.string(),
  updatedAt: z.string(),
  finishedAt: z.string().optional(),
  progress: z
    .object({
      engine: z.string().optional(),
      files: z.number().optional(),
      rules: z.number().optional(),
      dependencies: z.number().optional(),
    })
    .optional(),
  error: z.string().optional(),
  warnings: z.array(z.string()).optional(),
});

export const RunIndexEntrySchema = z.object({
  runId: z.string().min(1).max(200),
  runDir: z.string(),
  root: z.string(),
  phase: z.enum(RUN_PHASES),
  startedAt: z.string(),
  updatedAt: z.string(),
});

export const RunIndexSchema = z.object({
  schemaVersion: z.literal(1),
  runs: z.array(RunIndexEntrySchema).max(100_000),
});

const BaselineFixedEntrySchema = z
  .object({
    fingerprint: z.string(),
    ruleId: z.string(),
    file: z.string(),
    severity: z.string(),
    title: z.string(),
  })
  .passthrough();

/**
 * run.json. Only the fields a later command reads are constrained; the rest
 * (counts, inventory, engine details) is carried along untouched and never
 * interpreted.
 */
export const RunRecordSchema = z
  .object({
    runId: z.string().min(1).max(200).optional(),
    tool: z
      .object({
        name: z.string().optional(),
        version: z.string().optional(),
        node: z.string().optional(),
      })
      .passthrough()
      .optional(),
    args: z
      .object({
        root: z.string().optional(),
        resolvedRoot: z.string().optional(),
        profile: z.string().optional(),
        lang: z.string().optional(),
      })
      .passthrough()
      .optional(),
    startedAt: z.string().optional(),
    finishedAt: z.string().optional(),
    durationMs: z.number().optional(),
    rulesCount: z.number().optional(),
    rulesDir: z.string().optional(),
    rulesHash: z.string().optional(),
    warnings: z.array(z.string()).optional(),
    baseline: z
      .object({
        path: z.string(),
        entries: z.number(),
        new: z.number(),
        existing: z.number(),
        fixed: z.number(),
      })
      .optional(),
    baselineFixed: z.array(BaselineFixedEntrySchema).optional(),
    scope: z.object({ since: z.string(), changedFiles: z.number() }).optional(),
    pathContext: z.record(z.number()).optional(),
  })
  .passthrough();

const PATH_CONTEXT = z.enum(["test", "docs", "example", "vendored", "generated"]);

export const CoverageSchema = z
  .object({
    root: z.string(),
    stats: z.object({
      files: z.number(),
      scannedFiles: z.number(),
      partialFiles: z.number().optional(),
      skippedFiles: z.number(),
      loc: z.number(),
    }),
    languages: z.record(z.object({ files: z.number(), loc: z.number() })),
    scannedFiles: z.array(
      z.object({
        path: z.string(),
        language: z.string(),
        loc: z.number(),
        engines: z.array(z.string()),
        pathContext: PATH_CONTEXT.optional(),
      }),
    ),
    skipped: z.array(z.object({ path: z.string(), reason: z.string() })),
    manifests: z.array(
      z.object({ relPath: z.string(), type: z.string(), isLockfile: z.boolean() }).passthrough(),
    ),
    engines: z.array(
      z.object({
        name: z.string(),
        enabled: z.boolean(),
        status: z.string(),
        detail: z.string().optional(),
        durationMs: z.number().optional(),
      }),
    ),
    rulesCount: z.number(),
    warnings: z.array(z.string()),
    suppressed: z.array(
      z.object({ ruleId: z.string(), file: z.string(), line: z.number(), reason: z.string() }),
    ),
    pathContext: z
      .object({
        lowering: z.boolean(),
        files: z.object({
          test: z.number(),
          docs: z.number(),
          example: z.number(),
          vendored: z.number(),
          generated: z.number(),
        }),
      })
      .optional(),
    scope: z
      .object({
        since: z.string().nullable(),
        changedFiles: z.number(),
        outOfScope: z.number(),
      })
      .optional(),
  })
  .passthrough();

export const FindingsEnvelopeSchema = z
  .object({
    findings: z.array(FindingSchema).default([]),
    hotspots: z.array(FindingSchema).default([]),
  })
  .passthrough();

export const AgentFindingsSchema = z
  .object({
    findings: z.array(FindingSchema).default([]),
  })
  .passthrough();

/** Most steps in a verdict `trace`. */
export const MAX_TRACE_STEPS = 20;
/** Shortest `missing` text of a `proof_gap` verdict. */
export const MIN_MISSING_LENGTH = 20;

const LOCATION_FILE = z.string().min(1).max(1000);
const LOCATION_LINE = z.number().int().positive();
const NOTE = z.string().max(2000);

export const TraceStepSchema = z.object({
  file: LOCATION_FILE,
  line: LOCATION_LINE,
  role: z.enum(["source", "propagation", "sink"]),
  note: NOTE.optional(),
});

export const VerdictConditionsSchema = z.object({
  auth: z.enum(["none", "user", "admin", "unknown"]).optional(),
  userInteraction: z.boolean().optional(),
  note: NOTE.optional(),
});

export const VerdictControlSchema = z.object({
  file: LOCATION_FILE,
  line: LOCATION_LINE,
  note: NOTE,
});

/** Longest rationale, note or `missing` text stored with a verdict. */
export const MAX_VERDICT_TEXT = 4000;
/** Most verdict entries (primary and independent) stored for one finding. */
export const MAX_VERDICTS_PER_FINDING = 50;

/**
 * One entry of verdicts.json: what one reviewer decided about one
 * fingerprint, stored once (append-only; the current state is computed from
 * all entries of the fingerprint). Every field after `reviewer` is new in
 * schemaVersion 2 and optional, so version 1 entries read unchanged.
 */
export const VerdictRecordSchema = z.object({
  fingerprint: z.string().regex(FINGERPRINT),
  findingId: z.string().optional(),
  status: z.enum(VERDICT_STATUS_VALUES),
  rationale: z.string(),
  evidenceLines: z.array(z.string()).optional(),
  at: z.string(),
  actor: z.string().optional(),
  reviewer: z.string().optional(),
  /** Role of the reviewer who wrote this entry; absent (v1) means primary. */
  role: z.enum(["primary", "independent"]).optional(),
  /** For role independent: how independent the review was. */
  independence: z.enum(["subagent", "same-session"]).optional(),
  /** A primary verdict that knowingly replaced another reviewer's reviewed decision. */
  replace: z.boolean().optional(),
  trace: z.array(TraceStepSchema).max(MAX_TRACE_STEPS).optional(),
  conditions: VerdictConditionsSchema.optional(),
  control: VerdictControlSchema.optional(),
  missing: z.string().max(MAX_VERDICT_TEXT).optional(),
  cwe: z.string().regex(/^CWE-\d{1,6}$/).optional(),
  severityOverride: z
    .object({ severity: z.enum(SEVERITIES), reason: z.string().max(MAX_VERDICT_TEXT) })
    .optional(),
});

/** Version 1 and 2 are read; version 2 is written. */
export const VERDICTS_SCHEMA_VERSION = 2;

export const VerdictsSchema = z.object({
  schemaVersion: z.union([z.literal(1), z.literal(2)]),
  runId: z.string(),
  /**
   * Set by `audit_start` with `strict_evidence`: verdicts of this run require
   * structured evidence unless a call says otherwise. It can only make the
   * checks stricter than the default.
   */
  strictEvidence: z.boolean().optional(),
  entries: z.array(VerdictRecordSchema),
});

export class RunFileError extends Error {
  readonly code = "RUN_STORE_CORRUPT";

  constructor(message: string) {
    super(message);
    this.name = "RunFileError";
  }
}

function assertDepth(text: string, label: string): void {
  let depth = 0;
  let inString = false;
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    if (inString) {
      if (code === 92) index += 1; // backslash: skip the escaped character
      else if (code === 34) inString = false;
    } else if (code === 34) {
      inString = true;
    } else if (code === 123 || code === 91) {
      depth += 1;
      if (depth > MAX_JSON_DEPTH) {
        throw new RunFileError(`${label} is nested deeper than ${MAX_JSON_DEPTH} levels`);
      }
    } else if (code === 125 || code === 93) {
      depth -= 1;
    }
  }
}

/**
 * Parse and validate the text of a run file. Throws `RunFileError` with a
 * one-line message; the text of the file is never echoed beyond a short,
 * printable excerpt of what zod reports.
 */
export function parseRunFile<S extends z.ZodTypeAny>(
  text: string,
  schema: S,
  label: string,
): z.infer<S> {
  assertDepth(text, label);
  let raw: unknown;
  try {
    // An own `__proto__` key would become the prototype of a copied object.
    raw = JSON.parse(text, (key, value: unknown) => (key === "__proto__" ? undefined : value));
  } catch {
    throw new RunFileError(`${label} is not valid JSON`);
  }
  const parsed = schema.safeParse(raw);
  if (!parsed.success) {
    const issues = parsed.error.issues.slice(0, 3).map((issue) => {
      const where = issue.path.slice(0, 6).join(".") || "<root>";
      return `${printable(where, 80)}: ${printable(issue.message, 120)}`;
    });
    const more = parsed.error.issues.length - issues.length;
    throw new RunFileError(
      `${label} is not a valid code-audit file (${issues.join("; ")}${more > 0 ? `; ${more} more` : ""})`,
    );
  }
  return parsed.data as z.infer<S>;
}
