import fs from "node:fs";
import path from "node:path";
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import { anyGlobMatches } from "./glob.js";
import { resolveInside } from "./pathJail.js";

/** Control files that the inventory must never audit. */
export const IGNORE_FILE_NAME = ".code-audit-ignore";
export const BASELINE_FILE_NAME = ".code-audit-baseline.json";

const IsoDateSchema = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/, "expires must be an ISO date (YYYY-MM-DD)");

const IgnoreEntrySchema = z
  .object({
    fingerprint: z
      .string()
      .regex(/^[a-f0-9]{64}$/, "fingerprint must be 64 lowercase hex characters")
      .optional(),
    rule: z
      .string()
      .regex(/^[a-z0-9][a-z0-9-]*$/, "rule must be a rule id")
      .optional(),
    paths: z.array(z.string().min(1)).min(1).optional(),
    advisory: z.string().min(1).optional(),
    package: z.string().min(1).optional(),
    reason: z.string().min(1, "reason is required"),
    expires: IsoDateSchema.optional(),
  })
  .loose()
  .superRefine((entry, ctx) => {
    if (
      !entry.fingerprint &&
      !entry.rule &&
      !entry.paths &&
      !entry.advisory
    ) {
      ctx.addIssue({
        code: "custom",
        message:
          "entry needs at least one of fingerprint, rule, paths or advisory",
        path: ["fingerprint"],
      });
    }
  });

const IgnoreDocumentSchema = z.object({
  version: z.literal(1),
  ignore: z.array(IgnoreEntrySchema).default([]),
});

export type IgnoreEntry = z.infer<typeof IgnoreEntrySchema>;

export interface LoadedIgnoreFile {
  path: string;
  entries: IgnoreEntry[];
}

export class IgnoreFileError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IgnoreFileError";
  }
}

/**
 * Load and validate a `.code-audit-ignore` file. A missing file is not an
 * error (returns undefined). An invalid file throws `IgnoreFileError` naming
 * the entry index and the problem.
 */
export function loadIgnoreFile(file: string): LoadedIgnoreFile | undefined {
  let text: string;
  try {
    text = fs.readFileSync(file, "utf8");
  } catch (error) {
    const err = error as NodeJS.ErrnoException;
    if (err.code === "ENOENT") return undefined;
    throw new IgnoreFileError(
      `cannot read ignore file ${file}: ${err.code ?? err.message}`,
    );
  }

  let document: unknown;
  try {
    document = parseYaml(text);
  } catch (error) {
    throw new IgnoreFileError(
      `ignore file ${file} is not valid YAML: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }

  const parsed = IgnoreDocumentSchema.safeParse(document);
  if (!parsed.success) {
    const details = parsed.error.issues
      .map((issue) => {
        const entryIndex = issue.path[1];
        const where =
          typeof entryIndex === "number" ? `entry #${entryIndex}` : "<root>";
        const field = issue.path.slice(2).join(".") || "<root>";
        return `${where} ${field}: ${issue.message}`;
      })
      .join("; ");
    throw new IgnoreFileError(`invalid ignore file ${file}: ${details}`);
  }

  return { path: file, entries: parsed.data.ignore };
}

export interface IgnoreMatch {
  source: "ignore-file";
  entry: number;
  reason: string;
}

interface MatchInput {
  fingerprint: string;
  ruleId: string;
  file: string;
  advisoryId?: string;
  aliases?: readonly string[];
  packageName?: string;
}

/**
 * Find the first non-expired ignore entry that matches a finding or hotspot.
 * `today` is an ISO date string (YYYY-MM-DD); entries whose `expires` date is
 * in the past never match. Returns the entry index and reason on a match.
 */
export function matchIgnoreEntry(
  entries: readonly IgnoreEntry[],
  input: MatchInput,
  today: string,
): IgnoreMatch | undefined {
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    if (!entry) continue;
    if (entry.expires && entry.expires < today) continue;

    if (entry.fingerprint && entry.fingerprint === input.fingerprint) {
      return { source: "ignore-file", entry: index, reason: entry.reason };
    }
    if (entry.rule) {
      if (entry.rule !== input.ruleId && !scaRuleAliasMatches(entry.rule, input)) continue;
      const paths = entry.paths ?? [];
      if (paths.length === 0 || anyGlobMatches(paths, input.file)) {
        return { source: "ignore-file", entry: index, reason: entry.reason };
      }
      continue;
    }
    if (entry.advisory) {
      if (
        advisoryMatches(entry.advisory, input.advisoryId, input.aliases) &&
        (!entry.package ||
          normalizePackage(entry.package) === normalizePackage(input.packageName ?? ""))
      ) {
        return { source: "ignore-file", entry: index, reason: entry.reason };
      }
      continue;
    }
    if (entry.paths && anyGlobMatches(entry.paths, input.file)) {
      return { source: "ignore-file", entry: index, reason: entry.reason };
    }
  }
  return undefined;
}

/**
 * The rule id of an SCA finding embeds its advisory id (`sca-ghsa-...`), and
 * which of an advisory's names is used can change (a finding once reported as
 * `sca-pysec-2018-28` is now `sca-ghsa-x84v-xcm2-53pg`). A `rule:` entry
 * written for any of those names keeps matching: `sca-<id>` is accepted when
 * `<id>` is the finding's advisory id or one of its aliases.
 */
function scaRuleAliasMatches(entryRule: string, input: MatchInput): boolean {
  if (!/^sca-/i.test(input.ruleId)) return false;
  const match = /^sca-(.+)$/i.exec(entryRule.trim());
  if (!match) return false;
  return advisoryMatches(match[1] ?? "", input.advisoryId, input.aliases);
}

/**
 * An advisory entry matches when it equals the finding's advisory id or any of
 * its aliases (GHSA / CVE / PYSEC ...), compared case-insensitively.
 */
function advisoryMatches(
  entryAdvisory: string,
  advisoryId: string | undefined,
  aliases: readonly string[] | undefined,
): boolean {
  const wanted = entryAdvisory.trim().toUpperCase();
  if (!wanted) return false;
  if (advisoryId && advisoryId.toUpperCase() === wanted) return true;
  return (aliases ?? []).some((alias) => alias.toUpperCase() === wanted);
}

/** Package names compare case-insensitively with `-`, `_`, `.` treated alike. */
function normalizePackage(name: string): string {
  return name.trim().toLowerCase().replace(/[-_.]+/g, "-");
}

/**
 * Resolve the ignore file to use for a scan.
 *
 * - `noIgnoreFile` disables the file entirely.
 * - An explicit `ignoreFile` path must be absolute or resolve inside the root.
 * - Otherwise `<root>/.code-audit-ignore` is used when it exists.
 */
export function resolveIgnoreFile(options: {
  root: string;
  ignoreFile?: string;
  noIgnoreFile?: boolean;
}): string | undefined {
  if (options.noIgnoreFile) return undefined;
  if (options.ignoreFile) {
    const candidate = path.isAbsolute(options.ignoreFile)
      ? path.resolve(options.ignoreFile)
      : resolveInside(options.root, options.ignoreFile);
    return candidate;
  }
  const defaultFile = path.join(options.root, IGNORE_FILE_NAME);
  return fs.existsSync(defaultFile) ? defaultFile : undefined;
}