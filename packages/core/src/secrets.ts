import fs from "node:fs";
import { createFinding, type Confidence, type Finding, type Severity } from "./finding.js";
import type { InventoryFile } from "./inventory.js";
import {
  LINE_MASK_ALL,
  LINE_MASK_STRINGS,
  URL_CREDENTIALS,
  maskSecret,
  redactEvidence,
  redactLine,
  sensitiveLines,
  splitLines,
  type RedactRange,
} from "./redact.js";

interface SecretPattern {
  id: string;
  title: string;
  severity: Severity;
  cwe: string;
  pattern: RegExp;
  remediation: string;
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: "secret-aws-access-key",
    title: "Hardcoded AWS access key",
    severity: "high",
    cwe: "CWE-798",
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    remediation: "Rotate the key in AWS IAM immediately, switch to environment variables or an instance role, and purge the key from Git history.",
  },
  {
    id: "secret-github-token",
    title: "Hardcoded GitHub token",
    severity: "high",
    cwe: "CWE-798",
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b/g,
    remediation: "Revoke the token in GitHub settings, switch to short-lived credentials or a GitHub App, and purge it from commit history.",
  },
  {
    id: "secret-slack-token",
    title: "Hardcoded Slack token",
    severity: "high",
    cwe: "CWE-798",
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
    remediation: "Revoke the token in the Slack admin console and store credentials in a secrets manager.",
  },
  {
    id: "secret-private-key",
    title: "Private key block committed to the repository",
    severity: "critical",
    cwe: "CWE-798",
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    remediation: "Revoke and regenerate the key immediately, move it to a secrets manager, and remove it from Git history.",
  },
  {
    id: "secret-generic-assignment",
    title: "Possible hardcoded password or API key assignment",
    severity: "high",
    cwe: "CWE-798",
    pattern: /__generic_placeholder__/g,
    remediation: "Move credentials to environment variables or a secrets manager, rotate exposed values, and never commit plaintext credentials.",
  },
];

const URL_CREDENTIALS_DEFINITION = {
  id: "secret-url-credentials",
  title: "Credentials embedded in a URL",
  severity: "high" as Severity,
  cwe: "CWE-798",
  remediation:
    "Remove the credentials from the URL, rotate them, and supply them through the environment, a keyring or the package manager's credential store (for pip: PIP_INDEX_URL from a secret, or a netrc file).",
};

/** A URL password that is a variable reference or an obvious dummy. */
function isUrlPasswordPlaceholder(value: string): boolean {
  if (value.length < 3) return true;
  if (/^[$%]/.test(value) || /^\*+$/.test(value) || /[{}]/.test(value)) return true;
  if (/^(?:pass(?:word|wd)?|pwd|secret|token|user(?:name)?|redacted)$/i.test(value)) return true;
  if (PLACEHOLDER_PATTERN.test(value)) return true;
  return false;
}

/**
 * `name = "value"` / `"name": "value"` where the name is, or ends with, a
 * credential word. Group 1 is the compound prefix (`db_`), group 3 the quote
 * that closes a quoted key, group 5 the value.
 */
const GENERIC_ASSIGNMENT =
  /(?<![A-Za-z0-9])((?:[A-Za-z0-9]{1,40}[_.-]){0,6})(password|passwd|pwd|secret|api[_-]?key|auth[_-]?token|token)(["']?)\s*[:=]\s*(["'])([^"'\r\n]{8,})\4/gi;

const PLACEHOLDER_PATTERN =
  /(xxx|changeme|change_me|example|placeholder|dummy|sample|replace[_-]?me|your[_-]|todo|fixme|<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\})/i;

const KNOWN_SECRET_PATTERNS = SECRET_PATTERNS.filter(
  (pattern) => pattern.id !== "secret-generic-assignment",
).map((pattern) => pattern.pattern);

/**
 * Mask a secret value: fully when shorter than 16 characters, otherwise all
 * but the first 2 and last 2 characters. See `maskSecret`.
 */
export function redactSecret(value: string): string {
  return maskSecret(value);
}

/**
 * Redact the secrets on a line, preserving surrounding code. Alias of
 * `redactLine`, kept for callers that have no file context.
 */
export function redactSecretsInText(value: string): string {
  return redactLine(value);
}

/** True when a line starts or ends a PEM private-key block. */
export function isPrivateKeyBoundary(value: string): boolean {
  return /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----|-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/.test(
    value,
  );
}

function isPlaceholder(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length < 8) return true;
  if (PLACEHOLDER_PATTERN.test(trimmed)) return true;
  if (/^(.)\1+$/.test(trimmed)) return true;
  return false;
}

/**
 * Confidence of a generic-assignment finding on a compound name
 * (`db_password`) or a quoted key (`"password": ...`). Lower than for a bare
 * `password = "..."`: such names also hold hashes and sample data, and a more
 * specific rule on the same line stays the primary finding after merging.
 */
const BROADENED_CONFIDENCE: Confidence = "medium";

export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const char of value) {
    counts.set(char, (counts.get(char) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

function matchesKnownSecret(value: string): boolean {
  return KNOWN_SECRET_PATTERNS.some((pattern) => {
    pattern.lastIndex = 0;
    return pattern.test(value);
  });
}

export interface SecretScanResult {
  findings: Finding[];
  warnings: string[];
  scannedFiles: number;
}

function makeSecretFinding(
  file: InventoryFile,
  lineNumber: number,
  ruleId: string,
  title: string,
  severity: Severity,
  cwe: string,
  evidence: string,
  remediation: string,
  confidence: Confidence = "high",
): Finding {
  return createFinding({
    ruleId,
    title,
    category: "secrets",
    severity,
    cwe,
    confidence,
    owasp: "A07:2021",
    file: file.relPath,
    startLine: lineNumber,
    evidence,
    remediation,
    message: "Possible plaintext credential detected; evidence is redacted in every report.",
    provenance: { engine: "builtin-secrets", rule: ruleId },
    references: [cwe, "OWASP A07:2021"],
  });
}

/**
 * A value assigned to a compound name (`db_password`) or a quoted key
 * (`"password": ...`) that is clearly not a credential: a reference to the
 * environment, a format template, a constant name, a path or URL, prose.
 */
function isNonSecretValue(value: string): boolean {
  const trimmed = value.trim();
  if (/^(?:none|null|nil|undefined|true|false)$/i.test(trimmed)) return true;
  if (/os\.environ|process\.env|getenv|\$[A-Za-z_({]|%\(?\w*\)?[sd]|\{[\w.:!]*\}/.test(trimmed)) {
    return true;
  }
  if (/\s/.test(trimmed)) return true;
  if (/^(?:[a-z]+:)?\/\/|^[./~]|^[A-Za-z]:\\/.test(trimmed)) return true;
  // A field, header or setting name rather than a value: letters with
  // separators only (csrf_token, X-Auth-Token, password_confirmation).
  if (/^[A-Za-z]+(?:[_.:-][A-Za-z]+)*$/.test(trimmed)) return true;
  return false;
}

export interface SecretScanOptions {
  /**
   * Column ranges (per 1-based line) that a `redactEvidence` rule matched in a
   * file; they are masked in the evidence of secret findings on that line too.
   */
  lineRedactions?: (file: string) => Map<number, RedactRange[]> | undefined;
}

/**
 * Scan the inventory for plaintext credentials.
 *
 * - `scannable` files (everything except generated lockfiles, so including
 *   requirements files and manifests) get every detector.
 * - Generated lockfiles get the high-confidence detectors only: private-key
 *   blocks, vendor token formats and credentials embedded in a URL. The
 *   generic `password = "..."` heuristic is skipped there. None of the
 *   high-confidence formats can match a hex digest or base64 integrity hash,
 *   so lockfiles produce no hash false positives.
 * - Any other non-scannable file is not read.
 *
 * Evidence is always redacted with `redactLine`, so other secrets on the same
 * line are masked as well.
 *
 * Fingerprints are computed from the redacted evidence. A value shorter than
 * 16 characters is masked completely, so two different secrets of the same
 * length assigned to the same name produce the same evidence; they still get
 * distinct findings because `disambiguateFingerprints` numbers the occurrences
 * by line. A rotated secret of the same length therefore keeps its
 * fingerprint: a baseline or ignore entry for the old value also covers the
 * new one.
 */
export function scanSecrets(
  files: InventoryFile[],
  options: SecretScanOptions = {},
): SecretScanResult {
  const findings: Finding[] = [];
  const warnings: string[] = [];
  let scannedFiles = 0;

  for (const file of files) {
    if (!file.scannable && !file.isLockfile) continue;
    const highConfidenceOnly = !file.scannable;

    let content: string;
    try {
      content = fs.readFileSync(file.absPath, "utf8");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      warnings.push(`cannot read ${file.relPath}: ${message}`);
      continue;
    }
    scannedFiles += 1;
    const lines = splitLines(content);
    const flags = sensitiveLines(lines);
    const ruleRanges = options.lineRedactions?.(file.relPath);

    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index] ?? "";
      if (line.trim().length === 0) continue;

      const evidenceOf = (start: number, end: number): string => {
        if (flags[index] === LINE_MASK_ALL) return "[private key content redacted]";
        return redactEvidence(line, {
          file: file.relPath,
          column: start,
          ranges: [{ start, end }, ...(ruleRanges?.get(index + 1) ?? [])],
          maskAllStrings: flags[index] === LINE_MASK_STRINGS,
        });
      };

      for (const definition of SECRET_PATTERNS) {
        if (definition.id === "secret-generic-assignment") continue;
        definition.pattern.lastIndex = 0;
        const match = definition.pattern.exec(line);
        if (!match) continue;
        const secret = match[0];
        if (isPlaceholder(secret)) continue;
        const evidence =
          definition.id === "secret-private-key"
            ? "[private key block detected; content redacted]"
            : evidenceOf(match.index, match.index + secret.length);
        findings.push(
          makeSecretFinding(
            file,
            index + 1,
            definition.id,
            definition.title,
            definition.severity,
            definition.cwe,
            evidence,
            definition.remediation,
          ),
        );
      }

      // matchAll works on a copy of the regex, so the redaction helpers
      // (which reuse these global patterns) cannot disturb the iteration.
      for (const url of line.matchAll(URL_CREDENTIALS)) {
        const password = url[2] ?? "";
        if (isUrlPasswordPlaceholder(password)) continue;
        // A vendor token in the URL is already reported by its own detector.
        if (matchesKnownSecret(password)) continue;
        const start = (url.index ?? 0) + (url[1] ?? "").length;
        findings.push(
          makeSecretFinding(
            file,
            index + 1,
            URL_CREDENTIALS_DEFINITION.id,
            URL_CREDENTIALS_DEFINITION.title,
            URL_CREDENTIALS_DEFINITION.severity,
            URL_CREDENTIALS_DEFINITION.cwe,
            evidenceOf(start, start + password.length),
            URL_CREDENTIALS_DEFINITION.remediation,
          ),
        );
        break;
      }

      if (highConfidenceOnly) continue;
      if (line.length > 20_000) continue;

      for (const generic of line.matchAll(GENERIC_ASSIGNMENT)) {
        const value = generic[5] ?? "";
        if (isPlaceholder(value)) continue;
        if (matchesKnownSecret(value)) continue;
        if (shannonEntropy(value) < 3.0) continue;
        // `db_password = "..."` and `"password": "..."` are matched since the
        // broadened pattern; they carry more name-like and template values
        // than a bare `password = "..."`, so those are filtered out.
        const prefix = generic[1] ?? "";
        const broadened = prefix.endsWith("_") || (generic[3] ?? "") !== "";
        if (broadened && isNonSecretValue(value)) continue;

        const definition = SECRET_PATTERNS.find(
          (pattern) => pattern.id === "secret-generic-assignment",
        );
        if (!definition) continue;
        const start = (generic.index ?? 0) + generic[0].length - 1 - value.length;
        findings.push(
          makeSecretFinding(
            file,
            index + 1,
            definition.id,
            definition.title,
            definition.severity,
            definition.cwe,
            evidenceOf(start, start + value.length),
            definition.remediation,
            broadened ? BROADENED_CONFIDENCE : "high",
          ),
        );
      }
    }
  }

  return { findings, warnings, scannedFiles };
}
