import fs from "node:fs";
import { createFinding, type Finding, type Severity } from "./finding.js";
import type { InventoryFile } from "./inventory.js";

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

const GENERIC_ASSIGNMENT =
  /\b(password|passwd|pwd|secret|api[_-]?key|auth[_-]?token|token)\b\s*[:=]\s*(["'])([^"'\r\n]{8,})\2/gi;

const PLACEHOLDER_PATTERN =
  /(xxx|changeme|change_me|example|placeholder|dummy|sample|replace[_-]?me|your[_-]|todo|fixme|<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\})/i;

const KNOWN_SECRET_PATTERNS = SECRET_PATTERNS.filter(
  (pattern) => pattern.id !== "secret-generic-assignment",
).map((pattern) => pattern.pattern);

export function redactSecret(value: string): string {
  if (value.length <= 8) return "*".repeat(Math.max(4, value.length));
  const head = value.slice(0, 4);
  const tail = value.slice(-4);
  const masked = "*".repeat(Math.min(24, Math.max(4, value.length - 8)));
  return `${head}${masked}${tail}`;
}

/**
 * Redact only the secret substrings on a line, preserving surrounding code.
 * Used by the read/search tools so normal source text stays readable.
 */
export function redactSecretsInText(value: string): string {
  let output = value;
  for (const pattern of KNOWN_SECRET_PATTERNS) {
    pattern.lastIndex = 0;
    output = output.replace(pattern, (match) => redactSecret(match));
  }
  output = output.replace(
    GENERIC_ASSIGNMENT,
    (full, _key: string, _quote: string, secret: string) =>
      isPlaceholder(secret) ? full : full.replace(secret, redactSecret(secret)),
  );
  return output;
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
): Finding {
  return createFinding({
    ruleId,
    title,
    category: "secrets",
    severity,
    cwe,
    confidence: "high",
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

export function scanSecrets(files: InventoryFile[]): SecretScanResult {
  const findings: Finding[] = [];
  const warnings: string[] = [];
  let scannedFiles = 0;

  for (const file of files) {
    if (!file.scannable) continue;

    let content: string;
    try {
      content = fs.readFileSync(file.absPath, "utf8");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      warnings.push(`cannot read ${file.relPath}: ${message}`);
      continue;
    }
    scannedFiles += 1;
    const lines = content.split(/\r?\n/);

    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index] ?? "";
      if (line.trim().length === 0) continue;

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
            : line.trim().replace(secret, redactSecret(secret));
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

      GENERIC_ASSIGNMENT.lastIndex = 0;
      let generic: RegExpExecArray | null;
      while ((generic = GENERIC_ASSIGNMENT.exec(line)) !== null) {
        const value = generic[3] ?? "";
        if (isPlaceholder(value)) continue;
        if (matchesKnownSecret(value)) continue;
        if (shannonEntropy(value) < 3.0) continue;

        const definition = SECRET_PATTERNS.find(
          (pattern) => pattern.id === "secret-generic-assignment",
        );
        if (!definition) continue;
        const evidence = line.trim().replace(value, redactSecret(value));
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
    }
  }

  return { findings, warnings, scannedFiles };
}
