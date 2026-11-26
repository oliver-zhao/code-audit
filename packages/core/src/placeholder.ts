/*
 * Placeholder credentials
 * -----------------------
 * A detected secret whose value is an obvious placeholder is reported with
 * low confidence and the adjustment `placeholder-value`; it is never dropped,
 * because the value comes from the audited repository and a real password can
 * contain the word "example". The decision is made on the raw value, before
 * redaction, and the raw value is never stored.
 */

/**
 * Credentials that vendors print in their own documentation. Compared
 * case-sensitively against the whole value.
 */
export const DOCUMENTED_EXAMPLE_CREDENTIALS: ReadonlySet<string> = new Set([
  // AWS documentation: example access key id and secret access key.
  "AKIAIOSFODNN7EXAMPLE",
  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  // AWS documentation: second example pair (IAM user guide).
  "AKIAI44QH8DHBEXAMPLE",
  "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY",
]);

const PLACEHOLDER_WORDS =
  /redacted|example|change[-_]?me|dummy|sample|placeholder|replace[-_]?me|xxxx|your[-_ ][^\r\n]{0,60}?[-_ ]here|<[^<>\r\n]{1,80}>|\$\{[^{}\r\n]{0,80}\}/i;

/**
 * True when a secret value is an obvious placeholder: it contains `REDACTED`,
 * `EXAMPLE`, `changeme` / `change-me`, `dummy`, `sample`, `placeholder`,
 * `replace-me`, `xxxx`, `your-...-here`, `<...>` or `${...}`; it is one
 * character repeated; or it is a vendor-documented example credential.
 */
export function isPlaceholderSecret(rawValue: string): boolean {
  const value = rawValue.trim();
  if (value.length === 0) return false;
  if (DOCUMENTED_EXAMPLE_CREDENTIALS.has(value)) return true;
  if (value.length >= 2 && /^(.)\1+$/s.test(value)) return true;
  return PLACEHOLDER_WORDS.test(value);
}

/*
 * Whole-value classification for the generic `name = "value"` detector and
 * the URL-credential detector
 * ------------------------------------------------------------------------
 * These two detectors used to DROP every value that contained a placeholder
 * word, so `password = "example-Pr0d!"` was invisible. The policy now is:
 *
 * - `reference`: the value is a reference that something else fills in at
 *   run time (`${VAR}`, `{{ var }}`, `$(cmd)`, `$UPPER_CASE`, `%VAR%`, a
 *   format field such as `{name}` / `%s` / `%(name)s`, `os.environ[...]`,
 *   `process.env.X`, `env("X")`), possibly with a literal rest too short to
 *   be a credential. It is not a secret and is not reported.
 * - `placeholder`: the WHOLE value is a placeholder (`changeme`,
 *   `your-password-here`, `xxxx`, `<password>`, `example`, one repeated
 *   character, a vendor-documented example credential). It is reported with
 *   low confidence and the adjustment `placeholder-value`.
 * - `value`: everything else, including a value that merely contains a
 *   placeholder word next to other content (`example-Pr0d!`,
 *   `test_8f3kLq92x`). It is reported with the detector's normal confidence.
 */

export type SecretValueClass = "reference" | "placeholder" | "value";

/** Syntax that is substituted at run time. Bounded, no nested quantifiers. */
const REFERENCE_TOKENS =
  /\$\{[^{}\r\n]{0,120}\}|\{\{[^{}\r\n]{0,120}\}\}|\$\([^()\r\n]{0,120}\)|<%[^%\r\n]{0,120}%>|%\([A-Za-z_][A-Za-z0-9_]{0,60}\)[sd]|%[A-Z_][A-Z0-9_]{0,60}%|\$[A-Z_][A-Z0-9_]{0,60}(?![A-Za-z0-9_])|\{[A-Za-z0-9_.]{0,60}(?:![rsa])?(?::[^{}\r\n]{0,20})?\}|%[sd](?![A-Za-z0-9])/g;

/** The whole value is a call that reads the environment. */
const ENVIRONMENT_CALL =
  /^(?:os\.environ(?:\.get)?|os\.getenv|getenv|process\.env|System\.getenv|ENV|env)\s*[.[(]/;

/** Words that say "this is not the real value". */
const PLACEHOLDER_MARKERS = [
  "changeme", "changeit", "changethis", "change", "changed", "replaceme", "replace",
  "placeholder", "example", "sample", "dummy", "fake", "testing", "test", "demo",
  "mock", "todo", "fixme", "tbd", "redacted", "removed", "your", "insert", "xxx",
  "foobar", "foo", "bar", "baz", "lorem", "ipsum", "notreal", "notasecret",
];

/** Words that may surround a marker without making the value a real one. */
const PLACEHOLDER_FILLERS = [
  "password", "passphrase", "passwd", "pass", "pwd", "secret", "token", "apikey",
  "api", "key", "auth", "access", "private", "public", "client", "credentials",
  "credential", "username", "user", "name", "admin", "root", "value", "string",
  "here", "this", "that", "the", "with", "real", "actual", "goes", "please", "enter",
  "put", "add", "use", "own", "new", "old", "some", "any", "default", "temp", "tmp",
  "development", "dev", "local", "insecure", "unsafe", "super", "database", "db",
  "app", "service", "account", "me", "my", "it", "in", "to", "be", "is", "not",
  "set", "for", "of", "and", "or", "id", "x", "now", "later",
];

/** The whole value is the name of a credential, not a credential. */
const CREDENTIAL_WORD =
  /^(?:pass(?:word|wd|phrase)?|pwd|secret|token|key|api[-_]?key|user(?:name)?|redacted)$/i;

const PLACEHOLDER_VOCABULARY = [...PLACEHOLDER_MARKERS, ...PLACEHOLDER_FILLERS];

/**
 * Split a value into vocabulary words, separators and digits. Returns
 * undefined when some part of it is none of these; otherwise whether a marker
 * word or a filler word was needed. Dynamic programming, linear in the length
 * of the value times the vocabulary.
 */
function placeholderWords(value: string): { marker: boolean } | undefined {
  const text = value.toLowerCase();
  if (text.length === 0 || text.length > 120) return undefined;
  // best[i]: undefined = position not reachable, true = reachable with a
  // marker word, false = reachable without one.
  const best: Array<boolean | undefined> = new Array<boolean | undefined>(text.length + 1).fill(undefined);
  best[0] = false;
  for (let index = 0; index < text.length; index += 1) {
    const state = best[index];
    if (state === undefined) continue;
    const reach = (next: number, marker: boolean): void => {
      if (best[next] !== true) best[next] = marker;
    };
    const char = text[index] as string;
    if (!/[a-z]/.test(char)) reach(index + 1, state);
    for (let word = 0; word < PLACEHOLDER_VOCABULARY.length; word += 1) {
      const candidate = PLACEHOLDER_VOCABULARY[word] as string;
      if (text.startsWith(candidate, index)) {
        reach(index + candidate.length, state || word < PLACEHOLDER_MARKERS.length);
      }
    }
  }
  const end = best[text.length];
  return end === undefined ? undefined : { marker: end };
}

export interface SecretValueOptions {
  /**
   * Shortest literal text (letters and digits) that can be a credential for
   * this detector: 8 for `name = "value"`, 3 for a URL password. A reference
   * with a shorter literal rest is still a reference.
   */
  minLiteral?: number;
  /**
   * Also treat a value that is exactly one credential word (`password`,
   * `pass`, `secret`, `token`, ...) as a placeholder. Used for URL passwords,
   * where `https://user:password@host` is the documentation form. A longer
   * value made of such words (`password123`, `secretpassword`) is a weak
   * password, not a placeholder.
   */
  credentialWords?: boolean;
}

/** True when the whole value is a placeholder; see the policy above. */
export function isWholeValuePlaceholder(
  rawValue: string,
  options: SecretValueOptions = {},
): boolean {
  const value = rawValue.trim();
  if (value.length === 0) return true;
  if (DOCUMENTED_EXAMPLE_CREDENTIALS.has(value)) return true;
  if (value.length >= 2 && /^(.)\1+$/s.test(value)) return true;
  // Masking characters only: xxxx-xxxx, ********, ....
  if (/^[xX*#.?_\-•]+$/.test(value)) return true;
  if (/^<[^<>\r\n]{0,80}>$/.test(value) || /^\[[^[\]\r\n]{0,80}\]$/.test(value)) return true;
  if (options.credentialWords === true && CREDENTIAL_WORD.test(value)) return true;
  // More than a few digits is content of its own (`test12345678`).
  if ((value.match(/\d/g) ?? []).length > 4) return false;
  const words = placeholderWords(value);
  if (!words) return false;
  return words.marker;
}

/** Classify a detected value; see the policy above. */
export function classifySecretValue(
  rawValue: string,
  options: SecretValueOptions = {},
): SecretValueClass {
  const value = rawValue.trim();
  if (ENVIRONMENT_CALL.test(value)) return "reference";
  const rest = value.replace(REFERENCE_TOKENS, "");
  if (rest !== value) {
    const literal = rest.replace(/[^A-Za-z0-9]+/g, "");
    if (literal.length < (options.minLiteral ?? 8)) return "reference";
    return isWholeValuePlaceholder(rest, options) ? "placeholder" : "value";
  }
  return isWholeValuePlaceholder(value, options) ? "placeholder" : "value";
}
