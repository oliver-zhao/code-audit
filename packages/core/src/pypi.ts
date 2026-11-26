/**
 * PEP 440 version parsing and comparison.
 *
 * `compareVersions` in sca.ts is a generic dotted comparator. Python packages
 * need the full PEP 440 ordering: epochs, pre-releases (a/b/rc), post-releases,
 * dev releases, local versions, a leading `v`, and trailing-zero equality
 * (`1.0 == 1.0.0`).
 */

// Numeric parts are bigint: date-style versions such as 20240101123456789012
// exceed Number.MAX_SAFE_INTEGER and must still compare exactly.
interface PreRelease {
  rank: number;
  n: bigint;
}

interface LocalSegment {
  numeric: boolean;
  value: bigint | string;
}

interface ParsedVersion {
  epoch: bigint;
  release: bigint[];
  pre: PreRelease | null;
  post: bigint | null;
  dev: bigint | null;
  local: LocalSegment[] | null;
}

/** Longer strings are not versions; refusing them bounds the regex work. */
const MAX_VERSION_LENGTH = 256;

function compareBig(a: bigint, b: bigint): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Locale-independent string order (UTF-16 code units). */
function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

const VERSION_PATTERN = new RegExp(
  [
    "^\\s*v?",
    "(?:(?<epoch>\\d+)!)?",
    "(?<release>\\d+(?:\\.\\d+)*)",
    "(?<pre>[-_.]?(?<prekind>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?<pren>\\d+)?)?",
    "(?<post>-(?<postn1>\\d+)|[-_.]?(?<postkind>post|rev|r)[-_.]?(?<postn2>\\d+)?)?",
    "(?<dev>[-_.]?dev[-_.]?(?<devn>\\d+)?)?",
    "(?:\\+(?<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?",
    "\\s*$",
  ].join(""),
  "i",
);

const PRE_RANK: Record<string, number> = {
  a: 0,
  alpha: 0,
  b: 1,
  beta: 1,
  c: 2,
  rc: 2,
  pre: 2,
  preview: 2,
};

function parseLocal(local: string | undefined): LocalSegment[] | null {
  if (!local) return null;
  return local.split(/[-_.]/).map((part) =>
    /^\d+$/.test(part)
      ? { numeric: true, value: BigInt(part) }
      : { numeric: false, value: part.toLowerCase() },
  );
}

export function parsePypiVersion(version: string): ParsedVersion | undefined {
  if (typeof version !== "string" || version.length > MAX_VERSION_LENGTH) return undefined;
  const match = VERSION_PATTERN.exec(version);
  if (!match?.groups) return undefined;
  const groups = match.groups;
  const release = (groups.release ?? "0").split(".").map((part) => BigInt(part));
  const preKind = groups.prekind?.toLowerCase();
  const pre: PreRelease | null = preKind
    ? { rank: PRE_RANK[preKind] ?? 2, n: BigInt(groups.pren ?? 0) }
    : null;
  const post = groups.post
    ? BigInt(groups.postn1 ?? groups.postn2 ?? 0)
    : null;
  const dev = groups.dev ? BigInt(groups.devn ?? 0) : null;
  return {
    epoch: BigInt(groups.epoch ?? 0),
    release,
    pre,
    post,
    dev,
    local: parseLocal(groups.local),
  };
}

function stripTrailingZeros(release: bigint[]): bigint[] {
  const copy = [...release];
  while (copy.length > 1 && copy[copy.length - 1] === 0n) copy.pop();
  return copy;
}

type PreKey =
  | { kind: "neg" }
  | { kind: "pos" }
  | { kind: "value"; rank: number; n: bigint };

function preKey(parsed: ParsedVersion): PreKey {
  if (parsed.pre) return { kind: "value", rank: parsed.pre.rank, n: parsed.pre.n };
  if (parsed.post === null && parsed.dev !== null) return { kind: "neg" };
  return { kind: "pos" };
}

function comparePre(a: PreKey, b: PreKey): number {
  if (a.kind === "neg" && b.kind === "neg") return 0;
  if (a.kind === "neg") return -1;
  if (b.kind === "neg") return 1;
  if (a.kind === "pos" && b.kind === "pos") return 0;
  if (a.kind === "pos") return 1;
  if (b.kind === "pos") return -1;
  if (a.rank !== b.rank) return a.rank < b.rank ? -1 : 1;
  if (a.n !== b.n) return a.n < b.n ? -1 : 1;
  return 0;
}

function compareLocal(
  a: LocalSegment[] | null,
  b: LocalSegment[] | null,
): number {
  if (a === null && b === null) return 0;
  if (a === null) return -1;
  if (b === null) return 1;
  const length = Math.max(a.length, b.length);
  for (let index = 0; index < length; index += 1) {
    const left = a[index];
    const right = b[index];
    if (left === undefined) return -1;
    if (right === undefined) return 1;
    if (left.numeric && right.numeric) {
      const compared = compareBig(left.value as bigint, right.value as bigint);
      if (compared !== 0) return compared;
      continue;
    }
    if (left.numeric) return 1;
    if (right.numeric) return -1;
    const compared = compareText(String(left.value), String(right.value));
    if (compared !== 0) return compared;
  }
  return 0;
}

/**
 * Compare two version strings using PEP 440 ordering. Returns a negative
 * number when `a` sorts before `b`, zero when they are equal, and a positive
 * number when `a` sorts after `b`.
 *
 * Strings that are not PEP 440 versions never throw: they sort before every
 * valid version and among themselves by code unit, so the order is total and
 * deterministic on every machine.
 */
export function comparePypiVersions(a: string, b: string): number {
  const left = parsePypiVersion(a);
  const right = parsePypiVersion(b);
  if (!left || !right) {
    if (!left && !right) return compareText(String(a), String(b));
    return left ? 1 : -1;
  }

  if (left.epoch !== right.epoch) return compareBig(left.epoch, right.epoch);

  const leftRelease = stripTrailingZeros(left.release);
  const rightRelease = stripTrailingZeros(right.release);
  const releaseLength = Math.max(leftRelease.length, rightRelease.length);
  for (let index = 0; index < releaseLength; index += 1) {
    const compared = compareBig(leftRelease[index] ?? 0n, rightRelease[index] ?? 0n);
    if (compared !== 0) return compared;
  }

  const comparedPre = comparePre(preKey(left), preKey(right));
  if (comparedPre !== 0) return comparedPre;

  // No post-release sorts before any post-release.
  const comparedPost = compareBig(left.post ?? -1n, right.post ?? -1n);
  if (comparedPost !== 0) return comparedPost;

  // No dev-release sorts after any dev-release.
  if (left.dev === null || right.dev === null) {
    if (left.dev !== right.dev) return left.dev === null ? 1 : -1;
  } else {
    const comparedDev = compareBig(left.dev, right.dev);
    if (comparedDev !== 0) return comparedDev;
  }

  return compareLocal(left.local, right.local);
}

/** True when the string is a valid PEP 440 version. */
export function isPypiVersion(version: string): boolean {
  return parsePypiVersion(version) !== undefined;
}
