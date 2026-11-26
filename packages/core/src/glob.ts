/**
 * Minimal forward-slash glob matcher used by the ignore file.
 *
 * Supported syntax:
 *   `*`   matches any run of characters except `/`
 *   `**`  matches any run of characters including `/`
 *   `?`   matches a single character except `/`
 *
 * A double-star followed by a slash at the start of a pattern (or after a
 * slash) also matches zero path segments, so the glob double-star-slash-x
 * matches both x and a/b/x. A trailing slash plus double-star matches
 * everything nested under a directory. Every other character is matched
 * literally, so regular-expression metacharacters such as plus, parentheses,
 * and dot are treated as plain text. Matching is anchored at both ends.
 */

function escapeRegExpChar(char: string): string {
  return /[.*+?^${}()|[\]\\]/.test(char) ? `\\${char}` : char;
}

/**
 * Translate a forward-slash glob into an anchored regular expression. For
 * documentation and tests only: matching uses `compileGlob`, which cannot
 * backtrack.
 */
export function globToRegExp(glob: string): RegExp {
  let source = "";
  for (let index = 0; index < glob.length; index += 1) {
    const char = glob[index] ?? "";
    if (char === "*") {
      if (glob[index + 1] === "*") {
        index += 1;
        if (glob[index + 1] === "/") {
          index += 1;
          // `**/` matches zero or more leading path segments.
          source += "(?:.*/)?";
        } else {
          source += ".*";
        }
      } else {
        source += "[^/]*";
      }
    } else if (char === "?") {
      source += "[^/]";
    } else {
      source += escapeRegExpChar(char);
    }
  }
  return new RegExp(`^${source}$`);
}

/** Longest glob accepted by `compileGlob`. */
export const MAX_GLOB_LENGTH = 1024;

const enum Token {
  Literal,
  /** `?`: one character except `/`. */
  One,
  /** `*`: any run of characters except `/`. */
  Star,
  /** `**`: any run of characters. */
  GlobStar,
  /** A double star followed by a slash: nothing, or any run ending in `/`. */
  GlobStarSlash,
}

export class GlobError extends Error {
  readonly code = "INVALID_GLOB";

  constructor(message: string) {
    super(message);
    this.name = "GlobError";
  }
}

/**
 * Compile a glob to a matcher that runs in time proportional to
 * `glob length x path length`, whatever the glob and the path are.
 *
 * Globs come from run-time input (`search --glob`, the MCP `glob` argument,
 * the ignore file of an audited repository) and are matched against the
 * paths of an audited repository. The equivalent regular expression
 * backtracks: a glob made of a dozen double stars against a deep path takes
 * minutes. The matcher below simulates the same automaton state set by state
 * set and cannot backtrack.
 */
export function compileGlob(glob: string): (relativePath: string) => boolean {
  if (glob.length > MAX_GLOB_LENGTH) {
    throw new GlobError(`glob is too long (${glob.length} > ${MAX_GLOB_LENGTH} characters)`);
  }
  const kinds: Token[] = [];
  const chars: string[] = [];
  for (let index = 0; index < glob.length; index += 1) {
    const char = glob[index] ?? "";
    if (char === "*") {
      if (glob[index + 1] === "*") {
        index += 1;
        if (glob[index + 1] === "/") {
          index += 1;
          // Repeating it adds nothing.
          if (kinds[kinds.length - 1] !== Token.GlobStarSlash) {
            kinds.push(Token.GlobStarSlash);
            chars.push("");
          }
        } else if (kinds[kinds.length - 1] !== Token.GlobStar) {
          kinds.push(Token.GlobStar);
          chars.push("");
        }
      } else {
        kinds.push(Token.Star);
        chars.push("");
      }
    } else if (char === "?") {
      kinds.push(Token.One);
      chars.push("");
    } else {
      kinds.push(Token.Literal);
      chars.push(char);
    }
  }
  const count = kinds.length;

  return (relativePath: string): boolean => {
    // `current[i]`: token i is about to start. `inside[i]`: in the middle of
    // the "any run ending in a slash" of a GlobStarSlash token i.
    let current = new Uint8Array(count + 1);
    let next = new Uint8Array(count + 1);
    let inside = new Uint8Array(count + 1);
    let nextInside = new Uint8Array(count + 1);
    // Mark a state and every state reachable from it without input.
    const add = (set: Uint8Array, state: number): void => {
      for (let at = state; at <= count && set[at] === 0; at += 1) {
        set[at] = 1;
        const kind = kinds[at];
        if (kind !== Token.Star && kind !== Token.GlobStar && kind !== Token.GlobStarSlash) break;
      }
    };
    add(current, 0);
    for (let position = 0; position < relativePath.length; position += 1) {
      const char = relativePath[position] as string;
      const slash = char === "/";
      let any = false;
      for (let state = 0; state < count; state += 1) {
        if (current[state] === 0 && inside[state] === 0) continue;
        switch (kinds[state]) {
          case Token.Literal:
            if (chars[state] === char) add(next, state + 1);
            break;
          case Token.One:
            if (!slash) add(next, state + 1);
            break;
          case Token.Star:
            if (!slash) add(next, state);
            break;
          case Token.GlobStar:
            add(next, state);
            break;
          case Token.GlobStarSlash:
            nextInside[state] = 1;
            if (slash) add(next, state + 1);
            break;
          default:
            break;
        }
      }
      for (let state = 0; state <= count; state += 1) {
        if (next[state] === 1 || nextInside[state] === 1) {
          any = true;
          break;
        }
      }
      if (!any) return false;
      let swap = current;
      current = next;
      next = swap;
      next.fill(0);
      swap = inside;
      inside = nextInside;
      nextInside = swap;
      nextInside.fill(0);
    }
    return current[count] === 1;
  };
}

/** True when a forward-slash relative path matches the glob. */
export function globMatches(glob: string, relativePath: string): boolean {
  return compileGlob(glob)(relativePath);
}

/** True when any glob in the list matches the path. */
export function anyGlobMatches(
  globs: readonly string[],
  relativePath: string,
): boolean {
  return globs.some((glob) => {
    try {
      return globMatches(glob, relativePath);
    } catch {
      // An over-long glob in an ignore file matches nothing (nothing is hidden).
      return false;
    }
  });
}
