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

/** Translate a forward-slash glob into an anchored regular expression. */
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

/** True when a forward-slash relative path matches the glob. */
export function globMatches(glob: string, relativePath: string): boolean {
  return globToRegExp(glob).test(relativePath);
}

/** True when any glob in the list matches the path. */
export function anyGlobMatches(
  globs: readonly string[],
  relativePath: string,
): boolean {
  return globs.some((glob) => globMatches(glob, relativePath));
}