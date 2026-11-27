/*
 * Literal prefilter for rule patterns
 * -----------------------------------
 * Most rule locators can only match text that contains one of a few fixed
 * strings: `\bstrcpy\s*\(` needs "strcpy", `\b(?:Process\.Start|ShellExecute)`
 * needs "process.start" or "shellexecute" (case-insensitive rule). Testing a
 * line for those strings with `includes` is much cheaper than running the
 * regular expression, and most lines of a large repository contain none.
 *
 * `requiredLiterals` derives such a set from the pattern source when the rule
 * is loaded. The derivation is CONSERVATIVE: whatever it does not fully
 * understand (a construct it does not parse, the `u` flag, non-ASCII text in a
 * case-insensitive pattern, too many alternatives) yields `undefined`, and the
 * rule then runs on every line as before. When it returns a set, every match
 * of the pattern contains at least one of the strings (lower-cased for a
 * case-insensitive pattern, to be compared with the lower-cased text).
 *
 * Soundness, in short: a literal character that is not optional is part of
 * every match; a run of such characters with nothing between them is a
 * substring of every match; a sequence needs every one of its parts, so any
 * part's set is valid for the whole; an alternation needs one of its branches,
 * so the union of the branches' sets is valid when every branch has one.
 * Zero-width assertions and character classes end a run and add nothing.
 * Without the `u` flag a case-insensitive ASCII letter matches only its two
 * ASCII cases, and `toLowerCase` maps an ASCII character to the same place,
 * so comparing lower-cased strings is exact for ASCII literals.
 */

/** Required literals of a pattern; see the file comment. */
export interface LiteralPrefilter {
  /** At least one of these occurs in every match. */
  literals: string[];
  /** Compare with the lower-cased text (the pattern has the `i` flag). */
  lowerCase: boolean;
}

/** Shortest literal worth a prefilter: one or two characters are everywhere. */
const MIN_LITERAL_LENGTH = 3;
/** More alternatives than this cost more than they save. */
const MAX_ALTERNATIVES = 40;

class Unsupported extends Error {}

/** `undefined`: no constraint. Otherwise one of the strings is in every match. */
type Requirement = string[] | undefined;

interface Quantifier {
  min: number;
  max: number;
}

function score(requirement: string[]): number {
  let shortest = Infinity;
  for (const item of requirement) shortest = Math.min(shortest, item.length);
  // Longer is more selective; fewer alternatives are cheaper to test.
  return shortest * 100 - requirement.length;
}

function better(left: Requirement, right: Requirement): Requirement {
  if (!left) return right;
  if (!right) return left;
  return score(right) > score(left) ? right : left;
}

class Parser {
  private index = 0;

  constructor(
    private readonly source: string,
    private readonly ignoreCase: boolean,
  ) {}

  parse(): Requirement {
    const result = this.alternation();
    if (this.index !== this.source.length) throw new Unsupported("trailing text");
    return result;
  }

  private peek(offset = 0): string | undefined {
    return this.source[this.index + offset];
  }

  private alternation(): Requirement {
    const branches: Requirement[] = [this.sequence()];
    while (this.peek() === "|") {
      this.index += 1;
      branches.push(this.sequence());
    }
    if (branches.length === 1) return branches[0];
    const union = new Set<string>();
    for (const branch of branches) {
      if (!branch) return undefined;
      for (const item of branch) union.add(item);
    }
    return [...union];
  }

  private sequence(): Requirement {
    let best: Requirement;
    let run = "";
    const flush = (): void => {
      if (run.length > 0) best = better(best, [run]);
      run = "";
    };
    while (this.index < this.source.length) {
      const ch = this.peek() as string;
      if (ch === "|" || ch === ")") break;
      const atom = this.atom();
      const quantifier = this.quantifier();
      if (atom.kind === "char") {
        if (!quantifier) {
          run += atom.char;
        } else if (quantifier.min >= 1) {
          // One copy is certain; what follows may come after more copies.
          run += atom.char;
          flush();
        } else {
          flush();
        }
        continue;
      }
      flush();
      if (atom.kind === "group" && (!quantifier || quantifier.min >= 1)) {
        best = better(best, atom.requirement);
      }
    }
    flush();
    return best;
  }

  private quantifier(): Quantifier | undefined {
    const ch = this.peek();
    let result: Quantifier | undefined;
    if (ch === "*") result = { min: 0, max: Infinity };
    else if (ch === "+") result = { min: 1, max: Infinity };
    else if (ch === "?") result = { min: 0, max: 1 };
    else if (ch === "{") {
      const braces = /^\{(\d+)(?:(,)(\d*))?\}/.exec(this.source.slice(this.index, this.index + 24));
      if (!braces) return undefined; // a literal "{" (not a quantifier)
      const min = Number(braces[1]);
      const max = braces[2] ? (braces[3] ? Number(braces[3]) : Infinity) : min;
      this.index += braces[0].length;
      if (this.peek() === "?") this.index += 1;
      return { min, max };
    }
    if (!result) return undefined;
    this.index += 1;
    if (this.peek() === "?") this.index += 1;
    return result;
  }

  private literal(char: string): { kind: "char"; char: string } | { kind: "other" } {
    const code = char.charCodeAt(0);
    if (code > 127) return { kind: "other" };
    return { kind: "char", char: this.ignoreCase ? char.toLowerCase() : char };
  }

  private atom():
    | { kind: "char"; char: string }
    | { kind: "other" }
    | { kind: "group"; requirement: Requirement } {
    const ch = this.peek() as string;
    if (ch === "(") return this.group();
    if (ch === "[") {
      this.characterClass();
      return { kind: "other" };
    }
    if (ch === "\\") return this.escape();
    if (ch === "*" || ch === "+" || ch === "?") throw new Unsupported("quantifier without atom");
    this.index += 1;
    if (ch === "." || ch === "^" || ch === "$") return { kind: "other" };
    // "{", "}" and "]" are literal characters outside a quantifier or class.
    return this.literal(ch);
  }

  private escape(): { kind: "char"; char: string } | { kind: "other" } {
    const next = this.peek(1);
    if (next === undefined) throw new Unsupported("trailing backslash");
    this.index += 2;
    switch (next) {
      case "n":
        return this.literal("\n");
      case "r":
        return this.literal("\r");
      case "t":
        return this.literal("\t");
      case "f":
        return this.literal("\f");
      case "v":
        return this.literal("\v");
      case "x": {
        const hex = /^[0-9A-Fa-f]{2}/.exec(this.source.slice(this.index, this.index + 2));
        if (!hex) return { kind: "other" };
        this.index += 2;
        return this.literal(String.fromCharCode(parseInt(hex[0], 16)));
      }
      case "u": {
        const hex = /^[0-9A-Fa-f]{4}/.exec(this.source.slice(this.index, this.index + 4));
        if (!hex) return { kind: "other" };
        this.index += 4;
        return this.literal(String.fromCharCode(parseInt(hex[0], 16)));
      }
      case "k":
        if (this.peek() === "<") {
          const close = this.source.indexOf(">", this.index);
          if (close < 0) throw new Unsupported("named back-reference");
          this.index = close + 1;
        }
        return { kind: "other" };
      case "c":
        if (/[A-Za-z]/.test(this.peek() ?? "")) this.index += 1;
        return { kind: "other" };
      default:
        break;
    }
    if (/[0-9]/.test(next)) {
      // Back-reference or octal escape: no requirement.
      while (/[0-9]/.test(this.peek() ?? "")) this.index += 1;
      return { kind: "other" };
    }
    // \d \w \s \b \B, and identity escapes of letters: no requirement.
    if (/[A-Za-z]/.test(next)) return { kind: "other" };
    // An escaped punctuation character is that character.
    return this.literal(next);
  }

  private characterClass(): void {
    this.index += 1; // [
    if (this.peek() === "^") this.index += 1;
    while (this.index < this.source.length) {
      const ch = this.peek() as string;
      if (ch === "\\") {
        this.index += 2;
        continue;
      }
      this.index += 1;
      if (ch === "]") return;
    }
    throw new Unsupported("unterminated character class");
  }

  private group(): { kind: "other" } | { kind: "group"; requirement: Requirement } {
    this.index += 1; // (
    let lookaround = false;
    if (this.peek() === "?") {
      const rest = this.source.slice(this.index, this.index + 4);
      if (rest.startsWith("?:")) this.index += 2;
      else if (rest.startsWith("?=") || rest.startsWith("?!")) {
        this.index += 2;
        lookaround = true;
      } else if (rest.startsWith("?<=") || rest.startsWith("?<!")) {
        this.index += 3;
        lookaround = true;
      } else if (rest.startsWith("?<")) {
        const close = this.source.indexOf(">", this.index);
        if (close < 0) throw new Unsupported("group name");
        this.index = close + 1;
      } else {
        // Modifiers (`(?i:...)`) or anything else: not understood.
        throw new Unsupported("group syntax");
      }
    }
    const requirement = this.alternation();
    if (this.peek() !== ")") throw new Unsupported("unterminated group");
    this.index += 1;
    // A lookaround matches no text of its own.
    if (lookaround) return { kind: "other" };
    return { kind: "group", requirement };
  }
}

/**
 * Literals of which every match of `source` (compiled with `flags`) contains
 * at least one, or `undefined` when none can be derived with certainty.
 */
export function requiredLiterals(source: string, flags: string): LiteralPrefilter | undefined {
  if (flags.includes("u") || flags.includes("v")) return undefined;
  const ignoreCase = flags.includes("i");
  let requirement: Requirement;
  try {
    requirement = new Parser(source, ignoreCase).parse();
  } catch (error) {
    if (error instanceof Unsupported) return undefined;
    throw error;
  }
  if (!requirement || requirement.length === 0 || requirement.length > MAX_ALTERNATIVES) {
    return undefined;
  }
  // A literal that contains a shorter literal of the set is redundant: any
  // text that contains the longer one contains the shorter one too.
  const sorted = [...new Set(requirement)].sort((left, right) => left.length - right.length);
  const literals: string[] = [];
  for (const item of sorted) {
    if (!literals.some((kept) => item.includes(kept))) literals.push(item);
  }
  if (literals.some((item) => item.length < MIN_LITERAL_LENGTH)) return undefined;
  return { literals, lowerCase: ignoreCase };
}

/**
 * True when `text` may match: it contains one of the literals. `lower` is
 * `text.toLowerCase()`, computed by the caller once for many rules.
 */
export function passesPrefilter(prefilter: LiteralPrefilter, text: string, lower: string): boolean {
  const haystack = prefilter.lowerCase ? lower : text;
  for (const literal of prefilter.literals) {
    if (haystack.includes(literal)) return true;
  }
  return false;
}
