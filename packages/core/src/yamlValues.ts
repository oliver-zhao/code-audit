import {
  LineCounter,
  isAlias,
  isMap,
  isPair,
  isScalar,
  isSeq,
  parseAllDocuments,
  type Document,
  type Node,
  type Scalar,
  type YAMLMap,
} from "yaml";

/*
 * Structured view of a YAML file for rules with `withinKeys`
 * ----------------------------------------------------------
 * A rule such as "an attacker-controlled `${{ ... }}` expression inside a
 * `run:` script" cannot be decided by looking at lines: the script text may be
 * written under an anchor and used through an alias, the key may be quoted,
 * escaped, tagged or anchored, the value may be a flow scalar that continues
 * on the next line, and the expression may reach the script through `env:` or
 * `matrix:`. So the file is parsed and the rule patterns are matched against
 * the VALUE of each watched key.
 *
 * The file comes from the audited repository. Everything here is bounded
 * (input size, nodes visited, nesting depth, output size) and every failure
 * is reported to the caller, which then FAILS OPEN: it matches the rule
 * against every line of the file, as if `withinKeys` were not set.
 */

/** Files larger than this are not parsed (the caller falls back). */
export const YAML_VALUES_MAX_BYTES = 512 * 1024;
/** Node visits, including nodes reached again through an alias. */
export const YAML_VALUES_MAX_VISITS = 100_000;
/** Nesting depth, aliases included. A cycle cannot be built, a deep chain can. */
export const YAML_VALUES_MAX_DEPTH = 64;
/** Total length of the texts handed to the rule engine. */
export const YAML_VALUES_MAX_TEXT = 2 * 1024 * 1024;
/** Definitions substituted for one `env.X` / `matrix.X` reference. */
const MAX_DEFINITIONS_PER_REFERENCE = 50;

/** The value of one watched key, prepared for pattern matching. */
export interface YamlKeyValue {
  /** The key as written in the rule (`run`, `script`). */
  key: string;
  /**
   * The scalar value with every `${{ ... }}` expression rewritten to one
   * line in a canonical form (see `normalizeExpression`), each followed by the
   * expressions of the `env` / `matrix` entries it refers to.
   */
  text: string;
  /** Zero-based physical line of the character at `offset` of `text`. */
  lineAt: (offset: number) => number;
}

export type YamlKeyValuesResult =
  | { ok: true; values: YamlKeyValue[] }
  | { ok: false; reason: string };

class Bail extends Error {}

const EXPRESSION = /\$\{\{([\s\S]*?)\}\}/g;

/**
 * Canonical form of the body of a `${{ ... }}` expression, for matching:
 * lower case (context names are case-insensitive), white space collapsed (an
 * expression may span lines), `a['b']` written as `a.b`, no space around a
 * dot. String literals are lower-cased too; the result is only matched,
 * never shown.
 */
export function normalizeExpression(body: string): string {
  return body
    .replace(/\s+/g, " ")
    .replace(/\[\s*(['"])([A-Za-z_][A-Za-z0-9_-]*)\1\s*\]/g, ".$2")
    .replace(/\s*\.\s*/g, ".")
    .trim()
    .toLowerCase();
}

/**
 * Line `index` of a file with its `${{ ... }}` expressions in canonical form,
 * for the fail-open path (a file that could not be parsed is matched line by
 * line). An expression left open at the end of the line is completed from the
 * following lines (at most five), so one that is split across lines is seen.
 */
export function canonicalExpressionLine(lines: readonly string[], index: number): string {
  let text = lines[index] ?? "";
  const open = text.lastIndexOf("${{");
  if (open >= 0 && text.indexOf("}}", open) < 0) {
    for (let next = index + 1; next < Math.min(lines.length, index + 6); next += 1) {
      const following = (lines[next] ?? "").slice(0, 2000);
      text += ` ${following.trim()}`;
      if (following.includes("}}")) break;
    }
  }
  return text.replace(EXPRESSION, (_match, body: string) => `\${{ ${normalizeExpression(body)} }}`);
}

const CONTEXT_REFERENCE = /(?<![\w.])(env|matrix)\.([a-z_][a-z0-9_-]*)/g;

interface Scope {
  env: Map<string, string[]>;
  matrix: Map<string, string[]>;
}

/**
 * Values of the keys `keys` (compared case-insensitively) anywhere in a YAML
 * text, with aliases resolved and GitHub Actions `env` / `matrix`
 * indirection resolved one level:
 *
 *     env:
 *       TITLE: ${{ github.event.issue.title }}
 *     ...
 *       run: echo ${{ env.TITLE }}       <- text also holds the definition
 *
 * `env` is looked up on every enclosing mapping (step, job, workflow) and
 * `matrix` under `strategy` of every enclosing mapping; all definitions of a
 * name count, not only the innermost. A shell variable (`$TITLE`) is NOT
 * resolved: the shell receives it as data, which is the documented fix.
 */
export function yamlKeyValues(content: string, keys: readonly string[]): YamlKeyValuesResult {
  if (content.length > YAML_VALUES_MAX_BYTES) {
    return { ok: false, reason: `larger than ${YAML_VALUES_MAX_BYTES / 1024} KiB` };
  }
  const watched = new Map(keys.map((key) => [key.toLowerCase(), key]));
  const lineCounter = new LineCounter();
  let documents: Document.Parsed[];
  try {
    const parsed = parseAllDocuments(content, {
      lineCounter,
      uniqueKeys: false,
      logLevel: "silent",
      prettyErrors: false,
    });
    if (!Array.isArray(parsed)) return { ok: true, values: [] };
    documents = parsed as Document.Parsed[];
  } catch (error) {
    return { ok: false, reason: `not parseable (${error instanceof Error ? error.name : "error"})` };
  }
  for (const document of documents) {
    if (document.errors.length > 0) {
      const first = document.errors[0];
      return { ok: false, reason: `not valid YAML (${first?.code ?? "error"})` };
    }
  }

  const lineOfOffset = (offset: number): number => Math.max(0, lineCounter.linePos(offset).line - 1);
  const values: YamlKeyValue[] = [];
  let visits = 0;
  let totalText = 0;
  const tick = (depth: number): void => {
    visits += 1;
    if (visits > YAML_VALUES_MAX_VISITS) throw new Bail(`more than ${YAML_VALUES_MAX_VISITS} nodes after alias expansion`);
    if (depth > YAML_VALUES_MAX_DEPTH) throw new Bail(`nested deeper than ${YAML_VALUES_MAX_DEPTH} levels`);
  };

  try {
    for (const document of documents) {
      const resolve = (node: unknown): unknown => {
        let current = node;
        for (let hop = 0; isAlias(current); hop += 1) {
          if (hop > YAML_VALUES_MAX_DEPTH) throw new Bail("alias chain too long");
          const target = current.resolve(document);
          if (target === undefined) throw new Bail("unresolved alias");
          current = target;
        }
        return current;
      };
      const keyText = (key: unknown): string | undefined => {
        const node = resolve(key);
        if (isScalar(node)) return node.value === null ? undefined : String(node.value);
        return typeof node === "string" ? node : undefined;
      };
      const pairValue = (map: YAMLMap, name: string): unknown => {
        for (const pair of map.items) {
          if (keyText(pair.key)?.toLowerCase() === name) return resolve(pair.value);
        }
        return undefined;
      };
      /** Every scalar below `node`, as text. */
      const scalarsBelow = (node: unknown, depth: number, into: Scalar[]): void => {
        tick(depth);
        const target = resolve(node);
        if (isScalar(target)) into.push(target);
        else if (isMap(target)) {
          for (const pair of target.items) scalarsBelow(pair.value, depth + 1, into);
        } else if (isSeq(target)) {
          for (const item of target.items) scalarsBelow(isPair(item) ? item.value : item, depth + 1, into);
        }
      };
      const textOf = (scalar: Scalar): string =>
        scalar.value === null || scalar.value === undefined ? "" : String(scalar.value);

      const scopeOf = (ancestors: readonly YAMLMap[]): Scope => {
        const scope: Scope = { env: new Map(), matrix: new Map() };
        const add = (target: Map<string, string[]>, name: string, node: unknown): void => {
          const scalars: Scalar[] = [];
          scalarsBelow(node, 0, scalars);
          const list = target.get(name) ?? [];
          for (const scalar of scalars) {
            if (list.length < MAX_DEFINITIONS_PER_REFERENCE) list.push(textOf(scalar));
          }
          target.set(name, list);
        };
        for (const ancestor of ancestors) {
          const env = pairValue(ancestor, "env");
          if (isMap(env)) {
            for (const pair of env.items) {
              const name = keyText(pair.key);
              if (name !== undefined) add(scope.env, name.toLowerCase(), pair.value);
            }
          }
          const strategy = pairValue(ancestor, "strategy");
          const matrix = isMap(strategy) ? pairValue(strategy, "matrix") : undefined;
          if (isMap(matrix)) {
            for (const pair of matrix.items) {
              const name = keyText(pair.key);
              if (name === undefined) continue;
              if (name.toLowerCase() === "include") {
                const include = resolve(pair.value);
                if (!isSeq(include)) continue;
                for (const item of include.items) {
                  const entry = resolve(item);
                  if (!isMap(entry)) continue;
                  for (const inner of entry.items) {
                    const innerName = keyText(inner.key);
                    if (innerName !== undefined) add(scope.matrix, innerName.toLowerCase(), inner.value);
                  }
                }
              } else {
                add(scope.matrix, name.toLowerCase(), pair.value);
              }
            }
          }
        }
        return scope;
      };

      const emit = (key: string, scalar: Scalar, scope: () => Scope): void => {
        const value = textOf(scalar);
        if (value.length === 0) return;
        const range = scalar.range;
        const startOffset = range ? range[0] : 0;
        const startLine = lineOfOffset(startOffset);
        const literal = scalar.type === "BLOCK_LITERAL";
        // Where each "${{" of the value is written in the file: by position
        // in order, when the source holds exactly as many as the value.
        const sourceStarts: number[] = [];
        if (range) {
          const source = content.slice(range[0], range[1]);
          for (let at = source.indexOf("${{"); at >= 0; at = source.indexOf("${{", at + 3)) {
            sourceStarts.push(range[0] + at);
          }
        }
        const expressions = [...value.matchAll(EXPRESSION)];
        const exact = sourceStarts.length === expressions.length;

        let text = "";
        const segmentStarts: number[] = [];
        const segmentLines: number[] = [];
        const mark = (line: number): void => {
          segmentStarts.push(text.length);
          segmentLines.push(line);
        };
        let valueLine = 0;
        const plain = (part: string): void => {
          // Text between expressions keeps its line breaks. Only a literal
          // block scalar maps value lines onto file lines one to one.
          const pieces = part.split("\n");
          for (let index = 0; index < pieces.length; index += 1) {
            if (index > 0) {
              text += "\n";
              valueLine += 1;
            }
            mark(literal ? startLine + 1 + valueLine : startLine);
            text += pieces[index] as string;
          }
        };
        let resolved: Scope | undefined;
        let cursor = 0;
        for (let index = 0; index < expressions.length; index += 1) {
          const match = expressions[index] as RegExpMatchArray;
          const at = match.index ?? 0;
          plain(value.slice(cursor, at));
          const line = exact
            ? lineOfOffset(sourceStarts[index] as number)
            : literal
              ? startLine + 1 + valueLine
              : startLine;
          mark(line);
          const body = normalizeExpression(match[1] ?? "");
          text += `\${{ ${body} }}`;
          for (const reference of body.matchAll(CONTEXT_REFERENCE)) {
            resolved ??= scope();
            const definitions = (reference[1] === "env" ? resolved.env : resolved.matrix).get(
              reference[2] as string,
            );
            for (const definition of definitions ?? []) {
              for (const inner of definition.matchAll(EXPRESSION)) {
                text += ` \${{ ${normalizeExpression(inner[1] ?? "")} }}`;
              }
            }
          }
          valueLine += (match[0].match(/\n/g) ?? []).length;
          cursor = at + match[0].length;
        }
        plain(value.slice(cursor));

        totalText += text.length;
        if (totalText > YAML_VALUES_MAX_TEXT) throw new Bail("values too large after alias expansion");
        values.push({
          key,
          text,
          lineAt: (offset) => {
            let low = 0;
            let high = segmentStarts.length - 1;
            while (low < high) {
              const middle = (low + high + 1) >> 1;
              if ((segmentStarts[middle] as number) <= offset) low = middle;
              else high = middle - 1;
            }
            return segmentLines[low] ?? startLine;
          },
        });
      };

      const visit = (node: unknown, ancestors: readonly YAMLMap[], depth: number): void => {
        tick(depth);
        const target = resolve(node);
        if (isMap(target)) {
          const inner = [target, ...ancestors];
          let scope: Scope | undefined;
          for (const pair of target.items) {
            const name = keyText(pair.key);
            const key = name === undefined ? undefined : watched.get(name.toLowerCase());
            if (key !== undefined) {
              const scalars: Scalar[] = [];
              scalarsBelow(pair.value, depth + 1, scalars);
              for (const scalar of scalars) emit(key, scalar, () => (scope ??= scopeOf(inner)));
            }
            // A complex key (`? { run: ... }`) is a node too.
            if (!isScalar(pair.key) && !isAlias(pair.key)) visit(pair.key, inner, depth + 1);
            visit(pair.value, inner, depth + 1);
          }
        } else if (isSeq(target)) {
          for (const item of target.items) visit(isPair(item) ? item.value : item, ancestors, depth + 1);
        }
      };
      visit(document.contents as Node | null, [], 0);
    }
  } catch (error) {
    if (error instanceof Bail) return { ok: false, reason: error.message };
    if (error instanceof RangeError) return { ok: false, reason: "nested too deeply" };
    return { ok: false, reason: `not analysable (${error instanceof Error ? error.name : "error"})` };
  }
  return { ok: true, values };
}
