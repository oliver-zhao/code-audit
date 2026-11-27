# Built-in rules

The built-in engine is a pattern matcher: each rule is a set of regular
expressions with metadata, written in YAML under `rules/`. It needs nothing
but Node.js and runs in milliseconds per file. It is not a data-flow engine;
what a rule may claim is limited by what one statement shows (see
[Findings and hotspots](#findings-and-hotspots)).

`code-audit doctor` prints the number of rules your build loads, split into
finding rules and hotspot rules.

## Layout

| Directory | Content |
|---|---|
| `rules/sast/` | Code rules: Python (three files), JavaScript/TypeScript, Java, Go, C/C++, C#. |
| `rules/iac/` | Dockerfile, Compose, Kubernetes, Terraform, GitHub Actions. |
| `rules/agent/` | Agent configuration, instruction files and agent supply chain. |
| `rules/deps/` | Dependency hygiene (installs over plain HTTP, `--trusted-host`, downloads in post-install scripts). |
| `rules/opengrep/` | Rules in Opengrep/Semgrep syntax, including the Python taint rules. They are **not** loaded by the built-in engine; they are passed to `opengrep` (or `semgrep`) when that tool is installed, and use that tool's schema. |

Every `.yml` / `.yaml` file below the rules directory (except `opengrep/`) is
loaded. `--rules <dir>` or `CODE_AUDIT_RULES_DIR` replaces the whole built-in
rule set with another directory in the same format.

Secret detection (`packages/core/src/secrets.ts`) and dependency advisories
(`sca.ts`) are separate engines and have no rule files.

## How matching works

1. The inventory assigns each file a language from its name
   (`packages/core/src/language.ts`). A rule applies to a file when the
   file's language is in the rule's `languages` and the path passes
   `pathInclude` / `pathExclude`.
2. The file is split into **units**. For Python a unit is one *logical
   line*: a statement that spans several lines (open brackets, backslash
   continuation) is one unit; comments, docstrings and statements that are
   only a string are removed; the header of a `def` / `class` statement and
   `import` statements are not matched unless the rule sets
   `matchDeclarations`. C#, Java, JavaScript/TypeScript, Go, C/C++ and Rust
   go through one C-family lexer (`packages/core/src/lexers/clike.ts`) with
   each language's string and comment syntax: comments are blanked (columns
   stay those of the physical line), string text is kept, and a statement is
   one unit while a `(` or `[` is open (in all but C#, also an object or
   struct literal passed as an argument, `f({ ... })`), and across a line
   break next to a binary operator, `=`, `=>`, `.` or `?:` (a method chain
   `\n  .arg(x)` joins). C/C++ preprocessor directives are units of their own;
   C# directives are not code. Rust `#[cfg(test)] mod ... { }` modules are
   test code: findings there are lowered like findings in a test path. A
   Dockerfile instruction continued with `\` is one unit, and comment lines
   are blank. XML and Razor comments are blanked. Every other language is
   matched one physical line at a time. The physical lines of a unit are
   joined with a line break, so a pattern anchored at a line start needs the
   `m` flag.
3. In each unit, `pattern` (or the first entry of `patterns`) locates
   matches; **every** match is reported, at the line where it starts. With
   `patterns`, all other entries must match the same unit too (for long
   statements: the same call expression). `notPattern` discards a match when
   it matches the expression around it (Python, C#), or the physical lines
   of the match and the expression around it (the other C-family languages,
   whose rules were written for one line at a time; on a single-line
   statement that is the whole line).
4. `filePattern` / `fileAbsentPattern` gate the rule for a file: at least
   one line must match `filePattern`, and no line may match
   `fileAbsentPattern`.
5. Rules with `withinKeys` (YAML only) are matched against the *values* of
   the named mapping keys of the parsed document, so anchors, aliases, quoted
   keys and block scalars cannot hide a value. A file that does not parse is
   matched line by line, with a warning.
6. Hits of rules that share a `group` and overlap in one expression collapse
   into one result: the one with the highest confidence, then severity. This
   is how a specific rule and its API-only fallback avoid double reporting.
7. A comment `code-audit:ignore <rule-id>[, <rule-id>...] -- <reason>` on the
   matched line or the line before suppresses the hit (`*` matches any rule).
   In the C-family languages only real comments count: the same text inside
   a string literal suppresses nothing.
   Suppressed hits are listed in the report; `--no-inline-ignore` disables
   the comments.

Limits that keep matching bounded: a line longer than 2,000 characters is
matched in windows, a statement longer than 200 lines is split, each
file has a time budget of 5 seconds, and at most 100 matches per line and
rule are reported. Whenever one of these limits is hit the run gets a warning
naming the file and line. The Python lexer fails open: when it cannot tell
whether text is code or a string, the region is matched again as plain lines;
so does the C-family lexer (a string not closed on its line, a file that ends
inside a comment or an open bracket, a declaration inside an open `(`), with a
warning naming the language, file and lines.

## Rule file schema

A rule file is a YAML mapping with a `rules` list (or the list itself at top
level) and an optional `definitions` map:

```yaml
version: 1            # informational
definitions:          # optional: named regex fragments, referenced as {{NAME}}
  REQ: '\brequest\.(?:args|form|json)\b'
rules:
  - id: py-example-eval-request
    title: Python eval of request data
    severity: critical
    confidence: high
    kind: finding
    cwe: CWE-95
    owasp: A03:2021
    languages: [python]
    pattern: '\beval\(\s*{{REQ}}'
    codeOnly: true
    group: py-eval
    message: Request data is evaluated as Python code.
    remediation: Parse the value instead of evaluating it (ast.literal_eval for literals).
```

`definitions`: names must look like `REQUEST_VALUE` (`[A-Z][A-Z0-9_]*`). A
definition may use definitions that appear before it. `{{NAME}}` is expanded
in every regular-expression field; an unknown name is a load error.

Rule fields (this list is checked against the loader's schema, `RULE_FIELDS`
in `packages/core/src/rules.ts`, by a test):

| Field | Type | Required | Meaning |
|---|---|---|---|
| `id` | string | yes | Unique id: lowercase letters, digits and dashes, starting with a letter or digit. Used in reports, ignore entries and fingerprints; do not rename a released rule. |
| `title` | string | yes | Short title shown in reports. |
| `title_zh` | string | no | Chinese title (`--lang zh`). |
| `severity` | `critical` \| `high` \| `medium` \| `low` \| `info` | yes | Impact if the candidate is real. |
| `confidence` | `high` \| `medium` \| `low` | yes | How much the matched statement itself proves. See the policy below. |
| `kind` | `finding` \| `hotspot` | no (default `finding`) | A hotspot is a reading-list entry and is never counted. |
| `cwe` | string `CWE-<number>` | yes | Weakness id. |
| `owasp` | string | no | OWASP Top 10 reference, for example `A03:2021`. |
| `languages` | list, at least one of `csharp`, `java`, `javascript`, `typescript`, `python`, `go`, `c`, `cpp`, `dockerfile`, `yaml`, `json`, `markdown` | yes | File languages the rule applies to. Terraform files are `yaml`. |
| `pattern` | regex | one of `pattern` / `patterns` | The locator. |
| `patterns` | list of regex | one of `pattern` / `patterns` | The first entry is the locator; all others must also match (AND). Mutually exclusive with `pattern`. |
| `notPattern` | regex | no | Discards a match when it matches the expression around it. |
| `pathInclude` | regex | no | The rule applies only to paths (relative, `/`-separated) that match. Case-sensitive. |
| `pathExclude` | regex | no | The rule does not apply to paths that match. Case-sensitive. |
| `filePattern` | regex | no | The rule applies only to files in which at least one line matches (flags `im`). |
| `fileAbsentPattern` | regex | no | The rule does not apply to files in which any line matches (flags `im`). |
| `flags` | string of `i`, `m`, `s`, `u`, `y` | no (default `i`) | Flags for `pattern`, `patterns` and `notPattern`. Give `flags: ""` for a case-sensitive rule. |
| `group` | string (same form as `id`) | no | Overlapping hits of rules in one group produce one result. |
| `matchDeclarations` | boolean | no | Python: also match `def` / `class` headers and `import` statements. |
| `redactEvidence` | boolean | no | The match is a credential: mask it in every output. With a capture group named `secret` only that group is masked. Required for every rule that matches a credential literal. |
| `codeOnly` | boolean | no | Python and the C-family languages (C#, Java, JavaScript/TypeScript, Go, C/C++, Rust): ignore a match that starts inside a string literal or a JavaScript regex literal (for API-call rules). |
| `withinKeys` | list of YAML keys | no | YAML only (`languages: [yaml]`): match inside the values of these mapping keys. |
| `message` | string | yes | What was found and why it matters. |
| `message_zh` | string | no | Chinese message. |
| `remediation` | string | yes | How to fix it. |
| `remediation_zh` | string | no | Chinese remediation. |
| `references` | list of strings | no | Links or identifiers. |

A file that does not parse, a rule that fails the schema, an invalid regular
expression, an unknown `{{NAME}}` or a duplicate `id` stops the scan with exit
code 2 and a message naming the file and the rule index. Fields that are not
in the table are ignored.

## Findings and hotspots

The rule decides what kind of result a match is, and the policy is the same
for every rule file:

- **`kind: finding`, confidence `high`:** the matched statement itself shows
  attacker-controlled data (for example a request value) reaching the sink,
  or an option that is dangerous whatever the data (`verify=False`, a
  hard-coded private key).
- **`kind: finding`, confidence `medium`:** the statement shows a value built
  at run time reaching the sink, or a well-known dangerous form whatever the
  origin of the data (a non-literal command with `shell=True`), but not where
  the value comes from.
- **`kind: hotspot` (confidence `low`):** a dangerous API is used and the
  statement says nothing about the argument (`os.system(cmd)`). The reviewer
  has to read the context. Hotspots are listed in their own report section,
  are never part of the totals or the exit code, and can be promoted to a
  finding by a reviewer (`add-finding --promote`, MCP `audit_add_finding`
  with `hotspot_id`).

Pair a specific rule with its API-only hotspot through a shared `group`, so
that one call yields one result. Broad hotspots should exclude test paths.

After matching, the scan may lower a confidence because of where the file is
(test, docs, example, vendored or generated path); see
[reports.md](reports.md#path-context-dev-dependencies-and-placeholder-secrets).
Rules do not need to handle that themselves.

## Adding a rule

1. **Write the rule** in the file for its language or area. Rules must be
   original work: do not copy or translate rules from Semgrep registry rule
   packs or other scanners (see [CONTRIBUTING.md](../CONTRIBUTING.md)).
2. **Add a seed.** Put a minimal vulnerable sample in `fixtures/vulnerable/`
   (in the file for that language, or a new file) and add an entry to
   `fixtures/vulnerable/EXPECTED.json`:

   ```json
   { "file": "python/rules_exec.py", "line": 18, "ruleId": "py-os-system-api", "language": "python", "kind": "hotspot" }
   ```

   `file` is relative to `fixtures/vulnerable`, `line` is the line where the
   match starts, `kind` is `finding` or `hotspot`. The tests require at least
   one seed for every bundled rule and check that every seed is reported at
   that line with that kind.
3. **Add the clean counterpart.** Put the safe way to write the same code in
   `fixtures/clean/` (same relative file where possible). The clean tree must
   stay free of findings; only low-confidence hotspots are tolerated there.
   A rule that cannot be written without matching its clean counterpart
   should be a hotspot.
4. **Keep it cheap.** No nested or adjacent unbounded quantifiers; give gaps
   an upper bound (`[^)]{0,200}`); let exactly one quantifier consume
   whitespace. `rules.test.ts` runs every pattern of every rule file against
   pathological input and fails on slow ones.
5. **Credentials:** a rule that matches a credential literal must set
   `redactEvidence: true` (tested), and fixture values must be fake.
6. **Run** `pnpm test`. For an Opengrep-syntax rule under `rules/opengrep/`,
   add the expected hit to the `opengrep` list in `EXPECTED.json` and run the
   real-tool tests (see CONTRIBUTING.md).

To try a rule on real code before committing:

```sh
code-audit scan /path/to/project --offline --no-external --out /tmp/rule-try
code-audit findings /tmp/rule-try/<run-id> --kind all
```
