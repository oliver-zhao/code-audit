# PY1 report: stronger Python support

Task brief: `tasks/PY1.md`. This stage was started by the OpenCode implementer (model `ernie-5.5-free`), which stopped after step 4 when the free model's daily request limit was reached. Its rules passed their own fixtures but were unusable on real code (63 Python findings at confidence ≥ medium on the flask repository, almost all false). The work was then taken over on a macOS workstation, reworked by four engineers working on disjoint files, and verified on both macOS and Linux.

## What changed

### Dependencies (`sca.ts`, `pypi.ts`, `toml.ts`, `external/osvScanner.ts`, `external/merge.ts`)

- New lockfiles: `uv.lock`, `Pipfile.lock`, `pdm.lock`, `pylock.toml` / `pylock.*.toml`; requirements variants (`requirements*.txt`, `*requirements.txt`, `requirements/*.txt`), `-r` includes through the path jail with cycle and depth limits, continuations, hashes, markers, extras, `===`.
- Direct vs transitive and `dependencyScope` (`runtime` / `optional` / `dev` / `unknown`) from the lockfile and the sibling `pyproject.toml` / `Pipfile`.
- PEP 440 comparator for PyPI packages (fixed-version selection and upgrade advice).
- Advisory aliases are grouped: one finding per advisory group, GHSA id preferred, both in the built-in OSV.dev path and the OSV-Scanner adapter. Ignore-file `advisory:` entries match the id or any alias.
- OSV-Scanner findings carry root-relative paths (they were absolute).
- Hardening found by adversarial review of the first implementation: prototype pollution through a `[__proto__]` TOML table; quadratic regexes on long whitespace runs; `-r /absolute/path` and symlinked `pyproject.toml` read outside the root; workspace / directory packages queried as PyPI packages; the same release in several lockfiles reported once; GIT commit ranges used as fixed versions.

### Built-in Python rules (`rules/sast/python.yml`, `python-web.yml`, `python-crypto.yml`, `rules.ts`)

- 70 rules (44 findings, 26 hotspots), replacing the 13 original rules and the 58 draft rules.
- Engine: Python is matched on logical lines; comments, docstrings and string-only statements are ignored; `def` / `class` / `import` statements are not matched unless a rule opts in; named regex fragments (`definitions:` + `{{NAME}}`).
- Two identical vulnerable lines in one file used to collapse into one finding (same line-independent fingerprint). Repeated occurrences now get distinct, still line-independent fingerprints (`disambiguateFingerprints`).

### Opengrep taint rules (`rules/opengrep/python-taint.yml`, `python.yml`)

- 8 taint rules (SQL, command, path, SSRF, template, redirect, deserialization, eval) with Flask, Django, FastAPI / Starlette and `http.server` sources, argument-precise sinks and sanitizers, using `taint_intrafile` so helper functions in the same file are followed.
- Verified with Opengrep 1.33.1 only. Followed: assignment chains, string formatting, dict / loop / comprehension flows, helpers up to three levels, keyword / default / `*args` arguments. Not followed: `self.method(x)`, attributes set in one method and read in another, `**kwargs`, module-level lambdas, anything across files.

### Platform and MCP fixes (`pathJail.ts`, `git.ts`, `packages/mcp`, `bin/`)

- MCP: `audit_status` returned `RUN_NOT_FOUND` while a scan was still running whenever an external tool made the scan asynchronous. It now reports `running`; other tools return `RUN_NOT_READY`.
- Path jail: a root that is itself a symlink was refused; on case-insensitive file systems a differently-cased home directory bypassed the home-directory refusal; `--since` produced `../..` paths under a symlinked root; wrapper scripts failed when symlinked into a PATH directory. Path tests went from 6 to 19.
- Test setup now hides every PATH directory that contains a real scanner, so unit tests are hermetic on machines with Homebrew `gitleaks`.

## Verification

- macOS (Node 24): `pnpm build && pnpm test` → 291 passed, 6 skipped (real-tool tests; no Opengrep / OSV-Scanner on this machine). License check passes.
- Linux (Node 24) with Opengrep 1.33.1, OSV-Scanner 2.7.1, Gitleaks 8.30.1 on PATH: all test files pass including `realtools.test.ts`; without the tools on PATH: all pass.
- `fixtures/clean`: 0 findings with built-in engines and with all three real tools.

### Public repositories (all engines, Linux, shallow clones, scan only)

Python SAST findings at confidence ≥ medium, built-in plus Opengrep after cross-engine merge:

| Repository | first draft | now | notes |
|---|---|---|---|
| flask | 63 | 1 | `eval(compile(...))` of the user's own `PYTHONSTARTUP` in `flask shell` — defensible |
| requests | 19 | 0 | |
| httpie | 28 | 2 | one real `verify=False` in the update check; one `verify=False` context used only to list ciphers |
| DSVW (vulnerable) | 17 | 13 | SQL injection ×3, command injection, pickle, file inclusion, `exec`, XXE, XPath, redirect |
| Vulnerable-Flask-App (vulnerable) | 5 | 12 | SSTI, SQL injection, `yaml.load` of an upload, JWT `verify=False`, MD5 passwords, hard-coded secret |
| pygoat (vulnerable) | 59 | 43 | injection and deserialization labs, debug mode, hard-coded keys, weak hashes |

Dependency findings on flask went from 90 to 53 after alias grouping, and 38 of the 53 are now marked as dev dependencies.

## Not verified / known limits

- No real `poetry.lock`, `pdm.lock`, `Pipfile.lock` or `pylock.toml` from a public project was parsed; those parsers were tested on hand-built samples. `uv.lock` and requirements files were checked against real files.
- Taint rules: Opengrep 1.33.1 only; FastAPI and Django sources verified on our fixtures only. `taint_intrafile` is not a stable rule option.
- Known misses on the vulnerable apps: XSS, stored template injection through the file system, flows through class methods or module-level lambdas, authorization and business-logic flaws.
- Scan totals on real projects are still dominated by dependency advisories and by findings under `tests/`, `docs/` and `examples/`; report aggregation and path-context handling are the next stage.
- SCA finding ids changed from PYSEC-first to GHSA-first, so SCA fingerprints differ from baselines written by earlier versions.
- The logical-line lexer does not parse nested f-string expressions; a rule can still match text inside a string literal.

## Adversarial review rounds (added after the first draft of this report)

Two independent review passes were run on the merged work by reviewers who received only the code.

- **Round 1** confirmed 8 defects the test suite did not catch, among them: cubic regex backtracking in the new Python rules (a 6 KB line took 17 s; fixed by rewriting the patterns, an engine guard for over-long lines and a cost test that runs every rule regex of every language against pathological input); a stack overflow on a 400k-line requirements include; hard-coded-secret rules printing the secret into reports; files named like requirements files skipping secret detection; the logical-line matcher reporting one hit per statement and skipping `def` one-liners; `yaml.unsafe_load` never reported.
- **Round 2** confirmed 8 more, mostly introduced or left by the round-1 fixes: `y = 1 if"""{""" else 2` blacked out the rest of a file; lone `\r` line endings hid code behind a comment; a call with 15 comment lines inside it was not matched; padding a line with a long comment skipped it; secrets leaking through a second rule on the same line, through `add-finding`, and through partial masking.

Resulting design rules: the Python lexer **fails open** (when unsure it re-matches the region as plain lines and prints `python lexer fallback in <file> from line N`); anything deliberately not matched produces a warning with file and line; evidence redaction is a property of the **line** (`redactLine()` in `redact.ts`), shared by every engine and by `read` / `search` / `add-finding`; secrets shorter than 16 characters are fully masked, longer ones show two characters at each end. Inline `code-audit:ignore` comments are listed in the report and can be disabled with `--no-inline-ignore`.

Final state: macOS 371 tests passed (6 real-tool tests skipped); Linux with the three real scanners 374 passed. The reviewers' attack inputs were re-run by the project lead after the last fix round: every hidden sink is reported and no secret literal appears in any output file, `read`, `search`, the regenerated report or CI annotations.

Further limits found by review and left open: a call whose parts are more than one matching window apart (over 100 code lines) can be missed, with a warning; a string literal with no secret-like name and no rule match is shown as is by `read` / `search`; verdict rationale text written by the reviewing agent is stored as written; fingerprints of findings whose evidence contains a masked secret differ from earlier versions; the occurrence index used for repeated identical lines is count-based, so inserting an identical vulnerable line above existing ones reports the last one as new.
