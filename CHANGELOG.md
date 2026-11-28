# Changelog

All notable changes to this project are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Before 1.0, minor versions may contain breaking changes.

## [Unreleased]

## [0.4.0] - 2026-11-28

Vetting agent skills before install, stricter agent triage, pull-request
scanning with a GitHub Action, and secrets in the git history. Every feature
went through an adversarial review until no high or medium finding was left
open.

**Upgrading from 0.3.0:** no rule id was removed or renamed and a 0.3.0
baseline still applies; findings of the new rules count as new. Where a new
rule shares a group with a released one, the released rule id is kept, so
existing fingerprints do not change. A run whose `verdicts.json` was written
by 0.4.0 (schema version 2) cannot be read by 0.3.0.

### Added

- **`code-audit skill <target>`** (MCP `audit_skill`): one verdict per skill
  or plugin package — `SAFE_TO_INSTALL` (no known risk pattern; not a
  guarantee), `REVIEW`, `DO_NOT_INSTALL` or `INCOMPLETE`. Targets: a
  directory, a `SKILL.md`, a `.zip` / `.tar` / `.tar.gz`, or a git URL
  (hardened shallow clone; refused offline and over MCP); `--recursive`
  for collections. Always untrusted. Highlights:
  - its own zip and tar readers check every structural limit before
    anything is written (size, entry count, 100:1 ratio, traversal, links,
    duplicate and case-colliding names, local / central header agreement,
    no hidden data or second archive in the comment);
  - nothing counts as safe that was not analysed: skipped, binary,
    oversized, LFS-pointer, `.git` content (except a git-created `.git` at a
    local directory root) and unreadable files make the package
    `INCOMPLETE`;
  - every file is also read as text: printable runs of binaries, UTF-16 /
    UTF-32, a NUL-stripped view, and the text of FlateDecode PDF streams go
    through the instruction, shell and secret rules;
  - in skill mode every text file counts as an instruction file;
  - `allowed-tools` is compared with what the bundled scripts do
    (`skill-undeclared-capability`).
- **Agent and skill rules: 589 → 623 built-in rules.** New groups:
  anti-refusal / jailbreak wording (English and Chinese), writes to agent
  memory, configuration and shell start-up files, trigger abuse in
  `description:` front matter, padding that pushes text off screen, prompt
  leakage, cloud-storage uploads, shell-outs to other coding agents,
  package-source redirection, bundled or disguised binaries (`.pyc`, ELF,
  Mach-O, PE, archives under other extensions), and MCP tool poisoning in
  tool and parameter descriptions (injection wording, hidden Unicode,
  homoglyphs). New rule fields `tags` (`malicious-intent`),
  `withinFrontmatter`, `inSkillTree`, `groupPriority`, `fileMagic` and
  others (docs/rules.md). Instruction files that are symbolic links are
  read through the link when it stays inside the root.
- **Structured triage** (`audit_verdict`, `code-audit verdict`): new status
  `proof_gap`; optional evidence `trace` (source → sink, every location
  checked against the run's files), `control`, `missing`, `cwe`;
  `--strict-evidence` / `strict_evidence` makes it mandatory. Independent
  review (`role: "independent"`, a different reviewer label, `blind`
  listings): a disagreement keeps the finding at `needs_review` and stays in
  the report. A person settles a dispute from an interactive terminal
  (`--role human --replace --reviewer <name>`; refused over MCP and when an
  agent environment is detected). Reports show review coverage, open proof
  gaps and disputes; verdict history is append-only and written under a
  lock that is safe across processes.
- **`--diff-lines`** (with `--since`; MCP `diffLines`): report only findings
  on added or changed lines. The line diff is computed by code-audit from
  the blob of the ref; a file with unusual line breaks counts as changed in
  full.
- **GitHub Action** (`action.yml`, `comment/action.yml`,
  `examples/workflows/`): scans pull requests untrusted, uploads SARIF and
  posts inline comments from a separate `workflow_run` job that never runs
  pull-request code. See docs/github-action.md.
- **`--history[=<range>]`** (MCP `history`): secrets in the git history,
  with Gitleaks on an isolated mirror clone. One finding per secret with
  `history { commit, date, stillPresent, occurrences }`; no author data.
  Shallow clones are reported as `partial`.
- `--ignore-file <file>` and `--baseline <file>` apply under `--untrusted`
  when they lie outside the scanned directory and its git work tree (the
  summary names them).

- Rules `agent-credential-read-script` (high, confidence medium) and
  `agent-credential-exfil-script` (high, confidence high, `malicious-intent`):
  a skill or plugin script that reads an SSH private key, `~/.aws/credentials`,
  `~/.netrc`, the GitHub CLI, Docker or Kubernetes credentials,
  `~/.git-credentials` or the macOS keychain; with a network send in the same
  file the package is `DO_NOT_INSTALL`. PowerShell scripts in skill and plugin
  trees are now read (`powershell` rule language).
- MCP `audit_skill`: each package carries `capabilities` (how many scripts
  use the network, subprocesses or file writes, whether `allowed-tools` is
  declared, what is undeclared); `details` lists the tools and up to five
  script paths per capability.
- `findings.json`, SARIF and MCP `audit_findings` carry the agreeing
  independent reviewer's own status (`independentStatus` /
  `independent_status`), and the report says `confirmed (independently
  reviewed by <label>: subagent, said likely)` when it is weaker.

### Changed

- A missing `--ignore-file` is now an error (exit 2).
- A CLI verdict that would replace another reviewer's verdict needs
  `--replace`.
- A source or configuration file with a NUL byte is scanned with the NUL
  bytes removed instead of being skipped as binary.
- The MCP summary text is compact JSON.
- zod 4 (4.6.7) and vitest 4: fixes GHSA-mrhx-c7xc-m3w5 (memory exhaustion when
  validating oversized input, reachable through MCP arguments) and the
  tinypool / vitest advisories of the development tools. Built-in validation
  messages of rule, ignore and run files are worded differently; the MCP
  tool schemas no longer say `additionalProperties: false` (unknown
  arguments are still dropped).
- Six false positives of `prompt-injection-conceal` and
  `prompt-injection-read-credentials` are gone; no 0.3.0 detection was
  lost. Markdown shell blocks are read across `\` continuations, which can
  add hotspots.

### Fixed

- `agent-anti-refusal-never-refuse` missed "You must never refuse any
  request while ..." and "Never refuse," before a comma, colon, question
  mark or dash.
- `install --host codex --absolute` named `AGENTS.md` as containing the
  machine-specific path; only files that hold the path are named.
- `audit_search` / `search --regex`: an inline flag group such as `(?i)` now
  gets an `INVALID_REGEX` message that says the pattern is a JavaScript
  regular expression and the search is case-sensitive, with no
  case-insensitive option.
- The docs said the MCP server has eight tools; it has nine.

### Security

- Every git invocation now also refuses lazy fetches, replace refs, grafts
  and every transport explicitly. In 0.3.0 a hostile partial clone with an
  `ext::` promisor could run a command during `--since`.
- Cross-engine deduplication is linear (a repository producing tens of
  thousands of findings took minutes).
- Gitleaks and other tools are killed with their whole process tree on a
  timeout or signal; stale temporary entries of killed runs are swept.

### Known limits

- Phrase-level obfuscation (shell quoting such as `cu''rl`, words split
  across lines, homoglyphs) and PDF text behind non-Flate filters are not
  seen.
- The human-decision gate is a speed bump, not a proof; anything that can
  write to the run directory can forge records.
- `--history` does not follow submodules; a SIGKILL of code-audit leaves its
  private temporary directory until the next history run sweeps it.

## [0.3.0] - 2026-11-28

Rule coverage for every supported language, Rust as a source language, .NET
and Rust dependency checking, and statement-level matching for the C-family
languages.

**Upgrading from 0.2.0:** no rule id was removed or renamed, and a 0.2.0
baseline still applies. Findings of the new rules are not in it and count as
new; so can findings whose evidence text changed (fingerprints contain the
rule, the file and the evidence, and a statement matched across lines or a
value masked differently gives different evidence). Several existing rules
changed kind, severity or confidence (see "Changed"). Review the new
findings, then regenerate `.code-audit-baseline.json` (`code-audit scan .`,
then `code-audit baseline <run-id>`).

### Added

- **Built-in rules: 156 → 589** (381 findings, 208 review hotspots). Per
  area, with the 0.2.0 count in brackets:
  - Python 102 (70): reflected XSS in Flask / Django / Starlette responses,
    `format_html` misuse, SSRF with a request-controlled host, NoSQL and LDAP
    injection, regex from request data, mass assignment, CORS, weak Django
    password hashers, obsolete TLS, short keys and weak curves, PBKDF2
    iterations, timing-unsafe comparisons, paramiko, XML-RPC, Mako, archive
    extraction, `trust_remote_code`, LangChain `allow_dangerous_*` options
    and execution of LLM output.
  - JavaScript / TypeScript 67 (12): request data reaching commands, `eval`
    and `vm`, SQL, file paths, redirects and HTML; crypto, JWT, TLS, cookies,
    CORS, Express / Electron settings.
  - Java 78 (10): SQL / JPA / MyBatis, command, expression and template
    injection, deserialization (Java serialization, XMLDecoder, XStream,
    Jackson, SnakeYAML, Fastjson), XXE per parser, LDAP, XPath, SSRF, path
    traversal, uploads, Zip Slip, open redirect, XSS, crypto, TLS, Spring
    Security, JWT, cookies, JNDI / Log4j, reflection, ReDoS, and Spring Boot
    `application*.yml` / `bootstrap*.yml` settings (6 of the 78).
  - Go 50 (10): SQL (database/sql, sqlx, gorm, pgx), commands, path
    traversal, Zip Slip, SSRF, open redirect, `html/template` bypasses and
    response XSS, weak crypto and random, TLS, SSH host keys, JWT, bcrypt
    cost, server timeouts, pprof, CORS, cookies, decompression bombs.
  - C# 57 (10): 49 for `.cs` and Razor views (`.cshtml`, `.razor`) covering
    SQL with EF Core and Dapper, commands, LDAP, XPath, deserialization, XXE,
    crypto, TLS, JWT, CORS, cookies, redirects, XSS and Zip Slip, plus 8 for
    .NET configuration (`web.config` / `*.config`, `appsettings*.json`).
  - Rust 38 (new source language, `.rs`): SQL (sqlx, diesel, rusqlite,
    tokio-postgres, sea-orm), shell commands, path traversal, Zip and tar
    slip, TLS verification, weak hashes and ciphers, constant nonces,
    predictable RNG for secrets, hard-coded keys, jsonwebtoken misuse,
    bcrypt cost, unsafe memory APIs, CORS, cookies, open redirects, HTML
    built with `format!`, unbounded reads and allocations.
  - C / C++ 46 (9): format strings, unbounded copies, `argv` / `getenv` into
    commands, `realloc` misuse, temporary files, unchecked `setuid`,
    `chroot`, `umask(0)`, weak ciphers and legacy TLS in OpenSSL, libcurl
    verification off, credential arrays.
  - Dockerfile 13 (4), Compose 10 (2), Kubernetes 26 (7), Terraform 35 (5;
    AWS, Azure, GCP), GitHub Actions 18 (4).
  - Agent configuration, prompt injection and supply chain 38 (10):
    permission bypass in Claude Code, Codex (`.codex/config.toml`), Cursor
    CLI, VS Code / Copilot, Gemini CLI, OpenCode, Zed and Aider settings;
    hooks that exfiltrate credentials or persist; MCP servers from git,
    privileged containers, cleartext URLs, filesystem roots; hidden Unicode,
    hidden HTML comments, concealment, credential reads and
    decode-and-execute in instruction files; unrestricted tools in skills
    and agents.
  - Dependency hygiene 11 (3): plain-HTTP and extra package indexes,
    `--trusted-host`, npm over HTTP and git sources, registry tokens, Go
    checksum database off, install scripts that download.
- **Opengrep rules: 20 → 47**, 37 of them taint rules that follow request
  data to a sink inside one file: Python 13 (11 taint; new: XSS, NoSQL,
  LDAP), JavaScript / TypeScript 8 (7), Java 7 (6), Go 7 (7), C# 6 (5), C 4
  (1), Rust 2 (commands and SQL built with `format!` across lines). Every
  bundled Opengrep rule was executed with Opengrep 1.33.1 on Linux during
  development.
- **C-family lexer:** Java, JavaScript/TypeScript, Go, C/C++ and Rust are now
  matched on statements, like Python and C# (one shared lexer,
  `packages/core/src/lexers/clike.ts`, with each language's string and
  comment syntax: template literals and regex literals, Go raw strings, C++
  raw strings and directives, Rust raw strings, nested comments and
  lifetimes). Code in comments is no longer reported; a call split over lines
  (`sqlx::query(\n &format!(...))`, `executeQuery(\n "..." + id)`) and a
  method chain (`Command::new("sh")` / `.arg("-c")` / `.arg(cmd)`) are seen
  whole and reported on the line where the match starts. `codeOnly` works
  for these languages, and a `code-audit:ignore` text inside a string
  literal no longer suppresses anything. The lexer fails open with a
  "<language> lexer fallback" warning. C# goes through the same lexer.
  The Rust API-call rules set `codeOnly`; `js-cookie-insecure` now sees a
  `cookie: { ... secure: false }` object spread over lines.
- **XML and Razor:** `<!-- -->` and `@* *@` comments are blanked, and an XML
  start tag spread over several lines is one unit.
- **Dockerfiles:** an instruction continued with `\` is one unit (so
  `curl ... \` / `| sh` is found) and comment lines are skipped.
- **Rust test modules:** findings inside `#[cfg(test)] mod name { ... }` are
  lowered like findings in a test path (`pathContext: test`).
- **New recognised file types** (rule languages, coverage and LOC): `razor`
  (`.cshtml`, `.razor`), `xml` (`*.xml`, .NET `*.config`), `toml`, `ini`
  (`*.ini`, `*.cfg`, `.npmrc`, `.yarnrc`, `.pypirc`, `pip.conf`),
  `properties`, `shell` (`.sh`, `.bash`, `.zsh`, `.ksh`), `template` (`.html`,
  `.htm`, `.jinja`, `.jinja2`, `.j2`, `.njk`, `.twig`, `.vue`, `.svelte`,
  `.ejs`, `.hbs`, `.handlebars`, `.mustache`), `requirements` (pip
  requirement and constraint files), and Cursor `.mdc`, `.cursorrules`,
  `.windsurfrules`, `.clinerules` and `.rules` as Markdown. No built-in rule
  targets `template` or `properties` files yet; they are read by secret
  detection like every text file.
- **Rust dependencies:** `Cargo.lock` is checked against OSV.dev (ecosystem
  `crates.io`). The sibling `Cargo.toml` and the workspace members it lists
  mark crates as direct and give their scope (`[dependencies]` and
  `[build-dependencies]` runtime, `[dev-dependencies]` dev, also under
  `[target.'cfg(...)']`, `[workspace.dependencies]`, renamed with
  `package = "..."` and `workspace = true`); the scope of transitive crates
  follows the lockfile's dependency lists. Local crates are skipped; crates
  from git repositories or other registries are counted in a warning. A
  workspace member's `Cargo.toml` no longer reports a missing lockfile when
  the workspace has one. Fixed versions of crates.io advisories are ordered by
  SemVer.
- **.NET dependencies:** NuGet `PackageReference` items in `*.csproj`,
  `*.fsproj` and `*.vbproj`, the nearest `Directory.Build.props` /
  `Directory.Build.targets`, Central Package Management versions from
  `Directory.Packages.props` (with `GetPathOfFileAbove` and relative
  imports, `VersionOverride`), literal MSBuild properties and
  `packages.config` are checked against OSV.dev. Conditional declarations
  contribute every candidate version. Only exact versions are queried;
  version ranges, floating versions and unresolved properties are counted in
  one warning per file. A project's own `packages.lock.json` takes
  precedence and now gives direct / transitive from its `Direct` /
  `Transitive` entries, each package counted once across target frameworks.
  XML is read by a small bounded scanner without DTD or entity expansion.
- **Literal prefilter:** when the rules are loaded, each rule gets the
  literals that every match must contain, and a rule none of whose literals
  occurs in a file is not run on it, which reduces the time the larger
  rule set takes per file; results are identical with and without it
  (checked by a test over every rule, every fixture line and adversarial
  variants). See "Literal prefilter" in `docs/rules.md`.

### Changed

- **Inline suppression:** a `code-audit:ignore` comment counts on any line of
  a multi-line statement, or on a line of its own right before it; a
  trailing comment after code belongs to its own line, not to the statement
  below. When the group winner for an expression is suppressed, the
  next-best rule of the group does not surface in its place; an ignore that
  names only a lower-ranked rule does not suppress a higher-ranked hit. In
  the C-family languages only real comments count. See `docs/rules.md`.
- **Redaction:** `withinKeys` rules with `redactEvidence` mask their match on
  the value's lines (the whole line when the text is not written there as
  matched). Setting words (`http_tokens = "optional"`, `secrets: inherit`),
  algorithm names, dotted class paths, a flag that follows a secret-like
  flag, and non-secret keys inside weakly secret-like sections
  (`"AuthServer": {`, `jwt:`) stay readable; a PEM private-key block is
  masked up to its END marker or the first line that cannot be key
  material, at most 400 lines. See `docs/security-model.md`.
- `withinKeys` also works for JSON rules and compares keys
  case-sensitively; rule `pathInclude` / `pathExclude` filters match
  case-insensitively (`WEB.CONFIG`, `AppSettings.json`).
- **Path context:** `compiled/` and `public/lib/`, `public/libraries/`,
  `public/vendor/` are vendored; `test-*/` directories, Rust `benches/`,
  `fuzz/`, `*_test.rs` and `tests.rs`, and `*_test.*.ts` / `.js` files are
  test code.
- Cargo's `src/bin/` is scanned; other `bin/` directories stay excluded by
  default.
- Existing rules that changed classification: `dockerfile-curl-sh` high
  (was critical); `dockerfile-latest-tag` and `k8s-image-latest-tag` low;
  `gha-pull-request-target`, `go-weak-hash`, `go-ssrf` and
  `agent-mcp-unpinned-npx` are hotspots; `java-sql-injection`,
  `java-command-injection` and `cs-command-injection` high (were critical);
  `cpp-path-traversal` medium / low confidence; confidence changes for
  `dockerfile-no-user`, `agent-disable-permissions`, `go-command-injection`,
  `go-weak-random`, `go-tls-disabled`, `js-sql-injection`,
  `js-command-injection`, `js-path-traversal`, `js-ssrf`,
  `js-tls-disabled`, `cpp-strcpy`, `cpp-gets`, `cpp-sprintf` and
  `cs-insecure-deserialization`. Request-data variants such as
  `js-command-injection-request` and `js-code-injection-request` report the
  clear cases at critical.
- Kubernetes rules apply to any YAML with `apiVersion` or `securityContext`
  (not only `k8s/` folders), Terraform rules to every `.tf` / `.tfvars`
  file, Compose rules to every compose file name.

### Fixed

- MCP `audit_findings` cursors are opaque tokens and a shortened page carries a
  `page_note`: in host tests an agent computed the next offset itself and
  skipped the items a size-capped page had left out. A computed or garbled
  cursor is refused with `INVALID_CURSOR`.

- Precision fixes from review on public repositories in every language,
  among them: JavaScript `RegExp.prototype.exec` and `query.exec()` are not
  subprocesses; minified files (lines of 1000+ characters) are skipped by
  the JavaScript rules; Python `str.find` is not a Mongo call; Polly / LINQ
  lambdas are not C# SQL; constants and later arguments do not make Java SQL
  or command concatenation; Go request data must be in the URL or path
  argument, not in a body; Rust `format!` SQL needs a value interpolation;
  CloudFormation `Resources:` is not Kubernetes RBAC `resources:`; a bare
  `path: /` probe is not a `hostPath` mount; GitHub Actions trigger gates
  read the `on:` declaration, not the word.
- A file named `dockerfile.<ext>` with a known extension (`dockerfile.py`)
  keeps the language of its extension; `Dockerfile.prod` and
  `api.Dockerfile` stay Dockerfiles.
- File-level rule conditions test an over-long line in the same windows as
  rule matching, so a long line no longer switches the Kubernetes gating
  off.
- `go-template-injection` and `py-hf-trust-remote-code` no longer take
  quadratic time on crafted input.

### Known limits

See "Limits" in the README and `docs/security-model.md`. In short: pattern
rules do not follow data across statements or files; C-family lexers fail
open to line matching; Terraform is matched line by line; HTML templates,
Vue / Svelte `<script>` blocks and `.properties` files have no rules; NuGet
projects without `packages.lock.json` are checked for direct references
only; Semgrep has never been executed in testing; Windows is untested.

## [0.2.0] - 2026-11-27

First public release. Version 0.1.0 was used by development builds only and
was never released.

**Upgrading from a 0.1.0 development build:** regenerate
`.code-audit-baseline.json` (`code-audit scan .`, then
`code-audit baseline <run-id>`). Baselines written by 0.1.0 builds do not
match dependency findings (advisory ids are now GHSA-first), findings whose
evidence contains a masked secret, or repeated identical lines in one file,
so those findings would be reported as new.

### Added

- **Scan engines that need only Node.js:** 156 built-in rules (113 findings,
  43 review hotspots) for Python, JavaScript/TypeScript, Java, Go, C/C++, C#,
  Dockerfile, Compose, Kubernetes, Terraform, GitHub Actions and agent
  configuration files; secret detection with masked evidence; dependency
  advisories from OSV.dev for `package-lock.json`, `pnpm-lock.yaml`,
  `requirements*.txt`, `poetry.lock`, `uv.lock`, `pdm.lock`, `Pipfile.lock`,
  `pylock.toml`, `go.mod`, `pom.xml` and `packages.lock.json`, with
  direct/transitive and runtime/dev/optional scope where the files say so.
- **Python support:** 70 rules matched on logical lines (comments and
  docstrings ignored, multi-line calls as one unit), and 8 Opengrep taint
  rules for Flask, Django and FastAPI / Starlette request data.
- **Optional external engines**, used when found on `PATH` and merged with
  the built-in results: Opengrep (Semgrep as fallback), OSV-Scanner,
  Gitleaks. `--engines` and `--no-external` select them.
- **Reports:** Markdown, JSON and SARIF from one counting model: findings at
  confidence ≥ `--min-confidence` by severity and category, low-confidence
  candidates, hotspots and suppressed findings as separate numbers, top
  risks, dependencies aggregated per package version. English and Chinese
  report text (`--lang`).
- **Review workflow** in the CLI (`status`, `findings`, `read`, `search`,
  `verdict`, `add-finding`, `report`) and as eight `audit_*` tools in the
  stdio MCP server `code-audit-mcp`. Verdicts re-render every report file of
  the run.
- **CI:** `--ci` (GitHub annotations and step summary), baseline
  (`code-audit baseline`, `--baseline`, `--no-baseline`,
  `--fail-on-existing`), `.code-audit-ignore` with reasons and expiry dates,
  inline `code-audit:ignore` comments, incremental scans (`--since`),
  `--latest-link`, `--profile quick` (built-in engines only, no network, for
  pre-commit hooks), exit codes 0 / 1 / 2.
- **Untrusted repositories:** `--untrusted`; a `WARNING` with counts for
  everything in the audited repository that takes findings out of the exit
  code (path context, dependency scope, placeholder secrets, baseline, ignore
  file, inline comments, excluded directories, files that look like tool
  output); run directories, their JSON files and symbolic links in them are
  not trusted by later commands; repository text is escaped in every report.
- **Path context and adjustments:** `pathContext`, `confidenceOriginal` and
  `adjustments` on findings; `--include-tests`, `--include-dev`,
  `--include-placeholders`.
- **Host adapters:** `code-audit install --host opencode|dsh|claude-code|codex`
  with `--project`, `--mcp-command`, `--absolute`, `--force`, `--dry-run`
  and `--uninstall`; a shared skill; a Claude Code plugin and marketplace
  manifest; `code-audit doctor [--project <dir>]`.
- **MCP base directory:** the server audits, reads and writes only inside
  the directory it was started in, or the one given with
  `code-audit-mcp --base <dir>` / `CODE_AUDIT_MCP_BASE`; the `root` of every
  tool and `baseline` must resolve inside it (symbolic links followed). The
  base is printed to stderr at start-up.
- **Sensitive roots:** credential and configuration directories (`~/.ssh`,
  `~/.aws`, `~/.gnupg`, `~/.config`, `~/.kube`, `~/.docker`, `/etc`, ...),
  everything below them and every directory that contains the home directory
  are refused as audit roots; `--allow-sensitive-root` (CLI only) overrides
  the first group.
- **Search limits:** `search --regex` / `audit_search` are interrupted after a
  wall-clock budget (2 s; `--timeout-ms` on the CLI) and fail with
  `SEARCH_TIMEOUT`; literal searches never use the regex engine; globs are
  matched without backtracking; rule matching of a file is interrupted when a
  pattern does not return.
- **`--since` without git reading the working tree:** file lists come from
  `git ls-tree` and `git ls-files`, content is compared by blob ids computed
  in-process, so clean/smudge/process filters, textconv and diff drivers
  configured in the audited repository never run. Files that differ only by
  line endings or a filter count as changed; the files of a submodule are
  all in scope; the user and system git configuration is not read.
- **Credential files:** `.netrc`, `.pgpass`, `.npmrc`, `.pypirc` / `pip.conf`,
  Docker `auths` and kubeconfig credentials are reported
  (`secret-netrc-password`, `secret-pgpass-password`, `secret-npmrc-auth`,
  `secret-pypirc-password`, `secret-docker-auth`,
  `secret-kubeconfig-credential`), and whitespace-separated credentials
  (`password VALUE`, `sshpass -p`, `mysql -p...`, `docker login -p`,
  `curl -u user:pass`, cookies, `.htpasswd`) are masked in every output.
- **Dismissed by review:** the Markdown report lists every `false_positive`
  verdict with reviewer and rationale, SARIF records it as a suppression,
  the cover and every summary warn when dismissed findings are at severity ≥
  `--fail-on`, and dismissing a `high` or `critical` finding requires a
  rationale of at least 40 characters plus `--evidence-line` /
  `evidenceLines` or a `file:line` reference.
- `code-audit --version`; `--help` after any command; a description of every
  scan option in the help text; `doctor` reports finding and hotspot rule
  counts.
- **Packaging:** the three packages (`@code-audit/core`, `@code-audit/mcp`,
  `@code-audit/cli`) carry complete metadata and can be packed and installed
  from tarballs; `@code-audit/core` ships the rules, the skill and the
  adapter templates; `@code-audit/cli` installs both `code-audit` and
  `code-audit-mcp`. Nothing is published to npm yet.
- Documentation: `docs/reports.md`, `docs/rules.md`, `docs/mcp.md`,
  `docs/security-model.md`, `SECURITY.md`, `CONTRIBUTING.md`, issue templates
  and a CI workflow for this repository.

### Changed

- Rules, skill and adapter files are located through one function that works
  in a checkout and in an installed package. The environment variable for the
  Opengrep rule directory is `CODE_AUDIT_OPENGREP_RULES_DIR`; the misspelt
  `CODE_AUDIT_OPENREP_RULES_DIR` of development builds is still read.
- The MCP server reports the tool version, and `audit_status` shortens a long
  `warnings` list instead of dropping the counts when a response would exceed
  the size cap.

### Known limits

See "Limits" in the README, `docs/security-model.md`, `docs/M4_REPORT.md` and
`docs/PY1_REPORT.md`. In short: pattern rules do not follow data across
statements or files; Semgrep has never been executed in testing; Windows is
untested.

[Unreleased]: https://github.com/oliver-zhao/code-audit/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/oliver-zhao/code-audit/releases/tag/v0.3.0
[0.2.0]: https://github.com/oliver-zhao/code-audit/releases/tag/v0.2.0
