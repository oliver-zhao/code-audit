# Changelog

All notable changes to this project are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Before 1.0, minor versions may contain breaking changes.

## [Unreleased]

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
