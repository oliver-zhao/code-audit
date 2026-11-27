# Changelog

All notable changes to this project are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Before 1.0, minor versions may contain breaking changes.

## [Unreleased]

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

[Unreleased]: https://github.com/oliver-zhao/code-audit/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/oliver-zhao/code-audit/releases/tag/v0.2.0
