# code-audit

`code-audit` is a deterministic source-code security auditor. It scans a local
project, produces candidate findings with evidence, and gives a host agent (or a
human) the tools to review them and render a report. The core never calls an LLM:
**you** are the reviewer. All repository content is treated as untrusted data.

The project ships three layers:

- **Core** (`@code-audit/core`) — inventory, built-in rule engine, built-in secret
  detection, lockfile parsing with OSV.dev queries, finding model, dedupe,
  verdict storage and Markdown/JSON/SARIF reports.
- **CLI** (`code-audit`) — `scan`, `status`, `findings`, `read`, `search`,
  `verdict`, `add-finding`, `report`, `install`, `doctor`, `mcp`.
- **MCP server** (`code-audit-mcp`) — the same workflow exposed as `audit_*`
  tools over stdio for agent hosts.

## Quick start

```sh
pnpm install
pnpm build
pnpm run link:local          # creates ./bin/code-audit and ./bin/code-audit-mcp
export PATH="$PWD/bin:$PATH" # or add ./bin to your PATH permanently

code-audit scan <dir>                 # scan a project (writes <dir>/.audit/<run>)
code-audit scan <dir> --offline       # skip OSV.dev network queries
code-audit install --host opencode    # install the agent adapter files
code-audit doctor                     # show Node, rules and external tool status
```

`code-audit-mcp` is the stdio MCP server; point your host at it (the `install`
command writes the right config for each supported host).

## Engine tiers

The tool is designed so that a scan always succeeds with **zero external
dependencies**, and gets stronger when optional scanners are present.

| Tier | Engines | Dependency | Notes |
|---|---|---|---|
| **Tier 0** (always available) | built-in YAML rules, built-in secret detection, lockfile parsing + OSV.dev batch query | Node only | OSV queries send only package name/version; `--offline` skips them and the report says so. |
| **Tier 1** (auto when found) | Opengrep/Semgrep, OSV-Scanner, Gitleaks | present on `PATH` | Results are merged and deduped with Tier 0. A missing, failing or timing-out tool never fails the scan; it is recorded as a warning. |
| **Tier 2** (explicit, future) | govulncheck, Bandit, gosec, SpotBugs, Roslyn, clang-tidy | language toolchains | Not implemented yet. |

Use `--engines builtin,opengrep,osv-scanner,gitleaks` to select engines
explicitly, or `--no-external` for Tier 0 only. Opengrep is preferred over
Semgrep; Semgrep is used only when Opengrep is not installed.

## Python coverage

- **Built-in rules (no extra tools):** 70 Python rules — 44 findings and 26 review hotspots — covering SQL, command and code injection, template injection, deserialization, file handling, SSRF / redirect / LDAP / XPath, TLS and crypto, JWT, XML, Flask / Django configuration. Rules match Python *logical lines* (comments and docstrings are ignored, a multi-line call is one unit). A rule is a finding only when the matched statement itself shows request data or a clearly dangerous setting reaching the sink; a bare sink with an unknown variable is a hotspot (a reading list for the reviewing agent, excluded from totals and the exit code).
- **Taint rules (need Opengrep):** 8 data-flow rules follow request data from Flask, Django and FastAPI / Starlette handlers to SQL, command, path, SSRF, template, redirect, deserialization and `eval` sinks, across assignments, string formatting and helper functions in the same file. Not followed: flows across files, through class methods (`self.helper(x)`), the database or the file system.
- **Dependencies:** `requirements*.txt` (including `-r` includes and files in a `requirements/` directory), `poetry.lock`, `uv.lock`, `pdm.lock`, `Pipfile.lock`, `pylock.toml`. Versions are compared with PEP 440 rules, advisories that are aliases of each other (GHSA / CVE / PYSEC) are reported once, and each package is marked direct or transitive and runtime, optional or dev where the lockfile or `pyproject.toml` makes that knowable. Entries without a pinned version (`pkg @ url`, `git+…`, editable installs) cannot be checked and are counted in a warning.
- **Not covered:** XSS in templates, authorization and business-logic flaws, cross-file data flow. These are left to the reviewing agent (see `skills/code-audit/SKILL.md`).

Measured on public projects (see `docs/PY1_REPORT.md`): 0–2 Python findings at confidence ≥ medium on flask, requests and httpie; the deliberately vulnerable pygoat, Vulnerable-Flask-App and DSVW are reported with their real injection, deserialization and configuration flaws.

## Host support

| Host | Adapter | Verification status |
|---|---|---|
| OpenCode | `.opencode/` + `opencode.json` | Verified on a real host (OpenCode v2.4.1). |
| DSH | `dsh/cordis.patch.yml` + `.dsh/` | Verified on a real host (DSH 0.2.2-rc.5). |
| Claude Code | `.claude-plugin/`, `.mcp.json`, `skills/`, `commands/` | Format/schema checked only — **not verified on a real host**. |
| Codex | `.codex/config.toml`, `.agents/`, `AGENTS.md` | Format/schema checked only — **not verified on a real host**. |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Completed and no finding reached the `--fail-on` / `--min-confidence` thresholds. |
| `1` | At least one finding reached the thresholds (or Node < 22 for `doctor`). |
| `2` | Runtime error (bad arguments, missing path, rule loading failure, ...). |

## CI usage

`code-audit` is designed to run in CI with a baseline so that only **new**
findings break the build. Pre-existing findings are recorded in a baseline file
and do not fail the build until they are fixed or explicitly suppressed.

### Baseline workflow

1. Run a scan locally and create a baseline once:

   ```sh
   code-audit scan . --out audit-out
   code-audit baseline audit-out/<run-id>
   ```

   This writes `.code-audit-baseline.json` in the audit root. Commit it.

2. In CI, run with `--ci`. The scan automatically picks up
   `.code-audit-baseline.json` and fails only on findings whose fingerprint is
   not in the baseline:

   ```sh
   code-audit scan . --ci --format sarif,md --out audit-out --latest-link
   ```

   `--latest-link` copies the produced reports to `audit-out/latest/`
   (`audit-out/latest/results.sarif`, `audit-out/latest/report.md`) as plain
   files, so CI can reference a stable path instead of the run-id directory.
   The run directory layout (`audit-out/<run-id>/`) is unchanged.

   Use `--fail-on-existing` to restore the old behaviour (fail on any finding,
   including baseline entries). Use `--no-baseline` to ignore the baseline file.

3. When `GITHUB_ACTIONS=true`, each actionable finding is emitted as a GitHub
   workflow annotation (`::error` for critical/high, `::warning` for medium and
   below), capped at 50. When `GITHUB_STEP_SUMMARY` is set, a Markdown summary
   is appended to the job summary.

See `examples/ci/github-actions.yml`, `examples/ci/gitlab-ci.yml` and
`examples/ci/pre-commit-hook.sh` for reference configurations.

### Suppressing findings

Add a `.code-audit-ignore` file in the audit root to suppress findings by
fingerprint, rule id, path glob or SCA advisory:

```yaml
version: 1
ignore:
  - rule: "py-weak-hash"
    paths: ["tests/**", "legacy/*.py"]
    reason: "MD5 used for cache keys only"
  - paths: ["vendor/**"]
    reason: "third-party code"
  - fingerprint: "<64 hex>"
    reason: "reviewed, not exploitable"
    expires: "2027-06-30"
```

Suppressed findings stay in `findings.json` but are excluded from statistics
and the exit code. Use `--no-ignore-file` to audit everything.

Inline suppression with a `code-audit:ignore <rule-id> -- <reason>` comment on
the line (or the line before it) is also supported. These comments are part of
the audited repository, so they are never applied silently: every candidate
they suppress is listed in the report section "Suppressed findings" (rule,
file:line and the reason given) and kept in `findings.json` with
`status: "suppressed"` and `suppression.source: "inline"`, and a warning states
the count. When the repository is not trusted, pass `--no-inline-ignore`
(MCP `audit_start`: `noInlineIgnore: true`) to ignore the comments and report
every candidate as active.

### Incremental scans

`--since <git-ref>` restricts the report to findings in files changed between
the ref and the working tree (committed, staged, unstaged and untracked but
not git-ignored files). This is useful for pre-commit hooks and pull-request
checks:

```sh
code-audit scan . --since HEAD --ci --profile quick
```

## License

Apache-2.0. The repository bundles only self-written rules; no Semgrep
registry rules are distributed.