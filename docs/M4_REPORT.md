# M4 report: real-project results, report layout, host adapters, trust hardening

This stage was driven by scans of public repositories and by first runs on real host agents, followed by an independent adversarial review that confirmed 20 defects, all addressed below.

## Changes

### Reading the results
- One counting model (`summarizeFindings`, `countsTowardExitCode`, `runPolicy`) for the Markdown cover, SARIF properties, `findings.json`, the CLI and `--ci` summaries, the GitHub step summary, `status` and the MCP tools. The headline counts active findings at confidence ≥ `--min-confidence`, by severity and category; low-confidence candidates, hotspots and suppressed findings are separate numbers; the first line states how many findings count toward the exit code.
- Dependencies are aggregated per package@version with scope (runtime / optional / dev / unknown); advisories in dev dependencies are set aside (confidence low) unless `--include-dev`.
- Path context (`test`, `docs`, `example`, `vendored`, `generated`) is recorded on every finding and lowers confidence one step for test, docs and example paths. Never lowered: critical findings with high confidence, private keys, URL credentials, provider tokens, CI / Docker / manifest / agent-instruction files. A "generated" header alone never lowers.
- Placeholder-looking secret values are reported at low confidence instead of being dropped.
- `gha-script-injection` evaluates `run:` / `script:` values on the parsed YAML document (aliases, anchors, quoted keys, `env` and `matrix` indirection), with a line-based fallback and a warning when a file cannot be parsed.
- Report length on public projects: flask 581 → about 200 lines, pygoat 3289 → about 600.

### Nothing in the audited repository reduces the result silently
Every repository-controlled reduction is printed as a `WARNING` on the cover and in the CLI summary with counts: findings lowered by path context or dependency scope, an ignore file or baseline located inside the audited repository, inline ignore comments, source files in default-excluded directories, files recognised as the tool's own output. `--untrusted` switches all of these mechanisms off at once. The scanner no longer reads `.code-audit/installed.json`; an adapter file is skipped only when it is byte-identical to the shipped one, and merged files such as `.mcp.json` and `AGENTS.md` are always scanned.

### Run directories are not trusted
The audit root of a run is derived from where the run directory is, never from `run.json`. Runs are resolved without following symbolic links out of `<root>/.audit`. Every file the tool writes goes through an atomic no-follow write. Later commands load the bundled rules, not a rules directory named by the run. All JSON read from a run directory is schema-validated. After `verdict` and `add-finding` every derived file is re-rendered, and a `confirmed` verdict restores a lowered finding.

### Host adapters
- `install` plans, validates and then writes atomically with rollback; the MCP command comes only from the command line or the default; existing configuration is merged without rewriting user content and refused when it cannot be merged safely; `--uninstall`, `--absolute`, `--mcp-command`, `--force`.
- Claude Code: project install to `.claude/skills`, `.claude/commands` and `.mcp.json`; a standalone plugin in `adapters/claude-code` (validated with `claude plugin validate --strict`).
- Codex: verified end to end with the real Codex CLI 0.166 (`codex exec`): six MCP tools completed (`audit_start`, `audit_status`, `audit_findings`, `audit_read`, `audit_verdict`, `audit_report`). A project-level `.codex/config.toml` is only honoured for a trusted project, and non-interactive runs need the MCP tools pre-approved; `install` prints these steps.

## Verification
- macOS: 571 tests passed (6 real-tool tests skipped). Linux with Opengrep 1.33.1, OSV-Scanner 2.7.1, Gitleaks 8.30.1: 574 passed. License check passes. `fixtures/clean`: no finding with all engines.
- The reviewer's attack inputs were replayed by the project lead after the fixes: planted manifest (2 critical findings reported again), `# @generated` header (finding counted), YAML key variants (all reported), planted run directory (no read of, or write to, a neighbouring project), symlinked `report.md` (target untouched), planted manifest naming an MCP command (default command written).
- Public repositories, all engines, findings that count toward the exit code: flask 6, httpie 6, requests 7, DSVW 10, Vulnerable-Flask-App 61, NodeGoat 211, pygoat 379.

## Not verified / known limits
- Claude Code: everything that needs a logged-in CLI (approving the project MCP server, `/audit` end to end, skill discovery) — the CLI login on the test machine had expired.
- OpenCode and DSH adapters were verified on real hosts at an earlier stage and not re-run after this stage's installer changes.
- Codex project trust and `codex mcp add` were not exercised (they modify the user's configuration).
- Configuration files of the external tools inside the audited repository (`.gitleaks.toml`, `.gitleaksignore`, `.semgrepignore`, `osv-scanner.toml`) are still honoured by those tools; the scan only warns.
- Default-excluded directories (`node_modules`, `dist`, `vendor`, …) are not read unless `--untrusted`; their source files are counted in a warning.
- The generic password detector still ignores values under 8 characters and very low-entropy values.
- `shell:` keys and YAML merge keys are not interpreted by the workflow rules; composite actions are not covered.
- A parent directory swapped for a symbolic link between validation and rename can still redirect a write; Node offers no directory-descriptor traversal to close this fully.
- Baselines written by earlier versions do not match SCA findings (advisory ids are now GHSA-first) or findings whose evidence contains a masked secret.
