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

## Addendum for release 0.2.0

Later changes that affect statements above; the numbers above were not re-measured and are left as recorded.

- The OpenCode adapter was re-verified after this stage: a full audit through the MCP tools with OpenCode 2.4.1 on Linux. DSH 0.2.2-rc.5: the patch composes and the MCP server starts, but a full agent run was not possible (no model credential on the test host). Claude Code 2.1.183: the plugin's MCP server connects (`claude --plugin-dir ... mcp list`); nothing that needs a logged-in CLI was run.
- `js-command-injection` and `js-exec-api` no longer match method calls on other objects (`RegExp.prototype.exec`, `query.exec()`). The per-repository counts above include such matches where the repository contains JavaScript: for example the one critical `js-command-injection` reported in Vulnerable-Flask-App was `c.exec(b)` on a regular expression in a minified third-party script, and is no longer reported. NodeGoat was not re-measured.
- Offline scans with the built-in engines only (macOS, release 0.2.0, no OSV.dev queries, no external scanners), findings at confidence ≥ medium: flask 0, httpie 7, requests 6, DSVW 7, Vulnerable-Flask-App 7, pygoat 91. These are not comparable with the all-engines numbers above, which include dependency advisories and the Opengrep, OSV-Scanner and Gitleaks results.


## Final pre-release review (0.2.0)

A last independent review of the whole repository confirmed four defects and one design gap; all were fixed and the reviewer's inputs replayed by the project lead:

- **MCP root not contained.** A prompt-injected agent could call `audit_start` with any directory and read it back. The MCP server now fixes a base directory at start-up (`--base`, `CODE_AUDIT_MCP_BASE`, default: its working directory) and refuses every path outside it; credential directories are refused as audit roots unless `--allow-sensitive-root` is given on the CLI.
- **Regular-expression search could hang the server** (`(a|aa)+$`). Searches and rule matching now run under an interruptible time limit; globs use a non-backtracking matcher.
- **`--since` could execute a git filter** configured in a hostile `.git/config`. The tool no longer asks git to read the working tree: it lists the tree of the reference and hashes working files itself.
- **Whitespace-separated credentials** (`.netrc` and similar) were not masked by `read` / `search`; masking and detectors for `.netrc`, `.pgpass`, `.npmrc`, `.pypirc`, Docker and kubeconfig credentials were added.
- **Dismissals were invisible.** Findings marked false positive are now listed in a "Dismissed by review" section with reviewer and rationale, raise a cover warning at severity ≥ `--fail-on`, appear as SARIF suppressions, and need evidence for high and critical findings.

Final verification: macOS 644 tests passed (6 real-tool tests skipped); Linux with the three real scanners 647 passed. Package tarballs install and run (`pnpm run pack:verify`). End-to-end audits through MCP tools were re-run on this build with the real Codex CLI (macOS) and OpenCode (Linux). Findings that count toward the exit code with all engines: flask 6, httpie 6, pygoat 379.

Known consequences of the last fixes: with a user-level `safe.directory` no longer read, `--since` fails with a clear error in a repository owned by another user; a host that starts the MCP server outside the project directory must configure the base directory; on checkouts with line-ending conversion or LFS most files count as changed for `--since`.

## Claude Code verification (after 0.2.0 was prepared)

With a logged-in Claude Code 2.1.183 on macOS, both installation styles ran a full audit through the MCP tools with a small model:

- project install (`.mcp.json`, `.claude/skills`, `.claude/commands`), headless `claude -p "/audit" --mcp-config .mcp.json --allowedTools "mcp__code-audit__*"`: the skill, the `/audit` command and all eight tools were found; 42 tool calls, none failed, no permission denial; verdicts, two agent-added findings and the report (including the "Dismissed by review" section) were written; the installed adapter files were skipped by the scan as byte-identical adapter files;
- standalone plugin (`--plugin-dir adapters/claude-code`, `/code-audit:audit`): 29 tool calls, none failed.

This supersedes the "Claude Code … needs a logged-in CLI" item under "Not verified" above. Still not exercised: interactive approval of the project MCP server and installation through the plugin marketplace.
