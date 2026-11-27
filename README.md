# code-audit

[![CI](https://github.com/oliver-zhao/code-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/oliver-zhao/code-audit/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A security audit plugin for coding agents, with a deterministic scanning core.

[简体中文](README.zh-CN.md)

`code-audit` scans a local project for vulnerabilities, hard-coded secrets,
risky configuration and vulnerable dependencies, and writes the candidates
with their evidence to Markdown, JSON and SARIF. A coding agent (Claude Code,
Codex, OpenCode, DSH) then reviews them through eight MCP tools: it reads the
code around each candidate, records a verdict with a rationale, adds what the
scanner missed and renders the final report. The same workflow is available
to a person on the command line and to CI.

The scanner itself never calls a model. The split is deliberate:

| Part | Does | Does not |
|---|---|---|
| **Scanner** (this tool) | Finds candidates the same way every time, masks secrets, counts what fails a build, treats the scanned repository as untrusted input | Judge reachability or exploitability |
| **Reviewer** (your agent, or you) | Reads the code, confirms or dismisses each candidate with evidence, finds logic flaws | Decide silently: every dismissal is listed in the report |

- [Supported languages and files](#supported-languages-and-files)
- [Supported agents](#supported-agents)
- [Installation](#installation)
- [Usage](#usage): [command line](#command-line) · [in an agent](#in-an-agent) · [in CI](#in-ci)
- [Example](#example) · [Sample report](#sample-report)
- [Reading the result](#reading-the-result) · [Engines](#engines) · [Untrusted repositories](#untrusted-repositories)
- [Configuration reference](#configuration-reference) · [Exit codes](#exit-codes) · [Limits](#limits)
- [Testing](#testing) · [Development](#development) · [License](#license)

**What it is not.** It does **not prove the absence of vulnerabilities**: a
clean scan means these engines matched nothing, not that the code is safe.
Findings are **candidates**: most rules look at one statement at a time. It
does not find authorization and business-logic flaws, XSS in templates, or
data flow across files (see [Limits](#limits)).

## Supported languages and files

Everything in this table works with Node.js alone. `code-audit doctor` prints
the rule counts of your build.

| Language / file type | Recognised files | Built-in rules | Dependency files checked against [OSV.dev](https://osv.dev) |
|---|---|---:|---|
| **Python** | `.py`, `.pyw` | 70 | `requirements*.txt` (with `-r` includes), `poetry.lock`, `uv.lock`, `pdm.lock`, `Pipfile.lock`, `pylock.toml` |
| **JavaScript / TypeScript** | `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.mts`, `.cts` | 12 | `package-lock.json`, `pnpm-lock.yaml` |
| **Java** | `.java` | 10 | `pom.xml` (direct dependencies with literal versions) |
| **Go** | `.go` | 10 | `go.mod` |
| **C#** | `.cs` | 10 | `packages.lock.json` |
| **Rust** | none (no `.rs` rules yet) | 0 | `Cargo.lock` (with `Cargo.toml` and workspace members for direct/dev scope) |
| **C / C++** | `.c`, `.h`, `.cc`, `.cpp`, `.cxx`, `.hpp`, `.hh`, `.hxx` | 9 | none |
| **Dockerfile / Compose** | `Dockerfile*`, compose files | 6 | |
| **Kubernetes manifests** | `.yml`, `.yaml` | 7 | |
| **Terraform** | `.tf`, `.tfvars` | 5 | |
| **GitHub Actions** | `.github/workflows/*.yml` | 4 | |
| **Agent configuration** | MCP server configs, skills, `AGENTS.md`, hooks, agent settings | 10 | |
| **Dependency hygiene** | manifests, Dockerfiles, shell scripts | 3 | |
| **Secrets** | every text file | detectors, not rules | |

156 built-in rules in total: 113 report **findings** and 43 report
**hotspots** (a dangerous API with no visible attacker input: a reading list
for the reviewer, never counted). Python is the most developed language: its
rules match logical lines, ignore comments and docstrings, and cover SQL,
command and code injection, template injection, deserialization, file
handling, SSRF, redirects, TLS and crypto, JWT, XML, and Flask / Django
configuration. The other languages have a small set of pattern rules for the
most common injection and crypto mistakes.

With [Opengrep](https://github.com/opengrep/opengrep) installed, 20 more
bundled rules run (2 each for Python, JavaScript, Java, Go, C#, C, plus 8
**Python taint rules** that follow request data from Flask, Django and
FastAPI handlers to SQL, command, path, SSRF, template, redirect,
deserialization and `eval` sinks inside one file). See [Engines](#engines).

Secret detection covers private keys, provider tokens (AWS, GitHub, Slack,
...), credentials in URLs, password and key assignments, and credential files
(`.netrc`, `.pgpass`, `.npmrc`, `.pypirc`, Docker `auths`, kubeconfig). Secret
values are masked in every output.

## Supported agents

`code-audit install --host <host>` writes project-local configuration for each
host. All four were run end to end with a real model: a full audit from scan
to rendered report through the MCP tools, checked in the tool-call logs.

| Agent | Tested version | `--host` | Start an audit |
|---|---|---|---|
| [Claude Code](https://claude.com/claude-code) | 2.1.183 (macOS) | `claude-code` | `/audit` in the project, or headless `claude -p "/audit" --mcp-config .mcp.json --allowedTools "mcp__code-audit__*"` |
| [Codex CLI](https://developers.openai.com/codex/cli) | 0.166 (macOS) | `codex` | ask for a security audit; headless `codex exec` with the three `-c` overrides that `install` prints |
| [OpenCode](https://opencode.ai) | 2.4.1 (Linux) | `opencode` | `/audit`, or `opencode run "Run a security audit of this project with the code-audit skill"` |
| DeepSeek Harness (DSH) | 0.2.2-rc.5 (Linux) | `dsh` | `dsh <profile> --patch dsh/cordis.patch.yml`, then ask for a security audit |

Any other MCP-capable agent can use the stdio server `code-audit-mcp`
directly; the tools and their arguments are described in
[docs/mcp.md](docs/mcp.md). Not exercised: approving the Claude Code project
server interactively, installing the Claude Code plugin through a
marketplace, Codex project trust. Details per host:
[Agent host details](#agent-host-details) and `adapters/<host>/README.md`.

## Installation

Requirements: **Node.js 22 or later**, git, and pnpm (`corepack enable`
provides it; or `npm install -g pnpm`). macOS and Linux are tested; Windows is
not. The packages are not published to npm yet, so install from a checkout:

```sh
git clone https://github.com/oliver-zhao/code-audit.git
cd code-audit
corepack enable
pnpm install          # a "Failed to create bin" warning before the first build is harmless
pnpm build
export PATH="$PWD/bin:$PATH"    # bin/code-audit and bin/code-audit-mcp
```

Add the `export` line to your shell profile to keep the commands available.
Check the installation:

```sh
code-audit doctor
```

```text
code-audit doctor (0.2.0)
Node.js: 24.22.1 OK
Rules: 156 built-in: 113 finding, 43 hotspot (<checkout>/rules)
Opengrep rules: 20 (<checkout>/rules/opengrep)
External tools (detection only, not invoked):
  opengrep       missing
  osv-scanner    missing
  gitleaks       found  /opt/homebrew/bin/gitleaks (8.30.1)
```

**Optional scanners.** Nothing else is required. If `opengrep`, `osv-scanner`
or `gitleaks` are on your `PATH`, the scan runs them too and merges their
results (see [Engines](#engines)); `doctor` shows which ones it found and
where to get the others. code-audit never downloads tools or rule packs.

**Update:** `git pull && pnpm install && pnpm build`. **Uninstall:** remove
the checkout; per-project adapter files are removed with
`code-audit install --uninstall --host <host>`.

## Usage

### Command line

```sh
cd /path/to/project
code-audit scan .                      # add --offline to skip the OSV.dev lookups
```

The run is written to `.audit/<run-id>/` inside the project (add `.audit/` to
its `.gitignore`), or to `<dir>/<run-id>/` with `--out <dir>`:

| File | For |
|---|---|
| `report.md` | People: summary, top risks, every finding with evidence and remediation |
| `findings.json` | Complete data: findings, hotspots, suppressions, verdicts |
| `results.sarif` | Code-scanning tools (GitHub code scanning, IDEs) |
| `coverage.json`, `run.json` | What was and was not scanned; options and counts of the run |

Common variants:

```sh
code-audit scan . --offline --no-external      # built-in engines only, no network
code-audit scan . --fail-on critical           # exit 1 only for critical findings
code-audit scan . --since origin/main          # only files changed since a git ref
code-audit scan third-party/ --untrusted       # code you did not write: honour none of its own ignore rules
code-audit scan . --lang zh                    # report in Chinese
```

Review a run without an agent (`<run>` is the run id the scan printed):

```sh
code-audit findings <run> --severity high
code-audit read <run> app/server.py --start 15 --end 25
code-audit verdict <run> AUD-2026-0001 --status confirmed \
  --rationale "name comes from request.args and is formatted into the SQL text"
code-audit report <run> --format md            # report.md now carries the verdicts
```

All review commands are in [Reviewing findings](#reviewing-findings), all
flags in the [Configuration reference](#configuration-reference).

### In an agent

Install the adapter into the project you want to audit, then ask the agent.
`--absolute` writes the full path of this installation's MCP server, so it
works whatever `PATH` the agent was started with (do not commit the resulting
config file; without the flag the bare command `code-audit-mcp` is written,
which is the form to commit).

```sh
cd /path/to/project
code-audit install --host claude-code --absolute    # or: codex | opencode | dsh
code-audit doctor --project .                       # what is installed, does the MCP command resolve?
```

```text
code-audit install --host claude-code
Project: /path/to/project
  created   /path/to/project/.mcp.json
  created   /path/to/project/.claude/skills/code-audit/SKILL.md
  created   /path/to/project/.claude/commands/audit.md
```

Then, in the agent:

```text
/audit
```

or in plain words: *"Run a security audit of this project with the code-audit
skill and render the report."* The agent follows the shared workflow in
[skills/code-audit/SKILL.md](skills/code-audit/SKILL.md):

1. `audit_start`: run the scan; `audit_status`: wait for it and get the counts
2. `audit_findings`: list candidates, highest risk first
3. `audit_read` / `audit_search`: read the evidence (secrets masked, repository text marked as untrusted)
4. `audit_verdict`: `confirmed`, `likely`, `needs_review` or `false_positive`, each with a rationale
5. `audit_add_finding`: add what the rules missed, or promote a hotspot
6. `audit_report`: render the reviewed report

`install` only writes inside the project, merges into existing configuration
without rewriting your content, and shows its plan with `--dry-run`. The MCP
server only audits the directory the agent starts it in.

### In CI

```sh
code-audit scan . --ci --format sarif,md --out audit-out --latest-link
```

With a committed baseline only **new** findings fail the build. Baseline,
SARIF upload, GitHub annotations and incremental scans are described under
[CI usage](#ci-usage).

## Example

The repository contains a small, deliberately vulnerable project
([examples/demo-app](examples/demo-app)): a Flask service, a Node.js file, a
Dockerfile, a GitHub Actions workflow, old pinned dependencies and fake
credentials, 107 lines in 6 files.

```sh
code-audit scan examples/demo-app --no-external --out /tmp/code-audit-demo
```

```text
code-audit scan completed: 20261127T035043Z-e31e763d
Files: 6 scanned / 0 skipped, LOC 107
Rules: 156
Findings: 22 (critical 5, high 10, medium 7, low 0, info 0) at confidence >= medium
  by category: code 8, secrets 2, config/IaC 4, dependencies 8
  dependencies: advisories 8, vulnerable packages 3; advisories/packages by scope: runtime 0/0, dev/optional 0/0, unknown 8/3
Low-confidence candidates: 1 (not counted above; code 1, secrets 0, config/IaC 0, dependency advisories 0)
Hotspots: 2 (not counted above)
Exit code: 1 - 15 findings count toward the exit code (severity >= high, confidence >= medium)
Duration: 1993 ms
Report directory: /tmp/code-audit-demo/20261127T035043Z-e31e763d
```

The command exits with status 1 because findings reached the thresholds; that
is the expected result here (see [Exit codes](#exit-codes)). A few of the 22:

| Finding | Location | Rule |
|---|---|---|
| SQL built with an f-string from a request parameter | `app/server.py:21` | `py-sql-injection` (critical) |
| `pickle.loads(request.data)` | `app/server.py:46` | `py-insecure-deserialization` (critical) |
| Shell command built by concatenation | `web/tools.js:8` | `js-command-injection` (critical) |
| `curl ... \| sh` in an image build | `Dockerfile:4` | `dockerfile-curl-sh` (critical) |
| Issue title interpolated into a `run:` script | `.github/workflows/triage.yml:13` | `gha-script-injection` (high) |
| AWS access key id | `config/prod.env:4` | `secret-aws-access-key` (high) |
| pyyaml 5.3.1 → upgrade to 5.4 | `requirements.txt:2` | advisory `GHSA-8q59-q68h-6hv4` (critical) |

The parameterized query at `app/server.py:29` is **not** a finding: it is
listed as a hotspot for the reviewer and does not count. The dependency
advisories come from OSV.dev; with `--offline` they are skipped and the report
says the dependencies were not checked. Advisory data changes over time, so
your numbers for the dependency rows can differ.

The clean counterpart of the test fixtures gives the other result:

```sh
code-audit scan fixtures/clean --offline --no-external --out /tmp/code-audit-clean
```

```text
Findings: 0 (critical 0, high 0, medium 0, low 0, info 0) at confidence >= medium
Exit code: 0 - 0 findings count toward the exit code (severity >= high, confidence >= medium)
```

## Sample report

The complete `report.md` of the demo run above is committed as
[examples/demo-app/sample-report.md](examples/demo-app/sample-report.md)
(352 lines). It starts with what fails the build and the top risks:

```markdown
## 1. Executive Summary

**15 findings count toward the exit code** (severity ≥ high, confidence ≥ medium); a scan with these thresholds exits 1.

**Findings at confidence ≥ medium**

| Category | Critical | High | Medium | Low | Info | Total |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Code | 3 | 4 | 1 | 0 | 0 | 8 |
| Secrets | 0 | 2 | 0 | 0 | 0 | 2 |
| Configuration / IaC | 1 | 2 | 1 | 0 | 0 | 4 |
| Dependencies (advisories) | 1 | 2 | 5 | 0 | 0 | 8 |
| **Total** | **5** | **10** | **7** | **0** | **0** | **22** |

### Top risks

1. **CRITICAL** · high · Code — Python SQL statement built with string formatting — app/server.py:21
2. **CRITICAL** · high · Code — Python unpickles request data — app/server.py:46
3. **CRITICAL** · high · Code — Node.js child\_process command built with concatenation — web/tools.js:8
4. **CRITICAL** · high · Configuration / IaC — Dockerfile executes a remote script with curl \| sh — Dockerfile:4
5. **CRITICAL** · high · Dependency — pyyaml 5.3.1 (unknown, direct): 1 advisory, upgrade to 5.4 — requirements.txt
```

then lists every finding grouped by rule, with CWE, description, remediation
and the matched line:

```markdown
### Python SQL statement built with string formatting — `py-sql-injection`

**CRITICAL** · Code · CWE-89 · A03:2021 · 1 location

**Description**: A value is formatted into the SQL text \(f-string, concatenation, % or .format\(\) in value position\), or the statement comes straight from the request.

**Remediation**: Keep the SQL text constant and pass values as bound parameters \(? / %s placeholders with a parameter tuple\).

**AUD-2026-0001** · app/server.py:21 · Confidence: high · Status: candidate · Engine: builtin-rules

~~~text
cursor.execute(f"SELECT id, name FROM users WHERE name = '{name}'")
~~~
```

and aggregates dependencies per package:

```markdown
| Package | Installed | Scope | Relation | Advisories | Max severity | Recommended upgrade | Advisory IDs | Lockfile |
| --- | --- | --- | --- | ---: | --- | --- | --- | --- |
| pyyaml | 5.3.1 | unknown | direct | 1 | critical | 5.4 | GHSA-8q59-q68h-6hv4 | requirements.txt:2 |
| requests | 2.19.1 | unknown | direct | 5 | high | 2.33.0 | GHSA-x84v-xcm2-53pg, GHSA-9hjg-9r4m-mvj7, GHSA-9wx4-h78v-vm56 +2 more | requirements.txt:3 |
| flask | 2.0.1 | unknown | direct | 2 | high | 2.2.5 \(same major, 1 open\) / 3.1.3 \(fixes all\) | GHSA-m2qf-hxjv-5gpq, GHSA-68rp-wp8r-4726 | requirements.txt:1 |
```

Further sections: low-confidence candidates, review hotspots, suppressed
findings, findings dismissed by review, coverage and limitations (engines
that ran, files skipped, warnings), and the rules that fired. After an agent
or a person has reviewed the run, every finding shows its verdict and the
cover says how many were reviewed.

## Reading the result

The numbers on the cover and in every summary mean:

| Number | What it counts |
|---|---|
| **Findings** (the headline) | Active findings at confidence ≥ `--min-confidence` (default `medium`), by severity and category. |
| **Low-confidence candidates** | Active findings below that confidence. Listed separately; never in the exit code at that threshold. |
| **Hotspots** | Uses of dangerous APIs with no visible attacker input: a reading list for the reviewer. Never counted. |
| **Suppressed / false positive** | Excluded from the numbers above; both are always listed in the report ("Suppressed findings", "Dismissed by review"). |

`WARNING` lines on the cover mean that something inside the scanned repository
(a `tests/` path, a baseline, an ignore entry, an excluded directory) kept
findings out of the exit code; each one names the flag that counts them again.
The full counting model, report layout and confidence adjustments are in
[docs/reports.md](docs/reports.md).

### Reviewing findings

Every run can be reviewed from the command line (an agent does the same
through the MCP tools). `<run>` is the run id printed by the scan; run these
in the scanned project, or pass `--root <project>`.

```sh
code-audit findings <run> --kind finding --severity high
code-audit read <run> src/app.py --start 5 --end 20        # secrets masked
code-audit search <run> "shell=True"
code-audit verdict <run> AUD-2026-0001 --status confirmed \
  --rationale "username comes from request.args and is concatenated into the SQL text"
code-audit verdict <run> AUD-2026-0002 --status false_positive \
  --rationale "the command is a fixed argument list, no shell and no request data" \
  --evidence-line 'subprocess.run(["ls", "-l"])'
code-audit add-finding <run> --promote HOT-2026-0001 --rationale "cmd is request data"
code-audit report <run> --format md       # re-renders report.md with the verdicts
```

Verdicts are `confirmed`, `likely`, `needs_review` and `false_positive`.
After each verdict the report files of the run are rendered again, so every
output shows the same numbers. A `false_positive` is never just dropped: the
report lists every one under "Dismissed by review" with reviewer and
rationale, SARIF records it as a suppression, and when a dismissed finding is
at severity ≥ `--fail-on` the cover and every summary carry a `WARNING`.
Dismissing a `high` or `critical` finding needs a rationale of at least 40
characters and evidence (`--evidence-line`, or a `file:line` reference in the
rationale). `search` takes literal text; with `--regex` the search is
interrupted after `--timeout-ms` (default 2000) and fails with
`SEARCH_TIMEOUT`. For a run written with `--out <dir>` outside
`.audit`, pass the run directory instead of the id and `--root <project>` to
`read`, `search` and `add-finding`.

`scan` refuses the filesystem root, your home directory and well-known
credential and configuration directories (`~/.ssh`, `~/.aws`, `~/.config`,
`/etc`, ... and everything below them) as the audit root; pass
`--allow-sensitive-root` when you do mean to audit one (the same flag lets
`read`, `search` and `add-finding` work on such a run).

## Engines

| Engine | Needs | What it does |
|---|---|---|
| Built-in rules | Node only | 156 rules (113 findings, 43 hotspots); `code-audit doctor` prints the counts of your build. See [docs/rules.md](docs/rules.md). |
| Built-in secret detection | Node only | Private keys, provider tokens (AWS, GitHub, Slack, ...), credentials in URLs, password and key assignments, and credential files (`.netrc`, `.pgpass`, `.npmrc`, `.pypirc` / `pip.conf`, Docker `auths`, kubeconfig). Values are masked in every output. |
| Dependency advisories | Node only, network | Parses `package-lock.json`, `pnpm-lock.yaml`, `requirements*.txt`, `poetry.lock`, `uv.lock`, `pdm.lock`, `Pipfile.lock`, `pylock.toml`, `go.mod`, `pom.xml` (direct dependencies with literal versions), `packages.lock.json`, `Cargo.lock` and queries OSV.dev. Only package names and versions are sent. `--offline` skips the queries and the report says so. |
| Opengrep (optional) | `opengrep` on `PATH` | Runs the 20 bundled Opengrep-syntax rules, including 8 Python taint rules that follow request data to a sink inside one file. Executed for real with Opengrep 1.33.1. |
| Semgrep (optional) | `semgrep` on `PATH` | Fallback for the same rules when Opengrep is not installed. **Never executed in our testing.** |
| OSV-Scanner (optional) | `osv-scanner` on `PATH` | A second dependency scan with its own lockfile parsers; results are merged with the built-in ones. Executed for real with 2.7.1. |
| Gitleaks (optional) | `gitleaks` on `PATH` | Additional secret rules. Executed for real with 8.30.1. |

`code-audit doctor` calls the three Node-only engines "Tier 0" and the
optional scanners "Tier 1". A missing, failing or timed-out external tool
never fails the scan; it is recorded as a warning. `--no-external` runs the
built-in engines only; `--engines builtin,opengrep,osv-scanner,gitleaks`
selects explicitly. Only bundled, self-written rules are used: no registry
rule packs are downloaded.

## Agent host details

`code-audit install --host <host>` (run in the project, or with
`--project <dir>`) writes project-local files only: the MCP server entry, the
shared skill ([skills/code-audit/SKILL.md](skills/code-audit/SKILL.md)) and,
where the host supports it, an `/audit` command. It never touches `~/.claude`,
`~/.codex` or other user-level configuration, and `--dry-run` shows the plan.

| Host | `install` writes | What was verified |
|---|---|---|
| OpenCode 2.4.1 | `opencode.json`, `.opencode/skills/code-audit/SKILL.md`, `.opencode/commands/audit.md` | A full audit through the MCP tools, on Linux, with this version of the code. |
| Codex CLI 0.166 | `.codex/config.toml`, `.agents/skills/code-audit/SKILL.md`, `AGENTS.md` (managed blocks) | A full audit through the MCP tools, on macOS (`codex exec` with the overrides that `install` prints). |
| DSH 0.2.2-rc.5 | `dsh/cordis.patch.yml` (managed block), `.dsh/skills/code-audit/SKILL.md` | A full audit through the MCP tools, on Linux, in headless mode (`dsh headless --patch dsh/cordis.patch.yml --approval-policy never`): 21 tool calls from scan to report, none failed. The headless profile needs the credentials service and a model provider enabled; see the adapter README. |
| Claude Code 2.1.183 | `.mcp.json`, `.claude/skills/code-audit/SKILL.md`, `.claude/commands/audit.md` | A full audit through the MCP tools, on macOS, both ways: after a project install (`claude -p "/audit" --mcp-config .mcp.json --allowedTools "mcp__code-audit__*"`: the skill, the `/audit` command and the 8 tools were found) and through the standalone plugin (`--plugin-dir`, `/code-audit:audit`). Not exercised: approving the project server interactively, installing the plugin through the marketplace. |

Per-host details, including what the installer does with existing
configuration, are in `adapters/<host>/README.md`. `adapters/claude-code/` is
also a standalone Claude Code plugin.

- **The MCP server audits only its base directory.** That is the directory
  the host starts it in - the project, for the four hosts above - or the one
  you set with `code-audit-mcp --base <dir>` / `CODE_AUDIT_MCP_BASE`. A model
  cannot point it anywhere else: a `root` outside the base (also through
  `..` or a symbolic link) is refused, and so are credential directories. To
  audit another directory, start the host there or set the base in the
  server entry. See [docs/mcp.md](docs/mcp.md#base-directory).
- **The MCP command must resolve in the host's environment.** The adapter
  config uses the bare command `code-audit-mcp`, which works only when it is
  on the `PATH` of the host process (GUI-launched hosts often have a short
  `PATH`). `install` warns when it is not. Use `install --absolute` to write
  the absolute path of this installation (do not commit that file),
  `--mcp-command <path>` for any other command, and
  `code-audit doctor --project <dir>` to check what is installed and whether
  the commands resolve.
- **Codex** reads a project `.codex/config.toml` only for projects you have
  marked as trusted, and `codex exec` rejects MCP tool calls that are not
  pre-approved. `install --host codex` prints the three ways to make the
  server visible with the real path filled in; see
  [adapters/codex/README.md](adapters/codex/README.md).
- **Tool names** differ per host: `mcp__code-audit__audit_start` (Claude
  Code, DSH), `mcp__code_audit__audit_start` (Codex),
  `code-audit_audit_start` (OpenCode). The MCP tools are described in
  [docs/mcp.md](docs/mcp.md).
- **Uninstall:** `code-audit install --uninstall --host <host>` removes the
  files install created and only the `code-audit` entry or managed block from
  files you already had. A file you edited after install is kept; a file that
  install had to replace was saved under `.code-audit/backups/` and is put
  back.

## CI usage

Run with a baseline so that only **new** findings fail the build:

```sh
# once, locally
code-audit scan .
code-audit baseline <run-id>      # writes .code-audit-baseline.json; commit it

# in CI
code-audit scan . --ci --format sarif,md --out audit-out --latest-link
```

- `--ci` prints a Markdown summary instead of the terminal summary, appends it
  to `GITHUB_STEP_SUMMARY` when that is set, and under GitHub Actions emits
  one annotation per finding that counts toward the exit code (at most 50).
- `--latest-link` copies the reports to `audit-out/latest/`
  (`results.sarif`, `report.md`, `findings.json`), a stable path for upload
  steps.
- The baseline in the scanned directory is picked up automatically.
  `--fail-on-existing` counts baseline findings again, `--no-baseline`
  ignores the file, `--baseline <file>` names another one.
- `code-audit baseline` writes into the project that contains
  `.audit/<run-id>`. For a run written with `--out`, pass the run directory
  and `--output <file>`.
- `--since <git-ref>` reports only findings in files changed since the ref
  (committed, staged, unstaged and untracked), for pull requests and
  pre-commit hooks: `code-audit scan . --since origin/main --ci`. git is only
  asked for the file list of the ref and of the index; code-audit compares
  the content itself, so no filter, hook or diff driver configured in the
  repository runs. A file that differs only by line-ending conversion counts
  as changed, the files of a submodule are all in scope, and the user-level
  git configuration (`safe.directory`) is not read.

Reference configurations: [examples/ci/github-actions.yml](examples/ci/github-actions.yml),
[examples/ci/gitlab-ci.yml](examples/ci/gitlab-ci.yml),
[examples/ci/pre-commit-hook.sh](examples/ci/pre-commit-hook.sh). This
repository's own workflow is [.github/workflows/ci.yml](.github/workflows/ci.yml).

## Untrusted repositories

By default a scan honours what a repository says about itself (its ignore
file, baseline, inline `code-audit:ignore` comments, `tests/` and `vendor/`
directory names, dev-dependency scope), because that is what a team wants in
its own CI. Each of those is reported with a `WARNING` when it changes the
result. For code you did not write, turn all of it off:

```sh
code-audit scan <path> --untrusted
```

`--untrusted` implies `--no-ignore-file --no-baseline --no-inline-ignore
--include-tests --include-dev --include-placeholders`, reads the directories
that are skipped by default (`build`, `dist`, `vendor`, `node_modules`, ...;
not `.git`) and the tool's own adapter files and earlier reports. Expect more
findings and a longer scan.

The scanner only reads files. It never executes repository code, installs
dependencies or follows instructions found in files, and repository text
cannot change the structure of a report. The threat model, every
repository-controlled mechanism with its warning, and the limits of these
guarantees are in [docs/security-model.md](docs/security-model.md).

## Configuration reference

### `code-audit scan <path>`

| Flag | Default | Meaning |
|---|---|---|
| `--out <dir>` | `<path>/.audit` | Write the run to `<dir>/<run-id>/`. |
| `--format md,json,sarif` | all three | Report files to write. |
| `--offline` | off | No OSV.dev queries; dependencies are listed but not checked. |
| `--no-external` | off | Built-in engines only (same as `--engines builtin`). |
| `--engines <list>` | builtin + installed tools | Any of `builtin`, `opengrep`, `semgrep`, `osv-scanner`, `gitleaks`. |
| `--fail-on <severity>` | `high` | Lowest severity (`info`, `low`, `medium`, `high`, `critical`) that makes the exit code 1. |
| `--min-confidence <c>` | `medium` | Lowest confidence (`low`, `medium`, `high`) counted in the headline and the exit code. |
| `--lang en\|zh` | `en` | Report language. |
| `--rules <dir>` | bundled rules | Load built-in-format rules from another directory. |
| `--ignore-file <path>` | `<path>/.code-audit-ignore` | Ignore file to apply. |
| `--no-ignore-file` | off | Apply no ignore file. |
| `--no-inline-ignore` | off | Do not honour `code-audit:ignore` comments. |
| `--include-tests` | off | Do not lower confidence in test, docs, example, vendored and generated paths. |
| `--include-dev` | off | Count advisories in dev and optional dependencies at full weight. |
| `--include-placeholders` | off | Report placeholder-looking secrets at the detector's normal confidence. |
| `--untrusted` | off | All of the six flags above, plus default-excluded directories. |
| `--baseline <file>` | `<path>/.code-audit-baseline.json` if present | Baseline to compare with. |
| `--no-baseline` | off | Use no baseline. |
| `--fail-on-existing` | off | Findings already in the baseline count toward the exit code. |
| `--since <git-ref>` | off | Report only findings in files changed since the ref. |
| `--ci` | off | CI output (annotations, Markdown summary). |
| `--latest-link` | off | Also copy the reports to `<out>/latest/`. |
| `--allow-sensitive-root` | off | Audit a credential or configuration directory (`~/.ssh`, `~/.aws`, `~/.config`, `/etc`, ...) or one below it; refused without the flag. Not available over MCP. |
| `--profile quick\|standard` | `standard` | `quick`: built-in engines only and no OSV.dev lookups (like `--no-external --offline`), for pre-commit hooks; an explicit `--engines` still applies. `standard`: every installed engine and OSV.dev lookups. |

Other commands (`code-audit --help` prints the full synopsis):

| Command | Purpose |
|---|---|
| `baseline <run> [--output <file>]` | Write a baseline from a run. |
| `status`, `findings`, `read`, `search`, `verdict`, `add-finding`, `report` | Review a run (see [Reviewing findings](#reviewing-findings)). All accept `--json`, `--root <dir>`, `--rules <dir>` and `--allow-sensitive-root`; `search` also `--glob`, `--regex`, `--max-results`, `--timeout-ms`. |
| `install --host <host> [--project <dir>] [--mcp-command <path> \| --absolute] [--force] [--dry-run] [--uninstall]` | Install or remove a host adapter. |
| `doctor [--project <dir>] [--json]` | Environment report; exit 1 when Node is older than 22. |
| `mcp [--base <dir>]` | Start the stdio MCP server (same as `code-audit-mcp`); it audits only inside `<dir>` (default: the working directory, or `CODE_AUDIT_MCP_BASE`). |
| `--version`, `--help` | Version; usage. |

Environment: `CODE_AUDIT_RULES_DIR` and `CODE_AUDIT_OPENGREP_RULES_DIR`
replace the bundled rule directories; `GITHUB_ACTIONS` and
`GITHUB_STEP_SUMMARY` are read by `--ci`.

### Ignore file

`.code-audit-ignore` in the scanned directory (YAML) suppresses findings by
fingerprint, rule id, path glob or advisory. Every entry needs a `reason`:

```yaml
version: 1
ignore:
  - rule: "py-weak-hash"
    paths: ["tests/**", "legacy/*.py"]
    reason: "MD5 used for cache keys only"
  - paths: ["vendor/**"]
    reason: "third-party code"
  - advisory: "GHSA-xxxx-xxxx-xxxx"   # or a CVE / PYSEC alias
    package: "requests"               # optional
    reason: "not reachable: we never follow redirects"
    expires: "2027-06-30"             # the entry stops matching after this date
  - fingerprint: "<64 hex characters from findings.json>"
    reason: "reviewed, not exploitable"
```

Suppressed findings stay in `findings.json` and in the "Suppressed findings"
section of the report, and are excluded from the counts and the exit code.
This repository's own [.code-audit-ignore](.code-audit-ignore) is a working
example.

A comment `code-audit:ignore <rule-id> -- <reason>` on the matched line or
the line before it suppresses that rule's candidates on the line (`*` for
any rule). These
are listed in the report too, and `--no-inline-ignore` disables them.

### Baseline

`.code-audit-baseline.json` records the fingerprints of the findings of one
run, including those a reviewer marked false positive (this is how a verdict
reaches later scans). With a baseline, only findings that are not in it count
toward the exit code; the report still lists the others and adds a "fixed
since baseline" section. Fingerprints do not contain line numbers, so moving
code does not create new findings. Regenerate the baseline after upgrading
code-audit when the changelog says fingerprints changed.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Completed and no finding reached the thresholds. |
| `1` | At least one finding counts: active (not suppressed, not false positive), severity ≥ `--fail-on`, confidence ≥ `--min-confidence`, and new when a baseline is in use. (`doctor`: Node older than 22.) |
| `2` | Runtime error: bad arguments, missing path, invalid ignore file or baseline, rule loading failure, refused write. |

The scan prints the reason, for example
`Exit code: 1 - 2 findings count toward the exit code (severity >= high, confidence >= medium)`.

## Limits

- Built-in rules match one statement (Python: one logical line) at a time.
  They do not follow data across statements or files. The Opengrep taint
  rules follow data inside one file only, and not through class methods.
- Not covered: authorization and business logic, XSS in templates, race
  conditions, cryptographic design, anything that needs to run the code.
- Dependency results depend on a lockfile or pinned versions; unpinned
  entries are counted in a warning. `pom.xml` is read for direct dependencies
  with literal versions only. `yarn.lock`, `go.sum` and `composer.lock` are
  not parsed by the built-in engine. Crates from git repositories or from
  registries other than crates.io are counted in a warning, not checked.
- Semgrep is supported as a fallback for Opengrep but has never been executed
  in our testing.
- Tests pass on macOS (arm64) and Linux (x86_64). **Windows is untested.**
- Configuration files of the external tools inside the scanned repository
  (`.gitleaks.toml`, `.gitleaksignore`, `.semgrepignore`, `osv-scanner.toml`)
  are honoured by those tools; the scan only warns.

Results on public repositories and the complete list of known limits:
[docs/M4_REPORT.md](docs/M4_REPORT.md) and [docs/PY1_REPORT.md](docs/PY1_REPORT.md).

## Documentation

- [docs/reports.md](docs/reports.md): counting model, report layout, confidence adjustments
- [docs/rules.md](docs/rules.md): built-in rules, rule file schema, adding a rule
- [docs/mcp.md](docs/mcp.md): MCP tools, arguments and results
- [docs/security-model.md](docs/security-model.md): threat model and guarantees
- [docs/README.md](docs/README.md): index of the documentation
- [CHANGELOG.md](CHANGELOG.md), [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md)

## Testing

```sh
pnpm test                   # build, then the whole suite (several minutes)
pnpm exec vitest run packages/core/test/rules.test.ts     # one file while developing
```

The suite has about 650 tests and runs in CI on Node 22 and 24, on Linux and
macOS. What it covers:

| Area | How it is tested |
|---|---|
| Rules | `fixtures/vulnerable/` holds one seeded weakness per rule; [fixtures/vulnerable/EXPECTED.json](fixtures/vulnerable/EXPECTED.json) lists the rule, file and line of each, and every one must be reported. `fixtures/clean/` holds safe look-alikes of the same code and must produce **no** finding. For the Python rule files the check runs both ways: nothing unlisted may be reported. |
| Rule cost | Every regular expression of every rule file is run against pathological input with a time budget, so a rule that can backtrack catastrophically fails the build. |
| Dependencies | Lockfile parsers on real-shaped samples; advisory lookups through an injected HTTP client with recorded OSV data, so unit tests use no network. |
| External scanners | Fake executables replay recorded real output of Opengrep, OSV-Scanner and Gitleaks. A separate file runs the real tools when they are present in `.tools/bin` and is skipped otherwise. |
| Hostile repositories | Path-jail escapes (symlinks, `..`, case tricks), planted run directories and manifests, repository git configuration, malformed lockfiles and JSON, Markdown injection through file names, secrets in every output channel. |
| CLI, MCP, installer | Commands are spawned as real processes; the MCP server is driven over stdio; `install` / `--uninstall` run against temporary projects with existing user configuration. |
| Consistency | One run must show the same numbers in the report, SARIF, JSON, CLI, CI and MCP summaries; flags in `--help` and in this README, the rule schema and the MCP tools in the docs are checked against the code. |

Try the fixtures by hand:

```sh
code-audit scan fixtures/vulnerable --offline --no-external --no-ignore-file --out /tmp/ca-vulnerable   # exits 1
code-audit scan fixtures/clean      --offline --no-external --out /tmp/ca-clean                          # exits 0
```

How the tool behaved on public repositories (flask, requests, httpie and four
deliberately vulnerable applications), and what each review round found, is
recorded in [docs/M4_REPORT.md](docs/M4_REPORT.md) and
[docs/PY1_REPORT.md](docs/PY1_REPORT.md).

## Development

```sh
pnpm install
pnpm build                  # tsc -b for packages/core, packages/mcp, packages/cli
pnpm test                   # build + vitest
pnpm run check:licenses     # production dependencies must not be (A/L)GPL
pnpm run link:local         # rewrite the bin/ wrappers (they are committed)
pnpm run pack:verify        # pack the packages, install the tarballs in a temp dir, run them
```

The repository is a pnpm workspace: `packages/core` (engine),
`packages/mcp` (MCP server), `packages/cli` (command line); `rules/` holds the
rule files, `fixtures/` the vulnerable and clean samples the tests scan,
`skills/` and `adapters/` what `install` writes. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache License 2.0](LICENSE). Copyright 2026 The code-audit Authors; see [NOTICE](NOTICE).

- You may use, modify and redistribute the tool, including commercially,
  under the terms of the license. It comes with no warranty: a scan result is
  not a security guarantee.
- **Rules.** All built-in rules and the bundled Opengrep-syntax rules were
  written for this project and are covered by the same license. No Semgrep
  registry rules, Bandit rules or other third-party rule packs are included
  or downloaded.
- **Optional scanners are not bundled.** Opengrep, Semgrep, OSV-Scanner and
  Gitleaks are separate programs under their own licenses; code-audit only
  runs them when you have installed them yourself.
- **Dependencies.** Production dependencies must not be GPL, AGPL or LGPL
  licensed; `pnpm run check:licenses` enforces this in CI.
- **Advisory data** comes from [OSV.dev](https://osv.dev) at scan time and is
  subject to the licenses of the underlying advisory databases.
