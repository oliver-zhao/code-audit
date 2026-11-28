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
does not find authorization and business-logic flaws, XSS written in HTML
template files, or data flow across files (see [Limits](#limits)).

## Supported languages and files

Everything in this table works with Node.js alone. `code-audit doctor` prints
the rule counts of your build.

| Language / file type | Recognised files | Built-in rules | Dependency files checked against [OSV.dev](https://osv.dev) |
|---|---|---:|---|
| **Python** | `.py`, `.pyw` | 102 | `requirements*.txt` (with `-r` includes), `poetry.lock`, `uv.lock`, `pdm.lock`, `Pipfile.lock`, `pylock.toml` |
| **JavaScript / TypeScript** | `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.mts`, `.cts` | 67 | `package-lock.json`, `pnpm-lock.yaml` |
| **Java** | `.java`; Spring Boot `application*.yml` / `bootstrap*.yml` | 78 | `pom.xml` (direct dependencies with literal versions) |
| **Go** | `.go` | 50 | `go.mod` |
| **C# / .NET** | `.cs`, Razor `.cshtml` / `.razor`, `web.config` and other `*.config`, `appsettings*.json` | 57 | `packages.lock.json`, `*.csproj` / `*.fsproj` / `*.vbproj` (`PackageReference`), `Directory.Build.props` / `.targets`, `Directory.Packages.props`, `packages.config` |
| **Rust** | `.rs` | 38 | `Cargo.lock` (with `Cargo.toml` and workspace members for direct/dev scope) |
| **C / C++** | `.c`, `.h`, `.cc`, `.cpp`, `.cxx`, `.hpp`, `.hh`, `.hxx` | 46 | none |
| **Dockerfile** | `Dockerfile`, `Dockerfile.*`, `*.dockerfile` | 13 | |
| **Docker Compose** | compose files | 10 | |
| **Kubernetes manifests** | `.yml`, `.yaml` with `apiVersion` or `securityContext` | 26 | |
| **Terraform** | `.tf`, `.tfvars` (AWS, Azure, GCP) | 35 | |
| **GitHub Actions** | `.github/workflows/*.yml` | 18 | |
| **Agent configuration** | MCP server configs, agent settings and hooks, `.codex/config.toml`, skills, instruction files (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `SKILL.md`, ..., `.cursorrules`, `.windsurfrules`, `.clinerules`, `.rules`, Cursor `.mdc`) | 38 | |
| **Dependency hygiene** | `package.json`, Markdown, JSON, YAML, Dockerfiles, shell scripts (`.sh`, `.bash`, `.zsh`, `.ksh`), requirements files, `.npmrc`, `.yarnrc`, `pip.conf`, `*.ini`, `*.cfg`, `uv.toml` | 11 | |
| **Other recognised files** | HTML and templates (`.html`, `.jinja`, `.j2`, `.twig`, `.vue`, `.svelte`, `.ejs`, `.hbs`, ...), `.properties`, `.xml` (other than .NET `*.config`) | 0 (counted in coverage; secret detection only) | |
| **Secrets** | every text file | detectors, not rules | |

589 built-in rules in total: 381 report **findings** and 208 report
**hotspots** (a dangerous API with no visible attacker input: a reading list
for the reviewer, never counted). Source files are matched one statement at
a time, with comments ignored and a call split over several lines seen as
one: Python on logical lines (docstrings ignored too), C#, Java,
JavaScript/TypeScript, Go, C/C++ and Rust through a shared C-family lexer.
The rules cover injection (SQL, command, code, path), deserialization, SSRF
and redirects, XSS in responses, TLS, crypto and hard-coded keys, written
for the APIs of each language's main libraries and frameworks (for example
Flask and Django, Express, Spring, net/http and gin, ASP.NET Core and EF
Core, sqlx and diesel, OpenSSL and libcurl). The depth differs per language;
Python has the most rules. The rule
files and how matching works are described in [docs/rules.md](docs/rules.md).

With [Opengrep](https://github.com/opengrep/opengrep) installed, 47 more
bundled rules run, 37 of them **taint rules** that follow request data to a
sink (SQL, command, path, SSRF, template, redirect, XSS, deserialization,
`eval`) inside one file: Python 13 (11 taint, Flask, Django and FastAPI),
JavaScript/TypeScript 8 (7), Java 7 (6), Go 7 (7), C# 6 (5), C 4 (1), and
Rust 2 (commands and SQL built with `format!`). See [Engines](#engines).

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
| [Claude Code](https://claude.com/claude-code) | 2.1.332 (macOS) | `claude-code` | `/audit` in the project, or headless `claude -p "/audit" --mcp-config .mcp.json --allowedTools "mcp__code-audit__*"` |
| [Codex CLI](https://developers.openai.com/codex/cli) | 0.171 (macOS) | `codex` | ask for a security audit; headless `codex exec` with the three `-c` overrides that `install` prints |
| [OpenCode](https://opencode.ai) | 2.4.1 (Linux) | `opencode` | `/audit`, or `opencode run "Run a security audit of this project with the code-audit skill"`. In a new project, run `opencode mcp list` first and wait until it shows `code-audit` connected: with OpenCode 2.4.1 a session started before that has no MCP server. |
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
code-audit doctor (0.4.0)
Node.js: 24.22.1 OK
Rules: 589 built-in: 381 finding, 208 hotspot (<checkout>/rules)
Opengrep rules: 47 (<checkout>/rules/opengrep)
Active tier: Tier 0 + Tier 1
External tools (detection only, not invoked):
  opengrep       missing
  semgrep        missing
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
4. `audit_verdict`: `confirmed`, `likely`, `needs_review`, `proof_gap` or `false_positive`, each with a rationale and optional structured evidence (a source-to-sink `trace`, the `control` that makes it safe, or what is `missing`); critical and high verdicts get an independent second review
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
credentials, 107 lines in 6 files. The scan also reads the project's
`README.md` and the committed sample report, so it counts 8 files.

```sh
code-audit scan examples/demo-app --offline --no-external --out /tmp/code-audit-demo
```

```text
code-audit scan completed: 20261127T143732Z-479f2b6d
Files: 8 scanned / 0 skipped, LOC 504
Rules: 589
Findings: 15 (critical 4, high 9, medium 1, low 1, info 0) at confidence >= medium
  by category: code 9, secrets 2, config/IaC 4, dependencies 0
Low-confidence candidates: 0 (not counted above)
Hotspots: 2 (not counted above)
Exit code: 1 - 13 findings count toward the exit code (severity >= high, confidence >= medium)
Duration: 171 ms
Report directory: /tmp/code-audit-demo/20261127T143732Z-479f2b6d
warning: offline mode: skipped OSV.dev queries (3 dependencies were not checked for vulnerabilities)
```

The command exits with status 1 because findings reached the thresholds; that
is the expected result here (see [Exit codes](#exit-codes)). A few of the 15:

| Finding | Location | Rule |
|---|---|---|
| SQL built with an f-string from a request parameter | `app/server.py:21` | `py-sql-injection` (critical) |
| `pickle.loads(request.data)` | `app/server.py:46` | `py-insecure-deserialization` (critical) |
| Request parameter concatenated into a shell command | `web/tools.js:8` | `js-command-injection-request` (critical) |
| Request parameter passed to `eval` | `web/tools.js:12` | `js-code-injection-request` (critical) |
| `curl ... \| sh` in an image build | `Dockerfile:4` | `dockerfile-curl-sh` (high) |
| Issue title interpolated into a `run:` script | `.github/workflows/triage.yml:13` | `gha-script-injection` (high) |
| AWS access key id | `config/prod.env:4` | `secret-aws-access-key` (high) |

The parameterized query at `app/server.py:29` is **not** a finding: it is
listed as a hotspot for the reviewer and does not count. With `--offline` the
three pinned dependencies in `requirements.txt` (flask 2.0.1, pyyaml 5.3.1,
requests 2.19.1) are listed but not checked, and the warning says so. Run
without `--offline` to check them against OSV.dev; the advisories it reports
depend on the advisory data of the day.

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
(359 lines). It starts with what fails the build and the top risks:

```markdown
## 1. Executive Summary

**13 findings count toward the exit code** (severity ≥ high, confidence ≥ medium); a scan with these thresholds exits 1.

**Findings at confidence ≥ medium**

| Category | Critical | High | Medium | Low | Info | Total |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Code | 4 | 4 | 1 | 0 | 0 | 9 |
| Secrets | 0 | 2 | 0 | 0 | 0 | 2 |
| Configuration / IaC | 0 | 3 | 0 | 1 | 0 | 4 |
| Dependencies (advisories) | 0 | 0 | 0 | 0 | 0 | 0 |
| **Total** | **4** | **9** | **1** | **1** | **0** | **15** |

### Top risks

1. **CRITICAL** · high · Code — Python SQL statement built with string formatting — app/server.py:21
2. **CRITICAL** · high · Code — Python unpickles request data — app/server.py:46
3. **CRITICAL** · high · Code — Request data in a child\_process shell command — web/tools.js:8
4. **CRITICAL** · high · Code — Request data evaluated as JavaScript — web/tools.js:12
5. **HIGH** · high · Secrets — Hardcoded AWS access key — config/prod.env:4
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

and lists the review hotspots separately:

```markdown
| Severity | Rule ID | Title | Count | Locations |
| --- | --- | --- | ---: | --- |
| high | py-sql-api | Python executes a SQL statement | 1 | app/server.py:29 |
| low | py-bind-all | Service bound to all interfaces | 1 | app/server.py:60 |
```

With OSV.dev lookups, the dependency section aggregates advisories per
package version, with the recommended upgrade and the lockfile line.
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

Verdicts are `confirmed`, `likely`, `needs_review`, `proof_gap` (suspicious,
but one named fact is missing) and `false_positive`. `--trace
<file:line:role[:note]>` (repeatable), `--control <file:line:note>` and
`--missing <text>` record structured evidence; every location is checked
against the files the run scanned. `--role independent --independence
subagent|same-session` records a second review: when it disagrees, the
finding stays `needs_review` and the dispute stays in the report. A person
settles a dispute from an interactive terminal with `--role human --replace
--reviewer <name>` (refused over MCP and when an agent environment is
detected; a speed bump, not a proof). A re-triage under a different reviewer
label needs `--replace`.
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
| Built-in rules | Node only | 589 rules (381 findings, 208 hotspots); `code-audit doctor` prints the counts of your build. See [docs/rules.md](docs/rules.md). |
| Built-in secret detection | Node only | Private keys, provider tokens (AWS, GitHub, Slack, ...), credentials in URLs, password and key assignments, and credential files (`.netrc`, `.pgpass`, `.npmrc`, `.pypirc` / `pip.conf`, Docker `auths`, kubeconfig). Values are masked in every output. |
| Dependency advisories | Node only, network | Parses `package-lock.json`, `pnpm-lock.yaml`, `requirements*.txt`, `poetry.lock`, `uv.lock`, `pdm.lock`, `Pipfile.lock`, `pylock.toml`, `go.mod`, `pom.xml` (direct dependencies with literal versions), `packages.lock.json`, NuGet project files (`*.csproj`, `*.fsproj`, `*.vbproj`, `Directory.Build.props` / `.targets`, `Directory.Packages.props`, `packages.config`), `Cargo.lock` (with `Cargo.toml`) and queries OSV.dev. Only package names and versions are sent. `--offline` skips the queries and the report says so. |
| Opengrep (optional) | `opengrep` on `PATH` | Runs the 47 bundled Opengrep-syntax rules, including 37 taint rules (Python, JavaScript/TypeScript, Java, Go, C#, C) that follow request data to a sink inside one file. Every bundled rule was executed for real with Opengrep 1.33.1 on Linux during development; the test suite replays recorded output. |
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
| OpenCode 2.4.1 | `opencode.json`, `.opencode/skills/code-audit/SKILL.md`, `.opencode/commands/audit.md` | A full audit through the MCP tools, on Linux, with 0.3.0 (`opencode run --format json`, step-5-preview): 14 tool calls from scan to report, none failed, every page of findings reached through `next_cursor`. A session started before `opencode mcp list` shows the server connected has no MCP server (an OpenCode service issue). |
| Codex CLI 0.171 | `.codex/config.toml`, `.agents/skills/code-audit/SKILL.md`, `AGENTS.md` (managed blocks) | A full audit through the MCP tools, on macOS (`codex exec` with the overrides that `install` prints). |
| DSH 0.2.2-rc.5 | `dsh/cordis.patch.yml` (managed block), `.dsh/skills/code-audit/SKILL.md` | A full audit through the MCP tools, on Linux, in headless mode (`dsh headless --patch dsh/cordis.patch.yml --approval-policy never`), with 0.3.0: 19 tool calls from scan to report, none failed. The headless profile needs the credentials service and a model provider enabled; see the adapter README. |
| Claude Code 2.1.332 | `.mcp.json`, `.claude/skills/code-audit/SKILL.md`, `.claude/commands/audit.md` | A full audit through the MCP tools, on macOS, both ways: after a project install (`claude -p "/audit" --mcp-config .mcp.json --allowedTools "mcp__code-audit__*"`: the skill, the `/audit` command and the 8 tools were found) and through the standalone plugin (`--plugin-dir`, `/code-audit:audit`). Not exercised: approving the project server interactively, installing the plugin through the marketplace. |

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
| `--ignore-file <path>` | `<path>/.code-audit-ignore` | Ignore file to apply; a missing file is an error. Under `--untrusted` an explicit ignore file or `--baseline` applies only when it lies outside the scanned directory and its git work tree, and the summary names it. |
| `--no-ignore-file` | off | Apply no ignore file. |
| `--no-inline-ignore` | off | Do not honour `code-audit:ignore` comments. |
| `--include-tests` | off | Do not lower confidence in test, docs, example, vendored and generated paths. |
| `--include-dev` | off | Count advisories in dev and optional dependencies at full weight. |
| `--include-placeholders` | off | Report placeholder-looking secrets at the detector's normal confidence. |
| `--untrusted` | off | All of the six flags above, plus default-excluded directories. |
| `--baseline <file>` | `<path>/.code-audit-baseline.json` if present | Baseline to compare with. |
| `--no-baseline` | off | Use no baseline. |
| `--fail-on-existing` | off | Findings already in the baseline count toward the exit code. |
| `--strict-evidence` | off | Every verdict of this run needs structured evidence: a trace with a source and a sink for `confirmed`, a sink for `likely`, a control for `false_positive`, `missing` for `proof_gap` (see [docs/mcp.md](docs/mcp.md)). |
| `--since <git-ref>` | off | Report only findings in files changed since the ref. |
| `--diff-lines` | off | With `--since`: report only findings on lines added or changed since the ref (dependency and secret findings are kept per file; a file with unusual line breaks counts as changed in full). |
| `--history[=<range>]` | off | Also scan the git history for secrets with Gitleaks, in an isolated clone (all refs, or `<ref>`, `<ref>..<ref>`, `<ref>...<ref>`). A shallow clone is scanned only partially: fetch the full history first (`fetch-depth: 0` in GitHub Actions). || `--ci` | off | CI output (annotations, Markdown summary). |
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

- Built-in rules match one statement at a time. Python is split into logical
  lines; C#, Java, JavaScript/TypeScript, Go, C/C++ and Rust into statements
  by a shared C-family lexer; Dockerfiles into instructions (with `\`
  continuations); XML start tags spanning lines are one unit. Every other
  file type (YAML, JSON, Terraform, shell, Markdown, Razor, ...) is matched
  line by line; Terraform HCL is not parsed. When a lexer cannot tell code
  from strings (an unclosed string, a file ending inside a comment or
  bracket), it fails open: the region is matched as plain lines, with a
  warning. Rules do not follow data across statements or files. The Opengrep
  taint rules follow data inside one file only, and not through class
  methods.
- Not covered: authorization and business logic, race conditions,
  cryptographic design, anything that needs to run the code. XSS is covered
  in C# and Razor views and by response-XSS rules in Go, Java, JavaScript,
  Python and Rust, not in HTML template files in general: templates (`.html`,
  `.jinja`, `.vue`, `.svelte`, ...) are recognised but have no rules, and the
  `<script>` blocks of Vue and Svelte files are not analysed as JavaScript.
  Spring Boot settings are checked in `application*.yml` /
  `bootstrap*.yml`, not in `.properties` files.
- Dependency results depend on a lockfile or pinned versions; unpinned
  entries are counted in a warning. `pom.xml` is read for direct dependencies
  with literal versions only. A NuGet project without its own
  `packages.lock.json` is checked for its direct references only; version
  ranges, floating versions and unresolved MSBuild properties are counted in
  a warning, not checked. Crates from git repositories or from registries
  other than crates.io are counted in a warning, not checked. `yarn.lock`,
  `go.sum` and `composer.lock` are not parsed by the built-in engine.
- Directories named `bin` are excluded by default (like `build`, `dist`,
  `vendor`, ...), except Cargo's `src/bin`; `--untrusted` reads them.
- Semgrep is supported as a fallback for Opengrep but has never been executed
  in our testing.
- Tests pass on macOS (arm64) and Linux (x86_64). **Windows is untested.**
- Configuration files of the external tools inside the scanned repository
  (`.gitleaks.toml`, `.gitleaksignore`, `.semgrepignore`, `osv-scanner.toml`)
  are honoured by those tools; the scan only warns.

What changed in this release, with its known limits, is in
[CHANGELOG.md](CHANGELOG.md) (0.4.0). Measured results on public
repositories and the known limits found then are recorded in the reports of
earlier development stages, [docs/M4_REPORT.md](docs/M4_REPORT.md) and
[docs/PY1_REPORT.md](docs/PY1_REPORT.md); their numbers predate 0.3.0.

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

The suite has about 1,190 tests and runs in CI on Node 22 and 24, on Linux and
macOS. What it covers:

| Area | How it is tested |
|---|---|
| Rules | `fixtures/vulnerable/` holds one seeded weakness per rule; [fixtures/vulnerable/EXPECTED.json](fixtures/vulnerable/EXPECTED.json) lists the rule, file and line of each, and every one must be reported. `fixtures/clean/` holds safe look-alikes of the same code and must produce **no** finding. For the Python and C# rule files the check runs both ways: nothing unlisted may be reported. Per-language rule tests (`packages/core/test/rules-*.test.ts`) add negative cases and multi-line forms. |
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

How earlier versions behaved on public repositories (flask, requests, httpie
and four deliberately vulnerable applications), and what each review round
found, is recorded in the stage reports [docs/M4_REPORT.md](docs/M4_REPORT.md)
and [docs/PY1_REPORT.md](docs/PY1_REPORT.md); the changes since are in
[CHANGELOG.md](CHANGELOG.md).

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
