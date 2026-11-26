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

`code-audit install --host <host> --project <dir>` writes project-local adapter
files only; it never touches `~/.claude`, `~/.codex` or other user-level
configuration.

| Host | `install` writes | Then | Verification status |
|---|---|---|---|
| OpenCode | `opencode.json` (merged `mcp.servers.code-audit`), `.opencode/skills/code-audit/SKILL.md`, `.opencode/commands/audit.md` | Start OpenCode in the project, run `/audit`. | Verified on a real host (OpenCode v2.4.1, Linux). |
| DSH | managed block in `dsh/cordis.patch.yml`, `.dsh/skills/code-audit/SKILL.md` | `dsh --profile <profile> --patch dsh/cordis.patch.yml` | Verified on a real host (DSH 0.2.2-rc.5, Linux). |
| Claude Code | `.mcp.json` (merged `mcpServers.code-audit`), `.claude/skills/code-audit/SKILL.md`, `.claude/commands/audit.md` | Start `claude`, approve the project MCP server once, run `/audit`. Headless: `claude -p "/audit" --mcp-config .mcp.json --allowedTools "mcp__code-audit__*"` | Claude Code 2.1.183: `claude mcp list` sees the server (pending approval); plugin and marketplace manifests pass `claude plugin validate --strict`. **Not yet run with a model.** |
| Codex | managed block in `.codex/config.toml`, `.agents/skills/code-audit/SKILL.md`, managed block in `AGENTS.md` | See "Codex" below. | Verified end to end with Codex CLI 0.166 using the `-c` overrides. |

Details per host are in `adapters/<host>/README.md`. `adapters/claude-code/` is
also a standalone Claude Code plugin (`claude --plugin-dir adapters/claude-code`).

**The MCP command must resolve in the host's environment.** By default the
adapter config uses the bare command `code-audit-mcp`, which only works when
this checkout's `bin/` is on the `PATH` of the host process; hosts started from
a GUI or a service often have a minimal `PATH`. `install` warns when the command
is not on `PATH`. Alternatives:

```sh
code-audit install --host <host> --absolute              # absolute path of this checkout's bin/code-audit-mcp
code-audit install --host <host> --mcp-command <path>    # any other command or path
code-audit doctor --project <dir>                        # code-audit-mcp on PATH? installed hosts? do their commands resolve?
```

A config written with `--absolute` is machine-specific and should not be
committed.

**Codex.** Codex loads the skill and `AGENTS.md` from any project, but reads a
project `.codex/config.toml` only for projects you have marked as trusted. To
get the MCP server, do one of: trust the project in Codex
(`[projects."<path>"] trust_level = "trusted"` in your own
`~/.codex/config.toml`); register the server once with
`codex mcp add code-audit -- /absolute/path/to/bin/code-audit-mcp`; or pass
overrides for a one-off or CI run:

```sh
codex exec \
  -c 'mcp_servers.code-audit.command="/absolute/path/to/bin/code-audit-mcp"' \
  -c 'mcp_servers.code-audit.args=[]' \
  -c 'mcp_servers.code-audit.default_tools_approval_mode="approve"' \
  "Run a security audit of this project with the code-audit skill."
```

`codex exec` cannot prompt and rejects MCP tool calls that are not pre-approved,
hence the last override. `install --host codex` prints these commands with the
real path filled in and never edits `~/.codex`.

**Tool names** differ per host: `mcp__code-audit__audit_start` (Claude Code,
DSH), `mcp__code_audit__audit_start` (Codex), `code-audit_audit_start`
(OpenCode). The skill refers to the bare names (`audit_start`).

**Uninstall.** `code-audit install --uninstall --host <host> --project <dir>`
removes the files install created and only the `code-audit` entry or managed
block from files you already had (recorded in `.code-audit/installed.json`).
A file you edited after install is kept, a file install replaced is restored
from its backup, and other `<file>.code-audit-backup-<stamp>` copies are listed
and left in place.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Completed and no finding reached the `--fail-on` / `--min-confidence` thresholds. |
| `1` | At least one finding reached the thresholds (or Node < 22 for `doctor`). |
| `2` | Runtime error (bad arguments, missing path, rule loading failure, ...). |

A finding counts toward the exit code when it is active (not suppressed, not
marked false positive), its severity is at least `--fail-on` (default `high`),
its confidence is at least `--min-confidence` (default `medium`) and, when a
baseline is in use, it is new. The scan prints that number:
`Exit code: 1 - 6 findings count toward the exit code (severity >= high, confidence >= medium)`.

## Reading the report

Every summary — the Markdown cover, the terminal output, `--ci`, the GitHub job
summary, MCP `audit_status` / `audit_report` and `run.summary` in
`findings.json` — uses the same numbers:

| Number | What it counts |
|---|---|
| **Findings** (the headline) | Active findings with confidence at or above `--min-confidence`, broken down by severity and by category: code, secrets, configuration/IaC, dependencies. |
| **Low-confidence candidates** | Active findings below `--min-confidence`. Listed in their own section, never part of the headline and never in the exit code at that threshold. |
| **Hotspots** | Uses of dangerous APIs with no visible attacker input: a reading list for the reviewer. Never counted. |
| **Suppressed / false positive** | Excluded from all of the above; suppressed findings are always listed in the report. |

- **Dependencies** are counted twice on purpose: as *advisories* (one finding per
  advisory per lockfile entry) and as *vulnerable packages* (distinct
  `package@version`), each split by **dependency scope**: `runtime`,
  `dev`/`optional`, or `unknown` when the manifest does not say (for example a
  plain `requirements.txt`). The Markdown report has one row per vulnerable
  package version per lockfile, runtime first and dev/optional under their own
  heading; per-advisory detail is shown only for critical/high advisories of
  runtime packages. Everything else is in `findings.json` and `results.sarif`.
- **Path context**: a finding in a test, docs, example, vendored or generated
  path carries a tag (`` `test` ``, `` `docs` ``, ...) next to its location.
- **Lowered confidence**: when the scan lowers a confidence because of the path
  context, a placeholder value or a dev/optional dependency, the report shows
  it as `high → low` with the reason, and the summary says how many findings
  were lowered, how many of them dropped out of the headline and how many
  dev-dependency advisories were set aside (with the flag that counts them
  again, `--include-dev`). Nothing is removed:
  a repository cannot shrink the totals unnoticed by naming a directory
  `tests/`. Use `--min-confidence low` to count everything.
- **WARNING lines**: whenever something the audited repository contains took a
  finding at or above `--fail-on` out of the exit code, or kept files away
  from the scan, the cover (and the terminal, `--ci` and step summaries) says
  so in a `WARNING` line with the counts and the flag that turns it off. See
  [Auditing untrusted repositories](#auditing-untrusted-repositories).
- **Verdict status**: a finding with a reviewer's verdict shows its status
  wherever it is listed (top risks, finding details, low-confidence
  candidates, hotspots, dependency rows). A `confirmed` verdict makes the
  confidence high and a `likely` verdict restores the confidence the engine
  reported (at least medium), so a finding the scan had lowered counts again.

The Markdown report is ordered for reading: summary (the exit-code line, the
count table, the top 10 risks), findings grouped by rule, dependencies,
low-confidence candidates, hotspots, suppressed findings, fixed since baseline,
coverage and warnings. Large groups are shortened in Markdown (a few detail
blocks per rule, then a table); `findings.json` is always complete. In SARIF,
each result carries `properties` (confidence, category, `pathContext`,
`dependencyScope`, `adjustments`) and suppressed results carry `suppressions`
(`inSource` for an inline comment, `external` for the ignore file).

**Top risks** are ordered by severity first, with one entry per rule and one
per vulnerable `package@version` (all its advisories together). At most 3 of
the 10 entries are dependencies and at most 2 belong to one rule, so a long
advisory list cannot push code and secret findings off the list; the entries
passed over fill the list only when nothing else is left. When critical or
high findings are not on the list, the line below it says how many more are
in the sections that follow.

## CI usage

`code-audit` is designed to run in CI with a baseline so that only **new**
findings break the build. Pre-existing findings are recorded in a baseline file
and do not fail the build until they are fixed or explicitly suppressed.

### Baseline workflow

1. Run a scan locally and create a baseline once:

   ```sh
   code-audit scan .
   code-audit baseline <run-id>
   ```

   This writes `.code-audit-baseline.json` into the project: the directory
   that contains `.audit/<run-id>`. The destination is taken from where the
   run directory is, never from what its files say. For a run written with
   `--out <dir>`, or a run directory that was copied, pass
   `--output <file>`; without it the command is refused (exit 2). Findings a
   reviewer marked false positive are recorded in the baseline too, which is
   how a verdict reaches later scans. Commit the file.

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

3. When `GITHUB_ACTIONS=true`, each finding that counts toward the exit code
   is emitted as a GitHub workflow annotation (`::error` for critical/high,
   `::warning` for medium and below), highest severity first, capped at 50.
   Dependency advisories are folded into one annotation per vulnerable package.
   Findings that do not affect the exit code (low confidence, below
   `--fail-on`, already in the baseline) are not annotated; they are in the
   report. `--ci` prints the same count table as the report cover, and appends
   it to the job summary when `GITHUB_STEP_SUMMARY` is set.

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

### Path context, dev dependencies and placeholder secrets

Findings that are rarely about the shipped product keep their place in
`findings.json` but get a lower `confidence`. Nothing is dropped, and every
lowered finding says so itself:

| Field | Meaning |
|---|---|
| `pathContext` | `test`, `docs`, `example`, `vendored` or `generated`; absent for ordinary source. Decided from the file path (`tests/`, `docs/`, `examples/`, `vendor/`, `*.min.js`, `*_pb2.py`, ...). When the path says nothing, a "generated by" / "do not edit" comment in the first five lines sets `generated` **as a label only**. Also recorded per file in `coverage.json`. |
| `confidenceOriginal` | The confidence the engine reported; present only when `confidence` was lowered. |
| `adjustments` | Why it was lowered: `path-context:<context>`, `placeholder-value`, `dev-dependency`, `optional-dependency`. |

- **Path context:** one step down (high → medium → low) in test, docs and
  example paths; low in vendored and generated paths (`node_modules/`,
  `vendor/`, `third_party/`, `dist/`, `build/`, `*.min.js`, `*_pb2.py`,
  `*.pb.go`). The policy, given that the audited repository chooses its own
  file names:
  - Only the **path** lowers. A generated-file header comment (`# @generated`,
    `DO NOT EDIT`) is recorded as `pathContext: "generated"` and lowers
    nothing: one comment line must not take a file out of the exit code.
  - Never lowered, wherever the file is: critical findings that the rule
    reports with high confidence; private-key blocks; credentials embedded in
    a URL; credentials in a provider format (AWS access key ids, GitHub and
    Slack tokens); everything in CI / workflow files, Dockerfiles, dependency
    manifests and agent instruction files.
  - What remains (for example a medium-confidence rule in `tests/`, or a
    high-severity finding in `docs/` under `--min-confidence high`) is lowered
    and, when it would otherwise have counted toward the exit code, is counted
    in the `WARNING` line of the cover and the summaries.
  - `--include-tests` (MCP: `includeTests`) turns the lowering off.
- **Dev and optional dependencies:** an advisory in a dependency with
  `dependencyScope: "dev"` (build, lint and test tooling) is set aside: its
  confidence becomes **low**, so at the default `--min-confidence medium` it
  is not in the headline and does not affect the exit code. It is still
  listed with full data under "Development and optional dependencies" and in
  `findings.json` / `results.sarif`. An advisory in an `"optional"` dependency
  is lowered one step (high → medium) and stays in the headline. The summary
  states how many advisories and packages were set aside
  (`summary.dependenciesSetAside`). `--include-dev` (MCP: `includeDev`) gives
  both scopes full weight again; `--min-confidence low` counts everything.
- **Placeholder secrets:** a detected secret is never dropped because it looks
  like a placeholder; the value comes from the audited repository, and a real
  password can contain the word "example".
  - `password = "..."` assignments and credentials in a URL: a value that is a
    placeholder **as a whole** (`changeme`, `your-password-here`, `xxxx`,
    `<password>`, `example`, one repeated character, `user:password@` in a
    URL) is reported with low confidence and `adjustments:
    ["placeholder-value"]`. A value that merely contains such a word next to
    other content (`example-Pr0d!`, `test_8f3kLq92x`) is reported with the
    detector's normal confidence.
  - References that are filled in at run time are not secrets and are not
    reported: `${VAR}`, `{{ var }}`, `$(cmd)`, `$UPPER_CASE`, `%VAR%`, format
    fields (`{name}`, `%s`, `%(name)s`), `os.environ[...]`, `process.env.X`,
    `env("X")`.
  - Tokens in a provider format (AWS, GitHub, Slack) that are documented
    examples or contain a placeholder word are reported with low confidence.
  - `--include-placeholders` reports all of them at the detector's normal
    confidence.
- **Gitleaks results:** rules with a provider-specific token format are high
  confidence; rules that decide by a keyword and entropy (`generic-api-key`,
  `curl-auth-*`, `hashicorp-tf-password`, `kubernetes-secret-yaml`) are
  medium, so a documentation example falls below the default threshold
  through its path context while the same match in ordinary source counts.

Paths are chosen by the audited repository, so the effect is counted in
`run.json` (`pathContext: { test, docs, example, vendored, generated, lowered
}`, `adjustments`, `summary.reductions`) and shown as a `WARNING` on the
cover and in every summary whenever a finding at or above `--fail-on` stopped
counting because of it.

### Auditing untrusted repositories

By default the scan honours what a repository says about itself, because that
is what a team wants in its own CI. Each of these mechanisms is controlled by
the audited repository, is reported, and can be switched off:

| What the repository can supply | Effect | How it is reported | Off with |
|---|---|---|---|
| File and directory names (`tests/`, `docs/`, `examples/`, `vendor/`, `test_*.py`, `*.min.js`, ...) | Confidence lowered; see the policy above for what is never lowered | `WARNING: N finding(s) at severity ≥ <fail-on> do not count toward the exit code ...: path context N`; `high → low` on each finding | `--include-tests` |
| A generated-file header comment | Label only, no effect on confidence | `pathContext: "generated"` | — |
| Dev-only / optional dependency scope in a manifest | Advisory confidence lowered | Same `WARNING`, `dev-only dependency N` / `optional dependency N`; "set aside" line | `--include-dev` |
| Secret values that look like placeholders | Confidence low | Same `WARNING`, `placeholder-looking secret value N` | `--include-placeholders` |
| `.code-audit-baseline.json` in the repository (or a `--baseline` path inside it) | Findings marked existing do not count | `WARNING: baseline loaded from the audited repository: N finding(s) treated as existing (M at severity ≥ <fail-on> ...)` | `--no-baseline`, `--fail-on-existing` |
| `.code-audit-ignore` in the repository | Matching findings suppressed | `WARNING: ignore file from the audited repository suppressed N finding(s) (M at severity ≥ <fail-on>)`; "Suppressed findings" section | `--no-ignore-file` |
| Inline `code-audit:ignore` comments | Matching candidates suppressed | `WARNING: inline code-audit:ignore comments ... suppressed N finding(s) (M at ...)`; "Suppressed findings" section | `--no-inline-ignore` |
| Directories named `build`, `dist`, `vendor`, `bin`, `target`, `coverage`, `node_modules`, ... at any depth | Not read (performance) | `WARNING: N source file(s) in default-excluded directories were not read (vendor/ 2, build/ 1)`; "Skipped files" table | `--untrusted` |
| A directory that looks like a code-audit run directory (`run.json` naming the tool next to `findings.json`) outside `.audit/` | The tool's output file names in it are not matched against rules; **every secret detector still runs on them** | `WARNING: N file(s) in the audited repository look like code-audit output ...`; `code-audit output` rows in `coverage.json` | `--untrusted` |
| Files at the adapter paths of `code-audit install` | Skipped **only** when byte-identical (after newline normalisation) to the file this version ships; `.code-audit/installed.json` is never consulted | `code-audit adapter file` rows in `coverage.json` | `--untrusted` |
| `.gitleaks.toml`, `.gitleaksignore`, `.semgrepignore`, `osv-scanner.toml` | The external engine that reads the file may report less | A run warning naming the file (when that engine is selected) | `--engines builtin`, or scan a copy without the file |

One switch turns all of it off:

```sh
code-audit scan <path> --untrusted
```

`--untrusted` (MCP `audit_start`: `untrusted: true`) implies
`--no-ignore-file`, `--no-baseline`, `--no-inline-ignore`, `--include-tests`,
`--include-dev` and `--include-placeholders`; it scans the default-excluded
directories (all but `.git`), scans adapter files even when they match the
shipped ones, and recognises tool output only below `<root>/.audit/`, where
the tool itself writes. Use it for third-party code, a dependency you are
vetting, or a pull request from outside the project. Expect more findings:
vendored and build directories are read in full. The external engines'
own configuration files are still honoured by those engines; the scan warns
when one is present.

Text from the repository cannot shape the report either: every file name,
ignore reason, package name, advisory title and warning is rendered as a
single line (line breaks shown as `⏎`, control and bidirectional-override
characters as `�`), escaped so that it cannot start a heading, list, table
row, quote or code fence, and capped in length, in the Markdown report, the
terminal and the step summary.

### One set of numbers per run

The thresholds and switches a scan ran with are recorded in `run.json`
(`args`: `failOn`, `minConfidence`, `failOnExisting`, `baselineUsed`,
`includeTests`, `includeDev`, `includePlaceholders`, `untrusted`,
`noInlineIgnore`, `engines`). Every output of
that run is computed from its findings with that recorded policy by one
counting function: the report cover, `results.sarif` (`runs[0].properties`
and `countsTowardExitCode` per result), `run.summary` in `findings.json` and
`run.json`, the terminal summary, `--ci` and the GitHub step summary, and
later `code-audit status <run>`, `code-audit report <run>` and the MCP
`audit_status` / `audit_report` tools. After every `verdict` and
`add-finding` (CLI and MCP) the derived files of the run are rendered again
from the same state: `findings.json`, the counts in `run.json`, `report.md`
and `results.sarif` when the run has them, and their copies in `latest/` when
those belong to this run. `code-audit report <run> --format md|json|sarif`
writes the requested file and refreshes the others in the same way.

Verdicts are stored with their run. A new scan starts without them, so the
cover of a reviewed run states its result as that of the reviewed run, not as
the exit code of a new scan. To carry a decision forward, write a baseline
from the reviewed run or add an entry to `.code-audit-ignore`.

### Run directories are not trusted

`.audit/`, a run directory and every file in it are part of the repository
being audited. Later commands therefore take nothing on trust from them:

- A run id is resolved only as `<root>/.audit/<run-id>` of the current
  directory or of `--root <dir>` (MCP: the `root` argument, or the root of the
  `audit_start` call). A run directory that is a symbolic link leaving
  `<root>/.audit` is refused; the MCP tools accept ids only, never paths.
- The audit root is the directory that contains `.audit`, not the root
  written in `run.json`. For a run directory elsewhere (`--out`, a copy),
  `read`, `search` and `add-finding` need `--root <dir>` naming the root
  recorded in the run; `baseline` needs `--output <file>`.
- Rules come from the bundled rule set, or from `--rules <dir>` on that
  command line. A `rulesDir` in `run.json` is not loaded; a warning says when
  the rule set in use differs from the one recorded (by hash) at scan time.
- Every JSON file is validated before use. An invalid `.audit/index.json` is
  rebuilt with a warning; an invalid run file ends the command with exit 2.
- Files are written to a new temporary file and renamed into place, so a
  symbolic link planted at `report.md`, `latest/report.md`, `index.json` or a
  baseline path is replaced, never written through. A scan refuses to write
  when `.audit`, an `--out` inside the root, or `latest/` is a link that
  leaves the root.

The older count fields are still present and carry the same model:
`findingCounts` is the headline by severity (active findings at confidence >=
`--min-confidence`), `confidenceCounts` all active findings by confidence,
`hotspotCount` the active hotspots. `status` and `report --format summary`
also return `records` (every stored finding and hotspot, whatever its status)
and the full `summary`.

### The tool's own files inside the project

Earlier reports are not audited. Besides `.audit/`, the inventory skips the
tool's output files in any directory it recognises as one of its run
directories by content (a `run.json` that names this tool next to a
`findings.json`; the `latest/` copies; the `state.json` of an unfinished
run), so `--out reports/` inside the project is safe to reuse. The marker is
data in the audited repository, so it decides little: only the fixed output
file names (`run.json`, `findings.json`, `coverage.json`, `state.json`,
`report.md`, `results.sarif`, `verdicts.json`, `agent-findings.json`) are
exempt from rule matching (a report quotes vulnerable code), each one is
listed in `coverage.json` with the reason `code-audit output`, and any other
file in such a directory is scanned as usual. The exempt files still go
through every secret detector: genuine output holds secrets only in masked
form (masked values are passed over), so a credential next to a planted
`run.json` is found. The cover carries a `WARNING` with the number of such
files.

Files that `code-audit install` writes verbatim (the skill and command files:
`.claude/skills/code-audit/SKILL.md`, `.claude/commands/audit.md`,
`.opencode/skills/code-audit/SKILL.md`, `.opencode/commands/audit.md`,
`.dsh/skills/code-audit/SKILL.md`, `.agents/skills/code-audit/SKILL.md`) are
skipped (reason `code-audit adapter file`) only when their content is
identical to what this version of the tool ships; a copy with one changed
byte is audited like any agent instruction file. `.code-audit/installed.json`
lives in the project and decides nothing. Files the installer merges its
entry into (`.mcp.json`, `AGENTS.md`, `opencode.json` / `opencode.jsonc`,
`.codex/config.toml`, `dsh/cordis.patch.yml`) hold user content and are
always scanned in full; the tool's own entry in them produces no finding.

### Incremental scans

`--since <git-ref>` restricts the report to findings in files changed between
the ref and the working tree (committed, staged, unstaged and untracked but
not git-ignored files). The tool's own files (`.audit/`, the run directories
it wrote to an `--out` directory inside the project, `.code-audit-baseline.json`
and `.code-audit-ignore`) are not counted as changes. This is useful for
pre-commit hooks and pull-request checks:

```sh
code-audit scan . --since HEAD --ci --profile quick
```

## License

Apache-2.0. The repository bundles only self-written rules; no Semgrep
registry rules are distributed.