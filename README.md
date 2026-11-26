# code-audit

`code-audit` is a deterministic source-code security scanner with a review
workflow for coding agents. It scans a local project with built-in rules,
secret detection and dependency advisories, writes candidate findings with
evidence to Markdown, JSON and SARIF, and gives a host agent (or a person) the
commands to read the code around each candidate, record a verdict and render
the reviewed report.

**What it is**

- A scanner that needs only Node.js: 156 built-in rules for Python,
  JavaScript/TypeScript, Java, Go, C/C++, C#, Dockerfiles, Kubernetes,
  Terraform, Compose, GitHub Actions and agent configuration files; secret
  detection; lockfile parsing with [OSV.dev](https://osv.dev) lookups.
- Stronger when Opengrep, OSV-Scanner or Gitleaks are installed: they are
  found on `PATH`, run, and their results merged and de-duplicated.
- A CLI (`code-audit`) and a stdio MCP server (`code-audit-mcp`) that expose
  the same review workflow, plus installers for four agent hosts.
- Built for CI (baseline, ignore file, SARIF, exit codes) and for auditing
  code you do not trust (`--untrusted`).

**What it is not**

- It does **not prove the absence of vulnerabilities**. A clean scan means
  that these engines matched nothing, not that the code is safe.
- Findings are **candidates**. Most rules match one statement at a time; a
  finding says "this line looks like a known dangerous form", a hotspot says
  "a reviewer should read this".
- The tool **never calls an LLM**. Judgment (is this reachable? is it
  exploitable?) is the job of the reviewer: the host agent's model, or you.
- It does not find authorization and business-logic flaws, XSS in templates,
  or data flow across files (see [Limits](#limits)).

## Quick start (2 minutes)

Requirements: Node.js 22 or later, git, and pnpm (`corepack enable` provides
it; or `npm install -g pnpm`). The packages are not published to npm yet, so
install from a checkout:

```sh
git clone https://github.com/oliver-zhao/code-audit.git
cd code-audit
corepack enable
pnpm install          # a "Failed to create bin" warning before the first build is harmless
pnpm build
export PATH="$PWD/bin:$PATH"    # bin/code-audit and bin/code-audit-mcp

code-audit doctor     # Node version, rule counts, optional scanners, MCP command
```

First scan, on the small demo project in this repository (no network, no
external tools, results written outside the checkout):

```sh
code-audit scan examples/opencode-demo --offline --no-external --out /tmp/code-audit-demo
```

```text
code-audit scan completed: 20261126T161559Z-b9b2e1d9
Files: 3 scanned / 0 skipped, LOC 74
Rules: 156
Findings: 2 (critical 1, high 1, medium 0, low 0, info 0) at confidence >= medium
  by category: code 2, secrets 0, config/IaC 0, dependencies 0
Low-confidence candidates: 0 (not counted above)
Hotspots: 0 (not counted above)
Exit code: 1 - 2 findings count toward the exit code (severity >= high, confidence >= medium)
Duration: 55 ms
Report directory: /tmp/code-audit-demo/20261126T161559Z-b9b2e1d9
```

The command exits with status 1 because findings reached the thresholds; that
is the expected result here (see [Exit codes](#exit-codes)).

Then your own project:

```sh
cd /path/to/project
code-audit scan .                # add --offline to skip the OSV.dev queries
```

Without `--out`, the run is written to `.audit/<run-id>/` inside the project.
Add `.audit/` to the project's `.gitignore`.

## Reading the result

A run directory holds `report.md` (for people), `findings.json` (complete
data), `results.sarif` (for code-scanning tools), `coverage.json` (what was
and was not scanned) and `run.json` (the options and counts of the run).

`report.md` starts with the numbers that matter and the top risks:

```markdown
**2 findings count toward the exit code** (severity ≥ high, confidence ≥ medium); a scan with these thresholds exits 1.

| Category | Critical | High | Medium | Low | Info | Total |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Code | 1 | 1 | 0 | 0 | 0 | 2 |
| Secrets | 0 | 0 | 0 | 0 | 0 | 0 |
| Configuration / IaC | 0 | 0 | 0 | 0 | 0 | 0 |
| Dependencies (advisories) | 0 | 0 | 0 | 0 | 0 | 0 |

### Top risks

1. **CRITICAL** · high · Code — Python SQL statement built with string formatting — src/app.py:10
2. **HIGH** · medium · Code — Python subprocess with shell=True and a command computed at runtime — src/app.py:16
```

and then lists every finding with its rule, CWE, remediation and the matched
line (secrets are masked):

```markdown
**AUD-2026-0001** · src/app.py:10 · Confidence: high · Status: candidate · Engine: builtin-rules

cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")
```

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
| Dependency advisories | Node only, network | Parses `package-lock.json`, `pnpm-lock.yaml`, `requirements*.txt`, `poetry.lock`, `uv.lock`, `pdm.lock`, `Pipfile.lock`, `pylock.toml`, `go.mod`, `pom.xml` (direct dependencies with literal versions), `packages.lock.json` and queries OSV.dev. Only package names and versions are sent. `--offline` skips the queries and the report says so. |
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

## Using it from an agent host

`code-audit install --host <host>` (run in the project, or with
`--project <dir>`) writes project-local files only: the MCP server entry, the
shared skill ([skills/code-audit/SKILL.md](skills/code-audit/SKILL.md)) and,
where the host supports it, an `/audit` command. It never touches `~/.claude`,
`~/.codex` or other user-level configuration, and `--dry-run` shows the plan.

| Host | `install` writes | What was verified |
|---|---|---|
| OpenCode 2.4.1 | `opencode.json`, `.opencode/skills/code-audit/SKILL.md`, `.opencode/commands/audit.md` | A full audit through the MCP tools, on Linux, with this version of the code. |
| Codex CLI 0.166 | `.codex/config.toml`, `.agents/skills/code-audit/SKILL.md`, `AGENTS.md` (managed blocks) | A full audit through the MCP tools, on macOS (`codex exec` with the overrides that `install` prints). |
| DSH 0.2.2-rc.5 | `dsh/cordis.patch.yml` (managed block), `.dsh/skills/code-audit/SKILL.md` | The patch composes and the MCP server starts under real DSH. **A full agent run was not possible** (no model credential on the test host). |
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
| `--profile quick\|standard` | `standard` | Recorded in the run. Both profiles currently run the same engines. |

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
  with literal versions only. `yarn.lock`, `go.sum`, `Cargo.lock` and
  `composer.lock` are not parsed by the built-in engine.
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
- [docs/README.md](docs/README.md): index, including historical development records
- [CHANGELOG.md](CHANGELOG.md), [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md)

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

Apache-2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). The repository
contains only self-written rules; no Semgrep registry rules are distributed.
