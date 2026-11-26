# Reports and the counting model

How to read the output of a scan: which numbers exist, what lowers a
confidence, how the Markdown report is laid out, and why every output of one
run shows the same numbers. The short version is in the
[README](../README.md#reading-the-result).

## Files of a run

A scan writes a run directory, `<project>/.audit/<run-id>/` by default or
`<out>/<run-id>/` with `--out`:

| File | Content |
|---|---|
| `report.md` | The report for people (`--format md`). |
| `findings.json` | Every finding and hotspot with all fields, plus `run.summary` (`--format json`). |
| `results.sarif` | SARIF 2.1.0 for code-scanning tools (`--format sarif`). |
| `coverage.json` | Scanned and skipped files, engines and their status, warnings. |
| `run.json` | Options, thresholds, counts and warnings of the run. |
| `state.json` | Phase and progress (used by `status` and the MCP server while a scan runs). |
| `verdicts.json`, `agent-findings.json` | Written by `verdict` and `add-finding`. |

`<project>/.audit/index.json` lists the runs of a project. With
`--latest-link`, `findings.json`, `report.md` and `results.sarif` are also
copied to `<out>/latest/`.

## The numbers

Every summary — the Markdown cover, the terminal output, `--ci`, the GitHub job
summary, MCP `audit_status` / `audit_report` and `run.summary` in
`findings.json` — uses the same numbers:

| Number | What it counts |
|---|---|
| **Findings** (the headline) | Active findings with confidence at or above `--min-confidence`, broken down by severity and by category: code, secrets, configuration/IaC, dependencies. |
| **Low-confidence candidates** | Active findings below `--min-confidence`. Listed in their own section, never part of the headline and never in the exit code at that threshold. |
| **Hotspots** | Uses of dangerous APIs with no visible attacker input: a reading list for the reviewer. Never counted. |
| **Suppressed / false positive** | Excluded from all of the above; both are always listed in the report: "Suppressed findings" and "Dismissed by review". |

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
  [security-model.md](security-model.md).
- **Verdict status**: a finding with a reviewer's verdict shows its status
  wherever it is listed (top risks, finding details, low-confidence
  candidates, hotspots, dependency rows). A `confirmed` verdict makes the
  confidence high and a `likely` verdict restores the confidence the engine
  reported (at least medium), so a finding the scan had lowered counts again.

- **Dismissed by review**: every finding and hotspot with a `false_positive`
  verdict is listed in its own section once a run has been reviewed: id,
  kind, severity, rule, file, line, reviewer, and the rationale with its
  evidence lines (one escaped line, cut at 300 characters; 500 rows, then a
  count). When any dismissed finding is at severity ≥ `--fail-on`, the cover
  and every summary say `WARNING: N finding(s) at severity ≥ <fail-on> were
  marked false positive by <reviewers> and do not count toward the exit
  code; review the section "Dismissed by review".` (`summary.reductions.
  dismissed` holds the counts and reviewer labels.) A verdict of
  `false_positive` on a `high` or `critical` finding is only accepted with a
  rationale of at least 40 characters and evidence lines or a `file:line`
  reference.

The Markdown report is ordered for reading: summary (the exit-code line, the
count table, the top 10 risks), findings grouped by rule, dependencies,
low-confidence candidates, hotspots, suppressed findings, dismissed by review
(reviewed runs only), fixed since baseline, coverage and warnings. Large groups are shortened in Markdown (a few detail
blocks per rule, then a table); `findings.json` is always complete. In SARIF,
each result carries `properties` (confidence, category, `pathContext`,
`dependencyScope`, `adjustments`) and suppressed results carry `suppressions`
(`inSource` for an inline comment, `external` for the ignore file, and
`external` with the justification `Marked false positive by <reviewer>:
<rationale>` for a `false_positive` verdict). In `findings.json` a record
with a verdict has a `review` object (status, rationale, reviewer, time,
evidence lines), always taken from `verdicts.json`.

**Top risks** are ordered by severity first, with one entry per rule and one
per vulnerable `package@version` (all its advisories together). At most 3 of
the 10 entries are dependencies and at most 2 belong to one rule, so a long
advisory list cannot push code and secret findings off the list; the entries
passed over fill the list only when nothing else is left. When critical or
high findings are not on the list, the line below it says how many more are
in the sections that follow.

## Path context, dev dependencies and placeholder secrets

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

## One set of numbers per run

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

The older count fields are still present and carry the same model:
`findingCounts` is the headline by severity (active findings at confidence >=
`--min-confidence`), `confidenceCounts` all active findings by confidence,
`hotspotCount` the active hotspots. `status` and `report --format summary`
also return `records` (every stored finding and hotspot, whatever its status)
and the full `summary`.

## Incremental scans

`--since <git-ref>` restricts the report to findings in files changed between
the ref and the working tree (committed, staged, unstaged and untracked but
not git-ignored files). The tool's own files (`.audit/`, the run directories
it wrote to an `--out` directory inside the project, `.code-audit-baseline.json`
and `.code-audit-ignore`) are not counted as changes.

The comparison does not let git touch the working tree (see
[security-model.md](security-model.md#what-the-tool-guarantees)): git lists
the files of the ref and of the index, and code-audit hashes each working
file itself. A file therefore counts as changed whenever its bytes differ
from the blob of the ref - also when the difference is only CRLF/LF
conversion or a clean/smudge filter (git-lfs pointers, for example) - and
when its executable bit changed. Deleted files are left out, a renamed file
is in scope under its new name, and every file below a submodule or nested
repository is in scope (with a warning), because their content is not
compared. This is useful for pre-commit hooks and pull-request checks:

```sh
code-audit scan . --since HEAD --ci --profile quick
```
