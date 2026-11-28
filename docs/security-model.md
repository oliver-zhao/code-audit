# Security model

code-audit reads source code that may have been written by someone who wants
the audit to come out clean, or who wants to attack the person or agent
running it. This document states what the tool assumes, what it guarantees,
what it does not, and how to report a vulnerability in the tool itself.

## Threat model

**The audited repository is untrusted input.** That covers every file in it:
source, comments, file and directory names, lockfiles and manifests,
configuration files, earlier reports, a `.audit/` directory, a
`.code-audit-ignore`, a `.code-audit-baseline.json`, host adapter files, and
symbolic links.

An attacker who controls the repository may try to:

1. **Hide findings**: lower the result, suppress candidates or keep files
   away from the scan, so that a vulnerable change passes review or CI.
2. **Steer the reviewer**: plant instructions for the reviewing agent
   (prompt injection) in code, comments, file names or package metadata, or
   forge parts of the report.
3. **Abuse the tool's file access**: make it read files outside the audit
   root, or write outside the run directory, through paths, symbolic links or
   forged run files; or make the reviewing agent point the tool at another
   directory of the machine (`~/.aws`, another project).
4. **Leak secrets**: get credentials that the scan found copied in clear text
   into reports, CI logs or the agent's context.
5. **Exhaust the scan**: pathological input for the pattern engine or the
   parsers.
6. **Run code**: get a program of its choice executed by a tool the scan
   calls (git, through `.git/config` and `.gitattributes`).

**Arguments of MCP tools are untrusted too.** They are chosen by a model that
has read the repository, so anything an argument can express, a prompt
injection can ask for. The MCP server gives its arguments less room than the
command line gives a person: see "MCP base directory" below.

**Trusted:** the person or CI job that starts the tool and its command line;
the code-audit installation (code, bundled rules); the machine, Node.js and
the file system; the optional external scanners found on `PATH` and their
own behaviour; OSV.dev responses (used as advisory data only).

**Not a sandbox.** code-audit runs with the privileges of the user who starts
it. It is a reader with a strict idea of where it may read and write, not an
isolation boundary. When you run an agent host on an untrusted repository,
the host's own permission model decides what the agent may do besides
calling the audit tools.

## What the tool guarantees

These hold for the built-in engines, the CLI and the MCP server, with or
without `--untrusted`. Each is covered by tests in `packages/core/test`
(`trust`, `runtrust`, `untrusted`, `path`, `seams`, `review2`,
`since-hardening`, `redos`, `credential-files`, `dismissed`) and
`packages/mcp/test` (`base`).

- **No execution.** Repository code is never executed, imported or
  evaluated; dependencies are never installed; build files and package
  scripts are never run. Files are read as text.
- **git runs nothing from the repository.** `--since` and `--history` are
  the only features that start git (`--history` is described in
  [its own section](#git-history-scan---history)), and `.git/` is part of the
  untrusted repository. For `--since`, git is
  never asked to read, hash or convert a working-tree file - that is where
  it runs the `filter.<name>.clean` / `smudge` / `process` programs,
  `textconv` and external diff drivers that `.gitattributes` and
  `.git/config` name, and filters cannot be disabled by a wildcard. Only
  three commands are run: `git rev-parse`, `git ls-tree -r -z --full-tree
  <ref>` (the object database) and `git ls-files -z` with `--cached` or
  `--others --exclude-standard` (the index and a directory listing). The
  blob id of every working file is computed by code-audit itself
  (`sha1`/`sha256` of `"blob <size>\0"` + bytes) and compared with the tree.
  Every invocation also overrides `core.fsmonitor`, `core.hooksPath`,
  `core.pager`, `diff.external`, `core.attributesFile` and
  `protocol.allow`, and runs with `GIT_CONFIG_NOSYSTEM=1`,
  `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_ATTR_NOSYSTEM=1` and a minimal
  environment. Tests plant a marker program in each of `filter.*.clean`,
  `process`, `smudge`, `textconv`, `diff.external`, `core.fsmonitor`,
  `core.sshCommand`, an alias, `core.hooksPath`, `uploadpack`, pager, editor
  and credential-helper settings, and `include` / `includeIf` files; none is
  run. Consequences, by design: a file that differs from the ref only by
  line-ending conversion or by a filter counts as changed (more files in
  scope, never fewer); every file of a submodule or nested repository is in
  scope (a warning names it); and because the user and system git
  configuration is not read, a `safe.directory` entry there does not apply
  - in a repository owned by another user, `--since` fails with git's
  ownership message instead of scanning.
- **No LLM.** No model is called by the scan, the CLI or the MCP server.
- **Network.** The only network use is the dependency lookup at OSV.dev
  (package ecosystem, name and version; and advisory ids), skipped with
  `--offline`. External scanners follow their own network behaviour.
- **Reads stay inside the audit root.** Paths are resolved through a path
  jail; a symbolic link that leaves the root is not followed. `read`,
  `search`, `add-finding` and the MCP tools accept only files of the run's
  inventory. The file system root, the user's home directory and every
  directory that contains it are refused as audit roots. Well-known
  credential and configuration directories - `~/.ssh`, `~/.aws`, `~/.gnupg`,
  `~/.config`, `~/.kube`, `~/.docker`, `~/.azure`, `~/.oci`,
  `~/.password-store`, `~/.terraform.d`, `~/.local/share/keyrings`,
  `~/.claude`, `~/.codex`, `~/Library`, `~/AppData`, `/etc`, `/root`,
  `/var/root`, `/proc`, `/sys`, `/dev`, `/boot`, `/run/secrets`,
  `/var/run/secrets` - and everything below them are refused too
  (`ROOT_SENSITIVE`, checked on the canonical path, so a symbolic link to one
  is refused as well) unless `--allow-sensitive-root` is given on the command
  line. The list is a safety net for the obvious cases, not a definition of
  what is sensitive on your machine.
- **MCP base directory.** The MCP server audits, reads and writes only
  inside its base directory: `--base <dir>`, else `CODE_AUDIT_MCP_BASE`, else
  the directory the host started it in; printed to stderr at start-up and
  fixed for the life of the process. The `root` of `audit_start`, the `root`
  argument of every other tool and `baseline` must resolve inside it as
  canonical paths (symbolic links followed; `..` and links that leave the
  base are refused with `OUTSIDE_BASE`). No MCP argument names a rules
  directory, an output directory or an ignore file, and
  `--allow-sensitive-root` has no MCP equivalent. A base that is the
  filesystem root, the home directory or above it is refused for every call.
  What this does not limit: a base that spans several projects lets the model
  audit each of them; choose the base as narrowly as the project.
- **Writes stay inside the run directory** (and `<out>/latest/`, the run
  index, and a baseline path you name). Files are written to a temporary
  file and renamed into place, never through a symbolic link.
- **Secrets are masked** in `report.md`, `findings.json`, `results.sarif`,
  CI annotations, the terminal, and the output of `read` / `search` /
  `audit_read` / `audit_search`: short values are masked completely,
  longer ones keep a few characters at each end. Masking is a property of
  the line and errs on the side of masking too much. What is recognised:
  - values assigned to, compared with or passed as a secret-like name
    (`password = "..."`, `"token": "..."`, `API_KEY=...`, `--password ...`,
    `Authorization: Basic|Bearer ...`), vendor token formats, PEM private
    keys, `scheme://user:password@host`;
  - a value separated from a secret-like word by blanks only: any value
    after such a word at the start of a line of a configuration file
    (`requirepass ...`, `password ...` in `*.conf`, `*.ini`, `*.cnf`,
    `.npmrc`, `.pypirc`, `config`, `credentials`, ...), and in any other
    place (prose, comments, `the password is ...`) a value that mixes
    letters with digits or symbols;
  - by file name: the `password` and `account` fields of `.netrc` /
    `_netrc`, the password field of `.pgpass`, the hash of `.htpasswd`;
  - the password word of `sshpass -p`, `mysql`/`mariadb`/`mongo* -p...`,
    `docker|podman login -p`, `redis-cli -a`, `htpasswd -b`,
    `curl|wget -u user:password`, `echo ... | ... --password-stdin`, and
    the values of `Cookie:` / `Set-Cookie:` headers;
  - `_authToken` / `_auth` / `_password` in `.npmrc`, `"auth"` in a Docker
    `config.json`, `token:` / `client-key-data:` in a kubeconfig.
  `.netrc`, `.pgpass`, `.npmrc`, `.pypirc` / `pip.conf`, Docker `auths` and
  kubeconfig credentials are also reported as findings.
  Deliberately left readable, because they are not secrets, and only when
  the name is not itself a credential name (password, passwd, pwd, pw,
  secret, token, key, credential, connection string, ...): setting words
  (`http_tokens = "optional"`, `secrets: inherit`), JOSE and hash algorithm
  names where the name says algorithm or JWT/HMAC (`JWT_ALGORITHM = "HS256"`),
  dotted class paths in class lists (`PASSWORD_HASHERS`,
  `AUTHENTICATION_BACKENDS`), a flag that follows a non-credential flag
  (`--allow-unauthenticated --region`; `--password -X...` is masked), and
  inside a settings section named only weakly like a secret
  (`"AuthServer": {`, `jwt:`) the values of keys that are not secret-like
  (`"Authority"`, `"ClientId"`; `"Pw"`, `"Secret"` stay masked). A PEM
  private-key block is masked up to its END marker, or up to the first line
  that is neither blank, a PEM header, nor holds a run of 40 base64
  characters (so a BEGIN marker in a string literal of code does not mask
  the rest of the file, and a key quoted, commented, diffed or in a table is
  still masked), at most 400 lines.
- **Nothing in the repository lowers the result silently.** Every mechanism
  in the table below is counted and printed as a `WARNING`, and `--untrusted`
  turns all of them off.
- **A dismissal is never silent.** Every finding a reviewer marked
  `false_positive` is listed in the Markdown report under "Dismissed by
  review" with id, severity, rule, location, reviewer and rationale, is a
  `suppressions` entry (`kind: "external"`) in SARIF, and keeps its record in
  `findings.json`. When any of them is at severity ≥ `--fail-on`, the report
  cover, `status`, the scan, `--ci` and step summaries and the MCP
  `audit_status` / `audit_report` results carry `WARNING: N finding(s) at
  severity ≥ <fail-on> were marked false positive by <reviewers> ...`.
  Dismissing a `high` or `critical` finding is refused without a rationale of
  at least 40 characters plus evidence lines or a `file:line` reference. The
  reviewer label and the rationale are whatever the reviewer wrote; they are
  rendered as one escaped line each.
- **Repository text cannot restructure a report.** Every file name, ignore
  reason, package name, advisory title and warning is rendered as a single
  line (line breaks shown as `⏎`, control and bidirectional-override
  characters as `�`), escaped so that it cannot start a heading, list, table
  row, quote or code fence, and capped in length, in the Markdown report, the
  terminal and the step summary.
- **Repository content is labelled for agents.** The MCP server wraps file
  content, evidence lines, rule messages and search matches in
  `<<<UNTRUSTED_REPOSITORY_CONTENT>>> ... <<<END_UNTRUSTED_REPOSITORY_CONTENT>>>`
  with a note that it is data, and caps every response at 8 kB; the skill
  tells the agent never to follow instructions found in it. Other fields
  (file names, titles) are repository-derived too and are not wrapped.
- **Bounded matching.** Rule patterns are tested against pathological input,
  each file has a time budget, and over-long lines are matched in windows;
  whatever is skipped for these reasons is named in a warning. The budget is
  also enforced from outside the matching loop: when a single match does not
  return (possible with the rules of a `--rules` directory), matching of that
  file is interrupted one second after its budget (5 s per file, 0.5 s once
  five files have been slow), the findings made so far in the file are kept,
  and a warning names the file. A rule set is trusted input; this bounds the
  damage of a mistake in it, it does not make hostile rules safe.
- **Search has a hard time limit.** `search --regex` / `audit_search` with
  `regex` runs the match under a wall-clock limit that interrupts it: 2
  seconds for the whole search (`--timeout-ms` on the CLI, up to 60 s; fixed
  over MCP), then `SEARCH_TIMEOUT`, and the MCP server goes on answering. The
  structural check that rejects nested quantifiers is a convenience and is
  not relied on. Without `regex` the pattern is searched as literal text and
  never compiled. Lines are matched in 2,000-character windows up to 20,000
  characters; a search covers at most 20,000 files, 16 MB and 200 matches.
  Globs (`--glob`, the ignore file) are matched by a state machine that
  cannot backtrack. Not covered by the limit: listing the files of a very
  large tree before the search starts.

## What it does not guarantee

- **Absence of vulnerabilities.** A scan with no findings proves nothing
  about code the rules do not model (see the README "Limits").
- **Resistance to prompt injection of the host agent.** Delimiters and the
  skill reduce the risk; whether a model obeys text in a file is outside the
  tool's control. Review an agent's verdicts, in particular
  `false_positive`, before relying on them: the report lists them for that
  purpose ("Dismissed by review"). The evidence requirement stops a careless
  mass dismissal; an agent that is told what to write can still satisfy it.
  Verdict rationales are stored as the agent wrote them (secret-like values
  are masked where the report shows them).
- **Detection or masking of every secret.** The generic password detector
  ignores values under 8 characters and very low-entropy values. A string
  literal with no secret-like name and no rule match is shown as it is by
  `read` and `search`. So is a password made of letters only that follows a
  secret-like word in running text outside a configuration file
  (`the password is swordfish`), a credential in a file format the tool does
  not know, and anything that only context makes a secret.
- **Behaviour of external scanners.** Opengrep, Semgrep, OSV-Scanner and
  Gitleaks read their own configuration files from the repository
  (`.gitleaks.toml`, `.gitleaksignore`, `.semgrepignore`,
  `osv-scanner.toml`) and may report less because of them. The scan warns
  when one is present; use `--engines builtin` or scan a copy without the
  file when that matters.
- **A race-free file system.** A parent directory swapped for a symbolic
  link between validation and rename can still redirect a write; Node.js
  offers no directory-descriptor traversal to close this completely. Do not
  run scans of untrusted repositories in a directory that another untrusted
  process can modify at the same time.
- **Windows.** The path and symbolic-link handling is tested on macOS and
  Linux only.

## Repository-controlled mechanisms

By default the scan honours what a repository says about itself, because that
is what a team wants in its own CI. Each of these mechanisms is controlled by
the audited repository, is reported, and can be switched off:

| What the repository can supply | Effect | How it is reported | Off with |
|---|---|---|---|
| File and directory names (`tests/`, `docs/`, `examples/`, `vendor/`, `test_*.py`, `*.min.js`, ...) | Confidence lowered; see [reports.md](reports.md#path-context-dev-dependencies-and-placeholder-secrets) for what is never lowered | `WARNING: N finding(s) at severity ≥ <fail-on> do not count toward the exit code ...: path context N`; `high → low` on each finding | `--include-tests` |
| A generated-file header comment | Label only, no effect on confidence | `pathContext: "generated"` | — |
| Dev-only / optional dependency scope in a manifest | Advisory confidence lowered | Same `WARNING`, `dev-only dependency N` / `optional dependency N`; "set aside" line | `--include-dev` |
| Secret values that look like placeholders | Confidence low | Same `WARNING`, `placeholder-looking secret value N` | `--include-placeholders` |
| `.code-audit-baseline.json` in the repository (or a `--baseline` path inside it) | Findings marked existing do not count | `WARNING: baseline loaded from the audited repository: N finding(s) treated as existing (M at severity ≥ <fail-on> ...)` | `--no-baseline`, `--fail-on-existing` |
| `.code-audit-ignore` in the repository | Matching findings suppressed | `WARNING: ignore file from the audited repository suppressed N finding(s) (M at severity ≥ <fail-on>)`; "Suppressed findings" section | `--no-ignore-file` |
| Inline `code-audit:ignore` comments (on any line of the matched statement, or on a line of their own before it; a suppressed group winner suppresses that expression's result, see [rules.md](rules.md#how-matching-works)) | Matching candidates suppressed | `WARNING: inline code-audit:ignore comments ... suppressed N finding(s) (M at ...)`; "Suppressed findings" section | `--no-inline-ignore` |
| Directories named `build`, `dist`, `vendor`, `bin`, `target`, `coverage`, `node_modules`, ... at any depth | Not read (performance) | `WARNING: N source file(s) in default-excluded directories were not read (vendor/ 2, build/ 1)`; "Skipped files" table | `--untrusted` |
| A directory that looks like a code-audit run directory (`run.json` naming the tool next to `findings.json`) outside `.audit/` | The tool's output file names in it are not matched against rules; **every secret detector still runs on them** | `WARNING: N file(s) in the audited repository look like code-audit output ...`; `code-audit output` rows in `coverage.json` | `--untrusted` |
| Files at the adapter paths of `code-audit install` | Skipped **only** when byte-identical (after newline normalisation) to the file this version ships; `.code-audit/installed.json` is never consulted | `code-audit adapter file` rows in `coverage.json` | `--untrusted` |
| `.gitleaks.toml`, `.gitleaksignore`, `.semgrepignore`, `osv-scanner.toml` | The external engine that reads the file may report less (the `--history` scan passes the root's `.gitleaks.toml` and `.gitleaksignore` to Gitleaks too, but not with `--untrusted`) | A run warning naming the file (when that engine is selected, or `--history` reads it) | `--engines builtin`, or scan a copy without the file; for `--history`: `--untrusted` |
| `gitleaks:allow` comments in committed content | Gitleaks skips that line | — | `--untrusted` for the `--history` scan (`--ignore-gitleaks-allow`); the working-tree Gitleaks scan honours them |

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

## Git history scan (`--history`)

`scan --history[=<range>]` (MCP `audit_start`: `history`) also looks for
secrets in the git history, with Gitleaks. A secret that was committed and
later deleted is still in every clone, fork and cache of the repository, so
it is reported until it is rotated. Without gitleaks the history scan is
skipped (`coverage.json`: `history.status: "skipped"`), not an error.

The range is checked before anything runs: nothing, or `<ref>`,
`<ref>..<ref>`, `<ref>...<ref>` where a ref consists of `[A-Za-z0-9._/-]`,
does not start with `-` or `.` and follows git's ref-name rules (`HEAD~1`,
`a;b`, `--output=x` are refused with exit code 2). It reaches git as one
argument, never through a shell.

**No git process of the history scan can fetch or swap objects.** Every one
of them - `rev-parse` in the audited repository, the clone, the commands in
the copy and the git that Gitleaks starts - runs with
`GIT_NO_LAZY_FETCH=1`, `GIT_NO_REPLACE_OBJECTS=1` (and `--no-lazy-fetch
--no-replace-objects` where code-audit starts git), the `--since` hardening
above, and `protocol.allow=never` plus `protocol.<name>.allow=never` for
`ext`, `fd`, `file`, `ssh`, `git`, `http` and `https` - by name, because a
`protocol.ext.allow=always` in the audited repository's own configuration
is more specific than `protocol.allow` and would otherwise win. Without
this, a partial clone whose promisor remote is `ext::<command>` runs that
command as soon as git looks up a missing object (tested). The one exception
is `protocol.file.allow=always` for the mirror clone itself.

Gitleaks' git mode runs `git log -p` in the repository it is given, so it is
never given the audited repository:

1. `git rev-parse` finds the top level of the repository and resolves each
   ref of the range to a commit id. The copy is scanned with those ids,
   never with names; an id that the copy does not have (a pseudo-ref such as
   `ORIG_HEAD`, or a ref outside `refs/`) makes the history scan `failed`.
2. `git clone --mirror --no-local --no-hardlinks --template=` copies every
   ref and object into a new private temporary directory (mode 0700). The
   copy's configuration is written by git: it has none of the original's
   filter, textconv or diff drivers, fsmonitor, hooks path, aliases or
   attributes file, and `--template=` copies no hooks. `--no-local` makes
   git read the objects through `upload-pack` instead of copying the object
   directory, whose files a symbolic link could point anywhere.
   `upload-pack` runs for the audited repository with that repository's
   configuration, and the local transport drops the clone's `-c` options and
   `GIT_NO_*` variables on the way, so code-audit starts it as the fixed
   string `git --no-lazy-fetch --no-replace-objects -c core.fsmonitor=false
   -c core.hooksPath=/dev/null -c uploadpack.hideRefs=!refs
   -c transfer.hideRefs=!refs -c protocol.allow=never -c
   protocol.<name>.allow=never ... upload-pack`: a `hideRefs` entry of the
   repository cannot keep commits out of the scan. git ignores
   `uploadpack.packObjectsHook` in repository configuration. `--mirror`
   copies every ref, including `refs/remotes/`, `refs/stash` and other
   namespaces.
3. Replace refs (`refs/replace/*`) are deleted from the copy and
   `info/grafts` is removed, so that `git replace` cannot swap the commit
   that added a secret for a clean one (tested; the run warns when the
   repository had replace refs).
4. `git rev-list --count` and `git rev-list --topo-order` give the number of
   commits and their order. A failure is `failed`, never `ok`.
5. Gitleaks runs on the copy: `gitleaks git <copy> --log-opts
   "--full-history --max-count=N <ids|--all>" --report-format json
   --report-path <tmp>/report.json --no-banner --no-color --exit-code 0
   --gitleaks-ignore-path <empty dir>`, with `GIT_CONFIG_NOSYSTEM=1`,
   `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_ATTR_NOSYSTEM=1`,
   `GIT_NO_LAZY_FETCH=1`, `GIT_NO_REPLACE_OBJECTS=1` and, through
   `GIT_CONFIG_COUNT`, `core.fsmonitor=false`, `core.hooksPath=/dev/null`,
   `core.pager=cat`, `core.attributesFile=/dev/null`, `diff.external=`,
   `log.showSignature=false` and the protocol settings above. With
   `--untrusted` it also gets `--ignore-gitleaks-allow` and no configuration
   (the copy has no working tree, so Gitleaks uses its default rules);
   otherwise the root's own `.gitleaks.toml` and `.gitleaksignore` (regular
   files inside the root) are passed, as the working-tree scan reads them.
   Gitleaks exits 0 with `--exit-code 0` even when its `git log` failed; an
   error-level line in its output therefore makes the history scan `failed`.
6. **Gitleaks runs without `--redact`.** Its report, inside the private
   temporary directory, carries each secret: code-audit reads it into
   memory, deletes the report file at once, and uses the values only to
   hash, deduplicate, recognise placeholders and decide `stillPresent`.
   The values are never written anywhere else, never quoted in a warning
   (a JSON parse error is reported without the parser's message, which can
   quote the input), and evidence is the first line of Gitleaks' match with
   every string literal and every occurrence of the secret (and of each of
   its lines) masked. Nothing is read back from the copy, so deduplication
   has no per-file budget.
7. The temporary directory is removed when the scan ends, also on error and
   timeout. While a history scan runs, handlers for `SIGINT`, `SIGTERM`,
   `SIGHUP` and process exit kill Gitleaks and the git processes it was
   started with and remove the directory synchronously; then the signal's
   default action proceeds (the handlers are removed when no history scan
   runs). A `SIGKILL` of the code-audit process cannot be handled: the
   directory (mode 0700) is left in the system temporary directory.

Limits: `--max-count=10000` (`CODE_AUDIT_HISTORY_MAX_COMMITS`), one
five-minute budget for clone, `rev-list`, Gitleaks and fingerprinting, at
most 5,000 results and a 64 MB report. When a limit is hit the history
status is `partial`, the run says why, and the report cover and the CLI
print a `WARNING` line (also for `failed`).

Output. A history result is a finding of the Gitleaks rule
(`gitleaks-<rule>`, same severity and confidence mapping as the working-tree
scan) with `provenance.engine: "gitleaks-history"` and `history: { commit,
date, stillPresent, occurrences }`: the earliest commit that added it - the
oldest in `git rev-list --topo-order` order, by date only for a commit not
in that list - and how many results were folded into it. One finding per
rule, file and secret. A secret that the current scan reports is not
reported twice: the current finding gets the `history` instead
(`stillPresent: true`), and its remediation gets the sentence "This secret
is also in the git history: rotate it; deleting the file or rewriting the
history is not enough." (in Chinese in a Chinese report), when the
working-tree Gitleaks scan reports the same rule for the same value in the
same file, or else when the value is still in that file on a line where any
engine reports a secret. Author names, e-mail addresses and commit messages
from the report are never stored or shown. The fingerprint of a history
finding is `sha256(rule, file, scrypt(sha256(secret)))` with scrypt `N=2^9,
r=8, p=1` (salt `code-audit-history-v2`, rule and file; about 0.7 ms of CPU
and 512 KiB per secret, roughly 2,000 times one SHA-256), computed two at a
time inside the time budget: 5,000 distinct secrets take under 5 s of CPU,
and a fingerprint in a report or baseline cannot be used to test guesses of
a short password at hash speed. The remediation of a history finding says
to rotate the credential: deleting the file or rewriting the history is not
enough.

Documented limits:

- Submodules (their history is in another repository) and objects reachable
  from no ref (reflog, dangling commits) are not scanned.
- A `.git` file or symbolic link that points at another repository on the
  machine, or `objects/info/alternates`, makes `upload-pack` serve that
  repository's objects: its secrets are reported (masked) as history of the
  audited root. The same holds for `--since`. It is not refused, because
  linked worktrees legitimately keep their git directory outside the root.
- `--history` on a directory that is not in a git work tree, or with an
  unknown ref, is an error (exit code 2, like `--since`); without gitleaks
  the history scan is skipped instead. A `failed` or `partial` history scan
  is reported (coverage, warnings, `WARNING` line) but does not change the
  exit code.
- `stillPresent` is broader than "the current scan reports the same rule for
  the same value": it is also true for a history finding whose value the
  file in the working tree still contains although no current finding
  covers it (the working-tree Gitleaks scan was not selected, or the value
  is allowlisted there). It is never false for a value still in the file.
- Commit dates come from the commits and can be forged; the order of
  `rev-list --topo-order` decides first.

## Run directories are not trusted

`.audit/`, a run directory and every file in it are part of the repository
being audited. Later commands therefore take nothing on trust from them:

- A run id is resolved only as `<root>/.audit/<run-id>` of the current
  directory or of `--root <dir>` (MCP: the `root` argument, the root of the
  `audit_start` call, or the base directory - all inside the base). A run
  directory that is a symbolic link leaving
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

## The tool's own files inside the project

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

## Host adapter installation

`code-audit install` writes into a project that may have been prepared by
someone else. It plans first and writes second (a refusal changes nothing),
takes the MCP command only from the command line or the default (never from
a file in the project), refuses symbolic links at target paths and
directories that lead out of the project, leaves entries it did not write
alone unless `--force` is given, and keeps one backup of every replaced file
under `.code-audit/backups/`. It never writes to user-level configuration
(`~/.claude`, `~/.codex`, `~/.config/opencode`). Details per host are in
`adapters/<host>/README.md`.

## Reporting a vulnerability

Report vulnerabilities in code-audit privately through GitHub security
advisories: open the repository's **Security** tab and choose **Report a
vulnerability**
(<https://github.com/oliver-zhao/code-audit/security/advisories/new>). Do
not open a public issue for them. See [SECURITY.md](../SECURITY.md) for what
to include and what counts as a vulnerability.
