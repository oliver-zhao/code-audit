# Vetting a skill or plugin before install

`code-audit skill <target>` scans an agent skill or plugin package before it
is installed and gives every package one deterministic verdict. The MCP
server offers the same as the tool `audit_skill` (local paths only; see
[mcp.md](mcp.md#audit_skill)).

```sh
code-audit skill ./downloads/pdf-helper            # a directory
code-audit skill ./downloads/SKILL.md              # a single SKILL.md
code-audit skill ./downloads/pdf-helper.zip        # .zip, .tar, .tar.gz, .tgz
code-audit skill https://github.com/org/skills --recursive
code-audit skill ./plugins --recursive --json
```

Options: `--recursive`, `--format md,json,sarif`, `--out <dir>`, `--offline`,
`--engines <list>` (`--no-external`), `--rules <dir>`, `--lang en|zh`,
`--json` (print `skill.json` instead of text), `--allow-sensitive-root`.

Exit codes: `0` when every package is `SAFE_TO_INSTALL`; `1` when any package
is `REVIEW`, `DO_NOT_INSTALL` or `INCOMPLETE`; `2` on a runtime error (bad
arguments, a refused git URL, a refused archive).

## Verdicts

Checked in this order; the first that applies wins.

| Verdict | When |
|---|---|
| `DO_NOT_INSTALL` | A rule tagged `malicious-intent` matched at confidence medium or high, or a critical finding at confidence high. |
| `REVIEW` | A high or critical finding (any confidence), a medium finding at confidence medium or high, any hotspot, or a `malicious-intent` match at low confidence. |
| `INCOMPLETE` | Something was not analysed: see below. |
| `SAFE_TO_INSTALL` | None of the above: no known risk patterns found. **Not a guarantee of safety.** |

`REVIEW` and `DO_NOT_INSTALL` still list what was not analysed. A package
with a skipped file is never `SAFE_TO_INSTALL`.

`INCOMPLETE` reasons: a file the scanner skipped (over 1 MiB, unreadable, not
a regular file, a symbolic link); a binary file that is not a recognised
image, font, audio, video or PDF under its own extension (executables, nested
archives and unknown binaries count); an archive entry that was not unpacked
(too large, compression ratio over 100:1, unsupported method, encrypted,
unsupported tar entry type); rule matching that stopped early in a file; an
external engine that failed or timed out (or a requested one that is not
installed); `--engines` without `builtin`; dependencies of the package that
were not checked against OSV.dev (`--offline`, or OSV.dev unavailable).

The risk score (0-100) only orders the packages: critical 40, high 20,
medium 8, low 3, times the confidence factor (high 1.0, medium 0.6, low 0.3),
a hotspot counts a quarter, capped at 100. The verdict never looks at it.

Rule tags are read from the loaded rule set by rule id, so a custom rule set
(`--rules`) can tag its own rules `malicious-intent`.

## What is scanned

The package is always audited as untrusted (`--untrusted` cannot be turned
off): its ignore file, baseline, inline `code-audit:ignore` comments and path
names cannot lower the result, and normally skipped directories are scanned.
Default engines: `builtin` plus `opengrep` and `gitleaks` when installed;
`--engines` overrides.

With `--recursive`, every directory below the target that holds a
`SKILL.md`, a `.claude-plugin/plugin.json` or a `plugin.json` is a package
(`.git`, `.audit` and `node_modules` are not searched for packages, but are
scanned as content). A result in a nested package also counts for the
package around it: installing a plugin installs its skills. Results outside
every package are counted in `summary.outside`. Without `--recursive` the
target is one package.

### Capability declaration check

When `SKILL.md` declares `allowed-tools` (a string such as
`Read, Grep, Bash(git:*)`, or a list), the scripts of the skill (`.sh`, `.py`,
`.js`/`.ts`, `.rb`, `.pl`, `.ps1`, or a file with a matching `#!` line) are
checked for three capabilities:

| Capability | Detected by (examples) | Granted by |
|---|---|---|
| network | `curl`, `wget`, `fetch(`, `requests.`, `http.`, `urllib` | `Bash`, `WebFetch` |
| subprocess | `subprocess`, `child_process`, `os.system`, `exec(`; every shell script | `Bash` |
| file write | shell redirection `>`, `writeFile`, `open(..., "w")` | `Bash`, `Write`, `Edit`, `MultiEdit`, `NotebookEdit` |

A script that uses a capability no declared tool grants produces the hotspot
`skill-undeclared-capability` (medium, CWE-912), one per script and
capability, which makes the package `REVIEW`. It is an ordinary result of
the run: it appears in `findings.json` and the reports. Without
`allowed-tools` nothing is compared; the detected capabilities are still
listed in `skill.json`.

## Archives

Zip (stored and deflate) and tar (POSIX ustar, pax headers, GNU long names;
plain or gzip-compressed) are read by the tool itself on top of `node:zlib`.
Before anything is written the whole archive is checked; any of the following
refuses it (exit code 2, MCP code `ARCHIVE_*`):

- more than 10,000 entries, or more than 100 MiB uncompressed in total;
- an absolute path, a drive letter, a `..` segment, a backslash, a control
  character, or a name that is not valid UTF-8;
- a symbolic link, hard link, device, FIFO or socket entry;
- two entries for one path (compared after Unicode NFC normalisation and
  case folding), or a file used as a directory;
- zip: overlapping entries, a local header that disagrees with the central
  directory, an Info-ZIP Unicode path that names another file, ZIP64 or
  multi-volume archives; an entry that inflates beyond its declared size or
  fails its CRC-32;
- tar: a bad header checksum, a truncated archive; gzip: a ratio over 100:1
  for more than 1 MiB of output.

Entries over 1 MiB, with a compression ratio over 100:1, encrypted, or with
another compression method are not unpacked and make the package
`INCOMPLETE`. The archive is unpacked into a new temporary directory (files
mode 0644, created exclusively without following links, every path checked
against the directory afterwards) that is removed when the scan ends, also
after an error or Ctrl-C.

## Git targets

Only `https://host/path`, `ssh://[user@]host[:port]/path` and
`user@host:path` are accepted. `file://`, `git://`, `http://`, `ext::` and
every other `<transport>::` form, user info in an https URL, a password, and
anything starting with `-` are refused. With `--offline` a git target is
refused. The clone is

```
git -c protocol.allow=never -c protocol.https.allow=always -c protocol.ssh.allow=always
    -c protocol.file.allow=never -c core.hooksPath=/dev/null -c core.fsmonitor=false
    -c submodule.recurse=false -c credential.helper=
    clone --depth 1 --no-recurse-submodules --no-tags
    -c core.hooksPath=/dev/null -c protocol.file.allow=never -- <url> <tmp>
```

with no system or global git configuration (`GIT_CONFIG_NOSYSTEM`,
`GIT_CONFIG_GLOBAL=/dev/null`), `GIT_ALLOW_PROTOCOL=https:ssh`, no terminal
prompts, Git LFS smudging off, and ssh in batch mode. Nothing in the clone is
run. The MCP server never clones.

## Output

The run is written like any scan: `<target>/.audit/<run-id>/` for a
directory target, and `--out <dir>` or `./.audit/` for an unpacked archive, a
single `SKILL.md` or a clone (never into the temporary copy). Besides the
usual run files it holds `skill.json` and, with `md` in `--format`,
`skill.md`. Because the root of an unpacked or cloned target is removed after
the scan, `read` / `search` on such a run cannot show source lines.

`skill.json` (`schemaVersion: 1`; the zod schema is exported as
`SkillScanDocumentSchema` from `@code-audit/core`):

```json
{
  "schemaVersion": 1,
  "tool": { "name": "code-audit", "version": "0.3.0" },
  "target": { "input": "./downloads/pdf-helper.zip", "kind": "archive" },
  "recursive": false,
  "runId": "...",
  "runDir": "...",
  "packages": [
    {
      "path": ".",
      "name": "pdf-helper",
      "kind": "skill",
      "verdict": "REVIEW",
      "verdictText": "...",
      "riskScore": 9.5,
      "reasons": [{ "code": "hotspot", "message": "...", "findingId": "HOT-...", "ruleId": "...", "file": "...", "line": 3 }],
      "incomplete": [{ "path": "bin/tool", "reason": "ELF executable (not analysed)" }],
      "findings": [{ "id": "...", "ruleId": "...", "kind": "hotspot", "severity": "medium", "confidence": "medium", "title": "...", "file": "...", "startLine": 3, "tags": [], "evidence": "..." }],
      "capabilities": {
        "allowedTools": ["Read", "Grep"],
        "detected": { "network": ["scripts/fetch.py"], "subprocess": [], "fileWrite": [] },
        "undeclared": ["network"]
      },
      "notes": []
    }
  ],
  "summary": {
    "packages": 1,
    "verdicts": { "DO_NOT_INSTALL": 0, "REVIEW": 1, "INCOMPLETE": 0, "SAFE_TO_INSTALL": 0 },
    "verdict": "REVIEW",
    "exitCode": 1,
    "outside": { "findings": 0, "hotspots": 0 }
  }
}
```

Paths in `findings` and `reasons` are relative to the scanned root; paths in
`incomplete` are relative to the package. Everything quoted from the package
(names, paths, evidence) is untrusted text.

## Limits

- The verdict is only as good as the rules: a hostile package written to
  avoid every known pattern gets `SAFE_TO_INSTALL`, which is why that verdict
  says "not a guarantee of safety".
- The capability check is pattern based and per line; it does not follow
  imports, dynamic code or obfuscation.
- ZIP64, multi-volume zip, encrypted entries and compression methods other
  than store and deflate are not supported.
- `.tar.bz2` / `.tar.xz` and other formats are not accepted as targets; a
  nested archive inside a package is not unpacked (it makes the package
  `INCOMPLETE`).
