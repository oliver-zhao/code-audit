# Vetting a skill or plugin before install

`code-audit skill <target>` scans an agent skill or plugin package before it
is installed and gives every package one deterministic verdict. The MCP
server offers the same as the tool `audit_skill` (local paths only; see
[mcp.md](mcp.md#audit_skill)).

```sh
code-audit skill ./downloads/pdf-helper            # a directory
code-audit skill ./downloads/pdf-helper/SKILL.md   # the directory of this SKILL.md
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

`INCOMPLETE` reasons, each listed by path: a file the scanner skipped (over
1 MiB, unreadable, not a regular file, a symbolic link - also a `SKILL.md`
that is a link); every file inside a `.git` directory (the inventory never
enters one), except two cases: the `.git` of the tool's own fresh clone is
deleted before the scan, and a real `.git` directory at the root of a local
directory target (or of the directory of a `SKILL.md` target) is excluded
with the note "git metadata at .git/ not analysed: not part of an installed
skill" when it looks created by git: only git's standard top-level entries
(`HEAD`, `config`, `description`, `hooks`, `info`, `objects`, `refs`, `logs`,
`index`, `packed-refs`, `FETCH_HEAD`, `ORIG_HEAD`, `COMMIT_EDITMSG`,
`shallow`), only `*.sample` hooks, only `info/exclude`, loose objects and
pack files in `objects/`, no symbolic links, and no `config` key outside
`core.{repositoryformatversion,filemode,bare,logallrefupdates,ignorecase,precomposeunicode,symlinks}`,
`remote.*.{url,fetch,tagopt}`, `branch.*.{remote,merge}` and
`extensions.objectformat`; a `remote.*.url` must be an `https://`,
`ssh://`, `git://` or `user@host:path` address and `tagopt` `--no-tags` or
`--tags`. Otherwise every unusual entry is listed with its
reason, and every file in it. A nested `.git`, a `.git` inside an archive,
and a `.git` that is a file (gitdir pointer) or a symbolic link are still
reported; control files (`.code-audit-ignore`, `.code-audit-baseline.json`)
and files named like code-audit output that this run did not write (an
earlier or planted `.audit/<run>/`); a file the text pass (below) could not
cover (over 1 MiB, unreadable); an executable (ELF, Mach-O, PE) or a nested
archive, which stay listed after the text pass; a Git LFS pointer (the
content was not present); an archive entry that was not unpacked
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
every package (and unanalysed files there) form the group
`(outside packages)` (kind `outside`), which has its own verdict and counts
toward the exit code like a package; `summary.outside` counts its results.
Without `--recursive` the target is one package; a `SKILL.md` target scans
the directory that contains it.

Every text file below the target is treated as an instruction file,
whatever its extension (Markdown, `.txt`, `.yaml`, `.json`, templates,
extensionless files, and source code too): a skill tells the agent to read
its `reference.md`, `FORMS.md`, `config.yaml` and so on, and may point
outside its own directory (`../../shared.md`). The rules whose `pathInclude` uses the
`{{INSTR}}` macro (prompt injection, agent configuration) are applied to
them too; outside every package they feed the `<outside packages>` group.

In text output packages are shown as `./relative/path` (with their name in
parentheses) and the outside group as `<outside packages>`, which no package
path can produce.

### Text pass (file classification is not trusted)

Every file the inventory skips as binary (by extension or a NUL byte) and
every file that is not valid UTF-8 goes through a text pass. Results point
at the original file and the line its text starts on (approximate), with
evidence marked with the view that matched; a result the normal pass already
reported (same rule, file and line) is not repeated.

- UTF-16 (with a BOM, or mostly ASCII with a NUL in every other byte of the
  first 512 bytes) and UTF-32 with a BOM are decoded and matched like a
  UTF-8 file: the rules of the file's language, the instruction and shell
  rules, and the secret detectors. Wide text that does not decode is not
  analysed.
- Otherwise its printable runs (4 or more characters of ASCII or UTF-8, or a
  whole newline-terminated line) are matched with the Markdown (instruction)
  and shell rules and the secret detectors, and so is the same text with
  every NUL byte removed (bash drops NUL bytes and runs what is left).
- In a PDF, every `FlateDecode` stream is inflated (at most 1 MiB and a
  100:1 ratio per stream, 100 MiB per scan) and its printable text and the
  strings of its text operators (`Tj`, `TJ`, `'`, `"`, hex strings, joined
  per text object) are matched the same way. A stream over the limits makes
  the package `INCOMPLETE`. Streams with `LZWDecode`, `ASCII85Decode`,
  `ASCIIHexDecode` or `RunLengthDecode` are not decoded: a note says so (not
  `INCOMPLETE`).

A polyglot such as `%PDF-1.4` followed by a script is therefore matched like
the script. A file counts as analysed only once the text pass ran on it; a
file over 1 MiB is not analysed.

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
- a name component ending in a dot or space, or full-width dots that fold
  to `..` (Windows rewrites them);
- zip: an end record that is not exactly at end-of-file minus its declared
  comment length, or a comment that contains a zip record signature
  (`PK\1\2`, `PK\3\4`, `PK\5\6`, `PK\6\6`, `PK\6\7`, `PK\7\8`: a
  second archive hidden in the comment, which other extractors pick);
- zip: a local header that disagrees with the central directory on name,
  method, flags, CRC-32 or sizes (with bit 3 set: the data descriptor must
  match), an Info-ZIP Unicode path (in the local or the central record) that
  names another file, a malformed extra field, entries that do not tile the
  archive from offset 0 to the central directory (gaps, prefixes, local
  entries no central record points at, overlaps), data between the central
  directory and the end record, ZIP64 or multi-volume archives; an entry that
  inflates beyond its declared size or fails its CRC-32;
- tar: a bad header checksum, a truncated archive, a pax `size` that is not
  plain decimal; gzip: a ratio over 100:1 for more than 1 MiB of output.

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

The run is written to `--out <dir>` or `./.audit/<run-id>/` (the current
directory), never into the package or a temporary copy: a vetted directory is
often copied as it is into a host's skills directory. When the current
directory is inside the package, the run lands inside it, and an earlier run
there makes the next scan `INCOMPLETE` (run from outside the package, or pass
`--out`). Besides the
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

- PDF: only `FlateDecode` streams are decoded. Text in streams with other
  filters (LZW, ASCII85, ASCIIHex, RunLength, chains of them), text drawn
  through font encodings or CMaps that map codes to other characters, and
  text in images is not analysed; a note names the undecoded filters.
- Text obfuscated with shell quoting (`cu''rl`), encodings a script decodes
  at run time, or encryption is beyond pattern rules.

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
- A critical hotspot never gives `DO_NOT_INSTALL` (hotspots are review
  prompts; it gives `REVIEW`).
- Untrusted mode keeps placeholder-looking secrets at full confidence, so a
  documentation placeholder such as `api_key="your-api-key"` makes a package
  `REVIEW`.
- File names are printed as they are (a secret in a file name is not
  masked); package names, notes and evidence are masked.
- No size cap on a git clone other than its 180 s timeout; SIGTERM ends the
  scan and removes the temporary directory, but a `git clone` still running
  is not killed.
