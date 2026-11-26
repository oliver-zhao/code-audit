# OpenCode adapter for code-audit

This adapter registers the `code-audit` stdio MCP server with OpenCode and adds
the shared skill plus an `/audit` command.

| File | Purpose |
| --- | --- |
| `opencode.json` | Project `mcp.servers.code-audit` entry (`type: local`, stdio command). |
| `skills/code-audit/SKILL.md` | Shared audit workflow, discovered from `.opencode/skills/`. |
| `commands/audit.md` | `/audit [path]` command, discovered from `.opencode/commands/`. |

## Install

From the project you want to audit:

```sh
code-audit install --host opencode --project .
```

`code-audit` is not installed by this adapter. The config uses the bare command
`code-audit-mcp`, which must be on the `PATH` of the OpenCode process (from this
repo: `pnpm run link:local`, then add `bin/` to `PATH`). If that is not possible
(GUI or service launches often have a minimal `PATH`), install with
`--absolute` (writes the absolute path of this installation's `code-audit-mcp`;
do not commit the resulting config) or `--mcp-command <path>`.
`code-audit doctor --project .` reports whether the configured command resolves.

The installer merges into an existing `opencode.json`/`opencode.jsonc` and
never edits `~/.config/opencode`.
`code-audit install --uninstall --host opencode --project .` removes the
`code-audit` entry and the files install created.

What the installer does with a project it did not create:

- It plans first and writes second: every target is checked before anything is
  written, a failure half-way is rolled back, and `--dry-run` prints the whole
  plan, refusals included. A refusal exits with status 2 and changes nothing.
- The MCP command comes from `--mcp-command`, `--absolute` or the default
  `code-audit-mcp`, never from a file in the project. A re-install without the
  option goes back to the default and prints the old and the new command.
- Symbolic links at a target path, and directories that lead out of the
  project, are refused.
- Plain JSON is edited in place: indentation, key order and every other
  setting stay byte for byte as they were (a UTF-8 BOM is kept, an empty file
  counts as `{}`).
- A config with comments or trailing commas is not rewritten, because the
  comments would be lost. The installer prints the entry to add by hand:

  ```jsonc
  "mcp": { "servers": { "code-audit": { "type": "local", "command": ["code-audit-mcp"] } } }
  ```

  `--force` rewrites the file as plain JSON without comments instead and keeps
  the original as `.code-audit/backups/<path>`.
- A `mcp.servers.code-audit` entry that the installer did not write is left
  alone (`--force` replaces it, with a backup). Uninstall removes the entry
  only when it is what the installer writes.
- There is one backup per file, under `.code-audit/backups/`; a replaced file
  of yours is put back by uninstall.

Manual equivalent: copy `opencode.json` to the project root, copy
`skills/code-audit/SKILL.md` to `.opencode/skills/code-audit/SKILL.md`, and copy
`commands/audit.md` to `.opencode/commands/audit.md`.

## Verified on a real host

Verified with OpenCode **v2.4.1** on Linux using a project-local config (no
global changes): after `code-audit install --host opencode`, the server
connects, the skill and the `/audit` command are discovered, and a full audit
ran through the MCP tools with this version of the code.
`examples/opencode-demo/` holds the same config.

```text
$ opencode mcp list --server http://127.0.0.1:4102
✓ code-audit  connected
```

The server API also confirmed the skill and command were discovered:

```text
$ opencode api --server http://127.0.0.1:4102 mcp.list
{"location":{"directory":"/tmp/ocproj2"},"data":[{"name":"code-audit","status":{"status":"connected"}}]}

$ opencode api --server http://127.0.0.1:4102 skill.list
[{"id":"code-audit","name":"code-audit","path":"/tmp/ocproj2/.opencode/skills/code-audit/SKILL.md"}]

$ opencode api --server http://127.0.0.1:4102 command.list
[{"name":"audit","description":"Run a deterministic code-audit security review"}]
```

Note: a cold `opencode mcp list` right after startup can print "No MCP servers
configured" because the background server is still loading the project config.
Warm the server (or retry) before trusting that output.

## Which directory is audited

The MCP server audits, reads and writes only inside its **base directory**,
which is fixed when the server starts: the directory the host starts it in.
The entry written by `code-audit install` passes no arguments, so this works
when the host starts project MCP servers in the project directory. The server
prints the base to stderr at start-up
(`[code-audit] ... base directory: /path (working directory)`); look for that
line in the host's MCP log if `audit_start` answers `OUTSIDE_BASE` or
`BASE_TOO_BROAD`.

A model cannot change the base: a `root` outside it (also through `..` or a
symbolic link), and credential directories such as `~/.ssh` or `~/.aws`, are
refused. To audit a different directory, open the host in that directory, or
set the base yourself in the server entry (or with the environment variable
`CODE_AUDIT_MCP_BASE`):

```json
{ "mcp": { "servers": { "code-audit": { "type": "local", "command": ["code-audit-mcp", "--base", "/absolute/path/to/project"] } } } }
```

Do not commit an entry with an absolute path. Keep the base as narrow as the
project: every directory below it can be audited, and so read, by the model.
See [docs/mcp.md](../../docs/mcp.md#base-directory).
