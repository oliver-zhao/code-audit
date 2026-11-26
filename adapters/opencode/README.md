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

`code-audit` is not installed by this adapter. Make sure `code-audit-mcp` (from
this repo: add `packages/cli/node_modules/.bin` to `PATH`) resolves in the
environment that starts OpenCode.

The installer merges into an existing `opencode.json`/`opencode.jsonc`
(comments and trailing commas are tolerated) and backs up every changed file as
`<file>.code-audit-backup-<stamp>`. `--dry-run` prints the planned changes.
It never edits `~/.config/opencode`.

Manual equivalent: copy `opencode.json` to the project root, copy
`skills/code-audit/SKILL.md` to `.opencode/skills/code-audit/SKILL.md`, and copy
`commands/audit.md` to `.opencode/commands/audit.md`.

## Verified on a real host

Verified with OpenCode **v2.4.1** on Linux using a project-local config (no
global changes). `examples/opencode-demo/` holds the same config.

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
