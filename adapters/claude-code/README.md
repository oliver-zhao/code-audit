# Claude Code adapter for code-audit

**Not verified on a real host.** Claude Code is not installed on this machine.
The files below follow the documented plugin/MCP layout and are covered only by
JSON validity and required-field tests.

| File | Purpose |
| --- | --- |
| `.claude-plugin/plugin.json` | Plugin manifest (`name`, `version`, `description`, `author`). |
| `.mcp.json` | Project MCP server registration under `mcpServers`. |
| `skills/code-audit/SKILL.md` | Shared audit workflow. |
| `commands/audit.md` | `/audit [path]` slash command with frontmatter. |

## Install

From the project you want to audit:

```sh
code-audit install --host claude-code --project .
```

The installer merges `.mcp.json` and `.claude-plugin/plugin.json` instead of
overwriting them, backs up changed files as
`<file>.code-audit-backup-<stamp>`, and never writes to `~/.claude`.
`--dry-run` prints the planned changes.

Make sure `code-audit-mcp` resolves in the environment that starts the host.

## Verification level

- JSON parses and the manifest has the required fields (automated test).
- MCP entry has `command: "code-audit-mcp"` and an `args` array.
- Not executed on Claude Code; host-specific discovery and slash-command
  behavior still need a manual check.

Manual check once Claude Code is available:

```sh
claude mcp list
claude
# then run: /audit .
```
