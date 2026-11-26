# Claude Code adapter for code-audit

There are two ways to use code-audit from Claude Code.

## 1. Project install (recommended)

From the project you want to audit:

```sh
code-audit install --host claude-code --project .
```

This writes the files Claude Code reads for a project:

| File | Purpose |
| --- | --- |
| `.mcp.json` | Project MCP server `code-audit` (merged; other servers are kept). |
| `.claude/skills/code-audit/SKILL.md` | Shared audit workflow. |
| `.claude/commands/audit.md` | `/audit [path]` slash command. |

Then:

1. Start `claude` in the project and approve the project MCP server
   `code-audit` when asked. Until then `claude mcp list` shows it as pending
   approval.
2. Run `/audit` (or `/audit <path>`). The tools appear as
   `mcp__code-audit__audit_*`.
3. Headless:
   `claude -p "/audit" --mcp-config .mcp.json --allowedTools "mcp__code-audit__*"`.

The installer never writes to `~/.claude`.
`code-audit install --uninstall --host claude-code --project .` removes the
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
- `.mcp.json` is edited in place: indentation, key order and every other
  server stay byte for byte as they were (a UTF-8 BOM is kept, an empty file
  counts as `{}`). A `.mcp.json` with comments or trailing commas is not
  rewritten: the installer prints the entry to add by hand, or rewrites the
  file as plain JSON with `--force`.
- A `mcpServers.code-audit` entry that the installer did not write is left
  alone (`--force` replaces it). Uninstall removes the entry only when it is
  what the installer writes.
- A file of yours that has to be replaced (your own
  `.claude/commands/audit.md`, or a config rewritten with `--force`) is copied
  to `.code-audit/backups/<path>` first: one backup per file, never a second
  one next to it. Uninstall puts a replaced file back.

`.mcp.json` uses the bare command `code-audit-mcp`, which must be on the `PATH`
of the `claude` process. If it is not, install with `--absolute` (writes the
absolute path of this checkout's `bin/code-audit-mcp`; do not commit that
`.mcp.json`) or `--mcp-command <path>`. `code-audit doctor --project .` checks it.

## 2. Plugin (this directory)

This directory is a standalone Claude Code plugin:

| File | Purpose |
| --- | --- |
| `.claude-plugin/plugin.json` | Plugin manifest. |
| `.mcp.json` | MCP server `code-audit`. |
| `skills/code-audit/SKILL.md` | Shared audit workflow. |
| `commands/audit.md` | `/code-audit:audit [path]` slash command. |

```sh
claude --plugin-dir /path/to/code-audit/adapters/claude-code
```

The repository root also carries `.claude-plugin/marketplace.json`, so the
checkout can be added as a marketplace (`claude plugin marketplace add
/path/to/code-audit`, then `claude plugin install code-audit@code-audit`).
The plugin's `.mcp.json` uses the bare command `code-audit-mcp`; it must be on
`PATH`.

## Verification level

Checked with Claude Code 2.1.183 on macOS, without model calls:

- `claude plugin validate --strict adapters/claude-code` and
  `claude plugin validate --strict .` (marketplace) pass with no warnings.
- After a project install, `claude mcp list` in the project lists `code-audit`
  from `.mcp.json` (pending approval until the user approves it).

Not yet verified (needs a logged-in Claude Code): approving the server and
running `/audit` end to end, the headless command line above, skill
auto-discovery from `.claude/skills`, loading the plugin with `--plugin-dir`,
and installing it through the marketplace.
