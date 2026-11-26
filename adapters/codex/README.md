# Codex adapter for code-audit

**Not verified on a real host.** Codex is not installed on this machine. The
files below follow the documented `.agents/skills` + TOML MCP + `AGENTS.md`
layout and are covered only by format and required-field tests.

| File | Purpose |
| --- | --- |
| `.codex/config.toml` | Project MCP server registration (`[mcp_servers.code-audit]`). |
| `.agents/skills/code-audit/SKILL.md` | Shared audit workflow in the `.agents/skills` layout. |
| `AGENTS.md` | Managed project-instructions block that points at the skill. |

## Install

From the project you want to audit:

```sh
code-audit install --host codex --project .
```

The installer appends or replaces a managed block in `.codex/config.toml` and
`AGENTS.md`, backs up changed files as
`<file>.code-audit-backup-<stamp>`, and never writes to `~/.codex` or
`~/.agents`. Existing unrelated content is preserved. `--dry-run` prints the
planned changes.

Make sure `code-audit-mcp` resolves in the environment that starts the host.

## Verification level

- TOML contains `[mcp_servers.code-audit]` with `command = "code-audit-mcp"`.
- `AGENTS.md` keeps existing content and adds exactly one managed block.
- Not executed on Codex; host-specific discovery and skill loading still need a
  manual check.

Manual check once Codex is available:

```sh
codex mcp list
codex
# ask it to run a security review; the code-audit skill should be offered
```
