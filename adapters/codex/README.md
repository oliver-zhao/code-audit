# Codex adapter for code-audit

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
`AGENTS.md` and never writes to `~/.codex` or `~/.agents`. Existing unrelated
content is preserved byte for byte (CRLF line endings included);
`code-audit install --uninstall --host codex --project .` removes the managed
blocks and the files install created.

What the installer does with a project it did not create:

- It plans first and writes second: every target is checked before anything is
  written, a failure half-way is rolled back, and `--dry-run` prints the whole
  plan, refusals included. A refusal exits with status 2 and changes nothing.
- The MCP command comes from `--mcp-command`, `--absolute` or the default
  `code-audit-mcp`, never from a file in the project. A re-install without the
  option goes back to the default and prints the old and the new command.
- Symbolic links at a target path, and directories that lead out of the
  project, are refused.
- `.codex/config.toml` must parse, and must not define
  `mcp_servers.code-audit` outside the managed block in any spelling
  (`[mcp_servers.code-audit]`, `code-audit = { ... }` under `[mcp_servers]`,
  or a dotted key). Otherwise the file is not touched and the message says
  what to add or remove by hand.
- A managed block is a begin-marker line followed by its end-marker line. An
  orphan begin marker, a stray end marker or a second block is refused with
  the line number: the installer does not guess which lines are yours.
- A file of yours that has to be replaced is copied to
  `.code-audit/backups/<path>` first (one backup per file).

## Making the MCP server visible

Codex loads the skill and `AGENTS.md` from any project, but it reads a
project-level `.codex/config.toml` **only for projects you have marked as
trusted**. Until then the `code-audit` tools are missing. Pick one:

1. **Trust the project.** Interactive `codex` offers this on first start in a
   directory; it is stored in your own `~/.codex/config.toml` as

   ```toml
   [projects."/absolute/path/to/project"]
   trust_level = "trusted"
   ```

   code-audit never edits that file.
2. **Register the server once for your user:**

   ```sh
   codex mcp add code-audit -- /absolute/path/to/code-audit-mcp
   ```

3. **One-off or CI run** with command-line overrides:

   ```sh
   codex exec \
     -c 'mcp_servers.code-audit.command="/absolute/path/to/code-audit-mcp"' \
     -c 'mcp_servers.code-audit.args=[]' \
     -c 'mcp_servers.code-audit.default_tools_approval_mode="approve"' \
     "Run a security audit of this project with the code-audit skill."
   ```

**Headless runs need the tools pre-approved.** `codex exec` cannot ask for
approval and rejects every MCP tool call with "MCP tool call requires approval,
but approval policy is never" (the agent then falls back to the `code-audit`
CLI if it finds one). Keep the `default_tools_approval_mode="approve"` override
for `codex exec` with options 1 and 2 as well. Interactive `codex` asks instead.
The installer does not write that setting into the project config: whether to
pre-approve tool calls is your decision.

`code-audit install` prints these commands with the real path filled in.
Check with `codex mcp list`. The tools appear as `mcp__code_audit__audit_*`
(Codex rewrites the hyphen in the server name).

The project config uses the bare command `code-audit-mcp`, which must be on the
`PATH` of the Codex process. Otherwise install with `--absolute` (do not commit
the resulting `.codex/config.toml`) or `--mcp-command <path>`.

## Verification level

Verified with the real Codex CLI 0.166 on macOS after `code-audit install
--host codex`: the skill and `AGENTS.md` are picked up from the project, the
project `.codex/config.toml` is ignored for an untrusted project, and
`codex exec` with the three `-c` overrides above runs an audit through the MCP
tools (`audit_start`, `audit_status`, `audit_findings`, `audit_read`,
`audit_verdict`, `audit_report`). Without the approval override the same run
has every MCP call rejected. Options 1 and 2 and interactive approval were not
exercised because they change the user's `~/.codex/config.toml`.

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

```toml
[mcp_servers.code-audit]
command = "code-audit-mcp"
args = ["--base", "/absolute/path/to/project"]
```

Do not commit an entry with an absolute path. Keep the base as narrow as the
project: every directory below it can be audited, and so read, by the model.
See [docs/mcp.md](../../docs/mcp.md#base-directory).
