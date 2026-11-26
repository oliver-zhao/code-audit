# DSH adapter for code-audit

DSH composes profiles from Cordis patch layers. This adapter adds the
`@deepseek-ai/dsh-mcp-client` entry that launches `code-audit-mcp` and exposes
its tools as `mcp__code-audit__audit_*`.

The project-local skill is installed at `.dsh/skills/code-audit/SKILL.md`.
DSH's `dsh-skill-filesystem` provider registers it as source `project-dsh` with
rank 100 (`.agents/skills` is `project-agents`, rank 200); see
`node_modules/@deepseek-ai/dsh-skill-filesystem/README.md`.

## Install

```sh
code-audit install --host dsh --project .
```

writes a managed block into `dsh/cordis.patch.yml` and the skill into
`.dsh/skills/code-audit/SKILL.md`;
`code-audit install --uninstall --host dsh --project .` removes both again.
DSH does not load the patch on its own: pass it with `--patch` as shown below.

What the installer does with a project it did not create:

- It plans first and writes second: every target is checked before anything is
  written, a failure half-way is rolled back, and `--dry-run` prints the whole
  plan, refusals included. A refusal exits with status 2 and changes nothing.
- The MCP command comes from `--mcp-command`, `--absolute` or the default
  `code-audit-mcp`, never from a file in the project. A re-install without the
  option goes back to the default and prints the old and the new command.
- Symbolic links at a target path, and directories that lead out of the
  project, are refused.
- The command is always written as a quoted YAML string
  (`command: 'code-audit-mcp'`), so a value such as `true`, `123` or `a: b`
  stays a string. Line breaks and control characters in `--mcp-command` are
  refused.
- A managed block is a begin-marker line followed by its end-marker line. An
  orphan begin marker, a stray end marker or a second block is refused with
  the line number; nothing is appended to such a file.
- A file of yours that has to be replaced is copied to
  `.code-audit/backups/<path>` first (one backup per file).

The patch uses the bare command `code-audit-mcp`, which must be on the `PATH`
of the DSH process. Otherwise install with `--absolute` (do not commit the
resulting patch) or `--mcp-command <path>`; `code-audit doctor --project .`
reports whether the configured command resolves.

## Use without changing your profile

From the project root:

```sh
dsh --profile web --patch dsh/cordis.patch.yml
```

Verify the composed entry:

```sh
dsh --profile web --patch dsh/cordis.patch.yml --dump-config | grep -A8 mcp-code-audit
```

The patch only adds a project-local MCP server and never edits the global
profile under `$DSH_HOME`.

## Verification level

Checked with DSH **0.2.2-rc.5** on Linux, without changing the global profile,
using `examples/dsh-demo/`: the patch composes and the MCP server starts
under real DSH.

A full agent run was done in headless mode after a project install
(`code-audit install --host dsh --absolute`):

```sh
dsh headless --patch <models-overlay.yml> --patch dsh/cordis.patch.yml \
    --approval-policy never --json "Run a security audit of this project ..."
```

The model loaded the skill and called `mcp__code-audit__audit_start`,
`audit_status`, `audit_findings`, `audit_read`, `audit_search`,
`audit_verdict` and `audit_report`: 21 tool calls, every one completed. The
run was slow with the model used and was continued once with `--session-id`.

Two things to know for headless runs:

- The shipped `headless` profile has the `credentials` plugin disabled, so
  model keys stored through the web UI are not found
  (`MISSING_CREDENTIAL`). Either export the provider's key variable, or pass
  an overlay that enables it and configures a provider, for example:

  ```yaml
  - id: credentials
    disabled: false
  # followed by your `llm-pi-ai` providers and `agent-default-model` entries,
  # as in the web profile's cordis.patch.yml
  ```

- `--approval-policy never` is needed so MCP tool calls are not held for
  approval in a non-interactive run.

The static checks that came first:

```text
$ dsh --profile web --patch examples/dsh-demo/dsh/cordis.patch.yml --dump-config
- id: mcp-code-audit
  name: '@deepseek-ai/dsh-mcp-client'
  config:
    serverName: code-audit
    transport: stdio
    command: code-audit-mcp
    args: []
    failOnStartupError: false
```

The composed overlay has no `patch: entry ... not found` warning. A live stdio
probe through the real `@deepseek-ai/dsh-mcp-client` `probeServer` (see
`examples/dsh-demo/probe.mjs`) lists all eight tools:

```text
$ node examples/dsh-demo/probe.mjs
{
  "server": { "name": "code-audit", "version": "0.1.0" },
  "toolCount": 8,
  "tools": [
    "audit_start", "audit_status", "audit_findings", "audit_read",
    "audit_search", "audit_verdict", "audit_add_finding", "audit_report"
  ],
  "truncated": false
}
```

The `version` in this recorded output is that of the development build the
probe was first recorded with; the server reports the version of the
installed tool. DSH exposes the tools as `mcp__code-audit__audit_*` in the
model's tool list.

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

```yaml
    command: code-audit-mcp
    args: ['--base', '/absolute/path/to/project']
```

Do not commit an entry with an absolute path. Keep the base as narrow as the
project: every directory below it can be audited, and so read, by the model.
See [docs/mcp.md](../../docs/mcp.md#base-directory).
