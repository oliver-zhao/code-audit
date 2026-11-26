# DSH adapter for code-audit

DSH composes profiles from Cordis patch layers. This adapter adds the
`@deepseek-ai/dsh-mcp-client` entry that launches `code-audit-mcp` and exposes
its tools as `mcp__code-audit__audit_*`.

The project-local skill is installed at `.dsh/skills/code-audit/SKILL.md`.
DSH's `dsh-skill-filesystem` provider registers it as source `project-dsh` with
rank 100 (`.agents/skills` is `project-agents`, rank 200); see
`node_modules/@deepseek-ai/dsh-skill-filesystem/README.md`.

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

## Verified on a real host

Verified with DSH **0.2.2-rc.5** on Linux, without changing the global profile,
using `examples/dsh-demo/`:

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

DSH exposes these as `mcp__code-audit__audit_*` in the model's tool list.
