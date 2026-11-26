# OpenCode demo for code-audit

This project configures the `code-audit` MCP server for OpenCode. The
configuration was verified with `opencode v2.4.1` using `opencode mcp list`.

## Prerequisites

Make `code-audit-mcp` resolvable on `PATH`. From the repository root:

```sh
pnpm build
pnpm run link:local
export PATH="$PWD/bin:$PATH"
```

## Verify the host sees the server and its tools

```sh
cd examples/opencode-demo
opencode mcp list
```

Expected: `code-audit` is listed as connected. In an interactive session the
eight `audit_*` tools are then available to the agent.

## Run a review

In an OpenCode session rooted at this directory, ask for a security audit or run
the bundled command:

```text
/audit
```

The agent uses the `code-audit` skill: `audit_start`, poll `audit_status`,
triage `audit_findings`, verify with `audit_read`/`audit_search`, record
`audit_verdict`, then render `audit_report`.
