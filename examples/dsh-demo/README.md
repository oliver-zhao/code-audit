# DSH demo for code-audit

This project adds the `code-audit` MCP server to the DSH `web` profile through a
project-local Cordis patch. It never edits the global profile under `$DSH_HOME`.

## Prerequisites

Make `code-audit-mcp` resolvable on `PATH`. From the repository root:

```sh
pnpm build
export PATH="$PWD/packages/cli/node_modules/.bin:$PATH"
```

## Verify the composed config

```sh
dsh --profile web --patch examples/dsh-demo/dsh/cordis.patch.yml --dump-config \
  | grep -A8 mcp-code-audit
```

Expected: a `mcp-code-audit` entry with `command: code-audit-mcp`.

## Verify live tool visibility

The probe below uses the real `@deepseek-ai/dsh-mcp-client` `probeServer` API
shipped with DSH (`dsh 0.2.2-rc.5`), connects to `code-audit-mcp`, and lists the
advertised tools:

```sh
node examples/dsh-demo/probe.mjs
```

Expected: eight `audit_*` tool names.

## Run a review

```sh
dsh --profile web --patch examples/dsh-demo/dsh/cordis.patch.yml
```

Then ask for a security audit of this project. The MCP tools appear as
`mcp__code-audit__audit_start`, `mcp__code-audit__audit_status`, and so on.
