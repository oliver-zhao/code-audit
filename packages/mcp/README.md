# @code-audit/mcp

The stdio [Model Context Protocol](https://modelcontextprotocol.io) server of
[code-audit](https://github.com/oliver-zhao/code-audit). It exposes the audit
workflow as eight `audit_*` tools (start a scan, poll status, list findings,
read and search code with secrets redacted, record verdicts, add findings,
render the report). The server never calls an LLM; the host's model does the
review.

```sh
code-audit-mcp        # speaks MCP on stdin/stdout, diagnostics on stderr
```

`@code-audit/cli` installs the same `code-audit-mcp` command together with the
`code-audit` CLI; install this package on its own only when you need the
server without the CLI.

Tools, arguments and results: <https://github.com/oliver-zhao/code-audit/blob/master/docs/mcp.md>.
License: Apache-2.0.
