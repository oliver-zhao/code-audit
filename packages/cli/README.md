# @code-audit/cli

The command line of [code-audit](https://github.com/oliver-zhao/code-audit), a
deterministic source-code security scanner: built-in rules, secret detection
and dependency advisories, with optional Opengrep, OSV-Scanner and Gitleaks.
Findings are candidates for review; the tool does not prove that code is free
of vulnerabilities.

Installs two commands: `code-audit` and `code-audit-mcp` (the stdio MCP server
for agent hosts). Requires Node.js 22 or later.

```sh
code-audit scan .                 # writes .audit/<run-id>/report.md, findings.json, results.sarif
code-audit doctor                 # Node, rule counts, optional scanners, MCP command
code-audit install --host opencode|dsh|claude-code|codex
code-audit --help
```

Documentation: <https://github.com/oliver-zhao/code-audit#readme>.
License: Apache-2.0.
