#!/usr/bin/env node
// `code-audit-mcp` as installed with the CLI package: the stdio MCP server.
import { runMcpServer } from "@code-audit/mcp";

runMcpServer(process.argv.slice(2)).catch((error: unknown) => {
  process.stderr.write(
    `code-audit-mcp: ${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exit(1);
});
