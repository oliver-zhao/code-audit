#!/usr/bin/env node
import { runMcpServer } from "./index.js";

runMcpServer(process.argv.slice(2)).catch((error: unknown) => {
  process.stderr.write(
    `code-audit-mcp: ${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exit(1);
});