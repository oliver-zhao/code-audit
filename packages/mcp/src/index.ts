import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  createAuditServer,
  MCP_BASE_ENV,
  MCP_SERVER_NAME,
  MCP_SERVER_VERSION,
  resolveServerBase,
} from "./server.js";

export {
  createAuditServer,
  MCP_BASE_ENV,
  MCP_SERVER_NAME,
  MCP_SERVER_VERSION,
  resolveServerBase,
  type AuditServerOptions,
  type ServerBase,
} from "./server.js";

export const MCP_USAGE = `Usage: code-audit-mcp [--base <dir>]

  --base <dir>   the only directory the tools may audit, read or write in
                 (default: ${MCP_BASE_ENV}, else the working directory).
                 Fixed for the life of the server; no tool call can change it.
`;

/** Parse the command line of the server: only `--base <dir>` / `--base=<dir>`. */
export function parseServerArgs(argv: readonly string[]): { base?: string } {
  let base: string | undefined;
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index] as string;
    if (arg === "--base") {
      const value = argv[index + 1];
      if (value === undefined || value === "") throw new Error("--base requires a directory");
      base = value;
      index += 1;
    } else if (arg.startsWith("--base=")) {
      base = arg.slice("--base=".length);
      if (base === "") throw new Error("--base requires a directory");
    } else {
      throw new Error(`unknown argument: ${arg}\n${MCP_USAGE}`);
    }
  }
  return base !== undefined ? { base } : {};
}

/** Start the stdio MCP server. stdout is reserved for protocol messages. */
export async function runMcpServer(argv: readonly string[] = []): Promise<void> {
  const options = parseServerArgs(argv);
  const base = resolveServerBase(options);
  const server = createAuditServer({ base: base.dir });
  const transport = new StdioServerTransport();
  await server.connect(transport);
  const origin =
    base.source === "option"
      ? "--base"
      : base.source === "environment"
        ? MCP_BASE_ENV
        : "working directory";
  process.stderr.write(
    `[${MCP_SERVER_NAME}] v${MCP_SERVER_VERSION} ready on stdio; base directory: ${base.dir} (${origin}). ` +
      "Only directories inside it can be audited.\n",
  );
  if (base.problem) {
    process.stderr.write(`[${MCP_SERVER_NAME}] WARNING: ${base.problem}\n`);
  }
}
