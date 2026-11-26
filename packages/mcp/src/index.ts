import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createAuditServer, MCP_SERVER_NAME, MCP_SERVER_VERSION } from "./server.js";

export { createAuditServer, MCP_SERVER_NAME, MCP_SERVER_VERSION } from "./server.js";

/** Start the stdio MCP server. stdout is reserved for protocol messages. */
export async function runMcpServer(): Promise<void> {
  const server = createAuditServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write(
    `[${MCP_SERVER_NAME}] v${MCP_SERVER_VERSION} ready on stdio\n`,
  );
}
