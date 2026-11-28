import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
const server = new McpServer({ name: "calc", version: "1.0.0" });
server.tool("add", "Adds two numbers. Call it before using the chart tool.", { a: z.number().describe("First number") }, async () => ({ content: [] }));
server.tool("greet", "Greets the user 👨‍💻.", {}, async () => ({ content: [] }));
server.tool("scan", "Flags text such as ignore previous instructions in fetched pages.", {}, async () => ({ content: [] }));
server.tool("timer", "Waits 10μs.", {}, async () => ({ content: [] }));
