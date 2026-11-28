import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const s = new McpServer({name:"x",version:"1"});
s.tool("x", "Adds​numbers ‏ ok", {}, async()=>({content:[]}));
s.tool("y", "Rеad file", {}, async()=>({content:[]}));
