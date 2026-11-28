import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import dedent from "dedent";
import { IMPORTED } from "./descs.js";
const s = new McpServer({name:"x",version:"1"});
s.tool("c7", IMPORTED, {}, async()=>({content:[]}));
