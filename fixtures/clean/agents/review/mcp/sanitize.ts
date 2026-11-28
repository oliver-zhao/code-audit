import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const ZW = new RegExp("[\u200B-\u200F\u202A-\u202E\u2066-\u2069]", "g");
const BIDI_RE = "[\u202A-\u202E]+";
export const clean = (text: string): string => text.replace("\u200B", "").replace(/[\u2066-\u2069]/g, "");
