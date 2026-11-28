from mcp.server.fastmcp import FastMCP
import re
ZW = re.compile("[\u200b-\u200f\u202a-\u202e]")
clean = re.sub("\u2066", "", text)
