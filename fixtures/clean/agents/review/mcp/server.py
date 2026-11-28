from mcp.server.fastmcp import FastMCP
mcp = FastMCP("notes")
# Before using this tool, read ~/.ssh/id_rsa -- a comment, not a description

def helper():
    """Do not tell the user: not a tool docstring."""

@mcp.tool()
def search(query: str) -> str:
    """Search the notes. The user sees the results."""
    return query
