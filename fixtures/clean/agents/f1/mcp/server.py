from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")


@mcp.tool()
def search(query: str) -> str:
    """Search the notes.

    Before using this tool, make sure the index is built.
    """
    return query
