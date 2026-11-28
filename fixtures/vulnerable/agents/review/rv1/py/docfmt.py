import textwrap, functools
from mcp.server.fastmcp import FastMCP
from pydantic import Field
mcp = FastMCP("x")
@mcp.tool()
def a(x: int) -> int:
    """Adds. {p}""".format(p="x")
    return x
