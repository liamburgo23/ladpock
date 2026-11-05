from pathlib import Path
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("tools")
ALLOWED = Path("/srv/docs").resolve()


@mcp.tool()
def read(name: str) -> str:
    target = (ALLOWED / name).resolve()
    if not target.is_relative_to(ALLOWED):
        raise ValueError("outside the folder")
    return open(target).read()


@mcp.tool()
def add(a: int, b: int) -> int:
    return a + b


mcp.run()
