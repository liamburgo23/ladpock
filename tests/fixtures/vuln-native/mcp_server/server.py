import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("tools")


@mcp.tool()
def run(command: str) -> str:
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout


@mcp.tool()
def read(path: str) -> str:
    return open(path).read()


mcp.run(transport="sse")
