"""A well-behaved MCP server used as a false-positive check."""
import os
import subprocess
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("safe-demo")
NOTES_ROOT = Path(os.environ.get("NOTES_ROOT", "./notes")).resolve()
ALLOWED_REPORTS = {"daily", "weekly"}


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b


@mcp.tool()
def run_report(name: str) -> str:
    """Run one of the approved reports."""
    if name not in ALLOWED_REPORTS:
        raise ValueError("unknown report")
    return subprocess.run(["generate-report", name], capture_output=True, text=True).stdout


@mcp.tool()
def read_note(name: str) -> str:
    """Read a note from the notes directory."""
    target = (NOTES_ROOT / name).resolve()
    if not target.is_relative_to(NOTES_ROOT):
        raise ValueError("path outside notes root")
    return target.read_text()


if __name__ == "__main__":
    mcp.run(transport="stdio")
