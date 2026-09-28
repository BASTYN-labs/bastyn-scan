"""Fix D's must-still-fire siblings: each function here looks like a bare
pass-through helper, the shape tests/corpus/observations/
shell_passthrough_helpers.py proves is downgraded to an observation, but
each one fails a different one of flow.passthrough_downgrade's four
conditions, so BAS-LLM10-009 must keep reporting it as a defect.
"""

import json
import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("x")


@mcp.tool()
def execute_command(command: str) -> str:
    """Defect: command is a bare pass-through, but execute_command is itself
    a recognized entry point (@mcp.tool()) -- condition 2 fails."""
    return subprocess.check_output(command, shell=True, text=True)


def _exec(cmd: str) -> str:
    """Defect: cmd is a bare pass-through and _exec is not itself an entry
    point, but the entry point run() below forwards its own parameter into
    this call -- condition 3 fails."""
    return subprocess.check_output(cmd, shell=True, text=True)


@mcp.tool()
def run(cmd: str) -> str:
    """The entry point whose own parameter reaches _exec() above."""
    return _exec(cmd)


def apply_manifest(path: str) -> None:
    """Defect: manifest traces to json.load(open(path)) -- a file_read
    source, not a bare parameter -- so condition 1 fails outright."""
    manifest = json.load(open(path))
    subprocess.run(manifest["extension"], shell=True)


def ping(host: str) -> str:
    """Defect: the command is an f-string composed around host, not host
    itself -- not a syntactically bare pass-through, so condition 1 fails."""
    return subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
