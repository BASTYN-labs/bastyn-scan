"""Fix D's must-still-fire siblings: each function here looks like a bare
pass-through helper, the shape tests/corpus/observations/
shell_passthrough_helpers.py proves is downgraded to an observation, but
each one fails a different one of flow.passthrough_downgrade's four
conditions, so BAS-LLM10-009 must keep reporting it as a defect.
"""

import json
import subprocess
from http.server import BaseHTTPRequestHandler
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


def ping_reassigned(host: str) -> str:
    """Defect (fix round 1 regression): host is REASSIGNED to a composed
    f-string using its own name before reaching the sink -- the reassignment
    is itself a binding of `host`, so is_provably_bare_passthrough's
    zero-bindings rule for a parameter root correctly disqualifies it, the
    same as any other name. A check that only looked at whether the
    identifier's *text* matched a parameter name, with no reassignment
    check, would have wrongly downgraded this."""
    host = f"ping -c 1 {host}"
    return subprocess.check_output(host, shell=True, text=True)


def run_branch_alias(p: str, condition: bool) -> None:
    """Defect (fix round 1 regression): cmd is bound twice, once in each arm
    of an if/else -- one arm composes a command, the other passes `p`
    through bare. Since there is no way to prove, from this file-local
    syntactic check alone, which arm's binding actually reaches the sink,
    a second binding anywhere disqualifies the name outright, regardless of
    branch."""
    if condition:
        cmd = f"ping -v {p}"
    else:
        cmd = p
    subprocess.run(cmd, shell=True)


def run_for_loop_alias(p: str) -> None:
    """Defect (fix round 1 regression): cmd is bound by a `for` loop target,
    not a plain assignment -- is_provably_bare_passthrough only ever follows
    a plain `assignment` as its one permitted local-alias hop, so a `for`
    target (which this analysis has no way to reason about the iterable of)
    disqualifies the name, the same as a second assignment would."""
    for cmd in [f"ping {p}"]:
        subprocess.run(cmd, shell=True)


class HandlerA(BaseHTTPRequestHandler):
    """Defect (fix round 1 regression, C3): two unrelated
    BaseHTTPRequestHandler subclasses each define their own do_GET. Deciding
    "is the enclosing function an entry point" from a name-keyed map that
    drops an ambiguous (multiply-defined) name would have dropped BOTH
    classes' do_GET from the entry-point set, wrongly downgrading both.
    Deciding it directly from each function's own node has no such
    ambiguity: each do_GET is independently, correctly recognized as an
    entry point."""

    def do_GET(self) -> None:
        cmd = self.path
        subprocess.run(cmd, shell=True)


class HandlerB(BaseHTTPRequestHandler):
    """The second do_GET sharing HandlerA's method name -- see HandlerA's
    own docstring above."""

    def do_GET(self) -> None:
        cmd = self.headers.get("X-Cmd")
        subprocess.run(cmd, shell=True)


class Runner:
    """Defect (fix round 1 regression, I1b): self.cmd was set in __init__
    from run_tool()'s own @mcp.tool()-decorated parameter, but this
    file-local analysis has no way to trace an attribute write in one method
    to an attribute read in another -- self/cls must never qualify as a
    bare-parameter root, so self.cmd stays a defect rather than being
    wrongly treated as "just another parameter"."""

    def __init__(self, cmd: str) -> None:
        self.cmd = cmd

    def go(self) -> None:
        subprocess.run(self.cmd, shell=True)


@mcp.tool()
def run_tool(cmd: str) -> None:
    Runner(cmd).go()
