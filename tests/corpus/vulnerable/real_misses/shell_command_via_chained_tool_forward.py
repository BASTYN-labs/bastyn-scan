"""Known gap: flow.passthrough_downgrade's entry-point-forwarding check
(`collect_entry_point_forwards`) is bounded to exactly one hop of a *bare*
local-function call, the same documented precedent
`FlowGraph::wrapper_sink_parameters` already accepts for its own one-hop
sink relation ("a wrapper around a wrapper is out of reach by construction,
not merely untested"). A tool's own parameter forwarded through a second
local function before reaching the shell-command helper is invisible to it,
so BAS-LLM10-009 wrongly reports this as an observation rather than a
defect. See bastyn.yml's comment on BAS-LLM10-009.
"""

import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("x")


def _inner(cmd: str) -> str:
    """known_gap (LLM10): cmd is a bare pass-through, _inner is not itself
    an entry point, and _outer (the only in-file caller) is also not an
    entry point -- so nothing here looks like an entry point forwarded a
    parameter into _inner directly. The forwarding chain is real, it is
    just two hops (run -> _outer -> _inner) instead of the one hop
    collect_entry_point_forwards checks for."""
    return subprocess.check_output(cmd, shell=True, text=True)


def _outer(cmd: str) -> str:
    return _inner(cmd)


@mcp.tool()
def run(cmd: str) -> str:
    return _outer(cmd)
