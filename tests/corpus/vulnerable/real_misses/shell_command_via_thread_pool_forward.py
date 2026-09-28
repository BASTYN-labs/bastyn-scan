"""Known gap: flow.passthrough_downgrade's entry-point-forwarding check
(`collect_entry_point_forwards`) only recognizes a callee shape of a direct
bare-name call (`_exec(cmd)`) or a self/cls-qualified method call
(`self._exec(cmd)`). A tool's own parameter handed to `_exec` through
`asyncio.to_thread` -- or any of the equally common `pool.submit(_exec,
cmd)`, `Class._exec(self, cmd)`, `super()._exec(cmd)` shapes -- is invisible
to it, so BAS-LLM10-009 wrongly reports this as an observation rather than
a defect. See bastyn.yml's comment on BAS-LLM10-009.
"""

import asyncio
import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("x")


def _exec(cmd: str) -> str:
    """known_gap (LLM10): cmd is a bare pass-through, _exec is not itself
    an entry point, and run() -- the only in-file caller -- forwards its
    own cmd parameter to _exec through asyncio.to_thread(_exec, cmd) rather
    than a direct or self/cls-qualified call.
    collect_entry_point_forwards's callee-shape check does not recognize
    this as a forward at all, so nothing here connects run()'s own
    parameter to _exec()."""
    return subprocess.check_output(cmd, shell=True, text=True)


@mcp.tool()
async def run(cmd: str) -> str:
    return await asyncio.to_thread(_exec, cmd)
