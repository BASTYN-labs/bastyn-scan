"""A shell-injection sink inside a function nothing in this file calls,
reached through a bare pass-through of its own parameter.

BAS-LLM10-009 fires on the function's own body -- a non-literal command
reaching a shell -- with no reachability analysis: "does anything call
this" is a whole-program question this file-local engine cannot answer
(a caller could live in another file, another package, or nowhere at
all). flow.passthrough_downgrade turns this
specific shape -- a bare pass-through of a non-entry-point function's own
parameter -- into a correctly-handled observation rather than a false
positive: see bastyn.yml's comment on BAS-LLM10-009.
"""

import subprocess


def run_raw_command(command: str) -> str:
    """Observation (LLM10): nothing in this corpus imports or calls
    run_raw_command, and command is a bare pass-through of its own
    parameter with no recognized entry point in this file reaching it --
    flow.passthrough_downgrade reports this as an observation rather than
    a defect."""
    return subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode()
