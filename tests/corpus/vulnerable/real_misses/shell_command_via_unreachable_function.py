"""Known false positive: a shell-injection sink inside a function nothing
in this file calls.

BAS-LLM10-009 fires on the function's own body -- a non-literal command
reaching a shell -- with no reachability analysis: "does anything call
this" is a whole-program question this file-local engine cannot answer
(a caller could live in another file, another package, or nowhere at
all). Recorded as a known_false_positive rather than attempting dead-code
elimination, which is out of scope for a structural/flow rule -- see
bastyn.yml's comment on BAS-LLM10-009.
"""

import subprocess


def run_raw_command(command: str) -> str:
    """known_false_positive (LLM10): nothing in this corpus imports or
    calls run_raw_command -- BAS-LLM10-009 has no reachability analysis,
    so it reports the shape regardless of whether the function is ever
    invoked."""
    return subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode()
