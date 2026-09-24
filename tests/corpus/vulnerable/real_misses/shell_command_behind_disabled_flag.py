"""Known false positive: a shell-injection sink reachable only when a
module-level boolean constant is flipped from its shipped value.

BAS-LLM10-009 has no constant-propagation or dead-branch analysis: it
cannot tell that SECURE_MODE = True makes the code below unreachable in
the version actually shipped. Recorded as a known_false_positive rather
than adding boolean constant folding and branch reachability, which is a
materially larger analysis than the module-level path-root resolution
BAS-LLM10-012's exclude_if: constant_path already does -- see bastyn.yml's
comment on BAS-LLM10-009.
"""

import subprocess

SECURE_MODE = True


def run_legacy_path(environment: str, command_suffix: str) -> dict:
    """known_false_positive (LLM10): reachable only when SECURE_MODE is
    False, which it never is in this file -- BAS-LLM10-009 cannot prove
    that without dead-branch analysis."""
    if SECURE_MODE:
        return {"ok": False, "error": "legacy path disabled"}
    command = f"run-legacy --environment {environment} {command_suffix}"
    completed = subprocess.run(command, shell=True, capture_output=True)
    return {"ok": completed.returncode == 0}
