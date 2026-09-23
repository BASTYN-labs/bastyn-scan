"""Known false positive: a fixed literal command held in a local variable
one line above the sink.

BAS-LLM10-009 excludes a bare string-literal argument
(subprocess.run("$LIT", shell=True)) via `none:`, but `none:` only ever
matches alternate shapes of the *same* matched node -- it cannot see a
prior sibling statement. Here the command string is still a fixed
literal, just assigned to a local variable one line before the
subprocess.run() call that consumes it; $ARG's captured text at the call
site is just the variable name `cmd`, which is not itself a string
literal, so the exclusion cannot fire and the rule reports a false
critical finding.

This is the identical, already-accepted engine limitation documented for
BAS-LLM10-004 (see eval_guarded_by_local_check.py in this same directory,
and bastyn.yml's comment on BAS-LLM10-004): `none:` (same-node exclusion)
and `inside:` (ancestor constraint) both structurally cannot reach a
sibling assignment. Recorded as a known_false_positive rather than a
narrower guard pattern that would risk silently swallowing a real
non-literal command reaching a shell.
"""

import subprocess


def restart_worker_via_variable() -> None:
    """known_false_positive (LLM10): cmd is a fixed literal, but it is
    assigned one line above the subprocess.run() call, not passed
    inline -- BAS-LLM10-009's same-node `none:` exclusion cannot see the
    prior assignment."""
    cmd = "systemctl restart opsbot-worker"
    subprocess.run(cmd, shell=True)
