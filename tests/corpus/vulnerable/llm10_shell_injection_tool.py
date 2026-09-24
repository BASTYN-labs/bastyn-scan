"""OpsBot's network-diagnostics MCP tool.

A small set of "run this OS command for me" tools exposed to the agent.
Each one tries to defend itself with a check on the command string, but a
shell interprets the whole string -- checking only a prefix or a
substring blocklist leaves the rest of the command open to injection.
"""

import shlex
import subprocess
import sys

# Scaffolding for run_playbook_partially_quoted() below -- mirrored in
# tests/corpus/clean/near_misses.py's run_playbook_fully_quoted() near-miss
# counterpart.
SAFE_PLAYBOOKS = ("deploy", "rollback")
SAFE_HOSTS = ("prod-1", "prod-2")
RUNNER_PATH = "/opt/opsbot/run_playbook.py"


def ping_host(host: str) -> str:
    """BAS-LLM10-009: host is interpolated straight into a shell command
    with no validation at all -- '8.8.8.8; cat /etc/passwd' runs both."""
    command = f"ping -c 1 {host}"
    return subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode()


def run_allowlisted_command(command: str) -> str:
    """BAS-LLM10-009: the allowlist only inspects the first whitespace-
    split token, then runs the entire string through a shell -- 'ls;
    cat /etc/passwd' passes the check (its first token is 'ls')."""
    safe_commands = ["ls", "pwd", "whoami", "date"]
    if command.split()[0] in safe_commands:
        return subprocess.check_output(command, shell=True).decode()
    return "command not allowed"


def run_denylisted_command(command: str) -> str:
    """BAS-LLM10-009: the denylist blocks a few dangerous substrings, but
    anything that doesn't contain one of them -- pipes, backticks, cat,
    curl -- still runs unrestricted."""
    dangerous = ["rm", "mkfs", "dd", "format", ">", ">>"]
    if any(token in command for token in dangerous):
        return "blocked"
    return subprocess.check_output(command, shell=True).decode()


def run_playbook_partially_quoted(playbook: str, target_host: str, extra_args: str) -> dict:
    """LLM10 (BAS-LLM10-009): every interpolated value except extra_args is
    quoted -- one unquoted segment is enough to break out of the shell
    argument shlex.quote would otherwise have produced, so this must still
    fire."""
    if playbook not in SAFE_PLAYBOOKS or target_host not in SAFE_HOSTS:
        return {"ok": False, "error": "not allowed"}
    command = (
        f"{shlex.quote(sys.executable)} {shlex.quote(RUNNER_PATH)} "
        f"{shlex.quote(playbook)} --target {shlex.quote(target_host)} {extra_args}"
    )
    completed = subprocess.run(command, shell=True, capture_output=True)
    return {"ok": completed.returncode == 0}
