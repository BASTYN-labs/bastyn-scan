"""OpsBot's network-diagnostics MCP tool.

A small set of "run this OS command for me" tools exposed to the agent.
Each one tries to defend itself with a check on the command string, but a
shell interprets the whole string -- checking only a prefix or a
substring blocklist leaves the rest of the command open to injection.
"""

import subprocess


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
