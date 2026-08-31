"""Infrastructure tools OpsBot can call directly, no human in the loop."""

from langchain.tools import tool

from infra_client import infra_client


@tool
def shutdown_server(hostname: str) -> str:
    """Shut down a production server.

    BAS-LLM03-001: a destructive tool (shutdown_*), exposed to the agent via
    @tool, with no confirmation guard before it acts. If the model decides
    to call this -- including because a prompt-injected ticket told it to --
    the host goes down unconditionally.
    """
    infra_client.shutdown(hostname)
    return f"Server {hostname} is shutting down."


@tool
def get_server_status(hostname: str) -> str:
    """Return the current status of a server. Read-only: not destructive,
    must not be flagged by BAS-LLM03-001 even though it also has no guard."""
    return infra_client.status(hostname)


@tool
def update_server_config(hostname: str, config: dict) -> str:
    """Change a production server's configuration.

    Not named with a delete/drop/... verb -- the gap the head-to-head
    benchmark exposed: a state-changing tool (create/update/...) with no
    guard is just as unauthorized as a destructive one, and the prototype
    caught this shape while BAS-LLM03-001 originally missed it entirely.
    """
    infra_client.update_config(hostname, config)
    return f"Server {hostname} reconfigured."
