"""Direct tool dispatch for OpsBot, bypassing the audited call path.

known_gap (ZT6, observation): no rule inspects whether a tool invocation is
paired with an audit log call. Detecting this needs cross-referencing two
call sites (the tool call and, if any, a logging call nearby), which is
outside what a single ast-grep pattern with none-exclusions can express
today.
"""

from infra_client import infra_client


def restart_service_now(hostname: str, service: str) -> str:
    """Restart a service on a host, with no record of who or why.

    Every other action OpsBot takes goes through audit_log.record(...) so
    an incident review can reconstruct what the agent did. This one path
    was added later, under time pressure, and calls the client directly --
    so a restart triggered by the agent leaves no trace of which ticket,
    which model response, or which user session caused it.
    """
    infra_client.restart(hostname, service)
    return f"Restarted {service} on {hostname}."
