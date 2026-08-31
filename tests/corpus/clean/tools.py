"""Infrastructure tools OpsBot can call (safe)."""

from functools import wraps

from langchain.tools import tool

from infra_client import infra_client


def require_confirmation(fn):
    """Decorator-based guard: confirmation is enforced by a wrapper, not by
    an `if not X: raise/return` statement at the top of the function body.
    BAS-LLM03-001's `none:` exclusion only recognises the inline guard
    shape, so a destructive tool guarded this way is a precision risk: it
    is genuinely safe, but the rule cannot see the wrapper's check."""

    @wraps(fn)
    def wrapper(*args, confirmed: bool = False, **kwargs):
        if not confirmed:
            raise PermissionError(f"{fn.__name__} requires confirmed=True.")
        return fn(*args, **kwargs)

    return wrapper


@tool
@require_confirmation
def shutdown_server(hostname: str) -> str:
    """Shut down a production server. Guarded by @require_confirmation."""
    infra_client.shutdown(hostname)
    return f"Server {hostname} is shutting down."


@tool
def delete_stale_snapshot(snapshot_id: str, confirmed: bool = False) -> str:
    """Delete a stale infrastructure snapshot.

    Guarded with `assert`, not `if not X: raise`. BAS-LLM03-001's `none:`
    exclusion only recognises the raise/return guard shape, so this is a
    precision risk in the other direction: it is genuinely safe, but does
    not match the pattern that would suppress the rule.
    """
    assert confirmed, "delete_stale_snapshot requires confirmed=True"
    infra_client.delete_snapshot(snapshot_id)
    return f"Snapshot {snapshot_id} deleted."


@tool
def get_server_status(hostname: str) -> str:
    """Return the current status of a server. Read-only."""
    return infra_client.status(hostname)


@tool
def update_server_config(hostname: str, config: dict, confirmed: bool = False) -> str:
    """Change a production server's configuration. Guarded by an inline
    check -- proves the widened state-changing verb list still respects the
    same guard shapes as the destructive-verb case."""
    if not confirmed:
        raise PermissionError("update_server_config requires confirmed=True.")
    infra_client.update_config(hostname, config)
    return f"Server {hostname} reconfigured."
