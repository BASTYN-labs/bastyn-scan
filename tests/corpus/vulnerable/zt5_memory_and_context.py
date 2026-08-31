"""OpsBot's short-term conversation memory.

known_gap (ZT5, observation): no rule inspects how a memory or session
store is keyed. This category is inherently context-dependent -- a global
dict might be fine in a single-tenant deployment -- so even if a rule
existed it could only ever be an observation, never a defect. None exists
today.
"""

# Keyed by ticket ID only. OpsBot is deployed multi-tenant (one instance
# serves several customer orgs), so nothing here stops a follow-up question
# on a ticket from one org from pulling conversation context that was
# populated while triaging a *different* org's ticket, if ticket IDs ever
# collide or are guessed.
CONVERSATION_MEMORY: dict[str, list[dict]] = {}


def remember_turn(ticket_id: str, role: str, content: str) -> None:
    """Append one turn of conversation to global, ticket-keyed memory."""
    CONVERSATION_MEMORY.setdefault(ticket_id, []).append({"role": role, "content": content})


def recall_context(ticket_id: str) -> list[dict]:
    """Return everything remembered for a ticket, with no per-org scoping."""
    return CONVERSATION_MEMORY.get(ticket_id, [])
