"""A system prompt built in a bare `return` with three interpolations.

Taken from an application met in the wild, not invented. It is the same defect
as `overridable_system_prompt.py` — a caller-supplied override fully replaces
the system instructions — but written in a shape our pattern cannot express:
the interpolation count is three, and `BAS-ZT4-002` hard-codes two.

Counting interpolations does not generalise, and the count-independent
alternative (`f"$$$PARTS"` constrained by a regex on `PARTS`) does not work
because `metavariable_matches` has no effect on a `$$$` multi-node capture.
Recorded as a known gap.
"""

BASE_PROMPT = "You are a careful assistant. Refuse unsafe requests."


def build_system_prompt(state: dict) -> str:
    """Assemble the prompt sent to the model."""
    override = state.get("system_prompt_override", "")
    context_block = state.get("context", "")
    user_input = state.get("user_input", "")

    if override:
        return f"System: {override}{context_block}\n\nUser: {user_input}"
    return f"System: {BASE_PROMPT}{context_block}\n\nUser: {user_input}"
