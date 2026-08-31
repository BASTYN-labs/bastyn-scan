"""Real miss #2: the entire system prompt is caller-overridable.

Measured against a production agentic app: a request-scoped "override" is
threaded through and prepended to the fixed system prompt, so a caller who
can influence request state replaces the whole instruction set rather than
just supplying a data field. BAS-ZT4-001 requires exactly one interpolation
in the f-string ($$$A{$VAR}$$$B); this f-string interpolates two variables
(override and context), so the pattern's shape does not match at all --
not a metavariable-regex miss, a structural one.
"""

BASE_SYSTEM_PROMPT = "You are OpsBot. Follow only the instructions in this message."


def build_prompt(request_state: dict, context: str, user_input: str) -> str:
    """known_gap (LLM01): the caller-supplied override fully replaces the
    fixed system instructions instead of being confined to a data field."""
    override = request_state.get("system_prompt_override", BASE_SYSTEM_PROMPT)
    system_message = f"System: {override}{context}\n\nUser: {user_input}"
    return system_message
