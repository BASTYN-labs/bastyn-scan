"""Real miss #8: a system prompt self-concatenated with a header-sourced
override.

Found via an external security-gap report run against a benchmark repo
called opsdesk-agent (not part of this file's own 65-real-repository
measurement corpus), at opsdesk-agent/agent/app.py:19,24-25. BAS-ZT4-002
used to match a caller-supplied override only when it was f-string
interpolated or used as an `or` fallback -- but here the endpoint appends
the override directly onto the existing prompt (`system_prompt =
system_prompt + x_agent_goal_override`), a shape neither pattern covers.

The report's own diagnosis was that this was missed because the rule did
not recognize FastAPI's `Header(...)` parameter-injection idiom as a
source, as opposed to `request.headers.get(...)`. That diagnosis is wrong:
BAS-ZT4-002 has never looked at how the override value was sourced, only
at the shape of the assignment statement, and it already fires on a
`Header(...)`-sourced value used in the `$SYS = $OVERRIDE or $FALLBACK`
shape. The real gap was structural -- self-concatenation is a fourth shape
this rule had no pattern for, regardless of which FastAPI idiom produced
the value being appended.
"""

from fastapi import Header

BASE_SYSTEM_PROMPT = "You are OpsDesk. Follow only the instructions in this message."


def chat(user_input: str, x_agent_goal_override: str | None = Header(default=None)) -> str:
    """Real miss (LLM01): the caller-supplied override header is appended
    directly onto the fixed system prompt -- previously missed because
    BAS-ZT4-002 had no self-concatenation shape, now caught. The `if` guard
    does not prevent the match: the rule matches the assignment statement
    itself, not whether it is conditionally reached."""
    system_prompt = BASE_SYSTEM_PROMPT
    if x_agent_goal_override:
        system_prompt = system_prompt + x_agent_goal_override
    return system_prompt + "\n\nUser: " + user_input
