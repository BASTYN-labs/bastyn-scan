"""eval() on a bare function parameter -- no catalogued source at all.

Before 2026-09-25, BAS-LLM10-004 gated on where the argument's value came
from: traced to one of its listed sources (model_output, http_request,
retrieved_context, tool_output, file_read, network_read -- every
`SourceKind` variant that exists) it was a defect, traced to nowhere it was
a hidden observation (behind `--show-observations`). That list already
covered every `SourceKind` this engine knows, so "traced to some other real
source" was never actually reachable for this specific rule -- only the
"traced to a listed source" and "traced to nowhere" cases could ever fire.
A plain function parameter handed straight to eval() -- no assignment, no
call, nothing for the flow graph to classify -- is the second case: the
value's origin cannot be traced at all, which used to mean this appeared
only as a hidden, low-confidence observation, never in the default report.

That is exactly backwards for the shape this rule exists to catch: passing
caller-controlled input straight into eval()/exec() is rare enough, and bad
enough, that requiring the engine to first prove which catalogued source
produced it was buying little precision while hiding real findings. Since
2026-09-25 BAS-LLM10-004 drops the source gate entirely (the same
unconditional-composition philosophy BAS-LLM10-009/-017/-018 already use)
and reports unconditionally: a value closed over literals this file fixes,
or one a guard already dominates, is still dropped, but an untraceable
origin like the one below is now a full defect rather than a hidden
observation.
"""


def run_expression_tool(expression: str) -> object:
    """`expression` is a bare parameter with an unclassifiable origin --
    the flow graph cannot trace it to any catalogued source, and it is not
    closed over a fixed literal or dominated by a guard. Used to be
    reported only as an observation behind --show-observations; now a
    defect."""
    return eval(expression)
