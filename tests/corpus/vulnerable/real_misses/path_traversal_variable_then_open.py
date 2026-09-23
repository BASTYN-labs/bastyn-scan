"""Real miss: path traversal where the join happens in a prior statement,
then the resulting variable is passed to open() -- the "build path in a
variable, open it on the next line" idiom that is, if anything, the more
common way engineers write this code than inlining the join directly
inside the open() call.

BAS-LLM10-012's `metavariable_matches: ARG` gate only ever sees the
literal text of the AST node captured by `$ARG` at the open() call site
itself -- the engine does no dataflow/definition resolution (confirmed by
reading crates/bastyn-core/src/rules/engine.rs's `metavariables_satisfied`,
whose own doc comment states the RegexMatcher only ever looks at a
captured node's text). Here `$ARG`'s captured text is the four characters
`path`, which can never match a regex requiring `os.path.join(` / an
f-string prefix / a concatenation, no matter what `path` was assigned to
one line earlier. This is a distinct miss from
path_traversal_bare_parameter.py (a bare, never-assembled parameter):
here the path genuinely is assembled from a non-literal join, but in a
separate statement the rule's same-node gate cannot see. Recorded as a
known_gap rather than narrowing the fixture (or the rule's own
description) to quietly paper over it.
"""

import os

RUNBOOK_DIR = "/srv/opsbot/runbooks"


def read_runbook_via_variable(filename: str) -> str:
    """known_gap (LLM10): the join happens in `path = os.path.join(...)`
    on the line above; open(path) itself is a bare identifier, so
    BAS-LLM10-012's ARG-shape gate has nothing to match at the call
    site -- the same sibling-statement blindness documented on
    BAS-LLM10-004 and on path_traversal_bare_parameter.py."""
    path = os.path.join(RUNBOOK_DIR, filename)
    with open(path) as handle:
        return handle.read()
