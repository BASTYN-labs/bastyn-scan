"""Real miss: path traversal via a bare parameter, no join/f-string/concat
shape for BAS-LLM10-012's ARG gate to match.

BAS-LLM10-012 requires the open() argument's own text to look like
os.path.join(...), an f-string, or a concatenation -- the signal that
tells the rule "this path was assembled from more than one piece." Here
the caller-supplied path is passed straight through with no assembly at
all: filename is opened directly, having been checked only against a
string prefix in a separate statement this same-node rule cannot see
(the same sibling-statement blindness documented on BAS-LLM10-004 in
bastyn.yml). Catching this would need either a bare-identifier-is-this-
function's-own-parameter check (an `inside:` pattern cross-referencing
the same captured name against the enclosing def's parameter list, not
attempted here) or real dataflow tracing. Recorded as a known_gap rather
than papered over with an imprecise guard.
"""


def read_document(filename: str) -> str:
    """known_gap (LLM10): filename reaches open() completely unassembled
    -- BAS-LLM10-012's ARG-shape gate (os.path.join/f-string/concat) has
    nothing to match against a bare identifier."""
    if not filename.startswith("/app/documents"):
        raise PermissionError("access denied")
    with open(filename) as handle:
        return handle.read()
