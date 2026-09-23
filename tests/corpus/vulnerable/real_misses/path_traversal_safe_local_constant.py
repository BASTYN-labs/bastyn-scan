"""Known false positive: os.path.join(...) with one safe local constant
argument, not an attacker-controlled one.

BAS-LLM10-012's metavariable_not_matches exclusion (added 2026-09-23)
closes the all-literal-arguments case for os.path.join(...) -- an
exclusion anchored end-to-end on "os.path.join( then only quoted string
literals, comma-separated, then )". HERE below is not a quoted literal: it
is a bare identifier, so the exclusion regex correctly does not match, and
the rule fires exactly as its own contract says it should ("...built by
joining or interpolating a non-literal value" -- HERE genuinely is
non-literal).

In practice, though, this is a false positive: HERE is derived once, at
module import time, from os.path.dirname(__file__) -- a fixed, local,
never-attacker-influenceable constant, not a caller-supplied value. Bastyn
has no way to tell this apart from a real attacker-controlled variable
without dataflow analysis: metavariable_matches/metavariable_not_matches
only ever inspect the literal text of the captured $ARG node at the
open() call site (see bastyn.yml's comment on BAS-LLM10-012 and
crates/bastyn-core/src/rules/engine.rs's RegexMatcher), never how HERE was
assigned. This is the same precision ceiling every other
unconditional/structural rule in this batch (BAS-LLM10-009, -017, -018)
already accepts by design -- catching it would need real dataflow tracing,
not attempted here. Recorded as a known_false_positive rather than a
narrower exclusion that would risk also swallowing a real
os.path.join(some_caller_supplied_dir, filename) traversal.
"""

import os

HERE = os.path.dirname(__file__)


def read_bundled_config() -> str:
    """known_false_positive (LLM10): HERE is a safe, module-local constant
    -- never attacker-influenceable -- but BAS-LLM10-012 cannot tell that
    apart from a real non-literal without dataflow analysis, so it fires
    on the bare-identifier argument exactly as its contract says it
    should."""
    with open(os.path.join(HERE, "data.json")) as handle:
        return handle.read()
