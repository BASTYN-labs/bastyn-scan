"""Known false positive: a function parameter reaches os.path.join, but
every call site in this file passes a literal.

BAS-LLM10-012's exclude_if: constant_path resolves a *module-level*
name's own assignment chain; it does not perform interprocedural
call-site analysis (are every one of this parameter's callers passing a
literal?), which is a materially different and larger analysis. Recorded
as a known_false_positive rather than attempted here -- see bastyn.yml's
comment on BAS-LLM10-012.
"""

import os

RESULTS = "/var/opsbot/results"


def _load_result(name: str) -> str:
    """known_false_positive (LLM10): name is a bare parameter, not a
    constant_path -- BAS-LLM10-012 cannot see that every call site below
    passes a literal without call-site analysis it does not have."""
    with open(os.path.join(RESULTS, name)) as handle:
        return handle.read()


def load_all_results() -> tuple[str, str, str]:
    return (
        _load_result("summary.json"),
        _load_result("outcomes.json"),
        _load_result("detail.json"),
    )
