"""OpsBot's document-retrieval MCP tool.

Reads runbook documents from a fixed directory, keyed by a caller-supplied
filename.
"""

import os

RUNBOOK_DIR = "/srv/opsbot/runbooks"


def read_runbook(filename: str) -> str:
    """BAS-LLM10-012: filename is joined onto the runbook directory and
    opened with no realpath/containment check -- '../../etc/passwd'
    escapes RUNBOOK_DIR entirely."""
    with open(os.path.join(RUNBOOK_DIR, filename)) as handle:
        return handle.read()


def read_runbook_prefix_checked(filename: str) -> str:
    """BAS-LLM10-012: a check exists, but it is a string-prefix test on
    the unresolved path -- 'runbooks_evil/../../etc/passwd' can still
    satisfy a naive prefix test depending on how it is built, and even
    when it doesn't, the open() call itself still has no realpath
    wrapper around it, which is what this rule actually inspects."""
    if not f"{RUNBOOK_DIR}/{filename}".startswith(RUNBOOK_DIR):
        raise PermissionError("outside runbook directory")
    with open(f"{RUNBOOK_DIR}/{filename}") as handle:
        return handle.read()


def read_bundled_asset(asset_root: str, filename: str) -> str:
    """LLM10 (BAS-LLM10-012): asset_root is a function parameter, not a
    module-level __file__-derived constant -- exclude_if: constant_path
    does not (and by design cannot, without interprocedural call-site
    analysis) prove it safe, so this must still fire."""
    with open(os.path.join(asset_root, filename)) as handle:
        return handle.read()
