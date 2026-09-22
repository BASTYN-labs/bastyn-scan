"""Real miss #7: exec() with an explicit globals dict argument.

Found via an external security-gap report run against a benchmark repo
called opsdesk-agent (not part of this file's own 65-real-repository
measurement corpus), at opsdesk-agent/mcp_server/tools.py:104. BAS-LLM10-004
used to match only the single-argument shapes eval($ARG)/exec($ARG) -- but
Python's exec() and eval() both accept optional positional globals/locals
dict arguments (exec(source, globals=None, locals=None)), an ordinary,
common idiom often used specifically to *sandbox* the call by passing a
restricted globals dict. Confirmed directly with a built binary:
exec(manifest["setup_code"]) (1 arg) was caught; exec(manifest["setup_code"],
{}) (2 args) was silently missed, purely because of the extra argument --
not because of the dict-subscript expression. An incomplete sandbox dict
(here, an empty one, which still leaves __builtins__ available) makes this
exactly the shape worth catching, not a rare one to skip.
"""

import json


def load_plugin_manifest(manifest_path: str) -> dict:
    with open(manifest_path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def run_plugin_setup(manifest_path: str) -> dict:
    """Real miss (LLM10): exec() with an explicit globals dict argument --
    previously missed because BAS-LLM10-004 only matched the single-argument
    shape, now caught."""
    manifest = load_plugin_manifest(manifest_path)
    namespace: dict = {}
    exec(manifest["setup_code"], namespace)
    return namespace
