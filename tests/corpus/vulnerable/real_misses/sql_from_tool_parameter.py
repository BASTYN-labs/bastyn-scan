"""Real miss #10, a known gap: model output reaching SQL through a tool
function's own parameter.

Found via an external security-gap report run against a benchmark repo
called opsdesk-agent (not part of this file's own 65-real-repository
measurement corpus), at opsdesk-agent/mcp_server/tools.py. This is the
literal shape from that report: an MCP tool's own incoming parameter
(`query`) is interpolated into a local SQL variable, then executed.

Conceptually this parameter is agent/model-controlled the moment you know
`search_knowledge_base` is a tool handler an LLM calls with arguments the
model itself chose -- but BAS-LLM10-008 (see
crates/bastyn-core/rules/bastyn.yml) still misses it, and this is a real,
current, confirmed limit of that rule, not an oversight. The flow graph
resolves a bare parameter to `Origin::Parameter`, never
`Origin::Call{...}`, and `Origin::Parameter` cannot classify as
`source: model_output` no matter what the parameter is named -- the graph
has no concept that a parameter of an `@tool`-decorated function is
untrusted. Catching this would need a new `SourceKind` plus a
decorator-recognition pass that treats a tool function's own parameters as
tainted -- genuinely separate, larger engine work, not attempted here.

Contrast with sql_through_local_variable.py in this same directory: there,
the tainted value is traceable back through a local variable to an actual
model API call, which BAS-LLM10-008 does catch. Here, there is no
in-file call to trace back to at all -- just a parameter.
"""

from langchain.tools import tool


@tool
def search_knowledge_base(query: str, cursor) -> list[dict]:
    """known_gap (LLM10): `query` is this tool's own incoming parameter,
    agent-controlled once you know it's a tool handler -- but the flow
    graph resolves a bare parameter to Origin::Parameter, which no current
    rule classifies as model_output."""
    sql = f"SELECT id, title, body FROM kb_articles WHERE title LIKE '%{query}%'"
    cursor.execute(sql)
    return cursor.fetchall()
