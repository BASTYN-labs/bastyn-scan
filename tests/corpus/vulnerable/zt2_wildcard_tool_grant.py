"""Agent wiring: which tools OpsBot is allowed to call.

known_gap (ZT2): BAS-MCP-003 detects a wildcard tool grant, but only inside
a recognised MCP config file (mcp.json and its siblings). A Python-native
agent framework that grants every registered tool via a wildcard string in
application code -- the shape below -- has no equivalent rule; nothing in
bastyn.yml inspects an agent constructor's keyword arguments.
"""

from langchain.agents import initialize_agent

from llm03_excessive_agency import shutdown_server, get_server_status
from tools_extra import restart_service, delete_stale_snapshot, page_oncall

ALL_TOOLS = [shutdown_server, get_server_status, restart_service, delete_stale_snapshot, page_oncall]


def build_opsbot_agent(llm):
    """Wire up the OpsBot agent with every tool it will ever need.

    allowed_tools="*" grants every tool this agent could ever be extended
    with, present and future, rather than the specific handful the on-call
    triage flow actually needs. A new destructive tool added to ALL_TOOLS
    next quarter is trusted automatically, with no review of this wiring.
    """
    return initialize_agent(
        tools=ALL_TOOLS,
        llm=llm,
        allowed_tools="*",
        agent="zero-shot-react-description",
    )
