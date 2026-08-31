"""Real miss #4: autonomous action triggered by parsing model text.

Measured against a production agentic app: instead of a structured tool
call, the model is instructed to emit a sentinel token followed by a JSON
payload in its free-text reply. The application regex-searches for that
sentinel and, if found, acts on the embedded JSON directly -- no
confirmation, no schema validation beyond `json.loads`, and no rule
anywhere inspects a re.search() result feeding into an action dispatcher.
This is a different shape from BAS-LLM03-001 (a destructive-named tool
function with a missing guard clause): there is no tool function here at
all, just free text parsed for a magic marker.
"""

import json
import re

from infra_client import infra_client

EXECUTE_PATTERN = re.compile(r"EXECUTE_SIGNAL\{(.*?)\}", re.DOTALL)


def handle_model_reply(reply: str) -> str | None:
    """known_gap (LLM03): autonomous action from a regex match on model
    text, with no confirmation and no tool-call schema in between."""
    match = EXECUTE_PATTERN.search(reply)
    if not match:
        return None
    action = json.loads("{" + match.group(1) + "}")
    infra_client.dispatch(action["command"], action.get("args", {}))
    return f"Executed: {action['command']}"
