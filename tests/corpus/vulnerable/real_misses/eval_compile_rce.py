"""Real miss #1: eval(compile(...)) one hop away from the model reply.

Measured against a production agentic app: the model's reply is extracted
from a fenced code block first, then compiled and eval'd. BAS-LLM10-001
matches eval($ARG) where $ARG's own text contains a response/reply/... word
-- but here $ARG is `compiled`, a local variable one assignment removed
from the model's reply. The metavariable regex looks at the literal text of
the argument expression, not at what produced it, so this is missed.
"""

import re

from openai import OpenAI

from zt1_static_credentials import OPENAI_API_KEY, MODEL_NAME

client = OpenAI(api_key=OPENAI_API_KEY)

CODE_BLOCK = re.compile(r"```(?:python)?\n(.*?)```", re.DOTALL)


def ask_for_fix(incident_summary: str) -> str:
    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[{"role": "user", "content": f"Suggest a Python fix for: {incident_summary}"}],
        max_tokens=200,
    )
    return response.choices[0].message.content


def apply_suggested_fix(incident_summary: str):
    """known_gap (LLM10): eval(compile(...)) is one hop from the model reply."""
    reply = ask_for_fix(incident_summary)
    match = CODE_BLOCK.search(reply)
    code = match.group(1) if match else reply
    compiled = compile(code, "<model-suggestion>", "exec")
    return eval(compiled)
