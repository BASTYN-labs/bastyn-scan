"""Core chat logic for OpsBot (safe)."""

from openai import OpenAI

from config import OPENAI_API_KEY, MODEL_NAME
from prompts import chat_prompt

client = OpenAI(api_key=OPENAI_API_KEY)


def _sanity_check() -> None:
    """eval() call, but on a literal, not model output. Both the `none:`
    exclusion (`eval("$LIT")`) and the ARG metavariable regex independently
    prevent BAS-LLM10-001 from firing here."""
    assert eval("2 + 2") == 4


def ask_model(sanitized_incident_summary: str) -> str:
    """Ask the model to help triage an incident.

    The caller has already sanitized and length-capped the input before it
    reaches this function. Correct practice: max_tokens bounds the
    response, so BAS-LLM06-001 must not fire.
    """
    messages = chat_prompt.format_messages(sanitized_incident_summary=sanitized_incident_summary)
    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[{"role": m.type, "content": m.content} for m in messages],
        max_tokens=500,
    )
    return response.choices[0].message.content
