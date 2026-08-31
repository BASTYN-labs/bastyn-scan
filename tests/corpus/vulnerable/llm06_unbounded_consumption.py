"""Ticket summarization for OpsBot's daily digest."""

from openai import OpenAI

from zt1_static_credentials import OPENAI_API_KEY, MODEL_NAME

client = OpenAI(api_key=OPENAI_API_KEY)


def summarize_ticket_backlog(ticket_text: str) -> str:
    """Summarize an arbitrarily long batch of ticket text for the digest.

    BAS-LLM06-001 (observation): no max_tokens is set, so nothing here
    bounds a single call's cost or latency. A caller could pass in a whole
    day's worth of tickets and the response length is unbounded too. This
    is an observation, not a defect -- a gateway limiter elsewhere in the
    deployment might already cap it, and the source alone cannot say.
    """
    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": "Summarize the following support tickets."},
            {"role": "user", "content": ticket_text},
        ],
    )
    return response.choices[0].message.content
