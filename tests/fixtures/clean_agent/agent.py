"""Core chat logic and agent-exposed tools for the crypto advisor (safe)."""

from langchain.tools import tool
from openai import OpenAI

from config import API_KEY, MODEL_NAME
from prompts import chat_prompt
from wallet_service import wallet_service

client = OpenAI(api_key=API_KEY)


def ask_advisor(sanitized_input: str) -> str:
    """Ask the model a crypto question. The caller has already sanitized and
    length-capped the input before it reaches this function.

    Correct practice: max_tokens bounds the response. Must NOT be flagged by
    BAS-LLM06-001.
    """
    messages = chat_prompt.format_messages(sanitized_input=sanitized_input)
    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[{"role": m.type, "content": m.content} for m in messages],
        max_tokens=500,
    )
    return response.choices[0].message.content


@tool
def delete_wallet(wallet_id: str, confirmed: bool = False) -> str:
    """Permanently delete a user's wallet record.

    Correct practice: the destructive action is gated on an explicit
    confirmation flag, checked first. Must NOT be flagged by BAS-LLM03-001.
    """
    if not confirmed:
        raise PermissionError("Wallet deletion requires confirmed=True from an authenticated request.")
    wallet_service.delete(wallet_id)
    return f"Wallet {wallet_id} deleted."


@tool
def get_wallet_balance(wallet_id: str) -> float:
    """Return the current balance for a wallet. Read-only."""
    return wallet_service.get_balance(wallet_id)
