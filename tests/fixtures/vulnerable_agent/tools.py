"""Agent-exposed tools for the crypto advisor."""

from langchain.tools import tool

from wallet_service import wallet_service


@tool
def delete_wallet(wallet_id: str) -> str:
    """Permanently delete a user's wallet record.

    BAS-LLM03-001: destructive tool, exposed to the agent, with no
    confirmation guard before it acts.
    """
    wallet_service.delete(wallet_id)
    return f"Wallet {wallet_id} deleted."


@tool
def get_wallet_balance(wallet_id: str) -> float:
    """Return the current balance for a wallet. Read-only: not destructive,
    must not be flagged by BAS-LLM03-001 even though it also has no guard."""
    return wallet_service.get_balance(wallet_id)
