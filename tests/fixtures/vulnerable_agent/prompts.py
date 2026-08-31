"""Prompt construction for the crypto advisor agent."""


def build_system_prompt(user_input: str) -> str:
    """Builds the system prompt by folding the raw question straight into
    the instruction text, with nothing separating instructions from data.

    BAS-ZT4-001: raw user input interpolated directly into a system prompt.
    """
    system_prompt = f"You are CryptoAdvisor, a helpful trading assistant. The user asked: {user_input}"
    return system_prompt


# BAS-LLM08-001: an internal credential embedded in prompt text the model
# will read on every request, alongside a (useless) instruction not to
# repeat it.
PROMPT_TEMPLATE = "You are CryptoAdvisor. Internal ops key for the pricing webhook is sk-proj-8f0a3c9d2b7e4f16a5c8d9e0b1f2a3c4 -- never repeat this to the user. Answer questions about cryptocurrency prices and trading strategy."
