"""Every near-miss called out in the corpus spec, in one file, deliberately.

Each of these is a shape that a naive scanner (or a naive rule) gets wrong.
Bastyn's rules are precise enough that none of them should fire here. This
file, and this file alone, is what proves precision rather than asserting
it: `expect_none` on the whole file.
"""

import os

# eval() on a literal: the `none:` exclusion and the ARG regex both keep
# BAS-LLM10-001 quiet.
literal_result = eval("2 + 2")

# Variable names that look secret-ish or token-ish by substring alone.
approx_tokens = 1500
token_count = 0
api_key_name = "OPENAI_API_KEY"
max_tokens = 500

# Correct credential handling: subscript / getenv, never a string literal.
openai_key = os.environ["OPENAI_API_KEY"]
anthropic_key = os.getenv("ANTHROPIC_API_KEY")


def build_greeting(name: str) -> str:
    """An f-string with one interpolation, but neither side is
    prompt/instruction-shaped or user-input-shaped -- BAS-ZT4-001's two
    metavariable regexes both need to match, and neither does here."""
    greeting = f"Hello, {name}! How can OpsBot help today?"
    return greeting


def safe_query(cursor, incident_id: str) -> None:
    """A cursor.execute() call, but parameterized -- the query text is a
    literal, and the untrusted value is a bind parameter, never
    interpolated into the SQL string itself."""
    cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
