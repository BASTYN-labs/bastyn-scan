"""Configuration for the crypto advisor agent (safe)."""

import os

# Correct practice: the key is read from the environment, never written into
# source. Must NOT be flagged by BAS-ZT1-001.
API_KEY = os.environ["OPENAI_API_KEY"]

MODEL_NAME = os.environ.get("ADVISOR_MODEL", "gpt-4")

# Near-miss names that a naive (text/regex) scanner confuses for secrets.
# None of these are strings shaped like a credential, and none of them are
# assigned a bare "sk-..." literal, so no rule in bastyn.yml should touch
# them.
api_key_name = "OPENAI_API_KEY"
approx_tokens_per_word = 1.3
token_count = 0
