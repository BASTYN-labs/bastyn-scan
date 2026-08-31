"""Configuration for OpsBot (safe): credentials come from the environment."""

import os

# Correct practice: read from the environment, never a string literal.
# BAS-ZT1-001's pattern requires a string-literal RHS; a subscript
# expression on os.environ never matches it.
OPENAI_API_KEY = os.environ["OPENAI_API_KEY"]

# A variable *named* like a secret, holding the *name* of an env var, not a
# value. Neither BAS-ZT1-001 (value isn't sk-shaped) nor BAS-LLM08-001
# (name isn't prompt-shaped) fire on name alone -- this is the
# `approx_tokens` mistake from the scope doc, done deliberately.
api_key_name = "OPENAI_API_KEY"

MODEL_NAME = os.getenv("OPSBOT_MODEL", "gpt-4o")

# Variable names containing "token"/"count". Not strings, not secrets, not
# flagged by anything.
approx_tokens_per_word = 1.3
token_count = 0
max_tokens_per_call = 500

# A default DSN in an os.getenv() fallback, pointed at localhost -- the
# dominant real shape of BAS-ZT1-002's remaining false positives measured
# 2026-08-28: 9 findings, all a default connection string like this one in
# application config, not a test fixture (those were already handled by the
# test_path downgrade). A DSN whose host is localhost/127.0.0.1 cannot reach
# anything outside the machine running it, so it is excluded by
# `metavariable_not_matches` regardless of the surrounding user/password
# text -- see bastyn.yml's comment on BAS-ZT1-002.
AUDIT_DB_URL = os.getenv(
    "AUDIT_DB_PATH", "postgresql+asyncpg://user:password@localhost:5432/audit"
)
